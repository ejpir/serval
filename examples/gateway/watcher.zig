//! Kubernetes Resource Watcher
//!
//! Watches Gateway API resources and related K8s resources for changes.
//! Parses newline-delimited JSON watch event stream from K8s watch API
//! and triggers reconciliation when resources change.
//!
//! TigerStyle: Single thread, bounded buffers, reconnection with backoff.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const Io = std.Io;

const gateway = @import("serval-gateway");
const gw_config = gateway.config;
const Client = @import("k8s_client.zig").Client;

// =============================================================================
// Constants (TigerStyle: Explicit bounds and paths)
// =============================================================================

/// K8s API paths for Gateway API resources.
/// TigerStyle: Named constants, not magic strings.
pub const GATEWAY_CLASS_PATH = "/apis/gateway.networking.k8s.io/v1/gatewayclasses";
pub const GATEWAY_PATH = "/apis/gateway.networking.k8s.io/v1/gateways";
pub const HTTP_ROUTE_PATH = "/apis/gateway.networking.k8s.io/v1/httproutes";
pub const SERVICES_PATH = "/api/v1/services";
pub const ENDPOINTS_PATH = "/api/v1/endpoints";
pub const SECRETS_PATH = "/api/v1/secrets";

/// Maximum line buffer size for parsing watch events.
/// K8s objects can be large but 64KB should cover most Gateway API resources.
/// TigerStyle: Explicit bound prevents unbounded memory usage.
pub const MAX_LINE_SIZE_BYTES: u32 = 64 * 1024;

/// Maximum number of events to process per watch iteration.
/// TigerStyle: Bounded loop to prevent starvation.
pub const MAX_EVENTS_PER_ITERATION: u32 = 1000;

/// Maximum number of watch reconnection attempts before giving up.
/// TigerStyle: Bounded retry to prevent infinite loops.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 100;

/// Maximum number of resources to track per type.
/// TigerStyle: Bounded storage prevents unbounded growth.
pub const MAX_GATEWAYS: u32 = gw_config.MAX_GATEWAYS;
pub const MAX_HTTP_ROUTES: u32 = gw_config.MAX_HTTP_ROUTES;
pub const MAX_SERVICES: u32 = 256;
pub const MAX_ENDPOINTS: u32 = 256;
pub const MAX_SECRETS: u32 = 64;

/// Maximum string length for names/namespaces in parsed gw_config.
/// K8s DNS-1123 subdomain max is 253 chars.
pub const MAX_NAME_LEN: u32 = 253;

/// Maximum hostname length (matches K8s DNS-1123).
pub const MAX_HOSTNAME_LEN: u32 = 253;

/// Maximum path value length in route matches.
pub const MAX_PATH_VALUE_LEN: u32 = 512;

/// Maximum number of iteration passes for JSON array parsing.
/// Prevents unbounded loops when parsing malformed input.
pub const MAX_JSON_ARRAY_ITERATIONS: u32 = 1000;

/// Reconnection backoff configuration (milliseconds).
/// TigerStyle: Named constants with units in names.
pub const INITIAL_BACKOFF_MS: u32 = 1000;
pub const MAX_BACKOFF_MS: u32 = 30000;
pub const BACKOFF_MULTIPLIER: u32 = 2;

// =============================================================================
// Error Types (TigerStyle: Explicit error sets)
// =============================================================================

pub const WatcherError = error{
    /// Failed to parse watch event JSON
    ParseError,
    /// Line exceeds MAX_LINE_SIZE_BYTES
    LineTooLong,
    /// Unknown event type in watch response
    UnknownEventType,
    /// Maximum reconnection attempts exceeded
    MaxReconnectsExceeded,
    /// Watch stream closed unexpectedly
    StreamClosed,
    /// Out of memory during operation
    OutOfMemory,
    /// Buffer overflow - too many resources
    BufferOverflow,
    /// Client error during watch request
    ClientError,
    /// Invalid JSON structure
    InvalidJson,
    /// Missing required field in JSON
    MissingField,
};

// =============================================================================
// Watch Event Types
// =============================================================================

/// Watch event types from K8s API.
/// See: https://kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes
pub const EventType = enum {
    ADDED,
    MODIFIED,
    DELETED,
    BOOKMARK,
    ERROR,

    /// Parse event type from JSON string.
    /// Returns null for unknown types.
    pub fn fromString(s: []const u8) ?EventType {
        if (std.mem.eql(u8, s, "ADDED")) return .ADDED;
        if (std.mem.eql(u8, s, "MODIFIED")) return .MODIFIED;
        if (std.mem.eql(u8, s, "DELETED")) return .DELETED;
        if (std.mem.eql(u8, s, "BOOKMARK")) return .BOOKMARK;
        if (std.mem.eql(u8, s, "ERROR")) return .ERROR;
        return null;
    }

    /// Convert to string for logging.
    pub fn toString(self: EventType) []const u8 {
        return switch (self) {
            .ADDED => "ADDED",
            .MODIFIED => "MODIFIED",
            .DELETED => "DELETED",
            .BOOKMARK => "BOOKMARK",
            .ERROR => "ERROR",
        };
    }
};

/// Generic watch event from K8s API.
/// Contains the event type and raw JSON object.
pub const WatchEvent = struct {
    /// Event type (ADDED, MODIFIED, DELETED, BOOKMARK, ERROR).
    event_type: EventType,
    /// Raw JSON of the K8s object.
    /// TigerStyle: Store raw JSON to avoid complex parsing upfront.
    /// Specific fields can be extracted on demand.
    raw_object: []const u8,
};

/// Resource metadata extracted from K8s objects.
/// Minimal fields needed for tracking and reconciliation.
pub const ResourceMeta = struct {
    /// Resource name (metadata.name).
    name: []const u8,
    /// Resource namespace (metadata.namespace).
    namespace: []const u8,
    /// Resource version for watch resumption.
    resource_version: []const u8,
};

// =============================================================================
// Resource Store
// =============================================================================

/// Tracked resource with metadata and raw JSON.
/// TigerStyle: Fixed-size entry for bounded storage.
pub const TrackedResource = struct {
    meta: ResourceMeta,
    raw_json: []const u8,
    /// Indicates if this slot is in use.
    active: bool,
};

/// Storage for tracked resources of a single type.
/// TigerStyle: Fixed-size array with bounded capacity.
pub fn ResourceStore(comptime capacity: u32) type {
    return struct {
        const Self = @This();

        /// Fixed-size storage for resources.
        items: [capacity]TrackedResource,
        /// Number of active items.
        count: u32,
        /// Latest resource version seen (for watch resumption).
        latest_resource_version: [64]u8,
        latest_resource_version_len: u8,

        /// Initialize empty store.
        pub fn init() Self {
            var self = Self{
                .items = undefined,
                .count = 0,
                .latest_resource_version = std.mem.zeroes([64]u8),
                .latest_resource_version_len = 0,
            };
            // TigerStyle: Initialize all slots as inactive.
            for (&self.items) |*item| {
                item.active = false;
            }
            return self;
        }

        /// Add or update a resource.
        /// Returns error if store is full and resource doesn't exist.
        pub fn upsert(
            self: *Self,
            meta: ResourceMeta,
            raw_json: []const u8,
        ) WatcherError!void {
            assert(meta.name.len > 0); // S1: precondition
            assert(meta.namespace.len > 0); // S1: precondition

            // Try to find existing entry with same name/namespace.
            var found_idx: ?u32 = null;
            var iteration: u32 = 0;
            while (iteration < capacity) : (iteration += 1) {
                if (self.items[iteration].active) {
                    const existing = self.items[iteration].meta;
                    if (std.mem.eql(u8, existing.name, meta.name) and
                        std.mem.eql(u8, existing.namespace, meta.namespace))
                    {
                        found_idx = iteration;
                        break;
                    }
                }
            }

            if (found_idx) |idx| {
                // Update existing entry.
                self.items[idx].meta = meta;
                self.items[idx].raw_json = raw_json;
            } else {
                // Find first inactive slot.
                var slot_idx: ?u32 = null;
                iteration = 0;
                while (iteration < capacity) : (iteration += 1) {
                    if (!self.items[iteration].active) {
                        slot_idx = iteration;
                        break;
                    }
                }

                if (slot_idx) |idx| {
                    self.items[idx] = .{
                        .meta = meta,
                        .raw_json = raw_json,
                        .active = true,
                    };
                    self.count += 1;
                } else {
                    return WatcherError.BufferOverflow;
                }
            }

            // Update latest resource version.
            self.updateResourceVersion(meta.resource_version);
        }

        /// Remove a resource by name/namespace.
        /// Returns true if resource was found and removed.
        pub fn remove(self: *Self, name: []const u8, namespace: []const u8) bool {
            assert(name.len > 0); // S1: precondition
            assert(namespace.len > 0); // S1: precondition

            var iteration: u32 = 0;
            while (iteration < capacity) : (iteration += 1) {
                if (self.items[iteration].active) {
                    const existing = self.items[iteration].meta;
                    if (std.mem.eql(u8, existing.name, name) and
                        std.mem.eql(u8, existing.namespace, namespace))
                    {
                        self.items[iteration].active = false;
                        self.count -= 1;
                        return true;
                    }
                }
            }
            return false;
        }

        /// Get all active resources.
        /// TigerStyle: Returns slice of active items for iteration.
        pub fn getActive(self: *const Self, buffer: []TrackedResource) []TrackedResource {
            var count: u32 = 0;
            var iteration: u32 = 0;
            while (iteration < capacity and count < buffer.len) : (iteration += 1) {
                if (self.items[iteration].active) {
                    buffer[count] = self.items[iteration];
                    count += 1;
                }
            }
            return buffer[0..count];
        }

        /// Get the latest resource version for watch resumption.
        pub fn getLatestResourceVersion(self: *const Self) []const u8 {
            return self.latest_resource_version[0..self.latest_resource_version_len];
        }

        /// Update the latest resource version.
        /// Public to allow Watcher to update version on BOOKMARK events.
        pub fn updateResourceVersion(self: *Self, rv: []const u8) void {
            const len = @min(rv.len, self.latest_resource_version.len);
            @memcpy(self.latest_resource_version[0..len], rv[0..len]);
            self.latest_resource_version_len = @intCast(len);
        }
    };
}

// =============================================================================
// Parsed Config Storage
// =============================================================================

/// Fixed-size storage for a name string.
/// TigerStyle: Bounded storage, no allocation after init.
pub const NameStorage = struct {
    data: [MAX_NAME_LEN]u8,
    len: u8,

    pub fn init() NameStorage {
        return .{
            .data = std.mem.zeroes([MAX_NAME_LEN]u8),
            .len = 0,
        };
    }

    pub fn set(self: *NameStorage, value: []const u8) void {
        assert(value.len <= MAX_NAME_LEN); // S1: precondition
        const copy_len: u8 = @intCast(@min(value.len, MAX_NAME_LEN));
        @memcpy(self.data[0..copy_len], value[0..copy_len]);
        self.len = copy_len;
    }

    pub fn slice(self: *const NameStorage) []const u8 {
        return self.data[0..self.len];
    }
};

/// Fixed-size storage for a hostname string.
pub const HostnameStorage = struct {
    data: [MAX_HOSTNAME_LEN]u8,
    len: u8,

    pub fn init() HostnameStorage {
        return .{
            .data = std.mem.zeroes([MAX_HOSTNAME_LEN]u8),
            .len = 0,
        };
    }

    pub fn set(self: *HostnameStorage, value: []const u8) void {
        assert(value.len <= MAX_HOSTNAME_LEN); // S1: precondition
        const copy_len: u8 = @intCast(@min(value.len, MAX_HOSTNAME_LEN));
        @memcpy(self.data[0..copy_len], value[0..copy_len]);
        self.len = copy_len;
    }

    pub fn slice(self: *const HostnameStorage) []const u8 {
        return self.data[0..self.len];
    }
};

/// Fixed-size storage for a path value string.
pub const PathStorage = struct {
    data: [MAX_PATH_VALUE_LEN]u8,
    len: u16,

    pub fn init() PathStorage {
        return .{
            .data = std.mem.zeroes([MAX_PATH_VALUE_LEN]u8),
            .len = 0,
        };
    }

    pub fn set(self: *PathStorage, value: []const u8) void {
        assert(value.len <= MAX_PATH_VALUE_LEN); // S1: precondition
        const copy_len: u16 = @intCast(@min(value.len, MAX_PATH_VALUE_LEN));
        @memcpy(self.data[0..copy_len], value[0..copy_len]);
        self.len = copy_len;
    }

    pub fn slice(self: *const PathStorage) []const u8 {
        return self.data[0..self.len];
    }
};

/// Stored path match with inline storage.
pub const StoredPathMatch = struct {
    match_type: gw_config.PathMatch.Type,
    value: PathStorage,
    active: bool,

    pub fn init() StoredPathMatch {
        return .{
            .match_type = .PathPrefix,
            .value = PathStorage.init(),
            .active = false,
        };
    }

    /// Convert to gw_config.PathMatch (returns slice into internal storage).
    pub fn toPathMatch(self: *const StoredPathMatch) gw_config.PathMatch {
        return .{
            .type = self.match_type,
            .value = self.value.slice(),
        };
    }
};

/// Stored path rewrite with inline storage.
pub const StoredPathRewrite = struct {
    rewrite_type: gw_config.PathRewrite.Type,
    value: PathStorage,
    active: bool,

    pub fn init() StoredPathRewrite {
        return .{
            .rewrite_type = .ReplacePrefixMatch,
            .value = PathStorage.init(),
            .active = false,
        };
    }

    /// Convert to gw_config.PathRewrite (returns slice into internal storage).
    pub fn toPathRewrite(self: *const StoredPathRewrite) gw_config.PathRewrite {
        return .{
            .type = self.rewrite_type,
            .value = self.value.slice(),
        };
    }
};

/// Stored URL rewrite with inline storage.
pub const StoredURLRewrite = struct {
    path: StoredPathRewrite,
    has_path: bool,

    pub fn init() StoredURLRewrite {
        return .{
            .path = StoredPathRewrite.init(),
            .has_path = false,
        };
    }
};

/// Stored HTTP route filter with inline storage.
pub const StoredHTTPRouteFilter = struct {
    filter_type: gw_config.HTTPRouteFilter.Type,
    url_rewrite: StoredURLRewrite,
    active: bool,

    pub fn init() StoredHTTPRouteFilter {
        return .{
            .filter_type = .URLRewrite,
            .url_rewrite = StoredURLRewrite.init(),
            .active = false,
        };
    }
};

/// Stored HTTP route match with inline storage.
pub const StoredHTTPRouteMatch = struct {
    path: StoredPathMatch,
    has_path: bool,
    active: bool,

    pub fn init() StoredHTTPRouteMatch {
        return .{
            .path = StoredPathMatch.init(),
            .has_path = false,
            .active = false,
        };
    }
};

/// Stored backend reference with inline storage.
pub const StoredBackendRef = struct {
    name: NameStorage,
    namespace: NameStorage,
    port: u16,
    weight: u16,
    active: bool,

    pub fn init() StoredBackendRef {
        return .{
            .name = NameStorage.init(),
            .namespace = NameStorage.init(),
            .port = 0,
            .weight = 1,
            .active = false,
        };
    }
};

/// Stored HTTP route rule with inline storage.
pub const StoredHTTPRouteRule = struct {
    matches: [gw_config.MAX_MATCHES]StoredHTTPRouteMatch,
    matches_count: u8,
    filters: [gw_config.MAX_FILTERS]StoredHTTPRouteFilter,
    filters_count: u8,
    backend_refs: [gw_config.MAX_BACKEND_REFS]StoredBackendRef,
    backend_refs_count: u8,
    active: bool,

    pub fn init() StoredHTTPRouteRule {
        var rule = StoredHTTPRouteRule{
            .matches = undefined,
            .matches_count = 0,
            .filters = undefined,
            .filters_count = 0,
            .backend_refs = undefined,
            .backend_refs_count = 0,
            .active = false,
        };
        for (&rule.matches) |*m| m.* = StoredHTTPRouteMatch.init();
        for (&rule.filters) |*f| f.* = StoredHTTPRouteFilter.init();
        for (&rule.backend_refs) |*b| b.* = StoredBackendRef.init();
        return rule;
    }
};

/// Stored HTTP route with inline storage.
pub const StoredHTTPRoute = struct {
    name: NameStorage,
    namespace: NameStorage,
    hostnames: [gw_config.MAX_HOSTNAMES]HostnameStorage,
    hostnames_count: u8,
    rules: [gw_config.MAX_RULES]StoredHTTPRouteRule,
    rules_count: u8,
    active: bool,

    pub fn init() StoredHTTPRoute {
        var route = StoredHTTPRoute{
            .name = NameStorage.init(),
            .namespace = NameStorage.init(),
            .hostnames = undefined,
            .hostnames_count = 0,
            .rules = undefined,
            .rules_count = 0,
            .active = false,
        };
        for (&route.hostnames) |*h| h.* = HostnameStorage.init();
        for (&route.rules) |*r| r.* = StoredHTTPRouteRule.init();
        return route;
    }
};

/// Stored listener with inline storage.
pub const StoredListener = struct {
    name: NameStorage,
    port: u16,
    protocol: gw_config.Listener.Protocol,
    hostname: HostnameStorage,
    has_hostname: bool,
    active: bool,

    pub fn init() StoredListener {
        return .{
            .name = NameStorage.init(),
            .port = 0,
            .protocol = .HTTP,
            .hostname = HostnameStorage.init(),
            .has_hostname = false,
            .active = false,
        };
    }
};

/// Stored gateway with inline storage.
pub const StoredGateway = struct {
    name: NameStorage,
    namespace: NameStorage,
    listeners: [gw_config.MAX_LISTENERS]StoredListener,
    listeners_count: u8,
    active: bool,

    pub fn init() StoredGateway {
        var gw = StoredGateway{
            .name = NameStorage.init(),
            .namespace = NameStorage.init(),
            .listeners = undefined,
            .listeners_count = 0,
            .active = false,
        };
        for (&gw.listeners) |*l| l.* = StoredListener.init();
        return gw;
    }
};

// =============================================================================
// Watcher
// =============================================================================

/// Kubernetes resource watcher.
/// Watches Gateway API resources and triggers reconciliation on changes.
pub const Watcher = struct {
    /// K8s API client.
    client: *Client,
    /// Allocator for dynamic allocations.
    allocator: std.mem.Allocator,
    /// Atomic flag for graceful shutdown.
    running: std.atomic.Value(bool),
    /// Callback invoked when configuration changes.
    /// First arg is user context, second is new config.
    on_config_change: *const fn (?*anyopaque, *gw_config.GatewayConfig) void,
    /// User context passed to callback.
    callback_context: ?*anyopaque,

    /// Resource stores for each watched type.
    gateways: ResourceStore(MAX_GATEWAYS),
    http_routes: ResourceStore(MAX_HTTP_ROUTES),
    services: ResourceStore(MAX_SERVICES),
    endpoints: ResourceStore(MAX_ENDPOINTS),
    secrets: ResourceStore(MAX_SECRETS),

    /// Parsed Gateway storage (populated by reconcile).
    parsed_gateways: [MAX_GATEWAYS]StoredGateway,
    parsed_gateways_count: u8,

    /// Parsed HTTPRoute storage (populated by reconcile).
    parsed_http_routes: [MAX_HTTP_ROUTES]StoredHTTPRoute,
    parsed_http_routes_count: u8,

    /// Temporary slices for building GatewayConfig return value.
    /// These point into parsed_* storage and are valid until next reconcile().
    temp_gateways: [MAX_GATEWAYS]gw_config.Gateway,
    temp_http_routes: [MAX_HTTP_ROUTES]gw_config.HTTPRoute,

    /// Storage for temporary hostname slices per route.
    temp_hostnames: [MAX_HTTP_ROUTES][gw_config.MAX_HOSTNAMES][]const u8,
    /// Storage for temporary rules slices per route.
    temp_rules: [MAX_HTTP_ROUTES][gw_config.MAX_RULES]gw_config.HTTPRouteRule,
    /// Storage for temporary matches slices per rule.
    temp_matches: [MAX_HTTP_ROUTES][gw_config.MAX_RULES][gw_config.MAX_MATCHES]gw_config.HTTPRouteMatch,
    /// Storage for temporary filters slices per rule.
    temp_filters: [MAX_HTTP_ROUTES][gw_config.MAX_RULES][gw_config.MAX_FILTERS]gw_config.HTTPRouteFilter,
    /// Storage for temporary backend_refs slices per rule.
    temp_backend_refs: [MAX_HTTP_ROUTES][gw_config.MAX_RULES][gw_config.MAX_BACKEND_REFS]gw_config.BackendRef,
    /// Storage for temporary listeners slices per gateway.
    temp_listeners: [MAX_GATEWAYS][gw_config.MAX_LISTENERS]gw_config.Listener,

    /// Line buffer for parsing watch events.
    /// TigerStyle: Pre-allocated, bounded buffer.
    line_buffer: []u8,

    /// Current backoff duration in milliseconds.
    current_backoff_ms: u32,

    const Self = @This();

    /// Initialize watcher with client and callback.
    ///
    /// Preconditions:
    /// - client must be initialized and valid
    /// - on_config_change must be a valid function pointer
    pub fn init(
        allocator: std.mem.Allocator,
        client: *Client,
        on_config_change: *const fn (?*anyopaque, *gw_config.GatewayConfig) void,
        callback_context: ?*anyopaque,
    ) WatcherError!*Self {
        // S1: precondition - client must be valid (can't be null for pointer type)

        const self = allocator.create(Self) catch return WatcherError.OutOfMemory;
        errdefer allocator.destroy(self);

        const line_buffer = allocator.alloc(u8, MAX_LINE_SIZE_BYTES) catch return WatcherError.OutOfMemory;
        errdefer allocator.free(line_buffer);

        self.* = .{
            .client = client,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
            .on_config_change = on_config_change,
            .callback_context = callback_context,
            .gateways = ResourceStore(MAX_GATEWAYS).init(),
            .http_routes = ResourceStore(MAX_HTTP_ROUTES).init(),
            .services = ResourceStore(MAX_SERVICES).init(),
            .endpoints = ResourceStore(MAX_ENDPOINTS).init(),
            .secrets = ResourceStore(MAX_SECRETS).init(),
            .parsed_gateways = undefined,
            .parsed_gateways_count = 0,
            .parsed_http_routes = undefined,
            .parsed_http_routes_count = 0,
            .temp_gateways = undefined,
            .temp_http_routes = undefined,
            .temp_hostnames = undefined,
            .temp_rules = undefined,
            .temp_matches = undefined,
            .temp_filters = undefined,
            .temp_backend_refs = undefined,
            .temp_listeners = undefined,
            .line_buffer = line_buffer,
            .current_backoff_ms = INITIAL_BACKOFF_MS,
        };

        // Initialize parsed storage arrays.
        for (&self.parsed_gateways) |*gw| gw.* = StoredGateway.init();
        for (&self.parsed_http_routes) |*route| route.* = StoredHTTPRoute.init();

        return self;
    }

    /// Clean up all allocated resources.
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.line_buffer);
        self.allocator.destroy(self);
    }

    /// Start watching in a separate thread.
    /// Returns the spawned thread handle.
    pub fn start(self: *Self) !std.Thread {
        self.running.store(true, .release);
        return std.Thread.spawn(.{}, watchLoopWrapper, .{self});
    }

    /// Stop watching gracefully.
    /// Sets the running flag to false; thread will exit on next iteration.
    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
    }

    /// Thread wrapper for watch loop.
    fn watchLoopWrapper(self: *Self) void {
        self.watchLoop();
    }

    /// Main watch loop.
    /// Watches all resource types and handles reconnection.
    /// TigerStyle: Bounded iterations, explicit backoff, Io.Threaded for async I/O.
    fn watchLoop(self: *Self) void {
        // Initialize Io runtime for HTTP client.
        // TigerStyle: One-time initialization at thread start.
        var io_runtime = Io.Threaded.init(self.allocator, .{});
        defer io_runtime.deinit();
        const io = io_runtime.io();

        var reconnect_attempts: u32 = 0;

        while (self.running.load(.acquire) and reconnect_attempts < MAX_RECONNECT_ATTEMPTS) {
            // Watch each resource type.
            // TigerStyle: Explicit iteration over resource types.
            const watch_success = self.watchAllResources(io);

            if (watch_success) {
                // Reset backoff on success.
                self.current_backoff_ms = INITIAL_BACKOFF_MS;
                reconnect_attempts = 0;
            } else {
                // Apply exponential backoff on failure.
                reconnect_attempts += 1;
                self.applyBackoff();
            }
        }

        if (reconnect_attempts >= MAX_RECONNECT_ATTEMPTS) {
            std.log.err("watcher: max reconnection attempts ({d}) exceeded", .{MAX_RECONNECT_ATTEMPTS});
        }
    }

    /// Watch all resource types.
    /// Returns true if all watches completed successfully.
    fn watchAllResources(self: *Self, io: Io) bool {
        // Watch Gateway resources.
        const gateway_success = self.watchResourceType(GATEWAY_PATH, .gateway, io);
        if (!gateway_success) return false;

        // Watch HTTPRoute resources.
        const route_success = self.watchResourceType(HTTP_ROUTE_PATH, .http_route, io);
        if (!route_success) return false;

        // Watch Service resources.
        const service_success = self.watchResourceType(SERVICES_PATH, .service, io);
        if (!service_success) return false;

        // Watch Endpoints resources.
        const endpoint_success = self.watchResourceType(ENDPOINTS_PATH, .endpoints, io);
        if (!endpoint_success) return false;

        // Watch Secret resources.
        const secret_success = self.watchResourceType(SECRETS_PATH, .secret, io);
        if (!secret_success) return false;

        return true;
    }

    /// Resource type enum for dispatch.
    const ResourceType = enum {
        gateway,
        http_route,
        service,
        endpoints,
        secret,
    };

    /// Watch a single resource type.
    /// Returns true if watch completed without error.
    fn watchResourceType(self: *Self, path: []const u8, resource_type: ResourceType, io: Io) bool {
        // Build watch URL with resourceVersion for resumption.
        var url_buffer: [512]u8 = undefined;
        const rv = switch (resource_type) {
            .gateway => self.gateways.getLatestResourceVersion(),
            .http_route => self.http_routes.getLatestResourceVersion(),
            .service => self.services.getLatestResourceVersion(),
            .endpoints => self.endpoints.getLatestResourceVersion(),
            .secret => self.secrets.getLatestResourceVersion(),
        };

        const watch_url = if (rv.len > 0)
            std.fmt.bufPrint(&url_buffer, "{s}?watch=true&resourceVersion={s}", .{ path, rv }) catch {
                std.log.err("watcher: URL buffer overflow for {s}", .{path});
                return false;
            }
        else
            std.fmt.bufPrint(&url_buffer, "{s}?watch=true", .{path}) catch {
                std.log.err("watcher: URL buffer overflow for {s}", .{path});
                return false;
            };

        // Start watch stream.
        var stream = self.client.watch(watch_url);

        // Process events until stream ends or error.
        var events_processed: u32 = 0;
        while (events_processed < MAX_EVENTS_PER_ITERATION and self.running.load(.acquire)) {
            // Read next event line.
            const event_data = stream.readEvent(self.line_buffer, io) catch |err| {
                std.log.debug("watcher: read error for {s}: {s}", .{ path, @errorName(err) });
                return false;
            };

            if (event_data) |data| {
                // Parse and handle event.
                self.handleEvent(data, resource_type) catch |err| {
                    std.log.debug("watcher: event handling error: {s}", .{@errorName(err)});
                    // Continue processing despite parse errors.
                };
                events_processed += 1;
            } else {
                // Stream ended normally.
                break;
            }
        }

        return true;
    }

    /// Handle a single watch event.
    fn handleEvent(self: *Self, data: []const u8, resource_type: ResourceType) WatcherError!void {
        const event = try parseEvent(data);

        // Handle based on event type.
        switch (event.event_type) {
            .ADDED, .MODIFIED => {
                const meta = try extractResourceMeta(event.raw_object);
                switch (resource_type) {
                    .gateway => try self.gateways.upsert(meta, event.raw_object),
                    .http_route => try self.http_routes.upsert(meta, event.raw_object),
                    .service => try self.services.upsert(meta, event.raw_object),
                    .endpoints => try self.endpoints.upsert(meta, event.raw_object),
                    .secret => try self.secrets.upsert(meta, event.raw_object),
                }
                // Trigger reconciliation.
                self.triggerReconciliation();
            },
            .DELETED => {
                const meta = try extractResourceMeta(event.raw_object);
                const removed = switch (resource_type) {
                    .gateway => self.gateways.remove(meta.name, meta.namespace),
                    .http_route => self.http_routes.remove(meta.name, meta.namespace),
                    .service => self.services.remove(meta.name, meta.namespace),
                    .endpoints => self.endpoints.remove(meta.name, meta.namespace),
                    .secret => self.secrets.remove(meta.name, meta.namespace),
                };
                if (removed) {
                    self.triggerReconciliation();
                }
            },
            .BOOKMARK => {
                // Bookmark events just update resource version, no reconciliation needed.
                const meta = try extractResourceMeta(event.raw_object);
                switch (resource_type) {
                    .gateway => self.gateways.updateResourceVersion(meta.resource_version),
                    .http_route => self.http_routes.updateResourceVersion(meta.resource_version),
                    .service => self.services.updateResourceVersion(meta.resource_version),
                    .endpoints => self.endpoints.updateResourceVersion(meta.resource_version),
                    .secret => self.secrets.updateResourceVersion(meta.resource_version),
                }
            },
            .ERROR => {
                std.log.warn("watcher: received ERROR event", .{});
                // Error events may indicate watch needs restart.
            },
        }
    }

    /// Trigger reconciliation by building config and calling callback.
    fn triggerReconciliation(self: *Self) void {
        // Build GatewayConfig from stored resources.
        var gateway_config = self.reconcile() catch |err| {
            std.log.err("watcher: reconciliation failed: {s}", .{@errorName(err)});
            return;
        };

        // Invoke callback with context and new gw_config.
        self.on_config_change(self.callback_context, &gateway_config);
    }

    /// Reconcile stored resources into a GatewayConfig.
    /// Parses raw JSON from ResourceStores into typed config structs.
    ///
    /// TigerStyle:
    /// - S1: Preconditions checked on entry
    /// - S2: Postconditions verified on exit
    /// - S3: All loops bounded by MAX_* constants
    /// - No allocation after init (uses pre-allocated storage arrays)
    pub fn reconcile(self: *Self) WatcherError!gw_config.GatewayConfig {
        // Reset parsed counts.
        self.parsed_gateways_count = 0;
        self.parsed_http_routes_count = 0;

        // Phase 1: Parse raw JSON into typed storage.
        try self.parseStoredGateways();
        try self.parseStoredHTTPRoutes();

        // Phase 2: Build config slices from parsed storage.
        self.buildGatewayConfigs();
        self.buildHTTPRouteConfigs();

        // S2: Postconditions
        assert(self.parsed_gateways_count <= MAX_GATEWAYS);
        assert(self.parsed_http_routes_count <= MAX_HTTP_ROUTES);

        return gw_config.GatewayConfig{
            .gateways = self.temp_gateways[0..self.parsed_gateways_count],
            .http_routes = self.temp_http_routes[0..self.parsed_http_routes_count],
        };
    }

    /// Parse Gateway resources from ResourceStore into typed storage.
    /// TigerStyle: Bounded loop, explicit error handling.
    fn parseStoredGateways(self: *Self) WatcherError!void {
        var iteration: u32 = 0;
        const items = self.gateways.items;

        while (iteration < MAX_GATEWAYS) : (iteration += 1) {
            if (!items[iteration].active) continue;

            const raw_json = items[iteration].raw_json;
            if (raw_json.len == 0) continue;

            if (self.parsed_gateways_count >= MAX_GATEWAYS) {
                return WatcherError.BufferOverflow;
            }

            const idx = self.parsed_gateways_count;
            try parseGatewayJson(raw_json, &self.parsed_gateways[idx]);
            self.parsed_gateways[idx].active = true;
            self.parsed_gateways_count += 1;
        }

        // S2: Postcondition
        assert(self.parsed_gateways_count <= MAX_GATEWAYS);
    }

    /// Parse HTTPRoute resources from ResourceStore into typed storage.
    /// TigerStyle: Bounded loop, explicit error handling.
    fn parseStoredHTTPRoutes(self: *Self) WatcherError!void {
        var iteration: u32 = 0;
        const items = self.http_routes.items;

        while (iteration < MAX_HTTP_ROUTES) : (iteration += 1) {
            if (!items[iteration].active) continue;

            const raw_json = items[iteration].raw_json;
            if (raw_json.len == 0) continue;

            if (self.parsed_http_routes_count >= MAX_HTTP_ROUTES) {
                return WatcherError.BufferOverflow;
            }

            const idx = self.parsed_http_routes_count;
            try parseHTTPRouteJson(raw_json, &self.parsed_http_routes[idx]);
            self.parsed_http_routes[idx].active = true;
            self.parsed_http_routes_count += 1;
        }

        // S2: Postcondition
        assert(self.parsed_http_routes_count <= MAX_HTTP_ROUTES);
    }

    /// Build gw_config.Gateway slices from parsed storage.
    /// TigerStyle: Bounded loops, no allocation.
    fn buildGatewayConfigs(self: *Self) void {
        var gw_idx: u8 = 0;

        while (gw_idx < self.parsed_gateways_count) : (gw_idx += 1) {
            const stored = &self.parsed_gateways[gw_idx];

            // Build listeners slice for this gateway.
            var listener_idx: u8 = 0;
            while (listener_idx < stored.listeners_count) : (listener_idx += 1) {
                const stored_listener = &stored.listeners[listener_idx];
                self.temp_listeners[gw_idx][listener_idx] = gw_config.Listener{
                    .name = stored_listener.name.slice(),
                    .port = stored_listener.port,
                    .protocol = stored_listener.protocol,
                    .hostname = if (stored_listener.has_hostname) stored_listener.hostname.slice() else null,
                    .tls = null, // TLS config parsing not implemented yet
                };
            }

            self.temp_gateways[gw_idx] = gw_config.Gateway{
                .name = stored.name.slice(),
                .namespace = stored.namespace.slice(),
                .listeners = self.temp_listeners[gw_idx][0..stored.listeners_count],
            };
        }
    }

    /// Build gw_config.HTTPRoute slices from parsed storage.
    /// TigerStyle: Bounded loops, no allocation.
    fn buildHTTPRouteConfigs(self: *Self) void {
        var route_idx: u8 = 0;

        while (route_idx < self.parsed_http_routes_count) : (route_idx += 1) {
            const stored = &self.parsed_http_routes[route_idx];

            // Build hostnames slice.
            var hostname_idx: u8 = 0;
            while (hostname_idx < stored.hostnames_count) : (hostname_idx += 1) {
                self.temp_hostnames[route_idx][hostname_idx] = stored.hostnames[hostname_idx].slice();
            }

            // Build rules slice.
            var rule_idx: u8 = 0;
            while (rule_idx < stored.rules_count) : (rule_idx += 1) {
                self.buildRuleConfig(route_idx, rule_idx, &stored.rules[rule_idx]);
            }

            self.temp_http_routes[route_idx] = gw_config.HTTPRoute{
                .name = stored.name.slice(),
                .namespace = stored.namespace.slice(),
                .hostnames = self.temp_hostnames[route_idx][0..stored.hostnames_count],
                .rules = self.temp_rules[route_idx][0..stored.rules_count],
            };
        }
    }

    /// Build a single HTTPRouteRule config from stored rule.
    /// TigerStyle: Helper to keep buildHTTPRouteConfigs under 70 lines.
    fn buildRuleConfig(self: *Self, route_idx: u8, rule_idx: u8, stored_rule: *const StoredHTTPRouteRule) void {
        // S1: Preconditions
        assert(route_idx < gw_config.MAX_HTTP_ROUTES);
        assert(rule_idx < gw_config.MAX_RULES);

        // Build matches slice.
        var match_idx: u8 = 0;
        while (match_idx < stored_rule.matches_count) : (match_idx += 1) {
            const stored_match = &stored_rule.matches[match_idx];
            self.temp_matches[route_idx][rule_idx][match_idx] = gw_config.HTTPRouteMatch{
                .path = if (stored_match.has_path) stored_match.path.toPathMatch() else null,
            };
        }

        // Build filters slice.
        var filter_idx: u8 = 0;
        while (filter_idx < stored_rule.filters_count) : (filter_idx += 1) {
            const stored_filter = &stored_rule.filters[filter_idx];
            const url_rewrite: ?gw_config.URLRewrite = if (stored_filter.url_rewrite.has_path)
                gw_config.URLRewrite{ .path = stored_filter.url_rewrite.path.toPathRewrite() }
            else
                null;

            self.temp_filters[route_idx][rule_idx][filter_idx] = gw_config.HTTPRouteFilter{
                .type = stored_filter.filter_type,
                .url_rewrite = url_rewrite,
            };
        }

        // Build backend_refs slice.
        var backend_idx: u8 = 0;
        while (backend_idx < stored_rule.backend_refs_count) : (backend_idx += 1) {
            const stored_backend = &stored_rule.backend_refs[backend_idx];
            self.temp_backend_refs[route_idx][rule_idx][backend_idx] = gw_config.BackendRef{
                .name = stored_backend.name.slice(),
                .namespace = stored_backend.namespace.slice(),
                .port = stored_backend.port,
                .weight = stored_backend.weight,
            };
        }

        self.temp_rules[route_idx][rule_idx] = gw_config.HTTPRouteRule{
            .matches = self.temp_matches[route_idx][rule_idx][0..stored_rule.matches_count],
            .filters = self.temp_filters[route_idx][rule_idx][0..stored_rule.filters_count],
            .backend_refs = self.temp_backend_refs[route_idx][rule_idx][0..stored_rule.backend_refs_count],
        };
    }

    /// Apply backoff delay with exponential increase.
    fn applyBackoff(self: *Self) void {
        // Sleep for current backoff duration.
        const backoff_s: u64 = self.current_backoff_ms / 1000;
        const backoff_ns: u64 = (@as(u64, self.current_backoff_ms) % 1000) * 1_000_000;
        posix.nanosleep(backoff_s, backoff_ns);

        // Increase backoff for next attempt (capped at MAX_BACKOFF_MS).
        const new_backoff = self.current_backoff_ms * BACKOFF_MULTIPLIER;
        self.current_backoff_ms = @min(new_backoff, MAX_BACKOFF_MS);
    }
};

// =============================================================================
// JSON Parsing Helpers
// =============================================================================

/// Parse a watch event from JSON line.
/// K8s watch events are newline-delimited JSON with "type" and "object" fields.
///
/// Example:
/// {"type":"ADDED","object":{"kind":"Gateway","metadata":{"name":"my-gw",...}}}
pub fn parseEvent(line: []const u8) WatcherError!WatchEvent {
    assert(line.len > 0); // S1: precondition

    // Find "type" field.
    const type_value = extractJsonString(line, "type") orelse return WatcherError.MissingField;
    const event_type = EventType.fromString(type_value) orelse return WatcherError.UnknownEventType;

    // Find "object" field - this is the raw K8s object.
    const object_start = findObjectField(line, "object") orelse return WatcherError.MissingField;

    return WatchEvent{
        .event_type = event_type,
        .raw_object = object_start,
    };
}

/// Extract resource metadata from K8s object JSON.
/// Looks for metadata.name, metadata.namespace, metadata.resourceVersion.
pub fn extractResourceMeta(json: []const u8) WatcherError!ResourceMeta {
    assert(json.len > 0); // S1: precondition

    // Find metadata section.
    const metadata_start = findObjectField(json, "metadata") orelse return WatcherError.MissingField;

    // Extract fields from metadata.
    const name = extractJsonString(metadata_start, "name") orelse return WatcherError.MissingField;
    const namespace = extractJsonString(metadata_start, "namespace") orelse "default";
    const resource_version = extractJsonString(metadata_start, "resourceVersion") orelse "";

    return ResourceMeta{
        .name = name,
        .namespace = namespace,
        .resource_version = resource_version,
    };
}

/// Extract a string value from JSON by field name.
/// Only matches fields at the top level of the JSON object (depth 1).
/// Returns null if field not found at top level.
fn extractJsonString(json: []const u8, field_name: []const u8) ?[]const u8 {
    // Build search pattern: "fieldName":"
    var pattern_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":\"", .{field_name}) catch return null;

    // Scan through JSON tracking brace depth to find pattern at top level only.
    // Top-level fields are at depth 1 (inside the outermost object).
    var depth: u32 = 0;
    var pos: usize = 0;
    var iteration: u32 = 0;
    const max_iterations: u32 = 65536; // TigerStyle: bounded loop

    while (pos < json.len and iteration < max_iterations) : ({
        pos += 1;
        iteration += 1;
    }) {
        const c = json[pos];

        // Track brace depth (ignore braces inside strings for simplicity;
        // this works for well-formed JSON with string fields).
        if (c == '{') {
            depth += 1;
        } else if (c == '}') {
            if (depth > 0) depth -= 1;
        }

        // Only match pattern when at depth 1 (top-level fields).
        if (depth == 1 and pos + pattern.len <= json.len) {
            if (std.mem.eql(u8, json[pos .. pos + pattern.len], pattern)) {
                const value_start = pos + pattern.len;

                // Find closing quote (handle escaped quotes).
                var end_pos: usize = value_start;
                var inner_iteration: u32 = 0;
                const max_inner_iterations: u32 = 4096; // TigerStyle: bounded loop

                while (end_pos < json.len and inner_iteration < max_inner_iterations) : ({
                    end_pos += 1;
                    inner_iteration += 1;
                }) {
                    if (json[end_pos] == '"' and (end_pos == value_start or json[end_pos - 1] != '\\')) {
                        return json[value_start..end_pos];
                    }
                }

                return null;
            }
        }
    }

    return null;
}

/// Find the start of a JSON object field.
/// Returns slice starting at the opening brace of the object value.
fn findObjectField(json: []const u8, field_name: []const u8) ?[]const u8 {
    // Build search pattern: "fieldName":{
    var pattern_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":{{", .{field_name}) catch return null;

    // Find pattern in JSON.
    const pattern_start = std.mem.indexOf(u8, json, pattern) orelse return null;
    const object_start = pattern_start + pattern.len - 1; // Include opening brace.

    // Find matching closing brace.
    var depth: u32 = 0;
    var pos: usize = object_start;
    var iteration: u32 = 0;
    const max_iterations: u32 = 65536; // TigerStyle: bounded loop

    while (pos < json.len and iteration < max_iterations) : ({
        pos += 1;
        iteration += 1;
    }) {
        const c = json[pos];
        if (c == '{') {
            depth += 1;
        } else if (c == '}') {
            if (depth == 1) {
                return json[object_start .. pos + 1];
            }
            depth -= 1;
        }
    }

    return null;
}

/// Find the start of a JSON array field.
/// Returns slice starting at the opening bracket of the array value.
fn findArrayField(json: []const u8, field_name: []const u8) ?[]const u8 {
    // Build search pattern: "fieldName":[
    var pattern_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":[", .{field_name}) catch return null;

    // Find pattern in JSON.
    const pattern_start = std.mem.indexOf(u8, json, pattern) orelse return null;
    const array_start = pattern_start + pattern.len - 1; // Include opening bracket.

    // Find matching closing bracket.
    var depth: u32 = 0;
    var pos: usize = array_start;
    var iteration: u32 = 0;
    const max_iterations: u32 = 65536; // TigerStyle: bounded loop

    while (pos < json.len and iteration < max_iterations) : ({
        pos += 1;
        iteration += 1;
    }) {
        const c = json[pos];
        if (c == '[') {
            depth += 1;
        } else if (c == ']') {
            if (depth == 1) {
                return json[array_start .. pos + 1];
            }
            depth -= 1;
        }
    }

    return null;
}

/// Extract an integer value from JSON by field name.
/// Returns null if field not found or not a valid integer.
fn extractJsonInt(json: []const u8, field_name: []const u8) ?u16 {
    // Build search pattern: "fieldName":
    var pattern_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":", .{field_name}) catch return null;

    // Scan through JSON tracking brace depth to find pattern at top level only.
    var depth: u32 = 0;
    var pos: usize = 0;
    var iteration: u32 = 0;
    const max_iterations: u32 = 65536; // TigerStyle: bounded loop

    while (pos < json.len and iteration < max_iterations) : ({
        pos += 1;
        iteration += 1;
    }) {
        const c = json[pos];

        if (c == '{') {
            depth += 1;
        } else if (c == '}') {
            if (depth > 0) depth -= 1;
        }

        // Only match pattern when at depth 1 (top-level fields).
        if (depth == 1 and pos + pattern.len <= json.len) {
            if (std.mem.eql(u8, json[pos .. pos + pattern.len], pattern)) {
                const value_start = pos + pattern.len;

                // Find end of number (next comma, brace, or bracket).
                var end_pos: usize = value_start;
                var inner_iteration: u32 = 0;
                const max_inner_iterations: u32 = 32; // TigerStyle: bounded loop

                while (end_pos < json.len and inner_iteration < max_inner_iterations) : ({
                    end_pos += 1;
                    inner_iteration += 1;
                }) {
                    const end_c = json[end_pos];
                    if (end_c == ',' or end_c == '}' or end_c == ']' or end_c == ' ') {
                        const num_str = json[value_start..end_pos];
                        return std.fmt.parseInt(u16, num_str, 10) catch return null;
                    }
                }

                return null;
            }
        }
    }

    return null;
}

/// Iterate over objects in a JSON array.
/// Calls callback for each object, stopping early on error.
/// Returns the number of objects found (bounded by max_count).
fn iterateJsonArray(
    array_json: []const u8,
    comptime max_count: u8,
    callback: anytype,
    callback_arg: anytype,
) WatcherError!u8 {
    assert(array_json.len >= 2); // S1: at least "[]"
    assert(array_json[0] == '['); // S1: starts with bracket

    var count: u8 = 0;
    var pos: usize = 1; // Skip opening bracket.
    var iteration: u32 = 0;

    while (pos < array_json.len and iteration < MAX_JSON_ARRAY_ITERATIONS) : (iteration += 1) {
        // Skip whitespace and commas.
        while (pos < array_json.len and (array_json[pos] == ' ' or
            array_json[pos] == ',' or
            array_json[pos] == '\n' or
            array_json[pos] == '\r' or
            array_json[pos] == '\t'))
        {
            pos += 1;
        }

        if (pos >= array_json.len or array_json[pos] == ']') break;

        if (count >= max_count) {
            return WatcherError.BufferOverflow;
        }

        // Found start of object or string.
        const obj_start = pos;

        if (array_json[pos] == '{') {
            // Find matching closing brace.
            var depth: u32 = 0;
            var inner_iteration: u32 = 0;
            while (pos < array_json.len and inner_iteration < MAX_JSON_ARRAY_ITERATIONS) : ({
                pos += 1;
                inner_iteration += 1;
            }) {
                const c = array_json[pos];
                if (c == '{') {
                    depth += 1;
                } else if (c == '}') {
                    depth -= 1;
                    if (depth == 0) {
                        pos += 1;
                        break;
                    }
                }
            }
        } else if (array_json[pos] == '"') {
            // String value - find closing quote.
            pos += 1; // Skip opening quote.
            var inner_iteration: u32 = 0;
            while (pos < array_json.len and inner_iteration < MAX_JSON_ARRAY_ITERATIONS) : ({
                pos += 1;
                inner_iteration += 1;
            }) {
                if (array_json[pos] == '"' and array_json[pos - 1] != '\\') {
                    pos += 1;
                    break;
                }
            }
        } else {
            // Primitive value - skip to next delimiter.
            while (pos < array_json.len and array_json[pos] != ',' and array_json[pos] != ']') {
                pos += 1;
            }
        }

        const obj_end = pos;
        const object_json = array_json[obj_start..obj_end];

        // Call callback with the object.
        try callback(callback_arg, object_json, count);
        count += 1;
    }

    return count;
}

// =============================================================================
// Gateway JSON Parsing
// =============================================================================

/// Parse a Gateway resource from raw K8s JSON into StoredGateway.
///
/// Expected JSON structure:
/// ```json
/// {
///   "metadata": {"name": "my-gw", "namespace": "default"},
///   "spec": {
///     "listeners": [
///       {"name": "http", "port": 80, "protocol": "HTTP", "hostname": "*.example.com"}
///     ]
///   }
/// }
/// ```
///
/// TigerStyle: Bounded parsing, explicit error handling, no allocation.
pub fn parseGatewayJson(json: []const u8, out: *StoredGateway) WatcherError!void {
    assert(json.len > 0); // S1: precondition

    // Reset output.
    out.* = StoredGateway.init();

    // Parse metadata.
    const metadata = findObjectField(json, "metadata") orelse return WatcherError.MissingField;
    const name = extractJsonString(metadata, "name") orelse return WatcherError.MissingField;
    const namespace = extractJsonString(metadata, "namespace") orelse "default";

    if (name.len > MAX_NAME_LEN or namespace.len > MAX_NAME_LEN) {
        return WatcherError.InvalidJson;
    }

    out.name.set(name);
    out.namespace.set(namespace);

    // Parse spec.listeners.
    const spec = findObjectField(json, "spec") orelse return WatcherError.MissingField;
    const listeners_array = findArrayField(spec, "listeners") orelse {
        // No listeners is valid (empty gateway).
        out.listeners_count = 0;
        return;
    };

    // Parse each listener.
    const ListenerParseContext = struct {
        out: *StoredGateway,
    };
    var ctx = ListenerParseContext{ .out = out };

    out.listeners_count = try iterateJsonArray(
        listeners_array,
        gw_config.MAX_LISTENERS,
        struct {
            fn parse(c: *ListenerParseContext, listener_json: []const u8, idx: u8) WatcherError!void {
                try parseListenerJson(listener_json, &c.out.listeners[idx]);
                c.out.listeners[idx].active = true;
            }
        }.parse,
        &ctx,
    );

    // S2: Postconditions
    assert(out.name.len > 0);
    assert(out.listeners_count <= gw_config.MAX_LISTENERS);
}

/// Parse a single Listener from JSON.
fn parseListenerJson(json: []const u8, out: *StoredListener) WatcherError!void {
    assert(json.len > 0); // S1: precondition

    out.* = StoredListener.init();

    // Extract name.
    const name = extractJsonString(json, "name") orelse return WatcherError.MissingField;
    if (name.len > MAX_NAME_LEN) return WatcherError.InvalidJson;
    out.name.set(name);

    // Extract port.
    out.port = extractJsonInt(json, "port") orelse return WatcherError.MissingField;

    // Extract protocol.
    const protocol_str = extractJsonString(json, "protocol") orelse "HTTP";
    out.protocol = gw_config.Listener.Protocol.fromString(protocol_str) orelse .HTTP;

    // Extract optional hostname.
    if (extractJsonString(json, "hostname")) |hostname| {
        if (hostname.len <= MAX_HOSTNAME_LEN) {
            out.hostname.set(hostname);
            out.has_hostname = true;
        }
    }

    out.active = true;
}

// =============================================================================
// HTTPRoute JSON Parsing
// =============================================================================

/// Parse an HTTPRoute resource from raw K8s JSON into StoredHTTPRoute.
///
/// Expected JSON structure:
/// ```json
/// {
///   "metadata": {"name": "route", "namespace": "default"},
///   "spec": {
///     "hostnames": ["api.example.com"],
///     "rules": [{
///       "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
///       "filters": [{"type": "URLRewrite", "urlRewrite": {"path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/"}}}],
///       "backendRefs": [{"name": "svc", "namespace": "default", "port": 8080}]
///     }]
///   }
/// }
/// ```
///
/// TigerStyle: Bounded parsing, explicit error handling, no allocation.
pub fn parseHTTPRouteJson(json: []const u8, out: *StoredHTTPRoute) WatcherError!void {
    assert(json.len > 0); // S1: precondition

    // Reset output.
    out.* = StoredHTTPRoute.init();

    // Parse metadata.
    const metadata = findObjectField(json, "metadata") orelse return WatcherError.MissingField;
    const name = extractJsonString(metadata, "name") orelse return WatcherError.MissingField;
    const namespace = extractJsonString(metadata, "namespace") orelse "default";

    if (name.len > MAX_NAME_LEN or namespace.len > MAX_NAME_LEN) {
        return WatcherError.InvalidJson;
    }

    out.name.set(name);
    out.namespace.set(namespace);

    // Parse spec.
    const spec = findObjectField(json, "spec") orelse return WatcherError.MissingField;

    // Parse hostnames array.
    if (findArrayField(spec, "hostnames")) |hostnames_array| {
        out.hostnames_count = try iterateJsonArray(
            hostnames_array,
            gw_config.MAX_HOSTNAMES,
            struct {
                fn parse(route: *StoredHTTPRoute, hostname_json: []const u8, idx: u8) WatcherError!void {
                    // hostname_json is a quoted string like "api.example.com"
                    if (hostname_json.len >= 2 and hostname_json[0] == '"') {
                        const hostname = hostname_json[1 .. hostname_json.len - 1];
                        if (hostname.len <= MAX_HOSTNAME_LEN) {
                            route.hostnames[idx].set(hostname);
                        }
                    }
                }
            }.parse,
            out,
        );
    }

    // Parse rules array.
    const rules_array = findArrayField(spec, "rules") orelse {
        // No rules is valid (empty route).
        out.rules_count = 0;
        return;
    };

    const RuleParseContext = struct {
        out: *StoredHTTPRoute,
    };
    var ctx = RuleParseContext{ .out = out };

    out.rules_count = try iterateJsonArray(
        rules_array,
        gw_config.MAX_RULES,
        struct {
            fn parse(c: *RuleParseContext, rule_json: []const u8, idx: u8) WatcherError!void {
                try parseRuleJson(rule_json, &c.out.rules[idx]);
                c.out.rules[idx].active = true;
            }
        }.parse,
        &ctx,
    );

    // S2: Postconditions
    assert(out.name.len > 0);
    assert(out.rules_count <= gw_config.MAX_RULES);
}

/// Parse a single HTTPRouteRule from JSON.
fn parseRuleJson(json: []const u8, out: *StoredHTTPRouteRule) WatcherError!void {
    assert(json.len > 0); // S1: precondition

    out.* = StoredHTTPRouteRule.init();

    // Parse matches array.
    if (findArrayField(json, "matches")) |matches_array| {
        const MatchParseContext = struct {
            out: *StoredHTTPRouteRule,
        };
        var ctx = MatchParseContext{ .out = out };

        out.matches_count = try iterateJsonArray(
            matches_array,
            gw_config.MAX_MATCHES,
            struct {
                fn parse(c: *MatchParseContext, match_json: []const u8, idx: u8) WatcherError!void {
                    try parseMatchJson(match_json, &c.out.matches[idx]);
                    c.out.matches[idx].active = true;
                }
            }.parse,
            &ctx,
        );
    }

    // Parse filters array.
    if (findArrayField(json, "filters")) |filters_array| {
        const FilterParseContext = struct {
            out: *StoredHTTPRouteRule,
        };
        var ctx = FilterParseContext{ .out = out };

        out.filters_count = try iterateJsonArray(
            filters_array,
            gw_config.MAX_FILTERS,
            struct {
                fn parse(c: *FilterParseContext, filter_json: []const u8, idx: u8) WatcherError!void {
                    try parseFilterJson(filter_json, &c.out.filters[idx]);
                    c.out.filters[idx].active = true;
                }
            }.parse,
            &ctx,
        );
    }

    // Parse backendRefs array.
    if (findArrayField(json, "backendRefs")) |backends_array| {
        const BackendParseContext = struct {
            out: *StoredHTTPRouteRule,
        };
        var ctx = BackendParseContext{ .out = out };

        out.backend_refs_count = try iterateJsonArray(
            backends_array,
            gw_config.MAX_BACKEND_REFS,
            struct {
                fn parse(c: *BackendParseContext, backend_json: []const u8, idx: u8) WatcherError!void {
                    try parseBackendRefJson(backend_json, &c.out.backend_refs[idx]);
                    c.out.backend_refs[idx].active = true;
                }
            }.parse,
            &ctx,
        );
    }

    out.active = true;
}

/// Parse a single HTTPRouteMatch from JSON.
fn parseMatchJson(json: []const u8, out: *StoredHTTPRouteMatch) WatcherError!void {
    out.* = StoredHTTPRouteMatch.init();

    // Parse path match.
    if (findObjectField(json, "path")) |path_json| {
        const path_type_str = extractJsonString(path_json, "type") orelse "PathPrefix";
        const path_value = extractJsonString(path_json, "value") orelse "/";

        if (path_value.len <= MAX_PATH_VALUE_LEN) {
            out.path.match_type = gw_config.PathMatch.Type.fromString(path_type_str) orelse .PathPrefix;
            out.path.value.set(path_value);
            out.path.active = true;
            out.has_path = true;
        }
    }

    out.active = true;
}

/// Parse a single HTTPRouteFilter from JSON.
fn parseFilterJson(json: []const u8, out: *StoredHTTPRouteFilter) WatcherError!void {
    out.* = StoredHTTPRouteFilter.init();

    // Get filter type.
    const filter_type_str = extractJsonString(json, "type") orelse return;
    out.filter_type = gw_config.HTTPRouteFilter.Type.fromString(filter_type_str) orelse return;

    // Parse URLRewrite filter.
    if (out.filter_type == .URLRewrite) {
        if (findObjectField(json, "urlRewrite")) |rewrite_json| {
            if (findObjectField(rewrite_json, "path")) |path_json| {
                const rewrite_type_str = extractJsonString(path_json, "type") orelse "ReplacePrefixMatch";
                // K8s uses "replacePrefixMatch" field for the value in ReplacePrefixMatch type.
                const rewrite_value = extractJsonString(path_json, "replacePrefixMatch") orelse
                    extractJsonString(path_json, "replaceFullPath") orelse "/";

                if (rewrite_value.len <= MAX_PATH_VALUE_LEN) {
                    out.url_rewrite.path.rewrite_type = gw_config.PathRewrite.Type.fromString(rewrite_type_str) orelse .ReplacePrefixMatch;
                    out.url_rewrite.path.value.set(rewrite_value);
                    out.url_rewrite.path.active = true;
                    out.url_rewrite.has_path = true;
                }
            }
        }
    }

    out.active = true;
}

/// Parse a single BackendRef from JSON.
fn parseBackendRefJson(json: []const u8, out: *StoredBackendRef) WatcherError!void {
    out.* = StoredBackendRef.init();

    // Extract name (required).
    const name = extractJsonString(json, "name") orelse return;
    if (name.len > MAX_NAME_LEN) return;
    out.name.set(name);

    // Extract namespace (defaults to route's namespace, but we use "default" here).
    const namespace = extractJsonString(json, "namespace") orelse "default";
    if (namespace.len > MAX_NAME_LEN) return;
    out.namespace.set(namespace);

    // Extract port (required).
    out.port = extractJsonInt(json, "port") orelse return;

    // Extract weight (optional, defaults to 1).
    out.weight = extractJsonInt(json, "weight") orelse 1;

    out.active = true;
}

// =============================================================================
// Unit Tests
// =============================================================================

test "EventType.fromString - valid types" {
    try std.testing.expectEqual(EventType.ADDED, EventType.fromString("ADDED").?);
    try std.testing.expectEqual(EventType.MODIFIED, EventType.fromString("MODIFIED").?);
    try std.testing.expectEqual(EventType.DELETED, EventType.fromString("DELETED").?);
    try std.testing.expectEqual(EventType.BOOKMARK, EventType.fromString("BOOKMARK").?);
    try std.testing.expectEqual(EventType.ERROR, EventType.fromString("ERROR").?);
}

test "EventType.fromString - invalid types" {
    try std.testing.expect(EventType.fromString("UNKNOWN") == null);
    try std.testing.expect(EventType.fromString("added") == null); // Case sensitive
    try std.testing.expect(EventType.fromString("") == null);
}

test "EventType.toString" {
    try std.testing.expectEqualStrings("ADDED", EventType.ADDED.toString());
    try std.testing.expectEqualStrings("MODIFIED", EventType.MODIFIED.toString());
    try std.testing.expectEqualStrings("DELETED", EventType.DELETED.toString());
    try std.testing.expectEqualStrings("BOOKMARK", EventType.BOOKMARK.toString());
    try std.testing.expectEqualStrings("ERROR", EventType.ERROR.toString());
}

test "extractJsonString - basic extraction" {
    const json =
        \\{"type":"ADDED","kind":"Gateway"}
    ;
    try std.testing.expectEqualStrings("ADDED", extractJsonString(json, "type").?);
    try std.testing.expectEqualStrings("Gateway", extractJsonString(json, "kind").?);
}

test "extractJsonString - nested JSON" {
    const json =
        \\{"metadata":{"name":"my-gateway","namespace":"default"}}
    ;
    // Direct extraction from top-level won't find nested fields.
    try std.testing.expect(extractJsonString(json, "name") == null);

    // Find metadata section first.
    const metadata = findObjectField(json, "metadata").?;
    try std.testing.expectEqualStrings("my-gateway", extractJsonString(metadata, "name").?);
    try std.testing.expectEqualStrings("default", extractJsonString(metadata, "namespace").?);
}

test "extractJsonString - missing field" {
    const json =
        \\{"type":"ADDED"}
    ;
    try std.testing.expect(extractJsonString(json, "missing") == null);
}

test "extractJsonString - empty value" {
    const json =
        \\{"type":"","name":"test"}
    ;
    try std.testing.expectEqualStrings("", extractJsonString(json, "type").?);
    try std.testing.expectEqualStrings("test", extractJsonString(json, "name").?);
}

test "findObjectField - basic" {
    const json =
        \\{"metadata":{"name":"gw","namespace":"ns"}}
    ;
    const metadata = findObjectField(json, "metadata").?;
    try std.testing.expect(std.mem.startsWith(u8, metadata, "{"));
    try std.testing.expect(std.mem.endsWith(u8, metadata, "}"));
    try std.testing.expect(std.mem.indexOf(u8, metadata, "name") != null);
}

test "findObjectField - nested objects" {
    const json =
        \\{"spec":{"inner":{"deep":"value"},"other":"x"}}
    ;
    const spec = findObjectField(json, "spec").?;
    try std.testing.expect(std.mem.indexOf(u8, spec, "inner") != null);
    try std.testing.expect(std.mem.indexOf(u8, spec, "other") != null);
}

test "findObjectField - missing field" {
    const json =
        \\{"type":"ADDED"}
    ;
    try std.testing.expect(findObjectField(json, "missing") == null);
}

test "parseEvent - ADDED event" {
    const line =
        \\{"type":"ADDED","object":{"kind":"Gateway","metadata":{"name":"my-gw","namespace":"default","resourceVersion":"12345"}}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.ADDED, event.event_type);
    try std.testing.expect(std.mem.indexOf(u8, event.raw_object, "Gateway") != null);
}

test "parseEvent - MODIFIED event" {
    const line =
        \\{"type":"MODIFIED","object":{"kind":"HTTPRoute","metadata":{"name":"route1","namespace":"prod"}}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.MODIFIED, event.event_type);
    try std.testing.expect(std.mem.indexOf(u8, event.raw_object, "HTTPRoute") != null);
}

test "parseEvent - DELETED event" {
    const line =
        \\{"type":"DELETED","object":{"metadata":{"name":"old-gw","namespace":"default"}}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.DELETED, event.event_type);
}

test "parseEvent - BOOKMARK event" {
    const line =
        \\{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"99999"}}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.BOOKMARK, event.event_type);
}

test "parseEvent - ERROR event" {
    const line =
        \\{"type":"ERROR","object":{"message":"watch error","code":410}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.ERROR, event.event_type);
}

test "parseEvent - missing type field" {
    const line =
        \\{"object":{"metadata":{"name":"gw"}}}
    ;
    const result = parseEvent(line);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseEvent - unknown type" {
    const line =
        \\{"type":"UNKNOWN","object":{}}
    ;
    const result = parseEvent(line);
    try std.testing.expectError(WatcherError.UnknownEventType, result);
}

test "parseEvent - missing object field" {
    const line =
        \\{"type":"ADDED"}
    ;
    const result = parseEvent(line);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "extractResourceMeta - full metadata" {
    const json =
        \\{"kind":"Gateway","metadata":{"name":"my-gateway","namespace":"production","resourceVersion":"12345"}}
    ;
    const meta = try extractResourceMeta(json);
    try std.testing.expectEqualStrings("my-gateway", meta.name);
    try std.testing.expectEqualStrings("production", meta.namespace);
    try std.testing.expectEqualStrings("12345", meta.resource_version);
}

test "extractResourceMeta - default namespace" {
    const json =
        \\{"metadata":{"name":"cluster-resource","resourceVersion":"999"}}
    ;
    // Namespace defaults to "default" when not present.
    const meta = try extractResourceMeta(json);
    try std.testing.expectEqualStrings("cluster-resource", meta.name);
    try std.testing.expectEqualStrings("default", meta.namespace);
}

test "extractResourceMeta - missing name" {
    const json =
        \\{"metadata":{"namespace":"ns"}}
    ;
    const result = extractResourceMeta(json);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "extractResourceMeta - missing metadata" {
    const json =
        \\{"kind":"Gateway","spec":{}}
    ;
    const result = extractResourceMeta(json);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "ResourceStore - init" {
    const store = ResourceStore(16).init();
    try std.testing.expectEqual(@as(u32, 0), store.count);
    try std.testing.expectEqual(@as(usize, 0), store.getLatestResourceVersion().len);
}

test "ResourceStore - upsert and getActive" {
    var store = ResourceStore(16).init();

    // Add first resource.
    try store.upsert(.{
        .name = "gateway1",
        .namespace = "default",
        .resource_version = "100",
    }, "{}");
    try std.testing.expectEqual(@as(u32, 1), store.count);

    // Add second resource.
    try store.upsert(.{
        .name = "gateway2",
        .namespace = "default",
        .resource_version = "101",
    }, "{}");
    try std.testing.expectEqual(@as(u32, 2), store.count);

    // Update first resource (upsert).
    try store.upsert(.{
        .name = "gateway1",
        .namespace = "default",
        .resource_version = "102",
    }, "{\"updated\":true}");
    try std.testing.expectEqual(@as(u32, 2), store.count);

    // Verify latest resource version.
    try std.testing.expectEqualStrings("102", store.getLatestResourceVersion());
}

test "ResourceStore - remove" {
    var store = ResourceStore(16).init();

    // Add resources.
    try store.upsert(.{ .name = "gw1", .namespace = "ns1", .resource_version = "1" }, "{}");
    try store.upsert(.{ .name = "gw2", .namespace = "ns1", .resource_version = "2" }, "{}");
    try std.testing.expectEqual(@as(u32, 2), store.count);

    // Remove existing.
    try std.testing.expect(store.remove("gw1", "ns1"));
    try std.testing.expectEqual(@as(u32, 1), store.count);

    // Remove non-existing.
    try std.testing.expect(!store.remove("gw3", "ns1"));
    try std.testing.expectEqual(@as(u32, 1), store.count);

    // Remove with wrong namespace.
    try std.testing.expect(!store.remove("gw2", "ns2"));
    try std.testing.expectEqual(@as(u32, 1), store.count);
}

test "ResourceStore - buffer overflow" {
    var store = ResourceStore(2).init();

    // Fill store.
    try store.upsert(.{ .name = "gw1", .namespace = "ns", .resource_version = "1" }, "{}");
    try store.upsert(.{ .name = "gw2", .namespace = "ns", .resource_version = "2" }, "{}");

    // Third insert should fail.
    const result = store.upsert(.{ .name = "gw3", .namespace = "ns", .resource_version = "3" }, "{}");
    try std.testing.expectError(WatcherError.BufferOverflow, result);
}

test "ResourceStore - upsert reuses slot" {
    var store = ResourceStore(2).init();

    // Fill store.
    try store.upsert(.{ .name = "gw1", .namespace = "ns", .resource_version = "1" }, "{}");
    try store.upsert(.{ .name = "gw2", .namespace = "ns", .resource_version = "2" }, "{}");

    // Upsert existing should succeed (reuses slot).
    try store.upsert(.{ .name = "gw1", .namespace = "ns", .resource_version = "3" }, "{\"v\":3}");
    try std.testing.expectEqual(@as(u32, 2), store.count);
}

test "backoff calculation" {
    // Test the backoff multiplier calculation.
    var backoff: u32 = INITIAL_BACKOFF_MS;

    // First backoff: 1000ms
    try std.testing.expectEqual(@as(u32, 1000), backoff);

    // Second backoff: 2000ms
    backoff = @min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);
    try std.testing.expectEqual(@as(u32, 2000), backoff);

    // Third backoff: 4000ms
    backoff = @min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);
    try std.testing.expectEqual(@as(u32, 4000), backoff);

    // Eventually caps at MAX_BACKOFF_MS.
    var iteration: u32 = 0;
    while (iteration < 10) : (iteration += 1) {
        backoff = @min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);
    }
    try std.testing.expectEqual(MAX_BACKOFF_MS, backoff);
}

test "constants are sensible" {
    // Verify constants are within expected ranges.
    try std.testing.expect(MAX_LINE_SIZE_BYTES >= 16 * 1024); // At least 16KB
    try std.testing.expect(MAX_LINE_SIZE_BYTES <= 256 * 1024); // Not more than 256KB
    try std.testing.expect(MAX_EVENTS_PER_ITERATION >= 100);
    try std.testing.expect(MAX_RECONNECT_ATTEMPTS >= 10);
    try std.testing.expect(INITIAL_BACKOFF_MS >= 100);
    try std.testing.expect(MAX_BACKOFF_MS >= INITIAL_BACKOFF_MS);
    try std.testing.expect(BACKOFF_MULTIPLIER >= 2);
}

test "K8s API paths are correct" {
    // Verify paths match K8s Gateway API conventions.
    try std.testing.expect(std.mem.startsWith(u8, GATEWAY_CLASS_PATH, "/apis/gateway.networking.k8s.io/"));
    try std.testing.expect(std.mem.startsWith(u8, GATEWAY_PATH, "/apis/gateway.networking.k8s.io/"));
    try std.testing.expect(std.mem.startsWith(u8, HTTP_ROUTE_PATH, "/apis/gateway.networking.k8s.io/"));
    try std.testing.expect(std.mem.startsWith(u8, SERVICES_PATH, "/api/v1/"));
    try std.testing.expect(std.mem.startsWith(u8, ENDPOINTS_PATH, "/api/v1/"));
    try std.testing.expect(std.mem.startsWith(u8, SECRETS_PATH, "/api/v1/"));
}

// =============================================================================
// Gateway/HTTPRoute Parsing Tests
// =============================================================================

test "findArrayField - basic array" {
    const json =
        \\{"items":["a","b","c"]}
    ;
    const array = findArrayField(json, "items").?;
    try std.testing.expect(std.mem.startsWith(u8, array, "["));
    try std.testing.expect(std.mem.endsWith(u8, array, "]"));
    try std.testing.expect(std.mem.indexOf(u8, array, "\"a\"") != null);
}

test "findArrayField - nested arrays" {
    const json =
        \\{"outer":{"inner":[1,2,3]}}
    ;
    const outer = findObjectField(json, "outer").?;
    const inner = findArrayField(outer, "inner").?;
    try std.testing.expect(std.mem.startsWith(u8, inner, "["));
    try std.testing.expect(std.mem.indexOf(u8, inner, "1") != null);
}

test "findArrayField - missing field" {
    const json =
        \\{"other":"value"}
    ;
    try std.testing.expect(findArrayField(json, "missing") == null);
}

test "extractJsonInt - basic" {
    const json =
        \\{"port":8080,"count":42}
    ;
    try std.testing.expectEqual(@as(u16, 8080), extractJsonInt(json, "port").?);
    try std.testing.expectEqual(@as(u16, 42), extractJsonInt(json, "count").?);
}

test "extractJsonInt - nested" {
    const json =
        \\{"metadata":{"port":9090}}
    ;
    // Top-level extraction should not find nested fields.
    try std.testing.expect(extractJsonInt(json, "port") == null);

    // Extract from nested object.
    const metadata = findObjectField(json, "metadata").?;
    try std.testing.expectEqual(@as(u16, 9090), extractJsonInt(metadata, "port").?);
}

test "extractJsonInt - missing field" {
    const json =
        \\{"name":"test"}
    ;
    try std.testing.expect(extractJsonInt(json, "port") == null);
}

test "iterateJsonArray - object array" {
    const json = "[{\"name\":\"a\"},{\"name\":\"b\"}]";
    var names: [2][]const u8 = undefined;
    var count: u8 = 0;

    const ArrayContext = struct {
        names: *[2][]const u8,
        count: *u8,
    };
    var ctx = ArrayContext{ .names = &names, .count = &count };

    _ = try iterateJsonArray(
        json,
        2,
        struct {
            fn parse(c: *ArrayContext, obj: []const u8, idx: u8) WatcherError!void {
                c.names[idx] = extractJsonString(obj, "name") orelse "?";
                c.count.* = idx + 1;
            }
        }.parse,
        &ctx,
    );

    try std.testing.expectEqual(@as(u8, 2), count);
    try std.testing.expectEqualStrings("a", names[0]);
    try std.testing.expectEqualStrings("b", names[1]);
}

test "iterateJsonArray - string array" {
    const json = "[\"api.example.com\",\"www.example.com\"]";
    var hostnames: [2][]const u8 = undefined;
    var count: u8 = 0;

    const ArrayContext = struct {
        hostnames: *[2][]const u8,
        count: *u8,
    };
    var ctx = ArrayContext{ .hostnames = &hostnames, .count = &count };

    _ = try iterateJsonArray(
        json,
        2,
        struct {
            fn parse(c: *ArrayContext, item: []const u8, idx: u8) WatcherError!void {
                if (item.len >= 2 and item[0] == '"') {
                    c.hostnames[idx] = item[1 .. item.len - 1];
                }
                c.count.* = idx + 1;
            }
        }.parse,
        &ctx,
    );

    try std.testing.expectEqual(@as(u8, 2), count);
    try std.testing.expectEqualStrings("api.example.com", hostnames[0]);
    try std.testing.expectEqualStrings("www.example.com", hostnames[1]);
}

test "iterateJsonArray - empty array" {
    const json = "[]";
    var count: u8 = 0;

    _ = try iterateJsonArray(
        json,
        10,
        struct {
            fn parse(cnt: *u8, _: []const u8, _: u8) WatcherError!void {
                cnt.* += 1;
            }
        }.parse,
        &count,
    );

    try std.testing.expectEqual(@as(u8, 0), count);
}

test "parseGatewayJson - basic gateway" {
    const json =
        \\{
        \\  "metadata": {"name": "my-gateway", "namespace": "production"},
        \\  "spec": {
        \\    "listeners": [
        \\      {"name": "http", "port": 80, "protocol": "HTTP"},
        \\      {"name": "https", "port": 443, "protocol": "HTTPS", "hostname": "*.example.com"}
        \\    ]
        \\  }
        \\}
    ;

    var gw = StoredGateway.init();
    try parseGatewayJson(json, &gw);

    try std.testing.expectEqualStrings("my-gateway", gw.name.slice());
    try std.testing.expectEqualStrings("production", gw.namespace.slice());
    try std.testing.expectEqual(@as(u8, 2), gw.listeners_count);

    // Check first listener
    try std.testing.expectEqualStrings("http", gw.listeners[0].name.slice());
    try std.testing.expectEqual(@as(u16, 80), gw.listeners[0].port);
    try std.testing.expectEqual(gw_config.Listener.Protocol.HTTP, gw.listeners[0].protocol);
    try std.testing.expect(!gw.listeners[0].has_hostname);

    // Check second listener
    try std.testing.expectEqualStrings("https", gw.listeners[1].name.slice());
    try std.testing.expectEqual(@as(u16, 443), gw.listeners[1].port);
    try std.testing.expectEqual(gw_config.Listener.Protocol.HTTPS, gw.listeners[1].protocol);
    try std.testing.expect(gw.listeners[1].has_hostname);
    try std.testing.expectEqualStrings("*.example.com", gw.listeners[1].hostname.slice());
}

test "parseGatewayJson - no listeners" {
    const json =
        \\{
        \\  "metadata": {"name": "empty-gw", "namespace": "default"},
        \\  "spec": {}
        \\}
    ;

    var gw = StoredGateway.init();
    try parseGatewayJson(json, &gw);

    try std.testing.expectEqualStrings("empty-gw", gw.name.slice());
    try std.testing.expectEqual(@as(u8, 0), gw.listeners_count);
}

test "parseGatewayJson - default namespace" {
    const json =
        \\{
        \\  "metadata": {"name": "gw"},
        \\  "spec": {"listeners": []}
        \\}
    ;

    var gw = StoredGateway.init();
    try parseGatewayJson(json, &gw);

    try std.testing.expectEqualStrings("gw", gw.name.slice());
    try std.testing.expectEqualStrings("default", gw.namespace.slice());
}

test "parseGatewayJson - missing metadata" {
    const json =
        \\{
        \\  "spec": {"listeners": []}
        \\}
    ;

    var gw = StoredGateway.init();
    const result = parseGatewayJson(json, &gw);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseGatewayJson - missing name" {
    const json =
        \\{
        \\  "metadata": {"namespace": "default"},
        \\  "spec": {"listeners": []}
        \\}
    ;

    var gw = StoredGateway.init();
    const result = parseGatewayJson(json, &gw);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseHTTPRouteJson - full route" {
    const json =
        \\{
        \\  "metadata": {"name": "api-route", "namespace": "prod"},
        \\  "spec": {
        \\    "hostnames": ["api.example.com", "www.example.com"],
        \\    "rules": [
        \\      {
        \\        "matches": [
        \\          {"path": {"type": "PathPrefix", "value": "/api/"}}
        \\        ],
        \\        "filters": [
        \\          {"type": "URLRewrite", "urlRewrite": {"path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/"}}}
        \\        ],
        \\        "backendRefs": [
        \\          {"name": "api-svc", "namespace": "prod", "port": 8080, "weight": 90},
        \\          {"name": "api-svc-canary", "port": 8080, "weight": 10}
        \\        ]
        \\      }
        \\    ]
        \\  }
        \\}
    ;

    var route = StoredHTTPRoute.init();
    try parseHTTPRouteJson(json, &route);

    // Check metadata
    try std.testing.expectEqualStrings("api-route", route.name.slice());
    try std.testing.expectEqualStrings("prod", route.namespace.slice());

    // Check hostnames
    try std.testing.expectEqual(@as(u8, 2), route.hostnames_count);
    try std.testing.expectEqualStrings("api.example.com", route.hostnames[0].slice());
    try std.testing.expectEqualStrings("www.example.com", route.hostnames[1].slice());

    // Check rules
    try std.testing.expectEqual(@as(u8, 1), route.rules_count);

    const rule = &route.rules[0];

    // Check matches
    try std.testing.expectEqual(@as(u8, 1), rule.matches_count);
    try std.testing.expect(rule.matches[0].has_path);
    try std.testing.expectEqual(gw_config.PathMatch.Type.PathPrefix, rule.matches[0].path.match_type);
    try std.testing.expectEqualStrings("/api/", rule.matches[0].path.value.slice());

    // Check filters
    try std.testing.expectEqual(@as(u8, 1), rule.filters_count);
    try std.testing.expectEqual(gw_config.HTTPRouteFilter.Type.URLRewrite, rule.filters[0].filter_type);
    try std.testing.expect(rule.filters[0].url_rewrite.has_path);
    try std.testing.expectEqual(gw_config.PathRewrite.Type.ReplacePrefixMatch, rule.filters[0].url_rewrite.path.rewrite_type);
    try std.testing.expectEqualStrings("/", rule.filters[0].url_rewrite.path.value.slice());

    // Check backend refs
    try std.testing.expectEqual(@as(u8, 2), rule.backend_refs_count);
    try std.testing.expectEqualStrings("api-svc", rule.backend_refs[0].name.slice());
    try std.testing.expectEqualStrings("prod", rule.backend_refs[0].namespace.slice());
    try std.testing.expectEqual(@as(u16, 8080), rule.backend_refs[0].port);
    try std.testing.expectEqual(@as(u16, 90), rule.backend_refs[0].weight);

    try std.testing.expectEqualStrings("api-svc-canary", rule.backend_refs[1].name.slice());
    try std.testing.expectEqualStrings("default", rule.backend_refs[1].namespace.slice()); // defaults
    try std.testing.expectEqual(@as(u16, 10), rule.backend_refs[1].weight);
}

test "parseHTTPRouteJson - minimal route" {
    const json =
        \\{
        \\  "metadata": {"name": "minimal"},
        \\  "spec": {}
        \\}
    ;

    var route = StoredHTTPRoute.init();
    try parseHTTPRouteJson(json, &route);

    try std.testing.expectEqualStrings("minimal", route.name.slice());
    try std.testing.expectEqualStrings("default", route.namespace.slice());
    try std.testing.expectEqual(@as(u8, 0), route.hostnames_count);
    try std.testing.expectEqual(@as(u8, 0), route.rules_count);
}

test "parseHTTPRouteJson - exact path match" {
    const json =
        \\{
        \\  "metadata": {"name": "exact-route", "namespace": "default"},
        \\  "spec": {
        \\    "rules": [
        \\      {
        \\        "matches": [
        \\          {"path": {"type": "Exact", "value": "/health"}}
        \\        ],
        \\        "backendRefs": [
        \\          {"name": "health-svc", "port": 8080}
        \\        ]
        \\      }
        \\    ]
        \\  }
        \\}
    ;

    var route = StoredHTTPRoute.init();
    try parseHTTPRouteJson(json, &route);

    try std.testing.expectEqual(@as(u8, 1), route.rules_count);
    const match = &route.rules[0].matches[0];
    try std.testing.expectEqual(gw_config.PathMatch.Type.Exact, match.path.match_type);
    try std.testing.expectEqualStrings("/health", match.path.value.slice());
}

test "parseHTTPRouteJson - missing spec" {
    const json =
        \\{
        \\  "metadata": {"name": "no-spec"}
        \\}
    ;

    var route = StoredHTTPRoute.init();
    const result = parseHTTPRouteJson(json, &route);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseBackendRefJson - full backend" {
    const json =
        \\{"name": "my-svc", "namespace": "ns", "port": 9000, "weight": 50}
    ;

    var backend = StoredBackendRef.init();
    try parseBackendRefJson(json, &backend);

    try std.testing.expectEqualStrings("my-svc", backend.name.slice());
    try std.testing.expectEqualStrings("ns", backend.namespace.slice());
    try std.testing.expectEqual(@as(u16, 9000), backend.port);
    try std.testing.expectEqual(@as(u16, 50), backend.weight);
    try std.testing.expect(backend.active);
}

test "parseBackendRefJson - defaults" {
    const json =
        \\{"name": "svc", "port": 8080}
    ;

    var backend = StoredBackendRef.init();
    try parseBackendRefJson(json, &backend);

    try std.testing.expectEqualStrings("default", backend.namespace.slice());
    try std.testing.expectEqual(@as(u16, 1), backend.weight);
}

test "parseFilterJson - URLRewrite with ReplaceFullPath" {
    const json =
        \\{"type": "URLRewrite", "urlRewrite": {"path": {"type": "ReplaceFullPath", "replaceFullPath": "/new/path"}}}
    ;

    var filter = StoredHTTPRouteFilter.init();
    try parseFilterJson(json, &filter);

    try std.testing.expectEqual(gw_config.HTTPRouteFilter.Type.URLRewrite, filter.filter_type);
    try std.testing.expect(filter.url_rewrite.has_path);
    try std.testing.expectEqual(gw_config.PathRewrite.Type.ReplaceFullPath, filter.url_rewrite.path.rewrite_type);
    try std.testing.expectEqualStrings("/new/path", filter.url_rewrite.path.value.slice());
}

test "NameStorage - basic operations" {
    var storage = NameStorage.init();
    try std.testing.expectEqual(@as(u8, 0), storage.len);

    storage.set("test-name");
    try std.testing.expectEqual(@as(u8, 9), storage.len);
    try std.testing.expectEqualStrings("test-name", storage.slice());

    storage.set("another");
    try std.testing.expectEqualStrings("another", storage.slice());
}

test "PathStorage - basic operations" {
    var storage = PathStorage.init();
    try std.testing.expectEqual(@as(u16, 0), storage.len);

    storage.set("/api/v1/users");
    try std.testing.expectEqualStrings("/api/v1/users", storage.slice());
}

test "StoredPathMatch - toPathMatch" {
    var stored = StoredPathMatch.init();
    stored.match_type = .Exact;
    stored.value.set("/exact/path");
    stored.active = true;

    const path_match = stored.toPathMatch();
    try std.testing.expectEqual(gw_config.PathMatch.Type.Exact, path_match.type);
    try std.testing.expectEqualStrings("/exact/path", path_match.value);
}

test "StoredHTTPRouteRule init" {
    const rule = StoredHTTPRouteRule.init();
    try std.testing.expectEqual(@as(u8, 0), rule.matches_count);
    try std.testing.expectEqual(@as(u8, 0), rule.filters_count);
    try std.testing.expectEqual(@as(u8, 0), rule.backend_refs_count);
    try std.testing.expect(!rule.active);
}

test "StoredGateway init" {
    const gw = StoredGateway.init();
    try std.testing.expectEqual(@as(u8, 0), gw.name.len);
    try std.testing.expectEqual(@as(u8, 0), gw.listeners_count);
    try std.testing.expect(!gw.active);
}

test "StoredHTTPRoute init" {
    const route = StoredHTTPRoute.init();
    try std.testing.expectEqual(@as(u8, 0), route.name.len);
    try std.testing.expectEqual(@as(u8, 0), route.hostnames_count);
    try std.testing.expectEqual(@as(u8, 0), route.rules_count);
    try std.testing.expect(!route.active);
}
