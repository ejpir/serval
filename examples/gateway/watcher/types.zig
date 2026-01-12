//! Kubernetes Resource Watcher Types
//!
//! Type definitions for the Kubernetes resource watcher.
//! Contains constants, error types, event types, and storage structs.
//!
//! TigerStyle: Explicit types, bounded storage, no allocation after init.

const std = @import("std");
const log = @import("serval-core").log.scoped(.gateway_watcher);
const assert = std.debug.assert;

const gateway = @import("serval-k8s-gateway");
const gw_config = gateway.config;

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
pub const MAX_SECRETS: u32 = 16; // Reduced: 16 × 1MB = 16MB for TLS certs

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

/// Maximum size of raw JSON to store per resource.
/// Secrets with TLS certs can be 500KB+.
/// TigerStyle: Explicit bound for heap-allocated storage.
pub const MAX_RAW_JSON_LEN: u32 = 1024 * 1024;

/// Tracked resource with metadata and raw JSON.
/// Raw JSON buffer is heap-allocated to avoid stack overflow.
/// TigerStyle: Heap allocation at init, no allocation after init.
pub const TrackedResource = struct {
    /// Resource name - stored in fixed buffer (not a slice into temp memory).
    name: NameStorage,
    /// Resource namespace - stored in fixed buffer.
    namespace: NameStorage,
    /// Resource version - stored in fixed buffer.
    resource_version: NameStorage,
    /// Heap-allocated buffer for raw JSON.
    raw_json_buf: ?[]u8,
    raw_json_len: u32,
    /// Indicates if this slot is in use.
    active: bool,

    /// Get metadata as ResourceMeta (slices into our storage).
    pub fn meta(self: *const TrackedResource) ResourceMeta {
        return .{
            .name = self.name.slice(),
            .namespace = self.namespace.slice(),
            .resource_version = self.resource_version.slice(),
        };
    }

    /// Set metadata by copying into our storage.
    pub fn setMeta(self: *TrackedResource, m: ResourceMeta) void {
        self.name.set(m.name);
        self.namespace.set(m.namespace);
        self.resource_version.set(m.resource_version);
    }

    /// Get the raw JSON as a slice.
    pub fn rawJson(self: *const TrackedResource) []const u8 {
        if (self.raw_json_buf) |buf| {
            return buf[0..self.raw_json_len];
        }
        return "";
    }

    /// Set the raw JSON by copying from source.
    /// Truncates if source exceeds buffer size.
    pub fn setRawJson(self: *TrackedResource, source: []const u8) void {
        if (self.raw_json_buf) |buf| {
            const copy_len = @min(source.len, buf.len);
            @memcpy(buf[0..copy_len], source[0..copy_len]);
            self.raw_json_len = @intCast(copy_len);
        }
    }
};

/// Storage for tracked resources of a single type.
/// Raw JSON buffers are heap-allocated at init to avoid stack overflow.
/// TigerStyle: Fixed-size array with bounded capacity, heap buffers.
pub fn ResourceStore(comptime capacity: u32, comptime buffer_size: u32) type {
    return struct {
        const Self = @This();

        /// Fixed-size storage for resources.
        items: [capacity]TrackedResource,
        /// Number of active items.
        count: u32,
        /// Latest resource version seen (for watch resumption).
        latest_resource_version: [64]u8,
        latest_resource_version_len: u8,
        /// Allocator used for buffer allocation.
        allocator: std.mem.Allocator,

        /// Initialize empty store with heap-allocated buffers.
        /// TigerStyle: All allocation happens at init, none after.
        pub fn init(allocator: std.mem.Allocator) WatcherError!Self {
            var self = Self{
                .items = undefined,
                .count = 0,
                .latest_resource_version = std.mem.zeroes([64]u8),
                .latest_resource_version_len = 0,
                .allocator = allocator,
            };

            // Allocate raw_json buffers for each slot.
            var allocated: u32 = 0;
            errdefer {
                // Clean up on failure.
                var cleanup: u32 = 0;
                while (cleanup < allocated) : (cleanup += 1) {
                    if (self.items[cleanup].raw_json_buf) |buf| {
                        allocator.free(buf);
                    }
                }
            }

            while (allocated < capacity) : (allocated += 1) {
                self.items[allocated].name = NameStorage.init();
                self.items[allocated].namespace = NameStorage.init();
                self.items[allocated].resource_version = NameStorage.init();
                self.items[allocated].raw_json_buf = allocator.alloc(u8, buffer_size) catch {
                    return WatcherError.OutOfMemory;
                };
                self.items[allocated].raw_json_len = 0;
                self.items[allocated].active = false;
            }

            assert(self.count == 0); // S1: postcondition - empty store
            assert(self.latest_resource_version_len == 0); // S1: postcondition - no version yet
            return self;
        }

        /// Free all heap-allocated buffers.
        /// TigerStyle: Explicit cleanup paired with init.
        pub fn deinit(self: *Self) void {
            var idx: u32 = 0;
            while (idx < capacity) : (idx += 1) {
                if (self.items[idx].raw_json_buf) |buf| {
                    self.allocator.free(buf);
                    self.items[idx].raw_json_buf = null;
                }
            }
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

            log.debug("ResourceStore.upsert: name={s} namespace={s} current_count={d}", .{
                meta.name,
                meta.namespace,
                self.count,
            });

            // Try to find existing entry with same name/namespace.
            var found_idx: ?u32 = null;
            var iteration: u32 = 0;
            while (iteration < capacity) : (iteration += 1) {
                if (self.items[iteration].active) {
                    // Compare using stored buffers (not temp slices)
                    if (std.mem.eql(u8, self.items[iteration].name.slice(), meta.name) and
                        std.mem.eql(u8, self.items[iteration].namespace.slice(), meta.namespace))
                    {
                        found_idx = iteration;
                        break;
                    }
                }
            }

            if (found_idx) |idx| {
                // Update existing entry.
                log.debug("ResourceStore.upsert: updating existing at idx={d}", .{idx});
                self.items[idx].setMeta(meta);
                self.items[idx].setRawJson(raw_json);
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
                    log.debug("ResourceStore.upsert: adding new at idx={d}", .{idx});
                    self.items[idx].setMeta(meta);
                    self.items[idx].setRawJson(raw_json);
                    self.items[idx].active = true;
                    self.count += 1;
                    log.debug("ResourceStore.upsert: new count={d}", .{self.count});
                    assert(self.count <= capacity); // S1: postcondition - count within bounds
                } else {
                    return WatcherError.BufferOverflow;
                }
            }

            // Update latest resource version.
            self.updateResourceVersion(meta.resource_version);
            assert(self.count > 0); // S1: postcondition - at least one item after upsert
        }

        /// Remove a resource by name/namespace.
        /// Returns true if resource was found and removed.
        pub fn remove(self: *Self, name: []const u8, namespace: []const u8) bool {
            assert(name.len > 0); // S1: precondition
            assert(namespace.len > 0); // S1: precondition

            var iteration: u32 = 0;
            while (iteration < capacity) : (iteration += 1) {
                if (self.items[iteration].active) {
                    // Compare using stored buffers
                    if (std.mem.eql(u8, self.items[iteration].name.slice(), name) and
                        std.mem.eql(u8, self.items[iteration].namespace.slice(), namespace))
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
            assert(buffer.len > 0); // S1: precondition - non-empty buffer

            var count: u32 = 0;
            var iteration: u32 = 0;
            while (iteration < capacity and count < buffer.len) : (iteration += 1) {
                if (self.items[iteration].active) {
                    buffer[count] = self.items[iteration];
                    count += 1;
                }
            }
            assert(count <= self.count); // S1: postcondition - returned count is valid
            return buffer[0..count];
        }

        /// Get the latest resource version for watch resumption.
        pub fn getLatestResourceVersion(self: *const Self) []const u8 {
            return self.latest_resource_version[0..self.latest_resource_version_len];
        }

        /// Update the latest resource version.
        /// Public to allow Watcher to update version on BOOKMARK events.
        pub fn updateResourceVersion(self: *Self, rv: []const u8) void {
            assert(rv.len <= 64); // S1: precondition - resource version fits in buffer

            const len = @min(rv.len, self.latest_resource_version.len);
            @memcpy(self.latest_resource_version[0..len], rv[0..len]);
            self.latest_resource_version_len = @intCast(len);

            assert(self.latest_resource_version_len <= 64); // S1: postcondition - length within bounds
        }

        /// Reset resource version to empty.
        /// Called when K8s returns ERROR (410 Gone) indicating resourceVersion expired.
        /// Next watch will start fresh without resourceVersion parameter.
        pub fn resetResourceVersion(self: *Self) void {
            self.latest_resource_version_len = 0;
            assert(self.latest_resource_version_len == 0); // S1: postcondition - version cleared
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
        assert(self.active or self.value.len > 0); // S1: precondition - valid path match

        const result = gw_config.PathMatch{
            .type = self.match_type,
            .value = self.value.slice(),
        };
        assert(result.value.len <= MAX_PATH_VALUE_LEN); // S1: postcondition - value within bounds
        return result;
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
        assert(self.active or self.value.len > 0); // S1: precondition - valid path rewrite

        const result = gw_config.PathRewrite{
            .type = self.rewrite_type,
            .value = self.value.slice(),
        };
        assert(result.value.len <= MAX_PATH_VALUE_LEN); // S1: postcondition - value within bounds
        return result;
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

        assert(rule.matches_count == 0); // S1: postcondition - empty rule
        assert(rule.filters_count == 0); // S1: postcondition - no filters
        assert(rule.backend_refs_count == 0); // S1: postcondition - no backends
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

        assert(route.hostnames_count == 0); // S1: postcondition - no hostnames
        assert(route.rules_count == 0); // S1: postcondition - no rules
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
    /// Gateway class name (spec.gatewayClassName) - references a GatewayClass.
    gateway_class_name: NameStorage,
    listeners: [gw_config.MAX_LISTENERS]StoredListener,
    listeners_count: u8,
    active: bool,

    pub fn init() StoredGateway {
        var gw = StoredGateway{
            .name = NameStorage.init(),
            .namespace = NameStorage.init(),
            .gateway_class_name = NameStorage.init(),
            .listeners = undefined,
            .listeners_count = 0,
            .active = false,
        };
        for (&gw.listeners) |*l| l.* = StoredListener.init();

        assert(gw.listeners_count == 0); // S1: postcondition - no listeners
        assert(!gw.active); // S1: postcondition - not active until used
        return gw;
    }
};

// =============================================================================
// GatewayClass Storage
// =============================================================================

/// Maximum length for controller name strings.
/// Controller names are DNS-like strings (e.g., "serval.dev/gateway-controller").
/// TigerStyle: Explicit bound, u8 length sufficient for DNS names.
pub const MAX_CONTROLLER_NAME_LEN: u8 = 128;

/// Maximum number of GatewayClass resources to track.
/// Re-export from serval-k8s-gateway for consistency.
pub const MAX_GATEWAY_CLASSES: u8 = gw_config.MAX_GATEWAY_CLASSES;

/// Fixed-size storage for a controller name string.
/// TigerStyle: Bounded storage, no allocation after init.
pub const ControllerNameStorage = struct {
    data: [MAX_CONTROLLER_NAME_LEN]u8,
    len: u8,

    /// Initialize empty controller name storage.
    pub fn init() ControllerNameStorage {
        const result = ControllerNameStorage{
            .data = std.mem.zeroes([MAX_CONTROLLER_NAME_LEN]u8),
            .len = 0,
        };
        assert(result.len == 0); // S1: postcondition - empty storage
        return result;
    }

    /// Copy a controller name into storage.
    /// TigerStyle: Caller must ensure value length does not exceed MAX_CONTROLLER_NAME_LEN.
    pub fn set(self: *ControllerNameStorage, value: []const u8) void {
        assert(value.len <= MAX_CONTROLLER_NAME_LEN); // S1: precondition
        const copy_len: u8 = @intCast(@min(value.len, MAX_CONTROLLER_NAME_LEN));
        @memcpy(self.data[0..copy_len], value[0..copy_len]);
        self.len = copy_len;
        assert(self.len <= MAX_CONTROLLER_NAME_LEN); // S1: postcondition
    }

    /// Get controller name as slice.
    pub fn slice(self: *const ControllerNameStorage) []const u8 {
        assert(self.len <= MAX_CONTROLLER_NAME_LEN); // S1: precondition - valid length
        return self.data[0..self.len];
    }
};

/// Stored GatewayClass with inline storage.
/// GatewayClass is cluster-scoped (no namespace field).
/// TigerStyle: Fixed-size storage, no allocation after init.
pub const StoredGatewayClass = struct {
    /// GatewayClass name (metadata.name).
    name: NameStorage,
    /// Controller that manages this class (spec.controllerName).
    controller_name: ControllerNameStorage,
    /// Indicates if this slot is in use.
    active: bool,

    /// Initialize empty GatewayClass storage.
    pub fn init() StoredGatewayClass {
        const result = StoredGatewayClass{
            .name = NameStorage.init(),
            .controller_name = ControllerNameStorage.init(),
            .active = false,
        };
        assert(result.name.len == 0); // S1: postcondition - empty name
        assert(result.controller_name.len == 0); // S1: postcondition - empty controller name
        assert(!result.active); // S1: postcondition - not active until used
        return result;
    }
};

// =============================================================================
// Unit Tests
// =============================================================================

test "ControllerNameStorage init returns empty storage" {
    const storage = ControllerNameStorage.init();
    try std.testing.expectEqual(@as(u8, 0), storage.len);
    try std.testing.expectEqualStrings("", storage.slice());
}

test "ControllerNameStorage set and slice" {
    var storage = ControllerNameStorage.init();
    const controller = "serval.dev/gateway-controller";
    storage.set(controller);

    try std.testing.expectEqual(@as(u8, controller.len), storage.len);
    try std.testing.expectEqualStrings(controller, storage.slice());
}

test "ControllerNameStorage set with long controller name" {
    var storage = ControllerNameStorage.init();
    // Long but valid controller name (under MAX_CONTROLLER_NAME_LEN)
    const controller = "very-long-domain.example.com/path/to/gateway-controller-name";
    storage.set(controller);

    try std.testing.expectEqual(@as(u8, controller.len), storage.len);
    try std.testing.expectEqualStrings(controller, storage.slice());
}

test "ControllerNameStorage set max length" {
    var storage = ControllerNameStorage.init();
    // Create a string of exactly MAX_CONTROLLER_NAME_LEN characters
    const max_controller = "a" ** MAX_CONTROLLER_NAME_LEN;
    storage.set(max_controller);

    try std.testing.expectEqual(MAX_CONTROLLER_NAME_LEN, storage.len);
    try std.testing.expectEqual(@as(usize, MAX_CONTROLLER_NAME_LEN), storage.slice().len);
}

test "ControllerNameStorage overwrite existing value" {
    var storage = ControllerNameStorage.init();

    // Set initial value
    storage.set("controller-v1");
    try std.testing.expectEqualStrings("controller-v1", storage.slice());

    // Overwrite with new value
    storage.set("controller-v2");
    try std.testing.expectEqualStrings("controller-v2", storage.slice());
}

test "StoredGatewayClass init returns inactive empty storage" {
    const gc = StoredGatewayClass.init();

    try std.testing.expect(!gc.active);
    try std.testing.expectEqual(@as(u8, 0), gc.name.len);
    try std.testing.expectEqual(@as(u8, 0), gc.controller_name.len);
    try std.testing.expectEqualStrings("", gc.name.slice());
    try std.testing.expectEqualStrings("", gc.controller_name.slice());
}

test "StoredGatewayClass set name and controller_name" {
    var gc = StoredGatewayClass.init();

    gc.name.set("serval-gateway");
    gc.controller_name.set("serval.dev/gateway-controller");
    gc.active = true;

    try std.testing.expect(gc.active);
    try std.testing.expectEqualStrings("serval-gateway", gc.name.slice());
    try std.testing.expectEqualStrings("serval.dev/gateway-controller", gc.controller_name.slice());
}

test "StoredGatewayClass multiple instances are independent" {
    var gc1 = StoredGatewayClass.init();
    var gc2 = StoredGatewayClass.init();

    gc1.name.set("class-a");
    gc1.controller_name.set("example.com/controller-a");
    gc1.active = true;

    gc2.name.set("class-b");
    gc2.controller_name.set("example.com/controller-b");
    gc2.active = true;

    // Verify they are independent
    try std.testing.expectEqualStrings("class-a", gc1.name.slice());
    try std.testing.expectEqualStrings("class-b", gc2.name.slice());
    try std.testing.expectEqualStrings("example.com/controller-a", gc1.controller_name.slice());
    try std.testing.expectEqualStrings("example.com/controller-b", gc2.controller_name.slice());
}

test "MAX_GATEWAY_CLASSES matches serval-k8s-gateway config" {
    // Verify the re-exported constant matches the original
    try std.testing.expectEqual(gw_config.MAX_GATEWAY_CLASSES, MAX_GATEWAY_CLASSES);
}

test "MAX_CONTROLLER_NAME_LEN is sufficient for typical controller names" {
    // Typical controller name format: <domain>/<path>/<controller-name>
    // Example: "gateway.networking.k8s.io/gateway-controller"
    // MAX_CONTROLLER_NAME_LEN (128) should be sufficient
    comptime {
        assert(MAX_CONTROLLER_NAME_LEN >= 64); // Minimum reasonable size
        assert(MAX_CONTROLLER_NAME_LEN <= 255); // Fits in u8 length field
    }
}

// =============================================================================
// StoredGateway Tests
// =============================================================================

test "StoredGateway init returns empty storage" {
    const gw = StoredGateway.init();

    try std.testing.expect(!gw.active);
    try std.testing.expectEqual(@as(u8, 0), gw.name.len);
    try std.testing.expectEqual(@as(u8, 0), gw.namespace.len);
    try std.testing.expectEqual(@as(u8, 0), gw.gateway_class_name.len);
    try std.testing.expectEqual(@as(u8, 0), gw.listeners_count);
}

test "StoredGateway gateway_class_name field" {
    var gw = StoredGateway.init();

    gw.name.set("my-gateway");
    gw.namespace.set("production");
    gw.gateway_class_name.set("serval");
    gw.active = true;

    try std.testing.expectEqualStrings("my-gateway", gw.name.slice());
    try std.testing.expectEqualStrings("production", gw.namespace.slice());
    try std.testing.expectEqualStrings("serval", gw.gateway_class_name.slice());
    try std.testing.expect(gw.active);
}
