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

const Client = @import("client.zig").Client;
const config = @import("../config.zig");

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
pub const MAX_GATEWAYS: u32 = config.MAX_GATEWAYS;
pub const MAX_HTTP_ROUTES: u32 = config.MAX_HTTP_ROUTES;
pub const MAX_SERVICES: u32 = 256;
pub const MAX_ENDPOINTS: u32 = 256;
pub const MAX_SECRETS: u32 = 64;

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
    on_config_change: *const fn (*config.GatewayConfig) void,

    /// Resource stores for each watched type.
    gateways: ResourceStore(MAX_GATEWAYS),
    http_routes: ResourceStore(MAX_HTTP_ROUTES),
    services: ResourceStore(MAX_SERVICES),
    endpoints: ResourceStore(MAX_ENDPOINTS),
    secrets: ResourceStore(MAX_SECRETS),

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
        on_config_change: *const fn (*config.GatewayConfig) void,
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
            .gateways = ResourceStore(MAX_GATEWAYS).init(),
            .http_routes = ResourceStore(MAX_HTTP_ROUTES).init(),
            .services = ResourceStore(MAX_SERVICES).init(),
            .endpoints = ResourceStore(MAX_ENDPOINTS).init(),
            .secrets = ResourceStore(MAX_SECRETS).init(),
            .line_buffer = line_buffer,
            .current_backoff_ms = INITIAL_BACKOFF_MS,
        };

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

        // Invoke callback with new config.
        self.on_config_change(&gateway_config);
    }

    /// Reconcile stored resources into a GatewayConfig.
    /// TigerStyle: Pure function that builds config from current state.
    pub fn reconcile(self: *Self) WatcherError!config.GatewayConfig {
        // For now, return empty config.
        // Full implementation would parse Gateway/HTTPRoute JSON and build typed config.
        // This is intentionally minimal - full JSON parsing is a separate enhancement.
        _ = self;
        return config.GatewayConfig{
            .gateways = &[_]config.Gateway{},
            .http_routes = &[_]config.HTTPRoute{},
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
