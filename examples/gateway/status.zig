//! Gateway Status Manager
//!
//! Manages status updates for Gateway API resources (Gateway, GatewayClass).
//! Uses K8s API PATCH to update status subresources with conditions.
//!
//! Status updates are best-effort - failures are logged but don't fail reconciliation.
//! This follows Kubernetes controller patterns where status updates are informational.
//!
//! TigerStyle: Pre-allocated buffers, bounded operations, explicit error handling.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const k8s_client_mod = @import("k8s_client/mod.zig");
const K8sClient = k8s_client_mod.Client;
const ClientError = k8s_client_mod.ClientError;

// =============================================================================
// Constants (TigerStyle: Explicit bounds)
// =============================================================================

/// Maximum JSON size for status updates.
/// Gateway status with multiple listeners and conditions fits within 4KB.
pub const MAX_STATUS_JSON_SIZE: u32 = 4096;

/// Maximum path size for K8s API URLs.
/// Format: /apis/gateway.networking.k8s.io/v1/namespaces/{ns}/gateways/{name}/status
/// With 63-char names: ~120 chars base + 63 ns + 63 name = ~250 chars
pub const MAX_PATH_SIZE: u32 = 512;

/// Maximum listeners per Gateway for status (matches config.MAX_LISTENERS).
const MAX_LISTENERS: u8 = 16;

/// Maximum conditions per status object.
const MAX_CONDITIONS: u8 = 8;

/// RFC3339 timestamp length (e.g., "2024-01-15T10:30:00Z").
const RFC3339_TIMESTAMP_LEN: u8 = 20;

/// Maximum iterations for building listener status array.
const MAX_LISTENER_ITERATIONS: u8 = 32;

// =============================================================================
// Reconcile Result Types
// =============================================================================

/// Result of reconciling a Gateway resource.
/// Contains the status information to write back to Kubernetes.
pub const GatewayReconcileResult = struct {
    /// Whether the Gateway was accepted (config is valid).
    accepted: bool,
    /// Reason for accepted condition (CamelCase).
    accepted_reason: []const u8,
    /// Human-readable message for accepted condition.
    accepted_message: []const u8,
    /// Whether the Gateway was programmed into data plane.
    programmed: bool,
    /// Reason for programmed condition (CamelCase).
    programmed_reason: []const u8,
    /// Human-readable message for programmed condition.
    programmed_message: []const u8,
    /// Generation of the resource this status applies to.
    observed_generation: i64,
    /// Per-listener results.
    listener_results: []const ListenerReconcileResult,
};

/// Result of reconciling an individual listener.
pub const ListenerReconcileResult = struct {
    /// Listener name (matches spec.listeners[].name).
    name: []const u8,
    /// Whether the listener was accepted (config is valid).
    accepted: bool,
    /// Whether the listener was programmed into data plane.
    programmed: bool,
    /// Whether all backend references were resolved.
    resolved_refs: bool,
    /// Reason for resolved refs condition.
    resolved_refs_reason: []const u8,
    /// Number of routes attached to this listener.
    attached_routes: u32,
};

// =============================================================================
// JSON Serialization Types (match K8s API shape)
// =============================================================================

/// JSON shape for Gateway status PATCH request body.
const GatewayStatusPatch = struct {
    status: GatewayStatusJson,
};

/// Gateway status JSON structure.
const GatewayStatusJson = struct {
    conditions: []const ConditionJson,
    listeners: []const ListenerStatusJson,
};

/// Listener status JSON structure.
const ListenerStatusJson = struct {
    name: []const u8,
    attachedRoutes: i32,
    supportedKinds: []const SupportedKindJson,
    conditions: []const ConditionJson,
};

/// Supported route kind reference.
const SupportedKindJson = struct {
    group: []const u8,
    kind: []const u8,
};

/// Condition JSON structure matching K8s metav1.Condition.
const ConditionJson = struct {
    type: []const u8,
    status: []const u8,
    reason: []const u8,
    message: []const u8,
    lastTransitionTime: []const u8,
    observedGeneration: i64,
};

/// JSON shape for GatewayClass status PATCH request body.
const GatewayClassStatusPatch = struct {
    status: GatewayClassStatusJson,
};

/// GatewayClass status JSON structure.
const GatewayClassStatusJson = struct {
    conditions: []const ConditionJson,
};

// =============================================================================
// Supported Kinds (static)
// =============================================================================

/// HTTPRoute is the only supported route kind.
const SUPPORTED_KINDS: [1]SupportedKindJson = .{
    .{ .group = "gateway.networking.k8s.io", .kind = "HTTPRoute" },
};

// =============================================================================
// StatusManager
// =============================================================================

/// Manages status updates for Gateway API resources.
/// Uses pre-allocated buffers for JSON serialization (TigerStyle: no allocation after init).
pub const StatusManager = struct {
    const Self = @This();

    /// Allocator for Self allocation/deallocation.
    allocator: std.mem.Allocator,

    /// K8s API client for PATCH requests.
    k8s_client: *K8sClient,

    /// Controller name for GatewayClass status.
    controller_name: []const u8,

    /// Pre-allocated buffer for JSON serialization.
    json_buffer: [MAX_STATUS_JSON_SIZE]u8,

    /// Pre-allocated buffer for building API paths.
    path_buffer: [MAX_PATH_SIZE]u8,

    /// Pre-allocated buffer for RFC3339 timestamp.
    timestamp_buffer: [RFC3339_TIMESTAMP_LEN]u8,

    /// Pre-allocated arrays for Gateway conditions (2: Accepted, Programmed).
    gateway_conditions: [2]ConditionJson,

    /// Pre-allocated arrays for listener conditions (3: Accepted, Programmed, ResolvedRefs).
    listener_conditions: [MAX_LISTENERS][3]ConditionJson,

    /// Pre-allocated array for listener status entries.
    listener_statuses: [MAX_LISTENERS]ListenerStatusJson,

    /// Pre-allocated array for GatewayClass conditions (1: Accepted).
    gateway_class_conditions: [1]ConditionJson,

    /// Initialize StatusManager.
    ///
    /// Preconditions:
    /// - k8s_client must be initialized and valid
    /// - controller_name must be non-empty
    ///
    /// Returns heap-allocated StatusManager (TigerStyle C3: large struct ~70KB).
    pub fn init(
        allocator: std.mem.Allocator,
        k8s_client: *K8sClient,
        controller_name: []const u8,
    ) !*Self {
        // S1: Preconditions
        assert(@intFromPtr(k8s_client) != 0); // k8s_client must be valid pointer
        assert(controller_name.len > 0); // controller_name must be non-empty

        const self = allocator.create(Self) catch return error.OutOfMemory;

        self.* = Self{
            .allocator = allocator,
            .k8s_client = k8s_client,
            .controller_name = controller_name,
            .json_buffer = undefined,
            .path_buffer = undefined,
            .timestamp_buffer = undefined,
            .gateway_conditions = undefined,
            .listener_conditions = undefined,
            .listener_statuses = undefined,
            .gateway_class_conditions = undefined,
        };

        // S2: Postconditions
        assert(@intFromPtr(self.k8s_client) != 0); // k8s_client stored correctly
        assert(self.controller_name.len > 0); // controller_name stored correctly

        return self;
    }

    /// Clean up StatusManager resources.
    pub fn deinit(self: *Self) void {
        assert(@intFromPtr(self) != 0); // S1: precondition - valid self pointer
        self.allocator.destroy(self);
    }

    /// Update status for a Gateway resource.
    /// Best-effort: logs errors but doesn't propagate them.
    ///
    /// Preconditions:
    /// - gateway_name must be non-empty
    /// - namespace must be non-empty
    pub fn updateGatewayStatus(
        self: *Self,
        gateway_name: []const u8,
        namespace: []const u8,
        result: GatewayReconcileResult,
        io: Io,
    ) void {
        // S1: Preconditions
        assert(gateway_name.len > 0); // gateway_name must be non-empty
        assert(namespace.len > 0); // namespace must be non-empty

        self.updateGatewayStatusImpl(gateway_name, namespace, result, io) catch |err| {
            std.log.warn("failed to update Gateway status {s}/{s}: {s}", .{
                namespace,
                gateway_name,
                @errorName(err),
            });
        };
    }

    /// Update status for a GatewayClass resource.
    /// Best-effort: logs errors but doesn't propagate them.
    ///
    /// Preconditions:
    /// - gateway_class_name must be non-empty
    pub fn updateGatewayClassStatus(
        self: *Self,
        gateway_class_name: []const u8,
        io: Io,
    ) void {
        // S1: Precondition
        assert(gateway_class_name.len > 0); // gateway_class_name must be non-empty

        self.updateGatewayClassStatusImpl(gateway_class_name, io) catch |err| {
            std.log.warn("failed to update GatewayClass status {s}: {s}", .{
                gateway_class_name,
                @errorName(err),
            });
        };
    }

    // =========================================================================
    // Implementation (private)
    // =========================================================================

    /// Internal implementation of Gateway status update.
    fn updateGatewayStatusImpl(
        self: *Self,
        gateway_name: []const u8,
        namespace: []const u8,
        result: GatewayReconcileResult,
        io: Io,
    ) !void {
        // S1: Preconditions (already checked in public method, defensive here)
        assert(gateway_name.len > 0);
        assert(namespace.len > 0);

        // Generate RFC3339 timestamp
        const timestamp = self.generateTimestamp();

        // Build Gateway conditions
        self.gateway_conditions[0] = ConditionJson{
            .type = "Accepted",
            .status = if (result.accepted) "True" else "False",
            .reason = result.accepted_reason,
            .message = result.accepted_message,
            .lastTransitionTime = timestamp,
            .observedGeneration = result.observed_generation,
        };
        self.gateway_conditions[1] = ConditionJson{
            .type = "Programmed",
            .status = if (result.programmed) "True" else "False",
            .reason = result.programmed_reason,
            .message = result.programmed_message,
            .lastTransitionTime = timestamp,
            .observedGeneration = result.observed_generation,
        };

        // Build listener statuses
        const listener_count = self.buildListenerStatuses(result, timestamp);

        // Build JSON payload
        const patch = GatewayStatusPatch{
            .status = GatewayStatusJson{
                .conditions = self.gateway_conditions[0..2],
                .listeners = self.listener_statuses[0..listener_count],
            },
        };

        // Serialize to JSON
        var fbs = std.io.fixedBufferStream(&self.json_buffer);
        std.json.stringify(patch, .{}, fbs.writer()) catch |err| {
            std.log.err("failed to serialize Gateway status JSON: {s}", .{@errorName(err)});
            return error.JsonSerializationFailed;
        };
        const json_len = fbs.pos;

        // S1: Postcondition - JSON fits in buffer
        assert(json_len <= MAX_STATUS_JSON_SIZE);

        // Build API path
        const path = self.buildGatewayPath(namespace, gateway_name) catch |err| {
            std.log.err("failed to build Gateway path: {s}", .{@errorName(err)});
            return error.PathTooLong;
        };

        // PATCH status to K8s API
        self.k8s_client.patchStatus(path, self.json_buffer[0..json_len], io) catch |err| {
            if (err == ClientError.ConflictRetryable) {
                // HTTP 409 - resource version mismatch, log and continue
                std.log.debug("Gateway status update conflict (will retry on next reconcile)", .{});
            }
            return err;
        };

        std.log.debug("updated Gateway status {s}/{s}", .{ namespace, gateway_name });
    }

    /// Internal implementation of GatewayClass status update.
    fn updateGatewayClassStatusImpl(
        self: *Self,
        gateway_class_name: []const u8,
        io: Io,
    ) !void {
        // S1: Precondition
        assert(gateway_class_name.len > 0);

        // Generate RFC3339 timestamp
        const timestamp = self.generateTimestamp();

        // Build GatewayClass condition (Accepted=True - we're managing this class)
        self.gateway_class_conditions[0] = ConditionJson{
            .type = "Accepted",
            .status = "True",
            .reason = "Accepted",
            .message = "GatewayClass is accepted by controller",
            .lastTransitionTime = timestamp,
            .observedGeneration = 1, // GatewayClass doesn't track generation for now
        };

        // Build JSON payload
        const patch = GatewayClassStatusPatch{
            .status = GatewayClassStatusJson{
                .conditions = self.gateway_class_conditions[0..1],
            },
        };

        // Serialize to JSON
        var fbs = std.io.fixedBufferStream(&self.json_buffer);
        std.json.stringify(patch, .{}, fbs.writer()) catch |err| {
            std.log.err("failed to serialize GatewayClass status JSON: {s}", .{@errorName(err)});
            return error.JsonSerializationFailed;
        };
        const json_len = fbs.pos;

        // S1: Postcondition - JSON fits in buffer
        assert(json_len <= MAX_STATUS_JSON_SIZE);

        // Build API path (GatewayClass is cluster-scoped, no namespace)
        const path = self.buildGatewayClassPath(gateway_class_name) catch |err| {
            std.log.err("failed to build GatewayClass path: {s}", .{@errorName(err)});
            return error.PathTooLong;
        };

        // PATCH status to K8s API
        self.k8s_client.patchStatus(path, self.json_buffer[0..json_len], io) catch |err| {
            if (err == ClientError.ConflictRetryable) {
                std.log.debug("GatewayClass status update conflict (will retry on next reconcile)", .{});
            }
            return err;
        };

        std.log.debug("updated GatewayClass status {s}", .{gateway_class_name});
    }

    /// Build listener status entries from reconcile result.
    /// Returns the number of listeners built.
    fn buildListenerStatuses(
        self: *Self,
        result: GatewayReconcileResult,
        timestamp: []const u8,
    ) u8 {
        // S1: Precondition
        assert(timestamp.len > 0);

        var count: u8 = 0;
        var iteration: u8 = 0;

        for (result.listener_results) |listener_result| {
            // S3: Bounded loop
            if (iteration >= MAX_LISTENER_ITERATIONS) break;
            iteration += 1;

            if (count >= MAX_LISTENERS) break;

            // Build listener conditions (3 conditions per listener)
            self.listener_conditions[count][0] = ConditionJson{
                .type = "Accepted",
                .status = if (listener_result.accepted) "True" else "False",
                .reason = if (listener_result.accepted) "Accepted" else "Invalid",
                .message = if (listener_result.accepted) "Listener is valid" else "Listener configuration is invalid",
                .lastTransitionTime = timestamp,
                .observedGeneration = result.observed_generation,
            };
            self.listener_conditions[count][1] = ConditionJson{
                .type = "Programmed",
                .status = if (listener_result.programmed) "True" else "False",
                .reason = if (listener_result.programmed) "Programmed" else "Pending",
                .message = if (listener_result.programmed) "Listener is programmed" else "Listener is not yet programmed",
                .lastTransitionTime = timestamp,
                .observedGeneration = result.observed_generation,
            };
            self.listener_conditions[count][2] = ConditionJson{
                .type = "ResolvedRefs",
                .status = if (listener_result.resolved_refs) "True" else "False",
                .reason = listener_result.resolved_refs_reason,
                .message = if (listener_result.resolved_refs) "All references resolved" else "Some references could not be resolved",
                .lastTransitionTime = timestamp,
                .observedGeneration = result.observed_generation,
            };

            // Build listener status entry
            self.listener_statuses[count] = ListenerStatusJson{
                .name = listener_result.name,
                .attachedRoutes = @intCast(listener_result.attached_routes),
                .supportedKinds = &SUPPORTED_KINDS,
                .conditions = self.listener_conditions[count][0..3],
            };

            count += 1;
        }

        // S2: Postcondition - count within bounds
        assert(count <= MAX_LISTENERS);
        return count;
    }

    /// Generate RFC3339 timestamp for current time.
    /// Format: YYYY-MM-DDTHH:MM:SSZ
    fn generateTimestamp(self: *Self) []const u8 {
        const epoch_seconds: u64 = @intCast(std.time.timestamp());

        // Calculate date/time components from epoch seconds
        // Simplified: use days since epoch approach
        const epoch_days = epoch_seconds / 86400;
        const day_seconds = epoch_seconds % 86400;

        const hour: u8 = @intCast(day_seconds / 3600);
        const minute: u8 = @intCast((day_seconds % 3600) / 60);
        const second: u8 = @intCast(day_seconds % 60);

        // Convert epoch days to date (simplified calculation from 1970-01-01)
        const date = epochDaysToDate(epoch_days);

        // Format: YYYY-MM-DDTHH:MM:SSZ (20 chars)
        const written = std.fmt.bufPrint(&self.timestamp_buffer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
            date.year,
            date.month,
            date.day,
            hour,
            minute,
            second,
        }) catch {
            // Should never fail - buffer is exactly sized
            return "1970-01-01T00:00:00Z";
        };

        // S2: Postcondition - timestamp has expected length
        assert(written.len == RFC3339_TIMESTAMP_LEN);
        return written;
    }

    /// Build Gateway status API path.
    /// Format: /apis/gateway.networking.k8s.io/v1/namespaces/{ns}/gateways/{name}/status
    fn buildGatewayPath(
        self: *Self,
        namespace: []const u8,
        name: []const u8,
    ) ![]const u8 {
        // S1: Preconditions
        assert(namespace.len > 0);
        assert(name.len > 0);

        const path = std.fmt.bufPrint(
            &self.path_buffer,
            "/apis/gateway.networking.k8s.io/v1/namespaces/{s}/gateways/{s}/status",
            .{ namespace, name },
        ) catch {
            return error.PathTooLong;
        };

        // S2: Postcondition - path starts with /
        assert(path.len > 0);
        assert(path[0] == '/');

        return path;
    }

    /// Build GatewayClass status API path.
    /// Format: /apis/gateway.networking.k8s.io/v1/gatewayclasses/{name}/status
    fn buildGatewayClassPath(
        self: *Self,
        name: []const u8,
    ) ![]const u8 {
        // S1: Precondition
        assert(name.len > 0);

        const path = std.fmt.bufPrint(
            &self.path_buffer,
            "/apis/gateway.networking.k8s.io/v1/gatewayclasses/{s}/status",
            .{name},
        ) catch {
            return error.PathTooLong;
        };

        // S2: Postcondition - path starts with /
        assert(path.len > 0);
        assert(path[0] == '/');

        return path;
    }
};

// =============================================================================
// Date Calculation Helper
// =============================================================================

/// Date components.
const Date = struct {
    year: u16,
    month: u8,
    day: u8,
};

/// Convert epoch days (days since 1970-01-01) to date.
/// Uses a simplified algorithm sufficient for timestamp generation.
fn epochDaysToDate(epoch_days: u64) Date {
    // Based on Howard Hinnant's algorithms for date conversion
    // Simplified version for our use case

    var z = epoch_days + 719468; // Days since 0000-03-01
    const era: u64 = z / 146097; // 400-year era
    const doe: u64 = z - era * 146097; // Day of era [0, 146096]
    const yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // Year of era [0, 399]
    const y = yoe + era * 400;
    const doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100); // Day of year [0, 365]
    const mp: u64 = (5 * doy + 2) / 153; // Month offset
    const d: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1); // Day [1, 31]
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9); // Month [1, 12]
    const year_adj: u16 = @intCast(if (m <= 2) y + 1 else y);

    return Date{
        .year = year_adj,
        .month = m,
        .day = d,
    };
}

// =============================================================================
// Error Types
// =============================================================================

pub const StatusError = error{
    OutOfMemory,
    JsonSerializationFailed,
    PathTooLong,
};

// =============================================================================
// Unit Tests
// =============================================================================

test "StatusManager init and deinit" {
    const allocator = std.testing.allocator;

    // Create mock K8s client
    const k8s_client = try k8s_client_mod.Client.initWithConfig(
        allocator,
        "localhost",
        6443,
        "test-token-12345",
        "default",
    );
    defer k8s_client.deinit();

    // Create StatusManager
    const status_mgr = try StatusManager.init(allocator, k8s_client, "test-controller");
    defer status_mgr.deinit();

    try std.testing.expectEqualStrings("test-controller", status_mgr.controller_name);
    try std.testing.expect(@intFromPtr(status_mgr.k8s_client) != 0);
}

test "ConditionJson serialization" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const condition = ConditionJson{
        .type = "Accepted",
        .status = "True",
        .reason = "Accepted",
        .message = "Resource accepted",
        .lastTransitionTime = "2024-01-15T10:30:00Z",
        .observedGeneration = 42,
    };

    try std.json.stringify(condition, .{}, fbs.writer());
    const json = fbs.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"Accepted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"True\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"reason\":\"Accepted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"lastTransitionTime\":\"2024-01-15T10:30:00Z\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"observedGeneration\":42") != null);
}

test "GatewayClassStatusPatch serialization" {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const conditions = [_]ConditionJson{
        .{
            .type = "Accepted",
            .status = "True",
            .reason = "Accepted",
            .message = "GatewayClass is accepted",
            .lastTransitionTime = "2024-01-15T10:30:00Z",
            .observedGeneration = 1,
        },
    };

    const patch = GatewayClassStatusPatch{
        .status = GatewayClassStatusJson{
            .conditions = &conditions,
        },
    };

    try std.json.stringify(patch, .{}, fbs.writer());
    const json = fbs.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"conditions\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"Accepted\"") != null);
}

test "GatewayStatusPatch serialization" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const gateway_conditions = [_]ConditionJson{
        .{
            .type = "Accepted",
            .status = "True",
            .reason = "Accepted",
            .message = "Gateway is valid",
            .lastTransitionTime = "2024-01-15T10:30:00Z",
            .observedGeneration = 3,
        },
        .{
            .type = "Programmed",
            .status = "True",
            .reason = "Programmed",
            .message = "Gateway has been programmed",
            .lastTransitionTime = "2024-01-15T10:30:01Z",
            .observedGeneration = 3,
        },
    };

    const listener_conditions = [_]ConditionJson{
        .{
            .type = "Accepted",
            .status = "True",
            .reason = "Accepted",
            .message = "Listener is valid",
            .lastTransitionTime = "2024-01-15T10:30:00Z",
            .observedGeneration = 3,
        },
    };

    const listeners = [_]ListenerStatusJson{
        .{
            .name = "http",
            .attachedRoutes = 5,
            .supportedKinds = &SUPPORTED_KINDS,
            .conditions = &listener_conditions,
        },
    };

    const patch = GatewayStatusPatch{
        .status = GatewayStatusJson{
            .conditions = &gateway_conditions,
            .listeners = &listeners,
        },
    };

    try std.json.stringify(patch, .{}, fbs.writer());
    const json = fbs.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"conditions\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"listeners\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"http\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"attachedRoutes\":5") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"supportedKinds\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"kind\":\"HTTPRoute\"") != null);
}

test "ListenerStatusJson serialization with multiple conditions" {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    const conditions = [_]ConditionJson{
        .{
            .type = "Accepted",
            .status = "True",
            .reason = "Accepted",
            .message = "Listener accepted",
            .lastTransitionTime = "2024-01-15T10:30:00Z",
            .observedGeneration = 2,
        },
        .{
            .type = "Programmed",
            .status = "True",
            .reason = "Programmed",
            .message = "Listener programmed",
            .lastTransitionTime = "2024-01-15T10:30:00Z",
            .observedGeneration = 2,
        },
        .{
            .type = "ResolvedRefs",
            .status = "True",
            .reason = "ResolvedRefs",
            .message = "All references resolved",
            .lastTransitionTime = "2024-01-15T10:30:00Z",
            .observedGeneration = 2,
        },
    };

    const listener = ListenerStatusJson{
        .name = "https",
        .attachedRoutes = 10,
        .supportedKinds = &SUPPORTED_KINDS,
        .conditions = &conditions,
    };

    try std.json.stringify(listener, .{}, fbs.writer());
    const json = fbs.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"https\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"attachedRoutes\":10") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Accepted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Programmed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"ResolvedRefs\"") != null);
}

test "epochDaysToDate correctness" {
    // Test known dates
    // 1970-01-01 = epoch day 0
    {
        const date = epochDaysToDate(0);
        try std.testing.expectEqual(@as(u16, 1970), date.year);
        try std.testing.expectEqual(@as(u8, 1), date.month);
        try std.testing.expectEqual(@as(u8, 1), date.day);
    }

    // 2000-01-01 = epoch day 10957
    {
        const date = epochDaysToDate(10957);
        try std.testing.expectEqual(@as(u16, 2000), date.year);
        try std.testing.expectEqual(@as(u8, 1), date.month);
        try std.testing.expectEqual(@as(u8, 1), date.day);
    }

    // 2024-01-15 = epoch day 19737
    {
        const date = epochDaysToDate(19737);
        try std.testing.expectEqual(@as(u16, 2024), date.year);
        try std.testing.expectEqual(@as(u8, 1), date.month);
        try std.testing.expectEqual(@as(u8, 15), date.day);
    }
}

test "StatusManager.buildGatewayPath" {
    const allocator = std.testing.allocator;

    const k8s_client = try k8s_client_mod.Client.initWithConfig(
        allocator,
        "localhost",
        6443,
        "test-token-12345",
        "default",
    );
    defer k8s_client.deinit();

    const status_mgr = try StatusManager.init(allocator, k8s_client, "test-controller");
    defer status_mgr.deinit();

    const path = try status_mgr.buildGatewayPath("production", "my-gateway");
    try std.testing.expectEqualStrings(
        "/apis/gateway.networking.k8s.io/v1/namespaces/production/gateways/my-gateway/status",
        path,
    );
}

test "StatusManager.buildGatewayClassPath" {
    const allocator = std.testing.allocator;

    const k8s_client = try k8s_client_mod.Client.initWithConfig(
        allocator,
        "localhost",
        6443,
        "test-token-12345",
        "default",
    );
    defer k8s_client.deinit();

    const status_mgr = try StatusManager.init(allocator, k8s_client, "test-controller");
    defer status_mgr.deinit();

    const path = try status_mgr.buildGatewayClassPath("serval-gateway");
    try std.testing.expectEqualStrings(
        "/apis/gateway.networking.k8s.io/v1/gatewayclasses/serval-gateway/status",
        path,
    );
}

test "StatusManager.generateTimestamp format" {
    const allocator = std.testing.allocator;

    const k8s_client = try k8s_client_mod.Client.initWithConfig(
        allocator,
        "localhost",
        6443,
        "test-token-12345",
        "default",
    );
    defer k8s_client.deinit();

    const status_mgr = try StatusManager.init(allocator, k8s_client, "test-controller");
    defer status_mgr.deinit();

    const timestamp = status_mgr.generateTimestamp();

    // Check format: YYYY-MM-DDTHH:MM:SSZ
    try std.testing.expectEqual(@as(usize, RFC3339_TIMESTAMP_LEN), timestamp.len);
    try std.testing.expect(timestamp[4] == '-'); // YYYY-
    try std.testing.expect(timestamp[7] == '-'); // MM-
    try std.testing.expect(timestamp[10] == 'T'); // T
    try std.testing.expect(timestamp[13] == ':'); // HH:
    try std.testing.expect(timestamp[16] == ':'); // MM:
    try std.testing.expect(timestamp[19] == 'Z'); // Z
}

test "StatusManager.buildListenerStatuses" {
    const allocator = std.testing.allocator;

    const k8s_client = try k8s_client_mod.Client.initWithConfig(
        allocator,
        "localhost",
        6443,
        "test-token-12345",
        "default",
    );
    defer k8s_client.deinit();

    const status_mgr = try StatusManager.init(allocator, k8s_client, "test-controller");
    defer status_mgr.deinit();

    const listener_results = [_]ListenerReconcileResult{
        .{
            .name = "http",
            .accepted = true,
            .programmed = true,
            .resolved_refs = true,
            .resolved_refs_reason = "ResolvedRefs",
            .attached_routes = 3,
        },
        .{
            .name = "https",
            .accepted = true,
            .programmed = false,
            .resolved_refs = false,
            .resolved_refs_reason = "InvalidCertificateRef",
            .attached_routes = 0,
        },
    };

    const result = GatewayReconcileResult{
        .accepted = true,
        .accepted_reason = "Accepted",
        .accepted_message = "Gateway is valid",
        .programmed = true,
        .programmed_reason = "Programmed",
        .programmed_message = "Gateway is programmed",
        .observed_generation = 5,
        .listener_results = &listener_results,
    };

    const timestamp = "2024-01-15T10:30:00Z";
    const count = status_mgr.buildListenerStatuses(result, timestamp);

    try std.testing.expectEqual(@as(u8, 2), count);
    try std.testing.expectEqualStrings("http", status_mgr.listener_statuses[0].name);
    try std.testing.expectEqual(@as(i32, 3), status_mgr.listener_statuses[0].attachedRoutes);
    try std.testing.expectEqualStrings("https", status_mgr.listener_statuses[1].name);
    try std.testing.expectEqual(@as(i32, 0), status_mgr.listener_statuses[1].attachedRoutes);
}

test "GatewayReconcileResult construction" {
    const listener_results = [_]ListenerReconcileResult{
        .{
            .name = "http",
            .accepted = true,
            .programmed = true,
            .resolved_refs = true,
            .resolved_refs_reason = "ResolvedRefs",
            .attached_routes = 5,
        },
    };

    const result = GatewayReconcileResult{
        .accepted = true,
        .accepted_reason = "Accepted",
        .accepted_message = "Gateway configuration is valid",
        .programmed = true,
        .programmed_reason = "Programmed",
        .programmed_message = "Gateway has been programmed into the data plane",
        .observed_generation = 10,
        .listener_results = &listener_results,
    };

    try std.testing.expect(result.accepted);
    try std.testing.expect(result.programmed);
    try std.testing.expectEqualStrings("Accepted", result.accepted_reason);
    try std.testing.expectEqual(@as(i64, 10), result.observed_generation);
    try std.testing.expectEqual(@as(usize, 1), result.listener_results.len);
}

test "MAX constants are reasonable" {
    // Verify constants are within expected bounds
    comptime {
        assert(MAX_STATUS_JSON_SIZE >= 1024); // At least 1KB
        assert(MAX_STATUS_JSON_SIZE <= 65536); // At most 64KB
        assert(MAX_PATH_SIZE >= 256); // At least 256 bytes
        assert(MAX_PATH_SIZE <= 1024); // At most 1KB
        assert(MAX_LISTENERS <= 255); // Fits in u8
        assert(MAX_CONDITIONS <= 255); // Fits in u8
    }
}
