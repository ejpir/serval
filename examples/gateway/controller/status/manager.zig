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

const serval_core = @import("serval-core");
const log = serval_core.log.scoped(.gateway_controller);
const core_time = serval_core.time;

const k8s_client_mod = @import("../../k8s_client/mod.zig");
const K8sClient = k8s_client_mod.Client;
const ClientError = k8s_client_mod.ClientError;

const mod = @import("mod.zig");
const MAX_STATUS_JSON_SIZE = mod.MAX_STATUS_JSON_SIZE;
const MAX_PATH_SIZE = mod.MAX_PATH_SIZE;
const RFC3339_TIMESTAMP_LEN = mod.RFC3339_TIMESTAMP_LEN;

const types = @import("types.zig");
const GatewayReconcileResult = types.GatewayReconcileResult;
const ListenerReconcileResult = types.ListenerReconcileResult;
const ConditionJson = types.ConditionJson;
const ListenerStatusJson = types.ListenerStatusJson;
const SupportedKindJson = types.SupportedKindJson;
const epochDaysToDate = types.epochDaysToDate;

// =============================================================================
// Internal Constants
// =============================================================================

/// Maximum listeners per Gateway for status (matches config.MAX_LISTENERS).
const MAX_LISTENERS: u8 = 16;

/// Maximum iterations for building listener status array.
const MAX_LISTENER_ITERATIONS: u8 = 32;

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

        log.debug("status: updateGatewayStatus {s}/{s} accepted={} programmed={}", .{
            namespace,
            gateway_name,
            result.accepted,
            result.programmed,
        });

        self.updateGatewayStatusImpl(gateway_name, namespace, result, io) catch |err| {
            log.warn("failed to update Gateway status {s}/{s}: {s}", .{
                namespace,
                gateway_name,
                @errorName(err),
            });
        };

        log.debug("status: updateGatewayStatus {s}/{s} complete", .{ namespace, gateway_name });
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
            log.warn("failed to update GatewayClass status {s}: {s}", .{
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
        _ = listener_count; // Listener status JSON not yet implemented

        // Build JSON payload manually (TigerStyle: no allocation, no std.io dependency)
        // Format: {"status":{"conditions":[...]},"listeners":[...]}
        const json_len = self.buildGatewayStatusJson(
            self.gateway_conditions[0..2],
            result.observed_generation,
        ) catch {
            log.err("failed to build Gateway status JSON", .{});
            return error.JsonSerializationFailed;
        };

        // S1: Postcondition - JSON fits in buffer
        assert(json_len <= MAX_STATUS_JSON_SIZE);

        // Build API path
        const path = self.buildGatewayPath(namespace, gateway_name) catch |err| {
            log.err("failed to build Gateway path: {s}", .{@errorName(err)});
            return error.PathTooLong;
        };

        log.debug("status: PATCH path={s}", .{path});
        log.debug("status: PATCH json_len={d}", .{json_len});

        // PATCH status to K8s API
        self.k8s_client.patchStatus(path, self.json_buffer[0..json_len], io) catch |err| {
            log.debug("status: patchStatus returned error={s}", .{@errorName(err)});
            if (err == ClientError.ConflictRetryable) {
                // HTTP 409 - resource version mismatch, log and continue
                log.debug("Gateway status update conflict (will retry on next reconcile)", .{});
            }
            return err;
        };

        log.info("updated Gateway status {s}/{s}", .{ namespace, gateway_name });
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

        // Build JSON payload manually (TigerStyle: no allocation, no std.io dependency)
        const json_len = self.buildGatewayClassStatusJson(
            self.gateway_class_conditions[0..1],
        ) catch {
            log.err("failed to build GatewayClass status JSON", .{});
            return error.JsonSerializationFailed;
        };

        // S1: Postcondition - JSON fits in buffer
        assert(json_len <= MAX_STATUS_JSON_SIZE);

        // Build API path (GatewayClass is cluster-scoped, no namespace)
        const path = self.buildGatewayClassPath(gateway_class_name) catch |err| {
            log.err("failed to build GatewayClass path: {s}", .{@errorName(err)});
            return error.PathTooLong;
        };

        // PATCH status to K8s API
        self.k8s_client.patchStatus(path, self.json_buffer[0..json_len], io) catch |err| {
            if (err == ClientError.ConflictRetryable) {
                log.debug("GatewayClass status update conflict (will retry on next reconcile)", .{});
            }
            return err;
        };

        log.debug("updated GatewayClass status {s}", .{gateway_class_name});
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
    pub fn generateTimestamp(self: *Self) []const u8 {
        // Use serval-core time (returns nanoseconds since epoch)
        const nanos: i128 = core_time.realtimeNanos();
        // Convert to seconds, handling potential negative values gracefully
        const epoch_seconds: u64 = if (nanos > 0) @intCast(@divTrunc(nanos, core_time.ns_per_s)) else 0;

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
    pub fn buildGatewayPath(
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
    pub fn buildGatewayClassPath(
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

    /// Build Gateway status JSON manually using bufPrint.
    /// Returns the length of JSON written to json_buffer.
    /// TigerStyle: No allocation, bounded buffer.
    pub fn buildGatewayStatusJson(
        self: *Self,
        conditions: []const ConditionJson,
        observed_generation: i64,
    ) !usize {
        // S1: Preconditions
        assert(conditions.len > 0);
        assert(conditions.len <= 2);
        _ = observed_generation; // Used in conditions already

        // Build JSON: {"status":{"conditions":[...]}}
        // We build each condition separately to handle variable number
        var pos: usize = 0;

        // Opening
        const opening = "{\"status\":{\"conditions\":[";
        if (pos + opening.len > self.json_buffer.len) return error.JsonSerializationFailed;
        @memcpy(self.json_buffer[pos .. pos + opening.len], opening);
        pos += opening.len;

        // Write each condition
        for (conditions, 0..) |cond, i| {
            if (i > 0) {
                if (pos >= self.json_buffer.len) return error.JsonSerializationFailed;
                self.json_buffer[pos] = ',';
                pos += 1;
            }
            pos = try self.writeConditionJson(pos, cond);
        }

        // Closing: ],"listeners":[]}}
        // Note: listeners empty for now, can be extended later
        const closing = "],\"listeners\":[]}}";
        if (pos + closing.len > self.json_buffer.len) return error.JsonSerializationFailed;
        @memcpy(self.json_buffer[pos .. pos + closing.len], closing);
        pos += closing.len;

        return pos;
    }

    /// Build GatewayClass status JSON manually using bufPrint.
    /// Returns the length of JSON written to json_buffer.
    /// TigerStyle: No allocation, bounded buffer.
    pub fn buildGatewayClassStatusJson(
        self: *Self,
        conditions: []const ConditionJson,
    ) !usize {
        // S1: Preconditions
        assert(conditions.len > 0);
        assert(conditions.len <= 1);

        // Build JSON: {"status":{"conditions":[...]}}
        var pos: usize = 0;

        // Opening
        const opening = "{\"status\":{\"conditions\":[";
        if (pos + opening.len > self.json_buffer.len) return error.JsonSerializationFailed;
        @memcpy(self.json_buffer[pos .. pos + opening.len], opening);
        pos += opening.len;

        // Write each condition
        for (conditions, 0..) |cond, i| {
            if (i > 0) {
                if (pos >= self.json_buffer.len) return error.JsonSerializationFailed;
                self.json_buffer[pos] = ',';
                pos += 1;
            }
            pos = try self.writeConditionJson(pos, cond);
        }

        // Closing
        const closing = "]}}";
        if (pos + closing.len > self.json_buffer.len) return error.JsonSerializationFailed;
        @memcpy(self.json_buffer[pos .. pos + closing.len], closing);
        pos += closing.len;

        return pos;
    }

    /// Write a single condition as JSON to the buffer at the given position.
    /// Returns new position after writing.
    pub fn writeConditionJson(self: *Self, start_pos: usize, cond: ConditionJson) !usize {
        // Format: {"type":"...","status":"...","reason":"...","message":"...","lastTransitionTime":"...","observedGeneration":N}
        const json = std.fmt.bufPrint(
            self.json_buffer[start_pos..],
            "{{\"type\":\"{s}\",\"status\":\"{s}\",\"reason\":\"{s}\",\"message\":\"{s}\",\"lastTransitionTime\":\"{s}\",\"observedGeneration\":{d}}}",
            .{
                cond.type,
                cond.status,
                cond.reason,
                cond.message,
                cond.lastTransitionTime,
                cond.observedGeneration,
            },
        ) catch {
            return error.JsonSerializationFailed;
        };

        return start_pos + json.len;
    }
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

test "ConditionJson manual serialization" {
    // Test manual condition JSON building using bufPrint
    var buf: [512]u8 = undefined;

    const condition = ConditionJson{
        .type = "Accepted",
        .status = "True",
        .reason = "Accepted",
        .message = "Resource accepted",
        .lastTransitionTime = "2024-01-15T10:30:00Z",
        .observedGeneration = 42,
    };

    // Build JSON manually like writeConditionJson does
    const json = std.fmt.bufPrint(
        &buf,
        "{{\"type\":\"{s}\",\"status\":\"{s}\",\"reason\":\"{s}\",\"message\":\"{s}\",\"lastTransitionTime\":\"{s}\",\"observedGeneration\":{d}}}",
        .{
            condition.type,
            condition.status,
            condition.reason,
            condition.message,
            condition.lastTransitionTime,
            condition.observedGeneration,
        },
    ) catch unreachable;

    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"Accepted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"True\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"reason\":\"Accepted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"lastTransitionTime\":\"2024-01-15T10:30:00Z\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"observedGeneration\":42") != null);
}

test "GatewayClassStatusPatch manual serialization" {
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

    const status_mgr = try StatusManager.init(allocator, k8s_client, "test-controller");
    defer status_mgr.deinit();

    // Set up a condition
    status_mgr.gateway_class_conditions[0] = ConditionJson{
        .type = "Accepted",
        .status = "True",
        .reason = "Accepted",
        .message = "GatewayClass is accepted",
        .lastTransitionTime = "2024-01-15T10:30:00Z",
        .observedGeneration = 1,
    };

    // Build the JSON
    const json_len = try status_mgr.buildGatewayClassStatusJson(status_mgr.gateway_class_conditions[0..1]);
    const json = status_mgr.json_buffer[0..json_len];

    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"conditions\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"Accepted\"") != null);
}

test "GatewayStatusPatch manual serialization" {
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

    const status_mgr = try StatusManager.init(allocator, k8s_client, "test-controller");
    defer status_mgr.deinit();

    // Set up conditions
    status_mgr.gateway_conditions[0] = ConditionJson{
        .type = "Accepted",
        .status = "True",
        .reason = "Accepted",
        .message = "Gateway is valid",
        .lastTransitionTime = "2024-01-15T10:30:00Z",
        .observedGeneration = 3,
    };
    status_mgr.gateway_conditions[1] = ConditionJson{
        .type = "Programmed",
        .status = "True",
        .reason = "Programmed",
        .message = "Gateway has been programmed",
        .lastTransitionTime = "2024-01-15T10:30:01Z",
        .observedGeneration = 3,
    };

    // Build the JSON
    const json_len = try status_mgr.buildGatewayStatusJson(status_mgr.gateway_conditions[0..2], 3);
    const json = status_mgr.json_buffer[0..json_len];

    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"conditions\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"listeners\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"Accepted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"Programmed\"") != null);
}

test "writeConditionJson produces valid JSON" {
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

    const status_mgr = try StatusManager.init(allocator, k8s_client, "test-controller");
    defer status_mgr.deinit();

    const condition = ConditionJson{
        .type = "Accepted",
        .status = "True",
        .reason = "TestReason",
        .message = "Test message",
        .lastTransitionTime = "2024-01-15T10:30:00Z",
        .observedGeneration = 5,
    };

    const end_pos = try status_mgr.writeConditionJson(0, condition);
    const json = status_mgr.json_buffer[0..end_pos];

    // Verify JSON structure
    try std.testing.expect(json[0] == '{');
    try std.testing.expect(json[end_pos - 1] == '}');
    try std.testing.expect(std.mem.indexOf(u8, json, "\"observedGeneration\":5") != null);
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
