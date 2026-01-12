//! Gateway Status Types
//!
//! Type definitions for Gateway API status updates.
//! Includes reconcile results and JSON serialization types.
//!
//! TigerStyle: All types are explicit, no hidden allocations.

const std = @import("std");
const assert = std.debug.assert;

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
pub const GatewayStatusPatch = struct {
    status: GatewayStatusJson,
};

/// Gateway status JSON structure.
pub const GatewayStatusJson = struct {
    conditions: []const ConditionJson,
    listeners: []const ListenerStatusJson,
};

/// Listener status JSON structure.
pub const ListenerStatusJson = struct {
    name: []const u8,
    attachedRoutes: i32,
    supportedKinds: []const SupportedKindJson,
    conditions: []const ConditionJson,
};

/// Supported route kind reference.
pub const SupportedKindJson = struct {
    group: []const u8,
    kind: []const u8,
};

/// Condition JSON structure matching K8s metav1.Condition.
pub const ConditionJson = struct {
    type: []const u8,
    status: []const u8,
    reason: []const u8,
    message: []const u8,
    lastTransitionTime: []const u8,
    observedGeneration: i64,
};

/// JSON shape for GatewayClass status PATCH request body.
pub const GatewayClassStatusPatch = struct {
    status: GatewayClassStatusJson,
};

/// GatewayClass status JSON structure.
pub const GatewayClassStatusJson = struct {
    conditions: []const ConditionJson,
};

// =============================================================================
// Date Calculation Helper
// =============================================================================

/// Date components.
pub const Date = struct {
    year: u16,
    month: u8,
    day: u8,
};

/// Convert epoch days (days since 1970-01-01) to date.
/// Uses a simplified algorithm sufficient for timestamp generation.
pub fn epochDaysToDate(epoch_days: u64) Date {
    // Based on Howard Hinnant's algorithms for date conversion
    // Simplified version for our use case

    const z = epoch_days + 719468; // Days since 0000-03-01
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
// Unit Tests
// =============================================================================

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
