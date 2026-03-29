//! Gateway Status Module
//!
//! Manages status updates for Gateway API resources (Gateway, GatewayClass).
//! Uses K8s API PATCH to update status subresources with conditions.
//!
//! TigerStyle: Pre-allocated buffers, bounded operations, explicit error handling.

const std = @import("std");
const assert = std.debug.assert;

// =============================================================================
// Public Exports
// =============================================================================

/// Manager for Gateway and GatewayClass status updates.
/// Uses preallocated buffers to build status JSON and Kubernetes API paths, then PATCHes status subresources.
/// Public methods are best-effort: they log failures and surface client, serialization, or path errors.
pub const StatusManager = @import("manager.zig").StatusManager;

/// Reconcile result for a Gateway resource.
/// Captures accepted and programmed conditions, observed generation, and per-listener results.
/// Re-exported from `types.zig`; slice fields refer to caller-owned data.
pub const GatewayReconcileResult = @import("types.zig").GatewayReconcileResult;
/// Reconcile result for an individual Gateway listener.
/// Captures the accepted, programmed, and resolved-reference state used to build listener status.
/// Re-exported from `types.zig`; string fields are caller-owned slices.
pub const ListenerReconcileResult = @import("types.zig").ListenerReconcileResult;
/// Kubernetes-style condition object used in status JSON.
/// Mirrors the fields needed by `metav1.Condition`, including type, status, reason, message,
/// transition time, and observed generation.
pub const ConditionJson = @import("types.zig").ConditionJson;
/// Per-listener status entry included in Gateway status JSON.
/// Carries the listener name, attached route count, supported kinds, and conditions.
/// Re-exported from `types.zig` for building Kubernetes status responses.
pub const ListenerStatusJson = @import("types.zig").ListenerStatusJson;
/// Route kind reference advertised by a listener in Gateway status.
/// Each entry identifies a supported API group and kind pair.
/// Re-exported from `types.zig` and used to report `HTTPRoute` support.
pub const SupportedKindJson = @import("types.zig").SupportedKindJson;
/// JSON payload shape for a Gateway status PATCH request.
/// Contains the status object sent to the Kubernetes Gateway status subresource.
/// Re-exported from `types.zig` for callers that serialize Gateway updates.
pub const GatewayStatusPatch = @import("types.zig").GatewayStatusPatch;
/// JSON payload shape for a Gateway status PATCH request.
/// Contains the status object sent to the Kubernetes Gateway status subresource.
/// Re-exported from `types.zig` for callers that serialize Gateway updates.
pub const GatewayStatusJson = @import("types.zig").GatewayStatusJson;
/// JSON payload shape for a GatewayClass status PATCH request.
/// Wraps the `status` object expected by the Kubernetes Gateway API.
/// Re-exported from `types.zig` for callers that serialize status updates.
pub const GatewayClassStatusPatch = @import("types.zig").GatewayClassStatusPatch;
/// JSON payload shape for a GatewayClass status PATCH request.
/// Wraps the `status` object expected by the Kubernetes Gateway API.
/// Re-exported from `types.zig` for callers that serialize status updates.
pub const GatewayClassStatusJson = @import("types.zig").GatewayClassStatusJson;
/// Calendar date components used by the status timestamp helper.
/// Represents a year, month, and day in the proleptic Gregorian calendar.
/// The fields are plain values; callers are responsible for providing valid dates.
pub const Date = @import("types.zig").Date;
/// Re-export of `types.zig`'s epoch-day to calendar-date conversion helper.
/// Converts days since `1970-01-01` into a `Date` value for timestamp generation.
/// Intended for UTC-style status timestamps and does not perform time-zone handling.
pub const epochDaysToDate = @import("types.zig").epochDaysToDate;

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
pub const MAX_LISTENERS: u8 = 16;

/// Maximum conditions per status object.
pub const MAX_CONDITIONS: u8 = 8;

/// RFC3339 timestamp length (e.g., "2024-01-15T10:30:00Z").
pub const RFC3339_TIMESTAMP_LEN: u8 = 20;

// =============================================================================
// Error Types
// =============================================================================

/// Error set returned by Gateway status helpers in this module.
/// `OutOfMemory` indicates allocator failure, `JsonSerializationFailed` indicates JSON construction failed,
/// and `PathTooLong` indicates a generated Kubernetes API path did not fit in the fixed buffer.
pub const StatusError = error{
    OutOfMemory,
    JsonSerializationFailed,
    PathTooLong,
};

// =============================================================================
// Unit Tests
// =============================================================================

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

// Include tests from submodules
test {
    _ = @import("types.zig");
    _ = @import("manager.zig");
}
