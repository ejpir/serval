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

pub const StatusManager = @import("manager.zig").StatusManager;

pub const GatewayReconcileResult = @import("types.zig").GatewayReconcileResult;
pub const ListenerReconcileResult = @import("types.zig").ListenerReconcileResult;
pub const ConditionJson = @import("types.zig").ConditionJson;
pub const ListenerStatusJson = @import("types.zig").ListenerStatusJson;
pub const SupportedKindJson = @import("types.zig").SupportedKindJson;
pub const GatewayStatusPatch = @import("types.zig").GatewayStatusPatch;
pub const GatewayStatusJson = @import("types.zig").GatewayStatusJson;
pub const GatewayClassStatusPatch = @import("types.zig").GatewayClassStatusPatch;
pub const GatewayClassStatusJson = @import("types.zig").GatewayClassStatusJson;
pub const Date = @import("types.zig").Date;
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
