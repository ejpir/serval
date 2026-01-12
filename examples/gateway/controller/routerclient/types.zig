//! Router Client Types
//!
//! Type definitions for router client operations.
//!
//! TigerStyle: Explicit result types, clear semantics.

const std = @import("std");

// ============================================================================
// Push Result (TigerStyle: Explicit result type)
// ============================================================================

/// Result of pushing config to multiple router endpoints.
/// TigerStyle: Explicit success/failure counts for partial failures.
pub const PushResult = struct {
    /// Number of successful pushes.
    success_count: u8,
    /// Number of failed pushes.
    failure_count: u8,
    /// Total endpoints attempted.
    total: u8,

    /// Check if push was fully successful.
    pub fn isFullSuccess(self: PushResult) bool {
        return self.failure_count == 0 and self.success_count > 0;
    }

    /// Check if any pushes succeeded (partial success).
    pub fn hasAnySuccess(self: PushResult) bool {
        return self.success_count > 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "PushResult isFullSuccess" {
    // Full success
    const success = PushResult{ .success_count = 3, .failure_count = 0, .total = 3 };
    try std.testing.expect(success.isFullSuccess());
    try std.testing.expect(success.hasAnySuccess());

    // Partial success
    const partial = PushResult{ .success_count = 2, .failure_count = 1, .total = 3 };
    try std.testing.expect(!partial.isFullSuccess());
    try std.testing.expect(partial.hasAnySuccess());

    // Total failure
    const failure = PushResult{ .success_count = 0, .failure_count = 3, .total = 3 };
    try std.testing.expect(!failure.isFullSuccess());
    try std.testing.expect(!failure.hasAnySuccess());

    // Empty (config unchanged)
    const empty = PushResult{ .success_count = 0, .failure_count = 0, .total = 0 };
    try std.testing.expect(!empty.isFullSuccess()); // No success with 0 total
    try std.testing.expect(!empty.hasAnySuccess());
}
