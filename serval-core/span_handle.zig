// lib/serval-core/span_handle.zig
//! Span Handle - Lightweight Trace Context Reference
//!
//! Shared type for distributed tracing context propagation.
//! Lives in serval-core (layer 0) so Context can use it.
//! TigerStyle: Fixed-size, no allocation, W3C compliant.

const std = @import("std");

/// Lightweight reference to a span.
/// Uses byte arrays to match W3C Trace Context and OTLP wire format.
/// TigerStyle: Fixed-size (32 bytes), no allocation.
pub const SpanHandle = struct {
    /// 128-bit trace identifier (16 bytes)
    trace_id: [16]u8 = [_]u8{0} ** 16,
    /// 64-bit span identifier (8 bytes)
    span_id: [8]u8 = [_]u8{0} ** 8,
    /// 64-bit parent span identifier (8 bytes, all zeros if root)
    parent_span_id: [8]u8 = [_]u8{0} ** 8,

    const Self = @This();

    /// Check if this handle refers to a valid span (non-zero trace_id)
    pub fn isValid(self: Self) bool {
        // TigerStyle: explicit check, no std.mem.allEqual for clarity
        for (self.trace_id) |byte| {
            if (byte != 0) return true;
        }
        return false;
    }

    /// Convert trace_id to hex string (32 chars)
    pub fn traceIdHex(self: *const Self, buf: *[32]u8) []const u8 {
        const charset = "0123456789abcdef";
        for (self.trace_id, 0..) |byte, i| {
            buf[i * 2] = charset[byte >> 4];
            buf[i * 2 + 1] = charset[byte & 0x0f];
        }
        const result = buf[0..32];
        std.debug.assert(result.len == 32); // Postcondition: always 32 hex chars
        return result;
    }

    /// Convert span_id to hex string (16 chars)
    pub fn spanIdHex(self: *const Self, buf: *[16]u8) []const u8 {
        const charset = "0123456789abcdef";
        for (self.span_id, 0..) |byte, i| {
            buf[i * 2] = charset[byte >> 4];
            buf[i * 2 + 1] = charset[byte & 0x0f];
        }
        const result = buf[0..16];
        std.debug.assert(result.len == 16); // Postcondition: always 16 hex chars
        return result;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "SpanHandle default is invalid" {
    const span = SpanHandle{};
    try std.testing.expect(!span.isValid());
}

test "SpanHandle with non-zero trace_id is valid" {
    const span = SpanHandle{
        .trace_id = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
        .span_id = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
    };
    try std.testing.expect(span.isValid());
}

test "SpanHandle hex encoding" {
    const span = SpanHandle{
        .trace_id = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
        .span_id = [_]u8{ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };

    var trace_buf: [32]u8 = undefined;
    var span_buf: [16]u8 = undefined;

    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", span.traceIdHex(&trace_buf));
    try std.testing.expectEqualStrings("fedcba9876543210", span.spanIdHex(&span_buf));
}
