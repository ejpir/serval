// lib/serval-core/time.zig
//! Time Utilities
//!
//! Centralized time functions for consistent timing across serval modules.
//! TigerStyle: Single source of truth for time operations.

const std = @import("std");
const posix = std.posix;

// =============================================================================
// Wall Clock Time
// =============================================================================

/// Get current time as nanoseconds since Unix epoch.
/// Uses CLOCK_REALTIME for wall-clock time (suitable for logging timestamps).
/// Returns 0 on clock failure (non-fatal, allows request to proceed).
/// TigerStyle: Graceful degradation on error.
pub fn realtimeNanos() i128 {
    const ts = posix.clock_gettime(.REALTIME) catch return 0;
    // TigerStyle: Assert precondition - REALTIME clock should represent valid Unix time.
    std.debug.assert(ts.sec >= 0);
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

// =============================================================================
// Monotonic Time (for duration measurement)
// =============================================================================

/// Get monotonic timestamp in nanoseconds.
/// Uses CLOCK_MONOTONIC for duration measurement (not affected by NTP adjustments).
/// Returns 0 if timing is unavailable (non-fatal).
/// TigerStyle: Monotonic time for intervals, realtime for timestamps.
pub fn monotonicNanos() u64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch return 0;
    // TigerStyle: Assert precondition - MONOTONIC clock starts at boot, always positive.
    std.debug.assert(ts.sec >= 0);
    const sec_ns: u64 = @as(u64, @intCast(ts.sec)) *% std.time.ns_per_s;
    const nsec: u64 = @intCast(ts.nsec);
    return sec_ns +% nsec;
}

/// Compute elapsed nanoseconds between two monotonic timestamps.
/// TigerStyle: Handles wraparound gracefully (returns 0 if end < start).
pub fn elapsedNanos(start_ns: u64, end_ns: u64) u64 {
    return if (end_ns >= start_ns) end_ns - start_ns else 0;
}

/// Compute elapsed nanoseconds from start to now.
/// Convenience wrapper for common pattern.
pub fn elapsedSince(start_ns: u64) u64 {
    return elapsedNanos(start_ns, monotonicNanos());
}

// =============================================================================
// Tests
// =============================================================================

test "realtimeNanos returns positive value" {
    const ts = realtimeNanos();
    // Should be after year 2020 (1577836800 seconds = 2020-01-01)
    try std.testing.expect(ts > 1577836800 * std.time.ns_per_s);
}

test "monotonicNanos returns positive value" {
    const ts = monotonicNanos();
    try std.testing.expect(ts > 0);
}

test "elapsedNanos handles normal case" {
    try std.testing.expectEqual(@as(u64, 100), elapsedNanos(50, 150));
    try std.testing.expectEqual(@as(u64, 0), elapsedNanos(0, 0));
}

test "elapsedNanos handles wraparound gracefully" {
    // If end < start (clock issue), return 0 rather than underflow
    try std.testing.expectEqual(@as(u64, 0), elapsedNanos(100, 50));
}

test "monotonicNanos is monotonic" {
    const t1 = monotonicNanos();
    const t2 = monotonicNanos();
    try std.testing.expect(t2 >= t1);
}
