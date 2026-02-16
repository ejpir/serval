// lib/serval-core/time.zig
//! Time Utilities
//!
//! Centralized time functions for consistent timing across serval modules.
//! TigerStyle: Single source of truth for time operations.

const std = @import("std");
const assert = std.debug.assert;

// =============================================================================
// Time Unit Constants
// =============================================================================

/// Nanoseconds per second (1,000,000,000).
pub const ns_per_s: u64 = std.time.ns_per_s;

/// Nanoseconds per millisecond (1,000,000).
pub const ns_per_ms: u64 = std.time.ns_per_ms;

// =============================================================================
// Time Unit Conversions
// =============================================================================

/// Convert seconds to nanoseconds.
/// TigerStyle: Explicit conversion function, no magic multiplication.
pub inline fn secondsToNanos(seconds: u64) u64 {
    return seconds * ns_per_s;
}

/// Convert milliseconds to nanoseconds.
pub inline fn millisToNanos(millis: u64) u64 {
    return millis * ns_per_ms;
}

/// Convert nanoseconds to seconds (truncating).
pub inline fn nanosToSeconds(nanos: u64) u64 {
    return nanos / ns_per_s;
}

/// Convert nanoseconds to milliseconds (truncating).
pub inline fn nanosToMillis(nanos: u64) u64 {
    return nanos / ns_per_ms;
}

/// Convert i128 nanoseconds to u64 seconds (for realtimeNanos timestamps).
/// Returns 0 for negative values (graceful degradation).
/// TigerStyle: Safe conversion with explicit handling of edge cases.
pub inline fn nanosToSecondsI128(nanos: i128) u64 {
    if (nanos <= 0) return 0;
    return @intCast(@divFloor(nanos, ns_per_s));
}

// =============================================================================
// Sleep
// =============================================================================

/// Sleep for the specified number of nanoseconds.
/// TigerStyle: Single sleep function, hides sec/nsec split.
pub fn sleep(duration_ns: u64) void {
    std.Io.sleep(
        std.Options.debug_io,
        .fromNanoseconds(@intCast(duration_ns)),
        .awake,
    ) catch {};
}

// =============================================================================
// Wall Clock Time
// =============================================================================

/// Get current time as nanoseconds since Unix epoch.
/// Uses CLOCK_REALTIME for wall-clock time (suitable for logging timestamps).
/// Returns 0 on clock failure (non-fatal, allows request to proceed).
/// TigerStyle: Graceful degradation on error.
pub fn realtimeNanos() i128 {
    const ts = std.Io.Clock.real.now(std.Options.debug_io);
    // TigerStyle: Assert precondition - REALTIME clock should represent valid Unix time.
    assert(ts.nanoseconds >= 0);
    return @intCast(ts.nanoseconds);
}

// =============================================================================
// Monotonic Time (for duration measurement)
// =============================================================================

/// Get monotonic timestamp in nanoseconds.
/// Uses CLOCK_MONOTONIC for duration measurement (not affected by NTP adjustments).
/// Returns 0 if timing is unavailable (non-fatal).
/// TigerStyle: Monotonic time for intervals, realtime for timestamps.
pub fn monotonicNanos() u64 {
    const ts = std.Io.Clock.awake.now(std.Options.debug_io);
    // TigerStyle: Assert precondition - monotonic clock should be non-negative.
    assert(ts.nanoseconds >= 0);
    return @intCast(ts.nanoseconds);
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
    try std.testing.expect(ts > 1577836800 * ns_per_s);
}

test "secondsToNanos converts correctly" {
    try std.testing.expectEqual(@as(u64, 5_000_000_000), secondsToNanos(5));
    try std.testing.expectEqual(@as(u64, 0), secondsToNanos(0));
}

test "millisToNanos converts correctly" {
    try std.testing.expectEqual(@as(u64, 5_000_000), millisToNanos(5));
    try std.testing.expectEqual(@as(u64, 1_000_000_000), millisToNanos(1000));
}

test "nanosToSeconds converts correctly" {
    try std.testing.expectEqual(@as(u64, 5), nanosToSeconds(5_000_000_000));
    try std.testing.expectEqual(@as(u64, 0), nanosToSeconds(999_999_999));
}

test "nanosToMillis converts correctly" {
    try std.testing.expectEqual(@as(u64, 5), nanosToMillis(5_000_000));
    try std.testing.expectEqual(@as(u64, 1000), nanosToMillis(1_000_000_000));
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
