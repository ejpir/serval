//! Unified Health State
//!
//! Combined health bitmap and threshold-based state transitions.
//! Designed to be embedded directly in handlers without pointers.
//! TigerStyle: Cache-line aligned, no allocation, bounded loops.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

pub const MAX_UPSTREAMS: u8 = config.MAX_UPSTREAMS;
pub const UpstreamIndex = config.UpstreamIndex;

/// Cache line size for alignment to prevent false sharing.
const CACHE_LINE_BYTES: usize = 64;

/// Unified health state with embedded threshold tracking.
/// Embeddable in handlers without self-referential pointers.
pub const HealthState = struct {
    /// Health bitmap: bit N set = backend N healthy.
    health_bitmap: std.atomic.Value(u64) align(CACHE_LINE_BYTES),

    /// Consecutive failure counts per backend.
    failure_counts: [MAX_UPSTREAMS]u8,

    /// Consecutive success counts per backend.
    success_counts: [MAX_UPSTREAMS]u8,

    /// Number of configured backends (prevents out-of-bounds).
    backend_count: u8,

    /// Consecutive failures required to mark unhealthy.
    unhealthy_threshold: u8,

    /// Consecutive successes required to mark healthy.
    healthy_threshold: u8,

    // Compile-time verification
    comptime {
        assert(@alignOf(HealthState) == CACHE_LINE_BYTES);
        assert(MAX_UPSTREAMS <= 64); // Bitmap is u64
    }

    /// Compute bitmask for first `count` backends.
    /// Returns mask where bits 0..(count-1) are set.
    fn backendMask(count: u8) u64 {
        assert(count <= MAX_UPSTREAMS);
        if (count == 0) return 0;
        if (count >= 64) return std.math.maxInt(u64);
        return (@as(u64, 1) << @as(u6, @intCast(count))) - 1;
    }

    /// Initialize with backend count and thresholds.
    /// Only first backend_count backends start healthy.
    pub fn init(backend_count: u8, unhealthy_threshold: u8, healthy_threshold: u8) HealthState {
        assert(backend_count <= MAX_UPSTREAMS);
        assert(unhealthy_threshold > 0);
        assert(healthy_threshold > 0);

        return HealthState{
            .health_bitmap = std.atomic.Value(u64).init(backendMask(backend_count)),
            .failure_counts = std.mem.zeroes([MAX_UPSTREAMS]u8),
            .success_counts = std.mem.zeroes([MAX_UPSTREAMS]u8),
            .backend_count = backend_count,
            .unhealthy_threshold = unhealthy_threshold,
            .healthy_threshold = healthy_threshold,
        };
    }

    /// Record successful request/probe for backend.
    /// Resets failure counter; increments success counter if unhealthy.
    /// Transitions to healthy when success threshold is reached.
    pub inline fn recordSuccess(self: *HealthState, idx: UpstreamIndex) void {
        assert(idx < self.backend_count);

        // Reset failure counter on any success
        self.failure_counts[idx] = 0;

        // Fast path: already healthy
        if (self.isHealthy(idx)) return;

        // Increment success counter (saturating)
        const new_count = self.success_counts[idx] +| 1;
        self.success_counts[idx] = new_count;

        // Transition to healthy if threshold reached
        if (new_count >= self.healthy_threshold) {
            self.markHealthy(idx);
            self.success_counts[idx] = 0;
        }
    }

    /// Record failed request/probe for backend.
    /// Resets success counter; increments failure counter if healthy.
    /// Transitions to unhealthy when failure threshold is reached.
    pub inline fn recordFailure(self: *HealthState, idx: UpstreamIndex) void {
        assert(idx < self.backend_count);

        // Reset success counter on any failure
        self.success_counts[idx] = 0;

        // Fast path: already unhealthy
        if (!self.isHealthy(idx)) return;

        // Increment failure counter (saturating)
        const new_count = self.failure_counts[idx] +| 1;
        self.failure_counts[idx] = new_count;

        // Transition to unhealthy if threshold reached
        if (new_count >= self.unhealthy_threshold) {
            self.markUnhealthy(idx);
            self.failure_counts[idx] = 0;
        }
    }

    /// Check if backend is healthy (atomic read).
    pub inline fn isHealthy(self: *const HealthState, idx: UpstreamIndex) bool {
        assert(idx < self.backend_count);
        const bitmap = self.health_bitmap.load(.acquire);
        const mask: u64 = @as(u64, 1) << idx;
        return (bitmap & mask) != 0;
    }

    /// Count healthy backends (atomic read).
    pub fn countHealthy(self: *const HealthState) u32 {
        const bitmap = self.health_bitmap.load(.acquire);
        return @popCount(bitmap & backendMask(self.backend_count));
    }

    /// Find Nth healthy backend, wrapping around.
    /// Returns null only if no healthy backends exist.
    /// Used for round-robin selection across healthy backends.
    pub fn findNthHealthy(self: *const HealthState, n: u32) ?UpstreamIndex {
        var bitmap = self.health_bitmap.load(.acquire) & backendMask(self.backend_count);

        const healthy_count = @popCount(bitmap);
        if (healthy_count == 0) return null;

        var remaining = n % healthy_count;
        var iterations: u8 = 0;

        while (bitmap != 0 and iterations < MAX_UPSTREAMS) : (iterations += 1) {
            const lowest_bit_pos: u7 = @ctz(bitmap);
            if (remaining == 0) {
                assert(lowest_bit_pos < 64);
                return @intCast(lowest_bit_pos);
            }
            bitmap &= bitmap - 1;
            remaining -= 1;
        }

        assert(false);
        return null;
    }

    /// Find first healthy backend, optionally excluding one.
    /// Useful for failover when current backend fails.
    pub fn findFirstHealthy(self: *const HealthState, exclude_idx: ?UpstreamIndex) ?UpstreamIndex {
        var bitmap = self.health_bitmap.load(.acquire) & backendMask(self.backend_count);

        if (exclude_idx) |idx| {
            assert(idx < self.backend_count);
            bitmap &= ~(@as(u64, 1) << idx);
        }

        if (bitmap == 0) return null;

        const first: u7 = @ctz(bitmap);
        assert(first < 64);
        return @intCast(first);
    }

    /// Mark backend as healthy (atomic set bit).
    fn markHealthy(self: *HealthState, idx: UpstreamIndex) void {
        assert(idx < self.backend_count);
        const mask: u64 = @as(u64, 1) << idx;
        _ = self.health_bitmap.fetchOr(mask, .release);
    }

    /// Mark backend as unhealthy (atomic clear bit).
    fn markUnhealthy(self: *HealthState, idx: UpstreamIndex) void {
        assert(idx < self.backend_count);
        const mask: u64 = @as(u64, 1) << idx;
        _ = self.health_bitmap.fetchAnd(~mask, .release);
    }

    /// Reset all backends to healthy and clear counters.
    pub fn reset(self: *HealthState) void {
        self.health_bitmap.store(backendMask(self.backend_count), .release);
        self.failure_counts = std.mem.zeroes([MAX_UPSTREAMS]u8);
        self.success_counts = std.mem.zeroes([MAX_UPSTREAMS]u8);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "HealthState alignment" {
    try std.testing.expectEqual(@as(usize, CACHE_LINE_BYTES), @alignOf(HealthState));
}

test "HealthState init with backend count" {
    const state = HealthState.init(3, 3, 2);

    try std.testing.expectEqual(@as(u32, 3), state.countHealthy());
    try std.testing.expect(state.isHealthy(0));
    try std.testing.expect(state.isHealthy(1));
    try std.testing.expect(state.isHealthy(2));
    try std.testing.expectEqual(@as(u8, 3), state.unhealthy_threshold);
    try std.testing.expectEqual(@as(u8, 2), state.healthy_threshold);
}

test "HealthState init with zero backends" {
    const state = HealthState.init(0, 3, 2);
    try std.testing.expectEqual(@as(u32, 0), state.countHealthy());
}

test "HealthState init with max backends" {
    const state = HealthState.init(MAX_UPSTREAMS, 3, 2);
    try std.testing.expectEqual(@as(u32, MAX_UPSTREAMS), state.countHealthy());
    try std.testing.expect(state.isHealthy(0));
    try std.testing.expect(state.isHealthy(MAX_UPSTREAMS - 1));
}

test "HealthState recordFailure transitions after threshold" {
    var state = HealthState.init(3, 3, 2);

    // Start healthy
    try std.testing.expect(state.isHealthy(0));

    // First two failures - still healthy
    state.recordFailure(0);
    try std.testing.expect(state.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 1), state.failure_counts[0]);

    state.recordFailure(0);
    try std.testing.expect(state.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 2), state.failure_counts[0]);

    // Third failure - reaches threshold, now unhealthy
    state.recordFailure(0);
    try std.testing.expect(!state.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 0), state.failure_counts[0]);
}

test "HealthState recordSuccess transitions after threshold" {
    var state = HealthState.init(3, 3, 2);

    // Mark backend unhealthy via failures
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(0);
    try std.testing.expect(!state.isHealthy(0));

    // First success - still unhealthy
    state.recordSuccess(0);
    try std.testing.expect(!state.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 1), state.success_counts[0]);

    // Second success - reaches threshold, now healthy
    state.recordSuccess(0);
    try std.testing.expect(state.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 0), state.success_counts[0]);
}

test "HealthState success resets failure counter" {
    var state = HealthState.init(3, 3, 2);

    // Accumulate failures
    state.recordFailure(0);
    state.recordFailure(0);
    try std.testing.expectEqual(@as(u8, 2), state.failure_counts[0]);

    // Single success resets failure counter
    state.recordSuccess(0);
    try std.testing.expectEqual(@as(u8, 0), state.failure_counts[0]);
}

test "HealthState failure resets success counter" {
    var state = HealthState.init(3, 3, 2);

    // Mark unhealthy first
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(0);
    try std.testing.expect(!state.isHealthy(0));

    // Accumulate successes
    state.recordSuccess(0);
    try std.testing.expectEqual(@as(u8, 1), state.success_counts[0]);

    // Single failure resets success counter
    state.recordFailure(0);
    try std.testing.expectEqual(@as(u8, 0), state.success_counts[0]);
}

test "HealthState findNthHealthy" {
    var state = HealthState.init(5, 3, 2);

    // Mark some unhealthy: 0, 2 unhealthy; 1, 3, 4 healthy
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(2);
    state.recordFailure(2);
    state.recordFailure(2);

    try std.testing.expectEqual(@as(?UpstreamIndex, 1), state.findNthHealthy(0));
    try std.testing.expectEqual(@as(?UpstreamIndex, 3), state.findNthHealthy(1));
    try std.testing.expectEqual(@as(?UpstreamIndex, 4), state.findNthHealthy(2));
    // Wraps around
    try std.testing.expectEqual(@as(?UpstreamIndex, 1), state.findNthHealthy(3));
}

test "HealthState findFirstHealthy" {
    var state = HealthState.init(5, 3, 2);

    try std.testing.expectEqual(@as(?UpstreamIndex, 0), state.findFirstHealthy(null));
    try std.testing.expectEqual(@as(?UpstreamIndex, 1), state.findFirstHealthy(0));

    // Mark 0-1 unhealthy
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(1);
    state.recordFailure(1);
    state.recordFailure(1);

    try std.testing.expectEqual(@as(?UpstreamIndex, 2), state.findFirstHealthy(null));
}

test "HealthState findFirstHealthy returns null when all unhealthy" {
    var state = HealthState.init(2, 3, 2);

    // Mark all unhealthy
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(1);
    state.recordFailure(1);
    state.recordFailure(1);

    try std.testing.expectEqual(@as(?UpstreamIndex, null), state.findFirstHealthy(null));
}

test "HealthState reset" {
    var state = HealthState.init(3, 3, 2);

    // Mark all unhealthy
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(1);
    state.recordFailure(1);
    state.recordFailure(1);

    try std.testing.expectEqual(@as(u32, 1), state.countHealthy());

    // Reset
    state.reset();

    try std.testing.expectEqual(@as(u32, 3), state.countHealthy());
    try std.testing.expect(state.isHealthy(0));
    try std.testing.expect(state.isHealthy(1));
    try std.testing.expect(state.isHealthy(2));
}

test "HealthState fast path when already in target state" {
    var state = HealthState.init(3, 3, 2);

    // Already healthy - recordSuccess should be fast path
    try std.testing.expect(state.isHealthy(0));
    state.recordSuccess(0);
    // Success counter should not increment when already healthy
    try std.testing.expectEqual(@as(u8, 0), state.success_counts[0]);

    // Mark unhealthy
    state.recordFailure(0);
    state.recordFailure(0);
    state.recordFailure(0);
    try std.testing.expect(!state.isHealthy(0));

    // Already unhealthy - recordFailure should be fast path
    state.recordFailure(0);
    // Failure counter should not increment when already unhealthy
    try std.testing.expectEqual(@as(u8, 0), state.failure_counts[0]);
}
