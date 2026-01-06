//! Shared Health State
//!
//! Lock-free atomic bitmap for tracking backend health status.
//! Designed for concurrent access from multiple I/O threads without contention.
//!
//! TigerStyle: Cache-line aligned to prevent false sharing between cores.
//! All operations are O(1) or O(popcount) with bounded loops.

const std = @import("std");
const config = @import("serval-core").config;

/// Maximum backends supported (must match config for bitmap width).
const MAX_UPSTREAMS: u8 = config.MAX_UPSTREAMS;

pub const UpstreamIndex = config.UpstreamIndex;

/// Cache line size on x86_64 and ARM64.
const CACHE_LINE_BYTES: usize = 64;

/// Lock-free shared health state for all backends.
///
/// Uses atomic u64 bitmap where bit N = 1 means backend N is healthy.
/// Failure/success counters track consecutive events for threshold decisions.
///
/// Layout: bitmap on its own cache line, counters follow.
/// The bitmap is the hot path (checked on every request), counters are
/// only updated when health state changes.
///
/// TigerStyle: Aligned to cache line to prevent false sharing when
/// different threads access the bitmap vs. counters simultaneously.
pub const SharedHealthState = struct {
    /// Health bitmap: bit N set = backend N healthy.
    /// All backends start healthy (all bits set).
    /// Aligned to cache line - this is the hot path for reads.
    health_bitmap: std.atomic.Value(u64) align(CACHE_LINE_BYTES),

    /// Consecutive failure counts per backend.
    /// Reset to 0 when backend becomes healthy.
    failure_counts: [MAX_UPSTREAMS]std.atomic.Value(u8),

    /// Consecutive success counts per backend.
    /// Reset to 0 when backend becomes unhealthy.
    success_counts: [MAX_UPSTREAMS]std.atomic.Value(u8),

    const Self = @This();

    // Compile-time verification of alignment constraints.
    comptime {
        // Bitmap must be cache-line aligned for atomic access without false sharing.
        std.debug.assert(@alignOf(Self) == CACHE_LINE_BYTES);
        // u6 must be sufficient to index all backends.
        std.debug.assert(MAX_UPSTREAMS <= 64);
    }

    /// Initialize with specified number of backends healthy.
    /// Only the first `backend_count` backends are marked healthy.
    /// TigerStyle: Explicit count prevents out-of-bounds when upstream list
    /// is smaller than MAX_UPSTREAMS.
    pub fn initWithCount(backend_count: u8) Self {
        std.debug.assert(backend_count <= MAX_UPSTREAMS);

        // Only set the first backend_count bits as healthy.
        // If backend_count is 0, bitmap is 0 (none healthy).
        // If backend_count is MAX_UPSTREAMS, bitmap is all 1s.
        const initial_bitmap: u64 = if (backend_count == 0)
            0
        else if (backend_count >= MAX_UPSTREAMS)
            std.math.maxInt(u64)
        else
            (@as(u64, 1) << @as(u6, @intCast(backend_count))) - 1;

        var self = Self{
            .health_bitmap = std.atomic.Value(u64).init(initial_bitmap),
            .failure_counts = undefined,
            .success_counts = undefined,
        };

        // Initialize all counters to zero.
        for (0..MAX_UPSTREAMS) |i| {
            self.failure_counts[i] = std.atomic.Value(u8).init(0);
            self.success_counts[i] = std.atomic.Value(u8).init(0);
        }

        return self;
    }

    /// Initialize with all MAX_UPSTREAMS backends healthy.
    /// Use initWithCount() when you have fewer backends.
    pub fn init() Self {
        return initWithCount(MAX_UPSTREAMS);
    }

    /// Check if backend is healthy.
    /// O(1) atomic load and bit test.
    pub fn isHealthy(self: *const Self, idx: UpstreamIndex) bool {
        std.debug.assert(idx < MAX_UPSTREAMS);

        const bitmap = self.health_bitmap.load(.acquire);
        const mask: u64 = @as(u64, 1) << idx;
        return (bitmap & mask) != 0;
    }

    /// Count number of healthy backends.
    /// O(1) using hardware popcount instruction.
    pub fn countHealthy(self: *const Self) u32 {
        const bitmap = self.health_bitmap.load(.acquire);
        return @popCount(bitmap);
    }

    /// Find first healthy backend, optionally excluding one.
    /// O(1) using hardware count-trailing-zeros instruction.
    /// Returns null if no healthy backend available.
    pub fn findFirstHealthy(self: *const Self, exclude_idx: ?UpstreamIndex) ?UpstreamIndex {
        var bitmap = self.health_bitmap.load(.acquire);

        // Clear the excluded backend's bit if specified.
        if (exclude_idx) |idx| {
            std.debug.assert(idx < MAX_UPSTREAMS);
            const exclude_mask: u64 = @as(u64, 1) << idx;
            bitmap &= ~exclude_mask;
        }

        // No healthy backends available.
        if (bitmap == 0) {
            return null;
        }

        // ctz gives position of least significant set bit.
        const first: u7 = @ctz(bitmap);

        // Bounds check: ctz of non-zero u64 always returns 0-63.
        std.debug.assert(first < 64);
        return @intCast(first);
    }

    /// Find the Nth healthy backend (0-indexed), wrapping around.
    /// O(popcount) - iterates through set bits.
    /// Returns null only if NO healthy backends exist.
    /// TigerStyle: Wraps n by healthy_count for round-robin selection.
    pub fn findNthHealthy(self: *const Self, n: u32) ?UpstreamIndex {
        var bitmap = self.health_bitmap.load(.acquire);

        // Check if any healthy backends exist.
        const healthy_count = @popCount(bitmap);
        if (healthy_count == 0) {
            return null;
        }

        // Wrap n to valid range for round-robin selection.
        const target = n % healthy_count;

        // Bounded loop: at most MAX_UPSTREAMS iterations (one per possible backend).
        var remaining = target;
        var iterations: u8 = 0;
        while (bitmap != 0 and iterations < MAX_UPSTREAMS) : (iterations += 1) {
            const lowest_bit_pos: u7 = @ctz(bitmap);

            if (remaining == 0) {
                // Found the Nth healthy backend.
                std.debug.assert(lowest_bit_pos < 64);
                return @intCast(lowest_bit_pos);
            }

            // Clear the lowest set bit and continue searching.
            bitmap &= bitmap - 1;
            remaining -= 1;
        }

        // Should not reach here if popcount check passed.
        std.debug.assert(false);
        return null;
    }

    /// Mark backend as healthy.
    /// Atomically sets bit in bitmap and resets failure counter.
    pub fn markHealthy(self: *Self, idx: UpstreamIndex) void {
        std.debug.assert(idx < MAX_UPSTREAMS);

        const mask: u64 = @as(u64, 1) << idx;

        // Set the health bit atomically.
        _ = self.health_bitmap.fetchOr(mask, .release);

        // Reset failure counter - backend recovered.
        self.failure_counts[idx].store(0, .release);
    }

    /// Mark backend as unhealthy.
    /// Atomically clears bit in bitmap and resets success counter.
    pub fn markUnhealthy(self: *Self, idx: UpstreamIndex) void {
        std.debug.assert(idx < MAX_UPSTREAMS);

        const mask: u64 = @as(u64, 1) << idx;

        // Clear the health bit atomically.
        _ = self.health_bitmap.fetchAnd(~mask, .release);

        // Reset success counter - backend failed.
        self.success_counts[idx].store(0, .release);
    }

    /// Increment failure count for backend.
    /// Returns new count (saturates at 255).
    pub fn incrementFailureCount(self: *Self, idx: UpstreamIndex) u8 {
        std.debug.assert(idx < MAX_UPSTREAMS);

        // Saturating add prevents overflow - counter stays at max.
        const prev = self.failure_counts[idx].fetchAdd(1, .acq_rel);
        if (prev == 255) {
            // Already at max, fetchAdd wrapped, restore.
            self.failure_counts[idx].store(255, .release);
            return 255;
        }
        return prev + 1;
    }

    /// Increment success count for backend.
    /// Returns new count (saturates at 255).
    pub fn incrementSuccessCount(self: *Self, idx: UpstreamIndex) u8 {
        std.debug.assert(idx < MAX_UPSTREAMS);

        // Saturating add prevents overflow - counter stays at max.
        const prev = self.success_counts[idx].fetchAdd(1, .acq_rel);
        if (prev == 255) {
            // Already at max, fetchAdd wrapped, restore.
            self.success_counts[idx].store(255, .release);
            return 255;
        }
        return prev + 1;
    }

    /// Get current failure count for backend.
    pub fn getFailureCount(self: *const Self, idx: UpstreamIndex) u8 {
        std.debug.assert(idx < MAX_UPSTREAMS);
        return self.failure_counts[idx].load(.acquire);
    }

    /// Get current success count for backend.
    pub fn getSuccessCount(self: *const Self, idx: UpstreamIndex) u8 {
        std.debug.assert(idx < MAX_UPSTREAMS);
        return self.success_counts[idx].load(.acquire);
    }

    /// Reset all backends to healthy state.
    /// Used for re-initialization or testing.
    pub fn reset(self: *Self) void {
        // All backends healthy.
        self.health_bitmap.store(std.math.maxInt(u64), .release);

        // Reset all counters.
        for (0..MAX_UPSTREAMS) |i| {
            self.failure_counts[i].store(0, .release);
            self.success_counts[i].store(0, .release);
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "SharedHealthState alignment" {
    // Verify cache-line alignment for false sharing prevention.
    try std.testing.expectEqual(@as(usize, CACHE_LINE_BYTES), @alignOf(SharedHealthState));
}

test "SharedHealthState init starts all healthy" {
    const state = SharedHealthState.init();
    try std.testing.expectEqual(@as(u32, MAX_UPSTREAMS), state.countHealthy());
    try std.testing.expect(state.isHealthy(0));
    try std.testing.expect(state.isHealthy(MAX_UPSTREAMS - 1));
}

test "SharedHealthState initWithCount sets correct backends" {
    // Test with 2 backends - the bug case.
    const state2 = SharedHealthState.initWithCount(2);
    try std.testing.expectEqual(@as(u32, 2), state2.countHealthy());
    try std.testing.expect(state2.isHealthy(0));
    try std.testing.expect(state2.isHealthy(1));
    try std.testing.expect(!state2.isHealthy(2)); // This was the bug!
    try std.testing.expect(!state2.isHealthy(63));

    // findNthHealthy wraps around, only returns 0 or 1.
    try std.testing.expectEqual(@as(?UpstreamIndex, 0), state2.findNthHealthy(0));
    try std.testing.expectEqual(@as(?UpstreamIndex, 1), state2.findNthHealthy(1));
    try std.testing.expectEqual(@as(?UpstreamIndex, 0), state2.findNthHealthy(2)); // 2 % 2 = 0

    // Test with 0 backends.
    const state0 = SharedHealthState.initWithCount(0);
    try std.testing.expectEqual(@as(u32, 0), state0.countHealthy());
    try std.testing.expect(!state0.isHealthy(0));

    // Test with 1 backend.
    const state1 = SharedHealthState.initWithCount(1);
    try std.testing.expectEqual(@as(u32, 1), state1.countHealthy());
    try std.testing.expect(state1.isHealthy(0));
    try std.testing.expect(!state1.isHealthy(1));

    // Test with MAX_UPSTREAMS backends (max).
    const state_max = SharedHealthState.initWithCount(MAX_UPSTREAMS);
    try std.testing.expectEqual(@as(u32, MAX_UPSTREAMS), state_max.countHealthy());
    try std.testing.expect(state_max.isHealthy(0));
    try std.testing.expect(state_max.isHealthy(MAX_UPSTREAMS - 1));
}

test "SharedHealthState mark unhealthy" {
    var state = SharedHealthState.init();

    state.markUnhealthy(5);

    try std.testing.expect(!state.isHealthy(5));
    try std.testing.expect(state.isHealthy(4));
    try std.testing.expect(state.isHealthy(6));
    try std.testing.expectEqual(@as(u32, 63), state.countHealthy());
}

test "SharedHealthState mark healthy" {
    var state = SharedHealthState.init();

    state.markUnhealthy(5);
    try std.testing.expect(!state.isHealthy(5));

    state.markHealthy(5);
    try std.testing.expect(state.isHealthy(5));
    try std.testing.expectEqual(@as(u32, MAX_UPSTREAMS), state.countHealthy());
}

test "SharedHealthState findFirstHealthy" {
    var state = SharedHealthState.init();

    // First healthy should be 0.
    try std.testing.expectEqual(@as(?UpstreamIndex, 0), state.findFirstHealthy(null));

    // With 0 excluded, should be 1.
    try std.testing.expectEqual(@as(?UpstreamIndex, 1), state.findFirstHealthy(0));

    // Mark 0-2 unhealthy.
    state.markUnhealthy(0);
    state.markUnhealthy(1);
    state.markUnhealthy(2);

    // First healthy should now be 3.
    try std.testing.expectEqual(@as(?UpstreamIndex, 3), state.findFirstHealthy(null));
}

test "SharedHealthState findFirstHealthy returns null when all unhealthy" {
    var state = SharedHealthState.init();

    // Mark all unhealthy.
    for (0..MAX_UPSTREAMS) |i| {
        state.markUnhealthy(@intCast(i));
    }

    try std.testing.expectEqual(@as(?UpstreamIndex, null), state.findFirstHealthy(null));
}

test "SharedHealthState findNthHealthy" {
    var state = SharedHealthState.init();

    // Mark some unhealthy: 0, 2, 4 unhealthy; 1, 3, 5+ healthy.
    state.markUnhealthy(0);
    state.markUnhealthy(2);
    state.markUnhealthy(4);

    // Healthy backends: 1, 3, 5, 6, 7, ...
    try std.testing.expectEqual(@as(?UpstreamIndex, 1), state.findNthHealthy(0));
    try std.testing.expectEqual(@as(?UpstreamIndex, 3), state.findNthHealthy(1));
    try std.testing.expectEqual(@as(?UpstreamIndex, 5), state.findNthHealthy(2));
    try std.testing.expectEqual(@as(?UpstreamIndex, 6), state.findNthHealthy(3));
}

test "SharedHealthState findNthHealthy wraps around" {
    var state = SharedHealthState.init();

    // Only keep 3 backends healthy.
    for (3..MAX_UPSTREAMS) |i| {
        state.markUnhealthy(@intCast(i));
    }

    try std.testing.expectEqual(@as(u32, 3), state.countHealthy());
    try std.testing.expectEqual(@as(?UpstreamIndex, 0), state.findNthHealthy(0));
    try std.testing.expectEqual(@as(?UpstreamIndex, 1), state.findNthHealthy(1));
    try std.testing.expectEqual(@as(?UpstreamIndex, 2), state.findNthHealthy(2));
    // Wraps around: 3 % 3 = 0, 100 % 3 = 1
    try std.testing.expectEqual(@as(?UpstreamIndex, 0), state.findNthHealthy(3));
    try std.testing.expectEqual(@as(?UpstreamIndex, 1), state.findNthHealthy(100));
}

test "SharedHealthState failure counter increment" {
    var state = SharedHealthState.init();

    try std.testing.expectEqual(@as(u8, 0), state.getFailureCount(5));
    try std.testing.expectEqual(@as(u8, 1), state.incrementFailureCount(5));
    try std.testing.expectEqual(@as(u8, 2), state.incrementFailureCount(5));
    try std.testing.expectEqual(@as(u8, 2), state.getFailureCount(5));
}

test "SharedHealthState success counter increment" {
    var state = SharedHealthState.init();

    try std.testing.expectEqual(@as(u8, 0), state.getSuccessCount(10));
    try std.testing.expectEqual(@as(u8, 1), state.incrementSuccessCount(10));
    try std.testing.expectEqual(@as(u8, 2), state.incrementSuccessCount(10));
    try std.testing.expectEqual(@as(u8, 2), state.getSuccessCount(10));
}

test "SharedHealthState markHealthy resets failure counter" {
    var state = SharedHealthState.init();

    _ = state.incrementFailureCount(7);
    _ = state.incrementFailureCount(7);
    try std.testing.expectEqual(@as(u8, 2), state.getFailureCount(7));

    state.markHealthy(7);
    try std.testing.expectEqual(@as(u8, 0), state.getFailureCount(7));
}

test "SharedHealthState markUnhealthy resets success counter" {
    var state = SharedHealthState.init();

    _ = state.incrementSuccessCount(7);
    _ = state.incrementSuccessCount(7);
    try std.testing.expectEqual(@as(u8, 2), state.getSuccessCount(7));

    state.markUnhealthy(7);
    try std.testing.expectEqual(@as(u8, 0), state.getSuccessCount(7));
}

test "SharedHealthState reset" {
    var state = SharedHealthState.init();

    // Mess up state.
    state.markUnhealthy(0);
    state.markUnhealthy(10);
    state.markUnhealthy(63);
    _ = state.incrementFailureCount(5);
    _ = state.incrementSuccessCount(20);

    try std.testing.expectEqual(@as(u32, 61), state.countHealthy());

    // Reset should restore all healthy and zero counters.
    state.reset();

    try std.testing.expectEqual(@as(u32, MAX_UPSTREAMS), state.countHealthy());
    try std.testing.expect(state.isHealthy(0));
    try std.testing.expect(state.isHealthy(10));
    try std.testing.expect(state.isHealthy(MAX_UPSTREAMS - 1));
    try std.testing.expectEqual(@as(u8, 0), state.getFailureCount(5));
    try std.testing.expectEqual(@as(u8, 0), state.getSuccessCount(20));
}
