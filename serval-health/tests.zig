//! serval-health/tests.zig
//! Comprehensive Tests for HealthState
//!
//! Tests cover basic operations, threshold transitions, concurrent reads,
//! and boundary conditions.
//! TigerStyle: Bounded iterations, explicit types, assertions on results.

const std = @import("std");
const testing = std.testing;
const Thread = std.Thread;

const health_state = @import("health_state.zig");
const HealthState = health_state.HealthState;
const UpstreamIndex = health_state.UpstreamIndex;
const MAX_UPSTREAMS = health_state.MAX_UPSTREAMS;

// =============================================================================
// Constants
// =============================================================================

/// Number of threads for concurrent tests.
/// TigerStyle: Explicit constant, enough to stress atomic reads.
const THREAD_COUNT: u32 = 8;

/// Iterations per thread for concurrent tests.
/// TigerStyle: Bounded iterations, 1000+ to expose race conditions.
const ITERATIONS_PER_THREAD: u32 = 1000;

/// Maximum backend index (MAX_UPSTREAMS - 1).
const MAX_BACKEND_IDX: UpstreamIndex = MAX_UPSTREAMS - 1;

// =============================================================================
// Basic State Tests
// =============================================================================

test "all backends start healthy" {
    const hs = HealthState.init(MAX_UPSTREAMS, 3, 2);

    // Count should equal MAX_UPSTREAMS
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());

    // Every backend should be healthy
    for (0..MAX_UPSTREAMS) |i| {
        const idx: UpstreamIndex = @intCast(i);
        try testing.expect(hs.isHealthy(idx));
    }
}

test "initWithCount sets correct backends" {
    // Test with 2 backends
    const state2 = HealthState.init(2, 3, 2);
    try testing.expectEqual(@as(u32, 2), state2.countHealthy());
    try testing.expect(state2.isHealthy(0));
    try testing.expect(state2.isHealthy(1));

    // findNthHealthy wraps around, only returns 0 or 1.
    try testing.expectEqual(@as(?UpstreamIndex, 0), state2.findNthHealthy(0));
    try testing.expectEqual(@as(?UpstreamIndex, 1), state2.findNthHealthy(1));
    try testing.expectEqual(@as(?UpstreamIndex, 0), state2.findNthHealthy(2)); // 2 % 2 = 0

    // Test with 0 backends.
    const state0 = HealthState.init(0, 3, 2);
    try testing.expectEqual(@as(u32, 0), state0.countHealthy());

    // Test with 1 backend.
    const state1 = HealthState.init(1, 3, 2);
    try testing.expectEqual(@as(u32, 1), state1.countHealthy());
    try testing.expect(state1.isHealthy(0));
}

test "recordFailure transitions after threshold" {
    var hs = HealthState.init(3, 3, 2);

    // Initially healthy
    try testing.expect(hs.isHealthy(5 % 3)); // Using modulo for valid index

    const idx: UpstreamIndex = 0;

    // Record failures up to threshold
    hs.recordFailure(idx);
    try testing.expect(hs.isHealthy(idx)); // Still healthy at 1

    hs.recordFailure(idx);
    try testing.expect(hs.isHealthy(idx)); // Still healthy at 2

    hs.recordFailure(idx); // Third failure hits threshold
    try testing.expect(!hs.isHealthy(idx)); // Now unhealthy
}

test "recordSuccess transitions after threshold" {
    var hs = HealthState.init(3, 3, 2);

    // Mark backend unhealthy first
    hs.recordFailure(0);
    hs.recordFailure(0);
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));

    // First success - not yet healthy
    hs.recordSuccess(0);
    try testing.expect(!hs.isHealthy(0));

    // Second success - reaches threshold, now healthy
    hs.recordSuccess(0);
    try testing.expect(hs.isHealthy(0));
}

test "success resets failure counter" {
    var hs = HealthState.init(3, 3, 2);

    // Two failures
    hs.recordFailure(0);
    hs.recordFailure(0);
    try testing.expect(hs.isHealthy(0));

    // One success resets counter
    hs.recordSuccess(0);

    // Two more failures - should not trigger threshold
    hs.recordFailure(0);
    hs.recordFailure(0);
    try testing.expect(hs.isHealthy(0)); // Still healthy

    // Third failure triggers
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0)); // Now unhealthy
}

test "failure resets success counter" {
    var hs = HealthState.init(3, 3, 2);

    // Mark unhealthy first
    hs.recordFailure(0);
    hs.recordFailure(0);
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));

    // One success
    hs.recordSuccess(0);

    // Failure resets the success counter
    hs.recordFailure(0);

    // Two more successes needed
    hs.recordSuccess(0);
    try testing.expect(!hs.isHealthy(0)); // Still unhealthy

    hs.recordSuccess(0);
    try testing.expect(hs.isHealthy(0)); // Now healthy
}

test "countHealthy uses popcount" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Start with all MAX_UPSTREAMS healthy
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());

    // Mark a few unhealthy
    hs.recordFailure(0);
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 1), hs.countHealthy());

    hs.recordFailure(31);
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 2), hs.countHealthy());

    hs.recordFailure(MAX_UPSTREAMS - 1);
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 3), hs.countHealthy());

    // Mark one healthy again
    hs.recordSuccess(31);
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 2), hs.countHealthy());
}

test "findFirstHealthy skips excluded" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // All healthy, exclude none - should return 0
    const first = hs.findFirstHealthy(null);
    try testing.expectEqual(@as(?UpstreamIndex, 0), first);

    // Exclude backend 0 - should return 1
    const second = hs.findFirstHealthy(0);
    try testing.expectEqual(@as(?UpstreamIndex, 1), second);

    // Mark 0 and 1 unhealthy, exclude 2 - should return 3
    hs.recordFailure(0);
    hs.recordFailure(1);
    const third = hs.findFirstHealthy(2);
    try testing.expectEqual(@as(?UpstreamIndex, 3), third);

    // Mark all unhealthy - should return null
    for (0..MAX_UPSTREAMS) |i| {
        hs.recordFailure(@intCast(i));
    }
    const none = hs.findFirstHealthy(null);
    try testing.expectEqual(@as(?UpstreamIndex, null), none);
}

test "findNthHealthy wraps correctly" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // All healthy, find 0th (first healthy)
    try testing.expectEqual(@as(?UpstreamIndex, 0), hs.findNthHealthy(0));

    // Find 10th healthy
    try testing.expectEqual(@as(?UpstreamIndex, 10), hs.findNthHealthy(10));

    // Find 63rd healthy (last one)
    try testing.expectEqual(@as(?UpstreamIndex, 63), hs.findNthHealthy(63));

    // Mark some unhealthy and test
    hs.recordFailure(0);
    hs.recordFailure(1);
    hs.recordFailure(2);

    // Now 0th healthy is idx 3
    try testing.expectEqual(@as(?UpstreamIndex, 3), hs.findNthHealthy(0));

    // 60th healthy would be idx 63
    try testing.expectEqual(@as(?UpstreamIndex, 63), hs.findNthHealthy(60));
}

// =============================================================================
// Concurrent Read Tests
// =============================================================================

test "concurrent isHealthy reads are safe" {
    // HealthState supports concurrent reads of the health bitmap.
    // This test verifies reads don't corrupt state.
    var hs = HealthState.init(MAX_UPSTREAMS, 3, 2);

    const Context = struct {
        hs: *const HealthState,
    };

    const worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                // Just read health status
                const idx: UpstreamIndex = @intCast(iteration % MAX_UPSTREAMS);
                _ = ctx.hs.isHealthy(idx);
                _ = ctx.hs.countHealthy();
                _ = ctx.hs.findNthHealthy(iteration);
            }
        }
    }.run;

    var ctx = Context{ .hs = &hs };

    // Spawn threads
    var threads: [THREAD_COUNT]Thread = undefined;
    var spawned: u32 = 0;
    while (spawned < THREAD_COUNT) : (spawned += 1) {
        threads[spawned] = Thread.spawn(.{}, worker, .{&ctx}) catch unreachable;
    }

    // Join all threads
    var joined: u32 = 0;
    while (joined < THREAD_COUNT) : (joined += 1) {
        threads[joined].join();
    }

    // State should still be valid
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());
}

// =============================================================================
// Boundary Tests
// =============================================================================

test "idx 0 works correctly" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Verify idx 0 is healthy initially
    try testing.expect(hs.isHealthy(0));

    // Mark unhealthy
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));

    // Other indices unaffected
    try testing.expect(hs.isHealthy(1));
    try testing.expect(hs.isHealthy(63));

    // Mark healthy again
    hs.recordSuccess(0);
    try testing.expect(hs.isHealthy(0));

    // Count should reflect changes
    hs.recordFailure(0);
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 1), hs.countHealthy());
}

test "idx 63 works correctly" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Verify idx 63 (max valid) is healthy initially
    try testing.expect(hs.isHealthy(MAX_BACKEND_IDX));

    // Mark unhealthy
    hs.recordFailure(MAX_BACKEND_IDX);
    try testing.expect(!hs.isHealthy(MAX_BACKEND_IDX));

    // Other indices unaffected
    try testing.expect(hs.isHealthy(0));
    try testing.expect(hs.isHealthy(62));

    // Mark healthy again
    hs.recordSuccess(MAX_BACKEND_IDX);
    try testing.expect(hs.isHealthy(MAX_BACKEND_IDX));

    // Find operations work at boundary
    for (0..MAX_BACKEND_IDX) |i| {
        hs.recordFailure(@intCast(i));
    }
    // Only idx 63 is healthy
    try testing.expectEqual(@as(u32, 1), hs.countHealthy());
    try testing.expectEqual(@as(?UpstreamIndex, MAX_BACKEND_IDX), hs.findFirstHealthy(null));
}

test "operations on all MAX_UPSTREAMS backends" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Mark all unhealthy one by one
    for (0..MAX_UPSTREAMS) |i| {
        hs.recordFailure(@intCast(i));
        try testing.expectEqual(MAX_UPSTREAMS - 1 - @as(u32, @intCast(i)), hs.countHealthy());
    }

    // All should be unhealthy
    try testing.expectEqual(@as(u32, 0), hs.countHealthy());

    // Mark all healthy one by one
    for (0..MAX_UPSTREAMS) |i| {
        hs.recordSuccess(@intCast(i));
        try testing.expectEqual(@as(u32, @as(u32, @intCast(i)) + 1), hs.countHealthy());
    }

    // All should be healthy
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());
}

test "threshold 1 triggers immediately" {
    var hs = HealthState.init(3, 1, 1);

    // Single failure should trigger unhealthy
    try testing.expect(hs.isHealthy(0));
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));

    // Single success should trigger healthy
    hs.recordSuccess(0);
    try testing.expect(hs.isHealthy(0));
}

test "high threshold requires many consecutive events" {
    var hs = HealthState.init(3, 10, 10);

    // 9 failures should not trigger
    var i: u32 = 0;
    while (i < 9) : (i += 1) {
        hs.recordFailure(0);
    }
    try testing.expect(hs.isHealthy(0));

    // 10th failure triggers
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));

    // 9 successes should not recover
    i = 0;
    while (i < 9) : (i += 1) {
        hs.recordSuccess(0);
    }
    try testing.expect(!hs.isHealthy(0));

    // 10th success recovers
    hs.recordSuccess(0);
    try testing.expect(hs.isHealthy(0));
}

// =============================================================================
// Edge Case Tests
// =============================================================================

test "findFirstHealthy with single healthy backend" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Mark all unhealthy except one
    for (0..MAX_UPSTREAMS) |i| {
        const idx: UpstreamIndex = @intCast(i);
        if (idx != 30) {
            hs.recordFailure(idx);
        }
    }

    // Should always find idx 30
    try testing.expectEqual(@as(?UpstreamIndex, 30), hs.findFirstHealthy(null));
    try testing.expectEqual(@as(?UpstreamIndex, 30), hs.findFirstHealthy(0));
    try testing.expectEqual(@as(?UpstreamIndex, 30), hs.findFirstHealthy(29));

    // Excluding 30 should return null
    try testing.expectEqual(@as(?UpstreamIndex, null), hs.findFirstHealthy(30));
}

test "findNthHealthy with sparse healthy backends" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Only keep backends 10, 20, 30, 40 healthy
    for (0..MAX_UPSTREAMS) |i| {
        const idx: UpstreamIndex = @intCast(i);
        if (idx != 10 and idx != 20 and idx != 30 and idx != 40) {
            hs.recordFailure(idx);
        }
    }

    try testing.expectEqual(@as(u32, 4), hs.countHealthy());

    // Find nth healthy
    try testing.expectEqual(@as(?UpstreamIndex, 10), hs.findNthHealthy(0));
    try testing.expectEqual(@as(?UpstreamIndex, 20), hs.findNthHealthy(1));
    try testing.expectEqual(@as(?UpstreamIndex, 30), hs.findNthHealthy(2));
    try testing.expectEqual(@as(?UpstreamIndex, 40), hs.findNthHealthy(3));
}

test "fast path when already in target state" {
    var hs = HealthState.init(3, 3, 2);

    // Already healthy - recordSuccess should be fast path
    try testing.expect(hs.isHealthy(0));
    hs.recordSuccess(0);
    // Success counter should not increment when already healthy
    try testing.expectEqual(@as(u8, 0), hs.success_counts[0]);

    // Mark unhealthy
    hs.recordFailure(0);
    hs.recordFailure(0);
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));

    // Already unhealthy - recordFailure should be fast path
    hs.recordFailure(0);
    // Failure counter should not increment when already unhealthy
    try testing.expectEqual(@as(u8, 0), hs.failure_counts[0]);
}

test "reset restores all healthy" {
    var hs = HealthState.init(3, 1, 1);

    // Mess up state
    hs.recordFailure(0);
    hs.recordFailure(1);
    try testing.expectEqual(@as(u32, 1), hs.countHealthy());

    // Reset should restore all healthy
    hs.reset();

    try testing.expectEqual(@as(u32, 3), hs.countHealthy());
    try testing.expect(hs.isHealthy(0));
    try testing.expect(hs.isHealthy(1));
    try testing.expect(hs.isHealthy(2));
}
