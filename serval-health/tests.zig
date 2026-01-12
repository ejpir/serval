//! serval-health/tests.zig
//! Extended Tests for HealthState
//!
//! Covers concurrent reads, boundary conditions, and edge cases beyond
//! the basic functionality tested inline in health_state.zig.
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
const CONCURRENT_THREAD_COUNT: u32 = 8;

/// Iterations per thread for concurrent tests (enough to expose race conditions).
const ITERATIONS_PER_THREAD: u32 = 1000;

/// Maximum backend index (MAX_UPSTREAMS - 1).
const MAX_BACKEND_IDX: UpstreamIndex = MAX_UPSTREAMS - 1;

// =============================================================================
// Concurrent Read Tests
// =============================================================================

test "concurrent reads are thread-safe" {
    // HealthState supports concurrent reads of the health bitmap.
    // This test verifies reads do not corrupt state.
    var hs = HealthState.init(MAX_UPSTREAMS, 3, 2);

    const Context = struct {
        hs: *const HealthState,
    };

    const worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                const idx: UpstreamIndex = @intCast(iteration % MAX_UPSTREAMS);
                _ = ctx.hs.isHealthy(idx);
                _ = ctx.hs.countHealthy();
                _ = ctx.hs.findNthHealthy(iteration);
            }
        }
    }.run;

    var ctx = Context{ .hs = &hs };

    // Spawn threads
    var threads: [CONCURRENT_THREAD_COUNT]Thread = undefined;
    var spawned: u32 = 0;
    while (spawned < CONCURRENT_THREAD_COUNT) : (spawned += 1) {
        threads[spawned] = Thread.spawn(.{}, worker, .{&ctx}) catch unreachable;
    }

    // Join all threads
    var joined: u32 = 0;
    while (joined < CONCURRENT_THREAD_COUNT) : (joined += 1) {
        threads[joined].join();
    }

    // State should still be valid after concurrent reads
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());
}

// =============================================================================
// Boundary Tests
// =============================================================================

test "boundary: idx 0 operations" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Verify idx 0 is healthy initially
    try testing.expect(hs.isHealthy(0));

    // Mark unhealthy
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));

    // Other indices unaffected
    try testing.expect(hs.isHealthy(1));
    try testing.expect(hs.isHealthy(MAX_BACKEND_IDX));

    // Mark healthy again
    hs.recordSuccess(0);
    try testing.expect(hs.isHealthy(0));

    // Count should reflect changes
    hs.recordFailure(0);
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 1), hs.countHealthy());
}

test "boundary: idx 63 (max) operations" {
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

    // Mark all except idx 63 unhealthy
    for (0..MAX_BACKEND_IDX) |i| {
        hs.recordFailure(@intCast(i));
    }

    // Only idx 63 is healthy
    try testing.expectEqual(@as(u32, 1), hs.countHealthy());
    try testing.expectEqual(@as(?UpstreamIndex, MAX_BACKEND_IDX), hs.findFirstHealthy(null));
}

test "boundary: all MAX_UPSTREAMS backends" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Mark all unhealthy one by one, verify count decrements
    for (0..MAX_UPSTREAMS) |i| {
        hs.recordFailure(@intCast(i));
        const expected = MAX_UPSTREAMS - 1 - @as(u32, @intCast(i));
        try testing.expectEqual(expected, hs.countHealthy());
    }

    try testing.expectEqual(@as(u32, 0), hs.countHealthy());

    // Mark all healthy one by one, verify count increments
    for (0..MAX_UPSTREAMS) |i| {
        hs.recordSuccess(@intCast(i));
        const expected = @as(u32, @intCast(i)) + 1;
        try testing.expectEqual(expected, hs.countHealthy());
    }

    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());
}

// =============================================================================
// Threshold Edge Cases
// =============================================================================

test "threshold: high value requires many consecutive events" {
    var hs = HealthState.init(3, 10, 10);

    // 9 failures should not trigger unhealthy
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
// Sparse Backend Tests
// =============================================================================

test "sparse: single healthy backend in pool" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Mark all unhealthy except backend 30
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

test "sparse: distributed healthy backends" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Only keep backends 10, 20, 30, 40 healthy
    for (0..MAX_UPSTREAMS) |i| {
        const idx: UpstreamIndex = @intCast(i);
        if (idx != 10 and idx != 20 and idx != 30 and idx != 40) {
            hs.recordFailure(idx);
        }
    }

    try testing.expectEqual(@as(u32, 4), hs.countHealthy());

    // findNthHealthy should cycle through healthy backends
    try testing.expectEqual(@as(?UpstreamIndex, 10), hs.findNthHealthy(0));
    try testing.expectEqual(@as(?UpstreamIndex, 20), hs.findNthHealthy(1));
    try testing.expectEqual(@as(?UpstreamIndex, 30), hs.findNthHealthy(2));
    try testing.expectEqual(@as(?UpstreamIndex, 40), hs.findNthHealthy(3));

    // Wrapping: n=4 should return first healthy (10)
    try testing.expectEqual(@as(?UpstreamIndex, 10), hs.findNthHealthy(4));
}

test "sparse: findNthHealthy with gaps" {
    var hs = HealthState.init(MAX_UPSTREAMS, 1, 1);

    // Mark backends 0, 1, 2 unhealthy
    hs.recordFailure(0);
    hs.recordFailure(1);
    hs.recordFailure(2);

    // Now 0th healthy is idx 3
    try testing.expectEqual(@as(?UpstreamIndex, 3), hs.findNthHealthy(0));

    // 60th healthy would be idx 63 (skipping first 3)
    try testing.expectEqual(@as(?UpstreamIndex, 63), hs.findNthHealthy(60));
}

// =============================================================================
// Counter Behavior Tests
// =============================================================================

test "counter: success resets failure counter mid-way" {
    var hs = HealthState.init(3, 3, 2);

    // Two failures (not at threshold yet)
    hs.recordFailure(0);
    hs.recordFailure(0);
    try testing.expect(hs.isHealthy(0));

    // One success resets failure counter
    hs.recordSuccess(0);

    // Two more failures should not trigger (counter was reset)
    hs.recordFailure(0);
    hs.recordFailure(0);
    try testing.expect(hs.isHealthy(0));

    // Third failure now triggers
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));
}

test "counter: failure resets success counter mid-recovery" {
    var hs = HealthState.init(3, 3, 2);

    // Mark unhealthy
    hs.recordFailure(0);
    hs.recordFailure(0);
    hs.recordFailure(0);
    try testing.expect(!hs.isHealthy(0));

    // One success (not at threshold yet)
    hs.recordSuccess(0);

    // Failure resets success counter
    hs.recordFailure(0);

    // Now need two full successes to recover
    hs.recordSuccess(0);
    try testing.expect(!hs.isHealthy(0));

    hs.recordSuccess(0);
    try testing.expect(hs.isHealthy(0));
}
