//! serval-health/tests.zig
//! Comprehensive Tests for Health State and Tracker
//!
//! Tests cover basic operations, threshold transitions, concurrent access,
//! and boundary conditions.
//! TigerStyle: Bounded iterations, explicit types, assertions on results.

const std = @import("std");
const testing = std.testing;
const Thread = std.Thread;

const state = @import("state.zig");
const tracker = @import("tracker.zig");

const SharedHealthState = state.SharedHealthState;
const BackendIndex = state.BackendIndex;
const HealthTracker = tracker.HealthTracker;

const config = @import("serval-core").config;

// =============================================================================
// Constants
// =============================================================================

/// Number of backends supported (from config).
const MAX_UPSTREAMS: u8 = config.MAX_UPSTREAMS;

/// Number of threads for concurrent tests.
/// TigerStyle: Explicit constant, enough to stress atomic operations.
const THREAD_COUNT: u32 = 8;

/// Iterations per thread for concurrent tests.
/// TigerStyle: Bounded iterations, 1000+ to expose race conditions.
const ITERATIONS_PER_THREAD: u32 = 1000;

/// Maximum backend index (MAX_UPSTREAMS - 1).
const MAX_BACKEND_IDX: BackendIndex = MAX_UPSTREAMS - 1;

// =============================================================================
// Basic State Tests
// =============================================================================

test "all backends start healthy" {
    const hs = SharedHealthState.init();

    // All bits should be set (healthy)
    try testing.expectEqual(std.math.maxInt(u64), hs.health_bitmap.load(.seq_cst));

    // Count should equal MAX_UPSTREAMS
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());

    // Every backend should be healthy (use u8 counter to avoid u6 overflow)
    for (0..MAX_UPSTREAMS) |i| {
        const idx: BackendIndex = @intCast(i);
        try testing.expect(hs.isHealthy(idx));
    }
}

test "markUnhealthy clears bit" {
    var hs = SharedHealthState.init();

    // Initially healthy
    try testing.expect(hs.isHealthy(5));

    // Mark unhealthy
    hs.markUnhealthy(5);

    // Should now be unhealthy
    try testing.expect(!hs.isHealthy(5));

    // Other backends unaffected
    try testing.expect(hs.isHealthy(4));
    try testing.expect(hs.isHealthy(6));
}

test "markHealthy sets bit" {
    var hs = SharedHealthState.init();

    // First mark as unhealthy
    hs.markUnhealthy(10);
    try testing.expect(!hs.isHealthy(10));

    // Mark healthy again
    hs.markHealthy(10);
    try testing.expect(hs.isHealthy(10));
}

test "countHealthy uses popcount" {
    var hs = SharedHealthState.init();

    // Start with all 64 healthy
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());

    // Mark a few unhealthy
    hs.markUnhealthy(0);
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 1), hs.countHealthy());

    hs.markUnhealthy(31);
    try testing.expectEqual(@as(u32, 62), hs.countHealthy());

    hs.markUnhealthy(63);
    try testing.expectEqual(@as(u32, 61), hs.countHealthy());

    // Mark one healthy again
    hs.markHealthy(31);
    try testing.expectEqual(@as(u32, 62), hs.countHealthy());
}

test "findFirstHealthy skips excluded" {
    var hs = SharedHealthState.init();

    // All healthy, exclude none - should return 0
    const first = hs.findFirstHealthy(null);
    try testing.expectEqual(@as(?BackendIndex, 0), first);

    // Exclude backend 0 - should return 1
    const second = hs.findFirstHealthy(0);
    try testing.expectEqual(@as(?BackendIndex, 1), second);

    // Mark 0 and 1 unhealthy, exclude 2 - should return 3
    hs.markUnhealthy(0);
    hs.markUnhealthy(1);
    const third = hs.findFirstHealthy(2);
    try testing.expectEqual(@as(?BackendIndex, 3), third);

    // Mark all unhealthy - should return null
    for (0..MAX_UPSTREAMS) |i| {
        hs.markUnhealthy(@intCast(i));
    }
    const none = hs.findFirstHealthy(null);
    try testing.expectEqual(@as(?BackendIndex, null), none);
}

test "findNthHealthy wraps correctly" {
    var hs = SharedHealthState.init();

    // All healthy, find 0th (first healthy)
    try testing.expectEqual(@as(?BackendIndex, 0), hs.findNthHealthy(0));

    // Find 10th healthy
    try testing.expectEqual(@as(?BackendIndex, 10), hs.findNthHealthy(10));

    // Find 63rd healthy (last one)
    try testing.expectEqual(@as(?BackendIndex, 63), hs.findNthHealthy(63));

    // Mark some unhealthy and test
    hs.markUnhealthy(0);
    hs.markUnhealthy(1);
    hs.markUnhealthy(2);

    // Now 0th healthy is idx 3
    try testing.expectEqual(@as(?BackendIndex, 3), hs.findNthHealthy(0));

    // 60th healthy would be idx 63
    try testing.expectEqual(@as(?BackendIndex, 63), hs.findNthHealthy(60));
}

// =============================================================================
// Threshold Tests
// =============================================================================

test "single failure does not mark unhealthy" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 3, 2);

    // Backend starts healthy
    try testing.expect(ht.isHealthy(0));

    // Record one failure
    ht.recordFailure(0);

    // Should still be healthy (threshold is 3)
    try testing.expect(ht.isHealthy(0));

    // Record second failure
    ht.recordFailure(0);

    // Still healthy
    try testing.expect(ht.isHealthy(0));
}

test "consecutive failures at threshold marks unhealthy" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 3, 2);

    try testing.expect(ht.isHealthy(0));

    // Record failures up to threshold
    ht.recordFailure(0);
    ht.recordFailure(0);
    try testing.expect(ht.isHealthy(0)); // Still healthy at 2

    ht.recordFailure(0); // Third failure hits threshold
    try testing.expect(!ht.isHealthy(0)); // Now unhealthy
}

test "success resets failure counter" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 3, 2);

    // Two failures
    ht.recordFailure(0);
    ht.recordFailure(0);
    try testing.expect(ht.isHealthy(0));

    // One success resets counter
    ht.recordSuccess(0);

    // Two more failures - should not trigger threshold
    ht.recordFailure(0);
    ht.recordFailure(0);
    try testing.expect(ht.isHealthy(0)); // Still healthy

    // Third failure triggers
    ht.recordFailure(0);
    try testing.expect(!ht.isHealthy(0)); // Now unhealthy
}

test "failure resets success counter" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 3, 2);

    // Mark unhealthy first
    ht.recordFailure(0);
    ht.recordFailure(0);
    ht.recordFailure(0);
    try testing.expect(!ht.isHealthy(0));

    // One success
    ht.recordSuccess(0);

    // Failure resets the success counter
    ht.recordFailure(0);

    // Two more successes needed
    ht.recordSuccess(0);
    try testing.expect(!ht.isHealthy(0)); // Still unhealthy

    ht.recordSuccess(0);
    try testing.expect(ht.isHealthy(0)); // Now healthy
}

test "recovery requires consecutive successes" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 3, 3);

    // Mark backend unhealthy
    ht.recordFailure(0);
    ht.recordFailure(0);
    ht.recordFailure(0);
    try testing.expect(!ht.isHealthy(0));

    // Partial recovery
    ht.recordSuccess(0);
    ht.recordSuccess(0);
    try testing.expect(!ht.isHealthy(0)); // Still unhealthy

    // Full recovery
    ht.recordSuccess(0);
    try testing.expect(ht.isHealthy(0)); // Now healthy
}

// =============================================================================
// Concurrent/Race Condition Tests
// =============================================================================

test "concurrent markHealthy same backend" {
    var hs = SharedHealthState.init();

    // Start unhealthy so we can test marking healthy
    hs.markUnhealthy(5);
    try testing.expect(!hs.isHealthy(5));

    const Context = struct {
        hs: *SharedHealthState,
    };

    const worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                ctx.hs.markHealthy(5);
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

    // Final state should be healthy
    try testing.expect(hs.isHealthy(5));
}

test "concurrent markUnhealthy same backend" {
    var hs = SharedHealthState.init();

    // Start healthy
    try testing.expect(hs.isHealthy(10));

    const Context = struct {
        hs: *SharedHealthState,
    };

    const worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                ctx.hs.markUnhealthy(10);
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

    // Final state should be unhealthy
    try testing.expect(!hs.isHealthy(10));
}

test "concurrent mixed operations" {
    var hs = SharedHealthState.init();

    const Context = struct {
        hs: *SharedHealthState,
        thread_id: u32,
    };

    const worker = struct {
        fn run(ctx: *Context) void {
            // Each thread operates on its own backend subset to avoid contention
            // Thread 0: backends 0-7, Thread 1: backends 8-15, etc.
            const base_idx: BackendIndex = @intCast((ctx.thread_id * 8) % 64);

            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                const offset: BackendIndex = @intCast(iteration % 8);
                const idx: BackendIndex = base_idx +% offset;

                // Alternate between mark healthy and unhealthy
                if (iteration % 2 == 0) {
                    ctx.hs.markUnhealthy(idx);
                } else {
                    ctx.hs.markHealthy(idx);
                }
            }
        }
    }.run;

    // Create contexts for each thread
    var contexts: [THREAD_COUNT]Context = undefined;
    var ctx_idx: u32 = 0;
    while (ctx_idx < THREAD_COUNT) : (ctx_idx += 1) {
        contexts[ctx_idx] = Context{
            .hs = &hs,
            .thread_id = ctx_idx,
        };
    }

    // Spawn threads
    var threads: [THREAD_COUNT]Thread = undefined;
    var spawned: u32 = 0;
    while (spawned < THREAD_COUNT) : (spawned += 1) {
        threads[spawned] = Thread.spawn(.{}, worker, .{&contexts[spawned]}) catch unreachable;
    }

    // Join all threads
    var joined: u32 = 0;
    while (joined < THREAD_COUNT) : (joined += 1) {
        threads[joined].join();
    }

    // Verify no corruption - count should be valid (0-64)
    const count = hs.countHealthy();
    try testing.expect(count <= 64);

    // Verify bitmask is consistent - each bit represents valid state
    const mask = hs.health_bitmap.load(.seq_cst);
    var bit_count: u32 = 0;
    for (0..MAX_UPSTREAMS) |i| {
        if ((mask >> @as(u6, @intCast(i))) & 1 == 1) {
            bit_count += 1;
        }
    }
    try testing.expectEqual(count, bit_count);
}

test "concurrent recordSuccess from multiple threads" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 3, 2);

    // Mark backend 0 unhealthy first
    ht.recordFailure(0);
    ht.recordFailure(0);
    ht.recordFailure(0);
    try testing.expect(!ht.isHealthy(0));

    const Context = struct {
        ht: *HealthTracker,
    };

    const worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                ctx.ht.recordSuccess(0);
            }
        }
    }.run;

    var ctx = Context{ .ht = &ht };

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

    // After many successes, should be healthy
    try testing.expect(ht.isHealthy(0));
}

test "concurrent recordFailure from multiple threads" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 3, 2);

    // Backend starts healthy
    try testing.expect(ht.isHealthy(5));

    const Context = struct {
        ht: *HealthTracker,
    };

    const worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                ctx.ht.recordFailure(5);
            }
        }
    }.run;

    var ctx = Context{ .ht = &ht };

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

    // After many failures, should be unhealthy
    try testing.expect(!ht.isHealthy(5));
}

test "concurrent threshold transitions are atomic" {
    // Test that transitions between healthy/unhealthy are atomic
    // and don't result in corrupted intermediate states
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 2, 2);

    const Context = struct {
        ht: *HealthTracker,
        thread_id: u32,
    };

    const worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                // Even threads record failures, odd threads record successes
                if (ctx.thread_id % 2 == 0) {
                    ctx.ht.recordFailure(0);
                } else {
                    ctx.ht.recordSuccess(0);
                }
            }
        }
    }.run;

    // Create contexts for each thread
    var contexts: [THREAD_COUNT]Context = undefined;
    var ctx_idx: u32 = 0;
    while (ctx_idx < THREAD_COUNT) : (ctx_idx += 1) {
        contexts[ctx_idx] = Context{
            .ht = &ht,
            .thread_id = ctx_idx,
        };
    }

    // Spawn threads
    var threads: [THREAD_COUNT]Thread = undefined;
    var spawned: u32 = 0;
    while (spawned < THREAD_COUNT) : (spawned += 1) {
        threads[spawned] = Thread.spawn(.{}, worker, .{&contexts[spawned]}) catch unreachable;
    }

    // Join all threads
    var joined: u32 = 0;
    while (joined < THREAD_COUNT) : (joined += 1) {
        threads[joined].join();
    }

    // Verify state is valid (either healthy or unhealthy, not corrupted)
    const is_healthy = ht.isHealthy(0);

    // State should be deterministic based on final counter state
    // The key invariant is that isHealthy returns a consistent value
    // relative to the mask state
    const mask = hs.health_bitmap.load(.seq_cst);
    const bit_set = (mask & 1) == 1;
    try testing.expectEqual(bit_set, is_healthy);
}

// =============================================================================
// Boundary Tests
// =============================================================================

test "idx 0 works correctly" {
    var hs = SharedHealthState.init();

    // Verify idx 0 is healthy initially
    try testing.expect(hs.isHealthy(0));

    // Mark unhealthy
    hs.markUnhealthy(0);
    try testing.expect(!hs.isHealthy(0));

    // Other indices unaffected
    try testing.expect(hs.isHealthy(1));
    try testing.expect(hs.isHealthy(63));

    // Mark healthy again
    hs.markHealthy(0);
    try testing.expect(hs.isHealthy(0));

    // Count should reflect changes
    hs.markUnhealthy(0);
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 1), hs.countHealthy());
}

test "idx 63 works correctly" {
    var hs = SharedHealthState.init();

    // Verify idx 63 (max valid) is healthy initially
    try testing.expect(hs.isHealthy(MAX_BACKEND_IDX));

    // Mark unhealthy
    hs.markUnhealthy(MAX_BACKEND_IDX);
    try testing.expect(!hs.isHealthy(MAX_BACKEND_IDX));

    // Other indices unaffected
    try testing.expect(hs.isHealthy(0));
    try testing.expect(hs.isHealthy(62));

    // Mark healthy again
    hs.markHealthy(MAX_BACKEND_IDX);
    try testing.expect(hs.isHealthy(MAX_BACKEND_IDX));

    // Find operations work at boundary
    var idx: BackendIndex = 0;
    while (idx < MAX_BACKEND_IDX) : (idx +%= 1) {
        hs.markUnhealthy(idx);
    }
    // Only idx 63 is healthy
    try testing.expectEqual(@as(u32, 1), hs.countHealthy());
    try testing.expectEqual(@as(?BackendIndex, MAX_BACKEND_IDX), hs.findFirstHealthy(null));
}

test "operations on all 64 backends" {
    var hs = SharedHealthState.init();

    // Mark all unhealthy one by one
    for (0..MAX_UPSTREAMS) |i| {
        hs.markUnhealthy(@intCast(i));
        try testing.expectEqual(MAX_UPSTREAMS - 1 - @as(u32, @intCast(i)), hs.countHealthy());
    }

    // All should be unhealthy
    try testing.expectEqual(@as(u32, 0), hs.countHealthy());
    try testing.expectEqual(@as(u64, 0), hs.health_bitmap.load(.seq_cst));

    // Mark all healthy one by one
    for (0..MAX_UPSTREAMS) |i| {
        hs.markHealthy(@intCast(i));
        try testing.expectEqual(@as(u32, @as(u32, @intCast(i)) + 1), hs.countHealthy());
    }

    // All should be healthy
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());
    try testing.expectEqual(std.math.maxInt(u64), hs.health_bitmap.load(.seq_cst));
}

test "tracker operations on all backends" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 2, 2);

    // Mark all backends unhealthy via failures
    for (0..MAX_UPSTREAMS) |i| {
        const idx: BackendIndex = @intCast(i);
        ht.recordFailure(idx);
        ht.recordFailure(idx);
    }

    // All should be unhealthy
    for (0..MAX_UPSTREAMS) |i| {
        try testing.expect(!ht.isHealthy(@intCast(i)));
    }

    // Recover all via successes
    for (0..MAX_UPSTREAMS) |i| {
        const idx: BackendIndex = @intCast(i);
        ht.recordSuccess(idx);
        ht.recordSuccess(idx);
    }

    // All should be healthy
    for (0..MAX_UPSTREAMS) |i| {
        try testing.expect(ht.isHealthy(@intCast(i)));
    }
}

test "threshold 1 triggers immediately" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 1, 1);

    // Single failure should trigger unhealthy
    try testing.expect(ht.isHealthy(0));
    ht.recordFailure(0);
    try testing.expect(!ht.isHealthy(0));

    // Single success should trigger healthy
    ht.recordSuccess(0);
    try testing.expect(ht.isHealthy(0));
}

test "high threshold requires many consecutive events" {
    var hs = SharedHealthState.init();
    var ht = HealthTracker.init(&hs, 10, 10);

    // 9 failures should not trigger
    var i: u32 = 0;
    while (i < 9) : (i += 1) {
        ht.recordFailure(0);
    }
    try testing.expect(ht.isHealthy(0));

    // 10th failure triggers
    ht.recordFailure(0);
    try testing.expect(!ht.isHealthy(0));

    // 9 successes should not recover
    i = 0;
    while (i < 9) : (i += 1) {
        ht.recordSuccess(0);
    }
    try testing.expect(!ht.isHealthy(0));

    // 10th success recovers
    ht.recordSuccess(0);
    try testing.expect(ht.isHealthy(0));
}

// =============================================================================
// Edge Case Tests
// =============================================================================

test "findFirstHealthy with single healthy backend" {
    var hs = SharedHealthState.init();

    // Mark all unhealthy except one
    for (0..MAX_UPSTREAMS) |i| {
        const idx: BackendIndex = @intCast(i);
        if (idx != 30) {
            hs.markUnhealthy(idx);
        }
    }

    // Should always find idx 30
    try testing.expectEqual(@as(?BackendIndex, 30), hs.findFirstHealthy(null));
    try testing.expectEqual(@as(?BackendIndex, 30), hs.findFirstHealthy(0));
    try testing.expectEqual(@as(?BackendIndex, 30), hs.findFirstHealthy(29));

    // Excluding 30 should return null
    try testing.expectEqual(@as(?BackendIndex, null), hs.findFirstHealthy(30));
}

test "findNthHealthy with sparse healthy backends" {
    var hs = SharedHealthState.init();

    // Only keep backends 10, 20, 30, 40 healthy
    for (0..MAX_UPSTREAMS) |i| {
        const idx: BackendIndex = @intCast(i);
        if (idx != 10 and idx != 20 and idx != 30 and idx != 40) {
            hs.markUnhealthy(idx);
        }
    }

    try testing.expectEqual(@as(u32, 4), hs.countHealthy());

    // Find nth healthy
    try testing.expectEqual(@as(?BackendIndex, 10), hs.findNthHealthy(0));
    try testing.expectEqual(@as(?BackendIndex, 20), hs.findNthHealthy(1));
    try testing.expectEqual(@as(?BackendIndex, 30), hs.findNthHealthy(2));
    try testing.expectEqual(@as(?BackendIndex, 40), hs.findNthHealthy(3));
}

test "idempotent markHealthy and markUnhealthy" {
    var hs = SharedHealthState.init();

    // Multiple markHealthy calls should be idempotent
    hs.markHealthy(5);
    hs.markHealthy(5);
    hs.markHealthy(5);
    try testing.expect(hs.isHealthy(5));
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS), hs.countHealthy());

    // Multiple markUnhealthy calls should be idempotent
    hs.markUnhealthy(5);
    hs.markUnhealthy(5);
    hs.markUnhealthy(5);
    try testing.expect(!hs.isHealthy(5));
    try testing.expectEqual(@as(u32, MAX_UPSTREAMS - 1), hs.countHealthy());
}
