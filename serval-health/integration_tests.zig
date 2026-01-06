//! Integration Tests for Health Tracking
//!
//! Tests health module integration with upstream selection scenarios,
//! without starting actual servers. Catches bugs like init() vs initWithCount().

const std = @import("std");
const health = @import("mod.zig");
const config = @import("serval-core").config;

const SharedHealthState = health.SharedHealthState;
const HealthTracker = health.HealthTracker;
const UpstreamIndex = health.UpstreamIndex;

/// Simulated upstream for testing.
const TestUpstream = struct {
    host: []const u8,
    port: u16,
    idx: u8,
};

// =============================================================================
// Integration Tests: Upstream Selection with Health
// =============================================================================

test "integration: 2 backends with health-aware round-robin" {
    // This is the exact scenario that caused the panic in lb_example.
    const upstreams = [_]TestUpstream{
        .{ .host = "backend1", .port = 8001, .idx = 0 },
        .{ .host = "backend2", .port = 8002, .idx = 1 },
    };
    const upstream_count: u8 = upstreams.len;

    // CORRECT: Use initWithCount to match actual backend count.
    var state = SharedHealthState.initWithCount(upstream_count);
    var tracker = HealthTracker.init(
        &state,
        config.DEFAULT_UNHEALTHY_THRESHOLD,
        config.DEFAULT_HEALTHY_THRESHOLD,
    );

    // Simulate round-robin selection (like lb_example does).
    var next_idx: u32 = 0;

    // Run 100 selections - none should return an out-of-bounds index.
    for (0..100) |_| {
        const current = next_idx;
        next_idx +%= 1;

        if (tracker.findNthHealthy(current)) |idx| {
            // CRITICAL: idx must be valid for our upstream array.
            try std.testing.expect(idx < upstream_count);
            _ = upstreams[idx]; // Would panic if out of bounds.
        }
    }
}

test "integration: wrong init causes out-of-bounds (regression test)" {
    // Demonstrates the bug: init() sets all MAX_UPSTREAMS bits healthy.
    const upstreams = [_]TestUpstream{
        .{ .host = "backend1", .port = 8001, .idx = 0 },
        .{ .host = "backend2", .port = 8002, .idx = 1 },
    };

    // WRONG: Using init() with fewer than MAX_UPSTREAMS backends.
    var state = SharedHealthState.init();

    // This would return indices 0 to MAX_UPSTREAMS-1, but we only have 2 upstreams!
    // findNthHealthy(2) returns 2, which is out of bounds.
    const bad_idx = state.findNthHealthy(2);
    try std.testing.expect(bad_idx != null);
    try std.testing.expect(bad_idx.? >= upstreams.len); // Proves the bug!

    // CORRECT: initWithCount limits to actual backends.
    var state_correct = SharedHealthState.initWithCount(@intCast(upstreams.len));
    // With 2 healthy backends, findNthHealthy wraps: 2 % 2 = 0
    const good_idx = state_correct.findNthHealthy(2);
    try std.testing.expect(good_idx != null);
    try std.testing.expect(good_idx.? < upstreams.len);
    try std.testing.expectEqual(@as(?UpstreamIndex, 0), good_idx); // 2 % 2 = 0
}

test "integration: health transitions with upstream selection" {
    const upstreams = [_]TestUpstream{
        .{ .host = "backend1", .port = 8001, .idx = 0 },
        .{ .host = "backend2", .port = 8002, .idx = 1 },
        .{ .host = "backend3", .port = 8003, .idx = 2 },
    };
    const upstream_count: u8 = upstreams.len;

    var state = SharedHealthState.initWithCount(upstream_count);
    var tracker = HealthTracker.init(&state, 3, 2); // 3 failures → unhealthy, 2 successes → healthy

    // All 3 healthy initially.
    try std.testing.expectEqual(@as(u32, 3), tracker.countHealthy());

    // Simulate backend 1 failing 3 times (threshold).
    tracker.recordFailure(1);
    tracker.recordFailure(1);
    tracker.recordFailure(1);

    // Backend 1 should now be unhealthy.
    try std.testing.expect(!tracker.isHealthy(1));
    try std.testing.expectEqual(@as(u32, 2), tracker.countHealthy());

    // Selection should only return 0 or 2 now.
    for (0..50) |i| {
        if (tracker.findNthHealthy(@intCast(i))) |idx| {
            try std.testing.expect(idx != 1); // Backend 1 is unhealthy.
            try std.testing.expect(idx < upstream_count);
        }
    }

    // Backend 1 recovers with 2 successes.
    tracker.recordSuccess(1);
    tracker.recordSuccess(1);

    try std.testing.expect(tracker.isHealthy(1));
    try std.testing.expectEqual(@as(u32, 3), tracker.countHealthy());
}

test "integration: all backends unhealthy graceful degradation" {
    const upstreams = [_]TestUpstream{
        .{ .host = "backend1", .port = 8001, .idx = 0 },
        .{ .host = "backend2", .port = 8002, .idx = 1 },
    };
    const upstream_count: u8 = upstreams.len;

    var state = SharedHealthState.initWithCount(upstream_count);
    var tracker = HealthTracker.init(&state, 3, 2);

    // Mark all backends unhealthy.
    for (0..upstream_count) |i| {
        const idx: u6 = @intCast(i);
        tracker.recordFailure(idx);
        tracker.recordFailure(idx);
        tracker.recordFailure(idx);
    }

    try std.testing.expectEqual(@as(u32, 0), tracker.countHealthy());

    // findNthHealthy should return null when all unhealthy.
    try std.testing.expectEqual(@as(?UpstreamIndex, null), tracker.findNthHealthy(0));
    try std.testing.expectEqual(@as(?UpstreamIndex, null), tracker.findNthHealthy(1));

    // Graceful degradation: caller should fall back to round-robin.
    // This is what lb_example does.
    var next_idx: u32 = 0;
    for (0..10) |_| {
        const current = next_idx;
        next_idx +%= 1;

        const fallback_idx = current % upstream_count;
        try std.testing.expect(fallback_idx < upstream_count);
    }
}

test "integration: single backend" {
    const upstream_count: u8 = 1;
    var state = SharedHealthState.initWithCount(upstream_count);
    var tracker = HealthTracker.init(&state, 3, 2);

    // Only one backend, all selections should return 0.
    for (0..20) |i| {
        if (tracker.findNthHealthy(@intCast(i))) |idx| {
            try std.testing.expectEqual(@as(UpstreamIndex, 0), idx);
        }
    }

    // Mark it unhealthy.
    tracker.recordFailure(0);
    tracker.recordFailure(0);
    tracker.recordFailure(0);

    // Now findNthHealthy returns null.
    try std.testing.expectEqual(@as(?UpstreamIndex, null), tracker.findNthHealthy(0));
}

test "integration: concurrent selection simulation" {
    // Simulates multiple "threads" doing selections.
    const upstreams = [_]TestUpstream{
        .{ .host = "backend1", .port = 8001, .idx = 0 },
        .{ .host = "backend2", .port = 8002, .idx = 1 },
        .{ .host = "backend3", .port = 8003, .idx = 2 },
        .{ .host = "backend4", .port = 8004, .idx = 3 },
    };
    const upstream_count: u8 = upstreams.len;

    var state = SharedHealthState.initWithCount(upstream_count);

    // Use atomic counter like lb_example.
    var counter = std.atomic.Value(u32).init(0);

    // Simulate 1000 requests.
    for (0..1000) |_| {
        const n = counter.fetchAdd(1, .monotonic);

        if (state.findNthHealthy(n)) |idx| {
            try std.testing.expect(idx < upstream_count);
        }
    }
}

test "integration: max backends" {
    // Test with maximum supported backends.
    const upstream_count = config.MAX_UPSTREAMS;
    var state = SharedHealthState.initWithCount(upstream_count);

    try std.testing.expectEqual(@as(u32, upstream_count), state.countHealthy());

    // All indices should be valid.
    for (0..upstream_count) |i| {
        const idx = state.findNthHealthy(@intCast(i));
        try std.testing.expect(idx != null);
        try std.testing.expect(idx.? < upstream_count);
    }

    // Index at MAX_UPSTREAMS should wrap or return valid index.
    if (state.findNthHealthy(upstream_count)) |idx| {
        try std.testing.expect(idx < upstream_count);
    }
}
