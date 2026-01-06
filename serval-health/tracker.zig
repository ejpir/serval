// serval-health/tracker.zig
//! Health Tracker
//!
//! Threshold-based health state transitions for upstream backends.
//! Wraps SharedHealthState with consecutive success/failure counting.
//! TigerStyle: Inline hot paths, no allocation, explicit thresholds.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const SharedHealthState = @import("state.zig").SharedHealthState;

/// Maximum number of upstreams supported.
/// TigerStyle: Compile-time constant from config.
pub const MAX_UPSTREAMS: u8 = config.MAX_UPSTREAMS;

/// Health tracker with threshold-based state transitions.
/// Tracks consecutive successes/failures per upstream and transitions
/// health state when thresholds are reached.
/// TigerStyle: No allocation, fixed-size counters, inline hot paths.
pub const HealthTracker = struct {
    /// Shared atomic health state (healthy/unhealthy bitmap).
    state: *SharedHealthState,

    /// Consecutive failures required to mark unhealthy.
    /// TigerStyle: Explicit threshold, not magic number.
    unhealthy_threshold: u8,

    /// Consecutive successes required to mark healthy.
    /// TigerStyle: Explicit threshold, not magic number.
    healthy_threshold: u8,

    /// Consecutive failure counts per upstream.
    /// TigerStyle: Fixed array, no runtime allocation.
    failure_counts: [MAX_UPSTREAMS]u8 = [_]u8{0} ** MAX_UPSTREAMS,

    /// Consecutive success counts per upstream.
    /// TigerStyle: Fixed array, no runtime allocation.
    success_counts: [MAX_UPSTREAMS]u8 = [_]u8{0} ** MAX_UPSTREAMS,

    const Self = @This();

    /// Initialize health tracker with thresholds.
    /// TigerStyle: Assertions validate thresholds are positive.
    pub fn init(
        state: *SharedHealthState,
        unhealthy_threshold: u8,
        healthy_threshold: u8,
    ) Self {
        // TigerStyle: Preconditions - thresholds must be positive
        assert(unhealthy_threshold > 0);
        assert(healthy_threshold > 0);

        return Self{
            .state = state,
            .unhealthy_threshold = unhealthy_threshold,
            .healthy_threshold = healthy_threshold,
        };
    }

    /// Record a successful health check or request.
    /// Resets failure counter and increments success counter.
    /// Transitions to healthy when success threshold reached.
    /// TigerStyle: Inline for hot path, fast return if already healthy.
    pub inline fn recordSuccess(self: *Self, idx: u6) void {
        // TigerStyle: Precondition - valid upstream index
        assert(idx < MAX_UPSTREAMS);

        // Reset failure counter on any success
        self.failure_counts[idx] = 0;

        // Fast path: already healthy, nothing to do
        if (self.state.isHealthy(idx)) {
            return;
        }

        // Increment success counter (saturating to prevent overflow)
        const new_count = self.success_counts[idx] +| 1;
        self.success_counts[idx] = new_count;

        // Transition to healthy if threshold reached
        if (new_count >= self.healthy_threshold) {
            self.state.markHealthy(idx);
            self.success_counts[idx] = 0;
        }
    }

    /// Record a failed health check or request.
    /// Resets success counter and increments failure counter.
    /// Transitions to unhealthy when failure threshold reached.
    /// TigerStyle: Inline for hot path, fast return if already unhealthy.
    pub inline fn recordFailure(self: *Self, idx: u6) void {
        // TigerStyle: Precondition - valid upstream index
        assert(idx < MAX_UPSTREAMS);

        // Reset success counter on any failure
        self.success_counts[idx] = 0;

        // Fast path: already unhealthy, nothing to do
        if (!self.state.isHealthy(idx)) {
            return;
        }

        // Increment failure counter (saturating to prevent overflow)
        const new_count = self.failure_counts[idx] +| 1;
        self.failure_counts[idx] = new_count;

        // Transition to unhealthy if threshold reached
        if (new_count >= self.unhealthy_threshold) {
            self.state.markUnhealthy(idx);
            self.failure_counts[idx] = 0;
        }
    }

    // =========================================================================
    // Delegate Methods
    // =========================================================================

    /// Check if upstream at index is healthy.
    /// TigerStyle: Inline delegation to SharedHealthState.
    pub inline fn isHealthy(self: *const Self, idx: u6) bool {
        assert(idx < MAX_UPSTREAMS);
        return self.state.isHealthy(idx);
    }

    /// Count number of healthy upstreams.
    /// TigerStyle: Inline delegation to SharedHealthState.
    pub inline fn countHealthy(self: *const Self) u32 {
        return self.state.countHealthy();
    }

    /// Find first healthy upstream index, optionally excluding one.
    /// Returns null if no healthy upstreams.
    /// TigerStyle: Inline delegation to SharedHealthState.
    pub inline fn findFirstHealthy(self: *const Self, exclude_idx: ?u6) ?u6 {
        return self.state.findFirstHealthy(exclude_idx);
    }

    /// Find Nth healthy upstream (0-indexed).
    /// Used for round-robin over healthy upstreams.
    /// Returns null if fewer than n+1 healthy upstreams.
    /// TigerStyle: Inline delegation to SharedHealthState.
    pub inline fn findNthHealthy(self: *const Self, n: u32) ?u6 {
        return self.state.findNthHealthy(n);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "HealthTracker init validates thresholds" {
    // Cannot test assertion failures in Zig tests without catching them,
    // so we just verify valid initialization works
    var state = SharedHealthState.init();
    const tracker = HealthTracker.init(&state, 3, 2);
    try std.testing.expectEqual(@as(u8, 3), tracker.unhealthy_threshold);
    try std.testing.expectEqual(@as(u8, 2), tracker.healthy_threshold);
}

test "HealthTracker recordSuccess transitions after threshold" {
    var state = SharedHealthState.init();
    var tracker = HealthTracker.init(&state, 3, 2);

    // Start unhealthy
    state.markUnhealthy(0);
    try std.testing.expect(!tracker.isHealthy(0));

    // First success - not yet healthy
    tracker.recordSuccess(0);
    try std.testing.expect(!tracker.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 1), tracker.success_counts[0]);

    // Second success - reaches threshold, now healthy
    tracker.recordSuccess(0);
    try std.testing.expect(tracker.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 0), tracker.success_counts[0]);
}

test "HealthTracker recordFailure transitions after threshold" {
    var state = SharedHealthState.init();
    var tracker = HealthTracker.init(&state, 3, 2);

    // Start healthy (default)
    try std.testing.expect(tracker.isHealthy(0));

    // First two failures - not yet unhealthy
    tracker.recordFailure(0);
    try std.testing.expect(tracker.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 1), tracker.failure_counts[0]);

    tracker.recordFailure(0);
    try std.testing.expect(tracker.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 2), tracker.failure_counts[0]);

    // Third failure - reaches threshold, now unhealthy
    tracker.recordFailure(0);
    try std.testing.expect(!tracker.isHealthy(0));
    try std.testing.expectEqual(@as(u8, 0), tracker.failure_counts[0]);
}

test "HealthTracker success resets failure counter" {
    var state = SharedHealthState.init();
    var tracker = HealthTracker.init(&state, 3, 2);

    // Accumulate failures
    tracker.recordFailure(0);
    tracker.recordFailure(0);
    try std.testing.expectEqual(@as(u8, 2), tracker.failure_counts[0]);

    // Single success resets failure counter
    tracker.recordSuccess(0);
    try std.testing.expectEqual(@as(u8, 0), tracker.failure_counts[0]);
    try std.testing.expect(tracker.isHealthy(0));
}

test "HealthTracker failure resets success counter" {
    var state = SharedHealthState.init();
    var tracker = HealthTracker.init(&state, 3, 2);

    // Mark unhealthy first
    state.markUnhealthy(0);

    // Accumulate successes
    tracker.recordSuccess(0);
    try std.testing.expectEqual(@as(u8, 1), tracker.success_counts[0]);

    // Single failure resets success counter
    tracker.recordFailure(0);
    try std.testing.expectEqual(@as(u8, 0), tracker.success_counts[0]);
    try std.testing.expect(!tracker.isHealthy(0));
}

test "HealthTracker fast path when already in target state" {
    var state = SharedHealthState.init();
    var tracker = HealthTracker.init(&state, 3, 2);

    // Already healthy - recordSuccess should be fast path
    try std.testing.expect(tracker.isHealthy(0));
    tracker.recordSuccess(0);
    // Success counter should not increment when already healthy
    try std.testing.expectEqual(@as(u8, 0), tracker.success_counts[0]);

    // Mark unhealthy
    state.markUnhealthy(0);
    try std.testing.expect(!tracker.isHealthy(0));

    // Already unhealthy - recordFailure should be fast path
    tracker.recordFailure(0);
    // Failure counter should not increment when already unhealthy
    try std.testing.expectEqual(@as(u8, 0), tracker.failure_counts[0]);
}

test "HealthTracker delegate methods" {
    var state = SharedHealthState.init();
    const tracker = HealthTracker.init(&state, 3, 2);

    // Initial state: all healthy
    try std.testing.expect(tracker.isHealthy(0));
    try std.testing.expectEqual(@as(u32, MAX_UPSTREAMS), tracker.countHealthy());
    try std.testing.expectEqual(@as(u6, 0), tracker.findFirstHealthy(null).?);

    // Mark first two unhealthy
    state.markUnhealthy(0);
    state.markUnhealthy(1);

    try std.testing.expect(!tracker.isHealthy(0));
    try std.testing.expect(!tracker.isHealthy(1));
    try std.testing.expect(tracker.isHealthy(2));
    try std.testing.expectEqual(@as(u32, MAX_UPSTREAMS - 2), tracker.countHealthy());
    try std.testing.expectEqual(@as(u6, 2), tracker.findFirstHealthy(null).?);

    // findNthHealthy
    try std.testing.expectEqual(@as(u6, 2), tracker.findNthHealthy(0).?);
    try std.testing.expectEqual(@as(u6, 3), tracker.findNthHealthy(1).?);
}
