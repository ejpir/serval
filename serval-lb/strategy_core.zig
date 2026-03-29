//! Shared strategy core for health-aware upstream selection.
//!
//! Protocol-agnostic: no HTTP Request/LogEntry dependency.

const std = @import("std");
const assert = std.debug.assert;

const core = @import("serval-core");
const health_mod = @import("serval-health");

const Upstream = core.Upstream;
const config = core.config;

const HealthState = health_mod.HealthState;
const UpstreamIndex = config.UpstreamIndex;
const MAX_UPSTREAMS = health_mod.MAX_UPSTREAMS;

/// Configuration for health-state threshold counters used by strategy logic.
/// `unhealthy_threshold` defaults to `config.DEFAULT_UNHEALTHY_THRESHOLD`.
/// `healthy_threshold` defaults to `config.DEFAULT_HEALTHY_THRESHOLD`.
/// Both fields are `u8` values and can be overridden at initialization time.
pub const StrategyConfig = struct {
    unhealthy_threshold: u8 = config.DEFAULT_UNHEALTHY_THRESHOLD,
    healthy_threshold: u8 = config.DEFAULT_HEALTHY_THRESHOLD,
};

/// Round-robin upstream selector with health-aware preference and atomic index progression.
/// `init` requires `upstreams.len > 0`, `upstreams.len <= MAX_UPSTREAMS`, and non-zero health thresholds; it stores the provided upstream slice by reference.
/// The caller must keep `upstreams` alive and unchanged for the strategy lifetime, since selections return entries from that slice.
/// `select` advances `next_idx` atomically, returns the Nth healthy upstream when available, and falls back to modulo-based round-robin when none are healthy.
/// Index-based health APIs (`recordSuccess`, `recordFailure`, `isHealthy`) require `idx < upstreams.len`; violated preconditions trigger assertions.
pub const RoundRobinStrategy = struct {
    upstreams: []const Upstream,
    health: HealthState,
    next_idx: std.atomic.Value(u32),

    const Self = @This();

    /// Initializes this strategy instance with the provided upstream set and health thresholds.
    /// Preconditions: `upstreams.len` must be in `1..=MAX_UPSTREAMS`, and both thresholds must be greater than zero.
    /// Stores `upstreams` by reference (no copy); the backing memory must remain valid for the strategy’s lifetime.
    /// Resets internal health tracking from `strategy_config` and sets the atomic round-robin index to `0`.
    /// This function is infallible; violated preconditions trigger `assert` failure.
    pub fn init(self: *Self, upstreams: []const Upstream, strategy_config: StrategyConfig) void {
        assert(upstreams.len > 0);
        assert(upstreams.len <= MAX_UPSTREAMS);
        assert(strategy_config.unhealthy_threshold > 0);
        assert(strategy_config.healthy_threshold > 0);

        self.* = .{
            .upstreams = upstreams,
            .health = HealthState.init(
                @intCast(upstreams.len),
                strategy_config.unhealthy_threshold,
                strategy_config.healthy_threshold,
            ),
            .next_idx = std.atomic.Value(u32).init(0),
        };
    }

    /// Selects an upstream using a monotonically incrementing round-robin counter.
    /// Preconditions: `self.upstreams.len > 0` (enforced by assertion) and `health.backend_count` must be valid for modulo indexing.
    /// It first attempts `health.findNthHealthy(current)` and returns that healthy upstream when found.
    /// If no healthy backend is reported for this turn, it falls back to `current % backend_count` and returns that upstream by value (no ownership transfer).
    pub fn select(self: *Self) Upstream {
        assert(self.upstreams.len > 0);

        const current = self.next_idx.fetchAdd(1, .monotonic);
        if (self.health.findNthHealthy(current)) |idx| {
            return self.upstreams[idx];
        }

        const fallback_idx = current % @as(u32, self.health.backend_count);
        return self.upstreams[fallback_idx];
    }

    /// Records a successful outcome for the upstream at `idx` in this strategy's health tracker.
    /// Preconditions: `idx` must be a valid upstream index (`idx < self.upstreams.len`), enforced by assertion.
    /// This function does not allocate or return errors; it forwards directly to `self.health.recordSuccess(idx)`.
    pub fn recordSuccess(self: *Self, idx: UpstreamIndex) void {
        assert(idx < self.upstreams.len);
        self.health.recordSuccess(idx);
    }

    /// Records a failure for the upstream at `idx` in the health tracker.
    /// Preconditions: `idx` must be a valid index into `self.upstreams` (`idx < self.upstreams.len`).
    /// This function does not return an error; it forwards to `self.health.recordFailure` after the bounds assertion.
    pub fn recordFailure(self: *Self, idx: UpstreamIndex) void {
        assert(idx < self.upstreams.len);
        self.health.recordFailure(idx);
    }

    /// Returns the number of backends currently marked healthy by this strategy state.
    /// This is a read-only query that forwards to `self.health.countHealthy()`.
    /// Preconditions: `self` must reference a valid, initialized `Self` with a valid `health` tracker.
    /// Does not allocate, does not transfer ownership, and cannot fail.
    pub fn countHealthy(self: *const Self) u32 {
        return self.health.countHealthy();
    }

    /// Returns whether the upstream at `idx` is currently marked healthy.
    /// Preconditions: `idx` must be a valid index into `self.upstreams` (`idx < self.upstreams.len`), enforced by `assert`.
    /// This function is a pure query over internal health state and does not allocate or return errors.
    pub fn isHealthy(self: *const Self, idx: UpstreamIndex) bool {
        assert(idx < self.upstreams.len);
        return self.health.isHealthy(idx);
    }

    /// Returns a mutable pointer to this strategy's `HealthState`.
    /// Preconditions: `self` must be a valid, initialized `*Self`.
    /// The returned pointer aliases `self.health` and is only valid while `self` remains alive and not moved.
    pub fn healthPtr(self: *Self) *HealthState {
        return &self.health;
    }
};

test "RoundRobinStrategy select falls back when all unhealthy" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
    };

    var strategy: RoundRobinStrategy = undefined;
    strategy.init(&upstreams, .{ .unhealthy_threshold = 1, .healthy_threshold = 1 });

    strategy.recordFailure(0);
    strategy.recordFailure(1);
    try std.testing.expectEqual(@as(u32, 0), strategy.countHealthy());

    const first = strategy.select();
    const second = strategy.select();
    try std.testing.expectEqual(@as(u16, 8001), first.port);
    try std.testing.expectEqual(@as(u16, 8002), second.port);
}
