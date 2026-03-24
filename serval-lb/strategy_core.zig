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

pub const StrategyConfig = struct {
    unhealthy_threshold: u8 = config.DEFAULT_UNHEALTHY_THRESHOLD,
    healthy_threshold: u8 = config.DEFAULT_HEALTHY_THRESHOLD,
};

pub const RoundRobinStrategy = struct {
    upstreams: []const Upstream,
    health: HealthState,
    next_idx: std.atomic.Value(u32),

    const Self = @This();

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

    pub fn select(self: *Self) Upstream {
        assert(self.upstreams.len > 0);

        const current = self.next_idx.fetchAdd(1, .monotonic);
        if (self.health.findNthHealthy(current)) |idx| {
            return self.upstreams[idx];
        }

        const fallback_idx = current % @as(u32, self.health.backend_count);
        return self.upstreams[fallback_idx];
    }

    pub fn recordSuccess(self: *Self, idx: UpstreamIndex) void {
        assert(idx < self.upstreams.len);
        self.health.recordSuccess(idx);
    }

    pub fn recordFailure(self: *Self, idx: UpstreamIndex) void {
        assert(idx < self.upstreams.len);
        self.health.recordFailure(idx);
    }

    pub fn countHealthy(self: *const Self) u32 {
        return self.health.countHealthy();
    }

    pub fn isHealthy(self: *const Self, idx: UpstreamIndex) bool {
        assert(idx < self.upstreams.len);
        return self.health.isHealthy(idx);
    }

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
