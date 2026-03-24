//! Shared probe scheduler core.
//!
//! Protocol-agnostic loop/scheduling + health update behavior.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const core = @import("serval-core");
const log = core.log.scoped(.prober_scheduler);
const health_mod = @import("serval-health");

const Upstream = core.Upstream;
const HealthState = health_mod.HealthState;
const UpstreamIndex = core.config.UpstreamIndex;

pub const ProbeAdapter = struct {
    context: *anyopaque,
    probeFn: *const fn (context: *anyopaque, upstream: Upstream, io: Io) bool,
};

pub const SchedulerContext = struct {
    upstreams: []const Upstream,
    health: *HealthState,
    probe_running: *std.atomic.Value(bool),
    probe_interval_ms: u32,
    adapter: ProbeAdapter,
};

pub fn runLoopWithIo(ctx: SchedulerContext, io: Io) void {
    assert(ctx.probe_interval_ms > 0);

    const interval_duration = std.Io.Duration.fromMilliseconds(@intCast(ctx.probe_interval_ms));

    while (ctx.probe_running.load(.acquire)) {
        probeUnhealthyOnce(ctx, io);
        std.Io.sleep(std.Options.debug_io, interval_duration, .awake) catch |err| {
            log.debug("scheduler: sleep failed: {s}", .{@errorName(err)});
        };
    }
}

pub fn probeUnhealthyOnce(ctx: SchedulerContext, io: Io) void {
    assert(ctx.upstreams.len > 0);

    for (ctx.upstreams, 0..) |upstream, idx_usize| {
        const idx: UpstreamIndex = @intCast(idx_usize);

        if (ctx.health.isHealthy(idx)) continue;

        const success = ctx.adapter.probeFn(ctx.adapter.context, upstream, io);
        if (success) {
            ctx.health.recordSuccess(idx);
        }
    }
}

test "probeUnhealthyOnce records success for unhealthy backend" {
    const AdapterContext = struct {
        fn probe(context: *anyopaque, upstream: Upstream, io: Io) bool {
            _ = context;
            _ = io;
            return upstream.idx == 1;
        }
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
    };

    var health = HealthState.init(2, 1, 1);
    health.recordFailure(1);

    var running = std.atomic.Value(bool).init(true);
    var adapter_marker: u8 = 0;

    const ctx = SchedulerContext{
        .upstreams = &upstreams,
        .health = &health,
        .probe_running = &running,
        .probe_interval_ms = 100,
        .adapter = .{
            .context = &adapter_marker,
            .probeFn = AdapterContext.probe,
        },
    };

    try std.testing.expect(!health.isHealthy(1));
    probeUnhealthyOnce(ctx, undefined);
    try std.testing.expect(health.isHealthy(1));
}
