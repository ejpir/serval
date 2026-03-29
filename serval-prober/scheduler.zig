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
const SHUTDOWN_POLL_MS: u32 = 100;

/// Adapter that binds an opaque probe state pointer to a concrete probe callback.
/// `context` is type-erased and passed back to `probeFn` unchanged on each probe attempt.
/// Callers must ensure `context` remains valid for every invocation using this adapter.
/// The callback reports probe outcome via `bool`; no error union is propagated by this interface.
pub const ProbeAdapter = struct {
    context: *anyopaque,
    probeFn: *const fn (context: *anyopaque, upstream: Upstream, io: Io) bool,
};

/// Context bundle consumed by the probe scheduler to run health checks for configured upstreams.
/// `upstreams` is a borrowed, immutable slice; the pointed data must outlive all scheduler use.
/// `health` and `probe_running` are shared mutable state pointers and must remain valid for the same lifetime.
/// `probe_interval_ms` configures probe cadence, and `adapter` provides the probe execution mechanism.
pub const SchedulerContext = struct {
    upstreams: []const Upstream,
    health: *HealthState,
    probe_running: *std.atomic.Value(bool),
    probe_interval_ms: u32,
    adapter: ProbeAdapter,
};

/// Runs the unhealthy-probe loop using the provided I/O implementation.
/// Preconditions: `ctx.probe_interval_ms > 0` (enforced by assertion) and `ctx.probe_running` is initialized.
/// While `ctx.probe_running` is `true`, this calls `probeUnhealthyOnce(ctx, io)` then sleeps via `interruptibleSleep`.
/// The sleep is interruptible through `ctx.probe_running`; the function returns once the flag is observed `false`.
/// This function returns no error; any failures must be handled by the called operations.
pub fn runLoopWithIo(ctx: SchedulerContext, io: Io) void {
    assert(ctx.probe_interval_ms > 0);

    while (ctx.probe_running.load(.acquire)) {
        probeUnhealthyOnce(ctx, io);
        interruptibleSleep(ctx.probe_running, ctx.probe_interval_ms, io);
    }
}

fn interruptibleSleep(probe_running: *std.atomic.Value(bool), total_ms: u32, io: Io) void {
    var remaining_ms: u32 = total_ms;
    while (remaining_ms > 0 and probe_running.load(.acquire)) {
        const sleep_ms = @min(remaining_ms, SHUTDOWN_POLL_MS);
        const duration = std.Io.Duration.fromMilliseconds(@intCast(sleep_ms));
        std.Io.sleep(std.Options.debug_io, duration, .awake) catch |err| {
            log.debug("scheduler: interruptible sleep failed: {s}", .{@errorName(err)});
        };
        remaining_ms -= sleep_ms;
    }
    _ = io;
}

/// Probes each upstream that is currently marked unhealthy exactly once.
/// Requires `ctx.upstreams.len > 0`; this is asserted before any probe runs.
/// For every unhealthy upstream, calls `ctx.adapter.probeFn(ctx.adapter.context, upstream, io)` and records success in `ctx.health` when it returns `true`.
/// Returns `void` and does not report probe failures; healthy upstreams are skipped.
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

test "runLoopWithIo exits immediately when probe_running is false" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    var health = HealthState.init(1, 1, 1);
    var running = std.atomic.Value(bool).init(false);

    var adapter_marker: u8 = 0;
    const NoopAdapter = struct {
        fn probe(context: *anyopaque, upstream: Upstream, io: Io) bool {
            _ = context;
            _ = upstream;
            _ = io;
            return false;
        }
    };

    const ctx = SchedulerContext{
        .upstreams = &upstreams,
        .health = &health,
        .probe_running = &running,
        .probe_interval_ms = 60_000,
        .adapter = .{
            .context = &adapter_marker,
            .probeFn = NoopAdapter.probe,
        },
    };

    runLoopWithIo(ctx, undefined);
}

test "interruptibleSleep exits early when flag flips mid-sleep" {
    var running = std.atomic.Value(bool).init(true);
    const start_ns = core.monotonicNanos();

    const sleeper = struct {
        fn run(probe_running: *std.atomic.Value(bool)) void {
            var io_runtime = std.Io.Threaded.init(std.heap.page_allocator, .{});
            defer io_runtime.deinit();
            interruptibleSleep(probe_running, 4_000, io_runtime.io());
        }
    }.run;

    const stopper = struct {
        fn run(probe_running: *std.atomic.Value(bool)) void {
            var io_runtime = std.Io.Threaded.init(std.heap.page_allocator, .{});
            defer io_runtime.deinit();
            const delay = std.Io.Duration.fromMilliseconds(300);
            std.Io.sleep(std.Options.debug_io, delay, .awake) catch |err| {
                std.debug.panic("stopper sleep failed: {s}", .{@errorName(err)});
            };
            probe_running.store(false, .release);
        }
    }.run;

    const sleeper_thread = std.Thread.spawn(.{}, sleeper, .{&running}) catch unreachable;
    const stopper_thread = std.Thread.spawn(.{}, stopper, .{&running}) catch unreachable;

    sleeper_thread.join();
    stopper_thread.join();

    const elapsed_ns = core.elapsedNanos(start_ns, core.monotonicNanos());
    const elapsed_ms: u64 = elapsed_ns / 1_000_000;

    // Full non-interruptible sleep would take ~4s.
    try std.testing.expect(elapsed_ms < 1_500);
}
