// serval-lb/handler.zig
//! Load Balancer Handler
//!
//! Health-aware round-robin upstream selection with automatic background probing.
//! Backends recover automatically when probes succeed.
//!
//! TigerStyle: No allocation after init, bounded loops, explicit types.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const net = @import("serval-net");
const health_mod = @import("serval-health");
const prober = @import("serval-prober");
const ssl = @import("serval-tls").ssl;

const Context = core.Context;
const Request = core.Request;
const Upstream = core.Upstream;
const LogEntry = core.LogEntry;
const config = core.config;
const DnsResolver = net.DnsResolver;

const HealthState = health_mod.HealthState;
const UpstreamIndex = config.UpstreamIndex;
const MAX_UPSTREAMS = health_mod.MAX_UPSTREAMS;

/// Load balancer configuration.
pub const LbConfig = struct {
    /// Consecutive failures before marking unhealthy.
    unhealthy_threshold: u8 = config.DEFAULT_UNHEALTHY_THRESHOLD,
    /// Consecutive successes before marking healthy.
    healthy_threshold: u8 = config.DEFAULT_HEALTHY_THRESHOLD,
    /// Enable background health probing (set false for tests).
    enable_probing: bool = true,
    /// Interval between probe cycles in milliseconds.
    probe_interval_ms: u32 = config.DEFAULT_PROBE_INTERVAL_MS,
    /// Timeout for each probe in milliseconds.
    probe_timeout_ms: u32 = config.DEFAULT_PROBE_TIMEOUT_MS,
    /// Health check path.
    health_path: []const u8 = config.DEFAULT_HEALTH_PATH,
};

/// Load balancer handler with health tracking and automatic probing.
///
/// Features:
/// - Health-aware round-robin selection (skips unhealthy backends)
/// - Passive health updates via onLog (5xx = failure)
/// - Active background probing for recovery
/// - Graceful degradation when all backends unhealthy
///
/// TigerStyle: Embedded HealthState (no pointers), bounded by MAX_UPSTREAMS.
pub const LbHandler = struct {
    upstreams: []const Upstream,
    health: HealthState,
    next_idx: std.atomic.Value(u32),
    probe_running: std.atomic.Value(bool),
    probe_thread: ?std.Thread,
    lb_config: LbConfig,

    const Self = @This();

    /// Initialize load balancer and start background prober.
    /// TigerStyle C3: Out-pointer for large struct, stable pointer for thread.
    /// TigerStyle: Caller provides SSL_CTX for TLS probes (caller owns lifetime).
    ///
    /// client_ctx: SSL_CTX for TLS health probes (required if any upstream has tls=true).
    ///             Caller is responsible for creating and freeing the context.
    ///             Pass null if all upstreams are plain HTTP.
    /// dns_resolver: DNS resolver for hostname resolution in health probes.
    ///               Required if probing is enabled. Caller owns lifetime.
    pub fn init(
        self: *Self,
        upstreams: []const Upstream,
        lb_config: LbConfig,
        client_ctx: ?*ssl.SSL_CTX,
        dns_resolver: ?*DnsResolver,
    ) !void {
        assert(upstreams.len > 0);
        assert(upstreams.len <= MAX_UPSTREAMS);
        assert(lb_config.probe_interval_ms > 0);
        assert(lb_config.probe_timeout_ms > 0);
        // S1: if probing enabled, dns_resolver must be provided
        assert(!lb_config.enable_probing or dns_resolver != null);

        self.* = .{
            .upstreams = upstreams,
            .health = HealthState.init(
                @intCast(upstreams.len),
                lb_config.unhealthy_threshold,
                lb_config.healthy_threshold,
            ),
            .next_idx = std.atomic.Value(u32).init(0),
            .probe_running = std.atomic.Value(bool).init(false),
            .probe_thread = null,
            .lb_config = lb_config,
        };

        // Start background prober if enabled
        if (lb_config.enable_probing) {
            self.probe_running.store(true, .release);
            const ctx = prober.ProberContext{
                .upstreams = upstreams,
                .health = &self.health,
                .probe_running = &self.probe_running,
                .probe_interval_ms = lb_config.probe_interval_ms,
                .probe_timeout_ms = lb_config.probe_timeout_ms,
                .health_path = lb_config.health_path,
                .client_ctx = client_ctx,
                .dns_resolver = dns_resolver.?,
            };
            self.probe_thread = try std.Thread.spawn(.{}, prober.probeLoop, .{ctx});
        }
    }

    /// Stop background prober and clean up.
    pub fn deinit(self: *Self) void {
        // Signal prober to stop
        self.probe_running.store(false, .release);

        // Wait for thread to exit
        if (self.probe_thread) |thread| {
            thread.join();
            self.probe_thread = null;
        }
    }

    /// Health-aware round-robin selection.
    /// Falls back to simple round-robin if all backends unhealthy.
    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Upstream {
        _ = ctx;
        _ = request;
        assert(self.upstreams.len > 0);

        const current = self.next_idx.fetchAdd(1, .monotonic);

        // Try health-aware selection
        if (self.health.findNthHealthy(current)) |idx| {
            return self.upstreams[idx];
        }

        // Fallback: all unhealthy, use simple round-robin (graceful degradation)
        const fallback_idx = current % @as(u32, @intCast(self.upstreams.len));
        return self.upstreams[fallback_idx];
    }

    /// Record request outcome for passive health tracking.
    /// 5xx responses count as failures, everything else as success.
    pub fn onLog(self: *Self, ctx: *Context, entry: LogEntry) void {
        _ = ctx;

        const upstream = entry.upstream orelse return;

        assert(upstream.idx < MAX_UPSTREAMS);
        const idx: UpstreamIndex = @intCast(upstream.idx);

        if (entry.status >= 500) {
            self.health.recordFailure(idx);
        } else {
            self.health.recordSuccess(idx);
        }
    }

    /// Count healthy backends (for observability).
    pub fn countHealthy(self: *const Self) u32 {
        return self.health.countHealthy();
    }

    /// Check if specific backend is healthy.
    pub fn isHealthy(self: *const Self, idx: UpstreamIndex) bool {
        assert(idx < self.upstreams.len);
        return self.health.isHealthy(idx);
    }

};

// =============================================================================
// Tests
// =============================================================================

fn makeLogEntry(status: u16, upstream_idx: UpstreamIndex) LogEntry {
    return .{
        .timestamp_s = 0,
        .start_time_ns = 0,
        .duration_ns = 0,
        .method = .GET,
        .path = "/",
        .request_bytes = 0,
        .status = status,
        .response_bytes = 0,
        .upstream = .{ .host = "backend", .port = 8000, .idx = upstream_idx },
        .upstream_duration_ns = 0,
        .error_phase = null,
        .error_name = null,
        .connection_reused = false,
        .keepalive = true,
    };
}

test "LbHandler init and deinit" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
    };

    // Disable probing for tests (no real backends)
    var handler: LbHandler = undefined;
    try handler.init(&upstreams, .{ .enable_probing = false }, null, null);
    defer handler.deinit();

    try std.testing.expect(!handler.probe_running.load(.acquire));
    try std.testing.expect(handler.probe_thread == null);
}

test "LbHandler selectUpstream round-robin" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
        .{ .host = "127.0.0.1", .port = 8003, .idx = 2 },
    };

    var handler: LbHandler = undefined;
    try handler.init(&upstreams, .{ .enable_probing = false }, null, null);
    defer handler.deinit();

    var ctx = Context.init();
    const request = Request{};

    // All healthy - cycles through all
    const first = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqual(@as(u16, 8001), first.port);

    const second = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqual(@as(u16, 8002), second.port);

    const third = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqual(@as(u16, 8003), third.port);

    // Wraps around
    const fourth = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqual(@as(u16, 8001), fourth.port);
}

test "LbHandler skips unhealthy backends" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
        .{ .host = "127.0.0.1", .port = 8003, .idx = 2 },
    };

    // threshold=2: 2 failures = unhealthy
    var handler: LbHandler = undefined;
    try handler.init(&upstreams, .{
        .enable_probing = false,
        .unhealthy_threshold = 2,
        .healthy_threshold = 2,
    }, null, null);
    defer handler.deinit();

    var ctx = Context.init();
    const request = Request{};

    // Mark backend 0 unhealthy
    handler.onLog(&ctx, makeLogEntry(500, 0));
    handler.onLog(&ctx, makeLogEntry(500, 0));

    try std.testing.expect(!handler.isHealthy(0));
    try std.testing.expect(handler.isHealthy(1));

    // Selection skips backend 0
    const first = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqual(@as(u16, 8002), first.port);

    const second = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqual(@as(u16, 8003), second.port);
}

test "LbHandler fallback when all unhealthy" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
    };

    var handler: LbHandler = undefined;
    try handler.init(&upstreams, .{
        .enable_probing = false,
        .unhealthy_threshold = 1,
        .healthy_threshold = 1,
    }, null, null);
    defer handler.deinit();

    var ctx = Context.init();
    const request = Request{};

    // Mark all unhealthy
    handler.onLog(&ctx, makeLogEntry(500, 0));
    handler.onLog(&ctx, makeLogEntry(500, 1));

    try std.testing.expectEqual(@as(u32, 0), handler.countHealthy());

    // Falls back to round-robin
    const first = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqual(@as(u16, 8001), first.port);

    const second = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqual(@as(u16, 8002), second.port);
}

test "LbHandler onLog updates health" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    var handler: LbHandler = undefined;
    try handler.init(&upstreams, .{
        .enable_probing = false,
        .unhealthy_threshold = 3,
        .healthy_threshold = 2,
    }, null, null);
    defer handler.deinit();

    var ctx = Context.init();

    // 2xx/4xx = success
    handler.onLog(&ctx, makeLogEntry(200, 0));
    handler.onLog(&ctx, makeLogEntry(404, 0));
    try std.testing.expect(handler.isHealthy(0));

    // 3 failures = unhealthy
    handler.onLog(&ctx, makeLogEntry(500, 0));
    handler.onLog(&ctx, makeLogEntry(502, 0));
    handler.onLog(&ctx, makeLogEntry(503, 0));
    try std.testing.expect(!handler.isHealthy(0));

    // 2 successes = healthy again
    handler.onLog(&ctx, makeLogEntry(200, 0));
    handler.onLog(&ctx, makeLogEntry(200, 0));
    try std.testing.expect(handler.isHealthy(0));
}
