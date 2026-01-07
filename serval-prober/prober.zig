// serval-prober/prober.zig
//! Background Health Prober
//!
//! Probes unhealthy backends for recovery using HTTP GET requests.
//! TigerStyle: Blocking sockets with explicit timeouts, bounded operations.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;

const core = @import("serval-core");
const net = @import("serval-net");
const health_mod = @import("serval-health");

const Upstream = core.Upstream;
const HealthState = health_mod.HealthState;
const UpstreamIndex = core.config.UpstreamIndex;

/// Context for background prober thread.
/// TigerStyle: Explicit parameters, no implicit state.
pub const ProberContext = struct {
    upstreams: []const Upstream,
    health: *HealthState,
    probe_running: *std.atomic.Value(bool),
    probe_interval_ms: u32,
    probe_timeout_ms: u32,
    health_path: []const u8,
};

/// Background probe loop - probes unhealthy backends for recovery.
/// Runs until probe_running is set to false.
pub fn probeLoop(ctx: ProberContext) void {
    assert(ctx.probe_interval_ms > 0);
    assert(ctx.probe_timeout_ms > 0);

    const interval_s: u64 = ctx.probe_interval_ms / 1000;
    const interval_ns: u64 = (@as(u64, ctx.probe_interval_ms) % 1000) * 1_000_000;

    while (ctx.probe_running.load(.acquire)) {
        probeUnhealthyBackends(ctx);
        posix.nanosleep(interval_s, interval_ns);
    }
}

/// Probe all unhealthy backends.
fn probeUnhealthyBackends(ctx: ProberContext) void {
    // TigerStyle: Bounded loop over upstreams
    for (ctx.upstreams, 0..) |upstream, i| {
        const idx: UpstreamIndex = @intCast(i);

        // Only probe unhealthy backends (healthy ones get passive checks via traffic)
        if (ctx.health.isHealthy(idx)) continue;

        const success = probeBackend(upstream, ctx.probe_timeout_ms, ctx.health_path);
        if (success) {
            ctx.health.recordSuccess(idx);
        }
        // Don't record failure - backend is already unhealthy
    }
}

/// Probe a single backend with TCP connect + HTTP GET.
/// Returns true if probe succeeds (2xx response).
/// TigerStyle: Uses blocking sockets with timeouts for background thread.
fn probeBackend(upstream: Upstream, timeout_ms: u32, health_path: []const u8) bool {
    assert(timeout_ms > 0);

    // Parse IPv4 address
    var addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, upstream.port),
        .addr = net.parseIPv4(upstream.host) orelse return false,
    };

    // Create socket
    const sock = posix.socket(
        posix.AF.INET,
        posix.SOCK.STREAM,
        posix.IPPROTO.TCP,
    ) catch return false;
    defer posix.close(sock);

    // Set timeouts (non-critical, probe still works without them)
    const timeout_timeval = posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    // TigerStyle: Timeout is optimization, connect will timeout eventually via kernel defaults.
    // Failures logged at debug level - non-fatal for probe functionality.
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout_timeval)) catch |err| {
        std.log.debug("prober: SO_RCVTIMEO failed: {s}", .{@errorName(err)});
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout_timeval)) catch |err| {
        std.log.debug("prober: SO_SNDTIMEO failed: {s}", .{@errorName(err)});
    };

    // Connect
    posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch {
        return false;
    };

    // Send HTTP GET request
    var request_buf: [256]u8 = undefined;
    const request = std.fmt.bufPrint(&request_buf, "GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{
        health_path,
        upstream.host,
    }) catch return false;

    _ = posix.write(sock, request) catch return false;

    // Read response status line
    var response_buf: [128]u8 = undefined;
    const bytes_read = posix.read(sock, &response_buf) catch return false;
    if (bytes_read < 12) return false; // Minimum: "HTTP/1.1 200"

    // Parse status code
    const response = response_buf[0..bytes_read];
    if (!std.mem.startsWith(u8, response, "HTTP/1.")) return false;
    if (response.len < 12) return false;

    const status_str = response[9..12];
    const status = std.fmt.parseInt(u16, status_str, 10) catch return false;

    // 2xx = success
    return status >= 200 and status < 300;
}
