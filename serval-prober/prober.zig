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
const ssl = @import("serval-tls").ssl;

const Upstream = core.Upstream;
const HealthState = health_mod.HealthState;
const UpstreamIndex = core.config.UpstreamIndex;
const Socket = net.Socket;

// =============================================================================
// Prober Context
// =============================================================================

/// Context for background prober thread.
/// TigerStyle: Explicit parameters, no implicit state.
pub const ProberContext = struct {
    upstreams: []const Upstream,
    health: *HealthState,
    probe_running: *std.atomic.Value(bool),
    probe_interval_ms: u32,
    probe_timeout_ms: u32,
    health_path: []const u8,
    /// Caller-provided SSL context for TLS probes.
    /// TigerStyle: Explicit dependency injection, caller owns lifetime.
    /// Set to null if no TLS upstreams need probing (plain HTTP only).
    /// Verification settings are configured in the SSL_CTX by the caller.
    client_ctx: ?*ssl.SSL_CTX,
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
    assert(ctx.upstreams.len > 0); // S1: precondition

    // TigerStyle: Bounded loop over upstreams
    for (ctx.upstreams, 0..) |upstream, i| {
        const idx: UpstreamIndex = @intCast(i);

        // Only probe unhealthy backends (healthy ones get passive checks via traffic)
        if (ctx.health.isHealthy(idx)) continue;

        const success = probeBackend(upstream, ctx.probe_timeout_ms, ctx.health_path, ctx.client_ctx);
        if (success) {
            ctx.health.recordSuccess(idx);
        }
        // Don't record failure - backend is already unhealthy
    }
}

/// Probe a single backend with TCP connect + HTTP GET.
/// Returns true if probe succeeds (2xx response).
/// TigerStyle: Uses blocking sockets with timeouts for background thread.
fn probeBackend(
    upstream: Upstream,
    timeout_ms: u32,
    health_path: []const u8,
    client_ctx: ?*ssl.SSL_CTX,
) bool {
    assert(timeout_ms > 0); // S1: precondition
    assert(upstream.host.len > 0); // S1: precondition

    // Parse IPv4 address
    var addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, upstream.port),
        .addr = net.parseIPv4(upstream.host) orelse return false,
    };

    // Create socket
    const fd = posix.socket(
        posix.AF.INET,
        posix.SOCK.STREAM,
        posix.IPPROTO.TCP,
    ) catch return false;

    // Set timeouts (non-critical, probe still works without them)
    const timeout_timeval = posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    // TigerStyle: Timeout is optimization, connect will timeout eventually via kernel defaults.
    // Failures logged at debug level - non-fatal for probe functionality.
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout_timeval)) catch |err| {
        std.log.debug("prober: SO_RCVTIMEO failed: {s}", .{@errorName(err)});
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout_timeval)) catch |err| {
        std.log.debug("prober: SO_SNDTIMEO failed: {s}", .{@errorName(err)});
    };

    // Connect
    posix.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch {
        posix.close(fd);
        return false;
    };

    // Create Socket wrapper and probe
    if (upstream.tls) {
        const ctx = client_ctx orelse {
            std.log.debug("prober: TLS upstream but no client_ctx provided", .{});
            posix.close(fd);
            return false;
        };
        var socket = Socket.TLS.TLSSocket.initClient(fd, ctx, upstream.host) catch {
            std.log.debug("prober: TLS handshake failed for {s}:{d}", .{ upstream.host, upstream.port });
            posix.close(fd);
            return false;
        };
        defer socket.close();
        return probeWithSocket(&socket, upstream, health_path);
    } else {
        var socket = Socket.Plain.initClient(fd);
        defer socket.close();
        return probeWithSocket(&socket, upstream, health_path);
    }
}

/// Probe backend using Socket abstraction.
/// TigerStyle: Unified probe logic for both plain and TLS sockets.
fn probeWithSocket(socket: *Socket, upstream: Upstream, health_path: []const u8) bool {
    assert(upstream.host.len > 0); // S1: precondition

    // Send HTTP GET request
    var request_buf: [256]u8 = std.mem.zeroes([256]u8); // S5: zeroed to prevent leaks
    const request = std.fmt.bufPrint(&request_buf, "GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{
        health_path,
        upstream.host,
    }) catch return false;

    _ = socket.write(request) catch return false;

    // Read response status line
    var response_buf: [128]u8 = std.mem.zeroes([128]u8); // S5: zeroed to prevent leaks
    const bytes_read = socket.read(&response_buf) catch return false;
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

// =============================================================================
// Tests
// =============================================================================

test "parseHttpStatus - 2xx success codes" {
    // Test helper that mimics status parsing logic
    const testStatus = struct {
        fn check(response: []const u8) ?u16 {
            if (!std.mem.startsWith(u8, response, "HTTP/1.")) return null;
            if (response.len < 12) return null;
            const status_str = response[9..12];
            return std.fmt.parseInt(u16, status_str, 10) catch null;
        }
    }.check;

    // Valid 2xx responses
    try std.testing.expectEqual(@as(?u16, 200), testStatus("HTTP/1.1 200 OK\r\n"));
    try std.testing.expectEqual(@as(?u16, 201), testStatus("HTTP/1.1 201 Created\r\n"));
    try std.testing.expectEqual(@as(?u16, 204), testStatus("HTTP/1.1 204 No Content\r\n"));
    try std.testing.expectEqual(@as(?u16, 299), testStatus("HTTP/1.1 299 Custom\r\n"));

    // Non-2xx responses
    try std.testing.expectEqual(@as(?u16, 301), testStatus("HTTP/1.1 301 Moved\r\n"));
    try std.testing.expectEqual(@as(?u16, 404), testStatus("HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expectEqual(@as(?u16, 500), testStatus("HTTP/1.1 500 Error\r\n"));
    try std.testing.expectEqual(@as(?u16, 503), testStatus("HTTP/1.1 503 Unavailable\r\n"));

    // HTTP/1.0 also valid
    try std.testing.expectEqual(@as(?u16, 200), testStatus("HTTP/1.0 200 OK\r\n"));

    // Invalid responses
    try std.testing.expectEqual(@as(?u16, null), testStatus("HTTP/2.0 200 OK\r\n")); // HTTP/2 prefix
    try std.testing.expectEqual(@as(?u16, null), testStatus("HTTP/1.1 ")); // Too short
    try std.testing.expectEqual(@as(?u16, null), testStatus("INVALID")); // Not HTTP
    try std.testing.expectEqual(@as(?u16, null), testStatus("")); // Empty
}

test "isSuccessStatus - 2xx range check" {
    const isSuccess = struct {
        fn check(status: u16) bool {
            return status >= 200 and status < 300;
        }
    }.check;

    // Boundary: below 2xx
    try std.testing.expect(!isSuccess(199));

    // 2xx range (success)
    try std.testing.expect(isSuccess(200));
    try std.testing.expect(isSuccess(201));
    try std.testing.expect(isSuccess(204));
    try std.testing.expect(isSuccess(250));
    try std.testing.expect(isSuccess(299));

    // Boundary: above 2xx
    try std.testing.expect(!isSuccess(300));
    try std.testing.expect(!isSuccess(301));
    try std.testing.expect(!isSuccess(400));
    try std.testing.expect(!isSuccess(404));
    try std.testing.expect(!isSuccess(500));
    try std.testing.expect(!isSuccess(503));
}

test "ProberContext - field validation" {
    // ProberContext requires all fields to be set
    const ctx = ProberContext{
        .upstreams = &[_]Upstream{},
        .health = undefined,
        .probe_running = undefined,
        .probe_interval_ms = 5000,
        .probe_timeout_ms = 2000,
        .health_path = "/health",
        .client_ctx = null, // TLS context is optional (null = plain HTTP only)
    };

    try std.testing.expectEqual(@as(u32, 5000), ctx.probe_interval_ms);
    try std.testing.expectEqual(@as(u32, 2000), ctx.probe_timeout_ms);
    try std.testing.expectEqualStrings("/health", ctx.health_path);
    try std.testing.expect(ctx.client_ctx == null);
}

test "interval calculation" {
    // Test the interval_s and interval_ns calculation used in probeLoop
    const testInterval = struct {
        fn calc(interval_ms: u32) struct { s: u64, ns: u64 } {
            const interval_s: u64 = interval_ms / 1000;
            const interval_ns: u64 = (@as(u64, interval_ms) % 1000) * 1_000_000;
            return .{ .s = interval_s, .ns = interval_ns };
        }
    }.calc;

    // 5000ms = 5s + 0ns
    var result = testInterval(5000);
    try std.testing.expectEqual(@as(u64, 5), result.s);
    try std.testing.expectEqual(@as(u64, 0), result.ns);

    // 5500ms = 5s + 500_000_000ns
    result = testInterval(5500);
    try std.testing.expectEqual(@as(u64, 5), result.s);
    try std.testing.expectEqual(@as(u64, 500_000_000), result.ns);

    // 100ms = 0s + 100_000_000ns
    result = testInterval(100);
    try std.testing.expectEqual(@as(u64, 0), result.s);
    try std.testing.expectEqual(@as(u64, 100_000_000), result.ns);

    // 1ms = 0s + 1_000_000ns
    result = testInterval(1);
    try std.testing.expectEqual(@as(u64, 0), result.s);
    try std.testing.expectEqual(@as(u64, 1_000_000), result.ns);
}
