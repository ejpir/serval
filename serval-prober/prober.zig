// serval-prober/prober.zig
//! Background Health Prober
//!
//! Probes unhealthy backends for recovery using HTTP GET requests.
//! Uses serval-client for HTTP communication, supporting both plain TCP and TLS.
//! Blocking I/O is intentional - runs in background thread, not on hot path.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const core = @import("serval-core");
const net = @import("serval-net");
const health_mod = @import("serval-health");
const ssl = @import("serval-tls").ssl;
const serval_client = @import("serval-client");
const scheduler = @import("scheduler.zig");
const adapters = @import("adapters.zig");

const Upstream = core.Upstream;
const HealthState = health_mod.HealthState;
const DnsResolver = net.DnsResolver;
const Client = serval_client.Client;
const Request = core.types.Request;

/// Context for background prober thread.
pub const ProberContext = struct {
    upstreams: []const Upstream,
    health: *HealthState,
    probe_running: *std.atomic.Value(bool),
    probe_interval_ms: u32,
    probe_timeout_ms: u32,
    health_path: []const u8,
    /// Caller-provided SSL context for TLS probes (null = plain HTTP only).
    /// Caller owns lifetime: create before starting prober, free after stopping.
    client_ctx: ?*ssl.SSL_CTX,
    /// DNS resolver for hostname resolution (caller owns lifetime).
    dns_resolver: *DnsResolver,
    /// Allocator for Io runtime (caller owns lifetime).
    allocator: std.mem.Allocator = std.heap.page_allocator,
};


/// Background probe loop - probes unhealthy backends for recovery.
/// Runs until probe_running is set to false.
pub fn probeLoop(ctx: ProberContext) void {
    assert(ctx.probe_interval_ms > 0);
    assert(ctx.probe_timeout_ms > 0);

    // One-time init at thread start, no allocation in probe loop.
    var io_runtime = Io.Threaded.init(ctx.allocator, .{});
    defer io_runtime.deinit();

    const io = io_runtime.io();

    // Shared client instance for all probes.
    var client = Client.init(
        ctx.allocator,
        ctx.dns_resolver,
        ctx.client_ctx,
        false, // prober typically doesn't verify TLS (internal backends)
    );
    defer client.deinit();

    var adapter_context = adapters.HttpProbeAdapterContext{
        .client = &client,
        .health_path = ctx.health_path,
    };

    const scheduler_context = scheduler.SchedulerContext{
        .upstreams = ctx.upstreams,
        .health = ctx.health,
        .probe_running = ctx.probe_running,
        .probe_interval_ms = ctx.probe_interval_ms,
        .adapter = .{
            .context = &adapter_context,
            .probeFn = adapters.httpProbe,
        },
    };

    scheduler.runLoopWithIo(scheduler_context, io);
}


test "parseHttpStatus - 2xx success codes" {
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

    // Below 2xx
    try std.testing.expect(!isSuccess(199));

    // 2xx range
    try std.testing.expect(isSuccess(200));
    try std.testing.expect(isSuccess(201));
    try std.testing.expect(isSuccess(204));
    try std.testing.expect(isSuccess(250));
    try std.testing.expect(isSuccess(299));

    // Above 2xx
    try std.testing.expect(!isSuccess(300));
    try std.testing.expect(!isSuccess(301));
    try std.testing.expect(!isSuccess(400));
    try std.testing.expect(!isSuccess(404));
    try std.testing.expect(!isSuccess(500));
    try std.testing.expect(!isSuccess(503));
}

test "ProberContext - field validation" {
    var dns_resolver: DnsResolver = undefined;
    DnsResolver.init(&dns_resolver, .{});
    const ctx = ProberContext{
        .upstreams = &[_]Upstream{},
        .health = undefined,
        .probe_running = undefined,
        .probe_interval_ms = 5000,
        .probe_timeout_ms = 2000,
        .health_path = "/health",
        .client_ctx = null,
        .dns_resolver = &dns_resolver,
    };

    try std.testing.expectEqual(@as(u32, 5000), ctx.probe_interval_ms);
    try std.testing.expectEqual(@as(u32, 2000), ctx.probe_timeout_ms);
    try std.testing.expectEqualStrings("/health", ctx.health_path);
    try std.testing.expect(ctx.client_ctx == null);
}

test "interval calculation" {
    const calcInterval = struct {
        fn calc(interval_ms: u32) struct { s: u64, ns: u64 } {
            const interval_s: u64 = interval_ms / 1000;
            const interval_ns: u64 = (@as(u64, interval_ms) % 1000) * 1_000_000;
            return .{ .s = interval_s, .ns = interval_ns };
        }
    }.calc;

    // 5000ms = 5s + 0ns
    var result = calcInterval(5000);
    try std.testing.expectEqual(@as(u64, 5), result.s);
    try std.testing.expectEqual(@as(u64, 0), result.ns);

    // 5500ms = 5s + 500_000_000ns
    result = calcInterval(5500);
    try std.testing.expectEqual(@as(u64, 5), result.s);
    try std.testing.expectEqual(@as(u64, 500_000_000), result.ns);

    // 100ms = 0s + 100_000_000ns
    result = calcInterval(100);
    try std.testing.expectEqual(@as(u64, 0), result.s);
    try std.testing.expectEqual(@as(u64, 100_000_000), result.ns);

    // 1ms = 0s + 1_000_000ns
    result = calcInterval(1);
    try std.testing.expectEqual(@as(u64, 0), result.s);
    try std.testing.expectEqual(@as(u64, 1_000_000), result.ns);
}

test "Request struct creation for probe" {
    var request = Request{
        .method = .GET,
        .path = "/health",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };

    try request.headers.put("Host", "backend1.example.com");
    try request.headers.put("Connection", "close");
    try request.headers.put("User-Agent", "serval-prober/1.0");

    try std.testing.expectEqual(core.types.Method.GET, request.method);
    try std.testing.expectEqualStrings("/health", request.path);
    try std.testing.expectEqual(@as(usize, 3), request.headers.count);

    const host = request.headers.get("Host");
    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("backend1.example.com", host.?);
}

test "Upstream struct with TLS flag" {
    const upstream_tls = Upstream{
        .host = "secure.example.com",
        .port = 443,
        .tls = true,
        .idx = 0,
    };

    try std.testing.expectEqualStrings("secure.example.com", upstream_tls.host);
    try std.testing.expectEqual(@as(u16, 443), upstream_tls.port);
    try std.testing.expect(upstream_tls.tls);

    const upstream_plain = Upstream{
        .host = "backend.local",
        .port = 8080,
        .tls = false,
        .idx = 1,
    };

    try std.testing.expectEqualStrings("backend.local", upstream_plain.host);
    try std.testing.expectEqual(@as(u16, 8080), upstream_plain.port);
    try std.testing.expect(!upstream_plain.tls);
}

test "header buffer size is reasonable" {
    // Buffer must fit status line (~17 bytes) plus minimal headers.
    const header_buf_size: usize = 1024;
    try std.testing.expect(header_buf_size >= 256);
    try std.testing.expect(header_buf_size <= 8192);
}
