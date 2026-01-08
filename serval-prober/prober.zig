// serval-prober/prober.zig
//! Background Health Prober
//!
//! Probes unhealthy backends for recovery using HTTP GET requests.
//! Supports both IP addresses and hostnames via optional DNS resolution.
//! TigerStyle: Blocking sockets with explicit timeouts, bounded operations.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const Io = std.Io;

const core = @import("serval-core");
const net = @import("serval-net");
const health_mod = @import("serval-health");
const ssl = @import("serval-tls").ssl;

const Upstream = core.Upstream;
const HealthState = health_mod.HealthState;
const UpstreamIndex = core.config.UpstreamIndex;
const Socket = net.Socket;
const DnsResolver = net.DnsResolver;

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
    /// Optional DNS resolver for hostname resolution.
    /// TigerStyle: Shared resolver with TTL caching, caller owns lifetime.
    /// If null, only numeric IP addresses are supported (hostnames will fail probe).
    dns_resolver: ?*DnsResolver = null,
    /// Allocator for Io runtime (required if dns_resolver is set).
    /// TigerStyle: Explicit dependency, caller owns lifetime.
    allocator: std.mem.Allocator = std.heap.page_allocator,
};

/// Background probe loop - probes unhealthy backends for recovery.
/// Runs until probe_running is set to false.
/// TigerStyle: Creates Io runtime only if DNS resolver is configured.
pub fn probeLoop(ctx: ProberContext) void {
    assert(ctx.probe_interval_ms > 0);
    assert(ctx.probe_timeout_ms > 0);

    const interval_s: u64 = ctx.probe_interval_ms / 1000;
    const interval_ns: u64 = (@as(u64, ctx.probe_interval_ms) % 1000) * 1_000_000;

    // Initialize Io runtime for DNS resolution if resolver is configured.
    // TigerStyle: One-time initialization at thread start, no allocation in probe loop.
    var io_runtime: ?Io.Threaded = if (ctx.dns_resolver != null)
        Io.Threaded.init(ctx.allocator, .{})
    else
        null;
    defer if (io_runtime) |*runtime| runtime.deinit();

    // Get Io handle for DNS resolution (null if no resolver).
    const io: ?Io = if (io_runtime) |*runtime| runtime.io() else null;

    while (ctx.probe_running.load(.acquire)) {
        probeUnhealthyBackends(ctx, io);
        posix.nanosleep(interval_s, interval_ns);
    }
}

/// Probe all unhealthy backends.
/// TigerStyle: Accepts optional Io for DNS resolution.
fn probeUnhealthyBackends(ctx: ProberContext, io: ?Io) void {
    assert(ctx.upstreams.len > 0); // S1: precondition

    // TigerStyle: Bounded loop over upstreams
    for (ctx.upstreams, 0..) |upstream, i| {
        const idx: UpstreamIndex = @intCast(i);

        // Only probe unhealthy backends (healthy ones get passive checks via traffic)
        if (ctx.health.isHealthy(idx)) continue;

        const success = probeBackend(
            upstream,
            ctx.probe_timeout_ms,
            ctx.health_path,
            ctx.client_ctx,
            ctx.dns_resolver,
            io,
        );
        if (success) {
            ctx.health.recordSuccess(idx);
        }
        // Don't record failure - backend is already unhealthy
    }
}

/// Probe a single backend with TCP connect + HTTP GET.
/// Returns true if probe succeeds (2xx response).
/// TigerStyle: Uses blocking sockets with timeouts for background thread.
/// Supports both IPv4 addresses and hostnames (via DNS resolver).
fn probeBackend(
    upstream: Upstream,
    timeout_ms: u32,
    health_path: []const u8,
    client_ctx: ?*ssl.SSL_CTX,
    dns_resolver: ?*DnsResolver,
    io: ?Io,
) bool {
    assert(timeout_ms > 0); // S1: precondition
    assert(upstream.host.len > 0); // S1: precondition

    // Resolve address: try IPv4 first, then DNS if resolver available.
    // TigerStyle: Explicit fallback chain, no implicit behavior.
    const resolved = resolveAddress(upstream.host, upstream.port, dns_resolver, io) orelse {
        std.log.debug("prober: failed to resolve {s}:{d}", .{ upstream.host, upstream.port });
        return false;
    };

    // Create socket with appropriate address family.
    const fd = posix.socket(
        resolved.family,
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

    // Connect using resolved address.
    // TigerStyle: Cast storage to sockaddr pointer for connect() syscall.
    const sockaddr_ptr: *const posix.sockaddr = @ptrCast(&resolved.addr);
    posix.connect(fd, sockaddr_ptr, resolved.addrlen) catch {
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

/// Resolved address result for connect().
/// TigerStyle: Explicit struct to handle both IPv4 and IPv6.
/// Uses sockaddr.storage for IPv6 compatibility (128 bytes).
const ResolvedAddress = struct {
    addr: posix.sockaddr.storage,
    addrlen: posix.socklen_t,
    family: u32, // AF_INET or AF_INET6 as u32 for posix.socket()
};

/// Resolve hostname to address for connect().
/// Returns null if resolution fails.
/// TigerStyle: Try IPv4 parse first (fast path), then DNS resolution.
fn resolveAddress(
    host: []const u8,
    port: u16,
    dns_resolver: ?*DnsResolver,
    io: ?Io,
) ?ResolvedAddress {
    assert(host.len > 0); // S1: precondition
    assert(port > 0); // S1: precondition

    // Fast path: try parsing as IPv4 address (no DNS needed).
    if (net.parseIPv4(host)) |ipv4_addr| {
        return makeIPv4Result(ipv4_addr, port);
    }

    // Slow path: DNS resolution (if resolver available).
    const resolver = dns_resolver orelse return null;
    const io_handle = io orelse return null;

    const result = resolver.resolve(host, port, io_handle) catch |err| {
        std.log.debug("prober: DNS resolution failed for {s}: {s}", .{ host, @errorName(err) });
        return null;
    };

    // Convert Io.net.IpAddress to posix.sockaddr.
    // TigerStyle: Handle both IPv4 and IPv6 explicitly.
    switch (result.address) {
        .ip4 => |ip4| {
            return makeIPv4Result(@bitCast(ip4.bytes), ip4.port);
        },
        .ip6 => |ip6| {
            return makeIPv6Result(ip6.bytes, ip6.port, ip6.flow, ip6.interface.index);
        },
    }
}

/// Create IPv4 ResolvedAddress from address and port.
/// TigerStyle: Helper to avoid code duplication.
fn makeIPv4Result(addr: u32, port: u16) ResolvedAddress {
    // Initialize storage to zeros, then overlay IPv4 address.
    // TigerStyle: Zero initialization prevents information leaks.
    var storage: posix.sockaddr.storage = .{
        .family = posix.AF.INET,
        .padding = std.mem.zeroes([126]u8),
    };

    // Overlay IPv4 address onto storage.
    const in_ptr: *posix.sockaddr.in = @ptrCast(&storage);
    in_ptr.* = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = addr,
    };

    return .{
        .addr = storage,
        .addrlen = @sizeOf(posix.sockaddr.in),
        .family = posix.AF.INET,
    };
}

/// Create IPv6 ResolvedAddress from address components.
/// TigerStyle: Helper to avoid code duplication.
fn makeIPv6Result(addr: [16]u8, port: u16, flowinfo: u32, scope_id: u32) ResolvedAddress {
    // Initialize storage to zeros, then overlay IPv6 address.
    var storage: posix.sockaddr.storage = .{
        .family = posix.AF.INET6,
        .padding = std.mem.zeroes([126]u8),
    };

    // Overlay IPv6 address onto storage.
    const in6_ptr: *posix.sockaddr.in6 = @ptrCast(&storage);
    in6_ptr.* = .{
        .family = posix.AF.INET6,
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = flowinfo,
        .addr = addr,
        .scope_id = scope_id,
    };

    return .{
        .addr = storage,
        .addrlen = @sizeOf(posix.sockaddr.in6),
        .family = posix.AF.INET6,
    };
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
    // ProberContext requires all fields to be set (except optional dns_resolver and allocator)
    const ctx = ProberContext{
        .upstreams = &[_]Upstream{},
        .health = undefined,
        .probe_running = undefined,
        .probe_interval_ms = 5000,
        .probe_timeout_ms = 2000,
        .health_path = "/health",
        .client_ctx = null, // TLS context is optional (null = plain HTTP only)
        // dns_resolver defaults to null (only IP addresses supported)
        // allocator defaults to page_allocator
    };

    try std.testing.expectEqual(@as(u32, 5000), ctx.probe_interval_ms);
    try std.testing.expectEqual(@as(u32, 2000), ctx.probe_timeout_ms);
    try std.testing.expectEqualStrings("/health", ctx.health_path);
    try std.testing.expect(ctx.client_ctx == null);
    try std.testing.expect(ctx.dns_resolver == null);
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

test "resolveAddress - IPv4 fast path" {
    // IPv4 addresses should resolve without DNS (fast path)
    const result = resolveAddress("127.0.0.1", 8080, null, null);
    try std.testing.expect(result != null);

    const resolved = result.?;
    try std.testing.expectEqual(@as(u32, posix.AF.INET), resolved.family);
    try std.testing.expectEqual(@as(posix.socklen_t, @sizeOf(posix.sockaddr.in)), resolved.addrlen);

    // Verify address bytes (network byte order)
    const addr: *const posix.sockaddr.in = @ptrCast(&resolved.addr);
    try std.testing.expectEqual(posix.AF.INET, addr.family);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 8080), addr.port);
}

test "resolveAddress - IPv4 boundary addresses" {
    // Test various valid IPv4 addresses
    const test_cases = [_]struct { host: []const u8, expected_addr: u32 }{
        .{ .host = "0.0.0.0", .expected_addr = 0x00000000 },
        .{ .host = "255.255.255.255", .expected_addr = 0xFFFFFFFF },
        .{ .host = "192.168.1.1", .expected_addr = 0x0101A8C0 }, // Network byte order
    };

    for (test_cases) |tc| {
        const result = resolveAddress(tc.host, 80, null, null);
        try std.testing.expect(result != null);

        const resolved = result.?;
        const addr: *const posix.sockaddr.in = @ptrCast(&resolved.addr);
        try std.testing.expectEqual(tc.expected_addr, addr.addr);
    }
}

test "resolveAddress - hostname without resolver returns null" {
    // Hostnames should fail when no DNS resolver is provided
    const result = resolveAddress("example.com", 80, null, null);
    try std.testing.expect(result == null);
}

test "resolveAddress - invalid IPv4 returns null without resolver" {
    // Invalid addresses that aren't parseable as IPv4 should fail
    const test_cases = [_][]const u8{
        "256.0.0.1", // Invalid octet
        "127.0.0", // Missing octet
        "abc.def.ghi.jkl", // Non-numeric
    };

    for (test_cases) |host| {
        const result = resolveAddress(host, 80, null, null);
        try std.testing.expect(result == null);
    }
}

test "ResolvedAddress - struct size" {
    // TigerStyle: Verify struct is reasonably sized for stack allocation.
    // Uses sockaddr.storage (128 bytes) for IPv6 compatibility.
    const size = @sizeOf(ResolvedAddress);
    try std.testing.expect(size <= 144); // 128 (storage) + addrlen + family + padding
}
