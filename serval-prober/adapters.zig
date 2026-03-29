//! Probe adapters for protocol-specific probe behavior.
//!
//! HTTP adapter preserves current 2xx semantics.
//! TCP adapter uses connect success semantics (and TLS handshake for tls upstreams).
//! UDP adapter supports passive-only and active probing modes.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const posix = std.posix;

const core = @import("serval-core");
const net = @import("serval-net");
const serval_client = @import("serval-client");

const Upstream = core.Upstream;
const Request = core.types.Request;
const Client = serval_client.Client;
const DnsResolver = net.DnsResolver;

/// Context passed to HTTP probe adapter operations.
/// Holds a non-owning pointer to the shared `Client` used for probe requests.
/// `health_path` is the request path to probe (for example, `"/health"`), stored as a non-owning byte slice.
/// Callers must ensure both `client` and `health_path` remain valid for the full lifetime of this context.
pub const HttpProbeAdapterContext = struct {
    client: *Client,
    health_path: []const u8,
};

/// Runs an HTTP health probe for `upstream` using adapter state from `context`.
/// `context` must be a valid, correctly aligned `*HttpProbeAdapterContext` whose `health_path` is non-empty (asserted).
/// The call forwards `client`, `health_path`, and `io` to `probeHttp` and returns its boolean result.
/// This function does not allocate and does not take ownership of `context`, `upstream`, or `io`.
pub fn httpProbe(context: *anyopaque, upstream: Upstream, io: Io) bool {
    const adapter_context: *HttpProbeAdapterContext = @ptrCast(@alignCast(context));
    assert(adapter_context.health_path.len > 0);

    return probeHttp(adapter_context.client, upstream, adapter_context.health_path, io);
}

/// Adapter context for TCP probe operations, carrying the probe client instance.
/// `client` is a borrowed pointer and is not owned by this context.
/// The referenced `Client` must remain valid for the full lifetime of any adapter use of this context.
pub const TcpProbeAdapterContext = struct {
    client: *Client,
};

/// Attempts a TCP connect check using the adapter client for `upstream` and `io`.
/// `context` must be a valid, properly aligned `*TcpProbeAdapterContext` for this probe call.
/// On successful `client.connect`, the returned connection socket is immediately closed and not retained.
/// Returns `true` only when connect succeeds; returns `false` for any connect error.
pub fn tcpConnectProbe(context: *anyopaque, upstream: Upstream, io: Io) bool {
    const adapter_context: *TcpProbeAdapterContext = @ptrCast(@alignCast(context));

    const result = adapter_context.client.connect(upstream, io) catch {
        return false;
    };

    result.conn.socket.close();
    return true;
}

/// Controls how a UDP probe interacts with the target endpoint.
/// `passive_only` performs no outbound UDP send and only evaluates passive observations.
/// `active_send` sends a UDP probe packet without requiring any response.
/// `active_send_expect` sends a UDP probe packet and expects a response for success.
pub const UdpProbeMode = enum {
    passive_only,
    active_send,
    active_send_expect,
};

/// Context/configuration for UDP probe adapter execution.
/// `dns_resolver` must point to a valid `DnsResolver` for target resolution and must outlive any adapter use of this context.
/// `probe_mode` selects probe behavior; default is `.passive_only`.
/// `payload` is the probe payload for active sends, and `expect_payload` (if set) is the exact response payload to match; both slices are borrowed and must remain valid.
/// `response_timeout_ms` sets the response wait timeout in milliseconds (default `500`).
pub const UdpProbeAdapterContext = struct {
    dns_resolver: *DnsResolver,
    probe_mode: UdpProbeMode = .passive_only,
    payload: []const u8 = "serval-udp-probe",
    expect_payload: ?[]const u8 = null,
    response_timeout_ms: u32 = 500,
};

/// Performs a UDP probe using `adapter_context` from `context` and returns `true` only when the configured probe condition succeeds.
/// In `.passive_only` mode it always returns `false`; in active modes it resolves `upstream`, opens a datagram socket, sends `payload`, and closes the socket before returning.
/// Preconditions: `context` must point to a valid `UdpProbeAdapterContext`; `payload.len > 0` and `response_timeout_ms > 0` are required (asserted).
/// `.active_send` succeeds after a successful send; `.active_send_expect` additionally requires a non-empty response before timeout and, when `expect_payload` is set, an exact length/content match.
/// Any resolution/socket/send/setsockopt/recv failure (or invalid fd/empty response) results in `false`.
pub fn udpProbe(context: *anyopaque, upstream: Upstream, io: Io) bool {
    const adapter_context: *UdpProbeAdapterContext = @ptrCast(@alignCast(context));

    switch (adapter_context.probe_mode) {
        .passive_only => return false,
        .active_send, .active_send_expect => {},
    }

    assert(adapter_context.payload.len > 0);
    assert(adapter_context.response_timeout_ms > 0);

    const resolved = adapter_context.dns_resolver.resolve(upstream.host, upstream.port, io) catch {
        return false;
    };

    const stream = resolved.address.connect(io, .{ .mode = .datagram }) catch {
        return false;
    };
    defer posix.close(stream.socket.handle);

    const fd = stream.socket.handle;
    if (fd < 0) return false;

    _ = posix.send(fd, adapter_context.payload, 0) catch {
        return false;
    };

    if (adapter_context.probe_mode == .active_send) {
        return true;
    }

    const timeout_tv = makeTimeval(adapter_context.response_timeout_ms);
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout_tv)) catch {
        return false;
    };

    var response_buf: [256]u8 = std.mem.zeroes([256]u8);
    const response_len = posix.recv(fd, &response_buf, 0) catch {
        return false;
    };
    if (response_len == 0) return false;

    if (adapter_context.expect_payload) |expected| {
        if (response_len != expected.len) return false;
        return std.mem.eql(u8, response_buf[0..response_len], expected);
    }

    return true;
}

fn makeTimeval(timeout_ms: u32) posix.timeval {
    assert(timeout_ms > 0);

    const seconds: i64 = @intCast(timeout_ms / 1000);
    const micros: i64 = @intCast((timeout_ms % 1000) * 1000);

    return .{
        .sec = seconds,
        .usec = micros,
    };
}

fn probeHttp(client: *Client, upstream: Upstream, health_path: []const u8, io: Io) bool {
    assert(upstream.host.len > 0);
    assert(health_path.len > 0);

    var request = buildHttpProbeRequest(upstream.host, health_path) catch {
        return false;
    };

    var header_buf: [1024]u8 = std.mem.zeroes([1024]u8);

    var result = client.request(upstream, &request, &header_buf, io) catch {
        return false;
    };
    result.conn.socket.close();

    return isHttpSuccessStatus(result.response.status);
}

fn buildHttpProbeRequest(host: []const u8, health_path: []const u8) !Request {
    assert(host.len > 0);
    assert(health_path.len > 0);

    var request = Request{
        .method = .GET,
        .path = health_path,
        .version = .@"HTTP/1.1",
        .headers = .{},
    };

    try request.headers.put("Host", host);
    try request.headers.put("Connection", "close");
    try request.headers.put("User-Agent", "serval-prober/1.0");

    return request;
}

fn isHttpSuccessStatus(status: u16) bool {
    return status >= 200 and status < 300;
}

test "makeTimeval converts milliseconds" {
    const tv = makeTimeval(1500);
    try std.testing.expectEqual(@as(i64, 1), tv.sec);
    try std.testing.expectEqual(@as(i64, 500_000), tv.usec);
}

test "buildHttpProbeRequest preserves legacy probe request shape" {
    const request = try buildHttpProbeRequest("backend1.example.com", "/health");

    try std.testing.expectEqual(core.types.Method.GET, request.method);
    try std.testing.expectEqualStrings("/health", request.path);
    try std.testing.expectEqual(@as(usize, 3), request.headers.count);
    try std.testing.expectEqualStrings("backend1.example.com", request.headers.get("Host").?);
    try std.testing.expectEqualStrings("close", request.headers.get("Connection").?);
    try std.testing.expectEqualStrings("serval-prober/1.0", request.headers.get("User-Agent").?);
}

test "isHttpSuccessStatus keeps legacy 2xx success semantics" {
    try std.testing.expect(!isHttpSuccessStatus(199));
    try std.testing.expect(isHttpSuccessStatus(200));
    try std.testing.expect(isHttpSuccessStatus(204));
    try std.testing.expect(isHttpSuccessStatus(299));
    try std.testing.expect(!isHttpSuccessStatus(300));
    try std.testing.expect(!isHttpSuccessStatus(503));
}

test "udpProbe passive mode does not actively probe" {
    var dns_resolver: DnsResolver = undefined;
    DnsResolver.init(&dns_resolver, .{});

    var context = UdpProbeAdapterContext{
        .dns_resolver = &dns_resolver,
        .probe_mode = .passive_only,
    };

    const upstream = Upstream{ .host = "127.0.0.1", .port = 9999, .idx = 0 };
    try std.testing.expect(!udpProbe(&context, upstream, undefined));
}
