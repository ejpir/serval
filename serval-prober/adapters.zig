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

pub const HttpProbeAdapterContext = struct {
    client: *Client,
    health_path: []const u8,
};

pub fn httpProbe(context: *anyopaque, upstream: Upstream, io: Io) bool {
    const adapter_context: *HttpProbeAdapterContext = @ptrCast(@alignCast(context));
    assert(adapter_context.health_path.len > 0);

    return probeHttp(adapter_context.client, upstream, adapter_context.health_path, io);
}

pub const TcpProbeAdapterContext = struct {
    client: *Client,
};

pub fn tcpConnectProbe(context: *anyopaque, upstream: Upstream, io: Io) bool {
    const adapter_context: *TcpProbeAdapterContext = @ptrCast(@alignCast(context));

    const result = adapter_context.client.connect(upstream, io) catch {
        return false;
    };

    result.conn.socket.close();
    return true;
}

pub const UdpProbeMode = enum {
    passive_only,
    active_send,
    active_send_expect,
};

pub const UdpProbeAdapterContext = struct {
    dns_resolver: *DnsResolver,
    probe_mode: UdpProbeMode = .passive_only,
    payload: []const u8 = "serval-udp-probe",
    expect_payload: ?[]const u8 = null,
    response_timeout_ms: u32 = 500,
};

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
