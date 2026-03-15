//! HTTP/1.1 WebSocket Upgrade Forwarding
//!
//! Dedicated upgrade request/response handling for RFC 6455.
//! TigerStyle: Keep normal HTTP path unchanged; explicit upgrade path only.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const config = serval_core.config;
const debugLog = serval_core.debugLog;
const types = serval_core.types;

const serval_http = @import("serval-http");
const parseStatusCode = serval_http.parseStatusCode;
const parseContentLength = serval_http.parseContentLength;

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;

const serval_websocket = @import("serval-websocket");

const proxy_types = @import("../types.zig");
const ForwardError = proxy_types.ForwardError;

const request_mod = @import("request.zig");
const isHopByHopHeader = request_mod.isHopByHopHeader;
const methodToString = request_mod.methodToString;
const VIA_HEADER = request_mod.VIA_HEADER;
const sendBuffer = request_mod.sendBuffer;

const response_mod = @import("response.zig");
const receiveHeaders = response_mod.receiveHeaders;
const isChunkedResponse = response_mod.isChunkedResponse;

const body_mod = @import("body.zig");
const forwardBody = body_mod.forwardBody;

const chunked_mod = @import("chunked.zig");
const forwardChunkedBodyWithPreread = chunked_mod.forwardChunkedBodyWithPreread;

const pool_mod = @import("serval-pool").pool;
const Connection = pool_mod.Connection;

const Request = types.Request;

pub const ForwardedHeaders = struct {
    host: []const u8 = "",
    proto: []const u8 = "",
    client_ip: []const u8 = "",
};

pub const UpgradeResponseResult = struct {
    status: u16,
    response_bytes: u64,
    upgraded: bool,
};

pub fn buildUpgradeRequestBuffer(
    buffer: []u8,
    request: *const Request,
    effective_path: ?[]const u8,
    forwarded: ForwardedHeaders,
) ?usize {
    const path = effective_path orelse request.path;
    assert(path.len > 0);

    var pos: usize = 0;
    const method_str = methodToString(request.method);
    const version_str = " HTTP/1.1\r\n";
    const line_len = method_str.len + 1 + path.len + version_str.len;
    if (line_len > buffer.len) return null;

    @memcpy(buffer[pos..][0..method_str.len], method_str);
    pos += method_str.len;
    buffer[pos] = ' ';
    pos += 1;
    @memcpy(buffer[pos..][0..path.len], path);
    pos += path.len;
    @memcpy(buffer[pos..][0..version_str.len], version_str);
    pos += version_str.len;

    const max_headers: usize = config.MAX_HEADERS;
    for (request.headers.headers[0..@min(request.headers.count, max_headers)]) |header| {
        if (isHopByHopHeader(header.name)) continue;

        const needed = header.name.len + 2 + header.value.len + 2;
        if (pos + needed > buffer.len) return null;

        @memcpy(buffer[pos..][0..header.name.len], header.name);
        pos += header.name.len;
        @memcpy(buffer[pos..][0..2], ": ");
        pos += 2;
        @memcpy(buffer[pos..][0..header.value.len], header.value);
        pos += header.value.len;
        @memcpy(buffer[pos..][0..2], "\r\n");
        pos += 2;
    }

    pos = appendLiteral(buffer, pos, "Connection: Upgrade\r\n") orelse return null;
    pos = appendLiteral(buffer, pos, "Upgrade: websocket\r\n") orelse return null;
    pos = appendLiteral(buffer, pos, VIA_HEADER) orelse return null;
    if (forwarded.client_ip.len > 0) {
        pos = appendHeader(buffer, pos, "X-Forwarded-For", forwarded.client_ip) orelse return null;
    }
    if (forwarded.host.len > 0) {
        pos = appendHeader(buffer, pos, "X-Forwarded-Host", forwarded.host) orelse return null;
    }
    if (forwarded.proto.len > 0) {
        pos = appendHeader(buffer, pos, "X-Forwarded-Proto", forwarded.proto) orelse return null;
    }
    pos = appendLiteral(buffer, pos, "\r\n") orelse return null;

    assert(pos <= buffer.len);
    return pos;
}

pub fn sendUpgradeRequest(
    conn: *Connection,
    io: Io,
    request: *const Request,
    effective_path: ?[]const u8,
    forwarded: ForwardedHeaders,
) ForwardError!void {
    const path = effective_path orelse request.path;
    assert(path.len > 0);

    var buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([config.MAX_HEADER_SIZE_BYTES]u8);
    const header_len = buildUpgradeRequestBuffer(&buffer, request, effective_path, forwarded) orelse
        return ForwardError.SendFailed;

    logUpgradeRequestHeaders(request, path, forwarded);
    try sendBuffer(conn, io, buffer[0..header_len]);
}

pub fn forwardUpgradeResponse(
    io: Io,
    upstream_conn: *Connection,
    client_socket: *Socket,
    is_pooled: bool,
    expected_accept_key: []const u8,
) ForwardError!UpgradeResponseResult {
    assert(upstream_conn.get_fd() >= 0);
    assert(client_socket.get_fd() >= 0);
    assert(expected_accept_key.len == serval_websocket.websocket_accept_key_size_bytes);

    var header_buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([config.MAX_HEADER_SIZE_BYTES]u8);
    const headers = try receiveHeaders(upstream_conn, io, &header_buffer, is_pooled);
    const header_len: usize = headers.header_len;
    const header_end: usize = headers.header_end;

    const header_block = header_buffer[0..header_end];
    const status = parseStatusCode(header_block) orelse return ForwardError.InvalidResponse;
    var client_conn = Connection{ .socket = client_socket.* };

    if (status == 101) {
        serval_websocket.validateServerResponse(status, header_block, expected_accept_key) catch {
            return ForwardError.InvalidResponse;
        };
        logUpgradeResponseHeaders(status, header_block);
        try sendBuffer(&client_conn, io, header_buffer[0..header_len]);
        return .{
            .status = status,
            .response_bytes = header_len,
            .upgraded = true,
        };
    }

    try sendBuffer(&client_conn, io, header_block);
    const body_bytes = try forwardBufferedBody(
        upstream_conn,
        client_socket,
        header_buffer[header_end..header_len],
        header_block,
    );

    return .{
        .status = status,
        .response_bytes = @intCast(header_end + body_bytes),
        .upgraded = false,
    };
}

pub fn receiveUpgradeResponse(
    io: Io,
    upstream_conn: *Connection,
    is_pooled: bool,
    expected_accept_key: []const u8,
) ForwardError!UpgradeResponseResult {
    assert(upstream_conn.get_fd() >= 0);
    assert(expected_accept_key.len == serval_websocket.websocket_accept_key_size_bytes);

    var header_buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([config.MAX_HEADER_SIZE_BYTES]u8);
    const headers = try receiveHeaders(upstream_conn, io, &header_buffer, is_pooled);
    const header_len: usize = headers.header_len;
    const header_end: usize = headers.header_end;

    const header_block = header_buffer[0..header_end];
    const status = parseStatusCode(header_block) orelse return ForwardError.InvalidResponse;
    if (status != 101) {
        return .{
            .status = status,
            .response_bytes = header_len,
            .upgraded = false,
        };
    }

    serval_websocket.validateServerResponse(status, header_block, expected_accept_key) catch {
        return ForwardError.InvalidResponse;
    };
    logUpgradeResponseHeaders(status, header_block);
    return .{
        .status = status,
        .response_bytes = header_len,
        .upgraded = true,
    };
}

fn forwardBufferedBody(
    upstream_conn: *Connection,
    client_socket: *Socket,
    pre_read_body: []const u8,
    header_block: []const u8,
) ForwardError!u64 {
    const content_length = parseContentLength(header_block);
    const chunked = isChunkedResponse(header_block);

    if (chunked) {
        return forwardChunkedBodyWithPreread(&upstream_conn.socket, client_socket, pre_read_body);
    }

    if (content_length) |length| {
        var sent: u64 = 0;
        if (pre_read_body.len > 0) {
            client_socket.write_all(pre_read_body) catch {
                return ForwardError.SendFailed;
            };
            sent += pre_read_body.len;
        }
        if (length > sent) {
            sent += try forwardBody(&upstream_conn.socket, client_socket, length - sent);
        }
        return sent;
    }

    return 0;
}

fn appendLiteral(buffer: []u8, pos: usize, literal: []const u8) ?usize {
    assert(pos <= buffer.len);

    if (pos + literal.len > buffer.len) return null;
    @memcpy(buffer[pos..][0..literal.len], literal);
    return pos + literal.len;
}

fn appendHeader(buffer: []u8, pos: usize, name: []const u8, value: []const u8) ?usize {
    assert(pos <= buffer.len);
    assert(name.len > 0);

    const needed = name.len + 2 + value.len + 2;
    if (pos + needed > buffer.len) return null;

    @memcpy(buffer[pos..][0..name.len], name);
    var next_pos = pos + name.len;
    @memcpy(buffer[next_pos..][0..2], ": ");
    next_pos += 2;
    @memcpy(buffer[next_pos..][0..value.len], value);
    next_pos += value.len;
    @memcpy(buffer[next_pos..][0..2], "\r\n");
    return next_pos + 2;
}

fn logUpgradeRequestHeaders(request: *const Request, path: []const u8, forwarded: ForwardedHeaders) void {
    assert(path.len > 0);

    const host = request.headers.get("Host") orelse "";
    const origin = request.headers.get("Origin") orelse "";
    const user_agent = request.headers.get("User-Agent") orelse "";
    const connection = request.headers.get("Connection") orelse "";
    const upgrade = request.headers.get("Upgrade") orelse "";
    const version = request.headers.get("Sec-WebSocket-Version") orelse "";
    const protocol = request.headers.get("Sec-WebSocket-Protocol") orelse "";
    const extensions = request.headers.get("Sec-WebSocket-Extensions") orelse "";
    const key = request.headers.get("Sec-WebSocket-Key") orelse "";

    debugLog(
        "websocket request headers path={s} host={s} origin={s} user_agent={s} connection={s} upgrade={s} ws_version={s} ws_protocol={s} ws_extensions={s} ws_key_len={d}",
        .{
            path,
            host,
            origin,
            user_agent,
            connection,
            upgrade,
            version,
            protocol,
            extensions,
            key.len,
        },
    );
    debugLog("websocket forwarded headers path={s} xff={s} xfh={s} xfp={s}", .{
        path,
        forwarded.client_ip,
        forwarded.host,
        forwarded.proto,
    });
}

fn logUpgradeResponseHeaders(status: u16, raw_headers: []const u8) void {
    assert(status > 0);

    const connection = serval_websocket.getHeaderValue(raw_headers, "Connection") orelse "";
    const upgrade = serval_websocket.getHeaderValue(raw_headers, "Upgrade") orelse "";
    const accept = serval_websocket.getHeaderValue(raw_headers, "Sec-WebSocket-Accept") orelse "";
    const protocol = serval_websocket.getHeaderValue(raw_headers, "Sec-WebSocket-Protocol") orelse "";
    const extensions = serval_websocket.getHeaderValue(raw_headers, "Sec-WebSocket-Extensions") orelse "";
    const server = serval_websocket.getHeaderValue(raw_headers, "Server") orelse "";

    debugLog(
        "websocket response headers status={d} connection={s} upgrade={s} ws_accept_len={d} ws_protocol={s} ws_extensions={s} server={s}",
        .{
            status,
            connection,
            upgrade,
            accept.len,
            protocol,
            extensions,
            server,
        },
    );
}

test "buildUpgradeRequestBuffer preserves websocket headers and canonical upgrade hop-by-hop headers" {
    var buffer: [1024]u8 = undefined;
    var request = Request{
        .method = .GET,
        .path = "/chat",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");
    try request.headers.put("Upgrade", "websocket");
    try request.headers.put("Connection", "keep-alive, Upgrade");
    try request.headers.put("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try request.headers.put("Sec-WebSocket-Version", "13");
    try request.headers.put("X-Test", "value");

    const len = buildUpgradeRequestBuffer(&buffer, &request, null, .{}).?;
    const output = buffer[0..len];

    try std.testing.expect(std.mem.indexOf(u8, output, "Connection: Upgrade\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Upgrade: websocket\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Sec-WebSocket-Version: 13\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "X-Test: value\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, VIA_HEADER) != null);
}

test "buildUpgradeRequestBuffer uses effective path" {
    var buffer: [1024]u8 = undefined;
    var request = Request{
        .method = .GET,
        .path = "/api/chat",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");
    try request.headers.put("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try request.headers.put("Sec-WebSocket-Version", "13");

    const len = buildUpgradeRequestBuffer(&buffer, &request, "/chat", .{}).?;
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "GET /chat HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "/api/chat") == null);
}
