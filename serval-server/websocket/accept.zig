//! Native WebSocket Accept Handshake
//!
//! Formats and sends `101 Switching Protocols` for native WebSocket endpoints.
//! TigerStyle: Zero allocation, explicit validation, fixed buffers.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const config = serval_core.config;
const types = serval_core.types;

const serval_websocket = @import("serval-websocket");
const session = @import("session.zig");

pub const AcceptError = error{
    MissingRequestKey,
    InvalidRequestKey,
    InvalidSelectedSubprotocol,
    InvalidExtraHeaders,
    HeadersTooLarge,
    WriteFailed,
};

pub fn sendSwitchingProtocols(
    transport: *const session.Transport,
    request: *const types.Request,
    accept: session.WebSocketAccept,
) AcceptError!u64 {
    assert(@intFromPtr(transport.ctx) != 0);
    assert(@intFromPtr(request) != 0);

    const request_key = request.headers.get("Sec-WebSocket-Key") orelse return error.MissingRequestKey;

    serval_websocket.validateSubprotocolSelection(
        request.headers.get("Sec-WebSocket-Protocol"),
        accept.subprotocol,
    ) catch {
        return error.InvalidSelectedSubprotocol;
    };

    if (accept.extra_headers.len > 0 and !std.mem.endsWith(u8, accept.extra_headers, "\r\n")) {
        return error.InvalidExtraHeaders;
    }

    var accept_key_buf: [serval_websocket.websocket_accept_key_size_bytes]u8 = undefined;
    const accept_key = serval_websocket.computeAcceptKey(request_key, &accept_key_buf) catch {
        return error.InvalidRequestKey;
    };

    var response_buf: [config.MAX_HEADER_SIZE_BYTES]u8 = undefined;
    const response = buildSwitchingProtocolsResponse(&response_buf, accept_key, accept.subprotocol, accept.extra_headers) orelse {
        return error.HeadersTooLarge;
    };

    transport.writeAll(response) catch {
        return error.WriteFailed;
    };

    return response.len;
}

pub fn buildSwitchingProtocolsResponse(
    buffer: []u8,
    accept_key: []const u8,
    selected_subprotocol: ?[]const u8,
    extra_headers: []const u8,
) ?[]const u8 {
    assert(buffer.len > 0);
    assert(accept_key.len == serval_websocket.websocket_accept_key_size_bytes);

    var pos: usize = 0;
    pos = appendLiteral(buffer, pos, "HTTP/1.1 101 Switching Protocols\r\n") orelse return null;
    pos = appendLiteral(buffer, pos, "Upgrade: websocket\r\n") orelse return null;
    pos = appendLiteral(buffer, pos, "Connection: Upgrade\r\n") orelse return null;
    pos = appendNameValue(buffer, pos, "Sec-WebSocket-Accept", accept_key) orelse return null;

    if (selected_subprotocol) |subprotocol| {
        pos = appendNameValue(buffer, pos, "Sec-WebSocket-Protocol", subprotocol) orelse return null;
    }
    if (extra_headers.len > 0) {
        pos = appendLiteral(buffer, pos, extra_headers) orelse return null;
    }
    pos = appendLiteral(buffer, pos, "\r\n") orelse return null;

    assert(pos <= buffer.len);
    return buffer[0..pos];
}

fn appendNameValue(buffer: []u8, pos: usize, name: []const u8, value: []const u8) ?usize {
    assert(pos <= buffer.len);
    assert(name.len > 0);

    var out_pos = appendLiteral(buffer, pos, name) orelse return null;
    out_pos = appendLiteral(buffer, out_pos, ": ") orelse return null;
    out_pos = appendLiteral(buffer, out_pos, value) orelse return null;
    out_pos = appendLiteral(buffer, out_pos, "\r\n") orelse return null;
    return out_pos;
}

fn appendLiteral(buffer: []u8, pos: usize, literal: []const u8) ?usize {
    assert(pos <= buffer.len);

    if (pos + literal.len > buffer.len) return null;
    @memcpy(buffer[pos..][0..literal.len], literal);
    return pos + literal.len;
}

test "buildSwitchingProtocolsResponse includes accept key and selected subprotocol" {
    var buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = undefined;
    const response = buildSwitchingProtocolsResponse(
        &buffer,
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "chat",
        "X-Test: value\r\n",
    ).?;

    try std.testing.expect(std.mem.indexOf(u8, response, "101 Switching Protocols") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Sec-WebSocket-Protocol: chat\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "X-Test: value\r\n") != null);
}
