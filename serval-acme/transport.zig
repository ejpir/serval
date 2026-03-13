//! ACME transport execution adapter.
//!
//! Bridges ACME wire requests to serval-client execution and returns bounded
//! response views for orchestration.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const c = std.c;
const posix = std.posix;

const core = @import("serval-core");
const config = core.config;
const types = core.types;
const HeaderMap = core.HeaderMap;
const Method = types.Method;
const BodyFraming = types.BodyFraming;

const serval_client = @import("serval-client");
const Client = serval_client.Client;
const ClientError = serval_client.ClientError;
const ResponseHeaders = serval_client.ResponseHeaders;

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;
const SocketError = serval_socket.SocketError;

const serval_http = @import("serval-http");
const parseChunkSize = serval_http.chunked.parseChunkSize;
const isLastChunk = serval_http.chunked.isLastChunk;

const wire = @import("wire.zig");
const orchestration = @import("orchestration.zig");

const max_host_header_value_bytes: usize = config.ACME_MAX_DOMAIN_NAME_LEN + 6;
const max_content_length_digits: usize = 20;
const max_body_iterations: u32 = 1_000_000;
const max_chunk_iterations: u32 = 1_000_000;
const user_agent_header_value: []const u8 = "serval-acme/0";

pub const Error = ClientError || error{
    InvalidHeaderBuffer,
    TooManyRequestHeaders,
    ResponseBodyTooLarge,
    InvalidResponseBody,
    BodyReadFailed,
    BodyReadTimeout,
    BodyConnectionClosed,
    BodyIterationLimitExceeded,
    InvalidChunkedEncoding,
    ChunkedTrailerTooLarge,
};

pub const ExecuteOperationError =
    Error || orchestration.ProtocolError || orchestration.Error || wire.Error;

pub const ExecuteParams = struct {
    wire_request: *const wire.WireRequest,
    io: Io,
    header_buf: []u8,
    body_buf: []u8,
    upstream_idx: config.UpstreamIndex = 0,
};

pub const ExecuteOperationParams = struct {
    operation: orchestration.Operation,
    signed_body: []const u8 = &.{},
    io: Io,
    header_buf: []u8,
    body_buf: []u8,
    upstream_idx: config.UpstreamIndex = 0,
};

pub const ExecuteResponse = struct {
    status: u16,
    headers: HeaderMap,
    body: []const u8,

    pub fn responseView(self: *const ExecuteResponse) orchestration.ResponseView {
        assert(@intFromPtr(self) != 0);
        return .{
            .status = self.status,
            .headers = &self.headers,
            .body = self.body,
        };
    }
};

pub fn execute(client: *Client, params: ExecuteParams) Error!ExecuteResponse {
    assert(@intFromPtr(client) != 0);
    assert(@intFromPtr(params.wire_request) != 0);

    if (params.header_buf.len == 0) return error.InvalidHeaderBuffer;

    var host_header_buf: [max_host_header_value_bytes]u8 = undefined;
    var content_length_buf: [max_content_length_digits]u8 = undefined;
    var headers = HeaderMap.init();
    try populateRequestHeaders(
        &headers,
        params.wire_request,
        &host_header_buf,
        &content_length_buf,
    );

    const request = types.Request{
        .method = params.wire_request.method,
        .path = params.wire_request.path(),
        .version = .@"HTTP/1.1",
        .headers = headers,
        .body = if (params.wire_request.body.len > 0) params.wire_request.body else null,
    };

    const upstream = params.wire_request.upstream(params.upstream_idx);
    var request_result = try client.request(upstream, &request, params.header_buf, params.io);
    defer request_result.conn.close();

    const body = try readResponseBody(
        &request_result.conn.socket,
        &request_result.response,
        params.header_buf,
        params.body_buf,
    );

    return .{
        .status = request_result.response.status,
        .headers = request_result.response.headers,
        .body = body,
    };
}

pub fn executeOperation(
    flow_ctx: *orchestration.FlowContext,
    client: *Client,
    params: ExecuteOperationParams,
) ExecuteOperationError!orchestration.HandledResponse {
    assert(@intFromPtr(flow_ctx) != 0);
    assert(@intFromPtr(client) != 0);

    const wire_request = try flow_ctx.buildRequest(params.operation, params.signed_body);
    const response = try execute(client, .{
        .wire_request = &wire_request,
        .io = params.io,
        .header_buf = params.header_buf,
        .body_buf = params.body_buf,
        .upstream_idx = params.upstream_idx,
    });

    const response_view = response.responseView();
    return try flow_ctx.handleResponse(params.operation, &response_view);
}

fn populateRequestHeaders(
    headers: *HeaderMap,
    request: *const wire.WireRequest,
    host_header_buf: []u8,
    content_length_buf: []u8,
) Error!void {
    assert(@intFromPtr(headers) != 0);
    assert(@intFromPtr(request) != 0);

    const host_value = try formatHostHeaderValue(host_header_buf, &request.target);

    try mapHeaderPut(headers.put("Host", host_value));
    try mapHeaderPut(headers.put("User-Agent", user_agent_header_value));
    if (request.accept.len > 0) {
        try mapHeaderPut(headers.put("Accept", request.accept));
    }

    if (request.content_type) |content_type| {
        try mapHeaderPut(headers.put("Content-Type", content_type));
    }

    if (shouldSetContentLength(request.method, request.body.len)) {
        const value = std.fmt.bufPrint(content_length_buf, "{d}", .{request.body.len}) catch {
            return error.InvalidResponseBody;
        };
        try mapHeaderPut(headers.put("Content-Length", value));
    }
}

fn formatHostHeaderValue(out: []u8, target: *const wire.ParsedUrl) Error![]const u8 {
    assert(@intFromPtr(target) != 0);

    return std.fmt.bufPrint(out, "{s}:{d}", .{ target.host(), target.port }) catch {
        return error.InvalidResponseBody;
    };
}

fn shouldSetContentLength(method: Method, body_len: usize) bool {
    if (body_len > 0) return true;
    return switch (method) {
        .POST, .PUT, .PATCH => true,
        else => false,
    };
}

fn mapHeaderPut(result: error{ TooManyHeaders, DuplicateContentLength }!void) Error!void {
    result catch |err| switch (err) {
        error.TooManyHeaders, error.DuplicateContentLength => return error.TooManyRequestHeaders,
    };
}

fn readResponseBody(
    socket: *Socket,
    response: *const ResponseHeaders,
    header_buf: []const u8,
    body_buf: []u8,
) Error![]const u8 {
    assert(@intFromPtr(socket) != 0);
    assert(@intFromPtr(response) != 0);

    const pre_read = try preReadBodySlice(response, header_buf);

    return switch (response.body_framing) {
        .none => if (pre_read.len == 0) &.{} else error.InvalidResponseBody,
        .content_length => |content_length| try readContentLengthBody(
            socket,
            pre_read,
            content_length,
            body_buf,
        ),
        .chunked => try readChunkedBody(socket, pre_read, body_buf),
    };
}

fn preReadBodySlice(response: *const ResponseHeaders, header_buf: []const u8) Error![]const u8 {
    assert(@intFromPtr(response) != 0);

    const header_end: usize = response.header_bytes;
    const total: usize = response.total_bytes_read;
    if (header_end > total) return error.InvalidResponseBody;
    if (total > header_buf.len) return error.InvalidResponseBody;

    return header_buf[header_end..total];
}

fn readContentLengthBody(
    socket: *Socket,
    pre_read: []const u8,
    content_length_u64: u64,
    body_buf: []u8,
) Error![]const u8 {
    assert(@intFromPtr(socket) != 0);

    if (content_length_u64 > body_buf.len) return error.ResponseBodyTooLarge;
    const content_length: usize = @intCast(content_length_u64);

    if (pre_read.len > content_length) return error.InvalidResponseBody;

    if (pre_read.len > 0) {
        @memcpy(body_buf[0..pre_read.len], pre_read);
    }

    var cursor: usize = pre_read.len;
    var iterations: u32 = 0;

    while (cursor < content_length and iterations < max_body_iterations) : (iterations += 1) {
        const bytes_read = socket.read(body_buf[cursor..content_length]) catch |err| {
            return mapSocketReadError(err);
        };

        if (bytes_read == 0) return error.BodyConnectionClosed;
        cursor += bytes_read;
    }

    if (cursor != content_length) return error.BodyIterationLimitExceeded;
    return body_buf[0..content_length];
}

fn readChunkedBody(socket: *Socket, pre_read: []const u8, body_buf: []u8) Error![]const u8 {
    assert(@intFromPtr(socket) != 0);

    var pending: [config.MAX_HEADER_SIZE_BYTES]u8 = undefined;
    if (pre_read.len > pending.len) return error.ChunkedTrailerTooLarge;

    @memset(pending[0..], 0);
    if (pre_read.len > 0) {
        @memcpy(pending[0..pre_read.len], pre_read);
    }

    var pending_start: usize = 0;
    var pending_end: usize = pre_read.len;
    var out_cursor: usize = 0;
    var chunk_remaining: u64 = 0;
    var iterations: u32 = 0;

    const ParseState = enum {
        chunk_header,
        chunk_data,
        chunk_data_crlf,
        trailers,
        done,
    };
    var state: ParseState = .chunk_header;

    while (state != .done and iterations < max_chunk_iterations) : (iterations += 1) {
        switch (state) {
            .chunk_header => {
                const chunk_header = parseChunkSize(pending[pending_start..pending_end]) catch |err| switch (err) {
                    error.IncompleteChunk => {
                        try fillPending(socket, &pending, &pending_start, &pending_end);
                        continue;
                    },
                    else => return error.InvalidChunkedEncoding,
                };

                pending_start += chunk_header.consumed;
                if (isLastChunk(chunk_header.size)) {
                    state = .trailers;
                } else {
                    chunk_remaining = chunk_header.size;
                    state = .chunk_data;
                }
            },
            .chunk_data => {
                if (chunk_remaining == 0) {
                    state = .chunk_data_crlf;
                    continue;
                }

                const out_remaining = body_buf.len - out_cursor;
                if (chunk_remaining > @as(u64, @intCast(out_remaining))) {
                    return error.ResponseBodyTooLarge;
                }

                const pending_available = pending_end - pending_start;
                if (pending_available == 0) {
                    try fillPending(socket, &pending, &pending_start, &pending_end);
                    continue;
                }

                const chunk_remaining_usize: usize = @intCast(chunk_remaining);
                const to_copy: usize = @min(pending_available, chunk_remaining_usize);
                @memcpy(
                    body_buf[out_cursor..][0..to_copy],
                    pending[pending_start..][0..to_copy],
                );

                out_cursor += to_copy;
                pending_start += to_copy;
                chunk_remaining -= to_copy;

                if (chunk_remaining == 0) {
                    state = .chunk_data_crlf;
                }
            },
            .chunk_data_crlf => {
                while ((pending_end - pending_start) < 2) {
                    try fillPending(socket, &pending, &pending_start, &pending_end);
                }

                if (pending[pending_start] != '\r' or pending[pending_start + 1] != '\n') {
                    return error.InvalidChunkedEncoding;
                }

                pending_start += 2;
                state = .chunk_header;
            },
            .trailers => {
                const trailer_slice = pending[pending_start..pending_end];
                if (trailer_slice.len >= 2 and trailer_slice[0] == '\r' and trailer_slice[1] == '\n') {
                    pending_start += 2;
                    state = .done;
                    continue;
                }

                if (std.mem.indexOf(u8, trailer_slice, "\r\n\r\n")) |terminator_idx| {
                    pending_start += terminator_idx + 4;
                    state = .done;
                    continue;
                }

                try fillPending(socket, &pending, &pending_start, &pending_end);
            },
            .done => unreachable,
        }
    }

    if (state != .done) return error.BodyIterationLimitExceeded;
    return body_buf[0..out_cursor];
}

fn fillPending(
    socket: *Socket,
    pending: []u8,
    pending_start: *usize,
    pending_end: *usize,
) Error!void {
    assert(@intFromPtr(socket) != 0);
    assert(pending_start.* <= pending_end.*);
    assert(pending_end.* <= pending.len);

    if (pending_start.* == pending_end.*) {
        pending_start.* = 0;
        pending_end.* = 0;
    }

    if (pending_end.* == pending.len and pending_start.* > 0) {
        const kept = pending_end.* - pending_start.*;
        std.mem.copyForwards(u8, pending[0..kept], pending[pending_start.*..pending_end.*]);
        pending_start.* = 0;
        pending_end.* = kept;
    }

    if (pending_end.* == pending.len) return error.ChunkedTrailerTooLarge;

    const bytes_read = socket.read(pending[pending_end.*..]) catch |err| {
        return mapSocketReadError(err);
    };
    if (bytes_read == 0) return error.BodyConnectionClosed;

    pending_end.* += bytes_read;
}

fn mapSocketReadError(err: SocketError) Error {
    return switch (err) {
        error.Timeout => error.BodyReadTimeout,
        error.ConnectionReset,
        error.ConnectionClosed,
        error.BrokenPipe,
        => error.BodyConnectionClosed,
        error.TLSError,
        error.Unexpected,
        => error.BodyReadFailed,
    };
}

test "formatHostHeaderValue renders host and port" {
    var parsed = try wire.parseAbsoluteUrlSlice("https://acme.example:8443/new-order");

    var out: [max_host_header_value_bytes]u8 = undefined;
    const value = try formatHostHeaderValue(&out, &parsed);
    try std.testing.expectEqualStrings("acme.example:8443", value);
}

test "readContentLengthBody merges preread and socket bytes" {
    const fds = createTestSocketPair() orelse return;
    defer closeTestFd(fds[0]);
    defer closeTestFd(fds[1]);

    if (!writeTestBytes(fds[1], "de")) return;

    var socket = Socket.Plain.init_client(fds[0]);
    var out: [16]u8 = undefined;
    const body = try readContentLengthBody(&socket, "abc", 5, &out);
    try std.testing.expectEqualStrings("abcde", body);
}

test "readChunkedBody decodes pre-read chunked stream" {
    const fds = createTestSocketPair() orelse return;
    defer closeTestFd(fds[0]);
    defer closeTestFd(fds[1]);

    var socket = Socket.Plain.init_client(fds[0]);
    var out: [64]u8 = undefined;
    const body = try readChunkedBody(&socket, "5\r\nhello\r\n0\r\n\r\n", &out);
    try std.testing.expectEqualStrings("hello", body);
}

test "readChunkedBody decodes split pre-read and socket stream" {
    const fds = createTestSocketPair() orelse return;
    defer closeTestFd(fds[0]);
    defer closeTestFd(fds[1]);

    if (!writeTestBytes(fds[1], "llo\r\n0\r\n\r\n")) return;

    var socket = Socket.Plain.init_client(fds[0]);
    var out: [64]u8 = undefined;
    const body = try readChunkedBody(&socket, "5\r\nhe", &out);
    try std.testing.expectEqualStrings("hello", body);
}

test "readResponseBody rejects pre-read bytes when framing is none" {
    const fds = createTestSocketPair() orelse return;
    defer closeTestFd(fds[0]);
    defer closeTestFd(fds[1]);

    var socket = Socket.Plain.init_client(fds[0]);
    const response = ResponseHeaders{
        .status = 204,
        .headers = HeaderMap.init(),
        .body_framing = .none,
        .header_bytes = 0,
        .total_bytes_read = 1,
    };

    const header_buf = [_]u8{'x'};
    var body_buf: [1]u8 = undefined;
    try std.testing.expectError(
        error.InvalidResponseBody,
        readResponseBody(&socket, &response, &header_buf, &body_buf),
    );
}

fn createTestSocketPair() ?[2]i32 {
    var fds: [2]i32 = undefined;
    const rc = c.socketpair(
        @intCast(posix.AF.UNIX),
        @intCast(posix.SOCK.STREAM),
        0,
        &fds,
    );
    if (rc != 0) return null;
    return fds;
}

fn closeTestFd(fd: i32) void {
    _ = c.close(fd);
}

fn writeTestBytes(fd: i32, bytes: []const u8) bool {
    const written = c.write(fd, bytes.ptr, bytes.len);
    if (written < 0) return false;

    return @as(usize, @intCast(written)) == bytes.len;
}
