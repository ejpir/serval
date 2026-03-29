//! ACME transport execution adapter.
//!
//! Bridges ACME wire requests to serval-client execution and returns bounded
//! response views for orchestration.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

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
const test_io = @import("test_io.zig");

const max_host_header_value_bytes = config.ACME_MAX_DOMAIN_NAME_LEN + 6;
const max_content_length_digits = 20;
const max_body_iterations: u32 = 1_000_000;
const max_chunk_iterations: u32 = 1_000_000;
const user_agent_header_value: []const u8 = "serval-acme/0";
const cursor_max = std.math.maxInt(u32);

const ChunkParseState = enum {
    chunk_header,
    chunk_data,
    chunk_data_crlf,
    trailers,
    done,
};

const ChunkParseContext = struct {
    pending_start: u32 = 0,
    pending_end: u32 = 0,
    out_cursor: u32 = 0,
    chunk_remaining: u64 = 0,
};

/// Error set used by `execute` for client failures and HTTP response parsing/reading failures.
/// Covers invalid buffers, header limits, response body size and chunking errors, and body read failures.
/// These errors indicate the upstream response could not be safely converted into an `ExecuteResponse`.
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

/// Error set returned by `executeOperation`.
/// Includes request construction, transport, wire, and orchestration protocol/response failures.
/// Callers should treat any of these errors as a terminal failure for the operation.
pub const ExecuteOperationError =
    Error || orchestration.ProtocolError || orchestration.Error || wire.Error;

/// Parameters for `execute`, which sends a prebuilt wire request to an upstream.
/// `wire_request` must point to a valid request for the duration of the call.
/// `header_buf` and `body_buf` provide workspace for parsing and body collection, and `upstream_idx` selects the upstream.
pub const ExecuteParams = struct {
    wire_request: *const wire.WireRequest,
    io: Io,
    header_buf: []u8,
    body_buf: []u8,
    upstream_idx: config.UpstreamIndex = 0,
};

/// Parameters for `executeOperation`, including the orchestration operation and buffers used
/// while building and processing the upstream request/response exchange.
/// `signed_body` defaults to empty when the operation does not require a body signature.
/// `header_buf` and `body_buf` must remain valid for the duration of the call; `upstream_idx` selects the upstream.
pub const ExecuteOperationParams = struct {
    operation: orchestration.Operation,
    signed_body: []const u8 = &.{},
    io: Io,
    header_buf: []u8,
    body_buf: []u8,
    upstream_idx: config.UpstreamIndex = 0,
};

/// Result returned by `execute`, containing the upstream HTTP status, headers, and response body.
/// The body slice is owned by the caller's response storage and is not independently allocated here.
/// `responseView` exposes a borrowed orchestration view over these fields.
pub const ExecuteResponse = struct {
    status: u16,
    headers: HeaderMap,
    body: []const u8,

    /// Returns an orchestration response view that borrows the status, headers, and body from this result.
    /// `self` must remain alive while the returned view is in use.
    /// The status is expected to be a valid HTTP status code in the 100-599 range.
    pub fn responseView(self: *const ExecuteResponse) orchestration.ResponseView {
        assert(@intFromPtr(self) != 0);
        assert(self.status >= 100 and self.status <= 599);
        return .{
            .status = self.status,
            .headers = &self.headers,
            .body = self.body,
        };
    }
};

/// Executes a prebuilt wire request against the selected upstream and returns the upstream status,
/// headers, and response body bytes collected into `params.body_buf`.
/// `params.header_buf` must not be empty; this function returns `error.InvalidHeaderBuffer` otherwise.
/// The upstream connection is closed before return, and any request, header, or body-read errors propagate.
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

/// Builds a wire request from `params.operation` and `params.signed_body`,
/// sends it through `client`, and converts the upstream reply into a handled response.
/// `flow_ctx` and `client` must be valid non-null pointers for the duration of the call.
/// Errors from request construction, transport execution, or response handling are propagated.
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

    if (request.body.len > cursor_max) return error.InvalidResponseBody;
    const request_body_len: u32 = @intCast(request.body.len);
    if (shouldSetContentLength(request.method, request_body_len)) {
        const value = std.fmt.bufPrint(content_length_buf, "{d}", .{request.body.len}) catch {
            return error.InvalidResponseBody;
        };
        try mapHeaderPut(headers.put("Content-Length", value));
    }
}

fn formatHostHeaderValue(out: []u8, target: *const wire.ParsedUrl) Error![]const u8 {
    assert(@intFromPtr(target) != 0);
    assert(target.port > 0);

    return std.fmt.bufPrint(out, "{s}:{d}", .{ target.host(), target.port }) catch {
        return error.InvalidResponseBody;
    };
}

fn shouldSetContentLength(method: Method, body_len: u32) bool {
    assert(max_content_length_digits > 0);
    assert(max_body_iterations > 0);
    if (body_len > 0) return true;
    return switch (method) {
        .POST, .PUT, .PATCH => true,
        else => false,
    };
}

fn mapHeaderPut(result: error{ TooManyHeaders, DuplicateContentLength }!void) Error!void {
    assert(config.MAX_HEADERS > 0);
    assert(max_host_header_value_bytes > 0);
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
    assert(response.header_bytes <= response.total_bytes_read);

    const header_end = response.header_bytes;
    const total = response.total_bytes_read;
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
    assert(content_length_u64 <= cursor_max);
    assert(body_buf.len <= cursor_max);
    assert(pre_read.len <= cursor_max);
    const body_len: u32 = @intCast(body_buf.len);
    const pre_read_len: u32 = @intCast(pre_read.len);

    if (content_length_u64 > body_len) return error.ResponseBodyTooLarge;
    const content_length: u32 = @intCast(content_length_u64);

    if (pre_read_len > content_length) return error.InvalidResponseBody;

    if (pre_read.len > 0) {
        @memcpy(body_buf[0..pre_read.len], pre_read);
    }

    var cursor: u32 = pre_read_len;
    var iterations: u32 = 0;

    while (cursor < content_length and iterations < max_body_iterations) : (iterations += 1) {
        const bytes_read = try readSocketBytes(
            socket,
            body_buf[u32ToUsize(cursor)..u32ToUsize(content_length)],
        );
        cursor += bytes_read;
    }

    if (cursor != content_length) return error.BodyIterationLimitExceeded;
    return body_buf[0..@intCast(content_length)];
}

fn readChunkedBody(socket: *Socket, pre_read: []const u8, body_buf: []u8) Error![]const u8 {
    assert(@intFromPtr(socket) != 0);
    assert(max_chunk_iterations > 0);

    var pending: [config.MAX_HEADER_SIZE_BYTES]u8 = undefined;
    if (pre_read.len > pending.len) return error.ChunkedTrailerTooLarge;

    @memset(pending[0..], 0);
    if (pre_read.len > 0) {
        @memcpy(pending[0..pre_read.len], pre_read);
    }
    const pre_read_len: u32 = @intCast(pre_read.len);

    var ctx = ChunkParseContext{
        .pending_start = 0,
        .pending_end = pre_read_len,
    };
    var iterations: u32 = 0;
    var state: ChunkParseState = .chunk_header;

    while (state != .done and iterations < max_chunk_iterations) : (iterations += 1) {
        try stepChunkedState(socket, &pending, body_buf, &ctx, &state);
    }

    if (state != .done) return error.BodyIterationLimitExceeded;
    return body_buf[0..@intCast(ctx.out_cursor)];
}

fn stepChunkedState(
    socket: *Socket,
    pending: []u8,
    body_buf: []u8,
    ctx: *ChunkParseContext,
    state: *ChunkParseState,
) Error!void {
    assert(@intFromPtr(socket) != 0);
    assert(@intFromPtr(ctx) != 0);

    switch (state.*) {
        .chunk_header => try handleChunkHeader(socket, pending, ctx, state),
        .chunk_data => try handleChunkData(socket, pending, body_buf, ctx, state),
        .chunk_data_crlf => try handleChunkDataCrlf(socket, pending, ctx, state),
        .trailers => try handleChunkTrailers(socket, pending, ctx, state),
        .done => unreachable,
    }
}

fn handleChunkHeader(
    socket: *Socket,
    pending: []u8,
    ctx: *ChunkParseContext,
    state: *ChunkParseState,
) Error!void {
    assert(@intFromPtr(socket) != 0);
    assert(@intFromPtr(ctx) != 0);

    const chunk_header = parseChunkSize(pending[ctx.pending_start..ctx.pending_end]) catch |err| switch (err) {
        error.IncompleteChunk => {
            try fillPending(socket, pending, &ctx.pending_start, &ctx.pending_end);
            return;
        },
        else => return error.InvalidChunkedEncoding,
    };

    if (chunk_header.consumed > cursor_max) return error.InvalidChunkedEncoding;
    const consumed: u32 = @intCast(chunk_header.consumed);
    ctx.pending_start += consumed;
    if (isLastChunk(chunk_header.size)) {
        state.* = .trailers;
        return;
    }

    ctx.chunk_remaining = chunk_header.size;
    state.* = .chunk_data;
}

fn validateChunkCopyCapacity(body_buf: []u8, out_cursor: u32, chunk_remaining: u64) Error!void {
    assert(out_cursor <= cursor_max);
    assert(chunk_remaining <= std.math.maxInt(u64));

    if (body_buf.len > cursor_max) return error.ResponseBodyTooLarge;
    const body_len: u32 = @intCast(body_buf.len);
    if (out_cursor > body_len) return error.InvalidChunkedEncoding;

    if (chunk_remaining > cursor_max) return error.ResponseBodyTooLarge;
    const out_remaining = body_len - out_cursor;
    if (chunk_remaining > @as(u64, @intCast(out_remaining))) {
        return error.ResponseBodyTooLarge;
    }
}

fn copyPendingChunkData(pending: []u8, body_buf: []u8, ctx: *ChunkParseContext) u32 {
    assert(@intFromPtr(ctx) != 0);
    assert(ctx.pending_start <= ctx.pending_end);
    assert(ctx.chunk_remaining <= cursor_max);

    const pending_available = ctx.pending_end - ctx.pending_start;
    const chunk_remaining: u32 = @intCast(ctx.chunk_remaining);
    const to_copy: u32 = @min(pending_available, chunk_remaining);

    const out_start = u32ToUsize(ctx.out_cursor);
    const pending_start = u32ToUsize(ctx.pending_start);
    const copy_len = u32ToUsize(to_copy);
    @memcpy(
        body_buf[out_start..][0..copy_len],
        pending[pending_start..][0..copy_len],
    );

    ctx.out_cursor += to_copy;
    ctx.pending_start += to_copy;
    ctx.chunk_remaining -= to_copy;
    return to_copy;
}

fn handleChunkData(
    socket: *Socket,
    pending: []u8,
    body_buf: []u8,
    ctx: *ChunkParseContext,
    state: *ChunkParseState,
) Error!void {
    assert(@intFromPtr(socket) != 0);
    assert(@intFromPtr(ctx) != 0);

    if (ctx.chunk_remaining == 0) {
        state.* = .chunk_data_crlf;
        return;
    }

    try validateChunkCopyCapacity(body_buf, ctx.out_cursor, ctx.chunk_remaining);

    const pending_available = ctx.pending_end - ctx.pending_start;
    if (pending_available == 0) {
        try fillPending(socket, pending, &ctx.pending_start, &ctx.pending_end);
        return;
    }

    _ = copyPendingChunkData(pending, body_buf, ctx);
    if (ctx.chunk_remaining == 0) state.* = .chunk_data_crlf;
}

fn handleChunkDataCrlf(
    socket: *Socket,
    pending: []u8,
    ctx: *ChunkParseContext,
    state: *ChunkParseState,
) Error!void {
    assert(@intFromPtr(socket) != 0);
    assert(@intFromPtr(ctx) != 0);

    while ((ctx.pending_end - ctx.pending_start) < 2) {
        try fillPending(socket, pending, &ctx.pending_start, &ctx.pending_end);
    }

    if (pending[u32ToUsize(ctx.pending_start)] != '\r' or pending[u32ToUsize(ctx.pending_start + 1)] != '\n') {
        return error.InvalidChunkedEncoding;
    }

    ctx.pending_start += 2;
    state.* = .chunk_header;
}

fn handleChunkTrailers(
    socket: *Socket,
    pending: []u8,
    ctx: *ChunkParseContext,
    state: *ChunkParseState,
) Error!void {
    assert(@intFromPtr(socket) != 0);
    assert(@intFromPtr(ctx) != 0);

    const trailer_slice = pending[u32ToUsize(ctx.pending_start)..u32ToUsize(ctx.pending_end)];
    if (trailer_slice.len >= 2 and trailer_slice[0] == '\r' and trailer_slice[1] == '\n') {
        ctx.pending_start += 2;
        state.* = .done;
        return;
    }

    if (std.mem.indexOf(u8, trailer_slice, "\r\n\r\n")) |terminator_idx| {
        const trailer_consumed = terminator_idx + 4;
        if (trailer_consumed > cursor_max) return error.InvalidChunkedEncoding;
        ctx.pending_start += @intCast(trailer_consumed);
        state.* = .done;
        return;
    }

    try fillPending(socket, pending, &ctx.pending_start, &ctx.pending_end);
}

fn fillPending(
    socket: *Socket,
    pending: []u8,
    pending_start: *u32,
    pending_end: *u32,
) Error!void {
    assert(@intFromPtr(socket) != 0);
    assert(pending.len <= cursor_max);
    const pending_len: u32 = @intCast(pending.len);
    assert(pending_start.* <= pending_end.*);
    assert(pending_end.* <= pending_len);

    if (pending_start.* == pending_end.*) {
        pending_start.* = 0;
        pending_end.* = 0;
    }

    if (pending_end.* == pending_len and pending_start.* > 0) {
        const kept = pending_end.* - pending_start.*;
        std.mem.copyForwards(
            u8,
            pending[0..u32ToUsize(kept)],
            pending[u32ToUsize(pending_start.*)..u32ToUsize(pending_end.*)],
        );
        pending_start.* = 0;
        pending_end.* = kept;
    }

    if (pending_end.* == pending_len) return error.ChunkedTrailerTooLarge;

    const bytes_read = try readSocketBytes(socket, pending[u32ToUsize(pending_end.*)..]);
    pending_end.* += bytes_read;
}

fn u32ToUsize(value: u32) usize {
    assert(value <= cursor_max);
    assert(@as(u64, value) <= std.math.maxInt(usize));
    return @intCast(value);
}

fn readSocketBytes(socket: *Socket, out: []u8) Error!u32 {
    assert(@intFromPtr(socket) != 0);
    assert(out.len <= std.math.maxInt(usize));

    const bytes_read = socket.read(out) catch |err| {
        return mapSocketReadError(err);
    };
    if (bytes_read == 0) return error.BodyConnectionClosed;
    if (bytes_read > cursor_max) return error.BodyReadFailed;
    return @intCast(bytes_read);
}

fn mapSocketReadError(err: SocketError) Error {
    assert(max_body_iterations > 0);
    assert(max_chunk_iterations > 0);
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
    const fds = test_io.create_socket_pair() orelse return;
    defer test_io.close_fd(fds[0]);
    defer test_io.close_fd(fds[1]);

    if (!test_io.write_bytes(fds[1], "de")) return;

    var socket = Socket.Plain.init_client(fds[0]);
    var out: [16]u8 = undefined;
    const body = try readContentLengthBody(&socket, "abc", 5, &out);
    try std.testing.expectEqualStrings("abcde", body);
}

test "readChunkedBody decodes pre-read chunked stream" {
    const fds = test_io.create_socket_pair() orelse return;
    defer test_io.close_fd(fds[0]);
    defer test_io.close_fd(fds[1]);

    var socket = Socket.Plain.init_client(fds[0]);
    var out: [64]u8 = undefined;
    const body = try readChunkedBody(&socket, "5\r\nhello\r\n0\r\n\r\n", &out);
    try std.testing.expectEqualStrings("hello", body);
}

test "readChunkedBody decodes split pre-read and socket stream" {
    const fds = test_io.create_socket_pair() orelse return;
    defer test_io.close_fd(fds[0]);
    defer test_io.close_fd(fds[1]);

    if (!test_io.write_bytes(fds[1], "llo\r\n0\r\n\r\n")) return;

    var socket = Socket.Plain.init_client(fds[0]);
    var out: [64]u8 = undefined;
    const body = try readChunkedBody(&socket, "5\r\nhe", &out);
    try std.testing.expectEqualStrings("hello", body);
}

test "readResponseBody rejects pre-read bytes when framing is none" {
    const fds = test_io.create_socket_pair() orelse return;
    defer test_io.close_fd(fds[0]);
    defer test_io.close_fd(fds[1]);

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
