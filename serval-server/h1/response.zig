// lib/serval-server/h1/response.zig
//! HTTP/1.1 Response Writing Utilities
//!
//! Standalone functions for sending HTTP/1.1 responses to clients.
//! Extracted to enable code reuse and smaller file sizes.
//!
//! TigerStyle: Pure functions with explicit I/O parameters, no hidden state.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const config = @import("serval-core").config;

// Buffer sizes from centralized config
const RESPONSE_BUFFER_SIZE_BYTES = config.RESPONSE_BUFFER_SIZE_BYTES;
const WRITE_BUFFER_SIZE_BYTES = config.SERVER_WRITE_BUFFER_SIZE_BYTES;

// =============================================================================
// Status Text Mapping
// =============================================================================

/// Get HTTP status text for status code.
/// Returns canonical reason phrase per RFC 9110 Section 15.
/// TigerStyle: Pure function, no allocation.
pub fn statusText(status: u16) []const u8 {
    // Precondition: status codes are 3 digits (100-599)
    assert(status >= 100 and status < 600);

    return switch (status) {
        // 1xx Informational
        100 => "Continue",
        101 => "Switching Protocols",
        // 2xx Success
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        // 3xx Redirection
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        // 4xx Client Error
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        // 5xx Server Error
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => "Error",
    };
}

// =============================================================================
// Response Writers
// =============================================================================

/// Send HTTP response to client.
/// If close_after is true, includes Connection: close header (RFC 9112).
/// TigerStyle: Standalone function with explicit parameters.
pub fn sendResponse(
    io: Io,
    stream: Io.net.Stream,
    status: u16,
    content_type: []const u8,
    body: []const u8,
    close_after: bool,
) void {
    // Preconditions
    assert(status >= 100 and status < 600);
    // Body must fit in response buffer with headers (~200 bytes overhead)
    assert(body.len <= 512);

    var response_buf: [RESPONSE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([RESPONSE_BUFFER_SIZE_BYTES]u8);

    const response = if (close_after)
        std.fmt.bufPrint(
            &response_buf,
            "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
            .{ status, statusText(status), content_type, body.len, body },
        )
    else
        std.fmt.bufPrint(
            &response_buf,
            "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status, statusText(status), content_type, body.len, body },
        );

    const response_data = response catch return;

    var write_buf: [WRITE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([WRITE_BUFFER_SIZE_BYTES]u8);
    var writer = stream.writer(io, &write_buf);
    writer.interface.writeAll(response_data) catch return;
    writer.interface.flush() catch return;
}

/// Send error response and close connection (RFC 9112: errors close connection).
/// TigerStyle: Standalone function with explicit parameters.
pub fn sendErrorResponse(io: Io, stream: Io.net.Stream, status: u16, message: []const u8) void {
    // Preconditions: error responses are 4xx or 5xx
    assert(status >= 400 and status < 600);
    assert(message.len > 0);

    sendResponse(io, stream, status, "text/plain", message, true);
}

/// Send 100 Continue interim response (RFC 7231 Section 5.1.1).
/// Client can then proceed to send request body.
/// TigerStyle: Standalone function with explicit parameters.
pub fn send100Continue(io: Io, stream: Io.net.Stream) void {
    const response = "HTTP/1.1 100 Continue\r\n\r\n";

    // Postcondition: response is well-formed (ends with \r\n\r\n)
    assert(std.mem.endsWith(u8, response, "\r\n\r\n"));

    var write_buf: [64]u8 = std.mem.zeroes([64]u8);
    var writer = stream.writer(io, &write_buf);
    writer.interface.writeAll(response) catch return;
    writer.interface.flush() catch return;
}

/// Send 501 Not Implemented response (RFC 7231 Section 6.6.2).
/// Used for methods the server does not support (e.g., CONNECT).
/// TigerStyle: Standalone function with explicit parameters.
pub fn send501NotImplemented(io: Io, stream: Io.net.Stream, message: []const u8) void {
    assert(message.len > 0);

    sendResponse(io, stream, 501, "text/plain", message, true);
}

// =============================================================================
// Direct Response (for handlers that respond without forwarding)
// =============================================================================

const types = @import("serval-core").types;
const DirectResponse = types.DirectResponse;
const ResponseMode = types.ResponseMode;
const StreamResponse = types.StreamResponse;
const DIRECT_RESPONSE_HEADER_SIZE_BYTES = config.DIRECT_RESPONSE_HEADER_SIZE_BYTES;

/// Send a direct response from handler without forwarding to upstream.
/// Dispatches to Content-Length or chunked encoding based on response_mode.
/// TigerStyle: Standalone function with explicit parameters.
pub fn sendDirectResponse(io: Io, stream: Io.net.Stream, resp: DirectResponse) void {
    // Preconditions: validate response invariants before dispatch
    assert(resp.status >= 100 and resp.status < 600);
    assert(resp.content_type.len > 0);

    switch (resp.response_mode) {
        .content_length => sendDirectResponseContentLength(io, stream, resp),
        .chunked => sendDirectResponseChunked(io, stream, resp),
    }
}

/// Send direct response with Content-Length framing (RFC 9112 Section 6.2).
/// Body length is known upfront, sent as single unit after headers.
/// TigerStyle: Helper function keeps dispatch under 70 lines.
fn sendDirectResponseContentLength(io: Io, stream: Io.net.Stream, resp: DirectResponse) void {
    // Preconditions
    assert(resp.status >= 100 and resp.status < 600);
    assert(resp.content_type.len > 0);
    // Extra headers must end with \r\n if non-empty
    assert(resp.extra_headers.len == 0 or std.mem.endsWith(u8, resp.extra_headers, "\r\n"));

    // Format headers into local buffer (body is already in handler's buffer)
    var header_buf: [DIRECT_RESPONSE_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([DIRECT_RESPONSE_HEADER_SIZE_BYTES]u8);
    const headers = std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n{s}\r\n",
        .{ resp.status, statusText(resp.status), resp.content_type, resp.body.len, resp.extra_headers },
    ) catch return; // TigerStyle: Headers too large, silent fail (log in production)

    // Write headers + body (write buffer batches into single syscall when possible)
    var write_buf: [WRITE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([WRITE_BUFFER_SIZE_BYTES]u8);
    var writer = stream.writer(io, &write_buf);
    writer.interface.writeAll(headers) catch return;
    writer.interface.writeAll(resp.body) catch return;
    writer.interface.flush() catch return;
}

/// Send direct response with chunked Transfer-Encoding (RFC 9112 Section 7.1).
/// Body is chunk-encoded: hex-length CRLF body CRLF, terminated with 0 CRLF CRLF.
/// Why single chunk: Direct responses have complete body, no streaming benefit.
/// TigerStyle: Helper function keeps dispatch under 70 lines.
fn sendDirectResponseChunked(io: Io, stream: Io.net.Stream, resp: DirectResponse) void {
    // Preconditions
    assert(resp.status >= 100 and resp.status < 600);
    assert(resp.content_type.len > 0);
    // Extra headers must end with \r\n if non-empty
    assert(resp.extra_headers.len == 0 or std.mem.endsWith(u8, resp.extra_headers, "\r\n"));

    // Format headers with Transfer-Encoding: chunked instead of Content-Length
    var header_buf: [DIRECT_RESPONSE_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([DIRECT_RESPONSE_HEADER_SIZE_BYTES]u8);
    const headers = std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nTransfer-Encoding: chunked\r\n{s}\r\n",
        .{ resp.status, statusText(resp.status), resp.content_type, resp.extra_headers },
    ) catch return; // TigerStyle: Headers too large, silent fail (log in production)

    // Format chunk header: hex-length CRLF (max 16 hex digits + CRLF = 18 bytes)
    var chunk_header_buf: [20]u8 = std.mem.zeroes([20]u8);
    const chunk_header = std.fmt.bufPrint(
        &chunk_header_buf,
        "{x}\r\n",
        .{resp.body.len},
    ) catch return; // TigerStyle: Chunk header format failed

    // Terminator: CRLF after body + final zero chunk + trailing CRLF
    const chunk_terminator = "\r\n0\r\n\r\n";

    // Write: headers, chunk-header, body, terminator
    var write_buf: [WRITE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([WRITE_BUFFER_SIZE_BYTES]u8);
    var writer = stream.writer(io, &write_buf);
    writer.interface.writeAll(headers) catch return;
    writer.interface.writeAll(chunk_header) catch return;
    writer.interface.writeAll(resp.body) catch return;
    writer.interface.writeAll(chunk_terminator) catch return;
    writer.interface.flush() catch return;
}

// =============================================================================
// Streaming Response Helpers (for chunked Transfer-Encoding)
// =============================================================================

/// Maximum hex digits for chunk size: u64 max = 16 hex chars + \r\n = 18 bytes.
/// TigerStyle: Named constant with units, explicitly sized for max chunk header.
const CHUNK_HEADER_SIZE_BYTES: u32 = 20;

/// Send chunked transfer encoding headers for streaming response.
/// RFC 9112 Section 7.1: MUST include Transfer-Encoding: chunked.
/// RFC 9112 Section 6.2: MUST NOT include Content-Length with chunked.
/// TigerStyle: Pure function, explicit I/O parameter, no hidden state.
///
/// Parameters:
/// - writer: Write interface (supports TLS or plain socket via duck typing)
/// - resp: StreamResponse with status, content_type, extra_headers
///
/// Returns: void on success, error on write failure.
pub fn sendStreamHeaders(writer: anytype, resp: StreamResponse) !void {
    // S1: Preconditions - valid HTTP status code range (100-599)
    assert(resp.status >= 100 and resp.status < 600);
    // S1: Precondition - content_type must be non-empty
    assert(resp.content_type.len > 0);
    // S1: Precondition - extra_headers must end with \r\n if non-empty
    assert(resp.extra_headers.len == 0 or std.mem.endsWith(u8, resp.extra_headers, "\r\n"));

    // Format HTTP response headers with Transfer-Encoding: chunked
    // NOTE: Content-Length is intentionally omitted per RFC 9112
    var header_buf: [DIRECT_RESPONSE_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([DIRECT_RESPONSE_HEADER_SIZE_BYTES]u8);
    const headers = std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nTransfer-Encoding: chunked\r\n{s}\r\n",
        .{ resp.status, statusText(resp.status), resp.content_type, resp.extra_headers },
    ) catch return error.HeadersTooLarge;

    // S2: Postcondition - headers end with double CRLF (valid HTTP header block)
    assert(std.mem.endsWith(u8, headers, "\r\n\r\n"));

    try writer.writeAll(headers);
}

/// Send a single chunk in chunked transfer encoding format.
/// RFC 9112 Section 7.1: chunk = chunk-size CRLF chunk-data CRLF
/// Format: "{hex length}\r\n{data}\r\n"
/// TigerStyle: Pure function, explicit parameters, bounded buffer.
///
/// Parameters:
/// - writer: Write interface (supports TLS or plain socket via duck typing)
/// - data: Chunk data to send (must be non-empty for mid-stream chunks)
///
/// Returns: void on success, error on write failure.
pub fn sendChunk(writer: anytype, data: []const u8) !void {
    // S1: Precondition - don't send empty chunks mid-stream
    // Empty chunks are only valid as final chunk (sendFinalChunk handles that)
    assert(data.len > 0);

    // Format chunk header: hex length + CRLF
    // u64 max fits in 16 hex chars, plus 2 for CRLF = 18, buffer is 20 for safety
    var chunk_header_buf: [CHUNK_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([CHUNK_HEADER_SIZE_BYTES]u8);
    const chunk_header = std.fmt.bufPrint(
        &chunk_header_buf,
        "{x}\r\n",
        .{data.len},
    ) catch return error.ChunkHeaderFormatFailed;

    // Write: chunk-header, data, trailing CRLF
    try writer.writeAll(chunk_header);
    try writer.writeAll(data);
    try writer.writeAll("\r\n");
}

/// Send final chunk to terminate chunked transfer encoding.
/// RFC 9112 Section 7.1: last-chunk = 1*"0" CRLF
/// Followed by optional trailer and final CRLF.
/// Format: "0\r\n\r\n" (zero-length chunk without trailers)
/// TigerStyle: Pure function, explicit parameter, constant output.
///
/// Parameters:
/// - writer: Write interface (supports TLS or plain socket via duck typing)
///
/// Returns: void on success, error on write failure.
pub fn sendFinalChunk(writer: anytype) !void {
    // RFC 9112: Final chunk is "0\r\n" followed by optional trailer-section and final CRLF.
    // Without trailers: "0\r\n\r\n" (5 bytes total)
    const final_chunk = "0\r\n\r\n";

    // S2: Postcondition - final chunk has correct format
    assert(final_chunk.len == 5);
    assert(std.mem.startsWith(u8, final_chunk, "0\r\n"));
    assert(std.mem.endsWith(u8, final_chunk, "\r\n\r\n"));

    try writer.writeAll(final_chunk);
}

// =============================================================================
// Tests
// =============================================================================

test "statusText returns correct text for 1xx informational codes" {
    try std.testing.expectEqualStrings("Continue", statusText(100));
    try std.testing.expectEqualStrings("Switching Protocols", statusText(101));
}

test "statusText returns correct text for 2xx success codes" {
    try std.testing.expectEqualStrings("OK", statusText(200));
    try std.testing.expectEqualStrings("Created", statusText(201));
    try std.testing.expectEqualStrings("Accepted", statusText(202));
    try std.testing.expectEqualStrings("No Content", statusText(204));
    try std.testing.expectEqualStrings("Partial Content", statusText(206));
}

test "statusText returns correct text for 3xx redirection codes" {
    try std.testing.expectEqualStrings("Moved Permanently", statusText(301));
    try std.testing.expectEqualStrings("Found", statusText(302));
    try std.testing.expectEqualStrings("See Other", statusText(303));
    try std.testing.expectEqualStrings("Not Modified", statusText(304));
    try std.testing.expectEqualStrings("Temporary Redirect", statusText(307));
    try std.testing.expectEqualStrings("Permanent Redirect", statusText(308));
}

test "statusText returns correct text for 4xx client error codes" {
    try std.testing.expectEqualStrings("Bad Request", statusText(400));
    try std.testing.expectEqualStrings("Unauthorized", statusText(401));
    try std.testing.expectEqualStrings("Forbidden", statusText(403));
    try std.testing.expectEqualStrings("Not Found", statusText(404));
    try std.testing.expectEqualStrings("Method Not Allowed", statusText(405));
    try std.testing.expectEqualStrings("Request Timeout", statusText(408));
    try std.testing.expectEqualStrings("Conflict", statusText(409));
    try std.testing.expectEqualStrings("Gone", statusText(410));
    try std.testing.expectEqualStrings("Length Required", statusText(411));
    try std.testing.expectEqualStrings("Content Too Large", statusText(413));
    try std.testing.expectEqualStrings("URI Too Long", statusText(414));
    try std.testing.expectEqualStrings("Unsupported Media Type", statusText(415));
    try std.testing.expectEqualStrings("Too Many Requests", statusText(429));
    try std.testing.expectEqualStrings("Request Header Fields Too Large", statusText(431));
}

test "statusText returns correct text for 5xx server error codes" {
    try std.testing.expectEqualStrings("Internal Server Error", statusText(500));
    try std.testing.expectEqualStrings("Not Implemented", statusText(501));
    try std.testing.expectEqualStrings("Bad Gateway", statusText(502));
    try std.testing.expectEqualStrings("Service Unavailable", statusText(503));
    try std.testing.expectEqualStrings("Gateway Timeout", statusText(504));
}

test "statusText returns Error for unknown codes" {
    try std.testing.expectEqualStrings("Error", statusText(203)); // Non-standard
    try std.testing.expectEqualStrings("Error", statusText(305)); // Non-standard
    try std.testing.expectEqualStrings("Error", statusText(418)); // I'm a teapot
    try std.testing.expectEqualStrings("Error", statusText(599)); // Edge case (still unknown)
}

// =============================================================================
// Chunked Response Format Tests
// =============================================================================

test "chunked encoding format - chunk header for small body" {
    // Verify chunk header format: hex-length CRLF
    // Body length 13 ("Hello, World!") should produce "d\r\n"
    var buf: [20]u8 = std.mem.zeroes([20]u8);
    const chunk_header = std.fmt.bufPrint(&buf, "{x}\r\n", .{@as(usize, 13)}) catch unreachable;
    try std.testing.expectEqualStrings("d\r\n", chunk_header);
}

test "chunked encoding format - chunk header for zero-length body" {
    // Empty body should produce "0\r\n" as chunk header
    var buf: [20]u8 = std.mem.zeroes([20]u8);
    const chunk_header = std.fmt.bufPrint(&buf, "{x}\r\n", .{@as(usize, 0)}) catch unreachable;
    try std.testing.expectEqualStrings("0\r\n", chunk_header);
}

test "chunked encoding format - chunk header for large body" {
    // Body length 4096 (0x1000) should produce "1000\r\n"
    var buf: [20]u8 = std.mem.zeroes([20]u8);
    const chunk_header = std.fmt.bufPrint(&buf, "{x}\r\n", .{@as(usize, 4096)}) catch unreachable;
    try std.testing.expectEqualStrings("1000\r\n", chunk_header);
}

test "chunked encoding terminator format" {
    // RFC 9112: chunked body ends with CRLF after data, then 0 CRLF CRLF
    const terminator = "\r\n0\r\n\r\n";
    try std.testing.expectEqual(@as(usize, 7), terminator.len);
    try std.testing.expect(std.mem.endsWith(u8, terminator, "\r\n\r\n"));
}

test "DirectResponse with chunked mode preserves fields" {
    const resp = DirectResponse{
        .status = 200,
        .body = "test body",
        .content_type = "application/json",
        .extra_headers = "X-Custom: value\r\n",
        .response_mode = .chunked,
    };

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("test body", resp.body);
    try std.testing.expectEqualStrings("application/json", resp.content_type);
    try std.testing.expectEqualStrings("X-Custom: value\r\n", resp.extra_headers);
    try std.testing.expect(resp.response_mode == .chunked);
}

test "DirectResponse content_length mode is default" {
    // Backward compatibility: content_length is the default mode
    const resp = DirectResponse{
        .status = 200,
        .body = "test",
    };

    try std.testing.expect(resp.response_mode == .content_length);
}

// =============================================================================
// Streaming Response Helper Tests
// =============================================================================

/// Mock writer for testing streaming helpers.
/// Captures all writes to an internal buffer for verification.
/// TigerStyle: Bounded buffer, explicit size.
const MockWriter = struct {
    const BUFFER_SIZE: usize = 4096;
    buffer: [BUFFER_SIZE]u8 = std.mem.zeroes([BUFFER_SIZE]u8),
    pos: usize = 0,
    write_count: u32 = 0,

    pub fn writeAll(self: *MockWriter, data: []const u8) !void {
        if (self.pos + data.len > BUFFER_SIZE) {
            return error.BufferOverflow;
        }
        @memcpy(self.buffer[self.pos..][0..data.len], data);
        self.pos += data.len;
        self.write_count += 1;
    }

    pub fn written(self: *const MockWriter) []const u8 {
        return self.buffer[0..self.pos];
    }

    pub fn reset(self: *MockWriter) void {
        self.pos = 0;
        self.write_count = 0;
        @memset(&self.buffer, 0);
    }
};

test "sendStreamHeaders formats headers correctly" {
    var writer = MockWriter{};
    const resp = StreamResponse{
        .status = 200,
        .content_type = "text/event-stream",
        .extra_headers = "",
    };

    try sendStreamHeaders(&writer, resp);

    const expected = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    try std.testing.expectEqualStrings(expected, writer.written());
}

test "sendStreamHeaders includes extra headers" {
    var writer = MockWriter{};
    const resp = StreamResponse{
        .status = 200,
        .content_type = "application/json",
        .extra_headers = "Cache-Control: no-cache\r\n",
    };

    try sendStreamHeaders(&writer, resp);

    const expected = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache\r\n\r\n";
    try std.testing.expectEqualStrings(expected, writer.written());
}

test "sendStreamHeaders with non-200 status" {
    var writer = MockWriter{};
    const resp = StreamResponse{
        .status = 206,
        .content_type = "video/mp4",
        .extra_headers = "",
    };

    try sendStreamHeaders(&writer, resp);

    const expected = "HTTP/1.1 206 Partial Content\r\nContent-Type: video/mp4\r\nTransfer-Encoding: chunked\r\n\r\n";
    try std.testing.expectEqualStrings(expected, writer.written());
}

test "sendChunk formats small chunk correctly" {
    var writer = MockWriter{};
    const data = "Hello, World!";

    try sendChunk(&writer, data);

    // "Hello, World!" is 13 bytes = 0xd in hex
    const expected = "d\r\nHello, World!\r\n";
    try std.testing.expectEqualStrings(expected, writer.written());
}

test "sendChunk formats large chunk correctly" {
    var writer = MockWriter{};
    // Create 256-byte chunk (0x100 in hex)
    var data: [256]u8 = undefined;
    @memset(&data, 'X');

    try sendChunk(&writer, &data);

    // Verify header is "100\r\n"
    const output = writer.written();
    try std.testing.expect(std.mem.startsWith(u8, output, "100\r\n"));
    // Verify trailing CRLF
    try std.testing.expect(std.mem.endsWith(u8, output, "\r\n"));
    // Verify total length: 5 (header) + 256 (data) + 2 (trailing CRLF) = 263
    try std.testing.expectEqual(@as(usize, 263), output.len);
}

test "sendChunk with single byte" {
    var writer = MockWriter{};
    const data = "X";

    try sendChunk(&writer, data);

    const expected = "1\r\nX\r\n";
    try std.testing.expectEqualStrings(expected, writer.written());
}

test "sendFinalChunk sends correct terminator" {
    var writer = MockWriter{};

    try sendFinalChunk(&writer);

    const expected = "0\r\n\r\n";
    try std.testing.expectEqualStrings(expected, writer.written());
    try std.testing.expectEqual(@as(usize, 5), writer.written().len);
}

test "streaming sequence: headers, chunks, final" {
    var writer = MockWriter{};

    // Send stream headers
    try sendStreamHeaders(&writer, .{
        .status = 200,
        .content_type = "text/plain",
        .extra_headers = "",
    });

    // Send two chunks
    try sendChunk(&writer, "chunk1");
    try sendChunk(&writer, "chunk2");

    // Send final chunk
    try sendFinalChunk(&writer);

    const output = writer.written();

    // Verify structure
    try std.testing.expect(std.mem.indexOf(u8, output, "Transfer-Encoding: chunked") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "6\r\nchunk1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "6\r\nchunk2\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, output, "0\r\n\r\n"));
}

test "sendStreamHeaders multiple extra headers" {
    var writer = MockWriter{};
    const resp = StreamResponse{
        .status = 200,
        .content_type = "text/event-stream",
        .extra_headers = "Cache-Control: no-cache\r\nX-Accel-Buffering: no\r\n",
    };

    try sendStreamHeaders(&writer, resp);

    const output = writer.written();
    try std.testing.expect(std.mem.indexOf(u8, output, "Cache-Control: no-cache\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "X-Accel-Buffering: no\r\n") != null);
}
