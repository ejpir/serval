// lib/serval-proxy/h1/response.zig
//! HTTP Response Handling
//!
//! Receives and forwards HTTP/1.1 responses from upstream servers.
//! TigerStyle: Stale detection for pooled connections, bounded loops.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const config = serval_core.config;
const debugLog = serval_core.debugLog;
const time = serval_core.time;

const serval_http = @import("serval-http");
const parseStatusCode = serval_http.parseStatusCode;
const parseContentLength = serval_http.parseContentLength;

const proxy_types = @import("../types.zig");
const ForwardError = proxy_types.ForwardError;
const ForwardResult = proxy_types.ForwardResult;

const request_mod = @import("request.zig");
const sendBuffer = request_mod.sendBuffer;

const body_transfer = @import("body.zig");
const forwardBody = body_transfer.forwardBody;

// For tests: Import all parsing functions to verify contracts
const parseContentLengthValue = serval_http.parseContentLengthValue;

// =============================================================================
// Response Forwarding
// =============================================================================

/// Result of receiving headers from upstream.
pub const HeadersResult = struct {
    header_len: usize,
    header_end: usize,
};

/// Forward upstream response to client.
/// TigerStyle: Uses stream for headers, raw fds for splice body forwarding.
pub fn forwardResponse(
    io: Io,
    upstream_stream: Io.net.Stream,
    client_stream: Io.net.Stream,
    is_pooled: bool,
) ForwardError!ForwardResult {
    // Time the entire recv phase (headers + body from upstream)
    const recv_start_ns = time.monotonicNanos();

    var header_buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([config.MAX_HEADER_SIZE_BYTES]u8);

    const headers = try receiveHeaders(upstream_stream, io, &header_buffer, is_pooled);
    const status = parseStatusCode(header_buffer[0..headers.header_len]) orelse
        return ForwardError.InvalidResponse;
    const content_length = parseContentLength(header_buffer[0..headers.header_len]);

    debugLog("recv: headers received fd={d} status={d} content_length={?d}", .{ upstream_stream.socket.handle, status, content_length });

    // Forward headers and any pre-fetched body to client via async stream
    try sendBuffer(client_stream, io, header_buffer[0..headers.header_len]);

    // Forward remaining body
    // TigerStyle: Use u64 for body sizes (Content-Length can exceed 4GB).
    const body_already_read: u64 = headers.header_len - headers.header_end;
    var total_body_bytes: u64 = body_already_read;

    if (content_length) |length| {
        if (length > body_already_read) {
            const remaining = length - body_already_read;
            debugLog("recv: forwarding body remaining={d}", .{remaining});
            // Extract raw fds for splice zero-copy body forwarding
            const upstream_fd = upstream_stream.socket.handle;
            const client_fd = client_stream.socket.handle;
            total_body_bytes += try forwardBody(upstream_fd, client_fd, remaining);
        }
    }

    const recv_end_ns = time.monotonicNanos();
    const recv_duration_ns = time.elapsedNanos(recv_start_ns, recv_end_ns);
    debugLog("recv: complete duration_us={d} total_body={d}", .{ recv_duration_ns / 1000, total_body_bytes });

    assert(status >= 100 and status <= 599);
    return .{
        .status = status,
        .response_bytes = @intCast(headers.header_end + total_body_bytes),
        .connection_reused = false, // Set by forwardWithConnection
        .recv_duration_ns = recv_duration_ns,
    };
}

/// Receive HTTP response headers from upstream using async stream reader.
/// TigerStyle: Explicit io parameter, stale detection for pooled connections.
pub fn receiveHeaders(
    stream: Io.net.Stream,
    io: Io,
    buffer: *[config.MAX_HEADER_SIZE_BYTES]u8,
    is_pooled: bool,
) ForwardError!HeadersResult {
    var read_buf: [config.STREAM_READ_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([config.STREAM_READ_BUFFER_SIZE_BYTES]u8);
    var reader = stream.reader(io, &read_buf);

    var header_len: usize = 0;
    const max_iterations: usize = config.MAX_HEADER_SIZE_BYTES;
    var iterations: usize = 0;

    while (header_len < buffer.len and iterations < max_iterations) : (iterations += 1) {
        var bufs: [1][]u8 = .{buffer[header_len..]};
        const n = reader.interface.readVec(&bufs) catch {
            if (is_pooled and header_len == 0) return ForwardError.StaleConnection;
            return ForwardError.RecvFailed;
        };

        if (n == 0) {
            if (is_pooled and header_len == 0) return ForwardError.StaleConnection;
            return ForwardError.RecvFailed;
        }

        header_len += n;

        // Check for end of headers
        if (std.mem.indexOf(u8, buffer[0..header_len], "\r\n\r\n")) |end_pos| {
            const header_end = end_pos + 4;
            assert(header_end <= header_len);
            return .{ .header_len = header_len, .header_end = header_end };
        }
    }

    return ForwardError.HeadersTooLarge;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

// -----------------------------------------------------------------------------
// HeadersResult Tests
// -----------------------------------------------------------------------------

test "HeadersResult: correct structure layout" {
    // Verify HeadersResult has expected fields and types
    const result = HeadersResult{
        .header_len = 100,
        .header_end = 50,
    };
    try testing.expectEqual(@as(usize, 100), result.header_len);
    try testing.expectEqual(@as(usize, 50), result.header_end);

    // Verify invariant: header_end <= header_len
    try testing.expect(result.header_end <= result.header_len);
}

test "HeadersResult: zero values valid" {
    // Edge case: both zero is a degenerate case but structurally valid
    const result = HeadersResult{
        .header_len = 0,
        .header_end = 0,
    };
    try testing.expectEqual(@as(usize, 0), result.header_len);
    try testing.expectEqual(@as(usize, 0), result.header_end);
}

test "HeadersResult: body bytes calculation" {
    // Test the body bytes calculation: header_len - header_end = body bytes already read
    const result = HeadersResult{
        .header_len = 150,
        .header_end = 100,
    };
    const body_already_read = result.header_len - result.header_end;
    try testing.expectEqual(@as(usize, 50), body_already_read);
}

// -----------------------------------------------------------------------------
// Status Code Parsing Tests (via serval-http)
// Tests verify the contract between response.zig and parser.zig
// -----------------------------------------------------------------------------

test "parseStatusCode: common success codes" {
    // 2xx Success
    try testing.expectEqual(@as(?u16, 200), parseStatusCode("HTTP/1.1 200 OK\r\n"));
    try testing.expectEqual(@as(?u16, 201), parseStatusCode("HTTP/1.1 201 Created\r\n"));
    try testing.expectEqual(@as(?u16, 204), parseStatusCode("HTTP/1.1 204 No Content\r\n"));
}

test "parseStatusCode: redirect codes" {
    // 3xx Redirection
    try testing.expectEqual(@as(?u16, 301), parseStatusCode("HTTP/1.1 301 Moved Permanently\r\n"));
    try testing.expectEqual(@as(?u16, 302), parseStatusCode("HTTP/1.1 302 Found\r\n"));
    try testing.expectEqual(@as(?u16, 304), parseStatusCode("HTTP/1.1 304 Not Modified\r\n"));
    try testing.expectEqual(@as(?u16, 307), parseStatusCode("HTTP/1.1 307 Temporary Redirect\r\n"));
    try testing.expectEqual(@as(?u16, 308), parseStatusCode("HTTP/1.1 308 Permanent Redirect\r\n"));
}

test "parseStatusCode: client error codes" {
    // 4xx Client Errors
    try testing.expectEqual(@as(?u16, 400), parseStatusCode("HTTP/1.1 400 Bad Request\r\n"));
    try testing.expectEqual(@as(?u16, 401), parseStatusCode("HTTP/1.1 401 Unauthorized\r\n"));
    try testing.expectEqual(@as(?u16, 403), parseStatusCode("HTTP/1.1 403 Forbidden\r\n"));
    try testing.expectEqual(@as(?u16, 404), parseStatusCode("HTTP/1.1 404 Not Found\r\n"));
    try testing.expectEqual(@as(?u16, 405), parseStatusCode("HTTP/1.1 405 Method Not Allowed\r\n"));
    try testing.expectEqual(@as(?u16, 408), parseStatusCode("HTTP/1.1 408 Request Timeout\r\n"));
    try testing.expectEqual(@as(?u16, 413), parseStatusCode("HTTP/1.1 413 Payload Too Large\r\n"));
    try testing.expectEqual(@as(?u16, 429), parseStatusCode("HTTP/1.1 429 Too Many Requests\r\n"));
}

test "parseStatusCode: server error codes" {
    // 5xx Server Errors
    try testing.expectEqual(@as(?u16, 500), parseStatusCode("HTTP/1.1 500 Internal Server Error\r\n"));
    try testing.expectEqual(@as(?u16, 502), parseStatusCode("HTTP/1.1 502 Bad Gateway\r\n"));
    try testing.expectEqual(@as(?u16, 503), parseStatusCode("HTTP/1.1 503 Service Unavailable\r\n"));
    try testing.expectEqual(@as(?u16, 504), parseStatusCode("HTTP/1.1 504 Gateway Timeout\r\n"));
}

test "parseStatusCode: informational codes" {
    // 1xx Informational
    try testing.expectEqual(@as(?u16, 100), parseStatusCode("HTTP/1.1 100 Continue\r\n"));
    try testing.expectEqual(@as(?u16, 101), parseStatusCode("HTTP/1.1 101 Switching Protocols\r\n"));
}

test "parseStatusCode: boundary values" {
    // Minimum valid status
    try testing.expectEqual(@as(?u16, 100), parseStatusCode("HTTP/1.1 100 Continue\r\n"));
    // Maximum valid status
    try testing.expectEqual(@as(?u16, 599), parseStatusCode("HTTP/1.1 599 Custom\r\n"));
    // Just below minimum - invalid
    try testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 099 Too Low\r\n"));
    // Just above maximum - invalid
    try testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 600 Too High\r\n"));
}

test "parseStatusCode: HTTP/1.0 responses" {
    // HTTP/1.0 is also valid
    try testing.expectEqual(@as(?u16, 200), parseStatusCode("HTTP/1.0 200 OK\r\n"));
    try testing.expectEqual(@as(?u16, 404), parseStatusCode("HTTP/1.0 404 Not Found\r\n"));
}

test "parseStatusCode: malformed response lines" {
    // Empty string
    try testing.expectEqual(@as(?u16, null), parseStatusCode(""));
    // Too short
    try testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1"));
    try testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 "));
    try testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 20"));
    // Non-numeric status
    try testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 ABC OK\r\n"));
    try testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 2OO OK\r\n"));
    // Missing space after version
    try testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1200 OK\r\n"));
}

test "parseStatusCode: custom status codes" {
    // Non-standard but valid custom codes
    try testing.expectEqual(@as(?u16, 218), parseStatusCode("HTTP/1.1 218 This is fine\r\n"));
    try testing.expectEqual(@as(?u16, 451), parseStatusCode("HTTP/1.1 451 Unavailable For Legal Reasons\r\n"));
}

// -----------------------------------------------------------------------------
// Content-Length Parsing Tests
// -----------------------------------------------------------------------------

test "parseContentLength: no headers" {
    try testing.expectEqual(@as(?u64, null), parseContentLength("HTTP/1.1 200 OK\r\n\r\n"));
}

test "parseContentLength: single header" {
    try testing.expectEqual(@as(?u64, 0), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 1), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 1234), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"));
}

test "parseContentLength: maximum headers" {
    // Response with many headers, Content-Length near the end
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Date: Mon, 01 Jan 2024 00:00:00 GMT\r\n" ++
        "Server: Serval/1.0\r\n" ++
        "X-Custom-1: value1\r\n" ++
        "X-Custom-2: value2\r\n" ++
        "X-Custom-3: value3\r\n" ++
        "X-Custom-4: value4\r\n" ++
        "X-Custom-5: value5\r\n" ++
        "Content-Length: 42\r\n" ++
        "\r\n";
    try testing.expectEqual(@as(?u64, 42), parseContentLength(response));
}

test "parseContentLength: case insensitivity" {
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 100\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\nContent-length: 100\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\nconTENT-LENgth: 100\r\n\r\n"));
}

test "parseContentLength: whitespace handling" {
    // Whitespace after colon should be trimmed
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length:100\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length:  100\r\n\r\n"));
    try testing.expectEqual(@as(?u64, 100), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length:\t100\r\n\r\n"));
}

test "parseContentLength: empty body (zero length)" {
    try testing.expectEqual(@as(?u64, 0), parseContentLength("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"));
}

test "parseContentLength: large values" {
    // Large but valid Content-Length (within u64 range)
    try testing.expectEqual(@as(?u64, 1_000_000_000), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n"));
}

test "parseContentLength: missing header" {
    try testing.expectEqual(@as(?u64, null), parseContentLength("HTTP/1.1 200 OK\r\nX-Other: value\r\n\r\n"));
    try testing.expectEqual(@as(?u64, null), parseContentLength(""));
}

test "parseContentLength: rejects leading zeros" {
    try testing.expectEqual(@as(?u64, null), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 007\r\n\r\n"));
    try testing.expectEqual(@as(?u64, null), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 0123\r\n\r\n"));
    try testing.expectEqual(@as(?u64, null), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 00\r\n\r\n"));
}

// -----------------------------------------------------------------------------
// Content-Length Value Parsing Tests
// -----------------------------------------------------------------------------

test "parseContentLengthValue: valid values" {
    try testing.expectEqual(@as(?u64, 0), parseContentLengthValue("0"));
    try testing.expectEqual(@as(?u64, 1), parseContentLengthValue("1"));
    try testing.expectEqual(@as(?u64, 123), parseContentLengthValue("123"));
    try testing.expectEqual(@as(?u64, 1234567890), parseContentLengthValue("1234567890"));
}

test "parseContentLengthValue: u64 max" {
    // Maximum u64 value: 18446744073709551615
    try testing.expectEqual(@as(?u64, 18446744073709551615), parseContentLengthValue("18446744073709551615"));
}

test "parseContentLengthValue: overflow" {
    // One more than u64 max
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("18446744073709551616"));
    // Way larger
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("99999999999999999999999"));
}

test "parseContentLengthValue: invalid characters" {
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue(""));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("abc"));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("12a34"));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("-1"));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("1.5"));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue(" 100"));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("100 "));
}

test "parseContentLengthValue: rejects leading zeros" {
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("007"));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("00"));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("0123"));
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("01"));
    // Single zero is valid
    try testing.expectEqual(@as(?u64, 0), parseContentLengthValue("0"));
}

test "parseContentLengthValue: too long" {
    // More than 20 digits
    try testing.expectEqual(@as(?u64, null), parseContentLengthValue("123456789012345678901"));
}

// -----------------------------------------------------------------------------
// Response Header Pattern Tests
// Tests for various response scenarios the proxy must handle
// -----------------------------------------------------------------------------

test "response patterns: chunked transfer encoding detection" {
    // These are response patterns that forwardResponse must handle.
    // Currently chunked is not supported, so we just verify parsing works.
    const chunked_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";
    // Status code should parse correctly
    try testing.expectEqual(@as(?u16, 200), parseStatusCode(chunked_response));
    // No Content-Length when chunked
    try testing.expectEqual(@as(?u64, null), parseContentLength(chunked_response));
}

test "response patterns: connection close" {
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 5\r\n" ++
        "Connection: close\r\n" ++
        "\r\n";
    try testing.expectEqual(@as(?u16, 200), parseStatusCode(response));
    try testing.expectEqual(@as(?u64, 5), parseContentLength(response));
}

test "response patterns: connection keep-alive" {
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 5\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n";
    try testing.expectEqual(@as(?u16, 200), parseStatusCode(response));
    try testing.expectEqual(@as(?u64, 5), parseContentLength(response));
}

test "response patterns: 204 No Content" {
    // 204 responses have no body
    const response =
        "HTTP/1.1 204 No Content\r\n" ++
        "\r\n";
    try testing.expectEqual(@as(?u16, 204), parseStatusCode(response));
    try testing.expectEqual(@as(?u64, null), parseContentLength(response));
}

test "response patterns: 304 Not Modified" {
    // 304 responses have no body
    const response =
        "HTTP/1.1 304 Not Modified\r\n" ++
        "ETag: \"abc123\"\r\n" ++
        "\r\n";
    try testing.expectEqual(@as(?u16, 304), parseStatusCode(response));
    try testing.expectEqual(@as(?u64, null), parseContentLength(response));
}

test "response patterns: HEAD response with Content-Length" {
    // HEAD responses may have Content-Length but no body
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 12345\r\n" ++
        "\r\n";
    try testing.expectEqual(@as(?u16, 200), parseStatusCode(response));
    try testing.expectEqual(@as(?u64, 12345), parseContentLength(response));
}

// -----------------------------------------------------------------------------
// Buffer Boundary Tests
// -----------------------------------------------------------------------------

test "buffer boundary: header end detection with body" {
    // Simulate a response where headers and partial body are in the same buffer
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 10\r\n" ++
        "\r\n" ++
        "HelloW"; // 6 bytes of body already read

    // Find header end position
    const header_end_idx = std.mem.indexOf(u8, response, "\r\n\r\n");
    try testing.expect(header_end_idx != null);
    const header_end = header_end_idx.? + 4;

    // Header section ends at position, body starts after
    const body_in_buffer = response[header_end..];
    try testing.expectEqualStrings("HelloW", body_in_buffer);
    try testing.expectEqual(@as(usize, 6), body_in_buffer.len);
}

test "buffer boundary: exact header end" {
    // Headers end exactly at buffer boundary (no partial body)
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 10\r\n" ++
        "\r\n";

    const header_end_idx = std.mem.indexOf(u8, response, "\r\n\r\n");
    try testing.expect(header_end_idx != null);
    const header_end = header_end_idx.? + 4;

    try testing.expectEqual(response.len, header_end);
}

test "buffer boundary: minimal response" {
    // Minimal valid response
    const response = "HTTP/1.1 200 OK\r\n\r\n";
    try testing.expectEqual(@as(?u16, 200), parseStatusCode(response));
    try testing.expectEqual(@as(?u64, null), parseContentLength(response));

    const header_end_idx = std.mem.indexOf(u8, response, "\r\n\r\n");
    try testing.expect(header_end_idx != null);
    try testing.expectEqual(@as(usize, 15), header_end_idx.?);
}

// -----------------------------------------------------------------------------
// ForwardError Tests
// -----------------------------------------------------------------------------

test "ForwardError: all error variants exist" {
    // Verify all expected error variants are defined
    // This ensures the contract between response.zig and callers is maintained
    const errors = [_]ForwardError{
        ForwardError.ConnectFailed,
        ForwardError.SendFailed,
        ForwardError.RecvFailed,
        ForwardError.StaleConnection,
        ForwardError.HeadersTooLarge,
        ForwardError.InvalidResponse,
        ForwardError.SpliceFailed,
        ForwardError.InvalidAddress,
        ForwardError.RequestBodyTooLarge,
    };

    // Verify we have all expected errors
    try testing.expectEqual(@as(usize, 9), errors.len);
}

// -----------------------------------------------------------------------------
// ForwardResult Tests
// -----------------------------------------------------------------------------

test "ForwardResult: structure and defaults" {
    const result = ForwardResult{
        .status = 200,
        .response_bytes = 1024,
        .connection_reused = true,
    };

    try testing.expectEqual(@as(u16, 200), result.status);
    try testing.expectEqual(@as(u64, 1024), result.response_bytes);
    try testing.expect(result.connection_reused);

    // Verify defaults for timing fields
    try testing.expectEqual(@as(u64, 0), result.dns_duration_ns);
    try testing.expectEqual(@as(u64, 0), result.tcp_connect_duration_ns);
    try testing.expectEqual(@as(u64, 0), result.send_duration_ns);
    try testing.expectEqual(@as(u64, 0), result.recv_duration_ns);
    try testing.expectEqual(@as(u64, 0), result.pool_wait_ns);
    try testing.expectEqual(@as(u16, 0), result.upstream_local_port);
}

test "ForwardResult: timing fields" {
    const result = ForwardResult{
        .status = 200,
        .response_bytes = 512,
        .connection_reused = false,
        .dns_duration_ns = 1_000_000,
        .tcp_connect_duration_ns = 5_000_000,
        .send_duration_ns = 100_000,
        .recv_duration_ns = 2_000_000,
        .pool_wait_ns = 50_000,
        .upstream_local_port = 54321,
    };

    try testing.expectEqual(@as(u64, 1_000_000), result.dns_duration_ns);
    try testing.expectEqual(@as(u64, 5_000_000), result.tcp_connect_duration_ns);
    try testing.expectEqual(@as(u64, 100_000), result.send_duration_ns);
    try testing.expectEqual(@as(u64, 2_000_000), result.recv_duration_ns);
    try testing.expectEqual(@as(u64, 50_000), result.pool_wait_ns);
    try testing.expectEqual(@as(u16, 54321), result.upstream_local_port);
}

test "ForwardResult: status code range" {
    // Valid status codes (100-599)
    const result_100 = ForwardResult{
        .status = 100,
        .response_bytes = 0,
        .connection_reused = false,
    };
    try testing.expectEqual(@as(u16, 100), result_100.status);

    const result_599 = ForwardResult{
        .status = 599,
        .response_bytes = 0,
        .connection_reused = false,
    };
    try testing.expectEqual(@as(u16, 599), result_599.status);
}

// -----------------------------------------------------------------------------
// Config Constants Tests (verify response.zig uses correct limits)
// -----------------------------------------------------------------------------

test "config: MAX_HEADER_SIZE_BYTES is reasonable" {
    // Verify the constant is set to expected value
    try testing.expectEqual(@as(u32, 8192), config.MAX_HEADER_SIZE_BYTES);
    // Should be power of 2 or common page size multiple
    try testing.expect(config.MAX_HEADER_SIZE_BYTES >= 4096);
}

test "config: STREAM_READ_BUFFER_SIZE_BYTES is reasonable" {
    try testing.expectEqual(@as(u32, 4096), config.STREAM_READ_BUFFER_SIZE_BYTES);
    // Read buffer should not exceed header max
    try testing.expect(config.STREAM_READ_BUFFER_SIZE_BYTES <= config.MAX_HEADER_SIZE_BYTES);
}
