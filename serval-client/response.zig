// serval-client/response.zig
//! HTTP Response Parser for Client
//!
//! Zero-allocation HTTP/1.1 response parser for client-side use.
//! TigerStyle: Fixed-size buffers, explicit sizes, bounded loops, ~2 assertions per function.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const types = serval_core.types;
const config = serval_core.config;
const containsIgnoreCase = serval_core.containsIgnoreCase;
const HeaderMap = types.HeaderMap;
const BodyFraming = types.BodyFraming;

const serval_http = @import("serval-http");
const parseStatusCode = serval_http.parseStatusCode;
const parseContentLength = serval_http.parseContentLength;
const parseContentLengthValue = serval_http.parseContentLengthValue;

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;
const SocketError = serval_socket.SocketError;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during HTTP response parsing.
/// TigerStyle: Explicit error set, no catch {}.
pub const ResponseError = error{
    /// Socket read operation failed.
    RecvFailed,
    /// Socket read operation timed out.
    RecvTimeout,
    /// Response headers exceeded MAX_HEADER_SIZE_BYTES.
    ResponseHeadersTooLarge,
    /// Invalid status code in response line (not 100-599).
    InvalidResponseStatus,
    /// Malformed response headers (missing terminator, invalid format).
    InvalidResponseHeaders,
    /// Connection was closed by peer before complete response.
    ConnectionClosed,
};

// =============================================================================
// Response Headers
// =============================================================================

/// Parsed HTTP response headers.
/// TigerStyle: Zero-copy, slices reference the input buffer.
pub const ResponseHeaders = struct {
    /// HTTP status code (e.g., 200, 404, 500).
    /// Valid range: 100-599 per RFC 9110.
    status: u16,
    /// Parsed response headers.
    /// Slices point into the original header_buf.
    headers: HeaderMap,
    /// Body framing from Content-Length or Transfer-Encoding.
    /// Determines how to read the response body.
    body_framing: BodyFraming,
    /// Bytes consumed from header_buf (where body starts in buffer).
    /// This is the offset after \r\n\r\n in header_buf.
    /// TigerStyle S2: Use u32 for bounded values (max is MAX_HEADER_SIZE_BYTES = 8192).
    header_bytes: u32,
    /// Total bytes read into header_buf (may include body bytes past header_bytes).
    /// Pre-read body bytes are at header_buf[header_bytes..total_bytes_read].
    /// TigerStyle S2: Use u32 for bounded values.
    total_bytes_read: u32,

    /// Get the number of pre-read body bytes in header_buf.
    /// Returns 0 if no body bytes were read during header reading.
    /// TigerStyle S1: Assertion prevents underflow from invalid state.
    pub fn preReadBodyBytes(self: ResponseHeaders) u32 {
        // S1: Invariant - total_bytes_read always >= header_bytes (enforced at construction)
        assert(self.total_bytes_read >= self.header_bytes);
        return self.total_bytes_read - self.header_bytes;
    }
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum iterations for the header read loop.
/// TigerStyle S3: All loops must be bounded.
/// Why 10,000: At 1 byte per read (pathological case), this allows 10KB headers
/// which exceeds MAX_HEADER_SIZE_BYTES (8KB), ensuring we always hit the size
/// limit before the iteration limit.
const MAX_READ_ITERATIONS: u32 = 10_000;

// =============================================================================
// Header Byte Reading (Low-Level)
// =============================================================================

/// Result of reading header bytes from a socket.
/// TigerStyle: Explicit struct with clear naming.
pub const HeaderBytesResult = struct {
    /// Total bytes read into buffer (headers + any partial body).
    total_bytes: usize,
    /// Position where headers end (after \r\n\r\n).
    /// Body data starts at this offset in the buffer.
    header_end: usize,
};

/// Read response header bytes from socket until \r\n\r\n is found.
///
/// This is a low-level function that just reads bytes and finds the header
/// terminator. It does not parse the headers. Use readResponseHeaders for
/// full parsing, or call this directly when you only need the raw bytes.
///
/// TigerStyle:
/// - S1: Precondition assertions on parameters
/// - S3: Bounded read loop with MAX_READ_ITERATIONS
/// - S4: Explicit error handling for all socket operations
///
/// Returns: HeaderBytesResult with total bytes read and header end position
/// Errors: ResponseError on I/O failure or headers too large
pub fn readHeaderBytes(
    socket: *Socket,
    header_buf: []u8,
) ResponseError!HeaderBytesResult {
    // S1: Preconditions
    assert(header_buf.len > 0);
    assert(header_buf.len <= config.MAX_HEADER_SIZE_BYTES);

    var total_read: usize = 0;
    var iteration: u32 = 0;

    // S3: Bounded loop - read until we find \r\n\r\n or hit limits
    while (iteration < MAX_READ_ITERATIONS) : (iteration += 1) {
        // Check if we've already found the header terminator
        if (total_read >= 4) {
            if (findHeaderEnd(header_buf[0..total_read])) |end_pos| {
                // Found \r\n\r\n
                const header_end = end_pos + 4; // Include the \r\n\r\n
                // S2: Postcondition - header_end is within bounds
                assert(header_end <= total_read);
                return .{
                    .total_bytes = total_read,
                    .header_end = header_end,
                };
            }
        }

        // Check buffer space before reading
        if (total_read >= header_buf.len) {
            return error.ResponseHeadersTooLarge;
        }

        // Read more data
        const remaining_buf = header_buf[total_read..];
        const bytes_read = socket.read(remaining_buf) catch |err| {
            return mapSocketError(err);
        };

        if (bytes_read == 0) {
            // Connection closed before complete headers
            return error.ConnectionClosed;
        }

        total_read += bytes_read;

        // S2: Postcondition - bytes read is bounded
        assert(total_read <= header_buf.len);
    }

    // S3: Bounded loop exhausted - should not happen with correct limits
    // If we hit this, headers are too large or malformed
    return error.ResponseHeadersTooLarge;
}

// =============================================================================
// Response Parsing Functions
// =============================================================================

/// Read and parse HTTP response headers from socket.
///
/// Reads data into header_buf until finding \r\n\r\n (end of headers).
/// Parses status line and headers, returning parsed ResponseHeaders.
///
/// TigerStyle:
/// - S1: Precondition assertions on parameters
/// - Delegates to readHeaderBytes for bounded I/O loop
/// - S4: Explicit error handling for all socket operations
///
/// Returns: ResponseHeaders with parsed data
/// Errors: ResponseError on parsing or I/O failure
pub fn readResponseHeaders(
    socket: *Socket,
    header_buf: []u8,
) ResponseError!ResponseHeaders {
    // S1: Preconditions
    assert(header_buf.len > 0);
    assert(header_buf.len <= config.MAX_HEADER_SIZE_BYTES);

    // Read header bytes from socket
    const result = try readHeaderBytes(socket, header_buf);

    // S2: Postcondition - header_end is within total_bytes
    assert(result.header_end <= result.total_bytes);

    // Parse the headers
    // TigerStyle S2: Cast to u32 - bounded by MAX_HEADER_SIZE_BYTES (8192).
    return parseResponseHeaders(
        header_buf[0..result.total_bytes],
        @intCast(result.header_end),
        @intCast(result.total_bytes),
    );
}

/// Parse already-buffered response headers.
///
/// Used when headers have already been read into a buffer.
/// Parses status line, headers, and determines body framing.
///
/// TigerStyle:
/// - S1: Precondition assertions
/// - S2: Postcondition assertions on parsed values
/// - S2: Use u32 for bounded header_bytes (max is MAX_HEADER_SIZE_BYTES = 8192)
fn parseResponseHeaders(
    buffer: []const u8,
    header_bytes: u32,
    total_bytes_read: u32,
) ResponseError!ResponseHeaders {
    // S1: Preconditions
    assert(buffer.len >= header_bytes);
    assert(header_bytes >= 4); // At minimum "\r\n\r\n"
    assert(total_bytes_read >= header_bytes); // Total must include headers

    // Parse status line
    const status = parseStatusLine(buffer) orelse {
        return error.InvalidResponseStatus;
    };

    // S2: Status code is in valid range (enforced by parseStatusLine)
    assert(status >= 100 and status <= 599);

    // Parse headers
    var headers = HeaderMap.init();
    parseHeaderLines(buffer[0..header_bytes], &headers) catch {
        return error.InvalidResponseHeaders;
    };

    // Determine body framing
    const body_framing = determineBodyFraming(&headers, status);

    return ResponseHeaders{
        .status = status,
        .headers = headers,
        .body_framing = body_framing,
        .header_bytes = header_bytes,
        .total_bytes_read = total_bytes_read,
    };
}

/// Parse HTTP status line to extract status code.
///
/// Expects format: "HTTP/1.x NNN Reason\r\n"
/// Returns null for invalid format or out-of-range status (not 100-599).
///
/// TigerStyle: Delegates to serval-http parseStatusCode.
fn parseStatusLine(header: []const u8) ?u16 {
    // Handle empty input gracefully
    if (header.len == 0) return null;

    return parseStatusCode(header);
}

/// Parse response header lines into HeaderMap.
///
/// Parses headers from buffer, skipping the status line.
/// Headers are separated by \r\n.
///
/// TigerStyle:
/// - S3: Bounded loop limited by MAX_HEADERS
/// - S4: Validates header format
fn parseHeaderLines(buffer: []const u8, headers: *HeaderMap) !void {
    assert(headers.count == 0);
    assert(buffer.len > 0);

    // Find end of status line
    const first_crlf = std.mem.indexOf(u8, buffer, "\r\n") orelse {
        return error.InvalidResponseHeaders;
    };

    // Find headers end
    const headers_end = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse {
        return error.InvalidResponseHeaders;
    };

    // If no headers after status line
    if (first_crlf + 2 >= headers_end) {
        return; // No headers to parse
    }

    const header_section = buffer[first_crlf + 2 .. headers_end];
    var lines = std.mem.splitSequence(u8, header_section, "\r\n");

    // S3: Bounded loop
    var line_count: u8 = 0;
    const max_lines: u8 = config.MAX_HEADERS + 1;

    while (lines.next()) |line| : (line_count += 1) {
        if (line_count >= max_lines) {
            return error.TooManyHeaders;
        }
        if (line.len == 0) continue;

        // RFC 7230: obs-fold is deprecated, reject
        if (line[0] == 0x20 or line[0] == 0x09) {
            return error.InvalidResponseHeaders;
        }

        const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse {
            return error.InvalidResponseHeaders;
        };

        if (colon_pos == 0) {
            return error.InvalidResponseHeaders;
        }

        const name = line[0..colon_pos];
        const value_start = colon_pos + 1;
        const value = if (value_start < line.len)
            std.mem.trim(u8, line[value_start..], " \t")
        else
            "";

        headers.put(name, value) catch |err| switch (err) {
            error.TooManyHeaders => return error.TooManyHeaders,
            error.DuplicateContentLength => return error.InvalidResponseHeaders,
        };
    }

    assert(headers.count <= config.MAX_HEADERS);
}

/// Determine body framing from headers and status code.
///
/// RFC 9112 Section 6:
/// - 1xx, 204, 304 responses have no body
/// - Transfer-Encoding: chunked means chunked body
/// - Content-Length means fixed-length body
/// - Otherwise, body is read until connection close (for responses)
///
/// TigerStyle: Explicit switch, no implicit behavior.
fn determineBodyFraming(headers: *const HeaderMap, status: u16) BodyFraming {
    assert(status >= 100 and status <= 599);

    // RFC 9112 Section 6.3: 1xx, 204, 304 MUST NOT have a body
    if (status >= 100 and status < 200) return .none;
    if (status == 204 or status == 304) return .none;

    // Check Transfer-Encoding first (takes precedence over Content-Length)
    if (headers.getTransferEncoding()) |te| {
        if (containsIgnoreCase(te, "chunked")) {
            return .chunked;
        }
    }

    // Check Content-Length
    if (headers.getContentLength()) |cl_str| {
        if (parseContentLengthValue(cl_str)) |content_length| {
            return .{ .content_length = content_length };
        }
    }

    // No framing info - for responses, body continues until close
    // We return .none here; caller must handle read-until-close if needed
    return .none;
}

/// Find the position of \r\n\r\n in buffer.
///
/// Returns the index of the first \r in \r\n\r\n, or null if not found.
/// TigerStyle: Explicit bounds checking.
fn findHeaderEnd(buffer: []const u8) ?usize {
    if (buffer.len < 4) return null;

    // Search for \r\n\r\n
    return std.mem.indexOf(u8, buffer, "\r\n\r\n");
}

/// Map SocketError to ResponseError.
/// TigerStyle S6: Explicit error handling, no catch {}.
fn mapSocketError(err: SocketError) ResponseError {
    return switch (err) {
        SocketError.ConnectionReset => ResponseError.ConnectionClosed,
        SocketError.ConnectionClosed => ResponseError.ConnectionClosed,
        SocketError.BrokenPipe => ResponseError.ConnectionClosed,
        SocketError.Timeout => ResponseError.RecvTimeout,
        SocketError.TLSError => ResponseError.RecvFailed,
        SocketError.Unexpected => ResponseError.RecvFailed,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "parseStatusLine valid status codes" {
    try std.testing.expectEqual(@as(?u16, 200), parseStatusLine("HTTP/1.1 200 OK\r\n"));
    try std.testing.expectEqual(@as(?u16, 404), parseStatusLine("HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expectEqual(@as(?u16, 500), parseStatusLine("HTTP/1.1 500 Internal Server Error\r\n"));
    try std.testing.expectEqual(@as(?u16, 100), parseStatusLine("HTTP/1.1 100 Continue\r\n"));
    try std.testing.expectEqual(@as(?u16, 301), parseStatusLine("HTTP/1.1 301 Moved Permanently\r\n"));
    try std.testing.expectEqual(@as(?u16, 204), parseStatusLine("HTTP/1.1 204 No Content\r\n"));
}

test "parseStatusLine HTTP/1.0" {
    try std.testing.expectEqual(@as(?u16, 200), parseStatusLine("HTTP/1.0 200 OK\r\n"));
    try std.testing.expectEqual(@as(?u16, 304), parseStatusLine("HTTP/1.0 304 Not Modified\r\n"));
}

test "parseStatusLine invalid" {
    try std.testing.expectEqual(@as(?u16, null), parseStatusLine(""));
    try std.testing.expectEqual(@as(?u16, null), parseStatusLine("HTTP/1.1"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusLine("HTTP/1.1 ABC\r\n"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusLine("HTTP/1.1 99 Too Low\r\n"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusLine("HTTP/1.1 600 Too High\r\n"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusLine("INVALID"));
}

test "findHeaderEnd finds terminator" {
    // findHeaderEnd returns position of first \r in \r\n\r\n
    try std.testing.expectEqual(@as(?usize, 0), findHeaderEnd("\r\n\r\n"));
    try std.testing.expectEqual(@as(?usize, 9), findHeaderEnd("HTTP/1.1 \r\n\r\n")); // "HTTP/1.1 " = 9 chars
    try std.testing.expectEqual(@as(?usize, 15), findHeaderEnd("HTTP/1.1 200 OK\r\n\r\n")); // "HTTP/1.1 200 OK" = 15 chars
    try std.testing.expectEqual(@as(?usize, 34), findHeaderEnd("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); // 34 chars before final \r\n\r\n
}

test "findHeaderEnd returns null when not found" {
    try std.testing.expect(findHeaderEnd("") == null);
    try std.testing.expect(findHeaderEnd("HTTP") == null);
    try std.testing.expect(findHeaderEnd("HTTP/1.1 200 OK\r\n") == null);
    try std.testing.expect(findHeaderEnd("\r\n") == null);
    try std.testing.expect(findHeaderEnd("\r\n\r") == null);
}

test "determineBodyFraming 1xx has no body" {
    var headers = HeaderMap.init();
    try std.testing.expect(determineBodyFraming(&headers, 100) == .none);
    try std.testing.expect(determineBodyFraming(&headers, 101) == .none);
    try std.testing.expect(determineBodyFraming(&headers, 199) == .none);
}

test "determineBodyFraming 204 and 304 have no body" {
    var headers = HeaderMap.init();
    try std.testing.expect(determineBodyFraming(&headers, 204) == .none);
    try std.testing.expect(determineBodyFraming(&headers, 304) == .none);
}

test "determineBodyFraming with Content-Length" {
    var headers = HeaderMap.init();
    try headers.put("Content-Length", "1234");

    const framing = determineBodyFraming(&headers, 200);
    try std.testing.expect(framing == .content_length);
    try std.testing.expectEqual(@as(u64, 1234), framing.getContentLength().?);
}

test "determineBodyFraming with chunked Transfer-Encoding" {
    var headers = HeaderMap.init();
    try headers.put("Transfer-Encoding", "chunked");

    const framing = determineBodyFraming(&headers, 200);
    try std.testing.expect(framing == .chunked);
}

test "determineBodyFraming chunked takes precedence over Content-Length" {
    var headers = HeaderMap.init();
    // Note: Both headers shouldn't occur per RFC, but if they do, TE takes precedence
    try headers.put("Content-Length", "1234");
    try headers.put("Transfer-Encoding", "chunked");

    const framing = determineBodyFraming(&headers, 200);
    try std.testing.expect(framing == .chunked);
}

test "determineBodyFraming zero Content-Length" {
    var headers = HeaderMap.init();
    try headers.put("Content-Length", "0");

    const framing = determineBodyFraming(&headers, 200);
    try std.testing.expect(framing == .content_length);
    try std.testing.expectEqual(@as(u64, 0), framing.getContentLength().?);
}

test "determineBodyFraming no framing info returns none" {
    var headers = HeaderMap.init();
    try headers.put("Content-Type", "text/plain");

    const framing = determineBodyFraming(&headers, 200);
    try std.testing.expect(framing == .none);
}

test "parseResponseHeaders valid response" {
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 13\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n";

    const header_len: u32 = @intCast(response.len);
    const result = try parseResponseHeaders(response, header_len, header_len);

    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expectEqual(@as(u32, response.len), result.header_bytes);
    try std.testing.expect(result.body_framing == .content_length);
    try std.testing.expectEqual(@as(u64, 13), result.body_framing.getContentLength().?);
    try std.testing.expectEqualStrings("13", result.headers.getContentLength().?);
    try std.testing.expectEqualStrings("text/plain", result.headers.get("Content-Type").?);
}

test "parseResponseHeaders chunked response" {
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";

    const header_len: u32 = @intCast(response.len);
    const result = try parseResponseHeaders(response, header_len, header_len);

    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expect(result.body_framing == .chunked);
    try std.testing.expectEqualStrings("chunked", result.headers.getTransferEncoding().?);
}

test "parseResponseHeaders 204 No Content" {
    const response =
        "HTTP/1.1 204 No Content\r\n" ++
        "\r\n";

    const header_len: u32 = @intCast(response.len);
    const result = try parseResponseHeaders(response, header_len, header_len);

    try std.testing.expectEqual(@as(u16, 204), result.status);
    try std.testing.expect(result.body_framing == .none);
}

test "parseResponseHeaders 304 Not Modified" {
    const response =
        "HTTP/1.1 304 Not Modified\r\n" ++
        "ETag: \"abc123\"\r\n" ++
        "\r\n";

    const header_len: u32 = @intCast(response.len);
    const result = try parseResponseHeaders(response, header_len, header_len);

    try std.testing.expectEqual(@as(u16, 304), result.status);
    try std.testing.expect(result.body_framing == .none);
    try std.testing.expectEqualStrings("\"abc123\"", result.headers.get("ETag").?);
}

test "parseResponseHeaders invalid status - too short" {
    // parseStatusCode requires at least 12 characters ("HTTP/1.1 200")
    const response = "X\r\n\r\n";

    const header_len: u32 = @intCast(response.len);
    try std.testing.expectError(error.InvalidResponseStatus, parseResponseHeaders(response, header_len, header_len));
}

test "parseResponseHeaders invalid status - non-numeric code" {
    const response = "HTTP/1.1 ABC OK\r\n\r\n";

    const header_len: u32 = @intCast(response.len);
    try std.testing.expectError(error.InvalidResponseStatus, parseResponseHeaders(response, header_len, header_len));
}

test "parseResponseHeaders invalid status - out of range" {
    const response = "HTTP/1.1 999 Invalid\r\n\r\n";

    // Status 999 is out of valid range (100-599)
    const header_len: u32 = @intCast(response.len);
    try std.testing.expectError(error.InvalidResponseStatus, parseResponseHeaders(response, header_len, header_len));
}

test "parseResponseHeaders no headers" {
    const response = "HTTP/1.1 200 OK\r\n\r\n";

    const header_len: u32 = @intCast(response.len);
    const result = try parseResponseHeaders(response, header_len, header_len);

    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expectEqual(@as(u8, 0), result.headers.count);
    try std.testing.expect(result.body_framing == .none);
}

test "parseResponseHeaders multiple headers" {
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 42\r\n" ++
        "Cache-Control: no-cache\r\n" ++
        "X-Request-Id: abc123\r\n" ++
        "\r\n";

    const header_len: u32 = @intCast(response.len);
    const result = try parseResponseHeaders(response, header_len, header_len);

    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expectEqual(@as(u8, 4), result.headers.count);
    try std.testing.expectEqualStrings("application/json", result.headers.get("Content-Type").?);
    try std.testing.expectEqualStrings("42", result.headers.getContentLength().?);
    try std.testing.expectEqualStrings("no-cache", result.headers.get("Cache-Control").?);
    try std.testing.expectEqualStrings("abc123", result.headers.get("X-Request-Id").?);
}

test "mapSocketError maps all errors" {
    try std.testing.expectEqual(ResponseError.ConnectionClosed, mapSocketError(SocketError.ConnectionReset));
    try std.testing.expectEqual(ResponseError.ConnectionClosed, mapSocketError(SocketError.ConnectionClosed));
    try std.testing.expectEqual(ResponseError.ConnectionClosed, mapSocketError(SocketError.BrokenPipe));
    try std.testing.expectEqual(ResponseError.RecvTimeout, mapSocketError(SocketError.Timeout));
    try std.testing.expectEqual(ResponseError.RecvFailed, mapSocketError(SocketError.TLSError));
    try std.testing.expectEqual(ResponseError.RecvFailed, mapSocketError(SocketError.Unexpected));
}

test "ResponseHeaders struct layout" {
    // Verify the struct has expected fields and defaults
    const headers = ResponseHeaders{
        .status = 200,
        .headers = HeaderMap.init(),
        .body_framing = .none,
        .header_bytes = 0,
        .total_bytes_read = 0,
    };

    try std.testing.expectEqual(@as(u16, 200), headers.status);
    try std.testing.expect(headers.body_framing == .none);
    try std.testing.expectEqual(@as(u32, 0), headers.header_bytes);
    try std.testing.expectEqual(@as(u32, 0), headers.total_bytes_read);
    try std.testing.expectEqual(@as(u8, 0), headers.headers.count);
}

test "ResponseError error set complete" {
    // Verify all errors can be created and compared
    const errors_list = [_]ResponseError{
        error.RecvFailed,
        error.RecvTimeout,
        error.ResponseHeadersTooLarge,
        error.InvalidResponseStatus,
        error.InvalidResponseHeaders,
        error.ConnectionClosed,
    };

    for (errors_list) |err| {
        // Each error should be distinct
        const is_recv_failed = (err == error.RecvFailed);
        const is_timeout = (err == error.RecvTimeout);
        const is_too_large = (err == error.ResponseHeadersTooLarge);
        const is_invalid_status = (err == error.InvalidResponseStatus);
        const is_invalid_headers = (err == error.InvalidResponseHeaders);
        const is_closed = (err == error.ConnectionClosed);

        // Exactly one should be true
        var count: u8 = 0;
        if (is_recv_failed) count += 1;
        if (is_timeout) count += 1;
        if (is_too_large) count += 1;
        if (is_invalid_status) count += 1;
        if (is_invalid_headers) count += 1;
        if (is_closed) count += 1;
        try std.testing.expectEqual(@as(u8, 1), count);
    }
}
