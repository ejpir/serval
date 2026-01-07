// lib/serval-proxy/h1/request.zig
//! HTTP/1.1 Request Serialization
//!
//! Builds and sends HTTP/1.1 requests to upstream servers.
//! TigerStyle: Bounded iteration, RFC 7230 hop-by-hop filtering.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const config = serval_core.config;
const types = serval_core.types;

const proxy_types = @import("../types.zig");
const ForwardError = proxy_types.ForwardError;

const Request = types.Request;
const Method = types.Method;

const pool_mod = @import("serval-pool").pool;
const Connection = pool_mod.Connection;

// =============================================================================
// RFC 7230 Hop-by-Hop Header Filtering
// =============================================================================

/// RFC 7230 Section 6.1: Hop-by-hop headers MUST NOT be forwarded to upstream.
/// These headers are meaningful only for a single transport-level connection.
pub const HOP_BY_HOP_HEADERS = [_][]const u8{
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
};

/// Check if a header is a hop-by-hop header per RFC 7230 Section 6.1.
/// TigerStyle: Bounded iteration over fixed-size array.
pub fn isHopByHopHeader(name: []const u8) bool {
    assert(name.len > 0);

    // Check against standard hop-by-hop headers
    for (HOP_BY_HOP_HEADERS) |hop_header| {
        if (eqlIgnoreCase(name, hop_header)) return true;
    }
    return false;
}

/// Case-insensitive string comparison for header names.
/// TigerStyle: Bounded loop over string length.
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        const lower_a = if (ac >= 'A' and ac <= 'Z') ac + 32 else ac;
        const lower_b = if (bc >= 'A' and bc <= 'Z') bc + 32 else bc;
        if (lower_a != lower_b) return false;
    }
    return true;
}

// =============================================================================
// Request Building
// =============================================================================

/// Via header value per RFC 7230 Section 5.7.1.
/// Format: protocol-version pseudonym (e.g., "1.1 serval").
pub const VIA_HEADER = "Via: 1.1 serval\r\n";

/// Convert Method enum to string representation.
pub fn methodToString(method: Method) []const u8 {
    return switch (method) {
        .GET => "GET",
        .HEAD => "HEAD",
        .POST => "POST",
        .PUT => "PUT",
        .DELETE => "DELETE",
        .CONNECT => "CONNECT",
        .OPTIONS => "OPTIONS",
        .TRACE => "TRACE",
        .PATCH => "PATCH",
    };
}

/// Build HTTP/1.1 request into buffer. Returns length or null if buffer too small.
/// RFC 7230: Filters hop-by-hop headers and adds Via header.
/// TigerStyle: Bounded iteration, ~2 assertions.
pub fn buildRequestBuffer(buffer: []u8, request: *const Request) ?usize {
    assert(request.path.len > 0);

    var pos: usize = 0;

    // Request line: "METHOD /path HTTP/1.1\r\n"
    const method_str = methodToString(request.method);
    const version_str = " HTTP/1.1\r\n";
    const line_len = method_str.len + 1 + request.path.len + version_str.len;
    if (pos + line_len > buffer.len) return null;

    @memcpy(buffer[pos..][0..method_str.len], method_str);
    pos += method_str.len;
    buffer[pos] = ' ';
    pos += 1;
    @memcpy(buffer[pos..][0..request.path.len], request.path);
    pos += request.path.len;
    @memcpy(buffer[pos..][0..version_str.len], version_str);
    pos += version_str.len;

    // Headers - filter hop-by-hop headers per RFC 7230 Section 6.1
    const max_headers: usize = config.MAX_HEADERS;
    for (request.headers.headers[0..@min(request.headers.count, max_headers)]) |header| {
        // RFC 7230 Section 6.1: Do not forward hop-by-hop headers
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

    // RFC 7230 Section 5.7.1: Add Via header to indicate proxy hop
    if (pos + VIA_HEADER.len > buffer.len) return null;
    @memcpy(buffer[pos..][0..VIA_HEADER.len], VIA_HEADER);
    pos += VIA_HEADER.len;

    // TODO: Add X-Forwarded-For header with client IP once client address
    // is passed to the forwarder. Currently not available in Request type.

    // End of headers
    if (pos + 2 > buffer.len) return null;
    @memcpy(buffer[pos..][0..2], "\r\n");
    pos += 2;

    assert(pos <= buffer.len);
    return pos;
}

// =============================================================================
// Request Sending
// =============================================================================

/// Send buffer to connection (TLS or plaintext).
/// TigerStyle: Explicit io parameter for async I/O.
pub fn sendBuffer(conn: *Connection, io: Io, data: []const u8) ForwardError!void {
    assert(data.len > 0);

    // Use TLS write if connection is encrypted
    if (conn.tls) |*tls_stream| {
        // TLS write - blocking operation (socket is async via std.Io)
        var remaining = data;
        var iteration: u32 = 0;
        const max_iterations: u32 = 10000; // S4: explicit bound

        while (remaining.len > 0 and iteration < max_iterations) {
            iteration += 1;
            const written = tls_stream.write(remaining) catch return ForwardError.SendFailed;
            assert(written > 0);
            assert(written <= remaining.len);
            remaining = remaining[written..];
        }

        if (iteration >= max_iterations) {
            return ForwardError.SendFailed; // TLS write exceeded max iterations
        }
    } else {
        // Plain TCP write
        var write_buf: [config.STREAM_WRITE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([config.STREAM_WRITE_BUFFER_SIZE_BYTES]u8);
        var writer = conn.stream.writer(io, &write_buf);
        writer.interface.writeAll(data) catch return ForwardError.SendFailed;
        writer.interface.flush() catch return ForwardError.SendFailed;
    }
}

/// Send request body to connection (TLS or plaintext).
/// TigerStyle: Explicit io parameter for async I/O.
fn sendBody(conn: *Connection, io: Io, body: []const u8) ForwardError!void {
    assert(body.len > 0);
    try sendBuffer(conn, io, body);
}

/// Send complete HTTP request (headers + body) to connection.
/// TigerStyle: Explicit io parameter for async I/O.
pub fn sendRequest(conn: *Connection, io: Io, request: *const Request) ForwardError!void {
    assert(request.path.len > 0);

    var buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([config.MAX_HEADER_SIZE_BYTES]u8);
    const header_len = buildRequestBuffer(&buffer, request) orelse return ForwardError.SendFailed;

    try sendBuffer(conn, io, buffer[0..header_len]);

    if (request.body) |body| {
        try sendBody(conn, io, body);
    }
}

// =============================================================================
// Tests
// =============================================================================

test "methodToString - all HTTP methods" {
    // TigerStyle: Verify all enum variants are handled correctly.
    try std.testing.expectEqualStrings("GET", methodToString(.GET));
    try std.testing.expectEqualStrings("HEAD", methodToString(.HEAD));
    try std.testing.expectEqualStrings("POST", methodToString(.POST));
    try std.testing.expectEqualStrings("PUT", methodToString(.PUT));
    try std.testing.expectEqualStrings("DELETE", methodToString(.DELETE));
    try std.testing.expectEqualStrings("CONNECT", methodToString(.CONNECT));
    try std.testing.expectEqualStrings("OPTIONS", methodToString(.OPTIONS));
    try std.testing.expectEqualStrings("TRACE", methodToString(.TRACE));
    try std.testing.expectEqualStrings("PATCH", methodToString(.PATCH));
}

test "eqlIgnoreCase - basic comparisons" {
    // Exact match
    try std.testing.expect(eqlIgnoreCase("Connection", "Connection"));

    // Case insensitive
    try std.testing.expect(eqlIgnoreCase("CONNECTION", "connection"));
    try std.testing.expect(eqlIgnoreCase("connection", "CONNECTION"));
    try std.testing.expect(eqlIgnoreCase("CoNnEcTiOn", "cOnNeCtIoN"));

    // Different strings
    try std.testing.expect(!eqlIgnoreCase("Host", "Connection"));
    try std.testing.expect(!eqlIgnoreCase("Hosts", "Host"));

    // Different lengths
    try std.testing.expect(!eqlIgnoreCase("Host", "Hos"));
    try std.testing.expect(!eqlIgnoreCase("Ho", "Host"));
}

test "isHopByHopHeader - RFC 7230 hop-by-hop headers" {
    // All RFC 7230 hop-by-hop headers should be detected
    try std.testing.expect(isHopByHopHeader("connection"));
    try std.testing.expect(isHopByHopHeader("Connection"));
    try std.testing.expect(isHopByHopHeader("CONNECTION"));

    try std.testing.expect(isHopByHopHeader("keep-alive"));
    try std.testing.expect(isHopByHopHeader("Keep-Alive"));

    try std.testing.expect(isHopByHopHeader("proxy-authenticate"));
    try std.testing.expect(isHopByHopHeader("Proxy-Authenticate"));

    try std.testing.expect(isHopByHopHeader("proxy-authorization"));
    try std.testing.expect(isHopByHopHeader("Proxy-Authorization"));

    try std.testing.expect(isHopByHopHeader("te"));
    try std.testing.expect(isHopByHopHeader("TE"));

    try std.testing.expect(isHopByHopHeader("trailer"));
    try std.testing.expect(isHopByHopHeader("Trailer"));

    try std.testing.expect(isHopByHopHeader("transfer-encoding"));
    try std.testing.expect(isHopByHopHeader("Transfer-Encoding"));

    try std.testing.expect(isHopByHopHeader("upgrade"));
    try std.testing.expect(isHopByHopHeader("Upgrade"));

    // Non-hop-by-hop headers should not be detected
    try std.testing.expect(!isHopByHopHeader("Host"));
    try std.testing.expect(!isHopByHopHeader("Content-Type"));
    try std.testing.expect(!isHopByHopHeader("Content-Length"));
    try std.testing.expect(!isHopByHopHeader("X-Custom-Header"));
    try std.testing.expect(!isHopByHopHeader("Accept"));
    try std.testing.expect(!isHopByHopHeader("User-Agent"));
}

test "buildRequestBuffer - simple GET request" {
    var buffer: [1024]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/api/users",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");

    const len = buildRequestBuffer(&buffer, &request).?;

    const expected =
        "GET /api/users HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Via: 1.1 serval\r\n" ++
        "\r\n";

    try std.testing.expectEqualStrings(expected, buffer[0..len]);
    // TigerStyle: Postcondition - return value matches actual content
    try std.testing.expectEqual(expected.len, len);
}

test "buildRequestBuffer - POST request with Content-Length" {
    var buffer: [1024]u8 = undefined;

    var request = Request{
        .method = .POST,
        .path = "/api/submit",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");
    try request.headers.put("Content-Type", "application/json");
    try request.headers.put("Content-Length", "42");

    const len = buildRequestBuffer(&buffer, &request).?;

    const expected =
        "POST /api/submit HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 42\r\n" ++
        "Via: 1.1 serval\r\n" ++
        "\r\n";

    try std.testing.expectEqualStrings(expected, buffer[0..len]);
}

test "buildRequestBuffer - all HTTP methods" {
    var buffer: [1024]u8 = undefined;

    const methods = [_]Method{ .GET, .HEAD, .POST, .PUT, .DELETE, .CONNECT, .OPTIONS, .TRACE, .PATCH };

    for (methods) |method| {
        var request = Request{
            .method = method,
            .path = "/test",
            .version = .@"HTTP/1.1",
            .headers = .{},
        };
        try request.headers.put("Host", "test.com");

        const len = buildRequestBuffer(&buffer, &request);
        // TigerStyle: All methods must produce valid output
        try std.testing.expect(len != null);

        // Verify request line starts with correct method
        const method_str = methodToString(method);
        try std.testing.expect(std.mem.startsWith(u8, buffer[0..len.?], method_str));
    }
}

test "buildRequestBuffer - hop-by-hop headers filtered" {
    var buffer: [2048]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/test",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");
    try request.headers.put("Connection", "keep-alive"); // hop-by-hop - should be filtered
    try request.headers.put("Keep-Alive", "timeout=5"); // hop-by-hop - should be filtered
    try request.headers.put("Proxy-Authorization", "Basic xyz"); // hop-by-hop - should be filtered
    try request.headers.put("Transfer-Encoding", "chunked"); // hop-by-hop - should be filtered
    try request.headers.put("Upgrade", "websocket"); // hop-by-hop - should be filtered
    try request.headers.put("X-Custom", "value"); // end-to-end - should be preserved

    const len = buildRequestBuffer(&buffer, &request).?;
    const output = buffer[0..len];

    // Verify hop-by-hop headers are NOT in output
    try std.testing.expect(std.mem.indexOf(u8, output, "Connection:") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Keep-Alive:") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Proxy-Authorization:") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Transfer-Encoding:") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Upgrade:") == null);

    // Verify end-to-end headers ARE in output
    try std.testing.expect(std.mem.indexOf(u8, output, "Host: example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "X-Custom: value\r\n") != null);

    // Verify Via header is added
    try std.testing.expect(std.mem.indexOf(u8, output, "Via: 1.1 serval\r\n") != null);
}

test "buildRequestBuffer - request with no headers" {
    var buffer: [512]u8 = undefined;

    const request = Request{
        .method = .GET,
        .path = "/",
        .version = .@"HTTP/1.1",
        .headers = .{}, // No headers
    };

    const len = buildRequestBuffer(&buffer, &request).?;

    // Should have request line + Via header + terminator
    const expected =
        "GET / HTTP/1.1\r\n" ++
        "Via: 1.1 serval\r\n" ++
        "\r\n";

    try std.testing.expectEqualStrings(expected, buffer[0..len]);
}

test "buildRequestBuffer - path with query string" {
    var buffer: [1024]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/search?q=hello%20world&page=1&sort=desc",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "search.example.com");

    const len = buildRequestBuffer(&buffer, &request).?;

    // Verify path is preserved exactly
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "/search?q=hello%20world&page=1&sort=desc HTTP/1.1\r\n") != null);
}

test "buildRequestBuffer - path with special characters" {
    var buffer: [1024]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/api/v1/users/123?filter=%7B%22name%22%3A%22test%22%7D",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "api.example.com");

    const len = buildRequestBuffer(&buffer, &request).?;

    // Path with URL-encoded JSON should be preserved
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "/api/v1/users/123?filter=%7B%22name%22%3A%22test%22%7D") != null);
}

test "buildRequestBuffer - header with empty value" {
    var buffer: [1024]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/test",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");
    try request.headers.put("X-Empty", "");

    const len = buildRequestBuffer(&buffer, &request).?;

    // Empty header value should be preserved
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "X-Empty: \r\n") != null);
}

test "buildRequestBuffer - buffer too small returns null" {
    // Buffer too small for request line
    var tiny_buffer: [10]u8 = undefined;

    const request = Request{
        .method = .GET,
        .path = "/api/users",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };

    // TigerStyle: Explicit null on buffer overflow, not panic
    const result = buildRequestBuffer(&tiny_buffer, &request);
    try std.testing.expect(result == null);
}

test "buildRequestBuffer - buffer exactly fits" {
    // Calculate exact size needed
    const expected =
        "GET / HTTP/1.1\r\n" ++
        "Via: 1.1 serval\r\n" ++
        "\r\n";

    var buffer: [expected.len]u8 = undefined;

    const request = Request{
        .method = .GET,
        .path = "/",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };

    const len = buildRequestBuffer(&buffer, &request);

    // TigerStyle: Boundary condition - exact fit should succeed
    try std.testing.expect(len != null);
    try std.testing.expectEqual(expected.len, len.?);
    try std.testing.expectEqualStrings(expected, buffer[0..len.?]);
}

test "buildRequestBuffer - buffer one byte short returns null" {
    // Calculate exact size needed
    const expected =
        "GET / HTTP/1.1\r\n" ++
        "Via: 1.1 serval\r\n" ++
        "\r\n";

    // One byte short
    var buffer: [expected.len - 1]u8 = undefined;

    const request = Request{
        .method = .GET,
        .path = "/",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };

    const result = buildRequestBuffer(&buffer, &request);

    // TigerStyle: Boundary condition - one byte short should fail
    try std.testing.expect(result == null);
}

test "buildRequestBuffer - many headers" {
    var buffer: [4096]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/test",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };

    // Add many headers
    try request.headers.put("Host", "example.com");
    try request.headers.put("Accept", "application/json");
    try request.headers.put("Accept-Language", "en-US");
    try request.headers.put("Accept-Encoding", "gzip, deflate");
    try request.headers.put("Cache-Control", "no-cache");
    try request.headers.put("Content-Type", "application/json");
    try request.headers.put("User-Agent", "serval-test/1.0");
    try request.headers.put("X-Request-Id", "abc-123-def-456");
    try request.headers.put("Authorization", "Bearer token12345");
    try request.headers.put("X-Forwarded-For", "192.168.1.1");

    const len = buildRequestBuffer(&buffer, &request).?;

    // Verify all headers are present
    const output = buffer[0..len];
    try std.testing.expect(std.mem.indexOf(u8, output, "Host: example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Accept: application/json\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "User-Agent: serval-test/1.0\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Authorization: Bearer token12345\r\n") != null);

    // Verify proper termination
    try std.testing.expect(std.mem.endsWith(u8, output, "\r\n\r\n"));
}

test "buildRequestBuffer - long header value" {
    var buffer: [2048]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/test",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };

    const long_value = "x" ** 500; // 500 character value
    try request.headers.put("Host", "example.com");
    try request.headers.put("X-Long-Value", long_value);

    const len = buildRequestBuffer(&buffer, &request).?;

    // Verify long value is preserved
    const output = buffer[0..len];
    try std.testing.expect(std.mem.indexOf(u8, output, long_value) != null);
}

test "buildRequestBuffer - OPTIONS * request" {
    var buffer: [512]u8 = undefined;

    var request = Request{
        .method = .OPTIONS,
        .path = "*",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");

    const len = buildRequestBuffer(&buffer, &request).?;

    // OPTIONS * HTTP/1.1 is valid (asterisk-form)
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "OPTIONS * HTTP/1.1\r\n") != null);
}

test "buildRequestBuffer - CRLF termination" {
    var buffer: [1024]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/test",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");
    try request.headers.put("Accept", "text/html");

    const len = buildRequestBuffer(&buffer, &request).?;
    const output = buffer[0..len];

    // Each line ends with CRLF
    var line_count: u32 = 0;
    var i: usize = 0;
    while (i + 1 < output.len) : (i += 1) {
        if (output[i] == '\r' and output[i + 1] == '\n') {
            line_count += 1;
            i += 1; // Skip the \n
        }
    }

    // Request line + 2 headers + Via header + empty line terminator = 5 CRLFs
    try std.testing.expectEqual(@as(u32, 5), line_count);

    // Ends with double CRLF
    try std.testing.expect(std.mem.endsWith(u8, output, "\r\n\r\n"));
}

test "buildRequestBuffer - Via header always added" {
    var buffer: [1024]u8 = undefined;

    const methods = [_]Method{ .GET, .POST, .PUT, .DELETE, .PATCH };

    for (methods) |method| {
        var request = Request{
            .method = method,
            .path = "/test",
            .version = .@"HTTP/1.1",
            .headers = .{},
        };
        try request.headers.put("Host", "example.com");

        const len = buildRequestBuffer(&buffer, &request).?;

        // Via header should always be present
        try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "Via: 1.1 serval\r\n") != null);

        // Reset headers for next iteration
        request.headers.reset();
    }
}

test "buildRequestBuffer - preserves header order except hop-by-hop" {
    var buffer: [2048]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/test",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");
    try request.headers.put("Connection", "keep-alive"); // filtered
    try request.headers.put("Accept", "text/html");
    try request.headers.put("User-Agent", "test");
    try request.headers.put("Transfer-Encoding", "chunked"); // filtered

    const len = buildRequestBuffer(&buffer, &request).?;
    const output = buffer[0..len];

    // Find positions of preserved headers
    const host_pos = std.mem.indexOf(u8, output, "Host:").?;
    const accept_pos = std.mem.indexOf(u8, output, "Accept:").?;
    const user_agent_pos = std.mem.indexOf(u8, output, "User-Agent:").?;

    // Order should be preserved: Host < Accept < User-Agent
    try std.testing.expect(host_pos < accept_pos);
    try std.testing.expect(accept_pos < user_agent_pos);

    // Via header comes after all request headers
    const via_pos = std.mem.indexOf(u8, output, "Via:").?;
    try std.testing.expect(user_agent_pos < via_pos);
}

test "VIA_HEADER constant format" {
    // Verify Via header format per RFC 7230 Section 5.7.1
    try std.testing.expectEqualStrings("Via: 1.1 serval\r\n", VIA_HEADER);
}
