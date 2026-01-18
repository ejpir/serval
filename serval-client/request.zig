// serval-client/request.zig
//! HTTP/1.1 Client Request Serialization
//!
//! Builds and sends HTTP/1.1 requests from client to server.
//! TigerStyle: Bounded iteration, RFC 7230 hop-by-hop filtering.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const config = serval_core.config;
const types = serval_core.types;
const eqlIgnoreCase = serval_core.eqlIgnoreCase;

const Request = types.Request;
const Method = types.Method;

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;

// =============================================================================
// Error Types
// =============================================================================

/// Client request errors.
/// TigerStyle: Explicit error set, no catch {}.
pub const ClientError = error{
    SendFailed,
    SendTimeout,
    BufferTooSmall,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum iterations for bounded write loop.
/// TigerStyle S3: All loops must have explicit bounds.
pub const MAX_WRITE_ITERATIONS: u32 = 10_000;

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
    assert(name.len > 0); // S1: precondition - header name must not be empty

    // Check against standard hop-by-hop headers
    // TigerStyle: Loop bounded by compile-time array size
    for (HOP_BY_HOP_HEADERS) |hop_header| {
        if (eqlIgnoreCase(name, hop_header)) return true;
    }
    return false;
}

// =============================================================================
// Request Building
// =============================================================================

/// Via header value per RFC 7230 Section 5.7.1.
/// Format: protocol-version pseudonym (e.g., "1.1 serval").
pub const VIA_HEADER = "Via: 1.1 serval\r\n";

/// Convert Method enum to string representation.
/// TigerStyle: Exhaustive switch, no default case.
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
/// effective_path: If set, use this path instead of request.path (for path rewriting).
/// TigerStyle: Bounded iteration, ~2 assertions.
pub fn buildRequestBuffer(buffer: []u8, request: *const Request, effective_path: ?[]const u8) ?usize {
    // Use effective_path if provided (path rewriting), otherwise use request.path
    const path = effective_path orelse request.path;
    assert(path.len > 0); // S1: precondition - path must not be empty

    var pos: usize = 0;

    // Request line: "METHOD /path HTTP/1.1\r\n"
    const method_str = methodToString(request.method);
    const version_str = " HTTP/1.1\r\n";
    const line_len = method_str.len + 1 + path.len + version_str.len;
    if (pos + line_len > buffer.len) return null;

    @memcpy(buffer[pos..][0..method_str.len], method_str);
    pos += method_str.len;
    buffer[pos] = ' ';
    pos += 1;
    @memcpy(buffer[pos..][0..path.len], path);
    pos += path.len;
    @memcpy(buffer[pos..][0..version_str.len], version_str);
    pos += version_str.len;

    // Headers - filter hop-by-hop headers per RFC 7230 Section 6.1
    // TigerStyle: Bounded by compile-time MAX_HEADERS constant
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

    // End of headers
    if (pos + 2 > buffer.len) return null;
    @memcpy(buffer[pos..][0..2], "\r\n");
    pos += 2;

    assert(pos <= buffer.len); // S2: postcondition - never wrote past buffer
    return pos;
}

// =============================================================================
// Request Sending
// =============================================================================

/// Send buffer to socket using Socket abstraction.
/// Handles both TLS and plaintext transparently.
/// TigerStyle: Bounded write loop with MAX_WRITE_ITERATIONS.
/// This is the public version that can be called by other modules (e.g., serval-proxy).
pub fn sendBufferToSocket(socket: *Socket, data: []const u8) ClientError!void {
    assert(data.len > 0); // S1: precondition - data must not be empty

    var remaining = data;
    var iteration: u32 = 0;

    // TigerStyle S3: Bounded loop with explicit max iterations
    while (remaining.len > 0 and iteration < MAX_WRITE_ITERATIONS) {
        iteration += 1;
        const written = socket.write(remaining) catch return ClientError.SendFailed;
        if (written == 0) return ClientError.SendFailed;
        assert(written <= remaining.len); // S2: postcondition - wrote valid amount
        remaining = remaining[written..];
    }

    if (iteration >= MAX_WRITE_ITERATIONS) {
        return ClientError.SendTimeout; // Write exceeded max iterations
    }
}

/// Send complete HTTP request (headers + body) to socket.
/// effective_path: If set, use this path instead of request.path (for path rewriting).
/// TigerStyle: ~2 assertions per function.
pub fn sendRequest(socket: *Socket, request: *const Request, effective_path: ?[]const u8) ClientError!void {
    // Use effective_path if provided, otherwise use request.path
    const path = effective_path orelse request.path;
    assert(path.len > 0); // S1: precondition - path must not be empty

    var buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([config.MAX_HEADER_SIZE_BYTES]u8);
    const header_len = buildRequestBuffer(&buffer, request, effective_path) orelse return ClientError.BufferTooSmall;

    assert(header_len > 0); // S2: postcondition - built valid request
    try sendBufferToSocket(socket, buffer[0..header_len]);

    // Send body if present
    if (request.body) |body| {
        if (body.len > 0) {
            try sendBufferToSocket(socket, body);
        }
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

test "isHopByHopHeader - RFC 7230 hop-by-hop headers" {
    // All RFC 7230 hop-by-hop headers should be detected (lowercase)
    try std.testing.expect(isHopByHopHeader("connection"));
    try std.testing.expect(isHopByHopHeader("keep-alive"));
    try std.testing.expect(isHopByHopHeader("proxy-authenticate"));
    try std.testing.expect(isHopByHopHeader("proxy-authorization"));
    try std.testing.expect(isHopByHopHeader("te"));
    try std.testing.expect(isHopByHopHeader("trailer"));
    try std.testing.expect(isHopByHopHeader("transfer-encoding"));
    try std.testing.expect(isHopByHopHeader("upgrade"));
}

test "isHopByHopHeader - case insensitive detection" {
    try std.testing.expect(isHopByHopHeader("Connection"));
    try std.testing.expect(isHopByHopHeader("CONNECTION"));
    try std.testing.expect(isHopByHopHeader("Keep-Alive"));
    try std.testing.expect(isHopByHopHeader("KEEP-ALIVE"));
    try std.testing.expect(isHopByHopHeader("Proxy-Authenticate"));
    try std.testing.expect(isHopByHopHeader("Proxy-Authorization"));
    try std.testing.expect(isHopByHopHeader("TE"));
    try std.testing.expect(isHopByHopHeader("Trailer"));
    try std.testing.expect(isHopByHopHeader("Transfer-Encoding"));
    try std.testing.expect(isHopByHopHeader("Upgrade"));
}

test "isHopByHopHeader - end-to-end headers not detected" {
    try std.testing.expect(!isHopByHopHeader("Host"));
    try std.testing.expect(!isHopByHopHeader("Content-Type"));
    try std.testing.expect(!isHopByHopHeader("Content-Length"));
    try std.testing.expect(!isHopByHopHeader("X-Custom-Header"));
    try std.testing.expect(!isHopByHopHeader("Accept"));
    try std.testing.expect(!isHopByHopHeader("User-Agent"));
    try std.testing.expect(!isHopByHopHeader("Authorization"));
    try std.testing.expect(!isHopByHopHeader("Cache-Control"));
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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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

        const len = buildRequestBuffer(&buffer, &request, null);
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

    const len = buildRequestBuffer(&buffer, &request, null).?;
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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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
    const result = buildRequestBuffer(&tiny_buffer, &request, null);
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

    const len = buildRequestBuffer(&buffer, &request, null);

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

    const result = buildRequestBuffer(&buffer, &request, null);

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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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

    const len = buildRequestBuffer(&buffer, &request, null).?;

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

    const len = buildRequestBuffer(&buffer, &request, null).?;
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

        const len = buildRequestBuffer(&buffer, &request, null).?;

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

    const len = buildRequestBuffer(&buffer, &request, null).?;
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

test "buildRequestBuffer - effective_path overrides request.path" {
    var buffer: [1024]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/api/v1/users", // Original path
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");

    // Use effective_path to rewrite path (e.g., strip prefix)
    const len = buildRequestBuffer(&buffer, &request, "/users").?;

    const expected =
        "GET /users HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Via: 1.1 serval\r\n" ++
        "\r\n";

    try std.testing.expectEqualStrings(expected, buffer[0..len]);
    // TigerStyle: Postcondition - effective_path is used, not request.path
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "/api/v1/users") == null);
}

test "buildRequestBuffer - null effective_path uses request.path" {
    var buffer: [1024]u8 = undefined;

    var request = Request{
        .method = .GET,
        .path = "/original/path",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");

    // Pass null for effective_path - should use request.path
    const len = buildRequestBuffer(&buffer, &request, null).?;

    // Verify original path is used
    try std.testing.expect(std.mem.indexOf(u8, buffer[0..len], "GET /original/path HTTP/1.1\r\n") != null);
}

test "HOP_BY_HOP_HEADERS array completeness" {
    // Verify all RFC 7230 hop-by-hop headers are in the array
    try std.testing.expectEqual(@as(usize, 8), HOP_BY_HOP_HEADERS.len);

    // Check each header is present
    var found_connection = false;
    var found_keep_alive = false;
    var found_proxy_auth = false;
    var found_proxy_authz = false;
    var found_te = false;
    var found_trailer = false;
    var found_transfer_encoding = false;
    var found_upgrade = false;

    for (HOP_BY_HOP_HEADERS) |h| {
        if (std.mem.eql(u8, h, "connection")) found_connection = true;
        if (std.mem.eql(u8, h, "keep-alive")) found_keep_alive = true;
        if (std.mem.eql(u8, h, "proxy-authenticate")) found_proxy_auth = true;
        if (std.mem.eql(u8, h, "proxy-authorization")) found_proxy_authz = true;
        if (std.mem.eql(u8, h, "te")) found_te = true;
        if (std.mem.eql(u8, h, "trailer")) found_trailer = true;
        if (std.mem.eql(u8, h, "transfer-encoding")) found_transfer_encoding = true;
        if (std.mem.eql(u8, h, "upgrade")) found_upgrade = true;
    }

    try std.testing.expect(found_connection);
    try std.testing.expect(found_keep_alive);
    try std.testing.expect(found_proxy_auth);
    try std.testing.expect(found_proxy_authz);
    try std.testing.expect(found_te);
    try std.testing.expect(found_trailer);
    try std.testing.expect(found_transfer_encoding);
    try std.testing.expect(found_upgrade);
}

test "ClientError error set" {
    // Verify error set has expected variants
    const err1: ClientError = ClientError.SendFailed;
    const err2: ClientError = ClientError.SendTimeout;
    const err3: ClientError = ClientError.BufferTooSmall;

    // Type check - all errors are ClientError
    try std.testing.expect(@TypeOf(err1) == ClientError);
    try std.testing.expect(@TypeOf(err2) == ClientError);
    try std.testing.expect(@TypeOf(err3) == ClientError);

    // Errors are distinct
    try std.testing.expect(err1 != err2);
    try std.testing.expect(err2 != err3);
    try std.testing.expect(err1 != err3);
}

test "MAX_WRITE_ITERATIONS is reasonable" {
    // TigerStyle: Verify bounded iteration constant is sensible
    // 10,000 iterations at minimum 1 byte per write = 10KB minimum
    // This allows for pathological fragmentation while still bounding
    try std.testing.expect(MAX_WRITE_ITERATIONS >= 1000);
    try std.testing.expect(MAX_WRITE_ITERATIONS <= 100_000);
}
