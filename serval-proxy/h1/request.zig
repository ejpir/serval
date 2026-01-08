// lib/serval-proxy/h1/request.zig
//! HTTP/1.1 Request Serialization for Proxy
//!
//! Builds and sends HTTP/1.1 requests to upstream servers.
//! This module delegates to serval-client for request building and adds
//! proxy-specific adapters for Connection-based sending.
//!
//! TigerStyle: Reuses serval-client, thin adapter layer.

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

const net = @import("serval-net");
const Socket = net.Socket;

// Import serval-client request module for shared functionality
const client_request = @import("serval-client").request;

// =============================================================================
// Re-export from serval-client
// =============================================================================

/// RFC 7230 Section 6.1: Hop-by-hop headers MUST NOT be forwarded to upstream.
/// These headers are meaningful only for a single transport-level connection.
pub const HOP_BY_HOP_HEADERS = client_request.HOP_BY_HOP_HEADERS;

/// Check if a header is a hop-by-hop header per RFC 7230 Section 6.1.
/// TigerStyle: Bounded iteration over fixed-size array.
pub const isHopByHopHeader = client_request.isHopByHopHeader;

/// Case-insensitive string comparison for header names.
/// TigerStyle: Bounded loop over string length.
pub const eqlIgnoreCase = client_request.eqlIgnoreCase;

/// Via header value per RFC 7230 Section 5.7.1.
/// Format: protocol-version pseudonym (e.g., "1.1 serval").
pub const VIA_HEADER = client_request.VIA_HEADER;

/// Convert Method enum to string representation.
pub const methodToString = client_request.methodToString;

/// Build HTTP/1.1 request into buffer. Returns length or null if buffer too small.
/// RFC 7230: Filters hop-by-hop headers and adds Via header.
/// effective_path: If set, use this path instead of request.path (for path rewriting).
/// TigerStyle: Bounded iteration, ~2 assertions.
pub const buildRequestBuffer = client_request.buildRequestBuffer;

// =============================================================================
// Proxy-specific Request Sending (adapts Connection to Socket)
// =============================================================================

/// Send buffer to connection using Socket abstraction.
/// Handles both TLS and plaintext transparently.
/// TigerStyle: Explicit io parameter for async I/O (unused - Socket handles I/O).
pub fn sendBuffer(conn: *Connection, io: Io, data: []const u8) ForwardError!void {
    _ = io; // Unused - Socket handles I/O internally
    assert(data.len > 0); // S1: precondition - data must not be empty

    // Delegate to serval-client's sendBuffer, mapping errors
    client_request.sendBufferToSocket(&conn.socket, data) catch |err| {
        return switch (err) {
            client_request.ClientError.SendFailed => ForwardError.SendFailed,
            client_request.ClientError.SendTimeout => ForwardError.SendFailed,
            client_request.ClientError.BufferTooSmall => ForwardError.SendFailed,
        };
    };
}

/// Send request body to connection (TLS or plaintext).
/// TigerStyle: Explicit io parameter for async I/O.
fn sendBody(conn: *Connection, io: Io, body: []const u8) ForwardError!void {
    assert(body.len > 0); // S1: precondition - body must not be empty
    try sendBuffer(conn, io, body);
}

/// Send complete HTTP request (headers + body) to connection.
/// effective_path: If set, use this path instead of request.path (for path rewriting).
/// TigerStyle: Explicit io parameter for async I/O.
pub fn sendRequest(conn: *Connection, io: Io, request: *const Request, effective_path: ?[]const u8) ForwardError!void {
    // Use effective_path if provided, otherwise use request.path
    const path = effective_path orelse request.path;
    assert(path.len > 0); // S1: precondition - path must not be empty

    var buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([config.MAX_HEADER_SIZE_BYTES]u8);
    const header_len = buildRequestBuffer(&buffer, request, effective_path) orelse return ForwardError.SendFailed;

    assert(header_len > 0); // S2: postcondition - built valid request
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

test "VIA_HEADER constant format" {
    // Verify Via header format per RFC 7230 Section 5.7.1
    try std.testing.expectEqualStrings("Via: 1.1 serval\r\n", VIA_HEADER);
}
