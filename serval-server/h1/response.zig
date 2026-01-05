// lib/serval-server/h1/response.zig
//! HTTP/1.1 Response Writing Utilities
//!
//! Standalone functions for sending HTTP/1.1 responses to clients.
//! Extracted from http1.zig to enable code reuse and smaller file sizes.
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
