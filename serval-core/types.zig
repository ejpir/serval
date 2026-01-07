// serval-core/types.zig
//! Serval Core Types
//!
//! HTTP/1.1 request/response types for the serval library.
//! All types are zero-copy where possible (slices into buffers).
//!
//! TigerStyle: Zero undefined buffers, explicit sizes

const std = @import("std");
const config = @import("config.zig");

// Re-export HeaderMap from dedicated module
const header_map = @import("header_map.zig");
pub const Header = header_map.Header;
pub const HeaderMap = header_map.HeaderMap;

// =============================================================================
// HTTP Method
// =============================================================================

pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
};

// =============================================================================
// HTTP Version
// =============================================================================

pub const Version = enum {
    @"HTTP/1.0",
    @"HTTP/1.1",
};

// =============================================================================
// Body Framing (RFC 9112 Section 6)
// =============================================================================

/// How the message body length is determined per RFC 9112 Section 6.
///
/// Why tagged union: HTTP/1.1 has three mutually exclusive body framing modes.
/// The parser must know which mode applies to correctly read the body:
/// - content_length: Read exactly N bytes (most common for responses with bodies)
/// - chunked: Read chunk-size + data pairs until 0-length chunk (streaming)
/// - none: No body present (GET/HEAD requests, 204/304 responses)
///
/// TigerStyle: Tagged union prevents invalid states (e.g., both chunked AND content-length).
pub const BodyFraming = union(enum) {
    /// Fixed body size from Content-Length header.
    /// Why u64: HTTP allows bodies up to 2^64-1 bytes per RFC 9110 Section 8.6.
    content_length: u64,

    /// Transfer-Encoding: chunked - body sent as size-prefixed chunks.
    /// Total size unknown until final zero-length chunk received.
    chunked,

    /// No body present. Applies to:
    /// - Requests: GET, HEAD, DELETE, CONNECT, OPTIONS, TRACE (typically)
    /// - Responses: 1xx, 204 No Content, 304 Not Modified
    none,

    /// Returns true only if body length is known upfront.
    /// Why: Determines if we can pre-allocate buffer or must stream.
    /// TigerStyle: Trivial single-expression predicate, assertion-exempt.
    pub fn hasKnownLength(self: BodyFraming) bool {
        return self == .content_length;
    }

    /// Returns the Content-Length value if present, null otherwise.
    /// Why: Caller may need the actual length for buffer allocation or
    /// Content-Length header forwarding.
    /// TigerStyle: Trivial tagged union accessor, assertion-exempt.
    pub fn getContentLength(self: BodyFraming) ?u64 {
        return switch (self) {
            .content_length => |len| len,
            .chunked, .none => null,
        };
    }
};

// =============================================================================
// Request (zero-copy, references buffer)
// =============================================================================

pub const Request = struct {
    method: Method = .GET,
    path: []const u8 = "",
    version: Version = .@"HTTP/1.1",
    headers: HeaderMap = .{},
    body: ?[]const u8 = null,
};

// =============================================================================
// Response
// =============================================================================

pub const Response = struct {
    status: u16 = 200,
    headers: HeaderMap = .{},
    body: ?[]const u8 = null,
};

// =============================================================================
// Upstream
// =============================================================================

pub const Upstream = struct {
    host: []const u8,
    port: u16,
    /// Index into connection pool to retrieve/release connections for this upstream.
    /// TigerStyle: Uses UpstreamIndex from config for single source of truth.
    idx: config.UpstreamIndex = 0,
    /// Enable TLS for connections to this upstream.
    /// TigerStyle: Explicit boolean, false means plaintext TCP.
    tls: bool = false,
};

// =============================================================================
// Action (control flow from hooks)
// =============================================================================

/// Handler response for onRequest hook.
/// TigerStyle: Tagged union with explicit variants.
pub const Action = union(enum) {
    /// Continue to selectUpstream and forward the request to upstream.
    continue_request,
    /// Send a direct response without forwarding.
    /// Handler writes response body into server-provided buffer.
    send_response: DirectResponse,
};

/// How the response body length is communicated to the client.
/// TigerStyle: Explicit mode selection, no implicit behavior.
///
/// Why explicit enum: HTTP/1.1 supports both Content-Length and chunked
/// Transfer-Encoding. Rather than inferring the mode from body availability
/// or size, handlers explicitly declare their intent. This prevents
/// accidental chunked responses when Content-Length was intended, and
/// vice versa. The default (content_length) is the most common case
/// and maintains backward compatibility with existing handlers.
pub const ResponseMode = enum {
    /// Use Content-Length header (default). Body length known upfront.
    /// Preferred when body size is known before sending.
    content_length,
    /// Use Transfer-Encoding: chunked. Body sent in chunks.
    /// Use when body is streamed or size unknown until generation completes.
    chunked,
};

/// Direct response data for handlers that respond without forwarding.
/// Body slice must point into the response_buf provided by the server.
/// TigerStyle: Fixed-size, no allocation, explicit ownership.
pub const DirectResponse = struct {
    status: u16 = 200,
    /// Response body - must be slice into server-provided response_buf.
    body: []const u8 = "",
    /// Content-Type header value.
    content_type: []const u8 = "text/plain",
    /// Additional headers as pre-formatted string (e.g., "X-Backend-Id: foo\r\n").
    /// Handler is responsible for correct HTTP header formatting.
    extra_headers: []const u8 = "",
    /// Response framing mode. Default: content_length.
    /// Why configurable: Some handlers generate response bodies dynamically
    /// and don't know the final size until streaming completes. Others
    /// know the exact size upfront. Explicit mode selection prevents
    /// mismatches between handler intent and wire format.
    response_mode: ResponseMode = .content_length,
};

// =============================================================================
// Connection Info (for logging hooks)
// =============================================================================

/// Client connection information for logging hooks.
/// TigerStyle: Fixed-size struct, no allocations.
pub const ConnectionInfo = struct {
    /// Unique connection identifier for correlation.
    connection_id: u64,
    /// IPv4 or IPv6 address string, null-terminated (max 45 chars + null).
    client_addr: [46]u8,
    /// Client source port.
    client_port: u16,
    /// Server port client connected to.
    local_port: u16,
    /// TCP round-trip time estimate in microseconds.
    tcp_rtt_us: u32,
    /// TCP RTT variance in microseconds.
    tcp_rtt_var_us: u32,
};

/// Upstream connection timing for logging.
/// TigerStyle: Explicit timing with u64 nanoseconds.
pub const UpstreamConnectInfo = struct {
    /// DNS resolution duration in nanoseconds.
    dns_duration_ns: u64,
    /// TCP connect duration in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// Whether this connection was reused from pool.
    reused: bool,
    /// Time spent waiting for pool connection in nanoseconds.
    pool_wait_ns: u64,
    /// Local port used for upstream connection.
    local_port: u16,
};

// =============================================================================
// BodyFraming Tests
// =============================================================================

test "BodyFraming content_length variant" {
    const framing: BodyFraming = .{ .content_length = 1024 };

    try std.testing.expect(framing.hasKnownLength());
    try std.testing.expectEqual(@as(u64, 1024), framing.getContentLength().?);
}

test "BodyFraming content_length zero is valid" {
    // Zero Content-Length is valid (empty body, not "no body")
    const framing: BodyFraming = .{ .content_length = 0 };

    try std.testing.expect(framing.hasKnownLength());
    try std.testing.expectEqual(@as(u64, 0), framing.getContentLength().?);
}

test "BodyFraming content_length max u64" {
    // HTTP allows bodies up to 2^64-1 bytes per RFC 9110
    const framing: BodyFraming = .{ .content_length = std.math.maxInt(u64) };

    try std.testing.expect(framing.hasKnownLength());
    try std.testing.expectEqual(std.math.maxInt(u64), framing.getContentLength().?);
}

test "BodyFraming chunked variant" {
    const framing: BodyFraming = .chunked;

    try std.testing.expect(!framing.hasKnownLength());
    try std.testing.expect(framing.getContentLength() == null);
}

test "BodyFraming none variant" {
    const framing: BodyFraming = .none;

    try std.testing.expect(!framing.hasKnownLength());
    try std.testing.expect(framing.getContentLength() == null);
}

test "BodyFraming switch coverage" {
    // Verify all variants can be matched in a switch
    const framings = [_]BodyFraming{
        .{ .content_length = 100 },
        .chunked,
        .none,
    };

    for (framings) |framing| {
        const desc: []const u8 = switch (framing) {
            .content_length => "fixed",
            .chunked => "chunked",
            .none => "none",
        };
        try std.testing.expect(desc.len > 0);
    }
}

// =============================================================================
// Action and DirectResponse Tests
// =============================================================================

test "DirectResponse has sensible defaults" {
    const resp = DirectResponse{};
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("", resp.body);
    try std.testing.expectEqualStrings("text/plain", resp.content_type);
    try std.testing.expectEqualStrings("", resp.extra_headers);
    // Default response_mode is content_length for backward compatibility
    try std.testing.expect(resp.response_mode == .content_length);
}

test "DirectResponse with custom values" {
    const body = "Hello, World!";
    const resp = DirectResponse{
        .status = 201,
        .body = body,
        .content_type = "application/json",
        .extra_headers = "X-Custom: value\r\n",
    };
    try std.testing.expectEqual(@as(u16, 201), resp.status);
    try std.testing.expectEqualStrings("Hello, World!", resp.body);
    try std.testing.expectEqualStrings("application/json", resp.content_type);
    try std.testing.expectEqualStrings("X-Custom: value\r\n", resp.extra_headers);
}

test "Action continue_request variant" {
    const action: Action = .continue_request;
    try std.testing.expect(action == .continue_request);
}

test "Action send_response variant" {
    const resp = DirectResponse{ .status = 404, .body = "Not Found" };
    const action: Action = .{ .send_response = resp };
    switch (action) {
        .continue_request => try std.testing.expect(false),
        .send_response => |r| {
            try std.testing.expectEqual(@as(u16, 404), r.status);
            try std.testing.expectEqualStrings("Not Found", r.body);
        },
    }
}

// =============================================================================
// ResponseMode Tests
// =============================================================================

test "ResponseMode enum values" {
    // Verify both enum variants exist and are distinct
    const content_length: ResponseMode = .content_length;
    const chunked: ResponseMode = .chunked;

    try std.testing.expect(content_length != chunked);
    try std.testing.expect(content_length == .content_length);
    try std.testing.expect(chunked == .chunked);
}

test "ResponseMode switch coverage" {
    // Verify all variants can be matched in a switch (compile-time completeness check)
    const modes = [_]ResponseMode{ .content_length, .chunked };

    for (modes) |mode| {
        const desc: []const u8 = switch (mode) {
            .content_length => "fixed-length",
            .chunked => "chunked",
        };
        try std.testing.expect(desc.len > 0);
    }
}

test "DirectResponse with chunked response_mode" {
    // Explicit chunked mode for streaming responses
    const resp = DirectResponse{
        .status = 200,
        .body = "chunk1chunk2",
        .content_type = "application/octet-stream",
        .response_mode = .chunked,
    };

    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("chunk1chunk2", resp.body);
    try std.testing.expect(resp.response_mode == .chunked);
}

test "DirectResponse with explicit content_length response_mode" {
    // Explicit content_length mode (same as default, but explicitly set)
    const resp = DirectResponse{
        .status = 201,
        .body = "Created",
        .response_mode = .content_length,
    };

    try std.testing.expectEqual(@as(u16, 201), resp.status);
    try std.testing.expectEqualStrings("Created", resp.body);
    try std.testing.expect(resp.response_mode == .content_length);
}

test "DirectResponse response_mode in Action" {
    // Verify response_mode is preserved through Action union
    const resp = DirectResponse{
        .status = 202,
        .body = "Accepted",
        .response_mode = .chunked,
    };
    const action: Action = .{ .send_response = resp };

    switch (action) {
        .continue_request => try std.testing.expect(false),
        .send_response => |r| {
            try std.testing.expect(r.response_mode == .chunked);
        },
    }
}
