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

/// Handler response for request/response hooks.
/// TigerStyle: Tagged union with explicit variants, no implicit behavior.
pub const Action = union(enum) {
    /// Continue normal processing (forward request, send response, etc.).
    continue_request,
    /// Send a direct response without forwarding to upstream.
    /// Handler writes response body into server-provided buffer.
    send_response: DirectResponse,
    /// Reject the request with an error status (e.g., 400, 403, 429).
    /// Use for WAF blocking, rate limiting, auth failures.
    reject: RejectResponse,
    /// Stream a response incrementally using chunked Transfer-Encoding.
    /// Handler must implement nextChunk() method to generate content.
    /// Use for SSE, LLM responses, database cursors, large dynamic content.
    stream: StreamResponse,
};

/// Rejection response for handlers that block requests.
/// TigerStyle: Fixed-size, minimal fields for error responses.
pub const RejectResponse = struct {
    /// HTTP status code (typically 400-499 for client errors).
    status: u16 = 403,
    /// Short reason phrase for logging (not sent to client).
    reason: []const u8 = "Forbidden",
};

/// Handler response for body inspection hooks (onRequestBody, onResponseBody).
/// TigerStyle: Separate type for body hooks - simpler than full Action.
pub const BodyAction = union(enum) {
    /// Continue processing the body chunk.
    continue_body,
    /// Reject the request/response (e.g., WAF detected threat in body).
    reject: RejectResponse,
};

/// Handler response for onError hook.
/// TigerStyle: Allow handlers to customize error responses or request retry.
pub const ErrorAction = union(enum) {
    /// Use default error handling (send 502 Bad Gateway).
    default,
    /// Send a custom error response instead of default 502.
    send_response: DirectResponse,
    /// Retry the request with a different upstream (if available).
    /// Handler should have already selected a new upstream in selectUpstream.
    retry,
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

/// Streaming response for incrementally-generated content.
/// Used for SSE (Server-Sent Events), LLM responses, database cursors, etc.
/// Handler must implement nextChunk() to generate content incrementally.
/// Server will use Transfer-Encoding: chunked (RFC 9112 Section 7.1).
/// TigerStyle: Caller-owned buffer, bounded iterations, explicit termination.
pub const StreamResponse = struct {
    /// HTTP status code for the response.
    status: u16 = 200,
    /// Content-Type header value.
    /// Default: application/octet-stream (binary data).
    /// Use "text/event-stream" for SSE, "application/json" for JSON streaming.
    content_type: []const u8 = "application/octet-stream",
    /// Additional headers as pre-formatted string (e.g., "Cache-Control: no-cache\r\n").
    /// Handler is responsible for correct HTTP header formatting.
    /// NOTE: Do NOT include Transfer-Encoding or Content-Length headers -
    /// server manages these automatically for chunked streaming.
    extra_headers: []const u8 = "",
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

/// Upstream connection info for onUpstreamConnect hook.
/// TigerStyle: Explicit timing with u64 nanoseconds.
pub const UpstreamConnectInfo = struct {
    /// DNS resolution duration in nanoseconds.
    dns_duration_ns: u64,
    /// TCP connect duration in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// TLS handshake duration in nanoseconds (0 if plaintext).
    tls_handshake_duration_ns: u64 = 0,
    /// Whether this connection was reused from pool.
    reused: bool,
    /// Time spent waiting for pool connection in nanoseconds.
    pool_wait_ns: u64,
    /// Local port used for upstream connection.
    local_port: u16,
    /// TLS cipher suite name (empty if plaintext).
    tls_cipher: [64]u8 = std.mem.zeroes([64]u8),
    /// TLS protocol version (empty if plaintext).
    tls_version: [16]u8 = std.mem.zeroes([16]u8),
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
        .reject => try std.testing.expect(false),
        .stream => try std.testing.expect(false),
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
        .reject => try std.testing.expect(false),
        .stream => try std.testing.expect(false),
    }
}

// =============================================================================
// StreamResponse Tests
// =============================================================================

test "StreamResponse has sensible defaults" {
    const resp = StreamResponse{};
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("application/octet-stream", resp.content_type);
    try std.testing.expectEqualStrings("", resp.extra_headers);
}

test "StreamResponse with SSE content type" {
    // Server-Sent Events use text/event-stream content type
    const resp = StreamResponse{
        .status = 200,
        .content_type = "text/event-stream",
        .extra_headers = "Cache-Control: no-cache\r\n",
    };
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("text/event-stream", resp.content_type);
    try std.testing.expectEqualStrings("Cache-Control: no-cache\r\n", resp.extra_headers);
}

test "StreamResponse with JSON streaming content type" {
    // JSON streaming (e.g., LLM responses) uses application/json
    const resp = StreamResponse{
        .status = 200,
        .content_type = "application/json",
    };
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("application/json", resp.content_type);
}

test "StreamResponse with custom status" {
    // Streaming responses can have non-200 status codes
    const resp = StreamResponse{
        .status = 206, // Partial Content
        .content_type = "video/mp4",
    };
    try std.testing.expectEqual(@as(u16, 206), resp.status);
    try std.testing.expectEqualStrings("video/mp4", resp.content_type);
}

test "Action stream variant" {
    const stream_resp = StreamResponse{
        .status = 200,
        .content_type = "text/event-stream",
        .extra_headers = "X-Accel-Buffering: no\r\n",
    };
    const action: Action = .{ .stream = stream_resp };

    switch (action) {
        .continue_request => try std.testing.expect(false),
        .send_response => try std.testing.expect(false),
        .reject => try std.testing.expect(false),
        .stream => |s| {
            try std.testing.expectEqual(@as(u16, 200), s.status);
            try std.testing.expectEqualStrings("text/event-stream", s.content_type);
            try std.testing.expectEqualStrings("X-Accel-Buffering: no\r\n", s.extra_headers);
        },
    }
}

test "StreamResponse extra_headers with multiple headers" {
    // Multiple extra headers for SSE streaming
    const resp = StreamResponse{
        .status = 200,
        .content_type = "text/event-stream",
        .extra_headers = "Cache-Control: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n",
    };
    try std.testing.expectEqualStrings(
        "Cache-Control: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n",
        resp.extra_headers,
    );
}

// =============================================================================
// RejectResponse Tests
// =============================================================================

test "RejectResponse has sensible defaults" {
    const reject = RejectResponse{};
    try std.testing.expectEqual(@as(u16, 403), reject.status);
    try std.testing.expectEqualStrings("Forbidden", reject.reason);
}

test "RejectResponse with custom values" {
    const reject = RejectResponse{
        .status = 429,
        .reason = "Rate limit exceeded",
    };
    try std.testing.expectEqual(@as(u16, 429), reject.status);
    try std.testing.expectEqualStrings("Rate limit exceeded", reject.reason);
}

test "RejectResponse client error codes" {
    // Test common client error status codes (4xx range)
    const status_codes = [_]u16{ 400, 401, 403, 404, 429 };
    const reasons = [_][]const u8{
        "Bad Request",
        "Unauthorized",
        "Forbidden",
        "Not Found",
        "Too Many Requests",
    };

    for (status_codes, reasons) |code, reason| {
        const reject = RejectResponse{
            .status = code,
            .reason = reason,
        };
        try std.testing.expectEqual(code, reject.status);
        try std.testing.expectEqualStrings(reason, reject.reason);
    }
}

test "Action reject variant" {
    const reject = RejectResponse{ .status = 403, .reason = "WAF blocked" };
    const action: Action = .{ .reject = reject };

    switch (action) {
        .continue_request => try std.testing.expect(false),
        .send_response => try std.testing.expect(false),
        .reject => |r| {
            try std.testing.expectEqual(@as(u16, 403), r.status);
            try std.testing.expectEqualStrings("WAF blocked", r.reason);
        },
        .stream => try std.testing.expect(false),
    }
}

test "Action switch coverage" {
    // Verify all Action variants can be matched in a switch (compile-time check)
    const actions = [_]Action{
        .continue_request,
        .{ .send_response = DirectResponse{ .status = 200 } },
        .{ .reject = RejectResponse{ .status = 403 } },
        .{ .stream = StreamResponse{ .status = 200 } },
    };

    for (actions) |action| {
        const desc: []const u8 = switch (action) {
            .continue_request => "continue",
            .send_response => "response",
            .reject => "reject",
            .stream => "stream",
        };
        try std.testing.expect(desc.len > 0);
    }
}

// =============================================================================
// BodyAction Tests
// =============================================================================

test "BodyAction continue_body variant" {
    const action: BodyAction = .continue_body;
    try std.testing.expect(action == .continue_body);
}

test "BodyAction reject variant" {
    const reject = RejectResponse{ .status = 400, .reason = "Malformed body" };
    const action: BodyAction = .{ .reject = reject };

    switch (action) {
        .continue_body => try std.testing.expect(false),
        .reject => |r| {
            try std.testing.expectEqual(@as(u16, 400), r.status);
            try std.testing.expectEqualStrings("Malformed body", r.reason);
        },
    }
}

test "BodyAction switch coverage" {
    // Verify all BodyAction variants can be matched in a switch
    const actions = [_]BodyAction{
        .continue_body,
        .{ .reject = RejectResponse{ .status = 413, .reason = "Payload too large" } },
    };

    for (actions) |action| {
        const desc: []const u8 = switch (action) {
            .continue_body => "continue",
            .reject => "reject",
        };
        try std.testing.expect(desc.len > 0);
    }
}

// =============================================================================
// ErrorAction Tests
// =============================================================================

test "ErrorAction default variant" {
    const action: ErrorAction = .default;
    try std.testing.expect(action == .default);
}

test "ErrorAction retry variant" {
    const action: ErrorAction = .retry;
    try std.testing.expect(action == .retry);
}

test "ErrorAction send_response variant" {
    const resp = DirectResponse{
        .status = 503,
        .body = "Service Unavailable",
        .content_type = "text/plain",
    };
    const action: ErrorAction = .{ .send_response = resp };

    switch (action) {
        .default => try std.testing.expect(false),
        .retry => try std.testing.expect(false),
        .send_response => |r| {
            try std.testing.expectEqual(@as(u16, 503), r.status);
            try std.testing.expectEqualStrings("Service Unavailable", r.body);
            try std.testing.expectEqualStrings("text/plain", r.content_type);
        },
    }
}

test "ErrorAction switch coverage" {
    // Verify all ErrorAction variants can be matched in a switch
    const actions = [_]ErrorAction{
        .default,
        .retry,
        .{ .send_response = DirectResponse{ .status = 500 } },
    };

    for (actions) |action| {
        const desc: []const u8 = switch (action) {
            .default => "default",
            .retry => "retry",
            .send_response => "custom",
        };
        try std.testing.expect(desc.len > 0);
    }
}

// =============================================================================
// UpstreamConnectInfo Tests
// =============================================================================

test "UpstreamConnectInfo plaintext defaults" {
    // Test plaintext connection (no TLS fields set)
    const info = UpstreamConnectInfo{
        .dns_duration_ns = 1_000_000, // 1ms
        .tcp_connect_duration_ns = 5_000_000, // 5ms
        .reused = false,
        .pool_wait_ns = 0,
        .local_port = 45678,
    };

    try std.testing.expectEqual(@as(u64, 1_000_000), info.dns_duration_ns);
    try std.testing.expectEqual(@as(u64, 5_000_000), info.tcp_connect_duration_ns);
    try std.testing.expectEqual(@as(u64, 0), info.tls_handshake_duration_ns);
    try std.testing.expect(!info.reused);
    try std.testing.expectEqual(@as(u64, 0), info.pool_wait_ns);
    try std.testing.expectEqual(@as(u16, 45678), info.local_port);
    // TLS fields should be zero-initialized
    try std.testing.expectEqual(@as(u8, 0), info.tls_cipher[0]);
    try std.testing.expectEqual(@as(u8, 0), info.tls_version[0]);
}

test "UpstreamConnectInfo with TLS fields" {
    var info = UpstreamConnectInfo{
        .dns_duration_ns = 500_000, // 0.5ms
        .tcp_connect_duration_ns = 2_000_000, // 2ms
        .tls_handshake_duration_ns = 15_000_000, // 15ms
        .reused = false,
        .pool_wait_ns = 100_000, // 0.1ms
        .local_port = 54321,
    };

    // Set TLS cipher and version
    const cipher = "TLS_AES_256_GCM_SHA384";
    const version = "TLSv1.3";
    @memcpy(info.tls_cipher[0..cipher.len], cipher);
    @memcpy(info.tls_version[0..version.len], version);

    try std.testing.expectEqual(@as(u64, 15_000_000), info.tls_handshake_duration_ns);
    try std.testing.expectEqualStrings(cipher, info.tls_cipher[0..cipher.len]);
    try std.testing.expectEqualStrings(version, info.tls_version[0..version.len]);
}

test "UpstreamConnectInfo reused connection" {
    const info = UpstreamConnectInfo{
        .dns_duration_ns = 0, // No DNS for reused
        .tcp_connect_duration_ns = 0, // No TCP connect for reused
        .tls_handshake_duration_ns = 0, // No TLS handshake for reused
        .reused = true,
        .pool_wait_ns = 50_000, // 50us waiting for pool slot
        .local_port = 33333,
    };

    try std.testing.expect(info.reused);
    try std.testing.expectEqual(@as(u64, 0), info.dns_duration_ns);
    try std.testing.expectEqual(@as(u64, 0), info.tcp_connect_duration_ns);
    try std.testing.expectEqual(@as(u64, 0), info.tls_handshake_duration_ns);
    try std.testing.expectEqual(@as(u64, 50_000), info.pool_wait_ns);
}

test "UpstreamConnectInfo tls_cipher max length" {
    // Test that we can store a reasonably long cipher suite name
    var info = UpstreamConnectInfo{
        .dns_duration_ns = 0,
        .tcp_connect_duration_ns = 0,
        .reused = true,
        .pool_wait_ns = 0,
        .local_port = 12345,
    };

    // Longest common cipher suite name (63 chars max, plus null terminator space)
    const long_cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_SOMETHING_EXTRA_CHARS";
    const len = @min(long_cipher.len, info.tls_cipher.len - 1); // Leave room for null
    @memcpy(info.tls_cipher[0..len], long_cipher[0..len]);

    try std.testing.expectEqualStrings(long_cipher[0..len], info.tls_cipher[0..len]);
}
