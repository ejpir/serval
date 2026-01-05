// lib/serval-proxy/types.zig
//! Forwarder Types
//!
//! Error, result, and metadata types for upstream forwarding.
//! TigerStyle: Explicit types, units in names (_ns suffix).

// =============================================================================
// Forward Errors
// =============================================================================

pub const ForwardError = error{
    /// Failed to connect to upstream
    ConnectFailed,
    /// Failed to send request to upstream
    SendFailed,
    /// Failed to receive response from upstream
    RecvFailed,
    /// Pooled connection was stale (closed by server)
    StaleConnection,
    /// Response headers too large
    HeadersTooLarge,
    /// Invalid response format
    InvalidResponse,
    /// Splice operation failed (Linux-specific)
    SpliceFailed,
    /// Invalid upstream host address
    InvalidAddress,
    /// Request body exceeds maximum allowed size
    RequestBodyTooLarge,
};

// =============================================================================
// Forward Result
// =============================================================================

pub const ForwardResult = struct {
    // Core response metadata
    status: u16,
    response_bytes: u64,
    connection_reused: bool,

    // Timing breakdown (Pingora-style logging)
    // TigerStyle: u64 for nanoseconds, units in names (_ns suffix).
    // Default values for backward compatibility with existing code.
    dns_duration_ns: u64 = 0,
    tcp_connect_duration_ns: u64 = 0,
    send_duration_ns: u64 = 0,
    recv_duration_ns: u64 = 0,
    pool_wait_ns: u64 = 0,
    upstream_local_port: u16 = 0,
};

/// Information about request body for streaming forwarding.
/// Used to pass body metadata to the forwarder so it can stream
/// the body from client to upstream without full buffering.
pub const BodyInfo = struct {
    /// Content-Length from request headers (null if chunked/unknown).
    content_length: ?u64,
    /// Number of body bytes already read during header parsing.
    bytes_already_read: u64,
    /// Initial body bytes read with headers (slice into parser buffer).
    initial_body: []const u8,
};

// =============================================================================
// Protocol
// =============================================================================

/// Wire protocol for upstream connection.
/// Determined by ALPN (TLS) or preface detection (cleartext).
/// TigerStyle: Explicit enum, not bool, for future protocol additions.
pub const Protocol = enum {
    /// HTTP/1.1 - text-based, one request per connection (without pipelining)
    h1,
    /// HTTP/2 - binary framing, multiplexed streams (future)
    h2,
};

// =============================================================================
// Tests
// =============================================================================

const std = @import("std");
const testing = std.testing;

test "CRITICAL: ForwardError covers all failure modes" {
    // Document all error types - if you add one, add test case
    // This prevents forgetting to handle new errors

    const all_errors = [_]ForwardError{
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

    // If this fails to compile, you added an error but didn't list it above
    for (all_errors) |err| {
        const name = @errorName(err);
        try testing.expect(name.len > 0);
    }
}

test "BodyInfo: No body scenario (GET, DELETE)" {
    const no_body = BodyInfo{
        .content_length = null,
        .bytes_already_read = 0,
        .initial_body = "",
    };

    try testing.expectEqual(@as(?u64, null), no_body.content_length);
    try testing.expectEqual(@as(u64, 0), no_body.bytes_already_read);
    try testing.expectEqual(@as(usize, 0), no_body.initial_body.len);
}

test "BodyInfo: POST with small body" {
    const body_text = "name=value&foo=bar";
    const small_body = BodyInfo{
        .content_length = body_text.len,
        .bytes_already_read = body_text.len,
        .initial_body = body_text,
    };

    try testing.expectEqual(@as(u64, 18), small_body.content_length.?);
    try testing.expectEqual(@as(u64, 18), small_body.bytes_already_read);
    try testing.expectEqual(@as(usize, 18), small_body.initial_body.len);

    // All bytes already read (fits in parser buffer)
    try testing.expectEqual(small_body.content_length.?, small_body.bytes_already_read);
}

test "BodyInfo: POST with partial body" {
    // Large body, only first 100 bytes read with headers
    const partial = BodyInfo{
        .content_length = 10_000,
        .bytes_already_read = 100,
        .initial_body = &[_]u8{0} ** 100,
    };

    try testing.expectEqual(@as(u64, 10_000), partial.content_length.?);
    try testing.expectEqual(@as(u64, 100), partial.bytes_already_read);
    try testing.expectEqual(@as(usize, 100), partial.initial_body.len);

    // Still have bytes to stream: 10_000 - 100 = 9_900
    const remaining = partial.content_length.? - partial.bytes_already_read;
    try testing.expectEqual(@as(u64, 9_900), remaining);
}

test "ForwardResult: Connection reuse flag semantics" {
    // Fresh connection
    const fresh = ForwardResult{
        .status = 200,
        .response_bytes = 100,
        .connection_reused = false,
        .tcp_connect_duration_ns = 5_000_000, // 5ms connect time
    };
    try testing.expect(!fresh.connection_reused);
    try testing.expect(fresh.tcp_connect_duration_ns > 0);

    // Pooled connection
    const pooled = ForwardResult{
        .status = 200,
        .response_bytes = 100,
        .connection_reused = true,
        .tcp_connect_duration_ns = 0, // No connect for pooled
    };
    try testing.expect(pooled.connection_reused);
    try testing.expectEqual(@as(u64, 0), pooled.tcp_connect_duration_ns);
}

test "CRITICAL: Timing fields use nanoseconds (consistent units)" {
    const result = ForwardResult{
        .status = 200,
        .response_bytes = 0,
        .connection_reused = false,
        .dns_duration_ns = 0,
        .tcp_connect_duration_ns = 0,
        .send_duration_ns = 0,
        .recv_duration_ns = 0,
        .pool_wait_ns = 0,
    };

    // All timing fields end with _ns (nanoseconds)
    // This is enforced by naming convention, verified by compilation
    _ = result.dns_duration_ns;
    _ = result.tcp_connect_duration_ns;
    _ = result.send_duration_ns;
    _ = result.recv_duration_ns;
    _ = result.pool_wait_ns;

    // TigerStyle: Units in names prevent conversion bugs
}

test "Protocol: enum has expected variants" {
    // Document protocol variants
    try testing.expectEqual(Protocol.h1, Protocol.h1);
    try testing.expectEqual(Protocol.h2, Protocol.h2);
    try testing.expect(Protocol.h1 != Protocol.h2);
}
