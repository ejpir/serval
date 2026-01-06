// lib/serval-core/config.zig
//! Server Configuration
//!
//! All tunables with sensible defaults.
//! TigerStyle: Units in names, explicit values.

const std = @import("std");
const builtin = @import("builtin");

// =============================================================================
// Compile-time Flags
// =============================================================================

/// Enable debug logging at compile time.
/// Zero overhead in release builds - compiler eliminates all debug log calls.
/// TigerStyle: Comptime switch for debug code, not runtime check.
pub const DEBUG_LOGGING = builtin.mode == .Debug;

// =============================================================================
// Compile-time Limits (buffer sizes, array bounds)
// =============================================================================

/// Maximum number of headers per request
pub const MAX_HEADERS: u8 = 64;

/// Maximum header block size in bytes
pub const MAX_HEADER_SIZE_BYTES: u32 = 8192;

/// Maximum URI length in bytes
pub const MAX_URI_LENGTH_BYTES: u32 = 8192;

/// Maximum request body size in bytes
pub const MAX_BODY_SIZE_BYTES: u32 = 1024 * 1024;

/// Async stream write buffer size in bytes
/// TigerStyle: Sized for typical HTTP headers in single io_uring op.
pub const STREAM_WRITE_BUFFER_SIZE_BYTES: u32 = 4096;

/// Async stream read buffer size in bytes
/// TigerStyle: Sized for typical HTTP headers in single io_uring op.
pub const STREAM_READ_BUFFER_SIZE_BYTES: u32 = 4096;

/// Server request buffer size in bytes
/// Buffer for reading incoming HTTP requests (headers + partial body).
pub const REQUEST_BUFFER_SIZE_BYTES: u32 = 4096;

/// Server response buffer size in bytes
/// Buffer for formatting HTTP error responses.
pub const RESPONSE_BUFFER_SIZE_BYTES: u32 = 1024;

/// Server write buffer size in bytes
/// Small buffer for stream.writer() operations.
pub const SERVER_WRITE_BUFFER_SIZE_BYTES: u32 = 256;

/// Maximum bytes to transfer per splice syscall (64KB - Linux pipe buffer default)
pub const SPLICE_CHUNK_SIZE_BYTES: u32 = 65536;

/// Buffer size for portable copy fallback (non-Linux platforms)
pub const COPY_CHUNK_SIZE_BYTES: u32 = 4096;

/// Buffer size for direct response handlers (echo backends, health checks, etc.)
/// Only allocated when handler implements onRequest hook.
/// TigerStyle: Sized for typical API/debug responses, bounded.
pub const DIRECT_RESPONSE_BUFFER_SIZE_BYTES: u32 = 8192;

/// Header buffer size for direct responses (status line + standard headers + extra).
/// TigerStyle: Explicit limit, prevents unbounded formatting.
pub const DIRECT_RESPONSE_HEADER_SIZE_BYTES: u32 = 1024;

// =============================================================================
// Connection Pool Limits
// =============================================================================

/// Maximum connections per upstream in SimplePool
pub const MAX_CONNS_PER_UPSTREAM: u8 = 16;

/// Maximum number of upstreams in SimplePool
pub const MAX_UPSTREAMS: u8 = 64;

// =============================================================================
// Forwarding / Retry Limits
// =============================================================================

/// Maximum stale connection retries before creating fresh connection.
/// When a pooled connection is detected as stale (closed by backend),
/// the forwarder retries up to this many times before giving up and
/// creating a fresh TCP connection.
/// TigerStyle: Bounded retry prevents pool exhaustion spiral.
pub const MAX_STALE_RETRIES: u8 = 2;

// =============================================================================
// Health Check Limits
// =============================================================================

/// Consecutive failures before marking backend unhealthy.
/// TigerStyle: Small threshold catches real failures, not transient hiccups.
pub const DEFAULT_UNHEALTHY_THRESHOLD: u8 = 3;

/// Consecutive successes before marking backend healthy again.
/// TigerStyle: Lower than unhealthy threshold - recover faster than fail.
pub const DEFAULT_HEALTHY_THRESHOLD: u8 = 2;

/// Interval between active health probe cycles in milliseconds.
pub const DEFAULT_PROBE_INTERVAL_MS: u32 = 5000;

/// Timeout for each health probe request in milliseconds.
/// TigerStyle: Must be less than probe interval.
pub const DEFAULT_PROBE_TIMEOUT_MS: u32 = 2000;

/// Default path for HTTP health probes.
pub const DEFAULT_HEALTH_PATH: []const u8 = "/";

// =============================================================================
// OpenTelemetry / Tracing Limits
// =============================================================================

/// Maximum concurrent active spans in OtelTracer pool.
/// With ~7 spans per request, 128 supports ~18 concurrent requests.
/// TigerStyle: Fixed at compile time, no runtime allocation.
pub const OTEL_MAX_ACTIVE_SPANS: u32 = 128;

/// Maximum attributes per span
pub const OTEL_MAX_ATTRIBUTES: u32 = 32;

/// Maximum events per span
pub const OTEL_MAX_EVENTS: u32 = 8;

/// Maximum links per span
pub const OTEL_MAX_LINKS: u32 = 4;

/// Maximum attribute key length
pub const OTEL_MAX_KEY_LEN: u32 = 64;

/// Maximum span name length
pub const OTEL_MAX_NAME_LEN: u32 = 128;

/// Maximum string attribute value length
pub const OTEL_MAX_STRING_VALUE_LEN: u32 = 256;

/// Maximum trace state entries (W3C allows 32, we limit to 8)
pub const OTEL_MAX_TRACE_STATE_ENTRIES: u32 = 8;

/// Maximum trace state key length
pub const OTEL_MAX_TRACE_STATE_KEY_LEN: u32 = 64;

/// Maximum trace state value length
pub const OTEL_MAX_TRACE_STATE_VALUE_LEN: u32 = 256;

/// Maximum spans in BatchingProcessor queue
pub const OTEL_MAX_QUEUE_SIZE: u32 = 2048;

/// Maximum spans per export batch
pub const OTEL_MAX_EXPORT_BATCH_SIZE: u32 = 512;

/// Default batch export delay in milliseconds
pub const OTEL_BATCH_DELAY_MS: u32 = 5000;

/// Maximum OTLP export buffer size in bytes (1MB)
pub const OTEL_MAX_EXPORT_BUFFER_SIZE_BYTES: u32 = 1024 * 1024;

/// HTTP timeout for OTLP export in milliseconds
pub const OTEL_HTTP_TIMEOUT_MS: u32 = 30000;

/// Default OTLP endpoint
pub const OTEL_DEFAULT_ENDPOINT: []const u8 = "http://localhost:4318/v1/traces";

// =============================================================================
// Runtime Configuration
// =============================================================================

pub const Config = struct {
    /// Port to listen on
    port: u16 = 8080,

    /// Keep-alive timeout in milliseconds
    keepalive_timeout_ms: u32 = 15_000,

    /// Maximum requests per connection
    max_requests_per_connection: u32 = 1000,

    /// Kernel TCP backlog
    kernel_backlog: u31 = 128,

    /// Receive buffer size in bytes
    recv_buffer_size_bytes: u32 = 4096,

    /// Send buffer size in bytes
    send_buffer_size_bytes: u32 = 4096,
};

test "Config has sensible defaults" {
    const cfg = Config{};
    try std.testing.expectEqual(@as(u16, 8080), cfg.port);
    try std.testing.expectEqual(@as(u32, 15_000), cfg.keepalive_timeout_ms);
}

test "Limits are sensible" {
    try std.testing.expectEqual(@as(u8, 64), MAX_HEADERS);
    try std.testing.expectEqual(@as(u32, 8192), MAX_HEADER_SIZE_BYTES);
    try std.testing.expectEqual(@as(u32, 8192), MAX_URI_LENGTH_BYTES);
}
