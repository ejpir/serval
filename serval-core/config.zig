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

/// Buffer size for chunked transfer encoding forwarding.
/// 8KB balances memory usage with syscall efficiency.
pub const CHUNK_BUFFER_SIZE_BYTES: u32 = 8192;

/// Maximum iterations for chunked body forwarding loop.
/// TigerStyle S3: Bounded loop limit.
pub const MAX_CHUNK_ITERATIONS: u32 = 1024 * 1024;

/// Maximum chunks for streaming response callbacks.
/// TigerStyle S3: Bounded loop limit for handler-generated streams.
/// 64K chunks * 8KB buffer = 512MB max streamed response.
pub const MAX_STREAM_CHUNK_COUNT: u32 = 65536;

/// Buffer size for direct response handlers (echo backends, health checks, etc.)
/// Only allocated when handler implements onRequest hook.
/// TigerStyle: Sized for typical API/debug responses, bounded.
pub const DIRECT_RESPONSE_BUFFER_SIZE_BYTES: u32 = 8192;

/// Header buffer size for direct responses (status line + standard headers + extra).
/// TigerStyle: Explicit limit, prevents unbounded formatting.
pub const DIRECT_RESPONSE_HEADER_SIZE_BYTES: u32 = 1024;

/// Buffer size for reading request body in direct response handlers.
/// Only allocated when handler implements onRequest hook.
/// Bodies larger than this receive 413 Payload Too Large response.
/// TigerStyle: Stack-safe size (64KB), bounded.
pub const DIRECT_REQUEST_BODY_SIZE_BYTES: u32 = 65536;

// =============================================================================
// Connection Pool Limits
// =============================================================================

/// Maximum connections per upstream in SimplePool
pub const MAX_CONNS_PER_UPSTREAM: u8 = 50;

/// Maximum number of upstreams in SimplePool
pub const MAX_UPSTREAMS: u8 = 64;

// =============================================================================
// Routing Limits
// =============================================================================

/// Maximum number of backend pools in Router.
/// TigerStyle: Bounded array, explicit limit.
pub const MAX_POOLS: u8 = 64;

/// Maximum number of routes in Router (excluding default route).
/// TigerStyle: Bounded array, explicit limit.
pub const MAX_ROUTES: u8 = 128;

/// Maximum upstreams per pool.
/// TigerStyle: Bounded array per pool.
pub const MAX_UPSTREAMS_PER_POOL: u8 = 64;

/// Maximum string storage for router config in bytes (64KB).
/// For route names, paths, pool names, upstream hosts.
/// TigerStyle: Bounded buffer for all config strings, avoids use-after-free.
pub const ROUTER_STRING_STORAGE_BYTES: u32 = 64 * 1024;

// =============================================================================
// Type Aliases for Bounds (TigerStyle: Single source of truth)
// =============================================================================

/// Type for upstream indices (must fit MAX_UPSTREAMS).
/// TigerStyle: u6 fits exactly 0-63, matching 64-bit bitmap in health module.
pub const UpstreamIndex = u6;

/// Type for connection counts per upstream (must fit MAX_CONNS_PER_UPSTREAM).
pub const ConnectionCount = u8;

/// Type for header indices (must fit MAX_HEADERS).
pub const HeaderIndex = u8;

// TigerStyle: Compile-time assertions - max INDEX (count-1) must fit in type
comptime {
    if (MAX_UPSTREAMS - 1 > std.math.maxInt(UpstreamIndex)) {
        @compileError("MAX_UPSTREAMS-1 exceeds UpstreamIndex capacity");
    }
    if (MAX_CONNS_PER_UPSTREAM - 1 > std.math.maxInt(ConnectionCount)) {
        @compileError("MAX_CONNS_PER_UPSTREAM-1 exceeds ConnectionCount capacity");
    }
    if (MAX_HEADERS - 1 > std.math.maxInt(HeaderIndex)) {
        @compileError("MAX_HEADERS-1 exceeds HeaderIndex capacity");
    }
}

// =============================================================================
// Forwarding / Retry Limits
// =============================================================================

/// Maximum stale connection retries before creating fresh connection.
/// When a pooled connection is detected as stale (closed by backend),
/// the forwarder retries up to this many times before giving up and
/// creating a fresh TCP connection.
/// TigerStyle: Bounded retry prevents pool exhaustion spiral.
pub const MAX_STALE_RETRIES: u8 = 2;

/// Default upstream connection timeout in nanoseconds.
/// Used when creating TCP connections to backend servers.
/// TigerStyle: u64 nanoseconds, 30 seconds default (typical for load balancers).
pub const CONNECT_TIMEOUT_NS: u64 = 30 * 1000 * 1000 * 1000;

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
/// NOTE: Keep small - each span is ~12KB due to fixed-size attribute buffers.
/// 16 spans = ~200KB, which is safe for stack allocation.
/// TigerStyle: Fixed at compile time, no runtime allocation.
pub const OTEL_MAX_ACTIVE_SPANS: u32 = 16;

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
// DNS Resolution
// =============================================================================

/// Maximum DNS cache entries (matches MAX_UPSTREAMS for 1:1 mapping).
pub const DNS_MAX_CACHE_ENTRIES: u32 = 64;

/// Maximum hostname length per DNS spec (RFC 1035).
pub const DNS_MAX_HOSTNAME_LEN: u32 = 253;

/// Default DNS cache TTL in nanoseconds (60 seconds).
pub const DNS_DEFAULT_TTL_NS: u64 = 60 * std.time.ns_per_s;

/// DNS resolution timeout in nanoseconds (5 seconds).
pub const DNS_TIMEOUT_NS: u64 = 5 * std.time.ns_per_s;

// =============================================================================
// Admin API Configuration (for reconfigurable data planes)
// =============================================================================

/// Default admin API port for data plane management.
pub const DEFAULT_ADMIN_PORT: u16 = 9901;

/// Maximum request body size for admin API endpoints (1MB).
pub const MAX_ADMIN_REQUEST_BYTES: u32 = 1024 * 1024;

/// Maximum response body size for admin API endpoints (1MB).
pub const MAX_ADMIN_RESPONSE_BYTES: u32 = 1024 * 1024;

/// Admin request read timeout in nanoseconds (5 seconds).
pub const ADMIN_READ_TIMEOUT_NS: u64 = 5 * std.time.ns_per_s;

/// Admin response write timeout in nanoseconds (5 seconds).
pub const ADMIN_WRITE_TIMEOUT_NS: u64 = 5 * std.time.ns_per_s;

/// Maximum accept iterations per cycle for admin server.
pub const MAX_ADMIN_ACCEPT_ITERATIONS: u32 = 100;

// =============================================================================
// Dynamic Configuration Updates
// =============================================================================

/// Grace period after config swap before old config cleanup (milliseconds).
/// Allows in-flight requests using old config to complete.
pub const CONFIG_SWAP_GRACE_MS: u64 = 1000;

/// Number of router slots for atomic double-buffering.
pub const MAX_ROUTER_SLOTS: u8 = 2;

/// Maximum retries for pushing config to data plane.
pub const MAX_CONFIG_PUSH_RETRIES: u8 = 3;

/// Timeout for config push to data plane in nanoseconds (5 seconds).
pub const CONFIG_PUSH_TIMEOUT_NS: u64 = 5 * std.time.ns_per_s;

/// Base delay for exponential backoff on config push retry (milliseconds).
pub const CONFIG_PUSH_BACKOFF_BASE_MS: u64 = 100;

/// Maximum backoff delay for config push retry (milliseconds).
pub const MAX_CONFIG_PUSH_BACKOFF_MS: u64 = 5000;

// =============================================================================
// HTTP Client
// =============================================================================

/// Client connection timeout in nanoseconds.
/// TigerStyle: u64 nanoseconds, 5 seconds default.
pub const CLIENT_CONNECT_TIMEOUT_NS: u64 = 5 * std.time.ns_per_s;

/// Client read timeout in nanoseconds.
/// TigerStyle: u64 nanoseconds, 30 seconds default.
pub const CLIENT_READ_TIMEOUT_NS: u64 = 30 * std.time.ns_per_s;

/// Client write timeout in nanoseconds.
/// TigerStyle: u64 nanoseconds, 30 seconds default.
pub const CLIENT_WRITE_TIMEOUT_NS: u64 = 30 * std.time.ns_per_s;

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

    /// TLS configuration (optional - null means plaintext HTTP)
    tls: ?TlsConfig = null,
};

/// TLS configuration for client termination and upstream origination.
/// TigerStyle: Optional fields use null for unset, explicit defaults for all fields.
pub const TlsConfig = struct {
    // Server (client termination)
    /// Path to server certificate file (PEM format).
    cert_path: ?[]const u8 = null,
    /// Path to server private key file (PEM format).
    key_path: ?[]const u8 = null,

    // Client (upstream origination)
    /// Path to CA bundle for verifying upstream certificates (PEM format).
    ca_path: ?[]const u8 = null,
    /// Verify upstream certificates against CA bundle.
    /// TigerStyle: Explicit boolean, no implicit behavior.
    verify_upstream: bool = true,

    // Timeouts
    /// TLS handshake timeout in nanoseconds.
    /// Default: 10 seconds (typical handshake completes in <1s, allows retry).
    handshake_timeout_ns: u64 = 10 * std.time.ns_per_s,
    /// I/O operation timeout in nanoseconds.
    /// Default: 30 seconds (read/write operations during TLS session).
    io_timeout_ns: u64 = 30 * std.time.ns_per_s,
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
