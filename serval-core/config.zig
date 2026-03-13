// lib/serval-core/config.zig
//! Server Configuration
//!
//! All tunables with sensible defaults.
//! TigerStyle: Units in names, explicit values.

const std = @import("std");
const builtin = @import("builtin");
const time = @import("time.zig");

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

/// Maximum request body size in bytes (10GB - supports large file transfers)
/// TigerStyle: Bounded limit prevents unbounded resource consumption.
pub const MAX_BODY_SIZE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

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
/// TigerStyle: Heap-allocated to support large payloads (128MB).
pub const DIRECT_RESPONSE_BUFFER_SIZE_BYTES: u32 = 128 * 1024 * 1024;

/// Header buffer size for direct responses (status line + standard headers + extra).
/// TigerStyle: Explicit limit, prevents unbounded formatting.
pub const DIRECT_RESPONSE_HEADER_SIZE_BYTES: u32 = 1024;

/// Buffer size for reading request body in direct response handlers.
/// Only allocated when handler implements onRequest hook.
/// Bodies larger than this receive 413 Payload Too Large response.
/// TigerStyle: Matches DIRECT_RESPONSE_BUFFER_SIZE_BYTES for echo handlers.
pub const DIRECT_REQUEST_BODY_SIZE_BYTES: u32 = 128 * 1024 * 1024;

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

/// Maximum allowed hosts per router for virtual host filtering.
/// TigerStyle S7: Bounded array for host matching.
pub const MAX_ALLOWED_HOSTS: u8 = 64;

/// Maximum hostname length in bytes (RFC 1035: 253 octets max).
/// Used for allowed_hosts validation and storage sizing.
pub const MAX_HOSTNAME_LEN: u16 = 253;

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

/// Initial read buffer size for h2c prior-knowledge request parsing.
/// Must fit client preface + SETTINGS + first HEADERS block in common cases.
pub const H2C_INITIAL_READ_BUFFER_SIZE_BYTES: u32 = 16 * 1024;

/// Default HTTP/2 frame size per RFC 9113.
pub const H2_MAX_FRAME_SIZE_BYTES: u32 = 16_384;

/// Maximum header block bytes accepted while parsing the first h2c request.
/// TigerStyle: Explicit bound prevents unbounded HPACK parsing on new connections.
pub const H2_MAX_HEADER_BLOCK_SIZE_BYTES: u32 = 8 * 1024;

/// Maximum frames inspected before selecting an upstream for h2c tunneling.
/// TigerStyle: Bounded loop for connection preface parsing.
pub const H2_MAX_INITIAL_PARSE_FRAMES: u32 = 16;

/// Maximum CONTINUATION frames accepted while assembling one header block.
/// TigerStyle: Explicit bound prevents unbounded header-fragment loops.
pub const H2_MAX_CONTINUATION_FRAMES: u8 = 16;

/// Maximum SETTINGS entries accepted in a single SETTINGS payload.
/// TigerStyle: Fixed-capacity parser output for bounded connection setup.
pub const H2_MAX_SETTINGS_PER_FRAME: u8 = 32;

/// Maximum concurrent active streams tracked per HTTP/2 connection.
/// TigerStyle: Fixed-capacity stream table prevents unbounded fan-out.
pub const H2_MAX_CONCURRENT_STREAMS: u16 = 128;

/// Maximum live upstream HTTP/2 sessions per upstream index in rollover mode.
/// One active session for new streams plus one draining GOAWAY session.
pub const H2_MAX_SESSIONS_PER_UPSTREAM: u8 = 2;

/// Default per-stream HTTP/2 flow-control window.
/// TigerStyle: Explicit RFC default in bytes.
pub const H2_INITIAL_WINDOW_SIZE_BYTES: u32 = 65_535;

/// Default per-connection HTTP/2 flow-control window.
/// TigerStyle: Explicit RFC default in bytes.
pub const H2_CONNECTION_WINDOW_SIZE_BYTES: u32 = 65_535;

/// Maximum legal HTTP/2 flow-control window.
/// TigerStyle: 31-bit bound per RFC 9113.
pub const H2_MAX_WINDOW_SIZE_BYTES: u32 = 0x7fff_ffff;

/// Maximum frames processed on a terminated HTTP/2 server connection before closing it.
/// TigerStyle: Explicit bound on long-lived server-side frame loops.
pub const H2_SERVER_MAX_FRAME_COUNT: u32 = 1_048_576;

/// Maximum frames processed on an outbound HTTP/2 client connection before closing it.
/// TigerStyle: Explicit bound on long-lived client-side frame loops.
pub const H2_CLIENT_MAX_FRAME_COUNT: u32 = 1_048_576;

/// Maximum idle time for tunneled h2c/gRPC connections.
/// TigerStyle: Explicit timeout bounds long-lived relay loops.
pub const H2C_TUNNEL_IDLE_TIMEOUT_NS: u64 = time.secondsToNanos(3600);

/// poll(2) timeout for h2c/gRPC tunnel relay.
/// TigerStyle: Fixed interval keeps timeout checks responsive without busy-looping.
pub const H2C_TUNNEL_POLL_TIMEOUT_MS: i32 = 1000;

/// Maximum uncompressed gRPC message size supported by helper utilities.
/// TigerStyle: Explicit bound prevents unbounded envelope parsing.
pub const GRPC_MAX_MESSAGE_SIZE_BYTES: u32 = 4 * 1024 * 1024;

/// Maximum idle time for an upgraded WebSocket tunnel.
/// TigerStyle: Explicit timeout bounds long-lived relay loops.
pub const WEBSOCKET_TUNNEL_IDLE_TIMEOUT_NS: u64 = time.secondsToNanos(3600);

/// poll(2) timeout for WebSocket tunnel relay.
/// TigerStyle: Small fixed interval keeps timeout checks responsive without busy-looping.
pub const WEBSOCKET_TUNNEL_POLL_TIMEOUT_MS: i32 = 1000;

/// Maximum application message size for native WebSocket endpoints.
/// TigerStyle: Explicit bound prevents unbounded buffering during fragmentation reassembly.
pub const WEBSOCKET_MAX_MESSAGE_SIZE_BYTES: u32 = 1024 * 1024;

/// Maximum fragments allowed in a single native WebSocket message.
/// TigerStyle: Bounded fragmentation prevents infinite continuation streams.
pub const WEBSOCKET_MAX_FRAGMENTS_PER_MESSAGE: u32 = 1024;

/// Maximum idle time for native WebSocket sessions.
/// TigerStyle: Explicit timeout bounds long-lived receive loops.
pub const WEBSOCKET_SESSION_IDLE_TIMEOUT_NS: u64 = time.secondsToNanos(60);

/// Maximum time to wait for peer close after sending a WebSocket close frame.
/// TigerStyle: Close handshake loops must be explicitly bounded.
pub const WEBSOCKET_CLOSE_TIMEOUT_NS: u64 = time.secondsToNanos(5);

/// poll(2) timeout for native WebSocket session reads.
/// TigerStyle: Fixed interval keeps timeout checks responsive without busy-waiting.
pub const WEBSOCKET_SESSION_POLL_TIMEOUT_MS: i32 = 1000;

/// Maximum allowed control-frame payload size per RFC 6455 Section 5.5.
pub const WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES: u32 = 125;

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
pub const DNS_DEFAULT_TTL_NS: u64 = time.secondsToNanos(60);

/// DNS resolution timeout in nanoseconds (5 seconds).
pub const DNS_TIMEOUT_NS: u64 = time.secondsToNanos(5);

/// Maximum addresses returned from a single DNS lookup.
pub const DNS_MAX_ADDRESSES: u8 = 16;

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
pub const ADMIN_READ_TIMEOUT_NS: u64 = time.secondsToNanos(5);

/// Admin response write timeout in nanoseconds (5 seconds).
pub const ADMIN_WRITE_TIMEOUT_NS: u64 = time.secondsToNanos(5);

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
pub const CONFIG_PUSH_TIMEOUT_NS: u64 = time.secondsToNanos(5);

/// Base delay for exponential backoff on config push retry (milliseconds).
pub const CONFIG_PUSH_BACKOFF_BASE_MS: u64 = 100;

/// Maximum backoff delay for config push retry (milliseconds).
pub const MAX_CONFIG_PUSH_BACKOFF_MS: u64 = 5000;

// =============================================================================
// TLS Reloadable Context
// =============================================================================

/// Number of server TLS context slots for hot-reload generations.
/// One active slot + bounded retired generations awaiting in-flight release.
pub const TLS_RELOADABLE_CTX_SLOT_COUNT: u8 = 5;

comptime {
    if (TLS_RELOADABLE_CTX_SLOT_COUNT < 2) {
        @compileError("TLS_RELOADABLE_CTX_SLOT_COUNT must be >= 2");
    }
}

// =============================================================================
// HTTP Client
// =============================================================================

/// Client connection timeout in nanoseconds.
/// TigerStyle: u64 nanoseconds, 5 seconds default.
pub const CLIENT_CONNECT_TIMEOUT_NS: u64 = time.secondsToNanos(5);

/// Client read timeout in nanoseconds.
/// TigerStyle: u64 nanoseconds, 30 seconds default.
pub const CLIENT_READ_TIMEOUT_NS: u64 = time.secondsToNanos(30);

/// Client write timeout in nanoseconds.
/// TigerStyle: u64 nanoseconds, 30 seconds default.
pub const CLIENT_WRITE_TIMEOUT_NS: u64 = time.secondsToNanos(30);

// =============================================================================
// ACME / Let's Encrypt
// =============================================================================

/// Maximum domains included in one ACME certificate order.
/// TigerStyle: Fixed-capacity SAN list bound.
pub const ACME_MAX_DOMAINS_PER_CERT: u8 = 16;

/// Maximum active HTTP-01 challenges tracked concurrently.
/// TigerStyle: Bounded challenge table for deterministic memory usage.
pub const ACME_MAX_ACTIVE_CHALLENGES: u8 = 64;

/// Maximum ACME poll attempts for challenge/order status transitions.
/// TigerStyle: Bounded polling loop.
pub const ACME_MAX_POLL_ATTEMPTS: u16 = 120;

/// Maximum state transitions executed in one manager tick.
/// TigerStyle: Bounded work per scheduler cycle.
pub const ACME_MAX_TRANSITIONS_PER_TICK: u8 = 32;

/// Maximum ACME directory URL length in bytes.
pub const ACME_MAX_DIRECTORY_URL_BYTES: u16 = 1024;

/// Maximum contact e-mail length in bytes.
pub const ACME_MAX_CONTACT_EMAIL_BYTES: u16 = 320;

/// Maximum ACME state directory path length in bytes.
pub const ACME_MAX_STATE_DIR_PATH_BYTES: u16 = 512;

/// Maximum hostname/domain length in bytes (RFC 1035: 253 octets).
pub const ACME_MAX_DOMAIN_NAME_LEN: u16 = 253;

/// Maximum HTTP-01 token length in bytes.
pub const ACME_MAX_HTTP01_TOKEN_BYTES: u16 = 128;

/// Maximum HTTP-01 key-authorization length in bytes.
pub const ACME_MAX_HTTP01_KEY_AUTHORIZATION_BYTES: u16 = 512;

/// Maximum Replay-Nonce header value length in bytes.
pub const ACME_MAX_NONCE_BYTES: u16 = 512;

/// Maximum ACME directory response payload in bytes.
/// TigerStyle: Explicit cap for JSON parsing input.
pub const ACME_MAX_DIRECTORY_RESPONSE_BYTES: u32 = 64 * 1024;

/// Maximum ACME account response payload in bytes.
/// TigerStyle: Explicit cap for JSON parsing input.
pub const ACME_MAX_ACCOUNT_RESPONSE_BYTES: u32 = 64 * 1024;

/// Maximum ACME order response payload in bytes.
/// TigerStyle: Explicit cap for JSON parsing input.
pub const ACME_MAX_ORDER_RESPONSE_BYTES: u32 = 128 * 1024;

/// Maximum JSON body bytes emitted in ACME JWS payload encoding.
/// TigerStyle: Bounded serializer output.
pub const ACME_MAX_JWS_BODY_BYTES: u32 = 64 * 1024;

/// Maximum detached JWS signature bytes accepted by serializers.
/// ES256 signatures are 64 bytes; bound leaves room for future algorithms.
pub const ACME_MAX_JWS_SIGNATURE_BYTES: u16 = 512;

/// Maximum authorization URLs tracked from one order response.
/// In HTTP-01 flow this should match domain count upper bound.
pub const ACME_MAX_AUTHORIZATION_URLS_PER_ORDER: u8 = ACME_MAX_DOMAINS_PER_CERT;

/// Minimum renew-before window in nanoseconds (1 day).
pub const ACME_MIN_RENEW_BEFORE_NS: u64 = time.secondsToNanos(24 * 60 * 60);

/// Maximum renew-before window in nanoseconds (365 days).
pub const ACME_MAX_RENEW_BEFORE_NS: u64 = time.secondsToNanos(365 * 24 * 60 * 60);

/// Default renew-before window in nanoseconds (30 days).
pub const ACME_DEFAULT_RENEW_BEFORE_NS: u64 = time.secondsToNanos(30 * 24 * 60 * 60);

/// Default HTTP-01 listener port.
pub const ACME_DEFAULT_HTTP01_PORT: u16 = 80;

/// Default ACME poll interval in milliseconds.
pub const ACME_DEFAULT_POLL_INTERVAL_MS: u32 = 2000;

/// Default minimum failure backoff in milliseconds.
pub const ACME_DEFAULT_FAIL_BACKOFF_MIN_MS: u32 = 1000;

/// Default maximum failure backoff in milliseconds.
pub const ACME_DEFAULT_FAIL_BACKOFF_MAX_MS: u32 = 3_600_000;

comptime {
    if (ACME_MAX_DOMAINS_PER_CERT == 0) {
        @compileError("ACME_MAX_DOMAINS_PER_CERT must be > 0");
    }
    if (ACME_MAX_ACTIVE_CHALLENGES == 0) {
        @compileError("ACME_MAX_ACTIVE_CHALLENGES must be > 0");
    }
    if (ACME_MAX_POLL_ATTEMPTS == 0) {
        @compileError("ACME_MAX_POLL_ATTEMPTS must be > 0");
    }
    if (ACME_MAX_NONCE_BYTES == 0) {
        @compileError("ACME_MAX_NONCE_BYTES must be > 0");
    }
    if (ACME_MAX_DIRECTORY_RESPONSE_BYTES == 0) {
        @compileError("ACME_MAX_DIRECTORY_RESPONSE_BYTES must be > 0");
    }
    if (ACME_MAX_ORDER_RESPONSE_BYTES == 0) {
        @compileError("ACME_MAX_ORDER_RESPONSE_BYTES must be > 0");
    }
    if (ACME_MAX_JWS_BODY_BYTES == 0) {
        @compileError("ACME_MAX_JWS_BODY_BYTES must be > 0");
    }
    if (ACME_MAX_JWS_SIGNATURE_BYTES == 0) {
        @compileError("ACME_MAX_JWS_SIGNATURE_BYTES must be > 0");
    }
}

// =============================================================================
// Runtime Configuration
// =============================================================================

/// TLS frontend HTTP/2 dispatch mode.
/// - disabled: ignore ALPN h2 and stay on HTTP/1.1 request loop
/// - terminated_only: dispatch ALPN h2 only when handler implements terminated h2 hooks
/// - generic: reserved for full generic h2 frontend orchestration
pub const TlsH2FrontendMode = enum {
    disabled,
    terminated_only,
    generic,
};

/// ALPN policy when client offers both `h2` and `http/1.1`.
/// TigerStyle: explicit deployment policy, no hidden defaults.
pub const AlpnMixedOfferPolicy = enum {
    prefer_http11,
    prefer_h2,
};

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

    /// When true, plaintext listeners only accept HTTP/2 prior-knowledge preface.
    /// Non-h2c bytes are closed without HTTP/1.1 parsing.
    h2c_prior_knowledge_only: bool = false,

    /// Frontend TLS ALPN h2 dispatch mode.
    /// Default keeps current terminated-only behavior for handlers with explicit h2 callbacks.
    tls_h2_frontend_mode: TlsH2FrontendMode = .terminated_only,

    /// ALPN mixed-offer selection policy.
    /// Default is conservative for mixed traffic until full generic h2 rollout is complete.
    alpn_mixed_offer_policy: AlpnMixedOfferPolicy = .prefer_http11,

    /// ACME certificate automation configuration.
    /// Null disables automatic issuance/renewal.
    acme: ?AcmeConfig = null,
};

/// ACME / Let's Encrypt runtime configuration.
/// TigerStyle: Explicit defaults + bounded behavior knobs.
pub const AcmeConfig = struct {
    /// Enable ACME manager for automatic certificate lifecycle.
    enabled: bool = false,

    /// ACME directory URL (staging or production endpoint).
    directory_url: []const u8 = "",

    /// Contact e-mail for ACME account registration.
    contact_email: []const u8 = "",

    /// Directory for persisted account/cert/journal state.
    state_dir_path: []const u8 = "",

    /// HTTP port that serves HTTP-01 challenge tokens.
    challenge_bind_port: u16 = ACME_DEFAULT_HTTP01_PORT,

    /// Start renewal when not_after - renew_before_ns is reached.
    renew_before_ns: u64 = ACME_DEFAULT_RENEW_BEFORE_NS,

    /// Poll interval for authorization/order state checks.
    poll_interval_ms: u32 = ACME_DEFAULT_POLL_INTERVAL_MS,

    /// Minimum retry backoff for transient failures.
    fail_backoff_min_ms: u32 = ACME_DEFAULT_FAIL_BACKOFF_MIN_MS,

    /// Maximum retry backoff for transient failures.
    fail_backoff_max_ms: u32 = ACME_DEFAULT_FAIL_BACKOFF_MAX_MS,

    /// Requested certificate SAN domains.
    domains: []const []const u8 = &.{},
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
    handshake_timeout_ns: u64 = time.secondsToNanos(10),
    /// I/O operation timeout in nanoseconds.
    /// Default: 30 seconds (read/write operations during TLS session).
    io_timeout_ns: u64 = time.secondsToNanos(30),
};

test "Config has sensible defaults" {
    const cfg = Config{};
    try std.testing.expectEqual(@as(u16, 8080), cfg.port);
    try std.testing.expectEqual(@as(u32, 15_000), cfg.keepalive_timeout_ms);
    try std.testing.expect(cfg.tls == null);
    try std.testing.expect(!cfg.h2c_prior_knowledge_only);
    try std.testing.expectEqual(TlsH2FrontendMode.terminated_only, cfg.tls_h2_frontend_mode);
    try std.testing.expectEqual(AlpnMixedOfferPolicy.prefer_http11, cfg.alpn_mixed_offer_policy);
    try std.testing.expect(cfg.acme == null);
}

test "AcmeConfig has sensible defaults" {
    const cfg = AcmeConfig{};
    try std.testing.expect(!cfg.enabled);
    try std.testing.expectEqual(@as(u16, 80), cfg.challenge_bind_port);
    try std.testing.expectEqual(ACME_DEFAULT_RENEW_BEFORE_NS, cfg.renew_before_ns);
    try std.testing.expectEqual(ACME_DEFAULT_POLL_INTERVAL_MS, cfg.poll_interval_ms);
    try std.testing.expectEqual(@as(usize, 0), cfg.domains.len);
}

test "Limits are sensible" {
    try std.testing.expectEqual(@as(u8, 64), MAX_HEADERS);
    try std.testing.expectEqual(@as(u32, 8192), MAX_HEADER_SIZE_BYTES);
    try std.testing.expectEqual(@as(u32, 8192), MAX_URI_LENGTH_BYTES);
}
