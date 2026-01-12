//! Kubernetes API Client
//!
//! HTTP client for communicating with the Kubernetes API server.
//! Handles ServiceAccount authentication and TLS.
//!
//! Uses serval-client for HTTP communication with DNS resolution.
//!
//! TigerStyle: Bounded buffers, explicit error handling, no allocation after init.

// =============================================================================
// Constants (TigerStyle: Explicit bounds and paths)
// =============================================================================

/// Paths to ServiceAccount credentials (mounted in pods)
pub const SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";
pub const SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
pub const SA_NAMESPACE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Default K8s API server address (in-cluster)
/// Trailing dot makes this an explicit FQDN, preventing search domain appending
/// (ndots:5 in K8s resolv.conf would otherwise append search domains to names with <5 dots)
pub const DEFAULT_API_SERVER = "kubernetes.default.svc.cluster.local.";
pub const DEFAULT_API_PORT: u16 = 443;

/// Maximum token size in bytes (K8s JWT tokens are typically ~1KB)
pub const MAX_TOKEN_SIZE_BYTES: u32 = 8192;

/// Maximum namespace length (DNS label - 63 chars max per K8s spec)
pub const MAX_NAMESPACE_LEN: u32 = 63;

/// Maximum response buffer size for K8s API responses
pub const MAX_RESPONSE_SIZE_BYTES: u32 = 1024 * 1024; // 1MB

/// Maximum URL length for K8s API requests
pub const MAX_URL_SIZE_BYTES: u32 = 2048;

/// Maximum hostname length
pub const MAX_HOST_LEN: u32 = 253;

/// HTTP header buffer size
pub const HTTP_HEADER_BUFFER_SIZE: u32 = 4096;

/// HTTP timeout in seconds
pub const HTTP_TIMEOUT_SECS: u32 = 30;

/// Maximum iterations for response reading (TigerStyle: bounded loops)
pub const MAX_READ_ITERATIONS: u32 = 10000;

/// Bearer token header prefix
pub const BEARER_PREFIX = "Bearer ";

// =============================================================================
// Error Types (TigerStyle: Explicit error sets)
// =============================================================================

pub const ClientError = error{
    /// ServiceAccount token file not found or unreadable
    TokenNotFound,
    /// ServiceAccount namespace file not found or unreadable
    NamespaceNotFound,
    /// ServiceAccount CA certificate file not found or unreadable
    CaNotFound,
    /// Token exceeds MAX_TOKEN_SIZE_BYTES
    TokenTooLarge,
    /// Namespace exceeds MAX_NAMESPACE_LEN
    NamespaceTooLarge,
    /// Response exceeds MAX_RESPONSE_SIZE_BYTES
    ResponseTooLarge,
    /// URL construction failed (path too long)
    UrlTooLarge,
    /// DNS resolution failed
    DnsResolutionFailed,
    /// TCP connection failed
    ConnectionFailed,
    /// TLS handshake failed
    TlsHandshakeFailed,
    /// HTTP request failed
    RequestFailed,
    /// Non-success HTTP status (4xx, 5xx)
    HttpError,
    /// Empty response received
    EmptyResponse,
    /// Failed to parse HTTP response
    ResponseParseFailed,
    /// Out of memory during initialization
    OutOfMemory,
    /// SSL context creation failed
    SslContextFailed,
    /// Read operation exceeded MAX_READ_ITERATIONS
    ReadIterationsExceeded,
    /// Header error (too many headers, etc.)
    HeaderError,
    /// HTTP 409 Conflict - resource version mismatch, caller should retry with fresh data
    ConflictRetryable,
};

// =============================================================================
// Client Re-exports
// =============================================================================

const client_mod = @import("client.zig");
pub const Client = client_mod.Client;
pub const mapClientError = client_mod.mapClientError;

// =============================================================================
// Watch Stream Re-exports
// =============================================================================

const watch_stream_mod = @import("watch_stream.zig");
pub const WatchStream = watch_stream_mod.WatchStream;
pub const LazyWatchStream = watch_stream_mod.LazyWatchStream;
pub const MAX_WATCH_EVENT_SIZE = watch_stream_mod.MAX_WATCH_EVENT_SIZE;

// =============================================================================
// EndpointSlice Re-exports
// =============================================================================

/// Re-export EndpointSlice types and discovery functions.
/// Used for multi-instance router config push.
pub const endpoint_slice = @import("endpoint_slice.zig");

pub const RouterEndpoint = endpoint_slice.RouterEndpoint;
pub const RouterEndpoints = endpoint_slice.RouterEndpoints;
pub const EndpointSliceError = endpoint_slice.EndpointSliceError;
pub const discoverRouterEndpoints = endpoint_slice.discoverRouterEndpoints;
pub const MAX_ROUTER_ENDPOINTS = endpoint_slice.MAX_ROUTER_ENDPOINTS;
pub const MAX_IP_LEN = endpoint_slice.MAX_IP_LEN;
pub const MAX_POD_NAME_LEN = endpoint_slice.MAX_POD_NAME_LEN;

// =============================================================================
// JSON Types Re-export
// =============================================================================

pub const json_types = @import("json_types.zig");

// =============================================================================
// Unit Tests
// =============================================================================

const std = @import("std");

test "ClientError has ConflictRetryable variant" {
    // Verify ConflictRetryable error exists in the error set
    const err: ClientError = ClientError.ConflictRetryable;
    try std.testing.expect(err == ClientError.ConflictRetryable);

    // Verify it's distinct from HttpError
    try std.testing.expect(err != ClientError.HttpError);
}

test "ClientError error set completeness" {
    // Verify all error variants exist and are distinct
    const errors = [_]ClientError{
        ClientError.TokenNotFound,
        ClientError.NamespaceNotFound,
        ClientError.CaNotFound,
        ClientError.TokenTooLarge,
        ClientError.NamespaceTooLarge,
        ClientError.ResponseTooLarge,
        ClientError.UrlTooLarge,
        ClientError.DnsResolutionFailed,
        ClientError.ConnectionFailed,
        ClientError.TlsHandshakeFailed,
        ClientError.RequestFailed,
        ClientError.HttpError,
        ClientError.EmptyResponse,
        ClientError.ResponseParseFailed,
        ClientError.OutOfMemory,
        ClientError.SslContextFailed,
        ClientError.ReadIterationsExceeded,
        ClientError.HeaderError,
        ClientError.ConflictRetryable,
    };

    // Each error should be distinct
    for (errors, 0..) |err1, i| {
        for (errors[i + 1 ..]) |err2| {
            try std.testing.expect(err1 != err2);
        }
    }
}

// Run tests from submodules
test {
    _ = @import("client.zig");
    _ = @import("watch_stream.zig");
    _ = @import("endpoint_slice.zig");
    _ = @import("json_types.zig");
}
