// lib/serval-core/errors.zig
//! Serval Error Types
//!
//! Explicit error sets for each phase of request handling.
//! TigerStyle: No anyerror, all errors documented.

const types = @import("types.zig");
const Upstream = types.Upstream;

// =============================================================================
// Parse Errors
// =============================================================================

/// Errors reported while parsing and validating an HTTP request.
/// Includes malformed request lines, invalid headers, size limits, and framing errors.
/// Smuggling-related cases are rejected explicitly, including ambiguous or conflicting length headers.
/// `MissingHostHeader` is returned when an HTTP/1.1 request lacks `Host`.
pub const ParseError = error{
    EmptyRequest,
    InvalidMethod,
    InvalidUri,
    UriTooLong,
    InvalidHttpVersion,
    MalformedRequestLine,
    HeadersTooLarge,
    TooManyHeaders,
    InvalidHeaderName,
    InvalidHeaderValue,
    MalformedHeader,
    BodyTooLarge,
    // HTTP Request Smuggling prevention (RFC 7230 Section 3.3.3):
    // Reject requests with both Content-Length and Transfer-Encoding
    // to prevent CL-TE / TE-CL desync attacks.
    AmbiguousMessageLength,
    // Reject requests with multiple Content-Length headers with different values
    // to prevent request smuggling via CL disagreement.
    DuplicateContentLength,
    // Content-Length header value is not a valid non-negative integer.
    // Reject to prevent body framing ambiguity.
    InvalidContentLength,
    // RFC 7230 Section 5.4: HTTP/1.1 requests MUST contain Host header.
    // Missing Host header prevents virtual hosting and is often a sign of malformed requests.
    MissingHostHeader,
};

// =============================================================================
// Connection Errors
// =============================================================================

/// Errors reported when establishing or maintaining an upstream connection.
/// Includes connection refusal, reset, timeout, and generic connect failure cases.
/// These errors apply to the connection step and do not describe request parsing.
pub const ConnectionError = error{
    ConnectFailed,
    ConnectionRefused,
    ConnectionReset,
    Timeout,
};

// =============================================================================
// Upstream Errors
// =============================================================================

/// Errors reported by upstream request/response exchange.
/// Covers send and receive failures, invalid or empty responses, and stale connections.
/// These errors describe transport or protocol problems after an upstream has been selected.
pub const UpstreamError = error{
    SendFailed,
    RecvFailed,
    EmptyResponse,
    InvalidResponse,
    StaleConnection,
};

// =============================================================================
// Combined Request Error
// =============================================================================

/// The combined error set for request handling failures.
/// This aliases parse, connection, and upstream error sets into one request-level type.
/// Use it when a call can fail before, during, or after upstream communication.
pub const RequestError = ParseError || ConnectionError || UpstreamError;

// =============================================================================
// Error Context (passed to onError hook)
// =============================================================================

/// Carries the request error together with the phase and upstream context it came from.
/// `upstream` is optional and may be null when the error is not tied to a specific upstream.
/// `is_retry` marks whether the failure happened on a retry attempt.
pub const ErrorContext = struct {
    err: RequestError,
    phase: Phase,
    upstream: ?Upstream,
    is_retry: bool,

    /// Identifies the request-processing phase where an error occurred.
    /// Use this to distinguish parse, connection, upstream I/O, and handler phases.
    /// The values are used as error context and do not carry ownership or lifetime state.
    pub const Phase = enum {
        parse,
        handler_request,
        connect,
        send,
        recv,
        handler_response,
    };
};

