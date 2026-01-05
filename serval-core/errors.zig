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
    // Chunked Transfer-Encoding not supported - reject to prevent smuggling.
    // Future: implement proper chunked parsing before enabling.
    ChunkedNotSupported,
    // RFC 7230 Section 5.4: HTTP/1.1 requests MUST contain Host header.
    // Missing Host header prevents virtual hosting and is often a sign of malformed requests.
    MissingHostHeader,
};

// =============================================================================
// Connection Errors
// =============================================================================

pub const ConnectionError = error{
    ConnectFailed,
    ConnectionRefused,
    ConnectionReset,
    Timeout,
};

// =============================================================================
// Upstream Errors
// =============================================================================

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

pub const RequestError = ParseError || ConnectionError || UpstreamError;

// =============================================================================
// Error Context (passed to onError hook)
// =============================================================================

pub const ErrorContext = struct {
    err: RequestError,
    phase: Phase,
    upstream: ?Upstream,
    is_retry: bool,

    pub const Phase = enum {
        parse,
        handler_request,
        connect,
        send,
        recv,
        handler_response,
    };
};

