// lib/serval-proxy/h1/mod.zig
//! HTTP/1.1 Upstream Forwarding
//!
//! Sends HTTP/1.1 requests and forwards responses using text-based protocol.
//! TigerStyle: Protocol-specific code isolated for future h2 support.

/// Namespace import for HTTP/1.1 request-serialization helpers.
/// Exposes header filtering, request buffer construction, and request-sending adapters for upstream requests.
pub const request = @import("request.zig");
/// Namespace import for HTTP/1.1 response-forwarding helpers.
/// Exposes header parsing, response forwarding, and body-transfer logic for upstream responses.
pub const response = @import("response.zig");
/// Namespace import for HTTP/1.1 request-body forwarding helpers.
/// Exposes body streaming and zero-copy forwarding utilities used by the proxy request path.
pub const body = @import("body.zig");
/// Namespace import for HTTP/1.1 WebSocket upgrade helpers.
/// Exposes request serialization, response forwarding, and upgrade validation routines for the H1 upgrade path.
pub const websocket = @import("websocket.zig");

// Re-export commonly used functions for convenience
/// Re-export of `request.sendRequest`.
/// Builds a complete HTTP request and sends the headers and optional body to the upstream connection.
/// `effective_path`, when provided, replaces `request.path`; buffer or transport failures return `ForwardError.SendFailed`.
pub const sendRequest = request.sendRequest;
/// Re-export of `request.buildRequestBuffer`.
/// Serializes an HTTP/1.1 request into `buffer`, filtering hop-by-hop headers and appending the proxy Via header.
/// Returns the byte count written, or `null` if the request line or headers do not fit.
pub const buildRequestBuffer = request.buildRequestBuffer;
/// Re-export of `request.methodToString`.
/// Converts a `Method` value to the canonical uppercase HTTP token used on the wire.
/// The returned slice is static and carries no ownership.
pub const methodToString = request.methodToString;
/// Re-export of `request.isHopByHopHeader`.
/// Returns whether a header name matches the RFC 7230 hop-by-hop header set.
/// Comparison is case-insensitive and bounded by the fixed header list.
pub const isHopByHopHeader = request.isHopByHopHeader;
/// Re-export of `request.eqlIgnoreCase`.
/// Compares two header-name slices case-insensitively.
/// Returns `false` when the slices differ in length or any byte does not match ignoring ASCII case.
pub const eqlIgnoreCase = request.eqlIgnoreCase;

/// Re-export of `websocket.sendUpgradeRequest`.
/// Builds a WebSocket upgrade request and sends it on the supplied connection using the provided I/O backend.
/// Returns `ForwardError.SendFailed` if serialization fails to fit or if sending the request fails.
pub const sendUpgradeRequest = websocket.sendUpgradeRequest;
/// Re-export of `websocket.buildUpgradeRequestBuffer`.
/// Serializes a WebSocket upgrade request into the destination buffer, skipping hop-by-hop headers and appending upgrade headers.
/// Returns the number of bytes written, or `null` if the request line or headers do not fit.
pub const buildUpgradeRequestBuffer = websocket.buildUpgradeRequestBuffer;
/// Re-export of `websocket.ForwardedHeaders`.
/// Optional forwarded values injected into a WebSocket upgrade request when building proxy headers.
/// The slices are borrowed and must remain valid until the request buffer has been serialized.
pub const ForwardedHeaders = websocket.ForwardedHeaders;
/// Re-export of `websocket.forwardUpgradeResponse`.
/// Reads an upstream upgrade response and forwards it to the client, validating `101` responses against the expected accept key.
/// Non-`101` responses are forwarded as ordinary HTTP responses with any buffered body bytes.
pub const forwardUpgradeResponse = websocket.forwardUpgradeResponse;

/// Re-export of `response.forwardResponse`.
/// Reads upstream response headers, skips informational `1xx` responses, and forwards the final response to the client.
/// Body forwarding follows the upstream framing mode and may reject invalid or close-delimited responses.
pub const forwardResponse = response.forwardResponse;

/// Re-export of `body.streamRequestBody`.
/// Streams a request body from the client to the upstream connection using the framing described by `BodyInfo`.
/// Content-Length bodies are forwarded exactly; chunked bodies preserve the wire format.
pub const streamRequestBody = body.streamRequestBody;
/// Re-export of `body.forwardBody`.
/// Forwards a response body with zero-copy splice on Linux when possible, or buffered copy otherwise.
/// When `io` is provided, the fiber-safe copy path is used to avoid blocking concurrent body streaming.
pub const forwardBody = body.forwardBody;

test {
    _ = @import("request.zig");
    _ = @import("response.zig");
    _ = @import("body.zig");
    _ = @import("chunked.zig");
    _ = @import("websocket.zig");
}
