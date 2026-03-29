// serval-client/mod.zig
//! Serval Client - HTTP/1.1 Client Library
//!
//! Zero-allocation HTTP/1.1 client for making requests to upstream servers.
//! TigerStyle: Fixed buffers, explicit sizes, bounded loops.
//!
//! Layer: 2 (Infrastructure) - alongside serval-pool, serval-prober, serval-health

// Client - unified HTTP client
/// Re-export of the `client.zig` module as a namespace value.
/// Use `client` to access public client-side APIs defined in that file.
/// This is a compile-time import; no runtime allocation or ownership semantics apply.
/// Errors are those surfaced by the referenced APIs and by compile-time import resolution.
pub const client = @import("client.zig");
/// Public re-export of [`client.Client`], the HTTP/1.1 upstream client type for this module.
/// This declaration is a pure type alias and adds no runtime behavior or error surface.
/// Ownership/lifetime semantics come from `client.Client`: it does not own `dns_resolver` or `client_ctx`,
/// so those dependencies must outlive any `Client` value that uses them.
pub const Client = client.Client;
/// Re-export of [`client.ClientError`] for the public `serval-client` API surface.
/// Use this error set when handling failures returned by client operations in this module.
/// Semantics, variants, and stability follow `client.ClientError` exactly.
pub const ClientError = client.ClientError;
/// Result type used by client connection operations.
/// Public re-export of `client.ConnectResult`.
/// Ownership/lifetime expectations and any error-related fields are exactly
/// those defined by `client.ConnectResult`; this alias adds no behavior.
pub const ConnectResult = client.ConnectResult;
/// Public alias of `client.RequestResult`, the success value returned by `Client.request`.
/// Contains the established upstream `conn` plus parsed HTTP `response` headers.
/// `conn` ownership is transferred to the caller; release it back to a pool or close it when done.
/// This type represents only the success path; failures are returned separately as `ClientError`.
pub const RequestResult = client.RequestResult;
/// Re-export of `serval-pool`'s connection handle used by the HTTP client.
/// Wraps a unified `Socket` (plain TCP or TLS) plus pool bookkeeping metadata.
/// Ownership is transferred to the caller when returned in client results; return it to the owning pool or call `close()`.
/// This alias adds no behavior or error surface beyond `client.Connection`.
pub const Connection = client.Connection;

// HTTP/2 client primitives
/// Re-exports the `h2` submodule from `h2/mod.zig` as `serval-client.h2`.
/// This is a compile-time namespace alias with no runtime allocation or side effects.
/// Error behavior is defined by the imported declarations when they are used.
pub const h2 = @import("h2/mod.zig");
/// Public alias for `h2.SessionState`, the bounded in-memory HTTP/2 client session state type.
/// It carries connection protocol state (preface/settings/GOAWAY), stream-table state, and flow-control state.
/// Initialize with `H2SessionState.init()` and keep a valid `*H2SessionState` while invoking its mutating methods.
/// This alias itself has no error behavior; failures come from `H2SessionState` operations (via `H2SessionError`).
pub const H2SessionState = h2.SessionState;
/// Error set returned by Serval client HTTP/2 session state operations.
/// This is a direct alias of `serval-client/h2.SessionError` (`session.Error`), re-exported at the module root.
/// Includes local session-state failures (for example preface/order/closing conditions) plus propagated
/// HTTP/2 settings/stream and flow-control errors from `serval-h2` components.
pub const H2SessionError = h2.SessionError;
/// Alias for the client HTTP/2 runtime type (`h2.Runtime`).
/// Use this exported name when referencing Serval's HTTP/2 runtime from `serval-client`.
/// Behavior, lifecycle, ownership, and error semantics are exactly those defined by `h2.Runtime`.
pub const H2Runtime = h2.Runtime;
/// Alias of [`h2.RuntimeError`] used by `serval-client` APIs.
/// Represents runtime HTTP/2 failure conditions surfaced from the underlying `h2` layer.
/// Semantics and cases are identical to `h2.RuntimeError`; this declaration does not add or alter behavior.
pub const H2RuntimeError = h2.RuntimeError;
/// Public alias of `h2.ReceiveAction`, the action union returned by HTTP/2 frame receive handling.
/// Use this type to branch on receive outcomes such as `none`, ACK sends, response events, stream reset, or connection close.
/// This declaration is a pure type re-export; it has no runtime behavior, ownership changes, or lifetime rules on its own.
/// It does not introduce errors; error behavior comes from APIs that produce/consume `H2ReceiveAction` (for example `H2Runtime.receiveFrame`).
pub const H2ReceiveAction = h2.ReceiveAction;
/// Public alias of `h2.RequestHeadersWrite`, returned by `H2Runtime.writeRequestHeadersFrame`.
/// Contains the opened request `stream_id` and the serialized HTTP/2 headers `frame`.
/// `frame` is a borrowed slice into the caller-provided output buffer (`out`), so caller controls ownership and lifetime.
/// This alias has no direct error behavior; failures occur in producer APIs (for example `H2RuntimeError`).
pub const H2RequestHeadersWrite = h2.RequestHeadersWrite;
/// Re-export of `h2.ClientConnection` for HTTP/2 client-side connections.
/// This is a type alias (not a wrapper), so behavior is identical to `h2.ClientConnection`.
/// Ownership and lifetime rules are the same as the underlying `h2` connection APIs.
/// Any error behavior is defined by the specific `h2.ClientConnection` operations you call.
pub const H2ClientConnection = h2.ClientConnection;
/// Public re-export of `h2.ConnectionError`, used by `H2ClientConnection` send/receive and handshake operations.
/// Covers transport/driver failures (`ReadFailed`, `WriteFailed`, `ConnectionClosed`, `WouldBlock`) and
/// connection-state limits (`FrameLimitExceeded`, `SendWindowExhausted`, `UnexpectedHandshakeFrame`, `ConnectionClosing`).
/// This error set also propagates `H2RuntimeError` and HTTP/2 frame errors from `serval-h2`; the alias adds no new behavior.
pub const H2ConnectionError = h2.ConnectionError;

/// Re-exports the HTTP/2 upstream pool module from `h2/upstream_pool.zig`.
/// Use this namespace to access upstream pool types and functions via `serval-client`.
/// This is a compile-time module alias only; it has no runtime ownership or error behavior.
pub const h2_upstream_pool = @import("h2/upstream_pool.zig");
/// Public re-export of `h2_upstream_pool.UpstreamSession` for the `serval-client` API surface.
/// This is a pure type alias: it introduces no runtime behavior, allocation, or additional state.
/// Ownership and lifetime semantics are exactly those of `h2_upstream_pool.UpstreamSession` (including pool/session lifetime constraints when used via `H2UpstreamSessionPool`).
/// This declaration cannot fail; any errors come from methods invoked on `H2UpstreamSession` values (for example via `H2UpstreamSessionError`).
pub const H2UpstreamSession = h2_upstream_pool.UpstreamSession;
/// Root-level alias of `h2_upstream_pool.UpstreamSessionPool`, which manages reusable outbound HTTP/2 upstream sessions.
/// The pool is slot-based by upstream index and can retain an active and (during rollover) a draining session per slot.
/// Initialize with `init()` and release resources with `deinit()`/`close*()`; acquired `*UpstreamSession` pointers are borrowed from pool storage.
/// Those pointers become invalid when their slot is closed/replaced or when the pool is deinitialized.
/// This alias itself has no error behavior; fallible operations on the type return `H2UpstreamSessionError`.
pub const H2UpstreamSessionPool = h2_upstream_pool.UpstreamSessionPool;
/// Error set for HTTP/2 upstream session-pool operations.
/// This is a direct alias of `h2_upstream_pool.Error`; it adds no behavior or extra variants.
/// Includes pool-level failures such as `UnsupportedProtocol` and `UpstreamSessionPoolExhausted`,
/// plus propagated errors from the underlying client connect and HTTP/2 connection layers.
pub const H2UpstreamSessionError = h2_upstream_pool.Error;
/// Statistics snapshot type for HTTP/2 upstream connection attempts in the client pool.
/// This is a direct alias of `h2_upstream_pool.ConnectStats`, preserving identical fields and semantics.
/// Use this exported name when referencing connect metrics from `serval-client` public APIs.
/// Validation rules, field meanings, and any error/ownership semantics are defined by the source type.
pub const H2UpstreamConnectStats = h2_upstream_pool.ConnectStats;
/// Result returned by `H2UpstreamSessionPool.acquireOrConnect`.
/// `session` is a borrowed pointer to pool-owned `UpstreamSession` storage; do not free it, and treat it as invalid after pool slot replacement/close or pool deinit.
/// `connect` reports whether the session was reused; on reuse, timing fields and `local_port` are zero.
/// This alias is a pure re-export of `h2_upstream_pool.AcquireResult`; errors are returned by the producing API (`Error!H2UpstreamAcquireResult`).
pub const H2UpstreamAcquireResult = h2_upstream_pool.AcquireResult;

// Request serialization
/// Re-exports the `request` module from `request.zig` under `serval-client`.
/// Use this namespace to access request-related types and functions without importing `request.zig` directly.
/// This declaration itself performs no allocation and cannot fail; any errors come from APIs used within `request`.
pub const request = @import("request.zig");
/// Sends one HTTP/1.1 request over `socket`, writing serialized headers and then `request.body` when present and non-empty.
/// Uses `effective_path` when non-null; otherwise uses `request.path` (which must be non-empty).
/// Request serialization applies RFC 7230 hop-by-hop header filtering and appends a `Via` header.
/// The function does not take ownership of `socket` or `request`; referenced data must stay valid for the duration of the call.
/// Returns `ClientError.BufferTooSmall`, `ClientError.SendFailed`, or `ClientError.SendTimeout` on failure.
pub const sendRequest = request.sendRequest;
/// Builds an HTTP/1.1 request into `buffer` and returns the number of bytes written.
/// Uses `effective_path` when non-null, otherwise `request.path`; the selected path must be non-empty.
/// Serializes the request line, copies up to `config.MAX_HEADERS` non-hop-by-hop headers, adds `Via`, then terminates headers with `\r\n`.
/// `request` is borrowed read-only for the call; the resulting bytes are in caller-owned `buffer[0..len]`.
/// Returns `null` if `buffer` is too small for the complete serialized request.
pub const buildRequestBuffer = request.buildRequestBuffer;

// Response parsing
/// Re-exports the client response namespace from `response.zig`.
/// Use `client.response` to access response-related types and helpers.
/// This is a compile-time module alias and does not allocate or transfer ownership.
pub const response = @import("response.zig");
/// Public alias for parsed HTTP response metadata from `serval-client/response.zig`.
/// Instances are typically returned by `readResponseHeaders`-style APIs after parsing `\r\n\r\n`.
/// `headers` is zero-copy: header name/value slices borrow the caller-owned header buffer and are valid only while that buffer remains unchanged.
/// This declaration is a type re-export only; error behavior comes from the parsing APIs that construct it.
pub const ResponseHeaders = response.ResponseHeaders;
/// Re-export of [`response.ResponseError`] in the `serval-client` public API.
/// Use this alias when referring to response-level failures returned by this module.
/// Behavior, data ownership/lifetime, and any error semantics are exactly those of `response.ResponseError`.
pub const ResponseError = response.ResponseError;
/// Reads and parses an HTTP/1.1 response head from `socket` into `header_buf` (alias of `response.readResponseHeaders`).
/// Preconditions: `header_buf.len > 0` and `header_buf.len <= config.MAX_HEADER_SIZE_BYTES`; headers must terminate with `\r\n\r\n`.
/// Returns `ResponseHeaders` with status, parsed headers, and body framing; it may include pre-read body bytes metadata.
/// Lifetime/ownership: returned header name/value slices are zero-copy views into `header_buf`, so keep that buffer alive while using them.
/// Fails with `ResponseError` on socket read/timeout failures, connection close before complete headers, oversized headers, or invalid status/header format.
pub const readResponseHeaders = response.readResponseHeaders;
/// Alias of [`response.HeaderBytesResult`], returned by [`readHeaderBytes`].
/// `total_bytes` is the number of bytes currently present in the read buffer
/// (response headers plus any already-read body bytes), and `header_end` is the
/// offset immediately after the `\r\n\r\n` header terminator.
pub const HeaderBytesResult = response.HeaderBytesResult;
/// Reads raw HTTP response bytes from `socket` into `header_buf` until `\r\n\r\n` is found.
/// This only detects header termination; it does not parse status line or header fields.
/// Preconditions: `header_buf.len > 0` and `header_buf.len <= config.MAX_HEADER_SIZE_BYTES`.
/// Returns `HeaderBytesResult` (`total_bytes`, `header_end`) or `ResponseError` on I/O failure, closed connection, or oversized/incomplete headers.
pub const readHeaderBytes = response.readHeaderBytes;

// Body reading
/// Namespace for client request/response body helpers, re-exported from `body.zig`.
/// Access members as `body.<name>` from `serval-client`.
/// This is a compile-time module import; any compile errors in `body.zig` surface here.
pub const body = @import("body.zig");
/// Re-export of [`body.BodyReader`] for client-facing API access.
/// This is a direct type alias (`body.BodyReader`) with no added behavior or wrapping.
/// Ownership, lifetime, and error semantics are exactly those defined on `body.BodyReader`.
pub const BodyReader = body.BodyReader;
/// Public alias of [`body.BodyError`], the explicit error set for HTTP response body operations.
/// Used by `BodyReader` APIs (`readAll`, `readChunk`, `forwardTo`) and related body helpers.
/// Covers read/write I/O failures plus protocol/limit failures such as `UnexpectedEof`,
/// `BufferTooSmall`, `IterationLimitExceeded`, invalid chunked encoding, and splice/pipe errors.
pub const BodyError = body.BodyError;

test {
    _ = @import("client.zig");
    _ = @import("h2/mod.zig");
    _ = @import("h2/upstream_pool.zig");
    _ = @import("request.zig");
    _ = @import("response.zig");
    _ = @import("body.zig");
}
