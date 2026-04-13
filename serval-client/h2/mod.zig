//! HTTP/2 Client Primitives
//!
//! Bounded outbound HTTP/2 session/runtime primitives plus a fixed-buffer
//! socket driver used by stream-aware upstream clients.
//! TigerStyle: Explicit state, fixed-capacity tables, bounded socket I/O.

/// Public import of the client session-state implementation module.
/// This exposes the session bookkeeping type and its error set as a module namespace.
/// Re-exported symbols are defined in `session.zig`.
pub const session = @import("session.zig");
/// Connection-scoped HTTP/2 session state for a client endpoint.
/// Tracks preface and GOAWAY state, settings negotiation, stream allocation, and connection-level flow control.
/// Initialize with `SessionState.init()` and then mutate in place through the session helpers.
pub const SessionState = session.SessionState;
/// Error set returned by HTTP/2 client session state transitions.
/// Covers preface sequencing, SETTINGS acknowledgement handling, stream allocation, and connection shutdown.
/// Use this alias when mutating `SessionState` or handling session-level frame updates.
pub const SessionError = session.Error;

/// Public import of the client runtime implementation module.
/// This exposes frame-building helpers, receive actions, and the runtime error type as a module namespace.
/// Re-exported symbols are defined in `runtime.zig`.
pub const runtime = @import("runtime.zig");
/// HTTP/2 client runtime state for prior-knowledge upstream sessions.
/// The runtime does not own sockets; it tracks session state, HPACK decoding, and per-stream response bookkeeping.
/// Initialize caller-owned storage with `Runtime.initInto(runtime_cfg, response_fields_storage)` before sending or receiving frames.
pub const Runtime = runtime.Runtime;
/// Error set returned by the HTTP/2 runtime.
/// Covers invalid headers, unsupported frame features, stream-state mismatches, and protocol sequencing failures.
/// Use this alias when propagating errors from `Runtime` frame builders and frame handlers.
pub const RuntimeError = runtime.Error;
/// Result of processing a received frame when the runtime needs an outbound action.
/// Variants either request no response or carry the exact response the caller should emit next.
/// Ping acknowledgements preserve the received 8-byte opaque payload verbatim.
pub const ReceiveAction = runtime.ReceiveAction;
/// Result of encoding outbound request HEADERS for a new stream.
/// `stream_id` is the newly opened request stream used for the encoded block.
/// `frame` aliases the caller-provided output buffer and contains the complete HEADERS or CONTINUATION sequence.
pub const RequestHeadersWrite = runtime.RequestHeadersWrite;

/// Public import of the client connection implementation module.
/// This exposes the socket driver and its related error type as a module namespace.
/// Re-exported symbols are defined in `connection.zig`.
pub const connection = @import("connection.zig");
/// Client-side HTTP/2 connection state tied to a single socket.
/// The socket is borrowed; the caller keeps ownership and must keep it valid for the life of the connection.
/// Use this type to send frames, drive handshakes, and receive peer actions.
pub const ClientConnection = connection.ClientConnection;
/// Caller-owned fixed storage required by `ClientConnection`.
/// Keep the storage alive for at least as long as the associated connection.
pub const ConnectionStorage = connection.ConnectionStorage;
/// Error set returned by the HTTP/2 client connection driver.
/// Covers connection setup, frame I/O, protocol sequencing, and flow-control failures.
/// Use this alias when propagating errors from `ClientConnection` methods.
pub const ConnectionError = connection.Error;

test {
    _ = @import("session.zig");
    _ = @import("runtime.zig");
    _ = @import("connection.zig");
}
