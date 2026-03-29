// lib/serval-server/mod.zig
//! Serval HTTP Server
//!
//! Provides frontend protocol dispatch plus HTTP/1.1 (h1/) and HTTP/2 (h2/) drivers.
//! TigerStyle: Modular protocol implementations with explicit dispatch layer.

/// Public namespace import for frontend orchestration helpers.
/// Re-exported types and functions in this module are defined under `serval-server.frontend`.
pub const frontend = @import("frontend/mod.zig");
/// Public namespace import for the HTTP/1.1 server implementation.
/// Re-exported types and helpers in this module are defined under `serval-server.h1`.
pub const h1 = @import("h1/mod.zig");
/// Public namespace import for HTTP/2 server primitives and runtime helpers.
/// Re-exported types and functions in this module are defined under `serval-server.h2`.
pub const h2 = @import("h2/mod.zig");
/// Public namespace import for server-side WebSocket APIs.
/// Re-exported types and helpers in this module are defined under `serval-server.websocket`.
pub const websocket = @import("websocket/mod.zig");

// Primary exports (HTTP/1.1 for now)
/// Re-export of `h1.Server`, the generic HTTP/1.1 server type.
/// It is the primary HTTP/1.1 server entry point exported from `serval-server.h1`.
pub const Server = h1.Server;
/// Re-export of `h1.MinimalServer`, the minimal HTTP/1.1 server variant exported by `serval-server.h1`.
/// Use it when you want the HTTP/1.1 server surface without importing the `h1` module directly.
pub const MinimalServer = h1.MinimalServer;
/// Re-export of `websocket.WebSocketRouteAction`, the result of routing a WebSocket request.
/// `decline` leaves the request unhandled, `accept` starts a session, and `reject` returns an HTTP rejection response.
pub const WebSocketRouteAction = websocket.WebSocketRouteAction;
/// Re-export of `websocket.WebSocketAccept`, the negotiated parameters for accepting a WebSocket session.
/// Carries the selected subprotocol, extra response headers, message limits, idle timeout, and auto-pong setting without taking ownership of referenced slices.
pub const WebSocketAccept = websocket.WebSocketAccept;
/// Re-export of `websocket.WebSocketMessageKind`, the high-level classification for received WebSocket payloads.
/// `text` identifies UTF-8 text frames and `binary` identifies opaque byte payloads.
pub const WebSocketMessageKind = websocket.WebSocketMessageKind;
/// Re-export of `websocket.WebSocketMessage`, the result of reading a complete WebSocket message.
/// The payload slice borrows from the buffer used during assembly, and the value records the message kind and whether it was fragmented.
pub const WebSocketMessage = websocket.WebSocketMessage;
/// Re-export of `websocket.WebSocketSession`, the server-side WebSocket session type.
/// It operates on a borrowed transport and caller-provided buffers and upgrade settings; session methods may fail with protocol, timeout, read, write, or close-related errors.
pub const WebSocketSession = websocket.WebSocketSession;
/// Re-export of `websocket.WebSocketSessionError`, the error set reported by WebSocket session operations.
/// Use it to handle protocol violations, I/O failures, timeouts, UTF-8 failures, and close-handshake termination conditions.
pub const WebSocketSessionError = websocket.WebSocketSessionError;
/// Re-export of `websocket.WebSocketSessionState`, the lifecycle state for a WebSocket session.
/// `open` permits normal message processing, `close_sent` records that a close frame was sent, and `closed` marks a finished session.
/// Callers should stop reading messages once the session is no longer `open`.
pub const WebSocketSessionState = websocket.WebSocketSessionState;
/// Re-export of `websocket.WebSocketSessionStats`, the per-session accounting record for a WebSocket connection.
/// Tracks bytes sent and received, the last close code seen or sent, and whether the peer initiated close.
/// This type owns no buffers or transport resources and is safe to copy by value.
pub const WebSocketSessionStats = websocket.WebSocketSessionStats;
/// Re-export of `h2.ConnectionState`, the per-connection HTTP/2 state container.
/// Tracks preface and SETTINGS exchange, GOAWAY state, flow control, and fixed-capacity stream tables without owning any socket.
/// Methods return protocol or settings errors when the peer sequence is invalid or a bounded table cannot accept the update.
pub const H2ConnectionState = h2.ConnectionState;
/// Errors reported by HTTP/2 connection-state operations such as preface, SETTINGS, and stream bookkeeping updates.
/// Includes duplicate preface detection, SETTINGS sequencing mistakes, and the underlying settings, stream, and flow-control failures from `serval-h2`.
/// Use this set for state transitions that validate connection-level HTTP/2 invariants.
pub const H2ConnectionError = h2.ConnectionError;
/// Re-export of `h2.Runtime`, the bounded per-connection HTTP/2 frame processor.
/// It owns protocol state and header decoding, but not any socket or TLS stream.
/// Drive it with the preface, initial SETTINGS, and inbound frames to obtain explicit `H2ReceiveAction` results.
pub const H2Runtime = h2.Runtime;
/// Errors returned by `H2Runtime` while processing inbound HTTP/2 frames.
/// Covers preface and SETTINGS ordering problems, unsupported frame types, stream and connection protocol violations, and flow-control failures.
/// Also includes connection-state errors propagated from the underlying connection layer.
pub const H2RuntimeError = h2.RuntimeError;
/// Re-export of `h2.ReceiveAction`, the result produced by `H2Runtime.receiveFrame`.
/// Describes the next driver action, such as sending a SETTINGS ACK, replying to PING, forwarding request data, or closing the connection.
/// Data-bearing variants carry the decoded request, payload, or reset instruction for the server loop to handle immediately.
pub const H2ReceiveAction = h2.ReceiveAction;
/// Re-export of `h2.H2Header`, the name/value pair used for HTTP/2 response headers and trailers.
/// Both slices are borrowed; this type does not own the header storage.
/// Pass it to `H2ResponseWriter` methods when building a response header block.
pub const H2ResponseHeader = h2.H2Header;
/// Re-export of `h2.StreamCloseReason`, the reason a stream was closed or completed.
/// Distinguishes local end-of-stream, peer reset, local reset, and connection shutdown.
/// Use it with `H2StreamSummary` when reporting stream lifecycle outcomes.
pub const H2StreamCloseReason = h2.StreamCloseReason;
/// Re-export of `h2.StreamSummary`, a value-type summary for a completed HTTP/2 stream.
/// Records the connection id, stream id, response status, request and response byte counts, duration, close reason, and reset code.
/// The struct owns no resources and is suitable for close hooks and logging.
pub const H2StreamSummary = h2.StreamSummary;
/// Re-export of `h2.ResponseWriter`, the server-side handle for emitting response frames on one HTTP/2 stream.
/// It borrows the connection I/O adapter, runtime state, and stream tables; it does not own the socket or buffers it writes from.
/// Methods return transport, protocol, frame, or response-state errors when the response cannot be advanced safely.
pub const H2ResponseWriter = h2.ResponseWriter;
/// Errors returned by the H2 server driver and response writer operations.
/// Covers invalid preface, read and write failures, frame and header-block limits, response-state mistakes, and other connection-level protocol failures.
/// Use this set for failures that happen while servicing an HTTP/2 connection rather than during top-level startup.
pub const H2ServerError = h2.ServerError;
/// Errors returned by `runH2Server` when the H2 server cannot start or complete bootstrap.
/// Covers HTTP/2 bootstrap failures, frontend orchestration failures, TLS certificate or key loading errors, and listener setup failures.
/// Also includes SSL-context and allocation failures surfaced during server startup.
pub const H2RunError = h2.RunError;
/// Re-export of `h2.run`, the top-level HTTP/2 server entry point.
/// It bootstraps listener state, runs the frontend orchestrator, and serves connections until shutdown or startup failure.
/// The caller must provide a valid handler, configuration, I/O backend, and shutdown flag; errors are reported as `H2RunError`.
pub const runH2Server = h2.run;
/// Re-export of `h2.servePlainConnection` for serving one HTTP/2 connection over a plain file descriptor.
/// The caller keeps ownership of the socket and must pass a valid non-negative `fd` plus a live handler reference.
/// It forwards the same runtime, protocol, and transport failures reported by the H2 driver.
pub const servePlainH2Connection = h2.servePlainConnection;
/// Re-export of `h2.serveTlsConnection` for serving one HTTP/2 connection over a TLS stream.
/// The caller supplies the handler, live `TLSStream`, I/O object, and connection id; this function does not take ownership of the stream.
/// It returns the underlying H2 server errors when the connection cannot be served safely.
pub const serveTlsH2Connection = h2.serveTlsConnection;

test {
    _ = frontend;
    _ = h1;
    _ = h2;
    _ = websocket;
}
