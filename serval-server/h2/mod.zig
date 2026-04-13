//! HTTP/2 Server Primitives
//!
//! Early bounded server-side HTTP/2 connection state used to build the future
//! stream-aware server transport.
//! TigerStyle: Explicit state, no socket ownership.

/// Re-exports the HTTP/2 connection state module.
/// Use this namespace to work with the bounded per-connection state machine
/// and its related error and helper types.
pub const connection = @import("connection.zig");
/// Per-connection HTTP/2 state for the server transport.
/// Tracks preface, settings, GOAWAY, stream bookkeeping, and connection-level
/// flow control; initialize instances with `ConnectionState.init()`.
pub const ConnectionState = connection.ConnectionState;
/// Error set for HTTP/2 connection-state operations.
/// Includes protocol-ordering errors such as duplicate preface and unexpected
/// SETTINGS acknowledgements, plus errors from settings, stream, and flow control helpers.
pub const ConnectionError = connection.Error;

/// Re-exports the HTTP/2 bootstrap helper module.
/// Use this namespace to access transport-readiness validation and listen
/// address preflight helpers shared with the frontend bootstrap path.
pub const bootstrap = @import("bootstrap.zig");
/// Error set used by the HTTP/2 bootstrap helpers.
/// This aliases the shared frontend bootstrap error set, so callers should
/// handle the same validation failures for HTTP/2 and frontend preflight paths.
pub const H2BootstrapError = bootstrap.H2BootstrapError;
/// Validates that the configured transports are ready for HTTP/2 startup.
/// This delegates to the shared frontend bootstrap checks and returns the same
/// bootstrap error set when transport validation fails.
pub const validateTransportReadiness = bootstrap.validateTransportReadiness;
/// Resolve the listen address used by the HTTP/2 bootstrap path.
/// Delegates to the shared frontend bootstrap implementation and follows the same transport-readiness checks and address parsing rules.
/// Returns the frontend bootstrap error set when validation or resolution fails.
pub const preflightAndResolveListenAddress = bootstrap.preflightAndResolveListenAddress;

/// Imported namespace for HTTP/2 server runtime primitives.
/// Re-exported so callers can reach runtime state, actions, and error types from one module.
/// All behavior is defined by `runtime.zig`.
pub const runtime = @import("runtime.zig");
/// Fixed-capacity HTTP/2 server runtime state used to validate inbound frames and build outbound control frames.
/// The struct owns no sockets or heap allocations and reuses internal buffers for request decoding and body tracking.
/// Initialize caller-owned storage with `initInto()` before calling the frame-processing or frame-writing methods.
pub const Runtime = runtime.Runtime;
/// Errors returned by the runtime's frame-receive and control-frame write APIs.
/// Covers protocol and state violations, flow-control failures, unsupported frame handling, and errors propagated from connection and HTTP/2 helpers.
/// Use this type when processing inbound frames or emitting runtime control frames.
pub const RuntimeError = runtime.Error;
/// Tagged union describing the immediate action requested after a frame is processed.
/// Variants either update internal state only or carry zero-copy data for the caller to forward.
/// `none` means no external action is required for that frame.
pub const ReceiveAction = runtime.ReceiveAction;

/// Imported namespace for the HTTP/2 server connection driver.
/// Re-exported so callers can reach server-side types, errors, and connection helpers from one module.
/// All behavior is defined by `server.zig`.
pub const server = @import("server.zig");
/// A single HTTP/2 header field as a borrowed name/value pair.
/// Both slices are read during header-block encoding and this type does not own the bytes.
/// The value is stored exactly as provided by the caller.
pub const H2Header = server.Header;
/// Describes why a tracked HTTP/2 stream was closed.
/// `local_end_stream` and `local_reset` indicate server-initiated completion.
/// `peer_reset` and `connection_close` indicate remote or connection-level termination.
pub const StreamCloseReason = server.StreamCloseReason;
/// Per-stream accounting captured when a stream is closed.
/// Records connection and stream identity, request and response byte counts, response status, duration, close reason, and the raw reset or GOAWAY code.
/// `duration_ns` is measured with monotonic time.
pub const StreamSummary = server.StreamSummary;
/// Writer for sending HTTP/2 response frames on a single stream.
/// Holds borrowed pointers to connection I/O, runtime state, and tracking tables; those referenced values must outlive the writer.
/// `stream_id` must be a positive stream id before calling the send methods.
pub const ResponseWriter = server.ResponseWriter;
/// Error set used by HTTP/2 server connection and response-writing routines.
/// Combines server-local state errors with runtime, frame, HPACK, and h2c-upgrade failures from imported subsystems.
/// Treat this as the common failure type for the h2 server module.
pub const ServerError = server.Error;
/// Error set returned by `run`.
/// Combines HTTP/2 bootstrap errors, frontend-orchestrator errors, and server-startup failures such as listener, TLS certificate/key, and TLS context creation.
/// Use this type for failures that can occur before or during server startup.
pub const RunError = server.RunError;
/// Start the HTTP/2 server accept loop for the configured listener.
/// Resolves the listen address, starts the frontend runtime orchestrator, and optionally publishes the listener fd through `listener_fd_out`.
/// Accepted connections are handed to per-connection tasks until `shutdown` is set; startup and accept-loop errors are returned in `RunError`.
pub const run = server.run;
/// Serve a plain TCP connection without extra initial bytes.
/// Equivalent to calling the underlying plain driver with an empty initial-byte prefix.
/// `fd` must be a valid non-negative descriptor and remains owned by the caller; errors propagate from the connection driver.
pub const servePlainConnection = server.servePlainConnection;
/// Serve a TLS connection without extra initial bytes.
/// Equivalent to calling the underlying TLS driver with an empty initial-byte prefix.
/// `tls_stream` is borrowed for the call and is not closed by this helper; errors propagate from the connection driver.
pub const serveTlsConnection = server.serveTlsConnection;
/// Validate at comptime that `Handler` satisfies the HTTP/2 server contract.
/// Requires `handleH2Headers` and `handleH2Data`, and accepts optional hooks only when their signatures match.
/// Violations are reported as compile errors rather than runtime errors.
pub const verifyServerHandler = server.verifyHandler;

test {
    _ = @import("connection.zig");
    _ = @import("bootstrap.zig");
    _ = @import("runtime.zig");
    _ = @import("server.zig");
}
