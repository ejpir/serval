//! HTTP/2 Client Primitives
//!
//! Bounded outbound HTTP/2 session/runtime primitives plus a fixed-buffer
//! socket driver used by stream-aware upstream clients.
//! TigerStyle: Explicit state, fixed-capacity tables, bounded socket I/O.

pub const session = @import("session.zig");
pub const SessionState = session.SessionState;
pub const SessionError = session.Error;

pub const runtime = @import("runtime.zig");
pub const Runtime = runtime.Runtime;
pub const RuntimeError = runtime.Error;
pub const ReceiveAction = runtime.ReceiveAction;
pub const RequestHeadersWrite = runtime.RequestHeadersWrite;

pub const connection = @import("connection.zig");
pub const ClientConnection = connection.ClientConnection;
pub const ConnectionError = connection.Error;

test {
    _ = @import("session.zig");
    _ = @import("runtime.zig");
    _ = @import("connection.zig");
}
