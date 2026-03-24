//! HTTP/2 Server Primitives
//!
//! Early bounded server-side HTTP/2 connection state used to build the future
//! stream-aware server transport.
//! TigerStyle: Explicit state, no socket ownership.

pub const connection = @import("connection.zig");
pub const ConnectionState = connection.ConnectionState;
pub const ConnectionError = connection.Error;

pub const bootstrap = @import("bootstrap.zig");
pub const H2BootstrapError = bootstrap.H2BootstrapError;
pub const validateTransportReadiness = bootstrap.validateTransportReadiness;
pub const preflightAndResolveListenAddress = bootstrap.preflightAndResolveListenAddress;

pub const runtime = @import("runtime.zig");
pub const Runtime = runtime.Runtime;
pub const RuntimeError = runtime.Error;
pub const ReceiveAction = runtime.ReceiveAction;

pub const server = @import("server.zig");
pub const H2Header = server.Header;
pub const StreamCloseReason = server.StreamCloseReason;
pub const StreamSummary = server.StreamSummary;
pub const ResponseWriter = server.ResponseWriter;
pub const ServerError = server.Error;
pub const RunError = server.RunError;
pub const run = server.run;
pub const servePlainConnection = server.servePlainConnection;
pub const serveTlsConnection = server.serveTlsConnection;
pub const verifyServerHandler = server.verifyHandler;

test {
    _ = @import("connection.zig");
    _ = @import("bootstrap.zig");
    _ = @import("runtime.zig");
    _ = @import("server.zig");
}
