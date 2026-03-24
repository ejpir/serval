// lib/serval-server/mod.zig
//! Serval HTTP Server
//!
//! Provides frontend protocol dispatch plus HTTP/1.1 (h1/) and HTTP/2 (h2/) drivers.
//! TigerStyle: Modular protocol implementations with explicit dispatch layer.

pub const frontend = @import("frontend/mod.zig");
pub const h1 = @import("h1/mod.zig");
pub const h2 = @import("h2/mod.zig");
pub const websocket = @import("websocket/mod.zig");

// Primary exports (HTTP/1.1 for now)
pub const Server = h1.Server;
pub const MinimalServer = h1.MinimalServer;
pub const WebSocketRouteAction = websocket.WebSocketRouteAction;
pub const WebSocketAccept = websocket.WebSocketAccept;
pub const WebSocketMessageKind = websocket.WebSocketMessageKind;
pub const WebSocketMessage = websocket.WebSocketMessage;
pub const WebSocketSession = websocket.WebSocketSession;
pub const WebSocketSessionError = websocket.WebSocketSessionError;
pub const WebSocketSessionState = websocket.WebSocketSessionState;
pub const WebSocketSessionStats = websocket.WebSocketSessionStats;
pub const H2ConnectionState = h2.ConnectionState;
pub const H2ConnectionError = h2.ConnectionError;
pub const H2Runtime = h2.Runtime;
pub const H2RuntimeError = h2.RuntimeError;
pub const H2ReceiveAction = h2.ReceiveAction;
pub const H2ResponseHeader = h2.H2Header;
pub const H2StreamCloseReason = h2.StreamCloseReason;
pub const H2StreamSummary = h2.StreamSummary;
pub const H2ResponseWriter = h2.ResponseWriter;
pub const H2ServerError = h2.ServerError;
pub const H2RunError = h2.RunError;
pub const runH2Server = h2.run;
pub const servePlainH2Connection = h2.servePlainConnection;
pub const serveTlsH2Connection = h2.serveTlsConnection;

test {
    _ = frontend;
    _ = h1;
    _ = h2;
    _ = websocket;
}
