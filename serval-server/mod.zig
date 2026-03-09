// lib/serval-server/mod.zig
//! Serval HTTP Server
//!
//! Provides HTTP/1.1 server (h1/) with future HTTP/2 support (h2/).
//! TigerStyle: Modular protocol implementations.

pub const h1 = @import("h1/mod.zig");
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

test {
    _ = h1;
    _ = websocket;
}
