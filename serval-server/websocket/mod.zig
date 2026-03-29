//! Native WebSocket Server API
//!
//! Server-owned WebSocket accept and session lifecycle.
//! TigerStyle: Layer 5 orchestration; protocol stays in serval-websocket.

const std = @import("std");
const types = @import("serval-core").types;
const context_mod = @import("serval-core").context;

/// Native WebSocket accept-handshake helpers.
/// Provides the `sendSwitchingProtocols` and response-building APIs used to
/// format and send a `101 Switching Protocols` reply for an accepted upgrade.
/// The module does not own request or transport memory; callers retain those
/// lifetimes and must provide valid request headers and writable transport state.
pub const accept = @import("accept.zig");
/// Re-export of the `session` module for WebSocket session and message types.
/// Use it for the session state machine, message representation, accept parameters, and route actions.
/// This module contains the server-side WebSocket session API.
pub const session = @import("session.zig");
/// Re-export of the `io` module for WebSocket connection adaptation helpers.
/// Use it to construct transports from accepted connections and to work with the connection transport context type.
/// This module is part of the server-side WebSocket I/O layer.
pub const io = @import("io.zig");

/// Re-export of `session.WebSocketRouteAction`, the result of routing a WebSocket request.
/// `decline` leaves the request unhandled, `accept` starts a WebSocket session, and `reject` returns an HTTP rejection response.
/// This type keeps routing policy separate from session setup mechanics.
pub const WebSocketRouteAction = session.WebSocketRouteAction;
/// Re-export of `session.WebSocketAccept`, the negotiated upgrade parameters for a session.
/// Carries the selected subprotocol, extra response headers, message size limits, idle timeout, and auto-pong setting.
/// The session code reads these values but does not take ownership of any referenced slices.
pub const WebSocketAccept = session.WebSocketAccept;
/// Re-export of `session.WebSocketMessageKind`, the high-level payload classification for received messages.
/// `text` indicates UTF-8 text payloads and `binary` indicates opaque bytes.
/// The kind is derived from the initial data frame opcode.
pub const WebSocketMessageKind = session.WebSocketMessageKind;
/// Re-export of `session.WebSocketMessage`, the result of reading a complete WebSocket message.
/// The payload slice borrows from the caller-provided buffer used during assembly.
/// `kind` identifies the opcode class and `fragmented` reports whether the message spanned multiple frames.
pub const WebSocketMessage = session.WebSocketMessage;
/// Re-export of `session.WebSocketSession`, the server-side WebSocket session type.
/// Owns session state and operates on a borrowed transport plus caller-provided buffers and upgrade settings.
/// Session methods may return protocol, timeout, UTF-8, close-handshake, read, or write errors.
pub const WebSocketSession = session.WebSocketSession;
/// Re-export of `session.SessionError`, the error set reported by WebSocket session operations.
/// Covers protocol violations, UTF-8 failures, message size limits, connection and I/O failures, timeouts, and invalid close data.
/// Callers should treat `SessionClosed` and `ConnectionClosed` as terminal for the session.
pub const WebSocketSessionError = session.SessionError;
/// Re-export of `session.SessionState`, the lifecycle state for a WebSocket session.
/// `open` permits normal message processing, `close_sent` means a close frame was emitted, and `closed` marks a finished session.
/// Callers should stop reading messages once the session is no longer open.
pub const WebSocketSessionState = session.SessionState;
/// Re-export of `session.SessionStats` for per-session accounting.
/// Tracks bytes transferred, the last close code seen or sent, and whether the peer initiated close.
/// This type contains only counters and flags; it does not own buffers or transport resources.
pub const WebSocketSessionStats = session.SessionStats;
/// Re-export of `session.Transport`, the callback-based I/O adapter used by WebSocket sessions.
/// A transport carries a context pointer plus read, write, fd, and pending-read callbacks.
/// The callback implementation must remain valid for as long as the transport is used.
pub const WebSocketTransport = session.Transport;
/// Re-export of `io.ConnectionTransportContext` used to back a WebSocket transport.
/// Stores the accepted file descriptor, optional TLS stream pointer, and connection id for logging.
/// The struct does not own any of those resources; they must remain valid while the transport is in use.
pub const ConnectionTransportContext = io.ConnectionTransportContext;
/// Re-export of `io.initConnectionTransport` for constructing WebSocket transports.
/// Builds a transport adapter around caller-owned connection state and borrows that state for the lifetime of the transport value.
/// The adapter routes through TLS when present, otherwise it uses the raw file descriptor.
/// The caller retains ownership of the socket and TLS stream.
pub const initConnectionTransport = io.initConnectionTransport;
/// Re-export of `accept.sendSwitchingProtocols` for the WebSocket server API.
/// Formats and writes the `101 Switching Protocols` response for a successful upgrade.
/// On failure, returns the underlying handshake or transport error from the accept layer.
pub const sendSwitchingProtocols = accept.sendSwitchingProtocols;

const Context = context_mod.Context;
const Request = types.Request;

/// Verifies that an optional WebSocket handler extension is internally consistent.
/// If neither `selectWebSocket` nor `handleWebSocket` is present, this returns without error.
/// If exactly one hook is declared, compilation fails so the handler cannot advertise a half-implemented WebSocket path.
/// When both hooks exist, their signatures are validated by the WebSocket hook checkers.
pub fn verifyHandlerExtensions(comptime Handler: type) void {
    const has_select = @hasDecl(Handler, "selectWebSocket");
    const has_handle = @hasDecl(Handler, "handleWebSocket");

    if (!has_select and !has_handle) return;
    if (has_select and !has_handle) {
        @compileError("Handler with selectWebSocket must also implement handleWebSocket");
    }
    if (!has_select and has_handle) {
        @compileError("Handler with handleWebSocket must also implement selectWebSocket");
    }

    verifySelectWebSocket(Handler);
    verifyHandleWebSocket(Handler);
}

/// Returns whether `Handler` declares a member with the given compile-time name.
/// This is a thin wrapper over `@hasDecl` and performs no runtime checks.
/// Use it for optional hook detection when verifying handler capabilities.
pub fn hasHook(comptime Handler: type, comptime name: []const u8) bool {
    return @hasDecl(Handler, name);
}

fn verifySelectWebSocket(comptime Handler: type) void {
    const HookFn = @TypeOf(@field(Handler, "selectWebSocket"));
    const fn_info = getFunctionInfo(HookFn, "selectWebSocket");

    if (fn_info.return_type != WebSocketRouteAction) {
        @compileError("selectWebSocket must return serval_server.WebSocketRouteAction");
    }
    if (fn_info.params.len != 3) {
        @compileError("selectWebSocket must take exactly 3 parameters (self, ctx, request)");
    }
    if (fn_info.params[0].type != *Handler) {
        @compileError("selectWebSocket first parameter must be *Handler");
    }
    if (fn_info.params[1].type != *Context) {
        @compileError("selectWebSocket second parameter must be *Context");
    }
    if (fn_info.params[2].type != *const Request) {
        @compileError("selectWebSocket third parameter must be *const Request");
    }
}

fn verifyHandleWebSocket(comptime Handler: type) void {
    const HookFn = @TypeOf(@field(Handler, "handleWebSocket"));
    const fn_info = getFunctionInfo(HookFn, "handleWebSocket");

    if (fn_info.params.len != 4) {
        @compileError("handleWebSocket must take exactly 4 parameters (self, ctx, request, session)");
    }
    if (fn_info.params[0].type != *Handler) {
        @compileError("handleWebSocket first parameter must be *Handler");
    }
    if (fn_info.params[1].type != *Context) {
        @compileError("handleWebSocket second parameter must be *Context");
    }
    if (fn_info.params[2].type != *const Request) {
        @compileError("handleWebSocket third parameter must be *const Request");
    }
    if (fn_info.params[3].type != *WebSocketSession) {
        @compileError("handleWebSocket fourth parameter must be *serval_server.WebSocketSession");
    }

    const return_type = fn_info.return_type orelse {
        @compileError("handleWebSocket must return !void");
    };
    const return_info = @typeInfo(return_type);
    if (return_info != .error_union or return_info.error_union.payload != void) {
        @compileError("handleWebSocket must return !void");
    }
}

fn getFunctionInfo(comptime HookFn: type, comptime hook_name: []const u8) std.builtin.Type.Fn {
    const info = @typeInfo(HookFn);
    if (info != .@"fn") {
        @compileError(hook_name ++ " must be a function");
    }
    return info.@"fn";
}

test {
    _ = @import("accept.zig");
    _ = @import("session.zig");
    _ = @import("io.zig");
}
