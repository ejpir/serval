//! Native WebSocket Server API
//!
//! Server-owned WebSocket accept and session lifecycle.
//! TigerStyle: Layer 5 orchestration; protocol stays in serval-websocket.

const std = @import("std");
const types = @import("serval-core").types;
const context_mod = @import("serval-core").context;

pub const accept = @import("accept.zig");
pub const session = @import("session.zig");
pub const io = @import("io.zig");

pub const WebSocketRouteAction = session.WebSocketRouteAction;
pub const WebSocketAccept = session.WebSocketAccept;
pub const WebSocketMessageKind = session.WebSocketMessageKind;
pub const WebSocketMessage = session.WebSocketMessage;
pub const WebSocketSession = session.WebSocketSession;
pub const WebSocketSessionError = session.SessionError;
pub const WebSocketSessionState = session.SessionState;
pub const WebSocketSessionStats = session.SessionStats;
pub const WebSocketTransport = session.Transport;
pub const ConnectionTransportContext = io.ConnectionTransportContext;
pub const initConnectionTransport = io.initConnectionTransport;
pub const sendSwitchingProtocols = accept.sendSwitchingProtocols;

const Context = context_mod.Context;
const Request = types.Request;

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
