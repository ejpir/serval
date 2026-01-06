// lib/serval-core/hooks.zig
//! Handler Hook Verification
//!
//! Comptime verification that Handler types implement required hooks.
//! TigerStyle: Compile-time safety, explicit interface.
//!
//! ## Handler Interface
//!
//! ### Required
//!
//! - `selectUpstream(self: *Handler, ctx: *Context, request: *const Request) Upstream`
//!   Select which backend server to route the request to.
//!
//! ### Optional Request Hooks
//!
//! - `onRequest(self: *Handler, ctx: *Context, request: *Request, response_buf: []u8) Action`
//!   Called before forwarding to upstream. Can modify request or return direct response.
//!   Return `.continue_request` to proceed to selectUpstream and forward.
//!   Return `.{ .send_response = ... }` to send a direct response without forwarding.
//!   Use response_buf to format response body (server provides per-connection buffer).
//!
//! - `onResponse(self: *Handler, ctx: *Context, response: *Response) Action`
//!   Called after receiving upstream response. Can modify response.
//!
//! - `onError(self: *Handler, ctx: *Context, err: anyerror) void`
//!   Called on request processing errors.
//!
//! - `onLog(self: *Handler, ctx: *Context, entry: LogEntry) void`
//!   Called after request completes for access logging. LogEntry contains
//!   complete request lifecycle data (timing, status, bytes, upstream info).
//!
//! ### Optional Connection Lifecycle Hooks
//!
//! - `onConnectionOpen(self: *Handler, info: *const ConnectionInfo) void`
//!   Called when a new client connection is accepted. Use for connection-level
//!   metrics, rate limiting setup, or connection logging.
//!
//! - `onConnectionClose(self: *Handler, connection_id: u64, request_count: u32, duration_ns: u64) void`
//!   Called when a client connection closes. Provides request count and total
//!   connection duration for metrics and logging.

const std = @import("std");
const types = @import("types.zig");
const context_mod = @import("context.zig");
const log_mod = @import("log.zig");

const Context = context_mod.Context;
const Request = types.Request;
const Response = types.Response;
const Upstream = types.Upstream;
const Action = types.Action;
const ConnectionInfo = types.ConnectionInfo;
const LogEntry = log_mod.LogEntry;

/// Verify handler implements required interface at compile time.
/// Required: selectUpstream(self, ctx, request) -> Upstream
/// Optional: onRequest, onResponse, onError, onLog, onConnectionOpen, onConnectionClose
///
/// TigerStyle: Compile-time safety, catch signature errors at build time not runtime.
pub fn verifyHandler(comptime Handler: type) void {
    // Required: selectUpstream
    if (!@hasDecl(Handler, "selectUpstream")) {
        @compileError("Handler must implement: pub fn selectUpstream(self: *Handler, ctx: *Context, request: *const Request) Upstream");
    }

    // Verify selectUpstream signature fully
    verifySelectUpstream(Handler);

    // Verify optional request hooks if declared
    // onRequest signature: (self, ctx, request, response_buf) -> Action
    verifyOptionalHook(Handler, "onRequest", &[_]type{ *Handler, *Context, *Request, []u8 }, Action);
    verifyOptionalHook(Handler, "onResponse", &[_]type{ *Handler, *Context, *Response }, Action);
    verifyOptionalHook(Handler, "onError", &[_]type{ *Handler, *Context, anyerror }, void);
    verifyOptionalHook(Handler, "onLog", &[_]type{ *Handler, *Context, LogEntry }, void);

    // Verify optional connection lifecycle hooks if declared
    verifyOptionalHook(Handler, "onConnectionOpen", &[_]type{ *Handler, *const ConnectionInfo }, void);
    verifyOptionalHook(Handler, "onConnectionClose", &[_]type{ *Handler, u64, u32, u64 }, void);
}

/// Verify selectUpstream has correct signature: (self: *Handler, ctx: *Context, request: *const Request) Upstream
fn verifySelectUpstream(comptime Handler: type) void {
    const SelectFn = @TypeOf(@field(Handler, "selectUpstream"));
    const info = @typeInfo(SelectFn);

    if (info != .@"fn") {
        @compileError("selectUpstream must be a function");
    }

    const fn_info = info.@"fn";

    // Verify return type is Upstream
    if (fn_info.return_type != Upstream) {
        @compileError("selectUpstream must return Upstream, got: " ++ @typeName(fn_info.return_type.?));
    }

    // Verify takes 3 args: *Handler, *Context, *const Request
    if (fn_info.params.len != 3) {
        @compileError("selectUpstream must take exactly 3 parameters (self, ctx, request)");
    }

    // Verify first param is *Handler (self)
    if (fn_info.params[0].type != *Handler) {
        @compileError("selectUpstream first parameter must be *Handler (self)");
    }

    // Verify second param is *Context
    if (fn_info.params[1].type != *Context) {
        @compileError("selectUpstream second parameter must be *Context");
    }

    // Verify third param is *const Request
    if (fn_info.params[2].type != *const Request) {
        @compileError("selectUpstream third parameter must be *const Request");
    }
}

/// Verify an optional hook has correct signature if it exists.
/// TigerStyle: Generic helper keeps verifyHandler() concise.
fn verifyOptionalHook(
    comptime Handler: type,
    comptime hook_name: []const u8,
    comptime expected_params: []const type,
    comptime expected_return: type,
) void {
    if (!@hasDecl(Handler, hook_name)) {
        return; // Hook not declared, nothing to verify
    }

    const HookFn = @TypeOf(@field(Handler, hook_name));
    const info = @typeInfo(HookFn);

    if (info != .@"fn") {
        @compileError(hook_name ++ " must be a function");
    }

    const fn_info = info.@"fn";

    // Verify return type
    if (fn_info.return_type != expected_return) {
        @compileError(hook_name ++ " must return " ++ @typeName(expected_return));
    }

    // Verify parameter count
    if (fn_info.params.len != expected_params.len) {
        @compileError(hook_name ++ " must take exactly " ++ comptimeIntToStr(expected_params.len) ++ " parameters");
    }

    // Verify each parameter type
    inline for (expected_params, 0..) |expected_type, i| {
        // Special case: anyerror matches any error type
        if (expected_type == anyerror) {
            // Accept any error type for error parameters
            continue;
        }
        if (fn_info.params[i].type != expected_type) {
            @compileError(hook_name ++ " parameter " ++ comptimeIntToStr(i) ++ " must be " ++ @typeName(expected_type));
        }
    }
}

/// Convert integer to string at comptime for error messages.
fn comptimeIntToStr(comptime n: usize) []const u8 {
    return switch (n) {
        0 => "0",
        1 => "1",
        2 => "2",
        3 => "3",
        4 => "4",
        5 => "5",
        else => "N",
    };
}

/// Check if handler has optional hook
pub fn hasHook(comptime Handler: type, comptime name: []const u8) bool {
    return @hasDecl(Handler, name);
}

// =============================================================================
// Tests
// =============================================================================

const TestHandler = struct {
    counter: u32 = 0,

    pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        return .{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
    }

    pub fn onRequest(self: *@This(), ctx: *Context, request: *Request, response_buf: []u8) Action {
        _ = self;
        _ = ctx;
        _ = request;
        _ = response_buf;
        return .continue_request;
    }
};

test "verifyHandler accepts valid handler" {
    comptime verifyHandler(TestHandler);
}

test "hasHook detects optional hooks" {
    try std.testing.expect(hasHook(TestHandler, "selectUpstream"));
    try std.testing.expect(hasHook(TestHandler, "onRequest"));
    try std.testing.expect(!hasHook(TestHandler, "onError"));
}

/// Test handler with connection lifecycle hooks.
const TestHandlerWithConnectionHooks = struct {
    counter: u32 = 0,
    connections_opened: u32 = 0,
    connections_closed: u32 = 0,

    pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        return .{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
    }

    pub fn onConnectionOpen(self: *@This(), info: *const ConnectionInfo) void {
        _ = info;
        self.connections_opened += 1;
    }

    pub fn onConnectionClose(self: *@This(), connection_id: u64, request_count: u32, duration_ns: u64) void {
        _ = connection_id;
        _ = request_count;
        _ = duration_ns;
        self.connections_closed += 1;
    }
};

test "hasHook detects connection lifecycle hooks" {
    // Verify handler with connection hooks passes verification
    comptime verifyHandler(TestHandlerWithConnectionHooks);

    // Verify hook detection for connection lifecycle hooks
    try std.testing.expect(hasHook(TestHandlerWithConnectionHooks, "onConnectionOpen"));
    try std.testing.expect(hasHook(TestHandlerWithConnectionHooks, "onConnectionClose"));

    // Verify original handler does not have connection hooks
    try std.testing.expect(!hasHook(TestHandler, "onConnectionOpen"));
    try std.testing.expect(!hasHook(TestHandler, "onConnectionClose"));
}

/// Test handler with all optional hooks to verify complete signature checking.
const TestHandlerWithAllHooks = struct {
    counter: u32 = 0,

    pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        return .{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
    }

    pub fn onRequest(self: *@This(), ctx: *Context, request: *Request, response_buf: []u8) Action {
        _ = self;
        _ = ctx;
        _ = request;
        _ = response_buf;
        return .continue_request;
    }

    pub fn onResponse(self: *@This(), ctx: *Context, response: *Response) Action {
        _ = self;
        _ = ctx;
        _ = response;
        return .continue_request;
    }

    pub fn onError(self: *@This(), ctx: *Context, err: anyerror) void {
        _ = self;
        _ = ctx;
        _ = err;
    }

    pub fn onLog(self: *@This(), ctx: *Context, entry: LogEntry) void {
        _ = self;
        _ = ctx;
        _ = entry;
    }

    pub fn onConnectionOpen(self: *@This(), info: *const ConnectionInfo) void {
        _ = self;
        _ = info;
    }

    pub fn onConnectionClose(self: *@This(), connection_id: u64, request_count: u32, duration_ns: u64) void {
        _ = self;
        _ = connection_id;
        _ = request_count;
        _ = duration_ns;
    }
};

test "verifyHandler accepts handler with all optional hooks" {
    // All hooks have correct signatures - should compile
    comptime verifyHandler(TestHandlerWithAllHooks);

    // Verify all hooks are detected
    try std.testing.expect(hasHook(TestHandlerWithAllHooks, "selectUpstream"));
    try std.testing.expect(hasHook(TestHandlerWithAllHooks, "onRequest"));
    try std.testing.expect(hasHook(TestHandlerWithAllHooks, "onResponse"));
    try std.testing.expect(hasHook(TestHandlerWithAllHooks, "onError"));
    try std.testing.expect(hasHook(TestHandlerWithAllHooks, "onLog"));
    try std.testing.expect(hasHook(TestHandlerWithAllHooks, "onConnectionOpen"));
    try std.testing.expect(hasHook(TestHandlerWithAllHooks, "onConnectionClose"));
}
