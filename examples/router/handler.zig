// examples/router/handler.zig
//! Router Handler Wrapper
//!
//! Dynamically loads the current router on each request, enabling
//! hot config reload via swapRouter() without server restart.
//!
//! TigerStyle: Wrapper pattern avoids modifying server internals.

const std = @import("std");
const serval = @import("serval");
const serval_router = @import("serval-router");
const config_storage = @import("config_storage.zig");

const Context = serval.Context;
const LogEntry = serval.LogEntry;
const Request = serval.Request;
const Router = serval_router.Router;

/// Handler wrapper that dynamically loads the current router on each request.
///
/// This enables hot config reload - swapRouter() updates current_router atomically,
/// and subsequent requests use the new router without server restart.
pub const RouterHandler = struct {
    /// Select upstream by loading current router and delegating.
    /// Returns 503 if no router is available (shouldn't happen in normal operation).
    pub fn selectUpstream(_: *RouterHandler, ctx: *Context, request: *const Request) Router.Action {
        const router = config_storage.getActiveRouter() orelse {
            std.log.err("RouterHandler: no router available", .{});
            return .{ .reject = .{ .status = 503, .body = "Service Unavailable" } };
        };
        std.log.debug("RouterHandler: loaded router with {d} routes, {d} allowed_hosts", .{
            router.routes.len,
            router.allowed_hosts.len,
        });
        return router.selectUpstream(ctx, request);
    }

    /// Forward health tracking to current router.
    pub fn onLog(_: *RouterHandler, ctx: *Context, entry: LogEntry) void {
        const router = config_storage.getActiveRouter() orelse return;
        router.onLog(ctx, entry);
    }
};
