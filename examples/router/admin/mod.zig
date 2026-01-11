// examples/router/admin/mod.zig
//! Admin API Handler
//!
//! HTTP handler for router admin API endpoints.
//! Routes requests to appropriate CRUD handlers.
//!
//! ## Endpoints
//!
//!   GET /healthz           - Liveness probe (always returns 200 OK)
//!   GET /readyz            - Readiness probe (200 OK if router initialized)
//!   GET /routes            - Returns current routes, pools, and upstreams as JSON
//!   POST /routes/update    - Atomically update full router config from JSON body
//!   POST /routes/add       - Add a single route (incremental)
//!   POST /routes/remove    - Remove a route by name
//!   POST /pools/add        - Add a new pool with upstreams
//!   POST /pools/remove     - Remove a pool by name (fails if routes reference it)
//!   POST /upstreams/add    - Add an upstream to an existing pool
//!   POST /upstreams/remove - Remove an upstream from a pool
//!
//! TigerStyle: All state explicit, no hidden dependencies.

const std = @import("std");
const assert = std.debug.assert;

const serval = @import("serval");

const json = @import("../json/mod.zig");
const config_storage = @import("../config_storage.zig");

// Import CRUD handlers
pub const routes = @import("routes.zig");
pub const pools = @import("pools.zig");
pub const upstreams = @import("upstreams.zig");

const MAX_JSON_BODY_SIZE = json.MAX_JSON_BODY_SIZE;

/// Admin API handler for health checks and configuration updates.
/// TigerStyle: All state explicit, no hidden dependencies.
pub const AdminHandler = struct {
    /// Required by handler interface, but never called (onRequest handles everything).
    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, request: *const serval.Request) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        // TigerStyle: Explicit sentinel - this should never be reached.
        assert(false);
        return .{ .host = "0.0.0.0", .port = 0, .idx = 0 };
    }

    /// Intercept all requests and route to appropriate handler.
    /// TigerStyle: Uses server-provided buffer, no allocation.
    pub fn onRequest(
        self: *@This(),
        ctx: *serval.Context,
        request: *serval.Request,
        response_buf: []u8,
    ) serval.Action {
        _ = self;
        // Precondition: response buffer must be provided
        assert(response_buf.len > 0);

        // Route based on path and method
        if (std.mem.eql(u8, request.path, "/healthz")) {
            return .{ .send_response = .{
                .status = 200,
                .body = "OK",
                .content_type = "text/plain",
            } };
        }

        if (std.mem.eql(u8, request.path, "/readyz")) {
            if (config_storage.getActiveRouter() != null) {
                return .{ .send_response = .{
                    .status = 200,
                    .body = "OK",
                    .content_type = "text/plain",
                } };
            } else {
                return .{ .send_response = .{
                    .status = 503,
                    .body = "Not Ready",
                    .content_type = "text/plain",
                } };
            }
        }

        if (std.mem.eql(u8, request.path, "/routes")) {
            const router = config_storage.getActiveRouter() orelse {
                return .{ .send_response = .{
                    .status = 503,
                    .body = json.response.errors.no_router,
                    .content_type = "application/json",
                } };
            };

            const generation = config_storage.getRouterGeneration();
            const json_body = json.writer.streamRouterConfig(router, generation, response_buf) catch {
                return .{ .send_response = .{
                    .status = 500,
                    .body = json.response.errors.buffer_overflow,
                    .content_type = "application/json",
                } };
            };

            return .{ .send_response = .{
                .status = 200,
                .body = json_body,
                .content_type = "application/json",
            } };
        }

        if (std.mem.eql(u8, request.path, "/routes/update") and request.method == .POST) {
            // Read request body lazily using ctx.readBody()
            var body_buf: [MAX_JSON_BODY_SIZE]u8 = undefined;
            const body = ctx.readBody(&body_buf) catch |err| {
                return makeBodyReadErrorResponse(err, response_buf);
            };
            const body_or_null: ?[]const u8 = if (body.len > 0) body else null;
            const result = routes.handleRouteUpdate(body_or_null, response_buf);
            return .{ .send_response = .{
                .status = result.status,
                .body = result.body,
                .content_type = "application/json",
            } };
        }

        // Incremental CRUD endpoints - all require POST with JSON body
        if (request.method == .POST) {
            // Read request body for POST endpoints
            var body_buf: [MAX_JSON_BODY_SIZE]u8 = undefined;
            const body = ctx.readBody(&body_buf) catch |err| {
                return makeBodyReadErrorResponse(err, response_buf);
            };
            const body_or_null: ?[]const u8 = if (body.len > 0) body else null;

            // Route to appropriate handler
            if (std.mem.eql(u8, request.path, "/routes/add")) {
                const result = routes.handleRoutesAdd(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/routes/remove")) {
                const result = routes.handleRoutesRemove(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/pools/add")) {
                const result = pools.handlePoolsAdd(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/pools/remove")) {
                const result = pools.handlePoolsRemove(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/upstreams/add")) {
                const result = upstreams.handleUpstreamsAdd(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/upstreams/remove")) {
                const result = upstreams.handleUpstreamsRemove(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }
        }

        return .{ .send_response = .{
            .status = 404,
            .body = "Not Found",
            .content_type = "text/plain",
        } };
    }
};

/// Create error response for body read failures.
fn makeBodyReadErrorResponse(err: anyerror, response_buf: []u8) serval.Action {
    const error_msg = switch (err) {
        error.BodyReaderNotAvailable => "body reader not available",
        error.BodyTooLarge => "request body too large",
        error.ReadFailed => "failed to read request body",
        error.ChunkedNotSupported => "chunked encoding not supported",
        error.BodyReaderNotConfigured => "body reader not configured",
        else => "body read failed",
    };
    _ = std.fmt.bufPrint(response_buf, "{{\"error\":\"{s}\"}}", .{error_msg}) catch {
        // TigerStyle: Use comptime error string on buffer overflow
        return .{ .send_response = .{
            .status = 400,
            .body = json.response.errors.buffer_overflow,
            .content_type = "application/json",
        } };
    };
    const status: u16 = if (err == error.BodyTooLarge) 413 else 400;
    return .{ .send_response = .{
        .status = status,
        .body = response_buf[0..std.fmt.count("{{\"error\":\"{s}\"}}", .{error_msg})],
        .content_type = "application/json",
    } };
}
