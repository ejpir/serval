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
/// Generic over Tracer type for tracing config change events.
/// TigerStyle: All state explicit, no hidden dependencies.
pub fn AdminHandler(comptime Tracer: type) type {
    return struct {
        /// Tracer for recording config change events.
        tracer: *Tracer,

        const Self = @This();

        /// Initialize AdminHandler with tracer.
        pub fn init(tracer: *Tracer) Self {
            // S1: Precondition - tracer must be valid
            assert(@intFromPtr(tracer) != 0);
            return .{ .tracer = tracer };
        }

        /// Required by handler interface, but never called (onRequest handles everything).
        pub fn selectUpstream(self: *Self, ctx: *serval.Context, request: *const serval.Request) serval.Upstream {
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
            self: *Self,
            ctx: *serval.Context,
            request: *serval.Request,
            response_buf: []u8,
        ) serval.Action {
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

                // Add tracing events on successful config update
                if (result.status == 200) {
                    self.addConfigUpdateTrace(ctx);
                }

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
                    if (result.status == 200) {
                        self.tracer.addEvent(ctx.span_handle, "route_added");
                    }
                    return .{ .send_response = .{
                        .status = result.status,
                        .body = result.body,
                        .content_type = "application/json",
                    } };
                }

                if (std.mem.eql(u8, request.path, "/routes/remove")) {
                    const result = routes.handleRoutesRemove(body_or_null, response_buf);
                    if (result.status == 200) {
                        self.tracer.addEvent(ctx.span_handle, "route_removed");
                    }
                    return .{ .send_response = .{
                        .status = result.status,
                        .body = result.body,
                        .content_type = "application/json",
                    } };
                }

                if (std.mem.eql(u8, request.path, "/pools/add")) {
                    const result = pools.handlePoolsAdd(body_or_null, response_buf);
                    if (result.status == 200) {
                        self.tracer.addEvent(ctx.span_handle, "pool_added");
                    }
                    return .{ .send_response = .{
                        .status = result.status,
                        .body = result.body,
                        .content_type = "application/json",
                    } };
                }

                if (std.mem.eql(u8, request.path, "/pools/remove")) {
                    const result = pools.handlePoolsRemove(body_or_null, response_buf);
                    if (result.status == 200) {
                        self.tracer.addEvent(ctx.span_handle, "pool_removed");
                    }
                    return .{ .send_response = .{
                        .status = result.status,
                        .body = result.body,
                        .content_type = "application/json",
                    } };
                }

                if (std.mem.eql(u8, request.path, "/upstreams/add")) {
                    const result = upstreams.handleUpstreamsAdd(body_or_null, response_buf);
                    if (result.status == 200) {
                        self.tracer.addEvent(ctx.span_handle, "upstream_added");
                    }
                    return .{ .send_response = .{
                        .status = result.status,
                        .body = result.body,
                        .content_type = "application/json",
                    } };
                }

                if (std.mem.eql(u8, request.path, "/upstreams/remove")) {
                    const result = upstreams.handleUpstreamsRemove(body_or_null, response_buf);
                    if (result.status == 200) {
                        self.tracer.addEvent(ctx.span_handle, "upstream_removed");
                    }
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

        /// Add tracing event and attributes for config update.
        /// TigerStyle: Extracted for clarity and reuse.
        fn addConfigUpdateTrace(self: *Self, ctx: *serval.Context) void {
            // Add event for the config update
            self.tracer.addEvent(ctx.span_handle, "config_updated");

            // Get current router state for attributes
            const router = config_storage.getActiveRouter() orelse return;
            const generation = config_storage.getRouterGeneration();

            // Add config attributes
            // TigerStyle: i64 cast is safe since generation fits in i64 (u64 -> i64)
            self.tracer.setIntAttribute(ctx.span_handle, "config.generation", @intCast(generation));
            self.tracer.setIntAttribute(ctx.span_handle, "routes.count", @intCast(router.routes.len));
            self.tracer.setIntAttribute(ctx.span_handle, "pools.count", @intCast(router.pools.len));

            // Add route names (comma-separated, truncated to fit attribute limit)
            var route_names_buf: [256]u8 = undefined;
            var route_names_len: usize = 0;
            for (router.routes, 0..) |route, i| {
                if (i > 0 and route_names_len < route_names_buf.len - 1) {
                    route_names_buf[route_names_len] = ',';
                    route_names_len += 1;
                }
                const name = route.name;
                const copy_len = @min(name.len, route_names_buf.len - route_names_len);
                if (copy_len == 0) break;
                @memcpy(route_names_buf[route_names_len..][0..copy_len], name[0..copy_len]);
                route_names_len += copy_len;
            }
            if (route_names_len > 0) {
                self.tracer.setStringAttribute(ctx.span_handle, "routes.names", route_names_buf[0..route_names_len]);
            }

            // Add pool names (comma-separated, truncated to fit attribute limit)
            var pool_names_buf: [256]u8 = undefined;
            var pool_names_len: usize = 0;
            for (router.pools, 0..) |pool, i| {
                if (i > 0 and pool_names_len < pool_names_buf.len - 1) {
                    pool_names_buf[pool_names_len] = ',';
                    pool_names_len += 1;
                }
                const name = pool.name;
                const copy_len = @min(name.len, pool_names_buf.len - pool_names_len);
                if (copy_len == 0) break;
                @memcpy(pool_names_buf[pool_names_len..][0..copy_len], name[0..copy_len]);
                pool_names_len += copy_len;
            }
            if (pool_names_len > 0) {
                self.tracer.setStringAttribute(ctx.span_handle, "pools.names", pool_names_buf[0..pool_names_len]);
            }

            // Add upstream count and list (host:port, truncated to fit)
            var upstream_count: usize = 0;
            for (router.pools) |pool| {
                upstream_count += pool.lb_handler.upstreams.len;
            }
            self.tracer.setIntAttribute(ctx.span_handle, "upstreams.count", @intCast(upstream_count));

            // Format upstreams as "host:port,host:port,..."
            var upstreams_buf: [256]u8 = undefined;
            var upstreams_len: usize = 0;
            var first: bool = true;
            outer: for (router.pools) |pool| {
                for (pool.lb_handler.upstreams) |upstream| {
                    if (!first and upstreams_len < upstreams_buf.len - 1) {
                        upstreams_buf[upstreams_len] = ',';
                        upstreams_len += 1;
                    }
                    first = false;
                    // Format "host:port"
                    const formatted = std.fmt.bufPrint(
                        upstreams_buf[upstreams_len..],
                        "{s}:{d}",
                        .{ upstream.host, upstream.port },
                    ) catch break :outer;
                    upstreams_len += formatted.len;
                }
            }
            if (upstreams_len > 0) {
                self.tracer.setStringAttribute(ctx.span_handle, "upstreams.list", upstreams_buf[0..upstreams_len]);
            }
        }
    };
}

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
