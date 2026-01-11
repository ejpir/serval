// examples/router/admin/upstreams.zig
//! Upstream Admin Handlers
//!
//! Handlers for upstream CRUD operations via admin API.
//! TigerStyle: Bounded buffers, explicit error handling, validates all input.

const std = @import("std");
const assert = std.debug.assert;

const serval = @import("serval");
const serval_router = @import("serval-router");

const config = serval.config;
const Route = serval_router.Route;
const PoolConfig = serval_router.PoolConfig;
const Upstream = serval_router.Upstream;

const json = @import("../json/mod.zig");
const response = @import("../json/response.zig");
const config_storage = @import("../config_storage.zig");
const routes_handler = @import("routes.zig");

const AddUpstreamJson = json.AddUpstreamJson;
const RemoveUpstreamJson = json.RemoveUpstreamJson;
const MAX_JSON_BODY_SIZE = json.MAX_JSON_BODY_SIZE;
const RouteUpdateResult = routes_handler.RouteUpdateResult;

/// Handle POST /upstreams/add - add an upstream to an existing pool.
/// TigerStyle: Bounded buffers, explicit error handling.
pub fn handleUpstreamsAdd(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const request_body = body orelse {
        return .{ .status = 400, .body = response.errors.missing_body };
    };

    if (request_body.len == 0) {
        return .{ .status = 400, .body = response.errors.empty_body };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{ .status = 413, .body = response.errors.body_too_large };
    }

    // Get current router
    const router = config_storage.getActiveRouter() orelse {
        return .{ .status = 503, .body = response.errors.no_router };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(AddUpstreamJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{ .status = 400, .body = response.errors.json_parse };
    };
    defer parsed.deinit();

    const add_upstream = parsed.value;

    // Find pool by name
    var found_pool_idx: ?usize = null;
    for (router.pools, 0..) |*pool, i| {
        if (std.mem.eql(u8, pool.name, add_upstream.pool_name)) {
            found_pool_idx = i;
            break;
        }
    }

    if (found_pool_idx == null) {
        return .{ .status = 404, .body = response.errors.pool_not_found };
    }

    const pool_idx = found_pool_idx.?;
    const target_pool = &router.pools[pool_idx];

    // Check if we would exceed max upstreams
    if (target_pool.lb_handler.upstreams.len >= config.MAX_UPSTREAMS_PER_POOL) {
        return .{ .status = 400, .body = response.errors.max_upstreams };
    }

    // Validate idx fits in UpstreamIndex
    if (add_upstream.idx > std.math.maxInt(config.UpstreamIndex)) {
        return .{ .status = 400, .body = response.errors.upstream_idx_max };
    }

    // Check for duplicate upstream idx in pool
    for (target_pool.lb_handler.upstreams) |upstream| {
        if (upstream.idx == @as(config.UpstreamIndex, @intCast(add_upstream.idx))) {
            return .{ .status = 409, .body = response.errors.upstream_exists };
        }
    }

    // Build new config with added upstream
    var route_storage: [config.MAX_ROUTES]Route = undefined;
    var pool_storage: [config.MAX_POOLS]PoolConfig = undefined;
    var upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined;

    // Copy existing routes
    for (router.routes, 0..) |route, i| {
        route_storage[i] = route;
    }
    const routes: []const Route = route_storage[0..router.routes.len];

    // Copy existing pools, adding upstream to target pool
    for (router.pools, 0..) |*pool, i| {
        for (pool.lb_handler.upstreams, 0..) |upstream, j| {
            upstream_storage[i][j] = upstream;
        }

        var upstreams_len = pool.lb_handler.upstreams.len;

        // Add new upstream to target pool
        if (i == pool_idx) {
            upstream_storage[i][upstreams_len] = Upstream{
                .host = add_upstream.host,
                .port = add_upstream.port,
                .idx = @intCast(add_upstream.idx),
                .tls = add_upstream.tls,
            };
            upstreams_len += 1;
        }

        pool_storage[i] = PoolConfig{
            .name = pool.name,
            .upstreams = upstream_storage[i][0..upstreams_len],
            .lb_config = .{ .enable_probing = false },
        };
    }

    const pools: []const PoolConfig = pool_storage[0..router.pools.len];

    // Swap to new config (preserve existing allowed_hosts from current router)
    config_storage.swapRouter(routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{ .status = 500, .body = response.errors.swap_failed };
    };

    const generation = config_storage.getRouterGeneration();
    return .{ .status = 200, .body = response.success(response_buf, generation) };
}

/// Handle POST /upstreams/remove - remove an upstream from a pool.
/// TigerStyle: Bounded buffers, explicit error handling.
pub fn handleUpstreamsRemove(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const request_body = body orelse {
        return .{ .status = 400, .body = response.errors.missing_body };
    };

    if (request_body.len == 0) {
        return .{ .status = 400, .body = response.errors.empty_body };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{ .status = 413, .body = response.errors.body_too_large };
    }

    // Get current router
    const router = config_storage.getActiveRouter() orelse {
        return .{ .status = 503, .body = response.errors.no_router };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(RemoveUpstreamJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{ .status = 400, .body = response.errors.json_parse };
    };
    defer parsed.deinit();

    const remove_upstream = parsed.value;

    // Find pool by name
    var found_pool_idx: ?usize = null;
    for (router.pools, 0..) |*pool, i| {
        if (std.mem.eql(u8, pool.name, remove_upstream.pool_name)) {
            found_pool_idx = i;
            break;
        }
    }

    if (found_pool_idx == null) {
        return .{ .status = 404, .body = response.errors.pool_not_found };
    }

    const pool_idx = found_pool_idx.?;
    const target_pool = &router.pools[pool_idx];

    // Validate upstream_idx fits in UpstreamIndex
    if (remove_upstream.upstream_idx > std.math.maxInt(config.UpstreamIndex)) {
        return .{ .status = 400, .body = response.errors.upstream_idx_max };
    }

    // Find upstream by idx
    var found_upstream_idx: ?usize = null;
    for (target_pool.lb_handler.upstreams, 0..) |upstream, i| {
        if (upstream.idx == @as(config.UpstreamIndex, @intCast(remove_upstream.upstream_idx))) {
            found_upstream_idx = i;
            break;
        }
    }

    if (found_upstream_idx == null) {
        return .{ .status = 404, .body = response.errors.upstream_not_found };
    }

    // Must have at least one upstream remaining
    if (target_pool.lb_handler.upstreams.len <= 1) {
        return .{ .status = 400, .body = response.errors.last_upstream };
    }

    // Build new config without the removed upstream
    var route_storage: [config.MAX_ROUTES]Route = undefined;
    var pool_storage: [config.MAX_POOLS]PoolConfig = undefined;
    var upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined;

    // Copy existing routes
    for (router.routes, 0..) |route, i| {
        route_storage[i] = route;
    }
    const routes: []const Route = route_storage[0..router.routes.len];

    // Copy existing pools, removing upstream from target pool
    for (router.pools, 0..) |*pool, i| {
        var new_upstream_count: usize = 0;

        for (pool.lb_handler.upstreams, 0..) |upstream, j| {
            // Skip the upstream to remove (only for target pool)
            if (i == pool_idx and j == found_upstream_idx.?) {
                continue;
            }
            upstream_storage[i][new_upstream_count] = upstream;
            new_upstream_count += 1;
        }

        pool_storage[i] = PoolConfig{
            .name = pool.name,
            .upstreams = upstream_storage[i][0..new_upstream_count],
            .lb_config = .{ .enable_probing = false },
        };
    }

    const pools: []const PoolConfig = pool_storage[0..router.pools.len];

    // Swap to new config (preserve existing allowed_hosts from current router)
    config_storage.swapRouter(routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{ .status = 500, .body = response.errors.swap_failed };
    };

    const generation = config_storage.getRouterGeneration();
    return .{ .status = 200, .body = response.success(response_buf, generation) };
}
