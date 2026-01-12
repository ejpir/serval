// examples/router/admin/pools.zig
//! Pool Admin Handlers
//!
//! Handlers for pool CRUD operations via admin API.
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

const AddPoolJson = json.AddPoolJson;
const RemovePoolJson = json.RemovePoolJson;
const MAX_JSON_BODY_SIZE = json.MAX_JSON_BODY_SIZE;
const RouteUpdateResult = routes_handler.RouteUpdateResult;

/// Handle POST /pools/add - add a new pool with upstreams.
/// TigerStyle: Bounded buffers, explicit error handling.
pub fn handlePoolsAdd(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const validation = response.validateBody(body, MAX_JSON_BODY_SIZE);
    const request_body = switch (validation) {
        .valid => |b| b,
        .err => |e| return .{ .status = e.status, .body = e.body },
    };

    // Get current router
    const router = config_storage.getActiveRouter() orelse {
        return .{ .status = 503, .body = response.errors.no_router };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(AddPoolJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{ .status = 400, .body = response.errors.json_parse };
    };
    defer parsed.deinit();

    const add_pool = parsed.value;

    // Validate upstreams
    if (add_pool.upstreams.len == 0) {
        return .{ .status = 400, .body = response.errors.pool_no_upstreams };
    }

    if (add_pool.upstreams.len > config.MAX_UPSTREAMS_PER_POOL) {
        return .{ .status = 400, .body = response.errors.pool_too_many_upstreams };
    }

    // Check for duplicate pool name
    for (router.pools) |*pool| {
        if (std.mem.eql(u8, pool.name, add_pool.name)) {
            return .{ .status = 409, .body = response.errors.pool_exists };
        }
    }

    // Check if we would exceed max pools
    if (router.pools.len >= config.MAX_POOLS) {
        return .{ .status = 400, .body = response.errors.max_pools };
    }

    // Build new config with added pool
    var route_storage: [config.MAX_ROUTES]Route = undefined;
    var pool_storage: [config.MAX_POOLS]PoolConfig = undefined;
    var upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined;

    // Copy existing routes
    for (router.routes, 0..) |route, i| {
        route_storage[i] = route;
    }
    const routes: []const Route = route_storage[0..router.routes.len];

    // Copy existing pools
    for (router.pools, 0..) |*pool, i| {
        for (pool.lb_handler.upstreams, 0..) |upstream, j| {
            upstream_storage[i][j] = upstream;
        }
        pool_storage[i] = PoolConfig{
            .name = pool.name,
            .upstreams = upstream_storage[i][0..pool.lb_handler.upstreams.len],
            .lb_config = .{ .enable_probing = false },
        };
    }

    // Add new pool at the end
    const new_pool_idx = router.pools.len;
    for (add_pool.upstreams, 0..) |upstream_json, j| {
        // Validate idx fits in UpstreamIndex
        if (upstream_json.idx > std.math.maxInt(config.UpstreamIndex)) {
            return .{ .status = 400, .body = response.errors.upstream_idx_max };
        }

        upstream_storage[new_pool_idx][j] = Upstream{
            .host = upstream_json.host,
            .port = upstream_json.port,
            .idx = @intCast(upstream_json.idx),
            .tls = upstream_json.tls,
        };
    }

    pool_storage[new_pool_idx] = PoolConfig{
        .name = add_pool.name,
        .upstreams = upstream_storage[new_pool_idx][0..add_pool.upstreams.len],
        .lb_config = .{
            .enable_probing = add_pool.lb_config.enable_probing,
            .unhealthy_threshold = add_pool.lb_config.unhealthy_threshold,
            .healthy_threshold = add_pool.lb_config.healthy_threshold,
            .probe_interval_ms = add_pool.lb_config.probe_interval_ms,
            .probe_timeout_ms = add_pool.lb_config.probe_timeout_ms,
            .health_path = add_pool.lb_config.health_path,
        },
    };

    const pools: []const PoolConfig = pool_storage[0 .. router.pools.len + 1];

    // Swap to new config (preserve existing allowed_hosts from current router)
    config_storage.swapRouter(routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{ .status = 500, .body = response.errors.swap_failed };
    };

    const generation = config_storage.getRouterGeneration();
    return .{ .status = 200, .body = response.poolAdded(response_buf, generation, new_pool_idx) };
}

/// Handle POST /pools/remove - remove a pool by name.
/// Fails if any routes reference this pool.
/// TigerStyle: Bounded buffers, explicit error handling.
pub fn handlePoolsRemove(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const validation = response.validateBody(body, MAX_JSON_BODY_SIZE);
    const request_body = switch (validation) {
        .valid => |b| b,
        .err => |e| return .{ .status = e.status, .body = e.body },
    };

    // Get current router
    const router = config_storage.getActiveRouter() orelse {
        return .{ .status = 503, .body = response.errors.no_router };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(RemovePoolJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{ .status = 400, .body = response.errors.json_parse };
    };
    defer parsed.deinit();

    const remove_pool = parsed.value;

    // Find pool to remove
    var found_idx: ?usize = null;
    for (router.pools, 0..) |*pool, i| {
        if (std.mem.eql(u8, pool.name, remove_pool.name)) {
            found_idx = i;
            break;
        }
    }

    if (found_idx == null) {
        return .{ .status = 404, .body = response.errors.pool_not_found };
    }

    const pool_idx_to_remove: u8 = @intCast(found_idx.?);

    // Check if any routes reference this pool
    for (router.routes) |route| {
        if (route.pool_idx == pool_idx_to_remove) {
            return .{ .status = 409, .body = response.errors.pool_referenced };
        }
    }

    // Must have at least one pool remaining
    if (router.pools.len <= 1) {
        return .{ .status = 400, .body = response.errors.last_pool };
    }

    // Build new config without the removed pool
    // Note: pool indices shift down, so we need to update route pool_idx values
    var route_storage: [config.MAX_ROUTES]Route = undefined;
    var pool_storage: [config.MAX_POOLS]PoolConfig = undefined;
    var upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined;

    // Copy routes and adjust pool_idx for routes referencing pools after the removed one
    for (router.routes, 0..) |route, i| {
        route_storage[i] = route;
        if (route.pool_idx > pool_idx_to_remove) {
            route_storage[i].pool_idx = route.pool_idx - 1;
        }
    }
    const routes: []const Route = route_storage[0..router.routes.len];

    // Copy pools except the one to remove
    var new_pool_count: usize = 0;
    for (router.pools, 0..) |*pool, i| {
        if (i != found_idx.?) {
            for (pool.lb_handler.upstreams, 0..) |upstream, j| {
                upstream_storage[new_pool_count][j] = upstream;
            }
            pool_storage[new_pool_count] = PoolConfig{
                .name = pool.name,
                .upstreams = upstream_storage[new_pool_count][0..pool.lb_handler.upstreams.len],
                .lb_config = .{ .enable_probing = false },
            };
            new_pool_count += 1;
        }
    }

    const pools: []const PoolConfig = pool_storage[0..new_pool_count];

    // Swap to new config (preserve existing allowed_hosts from current router)
    config_storage.swapRouter(routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{ .status = 500, .body = response.errors.swap_failed };
    };

    const generation = config_storage.getRouterGeneration();
    return .{ .status = 200, .body = response.success(response_buf, generation) };
}
