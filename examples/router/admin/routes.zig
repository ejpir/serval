// examples/router/admin/routes.zig
//! Route Admin Handlers
//!
//! Handlers for route CRUD operations via admin API.
//! TigerStyle: Bounded buffers, explicit error handling, validates all input.

const std = @import("std");
const assert = std.debug.assert;

const serval = @import("serval");
const serval_router = @import("serval-router");

const config = serval.config;
const Route = serval_router.Route;
const PoolConfig = serval_router.PoolConfig;
const PathMatch = serval_router.PathMatch;
const Upstream = serval_router.Upstream;

const json = @import("../json/mod.zig");
const response = @import("../json/response.zig");
const config_storage = @import("../config_storage.zig");

const ConfigJson = json.ConfigJson;
const RouteJson = json.RouteJson;
const AddRouteJson = json.AddRouteJson;
const RemoveRouteJson = json.RemoveRouteJson;
const MAX_JSON_BODY_SIZE = json.MAX_JSON_BODY_SIZE;

/// Result of route update operation.
pub const RouteUpdateResult = struct {
    status: u16,
    body: []const u8,
};

/// Handle POST /routes/update - parse JSON and call swapRouter().
/// TigerStyle: Bounded buffer, explicit error handling, validates all input.
pub fn handleRouteUpdate(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    const request_body = body orelse {
        return .{ .status = 400, .body = response.errors.missing_body };
    };

    if (request_body.len == 0) {
        return .{ .status = 400, .body = response.errors.empty_body };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{ .status = 413, .body = response.errors.body_too_large };
    }

    // Parse JSON
    const parsed = std.json.parseFromSlice(ConfigJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{ .status = 400, .body = response.errors.json_parse };
    };
    defer parsed.deinit();

    const json_config = parsed.value;

    // Validate configuration
    if (json_config.pools.len == 0) {
        return .{ .status = 400, .body = response.errors.at_least_one_pool };
    }

    if (json_config.pools.len > config.MAX_POOLS) {
        return .{ .status = 400, .body = response.errors.too_many_pools };
    }

    if (json_config.routes.len > config.MAX_ROUTES) {
        return .{ .status = 400, .body = response.errors.too_many_routes };
    }

    if (json_config.allowed_hosts.len > config.MAX_ALLOWED_HOSTS) {
        return .{ .status = 400, .body = response.errors.too_many_allowed_hosts };
    }

    // Convert JSON config to Route[] and PoolConfig[] with storage
    var route_storage: [config.MAX_ROUTES]Route = undefined;
    var pool_storage: [config.MAX_POOLS]PoolConfig = undefined;
    var upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined;

    // Convert allowed_hosts (simple copy of slices, they point to parsed JSON)
    var allowed_hosts: [config.MAX_ALLOWED_HOSTS][]const u8 = undefined;
    const allowed_hosts_count = @min(json_config.allowed_hosts.len, config.MAX_ALLOWED_HOSTS);
    for (json_config.allowed_hosts[0..allowed_hosts_count], 0..) |host, i| {
        allowed_hosts[i] = host;
    }
    const allowed_hosts_slice: []const []const u8 = allowed_hosts[0..allowed_hosts_count];

    // Convert routes
    std.log.debug("handleRouteUpdate: converting {d} routes", .{json_config.routes.len});
    for (json_config.routes, 0..) |route_json, i| {
        if (route_json.pool_idx >= json_config.pools.len) {
            return .{ .status = 400, .body = response.errors.invalid_pool_idx };
        }

        // Validate exactly one of path_prefix or path_exact is set.
        // TigerStyle: Explicit validation at API boundary.
        const path_match: PathMatch = if (route_json.path_exact) |exact|
            .{ .exact = exact }
        else if (route_json.path_prefix) |prefix|
            .{ .prefix = prefix }
        else {
            return .{ .status = 400, .body = response.errors.route_needs_path };
        };

        std.log.debug("handleRouteUpdate: route[{d}] name={s} host={s} path={s} pool_idx={d}", .{
            i,
            route_json.name,
            route_json.host orelse "(null)",
            path_match.getPattern(),
            route_json.pool_idx,
        });

        route_storage[i] = Route{
            .name = route_json.name,
            .matcher = .{
                .host = route_json.host,
                .path = path_match,
            },
            .pool_idx = route_json.pool_idx,
            .strip_prefix = route_json.strip_prefix,
        };
    }
    const routes: []const Route = route_storage[0..json_config.routes.len];

    // Convert pools
    std.log.debug("handleRouteUpdate: converting {d} pools", .{json_config.pools.len});
    for (json_config.pools, 0..) |pool_json, i| {
        if (pool_json.upstreams.len == 0) {
            return .{ .status = 400, .body = response.errors.pool_no_upstreams };
        }

        if (pool_json.upstreams.len > config.MAX_UPSTREAMS_PER_POOL) {
            return .{ .status = 400, .body = response.errors.pool_too_many_upstreams };
        }

        std.log.debug("handleRouteUpdate: pool[{d}] name={s} upstreams={d}", .{
            i,
            pool_json.name,
            pool_json.upstreams.len,
        });

        // Convert upstreams for this pool
        for (pool_json.upstreams, 0..) |upstream_json, j| {
            // Validate idx fits in UpstreamIndex
            if (upstream_json.idx > std.math.maxInt(config.UpstreamIndex)) {
                return .{ .status = 400, .body = response.errors.upstream_idx_max };
            }

            std.log.debug("handleRouteUpdate: pool[{d}] upstream[{d}] host={s} port={d}", .{
                i,
                j,
                upstream_json.host,
                upstream_json.port,
            });

            upstream_storage[i][j] = Upstream{
                .host = upstream_json.host,
                .port = upstream_json.port,
                .idx = @intCast(upstream_json.idx),
                .tls = upstream_json.tls,
            };
        }

        pool_storage[i] = PoolConfig{
            .name = pool_json.name,
            .upstreams = upstream_storage[i][0..pool_json.upstreams.len],
            .lb_config = .{
                .enable_probing = pool_json.lb_config.enable_probing,
                .unhealthy_threshold = pool_json.lb_config.unhealthy_threshold,
                .healthy_threshold = pool_json.lb_config.healthy_threshold,
                .probe_interval_ms = pool_json.lb_config.probe_interval_ms,
                .probe_timeout_ms = pool_json.lb_config.probe_timeout_ms,
                .health_path = pool_json.lb_config.health_path,
            },
        };
    }
    const pools: []const PoolConfig = pool_storage[0..json_config.pools.len];

    std.log.debug("handleRouteUpdate: calling swapRouter with {d} routes, {d} pools, {d} allowed_hosts", .{
        routes.len,
        pools.len,
        allowed_hosts_slice.len,
    });

    // Call swapRouter to atomically update configuration
    config_storage.swapRouter(routes, pools, allowed_hosts_slice, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{ .status = 500, .body = response.errors.swap_failed };
    };

    // Verify the swap worked by loading the new router
    const new_router = config_storage.getActiveRouter();
    if (new_router) |r| {
        std.log.info("handleRouteUpdate: config swap successful - new router has {d} routes, {d} allowed_hosts", .{
            r.routes.len,
            r.allowed_hosts.len,
        });
    } else {
        std.log.err("handleRouteUpdate: swap succeeded but current_router is null!", .{});
    }

    const generation = config_storage.getRouterGeneration();
    return .{ .status = 200, .body = response.success(response_buf, generation) };
}

/// Handle POST /routes/add - add a single route to existing config.
/// TigerStyle: Bounded buffers, explicit error handling, validates all input.
pub fn handleRoutesAdd(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
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
    const parsed = std.json.parseFromSlice(AddRouteJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{ .status = 400, .body = response.errors.json_parse };
    };
    defer parsed.deinit();

    const add_route = parsed.value;

    // Validate pool_idx
    if (add_route.pool_idx >= router.pools.len) {
        return .{ .status = 400, .body = response.errors.invalid_pool_idx };
    }

    // Check for duplicate route name
    for (router.routes) |route| {
        if (std.mem.eql(u8, route.name, add_route.name)) {
            return .{ .status = 409, .body = response.errors.route_exists };
        }
    }

    // Check if we would exceed max routes
    if (router.routes.len >= config.MAX_ROUTES) {
        return .{ .status = 400, .body = response.errors.max_routes };
    }

    // Build new config with added route
    var route_storage: [config.MAX_ROUTES]Route = undefined;
    var pool_storage: [config.MAX_POOLS]PoolConfig = undefined;
    var upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined;

    // Copy existing routes
    for (router.routes, 0..) |route, i| {
        route_storage[i] = route;
    }

    // Validate exactly one of path_prefix or path_exact is set.
    const path_match: PathMatch = if (add_route.path_exact) |exact|
        .{ .exact = exact }
    else if (add_route.path_prefix) |prefix|
        .{ .prefix = prefix }
    else {
        return .{ .status = 400, .body = response.errors.route_needs_path };
    };

    // Add new route at the end
    route_storage[router.routes.len] = Route{
        .name = add_route.name,
        .matcher = .{
            .host = add_route.host,
            .path = path_match,
        },
        .pool_idx = add_route.pool_idx,
        .strip_prefix = add_route.strip_prefix,
    };

    const new_routes: []const Route = route_storage[0 .. router.routes.len + 1];

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

    const pools: []const PoolConfig = pool_storage[0..router.pools.len];

    // Swap to new config (preserve existing allowed_hosts from current router)
    config_storage.swapRouter(new_routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{ .status = 500, .body = response.errors.swap_failed };
    };

    const generation = config_storage.getRouterGeneration();
    return .{ .status = 200, .body = response.success(response_buf, generation) };
}

/// Handle POST /routes/remove - remove a route by name.
/// TigerStyle: Bounded buffers, explicit error handling.
pub fn handleRoutesRemove(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
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
    const parsed = std.json.parseFromSlice(RemoveRouteJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{ .status = 400, .body = response.errors.json_parse };
    };
    defer parsed.deinit();

    const remove_route = parsed.value;

    // Find route to remove
    var found_idx: ?usize = null;
    for (router.routes, 0..) |route, i| {
        if (std.mem.eql(u8, route.name, remove_route.name)) {
            found_idx = i;
            break;
        }
    }

    if (found_idx == null) {
        return .{ .status = 404, .body = response.errors.route_not_found };
    }

    // Build new config without the removed route
    var route_storage: [config.MAX_ROUTES]Route = undefined;
    var pool_storage: [config.MAX_POOLS]PoolConfig = undefined;
    var upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined;

    // Copy routes except the one to remove
    var new_route_count: usize = 0;
    for (router.routes, 0..) |route, i| {
        if (i != found_idx.?) {
            route_storage[new_route_count] = route;
            new_route_count += 1;
        }
    }

    const new_routes: []const Route = route_storage[0..new_route_count];

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

    const pools: []const PoolConfig = pool_storage[0..router.pools.len];

    // Swap to new config (preserve existing allowed_hosts from current router)
    config_storage.swapRouter(new_routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{ .status = 500, .body = response.errors.swap_failed };
    };

    const generation = config_storage.getRouterGeneration();
    return .{ .status = 200, .body = response.success(response_buf, generation) };
}
