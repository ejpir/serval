// serval-router/router.zig
//! Content-Based Router
//!
//! Routes requests to backend pools based on host and path matching.
//! Each pool embeds an LbHandler for health-aware load balancing.
//!
//! Features:
//! - Host + path matching (exact or prefix)
//! - Path rewriting (strip prefix before forwarding)
//! - Per-pool load balancing with health tracking
//! - First-match routing with explicit default route
//!
//! TigerStyle: No allocation after init, bounded loops, explicit types.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const net = @import("serval-net");
const lb = @import("serval-lb");
const ssl_mod = @import("serval-tls");
const types = @import("types.zig");

const config = core.config;
const Context = core.Context;
const Request = core.Request;
const Upstream = core.Upstream;
const LogEntry = core.LogEntry;
const LbHandler = lb.LbHandler;
const LbConfig = lb.LbConfig;
const DnsResolver = net.DnsResolver;
const ssl = ssl_mod.ssl;

const Route = types.Route;
const RouteMatcher = types.RouteMatcher;
const PathMatch = types.PathMatch;
const PoolConfig = types.PoolConfig;

// Re-export routing limits from config (single source of truth).
pub const MAX_POOLS = config.MAX_POOLS;
pub const MAX_ROUTES = config.MAX_ROUTES;

/// Content-based router with per-pool load balancing.
///
/// Routes incoming requests to backend pools based on host and path matching.
/// Each pool has its own LbHandler for health-aware upstream selection.
///
/// TigerStyle: Fixed-size embedded storage, no heap allocation after init.
pub const Router = struct {
    /// Route table (evaluated in order, first match wins).
    routes: []const Route,
    /// Default route when no match found.
    default_route: Route,
    /// Backend pools (indexed by Route.pool_idx).
    pools: []Pool,
    /// Embedded storage for pools (avoids heap allocation).
    pool_storage: [MAX_POOLS]Pool = undefined,

    const Self = @This();

    /// A backend pool with embedded load balancer.
    pub const Pool = struct {
        /// Pool name for logging/debugging.
        name: []const u8,
        /// Load balancer handler for health-aware upstream selection.
        lb_handler: LbHandler,
    };

    /// Initialize router with routes and backend pools.
    ///
    /// TigerStyle C3: Out-pointer for stable addresses (LbHandler has prober thread).
    /// Caller must ensure routes and pool_configs remain valid for Router lifetime.
    ///
    /// Arguments:
    ///   self: Out-pointer for Router instance (caller owns storage).
    ///   routes: Route table (evaluated in order, first match wins).
    ///   default_route: Fallback route when no match found.
    ///   pool_configs: Backend pool configurations (one per pool_idx).
    ///   client_ctx: SSL_CTX for TLS health probes (null if all upstreams are plaintext).
    ///   dns_resolver: DNS resolver for hostname resolution in health probes.
    ///                 Required if any pool has probing enabled. Caller owns lifetime.
    ///
    /// Errors:
    ///   error.TooManyPools: pool_configs.len > MAX_POOLS
    ///   error.TooManyRoutes: routes.len > MAX_ROUTES
    ///   error.InvalidPoolIndex: Route references non-existent pool
    ///   error.EmptyPool: Pool has no upstreams
    ///   (+ any errors from LbHandler.init)
    pub fn init(
        self: *Self,
        routes: []const Route,
        default_route: Route,
        pool_configs: []const PoolConfig,
        client_ctx: ?*ssl.SSL_CTX,
        dns_resolver: ?*DnsResolver,
    ) !void {
        // Preconditions
        assert(pool_configs.len > 0); // S1: At least one pool required
        assert(routes.len <= MAX_ROUTES); // S1: Route count within bounds

        // Validate pool count
        if (pool_configs.len > MAX_POOLS) {
            return error.TooManyPools;
        }

        // Validate route count
        if (routes.len > MAX_ROUTES) {
            return error.TooManyRoutes;
        }

        // Validate all route pool indices before initialization
        for (routes) |route| {
            if (route.pool_idx >= pool_configs.len) {
                return error.InvalidPoolIndex;
            }
        }
        if (default_route.pool_idx >= pool_configs.len) {
            return error.InvalidPoolIndex;
        }

        // Validate pool configurations
        for (pool_configs) |cfg| {
            if (cfg.upstreams.len == 0) {
                return error.EmptyPool;
            }
        }

        self.routes = routes;
        self.default_route = default_route;

        // Initialize pools with embedded LbHandlers
        var initialized_count: usize = 0;
        errdefer {
            // Cleanup already-initialized pools on error
            for (self.pool_storage[0..initialized_count]) |*pool| {
                pool.lb_handler.deinit();
            }
        }

        for (pool_configs, 0..) |cfg, i| {
            assert(i < MAX_POOLS); // S1: Loop invariant
            self.pool_storage[i].name = cfg.name;
            try self.pool_storage[i].lb_handler.init(
                cfg.upstreams,
                cfg.lb_config,
                client_ctx,
                dns_resolver,
            );
            initialized_count += 1;
        }

        self.pools = self.pool_storage[0..pool_configs.len];

        // Postconditions
        assert(self.pools.len == pool_configs.len); // S2: All pools initialized
        assert(self.pools.len > 0); // S2: At least one pool
    }

    /// Clean up all pools and stop background probers.
    pub fn deinit(self: *Self) void {
        for (self.pools) |*pool| {
            pool.lb_handler.deinit();
        }
    }

    /// Handler interface: select upstream for request.
    ///
    /// Matches request against routes (first match wins), then delegates
    /// to the matched pool's LbHandler for health-aware upstream selection.
    ///
    /// Sets ctx.rewritten_path if route has strip_prefix enabled.
    ///
    /// TigerStyle: Bounded loop (MAX_ROUTES), no allocation.
    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Upstream {
        assert(self.pools.len > 0); // S1: Router initialized

        const route = self.findRoute(request);

        // Store rewritten path if strip_prefix enabled
        ctx.rewritten_path = self.rewritePath(route, request.path);

        // Delegate to pool's LbHandler for health-aware selection
        assert(route.pool_idx < self.pools.len); // S1: Valid pool index
        return self.pools[route.pool_idx].lb_handler.selectUpstream(ctx, request);
    }

    /// Handler interface: forward health tracking to correct pool.
    ///
    /// Finds the pool that owns the upstream and forwards the log entry
    /// for passive health tracking (5xx = failure).
    ///
    /// TigerStyle: Bounded loops (MAX_POOLS * MAX_UPSTREAMS).
    pub fn onLog(self: *Self, ctx: *Context, entry: LogEntry) void {
        const upstream = entry.upstream orelse return;

        // Find which pool owns this upstream and forward onLog
        // TigerStyle S3: Bounded outer loop (MAX_POOLS)
        for (self.pools) |*pool| {
            // TigerStyle S3: Bounded inner loop (MAX_UPSTREAMS per pool)
            for (pool.lb_handler.upstreams, 0..) |u, local_idx| {
                if (u.idx == upstream.idx) {
                    // Create modified entry with local pool index for health tracking.
                    // The LbHandler uses upstream.idx as the health state index, which
                    // must be within the pool's backend_count (0..upstreams.len-1).
                    var local_upstream = u;
                    local_upstream.idx = @intCast(local_idx);

                    var local_entry = entry;
                    local_entry.upstream = local_upstream;

                    pool.lb_handler.onLog(ctx, local_entry);
                    return;
                }
            }
        }
        // Upstream not found in any pool - ignore (may be from different handler)
    }

    /// Find matching route. Returns default_route if no match.
    ///
    /// Routes are evaluated in order; first match wins.
    /// TigerStyle S3: Bounded loop (routes.len <= MAX_ROUTES).
    fn findRoute(self: *const Self, request: *const Request) *const Route {
        assert(self.routes.len <= MAX_ROUTES); // S1: Bounded

        const host = request.headers.get("Host");
        const path = request.path;

        // TigerStyle S3: Bounded loop, explicit exit
        for (self.routes) |*route| {
            if (route.matcher.matches(host, path)) {
                return route;
            }
        }

        return &self.default_route;
    }

    /// Rewrite path if route has strip_prefix enabled.
    ///
    /// Returns null if no rewrite needed (use original path).
    /// For prefix matches with strip_prefix=true, removes the matched
    /// prefix from the path, ensuring result starts with '/'.
    ///
    /// Examples (prefix="/api/"):
    ///   "/api/users" -> "/users"
    ///   "/api/"      -> "/"
    ///   "/api"       -> "/" (prefix matched without trailing slash)
    ///
    /// TigerStyle: No allocation, returns slice into original path or static "/".
    fn rewritePath(self: *const Self, route: *const Route, original_path: []const u8) ?[]const u8 {
        _ = self;

        if (!route.strip_prefix) {
            return null; // No rewrite needed
        }

        return switch (route.matcher.path) {
            .prefix => |prefix| blk: {
                assert(prefix.len > 0); // S1: Prefix must be non-empty

                // Path shorter than or equal to prefix - return root
                if (original_path.len <= prefix.len) {
                    break :blk "/";
                }

                const stripped = original_path[prefix.len..];

                // Empty after strip - return root
                if (stripped.len == 0) {
                    break :blk "/";
                }

                // Already starts with '/' - return as-is
                if (stripped[0] == '/') {
                    break :blk stripped;
                }

                // Prefix didn't end with '/', need to include the '/'
                // e.g., prefix="/api", path="/api/users" -> stripped="users"
                // We want "/users", so back up one character to get the '/'
                if (prefix.len > 0 and original_path.len > prefix.len - 1) {
                    break :blk original_path[prefix.len - 1 ..];
                }

                break :blk "/";
            },
            .exact => null, // Exact match: strip_prefix is no-op (path must match exactly)
        };
    }

    /// Get pool by index (for observability/testing).
    pub fn getPool(self: *const Self, idx: u8) ?*const Pool {
        if (idx >= self.pools.len) {
            return null;
        }
        return &self.pools[idx];
    }

    /// Count total healthy backends across all pools.
    pub fn countTotalHealthy(self: *const Self) u32 {
        var total: u32 = 0;
        for (self.pools) |*pool| {
            total += pool.lb_handler.countHealthy();
        }
        return total;
    }

    /// Count total backends across all pools.
    pub fn countTotalBackends(self: *const Self) u32 {
        var total: u32 = 0;
        for (self.pools) |pool| {
            total += @intCast(pool.lb_handler.upstreams.len);
        }
        return total;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Router findRoute matches first route" {
    // Setup: Two routes, both could match, first should win
    const routes = [_]Route{
        .{
            .name = "api-v1",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
        },
        .{
            .name = "api-v2",
            .matcher = .{ .path = .{ .prefix = "/api/v2/" } },
            .pool_idx = 1,
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
        .{ .name = "pool-1", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    // Request that matches both routes
    const request = Request{ .path = "/api/v2/users" };
    const matched = router.findRoute(&request);

    // First match wins (api-v1, not api-v2)
    try std.testing.expectEqualStrings("api-v1", matched.name);
}

test "Router findRoute returns default when no match" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .host = "api.example.com", .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    // Request that doesn't match (wrong host)
    var request = Request{ .path = "/api/users" };
    try request.headers.put("Host", "www.example.com");

    const matched = router.findRoute(&request);
    try std.testing.expectEqualStrings("default", matched.name);
}

test "Router rewritePath strips prefix" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
            .strip_prefix = true,
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    // Test: "/api/users" -> "/users"
    const route = &routes[0];
    const rewritten = router.rewritePath(route, "/api/users");
    try std.testing.expectEqualStrings("/users", rewritten.?);
}

test "Router rewritePath returns root for exact prefix match" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
            .strip_prefix = true,
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    // Test: "/api/" -> "/"
    const route = &routes[0];
    const rewritten = router.rewritePath(route, "/api/");
    try std.testing.expectEqualStrings("/", rewritten.?);
}

test "Router rewritePath returns null when strip_prefix is false" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
            .strip_prefix = false, // No stripping
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    const route = &routes[0];
    const rewritten = router.rewritePath(route, "/api/users");
    try std.testing.expect(rewritten == null);
}

test "Router rewritePath returns null for exact match" {
    const routes = [_]Route{
        .{
            .name = "health",
            .matcher = .{ .path = .{ .exact = "/health" } },
            .pool_idx = 0,
            .strip_prefix = true, // Should be ignored for exact matches
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    const route = &routes[0];
    const rewritten = router.rewritePath(route, "/health");
    try std.testing.expect(rewritten == null);
}

test "Router init validates pool index" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 5, // Invalid: only 1 pool
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    const result = router.init(&routes, default_route, &pool_configs, null, null);
    try std.testing.expectError(error.InvalidPoolIndex, result);
}

test "Router init validates default route pool index" {
    const routes = [_]Route{};

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 99, // Invalid
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    const result = router.init(&routes, default_route, &pool_configs, null, null);
    try std.testing.expectError(error.InvalidPoolIndex, result);
}

test "Router selectUpstream sets rewritten_path" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
            .strip_prefix = true,
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    var ctx = Context.init();
    const request = Request{ .path = "/api/users" };

    _ = router.selectUpstream(&ctx, &request);

    // rewritten_path should be set
    try std.testing.expectEqualStrings("/users", ctx.rewritten_path.?);
}

test "Router selectUpstream delegates to pool LbHandler" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
        },
        .{
            .name = "static",
            .matcher = .{ .path = .{ .prefix = "/static/" } },
            .pool_idx = 1,
        },
    };

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const api_upstreams = [_]Upstream{
        .{ .host = "api-1", .port = 8001, .idx = 0 },
        .{ .host = "api-2", .port = 8002, .idx = 1 },
    };

    const static_upstreams = [_]Upstream{
        .{ .host = "static-1", .port = 9001, .idx = 2 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "api-pool", .upstreams = &api_upstreams, .lb_config = .{ .enable_probing = false } },
        .{ .name = "static-pool", .upstreams = &static_upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    var ctx = Context.init();

    // Request to /api/ should go to api-pool
    const api_request = Request{ .path = "/api/users" };
    const api_upstream = router.selectUpstream(&ctx, &api_request);
    try std.testing.expect(std.mem.startsWith(u8, api_upstream.host, "api-"));

    // Request to /static/ should go to static-pool
    const static_request = Request{ .path = "/static/image.png" };
    const static_upstream = router.selectUpstream(&ctx, &static_request);
    try std.testing.expectEqualStrings("static-1", static_upstream.host);
    try std.testing.expectEqual(@as(u16, 9001), static_upstream.port);
}

test "Router countTotalHealthy" {
    const routes = [_]Route{};

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams_pool0 = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
    };

    const upstreams_pool1 = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 9001, .idx = 2 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams_pool0, .lb_config = .{ .enable_probing = false } },
        .{ .name = "pool-1", .upstreams = &upstreams_pool1, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    // All 3 backends should start healthy
    try std.testing.expectEqual(@as(u32, 3), router.countTotalHealthy());
    try std.testing.expectEqual(@as(u32, 3), router.countTotalBackends());
}

test "Router getPool returns pool by index" {
    const routes = [_]Route{};

    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "test-pool", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null, null);
    defer router.deinit();

    const pool = router.getPool(0);
    try std.testing.expect(pool != null);
    try std.testing.expectEqualStrings("test-pool", pool.?.name);

    // Invalid index returns null
    try std.testing.expect(router.getPool(99) == null);
}
