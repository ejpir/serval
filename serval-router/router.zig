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
//! - Host validation (allowed_hosts filtering)
//! - First-match routing (no implicit default)
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
pub const MAX_ALLOWED_HOSTS = config.MAX_ALLOWED_HOSTS;
pub const MAX_HOSTNAME_LEN = config.MAX_HOSTNAME_LEN;

/// Content-based router with per-pool load balancing.
///
/// Routes incoming requests to backend pools based on host and path matching.
/// Each pool has its own LbHandler for health-aware upstream selection.
///
/// TigerStyle: Fixed-size embedded storage, no heap allocation after init.
pub const Router = struct {
    /// Route table (evaluated in order, first match wins).
    routes: []const Route,
    /// Allowed hostnames for this router. Empty = allow any host.
    /// TigerStyle S7: Bounded by MAX_ALLOWED_HOSTS.
    allowed_hosts: []const []const u8 = &.{},
    /// Backend pools (indexed by Route.pool_idx).
    pools: []Pool,
    /// Embedded storage for pools (avoids heap allocation).
    pool_storage: [MAX_POOLS]Pool = undefined,

    const Self = @This();

    /// Action result for selectUpstream.
    /// TigerStyle: Tagged union with explicit variants.
    pub const Action = union(enum) {
        /// Forward to this upstream.
        forward: Upstream,
        /// Reject with status code and body.
        reject: struct {
            status: u16,
            body: []const u8,
        },
    };

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
    /// IMPORTANT: Caller must ensure routes, pool_configs, allowed_hosts, and all
    /// referenced strings remain valid for the lifetime of this Router instance.
    ///
    /// Arguments:
    ///   self: Out-pointer for Router instance (caller owns storage).
    ///   routes: Route table (evaluated in order, first match wins).
    ///   pool_configs: Backend pool configurations (one per pool_idx).
    ///   allowed_hosts: Hostnames this router will serve. Empty = allow any host.
    ///   client_ctx: SSL_CTX for TLS health probes (null if all upstreams are plaintext).
    ///   dns_resolver: DNS resolver for hostname resolution in health probes.
    ///                 Required if any pool has probing enabled. Caller owns lifetime.
    ///
    /// Errors:
    ///   error.TooManyPools: pool_configs.len > MAX_POOLS
    ///   error.TooManyRoutes: routes.len > MAX_ROUTES
    ///   error.TooManyAllowedHosts: allowed_hosts.len > MAX_ALLOWED_HOSTS
    ///   error.InvalidPoolIndex: Route references non-existent pool
    ///   error.EmptyPool: Pool has no upstreams
    ///   (+ any errors from LbHandler.init)
    pub fn init(
        self: *Self,
        routes: []const Route,
        pool_configs: []const PoolConfig,
        allowed_hosts: []const []const u8,
        client_ctx: ?*ssl.SSL_CTX,
        dns_resolver: ?*DnsResolver,
    ) !void {
        // Preconditions
        assert(pool_configs.len > 0); // S1: At least one pool required
        assert(routes.len <= MAX_ROUTES); // S1: Route count within bounds
        assert(allowed_hosts.len <= MAX_ALLOWED_HOSTS); // S1: allowed_hosts within bounds

        // Validate pool count
        if (pool_configs.len > MAX_POOLS) {
            return error.TooManyPools;
        }

        // Validate route count
        if (routes.len > MAX_ROUTES) {
            return error.TooManyRoutes;
        }

        // Validate allowed_hosts count
        if (allowed_hosts.len > MAX_ALLOWED_HOSTS) {
            return error.TooManyAllowedHosts;
        }

        // Validate all route pool indices before initialization
        for (routes) |route| {
            if (route.pool_idx >= pool_configs.len) {
                return error.InvalidPoolIndex;
            }
        }

        // Validate pool configurations
        for (pool_configs) |cfg| {
            if (cfg.upstreams.len == 0) {
                return error.EmptyPool;
            }
        }

        // Store route and allowed_hosts pointers (caller ensures data remains valid).
        self.routes = routes;
        self.allowed_hosts = allowed_hosts;

        // Initialize pools with embedded LbHandlers.
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
        assert(self.routes.len == routes.len); // S2: All routes copied
        assert(self.pools.len == pool_configs.len); // S2: All pools initialized
        assert(self.pools.len > 0); // S2: At least one pool
        assert(self.allowed_hosts.len == allowed_hosts.len); // S2: allowed_hosts stored
    }

    /// Clean up all pools and stop background probers.
    pub fn deinit(self: *Self) void {
        for (self.pools) |*pool| {
            pool.lb_handler.deinit();
        }
    }

    /// Handler interface: select upstream for request.
    ///
    /// Validates host against allowed_hosts (if configured), matches request
    /// against routes (first match wins), then delegates to the matched pool's
    /// LbHandler for health-aware upstream selection.
    ///
    /// Returns Action.reject for:
    /// - 421 Misdirected Request: Host not in allowed_hosts
    /// - 404 Not Found: No matching route
    ///
    /// Sets ctx.rewritten_path if route has strip_prefix enabled.
    ///
    /// TigerStyle: Bounded loop (MAX_ROUTES), no allocation.
    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Action {
        assert(self.pools.len > 0); // S1: Router initialized
        assert(self.allowed_hosts.len <= MAX_ALLOWED_HOSTS); // S1: Bounds check

        const host = request.headers.getHost();
        std.log.debug("router: selectUpstream host={s} path={s}", .{ host orelse "(no host)", request.path });

        // Validate Host against allowed_hosts (if any configured).
        // RFC 9110 §15.5.20: 421 for requests not intended for this server.
        if (self.allowed_hosts.len > 0) {
            if (!self.isHostAllowed(host)) {
                std.log.debug("router: host not allowed, rejecting with 421", .{});
                return .{ .reject = .{
                    .status = 421,
                    .body = "Misdirected Request",
                } };
            }
        }

        // Find matching route - no default fallback
        const route = self.findRoute(request) orelse {
            std.log.debug("router: no matching route, rejecting with 404", .{});
            return .{ .reject = .{
                .status = 404,
                .body = "Not Found",
            } };
        };
        std.log.debug("router: matched route={s} pool_idx={d}", .{ route.name, route.pool_idx });

        // Store rewritten path if strip_prefix enabled
        ctx.rewritten_path = self.rewritePath(route, request.path);

        // Delegate to pool's LbHandler for health-aware selection
        assert(route.pool_idx < self.pools.len); // S1: Valid pool index
        const upstream = self.pools[route.pool_idx].lb_handler.selectUpstream(ctx, request);
        std.log.debug("router: selected upstream host={s} port={d}", .{ upstream.host, upstream.port });
        return .{ .forward = upstream };
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

    /// Find matching route. Returns null if no match.
    ///
    /// Routes are evaluated in order; first match wins.
    /// TigerStyle S3: Bounded loop (routes.len <= MAX_ROUTES).
    fn findRoute(self: *const Self, request: *const Request) ?*const Route {
        assert(self.routes.len <= MAX_ROUTES); // S1: Bounded

        const host = request.headers.getHost(); // O(1) cached lookup
        const path = request.path;

        std.log.debug("router: findRoute checking {d} routes for host={s} path={s}", .{
            self.routes.len,
            host orelse "(null)",
            path,
        });

        // TigerStyle S3: Bounded loop, explicit exit
        for (self.routes, 0..) |*route, i| {
            const route_host = route.matcher.host orelse "*";
            const route_path = route.matcher.path.getPattern();
            const matched = route.matcher.matches(host, path);
            std.log.debug("router: route[{d}] name={s} host={s} path={s} matched={}", .{
                i,
                route.name,
                route_host,
                route_path,
                matched,
            });
            if (matched) {
                return route;
            }
        }

        std.log.debug("router: no matching route found", .{});
        return null;
    }

    /// Check if Host header matches any allowed hostname.
    /// Returns true if allowed_hosts is empty (allow-all mode).
    ///
    /// RFC 9110 §7.2: Host header may include port, which is stripped.
    /// RFC 9110 §4.2.3: Host comparison is case-insensitive.
    ///
    /// TigerStyle S4: Bounded loop over allowed_hosts.
    fn isHostAllowed(self: *const Self, host: ?[]const u8) bool {
        // S1: Preconditions
        assert(self.allowed_hosts.len <= MAX_ALLOWED_HOSTS);

        // Empty allowed_hosts = allow any host (backwards compatible)
        if (self.allowed_hosts.len == 0) {
            return true;
        }

        const h = host orelse return false;

        // Strip port if present. RFC 9110 §7.2: Host may include port.
        const hostname = if (std.mem.indexOfScalar(u8, h, ':')) |i| h[0..i] else h;

        // S1: Postcondition - hostname length check
        assert(hostname.len <= h.len);

        // S4: Bounded loop
        for (self.allowed_hosts, 0..) |allowed, i| {
            assert(i < MAX_ALLOWED_HOSTS); // S1: Loop invariant
            // RFC 9110 §4.2.3: Host comparison is case-insensitive.
            if (std.ascii.eqlIgnoreCase(allowed, hostname)) {
                return true;
            }
        }
        return false;
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
            return null;
        }

        const prefix = switch (route.matcher.path) {
            .prefix => |p| p,
            .exact => return null, // Exact match: strip_prefix is no-op
        };

        assert(prefix.len > 0); // S1: Prefix must be non-empty

        // Path shorter than or equal to prefix - return root
        if (original_path.len <= prefix.len) {
            return "/";
        }

        const stripped = original_path[prefix.len..];

        // Already starts with '/' - return as-is
        if (stripped[0] == '/') {
            return stripped;
        }

        // Prefix didn't end with '/', back up one char to include the '/'
        // e.g., prefix="/api", path="/api/users" -> "/users"
        return original_path[prefix.len - 1 ..];
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

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
        .{ .name = "pool-1", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    // Request that matches both routes
    const request = Request{ .path = "/api/v2/users" };
    const matched = router.findRoute(&request);

    // First match wins (api-v1, not api-v2)
    try std.testing.expect(matched != null);
    try std.testing.expectEqualStrings("api-v1", matched.?.name);
}

test "Router findRoute returns null when no match" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .host = "api.example.com", .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    // Request that doesn't match (wrong host)
    var request = Request{ .path = "/api/users" };
    try request.headers.put("Host", "www.example.com");

    const matched = router.findRoute(&request);
    try std.testing.expect(matched == null);
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

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
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

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
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

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
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

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
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

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    const result = router.init(&routes, &pool_configs, &.{}, null, null);
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

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    var ctx = Context.init();
    const request = Request{ .path = "/api/users" };

    const action = router.selectUpstream(&ctx, &request);

    // Should forward (route matches)
    try std.testing.expect(action == .forward);

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
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    var ctx = Context.init();

    // Request to /api/ should go to api-pool
    const api_request = Request{ .path = "/api/users" };
    const api_action = router.selectUpstream(&ctx, &api_request);
    try std.testing.expect(api_action == .forward);
    try std.testing.expect(std.mem.startsWith(u8, api_action.forward.host, "api-"));

    // Request to /static/ should go to static-pool
    const static_request = Request{ .path = "/static/image.png" };
    const static_action = router.selectUpstream(&ctx, &static_request);
    try std.testing.expect(static_action == .forward);
    try std.testing.expectEqualStrings("static-1", static_action.forward.host);
    try std.testing.expectEqual(@as(u16, 9001), static_action.forward.port);
}

test "Router selectUpstream returns 404 when no route matches" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    var ctx = Context.init();
    const request = Request{ .path = "/unknown/path" };

    const action = router.selectUpstream(&ctx, &request);

    // Should reject with 404
    try std.testing.expect(action == .reject);
    try std.testing.expectEqual(@as(u16, 404), action.reject.status);
    try std.testing.expectEqualStrings("Not Found", action.reject.body);
}

test "Router countTotalHealthy" {
    // Need at least one route to have a valid router
    const routes = [_]Route{
        .{
            .name = "default",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
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
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    // All 3 backends should start healthy
    try std.testing.expectEqual(@as(u32, 3), router.countTotalHealthy());
    try std.testing.expectEqual(@as(u32, 3), router.countTotalBackends());
}

test "Router getPool returns pool by index" {
    const routes = [_]Route{
        .{
            .name = "default",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "test-pool", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    const pool = router.getPool(0);
    try std.testing.expect(pool != null);
    try std.testing.expectEqualStrings("test-pool", pool.?.name);

    // Invalid index returns null
    try std.testing.expect(router.getPool(99) == null);
}

// =============================================================================
// allowed_hosts Tests
// =============================================================================

test "Router isHostAllowed allows any host when allowed_hosts is empty" {
    const routes = [_]Route{
        .{
            .name = "default",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    // With empty allowed_hosts, any host should be allowed
    try std.testing.expect(router.isHostAllowed("example.com"));
    try std.testing.expect(router.isHostAllowed("any.host.name"));
    try std.testing.expect(router.isHostAllowed(null));
}

test "Router isHostAllowed matches configured hosts" {
    const routes = [_]Route{
        .{
            .name = "default",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    const allowed_hosts = [_][]const u8{ "example.com", "api.example.com" };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &allowed_hosts, null, null);
    defer router.deinit();

    // Allowed hosts should match
    try std.testing.expect(router.isHostAllowed("example.com"));
    try std.testing.expect(router.isHostAllowed("api.example.com"));

    // Non-allowed hosts should not match
    try std.testing.expect(!router.isHostAllowed("other.com"));
    try std.testing.expect(!router.isHostAllowed(null));
}

test "Router isHostAllowed is case-insensitive" {
    const routes = [_]Route{
        .{
            .name = "default",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    const allowed_hosts = [_][]const u8{"Example.COM"};

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &allowed_hosts, null, null);
    defer router.deinit();

    // Case-insensitive matching per RFC 9110 §4.2.3
    try std.testing.expect(router.isHostAllowed("example.com"));
    try std.testing.expect(router.isHostAllowed("EXAMPLE.COM"));
    try std.testing.expect(router.isHostAllowed("Example.Com"));
}

test "Router isHostAllowed strips port from host" {
    const routes = [_]Route{
        .{
            .name = "default",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    const allowed_hosts = [_][]const u8{"example.com"};

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &allowed_hosts, null, null);
    defer router.deinit();

    // Host with port should match after stripping port (RFC 9110 §7.2)
    try std.testing.expect(router.isHostAllowed("example.com:8080"));
    try std.testing.expect(router.isHostAllowed("example.com:443"));
    try std.testing.expect(!router.isHostAllowed("other.com:8080"));
}

test "Router selectUpstream returns 421 for disallowed host" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    const allowed_hosts = [_][]const u8{"allowed.example.com"};

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &allowed_hosts, null, null);
    defer router.deinit();

    var ctx = Context.init();
    var request = Request{ .path = "/api/test" };
    try request.headers.put("Host", "disallowed.example.com");

    const action = router.selectUpstream(&ctx, &request);

    // Should reject with 421 Misdirected Request
    try std.testing.expect(action == .reject);
    try std.testing.expectEqual(@as(u16, 421), action.reject.status);
    try std.testing.expectEqualStrings("Misdirected Request", action.reject.body);
}

test "Router selectUpstream allows request for allowed host" {
    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    const allowed_hosts = [_][]const u8{"allowed.example.com"};

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &allowed_hosts, null, null);
    defer router.deinit();

    var ctx = Context.init();
    var request = Request{ .path = "/api/test" };
    try request.headers.put("Host", "allowed.example.com");

    const action = router.selectUpstream(&ctx, &request);

    // Should forward (host is allowed and route matches)
    try std.testing.expect(action == .forward);
}
