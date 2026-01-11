// examples/router_example.zig
//! Content-Based Router Example with Atomic Config Swap
//!
//! Demonstrates serval with Router for content-based routing with multiple backend pools.
//! Routes requests to different pools based on path prefix matching.
//!
//! ## Atomic Router Swap
//!
//! This example implements double-buffered router storage for atomic configuration updates:
//! - Two router slots (active + inactive) enable lock-free config swaps
//! - `swapRouter()` initializes new config in inactive slot, then atomically swaps pointers
//! - Grace period allows in-flight requests to complete before old config cleanup
//! - Generation counter tracks config versions for observability
//!
//! TigerStyle: No runtime allocation after init, bounded grace period, explicit error handling.
//!
//! ## Usage
//!
//!   router_example [OPTIONS]
//!
//! ## Options
//!
//!   --port <PORT>                Listening port (default: 8080)
//!   --admin-port <PORT>          Admin API port (default: 9901)
//!   --api-backends <HOSTS>       Comma-separated API backend addresses (default: 127.0.0.1:8001)
//!   --static-backends <HOSTS>    Comma-separated static backend addresses (default: 127.0.0.1:8002)
//!   --debug                      Enable debug logging
//!   --help                       Show help message
//!   --version                    Show version
//!
//! ## Admin API Endpoints
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
//! ## JSON Format for POST /routes/update
//!
//! ```json
//! {
//!   "allowed_hosts": ["example.com", "api.example.com"],
//!   "routes": [{"name": "...", "path_prefix": "/...", "pool_idx": 0, "strip_prefix": false}],
//!   "pools": [{"name": "...", "upstreams": [{"host": "...", "port": 8080, "idx": 0}]}]
//! }
//! ```
//!
//! Note: allowed_hosts is optional (defaults to empty, meaning accept any host).
//! Routes are evaluated in order; first match wins. Include a catch-all route
//! (path_prefix: "/") at the end if you want a default fallback.

const std = @import("std");
const serval = @import("serval");
const serval_router = @import("serval-router");
const serval_net = @import("serval-net");
const cli = @import("serval-cli");
const posix = std.posix;
const assert = std.debug.assert;

const DnsConfig = serval_net.DnsConfig;
const DnsResolver = serval_net.DnsResolver;
const Router = serval_router.Router;
const Route = serval_router.Route;
const RouteMatcher = serval_router.RouteMatcher;
const PathMatch = serval_router.PathMatch;
const PoolConfig = serval_router.PoolConfig;
const Upstream = serval_router.Upstream;
const LbConfig = serval_router.LbConfig;
const config = serval.config;
const Context = serval.Context;
const LogEntry = serval.LogEntry;
const Request = serval.Request;

/// Version of this binary.
const VERSION = "0.1.0";

// =============================================================================
// JSON Configuration Types (Admin API)
// =============================================================================

/// Maximum JSON body size for route updates.
const MAX_JSON_BODY_SIZE: u32 = 64 * 1024; // 64KB

/// JSON representation of an upstream for parsing.
const UpstreamJson = struct {
    host: []const u8,
    port: u16,
    idx: u8,
    tls: bool = false,
};

/// JSON representation of LB config for parsing.
const LbConfigJson = struct {
    enable_probing: bool = false,
    unhealthy_threshold: u8 = config.DEFAULT_UNHEALTHY_THRESHOLD,
    healthy_threshold: u8 = config.DEFAULT_HEALTHY_THRESHOLD,
    probe_interval_ms: u32 = config.DEFAULT_PROBE_INTERVAL_MS,
    probe_timeout_ms: u32 = config.DEFAULT_PROBE_TIMEOUT_MS,
    health_path: []const u8 = config.DEFAULT_HEALTH_PATH,
};

/// JSON representation of a pool for parsing.
const PoolJson = struct {
    name: []const u8,
    upstreams: []const UpstreamJson,
    lb_config: LbConfigJson = .{},
};

/// JSON representation of a route for parsing.
const RouteJson = struct {
    name: []const u8,
    path_prefix: []const u8,
    pool_idx: u8,
    strip_prefix: bool = false,
    host: ?[]const u8 = null,
};

/// JSON representation of full config for parsing.
const ConfigJson = struct {
    allowed_hosts: []const []const u8 = &.{},
    routes: []const RouteJson = &.{},
    pools: []const PoolJson,
};

// =============================================================================
// Incremental CRUD JSON Types (Admin API)
// =============================================================================

/// JSON for POST /routes/add - add a single route.
const AddRouteJson = struct {
    name: []const u8,
    path_prefix: []const u8,
    pool_idx: u8,
    strip_prefix: bool = false,
    host: ?[]const u8 = null,
};

/// JSON for POST /routes/remove - remove route by name.
const RemoveRouteJson = struct {
    name: []const u8,
};

/// JSON for POST /pools/add - add a new pool with upstreams.
const AddPoolJson = struct {
    name: []const u8,
    upstreams: []const UpstreamJson,
    lb_config: LbConfigJson = .{},
};

/// JSON for POST /pools/remove - remove pool by name.
const RemovePoolJson = struct {
    name: []const u8,
};

/// JSON for POST /upstreams/add - add upstream to existing pool.
const AddUpstreamJson = struct {
    pool_name: []const u8,
    host: []const u8,
    port: u16,
    idx: u8,
    tls: bool = false,
};

/// JSON for POST /upstreams/remove - remove upstream from pool.
const RemoveUpstreamJson = struct {
    pool_name: []const u8,
    upstream_idx: u8,
};

// =============================================================================
// Atomic Router Swap - Double-Buffered Storage
// =============================================================================

/// Config storage for route/pool/upstream data that must outlive JSON parsing.
/// TigerStyle: All config strings and data copied here before Router.init.
/// Double-buffered (one per router slot) so old config remains valid during grace period.
const ConfigStorage = struct {
    /// Storage for route structs.
    route_storage: [config.MAX_ROUTES]Route = undefined,
    /// Storage for upstream structs (per pool).
    upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined,
    /// Storage for PoolConfig structs.
    pool_storage: [config.MAX_POOLS]PoolConfig = undefined,
    /// Storage for all config strings (names, paths, hosts).
    string_storage: [config.ROUTER_STRING_STORAGE_BYTES]u8 = undefined,
    /// Current offset into string_storage.
    /// TigerStyle S2: Explicit u32 since bounded by ROUTER_STRING_STORAGE_BYTES.
    string_offset: u32 = 0,
    /// Storage for allowed_hosts strings.
    /// TigerStyle S7: Bounded by MAX_ALLOWED_HOSTS and MAX_HOSTNAME_LEN.
    allowed_hosts_storage: [config.MAX_ALLOWED_HOSTS][config.MAX_HOSTNAME_LEN]u8 = undefined,
    /// Pointers into allowed_hosts_storage.
    allowed_hosts_ptrs: [config.MAX_ALLOWED_HOSTS][]const u8 = undefined,
    /// Number of allowed_hosts stored.
    allowed_hosts_count: u8 = 0,

    const Self = @This();

    /// Reset storage for fresh config copy.
    fn reset(self: *Self) void {
        self.string_offset = 0;
        self.allowed_hosts_count = 0;
    }

    /// Copy a string into embedded storage, returning slice into storage.
    /// TigerStyle: Returns error if storage exhausted.
    fn copyString(self: *Self, s: []const u8) ![]const u8 {
        // S1: Preconditions
        assert(s.len <= config.ROUTER_STRING_STORAGE_BYTES);

        if (self.string_offset + @as(u32, @intCast(s.len)) > config.ROUTER_STRING_STORAGE_BYTES) {
            return error.StringStorageExhausted;
        }
        const dest = self.string_storage[self.string_offset..][0..s.len];
        @memcpy(dest, s);
        self.string_offset += @intCast(s.len);
        return dest;
    }

    /// Deep copy a route, copying all strings into embedded storage.
    fn copyRoute(self: *Self, route: Route) !Route {
        return Route{
            .name = try self.copyString(route.name),
            .matcher = .{
                .host = if (route.matcher.host) |h| try self.copyString(h) else null,
                .path = switch (route.matcher.path) {
                    .prefix => |p| .{ .prefix = try self.copyString(p) },
                    .exact => |e| .{ .exact = try self.copyString(e) },
                },
            },
            .pool_idx = route.pool_idx,
            .strip_prefix = route.strip_prefix,
        };
    }

    /// Deep copy an upstream, copying host string into embedded storage.
    fn copyUpstream(self: *Self, upstream: Upstream) !Upstream {
        return Upstream{
            .host = try self.copyString(upstream.host),
            .port = upstream.port,
            .idx = upstream.idx,
            .tls = upstream.tls,
        };
    }

    /// Deep copy routes into storage, returning slice.
    fn copyRoutes(self: *Self, routes: []const Route) ![]const Route {
        // S1: Precondition - routes within bounds
        assert(routes.len <= config.MAX_ROUTES);

        for (routes, 0..) |route, i| {
            self.route_storage[i] = try self.copyRoute(route);
        }
        return self.route_storage[0..routes.len];
    }

    /// Deep copy pool configs into storage, returning slice.
    /// Also deep copies all upstreams for each pool.
    fn copyPoolConfigs(self: *Self, pool_configs: []const PoolConfig) ![]const PoolConfig {
        // S1: Precondition - pools within bounds
        assert(pool_configs.len <= config.MAX_POOLS);

        for (pool_configs, 0..) |cfg, i| {
            // S1: Precondition - upstreams within bounds
            assert(cfg.upstreams.len <= config.MAX_UPSTREAMS_PER_POOL);

            // Deep copy upstreams for this pool
            for (cfg.upstreams, 0..) |upstream, j| {
                self.upstream_storage[i][j] = try self.copyUpstream(upstream);
            }

            // Create PoolConfig with copied data
            self.pool_storage[i] = PoolConfig{
                .name = try self.copyString(cfg.name),
                .upstreams = self.upstream_storage[i][0..cfg.upstreams.len],
                .lb_config = cfg.lb_config, // LbConfig has no pointers, copy by value
            };
        }
        return self.pool_storage[0..pool_configs.len];
    }

    /// Deep copy allowed_hosts into embedded storage, returning slice.
    /// TigerStyle S7: Bounded by MAX_ALLOWED_HOSTS and MAX_HOSTNAME_LEN.
    fn copyAllowedHosts(self: *Self, hosts: []const []const u8) ![]const []const u8 {
        // S1: Precondition - hosts count within bounds
        assert(hosts.len <= config.MAX_ALLOWED_HOSTS);

        for (hosts, 0..) |host, i| {
            // S1: Precondition - hostname length within bounds
            if (host.len > config.MAX_HOSTNAME_LEN) {
                return error.HostnameTooLong;
            }
            @memcpy(self.allowed_hosts_storage[i][0..host.len], host);
            self.allowed_hosts_ptrs[i] = self.allowed_hosts_storage[i][0..host.len];
        }
        self.allowed_hosts_count = @intCast(hosts.len);

        // S2: Postcondition - count matches input
        assert(self.allowed_hosts_count == hosts.len);
        return self.allowed_hosts_ptrs[0..hosts.len];
    }
};

/// Double-buffered config storage (one per router slot).
/// TigerStyle: Config data lives here, outlives JSON parsing.
var config_storage: [config.MAX_ROUTER_SLOTS]ConfigStorage = .{ .{}, .{} };

/// Double-buffered Router storage for atomic swap.
/// TigerStyle: Fixed-size array, no runtime allocation after init.
var router_storage: [config.MAX_ROUTER_SLOTS]Router = undefined;

/// Atomic pointer to currently active router.
/// TigerStyle: Acquire/release ordering ensures visibility of initialized router.
var current_router: std.atomic.Value(?*Router) = std.atomic.Value(?*Router).init(null);

/// Index of currently active slot (0 or 1).
/// TigerStyle: u8 for atomic compatibility, values constrained to 0 or 1 at runtime.
var active_slot: std.atomic.Value(u8) = std.atomic.Value(u8).init(0);

/// Generation counter for config changes (monotonically increasing).
/// TigerStyle: Enables detection of config updates without pointer comparison.
var router_generation: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Track which slots have been initialized (for cleanup).
/// TigerStyle: Explicit initialization state per slot.
var slot_initialized: [config.MAX_ROUTER_SLOTS]bool = .{ false, false };

/// Mutex to serialize config swaps.
/// TigerStyle: Prevents concurrent swap race conditions during grace period.
var swap_mutex: std.Thread.Mutex = .{};

/// Atomically swap to a new router configuration.
///
/// Initializes the new router in the inactive slot, then atomically swaps
/// the current_router pointer. Waits for grace period to allow in-flight
/// requests to complete before the old config is eligible for cleanup.
///
/// TigerStyle: Bounded grace period, explicit error handling, no allocation.
///
/// Arguments:
///   routes: New route table (evaluated in order, first match wins).
///   pool_configs: Backend pool configurations (one per pool_idx).
///   allowed_hosts: Hostnames this router will serve. Empty = allow any host.
///   dns_resolver: DNS resolver for hostname resolution in health probes (nullable).
///
/// Errors:
///   - Any error from Router.init propagates up (validation errors).
///   - On error, the swap does NOT occur (old config remains active).
fn swapRouter(
    routes: []const Route,
    pool_configs: []const PoolConfig,
    allowed_hosts: []const []const u8,
    dns_resolver: ?*DnsResolver,
) !void {
    // S1: Precondition - must have at least one pool config
    assert(pool_configs.len > 0);
    // S1: Precondition - allowed_hosts within bounds
    assert(allowed_hosts.len <= config.MAX_ALLOWED_HOSTS);

    // Serialize config swaps to prevent race during grace period.
    // TigerStyle: Explicit locking, defer unlock for exception safety.
    swap_mutex.lock();
    defer swap_mutex.unlock();

    // Calculate inactive slot (toggle between 0 and 1)
    const current_slot: u8 = active_slot.load(.acquire);
    assert(current_slot <= 1); // S1: slot must be 0 or 1
    const inactive_slot: u8 = 1 - current_slot;

    // S1: Slot index must be valid (0 or 1)
    assert(inactive_slot < config.MAX_ROUTER_SLOTS);

    // Deinit old router in inactive slot if it was previously initialized.
    // This is safe because no requests should be using the inactive slot.
    if (slot_initialized[inactive_slot]) {
        router_storage[inactive_slot].deinit();
        slot_initialized[inactive_slot] = false;
    }

    // Deep copy config data into persistent storage for this slot.
    // TigerStyle: Copy at API boundary - config data outlives JSON parsing.
    const storage = &config_storage[inactive_slot];
    storage.reset();

    const persistent_routes = try storage.copyRoutes(routes);
    const persistent_pools = try storage.copyPoolConfigs(pool_configs);
    const persistent_allowed_hosts = try storage.copyAllowedHosts(allowed_hosts);

    // Initialize new router in inactive slot with persistent config data.
    // If init fails, swap does NOT occur (old config remains active).
    try router_storage[inactive_slot].init(
        persistent_routes,
        persistent_pools,
        persistent_allowed_hosts,
        null, // client_ctx for TLS probes - not used in this example
        dns_resolver,
    );
    slot_initialized[inactive_slot] = true;

    // S2: Postcondition - new router initialized before swap
    assert(slot_initialized[inactive_slot]);

    // Atomic swap: update pointer and slot index.
    // Release ordering ensures all router initialization is visible.
    current_router.store(&router_storage[inactive_slot], .release);
    active_slot.store(inactive_slot, .release);

    // Increment generation counter (monotonic, no wrap concern for u64).
    _ = router_generation.fetchAdd(1, .monotonic);

    // Grace period: allow in-flight requests using old config to complete.
    // TigerStyle: Bounded wait with explicit timeout from config.
    // TigerStyle: Grace period in milliseconds converted to seconds + nanoseconds
    const grace_ns: u64 = config.CONFIG_SWAP_GRACE_MS * std.time.ns_per_ms;
    const grace_secs: u64 = grace_ns / std.time.ns_per_s;
    const grace_remaining_ns: u64 = grace_ns % std.time.ns_per_s;
    posix.nanosleep(grace_secs, grace_remaining_ns);

    // S2: Postcondition - current_router points to newly initialized slot
    const final_router = current_router.load(.acquire);
    assert(final_router != null);
    assert(final_router == &router_storage[inactive_slot]);
}

/// Get the currently active router (for request handling).
///
/// Returns null if no router has been initialized yet.
/// TigerStyle: Acquire ordering ensures visibility of router state.
fn getActiveRouter() ?*Router {
    return current_router.load(.acquire);
}

/// Get the current configuration generation.
///
/// TigerStyle: Useful for observability/debugging config changes.
fn getRouterGeneration() u64 {
    return router_generation.load(.monotonic);
}

/// Handler wrapper that dynamically loads the current router on each request.
///
/// This enables hot config reload - swapRouter() updates current_router atomically,
/// and subsequent requests use the new router without server restart.
///
/// TigerStyle: Wrapper pattern avoids modifying server internals.
const RouterHandler = struct {
    /// Select upstream by loading current router and delegating.
    /// Returns 503 if no router is available (shouldn't happen in normal operation).
    pub fn selectUpstream(_: *RouterHandler, ctx: *Context, request: *const Request) Router.Action {
        const router = current_router.load(.acquire) orelse {
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
        const router = current_router.load(.acquire) orelse return;
        router.onLog(ctx, entry);
    }
};

/// Cleanup all initialized router slots.
///
/// Must be called before program exit to cleanup LbHandler resources.
/// TigerStyle: Explicit cleanup of all initialized slots.
fn deinitAllRouters() void {
    // S3: Bounded loop (MAX_ROUTER_SLOTS = 2)
    for (&router_storage, 0..) |*router, i| {
        if (slot_initialized[i]) {
            router.deinit();
            slot_initialized[i] = false;
        }
    }
    current_router.store(null, .release);
}

/// Router-specific CLI options.
const RouterExtra = struct {
    /// Comma-separated list of API backend addresses (host:port,host:port,...)
    @"api-backends": []const u8 = "127.0.0.1:8001",
    /// Comma-separated list of static backend addresses (host:port,host:port,...)
    @"static-backends": []const u8 = "127.0.0.1:8002",
    /// Admin API port for health checks and configuration.
    @"admin-port": u16 = 9901,
};

/// Maximum number of upstreams per pool.
const MAX_UPSTREAMS_PER_POOL: u8 = 100;

const UpstreamIndex = serval.config.UpstreamIndex;

/// Parse backends string into Upstream array with sequential idx starting at base_idx.
/// Format: "host:port,host:port,..."
/// TigerStyle: Bounded loop, count only increments on successful parse.
fn parseBackends(
    backends_str: []const u8,
    upstreams: *[MAX_UPSTREAMS_PER_POOL]Upstream,
    base_idx: UpstreamIndex,
) UpstreamIndex {
    var count: UpstreamIndex = 0;
    var iter = std.mem.splitScalar(u8, backends_str, ',');

    // Bounded iteration - use count directly, MAX_UPSTREAMS_PER_POOL-1 is max valid index
    while (count < MAX_UPSTREAMS_PER_POOL) {
        const backend = iter.next() orelse break;

        // Find the colon separator
        const colon_pos = std.mem.lastIndexOfScalar(u8, backend, ':') orelse {
            std.debug.print("Invalid backend format (missing port): {s}\n", .{backend});
            continue;
        };

        const host = backend[0..colon_pos];
        const port_str = backend[colon_pos + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch {
            std.debug.print("Invalid port number: {s}\n", .{port_str});
            continue;
        };

        upstreams[count] = .{
            .host = host,
            .port = port,
            .idx = base_idx + count,
            .tls = false,
        };
        count += 1;
    }

    return count;
}

/// Format upstream list for display.
/// TigerStyle: Bounded loop.
fn formatUpstreams(upstreams: []const Upstream) void {
    std.debug.print("[", .{});
    for (upstreams, 0..) |upstream, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s}:{d}", .{ upstream.host, upstream.port });
    }
    std.debug.print("]", .{});
}

// =============================================================================
// Admin Handler (using serval.Server)
// =============================================================================

/// JSON response buffer size for GET /routes.
const JSON_RESPONSE_BUFFER_SIZE_BYTES: u32 = 32 * 1024; // 32KB

/// Admin API handler for health checks and configuration updates.
/// TigerStyle: All state explicit, no hidden dependencies.
const AdminHandler = struct {
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
            if (getActiveRouter() != null) {
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
            const router = getActiveRouter() orelse {
                return .{ .send_response = .{
                    .status = 503,
                    .body =
                    \\{"error":"no router configured"}
                    ,
                    .content_type = "application/json",
                } };
            };

            const json_body = formatRoutesJson(router, response_buf) catch {
                return .{ .send_response = .{
                    .status = 500,
                    .body =
                    \\{"error":"response buffer overflow"}
                    ,
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
            // TigerStyle: Handler provides buffer, body only read when needed.
            var body_buf: [MAX_JSON_BODY_SIZE]u8 = undefined;
            const body = ctx.readBody(&body_buf) catch |err| {
                // Handle body read errors
                const error_msg = switch (err) {
                    error.BodyReaderNotAvailable => "body reader not available",
                    error.BodyTooLarge => "request body too large",
                    error.ReadFailed => "failed to read request body",
                    error.ChunkedNotSupported => "chunked encoding not supported",
                    error.BodyReaderNotConfigured => "body reader not configured",
                };
                _ = std.fmt.bufPrint(response_buf, "{{\"error\":\"{s}\"}}", .{error_msg}) catch {
                    return .{ .send_response = .{
                        .status = 400,
                        .body =
                        \\{"error":"body read failed"}
                        ,
                        .content_type = "application/json",
                    } };
                };
                return .{ .send_response = .{
                    .status = if (err == error.BodyTooLarge) @as(u16, 413) else @as(u16, 400),
                    .body = response_buf[0..std.fmt.count("{{\"error\":\"{s}\"}}", .{error_msg})],
                    .content_type = "application/json",
                } };
            };

            const result = handleRouteUpdate(if (body.len > 0) body else null, response_buf);
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
                const error_msg = switch (err) {
                    error.BodyReaderNotAvailable => "body reader not available",
                    error.BodyTooLarge => "request body too large",
                    error.ReadFailed => "failed to read request body",
                    error.ChunkedNotSupported => "chunked encoding not supported",
                    error.BodyReaderNotConfigured => "body reader not configured",
                };
                _ = std.fmt.bufPrint(response_buf, "{{\"error\":\"{s}\"}}", .{error_msg}) catch {
                    return .{ .send_response = .{
                        .status = 400,
                        .body =
                        \\{"error":"body read failed"}
                        ,
                        .content_type = "application/json",
                    } };
                };
                return .{ .send_response = .{
                    .status = if (err == error.BodyTooLarge) @as(u16, 413) else @as(u16, 400),
                    .body = response_buf[0..std.fmt.count("{{\"error\":\"{s}\"}}", .{error_msg})],
                    .content_type = "application/json",
                } };
            };

            const body_or_null: ?[]const u8 = if (body.len > 0) body else null;

            // Route to appropriate handler
            if (std.mem.eql(u8, request.path, "/routes/add")) {
                const result = handleRoutesAdd(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/routes/remove")) {
                const result = handleRoutesRemove(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/pools/add")) {
                const result = handlePoolsAdd(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/pools/remove")) {
                const result = handlePoolsRemove(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/upstreams/add")) {
                const result = handleUpstreamsAdd(body_or_null, response_buf);
                return .{ .send_response = .{
                    .status = result.status,
                    .body = result.body,
                    .content_type = "application/json",
                } };
            }

            if (std.mem.eql(u8, request.path, "/upstreams/remove")) {
                const result = handleUpstreamsRemove(body_or_null, response_buf);
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

/// Result of route update operation.
const RouteUpdateResult = struct {
    status: u16,
    body: []const u8,
};

/// Handle POST /routes/update - parse JSON and call swapRouter().
/// TigerStyle: Bounded buffer, explicit error handling, validates all input.
fn handleRouteUpdate(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    const request_body = body orelse {
        return .{
            .status = 400,
            .body =
            \\{"error":"missing request body"}
            ,
        };
    };

    if (request_body.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"empty request body"}
            ,
        };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{
            .status = 413,
            .body =
            \\{"error":"request body too large"}
            ,
        };
    }

    // Parse JSON
    const parsed = std.json.parseFromSlice(ConfigJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{
            .status = 400,
            .body =
            \\{"error":"JSON parse error"}
            ,
        };
    };
    defer parsed.deinit();

    const json_config = parsed.value;

    // Validate configuration
    if (json_config.pools.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"at least one pool is required"}
            ,
        };
    }

    if (json_config.pools.len > config.MAX_POOLS) {
        return .{
            .status = 400,
            .body =
            \\{"error":"too many pools"}
            ,
        };
    }

    if (json_config.routes.len > config.MAX_ROUTES) {
        return .{
            .status = 400,
            .body =
            \\{"error":"too many routes"}
            ,
        };
    }

    if (json_config.allowed_hosts.len > config.MAX_ALLOWED_HOSTS) {
        return .{
            .status = 400,
            .body =
            \\{"error":"too many allowed_hosts"}
            ,
        };
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
            return .{
                .status = 400,
                .body =
                \\{"error":"route references invalid pool_idx"}
                ,
            };
        }

        std.log.debug("handleRouteUpdate: route[{d}] name={s} host={s} path_prefix={s} pool_idx={d}", .{
            i,
            route_json.name,
            route_json.host orelse "(null)",
            route_json.path_prefix,
            route_json.pool_idx,
        });

        route_storage[i] = Route{
            .name = route_json.name,
            .matcher = .{
                .host = route_json.host,
                .path = .{ .prefix = route_json.path_prefix },
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
            return .{
                .status = 400,
                .body =
                \\{"error":"pool has no upstreams"}
                ,
            };
        }

        if (pool_json.upstreams.len > config.MAX_UPSTREAMS_PER_POOL) {
            return .{
                .status = 400,
                .body =
                \\{"error":"pool has too many upstreams"}
                ,
            };
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
                return .{
                    .status = 400,
                    .body =
                    \\{"error":"upstream idx exceeds maximum"}
                    ,
                };
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
    swapRouter(routes, pools, allowed_hosts_slice, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{
            .status = 500,
            .body =
            \\{"error":"router swap failed"}
            ,
        };
    };

    // Verify the swap worked by loading the new router
    const new_router = current_router.load(.acquire);
    if (new_router) |r| {
        std.log.info("handleRouteUpdate: config swap successful - new router has {d} routes, {d} allowed_hosts", .{
            r.routes.len,
            r.allowed_hosts.len,
        });
    } else {
        std.log.err("handleRouteUpdate: swap succeeded but current_router is null!", .{});
    }

    const generation = getRouterGeneration();
    const success_body = std.fmt.bufPrint(response_buf, "{{\"status\":\"ok\",\"generation\":{d}}}", .{generation}) catch {
        return .{
            .status = 200,
            .body =
            \\{"status":"ok"}
            ,
        };
    };

    return .{
        .status = 200,
        .body = success_body,
    };
}

// =============================================================================
// Incremental CRUD Handlers
// =============================================================================

/// Handle POST /routes/add - add a single route to existing config.
/// TigerStyle: Bounded buffers, explicit error handling, validates all input.
fn handleRoutesAdd(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const request_body = body orelse {
        return .{
            .status = 400,
            .body =
            \\{"error":"missing request body"}
            ,
        };
    };

    if (request_body.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"empty request body"}
            ,
        };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{
            .status = 413,
            .body =
            \\{"error":"request body too large"}
            ,
        };
    }

    // Get current router
    const router = getActiveRouter() orelse {
        return .{
            .status = 503,
            .body =
            \\{"error":"no router configured"}
            ,
        };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(AddRouteJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{
            .status = 400,
            .body =
            \\{"error":"JSON parse error"}
            ,
        };
    };
    defer parsed.deinit();

    const add_route = parsed.value;

    // Validate pool_idx
    if (add_route.pool_idx >= router.pools.len) {
        return .{
            .status = 400,
            .body =
            \\{"error":"pool_idx references invalid pool"}
            ,
        };
    }

    // Check for duplicate route name
    for (router.routes) |route| {
        if (std.mem.eql(u8, route.name, add_route.name)) {
            return .{
                .status = 409,
                .body =
                \\{"error":"route with this name already exists"}
                ,
            };
        }
    }

    // Check if we would exceed max routes
    if (router.routes.len >= config.MAX_ROUTES) {
        return .{
            .status = 400,
            .body =
            \\{"error":"maximum routes reached"}
            ,
        };
    }

    // Build new config with added route
    var route_storage: [config.MAX_ROUTES]Route = undefined;
    var pool_storage: [config.MAX_POOLS]PoolConfig = undefined;
    var upstream_storage: [config.MAX_POOLS][config.MAX_UPSTREAMS_PER_POOL]Upstream = undefined;

    // Copy existing routes
    for (router.routes, 0..) |route, i| {
        route_storage[i] = route;
    }

    // Add new route at the end
    route_storage[router.routes.len] = Route{
        .name = add_route.name,
        .matcher = .{
            .host = add_route.host,
            .path = .{ .prefix = add_route.path_prefix },
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
    swapRouter(new_routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{
            .status = 500,
            .body =
            \\{"error":"router swap failed"}
            ,
        };
    };

    const generation = getRouterGeneration();
    const success_body = std.fmt.bufPrint(response_buf, "{{\"status\":\"ok\",\"generation\":{d}}}", .{generation}) catch {
        return .{
            .status = 200,
            .body =
            \\{"status":"ok"}
            ,
        };
    };

    return .{ .status = 200, .body = success_body };
}

/// Handle POST /routes/remove - remove a route by name.
/// TigerStyle: Bounded buffers, explicit error handling.
fn handleRoutesRemove(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const request_body = body orelse {
        return .{
            .status = 400,
            .body =
            \\{"error":"missing request body"}
            ,
        };
    };

    if (request_body.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"empty request body"}
            ,
        };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{
            .status = 413,
            .body =
            \\{"error":"request body too large"}
            ,
        };
    }

    // Get current router
    const router = getActiveRouter() orelse {
        return .{
            .status = 503,
            .body =
            \\{"error":"no router configured"}
            ,
        };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(RemoveRouteJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{
            .status = 400,
            .body =
            \\{"error":"JSON parse error"}
            ,
        };
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
        return .{
            .status = 404,
            .body =
            \\{"error":"route not found"}
            ,
        };
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
    swapRouter(new_routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{
            .status = 500,
            .body =
            \\{"error":"router swap failed"}
            ,
        };
    };

    const generation = getRouterGeneration();
    const success_body = std.fmt.bufPrint(response_buf, "{{\"status\":\"ok\",\"generation\":{d}}}", .{generation}) catch {
        return .{
            .status = 200,
            .body =
            \\{"status":"ok"}
            ,
        };
    };

    return .{ .status = 200, .body = success_body };
}

/// Handle POST /pools/add - add a new pool with upstreams.
/// TigerStyle: Bounded buffers, explicit error handling.
fn handlePoolsAdd(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const request_body = body orelse {
        return .{
            .status = 400,
            .body =
            \\{"error":"missing request body"}
            ,
        };
    };

    if (request_body.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"empty request body"}
            ,
        };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{
            .status = 413,
            .body =
            \\{"error":"request body too large"}
            ,
        };
    }

    // Get current router
    const router = getActiveRouter() orelse {
        return .{
            .status = 503,
            .body =
            \\{"error":"no router configured"}
            ,
        };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(AddPoolJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{
            .status = 400,
            .body =
            \\{"error":"JSON parse error"}
            ,
        };
    };
    defer parsed.deinit();

    const add_pool = parsed.value;

    // Validate upstreams
    if (add_pool.upstreams.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"pool has no upstreams"}
            ,
        };
    }

    if (add_pool.upstreams.len > config.MAX_UPSTREAMS_PER_POOL) {
        return .{
            .status = 400,
            .body =
            \\{"error":"pool has too many upstreams"}
            ,
        };
    }

    // Check for duplicate pool name
    for (router.pools) |*pool| {
        if (std.mem.eql(u8, pool.name, add_pool.name)) {
            return .{
                .status = 409,
                .body =
                \\{"error":"pool with this name already exists"}
                ,
            };
        }
    }

    // Check if we would exceed max pools
    if (router.pools.len >= config.MAX_POOLS) {
        return .{
            .status = 400,
            .body =
            \\{"error":"maximum pools reached"}
            ,
        };
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
            return .{
                .status = 400,
                .body =
                \\{"error":"upstream idx exceeds maximum"}
                ,
            };
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
    swapRouter(routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{
            .status = 500,
            .body =
            \\{"error":"router swap failed"}
            ,
        };
    };

    const generation = getRouterGeneration();
    const success_body = std.fmt.bufPrint(response_buf, "{{\"status\":\"ok\",\"generation\":{d},\"pool_idx\":{d}}}", .{ generation, new_pool_idx }) catch {
        return .{
            .status = 200,
            .body =
            \\{"status":"ok"}
            ,
        };
    };

    return .{ .status = 200, .body = success_body };
}

/// Handle POST /pools/remove - remove a pool by name.
/// Fails if any routes reference this pool.
/// TigerStyle: Bounded buffers, explicit error handling.
fn handlePoolsRemove(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const request_body = body orelse {
        return .{
            .status = 400,
            .body =
            \\{"error":"missing request body"}
            ,
        };
    };

    if (request_body.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"empty request body"}
            ,
        };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{
            .status = 413,
            .body =
            \\{"error":"request body too large"}
            ,
        };
    }

    // Get current router
    const router = getActiveRouter() orelse {
        return .{
            .status = 503,
            .body =
            \\{"error":"no router configured"}
            ,
        };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(RemovePoolJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{
            .status = 400,
            .body =
            \\{"error":"JSON parse error"}
            ,
        };
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
        return .{
            .status = 404,
            .body =
            \\{"error":"pool not found"}
            ,
        };
    }

    const pool_idx_to_remove: u8 = @intCast(found_idx.?);

    // Check if any routes reference this pool
    for (router.routes) |route| {
        if (route.pool_idx == pool_idx_to_remove) {
            return .{
                .status = 409,
                .body =
                \\{"error":"pool is referenced by routes"}
                ,
            };
        }
    }

    // Must have at least one pool remaining
    if (router.pools.len <= 1) {
        return .{
            .status = 400,
            .body =
            \\{"error":"cannot remove last pool"}
            ,
        };
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
    swapRouter(routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{
            .status = 500,
            .body =
            \\{"error":"router swap failed"}
            ,
        };
    };

    const generation = getRouterGeneration();
    const success_body = std.fmt.bufPrint(response_buf, "{{\"status\":\"ok\",\"generation\":{d}}}", .{generation}) catch {
        return .{
            .status = 200,
            .body =
            \\{"status":"ok"}
            ,
        };
    };

    return .{ .status = 200, .body = success_body };
}

/// Handle POST /upstreams/add - add an upstream to an existing pool.
/// TigerStyle: Bounded buffers, explicit error handling.
fn handleUpstreamsAdd(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const request_body = body orelse {
        return .{
            .status = 400,
            .body =
            \\{"error":"missing request body"}
            ,
        };
    };

    if (request_body.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"empty request body"}
            ,
        };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{
            .status = 413,
            .body =
            \\{"error":"request body too large"}
            ,
        };
    }

    // Get current router
    const router = getActiveRouter() orelse {
        return .{
            .status = 503,
            .body =
            \\{"error":"no router configured"}
            ,
        };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(AddUpstreamJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{
            .status = 400,
            .body =
            \\{"error":"JSON parse error"}
            ,
        };
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
        return .{
            .status = 404,
            .body =
            \\{"error":"pool not found"}
            ,
        };
    }

    const pool_idx = found_pool_idx.?;
    const target_pool = &router.pools[pool_idx];

    // Check if we would exceed max upstreams
    if (target_pool.lb_handler.upstreams.len >= config.MAX_UPSTREAMS_PER_POOL) {
        return .{
            .status = 400,
            .body =
            \\{"error":"maximum upstreams per pool reached"}
            ,
        };
    }

    // Validate idx fits in UpstreamIndex
    if (add_upstream.idx > std.math.maxInt(config.UpstreamIndex)) {
        return .{
            .status = 400,
            .body =
            \\{"error":"upstream idx exceeds maximum"}
            ,
        };
    }

    // Check for duplicate upstream idx in pool
    for (target_pool.lb_handler.upstreams) |upstream| {
        if (upstream.idx == @as(config.UpstreamIndex, @intCast(add_upstream.idx))) {
            return .{
                .status = 409,
                .body =
                \\{"error":"upstream with this idx already exists in pool"}
                ,
            };
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
    swapRouter(routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{
            .status = 500,
            .body =
            \\{"error":"router swap failed"}
            ,
        };
    };

    const generation = getRouterGeneration();
    const success_body = std.fmt.bufPrint(response_buf, "{{\"status\":\"ok\",\"generation\":{d}}}", .{generation}) catch {
        return .{
            .status = 200,
            .body =
            \\{"status":"ok"}
            ,
        };
    };

    return .{ .status = 200, .body = success_body };
}

/// Handle POST /upstreams/remove - remove an upstream from a pool.
/// TigerStyle: Bounded buffers, explicit error handling.
fn handleUpstreamsRemove(body: ?[]const u8, response_buf: []u8) RouteUpdateResult {
    // S1: Precondition - response buffer must be valid
    assert(response_buf.len > 0);

    const request_body = body orelse {
        return .{
            .status = 400,
            .body =
            \\{"error":"missing request body"}
            ,
        };
    };

    if (request_body.len == 0) {
        return .{
            .status = 400,
            .body =
            \\{"error":"empty request body"}
            ,
        };
    }

    if (request_body.len > MAX_JSON_BODY_SIZE) {
        return .{
            .status = 413,
            .body =
            \\{"error":"request body too large"}
            ,
        };
    }

    // Get current router
    const router = getActiveRouter() orelse {
        return .{
            .status = 503,
            .body =
            \\{"error":"no router configured"}
            ,
        };
    };

    // Parse JSON
    const parsed = std.json.parseFromSlice(RemoveUpstreamJson, std.heap.page_allocator, request_body, .{}) catch |err| {
        std.log.err("Admin: JSON parse error: {s}", .{@errorName(err)});
        return .{
            .status = 400,
            .body =
            \\{"error":"JSON parse error"}
            ,
        };
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
        return .{
            .status = 404,
            .body =
            \\{"error":"pool not found"}
            ,
        };
    }

    const pool_idx = found_pool_idx.?;
    const target_pool = &router.pools[pool_idx];

    // Validate upstream_idx fits in UpstreamIndex
    if (remove_upstream.upstream_idx > std.math.maxInt(config.UpstreamIndex)) {
        return .{
            .status = 400,
            .body =
            \\{"error":"upstream idx exceeds maximum"}
            ,
        };
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
        return .{
            .status = 404,
            .body =
            \\{"error":"upstream not found in pool"}
            ,
        };
    }

    // Must have at least one upstream remaining
    if (target_pool.lb_handler.upstreams.len <= 1) {
        return .{
            .status = 400,
            .body =
            \\{"error":"cannot remove last upstream from pool"}
            ,
        };
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
    swapRouter(routes, pools, router.allowed_hosts, null) catch |err| {
        std.log.err("Admin: swapRouter failed: {s}", .{@errorName(err)});
        return .{
            .status = 500,
            .body =
            \\{"error":"router swap failed"}
            ,
        };
    };

    const generation = getRouterGeneration();
    const success_body = std.fmt.bufPrint(response_buf, "{{\"status\":\"ok\",\"generation\":{d}}}", .{generation}) catch {
        return .{
            .status = 200,
            .body =
            \\{"status":"ok"}
            ,
        };
    };

    return .{ .status = 200, .body = success_body };
}

/// JSON writer helper using fixed buffer.
/// TigerStyle: Bounded buffer with explicit position tracking.
const JsonWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn init(buffer: []u8) JsonWriter {
        return .{ .buf = buffer };
    }

    fn writeAll(self: *JsonWriter, data: []const u8) !void {
        if (self.pos + data.len > self.buf.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    fn writeByte(self: *JsonWriter, byte: u8) !void {
        if (self.pos >= self.buf.len) return error.NoSpaceLeft;
        self.buf[self.pos] = byte;
        self.pos += 1;
    }

    fn writeInt(self: *JsonWriter, value: anytype) !void {
        var int_buf: [32]u8 = undefined;
        const int_str = std.fmt.bufPrint(&int_buf, "{d}", .{value}) catch return error.NoSpaceLeft;
        try self.writeAll(int_str);
    }

    fn getWritten(self: *JsonWriter) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Format router configuration as JSON.
/// TigerStyle: Bounded buffer, returns slice or error.
fn formatRoutesJson(router: *Router, buf: []u8) ![]const u8 {
    // S1: Precondition - router must be valid
    assert(@intFromPtr(router) != 0);

    var writer = JsonWriter.init(buf);

    // Start JSON object
    try writer.writeAll("{\"generation\":");
    try writer.writeInt(getRouterGeneration());

    // Write allowed_hosts array
    try writer.writeAll(",\"allowed_hosts\":[");
    for (router.allowed_hosts, 0..) |host, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("\"");
        try writeJsonString(&writer, host);
        try writer.writeAll("\"");
    }
    try writer.writeAll("]");

    // Write routes array
    try writer.writeAll(",\"routes\":[");
    for (router.routes, 0..) |route, i| {
        if (i > 0) try writer.writeAll(",");
        try writeRouteJson(&writer, route);
    }
    try writer.writeAll("]");

    // Write pools array
    try writer.writeAll(",\"pools\":[");
    for (router.pools, 0..) |*pool, i| {
        if (i > 0) try writer.writeAll(",");
        try writePoolFromRouter(&writer, pool);
    }
    try writer.writeAll("]");

    // Close JSON object
    try writer.writeAll("}");

    return writer.getWritten();
}

/// Write a single route as JSON.
fn writeRouteJson(writer: *JsonWriter, route: Route) !void {
    try writer.writeAll("{\"name\":\"");
    try writeJsonString(writer, route.name);
    try writer.writeAll("\",\"path_prefix\":\"");
    try writeJsonString(writer, route.matcher.path.getPattern());
    try writer.writeAll("\",\"pool_idx\":");
    try writer.writeInt(route.pool_idx);
    try writer.writeAll(",\"strip_prefix\":");
    try writer.writeAll(if (route.strip_prefix) "true" else "false");
    if (route.matcher.host) |host| {
        try writer.writeAll(",\"host\":\"");
        try writeJsonString(writer, host);
        try writer.writeAll("\"");
    }
    try writer.writeAll("}");
}

/// Write a single pool as JSON (from Router.Pool for GET /routes).
fn writePoolFromRouter(writer: *JsonWriter, pool: *const Router.Pool) !void {
    try writer.writeAll("{\"name\":\"");
    try writeJsonString(writer, pool.name);
    try writer.writeAll("\",\"upstreams\":[");
    for (pool.lb_handler.upstreams, 0..) |upstream, i| {
        if (i > 0) try writer.writeAll(",");
        try writeUpstreamJson(writer, upstream);
    }
    try writer.writeAll("],\"lb_config\":{\"enable_probing\":");
    // Note: We don't have direct access to the original enable_probing config,
    // but we can check if the prober is running
    try writer.writeAll("false"); // Conservative default for serialization
    try writer.writeAll("}}");
}

/// Write a single upstream as JSON.
fn writeUpstreamJson(writer: *JsonWriter, upstream: Upstream) !void {
    try writer.writeAll("{\"host\":\"");
    try writeJsonString(writer, upstream.host);
    try writer.writeAll("\",\"port\":");
    try writer.writeInt(upstream.port);
    try writer.writeAll(",\"idx\":");
    try writer.writeInt(upstream.idx);
    try writer.writeAll(",\"tls\":");
    try writer.writeAll(if (upstream.tls) "true" else "false");
    try writer.writeAll("}");
}

/// Write a JSON-escaped string (without surrounding quotes).
/// TigerStyle: Bounded loop through input string.
fn writeJsonString(writer: *JsonWriter, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    // Control character - write as \uXXXX
                    var hex_buf: [6]u8 = undefined;
                    const hex_str = std.fmt.bufPrint(&hex_buf, "\\u{x:0>4}", .{c}) catch return error.NoSpaceLeft;
                    try writer.writeAll(hex_str);
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

/// Admin server thread entry point.
/// TigerStyle: Explicit parameters, no hidden state.
fn runAdminServer(
    admin_server: anytype,
    io: std.Io,
    shutdown: *std.atomic.Value(bool),
) void {
    admin_server.run(io, shutdown) catch |err| {
        std.log.err("Admin server error: {}", .{err});
    };
}

pub fn main() !void {
    // Parse command-line arguments
    var args = cli.Args(RouterExtra).init("router_example", VERSION);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Parse API backends
    var api_upstreams_buf: [MAX_UPSTREAMS_PER_POOL]Upstream = std.mem.zeroes([MAX_UPSTREAMS_PER_POOL]Upstream);
    const api_count = parseBackends(args.extra.@"api-backends", &api_upstreams_buf, 0);

    if (api_count == 0) {
        std.debug.print("Error: no valid API backends specified\n", .{});
        return error.NoBackends;
    }

    const api_upstreams = api_upstreams_buf[0..api_count];

    // Parse static backends with idx continuing from api_count
    var static_upstreams_buf: [MAX_UPSTREAMS_PER_POOL]Upstream = std.mem.zeroes([MAX_UPSTREAMS_PER_POOL]Upstream);
    const static_count = parseBackends(args.extra.@"static-backends", &static_upstreams_buf, api_count);

    if (static_count == 0) {
        std.debug.print("Error: no valid static backends specified\n", .{});
        return error.NoBackends;
    }

    const static_upstreams = static_upstreams_buf[0..static_count];

    // Pool indices
    const API_POOL: u8 = 0;
    const STATIC_POOL: u8 = 1;

    // Define routes
    // TigerStyle: Routes are evaluated in order, first match wins.
    // Unmatched requests return 404 Not Found.
    const routes = [_]Route{
        // /api/* -> api-pool (strip prefix so /api/users becomes /users)
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = API_POOL,
            .strip_prefix = true,
        },
        // /static/* -> static-pool (strip prefix so /static/image.png becomes /image.png)
        .{
            .name = "static",
            .matcher = .{ .path = .{ .prefix = "/static/" } },
            .pool_idx = STATIC_POOL,
            .strip_prefix = true,
        },
    };

    // Pool configurations
    // TigerStyle: Disable probing for simplicity in this example
    const pool_configs = [_]PoolConfig{
        .{
            .name = "api-pool",
            .upstreams = api_upstreams,
            .lb_config = .{ .enable_probing = false },
        },
        .{
            .name = "static-pool",
            .upstreams = static_upstreams,
            .lb_config = .{ .enable_probing = false },
        },
    };

    // Initialize router in slot 0 of double-buffered storage.
    // TigerStyle: dns_resolver is null since probing is disabled for all pools.
    // Using atomic storage enables future config updates via swapRouter().
    // Empty allowed_hosts means accept any host.
    try router_storage[0].init(&routes, &pool_configs, &.{}, null, null);
    slot_initialized[0] = true;
    current_router.store(&router_storage[0], .release);
    defer deinitAllRouters();

    // S2: Postcondition - router must be available after init
    if (getActiveRouter() == null) {
        std.debug.print("Error: router initialization failed\n", .{});
        return error.RouterInitFailed;
    }

    // Initialize connection pool
    var pool = serval.SimplePool.init();

    // Initialize metrics (noop for simplicity)
    var metrics = serval.NoopMetrics{};

    // Initialize tracer (noop for simplicity)
    var tracer = serval.NoopTracer{};

    // Initialize async IO runtime
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    // Initialize admin handler and server
    // TigerStyle: Admin server runs independently, uses same shutdown flag.
    var admin_handler = AdminHandler{};

    // Create admin server type using serval.Server
    const AdminServerType = serval.Server(
        AdminHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );

    var admin_pool = serval.SimplePool.init();
    var admin_metrics = serval.NoopMetrics{};
    var admin_tracer = serval.NoopTracer{};

    var admin_server = AdminServerType.init(&admin_handler, &admin_pool, &admin_metrics, &admin_tracer, .{
        .port = args.extra.@"admin-port",
        .tls = null, // No TLS for admin API
    }, null, DnsConfig{});

    // Start admin server in separate thread
    const admin_thread = std.Thread.spawn(.{}, runAdminServer, .{
        &admin_server,
        io,
        &shutdown,
    }) catch |err| {
        std.debug.print("Failed to start admin server: {s}\n", .{@errorName(err)});
        return error.AdminServerFailed;
    };
    defer {
        // Signal shutdown and wait for admin thread to exit
        shutdown.store(true, .release);
        admin_thread.join();
    }

    // Print startup info
    std.debug.print("Router listening on :{d}\n", .{args.port});
    std.debug.print("Admin API listening on :{d}\n", .{args.extra.@"admin-port"});
    std.debug.print("  GET /healthz          - liveness probe\n", .{});
    std.debug.print("  GET /readyz           - readiness probe\n", .{});
    std.debug.print("  GET /routes           - current routes as JSON\n", .{});
    std.debug.print("  POST /routes/update   - full config replacement\n", .{});
    std.debug.print("  POST /routes/add      - add a single route\n", .{});
    std.debug.print("  POST /routes/remove   - remove route by name\n", .{});
    std.debug.print("  POST /pools/add       - add a new pool\n", .{});
    std.debug.print("  POST /pools/remove    - remove pool by name\n", .{});
    std.debug.print("  POST /upstreams/add   - add upstream to pool\n", .{});
    std.debug.print("  POST /upstreams/remove - remove upstream from pool\n", .{});
    std.debug.print("Routes:\n", .{});
    std.debug.print("  /api/* -> api-pool (strip prefix) ", .{});
    formatUpstreams(api_upstreams);
    std.debug.print("\n", .{});
    std.debug.print("  /static/* -> static-pool (strip prefix) ", .{});
    formatUpstreams(static_upstreams);
    std.debug.print("\n", .{});
    std.debug.print("  (other paths) -> 404 Not Found\n", .{});
    std.debug.print("Debug logging: {}\n", .{args.debug});
    std.debug.print("Config generation: {d}\n", .{getRouterGeneration()});

    // Run main server with RouterHandler wrapper.
    // RouterHandler dynamically loads current_router on each request,
    // enabling hot config reload via swapRouter() without server restart.
    const ServerType = serval.Server(
        RouterHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );

    var handler = RouterHandler{};
    var server = ServerType.init(&handler, &pool, &metrics, &tracer, .{
        .port = args.port,
        .tls = null, // No TLS for simplicity
    }, null, DnsConfig{});

    server.run(io, &shutdown) catch |err| {
        std.debug.print("Server error: {}\n", .{err});
        return;
    };
}
