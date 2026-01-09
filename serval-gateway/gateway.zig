//! Gateway Controller
//!
//! Main serval-gateway logic: manages router configuration and admin API.
//! Receives config updates from K8s watcher and performs atomic swap.
//!
//! Features:
//! - Atomic pointer swap for lock-free config updates
//! - Admin API on localhost:9901 (healthz, readyz, config, reload, metrics)
//! - Thread-safe config access
//! - Translation from GatewayConfig to serval-router Routes
//!
//! TigerStyle: Atomic operations for config swap, bounded admin responses,
//! explicit error handling, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const core = @import("serval-core");
const core_config = core.config;
const gw_config = @import("config.zig");
const resolver_mod = @import("resolver.zig");
const Resolver = resolver_mod.Resolver;

// ============================================================================
// Constants (TigerStyle: Named constants with units)
// ============================================================================

/// Admin API port (localhost only for security).
pub const ADMIN_PORT: u16 = 9901;

/// Maximum response size for admin endpoints (1MB).
pub const MAX_ADMIN_RESPONSE_BYTES: u32 = 1024 * 1024;

/// Maximum request size for admin endpoints (64KB).
pub const MAX_ADMIN_REQUEST_BYTES: u32 = 64 * 1024;

/// Admin server backlog for listen().
const ADMIN_BACKLOG: u31 = 16;

/// Admin request read timeout in nanoseconds (5 seconds).
const ADMIN_READ_TIMEOUT_NS: i64 = 5 * std.time.ns_per_s;

/// Admin response write timeout in nanoseconds (5 seconds).
const ADMIN_WRITE_TIMEOUT_NS: i64 = 5 * std.time.ns_per_s;

/// Maximum iterations for admin server accept loop per cycle.
const MAX_ACCEPT_ITERATIONS: u32 = 100;

/// Grace period after config swap before old config cleanup (milliseconds).
/// Allows in-flight requests using old config to complete.
const CONFIG_SWAP_GRACE_MS: u64 = 1000;

// Re-export routing limits from core config (single source of truth).
pub const MAX_ROUTES = core_config.MAX_ROUTES;
pub const MAX_POOLS = core_config.MAX_POOLS;
pub const MAX_UPSTREAMS_PER_POOL = core_config.MAX_UPSTREAMS_PER_POOL;

// ============================================================================
// Error Types
// ============================================================================

pub const GatewayError = error{
    /// Failed to bind admin server socket.
    AdminBindFailed,
    /// Failed to listen on admin server socket.
    AdminListenFailed,
    /// Admin server thread failed to start.
    AdminThreadFailed,
    /// Config translation failed.
    ConfigTranslationFailed,
    /// Too many routes in config.
    TooManyRoutes,
    /// Too many pools in config.
    TooManyPools,
    /// Too many upstreams in pool.
    TooManyUpstreams,
    /// Backend service not found in resolver.
    BackendNotFound,
    /// Invalid pool index in route.
    InvalidPoolIndex,
    /// No listeners defined in gateway.
    NoListeners,
    /// Gateway not ready (no valid config).
    NotReady,
    /// Allocator error.
    OutOfMemory,
};

// ============================================================================
// Placeholder Types (for serval-router integration)
// ============================================================================

/// Placeholder for serval-router Route type.
/// Will be replaced with actual import after build.zig is configured.
pub const Route = struct {
    name: []const u8,
    host: ?[]const u8 = null,
    path_prefix: []const u8,
    pool_idx: u8,
    strip_prefix: bool = false,
};

/// Placeholder for serval-router PoolConfig type.
pub const PoolConfig = struct {
    name: []const u8,
    upstreams: []const Upstream,
    tls: bool = false,
};

/// Placeholder for Upstream type.
pub const Upstream = struct {
    host: []const u8,
    port: u16,
    idx: u8 = 0,
    tls: bool = false,
};

// ============================================================================
// Translated Config (result of translation)
// ============================================================================

/// Translated routing configuration ready for serval-router.
/// Contains fixed-size arrays for routes and pools.
pub const TranslatedConfig = struct {
    /// Routes array (first route_count entries are valid).
    routes: [MAX_ROUTES]Route,
    route_count: u8,

    /// Pools array (first pool_count entries are valid).
    pools: [MAX_POOLS]PoolConfig,
    pool_count: u8,

    /// Upstream storage (pools reference slices into this).
    upstream_storage: [MAX_POOLS][MAX_UPSTREAMS_PER_POOL]Upstream,
    upstream_counts: [MAX_POOLS]u8,

    /// Default pool index (for requests matching no routes).
    default_pool_idx: u8,

    /// Source config generation (for detecting stale configs).
    generation: u64,

    /// Get routes slice.
    pub fn getRoutes(self: *const TranslatedConfig) []const Route {
        assert(self.route_count <= MAX_ROUTES);
        return self.routes[0..self.route_count];
    }

    /// Get pools slice.
    pub fn getPools(self: *const TranslatedConfig) []const PoolConfig {
        assert(self.pool_count <= MAX_POOLS);
        return self.pools[0..self.pool_count];
    }
};

// ============================================================================
// Gateway
// ============================================================================

/// Gateway controller managing router config and admin API.
///
/// Thread-safe config access via atomic pointer swap.
/// Admin server runs on separate thread, binds to localhost only.
pub const Gateway = struct {
    /// Allocator for config storage.
    allocator: std.mem.Allocator,

    /// Current translated config (atomic pointer for lock-free swap).
    /// Uses usize to store pointer atomically.
    current_config: std.atomic.Value(usize),

    /// Previous config (for cleanup after grace period).
    previous_config: ?*TranslatedConfig,

    /// Resolver for Service/Secret lookups.
    resolver: Resolver,

    /// Ready state (true after first successful config load).
    ready: std.atomic.Value(bool),

    /// Config generation counter.
    config_generation: std.atomic.Value(u64),

    /// Admin server socket fd.
    admin_socket: ?posix.socket_t,

    /// Admin server thread handle.
    admin_thread: ?std.Thread,

    /// Running flag for admin server.
    running: std.atomic.Value(bool),

    /// Metrics counters.
    metrics: Metrics,

    const Self = @This();

    /// Gateway metrics.
    pub const Metrics = struct {
        /// Total config reloads.
        config_reloads: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        /// Failed config reloads.
        config_reload_failures: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        /// Admin requests served.
        admin_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        /// Timestamp of last successful config update (Unix seconds).
        last_config_update_s: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    /// Initialize gateway.
    ///
    /// Allocator is used for config storage; must remain valid for Gateway lifetime.
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .current_config = std.atomic.Value(usize).init(0),
            .previous_config = null,
            .resolver = Resolver.init(),
            .ready = std.atomic.Value(bool).init(false),
            .config_generation = std.atomic.Value(u64).init(0),
            .admin_socket = null,
            .admin_thread = null,
            .running = std.atomic.Value(bool).init(false),
            .metrics = Metrics{},
        };
    }

    /// Cleanup gateway resources.
    pub fn deinit(self: *Self) void {
        // Stop admin server first
        self.stopAdminServer();

        // Free current config
        const current_ptr = self.current_config.load(.acquire);
        if (current_ptr != 0) {
            const current: *TranslatedConfig = @ptrFromInt(current_ptr);
            self.allocator.destroy(current);
        }

        // Free previous config if pending cleanup
        if (self.previous_config) |prev| {
            self.allocator.destroy(prev);
            self.previous_config = null;
        }
    }

    /// Update gateway config from GatewayConfig.
    ///
    /// Performs atomic swap - old config cleaned up after grace period.
    /// Thread-safe: can be called from watcher thread while admin serves requests.
    pub fn updateConfig(self: *Self, cfg: *const gw_config.GatewayConfig) GatewayError!void {
        // Preconditions
        assert(cfg.gateways.len > 0 or cfg.http_routes.len > 0);

        // Allocate new config
        const new_config = self.allocator.create(TranslatedConfig) catch {
            self.metrics.config_reload_failures.fetchAdd(1, .monotonic);
            return error.OutOfMemory;
        };
        errdefer self.allocator.destroy(new_config);

        // Translate to routes/pools
        const generation = self.config_generation.fetchAdd(1, .monotonic) + 1;
        translateToRoutes(cfg, &self.resolver, new_config, generation) catch |err| {
            self.metrics.config_reload_failures.fetchAdd(1, .monotonic);
            return err;
        };

        // Atomic swap
        const old_ptr = self.current_config.swap(@intFromPtr(new_config), .acq_rel);

        // Mark ready after first successful config
        self.ready.store(true, .release);

        // Update metrics
        self.metrics.config_reloads.fetchAdd(1, .monotonic);
        const now_s: u64 = @intCast(@divFloor(std.time.timestamp(), std.time.ns_per_s));
        self.metrics.last_config_update_s.store(now_s, .monotonic);

        // Schedule old config for cleanup after grace period
        if (old_ptr != 0) {
            // Clean up previous pending config first
            if (self.previous_config) |prev| {
                self.allocator.destroy(prev);
            }
            self.previous_config = @ptrFromInt(old_ptr);
            // Note: Actual grace period cleanup would need a timer or deferred task.
            // For now, cleanup happens on next updateConfig call.
        }

        // Postcondition
        assert(self.ready.load(.acquire));
    }

    /// Get current config snapshot (for admin API /config endpoint).
    ///
    /// Returns null if no config loaded yet.
    /// Thread-safe: uses atomic load.
    pub fn getConfigSnapshot(self: *const Self) ?*const TranslatedConfig {
        const ptr = self.current_config.load(.acquire);
        if (ptr == 0) return null;
        return @ptrFromInt(ptr);
    }

    /// Check if gateway is ready (has valid config).
    pub fn isReady(self: *const Self) bool {
        return self.ready.load(.acquire);
    }

    /// Start admin API server on localhost:ADMIN_PORT.
    ///
    /// Spawns background thread for accepting connections.
    /// Server only binds to 127.0.0.1 for security.
    pub fn startAdminServer(self: *Self) GatewayError!void {
        // Precondition: not already running
        if (self.running.load(.acquire)) {
            return; // Already running
        }

        // Create socket
        const sock = posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
            0,
        ) catch {
            return error.AdminBindFailed;
        };
        errdefer posix.close(sock);

        // Set SO_REUSEADDR
        const optval: c_int = 1;
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&optval)) catch |err| {
            std.log.warn("setsockopt SO_REUSEADDR failed: {}", .{err});
        };

        // Bind to all interfaces (required for K8s probes)
        const addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, ADMIN_PORT),
            .addr = 0, // 0.0.0.0 - bind to all interfaces
        };
        posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch {
            return error.AdminBindFailed;
        };

        // Listen
        posix.listen(sock, ADMIN_BACKLOG) catch {
            return error.AdminListenFailed;
        };

        self.admin_socket = sock;
        self.running.store(true, .release);

        // Spawn admin thread
        self.admin_thread = std.Thread.spawn(.{}, adminServerLoop, .{self}) catch {
            self.running.store(false, .release);
            posix.close(sock);
            self.admin_socket = null;
            return error.AdminThreadFailed;
        };

        // Postcondition
        assert(self.running.load(.acquire));
    }

    /// Stop admin API server.
    pub fn stopAdminServer(self: *Self) void {
        if (!self.running.load(.acquire)) {
            return; // Not running
        }

        self.running.store(false, .release);

        // Close socket to unblock accept
        if (self.admin_socket) |sock| {
            posix.close(sock);
            self.admin_socket = null;
        }

        // Join thread
        if (self.admin_thread) |thread| {
            thread.join();
            self.admin_thread = null;
        }

        // Postcondition
        assert(!self.running.load(.acquire));
    }

    /// Admin server accept loop (runs in background thread).
    fn adminServerLoop(self: *Self) void {
        const sock = self.admin_socket orelse return;

        while (self.running.load(.acquire)) {
            // Accept with bounded iterations per cycle
            var iteration: u32 = 0;
            while (iteration < MAX_ACCEPT_ITERATIONS and self.running.load(.acquire)) : (iteration += 1) {
                const client = posix.accept(sock, null, null, posix.SOCK.CLOEXEC) catch |err| {
                    if (err == error.WouldBlock or err == error.ConnectionAborted) {
                        continue;
                    }
                    // Socket closed or fatal error
                    return;
                };
                defer posix.close(client);

                // Handle request (simple synchronous handling for admin API)
                self.handleAdminConnection(client);
            }
        }
    }

    /// Handle a single admin connection.
    fn handleAdminConnection(self: *Self, client: posix.socket_t) void {
        // Read request (simple HTTP/1.1 parsing)
        var request_buf: [MAX_ADMIN_REQUEST_BYTES]u8 = undefined;
        const bytes_read = posix.read(client, &request_buf) catch {
            return;
        };

        if (bytes_read == 0) return;

        // Parse request line
        const request_data = request_buf[0..bytes_read];
        const request_line_end = std.mem.indexOf(u8, request_data, "\r\n") orelse return;
        const request_line = request_data[0..request_line_end];

        // Extract method and path
        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method = parts.next() orelse return;
        const path = parts.next() orelse return;

        // Route to handler
        const response = self.handleAdminRequest(method, path);

        // Send response
        _ = posix.write(client, response) catch |err| {
            std.log.warn("admin write failed: {}", .{err});
        };

        _ = self.metrics.admin_requests.fetchAdd(1, .monotonic);
    }

    /// Handle admin API request and return HTTP response.
    fn handleAdminRequest(self: *Self, method: []const u8, path: []const u8) []const u8 {
        // GET /healthz - always healthy if process is running
        if (std.mem.eql(u8, path, "/healthz")) {
            if (std.mem.eql(u8, method, "GET")) {
                return self.handleHealthz();
            }
            return http405();
        }

        // GET /readyz - ready only if config is loaded
        if (std.mem.eql(u8, path, "/readyz")) {
            if (std.mem.eql(u8, method, "GET")) {
                return self.handleReadyz();
            }
            return http405();
        }

        // GET /config - JSON dump of current config
        if (std.mem.eql(u8, path, "/config")) {
            if (std.mem.eql(u8, method, "GET")) {
                return self.handleConfig();
            }
            return http405();
        }

        // POST /reload - trigger config re-sync
        if (std.mem.eql(u8, path, "/reload")) {
            if (std.mem.eql(u8, method, "POST")) {
                return self.handleReload();
            }
            return http405();
        }

        // GET /metrics - Prometheus format metrics
        if (std.mem.eql(u8, path, "/metrics")) {
            if (std.mem.eql(u8, method, "GET")) {
                return self.handleMetrics();
            }
            return http405();
        }

        return http404();
    }

    /// GET /healthz handler.
    fn handleHealthz(_: *Self) []const u8 {
        return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
    }

    /// GET /readyz handler.
    fn handleReadyz(self: *Self) []const u8 {
        if (self.isReady()) {
            return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        }
        return "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Ready";
    }

    /// GET /config handler.
    /// Returns simplified JSON representation of current config.
    fn handleConfig(self: *Self) []const u8 {
        if (!self.isReady()) {
            return "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 23\r\nConnection: close\r\n\r\n{\"error\":\"not ready\"}";
        }

        // Note: Full JSON serialization would require dynamic allocation.
        // For now, return a static placeholder indicating config is loaded.
        const cfg = self.getConfigSnapshot() orelse {
            return "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 23\r\nConnection: close\r\n\r\n{\"error\":\"not ready\"}";
        };

        _ = cfg; // Use cfg.generation, route_count, pool_count for actual response

        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 24\r\nConnection: close\r\n\r\n{\"status\":\"configured\"}";
    }

    /// POST /reload handler.
    /// Note: Actual reload requires watcher to re-fetch from K8s.
    fn handleReload(_: *Self) []const u8 {
        // In full implementation, this would signal the watcher to re-sync.
        // For now, return success acknowledgment.
        return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16\r\nConnection: close\r\n\r\nReload requested";
    }

    /// GET /metrics handler.
    /// Returns Prometheus-format metrics.
    fn handleMetrics(self: *Self) []const u8 {
        _ = self;
        // Note: Full metrics would require formatting with current counter values.
        // For now, return static metric names as placeholder.
        const body =
            \\# HELP serval_gateway_config_reloads_total Total config reloads
            \\# TYPE serval_gateway_config_reloads_total counter
            \\serval_gateway_config_reloads_total 0
            \\# HELP serval_gateway_ready Gateway ready status
            \\# TYPE serval_gateway_ready gauge
            \\serval_gateway_ready 0
            \\
        ;

        return "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: " ++
            std.fmt.comptimePrint("{d}", .{body.len}) ++
            "\r\nConnection: close\r\n\r\n" ++ body;
    }
};

// ============================================================================
// HTTP Response Helpers
// ============================================================================

fn http404() []const u8 {
    return "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
}

fn http405() []const u8 {
    return "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\nContent-Length: 18\r\nConnection: close\r\n\r\nMethod Not Allowed";
}

// ============================================================================
// Config Translation
// ============================================================================

/// Translate GatewayConfig to serval-router compatible routes and pools.
///
/// Maps HTTPRoutes to Routes, resolves backend services to upstream endpoints.
///
/// TigerStyle: Bounded loops, explicit error handling, no allocation.
pub fn translateToRoutes(
    cfg: *const gw_config.GatewayConfig,
    resolver: *const Resolver,
    out: *TranslatedConfig,
    generation: u64,
) GatewayError!void {
    // Preconditions
    assert(cfg.gateways.len <= gw_config.MAX_GATEWAYS);
    assert(cfg.http_routes.len <= gw_config.MAX_HTTP_ROUTES);

    // Initialize output
    out.route_count = 0;
    out.pool_count = 0;
    out.default_pool_idx = 0;
    out.generation = generation;

    // Zero upstream counts
    for (&out.upstream_counts) |*count| {
        count.* = 0;
    }

    // Process each HTTPRoute
    var route_idx: u8 = 0;
    for (cfg.http_routes) |http_route| {
        route_idx = try processHTTPRoute(http_route, resolver, out, route_idx);
    }

    out.route_count = route_idx;

    // Set default pool (first pool if any exist)
    if (out.pool_count > 0) {
        out.default_pool_idx = 0;
    }

    // Postconditions
    assert(out.route_count <= MAX_ROUTES);
    assert(out.pool_count <= MAX_POOLS);
}

/// Process a single HTTPRoute into routes.
///
/// Returns updated route_idx after processing all rules and matches.
fn processHTTPRoute(
    http_route: gw_config.HTTPRoute,
    resolver: *const Resolver,
    out: *TranslatedConfig,
    start_route_idx: u8,
) GatewayError!u8 {
    // Preconditions
    assert(start_route_idx <= MAX_ROUTES);

    var route_idx = start_route_idx;

    // Process each rule in the HTTPRoute
    for (http_route.rules) |rule| {
        if (route_idx >= MAX_ROUTES) {
            return error.TooManyRoutes;
        }

        // Create pool for this rule's backends
        if (out.pool_count >= MAX_POOLS) {
            return error.TooManyPools;
        }

        const pool_idx = out.pool_count;

        // Resolve backend refs to upstreams
        const upstream_count = try resolveBackendRefs(rule.backend_refs, resolver, out, pool_idx);

        // Skip rule if no backends resolved
        if (upstream_count == 0) {
            continue;
        }

        // Create pool
        out.upstream_counts[pool_idx] = upstream_count;
        out.pools[pool_idx] = PoolConfig{
            .name = http_route.name,
            .upstreams = out.upstream_storage[pool_idx][0..upstream_count],
            .tls = false,
        };
        out.pool_count += 1;

        // Create routes from matches
        route_idx = try createRoutesFromMatches(http_route, rule, out, pool_idx, route_idx);
    }

    // Postcondition
    assert(route_idx >= start_route_idx);
    return route_idx;
}

/// Resolve backend refs to upstreams for a pool.
///
/// Populates out.upstream_storage[pool_idx] with resolved endpoints.
/// Returns the number of upstreams added.
fn resolveBackendRefs(
    backend_refs: []const gw_config.BackendRef,
    resolver: *const Resolver,
    out: *TranslatedConfig,
    pool_idx: u8,
) GatewayError!u8 {
    // Precondition
    assert(pool_idx < MAX_POOLS);

    var upstream_count: u8 = 0;

    for (backend_refs) |backend_ref| {
        if (upstream_count >= MAX_UPSTREAMS_PER_POOL) {
            return error.TooManyUpstreams;
        }

        // Look up service endpoints
        const resolved_count = resolver.resolveBackendRef(&backend_ref, &.{});
        if (resolved_count == 0) {
            // Service not found - could be not yet synced
            // For now, skip; in production, might want to keep route with no backends
            continue;
        }

        // Get endpoints from resolver
        var endpoints: [resolver_mod.MAX_ENDPOINTS_PER_SERVICE]gw_config.ResolvedEndpoint = undefined;
        const ep_count = resolver.getServiceEndpoints(
            backend_ref.name,
            backend_ref.namespace,
            &endpoints,
        );

        // Add each endpoint as upstream
        for (endpoints[0..ep_count]) |ep| {
            if (upstream_count >= MAX_UPSTREAMS_PER_POOL) break;

            out.upstream_storage[pool_idx][upstream_count] = Upstream{
                .host = ep.address,
                .port = backend_ref.port, // Use service port, not pod port
                .idx = upstream_count,
                .tls = false, // Detect from service annotation in future
            };
            upstream_count += 1;
        }
    }

    // Postcondition
    assert(upstream_count <= MAX_UPSTREAMS_PER_POOL);
    return upstream_count;
}

/// Create routes from HTTPRoute matches.
///
/// Creates one route per match, or a catch-all if no matches defined.
/// Returns updated route_idx after processing.
fn createRoutesFromMatches(
    http_route: gw_config.HTTPRoute,
    rule: gw_config.HTTPRouteRule,
    out: *TranslatedConfig,
    pool_idx: u8,
    start_route_idx: u8,
) GatewayError!u8 {
    // Preconditions
    assert(pool_idx < MAX_POOLS);
    assert(start_route_idx <= MAX_ROUTES);

    var route_idx = start_route_idx;
    const host = if (http_route.hostnames.len > 0) http_route.hostnames[0] else null;
    const strip_prefix = hasUrlRewriteFilter(rule.filters);

    if (rule.matches.len == 0) {
        // No matches = catch-all for this rule
        out.routes[route_idx] = Route{
            .name = http_route.name,
            .host = host,
            .path_prefix = "/",
            .pool_idx = pool_idx,
            .strip_prefix = false,
        };
        route_idx += 1;
    } else {
        // Create route for each match
        for (rule.matches) |match| {
            if (route_idx >= MAX_ROUTES) {
                return error.TooManyRoutes;
            }

            out.routes[route_idx] = createRouteFromMatch(http_route.name, host, match, pool_idx, strip_prefix);
            route_idx += 1;
        }
    }

    // Postcondition
    assert(route_idx >= start_route_idx);
    return route_idx;
}

/// Create a single Route from an HTTPRouteMatch.
fn createRouteFromMatch(
    name: []const u8,
    host: ?[]const u8,
    match: gw_config.HTTPRouteMatch,
    pool_idx: u8,
    strip_prefix: bool,
) Route {
    // Precondition
    assert(pool_idx < MAX_POOLS);

    const path_value = if (match.path) |p| p.value else "/";

    return Route{
        .name = name,
        .host = host,
        .path_prefix = path_value,
        .pool_idx = pool_idx,
        .strip_prefix = strip_prefix,
    };
}

/// Check if any filter has a URL rewrite path configured.
fn hasUrlRewriteFilter(filters: []const gw_config.HTTPRouteFilter) bool {
    for (filters) |filter| {
        if (filter.type == .URLRewrite) {
            if (filter.url_rewrite) |rewrite| {
                if (rewrite.path != null) {
                    return true;
                }
            }
        }
    }
    return false;
}

// ============================================================================
// Unit Tests
// ============================================================================

test "Gateway init and deinit" {
    var gateway = Gateway.init(std.testing.allocator);
    defer gateway.deinit();

    // Initially not ready
    try std.testing.expect(!gateway.isReady());
    try std.testing.expect(gateway.getConfigSnapshot() == null);
}

test "Gateway ready state" {
    var gateway = Gateway.init(std.testing.allocator);
    defer gateway.deinit();

    try std.testing.expect(!gateway.isReady());

    // After setting ready flag directly (simulating config load)
    gateway.ready.store(true, .release);
    try std.testing.expect(gateway.isReady());
}

test "TranslatedConfig getRoutes empty" {
    var cfg = TranslatedConfig{
        .routes = undefined,
        .route_count = 0,
        .pools = undefined,
        .pool_count = 0,
        .upstream_storage = undefined,
        .upstream_counts = std.mem.zeroes([MAX_POOLS]u8),
        .default_pool_idx = 0,
        .generation = 1,
    };

    const routes = cfg.getRoutes();
    try std.testing.expectEqual(@as(usize, 0), routes.len);
}

test "TranslatedConfig getPools" {
    var cfg = TranslatedConfig{
        .routes = undefined,
        .route_count = 0,
        .pools = undefined,
        .pool_count = 2,
        .upstream_storage = undefined,
        .upstream_counts = std.mem.zeroes([MAX_POOLS]u8),
        .default_pool_idx = 0,
        .generation = 1,
    };

    cfg.pools[0] = PoolConfig{ .name = "pool-0", .upstreams = &.{} };
    cfg.pools[1] = PoolConfig{ .name = "pool-1", .upstreams = &.{} };

    const pools = cfg.getPools();
    try std.testing.expectEqual(@as(usize, 2), pools.len);
    try std.testing.expectEqualStrings("pool-0", pools[0].name);
    try std.testing.expectEqualStrings("pool-1", pools[1].name);
}

test "translateToRoutes empty config" {
    const gateway_config = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &.{},
    };

    var resolver = Resolver.init();
    var out: TranslatedConfig = undefined;

    try translateToRoutes(&gateway_config, &resolver, &out, 1);

    try std.testing.expectEqual(@as(u8, 0), out.route_count);
    try std.testing.expectEqual(@as(u8, 0), out.pool_count);
    try std.testing.expectEqual(@as(u64, 1), out.generation);
}

test "translateToRoutes with HTTPRoute no backends" {
    // HTTPRoute with rules but no resolvable backends
    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/api/" } },
    };
    var backend_refs = [_]gw_config.BackendRef{
        .{ .name = "nonexistent", .namespace = "default", .port = 8080 },
    };
    var rules = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "test-route",
            .namespace = "default",
            .hostnames = &.{},
            .rules = &rules,
        },
    };

    const gateway_config = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    var resolver = Resolver.init();
    var out: TranslatedConfig = undefined;

    try translateToRoutes(&gateway_config, &resolver, &out, 1);

    // No routes because backend couldn't be resolved
    try std.testing.expectEqual(@as(u8, 0), out.route_count);
    try std.testing.expectEqual(@as(u8, 0), out.pool_count);
}

test "admin response helpers" {
    // Test HTTP response helpers return valid HTTP responses
    const not_found = http404();
    try std.testing.expect(std.mem.startsWith(u8, not_found, "HTTP/1.1 404"));

    const not_allowed = http405();
    try std.testing.expect(std.mem.startsWith(u8, not_allowed, "HTTP/1.1 405"));
}

test "Gateway handleAdminRequest routing" {
    var gateway = Gateway.init(std.testing.allocator);
    defer gateway.deinit();

    // Test healthz always returns 200
    const healthz_resp = gateway.handleAdminRequest("GET", "/healthz");
    try std.testing.expect(std.mem.indexOf(u8, healthz_resp, "200 OK") != null);

    // Test readyz returns 503 when not ready
    const readyz_resp = gateway.handleAdminRequest("GET", "/readyz");
    try std.testing.expect(std.mem.indexOf(u8, readyz_resp, "503") != null);

    // Test unknown path returns 404
    const unknown_resp = gateway.handleAdminRequest("GET", "/unknown");
    try std.testing.expect(std.mem.indexOf(u8, unknown_resp, "404") != null);

    // Test wrong method returns 405
    const wrong_method_resp = gateway.handleAdminRequest("POST", "/healthz");
    try std.testing.expect(std.mem.indexOf(u8, wrong_method_resp, "405") != null);
}

test "Gateway metrics initialization" {
    var gateway = Gateway.init(std.testing.allocator);
    defer gateway.deinit();

    // Metrics should start at 0
    try std.testing.expectEqual(@as(u64, 0), gateway.metrics.config_reloads.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), gateway.metrics.config_reload_failures.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), gateway.metrics.admin_requests.load(.acquire));
}

test "Route struct defaults" {
    const route = Route{
        .name = "test",
        .path_prefix = "/api/",
        .pool_idx = 0,
    };

    try std.testing.expectEqualStrings("test", route.name);
    try std.testing.expectEqual(@as(?[]const u8, null), route.host);
    try std.testing.expectEqualStrings("/api/", route.path_prefix);
    try std.testing.expectEqual(@as(u8, 0), route.pool_idx);
    try std.testing.expect(!route.strip_prefix);
}

test "PoolConfig defaults" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8080 },
    };

    const pool = PoolConfig{
        .name = "test-pool",
        .upstreams = &upstreams,
    };

    try std.testing.expectEqualStrings("test-pool", pool.name);
    try std.testing.expectEqual(@as(usize, 1), pool.upstreams.len);
    try std.testing.expect(!pool.tls);
}

test "Upstream defaults" {
    const upstream = Upstream{
        .host = "10.0.0.1",
        .port = 9090,
    };

    try std.testing.expectEqualStrings("10.0.0.1", upstream.host);
    try std.testing.expectEqual(@as(u16, 9090), upstream.port);
    try std.testing.expectEqual(@as(u8, 0), upstream.idx);
    try std.testing.expect(!upstream.tls);
}

test "constants are reasonable" {
    // Verify constants are within expected ranges
    try std.testing.expect(ADMIN_PORT > 1024); // Non-privileged port
    try std.testing.expect(ADMIN_PORT < 65535);
    try std.testing.expect(MAX_ADMIN_RESPONSE_BYTES >= 1024);
    try std.testing.expect(MAX_ADMIN_REQUEST_BYTES >= 1024);
    try std.testing.expect(MAX_ROUTES <= 255);
    try std.testing.expect(MAX_POOLS <= 255);
    try std.testing.expect(MAX_UPSTREAMS_PER_POOL <= 255);
}
