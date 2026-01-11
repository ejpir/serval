// examples/router/config_storage.zig
//! Atomic Router Configuration Storage
//!
//! Double-buffered router storage for atomic configuration updates.
//! Enables hot config reload without server restart.
//!
//! ## Design
//!
//! - Two router slots (active + inactive) enable lock-free config swaps
//! - `swapRouter()` initializes new config in inactive slot, then atomically swaps pointers
//! - Grace period allows in-flight requests to complete before old config cleanup
//! - Generation counter tracks config versions for observability
//!
//! TigerStyle: No runtime allocation after init, bounded grace period, explicit error handling.

const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;

const serval = @import("serval");
const serval_router = @import("serval-router");
const serval_net = @import("serval-net");

const config = serval.config;
const Router = serval_router.Router;
const Route = serval_router.Route;
const PoolConfig = serval_router.PoolConfig;
const Upstream = serval_router.Upstream;
const DnsResolver = serval_net.DnsResolver;

// =============================================================================
// Config Storage (per-slot)
// =============================================================================

/// Config storage for route/pool/upstream data that must outlive JSON parsing.
/// TigerStyle: All config strings and data copied here before Router.init.
/// Double-buffered (one per router slot) so old config remains valid during grace period.
pub const ConfigStorage = struct {
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
    pub fn reset(self: *Self) void {
        self.string_offset = 0;
        self.allowed_hosts_count = 0;
    }

    /// Copy a string into embedded storage, returning slice into storage.
    /// TigerStyle: Returns error if storage exhausted.
    pub fn copyString(self: *Self, s: []const u8) ![]const u8 {
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
    pub fn copyRoute(self: *Self, route: Route) !Route {
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
    pub fn copyUpstream(self: *Self, upstream: Upstream) !Upstream {
        return Upstream{
            .host = try self.copyString(upstream.host),
            .port = upstream.port,
            .idx = upstream.idx,
            .tls = upstream.tls,
        };
    }

    /// Deep copy routes into storage, returning slice.
    pub fn copyRoutes(self: *Self, routes: []const Route) ![]const Route {
        // S1: Precondition - routes within bounds
        assert(routes.len <= config.MAX_ROUTES);

        for (routes, 0..) |route, i| {
            self.route_storage[i] = try self.copyRoute(route);
        }
        return self.route_storage[0..routes.len];
    }

    /// Deep copy pool configs into storage, returning slice.
    /// Also deep copies all upstreams for each pool.
    pub fn copyPoolConfigs(self: *Self, pool_configs: []const PoolConfig) ![]const PoolConfig {
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
    pub fn copyAllowedHosts(self: *Self, hosts: []const []const u8) ![]const []const u8 {
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

// =============================================================================
// Global State (Double-Buffered Storage)
// =============================================================================

/// Double-buffered config storage (one per router slot).
/// TigerStyle: Config data lives here, outlives JSON parsing.
var storage: [config.MAX_ROUTER_SLOTS]ConfigStorage = .{ .{}, .{} };

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

// =============================================================================
// Public API
// =============================================================================

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
pub fn swapRouter(
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
    const slot_storage = &storage[inactive_slot];
    slot_storage.reset();

    const persistent_routes = try slot_storage.copyRoutes(routes);
    const persistent_pools = try slot_storage.copyPoolConfigs(pool_configs);
    const persistent_allowed_hosts = try slot_storage.copyAllowedHosts(allowed_hosts);

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
pub fn getActiveRouter() ?*Router {
    return current_router.load(.acquire);
}

/// Get the current configuration generation.
///
/// TigerStyle: Useful for observability/debugging config changes.
pub fn getRouterGeneration() u64 {
    return router_generation.load(.monotonic);
}

/// Initialize the first router in slot 0.
///
/// Must be called before server starts accepting requests.
/// TigerStyle: Explicit initialization, no implicit state.
pub fn initRouter(
    routes: []const Route,
    pool_configs: []const PoolConfig,
    allowed_hosts: []const []const u8,
    dns_resolver: ?*DnsResolver,
) !void {
    // S1: Precondition - no router initialized yet
    assert(current_router.load(.acquire) == null);
    assert(!slot_initialized[0]);

    try router_storage[0].init(routes, pool_configs, allowed_hosts, null, dns_resolver);
    slot_initialized[0] = true;
    current_router.store(&router_storage[0], .release);

    // S2: Postcondition - router available
    assert(getActiveRouter() != null);
}

/// Cleanup all initialized router slots.
///
/// Must be called before program exit to cleanup LbHandler resources.
/// TigerStyle: Explicit cleanup of all initialized slots.
pub fn deinitAllRouters() void {
    // S3: Bounded loop (MAX_ROUTER_SLOTS = 2)
    for (&router_storage, 0..) |*router, i| {
        if (slot_initialized[i]) {
            router.deinit();
            slot_initialized[i] = false;
        }
    }
    current_router.store(null, .release);
}
