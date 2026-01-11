// examples/router/json/types.zig
//! JSON Configuration Types for Router Admin API
//!
//! Types for parsing JSON request bodies in admin API endpoints.
//! TigerStyle: Fixed-size, no allocation, explicit defaults.

const serval = @import("serval");
const config = serval.config;

/// Maximum JSON body size for route updates.
pub const MAX_JSON_BODY_SIZE: u32 = 64 * 1024; // 64KB

// =============================================================================
// Full Config Types (POST /routes/update)
// =============================================================================

/// JSON representation of an upstream for parsing.
pub const UpstreamJson = struct {
    host: []const u8,
    port: u16,
    idx: u8,
    tls: bool = false,
};

/// JSON representation of LB config for parsing.
pub const LbConfigJson = struct {
    enable_probing: bool = false,
    unhealthy_threshold: u8 = config.DEFAULT_UNHEALTHY_THRESHOLD,
    healthy_threshold: u8 = config.DEFAULT_HEALTHY_THRESHOLD,
    probe_interval_ms: u32 = config.DEFAULT_PROBE_INTERVAL_MS,
    probe_timeout_ms: u32 = config.DEFAULT_PROBE_TIMEOUT_MS,
    health_path: []const u8 = config.DEFAULT_HEALTH_PATH,
};

/// JSON representation of a pool for parsing.
pub const PoolJson = struct {
    name: []const u8,
    upstreams: []const UpstreamJson,
    lb_config: LbConfigJson = .{},
};

/// JSON representation of a route for parsing.
/// Supports both prefix and exact path matching.
/// TigerStyle: Exactly one of path_prefix or path_exact must be set.
pub const RouteJson = struct {
    name: []const u8,
    /// Prefix path match (e.g., "/api/" matches "/api/users").
    path_prefix: ?[]const u8 = null,
    /// Exact path match (e.g., "/health" matches only "/health").
    path_exact: ?[]const u8 = null,
    pool_idx: u8,
    strip_prefix: bool = false,
    host: ?[]const u8 = null,
};

/// JSON representation of full config for parsing.
pub const ConfigJson = struct {
    allowed_hosts: []const []const u8 = &.{},
    routes: []const RouteJson = &.{},
    pools: []const PoolJson,
};

// =============================================================================
// Incremental CRUD Types
// =============================================================================

/// JSON for POST /routes/add - add a single route.
/// TigerStyle: Exactly one of path_prefix or path_exact must be set.
pub const AddRouteJson = struct {
    name: []const u8,
    /// Prefix path match (e.g., "/api/" matches "/api/users").
    path_prefix: ?[]const u8 = null,
    /// Exact path match (e.g., "/health" matches only "/health").
    path_exact: ?[]const u8 = null,
    pool_idx: u8,
    strip_prefix: bool = false,
    host: ?[]const u8 = null,
};

/// JSON for POST /routes/remove - remove route by name.
pub const RemoveRouteJson = struct {
    name: []const u8,
};

/// JSON for POST /pools/add - add a new pool with upstreams.
pub const AddPoolJson = struct {
    name: []const u8,
    upstreams: []const UpstreamJson,
    lb_config: LbConfigJson = .{},
};

/// JSON for POST /pools/remove - remove pool by name.
pub const RemovePoolJson = struct {
    name: []const u8,
};

/// JSON for POST /upstreams/add - add upstream to existing pool.
pub const AddUpstreamJson = struct {
    pool_name: []const u8,
    host: []const u8,
    port: u16,
    idx: u8,
    tls: bool = false,
};

/// JSON for POST /upstreams/remove - remove upstream from pool.
pub const RemoveUpstreamJson = struct {
    pool_name: []const u8,
    upstream_idx: u8,
};
