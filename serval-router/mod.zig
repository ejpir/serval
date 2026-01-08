// serval-router/mod.zig
//! Content-Based Router
//!
//! Routes requests to backend pools based on host and path matching.
//! Composes LbHandler per pool for health-aware load balancing.
//!
//! Layer 4 (Strategy) - alongside serval-lb

const router = @import("router.zig");
const types = @import("types.zig");

// Core router
pub const Router = router.Router;
pub const MAX_POOLS = router.MAX_POOLS;

// Types
pub const Route = types.Route;
pub const RouteMatcher = types.RouteMatcher;
pub const PathMatch = types.PathMatch;
pub const PoolConfig = types.PoolConfig;

// Re-export from dependencies for convenience
pub const LbHandler = types.LbHandler;
pub const LbConfig = types.LbConfig;
pub const Upstream = types.Upstream;

test {
    // Run tests from all submodules
    @import("std").testing.refAllDecls(@This());
    _ = router;
    _ = types;
}
