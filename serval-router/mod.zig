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
/// Public re-export of `router.Router`, the content-based router type used by `serval-router`.
/// Call `init` before use; it validates route/pool bounds and configuration consistency and may return configuration or `LbHandler.init` errors.
/// `selectUpstream` performs host + path routing (first match wins) and returns either `.forward` (selected upstream) or `.reject` (e.g. 421/404).
/// `init` borrows route/pool/host slices (caller-owned; must outlive the router), and `deinit` must be called to stop and release pool handlers.
pub const Router = router.Router;
/// Upper bound on the number of router pools supported by this module.
/// This re-exports `router.MAX_POOLS` so callers can use a stable module-level constant.
/// Exceeding this limit in pool-related configuration is invalid and should be rejected by validation paths.
pub const MAX_POOLS = router.MAX_POOLS;

// Types
/// Public re-export of `types.Route`, the route-table entry consumed by `Router`.
/// A route defines `matcher` (host + path), `pool_idx` (target backend pool), and optional `strip_prefix` path rewrite behavior.
/// Routes are evaluated in table order (first match wins), and `pool_idx` is validated by `Router.init` against configured pools.
/// Route string fields are borrowed slices; caller-owned data must outlive any `Router` that references this route.
pub const Route = types.Route;
/// Public alias for [`types.RouteMatcher`], which combines optional host matching with required `PathMatch`.
/// A route matches only when both host and path match; `host = null` matches any host.
/// Host comparison is case-insensitive and strips an optional request host port; `"*."` patterns match exactly one subdomain level.
/// `matches` is allocation-free and returns `bool` (no error union); host/path slices are borrowed and must remain valid while used.
pub const RouteMatcher = types.RouteMatcher;
/// Re-export of [`types.PathMatch`], the tagged-union path matcher used by router routes.
/// Supports `.exact`, `.exactPath` (ignores query string), and `.prefix` match modes via the same API as `types.PathMatch`.
/// This is a type alias, not a wrapper: matching behavior and return semantics are identical to the original (`matches` returns `bool`, no error union).
/// Pattern slices (`[]const u8`) are borrowed; caller-owned backing memory must remain valid for the lifetime of any stored `PathMatch` value.
pub const PathMatch = types.PathMatch;
/// Re-export of [`types.PoolConfig`], the per-backend-pool routing configuration.
/// Defines pool `name`, `upstreams`, and `lb_config` used by `Router.init`.
/// `upstreams` is a slice into caller-owned data; no ownership transfer or allocation is implied by this type.
/// Keep referenced upstream storage valid for the router lifetime when passed into router configuration.
pub const PoolConfig = types.PoolConfig;

// Re-export from dependencies for convenience
/// Public re-export of `types.LbHandler` for `serval-router` consumers.
/// This is a type alias only (compile-time namespace convenience), with no additional runtime state or behavior.
/// Ownership/lifetime requirements and all error behavior are exactly those of the underlying `LbHandler` APIs (`init`/`deinit`/selection methods).
pub const LbHandler = types.LbHandler;
/// Re-export of [`types.LbConfig`] for the public `serval-router` API surface.
/// This is a type alias, not a new type: behavior, validation rules, and field
/// semantics are defined by the original declaration in `types`.
/// Using this alias introduces no runtime behavior, ownership changes, or errors.
pub const LbConfig = types.LbConfig;
/// Re-export of [`types.Upstream`] for router-facing APIs.
/// Use this alias when referring to upstream endpoint configuration through `serval-router`.
/// Behavior, fields, validation, and lifetime semantics are defined by `types.Upstream`.
pub const Upstream = types.Upstream;

test {
    // Run tests from all submodules
    @import("std").testing.refAllDecls(@This());
    _ = router;
    _ = types;
}
