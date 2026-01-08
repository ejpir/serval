# serval-router Design

Content-based routing module for serval, providing the foundation for API gateway functionality and Kubernetes Gateway API integration.

## Overview

**Layer**: 4 (Strategy) - alongside `serval-lb`

**Purpose**: Route requests to backend pools based on host and path matching.

**Dependencies**:
- `serval-core` (types, config, context)
- `serval-lb` (LbHandler for backend pools)
- `serval-health` (indirect, via serval-lb)

## Design Decisions

| Decision | Choice | Future |
|----------|--------|--------|
| Routing scope | Path prefix, exact path, host matching | Headers, query params, method |
| Backend pools | Compose LbHandler per pool | - |
| Configuration | Compile-time routes | Runtime mutable routes |
| Path rewriting | Strip prefix only | Strip and replace |
| Fallback | Required default route | - |

## Types

### Route Matching

```zig
/// Path match mode
pub const PathMatch = union(enum) {
    /// Exact path match: "/api/v1/users" matches only "/api/v1/users"
    exact: []const u8,
    /// Prefix match: "/api/" matches "/api/users", "/api/v1/health"
    prefix: []const u8,
};

/// Route match criteria
pub const RouteMatcher = struct {
    /// Host to match (null = any host)
    host: ?[]const u8 = null,
    /// Path match mode
    path: PathMatch,
};

/// A single route entry
pub const Route = struct {
    /// Route name for logging/debugging
    name: []const u8,
    /// Match criteria
    matcher: RouteMatcher,
    /// Index into backend pools array
    pool_idx: u8,
    /// Strip matched prefix before forwarding
    strip_prefix: bool = false,
};
```

### Backend Pool Configuration

```zig
/// Configuration for a backend pool
pub const PoolConfig = struct {
    /// Pool name for logging/debugging
    name: []const u8,
    /// Upstream servers in this pool
    upstreams: []const Upstream,
    /// Load balancer configuration
    lb_config: LbHandler.LbConfig = .{},
};
```

### Router

```zig
pub const Router = struct {
    routes: []const Route,
    default_route: Route,
    pools: []Pool,

    pub const Pool = struct {
        name: []const u8,
        lb: LbHandler,
    };

    /// Initialize router with routes and backend pools.
    pub fn init(
        self: *Router,
        routes: []const Route,
        default_route: Route,
        pool_configs: []const PoolConfig,
        client_ctx: ?*ssl.SSL_CTX,
    ) !void;

    /// Stop all pool prober threads.
    pub fn deinit(self: *Router) void;

    /// Handler interface - select upstream for request.
    pub fn selectUpstream(
        self: *Router,
        ctx: *Context,
        request: *const Request,
    ) Upstream;

    /// Handler interface - forward health tracking to correct pool.
    pub fn onLog(self: *Router, ctx: *Context, entry: LogEntry) void;
};
```

## Route Matching Algorithm

First match wins, evaluated in route slice order:

```
1. For each route in routes:
   a. If route.matcher.host is set:
      - Extract host from request Host header (strip port if present)
      - If hosts don't match, skip route
   b. Check path:
      - exact: path must equal route path exactly
      - prefix: path must start with route prefix
   c. If both match, return route
2. Return default_route
```

**Match priority**: User controls via route order. Convention:
- More specific routes first (exact before prefix)
- Longer prefixes before shorter
- Host-specific before wildcard host

## Path Rewriting

When `strip_prefix = true` on a prefix route:

| Route Prefix | Request Path | Rewritten Path |
|--------------|--------------|----------------|
| `/api/v1` | `/api/v1/users` | `/users` |
| `/api/v1/` | `/api/v1/` | `/` |
| `/api` | `/api/users` | `/users` |
| `/api` | `/api` | `/` |

Implementation:
- Zero-copy: returns slice into original path
- Ensures result always starts with `/`
- Exact match routes ignore `strip_prefix`
- Rewritten path stored in `ctx.rewritten_path`

**Context change required**: Add `rewritten_path: ?[]const u8 = null` to `serval-core/context.zig`. Forwarder uses this instead of `request.path` if set.

## File Structure

```
serval-router/
├── mod.zig      # Re-exports
├── router.zig   # Router handler, matching logic
└── types.zig    # Route, RouteMatcher, PathMatch, PoolConfig
```

## Handler Interface

Router implements the handler interface:

**Required**:
- `selectUpstream(ctx, request) -> Upstream`

**Optional hooks**:
- `onLog(ctx, entry)` - forwards to correct pool for health tracking

## Testing Plan

### Unit Tests

1. **Route matching**
   - Exact path match
   - Prefix path match
   - Host matching (with/without port)
   - Host + path combination
   - Default route fallback

2. **Path rewriting**
   - Strip prefix basic case
   - Strip prefix preserves leading slash
   - Strip prefix edge case (path equals prefix)
   - Exact match ignores strip_prefix
   - Disabled strip_prefix

3. **Pool integration**
   - Routes delegate to correct pool
   - onLog updates correct pool's health
   - Multiple pools with independent health

4. **Edge cases**
   - Empty path handling
   - Query string preservation
   - Case sensitivity

### Integration Test

Full router with multiple pools, verify routing and health tracking.

All tests use `enable_probing = false`.

## Kubernetes Gateway API Alignment

This design provides the foundation for Gateway API HTTPRoute support. Mapping:

| Gateway API | serval-router | Status |
|-------------|---------------|--------|
| `PathPrefix` | `PathMatch.prefix` | Implemented |
| `Exact` | `PathMatch.exact` | Implemented |
| `hostnames[]` | `RouteMatcher.host` | Implemented |
| `ReplacePrefixMatch` | `strip_prefix` | Partial (strip only, no replace) |
| `backendRef.weight` | - | Future (via LbHandler weighted selection) |
| `headers[]` | - | Future |
| `queryParams[]` | - | Future |
| `method` | - | Future |
| `RegularExpression` | - | Future |
| `ReplaceFullPath` | - | Future |

**Match semantics alignment:**
- Gateway API: Multiple `matches[]` per rule use OR logic (any match succeeds)
- Gateway API: Within a match, conditions are ANDed (all must succeed)
- serval-router: First matching route wins (user controls order)
- serval-router: Currently only path + host AND logic

**Weighted backends:**
Gateway API uses proportional weights (sum = denominator, default = 1). Future serval-router can support this by extending LbHandler with weighted selection, keeping weights on Upstream structs within each pool.

**Runtime configuration:**
Gateway API expects dynamic route updates from control plane. Phase 2 will add runtime mutable routes with bounded route table and atomic swap.

## Future Work

1. **Runtime mutable routes** - For Kubernetes Gateway API control plane updates
2. **Additional matchers** - Headers, query params, method matching (AND logic)
3. **Match OR logic** - Multiple matches per route, any can succeed
4. **Path replacement** - `ReplacePrefixMatch` with custom replacement prefix
5. **Regex path matching** - `RegularExpression` path match type
6. **Weighted backends** - Proportional traffic splitting within pools
