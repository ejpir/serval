# serval-router

Content-based router for serval HTTP server.

## Purpose

Routes incoming requests to backend pools based on host and path matching. Each pool embeds an LbHandler for health-aware load balancing. Supports path rewriting (strip prefix) for API gateway patterns.

## Layer

Layer 4 (Strategy) - alongside serval-lb.

## Exports

- `Router` - Content-based router with per-pool load balancing
- `Route` - Route entry mapping match criteria to a backend pool
- `RouteMatcher` - Host + path match criteria
- `PathMatch` - Path match mode (exact or prefix)
- `PoolConfig` - Backend pool configuration with LB settings

## Features

### Host + Path Matching

Routes match on optional host (case-insensitive per RFC 9110) and required path (exact or prefix):

```zig
// Match any host with path prefix
.matcher = .{ .path = .{ .prefix = "/api/" } }

// Match specific host with exact path
.matcher = .{ .host = "api.example.com", .path = .{ .exact = "/health" } }
```

### Path Rewriting (Strip Prefix)

Remove matched prefix before forwarding to backend:

```zig
// Route: "/api/" -> backend, strip_prefix=true
// Request: "/api/users" -> Backend receives: "/users"
.strip_prefix = true
```

### Per-Pool Load Balancing

Each pool has its own LbHandler with independent health tracking and background probing.

### First-Match Routing

Routes are evaluated in order; first match wins. A default route is required when no routes match.

## Usage

```zig
const serval_router = @import("serval-router");
const serval = @import("serval");

// Define upstreams for each pool
const api_upstreams = [_]serval.Upstream{
    .{ .host = "api-1.internal", .port = 8001, .idx = 0 },
    .{ .host = "api-2.internal", .port = 8002, .idx = 1 },
};

const static_upstreams = [_]serval.Upstream{
    .{ .host = "static-1.internal", .port = 9001, .idx = 2 },
};

// Define pool configurations
const pool_configs = [_]serval_router.PoolConfig{
    .{
        .name = "api-pool",
        .upstreams = &api_upstreams,
        .lb_config = .{
            .unhealthy_threshold = 3,
            .healthy_threshold = 2,
            .probe_interval_ms = 5000,
            .health_path = "/health",
        },
    },
    .{
        .name = "static-pool",
        .upstreams = &static_upstreams,
        .lb_config = .{ .enable_probing = false },
    },
};

// Define routes (evaluated in order, first match wins)
const routes = [_]serval_router.Route{
    .{
        .name = "api",
        .matcher = .{ .path = .{ .prefix = "/api/" } },
        .pool_idx = 0,       // api-pool
        .strip_prefix = true, // "/api/users" -> "/users"
    },
    .{
        .name = "static",
        .matcher = .{ .path = .{ .prefix = "/static/" } },
        .pool_idx = 1,       // static-pool
    },
};

// Default route (required)
const default_route = serval_router.Route{
    .name = "default",
    .matcher = .{ .path = .{ .prefix = "/" } },
    .pool_idx = 0,
};

// Initialize router
var router: serval_router.Router = undefined;
try router.init(&routes, default_route, &pool_configs, null);
defer router.deinit();

// Use with server (implements handler interface)
// router.selectUpstream(ctx, request) -> Upstream
// router.onLog(ctx, entry) -> forwards health tracking to correct pool
```

## API Reference

### Router

```zig
pub const Router = struct {
    routes: []const Route,
    default_route: Route,
    pools: []Pool,

    pub fn init(
        self: *Self,
        routes: []const Route,
        default_route: Route,
        pool_configs: []const PoolConfig,
        client_ctx: ?*ssl.SSL_CTX,  // For TLS health probes
    ) !void
    pub fn deinit(self: *Self) void
    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Upstream
    pub fn onLog(self: *Self, ctx: *Context, entry: LogEntry) void
    pub fn getPool(self: *const Self, idx: u8) ?*const Pool
    pub fn countTotalHealthy(self: *const Self) u32
    pub fn countTotalBackends(self: *const Self) u32
};
```

### Route

```zig
pub const Route = struct {
    name: []const u8,           // Route name for logging
    matcher: RouteMatcher,       // Host + path match criteria
    pool_idx: u8,               // Index into pools array
    strip_prefix: bool = false, // Strip matched prefix before forwarding
};
```

### RouteMatcher

```zig
pub const RouteMatcher = struct {
    host: ?[]const u8 = null,   // Host to match (null = any host)
    path: PathMatch,            // Path match mode

    pub fn matches(self: RouteMatcher, request_host: ?[]const u8, request_path: []const u8) bool
};
```

### PathMatch

```zig
pub const PathMatch = union(enum) {
    exact: []const u8,   // Exact path match
    prefix: []const u8,  // Prefix match

    pub fn matches(self: PathMatch, request_path: []const u8) bool
    pub fn getPattern(self: PathMatch) []const u8
};
```

### PoolConfig

```zig
pub const PoolConfig = struct {
    name: []const u8,              // Pool name for logging
    upstreams: []const Upstream,   // Backend servers
    lb_config: LbConfig = .{},     // Load balancer configuration
};
```

## File Structure

```
serval-router/
├── mod.zig     # Module exports
├── router.zig  # Router implementation
└── types.zig   # Route, RouteMatcher, PathMatch, PoolConfig
```

## Kubernetes Deployment

Deploy as a standalone data plane with hardcoded routes:

```bash
# Build and deploy
zig build build-router-example
./deploy/build-and-load.sh router
sudo kubectl apply -f deploy/serval-router.yaml

# Check status
sudo kubectl get pods -l app=serval-router
sudo kubectl logs -l app=serval-router

# Test routing (NodePort)
curl http://localhost:31588/api/users    # -> /users (stripped)
curl http://localhost:31588/static/img   # -> /img (stripped)
curl http://localhost:31588/other        # -> /other (default)
```

Configure backends via CLI args in `deploy/serval-router.yaml`:

```yaml
args:
  - "--port"
  - "8080"
  - "--api-backends"
  - "my-api-service:8080"
  - "--static-backends"
  - "my-static-service:8080"
```

See `deploy/README.md` for full deployment commands.

## Implementation Status

| Feature | Status |
|---------|--------|
| Host + path matching | Complete |
| Exact path match | Complete |
| Prefix path match | Complete |
| Path rewriting (strip prefix) | Complete |
| Per-pool load balancing | Complete |
| First-match routing | Complete |
| Required default route | Complete |
| Runtime mutable routes | Not implemented |
| Header matching | Not implemented |
| Regex path matching | Not implemented |
| Method matching | Not implemented |

## Dependencies

- `serval-core` - Types, config (Upstream, Context, Request)
- `serval-lb` - LbHandler, LbConfig (per-pool load balancing)
- `serval-health` - HealthState (via serval-lb)
- `serval-prober` - Background health probing (via serval-lb)
- `serval-tls` - SSL_CTX for TLS health probes

## TigerStyle Compliance

- Out-pointer init for large struct (C3)
- Bounded arrays: MAX_POOLS=64, MAX_ROUTES=128 (S3)
- No runtime allocation after init (S5)
- ~2 assertions per function (S1)
- Explicit types: u8 for pool_idx, indices (S2)
- Tagged union for PathMatch prevents invalid states (S7)
- Case-insensitive host comparison per RFC 9110 (spec compliance)
- errdefer cleanup on partial initialization failure (S6)

## Future Work

- **Runtime mutable routes**: Hot-reload route configuration without restart
- **Header matching**: Route based on header values (e.g., X-API-Version)
- **Regex path matching**: Full regex support for complex path patterns
- **Method matching**: Route based on HTTP method (GET, POST, etc.)
- **Priority/weight**: Explicit route priority instead of first-match


Commits made (7 total):

1. feat(serval-core): add rewritten_path field to Context
2. docs: add serval-router design plan
3. docs: add Gateway API alignment section
4. feat(serval-router): add content-based routing module
5. feat(serval-proxy): add path rewriting support via effective_path
6. fix(serval-router): fix onLog index mismatch for health tracking
7. feat(examples): add router_example demonstrating content-based routing

Testing:

zig build test-router     # 23 unit tests pass
zig build run-router-example  # Integration test verified

How to test manually:

# Terminal 1: Start API backend
zig build run-echo-backend -- --port 8001 --id "api"

# Terminal 2: Start static backend
zig build run-echo-backend -- --port 8002 --id "static"

# Terminal 3: Start router
zig build run-router-example -- --port 8080

# Terminal 4: Test routing
curl http://localhost:8080/api/users      # -> api:8001, path: /users
curl http://localhost:8080/static/img.png # -> static:8002, path: /img.png
curl http://localhost:8080/other          # -> api:8001, path: /other

Ready for serval-gateway

The router provides the foundation needed for Kubernetes Gateway API integration:
- Path prefix/exact matching ✅
- Host matching ✅
- Path rewriting (strip prefix) ✅
- Per-pool health-aware load balancing ✅
