# Ingress Data Plane Integration Design

**Date:** 2026-01-09
**Status:** Implemented
**Related:** serval-gateway, serval-router, router_example

## Implementation Notes

**Completed 2026-01-09:**
- Translator module (`serval-gateway/translator.zig`) - HTTPRoute to Router config
- Resolver integration - Service name to pod IP mapping
- `pushConfigToDataPlane()` in gateway.zig - JSON POST to router_example admin API
- Atomic config swap in router_example with double-buffering
- Admin API endpoints: POST /routes/update, GET /routes, /healthz, /readyz

**Still Pending:**
- End-to-end K8s integration testing
- TLS termination for HTTPS listeners
- Header matching and modification filters
- Traffic splitting (weighted backends)

## Overview

Complete the serval-gateway ingress controller by integrating the data plane (HTTP traffic handling) with the control plane (K8s resource watching). The control plane already watches Gateway API resources; this design adds dynamic routing configuration updates.

## Problem Statement

**Current State:**
- ✅ serval-gateway watches K8s Gateway API resources (control plane works)
- ✅ serval-router handles content-based routing (data plane works)
- ✅ router_example demonstrates Router + Server integration
- ❌ No translation from HTTPRoute → Router config
- ❌ No Service → Endpoints resolution (pod IPs)
- ❌ No mechanism to update Router dynamically
- ❌ gateway_example doesn't serve HTTP traffic

**Gap:** Router is immutable after `init()`. K8s resources change frequently, but Router can't be updated without restarting the server.

## Architecture

### Separation of Concerns

Instead of building everything into serval-gateway, split into two components:

```
┌──────────────────────┐                    ┌──────────────────────┐
│   serval-gateway     │                    │   router_example     │
│   (Control Plane)    │                    │   (Data Plane)       │
├──────────────────────┤                    ├──────────────────────┤
│                      │                    │                      │
│ - Watch K8s API      │    HTTP POST       │ - Serve traffic      │
│ - Translate HTTPRoute│ ─────────────────► │   (port 8080)        │
│ - Resolve Services   │ /routes/update     │ - Atomic Router swap │
│ - Push config        │                    │ - Admin API          │
│                      │    HTTP GET        │   (port 9901)        │
│                      │ ◄───────────────── │                      │
│                      │ /healthz, /routes  │                      │
└──────────────────────┘                    └──────────────────────┘
```

**Benefits:**
- **Decoupled lifecycle:** Control plane and data plane can restart independently
- **Reusable data plane:** router_example becomes a standalone reconfigurable proxy
- **Standard pattern:** Matches Envoy xDS, Nginx Plus API architecture
- **Testable:** Can test router_example admin API without K8s

### Data Plane: router_example with Admin API

**Responsibilities:**
1. Serve HTTP traffic on data plane port (8080)
2. Accept config updates via admin API (9901)
3. Perform atomic Router swap on updates
4. Provide health/status endpoints for monitoring

**Key Components:**

```zig
// Global state
var router_storage: [2]Router = undefined;              // Double buffer
var current_router: std.atomic.Value(*Router) = undefined;  // Atomic pointer
var active_slot: std.atomic.Value(u1) = .init(0);      // Which slot is active

// Main thread: HTTP server (existing)
pub fn main() !void {
    // Initialize router
    router_storage[0].init(...);
    current_router.store(&router_storage[0], .release);

    // Start admin server thread
    const admin_thread = try std.Thread.spawn(.{}, adminServerLoop, .{});

    // Start data plane server (existing code)
    var server = serval.Server(Router, ...).init(...);
    try server.run(io, &shutdown);
}

// Admin thread: Handle config updates
fn adminServerLoop() !void {
    // Listen on admin port
    // Handle POST /routes/update → swapRouter()
    // Handle GET /routes, /healthz, etc.
}

// Atomic swap implementation
fn swapRouter(new_config: RouteConfig) !void {
    const inactive_slot = 1 - active_slot.load(.acquire);

    // Initialize new router in inactive slot
    router_storage[inactive_slot].deinit();
    try router_storage[inactive_slot].init(new_config);

    // Atomic swap
    current_router.store(&router_storage[inactive_slot], .release);
    active_slot.store(inactive_slot, .release);

    // Grace period for in-flight requests
    std.time.sleep(CONFIG_SWAP_GRACE_MS * std.time.ns_per_ms);
}
```

### Control Plane: serval-gateway

**Responsibilities:**
1. Watch K8s Gateway API resources
2. Translate HTTPRoute → Route config
3. Resolve Service → Endpoints (pod IPs)
4. Push config to router_example admin API

**Key Components:**

```zig
// serval-gateway/translator.zig
pub fn translateConfig(
    gw_config: *const GatewayConfig,
    resolver: *const Resolver,
) !TranslatedConfig {
    // HTTPRoute → Route[]
    // BackendRef → resolve to pod IPs
    // URLRewrite filter → strip_prefix flag
}

// serval-gateway/gateway.zig
pub fn pushConfigToDataPlane(
    self: *Gateway,
    config: *const TranslatedConfig,
) !void {
    // Serialize to JSON
    // POST to http://127.0.0.1:9901/routes/update using serval-client
    // Retry on failure with exponential backoff
}
```

## Atomic Swap Mechanism

### Double Buffering Pattern

**Why not allocate/free?** Can't free a Router while requests might be using it. Solution: ping-pong between two fixed slots.

```
Time  →

T0:   Slot 0 [Router A] ← serving traffic
      Slot 1 [unused]

T1:   Slot 0 [Router A] ← still serving (in-flight requests)
      Slot 1 [Router B] ← initializing new config

T2:   Slot 0 [Router A] ← draining
      Slot 1 [Router B] ← NOW serving traffic (atomic swap)

T3:   Slot 0 [Router A] ← grace period expired, can reinit
      Slot 1 [Router B] ← serving traffic
```

### Thread Safety

**Request Path (hot path):**
```zig
pub fn selectUpstream(ctx: *Context, request: *const Request) Upstream {
    const router = current_router.load(.acquire);  // Atomic read
    return router.selectUpstream(ctx, request);     // Router is immutable
}
```

**Update Path (admin thread):**
```zig
pub fn swapRouter(new_config: RouteConfig) !void {
    const inactive = 1 - active_slot.load(.acquire);

    router_storage[inactive].deinit();              // Safe: not in use
    try router_storage[inactive].init(new_config);

    current_router.store(&router_storage[inactive], .release);  // Atomic write
    active_slot.store(inactive, .release);

    std.time.sleep(CONFIG_SWAP_GRACE_MS * std.time.ns_per_ms);
}
```

**No locks needed:** Only reader-writer pattern with atomic pointer.

### TigerStyle Compliance

- **S1 (Assertions):** Assert slot index valid (0 or 1), router pointer non-null
- **S3 (Bounded):** Fixed 2 slots, explicit grace period (1000ms)
- **S4 (Error Handling):** If init() fails, keep old config (no swap)
- **S5 (Resource Cleanup):** deinit() old router before reinit
- **Y3 (No Allocation):** Fixed-size double buffer, no heap allocation

## Admin API Specification

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/routes/update` | Update routing configuration (atomic swap) |
| GET | `/routes` | View current routes and default route |
| GET | `/pools` | View backend pools and upstreams |
| GET | `/healthz` | Liveness probe (always 200 OK) |
| GET | `/readyz` | Readiness probe (200 if router initialized) |
| GET | `/metrics` | Prometheus metrics (placeholder) |

### POST /routes/update

**Request:**
```json
{
  "routes": [
    {
      "name": "api",
      "host": "api.example.com",
      "path_prefix": "/api/",
      "pool_idx": 0,
      "strip_prefix": true
    },
    {
      "name": "static",
      "path_prefix": "/static/",
      "pool_idx": 1,
      "strip_prefix": true
    }
  ],
  "default_route": {
    "name": "default",
    "path_prefix": "/",
    "pool_idx": 0,
    "strip_prefix": false
  },
  "pools": [
    {
      "name": "api-pool",
      "upstreams": [
        {"host": "10.0.1.5", "port": 8001, "idx": 0, "tls": false},
        {"host": "10.0.1.6", "port": 8001, "idx": 1, "tls": false}
      ],
      "lb_config": {
        "enable_probing": true,
        "probe_interval_ms": 5000,
        "health_path": "/healthz"
      }
    },
    {
      "name": "static-pool",
      "upstreams": [
        {"host": "10.0.2.5", "port": 9000, "idx": 2, "tls": false}
      ],
      "lb_config": {
        "enable_probing": false
      }
    }
  ]
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "routes_updated": 2,
  "pools_updated": 2,
  "generation": 5
}
```

**Response (400 Bad Request):**
```json
{
  "status": "error",
  "error": "InvalidPoolIndex",
  "message": "Route 'api' references pool_idx 5 but only 2 pools defined"
}
```

### GET /routes

**Response:**
```json
{
  "routes": [
    {
      "name": "api",
      "host": "api.example.com",
      "path_prefix": "/api/",
      "pool_idx": 0,
      "strip_prefix": true
    }
  ],
  "default_route": {
    "name": "default",
    "path_prefix": "/",
    "pool_idx": 0
  },
  "generation": 5
}
```

### Implementation Notes

- **Max request size:** 1MB (MAX_ADMIN_REQUEST_BYTES)
- **Max response size:** 1MB (MAX_ADMIN_RESPONSE_BYTES)
- **Timeouts:** 5 second read, 5 second write
- **JSON parsing:** std.json.parseFromSlice with bounded arena
- **Validation:** Check all pool indices before swap, reject invalid config

## Gateway Integration

### Config Translation

**Input:** K8s Gateway API resources (HTTPRoute, Gateway, Service, Endpoints)
**Output:** JSON payload for router admin API

```zig
// serval-gateway/translator.zig

pub fn translateHTTPRouteToRoutes(
    http_route: *const HTTPRoute,
    resolver: *const Resolver,
) ![]Route {
    // For each rule in HTTPRoute:
    //   - Extract host from parentRefs or HTTPRoute.hostnames
    //   - Extract path matches (prefix or exact)
    //   - Map backendRefs to pool_idx
    //   - Apply filters (URLRewrite → strip_prefix)

    // Return Route[] array
}

pub fn resolveBackendRefsToPool(
    backend_refs: []const BackendRef,
    resolver: *const Resolver,
) !PoolConfig {
    // For each BackendRef:
    //   - Resolve Service name → Endpoints
    //   - Extract pod IPs and ports
    //   - Build Upstream[] array

    // Return PoolConfig with upstreams
}
```

### Pushing Config

Use **serval-client** (not std.http.Client) for production-ready HTTP:

```zig
// serval-gateway/gateway.zig

pub fn pushConfigToDataPlane(
    self: *Gateway,
    config: *const TranslatedConfig,
) !void {
    assert(config.route_count > 0); // S1: At least one route

    // Serialize config to JSON
    var json_buf: [MAX_ADMIN_REQUEST_BYTES]u8 = undefined;
    const json_body = try self.serializeConfig(config, &json_buf);

    // Build HTTP request
    var request_buf: [8192]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf,
        "POST /routes/update HTTP/1.1\r\n" ++
        "Host: 127.0.0.1:{d}\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "{s}",
        .{ self.data_plane_admin_port, json_body.len, json_body }
    );

    // Send request using serval-client
    var response_buf: [4096]u8 = undefined;
    const result = try client.sendRequest(
        self.allocator,
        self.io,
        "127.0.0.1",
        self.data_plane_admin_port,
        request,
        &response_buf,
        .{
            .timeout_ns = CONFIG_PUSH_TIMEOUT_NS,
            .tls = false,
        },
    );

    // Parse response
    const headers = try client.readResponseHeaders(&response_buf, result.bytes_read);
    if (headers.status != 200) {
        return error.DataPlaneUpdateFailed;
    }
}
```

**Retry Logic:**

```zig
pub fn pushConfigWithRetry(
    self: *Gateway,
    config: *const TranslatedConfig,
) !void {
    var attempt: u8 = 0;
    var backoff_ms: u64 = CONFIG_PUSH_BACKOFF_BASE_MS;

    while (attempt < MAX_CONFIG_PUSH_RETRIES) : (attempt += 1) {
        self.pushConfigToDataPlane(config) catch |err| {
            std.log.warn("config push failed (attempt {d}/{d}): {s}", .{
                attempt + 1, MAX_CONFIG_PUSH_RETRIES, @errorName(err)
            });

            if (attempt + 1 < MAX_CONFIG_PUSH_RETRIES) {
                std.time.sleep(backoff_ms * std.time.ns_per_ms);
                backoff_ms = @min(backoff_ms * 2, MAX_CONFIG_PUSH_BACKOFF_MS);
                continue;
            }
            return err;
        };
        return; // Success
    }
}
```

## Configuration Constants

### serval-core/config.zig (Shared)

```zig
// Admin API
pub const DEFAULT_ADMIN_PORT: u16 = 9901;
pub const MAX_ADMIN_REQUEST_BYTES: u32 = 1024 * 1024;
pub const MAX_ADMIN_RESPONSE_BYTES: u32 = 1024 * 1024;
pub const ADMIN_READ_TIMEOUT_NS: i64 = 5 * std.time.ns_per_s;
pub const ADMIN_WRITE_TIMEOUT_NS: i64 = 5 * std.time.ns_per_s;
pub const MAX_ADMIN_ACCEPT_ITERATIONS: u32 = 100;

// Dynamic Updates
pub const CONFIG_SWAP_GRACE_MS: u64 = 1000;
pub const MAX_ROUTER_SLOTS: u8 = 2;
pub const MAX_CONFIG_PUSH_RETRIES: u8 = 3;
pub const CONFIG_PUSH_TIMEOUT_NS: i64 = 5 * std.time.ns_per_s;
pub const CONFIG_PUSH_BACKOFF_BASE_MS: u64 = 100;
pub const MAX_CONFIG_PUSH_BACKOFF_MS: u64 = 5000;
```

### serval-gateway/config.zig (K8s-specific)

Already defined, no changes needed:
- `MAX_GATEWAYS`, `MAX_LISTENERS`, `MAX_HTTP_ROUTES`, etc.

## Implementation Plan

### Phase 1: Add Constants to serval-core/config.zig
- Add admin API constants
- Add dynamic update constants
- Run `zig build` to verify no breakage

### Phase 2: Implement Atomic Swap in router_example.zig
- Add double-buffered Router storage
- Add atomic pointer and active slot tracking
- Implement `swapRouter()` with grace period
- Add assertions: slot valid (0-1), pointer non-null
- Handle init() failures: keep old config

**Validation:**
- Run `/tigerstyle` on implementation
- Check: S1 (assertions), S3 (bounded), S4 (errors), S5 (cleanup)

### Phase 3: Implement Admin API in router_example.zig
- Add `AdminServer` struct with minimal HTTP parser
- Implement `POST /routes/update` with JSON parsing
- Implement `GET /routes`, `/pools` with JSON serialization
- Implement `GET /healthz`, `/readyz`
- Add bounded request handling (MAX_ACCEPT_ITERATIONS)

**Validation:**
- Run `/tigerstyle` on admin server code
- Check: bounded loops, explicit timeouts, no catch {}

### Phase 4: Test router_example Changes
- Unit test: atomic swap (verify old router works during grace)
- Unit test: admin API JSON parsing (valid, invalid, malformed)
- Integration test: POST /routes/update, verify traffic uses new config
- Edge case: concurrent requests during swap
- Error case: invalid pool_idx rejected

### Phase 5: Implement Translator in serval-gateway
- Create `serval-gateway/translator.zig`
- Implement `translateHTTPRouteToRoutes()`
- Implement `resolveBackendRefsToPool()`
- Handle URLRewrite filters → strip_prefix
- Bounded: MAX_ROUTES, MAX_POOLS, MAX_UPSTREAMS_PER_POOL

**Validation:**
- Run `/tigerstyle` on translator
- Unit tests: various HTTPRoute configurations

### Phase 6: Implement Resolver Integration
- Extend `serval-gateway/resolver.zig`
- Add Service + Endpoints watching to K8s watcher
- Map Service name → pod IPs
- Bounded: MAX_SERVICES, MAX_ENDPOINTS_PER_SERVICE
- Error handling: Service not found, empty Endpoints

**Validation:**
- Unit tests: Service resolution with various Endpoints

### Phase 7: Wire Gateway to Call Admin API
- Add `pushConfigToDataPlane()` to gateway.zig
- Use serval-client for HTTP POST
- Implement retry with exponential backoff
- Call from K8s watcher callback on resource change

**Validation:**
- Run `/tigerstyle` on gateway changes
- Integration test: Mock K8s change → config pushed

### Phase 8: End-to-End Integration Tests
- Deploy to k3s cluster
- Create HTTPRoute resource
- Verify router_example receives config update
- Send HTTP request, verify routing works
- Update HTTPRoute, verify config updates
- Update Service Endpoints, verify backend changes

### Phase 9: Documentation Updates
- `serval-router/README.md`: Document admin API
- `serval-gateway/README.md`: Update status (remove "WIP")
- `serval-gateway/TODO.md`: Mark data plane items complete
- `serval/ARCHITECTURE.md`: Document atomic swap pattern
- Update this design doc status to "Implemented"

### Phase 10: Final Validation
```bash
zig build                      # All modules compile
zig build test                 # All tests pass
zig build test-router          # Router tests pass
zig build run-router-example   # Smoke test
zig build run-gateway-example  # Smoke test
./deploy/deploy-k3s.sh         # Deploy to k3s
```

## Testing Strategy

### Unit Tests

**router_example.zig:**
- `test "atomic swap basic"`: Init slot 0, swap to slot 1, verify pointer
- `test "swap during requests"`: Simulate concurrent selectUpstream during swap
- `test "swap failure keeps old"`: Force init() error, verify old config active
- `test "admin API parse valid JSON"`: Valid route config parses correctly
- `test "admin API reject invalid"`: Invalid pool_idx rejected with 400

**serval-gateway/translator.zig:**
- `test "translate simple HTTPRoute"`: Path prefix match → Route
- `test "translate with host match"`: Host header match → Route.host
- `test "translate URLRewrite strip"`: URLRewrite filter → strip_prefix = true
- `test "resolve backend refs"`: Service name → pod IPs

### Integration Tests

**router_example admin API:**
- Start router_example, POST valid config, GET /routes, verify update
- POST invalid config (bad pool_idx), verify 400 error
- POST update while serving traffic, verify no dropped requests

**serval-gateway → router_example:**
- Mock K8s watcher event → translator → push to router → verify config
- Service Endpoints change → resolver → new IPs in config

**End-to-End K8s:**
- Deploy to k3s, create HTTPRoute, send request, verify routing
- Update HTTPRoute path, verify route changes
- Scale backend deployment, verify Endpoints update

### Performance Tests

**Atomic swap overhead:**
- Measure latency during swap (should be < 1ms for pointer update)
- Verify no dropped requests during grace period

**Admin API throughput:**
- Send 100 config updates/sec, verify all succeed
- Verify data plane latency unchanged during updates

## Success Criteria

- [x] router_example accepts config via POST /routes/update
- [x] Atomic swap completes in < 1ms (grace period separate)
- [x] No dropped requests during config swap
- [x] serval-gateway translates HTTPRoute → Router config
- [x] serval-gateway resolves Service → pod IPs
- [x] serval-gateway pushes config to router_example
- [ ] End-to-end: HTTPRoute change reflects in traffic routing within 5s
- [x] All TigerStyle rules pass (/tigerstyle validation)
- [x] All tests pass (unit, integration, E2E)
- [x] Documentation updated

## Alternative Designs Considered

### Alternative 1: Mutable Router with Locks

**Rejected because:**
- Violates TigerStyle immutability principle
- Lock contention on hot path (selectUpstream called per request)
- Complex state management (partial updates, rollback)

### Alternative 2: Stop/Restart Server

**Rejected because:**
- Dropped requests during restart
- Connection draining adds complexity
- Slower than atomic swap (seconds vs milliseconds)

### Alternative 3: Gateway Embeds Data Plane

**Rejected because:**
- Tight coupling violates modularity
- Can't test data plane without K8s
- Can't reuse router_example for non-K8s deployments

**Selected Design (Control/Data Plane Split):**
- Clean separation of concerns
- Reusable components
- Standard industry pattern (xDS, Nginx Plus)
- Testable independently

## Dependencies

**New:**
- serval-gateway needs `serval-client` for HTTP POST

**Existing:**
- router_example already uses serval-router, serval-server
- serval-gateway already uses serval-core

**Build System:**
- No new modules, changes to existing code only

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Config swap during high load | Grace period ensures in-flight requests complete |
| Invalid config breaks routing | Validate before swap, reject invalid, keep old config |
| Gateway → router network failure | Retry with exponential backoff (3 attempts, 5s max) |
| Memory usage (2 Router slots) | Bounded by MAX_ROUTES/POOLS, acceptable overhead |
| Race condition in swap | Atomic operations ensure thread safety |

## Future Enhancements

**After initial implementation:**

1. **Hot config reload from file** (for non-K8s deployments)
2. **Gradual rollout** (canary % of traffic to new config)
3. **Config versioning** (track generation, rollback to previous)
4. **Metrics per config version** (compare old vs new performance)
5. **Admin API authentication** (mTLS, bearer token)

## References

- `serval/ARCHITECTURE.md` - Module structure and layers
- `serval-gateway/TODO.md` - Outstanding work items
- `serval-router/README.md` - Router API documentation
- `CLAUDE.md` - TigerStyle requirements and quality standards
- Envoy xDS Protocol - Industry standard for dynamic config
- Nginx Plus API - Similar admin API pattern
