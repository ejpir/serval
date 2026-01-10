# Allowed Hosts Validation Design

**Date:** 2026-01-10
**Status:** Approved
**Author:** Claude + Nick

## Overview

Add host validation to the router to reject requests for hosts the gateway is not configured to serve. Also remove `default_route` - unmatched requests return 404 instead of routing to a fallback.

## Requirements

- Validate Host header against configured allowed hosts BEFORE route matching
- Return 421 Misdirected Request when Host doesn't match allowed_hosts
- Return 404 Not Found when no route matches (no default_route fallback)
- Empty allowed_hosts = allow any host (backwards compatible)
- Router does exact match only (no wildcards)
- Controller does wildcard matching for Gateway listener → HTTPRoute compatibility
- Case-insensitive comparison per RFC 9110

## Request Flow

```
Request arrives
    ↓
Host in allowed_hosts? ──NO──→ 421 Misdirected Request
    ↓ YES
Route matches? ──NO──→ 404 Not Found
    ↓ YES
Forward to backend pool
```

## Data Flow

```
Gateway listener: hostname = "*.example.com" (may have wildcards)
    ↓
Controller checks: HTTPRoute hostnames compatible with listener?
    ↓ wildcard matching in controller
HTTPRoute: hostnames = ["api.example.com", "www.example.com"]
    ↓ translator extracts HTTPRoute hostnames (specific, no wildcards)
JSON: {"allowed_hosts": ["api.example.com", "www.example.com"], ...}
    ↓ router_example parses JSON
Router.allowed_hosts (exact match only)
    ↓ selectUpstream() validates Host header
Reject 421, 404, or forward to backend
```

## Wildcard Handling

| Component | Wildcard support | Hostname source |
|-----------|-----------------|-----------------|
| Controller | YES (compatibility check) | Gateway listeners |
| Translator | NO (passes through) | HTTPRoute hostnames |
| Router | NO (exact match only) | allowed_hosts from translator |

Example:
- Gateway listener: `*.example.com`
- HTTPRoute: `["api.example.com", "www.example.com"]`
- Controller: checks `api.example.com` matches `*.example.com` → YES, attach route
- Router receives: `allowed_hosts: ["api.example.com", "www.example.com"]`
- Router does exact matching only

## Implementation

### 1. Constants (serval-core/config.zig)

```zig
/// Maximum allowed hosts per router (TigerStyle S7: bounded queues).
pub const MAX_ALLOWED_HOSTS: u8 = 64;

/// Maximum hostname length in bytes (RFC 1035).
pub const MAX_HOSTNAME_LEN: u16 = 253;
```

### 2. Router Changes (serval-router/router.zig)

Remove `default_route`, add `allowed_hosts`, return 404 on no match:

```zig
pub const Router = struct {
    routes: []const Route,
    // REMOVED: default_route: Route,
    pools: []Pool,
    pool_storage: [MAX_POOLS]Pool = undefined,
    allowed_hosts: []const []const u8 = &.{},

    pub fn init(
        self: *Self,
        routes: []const Route,
        // REMOVED: default_route: Route,
        pool_configs: []const PoolConfig,
        allowed_hosts: []const []const u8,
        client_ctx: ?*ssl.SSL_CTX,
        dns_resolver: ?*DnsResolver,
    ) !void {
        // S1: Preconditions
        assert(allowed_hosts.len <= MAX_ALLOWED_HOSTS);
        // ... existing init ...
        self.allowed_hosts = allowed_hosts;
    }

    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Action {
        // S1: Preconditions
        assert(self.pools.len > 0);
        assert(self.allowed_hosts.len <= MAX_ALLOWED_HOSTS);

        const host = request.headers.getHost();

        // Validate Host against allowed_hosts (if any configured).
        // Empty allowed_hosts = allow any host (backwards compatible).
        if (self.allowed_hosts.len > 0) {
            if (!self.isHostAllowed(host)) {
                // 421 per RFC 9110: server is not configured to serve this host.
                return .{ .reject = .{
                    .status = 421,
                    .body = "Misdirected Request",
                }};
            }
        }

        // Find matching route - no default fallback
        const route = self.findRoute(request) orelse {
            return .{ .reject = .{
                .status = 404,
                .body = "Not Found",
            }};
        };

        // Store rewritten path if strip_prefix enabled
        ctx.rewritten_path = self.rewritePath(route, request.path);

        // Delegate to pool's LbHandler for health-aware selection
        assert(route.pool_idx < self.pools.len);
        return .{ .forward = self.pools[route.pool_idx].lb_handler.selectUpstream(ctx, request) };
    }

    /// Find matching route. Returns null if no route matches.
    fn findRoute(self: *const Self, request: *const Request) ?*const Route {
        assert(self.routes.len <= MAX_ROUTES);

        const host = request.headers.getHost();
        const path = request.path;

        for (self.routes) |*route| {
            if (route.matcher.matches(host, path)) {
                return route;
            }
        }
        return null;  // No default fallback
    }

    /// Check if Host header matches any allowed hostname.
    fn isHostAllowed(self: *const Self, host: ?[]const u8) bool {
        // S1: Preconditions
        assert(self.allowed_hosts.len <= MAX_ALLOWED_HOSTS);

        const h = host orelse return false;
        assert(h.len <= MAX_HOSTNAME_LEN);

        // Strip port if present. RFC 9110 §7.2: Host may include port.
        const hostname = if (std.mem.indexOfScalar(u8, h, ':')) |i| h[0..i] else h;

        // S4: Bounded loop
        for (self.allowed_hosts, 0..) |allowed, i| {
            assert(i < MAX_ALLOWED_HOSTS);
            // RFC 9110 §4.2.3: Host comparison is case-insensitive.
            if (std.ascii.eqlIgnoreCase(allowed, hostname)) {
                return true;
            }
        }
        return false;
    }
};
```

### 3. Translator Changes (serval-k8s-gateway/translator.zig)

Extract hostnames from **HTTPRoutes** (not Gateway listeners):

```zig
pub fn translateToJson(
    config_ptr: *const gw_config.GatewayConfig,
    resolved_backends: []const gw_config.ResolvedBackend,
    out_buf: *[MAX_JSON_SIZE_BYTES]u8,
) TranslatorError!usize {
    var writer = JsonWriter.init(out_buf);
    writer.writeRaw("{") catch return error.BufferTooSmall;

    // Write allowed_hosts array from HTTPRoute hostnames
    // (NOT from Gateway listeners - those may have wildcards)
    writer.writeRaw("\"allowed_hosts\":[") catch return error.BufferTooSmall;
    var host_count: u8 = 0;

    for (config_ptr.http_routes, 0..) |http_route, route_i| {
        if (route_i >= gw_config.MAX_HTTP_ROUTES) break;

        for (http_route.hostnames, 0..) |hostname, h_i| {
            if (h_i >= gw_config.MAX_HOSTNAMES) break;
            if (host_count >= MAX_ALLOWED_HOSTS) break;

            // Skip duplicates (simple O(n) check, bounded by MAX_ALLOWED_HOSTS)
            var is_duplicate = false;
            // ... duplicate check omitted for brevity ...

            if (!is_duplicate) {
                if (host_count > 0) {
                    writer.writeRaw(",") catch return error.BufferTooSmall;
                }
                writer.writeRaw("\"") catch return error.BufferTooSmall;
                writer.writeRaw(hostname) catch return error.BufferTooSmall;
                writer.writeRaw("\"") catch return error.BufferTooSmall;
                host_count += 1;
            }
        }
    }

    writer.writeRaw("],") catch return error.BufferTooSmall;

    // Write routes array (existing code)
    // REMOVED: default_route from output
    // Write pools array (existing code)
}
```

### 4. router_example.zig Changes

Remove default_route, add allowed_hosts parsing:

```zig
const ConfigJson = struct {
    allowed_hosts: []const []const u8 = &.{},
    routes: []const RouteJson = &.{},
    // REMOVED: default_route: RouteJson,
    pools: []const PoolJson,
};

const ConfigStorage = struct {
    // ... existing fields ...
    // REMOVED: default route storage

    allowed_hosts_storage: [config.MAX_ALLOWED_HOSTS][config.MAX_HOSTNAME_LEN]u8 = undefined,
    allowed_hosts_ptrs: [config.MAX_ALLOWED_HOSTS][]const u8 = undefined,
    allowed_hosts_count: u8 = 0,

    fn copyAllowedHosts(self: *Self, hosts: []const []const u8) ![]const []const u8 {
        assert(hosts.len <= config.MAX_ALLOWED_HOSTS);

        for (hosts, 0..) |host, i| {
            assert(host.len <= config.MAX_HOSTNAME_LEN);
            @memcpy(self.allowed_hosts_storage[i][0..host.len], host);
            self.allowed_hosts_ptrs[i] = self.allowed_hosts_storage[i][0..host.len];
        }
        self.allowed_hosts_count = @intCast(hosts.len);
        return self.allowed_hosts_ptrs[0..hosts.len];
    }
};

fn swapRouter(
    routes: []const Route,
    // REMOVED: default_route: Route,
    pool_configs: []const PoolConfig,
    allowed_hosts: []const []const u8,
    dns_resolver: ?*DnsResolver,
) !void {
    // ... copy to persistent storage ...
    try router_storage[inactive_slot].init(
        persistent_routes,
        // REMOVED: persistent_default,
        persistent_pools,
        persistent_allowed_hosts,
        null,
        dns_resolver,
    );
}
```

## JSON Format

```json
{
  "allowed_hosts": ["api.example.com", "www.example.com"],
  "routes": [
    {"name": "api", "host": "api.example.com", "path_prefix": "/api/", "pool_idx": 0}
  ],
  "pools": [
    {"name": "api-pool", "upstreams": [{"host": "10.0.1.5", "port": 8001, "idx": 0}]}
  ]
}
```

Note: `default_route` is removed from JSON format.

## Files to Modify

1. `serval-core/config.zig` - Add MAX_ALLOWED_HOSTS, MAX_HOSTNAME_LEN constants
2. `serval-router/router.zig` - Remove default_route, add allowed_hosts, return 404 on no match
3. `serval-k8s-gateway/translator.zig` - Extract hostnames from HTTPRoutes, remove default_route output
4. `examples/router_example.zig` - Remove default_route, parse allowed_hosts, update swapRouter

## Breaking Changes

- `default_route` removed from Router.init() signature
- `default_route` removed from JSON config format
- Requests that previously fell through to default_route now get 404

## Future Enhancements

- Wildcard hostname matching in controller (*.example.com)
- HTTPRoute status updates (Accepted/Rejected based on listener compatibility)

## TigerStyle Compliance

- S1: Assertions in isHostAllowed and selectUpstream
- S4: Bounded loops with MAX_ALLOWED_HOSTS limit
- S7: allowed_hosts bounded by MAX_ALLOWED_HOSTS constant
- Y5: Comments explain RFC references and design rationale
