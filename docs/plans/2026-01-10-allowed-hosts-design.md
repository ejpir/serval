# Allowed Hosts Validation Design

**Date:** 2026-01-10
**Status:** Approved
**Author:** Claude + Nick

## Overview

Add host validation to the router to reject requests for hosts the gateway is not configured to serve. This prevents the gateway from routing traffic for arbitrary hosts.

## Requirements

- Validate Host header against configured allowed hosts BEFORE route matching
- Return 421 Misdirected Request when Host doesn't match
- Empty allowed_hosts = allow any host (backwards compatible)
- Exact match only (no wildcards for now - future enhancement)
- Case-insensitive comparison per RFC 9110

## Data Flow

```
Gateway listeners (K8s)
    ↓ hostnames extracted by watcher
GatewayConfig.gateways[].listeners[].hostname
    ↓ translator collects unique hostnames
JSON: {"allowed_hosts": ["api.example.com"], "routes": [...]}
    ↓ router_example parses JSON
Router.allowed_hosts: []const []const u8
    ↓ selectUpstream() validates Host header
Reject 421 or continue to route matching
```

## Implementation

### 1. Constants (serval-core/config.zig)

```zig
/// Maximum allowed hosts per router (TigerStyle S7: bounded queues).
pub const MAX_ALLOWED_HOSTS: u8 = 64;

/// Maximum hostname length in bytes (RFC 1035).
pub const MAX_HOSTNAME_LEN: u8 = 253;
```

### 2. Router Changes (serval-router/router.zig)

Add `allowed_hosts` field and validation in `selectUpstream()`:

```zig
pub const Router = struct {
    routes: []const Route,
    default_route: Route,
    pools: []Pool,
    pool_storage: [MAX_POOLS]Pool = undefined,
    allowed_hosts: []const []const u8 = &.{},  // NEW

    pub fn init(
        self: *Self,
        routes: []const Route,
        default_route: Route,
        pool_configs: []const PoolConfig,
        allowed_hosts: []const []const u8,  // NEW
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

        // Continue with existing route matching...
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

Extract hostnames from Gateway listeners:

```zig
pub fn translateToJson(
    config_ptr: *const gw_config.GatewayConfig,
    resolved_backends: []const gw_config.ResolvedBackend,
    out_buf: *[MAX_JSON_SIZE_BYTES]u8,
) TranslatorError!usize {
    var writer = JsonWriter.init(out_buf);
    writer.writeRaw("{") catch return error.BufferTooSmall;

    // Write allowed_hosts array from Gateway listeners
    writer.writeRaw("\"allowed_hosts\":[") catch return error.BufferTooSmall;
    var host_count: u8 = 0;

    for (config_ptr.gateways, 0..) |gateway, gw_i| {
        if (gw_i >= gw_config.MAX_GATEWAYS) break;

        for (gateway.listeners, 0..) |listener, l_i| {
            if (l_i >= gw_config.MAX_LISTENERS) break;

            if (listener.hostname) |hostname| {
                if (host_count >= MAX_ALLOWED_HOSTS) break;
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

    // ... existing routes/pools code ...
}
```

### 4. router_example.zig Changes

Add parsing and storage for allowed_hosts:

```zig
const ConfigJson = struct {
    allowed_hosts: []const []const u8 = &.{},
    routes: []const RouteJson = &.{},
    default_route: RouteJson,
    pools: []const PoolJson,
};

const ConfigStorage = struct {
    // ... existing fields ...
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
```

## JSON Format

```json
{
  "allowed_hosts": ["api.example.com", "www.example.com"],
  "routes": [
    {"name": "api", "host": "api.example.com", "path_prefix": "/api/", "pool_idx": 0}
  ],
  "default_route": {"name": "default", "path_prefix": "/", "pool_idx": 0},
  "pools": [
    {"name": "api-pool", "upstreams": [{"host": "10.0.1.5", "port": 8001, "idx": 0}]}
  ]
}
```

## Files to Modify

1. `serval-core/config.zig` - Add MAX_ALLOWED_HOSTS, MAX_HOSTNAME_LEN constants
2. `serval-router/router.zig` - Add allowed_hosts field, validation in selectUpstream()
3. `serval-k8s-gateway/translator.zig` - Extract hostnames from Gateway listeners
4. `examples/router_example.zig` - Parse allowed_hosts, pass to Router.init

## Future Enhancements

- Wildcard hostname matching (*.example.com)
- Per-listener hostname validation (vs global allowed list)

## TigerStyle Compliance

- S1: Assertions in isHostAllowed and selectUpstream
- S4: Bounded loops with MAX_ALLOWED_HOSTS limit
- S7: allowed_hosts bounded by MAX_ALLOWED_HOSTS constant
- Y5: Comments explain RFC references and design rationale
