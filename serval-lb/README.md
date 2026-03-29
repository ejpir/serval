# serval-lb

Health-aware load balancer handler for serval HTTP server.

## Purpose

**Single-pool load balancing** with integrated health tracking and automatic background probing. Backends marked unhealthy after consecutive failures recover automatically when probes succeed.

Use `serval-lb` when you have one set of backends and need to distribute traffic across them. For routing to different backend pools based on path/host, see `serval-router`.

## When to Use

| Need | Module |
|------|--------|
| Balance across ONE pool of backends | **serval-lb** |
| Route to DIFFERENT pools based on path/host | serval-router |

```
serval-lb:     client → [LB] → backend1, backend2, backend3
serval-router: client → [Router] → /api/* → pool1 → backend1, backend2
                                 → /static/* → pool2 → backend3, backend4
```

## Exports

- `LbHandler` - Health-aware round-robin load balancer handler (HTTP adapter)
- `LbConfig` - Configuration for thresholds, probing intervals
- `RoundRobinStrategy` - Protocol-agnostic strategy core (TCP/UDP/HTTP reuse)
- `StrategyConfig` - Strategy thresholds shared across protocol adapters

## Usage

```zig
const serval_lb = @import("serval-lb");
const serval = @import("serval");
const tls = @import("serval-tls");
const net = @import("serval-net");

const upstreams = [_]serval.Upstream{
    .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
    .{ .host = "127.0.0.1", .port = 8003, .idx = 2 },
};

var handler: serval_lb.LbHandler = undefined;
const client_ctx = try tls.ssl.createClientCtx();
defer tls.ssl.SSL_CTX_free(client_ctx);

var dns_resolver: net.DnsResolver = undefined;
net.DnsResolver.init(&dns_resolver, .{});

try handler.init(&upstreams, .{
    .unhealthy_threshold = 3,    // 3 failures -> unhealthy
    .healthy_threshold = 2,       // 2 successes -> healthy
    .probe_interval_ms = 5000,    // Probe every 5 seconds
    .probe_timeout_ms = 2000,     // 2 second probe timeout
    .health_path = "/health",     // Health check endpoint
}, client_ctx, &dns_resolver);
defer handler.deinit();
```

## LbHandler

```zig
pub const LbHandler = struct {
    upstreams: []const Upstream,
    strategy: RoundRobinStrategy,
    probe_running: std.atomic.Value(bool),
    probe_thread: ?std.Thread,
    lb_config: LbConfig,

    // TigerStyle C3: Out-pointer for large struct
    pub fn init(self: *Self, upstreams: []const Upstream, lb_config: LbConfig, client_ctx: ?*tls.ssl.SSL_CTX, dns_resolver: ?*net.DnsResolver) !void
    pub fn deinit(self: *Self) void
    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Upstream
    pub fn onLog(self: *Self, ctx: *Context, entry: LogEntry) void
    pub fn countHealthy(self: *const Self) u32
    pub fn isHealthy(self: *const Self, idx: UpstreamIndex) bool
};
```

## LbConfig

```zig
pub const LbConfig = struct {
    unhealthy_threshold: u8 = 3,         // Consecutive failures before unhealthy
    healthy_threshold: u8 = 2,           // Consecutive successes before healthy
    enable_probing: bool = true,         // Enable background health probes
    probe_interval_ms: u32 = 5000,       // Probe cycle interval
    probe_timeout_ms: u32 = 2000,        // Per-probe timeout
    health_path: []const u8 = "/",       // Health check path
};
```

## Features

### Shared Strategy Core (HTTP/TCP/UDP)

`strategy_core.zig` owns transport-agnostic upstream selection and health transitions.
HTTP, TCP, and UDP paths consume this core instead of embedding policy logic in
transport mechanics.

### Health-Aware Selection

`selectUpstream()` skips unhealthy backends, cycling through only healthy ones:
- Uses embedded `HealthState` (atomic bitmap + threshold counters)
- Falls back to simple round-robin if all backends unhealthy (graceful degradation)

### Passive Health Tracking

`onLog()` hook updates health based on response status:
- 5xx responses count as failures
- Everything else counts as success
- Threshold transitions handled automatically

### Background Health Probing

Background thread probes unhealthy backends for recovery (via `serval-prober`):
- HTTP GET to configured health path
- Only probes unhealthy backends (healthy ones get passive checks via traffic)
- On 2xx response, records success toward recovery threshold

## File Structure

```
serval-lb/
├── mod.zig            # Module exports
├── strategy_core.zig  # Protocol-agnostic round-robin + health strategy core
└── handler.zig        # HTTP adapter over strategy_core
```

## Implementation Status

| Feature | Status |
|---------|--------|
| Health-aware round-robin | Complete |
| Passive health tracking (onLog) | Complete |
| Background health probing | Complete |
| Weighted round-robin | Not implemented |
| Least connections | Not implemented |
| IP hash | Not implemented |

## Dependencies

- `serval-core` - Types, config
- `serval-health` - HealthState, UpstreamIndex
- `serval-prober` - Background health probing

## TigerStyle Compliance

- Out-pointer init for large struct (C3)
- ~2 assertions per function (S1)
- No runtime allocation after init (S5)
- Bounded loops over MAX_UPSTREAMS (S4)
- Explicit error logging in prober (S6)
- Explicit types: u8, u32, u64 (S2)
- Units in names: probe_interval_ms, timeout_ms (Y3)
