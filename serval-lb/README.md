# serval-lb

Load balancer handler for serval HTTP server.

## Purpose

Standalone load balancing module compatible with serval's handler interface. Like Pingora's separate crates, this can be used independently or composed with the serval server.

## Exports

- `LbHandler` - Round-robin load balancer handler

## Usage

```zig
const serval_lb = @import("serval-lb");
const serval = @import("serval");

const upstreams = [_]serval.Upstream{
    .{ .host = "backend1", .port = 8001, .idx = 0 },
    .{ .host = "backend2", .port = 8002, .idx = 1 },
    .{ .host = "backend3", .port = 8003, .idx = 2 },
};

var handler = serval_lb.LbHandler.init(&upstreams);
var server = serval.Server(
    serval_lb.LbHandler,
    serval.SimplePool,
    serval.NoopMetrics,
    serval.NoopTracer,
).init(&handler, &pool, &metrics, &tracer, config);
```

## LbHandler

```zig
pub const LbHandler = struct {
    upstreams: []const Upstream,
    next_idx: u32 = 0,

    pub fn init(upstreams: []const Upstream) LbHandler
    pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) Upstream
};
```

## Load Balancing Algorithm

Currently implements simple round-robin:
- Cycles through upstreams in order
- Wraps at end of list
- Uses wrapping addition to handle u32 overflow

## Implementation Status

| Feature | Status |
|---------|--------|
| Round-robin | Complete |
| Weighted round-robin | Not implemented |
| Least connections | Not implemented |
| IP hash | Not implemented |
| Health checks | Not implemented |
| Circuit breaker | Not implemented |

## Handler Interface

LbHandler implements the required handler interface:

```zig
pub fn selectUpstream(self, ctx: *Context, request: *const Request) Upstream
```

Optional hooks (not implemented):
- `onRequest` - Pre-routing hook
- `onResponse` - Post-response hook
- `onError` - Error handling hook
- `onLog` - Logging hook

## TigerStyle Compliance

- No allocation (references caller's upstream slice)
- Wrapping arithmetic for counter overflow
- Assertion that upstreams.len > 0
- Explicit u32 for counter
