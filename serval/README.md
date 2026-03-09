# serval

HTTP/1.1 reverse proxy server library.

## Purpose

Complete, batteries-included server library that composes all serval modules. Import this single module to get access to the full functionality.

## Architecture

```
serval (this module)
├── serval-core     # Types, config, errors, context
├── serval-http     # HTTP/1.1 parser
├── serval-websocket # RFC 6455 handshake + frame helpers
├── serval-pool     # Connection pooling
├── serval-proxy    # Upstream forwarding
├── serval-metrics  # Request metrics
└── serval-tracing  # Distributed tracing
```

## Quick Start

```zig
const serval = @import("serval");
const serval_lb = @import("serval-lb");
const serval_net = @import("serval-net");

const upstreams = [_]serval.Upstream{
    .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
};

var handler = serval_lb.LbHandler.init(&upstreams);
var pool = serval.SimplePool.init();
var metrics = serval.NoopMetrics{};
var tracer = serval.NoopTracer{};

var server = serval.Server(
    serval_lb.LbHandler,
    serval.SimplePool,
    serval.NoopMetrics,
    serval.NoopTracer,
).init(&handler, &pool, &metrics, &tracer, .{ .port = 8080 }, null, serval_net.DnsConfig{});

var shutdown = std.atomic.Value(bool).init(false);
try server.run(io, &shutdown, null);
```

## Re-exports

Serval uses the **facade pattern** to provide convenient access to all sub-module types. See [ARCHITECTURE.md](ARCHITECTURE.md#the-facade-pattern-re-exports) for the rationale and maintenance guidelines.

You can access types two ways:
- `serval.Parser` — convenient, flat namespace
- `serval.http.Parser` — explicit module origin

### From serval-core
- Types: `Request`, `Response`, `Upstream`, `HeaderMap`, `Method`, `Version`, `Action`
- Config: `Config`, `MAX_HEADERS`, `MAX_HEADER_SIZE_BYTES`, etc.
- Errors: `ParseError`, `ConnectionError`, `RequestError`, `ErrorContext`, `LogEntry`
- Context: `Context`

### From serval-http
- `Parser`

### From serval-websocket
- `WebSocketHandshakeError`
- `WebSocketFrameError`
- `WebSocketCloseError`
- `WebSocketSubprotocolError`
- `WebSocketOpcode`
- `WebSocketFrameHeader`
- `looksLikeWebSocketUpgradeRequest`
- `validateWebSocketRequest`
- `computeWebSocketAcceptKey`
- `parseWebSocketFrameHeader`
- `buildWebSocketFrameHeader`
- `parseWebSocketClosePayload`
- `buildWebSocketClosePayload`
- `validateWebSocketSubprotocolSelection`

### From serval-pool
- `Connection`, `SimplePool`, `NoPool`, `verifyPool`

### From serval-proxy
- `Forwarder`, `ForwardError`, `ForwardResult`

### From serval-metrics
- `NoopMetrics`, `PrometheusMetrics`, `verifyMetrics`

### From serval-tracing
- `SpanHandle`, `NoopTracer`, `verifyTracer`

### Local
- `Server` - Generic HTTP/1.1 server
- `MinimalServer` - Server with SimplePool + NoopMetrics + NoopTracer
- `WebSocketRouteAction`, `WebSocketAccept`, `WebSocketSession`
- `WebSocketMessage`, `WebSocketMessageKind`, `WebSocketSessionStats`
- `verifyHandler`, `hasHook` - Handler interface utilities

## Server Generic Parameters

```zig
pub fn Server(
    comptime Handler: type,   // Must implement selectUpstream()
    comptime Pool: type,      // Connection pool (SimplePool, NoPool)
    comptime Metrics: type,   // Metrics collector (NoopMetrics, PrometheusMetrics)
    comptime Tracer: type,    // Distributed tracer (NoopTracer)
) type
```

## Handler Interface

Required:
```zig
pub fn selectUpstream(self, ctx: *Context, request: *const Request) Upstream
```

Optional hooks:
```zig
pub fn onRequest(self, ctx: *Context, request: *Request, response_buf: []u8) Action
pub fn onResponse(self, ctx: *Context, response: *Response) void
pub fn onError(self, ctx: *Context, err: ErrorContext) void
pub fn onLog(self, ctx: *Context, entry: LogEntry) void
pub fn selectWebSocket(self, ctx: *Context, request: *const Request) WebSocketRouteAction
pub fn handleWebSocket(self, ctx: *Context, request: *const Request, session: *WebSocketSession) !void
```

`onRequest` can return `.continue_request` to forward, or `.{ .send_response = DirectResponse{...} }` to respond directly without forwarding (for backends, health endpoints, etc.).

`selectWebSocket` lets the handler accept native WebSocket termination for a request.
If it returns `.{ .accept = ... }`, the server sends `101 Switching Protocols` and then
calls `handleWebSocket()` with a message-oriented session API.

## Implementation Status

| Feature | Status |
|---------|--------|
| HTTP/1.1 parsing | Complete |
| Keep-alive connections | Complete |
| Connection: close handling | Complete (RFC 9112) |
| Upstream forwarding | Complete |
| WebSocket proxy tunneling | Complete |
| Native WebSocket endpoint serving | Complete |
| Connection pooling | Complete |
| Zero-copy (splice) | Complete |
| Metrics collection | Complete |
| Handler hooks | Complete |
| HTTP/2 | Not implemented |
| TLS termination | Complete |
| Request body forwarding | Complete |
| Chunked encoding | Complete |

## TigerStyle Compliance

- Compile-time interface verification for all pluggable components
- No runtime allocation after init
- Fixed buffer sizes throughout
- Explicit error handling
- Bounded loops
- Assertions for preconditions and postconditions
