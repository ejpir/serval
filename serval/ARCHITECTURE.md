# Serval Architecture

Serval is a modular HTTP/1.1 reverse proxy library written in Zig, following TigerStyle principles.

## Philosophy

**Pingora-inspired modularity.** Like Cloudflare's Pingora, serval separates concerns into independent modules that can be used standalone or composed together. You can use just the HTTP parser, just the connection pool, or the full server.

**Compile-time composition.** All components are generic over their dependencies. The compiler verifies interfaces at build time - no runtime dispatch, no interface mismatches at runtime.

**Zero runtime allocation.** All memory is allocated at startup. Request handling uses fixed buffers. This eliminates allocation failures under load and makes memory usage predictable.

**Safety over convenience.** TigerStyle: ~2 assertions per function, bounded loops, explicit error handling. We catch bugs at development time, not in production.

### Priority Order

1. **Safety** - Correct behavior under all conditions
2. **Performance** - Efficient resource usage
3. **Developer Experience** - Clear APIs, good errors

---

## Module Structure

```
serval (umbrella - re-exports all modules)
├── serval-core     # Types, config, errors, context, hooks
├── serval-net      # Socket utilities (TCP_NODELAY, etc.)
├── serval-http     # HTTP/1.1 parser
├── serval-pool     # Connection pooling
├── serval-proxy    # Upstream forwarding (h1/ subdirectory)
├── serval-metrics  # Request metrics (real-time + Prometheus)
├── serval-tracing  # Distributed tracing interface
├── serval-otel     # OpenTelemetry implementation
└── serval-server   # HTTP server implementation (h1/ subdirectory)

Standalone modules:
├── serval-lb       # Load balancer handler (round-robin)
└── serval-cli      # CLI argument parsing utilities
```

### The Facade Pattern (Re-exports)

The `serval` umbrella module uses the **facade pattern** to provide a single import point:

```zig
// In lib/serval/mod.zig
pub const http = @import("serval-http");    // Expose module
pub const Parser = http.Parser;              // Re-export type at top level
```

**Why this pattern?**

1. **Single import for users** — `const serval = @import("serval");` gives access to everything
2. **Two access styles** — users choose between `serval.Parser` (convenient) or `serval.http.Parser` (explicit)
3. **Encapsulation** — internal module boundaries can change without breaking user code
4. **Discoverability** — IDE autocomplete shows all types in one namespace

**Maintenance rules:**

- When adding a new public type to a sub-module, also add a re-export in `mod.zig`
- Group re-exports by source module with section comments
- Keep both the module (`pub const http = ...`) and key types (`pub const Parser = ...`)

**What NOT to re-export:**

- Internal implementation types (prefixed with `_` or in `internal` namespace)
- Types only used within the module itself
- Test utilities

### Dependency Graph

```
Layer 0 (Foundation):
  serval-core ─────────────────────────────────────────────────────┐
       ↑                                                           │
       │                                                           │
Layer 1 (Protocol):                                                │
  serval-net ──────────────────────────────────────────────────────┤
       ↑                                                           │
       │                                                           │
  serval-http ─────────────────────────────────────────────────────┤
                                                                   │
Layer 2 (Infrastructure):                                          │
  serval-pool ←─────────────────────────────────────────────┐      │
                                                            │      │
  serval-metrics ───────────────────────────────────────────┤      │
                                                            │      │
  serval-tracing ───────────────────────────────────────────┤      │
       ↑                                                    │      │
  serval-otel (implements serval-tracing interface) ────────┤      │
                                                            │      │
Layer 3 (Mechanics):                                        │      │
  serval-proxy ─────────────────────────────────────────────┤      │
       ↑                                                    │      │
       │                                                    │      │
Layer 5 (Orchestration):                                    │      │
  serval-server ────────────────────────────────────────────┤      │
                                                            │      │
                                                       serval (composes all)

Standalone:
  serval-core ←── serval-lb (load balancer handler)
  serval-core ←── serval-cli (CLI utilities)
```

### Module Responsibilities

| Module | Purpose | Key Exports |
|--------|---------|-------------|
| serval-core | Shared types, config, errors, hook verification | `Request`, `Config`, `Context`, `verifyHandler`, `hasHook` |
| serval-net | Socket configuration utilities | `setTcpNoDelay` |
| serval-http | HTTP/1.1 parsing | `Parser` |
| serval-pool | Connection reuse | `SimplePool`, `NoPool`, `Connection` |
| serval-proxy | Request forwarding | `Forwarder`, `ForwardResult`, `BodyInfo`, `Protocol` |
| serval-metrics | Observability | `NoopMetrics`, `PrometheusMetrics`, `RealTimeMetrics` |
| serval-tracing | Distributed tracing interface | `NoopTracer`, `SpanHandle` |
| serval-otel | OpenTelemetry tracing | `Tracer`, `Span`, `OTLPExporter`, `BatchingProcessor` |
| serval-server | HTTP/1.1 server | `Server`, `MinimalServer` |
| serval-lb | Load balancing | `LbHandler` (round-robin with atomic counter) |
| serval-cli | CLI argument parsing | `Args`, `ParseResult`, comptime generics |

---

## Request Flow

A request flows through these stages:

```
Client                                                     Upstream
  │                                                           │
  │  1. TCP accept                                            │
  ▼                                                           │
┌─────────────────────────────────────────────────────────────┴───┐
│ Server.handleConnection()                                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  2. Read request    ──►  recv_buf[4096]                         │
│                                                                 │
│  3. Parse headers   ──►  Parser.parseHeaders()                  │
│                          └─► Request { method, path, headers }  │
│                                                                 │
│  4. onRequest hook  ──►  Handler.onRequest() [optional]         │
│                          └─► Action.continue or .send_response  │
│                                                                 │
│  5. Select upstream ──►  Handler.selectUpstream()               │
│                          └─► Upstream { host, port, idx }       │
│                                                                 │
│  6. Build BodyInfo  ──►  Parse Content-Length, track buffered   │
│                          └─► BodyInfo { content_length, ... }   │
│                                                                 │
│  7. Forward         ──►  Forwarder.forward()                    │
│     a. Get/create connection (Pool or Io.net.IpAddress.connect) │
│     b. Send request headers (async stream.writer)               │
│     c. Stream request body (splice/copy)  ─────────────────►    │
│     d. Receive response headers (async stream.reader) ◄─────    │
│     e. Stream response body to client (splice)  ◄───────────    │
│                                                                 │
│  8. onLog hook      ──►  Handler.onLog() [optional]             │
│                                                                 │
│  9. Keep-alive?     ──►  Loop to step 2, or close               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Async I/O and Zero-Copy Body Transfer

Upstream connections use async `Io.net.Stream` for headers (io_uring integration). Body transfers use Linux `splice()` for zero-copy when available:

```
Headers: stream.writer()/reader() ──► io_uring batch submission
Bodies:  Client fd ──splice()──► Pipe ──splice()──► Upstream fd
```

The forwarder extracts raw fds (`stream.socket.handle`) for splice operations while using async streams for header I/O. Fallback to userspace copy on non-Linux or when splice fails.

---

## Compile-Time Interfaces

Serval uses Zig's comptime to verify component interfaces at build time. No runtime dispatch overhead, no interface mismatches in production.

### Server Generic Parameters

```zig
pub fn Server(
    comptime Handler: type,   // Request routing
    comptime Pool: type,      // Connection pooling
    comptime Metrics: type,   // Observability
    comptime Tracer: type,    // Distributed tracing
) type
```

### Handler Interface

**Required:**
```zig
pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) Upstream
```

**Optional hooks** (detected at comptime with `hasHook()`):
```zig
pub fn onRequest(self: *@This(), ctx: *Context, request: *Request, response_buf: []u8) Action
pub fn onResponse(self: *@This(), ctx: *Context, response: *Response) void
pub fn onError(self: *@This(), ctx: *Context, err: ErrorContext) void
pub fn onLog(self: *@This(), ctx: *Context, entry: LogEntry) void
```

`onRequest` can return `.continue_request` to forward, or `.{ .send_response = DirectResponse{...} }` to respond directly.

### Pool Interface

```zig
pub fn acquire(self: *@This(), upstream_idx: u32) ?Connection
pub fn release(self: *@This(), upstream_idx: u32, conn: Connection, healthy: bool, io: Io) void
```

`Connection` wraps `Io.net.Stream` for async I/O. Use `conn.getFd()` for splice operations.

Implementations: `SimplePool` (basic reuse), `NoPool` (always fresh)

### Metrics Interface

```zig
pub fn connectionOpened(self: *@This()) void
pub fn connectionClosed(self: *@This()) void
pub fn requestStart(self: *@This()) void
pub fn requestEnd(self: *@This(), status: u16, duration_ns: u64) void
```

Implementations: `NoopMetrics` (zero overhead), `PrometheusMetrics`

### Tracer Interface

```zig
pub fn startSpan(self: *@This(), name: []const u8, parent: ?SpanHandle) SpanHandle
pub fn endSpan(self: *@This(), handle: SpanHandle, err: ?[]const u8) void
```

Implementations: `NoopTracer` (compiles away)

---

## Usage Examples

### Full Server with Load Balancing

```zig
const serval = @import("serval");
const serval_lb = @import("serval-lb");

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
).init(&handler, &pool, &metrics, &tracer, .{ .port = 8080 });

var shutdown = std.atomic.Value(bool).init(false);
try server.run(io, &shutdown);
```

### Custom Handler with Hooks

```zig
const MyHandler = struct {
    upstreams: []const serval.Upstream,

    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, req: *const serval.Request) serval.Upstream {
        // Route based on path prefix
        if (std.mem.startsWith(u8, req.path, "/api/")) {
            return self.upstreams[0];  // API backend
        }
        return self.upstreams[1];  // Default backend
    }

    pub fn onRequest(self: *@This(), ctx: *serval.Context, req: *serval.Request, response_buf: []u8) serval.Action {
        _ = self;
        _ = ctx;
        // Block requests without auth header
        if (req.headers.get("Authorization") == null) {
            const body = "Unauthorized";
            @memcpy(response_buf[0..body.len], body);
            return .{ .send_response = .{ .status = 401, .body = response_buf[0..body.len] } };
        }
        return .continue_request;
    }

    pub fn onLog(self: *@This(), ctx: *serval.Context, entry: serval.LogEntry) void {
        _ = self;
        std.log.info("{s} {s} -> {d} ({d}ms)", .{
            @tagName(entry.method), entry.path, entry.status, entry.duration_ns / 1_000_000
        });
    }
};
```

### Using Individual Modules

```zig
// Just the parser
const http = @import("serval-http");
var parser = http.Parser.init();
try parser.parseHeaders(data);
// parser.request.method, parser.request.path, parser.request.headers

// Just the pool (with async stream connections)
const pool_mod = @import("serval-pool");
var pool = pool_mod.SimplePool.init();
if (pool.acquire(upstream.idx, io)) |conn| {
    // Use conn.stream for async I/O
    // Use conn.getFd() for splice zero-copy
    defer pool.release(upstream.idx, conn, true, io);
}
// Graceful shutdown
pool.drain(io);
```

---

## Logging & Observability

Serval provides comprehensive observability through handler hooks and timing instrumentation.

### Handler Hooks

Handlers can implement optional hooks (detected at comptime):

| Hook | Purpose |
|------|---------|
| `onRequest` | Inspect/modify request before forwarding |
| `onResponse` | Inspect response after receiving from upstream |
| `onError` | Handle errors with structured context |
| `onLog` | Receive complete request log with timing |
| `onConnectionOpen` | Connection accepted (for metrics, rate limiting) |
| `onConnectionClose` | Connection ended (with request count, duration) |

### Timing Collection

Request timing is collected at each phase and available in `LogEntry`:

```
Client  ──parse──►  Handler  ──connect──►  Upstream  ──send──►  ──recv──►  Client
         parse_ns            connect_ns              send_ns    recv_ns
                             └─► dns_ns + tcp_connect_ns + pool_wait_ns
```

### LogEntry Fields

The `onLog` hook receives a `LogEntry` with:

- **Core**: `method`, `path`, `status`, `request_bytes`, `response_bytes`
- **Timing**: `duration_ns`, `parse_duration_ns`, `connect_duration_ns`, `send_duration_ns`, `recv_duration_ns`
- **Network**: `dns_duration_ns`, `tcp_connect_duration_ns`, `pool_wait_ns`
- **Connection**: `connection_id`, `request_number`, `connection_reused`, `keepalive`
- **Error**: `error_phase`, `error_name`

### Example: Handler with Logging

```zig
const MyHandler = struct {
    pub fn selectUpstream(self: *@This(), ctx: *Context, req: *const Request) Upstream {
        return self.upstream;
    }

    pub fn onConnectionOpen(self: *@This(), info: *const ConnectionInfo) void {
        std.log.info("conn={d} client={s}:{d}", .{
            info.connection_id, info.client_addr, info.client_port,
        });
    }

    pub fn onConnectionClose(self: *@This(), conn_id: u64, req_count: u32, duration_ns: u64) void {
        std.log.info("conn={d} requests={d} duration_ms={d}", .{
            conn_id, req_count, duration_ns / 1_000_000,
        });
    }

    pub fn onLog(self: *@This(), ctx: *Context, entry: LogEntry) void {
        std.log.info("{s} {s} {d} total={d}ms parse={d}us connect={d}us", .{
            @tagName(entry.method), entry.path, entry.status,
            entry.duration_ns / 1_000_000,
            entry.parse_duration_ns / 1_000,
            entry.connect_duration_ns / 1_000,
        });
    }
};
```

---

## Contributing & Extending

### Where to Make Changes

| Task | Location |
|------|----------|
| Add new request/response types | `lib/serval-core/types.zig` |
| Change config defaults or limits | `lib/serval-core/config.zig` |
| Add new error types | `lib/serval-core/errors.zig` |
| Add logging utilities | `lib/serval-core/log.zig` |
| Modify handler hook verification | `lib/serval-core/hooks.zig` |
| Add socket utilities | `lib/serval-net/socket.zig` |
| Modify HTTP parsing | `lib/serval-http/parser.zig` |
| Change connection pooling strategy | `lib/serval-pool/pool.zig` |
| Modify forwarding behavior | `lib/serval-proxy/forwarder.zig` |
| Add metrics exporters | `lib/serval-metrics/` |
| Add tracing backends | `lib/serval-tracing/` |
| Add load balancing algorithms | `lib/serval-lb/handler.zig` |
| Modify server request loop | `lib/serval-server/http1.zig` |

### Adding a New Pool Implementation

```zig
// lib/serval-pool/my_pool.zig
pub const MyPool = struct {
    // Must satisfy Pool interface (verified at comptime)
    pub fn get(self: *@This(), upstream: Upstream) ?Connection { ... }
    pub fn put(self: *@This(), upstream: Upstream, conn: Connection) void { ... }
    pub fn remove(self: *@This(), upstream: Upstream, conn: Connection) void { ... }
};

// Export from mod.zig
pub const MyPool = @import("my_pool.zig").MyPool;
```

### Adding a New Load Balancing Algorithm

```zig
// lib/serval-lb/weighted_handler.zig
pub const WeightedHandler = struct {
    upstreams: []const WeightedUpstream,

    pub fn selectUpstream(self: *@This(), ctx: *Context, req: *const Request) Upstream {
        // Implement weighted selection
    }
};
```

### TigerStyle Checklist for New Code

- [ ] ~2 assertions per function (preconditions, postconditions)
- [ ] All loops have explicit bounds
- [ ] No runtime allocation (use fixed buffers)
- [ ] Explicit error handling (no `catch {}`)
- [ ] Functions under 70 lines
- [ ] Units in variable names (`timeout_ms`, `size_bytes`)

---

## Implementation Status

### Complete

| Feature | Module | Notes |
|---------|--------|-------|
| HTTP/1.1 parsing | serval-http | Headers only, streaming bodies |
| Keep-alive connections | serval-server | RFC 9112 compliant |
| Connection pooling | serval-pool | SimplePool with mutex, stale connection detection |
| Async upstream I/O | serval-proxy | Uses Io.net.Stream (io_uring integration) |
| Upstream forwarding | serval-proxy | With stale connection retry (MAX_STALE_RETRIES=2) |
| Request body streaming | serval-proxy | splice() zero-copy on Linux |
| Response body streaming | serval-proxy | splice() zero-copy on Linux |
| Round-robin load balancing | serval-lb | Thread-safe with atomic counter |
| Handler hooks | serval-server | onRequest, onResponse, onError, onLog, onConnectionOpen/Close |
| Metrics interface | serval-metrics | Noop + Prometheus + RealTimeMetrics (per-upstream stats) |
| Tracing interface | serval-tracing | NoopTracer |
| OpenTelemetry tracing | serval-otel | Full OTLP/JSON export with batching |
| CLI argument parsing | serval-cli | Comptime-generic with custom options |
| Protocol abstraction | serval-proxy | h1/ subdirectory, Protocol enum ready for h2 |
| Chunked transfer encoding | serval-http, serval-proxy, serval-server | Parsing, forwarding, and direct response |

### Not Implemented

| Feature | Module | Complexity |
|---------|--------|------------|
| HTTP/2 | serval-proxy/h2 | High |
| TLS termination | serval-tls | Medium |
| Weighted round-robin | serval-lb | Low |
| Least connections LB | serval-lb | Low |
| Health checks | serval-health | Medium |
| Circuit breaker | serval-health | Medium |
| W3C Trace Context propagation | serval-otel | Low |

### Build & Test

Requires **Zig 0.16.0-dev.1859** or later.

```bash
# Build all
zig build

# Run serval library tests
zig build test-serval

# Run load balancer tests
zig build test-lb

# Run OpenTelemetry tests
zig build test-otel

# Run example
zig build run-lb-example -- --port 8080 --backends 127.0.0.1:9001,127.0.0.1:9002
```
