# Serval Architecture

Serval is a modular HTTP reverse proxy library written in Zig, following TigerStyle principles. Current transport support is HTTP/1.1 plus an initial gRPC-over-h2c proxy slice.

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
├── serval-net      # DNS resolution, TCP helpers (TCP_NODELAY, keepalive)
├── serval-socket   # Unified socket abstraction (plain TCP + TLS)
├── serval-http     # HTTP/1.1 parser
├── serval-websocket # RFC 6455 handshake, frame, close, and subprotocol helpers
├── serval-h2       # Minimal HTTP/2 / h2c frame, control, preface, HPACK, and initial-request helpers
├── serval-grpc     # gRPC metadata and message envelope helpers
├── serval-acme     # ACME certificate automation primitives (state/config/http-01 + protocol codecs)
├── serval-tls      # TLS termination and origination (OpenSSL)
├── serval-pool     # Connection pooling
├── serval-client   # HTTP/1.1 client + bounded outbound h2 session/runtime primitives
├── serval-health   # Backend health tracking (atomic bitmap, thresholds)
├── serval-prober   # Background health probing
├── serval-proxy    # Upstream forwarding (h1/ + initial h2 stream-bridge primitives)
├── serval-metrics  # Request metrics (real-time + Prometheus)
├── serval-tracing  # Distributed tracing interface
├── serval-otel     # OpenTelemetry implementation
└── serval-server   # HTTP server implementation (h1/ subdirectory)

Standalone modules:
├── serval-lb       # Load balancer handler (round-robin)
├── serval-router   # Content-based router (host/path matching, per-pool LB)
├── serval-k8s-gateway  # Gateway API types + translation (library, not controller)
└── serval-cli      # CLI argument parsing utilities

Future modules (API gateway):
├── serval-ratelimit  # Rate limiting (token bucket, sliding window)
├── serval-waf        # Web Application Firewall (SQLi, XSS detection)
├── serval-cache      # Response caching (keys, TTL, eviction)
└── serval-auth       # Authentication/authorization (JWT, API keys)
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
  serval-net (DNS, TCP helpers) ───────────────────────────────────┤
       ↑                                                           │
       │                                                           │
  serval-http ─────────────────────────────────────────────────────┤
                                                                   │
  serval-websocket ────────────────────────────────────────────────┤
                                                                   │
  serval-h2 ───────────────────────────────────────────────────────┤
                                                                   │
  serval-tls ──────────────────────────────────────────────────────┤
                                                                   │
Layer 2 (Infrastructure):                                          │
  serval-grpc (depends on core, h2) ───────────────────────────────┤
                                                                   │
  serval-acme (depends on core) ───────────────────────────────────┤
                                                                   │
  serval-socket (unified TCP/TLS socket) ←─────────────────┐       │
                                                           │       │
  serval-pool (depends on socket) ←────────────────────────┤       │
                                                           │       │
  serval-client (depends on core, net, socket, tls, http, pool) ←──┤
                                                           │       │
  serval-health ←──────────────────────────────────────────┤       │
                                                           │       │
  serval-prober (depends on serval-client) ←───────────────┤       │
                                                           │       │
  serval-metrics ──────────────────────────────────────────┤       │
                                                           │       │
  serval-tracing ──────────────────────────────────────────┤       │
       ↑                                                   │       │
  serval-otel (implements serval-tracing interface) ───────┤       │
                                                           │       │
Layer 3 (Mechanics):                                       │       │
  serval-proxy (depends on serval-client) ─────────────────┤       │
       ↑                                                   │       │
       │                                                   │       │
Layer 5 (Orchestration):                                   │       │
  serval-server ───────────────────────────────────────────┤       │
                                                           │       │
                                                      serval (composes all)

Standalone:
  serval-core ←── serval-lb (load balancer handler, depends on serval-health, serval-prober)
  serval-core ←── serval-router (content-based router, depends on serval-lb, serval-health, serval-prober)
  serval-core ←── serval-k8s-gateway (Gateway API types + translator, minimal deps)
  serval-core ←── serval-cli (CLI utilities)
```

### Module Responsibilities

| Module | Purpose | Key Exports |
|--------|---------|-------------|
| serval-core | Shared types, config, errors, hook verification | `Request`, `Config`, `Context`, `verifyHandler`, `hasHook` |
| serval-net | DNS resolution, TCP configuration utilities | `DnsResolver`, `set_tcp_no_delay`, `set_tcp_keep_alive` |
| serval-socket | Unified socket abstraction (plain TCP + TLS) | `Socket`, `SocketError`, `PlainSocket` |
| serval-http | HTTP/1.1 parsing | `Parser` |
| serval-websocket | RFC 6455 handshake + framing helpers | `validateClientRequest`, `computeAcceptKey`, `parseFrameHeader`, `buildClosePayload` |
| serval-h2 | Minimal HTTP/2 / h2c protocol helpers | `parseFrameHeader`, `buildFrameHeader`, `parseInitialRequest`, `parseSettingsPayload`, `buildGoAwayFrame`, `StreamTable`, `Window` |
| serval-grpc | gRPC metadata + envelope helpers | `validateRequest`, `buildMessage`, `parseMessage` |
| serval-acme | ACME certificate automation primitives | `CertState`, `RuntimeConfig`, `Http01Store`, `AcmeDirectory`, `AcmeNewOrderRequest`, `AcmeJwkP256`, `AcmeWireRequest`, `AcmeFlowContext`, `executeAcmeOperation`, `AcmeManager` |
| serval-pool | Connection reuse (wraps Socket) | `SimplePool`, `NoPool`, `Connection` |
| serval-client | HTTP/1.1 client for upstream requests + bounded outbound h2 session/runtime primitives | `Client`, `ClientError`, `ResponseHeaders`, `sendRequest`, `readResponseHeaders`, `H2SessionState`, `H2Runtime`, `H2ClientConnection`, `H2UpstreamSessionPool` |
| serval-health | Backend health tracking | `HealthState`, `UpstreamIndex`, `MAX_UPSTREAMS` |
| serval-prober | Background health probing (HTTP/HTTPS) | `ProberContext`, `probeLoop` |
| serval-proxy | Request forwarding + initial stream-aware h2 bridge primitives | `Forwarder`, `ForwardResult`, `BodyInfo`, `Protocol`, `H2StreamBridge` |
| serval-metrics | Observability | `NoopMetrics`, `PrometheusMetrics`, `RealTimeMetrics` |
| serval-tracing | Distributed tracing interface | `NoopTracer`, `SpanHandle` |
| serval-otel | OpenTelemetry tracing | `Tracer`, `Span`, `OTLPExporter`, `BatchingProcessor` |
| serval-server | HTTP/1.1 server + early HTTP/2 dispatch (h2c + TLS ALPN h2 for terminated handlers and configurable generic frontend adapter) | `Server`, `MinimalServer`, `servePlainH2Connection`, `serveTlsH2Connection` |
| serval-lb | Load balancing | `LbHandler` (health-aware round-robin with background probing) |
| serval-router | Content-based routing | `Router`, `Route`, `RouteMatcher`, `PathMatch`, `PoolConfig` |
| serval-k8s-gateway | Gateway API types + translation | `GatewayConfig`, `HTTPRoute`, `translateToJson` |
| serval-cli | CLI argument parsing | `Args`, `ParseResult`, comptime generics |

### Module Purpose Clarifications

Some modules have similar names but serve very different purposes:

| Module | Layer | What It Does | Handles Traffic? |
|--------|-------|--------------|------------------|
| **serval-server** | 5 (Orchestration) | HTTP server: accept loop, connection handling, dispatch to handlers | **Yes** - actual HTTP requests |
| **serval-k8s-gateway** | 4 (Strategy) | Gateway API types and JSON translation | **No** - just data types |
| **serval-router** | 4 (Strategy) | Routing decisions: match request → select backend | **Yes** - as a handler |
| **serval-lb** | 4 (Strategy) | Load balancing: round-robin across upstreams | **Yes** - as a handler |

**serval-server vs serval-k8s-gateway:**
- `serval-server` = "the engine that runs" - accepts connections, parses HTTP, invokes handlers
- `serval-k8s-gateway` = "the blueprint format" - Gateway API schema (GatewayConfig, HTTPRoute, etc.)

**In practice:**
```
examples/gateway/              # K8s controller (control plane - no traffic)
    └── uses serval-k8s-gateway types (GatewayConfig, HTTPRoute)
    └── watches K8s API for changes
    └── translates config and pushes to data plane

examples/router_example.zig    # Data plane (handles traffic)
    └── uses serval-server to accept HTTP connections
    └── uses serval-router for routing decisions
    └── receives config updates from gateway controller
```

**When to use which:**
- Building an HTTP server/proxy → `serval-server` + `serval-router` or `serval-lb`
- Building a K8s ingress controller → `serval-k8s-gateway` types + your own controller logic
- Building a config-file-based gateway → `serval-k8s-gateway` types + file watcher

### Control Plane vs Data Plane

Serval separates configuration management (control plane) from traffic handling (data plane):

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CONTROL PLANE                               │
│                                                                          │
│   Your Controller (K8s watcher, API platform, file watcher, etc.)       │
│         │                                                                │
│         │ uses                                                           │
│         ▼                                                                │
│   ┌─────────────────┐                                                    │
│   │ serval-k8s-gateway  │  ← Library: GatewayConfig types + translateToJson()│
│   └────────┬────────┘                                                    │
│            │ produces JSON                                               │
│            ▼                                                             │
│   POST /routes/update  ─────────────────────────────────────────────┐    │
│   { "routes": [...], "pools": [...] }                               │    │
└─────────────────────────────────────────────────────────────────────│────┘
                                                                      │
┌─────────────────────────────────────────────────────────────────────│────┐
│                              DATA PLANE                             │    │
│                                                                     ▼    │
│   ┌─────────────────┐     ┌─────────────────┐     ┌──────────────┐      │
│   │  serval-server  │────▶│  serval-router  │────▶│   Backends   │      │
│   │  (HTTP server)  │     │  (routing logic)│     │              │      │
│   └─────────────────┘     └─────────────────┘     └──────────────┘      │
│         ▲                        ▲                                       │
│         │                        │                                       │
│    Accepts HTTP            Decides which                                 │
│    connections             backend to use                                │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**Module roles:**

| Module | Role | Analogy |
|--------|------|---------|
| **serval-k8s-gateway** | Route definitions (types + JSON translation) | "The menu" |
| **serval-router** | Route matching + backend selection | "The waiter" |
| **serval-server** | Accept connections, parse HTTP, invoke handlers | "The restaurant" |

**The config flow:**

```
1. Control Plane                    2. Translation                 3. Data Plane

   GatewayConfig {                  JSON:                          Router receives:
     http_routes: [{                {                              - routes[] with matchers
       name: "api",                   "routes": [{                 - pools[] with upstreams
       hostnames: ["api.com"],          "name": "api",             - default_route
       rules: [{                        "host": "api.com",
         matches: [{path: "/v1"}],      "path_prefix": "/v1",      Router.updateConfig()
         backend_refs: [{               "pool_idx": 0              atomically swaps config
           name: "api-svc",           }],
           port: 8080                 "pools": [{                  Traffic now routes to
         }]                             "name": "api-pool",        new backends
       }]                               "upstreams": [...]
     }]                               }]
   }                                }

   ─────────────────▶              ─────────────────▶
   serval-k8s-gateway                  POST /routes/update
   translateToJson()               to serval-router
```

### Building an API Platform

Since serval-k8s-gateway is just a library with types, you can build any control plane:

```
┌─────────────────────────────────────────────────────────────┐
│                    API Platform Control Plane                │
├─────────────────────────────────────────────────────────────┤
│  Management API (REST)     │  Developer Portal (Web UI)     │
│  - CRUD routes/APIs        │  - Self-service onboarding     │
│  - API key management      │  - Usage dashboards            │
│  - Rate limit config       │  - API docs (OpenAPI)          │
├─────────────────────────────────────────────────────────────┤
│                         Database                             │
│  - Routes, backends, API keys, rate limits, usage metrics   │
├─────────────────────────────────────────────────────────────┤
│           Config Pusher (uses serval-k8s-gateway)               │
│  - Watches DB for changes                                    │
│  - Builds GatewayConfig from DB rows                        │
│  - Translates to JSON, pushes to data plane                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ POST /routes/update
┌─────────────────────────────────────────────────────────────┐
│                    Data Plane (serval-router)                │
│  - Receives config updates                                   │
│  - Routes traffic to backends                                │
│  - Enforces rate limits (per API key)                       │
│  - Validates auth tokens                                     │
└─────────────────────────────────────────────────────────────┘
```

**Use cases for different control planes:**

| Use Case | Control Plane | serval-k8s-gateway Usage |
|----------|---------------|---------------------|
| K8s Ingress | Watch K8s API | `examples/gateway/` |
| API Platform | Database + REST API | Build `GatewayConfig` from DB |
| Config Files | Watch YAML files | Parse YAML → `GatewayConfig` |
| GitOps | Watch git repo | Parse manifests → `GatewayConfig` |
| Multi-tenant SaaS | Per-tenant DB tables | Filter routes by tenant |

**What serval-k8s-gateway provides vs what you build:**

| Component | serval-k8s-gateway | You Build |
|-----------|----------------|-----------|
| Route types | `HTTPRoute`, `HTTPRouteRule`, `HTTPRouteMatch` | - |
| Backend types | `HTTPBackendRef` | - |
| Filter types | `HTTPRouteFilter` (rate limit, rewrite, headers) | - |
| JSON translation | `translateToJson()` | - |
| Storage | - | Database schema |
| Management API | - | REST endpoints |
| Auth/API keys | - | Validation logic |
| Developer portal | - | Web UI |

**Key insight:** serval-k8s-gateway defines **what a route looks like** (Gateway API spec). You choose **where the routes come from** (K8s, database, files, API). The translator converts to JSON, and you push to serval-router.

---

## Request Flow

A request flows through these stages:

```
Client                                                     Upstream
  │                                                           │
  │  1. TCP accept                                            │
  │     └─► onConnectionOpen() [optional]                     │
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
│                          └─► Action: .continue_request,         │
│                                      .send_response, .reject    │
│                                                                 │
│  5. Select upstream ──►  Handler.selectUpstream()               │
│                          └─► Upstream { host, port, idx }       │
│                                                                 │
│  6. onUpstreamRequest ─► Handler.onUpstreamRequest() [optional] │
│                          └─► Modify request before forwarding   │
│                                                                 │
│  7. Build BodyInfo  ──►  Parse Content-Length, track buffered   │
│                          └─► BodyInfo { content_length, ... }   │
│                                                                 │
│  8. Forward         ──►  Forwarder.forward()                    │
│     a. Get/create connection (Pool or Io.net.IpAddress.connect) │
│        └─► onUpstreamConnect() [optional]                       │
│     b. Send request headers (async stream.writer)               │
│     c. Stream request body (splice/copy)  ─────────────────►    │
│        └─► onRequestBody() per chunk [optional]                 │
│     d. Receive response headers (async stream.reader) ◄─────    │
│        └─► onResponse() [optional]                              │
│     e. Stream response body to client (splice)  ◄───────────    │
│        └─► onResponseBody() per chunk [optional]                │
│                                                                 │
│  9. On error        ──►  Handler.onError() [optional]           │
│                          └─► ErrorAction: .default,             │
│                                           .send_response, .retry│
│                                                                 │
│ 10. onLog hook      ──►  Handler.onLog() [optional]             │
│                                                                 │
│ 11. Keep-alive?     ──►  Loop to step 2, or close               │
│                                                                 │
│ 12. Connection close ─►  onConnectionClose() [optional]         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### WebSocket Upgrade Flow

When a request contains `Upgrade: websocket`, the HTTP/1.1 server takes an explicit
upgrade path instead of the normal request/response forwarding path:

1. `serval-websocket` validates the client handshake (`GET`, `Connection: Upgrade`, `Upgrade: websocket`, valid `Sec-WebSocket-Key`, version `13`, no HTTP body framing)
2. If the handler implements native endpoint hooks, `serval-server/websocket` asks `selectWebSocket()` whether to:
   - `.accept` and terminate locally in Serval
   - `.decline` and continue to proxy/upstream handling
   - `.reject` and send an HTTP error response
3. For native `.accept`, `serval-server/websocket/accept.zig` sends `101 Switching Protocols` and `serval-server/websocket/session.zig` switches the connection into a message-oriented RFC 6455 session loop
4. For proxy fallback, `serval-proxy/h1/websocket.zig` builds a canonical upstream upgrade request while preserving end-to-end WebSocket headers
5. Upstream response headers are read once and validated before any `101` is forwarded to the client
6. If upstream returns a non-`101` response, it is forwarded as plain HTTP and the connection closes
7. If upstream returns a valid `101 Switching Protocols`, `serval-proxy/tunnel.zig` switches to bidirectional byte relay and the upgraded upstream connection is never returned to the HTTP pool

### gRPC over h2c Prior-Knowledge + Upgrade Flow

The current gRPC slice supports two **cleartext HTTP/2** inbound entry paths with an explicit,
fail-closed handoff.

Separately, for non-proxy terminated handlers, `serval-server` can now dispatch cleartext
HTTP/2 into `servePlainH2Connection()` for both prior-knowledge and `Upgrade: h2c` entry
paths when the handler implements `handleH2Headers()` and `handleH2Data()`. The upgrade
path now includes stream-1 bootstrap from the HTTP/1.1 request plus optional post-101
client preface consumption before normal frame handling. The terminated runtime now also
tracks bounded per-stream lifecycle state and can emit optional `handleH2StreamOpen()` /
`handleH2StreamClose(summary)` callbacks for stream-scoped metrics/tracing/logging, and the
main cleartext server path now wires those callbacks into per-stream metrics, tracing span,
and `onLog` emission for both prior-knowledge and upgrade terminated sessions. Integration
coverage also includes fail-closed GOAWAY behavior for invalid DATA-before-HEADERS ordering
in post-101 upgrade streams. This terminated path remains intentionally narrow today: it now supports
cleartext prior-knowledge/upgrade plus TLS ALPN `h2` dispatch for terminated
handlers, and is still early-phase.

The proxy flow is:

#### Prior knowledge

1. `serval-server` reads the start of a new cleartext connection
2. `serval-h2` detects the client connection preface (`PRI * HTTP/2.0...`)
3. `serval-h2.parseInitialRequest()` parses the first HEADERS block using bounded HPACK decode (including dynamic-table references and Huffman strings)
4. `serval-grpc.validateRequest()` checks `POST`, `content-type: application/grpc*`, and `te: trailers`
5. The normal handler `selectUpstream()` runs against a synthetic `Request` built from the first h2c stream
6. If the selected upstream has `http_protocol = .h2c` and cleartext transport, `serval-server` enters the stream-aware h2 bridge path and `serval-proxy/h2/bridge.zig` acquires or reuses a bounded upstream h2 session
7. The bridge maps downstream stream ids to upstream stream ids, forwards HEADERS/DATA per stream, and drains upstream receive actions back to downstream HEADERS/DATA/trailers
8. gRPC responses are validated for mandatory `grpc-status`; missing/invalid status fails closed as downstream `RST_STREAM(PROTOCOL_ERROR)`
9. Upstream stream resets now fail-closed as downstream `RST_STREAM(CANCEL)` for the affected stream; non-h2c upstreams continue to use the legacy connection tunnel path

#### HTTP/1.1 `Upgrade: h2c`

1. `serval-server` parses the HTTP/1.1 request and detects `Upgrade: h2c`
2. `serval-h2.validateUpgradeRequest()` validates `Connection`, `Upgrade`, and `HTTP2-Settings`
3. `serval-grpc.validateRequest()` validates gRPC request metadata on the HTTP/1.1 request view
4. The normal handler `selectUpstream()` chooses an upstream
5. For cleartext h2c upstreams, Serval sends `101 Switching Protocols` and enters `h2/server.zig`
   upgraded mode with stream-1 bootstrap from the HTTP/1.1 request (headers + body)
6. The same stream-aware bridge handler used for prior-knowledge then maps downstream
   stream ids to upstream stream ids, forwards per-stream HEADERS/DATA, and maps
   upstream response/reset actions back downstream
7. For non-h2c upstreams, Serval keeps the legacy translation+tunnel fallback

The cleartext h2c proxy path is now stream-aware for both prior-knowledge and inbound
`Upgrade: h2c` entry when the selected upstream is cleartext h2c. Upstream `GOAWAY`
now respects `last_stream_id` for active streams (`NO_ERROR` GOAWAY no longer forces
an immediate reset when the active stream id is still allowed), with upstream
session rollover support (one active + one draining session per upstream index)
and bounded HEADERS+CONTINUATION reassembly plus bounded HPACK
dynamic-table/Huffman decode in initial parse and runtime paths.
Routing is still decided from the first request on the connection, and broader
control-frame propagation remains future work.

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

Request Phase:
```zig
pub fn onRequest(self: *@This(), ctx: *Context, request: *Request, response_buf: []u8) Action
pub fn onRequestBody(self: *@This(), ctx: *Context, chunk: []const u8, is_last: bool) BodyAction
```

Upstream Phase:
```zig
pub fn onUpstreamRequest(self: *@This(), ctx: *Context, request: *Request) void
pub fn onUpstreamConnect(self: *@This(), ctx: *Context, info: *const UpstreamConnectInfo) void
```

Response Phase:
```zig
pub fn onResponse(self: *@This(), ctx: *Context, response: *Response) Action
pub fn onResponseBody(self: *@This(), ctx: *Context, chunk: []const u8, is_last: bool) BodyAction
```

Error/Completion Phase:
```zig
pub fn onError(self: *@This(), ctx: *Context, err_ctx: *const ErrorContext) ErrorAction
pub fn onLog(self: *@This(), ctx: *Context, entry: LogEntry) void
```

Connection Lifecycle:
```zig
pub fn onConnectionOpen(self: *@This(), info: *const ConnectionInfo) void
pub fn onConnectionClose(self: *@This(), connection_id: u64, request_count: u32, duration_ns: u64) void
```

**Return types:**
- `Action`: `.continue_request`, `.send_response`, `.reject`
- `BodyAction`: `.continue_body`, `.reject`
- `ErrorAction`: `.default`, `.send_response`, `.retry`

`onRequest` can return `.continue_request` to forward, or `.{ .send_response = DirectResponse{...} }` to respond directly.

### Pool Interface

```zig
pub fn acquire(self: *@This(), upstream_idx: u32) ?Connection
pub fn release(self: *@This(), upstream_idx: u32, conn: Connection, healthy: bool) void
```

`Connection` wraps `Socket` for unified plain/TLS I/O. Use `conn.getFd()` for splice operations.

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
try server.run(io, &shutdown);
```

### Content-Based Routing with Multiple Pools

```zig
const serval = @import("serval");
const serval_router = @import("serval-router");
const serval_net = @import("serval-net");

const Router = serval_router.Router;
const Route = serval_router.Route;
const PoolConfig = serval_router.PoolConfig;

// Define upstreams for each pool
const api_upstreams = [_]serval.Upstream{
    .{ .host = "api-1", .port = 8001, .idx = 0 },
    .{ .host = "api-2", .port = 8002, .idx = 1 },
};
const static_upstreams = [_]serval.Upstream{
    .{ .host = "static-1", .port = 9001, .idx = 2 },
};

// Define routes (first match wins)
const routes = [_]Route{
    .{ .name = "api", .matcher = .{ .path = .{ .prefix = "/api/" } }, .pool_idx = 0, .strip_prefix = true },
    .{ .name = "static", .matcher = .{ .path = .{ .prefix = "/static/" } }, .pool_idx = 1, .strip_prefix = true },
};

// Required default route
const default_route = Route{
    .name = "default",
    .matcher = .{ .path = .{ .prefix = "/" } },
    .pool_idx = 0,
};

// Pool configurations
const pool_configs = [_]PoolConfig{
    .{ .name = "api-pool", .upstreams = &api_upstreams, .lb_config = .{ .enable_probing = false } },
    .{ .name = "static-pool", .upstreams = &static_upstreams, .lb_config = .{ .enable_probing = false } },
};

var router: Router = undefined;
try router.init(&routes, default_route, &pool_configs, null);
defer router.deinit();

// Use router as handler with Server
var server = serval.Server(Router, serval.SimplePool, serval.NoopMetrics, serval.NoopTracer)
    .init(&router, &pool, &metrics, &tracer, .{ .port = 8080 }, null, serval_net.DnsConfig{});
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
if (pool.acquire(upstream.idx)) |conn| {
    // Use conn.socket for I/O
    // Use conn.getFd() for splice zero-copy
    defer pool.release(upstream.idx, conn, true);
}
// Graceful shutdown
pool.drain();
```

---

## Logging & Observability

Serval provides comprehensive observability through handler hooks and timing instrumentation.

### Handler Hooks

Handlers can implement optional hooks (detected at comptime):

| Hook | Phase | Purpose | Return Type |
|------|-------|---------|-------------|
| `onRequest` | Request | Inspect/modify request before forwarding | `Action` |
| `onRequestBody` | Request | Inspect/transform request body chunks | `BodyAction` |
| `onUpstreamRequest` | Upstream | Modify request before sending to upstream | `void` |
| `onUpstreamConnect` | Upstream | Observe upstream connection establishment | `void` |
| `onResponse` | Response | Inspect/modify response from upstream | `Action` |
| `onResponseBody` | Response | Inspect/transform response body chunks | `BodyAction` |
| `onError` | Error | Handle errors with structured context | `ErrorAction` |
| `onLog` | Completion | Receive complete request log with timing | `void` |
| `onConnectionOpen` | Connection | Connection accepted (for metrics, rate limiting) | `void` |
| `onConnectionClose` | Connection | Connection ended (with request count, duration) | `void` |

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
| Add new request/response types | `serval-core/types.zig` |
| Change config defaults or limits | `serval-core/config.zig` |
| Add new error types | `serval-core/errors.zig` |
| Add logging utilities | `serval-core/log.zig` |
| Modify handler hook verification | `serval-core/hooks.zig` |
| Add DNS resolution features | `serval-net/dns.zig` |
| Add TCP socket options | `serval-net/tcp.zig` |
| Add socket abstraction features | `serval-socket/socket.zig` |
| Add TLS socket features | `serval-socket/tls_socket.zig` |
| Modify HTTP parsing | `serval-http/parser.zig` |
| Change connection pooling strategy | `serval-pool/pool.zig` |
| Modify forwarding behavior | `serval-proxy/forwarder.zig` |
| Add metrics exporters | `serval-metrics/` |
| Add tracing backends | `serval-tracing/` |
| Add load balancing algorithms | `serval-lb/handler.zig` |
| Modify server request loop | `serval-server/h1/server.zig` |

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
| Health-aware load balancing | serval-lb | Round-robin with background probing, onLog passive tracking |
| Content-based routing | serval-router | Host/path matching (exact, prefix), path rewriting (strip prefix), per-pool LbHandler |
| Handler hooks | serval-server | 10 lifecycle hooks: request phase (onRequest, onRequestBody), upstream phase (onUpstreamRequest, onUpstreamConnect), response phase (onResponse, onResponseBody), error/completion (onError, onLog), connection lifecycle (onConnectionOpen, onConnectionClose) |
| Metrics interface | serval-metrics | Noop + Prometheus + RealTimeMetrics (per-upstream stats) |
| Tracing interface | serval-tracing | NoopTracer |
| OpenTelemetry tracing | serval-otel | Full OTLP/JSON export with batching |
| CLI argument parsing | serval-cli | Comptime-generic with custom options |
| Protocol abstraction | serval-proxy | h1/ subdirectory, Protocol enum ready for h2 |
| Chunked transfer encoding | serval-http, serval-proxy, serval-server | Parsing, forwarding, and direct response |
| WebSocket proxy tunneling | serval-websocket, serval-proxy, serval-server | RFC 6455 handshake validation, HTTP/1.1 upgrade forwarding, bidirectional relay |
| Native WebSocket endpoint serving | serval-websocket, serval-server | RFC 6455 handshake acceptance, frame parsing, message-oriented server sessions |
| gRPC over h2c proxying (prior knowledge + inbound upgrade) | serval-h2, serval-grpc, serval-proxy, serval-server | Cleartext h2c upstreams now use a bounded stream-aware bridge in both entry paths (stream mapping + reused upstream sessions + reset mapping + GOAWAY `last_stream_id`-aware active-stream handling + fail-closed `grpc-status` enforcement); non-h2c targets use legacy tunnel fallback |
| Terminated HTTP/2 connection runtime primitives | serval-h2, serval-server | Bounded SETTINGS/ACK/PING/RST_STREAM/GOAWAY handling plus streaming HEADERS/DATA callbacks on plain and TLS streams, including DATA-driven connection+stream WINDOW_UPDATE replenishment and main accept-loop dispatch for prior-knowledge, `Upgrade: h2c`, and TLS ALPN `h2` terminated entry paths |
| TLS termination | serval-tls, serval-server | Client TLS (server-side), upstream TLS (client-side) |
| kTLS kernel offload | serval-tls | OpenSSL native + BoringSSL manual, automatic fallback |
| HTTP/1.1 client | serval-client | DNS, TCP, TLS, request/response |

### In Progress

| Feature | Module | Status |
|---------|--------|--------|
| Gateway refactor | serval-k8s-gateway | Refactoring to library-only (types + translator) |
| K8s controller | examples/gateway/ | Moving K8s-specific code to example |

### Not Implemented

| Feature | Module | Complexity |
|---------|--------|------------|
| HTTP/2 full stream-aware stack | serval-proxy/h2 | High |
| Native gRPC endpoints | serval-server, serval-grpc | High |
| Weighted round-robin | serval-lb | Low |
| Least connections LB | serval-lb | Low |
| W3C Trace Context propagation | serval-otel | Low |

### Build & Test

Requires **Zig 0.16.0-dev.2565+684032671** or later.

```bash
# Build all
zig build

# Run serval library tests
zig build test

# Run h2 / gRPC protocol tests
zig build test-h2
zig build test-grpc

# Run load balancer tests
zig build test-lb

# Run OpenTelemetry tests
zig build test-otel

# Run health module tests
zig build test-health

# Run router tests
zig build test-router

# Run integration tests
zig build test-integration

# Run load balancer example
zig build run-lb-example -- --port 8080 --backends 127.0.0.1:9001,127.0.0.1:9002

# Run router example (content-based routing)
zig build run-router-example -- --port 8080 --api-backends 127.0.0.1:8001 --static-backends 127.0.0.1:8002

# Build gateway controller (K8s ingress controller)
zig build build-gateway

# Deploy to k3s (builds, creates Docker images, deploys)
./deploy/deploy-k3s.sh
```
