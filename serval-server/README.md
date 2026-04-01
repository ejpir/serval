# serval-server

HTTP/1.1 server implementation for serval. Like Pingora's `server` + `apps` modules.

Provides generic HTTP server infrastructure with protocol-specific implementations organized by version (h1/ today, gRPC-oriented HTTP/2 ingress/proxy handoff for prior-knowledge and `Upgrade: h2c`, and an early `h2/` connection/runtime submodule for future generic stream-aware transport).

The terminated `h2/server.zig` path receives `std.Io` from downstream h2 entry points and keeps plain h2 transport on `std.Io` stream reader/writer operations so connection fibers yield naturally under backpressure and cancellation. TLS h2 reads use readiness-yield + retry rather than blocking `SSL_read()` directly, and h1 plain-socket reads stay on `std.Io` for consistent fiber behavior. Downstream terminated h2 connections use the long-lived `serval-core.config.H2_SERVER_IDLE_TIMEOUT_NS` readiness bound instead of a hardcoded 30 second stall window, so quiet mobile gRPC clients are not forced to reconnect during normal idle periods. When this readiness timeout is hit, the affected terminated h2 TLS connection is closed fail-closed instead of waiting indefinitely.

Runtime protocol policy now comes from nested server config sections rather than ad-hoc top-level constants:

- `Config.h2` controls deploy-time HTTP/2 settings such as advertised frame/window limits and downstream idle timeouts.
- `Config.websocket` controls native WebSocket session limits such as message size, fragment count, and close/idle timeouts.
- Fixed compile-time capacities still stay in owner modules or shared core invariants; runtime settings are validated against those bounds.
- The terminated server-side h2 runtime now takes caller-owned HEADERS/CONTINUATION scratch storage for pending request-header assembly, so that scratch-buffer ownership stays with the connection driver instead of being embedded in the protocol runtime state.
- The terminated server-side h2 driver now groups its per-connection receive buffer, decoded request stable storage, and temporary decoded request-field scratch in explicit connection-owned storage, so hot-path request-decode ownership is no longer split across unrelated helper allocations.
- The terminated server-side h2 driver now also keeps response DATA, recoverable RST_STREAM, and upgrade preamble/header-block scratch in `ConnectionStorage`, leaving only per-writer response assembly scratch on `H2ResponseWriter`.
- The h1-to-h2c bootstrap path now heap-backs its initial-request stable storage, temporary header-block scratch, temporary decoded request-field scratch, and initial-settings scratch, which keeps the prior-knowledge detection path from rebuilding that H2 state on fresh stack frames.
- The terminated server-side `H2ResponseWriter` now carries its own bounded outbound HEADERS/DATA scratch, so copied per-stream writers and background-task writers do not share mutable frame-assembly storage.

## Module Structure

```
lib/serval-server/
├── mod.zig            # Main module exports (Server, MinimalServer)
├── README.md          # This file
├── frontend/              # Protocol dispatch/adaptation + runtime orchestration helpers
│   ├── mod.zig            # Frontend module exports
│   ├── bootstrap.zig      # Shared startup preflight + transport validation
│   ├── orchestrator.zig   # Frontend-owned TCP/UDP runtime lifecycle orchestration
│   ├── tcp_runtime.zig    # TCP tunnel runtime mechanics (bounded accept/connect/relay)
│   ├── udp_runtime.zig    # UDP runtime mechanics (datagrams, sessions, expiry)
│   ├── dispatch.zig       # TLS ALPN h2 dispatch policy selection
│   └── generic_h2.zig     # Generic TLS h2 adapter (non-terminated handlers)
├── h1/                # HTTP/1.1 implementation
│   ├── mod.zig        # H1 module exports
│   ├── server.zig     # Generic Server struct with connection handling
│   ├── connection.zig # Connection state (ID generation, keep-alive detection)
│   ├── response.zig   # Response writing utilities (status text, response sending)
│   └── reader.zig     # Request reading utilities (header accumulation, body length)
├── h2/                # Early HTTP/2 connection/runtime primitives
│   ├── mod.zig        # H2 module exports
│   ├── connection.zig # Bounded peer/local settings, stream table, flow windows
│   ├── runtime.zig    # Per-frame inbound HTTP/2 runtime actions
│   └── server.zig     # Plain-fd terminating HTTP/2 connection driver with streaming callbacks and bounded outbound HEADERS+CONTINUATION emission
└── websocket/         # Native WebSocket endpoint support
    ├── mod.zig        # Public WebSocket server exports + hook verification
    ├── accept.zig     # `101 Switching Protocols` response builder
    ├── io.zig         # Plain/TLS connection transport adapters
    └── session.zig    # Message-oriented WebSocket session API
```

## Purpose

Generic HTTP server parameterized by Handler, Pool, Metrics, and Tracer types.
Handles accept loop, connection lifecycle, request parsing, HTTP forwarding orchestration,
WebSocket upgrade handoff to the proxy tunnel path, native WebSocket endpoint
termination with a message-oriented session API, gRPC-over-h2 prior-knowledge
or `Upgrade: h2c` connection detection plus proxy handoff, and cleartext HTTP/2
dispatch into the early terminated `h2/server.zig` driver for both prior-knowledge
and upgrade paths when the handler implements explicit HTTP/2 callbacks.

Native gRPC endpoint serving (service/method handlers owned by serval-server) is
not implemented yet.

Protocol implementations are isolated in subdirectories (h1/, h2/) with a neutral `frontend/` layer that owns shared preflight and runtime orchestration, keeping protocol/runtime routing decisions outside protocol-specific drivers.

ACME challenge handling is TLS-ALPN-01 based and is integrated via TLS hook
providers (`serval-acme/tls_alpn_hook.zig`) instead of a dedicated HTTP
challenge listener.

## Handler Hooks

The server calls handler hooks at specific points in the request lifecycle. `selectUpstream` remains required today; all other hooks are optional, including the native WebSocket pair `selectWebSocket` + `handleWebSocket`.

### Request Lifecycle

```
┌─ TCP Accept
│
├─ onConnectionOpen(info)           ← Connection accepted
│
├─ Loop: for each request
│  │
│  ├─ Parse headers
│  │
│  ├─ onRequest(ctx, request, response_buf) → Action
│  │    └─ .continue_request | .send_response | .reject
│  │
│  ├─ onRequestBody(ctx, chunk, is_last) → BodyAction
│  │    └─ .continue_body | .reject
│  │
│  ├─ If valid `Upgrade: websocket` and handler implements it:
│  │    selectWebSocket(ctx, request) → WebSocketRouteAction
│  │      └─ .decline | .accept | .reject
│  │
│  ├─ If `.accept`:
│  │    handleWebSocket(ctx, request, session)    ← Native endpoint session loop
│  │
│  ├─ Otherwise:
│  │    selectUpstream(ctx, request) → Upstream   [REQUIRED]
│  │
│  ├─ onUpstreamRequest(ctx, request)             ← Path rewriting
│  │
│  ├─ Forward to upstream...
│  │
│  ├─ onUpstreamConnect(ctx, info)                ← TLS cipher logging
│  │
│  ├─ onResponse(ctx, response) → Action
│  │
│  ├─ onResponseBody(ctx, chunk, is_last) → BodyAction
│  │
│  ├─ (on error) onError(ctx, err_ctx) → ErrorAction
│  │    └─ .default | .send_response | .retry
│  │
│  └─ onLog(ctx, entry)                           ← Access logging
│
└─ onConnectionClose(conn_id, req_count, duration_ns)
```

### Hook Reference

| Hook | Signature | Purpose |
|------|-----------|---------|
| `selectUpstream` | `(ctx, request) → Upstream` | Select backend for non-native requests (required today) |
| `selectWebSocket` | `(ctx, request) → WebSocketRouteAction` | Accept/decline native WebSocket endpoint handling |
| `handleWebSocket` | `(ctx, request, session) !void` | Native message-oriented WebSocket session loop |
| `onRequest` | `(ctx, request, response_buf) → Action` | Request validation, direct responses |
| `onRequestBody` | `(ctx, chunk, is_last) → BodyAction` | WAF body inspection |
| `onUpstreamRequest` | `(ctx, request) → void` | Path rewriting, header injection |
| `onUpstreamConnect` | `(ctx, info) → void` | TLS cipher logging, observability |
| `onResponse` | `(ctx, response) → Action` | Response modification |
| `onResponseBody` | `(ctx, chunk, is_last) → BodyAction` | Data leak detection |
| `onError` | `(ctx, err_ctx) → ErrorAction` | Custom error handling |
| `onLog` | `(ctx, entry) → void` | Access logging |
| `onConnectionOpen` | `(info) → void` | Connection metrics |
| `onConnectionClose` | `(conn_id, req_count, duration_ns) → void` | Connection cleanup |

### Return Types

- **Action**: `.continue_request` (proceed), `.send_response` (direct response), `.reject` (block with status)
- **BodyAction**: `.continue_body` (proceed), `.reject` (block with status)
- **ErrorAction**: `.default` (502), `.send_response` (custom error), `.retry` (try different upstream)
- **WebSocketRouteAction**: `.decline` (continue normal flow), `.accept` (send `101` and enter native session), `.reject` (send HTTP rejection)

## Design Rationale

The h1/ subdirectory structure follows TigerStyle modular design principles:

- **Protocol isolation**: HTTP/1.1 code is self-contained in h1/, allowing future HTTP/2 implementation in a parallel h2/ structure
- **Backwards compatibility**: Primary exports (Server, MinimalServer) remain at the top level via mod.zig
- **Code organization**: Large responsibilities (request reading, response writing) are split into focused modules
- **Separation of concerns**:
  - `server.zig`: Main Server generic, connection handling, handler orchestration
  - `connection.zig`: Connection ID generation, keep-alive detection, ProcessResult enum
  - `response.zig`: HTTP response writing (status text, response formatting)
  - `reader.zig`: Request reading with partial header accumulation

## Exports

| Symbol | Description |
|--------|-------------|
| `Server(Handler, Pool, Metrics, Tracer)` | Generic HTTP/1.1 server |
| `MinimalServer(Handler)` | Server with SimplePool, NoopMetrics, NoopTracer |
| `WebSocketRouteAction` | Native WebSocket accept/decline/reject decision |
| `WebSocketAccept` | Native WebSocket accept configuration |
| `WebSocketSession` | Message-oriented native WebSocket session API |
| `WebSocketMessage` | Text/binary message returned by `readMessage()` |
| `H2ConnectionState` | Bounded inbound HTTP/2 connection bookkeeping |
| `H2Runtime` | Per-frame inbound HTTP/2 runtime primitive |
| `H2ResponseWriter` | Streaming response writer for terminated HTTP/2 callbacks |
| `servePlainH2Connection` | Plain-fd terminating HTTP/2 connection loop |
| `h1` | HTTP/1.1 implementation module (re-exports Server, MinimalServer) |
| `h2` | Early HTTP/2 server primitive module |
| `websocket` | Native WebSocket server module |

## Usage

```zig
const serval_server = @import("serval-server");
const serval_lb = @import("serval-lb");
const serval_net = @import("serval-net");

var handler = serval_lb.LbHandler.init(&upstreams);
var pool = serval.SimplePool.init();
var metrics = serval.NoopMetrics{};
var tracer = serval.NoopTracer{};

var server = serval_server.Server(
    serval_lb.LbHandler,
    serval.SimplePool,
    serval.NoopMetrics,
    serval.NoopTracer,
).init(&handler, &pool, &metrics, &tracer, .{ .listen_host = "0.0.0.0", .port = 8080 }, null, serval_net.DnsConfig{});

var shutdown = std.atomic.Value(bool).init(false);
try server.run(io, &shutdown, null);
```

## File Responsibilities

### h1/server.zig
Main Server generic parameterized by Handler, Pool, Metrics, Tracer types. Implements the full request/response loop:
- Accept and track connections with unique IDs
- TCP_NODELAY configuration for low-latency responses
- Request parsing via reader utilities
- Handler invocation (onRequest hooks)
- WebSocket upgrade detection and fail-closed validation
- Native WebSocket routing (`selectWebSocket`) and session handoff (`handleWebSocket`)
- Proxy fallback for declined WebSocket upgrades
- h2c prior-knowledge detection for terminated handler dispatch or gRPC proxy connections
- h2c HTTP/1.1 upgrade validation plus terminated-handler or proxy handoff for gRPC connections
- Response sending via response utilities
- Keep-alive detection and connection lifecycle

### h1/connection.zig
Connection state and lifecycle utilities:
- `ProcessResult` enum: explicit control flow (keep_alive, close_connection, fatal_error)
- `nextConnectionId()`: atomic monotonic counter for unique connection IDs
- `clientWantsClose()`: RFC 9112 keep-alive detection logic

### h1/response.zig
HTTP/1.1 response writing utilities (pure functions with explicit I/O parameters):
- `statusText()`: Get HTTP status reason phrase per RFC 9110
- `sendResponse()`: Format and send complete response to client (Content-Length or chunked)
- `sendErrorResponse()`: Send error responses (4xx, 5xx)
- `send100Continue()`: Send 100 Continue for Expect headers
- `send501NotImplemented()`: Send 501 for unsupported HTTP methods

Supports both `Content-Length` and `Transfer-Encoding: chunked` responses via `ResponseMode`.

### h1/reader.zig
Request reading utilities with zero allocation:
- `readRequest()`: Read request bytes from stream into fixed buffer
- `readMoreData()`: Partial read accumulation for headers spanning TCP segments
- `getBodyLength()`: Extract Content-Length from parsed request headers
- Handles incomplete headers and body length validation

### websocket/accept.zig
Native `101 Switching Protocols` response building:
- computes `Sec-WebSocket-Accept`
- validates selected subprotocol against the client offer
- writes canonical upgrade response headers

### websocket/io.zig
Transport adapter for native WebSocket sessions:
- plain TCP vs TLS read/write dispatch
- `SSL_pending()` support for userspace TLS buffered reads
- bounded write-all loops

### websocket/session.zig
Message-oriented native session API:
- `readMessage()` with fragmentation reassembly
- `sendText()`, `sendBinary()`, `sendPing()`, `close()`
- auto-pong handling
- close-handshake timeout enforcement

## Current h2c Slice + Future HTTP/2 Structure

Canonical bridge writeup:
- [docs/architecture/h2-bridge.md](/home/nick/repos/serval/docs/architecture/h2-bridge.md)

### Orchestration vs Mechanics Contract

`serval-server` is the orchestration layer. It owns:

- downstream entry/path detection and lifecycle
- `selectUpstream()` decisions
- request-class policy (for example gRPC completion requirements)
- frontend runtime orchestration for optional L4 capabilities (`tcp_transport`, `udp_transport`)

```text
serval-server (orchestration/policy)
        │
        ▼
serval-proxy.H2StreamBridge (forwarding mechanics)
        │
        ▼
serval-client session/runtime (reusable upstream h2 infra)
```

`serval-server` does **not** own h2 bridge internals. It consumes the
`serval-proxy.H2StreamBridge` contract APIs (open/send/cancel/poll/close-action
mapping) and does not inspect binding-table storage directly.

This contract is a boundary clarification only; it does not change Serval layer
ownership.

Current support now has five HTTP/2 inbound behaviors:
- **TLS ALPN `h2` + terminated handler**: when ALPN negotiates `h2` and the handler implements `handleH2Headers` + `handleH2Data`, `Server` dispatches the TLS stream directly into `h2/server.zig` (terminated runtime over TLS)
- **ALPN rollout policy knobs**: `Config.alpn_mixed_offer_policy` controls mixed-offer ALPN selection (`prefer_http11` vs `prefer_h2`) and `Config.tls_h2_frontend_mode` keeps downstream TLS h2 dispatch explicit (`disabled`, `terminated_only`, `generic`); when ALPN has already negotiated `h2` and no terminated h2 hooks exist, server falls back to generic TLS h2 dispatch to avoid invalid h1 parsing on an h2 connection. The generic per-connection handler state is heap-backed because its stream-tracking tables are too large to keep on constrained connection stacks safely.
- **generic WebSocket over h2**: generic TLS h2 dispatch now advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`, accepts RFC 8441 Extended CONNECT with `:protocol=websocket`, upgrades to an h1 backend WebSocket upstream, and relays stream DATA bidirectionally on the h2 stream
- **generic non-gRPC request bodies over h2**: generic TLS h2 frontend now supports streamed request-body forwarding for h2->h1 routes with per-stream tracked upstream state; `content-length` is validated strictly when present, and requests without `content-length` are translated to HTTP/1.1 chunked transfer encoding (integration coverage asserts header translation behavior). Request trailers and invalid `TE` values are rejected fail-closed with stream reset (`RST_STREAM PROTOCOL_ERROR`).
- **prior knowledge + terminated handler**: when the handler implements `handleH2Headers` + `handleH2Data`, `Server` detects the client preface on a plain connection and dispatches the accepted socket into `h2/server.zig`
- **prior knowledge + proxy bridge/tunnel**: for upstream protocol `.h2c` (cleartext) or `.h2` (TLS), Serval routes through a bounded stream-aware bridge (downstream stream ↔ upstream stream mapping, response frame mapping, upstream reset fail-closed downstream reset, and `GOAWAY(NO_ERROR,last_stream_id>=active_stream)` no longer aborting that active stream). The bridge handler is transport-first (`H2cBridgeHandler`) and keeps gRPC completion requirements in a separate request-class policy table (`GrpcCompletionPolicy`): `grpc-status` is required only for streams classified as gRPC (fail-closed `RST_STREAM(PROTOCOL_ERROR)` on invalid/missing status), while non-gRPC streams no longer inherit gRPC trailer requirements. Unsupported request trailers remain fail-closed for all stream classes (`RST_STREAM(PROTOCOL_ERROR)`). Prior-knowledge detection emits server SETTINGS as soon as the client preface is complete (before waiting for first HEADERS) to interoperate with grpc-go/grpcurl clients that wait for server SETTINGS before sending RPC headers; unsupported upstream protocol combinations fail closed
- **`Upgrade: h2c` + terminated handler**: on cleartext connections with explicit h2 handler callbacks, Serval sends `101 Switching Protocols`, replays the upgraded request into stream 1 in the terminated runtime, accepts an optional post-101 client preface, then continues in full HTTP/2 frame mode
- **`Upgrade: h2c` + proxy bridge/tunnel**: Serval validates `HTTP2-Settings`, selects an upstream, and for upstream protocol `.h2c` (cleartext) or `.h2` (TLS) enters the bounded stream-aware bridge path (including stream-1 bootstrap from the HTTP/1.1 request) with request-class-aware completion rules (gRPC streams require `grpc-status`; non-gRPC streams do not). Unsupported request trailers remain fail-closed (`RST_STREAM(PROTOCOL_ERROR)`); unsupported upstream protocol combinations fail closed

For terminated HTTP/2 handlers, `h2/server.zig` now also supports optional per-stream lifecycle callbacks:
- `handleH2StreamOpen(stream_id, request)` when a new inbound request stream is first observed
- `handleH2StreamClose(summary)` when a stream ends via local END_STREAM, peer reset, local reset, or connection close

`summary` carries bounded per-stream accounting (`request_data_bytes`, `response_data_bytes`), status, duration, and close reason/error code to support stream-scoped metrics/tracing/logging hooks without heap allocation.
In main `h1/server.zig` terminated-h2 dispatch paths (prior-knowledge and upgrade), these callbacks are now wrapped to emit per-stream metrics (`requestStart`/`requestEnd`), per-stream tracer spans, and per-stream `onLog` entries while still forwarding handler-defined H2 lifecycle hooks.

The repository now includes the first Phase-B `h2/` building blocks:
- `connection.zig` for bounded peer/local settings, GOAWAY bookkeeping, stream tables, and flow windows
- `runtime.zig` for per-frame inbound HTTP/2 actions (`send_settings_ack`, request HEADERS/DATA dispatch, bounded HEADERS+CONTINUATION request-header reassembly, bounded HPACK dynamic-table/Huffman decode, ping ack, RST_STREAM, GOAWAY) with `server.zig` now replenishing connection+stream flow-control windows via WINDOW_UPDATE on inbound DATA, classifying stream DATA window exhaustion as stream-scoped flow-control failure without mutating connection-level window state
- `server.zig` for a terminating HTTP/2 driver over plain fd and TLS streams that wires those runtime actions into a real frame loop with streaming callbacks, supports upgraded stream-1 bootstrap + optional post-101 client preface, uses bounded nonblocking read/write retries for deterministic frame progress plus GOAWAY/RST emission under backpressure, emits explicit transport/fd/errno-or-tls-error diagnostics on failure paths, and can now be reached from the main accept loop for cleartext prior-knowledge/upgrade paths and TLS ALPN `h2` dispatch

Full stream-aware HTTP/2 support will continue expanding that `h2/` subdirectory toward
this target organization:

```
└── h2/               # HTTP/2 implementation (future)
    ├── mod.zig       # H2 module exports
    ├── server.zig    # H2 server with stream multiplexing
    ├── frames.zig    # HTTP/2 frame parsing (SETTINGS, HEADERS, DATA, etc.)
    ├── hpack.zig     # Header compression (Huffman encoding, dynamic table)
    ├── streams.zig   # Stream state machine and flow control
    └── connection.zig # Connection preface and upgrade handling
```

The mod.zig would dispatch based on negotiated protocol (via ALPN or h2c preface), maintaining the same top-level Server interface.

## TCP/UDP Capability Contract (frontend)

When `Config.tcp_transport` / `Config.udp_transport` are disabled or absent,
HTTP behavior is unchanged.

When enabled:
- `frontend/bootstrap.zig` performs shared transport config validation and
  startup preflight.
- `frontend/orchestrator.zig` starts/stops transport runtimes under the same
  shutdown contract as h1/h2 server paths.
- `frontend/tcp_runtime.zig` handles stream mechanics only (accept/connect/relay/
  timeout/capacity), consuming shared strategy outputs.
- `frontend/udp_runtime.zig` handles datagram/session mechanics only
  (ingress/egress, keying, expiry, bounded sessions), consuming shared strategy
  outputs.

## Dependencies

- serval-core: types, config, errors, context, traits
- serval-net: socket utilities
- serval-http: HTTP parser
- serval-websocket: WebSocket handshake, frame, close, and subprotocol helpers
- serval-h2: HTTP/2 frame, preface, HPACK, and initial-request helpers
- serval-grpc: gRPC metadata and message-envelope validation helpers
- serval-pool: connection pooling
- serval-proxy: upstream forwarding
- serval-metrics: metrics interface
- serval-tracing: tracing interface
- serval-tls: TLS termination for client connections

## Implementation Status

| Feature | Status |
|---------|--------|
| HTTP/1.1 server | ✅ Complete |
| Connection handling | ✅ Complete |
| Keep-alive (RFC 9112) | ✅ Complete |
| Concurrent connections (io_uring) | ✅ Complete |
| Handler hooks | ✅ Complete |
| Modular h1/ structure | ✅ Complete |
| TLS termination | ✅ Complete |
| TLS response forwarding | ✅ Complete |
| WebSocket upgrade proxy handoff | ✅ Complete |
| Native WebSocket endpoint serving | ✅ Complete |
| gRPC over h2 proxy handoff (TLS ALPN `h2`, prior knowledge, + inbound upgrade) | ✅ Stream-aware bridge active for downstream TLS `h2`, cleartext prior-knowledge, and cleartext `Upgrade: h2c` entry, with `.h2c` (cleartext) and `.h2` (TLS) upstream support; includes GOAWAY `last_stream_id`-aware active-stream handling, stale-binding retirement plus round-robin upstream-action scanning, and request-class-aware fail-closed `grpc-status` enforcement (gRPC only); background h2 bridge/websocket readers now use `std.Io.Group.concurrent()` instead of `Group.async()` so the per-connection h2 startup path cannot be hijacked by eager inline task execution; unsupported upstream protocol combinations fail closed |
| HTTP/2 full stream-aware stack | ✅ Complete for current Serval scope (terminated h2 + stream-aware proxy across gRPC and non-gRPC paths, with focused mixed-workload churn/soak coverage) |
| Native gRPC endpoints | ❌ Not implemented (high priority) |
| Daemon mode | ❌ Not implemented |
| Hot reload | ⏳ TLS context generation/refcount scaffolding integrated; PEM-driven activation API wired in TLS layer, external trigger/watch path pending |

### TLS Hot-Activation API (scaffold)

When server-side TLS is active and `run()` has published a reload manager:

- `reloadServerTlsFromPemFiles(cert_path, key_path)` → activates a new TLS generation.
- `activeServerTlsGeneration()` → reads the currently active generation.

These methods are intended for control-plane/ACME integration; file-watcher triggering is still pending.

## TigerStyle Compliance

- **Assertions**: Preconditions in parser functions, postconditions for connection IDs
- **Bounded loops**: All I/O operations with explicit buffer sizes
- **No allocations**: Zero-copy request/response handling, fixed buffers
- **Explicit types**: u64 for connection IDs, u16 for status codes
- **Clear control flow**: ProcessResult enum instead of boolean returns
