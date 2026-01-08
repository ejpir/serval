# serval-server

HTTP/1.1 server implementation for serval. Like Pingora's `server` + `apps` modules.

Provides generic HTTP server infrastructure with protocol-specific implementations organized by version (h1/ for HTTP/1.1, h2/ for HTTP/2 in the future).

## Module Structure

```
lib/serval-server/
├── mod.zig           # Main module exports (Server, MinimalServer)
├── README.md         # This file
└── h1/               # HTTP/1.1 implementation
    ├── mod.zig       # H1 module exports
    ├── server.zig    # Generic Server struct with connection handling
    ├── connection.zig # Connection state (ID generation, keep-alive detection)
    ├── response.zig  # Response writing utilities (status text, response sending)
    └── reader.zig    # Request reading utilities (header accumulation, body length)
```

## Purpose

Generic HTTP server parameterized by Handler, Pool, Metrics, and Tracer types.
Handles accept loop, connection lifecycle, request parsing, and forwarding orchestration.

Protocol implementations are isolated in subdirectories (h1/, h2/) to prepare for multi-protocol support while maintaining backwards-compatible top-level exports.

## Handler Hooks

The server calls handler hooks at specific points in the request lifecycle. All hooks except `selectUpstream` are optional (detected at comptime).

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
│  ├─ selectUpstream(ctx, request) → Upstream     [REQUIRED]
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
| `selectUpstream` | `(ctx, request) → Upstream` | Select backend (required) |
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
| `h1` | HTTP/1.1 implementation module (re-exports Server, MinimalServer) |

## Usage

```zig
const serval_server = @import("serval-server");
const serval_lb = @import("serval-lb");

var handler = serval_lb.LbHandler.init(&upstreams);
var pool = serval.SimplePool.init();
var metrics = serval.NoopMetrics{};
var tracer = serval.NoopTracer{};

var server = serval_server.Server(
    serval_lb.LbHandler,
    serval.SimplePool,
    serval.NoopMetrics,
    serval.NoopTracer,
).init(&handler, &pool, &metrics, &tracer, .{ .port = 8080 });

var shutdown = std.atomic.Value(bool).init(false);
try server.run(io, &shutdown);
```

## File Responsibilities

### h1/server.zig
Main Server generic parameterized by Handler, Pool, Metrics, Tracer types. Implements the full request/response loop:
- Accept and track connections with unique IDs
- TCP_NODELAY configuration for low-latency responses
- Request parsing via reader utilities
- Handler invocation (onRequest hooks)
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

## Future: HTTP/2 Structure

When HTTP/2 support is added, an h2/ subdirectory will mirror the h1/ organization:

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

## Dependencies

- serval-core: types, config, errors, context, traits
- serval-net: socket utilities
- serval-http: HTTP parser
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
| HTTP/2 | ⏳ Planned (h2/ structure) |
| Daemon mode | ❌ Not implemented |
| Hot reload | ❌ Not implemented |

## TigerStyle Compliance

- **Assertions**: Preconditions in parser functions, postconditions for connection IDs
- **Bounded loops**: All I/O operations with explicit buffer sizes
- **No allocations**: Zero-copy request/response handling, fixed buffers
- **Explicit types**: u64 for connection IDs, u16 for status codes
- **Clear control flow**: ProcessResult enum instead of boolean returns
