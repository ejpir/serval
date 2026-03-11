# serval-proxy

Async upstream forwarding with zero-copy body transfer and connection pooling.

## Purpose

Handles request forwarding to backend servers using async `Io.net.Stream` I/O integrated with io_uring. Uses Linux splice() for zero-copy body transfer where possible, with fallback to userspace copy.

## Exports

- `Forwarder` - Request forwarder (generic over Pool type)
- `ForwardError` - Error enum for forward failures
- `ForwardResult` - Success result with status and bytes
- `BodyInfo` - Request body metadata for streaming
- `Protocol` - Wire protocol enum (h1, h2)
- `TunnelStats` - WebSocket tunnel relay statistics
- `TunnelTermination` - Tunnel shutdown reason
- `H2StreamBridge` - Stream-aware h2 downstream↔upstream binding and action mapping helper

## Usage

```zig
const proxy = @import("serval-proxy");
const pool_mod = @import("serval-pool");
const tracing = @import("serval-tracing");
const net = @import("serval-net");

var pool = pool_mod.SimplePool.init();
var tracer = tracing.NoopTracer{};
// DnsConfig{} uses default TTL (60s) and timeout (5s) values
var forwarder = proxy.Forwarder(pool_mod.SimplePool, tracing.NoopTracer).init(&pool, &tracer, true, null, net.DnsConfig{});

// Forward using async stream I/O
// client_tls: pass TLS stream for encrypted client connections, null for plaintext
const result = forwarder.forward(io, client_stream, client_tls, &request, &upstream, body_info, span) catch |err| {
    // Handle ForwardError
};
// result.status, result.response_bytes, result.connection_reused
```

## ForwardError

```zig
pub const ForwardError = error{
    ConnectFailed,      // Could not connect to upstream
    InvalidAddress,     // Bad upstream host/port
    SendFailed,         // Failed to send request
    RecvFailed,         // Failed to receive response
    StaleConnection,    // Pooled connection was closed
    HeadersTooLarge,    // Response headers exceed buffer
    InvalidResponse,    // Malformed HTTP response
    SpliceFailed,       // Zero-copy transfer failed
};
```

## ForwardResult

```zig
pub const ForwardResult = struct {
    // Core response metadata
    status: u16,              // HTTP status code
    response_bytes: u64,      // Total bytes sent to client
    connection_reused: bool,  // Whether pool connection was reused

    // Timing breakdown (nanoseconds)
    dns_duration_ns: u64,         // DNS resolution time
    tcp_connect_duration_ns: u64, // TCP handshake time
    send_duration_ns: u64,        // Request send time
    recv_duration_ns: u64,        // Response receive time
    pool_wait_ns: u64,            // Time waiting for pool connection
    upstream_local_port: u16,     // Local port used for upstream
};
```

Timing fields default to 0 for backward compatibility. Use these for detailed Pingora-style request logging.

## Files

| File | Purpose |
|------|---------|
| `mod.zig` | Public API re-exports |
| `types.zig` | ForwardError, ForwardResult, BodyInfo, Protocol |
| `forwarder.zig` | Forwarder struct, pool coordination, timing |
| `connect.zig` | Connection wrapper (delegates to serval-client) |
| `h1/mod.zig` | HTTP/1.1 module exports |
| `h1/request.zig` | HTTP/1.1 request adapter (delegates to serval-client) |
| `h1/response.zig` | HTTP/1.1 response receiving, header parsing |
| `h1/body.zig` | HTTP/1.1 splice/copy body streaming |
| `h1/chunked.zig` | Chunked transfer encoding forwarding |
| `h1/websocket.zig` | Dedicated HTTP/1.1 WebSocket upgrade request/response handling |
| `h2/mod.zig` | HTTP/2 proxy primitive exports |
| `h2/bindings.zig` | Fixed-capacity downstream↔upstream stream binding table |
| `h2/bridge.zig` | Initial stream-aware bridge using `serval-client` h2 upstream sessions |
| `tunnel.zig` | Bidirectional byte relay after successful upgrade |

## Dependencies

- `serval-core` - Core types, config, logging
- `serval-net` - Socket abstraction, DNS resolver
- `serval-pool` - Connection pooling
- `serval-tracing` - Distributed tracing interface
- `serval-http` - HTTP/1.1 parser
- `serval-websocket` - RFC 6455 handshake validation helpers
- `serval-h2` - HTTP/2 / h2c frame and initial-request helpers
- `serval-grpc` - gRPC metadata and message-envelope helpers
- `serval-tls` - TLS termination/origination
- `serval-client` - HTTP/1.1 client request building (shared implementation)

**Protocol Abstraction:** HTTP/1.1 specific code is isolated in `h1/` subdirectory.
Current h2c support is split by upstream protocol:
- cleartext h2c upstreams now use the stream-aware `h2/bridge.zig` path for both
  prior-knowledge and inbound `Upgrade: h2c` entry (bounded downstream↔upstream
  stream bindings, upstream-session reuse, mapped response/reset actions)
- non-h2c upstreams continue to use the legacy translation+tunnel behavior

Full stream-aware h2/ support remains in progress. The repository now includes
bounded `h2/` primitives for that migration:
- `h2/bindings.zig` fixed-capacity downstream-stream ↔ upstream-stream ids
- `h2/bridge.zig` stream-aware bridge that opens/reuses upstream h2 sessions
  through `serval-client` and maps upstream receive actions back to downstream ids

## Features

- **Async I/O** - Uses `Io.net.Stream` for non-blocking upstream connections
- **io_uring integration** - Connect, send, and receive via io_uring batch submission
- **TLS support** - Client-side TLS for encrypted responses, upstream TLS for backend connections
- Connection pooling integration
- Stale connection retry (Pingora-style)
- Zero-copy with splice() when available (plaintext only, extracts raw fd from stream)
- splice forwarding now uses bounded EAGAIN/EINTR retries with stall timeouts and exact pipe-drain verification before counting bytes forwarded
- Userspace copy for TLS paths (both client and upstream)
- Content-Length body forwarding
- Response streaming to client
- WebSocket upgrade forwarding with RFC 6455 handshake validation
- Bidirectional tunnel relay after `101 Switching Protocols`
- gRPC over h2c stream-aware bridging for prior-knowledge and `Upgrade: h2c` entry (cleartext h2c upstreams), including fail-closed invalid responses (`grpc-status` required), GOAWAY `last_stream_id`-aware active-stream handling, and session-generation-aware binding across upstream rollover
- gRPC over h2c legacy translation+tunnel fallback for non-h2c upstream targets
- Upgraded/tunneled connections are closed instead of being returned to the HTTP pool

## Implementation Status

| Feature | Status |
|---------|--------|
| Basic forwarding | Complete |
| Connection pooling | Complete |
| Stale connection retry | Complete |
| splice() zero-copy | Complete |
| Userspace copy fallback | Complete |
| Content-Length bodies | Complete |
| Chunked transfer encoding | Complete |
| Request body forwarding | Complete |
| Client TLS responses | Complete |
| Upstream TLS | Complete |
| WebSocket proxy tunnel | Complete |
| gRPC over h2c proxying | Stream-aware bridge active for both prior-knowledge and inbound upgrade when upstream is cleartext h2c, including GOAWAY `last_stream_id`-aware active-stream handling |
| HTTP/2 stream-aware bridge primitives (`h2/bindings` + `h2/bridge`) | Initial slice complete |
| HTTP/2 full stream-aware upstream support | In progress |

## TigerStyle Compliance

- Bounded loops with explicit iteration limits
- Zero runtime allocation (fixed buffers)
- Explicit u64 for body lengths
- Assertions on preconditions
- RFC 9112 compliant (Connection: close handling noted)
