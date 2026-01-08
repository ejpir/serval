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
| `connect.zig` | TCP connect, socket options, protocol negotiation |
| `h1/mod.zig` | HTTP/1.1 module exports |
| `h1/request.zig` | HTTP/1.1 request adapter (delegates to serval-client) |
| `h1/response.zig` | HTTP/1.1 response receiving, header parsing |
| `h1/body.zig` | HTTP/1.1 splice/copy body streaming |
| `h1/chunked.zig` | Chunked transfer encoding forwarding |

## Dependencies

- `serval-core` - Core types, config, logging
- `serval-net` - Socket abstraction, DNS resolver
- `serval-pool` - Connection pooling
- `serval-tracing` - Distributed tracing interface
- `serval-http` - HTTP/1.1 parser
- `serval-tls` - TLS termination/origination
- `serval-client` - HTTP/1.1 client request building (shared implementation)

**Protocol Abstraction:** HTTP/1.1 specific code is isolated in `h1/` subdirectory.
When HTTP/2 is implemented, it will go in `h2/`. The `forwarder.zig` dispatches
based on the protocol negotiated at connection time (via ALPN for TLS, preface
detection for cleartext).

## Features

- **Async I/O** - Uses `Io.net.Stream` for non-blocking upstream connections
- **io_uring integration** - Connect, send, and receive via io_uring batch submission
- **TLS support** - Client-side TLS for encrypted responses, upstream TLS for backend connections
- Connection pooling integration
- Stale connection retry (Pingora-style)
- Zero-copy with splice() when available (plaintext only, extracts raw fd from stream)
- Userspace copy for TLS paths (both client and upstream)
- Content-Length body forwarding
- Response streaming to client

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
| HTTP/2 upstream | Not implemented |

## TigerStyle Compliance

- Bounded loops with explicit iteration limits
- Zero runtime allocation (fixed buffers)
- Explicit u64 for body lengths
- Assertions on preconditions
- RFC 9112 compliant (Connection: close handling noted)
