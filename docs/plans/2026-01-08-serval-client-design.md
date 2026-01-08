# serval-client Design

**Date:** 2026-01-08
**Status:** Draft

## Overview

serval-client is an HTTP/1.1 client library for making requests to upstream servers. It provides the client-side complement to serval-server.

### Purpose

- Unified HTTP client for all serval components
- Replaces duplicated HTTP client code in serval-gateway and serval-prober
- Provides building blocks that serval-proxy composes for forwarding

### Design Principles

- Async I/O via `std.Io` (io_uring integration)
- TigerStyle: explicit lifecycle, caller-provided buffers, no hidden allocation
- Separates bounded (headers) from unbounded (body) operations
- Fine-grained errors for debugging and metrics

### Scope

**What it does:**

- DNS resolution (via serval-net.DnsResolver)
- TCP connection with configurable timeouts
- TLS handshake (via serval-tls)
- HTTP/1.1 request serialization and sending
- HTTP/1.1 response header parsing
- Returns connection for caller to handle body

**What it does NOT do:**

- Connection pooling (delegate to serval-pool)
- Response body reading (caller handles via buffer, splice, or stream)
- Retry logic (caller decides)
- Keep-alive management (caller decides)

## Layer Placement

**Layer:** 2 (Infrastructure) - alongside serval-pool, serval-prober, serval-health

### Dependencies

| Module | What serval-client uses |
|--------|------------------------|
| serval-core | `Upstream`, `Request`, `Response`, `config` constants |
| serval-net | `Socket`, `DnsResolver`, `parseIPv4` |
| serval-tls | `ssl.SSL_CTX`, TLS handshake |
| serval-http | `parseStatusCode`, `parseContentLength` (response parsing) |
| serval-pool | `Connection` type (returned from connect) |

### Dependents

| Module | How they use it |
|--------|----------------|
| serval-proxy | `connect()`, `sendRequest()`, `readResponseHeaders()` - then splice for body |
| serval-prober | `connect()`, `sendRequest()`, `readResponseHeaders()` - check status code |
| serval-gateway | `connect()`, `sendRequest()`, `readResponseHeaders()` + read body into buffer |

## File Structure

```
serval-client/
├── mod.zig          # Public exports
├── client.zig       # Client struct, connect(), high-level request()
├── request.zig      # sendRequest() - moved from serval-proxy/h1/request.zig
├── response.zig     # readResponseHeaders(), response parsing
└── README.md        # Module documentation
```

## Public API

### Module Exports

```zig
// serval-client/mod.zig

pub const Client = @import("client.zig").Client;
pub const ClientError = @import("client.zig").ClientError;
pub const ResponseHeaders = @import("response.zig").ResponseHeaders;

// Re-exports for convenience
pub const Connection = @import("serval-pool").Connection;
pub const Request = @import("serval-core").types.Request;
```

### Client Struct

```zig
pub const Client = struct {
    allocator: Allocator,
    dns_resolver: *DnsResolver,
    client_ctx: ?*ssl.SSL_CTX,  // For TLS upstreams, null = plain only
    verify_tls: bool,

    pub fn init(
        allocator: Allocator,
        dns_resolver: *DnsResolver,
        client_ctx: ?*ssl.SSL_CTX,
        verify_tls: bool,
    ) Client;

    pub fn deinit(self: *Client) void;

    /// Low-level: explicit connection lifecycle
    /// Performs DNS resolution, TCP connect, and optional TLS handshake.
    /// Caller owns the returned Connection and must close it.
    pub fn connect(
        self: *Client,
        upstream: *const Upstream,
        io: Io,
    ) ClientError!Connection;

    /// Mid-level: send request on existing connection
    /// Serializes and sends HTTP/1.1 request (headers + body if present).
    /// effective_path: optional path override for rewriting (e.g., strip prefix)
    pub fn sendRequest(
        self: *Client,
        conn: *Connection,
        request: *const Request,
        effective_path: ?[]const u8,
    ) ClientError!void;

    /// Mid-level: read response headers (caller handles body)
    /// Reads and parses HTTP/1.1 response status line and headers.
    /// Returns body framing info for caller to handle body.
    pub fn readResponseHeaders(
        self: *Client,
        conn: *Connection,
        header_buf: []u8,
    ) ClientError!ResponseHeaders;

    /// High-level convenience: connect + send + read headers (one-shot)
    /// Opens connection, sends request, reads response headers, returns.
    /// Caller still owns connection cleanup via returned ResponseHeaders.
    pub fn request(
        self: *Client,
        upstream: *const Upstream,
        request: *const Request,
        header_buf: []u8,
        io: Io,
    ) ClientError!struct { conn: Connection, response: ResponseHeaders };
};
```

## Types

### ResponseHeaders

```zig
pub const ResponseHeaders = struct {
    /// HTTP status code (e.g., 200, 404, 500)
    status: u16,

    /// Parsed response headers
    headers: HeaderMap,

    /// Body framing from Content-Length or Transfer-Encoding
    body_framing: BodyFraming,

    /// Bytes consumed from header_buf (where body starts)
    header_bytes: usize,
};
```

### ClientError

```zig
pub const ClientError = error{
    // Connection phase
    DnsResolutionFailed,
    TcpConnectFailed,
    TcpConnectTimeout,
    TlsHandshakeFailed,

    // Send phase
    SendFailed,
    SendTimeout,

    // Receive phase
    RecvFailed,
    RecvTimeout,
    ResponseHeadersTooLarge,
    InvalidResponseStatus,
    InvalidResponseHeaders,
    ConnectionClosed,
};
```

### Configuration (in serval-core/config.zig)

```zig
// Add to existing serval-core/config.zig

/// Client connection timeout in nanoseconds
pub const CLIENT_CONNECT_TIMEOUT_NS: u64 = 5_000_000_000;  // 5 seconds

/// Client read timeout in nanoseconds
pub const CLIENT_READ_TIMEOUT_NS: u64 = 30_000_000_000;    // 30 seconds

/// Client write timeout in nanoseconds
pub const CLIENT_WRITE_TIMEOUT_NS: u64 = 30_000_000_000;   // 30 seconds

// MAX_HEADER_SIZE_BYTES already exists, reuse for response headers
```

### Local Constants (in serval-client)

```zig
// Safety bounds - implementation details, not in config.zig

/// Maximum write iterations (TigerStyle: bounded loops)
const MAX_WRITE_ITERATIONS: u32 = 10_000;

/// Maximum read iterations (TigerStyle: bounded loops)
const MAX_READ_ITERATIONS: u32 = 10_000;
```

## Code Migration

### What Moves from serval-proxy to serval-client

| From | To | Notes |
|------|-----|-------|
| `serval-proxy/h1/request.zig` → `buildRequestBuffer()` | `serval-client/request.zig` | Request serialization |
| `serval-proxy/h1/request.zig` → `sendBuffer()` | `serval-client/request.zig` | Bounded write loop |
| `serval-proxy/h1/request.zig` → `HOP_BY_HOP_HEADERS` | `serval-client/request.zig` | RFC 7230 constants |
| `serval-proxy/connect.zig` → `connectUpstream()` | `serval-client/client.zig` | DNS + TCP + TLS connect |

### What Stays in serval-proxy

| Code | Reason |
|------|--------|
| `forwarder.zig` | Proxy-specific: splice, body streaming, client-upstream relay |
| `types.zig` → `ForwardError`, `ForwardResult` | Proxy-specific results with timing breakdown |
| Pool integration logic | Proxy composes client + pool |

### serval-proxy After Refactor

```zig
// serval-proxy/forwarder.zig (after refactor)
const client = @import("serval-client");

// Use serval-client for connect
const conn = try self.client.connect(&upstream, io);

// Use serval-client for sending request
try self.client.sendRequest(&conn, request, effective_path);

// Use serval-client for response headers
const response = try self.client.readResponseHeaders(&conn, header_buf);

// Proxy-specific: splice body back to client (stays in forwarder)
try self.spliceResponseBody(conn, client_fd, response.body_framing);
```

## Consumer Integration

### serval-gateway (K8s client)

```zig
// serval-gateway/k8s/client.zig
const serval_client = @import("serval-client");

pub const Client = struct {
    http_client: serval_client.Client,
    k8s_upstream: Upstream,
    token: []const u8,
    header_buf: [config.MAX_HEADER_SIZE_BYTES]u8,
    response_buf: [MAX_RESPONSE_SIZE_BYTES]u8,

    pub fn get(self: *Client, path: []const u8, io: Io) ![]const u8 {
        var request = Request{ .method = .GET, .path = path, .headers = .{} };
        try request.headers.put("Authorization", self.bearer_header);
        try request.headers.put("Accept", "application/json");
        try request.headers.put("Connection", "close");

        // One-shot request (no pooling)
        const result = try self.http_client.request(
            &self.k8s_upstream, &request, &self.header_buf, io
        );
        defer result.conn.close();

        // Read body into buffer (K8s responses are small JSON)
        return try self.readBody(&result.conn, result.response.body_framing);
    }
};
```

### serval-prober

```zig
// serval-prober/prober.zig
const serval_client = @import("serval-client");

fn probeBackend(
    client: *serval_client.Client,
    upstream: Upstream,
    health_path: []const u8,
    io: Io,
) bool {
    var conn = client.connect(&upstream, io) catch return false;
    defer conn.close();

    var request = Request{ .method = .GET, .path = health_path, .headers = .{} };
    request.headers.put("Host", upstream.host) catch return false;
    request.headers.put("Connection", "close") catch return false;

    client.sendRequest(&conn, &request, null) catch return false;

    var header_buf: [512]u8 = undefined;
    const response = client.readResponseHeaders(&conn, &header_buf) catch return false;

    return response.status >= 200 and response.status < 300;
}
```

## TigerStyle Compliance

### Assertions (~2 per function)

```zig
pub fn connect(self: *Client, upstream: *const Upstream, io: Io) ClientError!Connection {
    assert(upstream.host.len > 0);       // S1: precondition
    assert(upstream.port > 0);            // S1: precondition

    // ... connection logic ...

    assert(conn.socket.getFd() >= 0);     // S1: postcondition
    return conn;
}
```

### Bounded Loops

```zig
// sendBuffer - bounded write iterations
var iteration: u32 = 0;

while (remaining.len > 0 and iteration < MAX_WRITE_ITERATIONS) {
    iteration += 1;
    const written = conn.socket.write(remaining) catch return ClientError.SendFailed;
    if (written == 0) return ClientError.SendFailed;
    remaining = remaining[written..];
}
if (iteration >= MAX_WRITE_ITERATIONS) return ClientError.SendFailed;
```

### No Allocation After Init

- Client.init() takes allocator only for DnsResolver compatibility
- All buffers provided by caller
- No internal allocations during connect/send/read

### Explicit Error Handling

- Fine-grained ClientError enum
- No `catch {}` - all errors propagated or handled explicitly

### Units in Names

- `connect_timeout_ns`, `read_timeout_ns` (nanoseconds)
- `max_header_size_bytes` (bytes)
- `header_bytes` in ResponseHeaders (bytes consumed)

## Testing Requirements

### Unit Tests

- `Client.connect()` - mock DNS resolver, verify socket creation
- `sendRequest()` - verify HTTP/1.1 format, CRLF, hop-by-hop filtering
- `readResponseHeaders()` - parse valid responses, reject malformed
- Error mapping - verify all error cases return correct ClientError

### Integration Tests

- Connect to real HTTP server, send request, verify response
- Connect to HTTPS server with TLS, verify handshake
- Timeout tests - verify timeouts are honored
- Large header tests - verify MAX_HEADER_SIZE_BYTES enforced

### Consumer Tests

- serval-prober using serval-client for probes
- serval-gateway using serval-client for K8s API
- serval-proxy using serval-client for upstream requests
