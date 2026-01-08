# serval-client

HTTP/1.1 client library for making requests to upstream servers.

## Overview

serval-client provides the client-side complement to serval-server. It handles DNS resolution, TCP connection, optional TLS handshake, request serialization, and response header parsing.

**Layer:** 2 (Infrastructure) - alongside serval-pool, serval-prober, serval-health

## Design Principles

- **Async I/O** - Uses `std.Io` (io_uring integration) for non-blocking operations
- **TigerStyle** - Explicit lifecycle, caller-provided buffers, no hidden allocation
- **Bounded/Unbounded Separation** - Reads bounded headers, caller handles unbounded body
- **Fine-grained Errors** - Specific error types for debugging and metrics

## Usage

### Basic Request

```zig
const serval_client = @import("serval-client");
const Client = serval_client.Client;

// Initialize client
var dns_resolver = DnsResolver.init(.{});
var client = Client.init(
    allocator,
    &dns_resolver,
    ssl_ctx,      // null for plaintext only
    true,         // verify_tls
);
defer client.deinit();

// Define upstream
const upstream = Upstream{
    .host = "api.example.com",
    .port = 443,
    .idx = 0,
    .tls = true,
};

// Build request
var request = Request{ .method = .GET, .path = "/api/users", .headers = .{} };
try request.headers.put("Host", "api.example.com");
try request.headers.put("Accept", "application/json");

// One-shot request
var header_buf: [8192]u8 = undefined;
const result = try client.request(upstream, &request, &header_buf, io);
defer result.conn.close();

// result.response.status, result.response.headers, result.response.body_framing
```

### Low-Level API (Explicit Lifecycle)

```zig
// Step 1: Connect
var conn = try client.connect(upstream, io);
errdefer conn.close();

// Step 2: Send request
try client.sendRequest(&conn, &request, null);

// Step 3: Read response headers
var header_buf: [8192]u8 = undefined;
const response = try client.readResponseHeaders(&conn, &header_buf);

// Step 4: Handle body based on response.body_framing
// - Caller can buffer small body
// - Caller can splice to another fd (zero-copy)
// - Caller can stream with callback

// Step 5: Close when done
conn.close();
```

### Path Rewriting

```zig
// Original path in request
var request = Request{ .method = .GET, .path = "/api/v1/users", ... };

// Override path when sending (e.g., strip prefix)
try client.sendRequest(&conn, &request, "/users");
```

## API Reference

### Client

```zig
pub const Client = struct {
    pub fn init(allocator, dns_resolver, client_ctx, verify_tls) Client;
    pub fn deinit(self) void;
    pub fn connect(self, upstream, io) ClientError!Connection;
    pub fn sendRequest(self, conn, request, effective_path) ClientError!void;
    pub fn readResponseHeaders(self, conn, header_buf) ClientError!ResponseHeaders;
    pub fn request(self, upstream, request, header_buf, io) ClientError!RequestResult;
};
```

### ResponseHeaders

```zig
pub const ResponseHeaders = struct {
    status: u16,              // HTTP status code (100-599)
    headers: HeaderMap,       // Parsed response headers
    body_framing: BodyFraming, // content_length, chunked, or none
    header_bytes: usize,      // Bytes consumed (where body starts)
};
```

### ClientError

```zig
pub const ClientError = error{
    // Connection
    DnsResolutionFailed,
    TcpConnectFailed,
    TcpConnectTimeout,
    TlsHandshakeFailed,
    // Send
    SendFailed,
    SendTimeout,
    BufferTooSmall,
    // Receive
    RecvFailed,
    RecvTimeout,
    ResponseHeadersTooLarge,
    InvalidResponseStatus,
    InvalidResponseHeaders,
    ConnectionClosed,
};
```

## Dependencies

| Module | Usage |
|--------|-------|
| serval-core | `Upstream`, `Request`, `HeaderMap`, `BodyFraming`, config |
| serval-net | `Socket`, `DnsResolver`, `SocketError` |
| serval-pool | `Connection` type |
| serval-tls | SSL context for TLS connections |
| serval-http | `parseStatusCode`, `parseContentLength` |

## Consumers

| Module | Usage |
|--------|-------|
| serval-proxy | connect + send + read headers, then splice body |
| serval-prober | connect + send + read headers, check status |
| serval-gateway | connect + send + read headers + buffer body |

## Configuration

Constants in `serval-core/config.zig`:

| Constant | Value | Description |
|----------|-------|-------------|
| `CLIENT_CONNECT_TIMEOUT_NS` | 5s | TCP connection timeout |
| `CLIENT_READ_TIMEOUT_NS` | 30s | Socket read timeout |
| `CLIENT_WRITE_TIMEOUT_NS` | 30s | Socket write timeout |
| `MAX_HEADER_SIZE_BYTES` | 8KB | Maximum response header size |

## TigerStyle Compliance

- **S1**: ~2 assertions per function (preconditions, postconditions)
- **S3**: No recursion, all loops bounded with `MAX_WRITE_ITERATIONS` / `MAX_READ_ITERATIONS`
- **S5**: No allocation after init, caller-provided buffers
- **S6**: Explicit error sets, no `catch {}`
- **S7**: Bounded buffers with explicit limits

## Testing

```bash
zig build test-client
```
