# serval-client

HTTP/1.1 client library for making requests to upstream servers, with bounded HTTP/2 client session/runtime primitives for stream-aware h2c upstream support.

## Overview

serval-client provides the client-side complement to serval-server. It handles DNS resolution, TCP connection, optional TLS handshake, request serialization, and response header parsing.

Current code also includes an `h2/` subdirectory with bounded outbound HTTP/2 primitives:
- `H2SessionState` for per-connection settings/flow-control/stream tables
- `H2Runtime` for frame-level actions (client preface+SETTINGS emission, request HEADERS/DATA frame building with bounded outbound HEADERS+CONTINUATION fragmentation honoring peer max-frame limits, response HEADERS/DATA/trailer parsing with bounded HEADERS+CONTINUATION reassembly and bounded HPACK dynamic-table/Huffman decode, and GOAWAY/RST/WINDOW_UPDATE handling)
- `H2ClientConnection` as a fixed-buffer socket driver over `H2Runtime` for prior-knowledge h2c sessions
- `H2UpstreamSessionPool` as a fixed-capacity per-upstream cache that owns connected `H2ClientConnection` sessions, supports GOAWAY rollover (active + draining session), and reuses sessions until stale/invalid state
- `h2_max_sessions_per_upstream` as the owner-local rollover bound for active + draining upstream h2 sessions

The h2 transport adapter now translates TLS `WantRead` / `WantWrite` signals
from `serval-tls` back into the client session's existing bounded retry model,
so higher-level h2 session logic stays transport-agnostic.
For plain sockets, the connection driver uses `std.Io` stream writer/reader
when an `Io` context is provided (the upstream session-pool path), keeping
outbound h2 operations fiber-schedulable instead of issuing raw blocking
syscalls from the protocol driver.

The client h2 runtime also treats duplicate/late upstream `RST_STREAM` frames
for already-retired known streams as idempotent control noise instead of
surfacing them as repeated missing-stream errors.

`H2Runtime` remains socket-agnostic; `H2ClientConnection` is the concrete socket-owning driver. `H2UpstreamSessionPool` is the first reusable higher-level lifecycle wrapper that connects, handshakes, caches, and returns stream-capable upstream sessions.

**Layer:** 2 (Infrastructure) - alongside serval-pool, serval-prober, serval-health

## Design Principles

- **Async I/O** - H2 connection driver uses `std.Io` (io_uring integration) for fiber-safe operations when an `Io` context is provided; HTTP/1 request/response paths use blocking socket I/O (fiber-safe variants live in `serval-proxy/h1/`)
- **TigerStyle** - Explicit lifecycle, caller-provided buffers, no hidden allocation
- **Bounded/Unbounded Separation** - Reads bounded headers, caller handles unbounded body
- **Fine-grained Errors** - Specific error types for debugging and metrics

## Usage

### Basic Request

```zig
const serval_client = @import("serval-client");
const Client = serval_client.Client;

// Initialize client
var dns_resolver: DnsResolver = undefined;
DnsResolver.init(&dns_resolver, .{});
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
try request.headers.put("Connection", "close"); // One-shot, close after response

// One-shot request
var header_buf: [8192]u8 = undefined;
const result = try client.request(upstream, &request, &header_buf, io);
defer result.conn.close();

// result.response.status, result.response.headers, result.response.body_framing
```

### Connection Header (Keep-Alive vs Close)

serval-client is a low-level library that gives callers full control over HTTP semantics. **You must set the `Connection` header yourself** based on your use case:

**One-shot requests (close after response):**
```zig
try request.headers.put("Connection", "close");
// ... make request ...
defer conn.close();
```

Without `Connection: close`, HTTP/1.1 defaults to keep-alive. The server will wait for more requests on the same connection. If you then close the connection, the server sees `ConnectionResetByPeer`.

**Pooled/reusable connections:**
```zig
// Do NOT set Connection: close
// Connection will be returned to pool for reuse
```

**Long-lived streaming (watches, SSE):**
```zig
// Do NOT set Connection: close
// Keep connection open for streaming events
```

### Low-Level API (Explicit Lifecycle)

```zig
// Step 1: Connect (returns timing info for observability)
var connect_result = try client.connect(upstream, io);
errdefer connect_result.conn.close();

// Timing info available:
// - connect_result.dns_duration_ns
// - connect_result.tcp_connect_duration_ns
// - connect_result.tls_handshake_duration_ns
// - connect_result.local_port

// Step 2: Send request
try client.sendRequest(&connect_result.conn, &request, null);

// Step 3: Read response headers
var header_buf: [8192]u8 = undefined;
const response = try client.readResponseHeaders(&connect_result.conn, &header_buf);

// Step 4: Handle body based on response.body_framing
// - Caller can buffer small body
// - Caller can splice to another fd (zero-copy)
// - Caller can stream with callback

// Step 5: Close when done
connect_result.conn.close();
```

### Body Reading

After reading response headers, use `BodyReader` to consume the response body:

**Buffer entire body (JSON APIs)**
```zig
var body_reader = serval_client.BodyReader.init(&result.conn.socket, result.response.body_framing);
var body_buf: [64 * 1024]u8 = undefined;
const json = try body_reader.readAll(&body_buf);
const parsed = try std.json.parseFromSlice(MyType, allocator, json, .{});
```

**Stream large file to disk**
```zig
var body_reader = serval_client.BodyReader.init(&conn.socket, response.body_framing);
var chunk_buf: [8192]u8 = undefined;
while (try body_reader.readChunk(&chunk_buf)) |chunk| {
    try file.writeAll(chunk);
}
```

**Forward response body (gateway/proxy)**
```zig
var body_reader = serval_client.BodyReader.init(&upstream_socket, response.body_framing);
var scratch: [16384]u8 = undefined;
const bytes_forwarded = try body_reader.forwardTo(&client_socket, &scratch);
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
    pub fn connect(self, upstream, io) ClientError!ConnectResult;
    pub fn sendRequest(self, conn, request, effective_path) ClientError!void;
    pub fn readResponseHeaders(self, conn, header_buf) ClientError!ResponseHeaders;
    pub fn request(self, upstream, request, header_buf, io) ClientError!RequestResult;
};
```

### ConnectResult

```zig
pub const ConnectResult = struct {
    conn: Connection,              // Connection with socket
    dns_duration_ns: u64,          // DNS resolution time
    tcp_connect_duration_ns: u64,  // TCP handshake time
    tls_handshake_duration_ns: u64, // TLS handshake time (0 if plaintext)
    local_port: u16,               // Ephemeral port
    connect_timeout_honored: bool, // false if backend fell back to unbounded connect
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

### H2 Session/Runtime Primitives

```zig
pub const H2SessionState = serval_client.H2SessionState;
pub const H2Runtime = serval_client.H2Runtime;
pub const H2ClientConnection = serval_client.H2ClientConnection;
pub const H2ClientConnectionStorage = serval_client.H2ClientConnectionStorage;
pub const H2UpstreamSessionPool = serval_client.H2UpstreamSessionPool;

// Session state only (settings, windows, stream table)
var session = try H2SessionState.init();

// Frame-level runtime (no socket ownership)
var response_fields_storage: [serval.config.MAX_HEADERS]serval_h2.HeaderField = undefined;
var runtime = try H2Runtime.init(.{}, &response_fields_storage);

// Socket-owning prior-knowledge h2c driver
var h2_storage = H2ClientConnectionStorage{};
var h2_conn = try H2ClientConnection.init(&socket, .{}, &h2_storage);

// Fixed-capacity per-upstream reusable session pool
var h2_pool: H2UpstreamSessionPool = undefined;
h2_pool.initInto(.{});
defer h2_pool.deinit();
```

`H2ClientConnectionStorage` now owns both inbound receive/header scratch and
the outbound preface, SETTINGS ACK, PING ACK, request-header-block, HEADERS,
DATA, RST_STREAM, WINDOW_UPDATE, plain-stream writer scratch, and bounded
response decode `HeaderField[MAX_HEADERS]` scratch used by the client H2
driver, so the connection hot path keeps its fixed-capacity buffers in one
explicit caller-owned storage object.

`H2Runtime` currently provides bounded helpers for:
- client preface + initial SETTINGS emission
- outbound request HEADERS/DATA frame construction on opened streams
- inbound response HEADERS/DATA/trailer decoding, including bounded HEADERS+CONTINUATION reassembly and bounded HPACK dynamic-table/Huffman decode
- SETTINGS ACK, PING ACK, WINDOW_UPDATE, RST_STREAM, and GOAWAY handling

The client runtime now borrows bounded caller-owned `HeaderField[MAX_HEADERS]`
scratch for response/trailer decode, so the receive hot path does not rebuild
that fixed-capacity array on the stack for each decoded header block.

`H2ClientConnection` adds fixed-buffer socket I/O around that runtime:
- `completeHandshake()` for prior-knowledge preface + SETTINGS synchronization
- `sendRequestHeaders()` / `sendRequestData()` on multiplexed stream ids
- `receiveAction()` / `receiveActionHandlingControl()` for inbound frame dispatch
- `sendRequestData()` now emits bounded DATA chunks using `min(connection_window, stream_window, peer_max_frame_size)` and fails closed with `SendWindowExhausted` when no outbound flow-control credit is available
- `receiveActionHandlingControl()` drains inbound control actions (`SETTINGS ACK`, `PING ACK`) before returning non-control actions to callers

`H2UpstreamSessionPool` adds bounded session lifecycle management above the driver:
- `initInto()` initializes caller-owned pool storage in place, which is the preferred entry point for heap-backed or stack-sensitive call sites
- `acquireOrConnect()` validates `.http_protocol = .h2c`, opens a fresh upstream session on miss, or returns a healthy cached session on hit
- GOAWAY-aware rollover: keep one draining session for in-flight streams while opening a fresh active session for new streams
- reconnect-on-demand when cached sessions are stale, exhausted (`H2_CLIENT_MAX_FRAME_COUNT`), or otherwise unusable
- `close()` / `closeAll()` for deterministic upstream session teardown

### BodyReader

```zig
pub const BodyReader = struct {
    pub fn init(socket: *Socket, framing: BodyFraming) BodyReader;
    pub fn readAll(self: *BodyReader, buf: []u8) BodyError![]u8;
    pub fn readChunk(self: *BodyReader, buf: []u8) BodyError!?[]u8;
    pub fn forwardTo(self: *BodyReader, dst: *Socket, scratch: []u8) BodyError!u64;
};
```

### BodyError

```zig
pub const BodyError = error{
    ReadFailed,
    WriteFailed,
    UnexpectedEof,
    BufferTooSmall,
    IterationLimitExceeded,
    InvalidChunkedEncoding,
    ChunkTooLarge,
    SpliceFailed,
    PipeCreationFailed,
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
| serval-k8s-gateway | connect + send + read headers + buffer body |

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
