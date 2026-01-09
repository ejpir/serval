# serval-core

Foundation types and configuration for the serval HTTP library.

## Purpose

Zero-dependency foundation module containing shared types, errors, configuration, and request context. All other serval modules depend on this.

## Exports

### Types
- `Request` - HTTP request representation (method, path, headers)
- `Response` - HTTP response representation
- `Upstream` - Backend server target (host, port, pool index, tls flag)
- `HeaderMap` - Fixed-size header storage (64 headers max) with O(1) cached lookups
- `Method` - HTTP methods enum
- `Version` - HTTP version enum
- `BodyFraming` - Body framing type (content_length, chunked, none)
- `ResponseMode` - Response encoding mode (content_length, chunked)

### Hook Action Types
- `Action` - Handler action for request/response hooks (continue_request, send_response, reject)
- `BodyAction` - Handler action for body inspection hooks (continue_body, reject)
- `ErrorAction` - Handler action for error hooks (default, send_response, retry)
- `RejectResponse` - Rejection info with status code and reason
- `DirectResponse` - Direct response data (status, body, content_type, extra_headers, response_mode)

### HeaderMap O(1) Lookups

`HeaderMap` caches indices for frequently-accessed headers during `put()`:

```zig
var headers = HeaderMap.init();
try headers.put("Content-Length", "42");
try headers.put("Host", "example.com");

// O(1) lookups for hot-path headers (no linear scan)
const len = headers.getContentLength();    // ?[]const u8
const host = headers.getHost();            // ?[]const u8
const conn = headers.getConnection();      // ?[]const u8
const enc = headers.getTransferEncoding(); // ?[]const u8

// O(n) fallback for custom headers
const custom = headers.get("X-Custom");    // ?[]const u8
```

**Why**: HTTP proxies check these headers on every request. Caching their indices avoids repeated O(n) scans at high throughput.

### Configuration
- `Config` - Server configuration (port, timeouts, limits)
- `TlsConfig` - TLS configuration (cert paths, verification, timeouts)
- `DEBUG_LOGGING` - Comptime flag (true in Debug builds)
- `MAX_HEADERS` - 64
- `MAX_HEADER_SIZE_BYTES` - 8192
- `MAX_URI_LENGTH_BYTES` - 8192
- `MAX_BODY_SIZE_BYTES` - 1MB
- `STREAM_WRITE_BUFFER_SIZE_BYTES` - 4096
- `STREAM_READ_BUFFER_SIZE_BYTES` - 4096

### Logging
- `debugLog` - Comptime-conditional debug logging (zero overhead in release)
- `LogEntry` - Request lifecycle info for `onLog` hook (timestamp, timing, status, errors)

### Hook Verification
- `verifyHandler` - Comptime verification that Handler types implement required hooks
- `hasHook` - Check if a Handler has an optional hook at comptime

### Errors
- `ParseError` - HTTP parsing failures
- `ConnectionError` - Network connection failures
- `UpstreamError` - Backend communication failures
- `RequestError` - Request processing failures
- `ErrorContext` - Structured error info with phase and upstream

### Context
- `Context` - Per-request context (timing, bytes, upstream, status)
- `BodyReader` - Lazy request body reader for `onRequest` hooks

### Observability Types
- `ConnectionInfo` - Client connection info for logging hooks
- `UpstreamConnectInfo` - Upstream timing breakdown for logging

## ConnectionInfo

Passed to `onConnectionOpen` handler hook:

```zig
pub const ConnectionInfo = struct {
    connection_id: u64,     // Unique connection identifier
    client_addr: [46]u8,    // Client IP (null-terminated)
    client_port: u16,       // Client source port
    local_port: u16,        // Server port client connected to
    tcp_rtt_us: u32,        // TCP RTT estimate (microseconds)
    tcp_rtt_var_us: u32,    // TCP RTT variance (microseconds)
};
```

## UpstreamConnectInfo

Upstream connection timing for detailed logging:

```zig
pub const UpstreamConnectInfo = struct {
    dns_duration_ns: u64,             // DNS resolution (nanoseconds)
    tcp_connect_duration_ns: u64,     // TCP handshake (nanoseconds)
    tls_handshake_duration_ns: u64,   // TLS handshake (nanoseconds, 0 if plaintext)
    reused: bool,                     // Connection from pool
    pool_wait_ns: u64,                // Pool wait time (nanoseconds)
    local_port: u16,                  // Upstream connection local port
    tls_cipher: [64]u8,               // TLS cipher suite name (empty if plaintext)
    tls_version: [16]u8,              // TLS protocol version (empty if plaintext)
};
```

**TLS fields:** When connecting to TLS upstreams, the `tls_cipher` and `tls_version` fields contain null-terminated strings identifying the negotiated cipher suite (e.g., "TLS_AES_256_GCM_SHA384") and protocol version (e.g., "TLSv1.3"). For plaintext connections, these fields are zero-initialized.

**Units convention:** `_ns` suffix for nanoseconds, `_us` suffix for microseconds.

## Hook Action Types

The lifecycle hooks return action types that control request processing flow.

### Action

Returned by `onRequest` and `onResponse` hooks to control request/response processing:

```zig
pub const Action = union(enum) {
    continue_request,              // Continue normal processing
    send_response: DirectResponse, // Send direct response without forwarding
    reject: RejectResponse,        // Reject with error status (400-499)
};
```

**Example: WAF blocking in onRequest**
```zig
fn onRequest(ctx: *Context, request: *Request, response_buf: []u8) Action {
    if (detectSqlInjection(request.path)) {
        return .{ .reject = .{ .status = 403, .reason = "SQL injection detected" } };
    }
    return .continue_request;
}
```

**Example: Direct response without upstream**
```zig
fn onRequest(ctx: *Context, request: *Request, response_buf: []u8) Action {
    if (std.mem.eql(u8, request.path, "/health")) {
        const body = "OK";
        @memcpy(response_buf[0..body.len], body);
        return .{ .send_response = .{
            .status = 200,
            .body = response_buf[0..body.len],
            .content_type = "text/plain",
        } };
    }
    return .continue_request;
}
```

### BodyAction

Returned by `onRequestBody` and `onResponseBody` hooks for body inspection:

```zig
pub const BodyAction = union(enum) {
    continue_body,         // Continue processing the body chunk
    reject: RejectResponse, // Reject (e.g., WAF detected threat in body)
};
```

**Example: Body size validation**
```zig
fn onRequestBody(ctx: *Context, chunk: []const u8, is_final: bool) BodyAction {
    ctx.body_bytes_seen += chunk.len;
    if (ctx.body_bytes_seen > MAX_BODY_SIZE) {
        return .{ .reject = .{ .status = 413, .reason = "Payload too large" } };
    }
    return .continue_body;
}
```

### ErrorAction

Returned by `onError` hook to customize error handling:

```zig
pub const ErrorAction = union(enum) {
    default,                       // Use default 502 Bad Gateway response
    send_response: DirectResponse, // Send custom error response
    retry,                         // Retry with different upstream
};
```

**Example: Custom error page**
```zig
fn onError(ctx: *Context, err: ErrorContext, response_buf: []u8) ErrorAction {
    const body = "{\"error\": \"service_unavailable\"}";
    @memcpy(response_buf[0..body.len], body);
    return .{ .send_response = .{
        .status = 503,
        .body = response_buf[0..body.len],
        .content_type = "application/json",
    } };
}
```

### RejectResponse

Used by `Action.reject` and `BodyAction.reject` variants:

```zig
pub const RejectResponse = struct {
    status: u16 = 403,            // HTTP status code (typically 400-499)
    reason: []const u8 = "Forbidden", // Reason phrase for logging (not sent to client)
};
```

### DirectResponse

Used by `Action.send_response` and `ErrorAction.send_response` variants:

```zig
pub const DirectResponse = struct {
    status: u16 = 200,
    body: []const u8 = "",                    // Must point into response_buf
    content_type: []const u8 = "text/plain",
    extra_headers: []const u8 = "",           // Pre-formatted headers
    response_mode: ResponseMode = .content_length,
};
```

**Note:** The `body` slice must reference memory in the `response_buf` parameter provided to the hook. The server owns this buffer and will send its contents after the hook returns.

## BodyReader

Lazy request body reading for `onRequest` hooks. The body is only read when explicitly requested via `ctx.readBody()`.

```zig
fn onRequest(ctx: *Context, request: *Request, response_buf: []u8) Action {
    // Read body into caller-provided buffer (lazy - only reads if called)
    var body_buf: [8192]u8 = undefined;
    const body = ctx.readBody(&body_buf) catch |err| {
        return .{ .reject = .{ .status = 400, .reason = "Failed to read body" } };
    };

    // Process body...
    return .continue_request;
}
```

**TigerStyle:** Industry-standard lazy evaluation pattern. Body is only read when handler needs it, avoiding unnecessary I/O for handlers that don't inspect bodies.

**Errors:**
- `BodyTooLarge` - Body exceeds `DIRECT_REQUEST_BODY_SIZE_BYTES` (64KB default)
- `ReadFailed` - Network read error
- `ChunkedNotSupported` - Chunked transfer encoding not yet supported for direct body reading

## Usage

```zig
const core = @import("serval-core");

var ctx = core.Context.init();
const upstream = core.Upstream{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
```

## Implementation Status

| Feature | Status |
|---------|--------|
| Types | ✅ Complete |
| Config | ✅ Complete |
| Errors | ✅ Complete |
| Context | ✅ Complete |
| BodyReader | ✅ Complete |
| Logging | ✅ Complete |
| Hook verification | ✅ Complete |

## TigerStyle Compliance

- Explicit types (u16, u32, u64 - no usize except where required)
- Fixed-size buffers with compile-time limits
- Zero allocation at runtime
- Headers array zeroed for defense-in-depth
- ~2 assertions per function (preconditions, postconditions)
- O(1) hot-path optimization via index caching
