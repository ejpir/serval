# serval-core

Foundation types and configuration for the serval HTTP library.

## Purpose

Zero-dependency foundation module containing shared types, errors, configuration, and request context. All other serval modules depend on this.

## Exports

### Types
- `Request` - HTTP request representation (method, path, headers)
- `Response` - HTTP response representation
- `Upstream` - Backend server target (host, port, pool index)
- `HeaderMap` - Fixed-size header storage (64 headers max) with O(1) cached lookups
- `Method` - HTTP methods enum
- `Version` - HTTP version enum
- `Action` - Handler action enum (continue_request, send_response)
- `BodyFraming` - Body framing type (content_length, chunked, none)
- `ResponseMode` - Response encoding mode (content_length, chunked)

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
    dns_duration_ns: u64,         // DNS resolution (nanoseconds)
    tcp_connect_duration_ns: u64, // TCP handshake (nanoseconds)
    reused: bool,                 // Connection from pool
    pool_wait_ns: u64,            // Pool wait time (nanoseconds)
    local_port: u16,              // Upstream connection local port
};
```

**Units convention:** `_ns` suffix for nanoseconds, `_us` suffix for microseconds.

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
| Logging | ✅ Complete |
| Hook verification | ✅ Complete |

## TigerStyle Compliance

- Explicit types (u16, u32, u64 - no usize except where required)
- Fixed-size buffers with compile-time limits
- Zero allocation at runtime
- Headers array zeroed for defense-in-depth
- ~2 assertions per function (preconditions, postconditions)
- O(1) hot-path optimization via index caching
