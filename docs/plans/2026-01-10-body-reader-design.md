# BodyReader Design

Composable HTTP response body reader for serval-client.

## Overview

Add `BodyReader` to serval-client that handles three body consumption patterns:
- **Buffer** - `readAll()` for JSON APIs, small responses
- **Stream** - `readChunk()` for large files, incremental processing
- **Forward** - `forwardTo()` for proxy/gateway with zero-copy splice

## API

### BodyReader Struct

```zig
/// HTTP response body reader with multiple consumption patterns.
///
/// TigerStyle: Caller-owned buffers, bounded iterations, no allocation after init.
pub const BodyReader = struct {
    /// Source socket to read from.
    socket: *Socket,
    /// Body framing from response headers.
    framing: BodyFraming,
    /// Bytes remaining (for content_length), or null if unknown.
    bytes_remaining: ?u64,
    /// True if body fully consumed.
    done: bool,
    /// Iteration counter for bounded loops.
    iterations: u32,

    /// Initialize body reader from socket and framing info.
    pub fn init(socket: *Socket, framing: BodyFraming) BodyReader;

    /// Read entire body into caller-owned buffer.
    /// Returns slice of buffer containing body data.
    pub fn readAll(self: *BodyReader, buf: []u8) BodyError![]u8;

    /// Read next chunk into caller-owned buffer.
    /// Returns slice with chunk data, or null when complete.
    pub fn readChunk(self: *BodyReader, buf: []u8) BodyError!?[]u8;

    /// Forward body to destination socket.
    /// Uses splice (zero-copy) when both sockets support it.
    pub fn forwardTo(self: *BodyReader, dst: *Socket, scratch: []u8) BodyError!u64;
};
```

### Error Types

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
};
```

### Constants

```zig
/// Maximum iterations for body read loops.
/// TigerStyle S4: All loops bounded.
pub const MAX_BODY_READ_ITERATIONS: u32 = 1_000_000;

/// Maximum single chunk size for chunked encoding.
/// TigerStyle S7: Bounded to prevent memory exhaustion.
pub const MAX_CHUNK_SIZE_BYTES: u32 = 16 * 1024 * 1024;  // 16MB
```

## Usage Examples

### Buffer entire JSON response

```zig
const result = try client.request(upstream, &req, &header_buf, io);
defer result.conn.socket.close();

var body_reader = BodyReader.init(&result.conn.socket, result.response.body_framing);
var body_buf: [64 * 1024]u8 = undefined;
const json = try body_reader.readAll(&body_buf);
const parsed = try std.json.parseFromSlice(MyType, allocator, json, .{});
```

### Stream large file to disk

```zig
var body_reader = BodyReader.init(&conn.socket, response.body_framing);
var chunk_buf: [8192]u8 = undefined;

while (try body_reader.readChunk(&chunk_buf)) |chunk| {
    try file.writeAll(chunk);
}
```

### Forward response body (gateway)

```zig
var body_reader = BodyReader.init(&upstream_socket, response.body_framing);
var scratch: [16384]u8 = undefined;

const bytes_forwarded = try body_reader.forwardTo(&client_socket, &scratch);
```

## Zero-Copy Splice

`forwardTo()` uses splice (zero-copy) when both sockets support it:
- Both plain TCP sockets
- Both kTLS-enabled sockets (kernel handles crypto)

Falls back to userspace copy when either socket uses userspace TLS.

```zig
pub fn forwardTo(self: *BodyReader, dst: *Socket, scratch: []u8) BodyError!u64 {
    const can_splice = self.socket.canSplice() and dst.canSplice();

    if (can_splice) {
        return self.spliceTo(dst.getFd(), ...);
    } else {
        return self.copyTo(dst, scratch, ...);
    }
}
```

## Files Changed

| File | Change |
|------|--------|
| serval-client/body.zig | NEW: BodyReader, BodyError, constants |
| serval-client/mod.zig | Add: `pub const body = @import("body.zig");` |
| serval-client/README.md | Document BodyReader API |
| serval-net/socket.zig | Add: `canSplice()` method if not present |

## Migration

### Required: examples/gateway/k8s_client.zig

```zig
// BEFORE: ~60 lines of manual body reading
fn readBody(self: *Self, conn: *Connection, response: ResponseHeaders) ClientError![]const u8 {
    var total_read: usize = 0;
    switch (response.body_framing) {
        .content_length => { /* manual loop */ },
        .chunked => { /* TODO: proper decoding */ },
        .none => { /* manual loop */ },
    }
}

// AFTER: ~10 lines using BodyReader
fn readBody(self: *Self, conn: *Connection, response: ResponseHeaders) ClientError![]const u8 {
    var reader = BodyReader.init(&conn.socket, response.body_framing);
    return reader.readAll(self.response_buffer) catch |err| switch (err) {
        error.BufferTooSmall => ClientError.ResponseTooLarge,
        error.UnexpectedEof => ClientError.ConnectionClosed,
        else => ClientError.RequestFailed,
    };
}
```

## Layer Architecture

```
serval-client/body.zig (Layer 2: Infrastructure)
    ├── imports serval-http/chunked.zig (Layer 1: Protocol)
    ├── imports serval-net/Socket (Layer 1: Protocol)
    └── imports serval-core/types.zig (Layer 0: Foundation)
```

No sideways dependencies. Follows CLAUDE.md architecture rules.

## TigerStyle Compliance

| Rule | Status | Implementation |
|------|--------|----------------|
| S1 assertions | PASS | Preconditions on buffer, postconditions on bytes read |
| S2 explicit-types | PASS | u32 for iterations, u64 for bytes |
| S3 no-recursion | PASS | No recursive calls |
| S4 bounded-loops | PASS | MAX_BODY_READ_ITERATIONS bounds all loops |
| S5 memory-safety | PASS | Caller-owned buffers, no allocation |
| S6 error-handling | PASS | Explicit BodyError set |
| S7 no-unbounded | PASS | MAX_CHUNK_SIZE_BYTES bounds chunks |

## Future Work

1. **Consolidate splice logic** - serval-proxy/h1/body.zig and BodyReader both implement splice/copy selection. Could extract shared helper to serval-net for DRY.

2. **Prober body validation** - Enhance serval-prober to optionally validate health endpoint response body using BodyReader (currently only checks status code).

3. **Streaming response (server-side)** - Separate concern from this design. See `docs/plans/2026-01-10-streaming-response-design.md` for handler → client streaming.

## Testing

1. **Unit tests** - Each method with content_length, chunked, none framing
2. **Boundary tests** - Empty body, max size, buffer exactly full
3. **Error tests** - Buffer too small, unexpected EOF, invalid chunks
4. **Integration** - Real socket with mock HTTP server
5. **Splice tests** - Verify zero-copy path taken when applicable
