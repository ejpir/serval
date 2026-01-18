# serval-socket

Unified socket abstraction for both plain TCP and TLS connections.

## Layer

Layer 2 (Infrastructure) - composes `serval-tls` primitives into a single `Socket` tagged union.

## Purpose

Provides a single `Socket` type that abstracts over:
- Plain TCP sockets (direct fd operations)
- TLS sockets (wrapping `serval-tls.TLSStream`)

This allows higher-level modules (pool, proxy, client, server) to work with sockets uniformly without caring whether encryption is enabled.

## Exports

| Symbol | Description |
|--------|-------------|
| `Socket` | Tagged union for plain TCP and TLS sockets |
| `SocketError` | Unified error type for socket operations |
| `PlainSocket` | Plain TCP socket wrapper |
| `Socket.Plain.init_client(fd)` | Create plain client socket from fd |
| `Socket.Plain.init_server(fd)` | Create plain server socket from fd |
| `Socket.TLS.TLSSocket.init_client(fd, ctx, host, enable_ktls)` | Create TLS client socket with SNI |
| `Socket.TLS.TLSSocket.init_server(fd, ctx)` | Create TLS server socket |
| `socket.read(buf)` | Read data into buffer |
| `socket.write(data)` | Write data to socket |
| `socket.write_all(data)` | Write all bytes (handles partial writes) |
| `socket.read_at_least(buf, min_bytes)` | Read at least min_bytes |
| `socket.close()` | Close socket and free resources |
| `socket.get_fd()` | Get raw fd for splice/poll |
| `socket.is_tls()` | Check if TLS socket |
| `socket.is_ktls()` | Check if kTLS kernel offload active |
| `socket.can_splice()` | Check splice eligibility (plain or kTLS) |

## Socket API

### Socket (Tagged Union)

Unified socket type for both plain TCP and TLS connections. Tagged union with explicit dispatch - not generics (TigerStyle: explicit types).

```zig
pub const Socket = union(enum) {
    plain: PlainSocket,
    tls: TLSSocket,
};
```

### SocketError

Unified error type for all socket operations:

| Error | Description |
|-------|-------------|
| `ConnectionReset` | RST received from peer |
| `ConnectionClosed` | Clean close by peer |
| `BrokenPipe` | Write to closed connection (EPIPE) |
| `Timeout` | Operation timed out |
| `TLSError` | TLS handshake, encryption, or certificate error |
| `Unexpected` | Unknown error from syscall or SSL |

### Socket.Plain.init_client(fd: i32) Socket

Create plain client socket from file descriptor.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)

**Returns:** `Socket` with `.plain` variant

### Socket.Plain.init_server(fd: i32) Socket

Create plain server socket from file descriptor. Same as `init_client` for plain TCP, but documents intent for symmetric API with TLS.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)

**Returns:** `Socket` with `.plain` variant

### Socket.TLS.TLSSocket.init_client(fd, ctx, host, enable_ktls) SocketError!Socket

Create TLS client socket with Server Name Indication (SNI). Performs TLS handshake.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)
- `ctx`: OpenSSL SSL_CTX pointer (caller owns lifecycle)
- `host`: Hostname for SNI (max 253 chars per RFC 6066)
- `enable_ktls`: If true, attempt kernel TLS offload. If false, use userspace TLS.

**Returns:** `Socket` with `.tls` variant, or `SocketError`

### Socket.TLS.TLSSocket.init_server(fd, ctx) SocketError!Socket

Create TLS server socket for incoming client connection. Performs TLS handshake.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)
- `ctx`: OpenSSL SSL_CTX pointer (caller owns lifecycle)

**Returns:** `Socket` with `.tls` variant, or `SocketError`

### socket.read(buf: []u8) SocketError!u32

Read data into buffer. Works for both plain and TLS sockets.

**Parameters:**
- `buf`: Buffer to read into (must be non-empty)

**Returns:** Bytes read (u32), 0 on EOF/clean close

### socket.write(data: []const u8) SocketError!u32

Write data to socket. Works for both plain and TLS sockets.

**Parameters:**
- `data`: Data to write (must be non-empty)

**Returns:** Bytes written (u32)

### socket.write_all(data: []const u8) SocketError!void

Write all bytes to socket, handling partial writes.

**Parameters:**
- `data`: Data to write (must be non-empty)

**Returns:** Error if unable to write all bytes

### socket.read_at_least(buf: []u8, min_bytes: u32) SocketError!u32

Read at least min_bytes into buffer.

**Parameters:**
- `buf`: Buffer to read into (must be non-empty)
- `min_bytes`: Minimum bytes to read (must be > 0 and <= buf.len)

**Returns:** Total bytes read (may be more than min_bytes)

### socket.close() void

Close socket and free resources. For TLS, performs graceful shutdown before closing fd.

### socket.get_fd() i32

Get raw file descriptor. Useful for splice (plaintext only) and poll operations.

### socket.is_tls() bool

Check if this is a TLS socket.

### socket.is_ktls() bool

Check if this socket is using kTLS kernel offload. Returns true for TLS sockets where the kernel handles encryption/decryption, false for plain sockets or userspace TLS.

### socket.can_splice() bool

Check if this socket supports zero-copy splice operations. Returns true for:
- Plain TCP sockets (always splice-capable)
- TLS sockets with kTLS enabled (kernel handles encryption transparently)

Returns false for TLS sockets using userspace crypto, where data must pass through OpenSSL.

## Usage

### Plain TCP Socket

```zig
const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;

// Create plain socket from accepted fd
var socket = Socket.Plain.init_server(client_fd);
defer socket.close();

// Read/write
var buf: [4096]u8 = undefined;
const n = try socket.read(&buf);
try socket.write_all(buf[0..n]);

// Check for splice eligibility
if (socket.can_splice()) {
    // Use zero-copy splice
}
```

### TLS Socket (Client)

```zig
const serval_socket = @import("serval-socket");
const tls = @import("serval-tls");
const Socket = serval_socket.Socket;

// SSL_CTX lifecycle is caller's responsibility
const ctx = try tls.ssl.createClientContext();
defer tls.ssl.destroyContext(ctx);

// Create TLS socket with SNI (enable_ktls=true for kernel TLS offload)
var socket = try Socket.TLS.TLSSocket.init_client(upstream_fd, ctx, "api.example.com", true);
defer socket.close();

// Read/write (encrypted transparently)
const n = try socket.read(&buf);
try socket.write_all(response);
```

### TLS Socket (Server)

```zig
const serval_socket = @import("serval-socket");
const tls = @import("serval-tls");
const Socket = serval_socket.Socket;

// SSL_CTX with cert/key is caller's responsibility
const ctx = try tls.ssl.createServerContext("cert.pem", "key.pem");
defer tls.ssl.destroyContext(ctx);

// Accept and wrap with TLS
var socket = try Socket.TLS.TLSSocket.init_server(client_fd, ctx);
defer socket.close();

// Read/write (decryption transparent)
const n = try socket.read(&buf);
try socket.write_all(response);
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Tagged union, not generics | TigerStyle: explicit types, predictable code size |
| Caller owns SSL_CTX | TigerStyle: explicit resource management, no hidden state |
| Zero-copy splice only for plain/kTLS | TLS requires encryption/decryption - can't splice ciphertext |
| SNI max 253 chars | RFC 6066 limit, bounded stack buffer (no allocation) |
| SocketError unifies errors | Single error type for both plain and TLS operations |
| u32 return for read/write | TigerStyle S2: explicit bounded type instead of usize |
| Bulk ops: write_all, read_at_least | Common patterns with bounded retry loops |

## Dependencies

- `serval-tls` - TLS handshake and stream operations

## Implementation Status

| Feature | Status |
|---------|--------|
| Socket tagged union | Complete |
| Plain socket read/write/close | Complete |
| TLS socket init_client with SNI | Complete |
| TLS socket init_server | Complete |
| TLS socket read/write/close | Complete |
| get_fd for splice/poll | Complete |
| is_tls check | Complete |
| is_ktls check | Complete |
| can_splice eligibility | Complete |
| write_all (bulk write) | Complete |
| read_at_least (bulk read) | Complete |

## TigerStyle Compliance

| Rule | Status | Notes |
|------|--------|-------|
| S1: Assertions | Pass | Preconditions on all functions (fd >= 0, buf.len > 0, etc.) |
| S2: Explicit types | Pass | u32 return instead of usize |
| S3: Bounded loops | Pass | write_all/read_at_least have max_iterations |
| S4: No catch {} | Pass | All errors mapped explicitly to SocketError |
| S5: No allocation after init | Pass | SNI uses stack buffer, zeroed |
| S6: Explicit error handling | Pass | map_posix_error, map_tls_error handle all cases |
| P1: Network >> CPU | Pass | Tagged union dispatch is negligible vs I/O |
| Y1: snake_case | Pass | All identifiers follow convention |

## Note on raw std.posix usage

This module uses raw `std.posix` calls for socket operations because it is the lowest-level socket abstraction in the serval stack. Higher-level modules should use `serval-socket.Socket` instead of raw posix calls.
