# serval-net

Network utilities for serval. Like Pingora's `connectors` module.

## Purpose

Unified socket abstraction (plain TCP + TLS) and TCP configuration helpers.

## Exports

| Symbol | Description |
|--------|-------------|
| `Socket` | Tagged union for plain TCP and TLS sockets |
| `SocketError` | Unified error type for socket operations |
| `Socket.Plain.initClient(fd)` | Create plain client socket from fd |
| `Socket.Plain.initServer(fd)` | Create plain server socket from fd |
| `Socket.TLS.TLSSocket.initClient(fd, ctx, host)` | Create TLS client socket with SNI |
| `Socket.TLS.TLSSocket.initServer(fd, ctx)` | Create TLS server socket |
| `socket.read(buf)` | Read data into buffer |
| `socket.write(data)` | Write data to socket |
| `socket.close()` | Close socket and free resources |
| `socket.getFd()` | Get raw fd for splice/poll |
| `socket.isTLS()` | Check if TLS socket |
| `socket.isKtls()` | Check if kTLS kernel offload active |
| `socket.canSplice()` | Check splice eligibility (plain or kTLS) |
| `tcp.setTcpNoDelay(fd)` | Disable Nagle's algorithm |
| `tcp.setTcpKeepAlive(fd, idle, interval, count)` | Configure TCP keepalive |
| `tcp.setTcpQuickAck(fd)` | Disable delayed ACKs (Linux) |
| `tcp.setSoLinger(fd, timeout)` | Configure SO_LINGER |
| `parseIPv4(host)` | Parse IPv4 address to network-order u32 |

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

### Socket.Plain.initClient(fd: i32) Socket

Create plain client socket from file descriptor.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)

**Returns:** `Socket` with `.plain` variant

### Socket.Plain.initServer(fd: i32) Socket

Create plain server socket from file descriptor. Same as `initClient` for plain TCP, but documents intent for symmetric API with TLS.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)

**Returns:** `Socket` with `.plain` variant

### Socket.TLS.TLSSocket.initClient(fd: i32, ctx: *SSL_CTX, host: []const u8) SocketError!Socket

Create TLS client socket with Server Name Indication (SNI). Performs TLS handshake.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)
- `ctx`: OpenSSL SSL_CTX pointer (caller owns lifecycle)
- `host`: Hostname for SNI (max 253 chars per RFC 6066)

**Returns:** `Socket` with `.tls` variant, or `SocketError`

### Socket.TLS.TLSSocket.initServer(fd: i32, ctx: *SSL_CTX) SocketError!Socket

Create TLS server socket for incoming client connection. Performs TLS handshake.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)
- `ctx`: OpenSSL SSL_CTX pointer (caller owns lifecycle)

**Returns:** `Socket` with `.tls` variant, or `SocketError`

### socket.read(buf: []u8) SocketError!usize

Read data into buffer. Works for both plain and TLS sockets.

**Parameters:**
- `buf`: Buffer to read into (must be non-empty)

**Returns:** Bytes read, 0 on EOF/clean close

### socket.write(data: []const u8) SocketError!usize

Write data to socket. Works for both plain and TLS sockets.

**Parameters:**
- `data`: Data to write (must be non-empty)

**Returns:** Bytes written

### socket.close() void

Close socket and free resources. For TLS, performs graceful shutdown before closing fd.

### socket.getFd() i32

Get raw file descriptor. Useful for splice (plaintext only) and poll operations.

### socket.isTLS() bool

Check if this is a TLS socket.

### socket.isKtls() bool

Check if this socket is using kTLS kernel offload. Returns true for TLS sockets where the kernel handles encryption/decryption, false for plain sockets or userspace TLS.

### socket.canSplice() bool

Check if this socket supports zero-copy splice operations. Returns true for:
- Plain TCP sockets (always splice-capable)
- TLS sockets with kTLS enabled (kernel handles encryption transparently)

Returns false for TLS sockets using userspace crypto, where data must pass through OpenSSL.

## TCP Utilities API

### `setTcpNoDelay(fd: i32) bool`

Disable Nagle's algorithm on a TCP socket to prevent 40ms delays when sending small packets.

**Parameters:**
- `fd`: Socket file descriptor. Pass -1 as a sentinel to skip (returns true).

**Returns:**
- `true`: Success (or fd was -1 sentinel)
- `false`: setsockopt failed (logged at debug level)

### `setTcpKeepAlive(fd: i32, idle_secs: u32, interval_secs: u32, count: u32) bool`

Configure TCP keepalive probes for detecting dead connections in connection pools.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)
- `idle_secs`: Seconds of inactivity before first probe (must be > 0)
- `interval_secs`: Seconds between probes (must be > 0)
- `count`: Number of failed probes before closing connection (must be > 0)

**Returns:**
- `true`: All options set successfully
- `false`: setsockopt failed (logged at debug level)

**Platform Notes:**
- On Linux, all four options (SO_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT) are set
- On other platforms, only SO_KEEPALIVE is set; system defaults apply for timing

### `setTcpQuickAck(fd: i32) bool`

Disable delayed ACKs for lower latency at cost of more ACK packets.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)

**Returns:**
- `true`: Success (or not Linux)
- `false`: setsockopt failed (logged at debug level)

**Platform Notes:**
- Linux only; returns true (no-op) on other platforms

### `setSoLinger(fd: i32, timeout_secs: u16) bool`

Configure SO_LINGER close behavior.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)
- `timeout_secs`: Linger timeout in seconds
  - `0`: Immediate close with RST, unsent data lost (l_onoff=0)
  - `>0`: close() blocks up to timeout_secs waiting for data to send (l_onoff=1)

**Returns:**
- `true`: Success
- `false`: setsockopt failed (logged at debug level)

### `parseIPv4(host: []const u8) ?u32`

Parse IPv4 address string to network-order u32.

**Parameters:**
- `host`: IPv4 address string (e.g., "192.168.1.1")

**Returns:**
- `u32`: Network-order address
- `null`: Invalid address format

## Usage

### Plain TCP Socket

```zig
const net = @import("serval-net");

// Create plain socket from accepted fd
var socket = net.Socket.Plain.initServer(client_fd);
defer socket.close();

// Configure TCP options
_ = net.tcp.setTcpNoDelay(socket.getFd());

// Read/write
var buf: [4096]u8 = undefined;
const n = try socket.read(&buf);
_ = try socket.write(buf[0..n]);

// Check for splice eligibility
if (!socket.isTLS()) {
    // Can use zero-copy splice
}
```

### TLS Socket (Client)

```zig
const net = @import("serval-net");
const tls = @import("serval-tls");

// SSL_CTX lifecycle is caller's responsibility
const ctx = try tls.ssl.createClientContext();
defer tls.ssl.destroyContext(ctx);

// Create TLS socket with SNI
var socket = try net.Socket.TLS.TLSSocket.initClient(upstream_fd, ctx, "api.example.com");
defer socket.close();

// Read/write (encrypted transparently)
const n = try socket.read(&buf);
_ = try socket.write(response);
```

### TLS Socket (Server)

```zig
const net = @import("serval-net");
const tls = @import("serval-tls");

// SSL_CTX with cert/key is caller's responsibility
const ctx = try tls.ssl.createServerContext("cert.pem", "key.pem");
defer tls.ssl.destroyContext(ctx);

// Accept and wrap with TLS
var socket = try net.Socket.TLS.TLSSocket.initServer(client_fd, ctx);
defer socket.close();

// Read/write (decryption transparent)
const n = try socket.read(&buf);
_ = try socket.write(response);
```

### TCP Configuration

```zig
const net = @import("serval-net");

// Disable Nagle for low latency
if (!net.setTcpNoDelay(socket_fd)) {
    // Handle failure (rare, usually indicates invalid socket)
}

// Enable keepalive: probe after 60s idle, then every 10s, close after 3 failed probes
_ = net.setTcpKeepAlive(socket_fd, 60, 10, 3);

// Disable delayed ACKs for even lower latency (Linux only)
_ = net.setTcpQuickAck(socket_fd);

// Configure close behavior: immediate RST (0) or graceful wait (seconds)
_ = net.setSoLinger(socket_fd, 0); // Immediate close with RST
_ = net.setSoLinger(socket_fd, 5); // Wait up to 5s for data to send
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Tagged union, not generics | TigerStyle: explicit types, predictable code size |
| Caller owns SSL_CTX | TigerStyle: explicit resource management, no hidden state |
| Zero-copy splice only for plain | TLS requires encryption/decryption - can't splice ciphertext |
| SNI max 253 chars | RFC 6066 limit, bounded stack buffer (no allocation) |
| SocketError unifies errors | Single error type for both plain and TLS operations |

## Dependencies

- `serval-tls` - TLS handshake and stream operations
- `std` - POSIX socket operations

## Implementation Status

| Feature | Status |
|---------|--------|
| Socket tagged union | Complete |
| Plain socket read/write/close | Complete |
| TLS socket initClient with SNI | Complete |
| TLS socket initServer | Complete |
| TLS socket read/write/close | Complete |
| getFd for splice/poll | Complete |
| isTLS check | Complete |
| isKtls check | Complete |
| canSplice eligibility | Complete |
| TCP_NODELAY | Complete |
| TCP_KEEPALIVE | Complete |
| TCP_QUICKACK | Complete (Linux) |
| SO_LINGER | Complete |
| parseIPv4 | Complete |
| Socket buffers (SO_RCVBUF/SO_SNDBUF) | Not implemented |

## TigerStyle Compliance

| Rule | Status | Notes |
|------|--------|-------|
| S1: Assertions | Pass | Preconditions on all functions (fd >= 0, buf.len > 0, etc.) |
| S2: No recursion | Pass | No recursive calls |
| S3: Bounded loops | Pass | parseIPv4 uses max_iterations bound |
| S4: No catch {} | Pass | All errors mapped explicitly to SocketError |
| S5: No allocation after init | Pass | SNI uses stack buffer, zeroed |
| S6: Explicit error handling | Pass | mapPosixError, mapTlsError handle all cases |
| P1: Network >> CPU | Pass | Tagged union dispatch is negligible vs I/O |
| C1: Units in names | Pass | timeout_secs, interval_secs |
| Y1: snake_case | Pass | All identifiers follow convention |
