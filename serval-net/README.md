# serval-net

Network utilities for serval. Like Pingora's `connectors` module.

## Purpose

Socket configuration and connection establishment helpers.

## Exports

| Symbol | Description |
|--------|-------------|
| `setTcpNoDelay(fd: i32) bool` | Disable Nagle's algorithm for low-latency responses |
| `setTcpKeepAlive(fd: i32, idle_secs: u32, interval_secs: u32, count: u32) bool` | Configure TCP keepalive probes |
| `setTcpQuickAck(fd: i32) bool` | Disable delayed ACKs (Linux only) |
| `setSoLinger(fd: i32, timeout_secs: u16) bool` | Configure SO_LINGER close behavior |

## API

### `setTcpNoDelay(fd: i32) bool`

Disable Nagle's algorithm on a TCP socket to prevent 40ms delays when sending small packets.

**Parameters:**
- `fd`: Socket file descriptor. Pass -1 as a sentinel to skip (returns true).

**Returns:**
- `true`: Success (or fd was -1 sentinel)
- `false`: setsockopt failed (logged at debug level)

**TigerStyle Notes:**
- Returns bool instead of void to avoid swallowing errors with `catch {}`
- Callers can explicitly discard with `_ = setTcpNoDelay(fd)` if result not needed
- Asserts `fd >= -1` (fd < -1 indicates programming error)

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

## Future Additions

- `setSocketBuffer()` - SO_RCVBUF/SO_SNDBUF sizing
- `setReuseAddr()` - SO_REUSEADDR/SO_REUSEPORT
- Connection timeout helpers

## Usage

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

## Dependencies

None (uses only std).

## Implementation Status

| Feature | Status |
|---------|--------|
| TCP_NODELAY | Complete |
| TCP_KEEPALIVE | Complete |
| TCP_QUICKACK | Complete (Linux) |
| SO_LINGER | Complete |
| Socket buffers | Not implemented |
