# serval-net

Network utilities for serval. Like Pingora's `connectors` module (DNS portion).

## Purpose

DNS resolution with TTL caching and TCP socket configuration utilities.

**Note:** Socket abstraction (plain TCP + TLS unified interface) has moved to `serval-socket` (Layer 2).

## Layer

Layer 1 (Protocol) - provides DNS and TCP helpers used by higher-level modules.

## Exports

| Symbol | Description |
|--------|-------------|
| `DnsResolver` | Thread-safe DNS resolver with TTL caching |
| `DnsResolver.init(&resolver, config)` | Initialize resolver with configuration |
| `resolver.resolve(hostname, port, io)` | Resolve hostname to single IP address |
| `resolver.resolve_all(hostname, port, io, out)` | Resolve hostname to all IP addresses (out-pointer) |
| `DnsResolver.normalize_fqdn(hostname, buf)` | Add trailing dot to FQDNs (bypass search domains) |
| `resolver.invalidate(hostname)` | Invalidate cached entry for hostname |
| `resolver.invalidate_all()` | Clear entire DNS cache |
| `resolver.get_stats()` | Get cache hit/miss statistics |
| `DnsConfig` | DNS resolver configuration (ttl_ns) |
| `DnsError` | DNS resolution error type |
| `ResolveResult` | Single address resolution result |
| `ResolveAllResult` | Multi-address resolution result |
| `tcp.set_tcp_no_delay(fd)` | Disable Nagle's algorithm |
| `tcp.set_tcp_keep_alive(fd, idle, interval, count)` | Configure TCP keepalive |
| `tcp.set_tcp_quick_ack(fd)` | Disable delayed ACKs (Linux) |
| `tcp.set_so_linger(fd, timeout)` | Configure SO_LINGER |
| `parse_ipv4(host)` | Parse IPv4 address to network-order u32 |

## DNS Resolution API

### DnsResolver

Thread-safe DNS resolver with fixed-size TTL cache. Zero allocation after init.

```zig
const net = @import("serval-net");

// Initialize resolver with default config (30s TTL)
var resolver: net.DnsResolver = undefined;
net.DnsResolver.init(&resolver, .{});

// Or with custom config
var resolver_custom: net.DnsResolver = undefined;
net.DnsResolver.init(&resolver_custom, .{
    .ttl_ns = 60_000_000_000, // 60 second cache TTL
});

// Single address resolution
const result = try resolver.resolve("example.com", 80, io);
// result.address contains the resolved IP
// result.from_cache indicates if result was cached
// result.resolution_ns is time spent resolving (0 if cached)

// All addresses resolution (out-pointer pattern per TigerStyle C3)
var all_result: net.ResolveAllResult = undefined;
try resolver.resolve_all("example.com", 80, io, &all_result);
for (all_result.slice()) |addr| {
    // Use each address (e.g., for connection failover)
    _ = addr;
}

// FQDN normalization for search domain bypass
// Adds trailing dot to FQDNs with 4+ dots (e.g., Kubernetes service names)
var buf: [256]u8 = undefined;
const normalized = try net.DnsResolver.normalize_fqdn(
    "service.namespace.svc.cluster.local",
    &buf,
);
// Returns "service.namespace.svc.cluster.local."
// The trailing dot tells DNS resolvers to skip search domain expansion

// Cache management
resolver.invalidate("example.com"); // Invalidate single entry
resolver.invalidate_all(); // Clear entire cache

// Statistics
const stats = resolver.get_stats();
std.debug.print("Cache hits: {d}, misses: {d}\n", .{ stats.hits, stats.misses });
```

### DnsError

| Error | Description |
|-------|-------------|
| `DnsResolutionFailed` | Hostname resolution failed |
| `DnsTimeout` | Resolution timed out |
| `InvalidHostname` | Hostname is empty or exceeds maximum length |
| `CacheFull` | Cache is full (should not occur with LRU) |
| `AddressOverflow` | DNS returned more addresses than buffer can hold |

## TCP Utilities API

### `set_tcp_no_delay(fd: i32) bool`

Disable Nagle's algorithm on a TCP socket to prevent 40ms delays when sending small packets.

**Parameters:**
- `fd`: Socket file descriptor. Pass -1 as a sentinel to skip (returns true).

**Returns:**
- `true`: Success (or fd was -1 sentinel)
- `false`: setsockopt failed (logged at debug level)

### `set_tcp_keep_alive(fd: i32, idle_secs: u32, interval_secs: u32, count: u32) bool`

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

### `set_tcp_quick_ack(fd: i32) bool`

Disable delayed ACKs for lower latency at cost of more ACK packets.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)

**Returns:**
- `true`: Success (or not Linux)
- `false`: setsockopt failed (logged at debug level)

**Platform Notes:**
- Linux only; returns true (no-op) on other platforms

### `set_so_linger(fd: i32, timeout_secs: u16) bool`

Configure SO_LINGER close behavior.

**Parameters:**
- `fd`: Socket file descriptor (must be >= 0)
- `timeout_secs`: Linger timeout in seconds
  - `0`: Immediate close with RST, unsent data lost (l_onoff=0)
  - `>0`: close() blocks up to timeout_secs waiting for data to send (l_onoff=1)

**Returns:**
- `true`: Success
- `false`: setsockopt failed (logged at debug level)

### `parse_ipv4(host: []const u8) ?u32`

Parse IPv4 address string to network-order u32.

**Parameters:**
- `host`: IPv4 address string (e.g., "192.168.1.1")

**Returns:**
- `u32`: Network-order address
- `null`: Invalid address format

## Usage

### TCP Configuration

```zig
const net = @import("serval-net");

// Disable Nagle for low latency
if (!net.set_tcp_no_delay(socket_fd)) {
    // Handle failure (rare, usually indicates invalid socket)
}

// Enable keepalive: probe after 60s idle, then every 10s, close after 3 failed probes
_ = net.set_tcp_keep_alive(socket_fd, 60, 10, 3);

// Disable delayed ACKs for even lower latency (Linux only)
_ = net.set_tcp_quick_ack(socket_fd);

// Configure close behavior: immediate RST (0) or graceful wait (seconds)
_ = net.set_so_linger(socket_fd, 0); // Immediate close with RST
_ = net.set_so_linger(socket_fd, 5); // Wait up to 5s for data to send
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Fixed-size DNS cache | TigerStyle: no runtime allocation, bounded memory |
| DNS TTL caching | Reduces DNS queries, configurable expiration |
| FQDN trailing dot | Bypasses search domain expansion in Kubernetes/Docker environments |
| ResolveAllResult out-pointer | TigerStyle C3: struct >64 bytes uses init(out: *T) to avoid stack copies |

## Dependencies

- `serval-core` - Configuration constants and timing utilities
- `std` - POSIX socket operations, DNS resolution

## Implementation Status

| Feature | Status |
|---------|--------|
| DNS resolver with TTL caching | Complete |
| DNS resolve (single address) | Complete |
| DNS resolve_all (all addresses) | Complete |
| DNS normalize_fqdn (trailing dot) | Complete |
| DNS cache invalidation | Complete |
| DNS cache statistics | Complete |
| TCP_NODELAY | Complete |
| TCP_KEEPALIVE | Complete |
| TCP_QUICKACK | Complete (Linux) |
| SO_LINGER | Complete |
| parse_ipv4 | Complete |
| Socket buffers (SO_RCVBUF/SO_SNDBUF) | Not implemented |

## TigerStyle Compliance

| Rule | Status | Notes |
|------|--------|-------|
| S1: Assertions | Pass | Preconditions on all functions (fd >= 0, hostname.len > 0, etc.) |
| S2: No recursion | Pass | No recursive calls |
| S3: Bounded loops | Pass | All loops have explicit max iterations |
| S4: No catch {} | Pass | All errors mapped explicitly |
| S5: No allocation after init | Pass | DNS cache uses fixed-size arrays |
| S6: Explicit error handling | Pass | DnsError, map_dns_error handle all cases |
| P1: Network >> CPU | Pass | DNS caching reduces network round-trips |
| C1: Units in names | Pass | timeout_secs, interval_secs, ttl_ns |
| Y1: snake_case | Pass | All identifiers follow convention |
