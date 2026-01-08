# serval-pool

Fixed-size connection pooling with no runtime allocation.

## Purpose

Provides connection reuse between the proxy and upstream backends. Implements a compile-time interface that allows swapping pool implementations. Includes lifecycle management with idle timeout eviction and max connection age limits.

## Dependencies

- `serval-core` - Foundation types, time utilities
- `serval-net` - Socket type (unified plain/TLS abstraction)

## Exports

- `Connection` - Connection handle wrapping `Socket` for unified I/O (plain or TLS)
- `SimplePool` - Fixed-size connection pool with lifecycle management (default)
- `PoolStats` - Pool statistics snapshot for observability
- `PoolEvent` - Metrics event types for pool operations
- `MetricsCallback` - Optional callback function type for receiving pool events
- `NoPool` - No pooling, fresh connection per request
- `verifyPool` - Compile-time interface verification

## Usage

```zig
const pool_mod = @import("serval-pool");
const time = @import("serval-core").time;

var pool = pool_mod.SimplePool.init();

// Try to reuse an existing connection
if (pool.acquire(upstream_idx)) |conn| {
    // Use conn.socket for I/O (handles both plain and TLS)
    // Use conn.getFd() for raw fd (splice operations)
} else {
    // Create new connection via Socket.connect()
    // Set created_ns for max age tracking:
    var new_conn = Connection{ .socket = socket, .created_ns = time.monotonicNanos() };
}

// Return connection to pool
// release() automatically sets last_used_ns
pool.release(upstream_idx, conn, healthy);

// During server shutdown, drain all pooled connections
pool.drain();
```

## Connection

Wraps a `Socket` for unified I/O supporting both plain TCP and TLS connections:

```zig
pub const Connection = struct {
    socket: Socket,           // Unified socket (plain or TLS)
    created_ns: u64 = 0,      // Monotonic timestamp when established
    last_used_ns: u64 = 0,    // Monotonic timestamp when last released
    pool_sentinel: u32,       // Defense against double-release

    pub fn close(self: *Connection) void;
    pub fn getFd(self: *const Connection) i32;  // For splice zero-copy
    pub fn isUnusable(self: *const Connection) bool;  // Check if connection should not be reused
};
```

## Pool Interface

Any pool implementation must provide:

```zig
pub fn acquire(self, upstream_idx: u32) ?Connection
pub fn release(self, upstream_idx: u32, conn: Connection, healthy: bool) void
pub fn drain(self) void
```

## Lifecycle Management

### Idle Timeout (60 seconds)
Connections idle in the pool longer than 60 seconds are evicted and closed on the next `acquire()` call. This prevents returning connections to backends that may have closed them.

### Max Connection Age (5 minutes)
Connections older than 5 minutes are evicted regardless of activity. This handles backend restarts and ensures connection churn for load balancing.

### Pool Sentinel
A magic value (`IN_USE_SENTINEL` / `IN_POOL_SENTINEL`) tracks connection state:
- Prevents double-release bugs (assertion failure)
- Detects use-after-release (defense in depth)

### Graceful Shutdown
Call `drain()` during server shutdown to close all pooled connections cleanly.

## Implementations

### SimplePool (default)
- 16 connections per upstream
- 64 upstreams max
- Stack-based (LIFO for cache locality)
- Closes unhealthy connections
- Idle timeout eviction (60s)
- Max age eviction (5min)
- Thread-safe (mutex-protected)

### NoPool
- Always returns null on acquire
- Always closes on release
- `drain()` is a no-op
- For testing or when pooling is unwanted

## Observability

### Checked-Out Tracking
The pool tracks connections currently in use (checked out) to detect hung or leaked connections:

```zig
const stats = pool.getStats();

// Per-upstream counts
for (0..stats.available.len) |i| {
    if (stats.available[i] > 0 or stats.checked_out[i] > 0) {
        log.info("upstream {d}: available={d}, in_use={d}", .{
            i, stats.available[i], stats.checked_out[i],
        });
    }
}

// Totals across all upstreams
log.info("pool totals: available={d}, in_use={d}", .{
    stats.total_available, stats.total_checked_out,
});
```

### PoolStats
```zig
pub const PoolStats = struct {
    available: [MAX_UPSTREAMS]u8,     // Connections in pool per upstream
    checked_out: [MAX_UPSTREAMS]u8,   // Connections in use per upstream
    total_available: u32,              // Sum of available
    total_checked_out: u32,            // Sum of checked_out
};
```

### Use Cases
- **Leak detection**: `total_checked_out` grows unbounded if connections are never released
- **Capacity monitoring**: Compare `checked_out` against limits to detect saturation
- **Hangs debugging**: Identify which upstream has connections that are never returned

## Metrics Hooks

The pool supports an optional metrics callback for observability integration:

```zig
const pool_mod = @import("serval-pool");

fn handlePoolEvent(upstream_idx: u32, event: pool_mod.PoolEvent) void {
    switch (event) {
        .acquire_hit => metrics.increment("pool.hit", upstream_idx),
        .acquire_miss => metrics.increment("pool.miss", upstream_idx),
        .acquire_evicted => metrics.increment("pool.evicted", upstream_idx),
        .release_stored => metrics.increment("pool.stored", upstream_idx),
        .release_closed => metrics.increment("pool.closed", upstream_idx),
    }
}

var pool = pool_mod.SimplePool.initWithMetrics(handlePoolEvent);
```

### PoolEvent

```zig
pub const PoolEvent = enum {
    acquire_hit,      // Connection found in pool (cache hit)
    acquire_miss,     // No connection available (cache miss)
    acquire_evicted,  // Connection evicted (idle/age timeout)
    release_stored,   // Connection returned to pool successfully
    release_closed,   // Connection closed (unhealthy or pool full)
};
```

### Zero-Cost When Disabled

When no callback is set (using `SimplePool.init()`), the metrics check is a simple null pointer comparison with no overhead.

## Implementation Status

| Feature | Status |
|---------|--------|
| Basic pooling | Complete |
| Health tracking | Complete |
| Connection limits | Complete |
| Per-upstream isolation | Complete |
| Idle timeout eviction | Complete |
| Max connection age | Complete |
| Graceful shutdown (drain) | Complete |
| Pool sentinel | Complete |
| Checked-out tracking | Complete |
| Pool statistics (getStats) | Complete |
| Metrics hooks | Complete |
| Health checking | Relies on retry |

## TigerStyle Compliance

- Fixed-size arrays, no dynamic allocation
- Bounded limits (MAX_CONNS_PER_UPSTREAM, MAX_UPSTREAMS)
- Assertions on upstream_idx bounds
- Explicit u8/u32/u64 types
- Unit suffixes: `created_ns`, `last_used_ns`, `IDLE_TIMEOUT_NS`
- Sentinel values for use-after-release detection
