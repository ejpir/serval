// lib/serval-pool/pool.zig
//! Connection Pool Interface
//!
//! Comptime interface for connection pooling.
//! Includes SimplePool (fixed-size) and NoPool (no pooling).
//! TigerStyle: No runtime allocation, fixed sizes.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const time = @import("serval-core").time;
const UpstreamIndex = config.UpstreamIndex;

// debug
const serval_core = @import("serval-core");
const log = serval_core.log.scoped(.pool);

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;

// =============================================================================
// Pool Interface Verification
// =============================================================================

/// Compile-time contract check for pool types used by this module.
/// Verifies that `Pool` declares `acquire`, `release`, and `drain` with the expected pool-facing API.
/// Fails compilation with `@compileError` if any required declaration is missing.
/// Performs no runtime work and does not validate declaration signatures beyond presence.
pub fn verifyPool(comptime Pool: type) void {
    if (!@hasDecl(Pool, "acquire")) {
        @compileError("Pool must implement: pub fn acquire(self, upstream_idx: UpstreamIndex) ?Connection");
    }
    if (!@hasDecl(Pool, "release")) {
        @compileError("Pool must implement: pub fn release(self, upstream_idx: UpstreamIndex, conn: Connection, healthy: bool) void");
    }
    if (!@hasDecl(Pool, "drain")) {
        @compileError("Pool must implement: pub fn drain(self) void");
    }
}

// =============================================================================
// Pool Metrics
// =============================================================================

/// Pool metrics for observability.
/// TigerStyle: Explicit event types, no magic strings.
pub const PoolEvent = enum {
    /// Connection found in pool (cache hit).
    acquire_hit,
    /// No connection available in pool (cache miss).
    acquire_miss,
    /// Connection evicted during acquire (idle/age timeout).
    acquire_evicted,
    /// Connection returned to pool successfully.
    release_stored,
    /// Connection closed on release (unhealthy or pool full).
    release_closed,
};

/// Optional metrics callback type.
/// Set to non-null to receive pool events.
/// TigerStyle: Function pointer for zero-cost abstraction when null.
pub const MetricsCallback = *const fn (upstream_idx: UpstreamIndex, event: PoolEvent) void;

// =============================================================================
// Connection Handle (opaque, pool-specific)
// =============================================================================

/// Poll flags indicating a connection is stale or unusable.
/// TigerStyle: Module-level constant for clarity and reuse.
const STALE_CONNECTION_FLAGS = std.posix.POLL.IN | std.posix.POLL.HUP |
    std.posix.POLL.ERR | std.posix.POLL.NVAL;

/// Pool-managed connection that wraps a unified plain-TCP or TLS `Socket`.
/// Stores monotonic-nanosecond lifecycle metadata (`created_ns`, `last_used_ns`) used by pool reuse/eviction logic.
/// `pool_sentinel` and `from_pool` are internal integrity/accounting flags for correct acquire/release behavior.
/// Treat an acquired `Connection` as exclusively owned while in use; call `close()` to retire the underlying socket.
/// `get_fd()` asserts the descriptor is valid, and `isUnusable()` conservatively returns `true` on invalid fd or poll-detected error/closure.
pub const Connection = struct {
    /// Unified socket (plain TCP or TLS).
    /// TigerStyle: Single type handles both encrypted and unencrypted connections.
    socket: Socket,
    /// Timestamp when connection was established (monotonic nanoseconds).
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    created_ns: u64 = 0,
    /// Timestamp when connection was last released to pool (monotonic nanoseconds).
    /// Used for idle timeout eviction.
    last_used_ns: u64 = 0,
    /// Sentinel to detect double-release. Set to magic value when in pool.
    /// TigerStyle: Defense in depth against use-after-release bugs.
    pool_sentinel: u32 = IN_USE_SENTINEL,
    /// True when this checkout came from pool.acquire() rather than fresh connect.
    /// Used to keep checked_out_counts semantics precise.
    from_pool: bool = false,

    const IN_POOL_SENTINEL: u32 = 0xDEAD_BEEF;
    const IN_USE_SENTINEL: u32 = 0xCAFE_BABE;

    /// Close the connection socket.
    /// TigerStyle: Socket.close() handles both plain and TLS cleanup.
    pub fn close(self: *Connection) void {
        self.socket.close();
    }

    /// Get raw file descriptor for splice operations and polling.
    /// TigerStyle: Zero-copy splice needs raw fd.
    pub fn get_fd(self: *const Connection) i32 {
        const fd = self.socket.get_fd();
        assert(fd >= 0);
        return fd;
    }

    /// Check if connection is unusable and should not be reused.
    /// Detects: stale data, closed by peer, socket errors, invalid fd.
    /// Uses poll() with zero timeout for non-blocking check.
    /// Returns true if connection should NOT be reused.
    /// TigerStyle: Positive naming - true means "bad, don't use".
    pub fn isUnusable(self: *const Connection) bool {
        const fd = self.socket.get_fd();
        if (fd < 0) return true;

        var poll_fds = [_]std.posix.pollfd{
            .{
                .fd = fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            },
        };

        // Poll with 0 timeout = non-blocking check
        const result = std.posix.poll(&poll_fds, 0) catch |err| {
            // TigerStyle: Log errors instead of silently swallowing
            log.debug("isUnusable poll failed on fd {d}: {s}", .{ fd, @errorName(err) });
            return true; // Assume unusable on error
        };

        if (result > 0) {
            if ((poll_fds[0].revents & STALE_CONNECTION_FLAGS) != 0) return true;
        }

        return false;
    }

    /// Deprecated: Use isUnusable() instead.
    /// Kept for backward compatibility.
    pub fn hasStaleData(self: *const Connection) bool {
        return self.isUnusable();
    }
};

// =============================================================================
// NoPool (fresh connection per request)
// =============================================================================

/// A stateless pool implementation that never retains reusable connections.
/// `acquire` always returns `null`, so callers must establish a fresh connection when needed.
/// `release` unconditionally closes the provided `Connection`; ownership is consumed and it must not be used afterward.
/// `drain` is a no-op because `NoPool` stores no connections and reports no errors.
pub const NoPool = struct {
    /// Attempts to acquire a `Connection` for the given `UpstreamIndex`.
    /// Currently this implementation is a no-op and always returns `null`.
    /// No allocation or ownership transfer occurs, and there is no error path beyond the nullable result.
    pub fn acquire(_: *@This(), _: UpstreamIndex) ?Connection {
        return null;
    }

    /// Releases a connection by closing it immediately and unconditionally.
    /// This implementation does not pool or reuse connections; `UpstreamIndex` and the boolean flag are ignored.
    /// Preconditions: `conn` should reference a valid connection object that can be closed.
    /// Error behavior: none (`void`); closure is performed via `Connection.close()`.
    pub fn release(_: *@This(), _: UpstreamIndex, conn: Connection, _: bool) void {
        var c = conn;
        c.close();
    }

    /// No-op for NoPool since it doesn't store connections.
    pub fn drain(_: *@This()) void {}
};

// =============================================================================
// SimplePool (fixed-size, no allocation, thread-safe)
// =============================================================================

/// Fixed-capacity connection pool with independent slots per upstream, sized by centralized config limits.
/// Internally synchronized with a mutex so pooled state (connections/counters) is safe under concurrent access.
/// Supports optional `PoolEvent` emission through a callback for observability with zero overhead when disabled.
/// Stale pooled entries are evicted using idle-time and max-age policies during acquisition.
pub const SimplePool = struct {
    // Pool sizing from centralized config
    const MAX_CONNS_PER_UPSTREAM = config.MAX_CONNS_PER_UPSTREAM;
    const MAX_UPSTREAMS = config.MAX_UPSTREAMS;

    /// Default idle timeout: 60 seconds.
    /// Connections idle longer than this are evicted on acquire.
    /// TigerStyle: Explicit constant, unit in name.
    const IDLE_TIMEOUT_NS: u64 = 60 * time.ns_per_s;

    /// Default max connection age: 5 minutes.
    /// Connections older than this are evicted regardless of activity.
    /// TigerStyle: Prevents stale connections from backend restarts.
    const MAX_CONNECTION_AGE_NS: u64 = 5 * 60 * time.ns_per_s;

    /// Mutex protects connections and counts arrays.
    /// TigerStyle: Simple mutex over complex lock-free for correctness.
    mutex: std.Io.Mutex = .init,
    connections: [MAX_UPSTREAMS][MAX_CONNS_PER_UPSTREAM]?Connection =
        [_][MAX_CONNS_PER_UPSTREAM]?Connection{[_]?Connection{null} ** MAX_CONNS_PER_UPSTREAM} ** MAX_UPSTREAMS,
    counts: [MAX_UPSTREAMS]u8 = [_]u8{0} ** MAX_UPSTREAMS,

    /// Count of pooled connections currently checked out per upstream.
    /// Excludes fresh miss-path connections that were never acquired from pool.
    /// TigerStyle: Explicit tracking for observability and leak detection.
    checked_out_counts: [MAX_UPSTREAMS]u8 = [_]u8{0} ** MAX_UPSTREAMS,

    /// Optional metrics callback for observability.
    /// TigerStyle: Null by default, opt-in for overhead.
    metrics_callback: ?MetricsCallback = null,

    /// Creates a new `SimplePool` in its default, empty state.
    /// This function has no preconditions and performs no heap allocation.
    /// Ownership of the returned value is transferred to the caller, who manages its lifetime.
    /// This initializer is infallible and does not return an error.
    pub fn init() SimplePool {
        return .{};
    }

    /// Initialize with metrics callback.
    pub fn initWithMetrics(callback: MetricsCallback) SimplePool {
        return .{ .metrics_callback = callback };
    }

    /// Helper to emit metrics.
    /// TigerStyle: Inline check for null, zero cost when disabled.
    fn emitMetric(self: *SimplePool, upstream_idx: UpstreamIndex, event: PoolEvent) void {
        if (self.metrics_callback) |cb| {
            cb(upstream_idx, event);
        }
    }

    /// Acquire a pooled connection for the given upstream.
    /// Returns null if no connections available.
    /// Skips and collects stale connections (idle timeout or max age exceeded).
    /// TigerStyle: Mutex held only for array access, I/O (close) outside lock.
    pub fn acquire(self: *SimplePool, upstream_idx: UpstreamIndex) ?Connection {
        assert(upstream_idx < MAX_UPSTREAMS);

        const now_ns = time.monotonicNanos();
        const idx = @as(usize, upstream_idx);

        // Collect stale connections to close outside the lock.
        // TigerStyle: Bounded array, no allocation.
        var stale_conns: [MAX_CONNS_PER_UPSTREAM]?Connection =
            [_]?Connection{null} ** MAX_CONNS_PER_UPSTREAM;
        var stale_count: u8 = 0;
        var result: ?Connection = null;

        {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);

            // Try connections from top of stack (LIFO), skipping stale ones
            while (self.counts[idx] > 0) {
                self.counts[idx] -= 1;
                const conn = self.connections[idx][self.counts[idx]];
                self.connections[idx][self.counts[idx]] = null;

                if (conn) |c| {
                    // TigerStyle: Verify sentinel - must be from pool
                    assert(c.pool_sentinel == Connection.IN_POOL_SENTINEL);

                    // Check idle timeout (time since last release)
                    const idle_ns = if (now_ns >= c.last_used_ns) now_ns - c.last_used_ns else 0;
                    if (idle_ns > IDLE_TIMEOUT_NS) {
                        // Connection too idle, mark for closure
                        assert(stale_count < MAX_CONNS_PER_UPSTREAM);
                        stale_conns[stale_count] = c;
                        stale_count += 1;
                        continue;
                    }

                    // Check max age (time since creation)
                    const age_ns = if (now_ns >= c.created_ns) now_ns - c.created_ns else 0;
                    if (age_ns > MAX_CONNECTION_AGE_NS) {
                        // Connection too old, mark for closure
                        assert(stale_count < MAX_CONNS_PER_UPSTREAM);
                        stale_conns[stale_count] = c;
                        stale_count += 1;
                        continue;
                    }

                    // Connection is valid - mark as in-use before returning
                    var valid_conn = c;
                    valid_conn.pool_sentinel = Connection.IN_USE_SENTINEL;
                    valid_conn.from_pool = true;
                    assert(self.checked_out_counts[idx] < std.math.maxInt(u8));
                    self.checked_out_counts[idx] += 1;
                    result = valid_conn;
                    break;
                }
            }
        }

        // Close stale connections outside the lock.
        // TigerStyle: I/O outside mutex to avoid blocking pool access.
        for (stale_conns[0..stale_count]) |maybe_conn| {
            if (maybe_conn) |*conn| {
                var c = conn.*;
                c.close();
                self.emitMetric(upstream_idx, .acquire_evicted);
            }
        }

        // Perform non-blocking liveness check outside lock and before hit/miss metric emit.
        if (result) |conn| {
            if (conn.isUnusable()) {
                var unusable_conn = conn;
                unusable_conn.close();

                self.mutex.lockUncancelable(std.Options.debug_io);
                assert(self.checked_out_counts[idx] > 0);
                self.checked_out_counts[idx] -= 1;
                self.mutex.unlock(std.Options.debug_io);

                self.emitMetric(upstream_idx, .acquire_evicted);
                result = null;
            }
        }

        // Emit appropriate metric based on result
        if (result != null) {
            self.emitMetric(upstream_idx, .acquire_hit);
        } else {
            self.emitMetric(upstream_idx, .acquire_miss);
        }

        return result;
    }

    /// Release a connection back to the pool.
    /// Closes connection if unhealthy or pool is full.
    /// Updates last_used_ns timestamp for idle timeout tracking.
    /// TigerStyle: Single lock acquisition for atomic state update, I/O outside mutex.
    /// Defense in depth with sentinel to detect double-release.
    /// self.pool.release(upstream.idx, mutable_conn, true);
    pub fn release(self: *SimplePool, upstream_idx: UpstreamIndex, conn: Connection, healthy: bool) void {
        assert(upstream_idx < MAX_UPSTREAMS);
        // TigerStyle: Verify sentinel - must not be double-released
        assert(conn.pool_sentinel == Connection.IN_USE_SENTINEL);

        const idx = @as(usize, upstream_idx);
        var should_close = !healthy;
        var c = conn;

        // Single lock acquisition for atomic state transition.
        // TigerStyle: Decrement checked_out and store connection atomically.
        {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);

            // Only decrement for connections that were checked out from this pool.
            if (conn.from_pool) {
                assert(self.checked_out_counts[idx] > 0);
                self.checked_out_counts[idx] -= 1;
            }

            if (healthy) {
                // Update timestamp and sentinel for pool storage
                c.last_used_ns = time.monotonicNanos();
                c.pool_sentinel = Connection.IN_POOL_SENTINEL;
                c.from_pool = false;

                if (self.counts[idx] < MAX_CONNS_PER_UPSTREAM) {
                    // Store in pool
                    self.connections[idx][self.counts[idx]] = c;
                    self.counts[idx] += 1;
                } else {
                    // Pool full - mark for closure
                    should_close = true;
                }
            }
        }

        // I/O outside mutex - close if unhealthy or pool was full
        if (should_close) {
            c.close();
            self.emitMetric(upstream_idx, .release_closed);
        } else if (healthy) {
            self.emitMetric(upstream_idx, .release_stored);
        } else {
            self.emitMetric(upstream_idx, .release_closed);
        }
    }

    /// Close all pooled connections. Call during server shutdown.
    /// TigerStyle: Socket.close() handles both plain and TLS cleanup.
    pub fn drain(self: *SimplePool) void {
        // Collect connections to close under lock.
        // TigerStyle: Bounded array, no allocation.
        var to_close: [MAX_UPSTREAMS * MAX_CONNS_PER_UPSTREAM]?Connection =
            [_]?Connection{null} ** (MAX_UPSTREAMS * MAX_CONNS_PER_UPSTREAM);
        var close_count: u32 = 0;

        {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);

            for (0..MAX_UPSTREAMS) |upstream_idx| {
                while (self.counts[upstream_idx] > 0) {
                    self.counts[upstream_idx] -= 1;
                    assert(close_count < MAX_UPSTREAMS * MAX_CONNS_PER_UPSTREAM);
                    to_close[close_count] = self.connections[upstream_idx][self.counts[upstream_idx]];
                    self.connections[upstream_idx][self.counts[upstream_idx]] = null;
                    close_count += 1;
                }
            }
        }

        // Close outside lock.
        // TigerStyle: I/O outside mutex to avoid blocking pool access.
        for (to_close[0..close_count]) |maybe_conn| {
            if (maybe_conn) |*conn| {
                var c = conn.*;
                c.close();
            }
        }
    }

    /// Pool statistics for observability and leak detection.
    /// TigerStyle: Snapshot of pool state under single lock acquisition.
    pub const PoolStats = struct {
        /// Connections available in pool per upstream.
        available: [MAX_UPSTREAMS]u8,
        /// Pooled connections currently checked out per upstream.
        checked_out: [MAX_UPSTREAMS]u8,
        /// Total available across all upstreams.
        total_available: u32,
        /// Total checked out across all upstreams.
        total_checked_out: u32,
    };

    /// Get current pool statistics.
    /// TigerStyle: Snapshot under single lock acquisition for consistency.
    pub fn getStats(self: *SimplePool) PoolStats {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        var stats = PoolStats{
            .available = self.counts,
            .checked_out = self.checked_out_counts,
            .total_available = 0,
            .total_checked_out = 0,
        };

        for (0..MAX_UPSTREAMS) |i| {
            stats.total_available += self.counts[i];
            stats.total_checked_out += self.checked_out_counts[i];
        }

        return stats;
    }
};

// =============================================================================
// Tests
// =============================================================================

const TestSocketPair = struct {
    conn: Connection,
    peer_fd: std.posix.fd_t,
};

fn testConnection(created_ns: u64, last_used_ns: u64, pool_sentinel: u32, from_pool: bool) !TestSocketPair {
    const fds = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    return .{
        .conn = .{
            .socket = Socket.Plain.init_client(fds[0]),
            .created_ns = created_ns,
            .last_used_ns = last_used_ns,
            .pool_sentinel = pool_sentinel,
            .from_pool = from_pool,
        },
        .peer_fd = fds[1],
    };
}

fn closePeerFd(fd: std.posix.fd_t) void {
    if (fd >= 0) std.posix.close(fd);
}

test "NoPool always returns null" {
    var pool = NoPool{};
    try std.testing.expectEqual(@as(?Connection, null), pool.acquire(0));
}

test "SimplePool acquire from empty returns null" {
    var pool = SimplePool.init();
    try std.testing.expectEqual(@as(?Connection, null), pool.acquire(0));
}

test "SimplePool stores and retrieves connections" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Initially empty
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    var pair = try testConnection(now_ns, now_ns, Connection.IN_POOL_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    pool.connections[0][0] = pair.conn;
    pool.counts[0] = 1;
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Acquire returns it
    const conn = pool.acquire(0);
    try std.testing.expect(conn != null);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);
    var acquired = conn.?;
    defer acquired.close();
    // Verify sentinel changed to IN_USE after acquire
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, acquired.pool_sentinel);
    try std.testing.expect(acquired.from_pool);
}

test "SimplePool respects max connections per upstream" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Fill up the pool for upstream 0 with properly initialized connections
    for (0..SimplePool.MAX_CONNS_PER_UPSTREAM) |i| {
        pool.connections[0][i] = .{
            .socket = undefined,
            .created_ns = now_ns,
            .last_used_ns = now_ns,
            .pool_sentinel = Connection.IN_POOL_SENTINEL,
        };
    }
    pool.counts[0] = SimplePool.MAX_CONNS_PER_UPSTREAM;

    try std.testing.expectEqual(SimplePool.MAX_CONNS_PER_UPSTREAM, pool.counts[0]);
}

test "Connection has timestamp fields" {
    const conn: Connection = .{
        .socket = undefined,
        .created_ns = 12345,
        .last_used_ns = 67890,
    };
    try std.testing.expectEqual(@as(u64, 12345), conn.created_ns);
    try std.testing.expectEqual(@as(u64, 67890), conn.last_used_ns);
}

test "Connection sentinel values" {
    // Default sentinel is IN_USE
    const conn: Connection = .{ .socket = undefined };
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn.pool_sentinel);

    // IN_POOL sentinel marks connection as pooled
    const pooled_conn: Connection = .{
        .socket = undefined,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    try std.testing.expectEqual(Connection.IN_POOL_SENTINEL, pooled_conn.pool_sentinel);
}

test "verifyPool accepts valid pools" {
    comptime verifyPool(NoPool);
    comptime verifyPool(SimplePool);
}

test "SimplePool getStats returns correct counts" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Initially all zeros
    const initial_stats = pool.getStats();
    try std.testing.expectEqual(@as(u32, 0), initial_stats.total_available);
    try std.testing.expectEqual(@as(u32, 0), initial_stats.total_checked_out);

    // Add some connections to the pool (simulating release)
    pool.connections[0][0] = .{
        .socket = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.connections[0][1] = .{
        .socket = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.counts[0] = 2;

    // Add connections for a second upstream
    pool.connections[1][0] = .{
        .socket = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.counts[1] = 1;

    // Simulate some checked out connections
    pool.checked_out_counts[0] = 3;
    pool.checked_out_counts[2] = 1;

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u8, 2), stats.available[0]);
    try std.testing.expectEqual(@as(u8, 1), stats.available[1]);
    try std.testing.expectEqual(@as(u8, 3), stats.checked_out[0]);
    try std.testing.expectEqual(@as(u8, 1), stats.checked_out[2]);
    try std.testing.expectEqual(@as(u32, 3), stats.total_available);
    try std.testing.expectEqual(@as(u32, 4), stats.total_checked_out);
}

test "SimplePool checked_out_counts tracks acquire and release" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    defer pool.drain();

    // Initially no checked out connections
    try std.testing.expectEqual(@as(u8, 0), pool.checked_out_counts[0]);

    var pair = try testConnection(now_ns, now_ns, Connection.IN_POOL_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    pool.connections[0][0] = pair.conn;
    pool.counts[0] = 1;

    // Acquire increments checked_out_counts
    const conn_opt = pool.acquire(0);
    try std.testing.expect(conn_opt != null);
    const conn = conn_opt.?;
    try std.testing.expectEqual(@as(u8, 1), pool.checked_out_counts[0]);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);
    try std.testing.expect(conn.from_pool);

    pool.release(0, conn, true);
    try std.testing.expectEqual(@as(u8, 0), pool.checked_out_counts[0]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);
}

// =============================================================================
// Contract and Invariant Tests
// =============================================================================

test "Contract: acquired connections must have created_ns > 0" {
    // This test would have caught the forwarder bug where created_ns wasn't initialized!
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Store connection with created_ns = 0 (the bug case)
    pool.connections[0][0] = .{
        .socket = undefined,
        .created_ns = 0, // BUG: forwarder didn't set this
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.counts[0] = 1;

    // Pool should evict it as too old (age = now_ns - 0 = massive)
    const result = pool.acquire(0);
    try std.testing.expectEqual(@as(?Connection, null), result);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // Evicted
}

test "Invariant: acquired connections have valid timestamps" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    var pair = try testConnection(now_ns - 1000, now_ns, Connection.IN_POOL_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    pool.connections[0][0] = pair.conn;
    pool.counts[0] = 1;

    const result = pool.acquire(0);
    try std.testing.expect(result != null);
    var acquired = result.?;
    defer acquired.close();

    // INVARIANT: All acquired connections MUST have valid timestamps
    try std.testing.expect(acquired.created_ns > 0);
    try std.testing.expect(acquired.last_used_ns > 0);
    try std.testing.expect(acquired.last_used_ns >= acquired.created_ns);
    try std.testing.expect(acquired.from_pool);
}

test "Pool evicts connections exceeding max age (5 minutes)" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    const max_age_ns = 5 * 60 * time.ns_per_s;
    const old_conn: Connection = .{
        .socket = undefined,
        .created_ns = now_ns - (max_age_ns + (60 * time.ns_per_s)), // 6 min old
        .last_used_ns = now_ns - 1000, // Used recently, but too old overall
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };

    pool.connections[0][0] = old_conn;
    pool.counts[0] = 1;

    // Should evict due to max age
    const result = pool.acquire(0);
    try std.testing.expectEqual(@as(?Connection, null), result);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);
}

test "Pool evicts connections exceeding idle timeout (60 seconds)" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    const idle_timeout_ns = 60 * time.ns_per_s;
    const idle_conn: Connection = .{
        .socket = undefined,
        .created_ns = now_ns - (10 * time.ns_per_s), // 10s old
        .last_used_ns = now_ns - (idle_timeout_ns + time.ns_per_s), // 61s idle
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };

    pool.connections[0][0] = idle_conn;
    pool.counts[0] = 1;

    // Should evict due to idle timeout
    const result = pool.acquire(0);
    try std.testing.expectEqual(@as(?Connection, null), result);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);
}

test "Pool retains fresh, recently-used connections" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    var pair = try testConnection(
        now_ns - (30 * time.ns_per_s),
        now_ns - (5 * time.ns_per_s),
        Connection.IN_POOL_SENTINEL,
        false,
    );
    defer closePeerFd(pair.peer_fd);
    pool.connections[0][0] = pair.conn;
    pool.counts[0] = 1;

    // Should successfully acquire (not evicted)
    const result = pool.acquire(0);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // Removed from pool
    var acquired = result.?;
    defer acquired.close();
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, acquired.pool_sentinel);
    try std.testing.expect(acquired.from_pool);
}

test "Full lifecycle: acquire → release → acquire reuses connection" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    defer pool.drain();

    // Simulate first request: create connection and release to pool
    var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    const new_conn = pair.conn;

    pool.release(0, new_conn, true);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Simulate second request: acquire from pool
    const reused_conn = pool.acquire(0);
    try std.testing.expect(reused_conn != null);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    // Verify timestamps are preserved
    const acquired = reused_conn.?;
    try std.testing.expectEqual(now_ns, acquired.created_ns);
    try std.testing.expect(acquired.last_used_ns >= acquired.created_ns);
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, acquired.pool_sentinel);
    try std.testing.expect(acquired.from_pool);
    pool.release(0, acquired, true);
    try std.testing.expectEqual(@as(u8, 0), pool.checked_out_counts[0]);
}

// =============================================================================
// Critical Safety Tests
// =============================================================================

test "CRITICAL: Release unhealthy connection does NOT pool it" {
    // Unhealthy connections must be closed, not returned to pool
    // Bug here = stale connections reused = request failures
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    const unhealthy_conn = pair.conn;

    // Release as unhealthy (healthy=false)
    pool.release(0, unhealthy_conn, false);

    // Should NOT be in pool
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    // Next acquire should return null (pool is empty)
    const result = pool.acquire(0);
    try std.testing.expectEqual(@as(?Connection, null), result);
}

test "CRITICAL: Pool full drops healthy connection (bounded buffer)" {
    // Pool has fixed size - releasing to full pool must not overflow
    // Bug here = buffer overflow, corruption
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    var peer_fds: [SimplePool.MAX_CONNS_PER_UPSTREAM + 1]std.posix.fd_t = [_]std.posix.fd_t{-1} ** (SimplePool.MAX_CONNS_PER_UPSTREAM + 1);
    defer {
        for (peer_fds) |fd| closePeerFd(fd);
    }

    // Fill pool to MAX_CONNS_PER_UPSTREAM
    for (0..SimplePool.MAX_CONNS_PER_UPSTREAM) |i| {
        var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
        peer_fds[i] = pair.peer_fd;
        pool.release(0, pair.conn, true);
        try std.testing.expectEqual(@as(u8, @intCast(i + 1)), pool.counts[0]);
    }

    // Pool is now full
    try std.testing.expectEqual(SimplePool.MAX_CONNS_PER_UPSTREAM, pool.counts[0]);

    // Release one more healthy connection - should be dropped (closed)
    var overflow_pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
    peer_fds[SimplePool.MAX_CONNS_PER_UPSTREAM] = overflow_pair.peer_fd;
    pool.release(0, overflow_pair.conn, true);

    // Pool should still be at max (overflow connection was closed)
    try std.testing.expectEqual(SimplePool.MAX_CONNS_PER_UPSTREAM, pool.counts[0]);
}

test "CRITICAL: Multiple upstreams are isolated" {
    // Connections to upstream[0] must not leak to upstream[1]
    // Bug here = routing errors, security violation
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Release connection to upstream 0
    var pair_0 = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair_0.peer_fd);
    pool.release(0, pair_0.conn, true);

    // Release connection to upstream 1
    var pair_1 = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair_1.peer_fd);
    pool.release(1, pair_1.conn, true);

    // Verify counts
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[1]);

    // Acquire from upstream 0 - should get upstream 0's connection
    const result_0 = pool.acquire(0);
    try std.testing.expect(result_0 != null);
    var acquired_0 = result_0.?;
    defer acquired_0.close();
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // upstream 0 now empty
    try std.testing.expectEqual(@as(u8, 1), pool.counts[1]); // upstream 1 unchanged

    // Acquire from upstream 1 - should get upstream 1's connection
    const result_1 = pool.acquire(1);
    try std.testing.expect(result_1 != null);
    var acquired_1 = result_1.?;
    defer acquired_1.close();
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // upstream 0 still empty
    try std.testing.expectEqual(@as(u8, 0), pool.counts[1]); // upstream 1 now empty
}

test "CRITICAL: LIFO order preserves cache locality" {
    // Pool should return most recently used connection (LIFO stack)
    // Bug here = poor cache performance, more TCP handshakes
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Release 3 connections with different timestamps
    var pair_old = try testConnection(now_ns - 1000, now_ns - 1000, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair_old.peer_fd);
    pool.release(0, pair_old.conn, true);

    var pair_mid = try testConnection(now_ns - 500, now_ns - 500, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair_mid.peer_fd);
    pool.release(0, pair_mid.conn, true);

    var pair_recent = try testConnection(now_ns - 100, now_ns - 100, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair_recent.peer_fd);
    pool.release(0, pair_recent.conn, true);

    try std.testing.expectEqual(@as(u8, 3), pool.counts[0]);

    // Acquire should return MOST RECENT (LIFO)
    const result = pool.acquire(0);
    try std.testing.expect(result != null);
    var acquired = result.?;
    defer acquired.close();
    try std.testing.expectEqual(now_ns - 100, acquired.last_used_ns);
}

test "CRITICAL: Drain closes all pooled connections" {
    // Drain must close all connections across all upstreams
    // Bug here = resource leak on shutdown
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    var peer_fds = [_]std.posix.fd_t{-1} ** 3;
    defer {
        for (peer_fds) |fd| closePeerFd(fd);
    }

    // Add connections to multiple upstreams
    for (0..3) |upstream_idx| {
        var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
        peer_fds[upstream_idx] = pair.peer_fd;
        pool.release(@intCast(upstream_idx), pair.conn, true);
    }

    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[1]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[2]);

    // Drain should empty all pools
    pool.drain();

    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[1]);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[2]);

    // Verify stats show empty
    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u32, 0), stats.total_available);
}

test "CRITICAL: Metrics callback receives correct events" {
    // Metrics are used for observability - wrong events = bad monitoring
    const TestMetrics = struct {
        var acquire_hits: u32 = 0;
        var acquire_misses: u32 = 0;
        var release_stored: u32 = 0;
        var release_closed: u32 = 0;

        fn reset() void {
            acquire_hits = 0;
            acquire_misses = 0;
            release_stored = 0;
            release_closed = 0;
        }

        fn callback(_: u32, event: PoolEvent) void {
            switch (event) {
                .acquire_hit => acquire_hits += 1,
                .acquire_miss => acquire_misses += 1,
                .release_stored => release_stored += 1,
                .release_closed => release_closed += 1,
                .acquire_evicted => {}, // Not tracked in this test
            }
        }
    };

    TestMetrics.reset();
    var pool = SimplePool.initWithMetrics(TestMetrics.callback);
    const now_ns = time.monotonicNanos();

    // Acquire from empty pool - should emit acquire_miss
    _ = pool.acquire(0);
    try std.testing.expectEqual(@as(u32, 0), TestMetrics.acquire_hits);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.acquire_misses);

    // Release healthy connection - should emit release_stored
    var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    pool.release(0, pair.conn, true);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.release_stored);
    try std.testing.expectEqual(@as(u32, 0), TestMetrics.release_closed);

    // Acquire from pool - should emit acquire_hit
    const acquired_opt = pool.acquire(0);
    try std.testing.expect(acquired_opt != null);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.acquire_hits);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.acquire_misses); // Unchanged

    // Release unhealthy connection - should emit release_closed
    pool.release(0, acquired_opt.?, false);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.release_stored); // Unchanged
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.release_closed);
}

test "CRITICAL: Boundary - connection at exactly max age threshold" {
    // Off-by-one errors at boundaries are common
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    const max_age_ns = 5 * 60 * time.ns_per_s;

    // Connection at EXACTLY max age (not over)
    var pair = try testConnection(now_ns - max_age_ns, now_ns, Connection.IN_POOL_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    const boundary_conn = pair.conn;

    pool.connections[0][0] = boundary_conn;
    pool.counts[0] = 1;

    // Should be evicted (age > MAX, not >=)
    const result = pool.acquire(0);
    // TigerStyle: Document expected behavior explicitly
    // Current implementation: if (age_ns > MAX_CONNECTION_AGE_NS)
    // So exactly-at-threshold should NOT be evicted
    try std.testing.expect(result != null);
    var acquired = result.?;
    defer acquired.close();
}

test "CRITICAL: Boundary - connection at exactly idle timeout threshold" {
    // Off-by-one errors at boundaries are common
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    const idle_timeout_ns = 60 * time.ns_per_s;

    // Connection at EXACTLY idle timeout (not over)
    var pair = try testConnection(now_ns - 1000, now_ns - idle_timeout_ns, Connection.IN_POOL_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    const boundary_conn = pair.conn;

    pool.connections[0][0] = boundary_conn;
    pool.counts[0] = 1;

    // Should NOT be evicted (idle > TIMEOUT, not >=)
    const result = pool.acquire(0);
    try std.testing.expect(result != null);
    var acquired = result.?;
    defer acquired.close();
}

test "CRITICAL: checked_out_counts prevents pool accounting bugs" {
    // checked_out_counts must stay in sync with actual usage
    // Bug here = connection leak detection fails
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    defer pool.drain();

    var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    pool.release(0, pair.conn, true);

    try std.testing.expectEqual(@as(u8, 0), pool.checked_out_counts[0]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Acquire increments checked_out
    const acquired = pool.acquire(0);
    try std.testing.expect(acquired != null);
    try std.testing.expectEqual(@as(u8, 1), pool.checked_out_counts[0]);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    // Release decrements checked_out
    pool.release(0, acquired.?, true);
    try std.testing.expectEqual(@as(u8, 0), pool.checked_out_counts[0]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Stats should reflect accurate counts
    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u8, 1), stats.available[0]);
    try std.testing.expectEqual(@as(u8, 0), stats.checked_out[0]);
}

// =============================================================================
// Concurrency and Race Condition Tests
// =============================================================================

test "CRITICAL: Concurrent acquire/release is thread-safe" {
    // Pool uses mutex - verify no races under concurrent access
    // Bug here = data races, crashes, corrupted counts
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    defer pool.drain();

    // Pre-populate pool with connections
    const NUM_INITIAL_CONNECTIONS = 8;
    var peer_fds: [NUM_INITIAL_CONNECTIONS]std.posix.fd_t = [_]std.posix.fd_t{-1} ** NUM_INITIAL_CONNECTIONS;
    defer {
        for (peer_fds) |fd| closePeerFd(fd);
    }
    for (0..NUM_INITIAL_CONNECTIONS) |i| {
        var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
        peer_fds[i] = pair.peer_fd;
        pool.release(0, pair.conn, true);
    }

    try std.testing.expectEqual(@as(u8, NUM_INITIAL_CONNECTIONS), pool.counts[0]);

    // Worker thread function
    const Worker = struct {
        fn run(p: *SimplePool, iterations: u32) void {
            var i: u32 = 0;
            while (i < iterations) : (i += 1) {
                // Try to acquire
                if (p.acquire(0)) |conn| {
                    // Simulate some work
                    std.Thread.yield() catch |err| {
                        std.log.warn("pool test worker yield failed: {s}", .{@errorName(err)});
                    };

                    // Release back to pool
                    p.release(0, conn, true);
                } else {
                    // Pool was empty, yield and retry
                    std.Thread.yield() catch |err| {
                        std.log.warn("pool test worker retry yield failed: {s}", .{@errorName(err)});
                    };
                }
            }
        }
    };

    // Spawn multiple threads
    const NUM_THREADS = 4;
    const ITERATIONS_PER_THREAD = 100;

    var threads: [NUM_THREADS]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &pool, ITERATIONS_PER_THREAD });
    }

    // Wait for all threads
    for (threads) |thread| {
        thread.join();
    }

    // Verify final state: all connections back in pool
    try std.testing.expectEqual(@as(u8, NUM_INITIAL_CONNECTIONS), pool.counts[0]);
    try std.testing.expectEqual(@as(u8, 0), pool.checked_out_counts[0]);

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u32, NUM_INITIAL_CONNECTIONS), stats.total_available);
    try std.testing.expectEqual(@as(u32, 0), stats.total_checked_out);
}

test "CRITICAL: Race on pool full condition does not overflow" {
    // Multiple threads releasing simultaneously when pool is nearly full
    // Bug here = buffer overflow past MAX_CONNS_PER_UPSTREAM
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    defer pool.drain();

    // Fill pool to MAX - 1
    const INITIAL = SimplePool.MAX_CONNS_PER_UPSTREAM - 1;
    var initial_peer_fds: [INITIAL]std.posix.fd_t = [_]std.posix.fd_t{-1} ** INITIAL;
    defer {
        for (initial_peer_fds) |fd| closePeerFd(fd);
    }
    for (0..INITIAL) |i| {
        var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
        initial_peer_fds[i] = pair.peer_fd;
        pool.release(0, pair.conn, true);
    }

    // Multiple threads try to release simultaneously
    // Only one should succeed, rest should close (not crash)
    const ReleaseWorker = struct {
        fn run(p: *SimplePool, conn: Connection) void {
            p.release(0, conn, true);
        }
    };

    const NUM_THREADS = 4;
    var thread_peer_fds: [NUM_THREADS]std.posix.fd_t = [_]std.posix.fd_t{-1} ** NUM_THREADS;
    defer {
        for (thread_peer_fds) |fd| closePeerFd(fd);
    }
    var thread_conns: [NUM_THREADS]Connection = undefined;
    for (0..NUM_THREADS) |i| {
        var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
        thread_peer_fds[i] = pair.peer_fd;
        thread_conns[i] = pair.conn;
    }

    var threads: [NUM_THREADS]std.Thread = undefined;
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, ReleaseWorker.run, .{ &pool, thread_conns[i] });
    }

    for (threads) |thread| {
        thread.join();
    }

    // Pool should be exactly at MAX (not overflowed)
    try std.testing.expectEqual(SimplePool.MAX_CONNS_PER_UPSTREAM, pool.counts[0]);
}

// =============================================================================
// Sentinel / Double-Release Protection Tests
// =============================================================================

test "CRITICAL: Sentinel lifecycle prevents use-after-release" {
    // Sentinel changes through lifecycle: IN_USE → IN_POOL → IN_USE
    // This prevents double-release bugs (would assert in debug mode)
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // New connection starts with IN_USE_SENTINEL
    var pair = try testConnection(now_ns, now_ns, Connection.IN_USE_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    var conn: Connection = pair.conn;
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn.pool_sentinel);

    // Release to pool (changes sentinel to IN_POOL_SENTINEL internally)
    pool.release(0, conn, true);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // NOTE: `conn` is now INVALID - sentinel changed, must not be used
    // Attempting to release again would assert: sentinel != IN_USE_SENTINEL

    // Correct usage: acquire fresh connection
    const conn2 = pool.acquire(0);
    try std.testing.expect(conn2 != null);
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn2.?.pool_sentinel);

    // This NEW connection can be released
    pool.release(0, conn2.?, true);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Full cycle again
    const conn3 = pool.acquire(0);
    try std.testing.expect(conn3 != null);
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn3.?.pool_sentinel);

    // Release as unhealthy (still requires correct sentinel)
    pool.release(0, conn3.?, false);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // Not pooled (unhealthy)
}

test "Sentinel: Default connection has IN_USE_SENTINEL" {
    // Document that default initialization is IN_USE (safe for new connections)
    const conn: Connection = .{
        .socket = undefined,
    };
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn.pool_sentinel);
}

test "Sentinel: Pool acquire changes IN_POOL → IN_USE" {
    // Verify sentinel transition during acquire
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Manually insert connection with IN_POOL_SENTINEL
    var pair = try testConnection(now_ns, now_ns, Connection.IN_POOL_SENTINEL, false);
    defer closePeerFd(pair.peer_fd);
    pool.connections[0][0] = pair.conn;
    pool.counts[0] = 1;

    // Acquire should change sentinel to IN_USE
    const conn = pool.acquire(0);
    try std.testing.expect(conn != null);
    var acquired = conn.?;
    defer acquired.close();
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, acquired.pool_sentinel);
}
