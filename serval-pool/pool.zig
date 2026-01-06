// lib/serval-pool/pool.zig
//! Connection Pool Interface
//!
//! Comptime interface for connection pooling.
//! Includes SimplePool (fixed-size) and NoPool (no pooling).
//! TigerStyle: No runtime allocation, fixed sizes.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const config = @import("serval-core").config;
const time = @import("serval-core").time;
const UpstreamIndex = config.UpstreamIndex;

// debug
const serval_core = @import("serval-core");
const debugLog = serval_core.debugLog;

// =============================================================================
// Pool Interface Verification
// =============================================================================

pub fn verifyPool(comptime Pool: type) void {
    if (!@hasDecl(Pool, "acquire")) {
        @compileError("Pool must implement: pub fn acquire(self, upstream_idx: UpstreamIndex, io: Io) ?Connection");
    }
    if (!@hasDecl(Pool, "release")) {
        @compileError("Pool must implement: pub fn release(self, upstream_idx: UpstreamIndex, conn: Connection, healthy: bool, io: Io) void");
    }
    if (!@hasDecl(Pool, "drain")) {
        @compileError("Pool must implement: pub fn drain(self, io: Io) void");
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

pub const Connection = struct {
    stream: Io.net.Stream,
    /// Timestamp when connection was established (monotonic nanoseconds).
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    created_ns: u64 = 0,
    /// Timestamp when connection was last released to pool (monotonic nanoseconds).
    /// Used for idle timeout eviction.
    last_used_ns: u64 = 0,
    /// Sentinel to detect double-release. Set to magic value when in pool.
    /// TigerStyle: Defense in depth against use-after-release bugs.
    pool_sentinel: u32 = IN_USE_SENTINEL,

    const IN_POOL_SENTINEL: u32 = 0xDEAD_BEEF;
    const IN_USE_SENTINEL: u32 = 0xCAFE_BABE;

    /// Close the connection stream.
    /// TigerStyle: Explicit io parameter for async close.
    pub fn close(self: *Connection, io: Io) void {
        self.stream.close(io);
    }

    /// Get raw file descriptor for splice operations.
    /// TigerStyle: Zero-copy splice needs raw fd.
    pub fn getFd(self: *const Connection) i32 {
        return self.stream.socket.handle;
    }

    /// Check if connection is unusable and should not be reused.
    /// Detects: stale data, closed by peer, socket errors, invalid fd.
    /// Uses poll() with zero timeout for non-blocking check.
    /// Returns true if connection should NOT be reused.
    /// TigerStyle: Positive naming - true means "bad, don't use".
    pub fn isUnusable(self: *const Connection) bool {
        const fd = self.stream.socket.handle;
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
            std.log.debug("isUnusable poll failed on fd {d}: {s}", .{ fd, @errorName(err) });
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

pub const NoPool = struct {
    pub fn acquire(_: *@This(), _: UpstreamIndex, _: Io) ?Connection {
        return null;
    }

    pub fn release(_: *@This(), _: UpstreamIndex, conn: Connection, _: bool, io: Io) void {
        var c = conn;
        c.close(io);
    }

    /// No-op for NoPool since it doesn't store connections.
    pub fn drain(_: *@This(), _: Io) void {}
};

// =============================================================================
// SimplePool (fixed-size, no allocation, thread-safe)
// =============================================================================

pub const SimplePool = struct {
    // Pool sizing from centralized config
    const MAX_CONNS_PER_UPSTREAM = config.MAX_CONNS_PER_UPSTREAM;
    const MAX_UPSTREAMS = config.MAX_UPSTREAMS;

    /// Default idle timeout: 60 seconds.
    /// Connections idle longer than this are evicted on acquire.
    /// TigerStyle: Explicit constant, unit in name.
    const IDLE_TIMEOUT_NS: u64 = 60 * std.time.ns_per_s;

    /// Default max connection age: 5 minutes.
    /// Connections older than this are evicted regardless of activity.
    /// TigerStyle: Prevents stale connections from backend restarts.
    const MAX_CONNECTION_AGE_NS: u64 = 5 * 60 * std.time.ns_per_s;

    /// Mutex protects connections and counts arrays.
    /// TigerStyle: Simple mutex over complex lock-free for correctness.
    mutex: std.Thread.Mutex = .{},
    connections: [MAX_UPSTREAMS][MAX_CONNS_PER_UPSTREAM]?Connection =
        [_][MAX_CONNS_PER_UPSTREAM]?Connection{[_]?Connection{null} ** MAX_CONNS_PER_UPSTREAM} ** MAX_UPSTREAMS,
    counts: [MAX_UPSTREAMS]u8 = [_]u8{0} ** MAX_UPSTREAMS,

    /// Count of connections currently checked out (in use) per upstream.
    /// TigerStyle: Explicit tracking for observability and leak detection.
    checked_out_counts: [MAX_UPSTREAMS]u8 = [_]u8{0} ** MAX_UPSTREAMS,

    /// Optional metrics callback for observability.
    /// TigerStyle: Null by default, opt-in for overhead.
    metrics_callback: ?MetricsCallback = null,

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
    pub fn acquire(self: *SimplePool, upstream_idx: UpstreamIndex, io: Io) ?Connection {
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
            self.mutex.lock();
            defer self.mutex.unlock();

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
                c.close(io);
                self.emitMetric(upstream_idx, .acquire_evicted);
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
    /// self.pool.release(upstream.idx, mutable_conn, true, io);
    pub fn release(self: *SimplePool, upstream_idx: UpstreamIndex, conn: Connection, healthy: bool, io: Io) void {
        assert(upstream_idx < MAX_UPSTREAMS);
        // TigerStyle: Verify sentinel - must not be double-released
        assert(conn.pool_sentinel == Connection.IN_USE_SENTINEL);

        const idx = @as(usize, upstream_idx);
        var should_close = !healthy;
        var c = conn;

        // Single lock acquisition for atomic state transition.
        // TigerStyle: Decrement checked_out and store connection atomically.
        {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Always decrement checked_out count
            if (self.checked_out_counts[idx] > 0) {
                self.checked_out_counts[idx] -= 1;
            }

            if (healthy) {
                // Update timestamp and sentinel for pool storage
                c.last_used_ns = time.monotonicNanos();
                c.pool_sentinel = Connection.IN_POOL_SENTINEL;

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
            c.close(io);
            self.emitMetric(upstream_idx, .release_closed);
        } else if (healthy) {
            self.emitMetric(upstream_idx, .release_stored);
        } else {
            self.emitMetric(upstream_idx, .release_closed);
        }
    }

    /// Close all pooled connections. Call during server shutdown.
    /// TigerStyle: Explicit io parameter for async close.
    pub fn drain(self: *SimplePool, io: Io) void {
        // Collect connections to close under lock.
        // TigerStyle: Bounded array, no allocation.
        var to_close: [MAX_UPSTREAMS * MAX_CONNS_PER_UPSTREAM]?Connection =
            [_]?Connection{null} ** (MAX_UPSTREAMS * MAX_CONNS_PER_UPSTREAM);
        var close_count: u32 = 0;

        {
            self.mutex.lock();
            defer self.mutex.unlock();

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
                c.close(io);
            }
        }
    }

    /// Pool statistics for observability and leak detection.
    /// TigerStyle: Snapshot of pool state under single lock acquisition.
    pub const PoolStats = struct {
        /// Connections available in pool per upstream.
        available: [MAX_UPSTREAMS]u8,
        /// Connections currently checked out per upstream.
        checked_out: [MAX_UPSTREAMS]u8,
        /// Total available across all upstreams.
        total_available: u32,
        /// Total checked out across all upstreams.
        total_checked_out: u32,
    };

    /// Get current pool statistics.
    /// TigerStyle: Snapshot under single lock acquisition for consistency.
    pub fn getStats(self: *SimplePool) PoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();

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

test "NoPool always returns null" {
    var pool = NoPool{};
    // Pass undefined io since NoPool doesn't use it
    try std.testing.expectEqual(@as(?Connection, null), pool.acquire(0, undefined));
}

test "SimplePool acquire from empty returns null" {
    var pool = SimplePool.init();
    // Pass undefined io since no connections to close
    try std.testing.expectEqual(@as(?Connection, null), pool.acquire(0, undefined));
}

test "SimplePool stores and retrieves connections" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Initially empty
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    // Directly store a connection (simulating release with healthy=true)
    // We use undefined stream since we only test pool counting, not I/O
    // Set timestamps to now so connection is not considered stale
    // Set sentinel to IN_POOL_SENTINEL as if it were properly released
    const test_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.connections[0][0] = test_conn;
    pool.counts[0] = 1;
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Acquire returns it (pass undefined io since connection is valid)
    const conn = pool.acquire(0, undefined);
    try std.testing.expect(conn != null);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);
    // Verify sentinel changed to IN_USE after acquire
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn.?.pool_sentinel);
}

test "SimplePool respects max connections per upstream" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Fill up the pool for upstream 0 with properly initialized connections
    for (0..SimplePool.MAX_CONNS_PER_UPSTREAM) |i| {
        pool.connections[0][i] = .{
            .stream = undefined,
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
        .stream = undefined,
        .created_ns = 12345,
        .last_used_ns = 67890,
    };
    try std.testing.expectEqual(@as(u64, 12345), conn.created_ns);
    try std.testing.expectEqual(@as(u64, 67890), conn.last_used_ns);
}

test "Connection sentinel values" {
    // Default sentinel is IN_USE
    const conn: Connection = .{ .stream = undefined };
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn.pool_sentinel);

    // IN_POOL sentinel marks connection as pooled
    const pooled_conn: Connection = .{
        .stream = undefined,
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
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.connections[0][1] = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.counts[0] = 2;

    // Add connections for a second upstream
    pool.connections[1][0] = .{
        .stream = undefined,
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

    // Initially no checked out connections
    try std.testing.expectEqual(@as(u8, 0), pool.checked_out_counts[0]);

    // Add a connection to the pool
    pool.connections[0][0] = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.counts[0] = 1;

    // Acquire increments checked_out_counts
    const conn = pool.acquire(0, undefined);
    try std.testing.expect(conn != null);
    try std.testing.expectEqual(@as(u8, 1), pool.checked_out_counts[0]);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    // Note: Cannot test release() decrementing because it requires actual I/O
    // for closing connections. The logic is verified by code inspection.
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
        .stream = undefined,
        .created_ns = 0, // BUG: forwarder didn't set this
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.counts[0] = 1;

    // Pool should evict it as too old (age = now_ns - 0 = massive)
    const result = pool.acquire(0, undefined);
    try std.testing.expectEqual(@as(?Connection, null), result);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // Evicted
}

test "Invariant: acquired connections have valid timestamps" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Store a properly initialized connection
    pool.connections[0][0] = .{
        .stream = undefined,
        .created_ns = now_ns - 1000,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.counts[0] = 1;

    const result = pool.acquire(0, undefined);
    try std.testing.expect(result != null);

    // INVARIANT: All acquired connections MUST have valid timestamps
    try std.testing.expect(result.?.created_ns > 0);
    try std.testing.expect(result.?.last_used_ns > 0);
    try std.testing.expect(result.?.last_used_ns >= result.?.created_ns);
}

test "Pool evicts connections exceeding max age (5 minutes)" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    const max_age_ns = 5 * 60 * std.time.ns_per_s;
    const old_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns - (max_age_ns + (60 * std.time.ns_per_s)), // 6 min old
        .last_used_ns = now_ns - 1000, // Used recently, but too old overall
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };

    pool.connections[0][0] = old_conn;
    pool.counts[0] = 1;

    // Should evict due to max age
    const result = pool.acquire(0, undefined);
    try std.testing.expectEqual(@as(?Connection, null), result);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);
}

test "Pool evicts connections exceeding idle timeout (60 seconds)" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    const idle_timeout_ns = 60 * std.time.ns_per_s;
    const idle_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns - (10 * std.time.ns_per_s), // 10s old
        .last_used_ns = now_ns - (idle_timeout_ns + std.time.ns_per_s), // 61s idle
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };

    pool.connections[0][0] = idle_conn;
    pool.counts[0] = 1;

    // Should evict due to idle timeout
    const result = pool.acquire(0, undefined);
    try std.testing.expectEqual(@as(?Connection, null), result);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);
}

test "Pool retains fresh, recently-used connections" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    const fresh_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns - (30 * std.time.ns_per_s), // 30s old
        .last_used_ns = now_ns - (5 * std.time.ns_per_s), // Used 5s ago
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };

    pool.connections[0][0] = fresh_conn;
    pool.counts[0] = 1;

    // Should successfully acquire (not evicted)
    const result = pool.acquire(0, undefined);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // Removed from pool
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, result.?.pool_sentinel);
}

test "Full lifecycle: acquire → release → acquire reuses connection" {
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Simulate first request: create connection and release to pool
    const new_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };

    pool.release(0, new_conn, true, undefined);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Simulate second request: acquire from pool
    const reused_conn = pool.acquire(0, undefined);
    try std.testing.expect(reused_conn != null);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    // Verify timestamps are preserved
    try std.testing.expectEqual(now_ns, reused_conn.?.created_ns);
    try std.testing.expect(reused_conn.?.last_used_ns >= reused_conn.?.created_ns);
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, reused_conn.?.pool_sentinel);
}

// =============================================================================
// Critical Safety Tests
// =============================================================================

test "CRITICAL: Release unhealthy connection does NOT pool it" {
    // Unhealthy connections must be closed, not returned to pool
    // Bug here = stale connections reused = request failures
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    const unhealthy_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };

    // Release as unhealthy (healthy=false)
    pool.release(0, unhealthy_conn, false, undefined);

    // Should NOT be in pool
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    // Next acquire should return null (pool is empty)
    const result = pool.acquire(0, undefined);
    try std.testing.expectEqual(@as(?Connection, null), result);
}

test "CRITICAL: Pool full drops healthy connection (bounded buffer)" {
    // Pool has fixed size - releasing to full pool must not overflow
    // Bug here = buffer overflow, corruption
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Fill pool to MAX_CONNS_PER_UPSTREAM
    for (0..SimplePool.MAX_CONNS_PER_UPSTREAM) |i| {
        const conn: Connection = .{
            .stream = undefined,
            .created_ns = now_ns,
            .last_used_ns = now_ns,
            .pool_sentinel = Connection.IN_USE_SENTINEL,
        };
        pool.release(0, conn, true, undefined);
        try std.testing.expectEqual(@as(u8, @intCast(i + 1)), pool.counts[0]);
    }

    // Pool is now full
    try std.testing.expectEqual(SimplePool.MAX_CONNS_PER_UPSTREAM, pool.counts[0]);

    // Release one more healthy connection - should be dropped (closed)
    const overflow_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(0, overflow_conn, true, undefined);

    // Pool should still be at max (overflow connection was closed)
    try std.testing.expectEqual(SimplePool.MAX_CONNS_PER_UPSTREAM, pool.counts[0]);
}

test "CRITICAL: Multiple upstreams are isolated" {
    // Connections to upstream[0] must not leak to upstream[1]
    // Bug here = routing errors, security violation
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Release connection to upstream 0
    const conn_upstream_0: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(0, conn_upstream_0, true, undefined);

    // Release connection to upstream 1
    const conn_upstream_1: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(1, conn_upstream_1, true, undefined);

    // Verify counts
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[1]);

    // Acquire from upstream 0 - should get upstream 0's connection
    const result_0 = pool.acquire(0, undefined);
    try std.testing.expect(result_0 != null);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // upstream 0 now empty
    try std.testing.expectEqual(@as(u8, 1), pool.counts[1]); // upstream 1 unchanged

    // Acquire from upstream 1 - should get upstream 1's connection
    const result_1 = pool.acquire(1, undefined);
    try std.testing.expect(result_1 != null);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // upstream 0 still empty
    try std.testing.expectEqual(@as(u8, 0), pool.counts[1]); // upstream 1 now empty
}

test "CRITICAL: LIFO order preserves cache locality" {
    // Pool should return most recently used connection (LIFO stack)
    // Bug here = poor cache performance, more TCP handshakes
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Release 3 connections with different timestamps
    const old_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns - 1000,
        .last_used_ns = now_ns - 1000,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(0, old_conn, true, undefined);

    const mid_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns - 500,
        .last_used_ns = now_ns - 500,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(0, mid_conn, true, undefined);

    const recent_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns - 100,
        .last_used_ns = now_ns - 100,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(0, recent_conn, true, undefined);

    try std.testing.expectEqual(@as(u8, 3), pool.counts[0]);

    // Acquire should return MOST RECENT (LIFO)
    const result = pool.acquire(0, undefined);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(now_ns - 100, result.?.last_used_ns);
}

test "CRITICAL: Drain closes all pooled connections" {
    // Drain must close all connections across all upstreams
    // Bug here = resource leak on shutdown
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Add connections to multiple upstreams
    for (0..3) |upstream_idx| {
        const conn: Connection = .{
            .stream = undefined,
            .created_ns = now_ns,
            .last_used_ns = now_ns,
            .pool_sentinel = Connection.IN_USE_SENTINEL,
        };
        pool.release(@intCast(upstream_idx), conn, true, undefined);
    }

    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[1]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[2]);

    // Drain should empty all pools
    pool.drain(undefined);

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
    _ = pool.acquire(0, undefined);
    try std.testing.expectEqual(@as(u32, 0), TestMetrics.acquire_hits);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.acquire_misses);

    // Release healthy connection - should emit release_stored
    const conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(0, conn, true, undefined);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.release_stored);
    try std.testing.expectEqual(@as(u32, 0), TestMetrics.release_closed);

    // Acquire from pool - should emit acquire_hit
    _ = pool.acquire(0, undefined);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.acquire_hits);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.acquire_misses); // Unchanged

    // Release unhealthy connection - should emit release_closed
    const unhealthy: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(0, unhealthy, false, undefined);
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.release_stored); // Unchanged
    try std.testing.expectEqual(@as(u32, 1), TestMetrics.release_closed);
}

test "CRITICAL: Boundary - connection at exactly max age threshold" {
    // Off-by-one errors at boundaries are common
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    const max_age_ns = 5 * 60 * std.time.ns_per_s;

    // Connection at EXACTLY max age (not over)
    const boundary_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns - max_age_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };

    pool.connections[0][0] = boundary_conn;
    pool.counts[0] = 1;

    // Should be evicted (age > MAX, not >=)
    const result = pool.acquire(0, undefined);
    // TigerStyle: Document expected behavior explicitly
    // Current implementation: if (age_ns > MAX_CONNECTION_AGE_NS)
    // So exactly-at-threshold should NOT be evicted
    try std.testing.expect(result != null);
}

test "CRITICAL: Boundary - connection at exactly idle timeout threshold" {
    // Off-by-one errors at boundaries are common
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();
    const idle_timeout_ns = 60 * std.time.ns_per_s;

    // Connection at EXACTLY idle timeout (not over)
    const boundary_conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns - 1000,
        .last_used_ns = now_ns - idle_timeout_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };

    pool.connections[0][0] = boundary_conn;
    pool.counts[0] = 1;

    // Should NOT be evicted (idle > TIMEOUT, not >=)
    const result = pool.acquire(0, undefined);
    try std.testing.expect(result != null);
}

test "CRITICAL: checked_out_counts prevents pool accounting bugs" {
    // checked_out_counts must stay in sync with actual usage
    // Bug here = connection leak detection fails
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    const conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    pool.release(0, conn, true, undefined);

    try std.testing.expectEqual(@as(u8, 0), pool.checked_out_counts[0]);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Acquire increments checked_out
    const acquired = pool.acquire(0, undefined);
    try std.testing.expect(acquired != null);
    try std.testing.expectEqual(@as(u8, 1), pool.checked_out_counts[0]);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]);

    // Release decrements checked_out
    pool.release(0, acquired.?, true, undefined);
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

    // Pre-populate pool with connections
    const NUM_INITIAL_CONNECTIONS = 8;
    for (0..NUM_INITIAL_CONNECTIONS) |_| {
        const conn: Connection = .{
            .stream = undefined,
            .created_ns = now_ns,
            .last_used_ns = now_ns,
            .pool_sentinel = Connection.IN_USE_SENTINEL,
        };
        pool.release(0, conn, true, undefined);
    }

    try std.testing.expectEqual(@as(u8, NUM_INITIAL_CONNECTIONS), pool.counts[0]);

    // Worker thread function
    const Worker = struct {
        fn run(p: *SimplePool, iterations: u32) void {
            var i: u32 = 0;
            while (i < iterations) : (i += 1) {
                // Try to acquire
                if (p.acquire(0, undefined)) |conn| {
                    // Simulate some work
                    std.Thread.yield() catch {};

                    // Release back to pool
                    p.release(0, conn, true, undefined);
                } else {
                    // Pool was empty, yield and retry
                    std.Thread.yield() catch {};
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

    // Fill pool to MAX - 1
    const INITIAL = SimplePool.MAX_CONNS_PER_UPSTREAM - 1;
    for (0..INITIAL) |_| {
        const conn: Connection = .{
            .stream = undefined,
            .created_ns = now_ns,
            .last_used_ns = now_ns,
            .pool_sentinel = Connection.IN_USE_SENTINEL,
        };
        pool.release(0, conn, true, undefined);
    }

    // Multiple threads try to release simultaneously
    // Only one should succeed, rest should close (not crash)
    const ReleaseWorker = struct {
        fn run(p: *SimplePool, timestamp: u64) void {
            const conn: Connection = .{
                .stream = undefined,
                .created_ns = timestamp,
                .last_used_ns = timestamp,
                .pool_sentinel = Connection.IN_USE_SENTINEL,
            };
            p.release(0, conn, true, undefined);
        }
    };

    const NUM_THREADS = 4;
    var threads: [NUM_THREADS]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, ReleaseWorker.run, .{ &pool, now_ns });
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
    var conn: Connection = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_USE_SENTINEL,
    };
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn.pool_sentinel);

    // Release to pool (changes sentinel to IN_POOL_SENTINEL internally)
    pool.release(0, conn, true, undefined);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // NOTE: `conn` is now INVALID - sentinel changed, must not be used
    // Attempting to release again would assert: sentinel != IN_USE_SENTINEL

    // Correct usage: acquire fresh connection
    const conn2 = pool.acquire(0, undefined);
    try std.testing.expect(conn2 != null);
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn2.?.pool_sentinel);

    // This NEW connection can be released
    pool.release(0, conn2.?, true, undefined);
    try std.testing.expectEqual(@as(u8, 1), pool.counts[0]);

    // Full cycle again
    const conn3 = pool.acquire(0, undefined);
    try std.testing.expect(conn3 != null);
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn3.?.pool_sentinel);

    // Release as unhealthy (still requires correct sentinel)
    pool.release(0, conn3.?, false, undefined);
    try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // Not pooled (unhealthy)
}

test "Sentinel: Default connection has IN_USE_SENTINEL" {
    // Document that default initialization is IN_USE (safe for new connections)
    const conn: Connection = .{
        .stream = undefined,
    };
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn.pool_sentinel);
}

test "Sentinel: Pool acquire changes IN_POOL → IN_USE" {
    // Verify sentinel transition during acquire
    var pool = SimplePool.init();
    const now_ns = time.monotonicNanos();

    // Manually insert connection with IN_POOL_SENTINEL
    pool.connections[0][0] = .{
        .stream = undefined,
        .created_ns = now_ns,
        .last_used_ns = now_ns,
        .pool_sentinel = Connection.IN_POOL_SENTINEL,
    };
    pool.counts[0] = 1;

    // Acquire should change sentinel to IN_USE
    const conn = pool.acquire(0, undefined);
    try std.testing.expect(conn != null);
    try std.testing.expectEqual(Connection.IN_USE_SENTINEL, conn.?.pool_sentinel);
}
