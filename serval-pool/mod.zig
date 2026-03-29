// lib/serval-pool/mod.zig
//! Serval Pool - Connection Pooling
//!
//! Fixed-size connection pool with no runtime allocation.
//! TigerStyle: Bounded arrays, explicit sizes.

/// Re-exports the pool module namespace from `pool.zig`.
/// Use `pool` to access the public declarations defined in that file.
/// This is a compile-time module binding; it performs no runtime allocation or I/O.
pub const pool = @import("pool.zig");
/// Public re-export of `pool.Connection`, the pool-managed handle around a plain-TCP or TLS `Socket`.
/// Use this alias in external API signatures instead of importing `pool.zig` directly.
/// Ownership and lifetime are unchanged: treat an acquired connection as exclusively owned until you release it to a pool or close it.
/// This alias has no runtime behavior or error path; any assertions/error handling come from `pool.Connection` methods.
pub const Connection = pool.Connection;
/// Re-export of `pool.NoPool`, the stateless "no connection pooling" implementation.
/// `acquire` always returns `null`, so callers must create a fresh upstream connection.
/// `release` consumes the passed `Connection` and closes it immediately; do not use that connection afterward.
/// `drain` is a no-op, and this type has no internal pooled state or drain-time error path.
pub const NoPool = pool.NoPool;
/// Re-export of `pool.SimplePool`, the default fixed-capacity pool implementation.
/// It stores connections in bounded per-upstream arrays and uses a mutex to protect shared state.
/// The pool performs no heap allocation and can optionally emit `PoolEvent` metrics through a callback.
/// Stale entries may be evicted during `acquire()` based on idle time or maximum connection age.
pub const SimplePool = pool.SimplePool;
/// Re-export of `SimplePool.PoolStats`, a snapshot of pool availability and checkout counts.
/// The struct reports per-upstream and total counts copied under a single lock for consistency.
/// Use it for observability, capacity checks, and leak detection.
pub const PoolStats = SimplePool.PoolStats;
/// Re-export of `pool.PoolEvent`, the event set used by the pool metrics callback.
/// Values describe acquire hits and misses, stale evictions, and release outcomes.
/// These events are emitted by `SimplePool` when metrics reporting is enabled.
pub const PoolEvent = pool.PoolEvent;
/// Re-export of `pool.MetricsCallback`, the function-pointer type used for pool metrics hooks.
/// The callback receives the upstream index and the `PoolEvent` being reported.
/// It is invoked synchronously by `SimplePool` and does not allocate or return a value.
pub const MetricsCallback = pool.MetricsCallback;
/// Re-export of `pool.verifyPool`, a comptime contract check for pool implementations.
/// It requires `acquire`, `release`, and `drain` declarations to exist on the supplied type.
/// The check runs at compile time only and performs no runtime work.
pub const verifyPool = pool.verifyPool;

test {
    _ = @import("pool.zig");
}
