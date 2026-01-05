// lib/serval-pool/mod.zig
//! Serval Pool - Connection Pooling
//!
//! Fixed-size connection pool with no runtime allocation.
//! TigerStyle: Bounded arrays, explicit sizes.

pub const pool = @import("pool.zig");
pub const Connection = pool.Connection;
pub const NoPool = pool.NoPool;
pub const SimplePool = pool.SimplePool;
pub const PoolStats = SimplePool.PoolStats;
pub const PoolEvent = pool.PoolEvent;
pub const MetricsCallback = pool.MetricsCallback;
pub const verifyPool = pool.verifyPool;

test {
    _ = @import("pool.zig");
}
