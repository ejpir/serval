// lib/serval-metrics/mod.zig
//! Serval Metrics - Request Metrics Interface
//!
//! Comptime interface for request metrics.
//! TigerStyle: Atomic counters, fixed histograms.

pub const metrics = @import("metrics.zig");
pub const NoopMetrics = metrics.NoopMetrics;
pub const PrometheusMetrics = metrics.PrometheusMetrics;
pub const verifyMetrics = metrics.verifyMetrics;

pub const stats = @import("stats.zig");
pub const RealTimeMetrics = stats.RealTimeMetrics;
pub const StatsSnapshot = stats.StatsSnapshot;
pub const UpstreamStats = stats.UpstreamStats;

// Re-export from config for convenience (single source of truth)
pub const MAX_UPSTREAMS = @import("serval-core").config.MAX_UPSTREAMS;

test {
    _ = @import("metrics.zig");
    _ = @import("stats.zig");
}
