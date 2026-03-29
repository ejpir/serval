// lib/serval-metrics/mod.zig
//! Serval Metrics - Request Metrics Interface
//!
//! Comptime interface for request metrics.
//! TigerStyle: Atomic counters, fixed histograms.

/// Public re-export of the request-metrics implementation module.
/// Import this namespace to access `verifyMetrics`, `NoopMetrics`, and `PrometheusMetrics` directly.
pub const metrics = @import("metrics.zig");
/// Zero-overhead metrics backend for callers that do not need metrics collection.
/// All methods satisfy the shared metrics interface and intentionally do no work.
/// The methods never return errors.
pub const NoopMetrics = metrics.NoopMetrics;
/// Atomic Prometheus-compatible metrics backend with fixed counters and histograms.
/// Supports request, status, connection, and latency tracking without allocation.
/// `upstreamLatency` is intentionally a no-op in this backend.
pub const PrometheusMetrics = metrics.PrometheusMetrics;
/// Compile-time validator for metrics backends.
/// Emits a compile error unless `M` provides `requestStart` and `requestEnd`.
/// This function only checks the type at comptime and does not instantiate or call `M`.
pub const verifyMetrics = metrics.verifyMetrics;

/// Public re-export of the metrics implementation module.
/// Use this namespace to access the request-metrics interface and concrete metrics backends.
pub const stats = @import("stats.zig");
/// Real-time metrics collector with atomic global counters and fixed per-upstream tracking.
/// Call the request and connection methods to update state, then `snapshot()` to derive rates and percentiles.
/// The type uses fixed arrays and does not allocate after initialization.
pub const RealTimeMetrics = stats.RealTimeMetrics;
/// Point-in-time view of global and per-upstream metrics.
/// Rates are derived from deltas since the previous snapshot.
/// The upstream array is fixed-size and owned by the snapshot value.
pub const StatsSnapshot = stats.StatsSnapshot;
/// Per-upstream metrics summary returned by `RealTimeMetrics.snapshot()`.
/// Captures totals, request rate, average latency, and health for one upstream.
pub const UpstreamStats = stats.UpstreamStats;

// Re-export from config for convenience (single source of truth)
/// Maximum number of upstreams supported by Serval metrics types.
/// This re-exports `serval-core.config.MAX_UPSTREAMS` so all metrics code uses the same bound.
pub const MAX_UPSTREAMS = @import("serval-core").config.MAX_UPSTREAMS;

test {
    _ = @import("metrics.zig");
    _ = @import("stats.zig");
}
