// lib/serval-metrics/stats.zig
//! Real-Time Metrics Collection
//!
//! Types for collecting and snapshotting live metrics with per-upstream tracking.
//! TigerStyle: Fixed arrays (no allocation), atomic counters, ~2 assertions per function.

const std = @import("std");
const assert = std.debug.assert;
const serval_core = @import("serval-core");
const time = serval_core.time;
const config = serval_core.config;
const metrics = @import("metrics.zig");
const PrometheusMetrics = metrics.PrometheusMetrics;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of upstreams tracked (from serval-core.config).
const MAX_UPSTREAMS = config.MAX_UPSTREAMS;
const UpstreamIndex = config.UpstreamIndex;

/// Error rate threshold for marking upstream as unhealthy (50% = 1/2).
const UNHEALTHY_ERROR_RATE_DIVISOR: u64 = 2;

// =============================================================================
// Snapshot Types
// =============================================================================

/// Per-upstream statistics snapshot.
pub const UpstreamStats = struct {
    requests_total: u64,
    requests_per_sec: f64,
    errors_total: u64,
    avg_latency_ms: u32,
    healthy: bool,
};

/// Point-in-time metrics snapshot.
/// Rates are calculated from deltas since previous snapshot.
pub const StatsSnapshot = struct {
    // Totals
    requests_total: u64,
    errors_total: u64,
    connections_active: i64,

    // Rates (calculated from deltas)
    requests_per_sec: f64,
    errors_per_sec: f64,

    // Latency percentiles
    latency_p50_ms: u32,
    latency_p95_ms: u32,
    latency_p99_ms: u32,

    // Per-upstream (fixed array)
    upstream_stats: [MAX_UPSTREAMS]UpstreamStats,
    upstream_count: u8,
};

// =============================================================================
// Internal Types
// =============================================================================

/// Result type for buildUpstreamStats helper.
const UpstreamStatsResult = struct {
    stats: [MAX_UPSTREAMS]UpstreamStats,
    count: u8,
};

/// Latency percentile results.
const LatencyPercentiles = struct {
    p50: u32,
    p95: u32,
    p99: u32,
};

// =============================================================================
// RealTimeMetrics
// =============================================================================

/// Real-time metrics collector with per-upstream tracking and rate calculation.
/// Extends PrometheusMetrics with upstream-level granularity.
/// Fixed arrays, atomic operations, no allocation after init.
pub const RealTimeMetrics = struct {
    base: PrometheusMetrics = .{},

    // Per-upstream counters (atomic)
    upstream_requests: [MAX_UPSTREAMS]std.atomic.Value(u64) =
        [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** MAX_UPSTREAMS,
    upstream_errors: [MAX_UPSTREAMS]std.atomic.Value(u64) =
        [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** MAX_UPSTREAMS,
    upstream_latency_sum_ns: [MAX_UPSTREAMS]std.atomic.Value(u64) =
        [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** MAX_UPSTREAMS,

    // Rate calculation state - only accessed from snapshot(), NOT thread-safe.
    // TigerStyle: Single-writer pattern, display thread owns these fields.
    prev_requests: u64 = 0,
    prev_errors: u64 = 0,
    prev_timestamp_ns: u64 = 0,
    prev_upstream_requests: [MAX_UPSTREAMS]u64 = [_]u64{0} ** MAX_UPSTREAMS,

    /// Initialize a new RealTimeMetrics instance with all fields zeroed.
    pub fn init() RealTimeMetrics {
        return .{};
    }

    /// Take a point-in-time snapshot of all metrics.
    /// Calculates rates from deltas since the last snapshot.
    pub fn snapshot(self: *RealTimeMetrics) StatsSnapshot {
        const now_ns = time.monotonicNanos();
        const requests_total = self.base.requests_total.load(.monotonic);
        const errors_total = self.calculateTotalErrors();
        const connections_active = self.base.connections_active.load(.monotonic);

        const elapsed_ns = time.elapsedNanos(self.prev_timestamp_ns, now_ns);
        // Guard against division by zero with minimum 1ms window
        const elapsed_sec: f64 = if (elapsed_ns > 0)
            @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(time.ns_per_s))
        else
            0.001; // Minimum 1ms to avoid division by zero

        // Calculate rates
        const request_delta = requests_total -| self.prev_requests;
        const error_delta = errors_total -| self.prev_errors;
        const requests_per_sec = @as(f64, @floatFromInt(request_delta)) / elapsed_sec;
        const errors_per_sec = @as(f64, @floatFromInt(error_delta)) / elapsed_sec;

        // Calculate latency percentiles from histogram buckets
        const latency_percentiles = self.calculateLatencyPercentiles();

        // Build per-upstream stats
        const upstream_result = self.buildUpstreamStats(elapsed_sec);

        // Update previous values for next rate calculation
        self.prev_requests = requests_total;
        self.prev_errors = errors_total;
        self.prev_timestamp_ns = now_ns;

        return .{
            .requests_total = requests_total,
            .errors_total = errors_total,
            .connections_active = connections_active,
            .requests_per_sec = requests_per_sec,
            .errors_per_sec = errors_per_sec,
            .latency_p50_ms = latency_percentiles.p50,
            .latency_p95_ms = latency_percentiles.p95,
            .latency_p99_ms = latency_percentiles.p99,
            .upstream_stats = upstream_result.stats,
            .upstream_count = upstream_result.count,
        };
    }

    /// Build per-upstream stats from atomic counters.
    fn buildUpstreamStats(self: *RealTimeMetrics, elapsed_sec: f64) UpstreamStatsResult {
        assert(elapsed_sec > 0);

        var stats: [MAX_UPSTREAMS]UpstreamStats = undefined;
        var count: u8 = 0;

        for (0..MAX_UPSTREAMS) |i| {
            const idx: u8 = @intCast(i);
            const req_count = self.upstream_requests[i].load(.monotonic);
            const err_count = self.upstream_errors[i].load(.monotonic);
            const latency_sum = self.upstream_latency_sum_ns[i].load(.monotonic);

            if (req_count > 0) {
                const prev_req = self.prev_upstream_requests[i];
                const upstream_delta = req_count -| prev_req;
                const upstream_rps = @as(f64, @floatFromInt(upstream_delta)) / elapsed_sec;

                // Calculate average latency in milliseconds (req_count already > 0 here)
                const avg_latency_ns = latency_sum / req_count;
                const avg_latency_ms: u32 = @intCast(avg_latency_ns / time.ns_per_ms);

                stats[idx] = .{
                    .requests_total = req_count,
                    .requests_per_sec = upstream_rps,
                    .errors_total = err_count,
                    .avg_latency_ms = avg_latency_ms,
                    // Health determined by error rate < 50%.
                    .healthy = err_count < req_count / UNHEALTHY_ERROR_RATE_DIVISOR,
                };
                // count is highest active index + 1, not count of active upstreams.
                count = idx + 1;

                // Update previous for next snapshot
                self.prev_upstream_requests[i] = req_count;
            } else {
                stats[idx] = .{
                    .requests_total = 0,
                    .requests_per_sec = 0,
                    .errors_total = 0,
                    .avg_latency_ms = 0,
                    .healthy = true,
                };
            }
        }

        // TigerStyle: Postcondition - count bounded by array size.
        assert(count <= MAX_UPSTREAMS);

        return .{ .stats = stats, .count = count };
    }

    /// Record request start.
    pub fn requestStart(self: *RealTimeMetrics) void {
        self.base.requestStart();
    }

    /// Record request end with status and duration.
    pub fn requestEnd(self: *RealTimeMetrics, status: u16, duration_ns: u64) void {
        assert(status >= 100 and status <= 599);
        self.base.requestEnd(status, duration_ns);
    }

    /// Record request end with upstream tracking for per-upstream load balancer visibility.
    pub fn requestEndWithUpstream(
        self: *RealTimeMetrics,
        status: u16,
        duration_ns: u64,
        upstream_idx: UpstreamIndex,
    ) void {
        assert(upstream_idx < MAX_UPSTREAMS);
        assert(status >= 100 and status <= 599);

        self.base.requestEnd(status, duration_ns);

        _ = self.upstream_requests[upstream_idx].fetchAdd(1, .monotonic);
        _ = self.upstream_latency_sum_ns[upstream_idx].fetchAdd(duration_ns, .monotonic);

        if (status >= 500 and status <= 599) {
            _ = self.upstream_errors[upstream_idx].fetchAdd(1, .monotonic);
        }
    }

    /// Record per-upstream stats only (no base metrics update).
    /// Use when server already called requestEnd() to avoid double-counting totals.
    pub fn recordUpstreamStats(
        self: *RealTimeMetrics,
        status: u16,
        duration_ns: u64,
        upstream_idx: UpstreamIndex,
    ) void {
        assert(upstream_idx < MAX_UPSTREAMS);
        assert(status >= 100 and status <= 599);

        _ = self.upstream_requests[upstream_idx].fetchAdd(1, .monotonic);
        _ = self.upstream_latency_sum_ns[upstream_idx].fetchAdd(duration_ns, .monotonic);

        if (status >= 400) {
            _ = self.upstream_errors[upstream_idx].fetchAdd(1, .monotonic);
        }
    }

    /// Record connection opened.
    pub fn connectionOpened(self: *RealTimeMetrics) void {
        self.base.connectionOpened();
    }

    /// Record connection closed.
    pub fn connectionClosed(self: *RealTimeMetrics) void {
        self.base.connectionClosed();
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /// Sum of 4xx and 5xx response counts.
    fn calculateTotalErrors(self: *RealTimeMetrics) u64 {
        const errors_4xx = self.base.requests_by_status[3].load(.monotonic);
        const errors_5xx = self.base.requests_by_status[4].load(.monotonic);
        return errors_4xx + errors_5xx;
    }

    /// Calculate approximate latency percentiles from histogram bucket midpoints.
    fn calculateLatencyPercentiles(self: *RealTimeMetrics) LatencyPercentiles {
        // Bucket boundaries in ms: 1, 5, 10, 50, 100, 500, 1000, 5000+
        const bucket_midpoints_ms = [_]u32{ 1, 3, 7, 30, 75, 300, 750, 5000 };

        // Load bucket counts and calculate total
        var counts: [8]u64 = undefined;
        var total: u64 = 0;
        for (0..8) |i| {
            counts[i] = self.base.request_duration_buckets[i].load(.monotonic);
            total += counts[i];
        }

        if (total == 0) {
            return .{ .p50 = 0, .p95 = 0, .p99 = 0 };
        }

        // Find bucket index where cumulative count reaches percentile threshold
        const p50_bucket = findPercentileBucket(&counts, total, 50);
        const p95_bucket = findPercentileBucket(&counts, total, 95);
        const p99_bucket = findPercentileBucket(&counts, total, 99);

        return .{
            .p50 = bucket_midpoints_ms[p50_bucket],
            .p95 = bucket_midpoints_ms[p95_bucket],
            .p99 = bucket_midpoints_ms[p99_bucket],
        };
    }

    /// Find the bucket index where cumulative count reaches the percentile threshold.
    /// Returns last bucket (7) if threshold not reached within 8 iterations.
    fn findPercentileBucket(counts: *const [8]u64, total: u64, percentile: u8) u8 {
        assert(percentile > 0 and percentile <= 100);
        assert(total > 0);

        const threshold = (total * percentile) / 100;
        var cumulative: u64 = 0;

        for (0..8) |i| {
            cumulative += counts[i];
            if (cumulative >= threshold) {
                return @intCast(i);
            }
        }
        return 7; // Last bucket if threshold not reached
    }
};

// =============================================================================
// Tests
// =============================================================================

test "RealTimeMetrics init creates zeroed state" {
    const m = RealTimeMetrics.init();
    try std.testing.expectEqual(@as(u64, 0), m.base.requests_total.load(.monotonic));
    try std.testing.expectEqual(@as(i64, 0), m.base.connections_active.load(.monotonic));
}

test "RealTimeMetrics requestStart increments counter" {
    var m = RealTimeMetrics.init();
    m.requestStart();
    m.requestStart();
    try std.testing.expectEqual(@as(u64, 2), m.base.requests_total.load(.monotonic));
}

test "RealTimeMetrics requestEnd tracks status" {
    var m = RealTimeMetrics.init();
    m.requestStart();
    m.requestEnd(200, 5 * time.ns_per_ms);

    // 2xx bucket (index 1)
    try std.testing.expectEqual(@as(u64, 1), m.base.requests_by_status[1].load(.monotonic));
}

test "RealTimeMetrics requestEndWithUpstream tracks per-upstream" {
    var m = RealTimeMetrics.init();

    // Upstream 0: 2 requests, 1 error
    m.requestStart();
    m.requestEndWithUpstream(200, 10 * time.ns_per_ms, 0);
    m.requestStart();
    m.requestEndWithUpstream(500, 20 * time.ns_per_ms, 0);

    // Upstream 1: 1 request, no errors
    m.requestStart();
    m.requestEndWithUpstream(200, 5 * time.ns_per_ms, 1);

    try std.testing.expectEqual(@as(u64, 2), m.upstream_requests[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.upstream_errors[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.upstream_requests[1].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), m.upstream_errors[1].load(.monotonic));
}

test "RealTimeMetrics connectionOpened and connectionClosed" {
    var m = RealTimeMetrics.init();

    m.connectionOpened();
    m.connectionOpened();
    try std.testing.expectEqual(@as(i64, 2), m.base.connections_active.load(.monotonic));

    m.connectionClosed();
    try std.testing.expectEqual(@as(i64, 1), m.base.connections_active.load(.monotonic));
}

test "RealTimeMetrics snapshot captures state" {
    var m = RealTimeMetrics.init();

    // Add some traffic
    m.connectionOpened();
    m.requestStart();
    m.requestEndWithUpstream(200, 10 * time.ns_per_ms, 0);
    m.requestStart();
    m.requestEndWithUpstream(500, 20 * time.ns_per_ms, 0);

    const snap = m.snapshot();

    try std.testing.expectEqual(@as(u64, 2), snap.requests_total);
    try std.testing.expectEqual(@as(u64, 1), snap.errors_total); // 1 x 5xx
    try std.testing.expectEqual(@as(i64, 1), snap.connections_active);
    try std.testing.expect(snap.upstream_count >= 1);
    try std.testing.expectEqual(@as(u64, 2), snap.upstream_stats[0].requests_total);
    try std.testing.expectEqual(@as(u64, 1), snap.upstream_stats[0].errors_total);
}

test "RealTimeMetrics snapshot calculates rates" {
    var m = RealTimeMetrics.init();

    // First snapshot establishes baseline
    _ = m.snapshot();

    // Add traffic
    m.requestStart();
    m.requestEnd(200, 5 * time.ns_per_ms);
    m.requestStart();
    m.requestEnd(200, 5 * time.ns_per_ms);

    // Second snapshot calculates rates
    const snap = m.snapshot();

    // Should have positive rate (2 requests in short interval)
    try std.testing.expectEqual(@as(u64, 2), snap.requests_total);
    try std.testing.expect(snap.requests_per_sec > 0);
}

test "RealTimeMetrics latency percentiles with no data" {
    var m = RealTimeMetrics.init();
    const snap = m.snapshot();

    try std.testing.expectEqual(@as(u32, 0), snap.latency_p50_ms);
    try std.testing.expectEqual(@as(u32, 0), snap.latency_p95_ms);
    try std.testing.expectEqual(@as(u32, 0), snap.latency_p99_ms);
}

test "RealTimeMetrics latency percentiles with data" {
    var m = RealTimeMetrics.init();

    // Add requests in different latency buckets
    // Bucket 0 (<=1ms): 50 requests
    for (0..50) |_| {
        m.requestStart();
        m.requestEnd(200, 1 * time.ns_per_ms);
    }
    // Bucket 2 (6-10ms): 45 requests
    for (0..45) |_| {
        m.requestStart();
        m.requestEnd(200, 10 * time.ns_per_ms);
    }
    // Bucket 6 (501-1000ms): 5 requests
    for (0..5) |_| {
        m.requestStart();
        m.requestEnd(200, 1000 * time.ns_per_ms);
    }

    const snap = m.snapshot();

    // p50 should be in bucket 0 (1ms) - 50/100 = 50%
    try std.testing.expectEqual(@as(u32, 1), snap.latency_p50_ms);
    // p95 should be in bucket 2 (7ms midpoint) - 95/100 in first two buckets
    try std.testing.expectEqual(@as(u32, 7), snap.latency_p95_ms);
    // p99 should be in bucket 6 (750ms midpoint) - 99/100
    try std.testing.expectEqual(@as(u32, 750), snap.latency_p99_ms);
}

test "UpstreamStats healthy flag" {
    var m = RealTimeMetrics.init();

    // Upstream 0: healthy (no errors)
    for (0..10) |_| {
        m.requestStart();
        m.requestEndWithUpstream(200, 5 * time.ns_per_ms, 0);
    }

    // Upstream 1: unhealthy (>50% errors)
    for (0..3) |_| {
        m.requestStart();
        m.requestEndWithUpstream(200, 5 * time.ns_per_ms, 1);
    }
    for (0..7) |_| {
        m.requestStart();
        m.requestEndWithUpstream(500, 5 * time.ns_per_ms, 1);
    }

    const snap = m.snapshot();

    try std.testing.expect(snap.upstream_stats[0].healthy == true);
    try std.testing.expect(snap.upstream_stats[1].healthy == false);
}
