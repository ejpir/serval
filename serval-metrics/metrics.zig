// lib/serval-metrics/metrics.zig
//! Metrics Interface
//!
//! Comptime interface for request metrics.
//! Includes NoopMetrics (zero overhead) and PrometheusMetrics.
//! TigerStyle: Atomic counters, fixed-size histograms, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const time = @import("serval-core").time;

// =============================================================================
// Metrics Interface Verification
// =============================================================================

/// Verifies at compile time that `M` provides the required metrics hooks.
/// Emits a compile error if `requestStart` or `requestEnd` is missing.
/// This check runs at comptime and does not instantiate or call `M`.
pub fn verifyMetrics(comptime M: type) void {
    if (!@hasDecl(M, "requestStart")) {
        @compileError("Metrics must implement: pub fn requestStart(self) void");
    }
    if (!@hasDecl(M, "requestEnd")) {
        @compileError("Metrics must implement: pub fn requestEnd(self, status: u16, duration_ns: u64) void");
    }
}

// =============================================================================
// NoopMetrics (zero overhead)
// =============================================================================

/// No-op metrics implementation for callers that do not want to collect data.
/// Each method satisfies the shared metrics interface but intentionally
/// performs no work and returns no errors.
pub const NoopMetrics = struct {
    /// Records the start of a request without storing any metrics.
    /// This no-op form exists to satisfy the shared metrics API.
    /// The call never returns an error.
    pub fn requestStart(_: *@This()) void {}
    /// Records the end of a request without storing any metrics.
    /// This no-op form accepts the HTTP status and request duration so it can
    /// satisfy the shared metrics API.
    /// The call never returns an error.
    pub fn requestEnd(_: *@This(), _: u16, _: u64) void {}
    /// Increments the active-connection gauge by one.
    /// This is a no-op implementation for metrics backends that do not track
    /// connection state.
    /// The call never returns an error.
    pub fn connectionOpened(_: *@This()) void {}
    /// Decrements the active-connection gauge by one.
    /// This is a no-op implementation for metrics backends that do not track
    /// connection state.
    /// The call never returns an error.
    pub fn connectionClosed(_: *@This()) void {}
    /// Records upstream latency for the public metrics interface.
    /// This implementation intentionally does nothing.
    /// Per-upstream latency is tracked by `RealTimeMetrics` instead.
    pub fn upstreamLatency(_: *@This(), _: u32, _: u64) void {}
};

// =============================================================================
// PrometheusMetrics (fixed-size, atomic)
// =============================================================================

/// Atomic Prometheus-compatible request and connection metrics.
/// Stores counters, gauges, and fixed histogram buckets initialized to zero.
/// Updates use monotonic atomic operations and do not allocate or return errors.
pub const PrometheusMetrics = struct {
    // Counters
    requests_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    requests_by_status: [6]std.atomic.Value(u64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 6,

    // Gauges
    connections_active: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    // Histograms (buckets: 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s)
    request_duration_buckets: [8]std.atomic.Value(u64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 8,

    /// Increments the total request counter.
    /// Uses a monotonic atomic update and does not report an error.
    /// Call this at request start before any outcome is known.
    pub fn requestStart(self: *@This()) void {
        _ = self.requests_total.fetchAdd(1, .monotonic);
    }

    /// Records the end of a request in the status and duration buckets.
    /// Status codes are grouped into 1xx-5xx classes, with all other values
    /// placed into the final `other` bucket.
    /// Duration is classified by `durationToBucket` and both counters are updated
    /// with monotonic atomic operations.
    pub fn requestEnd(self: *@This(), status: u16, duration_ns: u64) void {
        // Status bucket (0=1xx, 1=2xx, 2=3xx, 3=4xx, 4=5xx, 5=other)
        // TigerStyle: Use u8 for bucket index (only 6 buckets).
        const status_bucket: u8 = if (status >= 100 and status < 600)
            @intCast((status / 100) - 1)
        else
            5;
        _ = self.requests_by_status[status_bucket].fetchAdd(1, .monotonic);

        // Duration histogram
        const bucket = durationToBucket(duration_ns);
        _ = self.request_duration_buckets[bucket].fetchAdd(1, .monotonic);
    }

    /// Increments the active-connection gauge by one.
    /// Uses a monotonic atomic update and does not report an error.
    /// Call this when a connection becomes active.
    pub fn connectionOpened(self: *@This()) void {
        _ = self.connections_active.fetchAdd(1, .monotonic);
    }

    /// Decrements the active-connection gauge by one.
    /// Uses a monotonic atomic update and does not report an error.
    /// The caller is responsible for ensuring the counter does not underflow.
    pub fn connectionClosed(self: *@This()) void {
        _ = self.connections_active.fetchSub(1, .monotonic);
    }

    /// Records upstream latency for the public metrics interface.
    /// This implementation is intentionally a no-op because per-upstream latency
    /// is tracked by `RealTimeMetrics` instead of this metrics backend.
    pub fn upstreamLatency(_: *@This(), _: u32, _: u64) void {
        // Intentionally empty - per-upstream latency tracked in RealTimeMetrics.
    }

    // TigerStyle: Return u8 for bucket index (only 8 buckets).
    fn durationToBucket(duration_ns: u64) u8 {
        const ms = duration_ns / time.ns_per_ms;
        return switch (ms) {
            0...1 => 0,
            2...5 => 1,
            6...10 => 2,
            11...50 => 3,
            51...100 => 4,
            101...500 => 5,
            501...1000 => 6,
            else => 7,
        };
    }

    /// Get total requests count
    pub fn getRequestsTotal(self: *@This()) u64 {
        return self.requests_total.load(.monotonic);
    }

    /// Get active connections count
    pub fn getActiveConnections(self: *@This()) i64 {
        return self.connections_active.load(.monotonic);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "NoopMetrics compiles and runs" {
    var m = NoopMetrics{};
    m.requestStart();
    m.requestEnd(200, 1000);
    m.connectionOpened();
    m.connectionClosed();
}

test "PrometheusMetrics counts requests" {
    var m = PrometheusMetrics{};

    m.requestStart();
    m.requestStart();
    try std.testing.expectEqual(@as(u64, 2), m.getRequestsTotal());

    m.requestEnd(200, 5 * time.ns_per_ms);
    m.requestEnd(404, 100 * time.ns_per_ms);

    // 2xx bucket
    try std.testing.expectEqual(@as(u64, 1), m.requests_by_status[1].load(.monotonic));
    // 4xx bucket
    try std.testing.expectEqual(@as(u64, 1), m.requests_by_status[3].load(.monotonic));
}

test "PrometheusMetrics duration buckets" {
    var m = PrometheusMetrics{};

    m.requestEnd(200, 1 * time.ns_per_ms); // bucket 0
    m.requestEnd(200, 10 * time.ns_per_ms); // bucket 2
    m.requestEnd(200, 1000 * time.ns_per_ms); // bucket 6

    try std.testing.expectEqual(@as(u64, 1), m.request_duration_buckets[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.request_duration_buckets[2].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.request_duration_buckets[6].load(.monotonic));
}

test "verifyMetrics accepts valid metrics" {
    comptime verifyMetrics(NoopMetrics);
    comptime verifyMetrics(PrometheusMetrics);
}
