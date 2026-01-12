// lib/serval-metrics/metrics.zig
//! Metrics Interface
//!
//! Comptime interface for request metrics.
//! Includes NoopMetrics (zero overhead) and PrometheusMetrics.
//! TigerStyle: Atomic counters, fixed-size histograms, no allocation.

const std = @import("std");
const assert = std.debug.assert;

// =============================================================================
// Metrics Interface Verification
// =============================================================================

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

pub const NoopMetrics = struct {
    pub fn requestStart(_: *@This()) void {}
    pub fn requestEnd(_: *@This(), _: u16, _: u64) void {}
    pub fn connectionOpened(_: *@This()) void {}
    pub fn connectionClosed(_: *@This()) void {}
    pub fn upstreamLatency(_: *@This(), _: u32, _: u64) void {}
};

// =============================================================================
// PrometheusMetrics (fixed-size, atomic)
// =============================================================================

pub const PrometheusMetrics = struct {
    // Counters
    requests_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    requests_by_status: [6]std.atomic.Value(u64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 6,

    // Gauges
    connections_active: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    // Histograms (buckets: 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s)
    request_duration_buckets: [8]std.atomic.Value(u64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 8,

    pub fn requestStart(self: *@This()) void {
        _ = self.requests_total.fetchAdd(1, .monotonic);
    }

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

    pub fn connectionOpened(self: *@This()) void {
        _ = self.connections_active.fetchAdd(1, .monotonic);
    }

    pub fn connectionClosed(self: *@This()) void {
        _ = self.connections_active.fetchSub(1, .monotonic);
    }

    pub fn upstreamLatency(_: *@This(), _: u32, _: u64) void {
        // Intentionally empty - per-upstream latency tracked in RealTimeMetrics.
    }

    // TigerStyle: Return u8 for bucket index (only 8 buckets).
    fn durationToBucket(duration_ns: u64) u8 {
        const ms = duration_ns / std.time.ns_per_ms;
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

    m.requestEnd(200, 5 * std.time.ns_per_ms);
    m.requestEnd(404, 100 * std.time.ns_per_ms);

    // 2xx bucket
    try std.testing.expectEqual(@as(u64, 1), m.requests_by_status[1].load(.monotonic));
    // 4xx bucket
    try std.testing.expectEqual(@as(u64, 1), m.requests_by_status[3].load(.monotonic));
}

test "PrometheusMetrics duration buckets" {
    var m = PrometheusMetrics{};

    m.requestEnd(200, 1 * std.time.ns_per_ms); // bucket 0
    m.requestEnd(200, 10 * std.time.ns_per_ms); // bucket 2
    m.requestEnd(200, 1000 * std.time.ns_per_ms); // bucket 6

    try std.testing.expectEqual(@as(u64, 1), m.request_duration_buckets[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.request_duration_buckets[2].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.request_duration_buckets[6].load(.monotonic));
}

test "verifyMetrics accepts valid metrics" {
    comptime verifyMetrics(NoopMetrics);
    comptime verifyMetrics(PrometheusMetrics);
}
