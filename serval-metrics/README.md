# serval-metrics

Request metrics interface with zero-overhead and Prometheus implementations.

## Purpose

Provides compile-time pluggable metrics collection. Supports both zero-overhead (production where metrics not needed) and atomic counter implementations.

## Exports

- `NoopMetrics` - Zero-overhead, does nothing
- `PrometheusMetrics` - Atomic counters and histograms
- `RealTimeMetrics` - Extended PrometheusMetrics with per-upstream tracking and rate calculation
- `StatsSnapshot` - Point-in-time metrics snapshot
- `UpstreamStats` - Per-upstream statistics
- `verifyMetrics` - Compile-time interface verification

## Usage

```zig
const metrics_mod = @import("serval-metrics");

// Zero overhead - compiles away
var metrics = metrics_mod.NoopMetrics{};

// Or with actual collection
var metrics = metrics_mod.PrometheusMetrics{};

metrics.requestStart();
// ... handle request ...
metrics.requestEnd(status_code, duration_ns);
```

## Metrics Interface

Any metrics implementation must provide:

```zig
pub fn requestStart(self) void
pub fn requestEnd(self, status: u16, duration_ns: u64) void
```

Optional (PrometheusMetrics provides):
- `connectionOpened()` / `connectionClosed()`
- `upstreamLatency(upstream_idx, duration_ns)`
- `getRequestsTotal()` / `getActiveConnections()`

## RealTimeMetrics

Real-time statistics collector with per-upstream tracking and rate calculation. Extends PrometheusMetrics with upstream-level granularity.

### Methods

- `init()` - Create a new RealTimeMetrics instance
- `snapshot()` - Take a point-in-time snapshot of all metrics
- `requestStart()` - Record request start
- `requestEnd(status, duration_ns)` - Record request completion
- `requestEndWithUpstream(status, duration_ns, upstream_idx)` - Record request with upstream tracking
- `connectionOpened()` - Track connection opened
- `connectionClosed()` - Track connection closed

### Usage Example

```zig
const metrics_mod = @import("serval-metrics");

var metrics = metrics_mod.RealTimeMetrics.init();

// Track requests with upstream info
metrics.requestStart();
metrics.requestEndWithUpstream(200, duration_ns, upstream_idx);

// Get a snapshot for display/export
const snap = metrics.snapshot();
std.debug.print("RPS: {d:.1}\n", .{snap.requests_per_sec});
std.debug.print("P99 latency: {}ms\n", .{snap.latency_p99_ms});
```

## StatsSnapshot

Point-in-time metrics snapshot returned by `RealTimeMetrics.snapshot()`.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `requests_total` | u64 | Total request count |
| `errors_total` | u64 | Total 4xx + 5xx responses |
| `connections_active` | i64 | Current open connections |
| `requests_per_sec` | f64 | Request rate (calculated from deltas) |
| `errors_per_sec` | f64 | Error rate (calculated from deltas) |
| `latency_p50_ms` | u32 | 50th percentile latency |
| `latency_p95_ms` | u32 | 95th percentile latency |
| `latency_p99_ms` | u32 | 99th percentile latency |
| `upstream_stats` | [MAX_UPSTREAMS]UpstreamStats | Per-upstream statistics |
| `upstream_count` | u8 | Highest active upstream index + 1 |

## UpstreamStats

Per-upstream statistics within a snapshot.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `requests_total` | u64 | Requests to this upstream |
| `requests_per_sec` | f64 | Request rate to this upstream |
| `errors_total` | u64 | 5xx responses from this upstream |
| `avg_latency_ms` | u32 | Average latency to this upstream |
| `healthy` | bool | True if error rate < 50% |

## PrometheusMetrics Details

### Counters
- `requests_total` - Total request count
- `requests_by_status[6]` - Bucketed by status class (1xx-5xx, other)

### Gauges
- `connections_active` - Current open connections

### Histograms
- `request_duration_buckets[8]` - Latency buckets (1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s+)

## Implementation Status

| Feature | Status |
|---------|--------|
| NoopMetrics | Complete |
| PrometheusMetrics counters | Complete |
| Duration histograms | Complete |
| Connection tracking | Complete |
| RealTimeMetrics | Complete |
| Per-upstream tracking | Complete |
| Rate calculation | Complete |
| Latency percentiles | Complete |
| Prometheus exposition format | Not implemented |

## TigerStyle Compliance

- Atomic counters for thread safety
- Fixed-size histogram buckets
- Explicit u8 for bucket indices (only 6-8 buckets)
- No dynamic allocation
