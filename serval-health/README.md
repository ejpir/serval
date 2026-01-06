# serval-health

Lock-free health tracking for backend upstreams.

## Purpose

Provides atomic health state tracking with threshold-based transitions. Designed for concurrent access from multiple I/O threads without contention. Inspired by Pingora's simple boolean health model (no explicit circuit breaker state machine).

## Exports

- `SharedHealthState` - Lock-free atomic bitmap for health status
- `HealthTracker` - Threshold-based state transitions
- `BackendIndex` - Type alias for upstream index (u6)

## Usage

```zig
const health = @import("serval-health");
const config = @import("serval-core").config;

// Initialize shared state (all backends start healthy)
var state = health.SharedHealthState.init();

// Create tracker with thresholds
var tracker = health.HealthTracker.init(
    &state,
    config.DEFAULT_UNHEALTHY_THRESHOLD,  // 3 consecutive failures
    config.DEFAULT_HEALTHY_THRESHOLD,     // 2 consecutive successes
);

// On request success
tracker.recordSuccess(upstream_idx);

// On request failure
tracker.recordFailure(upstream_idx);

// Query health for upstream selection
if (tracker.isHealthy(upstream_idx)) {
    // Use this backend
}

// Find healthy backend for failover
if (tracker.findFirstHealthy(exclude_idx)) |healthy_idx| {
    // Use healthy_idx as failover
}

// Round-robin among healthy backends
const n = counter.fetchAdd(1, .monotonic);
if (tracker.findNthHealthy(n)) |idx| {
    return upstreams[idx];
}
```

## SharedHealthState

```zig
pub const SharedHealthState = struct {
    health_bitmap: std.atomic.Value(u64),  // Bit N = 1 means healthy
    failure_counts: [MAX_UPSTREAMS]std.atomic.Value(u8),
    success_counts: [MAX_UPSTREAMS]std.atomic.Value(u8),

    pub fn init() Self
    pub fn isHealthy(self: *const Self, idx: BackendIndex) bool
    pub fn countHealthy(self: *const Self) u32
    pub fn findFirstHealthy(self: *const Self, exclude_idx: ?BackendIndex) ?BackendIndex
    pub fn findNthHealthy(self: *const Self, n: u32) ?BackendIndex
    pub fn markHealthy(self: *Self, idx: BackendIndex) void
    pub fn markUnhealthy(self: *Self, idx: BackendIndex) void
    pub fn reset(self: *Self) void
};
```

## HealthTracker

```zig
pub const HealthTracker = struct {
    state: *SharedHealthState,
    unhealthy_threshold: u8,
    healthy_threshold: u8,

    pub fn init(state: *SharedHealthState, unhealthy_threshold: u8, healthy_threshold: u8) Self
    pub fn recordSuccess(self: *Self, idx: u6) void  // inline hot path
    pub fn recordFailure(self: *Self, idx: u6) void  // inline hot path
    pub fn isHealthy(self: *const Self, idx: u6) bool
    pub fn countHealthy(self: *const Self) u32
    pub fn findFirstHealthy(self: *const Self, exclude_idx: ?u6) ?u6
    pub fn findNthHealthy(self: *const Self, n: u32) ?u6
};
```

## Design

### Why No Circuit Breaker State Machine?

Following Pingora's approach: simple boolean health with consecutive threshold counters is equally effective and simpler to reason about:

- **Healthy** + N consecutive failures → **Unhealthy**
- **Unhealthy** + M consecutive successes → **Healthy**

No explicit open/half-open/closed states. The threshold counters prevent flapping on transient failures.

### Lock-Free Operations

- Health bitmap uses atomic `fetchOr`/`fetchAnd` (no CAS loops needed)
- O(1) health check via single bit test
- O(1) count via hardware `@popCount`
- O(1) first healthy via hardware `@ctz` (count trailing zeros)
- O(popcount) for Nth healthy selection

### Cache-Line Alignment

The bitmap is aligned to 64 bytes to prevent false sharing when different threads access health state concurrently.

## Configuration

From `serval-core/config.zig`:

```zig
pub const DEFAULT_UNHEALTHY_THRESHOLD: u8 = 3;   // 3 failures → unhealthy
pub const DEFAULT_HEALTHY_THRESHOLD: u8 = 2;     // 2 successes → healthy
pub const DEFAULT_PROBE_INTERVAL_MS: u32 = 5000; // For active probing
pub const DEFAULT_PROBE_TIMEOUT_MS: u32 = 2000;
pub const DEFAULT_HEALTH_PATH: []const u8 = "/";
```

## Implementation Status

| Feature | Status |
|---------|--------|
| Atomic health bitmap | Complete |
| Threshold-based transitions | Complete |
| Concurrent access safety | Complete |
| Active health probes | Not implemented (handler layer responsibility) |

## Integration with serval-lb

```zig
// In handler
pub fn selectUpstream(self: *Self, ctx: *Context, req: *const Request) ?Upstream {
    const healthy_count = self.tracker.countHealthy();
    if (healthy_count == 0) return null;

    const n = self.counter.fetchAdd(1, .monotonic);
    const idx = self.tracker.findNthHealthy(n) orelse return null;
    return self.upstreams[idx];
}
```

## TigerStyle Compliance

- Cache-line aligned bitmap prevents false sharing
- All loops bounded by MAX_UPSTREAMS (64)
- Explicit types: u6 for indices, u8 for counters, u32 for counts
- ~2 assertions per function (preconditions on idx bounds)
- Inline hot paths for recordSuccess/recordFailure
- Saturating arithmetic prevents counter overflow
