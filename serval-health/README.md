# serval-health

Lock-free health tracking for backend upstreams.

## Purpose

Provides atomic health state tracking with threshold-based transitions. Designed for concurrent access from multiple I/O threads without contention. Inspired by Pingora's simple boolean health model (no explicit circuit breaker state machine).

## Exports

Primary (use these):
- `HealthState` - Unified health state with embedded threshold tracking (embeddable)
- `UpstreamIndex` - Type alias for upstream index (u6)
- `MAX_UPSTREAMS` - Maximum supported backends (64)

Legacy (for transition):
- `SharedHealthState` - Lock-free atomic bitmap (pointer-based)
- `HealthTracker` - Threshold wrapper for SharedHealthState

## Usage

### Recommended: HealthState (Embeddable)

```zig
const health = @import("serval-health");

// Initialize with backend count and thresholds
var state = health.HealthState.init(
    3,  // backend_count
    3,  // unhealthy_threshold (consecutive failures)
    2,  // healthy_threshold (consecutive successes)
);

// On request success
state.recordSuccess(upstream_idx);

// On request failure
state.recordFailure(upstream_idx);

// Query health
if (state.isHealthy(upstream_idx)) {
    // Use this backend
}

// Round-robin among healthy backends
const n = counter.fetchAdd(1, .monotonic);
if (state.findNthHealthy(n)) |idx| {
    return upstreams[idx];
}
```

### Legacy: SharedHealthState + HealthTracker

```zig
const upstream_count: u8 = 3;
var shared = health.SharedHealthState.initWithCount(upstream_count);
var tracker = health.HealthTracker.init(&shared, 3, 2);

tracker.recordSuccess(0);
tracker.recordFailure(1);
```

## HealthState

Unified health state designed for embedding in handlers (no pointers required):

```zig
pub const HealthState = struct {
    health_bitmap: std.atomic.Value(u64) align(64),  // Cache-line aligned
    failure_counts: [MAX_UPSTREAMS]u8,
    success_counts: [MAX_UPSTREAMS]u8,
    backend_count: u8,
    unhealthy_threshold: u8,
    healthy_threshold: u8,

    pub fn init(backend_count: u8, unhealthy_threshold: u8, healthy_threshold: u8) Self
    pub fn recordSuccess(self: *Self, idx: UpstreamIndex) void   // inline
    pub fn recordFailure(self: *Self, idx: UpstreamIndex) void   // inline
    pub fn isHealthy(self: *const Self, idx: UpstreamIndex) bool // inline
    pub fn countHealthy(self: *const Self) u32
    pub fn findNthHealthy(self: *const Self, n: u32) ?UpstreamIndex
    pub fn findFirstHealthy(self: *const Self, exclude_idx: ?UpstreamIndex) ?UpstreamIndex
    pub fn reset(self: *Self) void
};
```

## File Structure

```
serval-health/
├── mod.zig              # Module exports
├── health_state.zig     # HealthState (unified, embeddable) - PREFERRED
├── state.zig            # SharedHealthState (legacy, pointer-based)
├── tracker.zig          # HealthTracker (legacy, wraps SharedHealthState)
├── tests.zig            # Comprehensive tests
└── integration_tests.zig # Integration scenarios
```

## Design

### Why No Circuit Breaker State Machine?

Following Pingora's approach: simple boolean health with consecutive threshold counters is equally effective and simpler to reason about:

- **Healthy** + N consecutive failures -> **Unhealthy**
- **Unhealthy** + M consecutive successes -> **Healthy**

No explicit open/half-open/closed states. The threshold counters prevent flapping on transient failures.

### Lock-Free Operations

- Health bitmap uses atomic `fetchOr`/`fetchAnd` (no CAS loops needed)
- O(1) health check via single bit test
- O(1) count via hardware `@popCount`
- O(1) first healthy via hardware `@ctz` (count trailing zeros)
- O(popcount) for Nth healthy selection

### Cache-Line Alignment

The bitmap is aligned to 64 bytes to prevent false sharing when different threads access health state concurrently.

### Fast Paths

`recordSuccess()` and `recordFailure()` have fast paths:
- If already in target state, return immediately
- No counter increments for already-healthy/already-unhealthy backends

## Configuration

From `serval-core/config.zig`:

```zig
pub const DEFAULT_UNHEALTHY_THRESHOLD: u8 = 3;   // 3 failures -> unhealthy
pub const DEFAULT_HEALTHY_THRESHOLD: u8 = 2;     // 2 successes -> healthy
pub const MAX_UPSTREAMS: u8 = 64;                // Bitmap width
```

## Implementation Status

| Feature | Status |
|---------|--------|
| Atomic health bitmap | Complete |
| Threshold-based transitions | Complete |
| Concurrent access safety | Complete |
| Embeddable HealthState | Complete |
| Active health probes | Handler responsibility (see serval-lb) |

## TigerStyle Compliance

- Cache-line aligned bitmap prevents false sharing (P4)
- All loops bounded by MAX_UPSTREAMS (S4)
- Explicit types: u6 for indices, u8 for counters, u32 for counts (S2)
- ~2 assertions per function (S1)
- Inline hot paths for recordSuccess/recordFailure (P4)
- Saturating arithmetic prevents counter overflow (S5)
- std.mem.zeroes for initialization (S5)
