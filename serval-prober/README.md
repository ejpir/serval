# serval-prober

Background health probing for backend upstreams.

## Purpose

Active health checking module that runs HTTP GET probes against unhealthy backends in a background thread. Used by load balancers and routers to detect when failed backends recover.

## Exports

- `ProberContext` - Context struct for background prober thread
- `probeLoop` - Background loop function (run in separate thread)

## Usage

```zig
const prober = @import("serval-prober");
const std = @import("std");

// Create context for prober thread
const ctx = prober.ProberContext{
    .upstreams = &upstreams,
    .health = &health_state,
    .probe_running = &probe_running,
    .probe_interval_ms = 5000,
    .probe_timeout_ms = 2000,
    .health_path = "/health",
};

// Start prober in background thread
probe_running.store(true, .release);
const thread = try std.Thread.spawn(.{}, prober.probeLoop, .{ctx});

// Stop prober
probe_running.store(false, .release);
thread.join();
```

## ProberContext

```zig
pub const ProberContext = struct {
    upstreams: []const Upstream,           // Backends to probe
    health: *HealthState,                  // Health state to update
    probe_running: *std.atomic.Value(bool), // Shutdown signal
    probe_interval_ms: u32,                // Interval between probe cycles
    probe_timeout_ms: u32,                 // Per-probe TCP timeout
    health_path: []const u8,               // HTTP path to probe
};
```

## Design

### Passive vs Active Probing

- **Passive**: Handler hooks (e.g., `onLog`) track success/failure from real traffic
- **Active**: This module probes unhealthy backends that aren't receiving traffic

Active probing only targets unhealthy backends - healthy ones get passive checks via normal traffic.

### Probe Protocol

1. TCP connect with timeout
2. Send `GET {health_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n`
3. Read response, check for `2xx` status
4. On success, call `health.recordSuccess(idx)`

### Blocking I/O

Uses blocking sockets with `SO_RCVTIMEO`/`SO_SNDTIMEO` timeouts. This is intentional:
- Background thread, not on hot path
- Simple, predictable behavior
- No async machinery needed

## File Structure

```
serval-prober/
├── mod.zig     # Module exports
└── prober.zig  # Prober implementation
```

## Dependencies

- `serval-core` - Upstream type, config
- `serval-net` - parseIPv4 for address parsing
- `serval-health` - HealthState for recording results

## TigerStyle Compliance

- Assertions on function entry (S1)
- Explicit types: u32 for timeouts, u64 for intervals (S2)
- Bounded loop over upstreams slice (S4)
- Errors logged at debug level, not swallowed (S6)
- Units in names: probe_interval_ms, timeout_ms (Y3)
- Resource grouping: socket + defer close (C5)
