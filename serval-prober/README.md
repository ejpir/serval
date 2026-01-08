# serval-prober

Background health probing for backend upstreams.

## Purpose

Active health checking module that runs HTTP/HTTPS GET probes against unhealthy backends in a background thread. Uses serval-client for HTTP/HTTPS health probes. Supports both plain HTTP and TLS-encrypted HTTPS backends. Used by load balancers and routers to detect when failed backends recover.

## Exports

- `ProberContext` - Context struct for background prober thread
- `probeLoop` - Background loop function (run in separate thread)

## Usage

```zig
const prober = @import("serval-prober");
const ssl = @import("serval-tls").ssl;
const std = @import("std");

// Initialize OpenSSL (once, at startup)
ssl.init();

// Create SSL context for TLS probes (if any upstreams use TLS)
const client_ctx = try ssl.createClientCtx();
defer ssl.SSL_CTX_free(client_ctx);

// Create context for prober thread
const ctx = prober.ProberContext{
    .upstreams = &upstreams,
    .health = &health_state,
    .probe_running = &probe_running,
    .probe_interval_ms = 5000,
    .probe_timeout_ms = 2000,
    .health_path = "/health",
    .client_ctx = client_ctx,  // Pass null if no TLS upstreams
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
    upstreams: []const Upstream,            // Backends to probe
    health: *HealthState,                   // Health state to update
    probe_running: *std.atomic.Value(bool), // Shutdown signal
    probe_interval_ms: u32,                 // Interval between probe cycles
    probe_timeout_ms: u32,                  // Per-probe TCP timeout
    health_path: []const u8,                // HTTP path to probe
    client_ctx: ?*ssl.SSL_CTX,              // Caller-provided SSL context for TLS probes
};
```

**SSL Context Lifecycle:**
- Caller creates `SSL_CTX` via `ssl.createClientCtx()` before starting prober
- Pass `client_ctx` to `ProberContext` for TLS probes
- Caller frees `SSL_CTX` via `ssl.SSL_CTX_free()` after stopping prober
- Pass `null` if no upstreams use TLS

## Design

### Passive vs Active Probing

- **Passive**: Handler hooks (e.g., `onLog`) track success/failure from real traffic
- **Active**: This module probes unhealthy backends that aren't receiving traffic

Active probing only targets unhealthy backends - healthy ones get passive checks via normal traffic.

### Probe Protocol

The prober uses `serval-client.Client` for HTTP requests. DNS resolution, TCP connection, and TLS handshake are all handled by serval-client. The prober simply:

1. Build a `Request` struct with the health path and Host header
2. Call `client.request()` to perform the probe
3. Check for `2xx` status in the response
4. On success, call `health.recordSuccess(idx)`

For HTTPS upstreams (upstream.tls = true), serval-client automatically performs TLS handshake with SNI set to the upstream host.

### Blocking I/O

Uses blocking I/O via serval-client. This is intentional:
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

| Module | Purpose |
|--------|---------|
| serval-core | Upstream type, config |
| serval-client | HTTP/1.1 client for probes |
| serval-health | HealthState for recording results |

**Note:** serval-client handles DNS resolution, TCP connections, and TLS handshakes internally. Requires linking OpenSSL/LibreSSL (`-lssl -lcrypto`) for TLS support.

## TigerStyle Compliance

- Assertions on function entry (S1)
- Explicit types: u32 for timeouts, u64 for intervals (S2)
- Bounded loop over upstreams slice (S4)
- Errors logged at debug level, not swallowed (S6)
- Units in names: probe_interval_ms, timeout_ms (Y3)
- Resource grouping: socket + defer close (C5)
