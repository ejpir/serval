//! serval-prober - Background Health Probing
//!
//! Active health checks for unhealthy backends using HTTP GET requests.
//! Runs in a background thread with configurable interval and timeout.
//!
//! TigerStyle: Blocking sockets with explicit timeouts, bounded operations.

pub const prober = @import("prober.zig");
pub const ProberContext = prober.ProberContext;
pub const probeLoop = prober.probeLoop;

test {
    _ = prober;
}
