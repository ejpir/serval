//! serval-prober - Background Health Probing
//!
//! Active health checks for unhealthy backends using HTTP GET requests.
//! Runs in a background thread with configurable interval and timeout.
//! Supports both plain HTTP and HTTPS (TLS) backends.
//!
//! TLS Note: Caller provides SSL_CTX via ProberContext.client_ctx.
//! The SSL_CTX lifetime is owned by the caller (create before starting prober,
//! free after stopping prober).
//!
//! TigerStyle: Blocking sockets with explicit timeouts, bounded operations.

pub const prober = @import("prober.zig");
pub const scheduler = @import("scheduler.zig");
pub const adapters = @import("adapters.zig");

pub const ProberContext = prober.ProberContext;
pub const probeLoop = prober.probeLoop;
pub const SchedulerContext = scheduler.SchedulerContext;
pub const ProbeAdapter = scheduler.ProbeAdapter;
pub const runProbeSchedulerLoop = scheduler.runLoopWithIo;
pub const TcpProbeAdapterContext = adapters.TcpProbeAdapterContext;
pub const UdpProbeAdapterContext = adapters.UdpProbeAdapterContext;
pub const UdpProbeMode = adapters.UdpProbeMode;
pub const httpProbe = adapters.httpProbe;
pub const tcpConnectProbe = adapters.tcpConnectProbe;
pub const udpProbe = adapters.udpProbe;

test {
    _ = prober;
    _ = scheduler;
    _ = adapters;
}
