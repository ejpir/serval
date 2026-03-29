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

/// Re-export of the background prober module.
/// Provides the legacy `ProberContext` and `probeLoop` entry point built on top of the shared scheduler and adapters.
/// This constant has no runtime behavior; it is the module handle for the background prober API.
pub const prober = @import("prober.zig");
/// Re-export of the shared probe scheduler module.
/// Exposes the scheduler context, probe adapter contract, and bounded run loop used by background probing.
/// This constant has no runtime behavior; it exists to group the scheduler API under one module handle.
pub const scheduler = @import("scheduler.zig");
/// Re-export of the protocol-specific probe adapter module.
/// Provides the HTTP, TCP, and UDP probe adapters plus their context and mode types.
/// This constant has no runtime behavior; it is the module handle for adapter APIs.
pub const adapters = @import("adapters.zig");

/// Re-export of the legacy background prober context.
/// Stores borrowed upstream, health, resolver, and shutdown state plus probe timing and HTTP path configuration.
/// Caller-owned resources such as the resolver, health state, and SSL context must remain valid for the full probe loop lifetime.
pub const ProberContext = prober.ProberContext;
/// Re-export of `prober.probeLoop`, the background health-probe entry point.
/// Builds the I/O runtime, client, and HTTP adapter state from `ProberContext`, then runs the shared scheduler loop.
/// Returns only after the shutdown flag is observed false; it does not report errors to the caller.
pub const probeLoop = prober.probeLoop;
/// Re-export of the scheduler context used by `runProbeSchedulerLoop`.
/// Carries the borrowed upstream slice, shared health state, shutdown flag, cadence, and probe adapter.
/// All referenced state must outlive scheduler use; the struct itself does not allocate or transfer ownership.
pub const SchedulerContext = scheduler.SchedulerContext;
/// Re-export of the scheduler's type-erased probe adapter contract.
/// Binds an opaque context pointer to a probe callback that returns `bool` instead of an error union.
/// The adapter owns no resources; callers must keep the referenced context valid for each invocation.
pub const ProbeAdapter = scheduler.ProbeAdapter;
/// Re-export of `scheduler.runLoopWithIo`, the bounded probe scheduler loop.
/// Runs the unhealthy-probe cycle using the provided scheduler context and I/O implementation until `probe_running` becomes false.
/// The function returns no error; probe failures are handled by the adapter and scheduler internals.
pub const runProbeSchedulerLoop = scheduler.runLoopWithIo;
/// Context for `tcpConnectProbe` adapter calls.
/// Holds a borrowed `Client` pointer that must remain valid for every probe invocation using this context.
/// The context owns no resources and is only a lightweight handle for adapter state.
pub const TcpProbeAdapterContext = adapters.TcpProbeAdapterContext;
/// Context for `httpProbe` adapter calls.
/// Holds borrowed references to the shared HTTP `Client` and the probe path; both must remain valid for the full adapter lifetime.
/// The adapter does not take ownership of either field and does not allocate on behalf of the context.
pub const UdpProbeAdapterContext = adapters.UdpProbeAdapterContext;
/// UDP probe execution mode for `udpProbe`.
/// `passive_only` skips active network I/O, `active_send` sends a probe packet, and `active_send_expect` also waits for a matching response.
/// The enum does not own any resources; it only selects probe behavior.
pub const UdpProbeMode = adapters.UdpProbeMode;
/// Re-export of `adapters.httpProbe` for HTTP health checks.
/// The opaque context must reference a valid `HttpProbeAdapterContext` with a non-empty `health_path`.
/// Returns `true` for 2xx responses and `false` for request, transport, or non-2xx failures.
pub const httpProbe = adapters.httpProbe;
/// Re-export of `adapters.tcpConnectProbe` for TCP connect health checks.
/// The opaque context must reference a valid `TcpProbeAdapterContext` whose client remains alive for the call.
/// Returns `true` only when `client.connect` succeeds; any connect error is reported as `false`.
pub const tcpConnectProbe = adapters.tcpConnectProbe;
/// Re-export of `adapters.udpProbe` for UDP health-check callers.
/// Accepts an opaque adapter context pointer that must reference a valid `UdpProbeAdapterContext`.
/// Returns `true` only when the configured UDP probe condition succeeds; failures and unsupported passive mode return `false`.
pub const udpProbe = adapters.udpProbe;

test {
    _ = prober;
    _ = scheduler;
    _ = adapters;
}
