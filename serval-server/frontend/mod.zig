//! Frontend orchestration helpers.

/// Re-exports the dispatch frontend implementation for this package.
/// Use this module to access the dispatch-specific frontend entry points and helpers.
/// This declaration does not allocate or transfer ownership; it only exposes the submodule.
pub const dispatch = @import("dispatch.zig");
/// Re-exports the generic HTTP/2 frontend implementation for this package.
/// Use this module to access the shared generic H2 frontend types and helpers.
/// This declaration does not allocate or transfer ownership; it only exposes the submodule.
pub const generic_h2 = @import("generic_h2.zig");
/// Public import of the frontend bootstrap helpers module.
/// Exposes transport-readiness validation and listen-address preflight resolution.
/// Use this namespace when validating startup configuration before binding sockets.
pub const bootstrap = @import("bootstrap.zig");
/// Public import of the TCP frontend runtime module.
/// Exposes TCP runtime initialization, execution, and TCP-specific error types.
/// Use this namespace when working with TCP listener and connection management.
pub const tcp_runtime = @import("tcp_runtime.zig");
/// Public import of the UDP frontend runtime module.
/// Exposes UDP runtime initialization, execution, and UDP-specific error types.
/// Use this namespace when working with UDP listener and session management.
pub const udp_runtime = @import("udp_runtime.zig");
/// Public import of the frontend orchestrator module.
/// Exposes the runtime orchestrator and its transport-startup error set.
/// Use this namespace when working with transport lifecycle management.
pub const orchestrator = @import("orchestrator.zig");

/// Dispatch outcome for a TLS-terminated frontend connection.
/// `continue_h1` keeps HTTP/1 parsing, `generic_h2` routes to the generic HTTP/2 path, and `terminated_h2` routes to a terminated HTTP/2 handler.
/// Use this with the ALPN dispatch helpers to separate protocol selection from transport mechanics.
pub const TlsDispatchAction = dispatch.TlsDispatchAction;
/// Alias for `dispatch.selectTlsAlpnDispatchAction`.
/// Reads the negotiated ALPN from an optional TLS stream and chooses the frontend dispatch path.
/// Treats a missing TLS stream as no ALPN and never allocates or returns an error.
pub const selectTlsAlpnDispatchAction = dispatch.selectTlsAlpnDispatchAction;
/// Alias for `generic_h2.tryServeTlsAlpnConnection`.
/// Attempts to serve a TLS connection on the generic HTTP/2 frontend when the peer negotiated `h2`.
/// Returns `false` when there is no TLS stream, the ALPN is not `h2`, the handler already owns explicit H2 termination, or bridge-pool allocation fails.
pub const tryServeTlsAlpnConnection = generic_h2.tryServeTlsAlpnConnection;
/// Alias for `bootstrap.FrontendBootstrapError`.
/// Error set used by frontend bootstrap validation and listen-address resolution.
/// Contains transport-validation and address-parsing failures.
pub const FrontendBootstrapError = bootstrap.FrontendBootstrapError;
/// Alias for `bootstrap.validateTransportReadiness`.
/// Checks whether the transport-related frontend configuration is valid for startup.
/// Returns `error.InvalidTransportConfig` when the transport configuration fails validation.
pub const validateTransportReadiness = bootstrap.validateTransportReadiness;
/// Alias for `bootstrap.preflightAndResolveListenAddress`.
/// Validates frontend transport readiness and resolves the configured listen host and port to an IP address.
/// Returns `error.InvalidTransportConfig` or `error.InvalidAddress` when validation or parsing fails.
pub const preflightAndResolveListenAddress = bootstrap.preflightAndResolveListenAddress;
/// Alias for `tcp_runtime.Runtime`.
/// Holds the TCP frontend listener state, upstream selection state, connection counters, and runtime limits.
/// Initialize it before calling `run`; it borrows the referenced config memory for the lifetime of the runtime.
pub const TcpRuntime = tcp_runtime.Runtime;
/// Alias for `tcp_runtime.RuntimeError`.
/// Returned by TCP runtime initialization and execution when configuration, listener setup, or socket creation fails.
/// See `tcp_runtime.Runtime` for the operations that produce this error set.
pub const TcpRuntimeError = tcp_runtime.RuntimeError;
/// Alias for `udp_runtime.Runtime`.
/// Holds the UDP frontend listener state, upstream selection state, session tracking, and runtime counters.
/// Initialize it before calling `run`; it copies transport metadata but keeps referenced config memory owned by the caller.
pub const UdpRuntime = udp_runtime.Runtime;
/// Alias for `udp_runtime.RuntimeError`.
/// Returned by UDP runtime initialization and execution when configuration, listener setup, or DNS resolution fails.
/// See `udp_runtime.Runtime` for the operations that produce this error set.
pub const UdpRuntimeError = udp_runtime.RuntimeError;
/// Alias for `orchestrator.RuntimeOrchestrator`.
/// Coordinates frontend transport startup and shutdown for a server instance.
/// Owns no transport configuration memory; it stores references and thread handles managed by the caller.
pub const RuntimeOrchestrator = orchestrator.RuntimeOrchestrator;
/// Alias for `orchestrator.OrchestratorError`.
/// Returned when a frontend transport cannot be initialized or its worker thread cannot be spawned.
/// Use the specific variant to distinguish TCP versus UDP and init versus thread-start failures.
pub const FrontendOrchestratorError = orchestrator.OrchestratorError;
