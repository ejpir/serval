// lib/serval-proxy/mod.zig
//! Serval Proxy - Upstream Forwarding
//!
//! Zero-copy upstream forwarding with connection pooling.
//! TigerStyle: Splice for zero-copy, bounded loops.

/// Re-exports the proxy type namespace from `types.zig`.
/// Use this as `proxy.types` to access public type declarations without importing `types.zig` directly.
/// This is a compile-time module alias and introduces no runtime behavior or error paths.
pub const types = @import("types.zig");
/// Canonical error set returned by upstream forwarding APIs in `serval-proxy`.
/// Re-export of `types.ForwardError`; this alias does not add or change variants.
/// Covers upstream connect/address/DNS failures, send/recv/splice I/O failures, and stale pooled connections.
/// Also includes validation/policy failures such as `HeadersTooLarge`, `InvalidResponse`, `RequestBodyTooLarge`, and `UnsupportedProtocol`.
pub const ForwardError = types.ForwardError;
/// Public re-export of [`types.ForwardResult`](types.zig), the result record for an upstream forward attempt.
/// Contains response metadata (`status`, `response_bytes`, `connection_reused`) plus timing fields in nanoseconds.
/// Timing and `upstream_local_port` fields default to `0` when not populated by the forward path.
/// This declaration is a pure type alias: it performs no allocation, ownership transfer, or error-producing work.
pub const ForwardResult = types.ForwardResult;
/// Re-export of `types.BodyInfo`, used to describe request-body framing for streaming proxy forwarding.
/// `framing` is exclusive (`content_length`, `chunked`, or `none`) and prevents mixed invalid body states.
/// `bytes_already_read` and `initial_body` report bytes already consumed during header parsing.
/// `initial_body` is a borrowed slice (typically parser-buffer backed), so its storage must stay valid while it is consumed.
/// This type is metadata-only and does not allocate or return errors by itself.
pub const BodyInfo = types.BodyInfo;
/// Public re-export of the proxy upstream wire protocol enum.
/// Use this for selected/negotiated HTTP protocol values (`.h1`, `.h2c`, `.h2`).
/// Semantics are identical to `serval-core.HttpProtocol`; this is a type alias, not a wrapper.
/// Value type only: no allocation, ownership transfer, or error behavior.
pub const Protocol = @import("serval-core").HttpProtocol;

/// Re-exports the proxy tunneling module from `tunnel.zig`.
/// Use this namespace to access tunnel-related types and functions via `proxy.tunnel`.
/// Behavior, preconditions, ownership, and errors are defined by the individual declarations inside `tunnel.zig`.
pub const tunnel = @import("tunnel.zig");
/// Public type alias for `tunnel.TunnelStats`, returned by tunnel relay paths to summarize a completed session.
/// Tracks directional byte counters, total tunnel duration in nanoseconds, and final `termination` reason.
/// Value-only record: fields are owned by the struct value (no borrowed memory or lifetime coupling).
/// This alias adds no runtime behavior, allocation, or error path beyond `tunnel.TunnelStats` itself.
pub const TunnelStats = tunnel.TunnelStats;
/// Re-export of [`tunnel.Termination`] used as the public tunnel-shutdown signal type in `serval-proxy`.
/// This alias introduces no new behavior, ownership, or lifetime rules beyond the original declaration.
/// See `tunnel.Termination` for exact semantics, valid states, and any associated error/cleanup behavior.
pub const TunnelTermination = tunnel.Termination;
/// Re-exports the HTTP/1 module namespace from `h1/mod.zig`.
/// Use this constant to access the proxy's HTTP/1 types and helpers via `proxy.h1`.
/// This is a compile-time module alias only; it performs no runtime allocation or I/O.
pub const h1 = @import("h1/mod.zig");

/// Re-exports the HTTP/2 proxy namespace from `h2/mod.zig` as `proxy.h2`.
/// Provides access to HTTP/2 binding and stream-bridge declarations (for example `BindingTable` and `StreamBridge`).
/// This is a compile-time module alias only: it performs no runtime work, allocation, or ownership transfer.
/// Any preconditions, lifetimes, and errors are defined by the individual APIs inside `h2/mod.zig`.
pub const h2 = @import("h2/mod.zig");
/// Alias for [`h2.Binding`], the proxy's HTTP/2 binding type.
/// Use this exported name when referring to HTTP/2 listener/bind configuration in `serval-proxy`.
/// This declaration is a pure type re-export and does not allocate, own resources, or return errors.
pub const H2Binding = h2.Binding;
/// Public alias of `h2.BindingTable`, the HTTP/2 downstream-to-upstream stream binding map.
/// The table is fixed-capacity (`serval-core.config.H2_MAX_CONCURRENT_STREAMS`) and stores bindings by value.
/// Construct caller-owned storage with the underlying `h2.BindingTable.initInto()` API, then mutate it via `put` and the remove/lookup helpers.
/// This alias has no runtime behavior or error path; method-level failures come from `h2.BindingTable` operations.
pub const H2BindingTable = h2.BindingTable;
/// Re-export of `h2.BindingError` for proxy-facing HTTP/2 binding APIs.
/// Any function returning this error set propagates binding failures from the underlying `h2` layer.
/// This alias does not add, remove, or redefine error variants; see `h2.BindingError` for exact cases.
pub const H2BindingError = h2.BindingError;
/// Public re-export of [`h2.StreamBridge`](h2/mod.zig), the HTTP/2 stream-bridging state machine used by the proxy.
/// Use this alias when opening, binding, and polling downstream/upstream H2 stream pairs via the `serval-proxy` API.
/// Ownership/lifetime rules are defined by `h2.StreamBridge`: initialize caller-owned storage with `initInto(client, sessions)`, and keep those borrowed `Client` and `H2UpstreamSessionPool` pointers valid for the bridge lifetime.
/// This declaration is a pure type alias and introduces no additional allocation or error behavior by itself.
pub const H2StreamBridge = h2.StreamBridge;
/// Canonical error set returned by `H2StreamBridge` operations in `serval-proxy`.
/// This is a pure re-export of `h2.StreamBridgeError` (`h2.bridge.Error`), so variants and semantics are identical.
/// Includes bridge-local failures (`SessionNotFound`, `UnexpectedReceiveAction`) plus propagated binding/session errors.
/// Alias declaration only; it performs no work, allocates nothing, and has no ownership/lifetime effects.
pub const H2StreamBridgeError = h2.StreamBridgeError;
/// Public alias of [`h2.StreamBridgeOpenResult`](h2/mod.zig), returned by `H2StreamBridge.openDownstreamStream`.
/// Holds the established stream binding (`binding`) and upstream connection-acquisition stats (`connect`).
/// Value-only type alias: this declaration performs no work and has no additional preconditions.
/// No ownership transfer or error behavior is introduced beyond the source type.
pub const H2StreamBridgeOpenResult = h2.StreamBridgeOpenResult;
/// Public re-export of `h2.StreamBridgeReceiveAction`, the tagged union returned by `H2StreamBridge` receive/poll APIs.
/// Encodes mapped upstream events: `.none`, `.response_headers`, `.response_data`, `.response_trailers`, `.stream_reset`, or `.connection_close`.
/// This alias adds no runtime behavior or error path; failures are reported by the function returning this type.
/// Ownership and lifetime of any referenced payload data follow the underlying `h2.StreamBridgeReceiveAction` producer APIs.
pub const H2StreamBridgeReceiveAction = h2.StreamBridgeReceiveAction;

/// Re-exports the `forwarder.zig` module under `proxy.forwarder`.
/// Use this namespace to access forwarding types/functions as `forwarder.*`.
/// This is a compile-time module import and does not allocate or transfer ownership at runtime.
pub const forwarder = @import("forwarder.zig");
/// Re-export of [`forwarder.Forwarder`] from this module's public API.
/// This is a type alias, so behavior, preconditions, ownership/lifetime,
/// and error semantics are exactly those documented on `forwarder.Forwarder`.
pub const Forwarder = forwarder.Forwarder;

test {
    _ = @import("types.zig");
    _ = @import("connect.zig");
    _ = @import("h1/mod.zig");
    _ = @import("h2/mod.zig");
    _ = @import("tunnel.zig");
    _ = @import("forwarder.zig");
}
