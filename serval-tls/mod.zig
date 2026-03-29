// serval-tls/mod.zig
//! Serval TLS - Transport Layer Security
//!
//! Layer 1 (Protocol) - TLS termination and origination.
//! Provides TLS handshake, encryption, and stream abstraction.
//! Uses BoringSSL for crypto operations.
//!
//! Features:
//! - TLS stream abstraction (userspace encryption via BoringSSL)
//! - kTLS offload support (kernel encryption on Linux 4.13+)

// BoringSSL bindings
/// Public namespace for low-level TLS/SSL bindings and constants.
/// Imports `ssl.zig`, which exposes manual BoringSSL `extern` declarations
/// and small wrapper helpers (for example SNI and kTLS BIO checks).
/// This is a compile-time module alias; member access does not allocate,
/// transfer ownership, or itself return Zig errors.
pub const ssl = @import("ssl.zig");
/// Re-export of [`ssl.ServerAlpnHook`] for the `serval-tls` public API.
/// Use this alias when configuring server-side ALPN selection callbacks in this module.
/// Behavior, preconditions, and error semantics are exactly those of `ssl.ServerAlpnHook`.
pub const ServerAlpnHook = ssl.ServerAlpnHook;
/// Re-export of [`ssl.ServerAlpnHookInput`], passed to `ServerAlpnHook` during server ALPN selection.
/// `sni` is the resolved server name (or `null` if unavailable), and the boolean flags indicate which ALPN protocols the client offered.
/// The value is read-only hook input with borrowed data; do not assume ownership or persist referenced slices beyond the callback.
/// This type does not encode failures itself; hook outcomes are expressed via `ServerAlpnHookDecision`.
pub const ServerAlpnHookInput = ssl.ServerAlpnHookInput;
/// Re-export of `ssl.ServerAlpnHookDecision` for server-side ALPN hook results.
/// Use this as the callback return decision during TLS ALPN negotiation.
/// This is a type alias only; variant meanings, preconditions, and error-handling
/// implications are defined by `ssl.ServerAlpnHookDecision`.
pub const ServerAlpnHookDecision = ssl.ServerAlpnHookDecision;
/// Alias for [`ssl.ServerCertHook`] exposed by `serval-tls`.
/// Use this type when wiring server-certificate hook callbacks in this module.
/// Behavior, callback contract, ownership/lifetime requirements, and any error
/// semantics are exactly those defined by `ssl.ServerCertHook`.
pub const ServerCertHook = ssl.ServerCertHook;
/// Input passed to `ServerCertHook` during TLS server-name certificate selection.
/// `sni` is the ClientHello SNI hostname, or `null` when no server name is available.
/// `sni` is borrowed, read-only callback data; do not store it beyond the hook invocation.
/// Re-export alias of `ssl.ServerCertHookInput`.
pub const ServerCertHookInput = ssl.ServerCertHookInput;
/// Decision returned by `ServerCertHook` during SNI-based certificate selection.
/// `.default_ctx` keeps the listener's current `SSL_CTX`, `.reject` aborts the handshake,
/// and `.override_ctx` switches the connection to the provided `*SSL_CTX`.
/// `override_ctx` is borrowed (no ownership transfer); the pointed context must remain valid for callback use.
pub const ServerCertHookDecision = ssl.ServerCertHookDecision;

// TLS stream abstraction
const stream = @import("stream.zig");
/// Re-export of `stream.TLSStream`, Serval’s TLS connection abstraction.
/// Construct via `TLSStream.initServer` or `TLSStream.initClient`, which perform the TLS handshake and return `!TLSStream`.
/// The type unifies userspace TLS (`*ssl.SSL`) and kTLS-backed operation behind the same `read`/`write` interface.
/// Ownership/lifetime: `close()` frees TLS/SSL resources, but the caller still owns the socket fd and must close it.
/// Error behavior is explicit: fallible APIs return typed errors for TLS/SSL failures and retry/reset conditions (for example `WouldBlock`).
pub const TLSStream = stream.TLSStream;
/// Re-export of `stream.HandshakeInfo`, used by `TLSStream` to report completed-handshake metadata.
/// This is a pure type alias: fields, methods, and invariants are exactly those of `stream.HandshakeInfo`.
/// Values use fixed-size internal buffers and are plain value data with no heap ownership transfer.
/// Declaring or referencing this alias has no runtime side effects and no error behavior.
pub const HandshakeInfo = stream.HandshakeInfo;

// Reloadable server TLS context generations
const reloadable_ctx = @import("reloadable_ctx.zig");
/// Alias of `reloadable_ctx.ReloadableServerCtx`, a mutex-protected manager for reloadable server `SSL_CTX` generations.
/// Keeps one active context and bounded retired slots; `activate` atomically switches the active generation.
/// `acquire` returns a lease to the current context, and every lease must be paired with `release`; retired contexts are freed only after last release.
/// `deinit` requires no outstanding leases (asserted) and frees all owned `SSL_CTX` instances; fallible operations return `NoActiveContext`, `NoFreeSlot`, or `RefCountOverflow`.
pub const ReloadableServerCtx = reloadable_ctx.ReloadableServerCtx;
/// Error set for reloadable server TLS context management APIs.
/// This is an alias of `reloadable_ctx.Error` and is returned by operations such as
/// `ReloadableServerCtx.acquire` and `ReloadableServerCtx.activate` (and composed into
/// `activateFromPemFiles`); cases are `NoActiveContext`, `RefCountOverflow`, and `NoFreeSlot`.
pub const ReloadableServerCtxError = reloadable_ctx.Error;

// kTLS (Kernel TLS) offload - Linux-only optimization
/// Linux kTLS support namespace, re-exported from `ktls.zig`.
/// Import this via `serval-tls.ktls` to access kTLS-specific types and helpers.
/// This is a compile-time module alias (`@import`), so it has no runtime ownership or lifetime semantics.
/// Any errors or platform constraints are defined by the declarations inside `ktls.zig`.
pub const ktls = @import("ktls.zig");

test {
    _ = @import("ssl.zig");
    _ = @import("stream.zig");
    _ = @import("handshake_info.zig");
    _ = @import("reloadable_ctx.zig");
    _ = @import("ktls.zig");
}
