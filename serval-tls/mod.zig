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
pub const ssl = @import("ssl.zig");
pub const ServerAlpnHook = ssl.ServerAlpnHook;
pub const ServerAlpnHookInput = ssl.ServerAlpnHookInput;
pub const ServerAlpnHookDecision = ssl.ServerAlpnHookDecision;
pub const ServerCertHook = ssl.ServerCertHook;
pub const ServerCertHookInput = ssl.ServerCertHookInput;
pub const ServerCertHookDecision = ssl.ServerCertHookDecision;

// TLS stream abstraction
const stream = @import("stream.zig");
pub const TLSStream = stream.TLSStream;
pub const HandshakeInfo = stream.HandshakeInfo;

// Reloadable server TLS context generations
const reloadable_ctx = @import("reloadable_ctx.zig");
pub const ReloadableServerCtx = reloadable_ctx.ReloadableServerCtx;
pub const ReloadableServerCtxError = reloadable_ctx.Error;

// kTLS (Kernel TLS) offload - Linux-only optimization
pub const ktls = @import("ktls.zig");

test {
    _ = @import("ssl.zig");
    _ = @import("stream.zig");
    _ = @import("handshake_info.zig");
    _ = @import("reloadable_ctx.zig");
    _ = @import("ktls.zig");
}
