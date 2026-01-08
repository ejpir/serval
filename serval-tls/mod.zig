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

// TLS stream abstraction
const stream = @import("stream.zig");
pub const TLSStream = stream.TLSStream;
pub const HandshakeInfo = stream.HandshakeInfo;

// kTLS (Kernel TLS) offload - Linux-only optimization
pub const ktls = @import("ktls.zig");

test {
    _ = @import("ssl.zig");
    _ = @import("stream.zig");
    _ = @import("handshake_info.zig");
    _ = @import("ktls.zig");
}
