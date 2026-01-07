// lib/serval-tls/mod.zig
//! Serval TLS - Transport Layer Security
//!
//! Layer 1 (Protocol) - TLS termination and origination.
//! Provides TLS handshake, encryption, and stream abstraction.
//! Uses BoringSSL for crypto operations.
//! Phase 1: Userspace-only (kTLS deferred to Phase 2).

// BoringSSL bindings
pub const ssl = @import("ssl.zig");

// TLS stream abstraction
pub const TLSStream = @import("stream.zig").TLSStream;

test {
    _ = @import("ssl.zig");
    _ = @import("stream.zig");
}
