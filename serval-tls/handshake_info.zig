//! TLS Handshake Information
//!
//! Captures metadata from a completed TLS handshake for tracing and diagnostics.
//! All buffers are fixed-size (TigerStyle: no allocation after init).

const std = @import("std");
const assert = std.debug.assert;

/// Information extracted from a completed TLS handshake.
/// All string fields use fixed buffers with length tracking.
pub const HandshakeInfo = struct {
    const Self = @This();

    // Buffer size constants (TigerStyle: named constants)
    /// Fixed buffer size for storing a TLS version string representation.
    /// Callers that format or copy version text should provide a buffer of at least `VERSION_BUF_SIZE` bytes.
    /// This constant has no runtime failure behavior; using a smaller buffer may cause downstream formatting/copy errors.
    pub const VERSION_BUF_SIZE: u8 = 16; // "TLSv1.3" etc
    /// Fixed byte capacity for cipher-related buffers in handshake metadata.
    /// Callers that provide storage for cipher data should allocate at least this many bytes.
    /// Stored as `u8` to keep the size explicit and bounded at compile time.
    pub const CIPHER_BUF_SIZE: u8 = 128; // "TLS_AES_256_GCM_SHA384" etc
    /// Fixed ALPN buffer capacity, in bytes, used by this module.
    /// Value is `32` and is stored as `u8`, so it is suitable for length/capacity checks in `u8`-typed APIs.
    /// Callers allocating ALPN storage should provide at least `ALPN_BUF_SIZE` bytes.
    /// This declaration cannot fail and does not perform allocation or ownership transfer.
    pub const ALPN_BUF_SIZE: u8 = 32; // "h2", "http/1.1"
    /// Maximum capacity, in bytes, of each fixed X.509 name buffer in `HandshakeInfo`.
    /// Applies to both `cert_subject_buf` and `cert_issuer_buf`.
    /// Any stored name length must remain `<= CERT_NAME_BUF_SIZE` to satisfy accessor assertions.
    /// This is a size constant only; it performs no allocation and returns no errors.
    pub const CERT_NAME_BUF_SIZE: u16 = 256; // X509 name strings

    // Protocol info
    version_buf: [VERSION_BUF_SIZE]u8 = undefined,
    version_len: u8 = 0,
    cipher_buf: [CIPHER_BUF_SIZE]u8 = undefined,
    cipher_len: u8 = 0,

    // Session state
    resumed: bool = false,

    // ALPN (if negotiated)
    alpn_buf: [ALPN_BUF_SIZE]u8 = undefined,
    alpn_len: u8 = 0,

    // Peer certificate (server mode: client cert, client mode: server cert)
    cert_subject_buf: [CERT_NAME_BUF_SIZE]u8 = undefined,
    cert_subject_len: u16 = 0,
    cert_issuer_buf: [CERT_NAME_BUF_SIZE]u8 = undefined,
    cert_issuer_len: u16 = 0,

    // Timing (TigerStyle: _ns suffix for nanoseconds)
    handshake_duration_ns: u64 = 0,

    // Connection context
    client_mode: bool = false,

    // kTLS status (kernel TLS offload)
    ktls_enabled: bool = false,

    /// Returns the negotiated TLS version string (for example `"TLSv1.3"`).
    /// The returned slice borrows from `self.version_buf` and remains valid while `self` is unchanged.
    /// This accessor is infallible and performs no allocation.
    pub fn version(self: *const Self) []const u8 {
        assert(self.version_len <= VERSION_BUF_SIZE); // S1: postcondition
        return self.version_buf[0..self.version_len];
    }

    /// Returns the negotiated cipher suite name (for example `"TLS_AES_256_GCM_SHA384"`).
    /// The returned slice borrows from `self.cipher_buf` and remains valid while `self` is unchanged.
    /// This accessor is infallible and performs no allocation.
    pub fn cipher(self: *const Self) []const u8 {
        assert(self.cipher_len <= CIPHER_BUF_SIZE); // S1: postcondition
        return self.cipher_buf[0..self.cipher_len];
    }

    /// Returns the negotiated ALPN protocol, or `null` when ALPN was not negotiated.
    /// Any non-null slice borrows from `self.alpn_buf` and remains valid while `self` is unchanged.
    /// This accessor is infallible and performs no allocation.
    pub fn alpn(self: *const Self) ?[]const u8 {
        assert(self.alpn_len <= ALPN_BUF_SIZE); // S1: postcondition
        if (self.alpn_len == 0) return null;
        return self.alpn_buf[0..self.alpn_len];
    }

    /// Returns the peer certificate subject, or `null` when no peer certificate was captured.
    /// Any non-null slice borrows from `self.cert_subject_buf` and remains valid while `self` is unchanged.
    /// This accessor is infallible and performs no allocation.
    pub fn certSubject(self: *const Self) ?[]const u8 {
        assert(self.cert_subject_len <= CERT_NAME_BUF_SIZE); // S1: postcondition
        if (self.cert_subject_len == 0) return null;
        return self.cert_subject_buf[0..self.cert_subject_len];
    }

    /// Returns the peer certificate issuer, or `null` when no peer certificate was captured.
    /// Any non-null slice borrows from `self.cert_issuer_buf` and remains valid while `self` is unchanged.
    /// This accessor is infallible and performs no allocation.
    pub fn certIssuer(self: *const Self) ?[]const u8 {
        assert(self.cert_issuer_len <= CERT_NAME_BUF_SIZE); // S1: postcondition
        if (self.cert_issuer_len == 0) return null;
        return self.cert_issuer_buf[0..self.cert_issuer_len];
    }

    /// Returns handshake duration converted from stored nanoseconds to whole milliseconds.
    /// This is intended for telemetry attributes and does not mutate state.
    /// Infallible conversion: no allocation and no error path.
    pub fn handshakeDurationMs(self: *const Self) i64 {
        const ns_per_ms: u64 = 1_000_000;
        return @intCast(self.handshake_duration_ns / ns_per_ms);
    }
};

test "HandshakeInfo accessors" {
    var info = HandshakeInfo{};

    // Set version
    const ver = "TLSv1.3";
    @memcpy(info.version_buf[0..ver.len], ver);
    info.version_len = ver.len;
    try std.testing.expectEqualStrings("TLSv1.3", info.version());

    // Set cipher
    const ciph = "TLS_AES_256_GCM_SHA384";
    @memcpy(info.cipher_buf[0..ciph.len], ciph);
    info.cipher_len = ciph.len;
    try std.testing.expectEqualStrings("TLS_AES_256_GCM_SHA384", info.cipher());

    // ALPN not set - returns null
    try std.testing.expect(info.alpn() == null);

    // Set ALPN
    const alpn_proto = "h2";
    @memcpy(info.alpn_buf[0..alpn_proto.len], alpn_proto);
    info.alpn_len = alpn_proto.len;
    try std.testing.expectEqualStrings("h2", info.alpn().?);

    // Cert not set - returns null
    try std.testing.expect(info.certSubject() == null);
    try std.testing.expect(info.certIssuer() == null);

    // Duration conversion
    info.handshake_duration_ns = 5_500_000; // 5.5ms
    try std.testing.expectEqual(@as(i64, 5), info.handshakeDurationMs());
}
