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
    pub const VERSION_BUF_SIZE: u8 = 16; // "TLSv1.3" etc
    pub const CIPHER_BUF_SIZE: u8 = 128; // "TLS_AES_256_GCM_SHA384" etc
    pub const ALPN_BUF_SIZE: u8 = 32; // "h2", "http/1.1"
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

    /// Returns the negotiated TLS version string (e.g., "TLSv1.3").
    pub fn version(self: *const Self) []const u8 {
        assert(self.version_len <= VERSION_BUF_SIZE); // S1: postcondition
        return self.version_buf[0..self.version_len];
    }

    /// Returns the negotiated cipher suite name (e.g., "TLS_AES_256_GCM_SHA384").
    pub fn cipher(self: *const Self) []const u8 {
        assert(self.cipher_len <= CIPHER_BUF_SIZE); // S1: postcondition
        return self.cipher_buf[0..self.cipher_len];
    }

    /// Returns the negotiated ALPN protocol, or null if none.
    pub fn alpn(self: *const Self) ?[]const u8 {
        assert(self.alpn_len <= ALPN_BUF_SIZE); // S1: postcondition
        if (self.alpn_len == 0) return null;
        return self.alpn_buf[0..self.alpn_len];
    }

    /// Returns the peer certificate subject, or null if no peer cert.
    pub fn certSubject(self: *const Self) ?[]const u8 {
        assert(self.cert_subject_len <= CERT_NAME_BUF_SIZE); // S1: postcondition
        if (self.cert_subject_len == 0) return null;
        return self.cert_subject_buf[0..self.cert_subject_len];
    }

    /// Returns the peer certificate issuer, or null if no peer cert.
    pub fn certIssuer(self: *const Self) ?[]const u8 {
        assert(self.cert_issuer_len <= CERT_NAME_BUF_SIZE); // S1: postcondition
        if (self.cert_issuer_len == 0) return null;
        return self.cert_issuer_buf[0..self.cert_issuer_len];
    }

    /// Returns handshake duration in milliseconds (for span attributes).
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
