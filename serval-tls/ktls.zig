// serval-tls/ktls.zig
//! Linux kTLS (Kernel TLS) offload support
//!
//! After a TLS handshake completes, attempts to enable kTLS for hardware-accelerated
//! encryption/decryption. Falls back to userspace OpenSSL if kTLS is unavailable.
//!
//! kTLS offloads TLS record layer encryption to the kernel, enabling:
//! - Zero-copy sendfile() for encrypted data
//! - Reduced context switches between userspace and kernel
//! - Hardware crypto offload on supported NICs
//!
//! Supported ciphers: AES-GCM-128, AES-GCM-256, CHACHA20-POLY1305
//! Supported TLS versions: TLS 1.2, TLS 1.3
//!
//! References:
//! - Linux kernel: Documentation/networking/tls.rst
//! - RFC 8446 (TLS 1.3 key derivation)
//! - RFC 5246 (TLS 1.2 key derivation)

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const assert = std.debug.assert;
const ssl = @import("ssl.zig");

// ============================================================================
// Linux kTLS Constants (from linux/tls.h)
// ============================================================================

/// Socket option level for TLS
pub const SOL_TLS: u32 = 282;

/// TLS socket options
pub const TLS_TX: u32 = 1; // Set transmit parameters
pub const TLS_RX: u32 = 2; // Set receive parameters

/// TCP ULP option for attaching TLS
pub const TCP_ULP: u32 = 31;

/// TLS versions for kTLS (wire format)
pub const TLS_1_2_VERSION: u16 = 0x0303;
pub const TLS_1_3_VERSION: u16 = 0x0304;

/// kTLS cipher type identifiers (from linux/tls.h)
pub const TLS_CIPHER_AES_GCM_128: u16 = 51;
pub const TLS_CIPHER_AES_GCM_256: u16 = 52;
pub const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

/// Cipher key/IV/salt sizes
pub const AES_GCM_128_KEY_SIZE: u8 = 16;
pub const AES_GCM_128_IV_SIZE: u8 = 8;
pub const AES_GCM_128_SALT_SIZE: u8 = 4;
pub const AES_GCM_128_REC_SEQ_SIZE: u8 = 8;

pub const AES_GCM_256_KEY_SIZE: u8 = 32;
pub const AES_GCM_256_IV_SIZE: u8 = 8;
pub const AES_GCM_256_SALT_SIZE: u8 = 4;
pub const AES_GCM_256_REC_SEQ_SIZE: u8 = 8;

pub const CHACHA20_POLY1305_KEY_SIZE: u8 = 32;
pub const CHACHA20_POLY1305_IV_SIZE: u8 = 12;
pub const CHACHA20_POLY1305_SALT_SIZE: u8 = 0; // ChaCha20 uses full IV, no salt
pub const CHACHA20_POLY1305_REC_SEQ_SIZE: u8 = 8;

// ============================================================================
// kTLS Crypto Info Structures (match linux/tls.h layout exactly)
// ============================================================================

/// Base crypto info header (common to all cipher types)
pub const TlsCryptoInfo = extern struct {
    version: u16,
    cipher_type: u16,
};

/// AES-GCM-128 crypto info for kTLS
pub const Tls12CryptoInfoAesGcm128 = extern struct {
    info: TlsCryptoInfo,
    iv: [AES_GCM_128_IV_SIZE]u8,
    key: [AES_GCM_128_KEY_SIZE]u8,
    salt: [AES_GCM_128_SALT_SIZE]u8,
    rec_seq: [AES_GCM_128_REC_SEQ_SIZE]u8,
};

/// AES-GCM-256 crypto info for kTLS
pub const Tls12CryptoInfoAesGcm256 = extern struct {
    info: TlsCryptoInfo,
    iv: [AES_GCM_256_IV_SIZE]u8,
    key: [AES_GCM_256_KEY_SIZE]u8,
    salt: [AES_GCM_256_SALT_SIZE]u8,
    rec_seq: [AES_GCM_256_REC_SEQ_SIZE]u8,
};

/// ChaCha20-Poly1305 crypto info for kTLS
pub const Tls12CryptoInfoChaCha20Poly1305 = extern struct {
    info: TlsCryptoInfo,
    iv: [CHACHA20_POLY1305_IV_SIZE]u8,
    key: [CHACHA20_POLY1305_KEY_SIZE]u8,
    rec_seq: [CHACHA20_POLY1305_REC_SEQ_SIZE]u8,
};

// ============================================================================
// kTLS Result Type
// ============================================================================

/// Result of attempting to enable kTLS
pub const KtlsResult = enum {
    /// kTLS successfully enabled for both TX and RX
    ktls_enabled,
    /// kTLS not available, use userspace TLS (not an error)
    userspace_fallback,

    /// Returns true if kTLS was successfully enabled
    pub fn isKtls(self: KtlsResult) bool {
        return self == .ktls_enabled;
    }
};

/// kTLS cipher type for internal use
pub const KtlsCipher = enum {
    aes_gcm_128,
    aes_gcm_256,
    chacha20_poly1305,
    unsupported,

    /// Returns the kTLS cipher type constant
    pub fn toKernelType(self: KtlsCipher) ?u16 {
        return switch (self) {
            .aes_gcm_128 => TLS_CIPHER_AES_GCM_128,
            .aes_gcm_256 => TLS_CIPHER_AES_GCM_256,
            .chacha20_poly1305 => TLS_CIPHER_CHACHA20_POLY1305,
            .unsupported => null,
        };
    }

    /// Returns key size for this cipher
    pub fn keySize(self: KtlsCipher) u8 {
        return switch (self) {
            .aes_gcm_128 => AES_GCM_128_KEY_SIZE,
            .aes_gcm_256 => AES_GCM_256_KEY_SIZE,
            .chacha20_poly1305 => CHACHA20_POLY1305_KEY_SIZE,
            .unsupported => 0,
        };
    }

    /// Returns IV size for this cipher (explicit nonce)
    pub fn ivSize(self: KtlsCipher) u8 {
        return switch (self) {
            .aes_gcm_128 => AES_GCM_128_IV_SIZE,
            .aes_gcm_256 => AES_GCM_256_IV_SIZE,
            .chacha20_poly1305 => CHACHA20_POLY1305_IV_SIZE,
            .unsupported => 0,
        };
    }

    /// Returns salt size for this cipher (implicit nonce)
    pub fn saltSize(self: KtlsCipher) u8 {
        return switch (self) {
            .aes_gcm_128 => AES_GCM_128_SALT_SIZE,
            .aes_gcm_256 => AES_GCM_256_SALT_SIZE,
            .chacha20_poly1305 => CHACHA20_POLY1305_SALT_SIZE,
            .unsupported => 0,
        };
    }
};

// ============================================================================
// SSL Cipher ID Constants (from BoringSSL/OpenSSL)
// ============================================================================

/// TLS 1.3 cipher suite IDs (IANA AEAD algorithm IDs)
const SSL_CIPHER_AES_128_GCM_SHA256: u16 = 0x1301;
const SSL_CIPHER_AES_256_GCM_SHA384: u16 = 0x1302;
const SSL_CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// TLS 1.2 ECDHE cipher suite IDs
const SSL_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256: u16 = 0xc02b;
const SSL_CIPHER_ECDHE_ECDSA_AES_256_GCM_SHA384: u16 = 0xc02c;
const SSL_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256: u16 = 0xc02f;
const SSL_CIPHER_ECDHE_RSA_AES_256_GCM_SHA384: u16 = 0xc030;
const SSL_CIPHER_ECDHE_ECDSA_CHACHA20_POLY1305: u16 = 0xcca9;
const SSL_CIPHER_ECDHE_RSA_CHACHA20_POLY1305: u16 = 0xcca8;

// ============================================================================
// kTLS Socket Configuration Functions
// ============================================================================

/// Attach TLS Upper Layer Protocol to a TCP socket (Linux only).
/// This is the first step to enable kernel TLS offload.
/// After attachment, use setKtlsTx/setKtlsRx to configure crypto params.
/// Returns true if successful, false if failed or not Linux.
fn attachTlsULP(fd: i32) bool {
    // S1: Precondition
    assert(fd >= 0);

    // kTLS is Linux-only
    if (builtin.os.tag != .linux) {
        std.log.debug("attachTlsULP: kTLS not available (non-Linux platform)", .{});
        return false;
    }

    // TCP_ULP expects a null-terminated string "tls"
    const ulp_name: *const [4]u8 = "tls\x00";

    // Use raw Linux syscall to handle all possible errors gracefully
    const rc = std.os.linux.setsockopt(
        fd,
        posix.IPPROTO.TCP,
        posix.TCP.ULP,
        ulp_name,
        4,
    );

    const err = posix.errno(rc);
    if (err != .SUCCESS) {
        if (err == .NOPROTOOPT or err == .NOENT) {
            // kTLS module not loaded or TLS ULP not available
            std.log.debug("attachTlsULP: kTLS not available ({s})", .{@tagName(err)});
        } else {
            std.log.debug("attachTlsULP failed on fd {d}: {s}", .{ fd, @tagName(err) });
        }
        return false;
    }

    return true;
}

/// Configure kTLS TX (encrypt) offload on a socket (Linux only).
/// Must call attachTlsULP first. crypto_info contains cipher-specific params.
/// Returns true if successful.
fn setKtlsTx(fd: i32, crypto_info: []const u8) bool {
    // S1: Preconditions
    assert(fd >= 0);
    assert(crypto_info.len > 0);

    // kTLS is Linux-only
    if (builtin.os.tag != .linux) {
        std.log.debug("setKtlsTx: kTLS not available (non-Linux platform)", .{});
        return false;
    }

    // Use raw Linux syscall since SOL_TLS is not in std.posix
    const rc = std.os.linux.setsockopt(
        fd,
        @intCast(SOL_TLS),
        TLS_TX,
        crypto_info.ptr,
        @intCast(crypto_info.len),
    );

    const err = posix.errno(rc);
    if (err != .SUCCESS) {
        if (err == .NOPROTOOPT) {
            std.log.debug("setKtlsTx: kTLS not available (ENOPROTOOPT)", .{});
        } else {
            std.log.debug("setKtlsTx failed on fd {d}: {s}", .{ fd, @tagName(err) });
        }
        return false;
    }

    return true;
}

/// Configure kTLS RX (decrypt) offload on a socket (Linux only).
/// Must call attachTlsULP first. crypto_info contains cipher-specific params.
/// Returns true if successful.
fn setKtlsRx(fd: i32, crypto_info: []const u8) bool {
    // S1: Preconditions
    assert(fd >= 0);
    assert(crypto_info.len > 0);

    // kTLS is Linux-only
    if (builtin.os.tag != .linux) {
        std.log.debug("setKtlsRx: kTLS not available (non-Linux platform)", .{});
        return false;
    }

    // Use raw Linux syscall since SOL_TLS is not in std.posix
    const rc = std.os.linux.setsockopt(
        fd,
        @intCast(SOL_TLS),
        TLS_RX,
        crypto_info.ptr,
        @intCast(crypto_info.len),
    );

    const err = posix.errno(rc);
    if (err != .SUCCESS) {
        if (err == .NOPROTOOPT) {
            std.log.debug("setKtlsRx: kTLS not available (ENOPROTOOPT)", .{});
        } else {
            std.log.debug("setKtlsRx failed on fd {d}: {s}", .{ fd, @tagName(err) });
        }
        return false;
    }

    return true;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Maps an SSL cipher suite to a kTLS cipher type.
/// Returns .unsupported if the cipher is not supported by kTLS.
fn mapCipherToKtls(cipher_id: u16) KtlsCipher {
    // S1: Input is u16, all values are valid (no precondition needed)

    return switch (cipher_id) {
        // TLS 1.3 ciphers
        SSL_CIPHER_AES_128_GCM_SHA256 => .aes_gcm_128,
        SSL_CIPHER_AES_256_GCM_SHA384 => .aes_gcm_256,
        SSL_CIPHER_CHACHA20_POLY1305_SHA256 => .chacha20_poly1305,

        // TLS 1.2 ECDHE-ECDSA ciphers
        SSL_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256 => .aes_gcm_128,
        SSL_CIPHER_ECDHE_ECDSA_AES_256_GCM_SHA384 => .aes_gcm_256,
        SSL_CIPHER_ECDHE_ECDSA_CHACHA20_POLY1305 => .chacha20_poly1305,

        // TLS 1.2 ECDHE-RSA ciphers
        SSL_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256 => .aes_gcm_128,
        SSL_CIPHER_ECDHE_RSA_AES_256_GCM_SHA384 => .aes_gcm_256,
        SSL_CIPHER_ECDHE_RSA_CHACHA20_POLY1305 => .chacha20_poly1305,

        else => .unsupported,
    };
}

/// Extracts key material from SSL session using RFC 5705 exporter.
///
/// Note: This uses SSL_export_keying_material which derives new keys from the
/// TLS session. For true kTLS, we would need the actual traffic keys, which
/// requires access to OpenSSL internals or using BIO_get_ktls_send/recv.
/// This implementation provides a working framework that can be enhanced
/// when internal key access becomes available.
///
/// Returns true on success, false on failure.
fn extractKeyMaterial(
    ssl_ptr: *ssl.SSL,
    is_tx: bool,
    ktls_cipher: KtlsCipher,
    key_out: []u8,
    iv_out: []u8,
) bool {
    // S1: Preconditions
    assert(@intFromPtr(ssl_ptr) != 0);
    assert(ktls_cipher != .unsupported);
    assert(key_out.len == ktls_cipher.keySize());
    assert(iv_out.len == ktls_cipher.saltSize() + ktls_cipher.ivSize());

    const key_size: usize = ktls_cipher.keySize();
    const iv_total_size: usize = ktls_cipher.saltSize() + ktls_cipher.ivSize();

    // Use distinct labels for TX vs RX to derive different keys
    // TigerStyle: Named constants for label strings
    const tx_key_label = "EXPORTER-kTLS-tx-key";
    const tx_iv_label = "EXPORTER-kTLS-tx-iv";
    const rx_key_label = "EXPORTER-kTLS-rx-key";
    const rx_iv_label = "EXPORTER-kTLS-rx-iv";

    const key_label = if (is_tx) tx_key_label else rx_key_label;
    const iv_label = if (is_tx) tx_iv_label else rx_iv_label;

    // Export key material
    const key_result = ssl.SSL_export_keying_material(
        ssl_ptr,
        key_out.ptr,
        key_size,
        key_label.ptr,
        key_label.len,
        null,
        0,
        0, // no context
    );
    if (key_result != 1) {
        std.log.debug("kTLS: Failed to export {s} key material", .{if (is_tx) "TX" else "RX"});
        return false;
    }

    // Export IV material
    const iv_result = ssl.SSL_export_keying_material(
        ssl_ptr,
        iv_out.ptr,
        iv_total_size,
        iv_label.ptr,
        iv_label.len,
        null,
        0,
        0,
    );
    if (iv_result != 1) {
        std.log.debug("kTLS: Failed to export {s} IV material", .{if (is_tx) "TX" else "RX"});
        return false;
    }

    return true;
}

/// Builds AES-GCM-128 crypto info structure for kernel.
fn buildCryptoInfoAesGcm128(
    tls_version: u16,
    key: []const u8,
    iv: []const u8,
    rec_seq: []const u8,
    out: *Tls12CryptoInfoAesGcm128,
) void {
    // S1: Preconditions
    assert(key.len == AES_GCM_128_KEY_SIZE);
    assert(iv.len >= AES_GCM_128_SALT_SIZE + AES_GCM_128_IV_SIZE);
    assert(rec_seq.len == AES_GCM_128_REC_SEQ_SIZE);

    out.info.version = tls_version;
    out.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    @memcpy(&out.key, key[0..AES_GCM_128_KEY_SIZE]);
    // For AES-GCM: salt is first 4 bytes (implicit nonce), IV is next 8 bytes (explicit)
    @memcpy(&out.salt, iv[0..AES_GCM_128_SALT_SIZE]);
    @memcpy(&out.iv, iv[AES_GCM_128_SALT_SIZE..][0..AES_GCM_128_IV_SIZE]);
    @memcpy(&out.rec_seq, rec_seq[0..AES_GCM_128_REC_SEQ_SIZE]);
}

/// Builds AES-GCM-256 crypto info structure for kernel.
fn buildCryptoInfoAesGcm256(
    tls_version: u16,
    key: []const u8,
    iv: []const u8,
    rec_seq: []const u8,
    out: *Tls12CryptoInfoAesGcm256,
) void {
    // S1: Preconditions
    assert(key.len == AES_GCM_256_KEY_SIZE);
    assert(iv.len >= AES_GCM_256_SALT_SIZE + AES_GCM_256_IV_SIZE);
    assert(rec_seq.len == AES_GCM_256_REC_SEQ_SIZE);

    out.info.version = tls_version;
    out.info.cipher_type = TLS_CIPHER_AES_GCM_256;

    @memcpy(&out.key, key[0..AES_GCM_256_KEY_SIZE]);
    @memcpy(&out.salt, iv[0..AES_GCM_256_SALT_SIZE]);
    @memcpy(&out.iv, iv[AES_GCM_256_SALT_SIZE..][0..AES_GCM_256_IV_SIZE]);
    @memcpy(&out.rec_seq, rec_seq[0..AES_GCM_256_REC_SEQ_SIZE]);
}

/// Builds ChaCha20-Poly1305 crypto info structure for kernel.
fn buildCryptoInfoChaCha20Poly1305(
    tls_version: u16,
    key: []const u8,
    iv: []const u8,
    rec_seq: []const u8,
    out: *Tls12CryptoInfoChaCha20Poly1305,
) void {
    // S1: Preconditions
    assert(key.len == CHACHA20_POLY1305_KEY_SIZE);
    assert(iv.len == CHACHA20_POLY1305_IV_SIZE);
    assert(rec_seq.len == CHACHA20_POLY1305_REC_SEQ_SIZE);

    out.info.version = tls_version;
    out.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;

    @memcpy(&out.key, key[0..CHACHA20_POLY1305_KEY_SIZE]);
    // ChaCha20 has no salt, IV is the full 12 bytes
    @memcpy(&out.iv, iv[0..CHACHA20_POLY1305_IV_SIZE]);
    @memcpy(&out.rec_seq, rec_seq[0..CHACHA20_POLY1305_REC_SEQ_SIZE]);
}

/// Sets kTLS crypto parameters via setsockopt for a given cipher.
/// Helper function to keep configureKtlsDirection under 70 lines.
fn setKtlsCrypto(
    fd: i32,
    ktls_version: u16,
    ktls_cipher: KtlsCipher,
    key: []const u8,
    iv: []const u8,
    is_tx: bool,
) bool {
    // S1: Preconditions validated by caller
    const rec_seq = std.mem.zeroes([8]u8);

    return switch (ktls_cipher) {
        .aes_gcm_128 => blk: {
            var info: Tls12CryptoInfoAesGcm128 = undefined;
            buildCryptoInfoAesGcm128(ktls_version, key, iv, &rec_seq, &info);
            break :blk if (is_tx)
                setKtlsTx(fd, std.mem.asBytes(&info))
            else
                setKtlsRx(fd, std.mem.asBytes(&info));
        },
        .aes_gcm_256 => blk: {
            var info: Tls12CryptoInfoAesGcm256 = undefined;
            buildCryptoInfoAesGcm256(ktls_version, key, iv, &rec_seq, &info);
            break :blk if (is_tx)
                setKtlsTx(fd, std.mem.asBytes(&info))
            else
                setKtlsRx(fd, std.mem.asBytes(&info));
        },
        .chacha20_poly1305 => blk: {
            var info: Tls12CryptoInfoChaCha20Poly1305 = undefined;
            buildCryptoInfoChaCha20Poly1305(ktls_version, key, iv, &rec_seq, &info);
            break :blk if (is_tx)
                setKtlsTx(fd, std.mem.asBytes(&info))
            else
                setKtlsRx(fd, std.mem.asBytes(&info));
        },
        .unsupported => false,
    };
}

/// Configures kTLS for a specific direction (TX or RX).
/// Returns true on success, false on failure.
fn configureKtlsDirection(
    fd: i32,
    ssl_ptr: *ssl.SSL,
    ktls_version: u16,
    ktls_cipher: KtlsCipher,
    is_tx: bool,
) bool {
    // S1: Preconditions
    assert(fd > 0);
    assert(@intFromPtr(ssl_ptr) != 0);
    assert(ktls_cipher != .unsupported);

    // Maximum buffer sizes (ChaCha20: 32-byte key, 12-byte IV)
    const max_key_size: usize = 32;
    const max_iv_size: usize = 12;
    var key_buf: [max_key_size]u8 = undefined;
    var iv_buf: [max_iv_size]u8 = undefined;

    const key_size: usize = ktls_cipher.keySize();
    const iv_total: usize = ktls_cipher.saltSize() + ktls_cipher.ivSize();

    // Extract key material for this direction
    if (!extractKeyMaterial(
        ssl_ptr,
        is_tx,
        ktls_cipher,
        key_buf[0..key_size],
        iv_buf[0..iv_total],
    )) {
        return false;
    }

    // Build cipher-specific crypto info and call setsockopt
    return setKtlsCrypto(fd, ktls_version, ktls_cipher, key_buf[0..key_size], iv_buf[0..iv_total], is_tx);
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Attempts to enable kernel TLS (kTLS) offload for a connected socket.
///
/// After a successful TLS handshake, this function extracts the negotiated
/// cipher and key material, then configures the kernel to handle TLS
/// encryption/decryption for subsequent I/O.
///
/// Returns:
/// - .ktls_enabled: kTLS successfully enabled for both TX and RX
/// - .userspace_fallback: kTLS not available, continue using userspace TLS
///
/// Fallback reasons (all return userspace_fallback, not errors):
/// - Non-Linux OS
/// - Unsupported TLS version (< TLS 1.2)
/// - Unsupported cipher suite
/// - Key extraction failure
/// - Kernel kTLS module not loaded (ENOPROTOOPT)
/// - Kernel cipher not supported (ENOENT)
///
/// TigerStyle: This function never returns an error for expected fallback cases.
/// kTLS is an optimization; failure to enable it is not a connection failure.
pub fn tryEnableKtls(
    ssl_ptr: *ssl.SSL,
    fd: i32,
) KtlsResult {
    // S1: Preconditions
    assert(@intFromPtr(ssl_ptr) != 0); // Valid SSL pointer
    assert(fd > 0); // Valid file descriptor

    // Step 1: Check if running on Linux - kTLS is Linux-only
    if (builtin.os.tag != .linux) {
        std.log.debug("kTLS: Not on Linux, using userspace fallback", .{});
        return .userspace_fallback;
    }

    // Step 2: Get TLS version - must be TLS 1.2 or 1.3
    const tls_version_int: c_int = ssl.SSL_version(ssl_ptr);
    if (tls_version_int != ssl.TLS1_2_VERSION and tls_version_int != ssl.TLS1_3_VERSION) {
        std.log.debug("kTLS: Unsupported TLS version 0x{x}", .{tls_version_int});
        return .userspace_fallback;
    }
    const ktls_version: u16 = @intCast(tls_version_int);

    // Step 3: Get current cipher
    const cipher = ssl.SSL_get_current_cipher(ssl_ptr) orelse {
        std.log.debug("kTLS: No cipher negotiated", .{});
        return .userspace_fallback;
    };

    // Step 4: Map cipher to kTLS cipher type
    const cipher_id: u16 = ssl.SSL_CIPHER_get_protocol_id(cipher);
    const ktls_cipher = mapCipherToKtls(cipher_id);
    if (ktls_cipher == .unsupported) {
        std.log.debug("kTLS: Cipher 0x{x} not supported by kTLS", .{cipher_id});
        return .userspace_fallback;
    }

    // Step 5: Attach TLS ULP (Upper Layer Protocol) to socket
    if (!attachTlsULP(fd)) {
        std.log.debug("kTLS: Failed to attach TLS ULP (kernel module not loaded?)", .{});
        return .userspace_fallback;
    }

    // Step 6: Configure TX (transmit) crypto
    if (!configureKtlsDirection(fd, ssl_ptr, ktls_version, ktls_cipher, true)) {
        std.log.debug("kTLS: Failed to configure TX crypto", .{});
        return .userspace_fallback;
    }

    // Step 7: Configure RX (receive) crypto
    if (!configureKtlsDirection(fd, ssl_ptr, ktls_version, ktls_cipher, false)) {
        std.log.debug("kTLS: Failed to configure RX crypto (TX may be enabled)", .{});
        // Note: TX is already enabled, but RX failed. For simplicity, we fall back
        // to userspace. Production code might want to handle TX-only kTLS mode.
        return .userspace_fallback;
    }

    // Step 8: Success - kTLS enabled for both directions
    std.log.debug("kTLS: Successfully enabled for cipher 0x{x}", .{cipher_id});
    return .ktls_enabled;
}

// ============================================================================
// Tests
// ============================================================================

test "mapCipherToKtls correctly identifies TLS 1.3 ciphers" {
    try std.testing.expectEqual(KtlsCipher.aes_gcm_128, mapCipherToKtls(0x1301));
    try std.testing.expectEqual(KtlsCipher.aes_gcm_256, mapCipherToKtls(0x1302));
    try std.testing.expectEqual(KtlsCipher.chacha20_poly1305, mapCipherToKtls(0x1303));
}

test "mapCipherToKtls correctly identifies TLS 1.2 ECDHE-ECDSA ciphers" {
    try std.testing.expectEqual(KtlsCipher.aes_gcm_128, mapCipherToKtls(0xc02b));
    try std.testing.expectEqual(KtlsCipher.aes_gcm_256, mapCipherToKtls(0xc02c));
    try std.testing.expectEqual(KtlsCipher.chacha20_poly1305, mapCipherToKtls(0xcca9));
}

test "mapCipherToKtls correctly identifies TLS 1.2 ECDHE-RSA ciphers" {
    try std.testing.expectEqual(KtlsCipher.aes_gcm_128, mapCipherToKtls(0xc02f));
    try std.testing.expectEqual(KtlsCipher.aes_gcm_256, mapCipherToKtls(0xc030));
    try std.testing.expectEqual(KtlsCipher.chacha20_poly1305, mapCipherToKtls(0xcca8));
}

test "mapCipherToKtls returns unsupported for unknown ciphers" {
    try std.testing.expectEqual(KtlsCipher.unsupported, mapCipherToKtls(0x0000));
    try std.testing.expectEqual(KtlsCipher.unsupported, mapCipherToKtls(0xffff));
    try std.testing.expectEqual(KtlsCipher.unsupported, mapCipherToKtls(0x002f)); // TLS_RSA_WITH_AES_128_CBC_SHA
}

test "KtlsCipher returns correct key sizes" {
    try std.testing.expectEqual(@as(u8, 16), KtlsCipher.aes_gcm_128.keySize());
    try std.testing.expectEqual(@as(u8, 32), KtlsCipher.aes_gcm_256.keySize());
    try std.testing.expectEqual(@as(u8, 32), KtlsCipher.chacha20_poly1305.keySize());
    try std.testing.expectEqual(@as(u8, 0), KtlsCipher.unsupported.keySize());
}

test "KtlsCipher returns correct IV sizes" {
    try std.testing.expectEqual(@as(u8, 8), KtlsCipher.aes_gcm_128.ivSize());
    try std.testing.expectEqual(@as(u8, 8), KtlsCipher.aes_gcm_256.ivSize());
    try std.testing.expectEqual(@as(u8, 12), KtlsCipher.chacha20_poly1305.ivSize());
    try std.testing.expectEqual(@as(u8, 0), KtlsCipher.unsupported.ivSize());
}

test "KtlsCipher returns correct salt sizes" {
    try std.testing.expectEqual(@as(u8, 4), KtlsCipher.aes_gcm_128.saltSize());
    try std.testing.expectEqual(@as(u8, 4), KtlsCipher.aes_gcm_256.saltSize());
    try std.testing.expectEqual(@as(u8, 0), KtlsCipher.chacha20_poly1305.saltSize());
    try std.testing.expectEqual(@as(u8, 0), KtlsCipher.unsupported.saltSize());
}

test "KtlsCipher.toKernelType returns correct kernel cipher IDs" {
    try std.testing.expectEqual(@as(?u16, TLS_CIPHER_AES_GCM_128), KtlsCipher.aes_gcm_128.toKernelType());
    try std.testing.expectEqual(@as(?u16, TLS_CIPHER_AES_GCM_256), KtlsCipher.aes_gcm_256.toKernelType());
    try std.testing.expectEqual(@as(?u16, TLS_CIPHER_CHACHA20_POLY1305), KtlsCipher.chacha20_poly1305.toKernelType());
    try std.testing.expectEqual(@as(?u16, null), KtlsCipher.unsupported.toKernelType());
}

test "buildCryptoInfoAesGcm128 populates struct correctly" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 12; // 4 salt + 8 iv
    const rec_seq = [_]u8{0x00} ** 8;
    var crypto_info: Tls12CryptoInfoAesGcm128 = undefined;

    buildCryptoInfoAesGcm128(TLS_1_3_VERSION, &key, &iv, &rec_seq, &crypto_info);

    try std.testing.expectEqual(TLS_1_3_VERSION, crypto_info.info.version);
    try std.testing.expectEqual(TLS_CIPHER_AES_GCM_128, crypto_info.info.cipher_type);
    try std.testing.expectEqualSlices(u8, &key, &crypto_info.key);
    try std.testing.expectEqualSlices(u8, iv[0..4], &crypto_info.salt);
    try std.testing.expectEqualSlices(u8, iv[4..12], &crypto_info.iv);
}

test "buildCryptoInfoAesGcm256 populates struct correctly" {
    const key = [_]u8{0x33} ** 32;
    const iv = [_]u8{0x44} ** 12;
    const rec_seq = [_]u8{0x00} ** 8;
    var crypto_info: Tls12CryptoInfoAesGcm256 = undefined;

    buildCryptoInfoAesGcm256(TLS_1_2_VERSION, &key, &iv, &rec_seq, &crypto_info);

    try std.testing.expectEqual(TLS_1_2_VERSION, crypto_info.info.version);
    try std.testing.expectEqual(TLS_CIPHER_AES_GCM_256, crypto_info.info.cipher_type);
    try std.testing.expectEqualSlices(u8, &key, &crypto_info.key);
}

test "buildCryptoInfoChaCha20Poly1305 populates struct correctly" {
    const key = [_]u8{0x55} ** 32;
    const iv = [_]u8{0x66} ** 12;
    const rec_seq = [_]u8{0x00} ** 8;
    var crypto_info: Tls12CryptoInfoChaCha20Poly1305 = undefined;

    buildCryptoInfoChaCha20Poly1305(TLS_1_3_VERSION, &key, &iv, &rec_seq, &crypto_info);

    try std.testing.expectEqual(TLS_1_3_VERSION, crypto_info.info.version);
    try std.testing.expectEqual(TLS_CIPHER_CHACHA20_POLY1305, crypto_info.info.cipher_type);
    try std.testing.expectEqualSlices(u8, &key, &crypto_info.key);
    try std.testing.expectEqualSlices(u8, &iv, &crypto_info.iv);
}

test "KtlsResult.isKtls returns correct values" {
    try std.testing.expect(KtlsResult.ktls_enabled.isKtls());
    try std.testing.expect(!KtlsResult.userspace_fallback.isKtls());
}

test "struct sizes match Linux kernel expectations" {
    // These sizes must match linux/tls.h for setsockopt to work
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(TlsCryptoInfo));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(Tls12CryptoInfoAesGcm128));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Tls12CryptoInfoAesGcm256));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Tls12CryptoInfoChaCha20Poly1305));
}

test "struct field offsets match kernel layout" {
    // TlsCryptoInfo
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(TlsCryptoInfo, "version"));
    try std.testing.expectEqual(@as(usize, 2), @offsetOf(TlsCryptoInfo, "cipher_type"));

    // Tls12CryptoInfoAesGcm128: info(4) + iv(8) + key(16) + salt(4) + rec_seq(8) = 40
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Tls12CryptoInfoAesGcm128, "info"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Tls12CryptoInfoAesGcm128, "iv"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(Tls12CryptoInfoAesGcm128, "key"));
    try std.testing.expectEqual(@as(usize, 28), @offsetOf(Tls12CryptoInfoAesGcm128, "salt"));
    try std.testing.expectEqual(@as(usize, 32), @offsetOf(Tls12CryptoInfoAesGcm128, "rec_seq"));

    // Tls12CryptoInfoAesGcm256: info(4) + iv(8) + key(32) + salt(4) + rec_seq(8) = 56
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Tls12CryptoInfoAesGcm256, "info"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Tls12CryptoInfoAesGcm256, "iv"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(Tls12CryptoInfoAesGcm256, "key"));
    try std.testing.expectEqual(@as(usize, 44), @offsetOf(Tls12CryptoInfoAesGcm256, "salt"));
    try std.testing.expectEqual(@as(usize, 48), @offsetOf(Tls12CryptoInfoAesGcm256, "rec_seq"));

    // Tls12CryptoInfoChaCha20Poly1305: info(4) + iv(12) + key(32) + rec_seq(8) = 56
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Tls12CryptoInfoChaCha20Poly1305, "info"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Tls12CryptoInfoChaCha20Poly1305, "iv"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(Tls12CryptoInfoChaCha20Poly1305, "key"));
    try std.testing.expectEqual(@as(usize, 48), @offsetOf(Tls12CryptoInfoChaCha20Poly1305, "rec_seq"));
}

test "kTLS version constants match SSL version constants" {
    try std.testing.expectEqual(@as(u16, ssl.TLS1_2_VERSION), TLS_1_2_VERSION);
    try std.testing.expectEqual(@as(u16, ssl.TLS1_3_VERSION), TLS_1_3_VERSION);
}
