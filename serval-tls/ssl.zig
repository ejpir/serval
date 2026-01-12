// lib/serval-tls/ssl.zig
//! Manual BoringSSL bindings
//!
//! Avoids @cImport issues with complex macros.
//! Only includes functions needed for TLS support.
//! Based on validated POC in experiments/tls-poc/.

const std = @import("std");
const log = @import("serval-core").log.scoped(.tls);

// Opaque types
pub const SSL_CTX = opaque {};
pub const SSL = opaque {};
pub const SSL_METHOD = opaque {};
pub const SSL_CIPHER = opaque {};
pub const SSL_SESSION = opaque {};
pub const BIO = opaque {};
pub const X509 = opaque {};
pub const EVP_PKEY = opaque {};
pub const X509_NAME = opaque {};

// Error codes
pub const SSL_ERROR_NONE = 0;
pub const SSL_ERROR_SSL = 1;
pub const SSL_ERROR_WANT_READ = 2;
pub const SSL_ERROR_WANT_WRITE = 3;
pub const SSL_ERROR_WANT_X509_LOOKUP = 4;
pub const SSL_ERROR_SYSCALL = 5;
pub const SSL_ERROR_ZERO_RETURN = 6;
pub const SSL_ERROR_WANT_CONNECT = 7;
pub const SSL_ERROR_WANT_ACCEPT = 8;

// TLS versions
pub const TLS1_VERSION = 0x0301;
pub const TLS1_1_VERSION = 0x0302;
pub const TLS1_2_VERSION = 0x0303;
pub const TLS1_3_VERSION = 0x0304;

// File types for key loading
pub const SSL_FILETYPE_PEM = 1;
pub const SSL_FILETYPE_ASN1 = 2;

// Verification modes
pub const SSL_VERIFY_NONE = 0x00;
pub const SSL_VERIFY_PEER = 0x01;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;

// SSL options (for SSL_set_options/SSL_get_options)
// Note: These are OpenSSL 3.x values. BoringSSL may differ.
pub const SSL_OP_ENABLE_KTLS: u64 = 1 << 3; // Enable kernel TLS (OpenSSL 3.0+)
pub const SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE: u64 = 1 << 34; // Zero-copy sendfile with kTLS

// Library initialization
pub extern fn OPENSSL_init_ssl(opts: u64, settings: ?*anyopaque) c_int;

// SSL_CTX functions
pub extern fn TLS_method() ?*const SSL_METHOD;
pub extern fn TLS_client_method() ?*const SSL_METHOD;
pub extern fn TLS_server_method() ?*const SSL_METHOD;
pub extern fn SSL_CTX_new(method: ?*const SSL_METHOD) ?*SSL_CTX;
pub extern fn SSL_CTX_free(ctx: *SSL_CTX) void;
pub extern fn SSL_CTX_set_min_proto_version(ctx: *SSL_CTX, version: u16) c_int;
pub extern fn SSL_CTX_set_max_proto_version(ctx: *SSL_CTX, version: u16) c_int;
pub extern fn SSL_CTX_use_certificate_chain_file(ctx: *SSL_CTX, file: [*:0]const u8) c_int;
pub extern fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, file: [*:0]const u8, type_: c_int) c_int;
pub extern fn SSL_CTX_load_verify_locations(ctx: *SSL_CTX, ca_file: ?[*:0]const u8, ca_path: ?[*:0]const u8) c_int;
pub extern fn SSL_CTX_set_verify(ctx: *SSL_CTX, mode: c_int, callback: ?*anyopaque) void;

// SSL functions
pub extern fn SSL_new(ctx: *SSL_CTX) ?*SSL;
pub extern fn SSL_free(ssl: *SSL) void;
pub extern fn SSL_set_fd(ssl: *SSL, fd: c_int) c_int;
pub extern fn SSL_set_connect_state(ssl: *SSL) void;
pub extern fn SSL_set_accept_state(ssl: *SSL) void;
pub extern fn SSL_connect(ssl: *SSL) c_int;
pub extern fn SSL_accept(ssl: *SSL) c_int;
pub extern fn SSL_do_handshake(ssl: *SSL) c_int;
pub extern fn SSL_is_init_finished(ssl: *const SSL) c_int;
pub extern fn SSL_read(ssl: *SSL, buf: [*]u8, num: c_int) c_int;
pub extern fn SSL_write(ssl: *SSL, buf: [*]const u8, num: c_int) c_int;
pub extern fn SSL_shutdown(ssl: *SSL) c_int;
pub extern fn SSL_get_error(ssl: *const SSL, ret: c_int) c_int;
pub extern fn SSL_get_version(ssl: *const SSL) ?[*:0]const u8;
pub extern fn SSL_get_current_cipher(ssl: *const SSL) ?*const SSL_CIPHER;

// SSL options - enable/disable features like kTLS
pub extern fn SSL_set_options(ssl: *SSL, options: u64) u64;
pub extern fn SSL_get_options(ssl: *const SSL) u64;
pub extern fn SSL_clear_options(ssl: *SSL, options: u64) u64;

// BIO functions - needed for kTLS status checks
pub extern fn SSL_get_rbio(ssl: *const SSL) ?*BIO;
pub extern fn SSL_get_wbio(ssl: *const SSL) ?*BIO;
pub extern fn BIO_ctrl(bio: *BIO, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;

// BIO control commands for kTLS status (OpenSSL 3.0+)
pub const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
pub const BIO_CTRL_GET_KTLS_RECV: c_int = 76;

/// Check if kTLS is enabled for sending (TX direction)
pub fn BIO_get_ktls_send(bio: *BIO) bool {
    return BIO_ctrl(bio, BIO_CTRL_GET_KTLS_SEND, 0, null) != 0;
}

/// Check if kTLS is enabled for receiving (RX direction)
pub fn BIO_get_ktls_recv(bio: *BIO) bool {
    return BIO_ctrl(bio, BIO_CTRL_GET_KTLS_RECV, 0, null) != 0;
}

// SNI - SSL_set_tlsext_host_name is a macro, use SSL_ctrl directly
pub extern fn SSL_ctrl(ssl: *SSL, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;

// SSL_CTRL_SET_TLSEXT_HOSTNAME constant (from openssl/tls1.h)
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
pub const TLSEXT_NAMETYPE_host_name = 0;

/// Set SNI hostname for TLS connection
pub fn SSL_set_tlsext_host_name(ssl: *SSL, name: [*:0]const u8) c_int {
    const result = SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, @ptrCast(@constCast(name)));
    return if (result == 1) 1 else 0;
}

// Cipher functions
pub extern fn SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) ?[*:0]const u8;
pub extern fn SSL_CIPHER_get_id(cipher: *const SSL_CIPHER) u32;
/// Returns the cipher's two-byte protocol ID (IANA cipher suite value).
/// For TLS 1.3: 0x1301 (AES-128-GCM), 0x1302 (AES-256-GCM), 0x1303 (ChaCha20)
/// For TLS 1.2: 0xc02b (ECDHE-ECDSA-AES-128-GCM), 0xc02f (ECDHE-RSA-AES-128-GCM), etc.
pub extern fn SSL_CIPHER_get_protocol_id(cipher: *const SSL_CIPHER) u16;

// TLS version query
// Returns TLS version as integer (e.g., TLS1_2_VERSION, TLS1_3_VERSION)
pub extern fn SSL_version(ssl: *const SSL) c_int;

// ============================================================================
// kTLS Key Extraction Functions
// ============================================================================
// These functions provide access to TLS session keys and random data needed
// for kernel TLS (kTLS) offload. kTLS allows the kernel to encrypt/decrypt
// TLS records directly, bypassing userspace for improved performance.
//
// Key extraction workflow:
// 1. Complete TLS handshake
// 2. Get session via SSL_get_session
// 3. Extract master key, client/server random
// 4. Use SSL_export_keying_material for TLS 1.3+ key derivation
// 5. Pass keys to kernel via setsockopt(SOL_TLS, TLS_TX/TLS_RX)
// ============================================================================

// Session access - required to get master key for kTLS
pub extern fn SSL_get_session(ssl: *const SSL) ?*SSL_SESSION;

// Master key extraction - returns key length written to out buffer
// For TLS 1.2: master secret is 48 bytes
// For TLS 1.3: use SSL_export_keying_material instead
pub extern fn SSL_SESSION_get_master_key(session: *const SSL_SESSION, out: ?[*]u8, max_out: usize) usize;

// Client/server random extraction - needed for TLS 1.2 key derivation
// Both return 32 bytes of random data when complete
pub extern fn SSL_get_client_random(ssl: *const SSL, out: ?[*]u8, max_out: usize) usize;
pub extern fn SSL_get_server_random(ssl: *const SSL, out: ?[*]u8, max_out: usize) usize;

// RFC 5705 key material export - primary method for TLS 1.3 kTLS keys
// Returns 1 on success, 0 on failure
// For kTLS TLS 1.3, use label "EXPORTER-traffic-secret" with appropriate context
pub extern fn SSL_export_keying_material(
    ssl: *SSL,
    out: [*]u8,
    out_len: usize,
    label: [*:0]const u8,
    label_len: usize,
    context: ?[*]const u8,
    context_len: usize,
    use_context: c_int,
) c_int;

// Session resumption
pub extern fn SSL_session_reused(ssl: *const SSL) c_int;

// ALPN - returns pointer to selected protocol and length
// Note: data is set to NULL if no ALPN was negotiated
pub extern fn SSL_get0_alpn_selected(ssl: *const SSL, data: *?[*]const u8, len: *c_uint) void;

// Certificate inspection
// Note: OpenSSL 3.x renamed SSL_get_peer_certificate to SSL_get1_peer_certificate
pub extern fn SSL_get1_peer_certificate(ssl: *const SSL) ?*X509;
pub extern fn X509_free(x509: *X509) void;
pub extern fn X509_get_subject_name(x509: *const X509) ?*X509_NAME;
pub extern fn X509_get_issuer_name(x509: *const X509) ?*X509_NAME;
pub extern fn X509_NAME_oneline(name: *const X509_NAME, buf: [*]u8, size: c_int) ?[*:0]u8;

// Error functions
pub extern fn ERR_get_error() c_ulong;
pub extern fn ERR_error_string_n(err: c_ulong, buf: [*]u8, len: usize) void;
pub extern fn ERR_clear_error() void;

// High-level wrappers
pub fn init() void {
    _ = OPENSSL_init_ssl(0, null);
}

pub fn createClientCtx() !*SSL_CTX {
    const method = TLS_client_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    // NOTE: SSL_CTX_set_min_proto_version is BoringSSL-specific, not in OpenSSL
    // TODO: Use OpenSSL-compatible SSL_CTX_set_options with SSL_OP_NO_TLSv1 etc
    // _ = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

pub fn createServerCtx() !*SSL_CTX {
    const method = TLS_server_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    // NOTE: SSL_CTX_set_min_proto_version is BoringSSL-specific, not in OpenSSL
    // TODO: Use OpenSSL-compatible SSL_CTX_set_options with SSL_OP_NO_TLSv1 etc
    // _ = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

pub fn createSsl(ctx: *SSL_CTX) !*SSL {
    // S1: precondition - ctx pointer must be valid (enforced by type system)
    const ssl_obj = SSL_new(ctx) orelse return error.SslNew;
    // S1: postcondition - ssl is non-null (verified by orelse above)
    return ssl_obj;
}

pub fn printErrors() void {
    var err: c_ulong = ERR_get_error(); // S2: explicit type
    var iteration: u32 = 0;
    const max_errors: u32 = 100; // S4: explicit bound

    while (err != 0 and iteration < max_errors) { // S4: bounded loop
        iteration += 1;
        var buf = std.mem.zeroes([256]u8); // S5: zeroed to prevent information leaks
        ERR_error_string_n(err, &buf, buf.len);
        log.err("SSL: {s}", .{std.mem.sliceTo(&buf, 0)});
        err = ERR_get_error();
    }
}
