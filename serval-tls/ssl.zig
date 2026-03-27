// lib/serval-tls/ssl.zig
//! Manual BoringSSL bindings
//!
//! Avoids @cImport issues with complex macros.
//! Only includes functions needed for TLS support.
//! Based on validated POC in experiments/tls-poc/.

const std = @import("std");
const assert = std.debug.assert;
const serval_core = @import("serval-core");
const log = serval_core.log.scoped(.tls);
const config = serval_core.config;
const posix = std.posix;

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
pub extern fn SSL_set_verify(ssl_obj: *SSL, mode: c_int, callback: ?*anyopaque) void;
pub extern fn SSL_get_verify_mode(ssl_obj: *const SSL) c_int;

pub const ServerNameCallback = *const fn (
    ssl: *SSL,
    alert: *c_int,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub extern fn SSL_CTX_ctrl(ctx: *SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
pub extern fn SSL_CTX_callback_ctrl(ctx: *SSL_CTX, cmd: c_int, cb: ?*const anyopaque) c_long;

pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG: c_int = 54;

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
pub extern fn SSL_set_quiet_shutdown(ssl: *SSL, mode: c_int) void;
pub extern fn SSL_get_error(ssl: *const SSL, ret: c_int) c_int;
pub extern fn SSL_pending(ssl: *const SSL) c_int;
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

// ALPN helpers
// OpenSSL wire format: concatenated [len][proto-bytes] entries.
// Example for ["h2", "http/1.1"]:
//   0x02 'h' '2' 0x08 'h' 't' 't' 'p' '/' '1' '.' '1'
pub extern fn SSL_CTX_set_alpn_protos(ctx: *SSL_CTX, protos: [*]const u8, protos_len: c_uint) c_int;
pub extern fn SSL_set_alpn_protos(ssl: *SSL, protos: [*]const u8, protos_len: c_uint) c_int;

pub const AlpnSelectCallback = *const fn (
    ssl: *SSL,
    out: *?[*]const u8,
    outlen: *u8,
    in: [*]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub extern fn SSL_CTX_set_alpn_select_cb(ctx: *SSL_CTX, cb: AlpnSelectCallback, arg: ?*anyopaque) void;

// ALPN - returns pointer to selected protocol and length
// Note: data is set to NULL if no ALPN was negotiated
pub extern fn SSL_get0_alpn_selected(ssl: *const SSL, data: *?[*]const u8, len: *c_uint) void;
pub extern fn SSL_get_servername(ssl: *const SSL, type_: c_int) ?[*:0]const u8;
pub extern fn SSL_set_SSL_CTX(ssl: *SSL, ctx: *SSL_CTX) ?*SSL_CTX;

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
    installSigpipeIgnore();
    _ = OPENSSL_init_ssl(0, null);
}

fn installSigpipeIgnore() void {
    const sig_ign: ?posix.Sigaction.handler_fn = @ptrFromInt(1);
    const action = posix.Sigaction{
        .handler = .{ .handler = sig_ign },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.PIPE, &action, null);
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
    configureServerAlpn(ctx);
    configureServerCertHook(ctx);
    return ctx;
}

/// Errors returned by `createServerCtxFromPemFiles()`.
pub const CreateServerCtxFromPemFilesError = error{
    InvalidCertPath,
    InvalidKeyPath,
    NoTlsMethod,
    SslCtxNew,
    LoadCertFailed,
    LoadKeyFailed,
    OutOfMemory,
};

/// Create a server SSL context and load certificate/key PEM files.
///
/// Used by initial TLS bootstrap and future hot-activation paths.
pub fn createServerCtxFromPemFiles(
    cert_path: []const u8,
    key_path: []const u8,
) CreateServerCtxFromPemFilesError!*SSL_CTX {
    if (cert_path.len == 0) return error.InvalidCertPath;
    if (key_path.len == 0) return error.InvalidKeyPath;
    assert(cert_path.len > 0);
    assert(key_path.len > 0);

    init();

    const ctx = try createServerCtx();
    errdefer SSL_CTX_free(ctx);

    const allocator = std.heap.c_allocator;

    const cert_path_z = try allocator.dupeZ(u8, cert_path);
    defer allocator.free(cert_path_z);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path_z) != 1) {
        printErrors();
        return error.LoadCertFailed;
    }

    const key_path_z = try allocator.dupeZ(u8, key_path);
    defer allocator.free(key_path_z);
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path_z, SSL_FILETYPE_PEM) != 1) {
        printErrors();
        return error.LoadKeyFailed;
    }

    return ctx;
}

pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

const alpn_protocol_h2: []const u8 = "h2";
const alpn_protocol_http11: []const u8 = "http/1.1";
const alpn_protocol_acme_tls_1: []const u8 = "acme-tls/1";

pub const AlpnMixedOfferPolicy = config.AlpnMixedOfferPolicy;

pub const ServerAlpnHookDecision = enum {
    default_policy,
    force_acme_tls_1,
    reject,
};

pub const ServerAlpnHookInput = struct {
    sni: ?[]const u8,
    client_offers_http11: bool,
    client_offers_h2: bool,
    client_offers_acme_tls_1: bool,
};

pub const ServerAlpnHook = *const fn (input: *const ServerAlpnHookInput) ServerAlpnHookDecision;

pub const ServerCertHookDecision = union(enum) {
    default_ctx,
    reject,
    override_ctx: *SSL_CTX,
};

pub const ServerCertHookInput = struct {
    sni: ?[]const u8,
};

pub const ServerCertHook = *const fn (input: *const ServerCertHookInput) ServerCertHookDecision;

/// Global mixed-offer ALPN policy used by all server contexts in this process.
/// TigerStyle: explicit mutable policy for deployment-controlled rollouts.
var server_alpn_mixed_offer_policy: AlpnMixedOfferPolicy = .prefer_http11;

/// Optional process-wide ALPN override hook.
/// Used by specialized flows (e.g. ACME TLS-ALPN-01) without polluting core modules.
var server_alpn_hook: ?ServerAlpnHook = null;

/// Optional process-wide cert selection hook keyed by SNI.
/// Allows dynamic context override without changing server modules.
var server_cert_hook: ?ServerCertHook = null;

pub fn setServerAlpnMixedOfferPolicy(policy: AlpnMixedOfferPolicy) void {
    server_alpn_mixed_offer_policy = policy;
}

pub fn getServerAlpnMixedOfferPolicy() AlpnMixedOfferPolicy {
    return server_alpn_mixed_offer_policy;
}

pub fn setServerAlpnHook(hook: ?ServerAlpnHook) void {
    server_alpn_hook = hook;
}

pub fn getServerAlpnHook() ?ServerAlpnHook {
    return server_alpn_hook;
}

pub fn setServerCertHook(hook: ?ServerCertHook) void {
    server_cert_hook = hook;
}

pub fn getServerCertHook() ?ServerCertHook {
    return server_cert_hook;
}

fn resolveServerAlpnMixedOfferPolicy(arg: ?*anyopaque) AlpnMixedOfferPolicy {
    if (arg) |raw| {
        const policy_ptr: *const AlpnMixedOfferPolicy = @ptrCast(@alignCast(raw));
        return policy_ptr.*;
    }
    return server_alpn_mixed_offer_policy;
}

fn resolveServerName(ssl_conn: *SSL) ?[]const u8 {
    // Unit tests call callbacks with sentinel non-SSL pointers.
    // Guard low/null-like addresses before handing to OpenSSL.
    if (@intFromPtr(ssl_conn) < 4096) return null;

    const sni_z = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name) orelse return null;
    const sni = std.mem.sliceTo(sni_z, 0);
    if (sni.len == 0) return null;
    return sni;
}

fn applyServerAlpnHook(
    ssl_conn: *SSL,
    out: *?[*]const u8,
    outlen: *u8,
    supports_http11: bool,
    supports_h2: bool,
    supports_acme_tls_1: bool,
) ?c_int {
    const hook = server_alpn_hook orelse return null;

    const input = ServerAlpnHookInput{
        .sni = resolveServerName(ssl_conn),
        .client_offers_http11 = supports_http11,
        .client_offers_h2 = supports_h2,
        .client_offers_acme_tls_1 = supports_acme_tls_1,
    };

    return switch (hook(&input)) {
        .default_policy => null,
        .reject => SSL_TLSEXT_ERR_ALERT_FATAL,
        .force_acme_tls_1 => blk: {
            if (!supports_acme_tls_1) break :blk SSL_TLSEXT_ERR_ALERT_FATAL;
            out.* = @ptrCast(alpn_protocol_acme_tls_1.ptr);
            outlen.* = @intCast(alpn_protocol_acme_tls_1.len);
            break :blk SSL_TLSEXT_ERR_OK;
        },
    };
}

fn serverAlpnSelectCb(
    ssl_conn: *SSL,
    out: *?[*]const u8,
    outlen: *u8,
    in: [*]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    const alpn_policy = resolveServerAlpnMixedOfferPolicy(arg);
    const client_len: usize = @intCast(inlen);
    var pos: usize = 0;
    var supports_http11 = false;
    var supports_h2 = false;
    var supports_acme_tls_1 = false;

    while (pos < client_len) {
        const proto_len: usize = in[pos];
        pos += 1;

        if (proto_len == 0) return SSL_TLSEXT_ERR_NOACK;
        if (pos + proto_len > client_len) return SSL_TLSEXT_ERR_NOACK;

        const proto = in[pos .. pos + proto_len];
        if (std.mem.eql(u8, proto, alpn_protocol_http11)) {
            supports_http11 = true;
        } else if (std.mem.eql(u8, proto, alpn_protocol_h2)) {
            supports_h2 = true;
        } else if (std.mem.eql(u8, proto, alpn_protocol_acme_tls_1)) {
            supports_acme_tls_1 = true;
        }

        pos += proto_len;
    }

    if (applyServerAlpnHook(ssl_conn, out, outlen, supports_http11, supports_h2, supports_acme_tls_1)) |hook_rc| {
        return hook_rc;
    }

    switch (alpn_policy) {
        .prefer_http11 => {
            if (supports_http11) {
                out.* = @ptrCast(alpn_protocol_http11.ptr);
                outlen.* = @intCast(alpn_protocol_http11.len);
                return SSL_TLSEXT_ERR_OK;
            }
            if (supports_h2) {
                out.* = @ptrCast(alpn_protocol_h2.ptr);
                outlen.* = @intCast(alpn_protocol_h2.len);
                return SSL_TLSEXT_ERR_OK;
            }
        },
        .prefer_h2 => {
            if (supports_h2) {
                out.* = @ptrCast(alpn_protocol_h2.ptr);
                outlen.* = @intCast(alpn_protocol_h2.len);
                return SSL_TLSEXT_ERR_OK;
            }
            if (supports_http11) {
                out.* = @ptrCast(alpn_protocol_http11.ptr);
                outlen.* = @intCast(alpn_protocol_http11.len);
                return SSL_TLSEXT_ERR_OK;
            }
        },
        .http11_only => {
            if (supports_http11) {
                out.* = @ptrCast(alpn_protocol_http11.ptr);
                outlen.* = @intCast(alpn_protocol_http11.len);
                return SSL_TLSEXT_ERR_OK;
            }
            // Reject h2-only clients with TLS no_application_protocol alert.
            // This causes the TLS handshake to fail immediately, so clients
            // fall back to alternative transports (e.g., WebSocket) quickly
            // rather than holding idle connections.
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        },
    }

    return SSL_TLSEXT_ERR_NOACK;
}

fn serverNameSelectCb(
    ssl_conn: *SSL,
    alert: *c_int,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = alert;
    _ = arg;

    const hook = server_cert_hook orelse return SSL_TLSEXT_ERR_NOACK;
    const decision = hook(&.{ .sni = resolveServerName(ssl_conn) });

    return switch (decision) {
        .default_ctx => SSL_TLSEXT_ERR_NOACK,
        .reject => SSL_TLSEXT_ERR_ALERT_FATAL,
        .override_ctx => |ctx| blk: {
            if (SSL_set_SSL_CTX(ssl_conn, ctx) == null) break :blk SSL_TLSEXT_ERR_ALERT_FATAL;
            break :blk SSL_TLSEXT_ERR_OK;
        },
    };
}

pub fn configureServerAlpn(ctx: *SSL_CTX) void {
    const policy_ptr: *AlpnMixedOfferPolicy = &server_alpn_mixed_offer_policy;
    SSL_CTX_set_alpn_select_cb(ctx, serverAlpnSelectCb, @ptrCast(policy_ptr));
}

pub fn configureServerCertHook(ctx: *SSL_CTX) void {
    _ = SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, @ptrCast(&serverNameSelectCb));
    _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, null);
}

pub fn setClientAlpnProtocol(ssl_conn: *SSL, protocol: []const u8) !void {
    if (protocol.len == 0) return error.InvalidAlpnProtocol;
    if (protocol.len > 255) return error.InvalidAlpnProtocol;

    var wire_buf: [256]u8 = undefined;
    wire_buf[0] = @intCast(protocol.len);
    @memcpy(wire_buf[1 .. 1 + protocol.len], protocol);

    const wire_len: c_uint = @intCast(1 + protocol.len);
    if (SSL_set_alpn_protos(ssl_conn, &wire_buf, wire_len) != 0) {
        return error.SslSetAlpn;
    }
}

pub fn createSsl(ctx: *SSL_CTX) !*SSL {
    // S1: precondition - ctx pointer must be valid (enforced by type system)
    const ssl_obj = SSL_new(ctx) orelse return error.SslNew;
    // S1: postcondition - ssl is non-null (verified by orelse above)
    return ssl_obj;
}

pub fn sslErrorName(err: c_int) []const u8 {
    return switch (err) {
        SSL_ERROR_NONE => "SSL_ERROR_NONE",
        SSL_ERROR_SSL => "SSL_ERROR_SSL",
        SSL_ERROR_WANT_READ => "SSL_ERROR_WANT_READ",
        SSL_ERROR_WANT_WRITE => "SSL_ERROR_WANT_WRITE",
        SSL_ERROR_WANT_X509_LOOKUP => "SSL_ERROR_WANT_X509_LOOKUP",
        SSL_ERROR_SYSCALL => "SSL_ERROR_SYSCALL",
        SSL_ERROR_ZERO_RETURN => "SSL_ERROR_ZERO_RETURN",
        SSL_ERROR_WANT_CONNECT => "SSL_ERROR_WANT_CONNECT",
        SSL_ERROR_WANT_ACCEPT => "SSL_ERROR_WANT_ACCEPT",
        else => "SSL_ERROR_UNKNOWN",
    };
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

test "createServerCtxFromPemFiles rejects empty cert path" {
    try std.testing.expectError(
        error.InvalidCertPath,
        createServerCtxFromPemFiles("", "/tmp/non-empty-key.pem"),
    );
}

test "createServerCtxFromPemFiles rejects empty key path" {
    try std.testing.expectError(
        error.InvalidKeyPath,
        createServerCtxFromPemFiles("/tmp/non-empty-cert.pem", ""),
    );
}

test "server ALPN callback prefers http/1.1 for mixed protocol offers" {
    const wire = [_]u8{ 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;
    var policy: AlpnMixedOfferPolicy = .prefer_http11;

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_OK, rc);
    try std.testing.expect(selected_ptr != null);
    try std.testing.expectEqual(@as(u8, @intCast(alpn_protocol_http11.len)), selected_len);
    const selected = selected_ptr.?[0..selected_len];
    try std.testing.expectEqualStrings(alpn_protocol_http11, selected);
}

test "server ALPN callback prefers h2 for mixed protocol offers when policy is prefer_h2" {
    const wire = [_]u8{ 8, 'h', 't', 't', 'p', '/', '1', '.', '1', 2, 'h', '2' };
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;
    var policy: AlpnMixedOfferPolicy = .prefer_h2;

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_OK, rc);
    try std.testing.expect(selected_ptr != null);
    try std.testing.expectEqual(@as(u8, @intCast(alpn_protocol_h2.len)), selected_len);
    const selected = selected_ptr.?[0..selected_len];
    try std.testing.expectEqualStrings(alpn_protocol_h2, selected);
}

test "server ALPN callback selects h2 when client does not offer http/1.1" {
    const wire = [_]u8{ 2, 'h', '2' };
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;
    var policy: AlpnMixedOfferPolicy = .prefer_http11;

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_OK, rc);
    try std.testing.expect(selected_ptr != null);
    try std.testing.expectEqual(@as(u8, @intCast(alpn_protocol_h2.len)), selected_len);
    const selected = selected_ptr.?[0..selected_len];
    try std.testing.expectEqualStrings(alpn_protocol_h2, selected);
}

test "server ALPN callback falls back to http/1.1 when h2 is absent" {
    const wire = [_]u8{ 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;
    var policy: AlpnMixedOfferPolicy = .prefer_h2;

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_OK, rc);
    try std.testing.expect(selected_ptr != null);
    try std.testing.expectEqual(@as(u8, @intCast(alpn_protocol_http11.len)), selected_len);
    const selected = selected_ptr.?[0..selected_len];
    try std.testing.expectEqualStrings(alpn_protocol_http11, selected);
}

test "setServerAlpnMixedOfferPolicy updates global ALPN policy" {
    const initial = getServerAlpnMixedOfferPolicy();
    defer setServerAlpnMixedOfferPolicy(initial);

    setServerAlpnMixedOfferPolicy(.prefer_h2);
    try std.testing.expectEqual(AlpnMixedOfferPolicy.prefer_h2, getServerAlpnMixedOfferPolicy());

    setServerAlpnMixedOfferPolicy(.prefer_http11);
    try std.testing.expectEqual(AlpnMixedOfferPolicy.prefer_http11, getServerAlpnMixedOfferPolicy());
}

test "ALPN http11_only selects http/1.1 when client offers both" {
    var policy: AlpnMixedOfferPolicy = .http11_only;
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;

    // Wire format: [len][proto][len][proto]
    const wire = [_]u8{2} ++ "h2" ++ [_]u8{8} ++ "http/1.1";

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_OK, rc);
    try std.testing.expect(selected_ptr != null);
    try std.testing.expectEqualStrings(alpn_protocol_http11, selected_ptr.?[0..selected_len]);
}

fn testHookForceAcme(input: *const ServerAlpnHookInput) ServerAlpnHookDecision {
    _ = input;
    return .force_acme_tls_1;
}

fn testHookReject(input: *const ServerAlpnHookInput) ServerAlpnHookDecision {
    _ = input;
    return .reject;
}

test "ALPN http11_only rejects h2-only client with fatal alert" {
    var policy: AlpnMixedOfferPolicy = .http11_only;
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;

    // Wire format: h2 only
    const wire = [_]u8{2} ++ "h2";

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_ALERT_FATAL, rc);
}

test "ALPN hook can force acme-tls/1 when offered" {
    const original_hook = getServerAlpnHook();
    defer setServerAlpnHook(original_hook);

    setServerAlpnHook(testHookForceAcme);

    var policy: AlpnMixedOfferPolicy = .prefer_http11;
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;

    const wire = [_]u8{8} ++ "http/1.1" ++ [_]u8{10} ++ "acme-tls/1" ++ [_]u8{2} ++ "h2";

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_OK, rc);
    try std.testing.expect(selected_ptr != null);
    try std.testing.expectEqualStrings(alpn_protocol_acme_tls_1, selected_ptr.?[0..selected_len]);
}

test "ALPN hook force acme-tls/1 fails if client did not offer protocol" {
    const original_hook = getServerAlpnHook();
    defer setServerAlpnHook(original_hook);

    setServerAlpnHook(testHookForceAcme);

    var policy: AlpnMixedOfferPolicy = .prefer_http11;
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;

    const wire = [_]u8{8} ++ "http/1.1" ++ [_]u8{2} ++ "h2";

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_ALERT_FATAL, rc);
}

test "ALPN hook can reject handshake" {
    const original_hook = getServerAlpnHook();
    defer setServerAlpnHook(original_hook);

    setServerAlpnHook(testHookReject);

    var policy: AlpnMixedOfferPolicy = .prefer_http11;
    var selected_ptr: ?[*]const u8 = null;
    var selected_len: u8 = 0;

    const wire = [_]u8{8} ++ "http/1.1";

    const rc = serverAlpnSelectCb(
        @ptrFromInt(1),
        &selected_ptr,
        &selected_len,
        wire[0..].ptr,
        @intCast(wire.len),
        @ptrCast(&policy),
    );

    try std.testing.expectEqual(SSL_TLSEXT_ERR_ALERT_FATAL, rc);
}
