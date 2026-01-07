// lib/serval-tls/ssl.zig
//! Manual BoringSSL bindings
//!
//! Avoids @cImport issues with complex macros.
//! Only includes functions needed for TLS support.
//! Based on validated POC in experiments/tls-poc/.

const std = @import("std");

// Opaque types
pub const SSL_CTX = opaque {};
pub const SSL = opaque {};
pub const SSL_METHOD = opaque {};
pub const SSL_CIPHER = opaque {};
pub const BIO = opaque {};
pub const X509 = opaque {};
pub const EVP_PKEY = opaque {};

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

// SNI - SSL_set_tlsext_host_name is a macro, use SSL_ctrl directly
pub extern fn SSL_ctrl(ssl: *SSL, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;

// SSL_CTRL_SET_TLSEXT_HOSTNAME constant (from openssl/tls1.h)
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
pub const TLSEXT_NAMETYPE_host_name = 0;

/// Set SNI hostname for TLS connection
pub fn SSL_set_tlsext_host_name(ssl: *SSL, name: [*:0]const u8) c_int {
    const result = SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, @constCast(@ptrCast(name)));
    return if (result == 1) 1 else 0;
}

// Cipher functions
pub extern fn SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) ?[*:0]const u8;

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
    const ssl = SSL_new(ctx) orelse return error.SslNew;
    // S1: postcondition - ssl is non-null (verified by orelse above)
    return ssl;
}

pub fn getErrorString(err: c_ulong) []const u8 {
    var buf = std.mem.zeroes([256]u8); // S5: zeroed to prevent information leaks
    ERR_error_string_n(err, &buf, buf.len);
    return std.mem.sliceTo(&buf, 0);
}

pub fn printErrors() void {
    var err: c_ulong = ERR_get_error(); // S2: explicit type
    var iteration: u32 = 0;
    const max_errors: u32 = 100; // S4: explicit bound

    while (err != 0 and iteration < max_errors) { // S4: bounded loop
        iteration += 1;
        var buf = std.mem.zeroes([256]u8); // S5: zeroed to prevent information leaks
        ERR_error_string_n(err, &buf, buf.len);
        std.log.err("SSL: {s}", .{std.mem.sliceTo(&buf, 0)});
        err = ERR_get_error();
    }
}
