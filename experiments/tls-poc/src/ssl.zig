// Manual BoringSSL bindings - only what we need
// Avoids @cImport issues with complex macros

const std = @import("std");
const log = @import("serval-core").log.scoped(.tls_experiment);

// Opaque types
/// Opaque BoringSSL context type used to hold TLS configuration and shared state.
/// Values are handled only as pointers (`*SSL_CTX`) and must not be inspected or dereferenced in Zig code.
/// Instances are created by `SSL_CTX_new` (or wrappers like `createClientCtx`/`createServerCtx`).
/// Ownership is with the caller; release owned contexts with `SSL_CTX_free` when no longer needed.
pub const SSL_CTX = opaque {};
/// Opaque handle type for an `SSL` object exposed via foreign APIs.
/// The layout is intentionally unknown in Zig and cannot be instantiated or accessed directly.
/// Use only through pointers provided by the corresponding SSL API functions.
/// Ownership, lifetime, and error semantics are defined by those API calls, not by this type itself.
pub const SSL = opaque {};
/// Opaque OpenSSL method descriptor type (forward declaration).
/// This type carries no accessible fields in Zig and is used only via pointers in FFI calls.
/// Preconditions: treat values as externally managed OpenSSL objects; do not construct or copy by value.
/// Ownership/lifetime is defined by the OpenSSL API that returns or consumes `*SSL_METHOD`.
pub const SSL_METHOD = opaque {};
/// Opaque TLS cipher descriptor type (`SSL_CIPHER`) exposed by the SSL API.
/// Values are not constructed or inspected directly in Zig; use library functions via pointers.
/// Treat any `*SSL_CIPHER` as library-owned metadata with lifetime defined by the associated SSL context/session.
/// No Zig-side errors are produced by this declaration itself.
pub const SSL_CIPHER = opaque {};
/// Opaque handle type for BoringSSL `BIO` objects.
/// This declaration exposes C ABI type identity only; Zig code cannot inspect fields.
/// Use `*BIO` pointers only with matching BoringSSL extern functions, which define ownership and errors.
pub const BIO = opaque {};
/// Opaque handle type for an X.509 certificate object.
/// This type has no visible fields and must only be used through pointers in API calls.
/// Ownership and lifetime are managed by the functions that create/return and free `X509` values.
/// Direct use of `X509` itself does not produce errors; error behavior is defined by those APIs.
pub const X509 = opaque {};
/// Opaque BoringSSL key type (`EVP_PKEY`) used across the C TLS API boundary.
/// Values are only meaningful as pointers returned/accepted by BoringSSL functions.
/// Callers must not dereference or assume layout in Zig; treat it as an external handle.
/// Ownership, lifetime, and cleanup are defined by the specific BoringSSL API in use.
pub const EVP_PKEY = opaque {};

// Error codes
/// SSL error code indicating success / no error condition.
/// Value is `0`, matching the underlying C/OpenSSL `SSL_ERROR_NONE` constant.
/// Use this as a comparison sentinel when interpreting SSL operation status.
pub const SSL_ERROR_NONE = 0;
/// Generic SSL failure code (`1`).
/// Use this constant when matching numeric SSL error results in this module.
/// A match indicates an SSL-layer error occurred (not a success condition).
/// This constant carries no ownership or lifetime implications.
pub const SSL_ERROR_SSL = 1;
/// SSL error code indicating that a read operation should be retried.
/// This value is part of the external error-code set used by the SSL API.
/// Commonly used with non-blocking I/O when the socket has no application data yet.
pub const SSL_ERROR_WANT_READ = 2;
/// SSL error code indicating that a write operation should be retried.
/// This value is part of the external error-code set used by the SSL API.
/// Commonly used with non-blocking I/O when the socket cannot accept more data yet.
pub const SSL_ERROR_WANT_WRITE = 3;
/// SSL error code indicating that an X509 lookup should be retried later.
/// This value is part of the external error-code set used by the SSL API.
/// It signals that certificate lookup is not yet ready to complete the operation.
pub const SSL_ERROR_WANT_X509_LOOKUP = 4;
/// SSL error code indicating a system-level I/O failure during SSL work.
/// This value is part of the external error-code set used by the SSL API.
/// The underlying OS error context, if any, must be inspected separately.
pub const SSL_ERROR_SYSCALL = 5;
/// SSL error code indicating that the peer has cleanly closed the TLS session.
/// This value is part of the external error-code set used by the SSL API.
/// Use this to distinguish an orderly shutdown from transport or protocol failure.
pub const SSL_ERROR_ZERO_RETURN = 6;
/// SSL error code indicating that a connect operation should be retried.
/// This value is part of the external error-code set used by the SSL API.
/// Check for this constant when a non-blocking connection is not yet complete.
pub const SSL_ERROR_WANT_CONNECT = 7;
/// OpenSSL error code indicating `SSL_accept` needs to be retried after an accept-related condition.
/// This is typically used in non-blocking handshake loops when OpenSSL reports a transient state.
/// Value: `8`.
pub const SSL_ERROR_WANT_ACCEPT = 8;

// TLS versions
/// OpenSSL constant for TLS 1.0.
/// Use this with protocol version configuration APIs that accept a version number.
/// Value: `0x0301`.
pub const TLS1_VERSION = 0x0301;
/// OpenSSL constant for TLS 1.1.
/// Use this with protocol version configuration APIs that accept a version number.
/// Value: `0x0302`.
pub const TLS1_1_VERSION = 0x0302;
/// OpenSSL constant for TLS 1.2.
/// Use this with protocol version configuration APIs that accept a version number.
/// Value: `0x0303`.
pub const TLS1_2_VERSION = 0x0303;
/// OpenSSL constant for TLS 1.3.
/// Use this with protocol version configuration APIs that accept a version number.
/// Value: `0x0304`.
pub const TLS1_3_VERSION = 0x0304;

// File types for key loading
/// OpenSSL file type constant for PEM-encoded certificate or key files.
/// Pass this to OpenSSL file-loading APIs that require an explicit input encoding.
/// Value: `1`.
pub const SSL_FILETYPE_PEM = 1;
/// OpenSSL file type constant for ASN.1-encoded certificate or key files.
/// Pass this to OpenSSL file-loading APIs that require an explicit input encoding.
/// Value: `2`.
pub const SSL_FILETYPE_ASN1 = 2;

// Verification modes
/// Verifier flag that disables peer certificate verification.
/// This is the zero-valued OpenSSL verification mode.
/// Value: `0x00`.
pub const SSL_VERIFY_NONE = 0x00;
/// Verifier flag that enables peer certificate verification.
/// Use this when the application expects OpenSSL to validate the remote certificate chain.
/// Value: `0x01`.
pub const SSL_VERIFY_PEER = 0x01;
/// Verifier flag that fails the handshake when the peer does not present a certificate.
/// Use this with OpenSSL peer verification settings on server-side configurations.
/// Value: `0x02`.
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
pub extern fn SSL_read(ssl: *SSL, buf: [*]u8, num: c_int) c_int;
pub extern fn SSL_write(ssl: *SSL, buf: [*]const u8, num: c_int) c_int;
pub extern fn SSL_shutdown(ssl: *SSL) c_int;
pub extern fn SSL_get_error(ssl: *const SSL, ret: c_int) c_int;
pub extern fn SSL_get_version(ssl: *const SSL) ?[*:0]const u8;
pub extern fn SSL_get_current_cipher(ssl: *const SSL) ?*const SSL_CIPHER;

// SNI
pub extern fn SSL_set_tlsext_host_name(ssl: *SSL, name: [*:0]const u8) c_int;

// Cipher functions
pub extern fn SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) ?[*:0]const u8;

// Error functions
pub extern fn ERR_get_error() c_ulong;
pub extern fn ERR_error_string_n(err: c_ulong, buf: [*]u8, len: usize) void;
pub extern fn ERR_clear_error() void;

// High-level wrappers
/// Performs one-time OpenSSL SSL library initialization.
/// The OpenSSL return value is ignored, so this function never reports initialization failure.
/// Call this before creating SSL contexts or SSL objects.
pub fn init() void {
    _ = OPENSSL_init_ssl(0, null);
}

/// Creates a client-side TLS context using OpenSSL's client method.
/// Returns `error.NoTlsMethod` if the TLS method is unavailable and `error.SslCtxNew` if context allocation fails.
/// Attempts to set the minimum protocol version to TLS 1.2 before returning the context.
pub fn createClientCtx() !*SSL_CTX {
    const method = TLS_client_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    _ = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

/// Creates a server-side TLS context using OpenSSL's server method.
/// Returns `error.NoTlsMethod` if the TLS method is unavailable and `error.SslCtxNew` if context allocation fails.
/// Attempts to set the minimum protocol version to TLS 1.2 before returning the context.
pub fn createServerCtx() !*SSL_CTX {
    const method = TLS_server_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    _ = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

/// Creates a new `SSL` object for the provided `SSL_CTX`.
/// Returns `error.SslNew` when OpenSSL cannot allocate the object.
/// The returned pointer is owned by the caller and must be released with the matching OpenSSL cleanup routine.
pub fn createSsl(ctx: *SSL_CTX) !*SSL {
    return SSL_new(ctx) orelse error.SslNew;
}

/// Formats an OpenSSL error code into a human-readable string.
/// The returned slice references a stack-allocated buffer and is only valid until this function returns.
/// Use the result immediately; do not store the slice for later use.
pub fn getErrorString(err: c_ulong) []const u8 {
    var buf: [256]u8 = undefined;
    ERR_error_string_n(err, &buf, buf.len);
    return std.mem.sliceTo(&buf, 0);
}

/// Drains the current OpenSSL error queue and logs each pending error.
/// Stops when `ERR_get_error()` returns `0`, so it does not report errors added after the loop begins.
/// This function does not return an error and does not clear any state outside the OpenSSL error queue.
pub fn printErrors() void {
    var err = ERR_get_error();
    while (err != 0) {
        var buf: [256]u8 = undefined;
        ERR_error_string_n(err, &buf, buf.len);
        log.err("SSL: {s}", .{std.mem.sliceTo(&buf, 0)});
        err = ERR_get_error();
    }
}
