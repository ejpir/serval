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
/// Opaque handle type for an SSL/TLS context object from the underlying C library.
/// This type has no known layout in Zig and is intended to be used only via pointers (`*SSL_CTX`/`?*SSL_CTX`).
/// Instances are not created or destroyed directly in Zig; use the corresponding library functions for lifecycle management.
/// This declaration itself does not perform operations and therefore does not return Zig errors.
pub const SSL_CTX = opaque {};
/// Opaque handle type for a TLS session object (`SSL`).
/// Callers must treat this as an external/foreign type and only access it through API functions that accept `*SSL`.
/// This declaration defines no ownership or error behavior by itself; lifecycle and failures are determined by those APIs.
pub const SSL = opaque {};
/// Opaque BoringSSL method descriptor type used to configure `SSL_CTX`.
/// Values are obtained from `TLS_method`, `TLS_client_method`, or `TLS_server_method` and passed as `?*const SSL_METHOD` to `SSL_CTX_new`.
/// This type has no accessible fields and must not be instantiated or dereferenced in Zig.
/// The pointer is library-managed; this binding exposes no allocator/free API or direct error surface for `SSL_METHOD` itself.
pub const SSL_METHOD = opaque {};
/// Opaque BoringSSL cipher-suite descriptor used by Serval TLS bindings.
/// Instances are not constructed or freed directly in Zig; obtain pointers from BoringSSL APIs such as `SSL_get_current_cipher`.
/// Use `SSL_CIPHER_get_name`, `SSL_CIPHER_get_id`, and `SSL_CIPHER_get_protocol_id` to read metadata.
/// Ownership and lifetime are external to Zig and managed by the underlying SSL/BoringSSL objects.
pub const SSL_CIPHER = opaque {};
/// Opaque handle type for a TLS session object managed by the underlying SSL library.
/// The session internals are intentionally hidden and cannot be accessed from Zig code.
/// Use `*SSL_SESSION` only with the corresponding SSL API functions that create, reference, or free it.
/// Ownership and lifetime are defined by those APIs, not by this type declaration itself.
pub const SSL_SESSION = opaque {};
/// Opaque OpenSSL/BoringSSL BIO handle type used by these TLS bindings.
/// `*BIO` is an external library pointer; Zig code must not inspect or construct it directly.
/// In this module, BIO pointers are obtained from `SSL_get_rbio`/`SSL_get_wbio` and used with `BIO_ctrl`.
/// This declaration defines only the type; ownership, lifetime, and errors are governed by the called C APIs.
pub const BIO = opaque {};
/// Opaque handle to an OpenSSL `X509` certificate object.
/// The certificate contents are not accessible directly from Zig; use `X509_*` extern APIs.
/// Ownership is API-dependent: a pointer returned by `SSL_get1_peer_certificate` must be released with `X509_free`.
/// This type itself has no error behavior; nullability and failures are expressed by functions that return or consume `*X509`.
pub const X509 = opaque {};
/// Opaque C type representing an `EVP_PKEY` key object from the SSL/crypto library.
/// The concrete layout is hidden; Zig code must not construct, copy, or inspect it by value.
/// Use `*EVP_PKEY` only when calling the corresponding C APIs.
/// Ownership and lifetime are determined by those APIs (allocation/freeing is not defined by this declaration).
pub const EVP_PKEY = opaque {};
/// Opaque BoringSSL `X509_NAME` handle type used in certificate name APIs.
/// This binding exposes only the type identity; fields are intentionally inaccessible from Zig.
/// Use it through pointers returned/accepted by related extern functions (for example, X509 subject/issuer name helpers).
/// Ownership and lifetime are defined by the producing API; this declaration itself allocates, frees, and errors on nothing.
pub const X509_NAME = opaque {};

// Error codes
/// OpenSSL SSL error code for "no error" (`0`).
/// Indicates that the associated SSL operation completed successfully and no SSL-layer error is reported.
/// Used as the non-error sentinel when comparing values returned by SSL error-query APIs.
pub const SSL_ERROR_NONE = 0;
/// Error code value `1`, matching `SSL_ERROR_SSL`.
/// Indicates a failure in the SSL/TLS layer (protocol or library-level error),
/// not a transport I/O condition.
/// Compare against return values from OpenSSL-style error APIs that report these codes.
pub const SSL_ERROR_SSL = 1;
/// OpenSSL-style error code `2` for `SSL_ERROR_WANT_READ`.
/// Indicates an SSL operation cannot currently proceed until more input is readable.
/// Treat this as a retry condition after waiting for the underlying transport to become readable,
/// not as a terminal protocol failure.
pub const SSL_ERROR_WANT_READ = 2;
/// OpenSSL-style error code indicating a write operation cannot proceed yet.
/// This value is returned by `SSL_get_error` as `SSL_ERROR_WANT_WRITE` (`3`).
/// In non-blocking I/O, retry the TLS operation after the underlying transport becomes writable.
/// Not a fatal TLS failure by itself; it signals a temporary would-block condition.
pub const SSL_ERROR_WANT_WRITE = 3;
/// OpenSSL-style `SSL_get_error` code indicating `SSL_ERROR_WANT_X509_LOOKUP` (`4`).
/// Signals that the operation paused pending an X509 lookup (typically via a callback).
/// Treat as a non-fatal, retryable condition after the lookup context has progressed.
pub const SSL_ERROR_WANT_X509_LOOKUP = 4;
/// OpenSSL `SSL_get_error` result code for `SSL_ERROR_SYSCALL` (value `5`).
/// Indicates that the TLS operation failed due to an underlying system-call/I/O condition,
/// rather than a protocol-level SSL error.
/// Handle by checking platform I/O error state (for example `errno`) and the OpenSSL error queue.
pub const SSL_ERROR_SYSCALL = 5;
/// OpenSSL-compatible error code value for `SSL_ERROR_ZERO_RETURN`.
/// Returned by `SSL_get_error`-style APIs when the TLS/SSL session reached a clean shutdown state.
/// Numeric value is fixed to `6` for ABI/API compatibility with OpenSSL constants.
pub const SSL_ERROR_ZERO_RETURN = 6;
/// OpenSSL-style `SSL_get_error` code indicating the operation could not complete yet
/// because the transport is still establishing a connection.
/// This is a non-fatal, retryable condition (commonly with non-blocking I/O).
/// Treat it as "try again when the socket is connect-ready," not as a hard TLS failure.
pub const SSL_ERROR_WANT_CONNECT = 7;
/// `SSL_get_error` code for the `WANT_ACCEPT` condition (`8`).
/// Indicates the attempted SSL operation could not complete because an accept step must be retried.
/// Typically treated as a non-fatal, retry-later status rather than a terminal failure.
pub const SSL_ERROR_WANT_ACCEPT = 8;

// TLS versions
/// Wire-protocol version identifier for TLS 1.0.
/// Value is `0x0301` (major `0x03`, minor `0x01`) as encoded in TLS headers.
/// Use when matching or emitting protocol version fields that require the TLS 1.0 constant.
pub const TLS1_VERSION = 0x0301;
/// Wire-level protocol version code for TLS 1.1 (`0x0302`).
/// Use this constant when encoding or comparing TLS version fields in records/handshakes.
/// This is a compile-time constant and has no ownership, lifetime, or error behavior.
pub const TLS1_1_VERSION = 0x0302;
/// Wire-format protocol version identifier for TLS 1.2 (`0x0303`).
/// Use this constant when encoding or validating TLS version fields that must match TLS 1.2.
/// Pure value constant: no ownership, lifetime, or error behavior applies.
pub const TLS1_2_VERSION = 0x0303;
/// Numeric protocol version code for TLS 1.3 (`0x0304`).
/// Use this constant when encoding or validating TLS version fields that
/// represent TLS 1.3 in protocol messages.
pub const TLS1_3_VERSION = 0x0304;

// File types for key loading
/// Identifies PEM-encoded input for SSL/TLS file-loading APIs.
/// Use this constant when an API expects a file type selector (e.g. cert/key files).
/// This value is metadata only; validation and parsing errors are reported by the called API.
pub const SSL_FILETYPE_PEM = 1;
/// File-type selector value for DER/ASN.1 encoded key or certificate files.
/// Pass this as the `type_` argument to OpenSSL/BoringSSL file-loading APIs
/// (for example `SSL_CTX_use_PrivateKey_file`) when the input is not PEM.
/// This constant is a plain tag (`2`); ownership, I/O, and errors are handled by the called API.
pub const SSL_FILETYPE_ASN1 = 2;

// Verification modes
/// Verify-mode bitmask value indicating that no verification flags are set (`0x00`).
/// Use this as the baseline/disabled value when configuring SSL/TLS peer-certificate verification.
/// This constant itself performs no checks and has no ownership or lifetime implications.
pub const SSL_VERIFY_NONE = 0x00;
/// Verify-mode bit flag with value `0x01`.
/// Use this constant where SSL verify options are passed as a bitmask.
/// This symbol is immutable and has no ownership or lifetime implications.
/// Any error behavior depends on the API that consumes this flag.
pub const SSL_VERIFY_PEER = 0x01;
/// Verification-mode bit flag (`0x02`) for TLS peer-certificate enforcement.
/// Use in an SSL verify-mode bitmask to require a peer certificate during verification.
/// If this bit is set and no peer certificate is presented, verification must fail.
/// This constant is a raw flag value and does not own or manage any resources.
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;

// SSL options (for SSL_set_options/SSL_get_options)
// Note: These are OpenSSL 3.x values. BoringSSL may differ.
/// OpenSSL option bit that requests Kernel TLS (KTLS) support for an `SSL` connection.
/// Value is `1 << 3` in the `u64` SSL options bitmask space and is intended for bitwise OR with other `SSL_OP_*` flags.
/// This constant itself performs no I/O and cannot fail; any enablement/support checks occur in the API that consumes the option.
pub const SSL_OP_ENABLE_KTLS: u64 = 1 << 3; // Enable kernel TLS (OpenSSL 3.0+)
/// Option bit for enabling kTLS transmit-path zerocopy `sendfile` behavior.
/// Use this as a mask in SSL options APIs (e.g. OR into an options bitset).
/// This declaration only defines the flag value (`1 << 34`); it performs no validation.
/// Any support checks and resulting errors are handled by the SSL API that consumes this option.
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

/// C ABI callback signature for TLS SNI server-name selection hooks.
/// `ssl` is the active connection pointer and is only valid under the SSL library's callback lifetime rules.
/// `alert` points to an alert-code output slot that may be set by the callback for error signaling.
/// `arg` is opaque user context passed via `SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG` and may be `null`.
/// Returns a `c_int` status code (typically one of the `SSL_TLSEXT_ERR_*` constants) consumed by the SSL library.
pub const ServerNameCallback = *const fn (
    ssl: *SSL,
    alert: *c_int,
    arg: ?*anyopaque,
) callconv(.c) c_int;

pub extern fn SSL_CTX_ctrl(ctx: *SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
pub extern fn SSL_CTX_callback_ctrl(ctx: *SSL_CTX, cmd: c_int, cb: ?*const anyopaque) c_long;

/// OpenSSL `SSL_CTRL_*` opcode for registering the TLS Server Name Indication (SNI) callback.
/// Use this constant as the `cmd` value in `SSL_CTX_ctrl`-style calls when setting servername-callback behavior.
/// This is a raw C control ID (`53`); validity and any errors are determined by the underlying OpenSSL API call.
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
/// OpenSSL `SSL_ctrl`/`SSL_CTX_ctrl` command identifier for `SET_TLSEXT_SERVERNAME_ARG`.
/// Use this numeric selector (`54`) when dispatching control calls that configure the
/// argument associated with TLS Server Name Indication (SNI) handling.
/// This constant is metadata only; validation and failure behavior are defined by the target control API.
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
/// OpenSSL BIO control command ID for querying send-side kTLS status.
/// Use this with `BIO_ctrl`-style APIs where the command argument is required.
/// This declaration only exposes the numeric constant (`73`); semantics and return values are defined by OpenSSL.
pub const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
/// OpenSSL `BIO_ctrl` command value for querying kernel TLS receive (KTLS RX) state.
/// Use this as the `cmd` argument when issuing a control call against a BIO.
/// This constant is just an opcode identifier; it performs no allocation and has no direct error behavior.
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
/// OpenSSL `SSL_ctrl` operation code for configuring the TLS SNI server name.
/// Use this selector with `SSL_ctrl` on an `SSL*` before the handshake starts.
/// This constant itself cannot fail; any validation or failure is reported by the corresponding `SSL_ctrl` call.
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
/// TLS SNI name type value for a DNS host name (`host_name`).
/// Use this constant when encoding or validating `ServerName.name_type` in the
/// TLS `server_name` extension; the wire value is always `0` for host names.
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

/// C ABI callback type used during ALPN protocol selection for an `SSL` handshake.
/// `in[0..inlen]` contains the peer-offered ALPN protocol list (wire format); `arg` is user context.
/// On success, write the selected protocol pointer to `out` and its byte length to `outlen`.
/// The returned `c_int` is the callback status code consumed by the TLS library.
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
/// Initializes process-wide TLS runtime prerequisites for Serval.
/// Installs `SIGPIPE` ignore handling and then calls `OPENSSL_init_ssl(0, null)`.
/// This function does not return errors and intentionally ignores OpenSSL's return value.
/// Effects are global to the process and should be treated as one-time startup initialization.
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

/// Creates a new client-side `SSL_CTX` using `TLS_client_method()`.
/// Returns `error.NoTlsMethod` if no TLS client method is available.
/// Returns `error.SslCtxNew` if `SSL_CTX_new` fails to allocate/initialize the context.
/// On success, the caller owns the returned `*SSL_CTX` and must release it with `SSL_CTX_free`.
pub fn createClientCtx() !*SSL_CTX {
    const method = TLS_client_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    // NOTE: SSL_CTX_set_min_proto_version is BoringSSL-specific, not in OpenSSL
    // TODO: Use OpenSSL-compatible SSL_CTX_set_options with SSL_OP_NO_TLSv1 etc
    // _ = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

/// Creates a server-side `SSL_CTX` using `TLS_server_method()` and `SSL_CTX_new()`.
/// On success, it applies server ALPN and certificate-selection hook configuration before returning.
/// Returns `error.NoTlsMethod` if no TLS server method is available, or `error.SslCtxNew` if context allocation fails.
/// Ownership of the returned context is transferred to the caller, which must release it with `SSL_CTX_free()`.
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

/// OpenSSL TLS extension callback return code indicating success.
/// Use this constant when a callback has handled the extension without error.
/// Numeric value is `0` (`c_int`), matching OpenSSL's `SSL_TLSEXT_ERR_OK`.
pub const SSL_TLSEXT_ERR_OK: c_int = 0;
/// OpenSSL TLS extension callback return code for a fatal alert condition.
/// Use this value to signal that processing must terminate the TLS handshake immediately.
/// Constant value is `2` (`c_int`); it is a status code, not an error union.
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
/// OpenSSL TLS extension callback return code indicating "no acknowledgment".
/// Use this value from extension-related callbacks when no extension response should be sent.
/// Numeric value is `3` and matches the C `SSL_TLSEXT_ERR_NOACK` constant.
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

const alpn_protocol_h2: []const u8 = "h2";
const alpn_protocol_http11: []const u8 = "http/1.1";
const alpn_protocol_acme_tls_1: []const u8 = "acme-tls/1";

/// Public re-export of `serval-core.config.AlpnMixedOfferPolicy` for TLS-facing APIs in this module.
/// Governs ALPN behavior for mixed `h2`/`http/1.1` client offers, including strict `http11_only` deployments.
/// Variant semantics are defined by the source enum (`prefer_http11`, `prefer_h2`, `http11_only`); this alias does not modify them.
/// This is a private type alias only: no allocation, ownership/lifetime effects, or error behavior.
const AlpnMixedOfferPolicy = config.AlpnMixedOfferPolicy;

/// Decision for server-side ALPN hook handling during TLS negotiation.
/// `default_policy` applies the normal ALPN selection policy.
/// `force_acme_tls_1` forces handling as ACME `tls-alpn-01` (`acme-tls/1`).
/// `reject` rejects the connection during ALPN processing.
pub const ServerAlpnHookDecision = enum {
    default_policy,
    force_acme_tls_1,
    reject,
};

/// Input passed to server-side ALPN selection logic for a single TLS handshake.
/// `sni` is the client-provided Server Name Indication, or `null` when SNI is absent.
/// The `client_offers_*` flags indicate whether the client advertised each ALPN token (`http/1.1`, `h2`, `acme-tls/1`).
/// This is read-only handshake metadata and does not transfer ownership of any referenced bytes.
pub const ServerAlpnHookInput = struct {
    sni: ?[]const u8,
    client_offers_http11: bool,
    client_offers_h2: bool,
    client_offers_acme_tls_1: bool,
};

/// Callback type for process-wide server ALPN override logic (set via `setServerAlpnHook`).
/// Called with a non-null, read-only `input` snapshot of SNI and client-offered ALPN protocols.
/// `input` is borrowed for the duration of the call only; implementations must not store the pointer.
/// Returns a `ServerAlpnHookDecision` (`.default_policy`, `.force_acme_tls_1`, or `.reject`) and does not use Zig error returns.
pub const ServerAlpnHook = *const fn (input: *const ServerAlpnHookInput) ServerAlpnHookDecision;

/// Decision returned by the server-certificate hook to control TLS context selection per connection.
/// `default_ctx` keeps using the listener/server default `SSL_CTX`.
/// `reject` declines the connection instead of selecting a certificate context.
/// `override_ctx` selects the provided `*SSL_CTX` for this connection.
pub const ServerCertHookDecision = union(enum) {
    default_ctx,
    reject,
    override_ctx: *SSL_CTX,
};

/// Input passed to the server-certificate selection hook.
/// `sni` is the hostname from the TLS SNI extension, or `null` when the client did not send SNI.
/// The hostname slice is read-only (`[]const u8`) and not NUL-terminated.
/// This struct does not own `sni`; copy it if you need to keep it beyond hook processing.
pub const ServerCertHookInput = struct {
    sni: ?[]const u8,
};

/// Process-wide hook signature used during server-name (SNI) certificate selection.
/// `input` is read-only and call-scoped; its `sni` may be `null` when no usable hostname is available.
/// The hook must not retain `input` or any slice it references beyond the call.
/// Return `.default_ctx` to keep the current context, `.reject` to fail the handshake, or `.override_ctx` to request `SSL_set_SSL_CTX` with the provided context.
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

/// Sets the server-side ALPN mixed-offer policy to `policy`.
/// This updates the module-level policy value used by TLS server ALPN handling.
/// Does not allocate or return errors; the assignment takes effect immediately.
pub fn setServerAlpnMixedOfferPolicy(policy: AlpnMixedOfferPolicy) void {
    server_alpn_mixed_offer_policy = policy;
}

/// Returns the current server ALPN mixed-offer policy configured in this module.
/// This is a pure accessor with no side effects and no required preconditions.
/// The policy is returned by value (`AlpnMixedOfferPolicy`) and cannot fail.
pub fn getServerAlpnMixedOfferPolicy() AlpnMixedOfferPolicy {
    return server_alpn_mixed_offer_policy;
}

/// Sets the process-wide server ALPN callback used by TLS server handshakes.
/// Pass a non-null `hook` to install/replace the callback, or `null` to clear it.
/// The value is stored directly for later use; this function does not take ownership of external state.
/// This operation cannot fail and reports no errors.
pub fn setServerAlpnHook(hook: ?ServerAlpnHook) void {
    server_alpn_hook = hook;
}

/// Returns the currently configured server ALPN selection hook.
/// The result is `null` when no hook has been registered.
/// This function does not allocate or transfer ownership; it only exposes the stored hook value.
pub fn getServerAlpnHook() ?ServerAlpnHook {
    return server_alpn_hook;
}

/// Sets the global server-certificate hook used by the TLS layer.
/// Pass a non-null `hook` to install/replace the current callback; pass `null` to clear it.
/// This function only updates stored state and does not perform validation or return errors.
pub fn setServerCertHook(hook: ?ServerCertHook) void {
    server_cert_hook = hook;
}

/// Returns the process-wide server certificate callback currently registered in this module.
/// The result is `null` when no hook has been configured.
/// This is a read-only accessor: it does not allocate, transfer ownership, or modify hook state.
/// This function does not fail and returns immediately.
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

/// Configures ALPN selection for a server `SSL_CTX` by installing `serverAlpnSelectCb`.
/// Uses `server_alpn_mixed_offer_policy` as the callback policy context via `SSL_CTX_set_alpn_select_cb`.
/// `ctx` must be a valid, initialized SSL context intended for server-side handshakes.
/// This function returns no error; any ALPN negotiation failures are handled later by the configured callback.
pub fn configureServerAlpn(ctx: *SSL_CTX) void {
    const policy_ptr: *AlpnMixedOfferPolicy = &server_alpn_mixed_offer_policy;
    SSL_CTX_set_alpn_select_cb(ctx, serverAlpnSelectCb, @ptrCast(policy_ptr));
}

/// Configures `ctx` to use Serval's TLS Server Name Indication (SNI) certificate-selection hook.
/// Sets the OpenSSL servername callback to `serverNameSelectCb` and sets the callback argument to `null`.
/// Preconditions: `ctx` must be a valid, writable `SSL_CTX` initialized by OpenSSL.
/// This function does not transfer ownership; `ctx` lifetime remains managed by the caller, and OpenSSL return values are ignored (no error is reported on failure).
pub fn configureServerCertHook(ctx: *SSL_CTX) void {
    _ = SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, @ptrCast(&serverNameSelectCb));
    _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, null);
}

/// Sets a single client ALPN protocol on `ssl_conn` using OpenSSL's length-prefixed wire format.
/// `protocol` must be non-empty and at most 255 bytes, otherwise `error.InvalidAlpnProtocol` is returned.
/// The protocol bytes are copied into a temporary buffer for the call; the caller keeps ownership of `protocol`.
/// Returns `error.SslSetAlpn` if `SSL_set_alpn_protos` reports failure.
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

/// Creates a new `SSL` object from the provided `SSL_CTX`.
/// Requires `ctx` to point to a valid context suitable for `SSL_new`.
/// Returns a non-null `*SSL` on success; returns `error.SslNew` if allocation/creation fails.
pub fn createSsl(ctx: *SSL_CTX) !*SSL {
    // S1: precondition - ctx pointer must be valid (enforced by type system)
    const ssl_obj = SSL_new(ctx) orelse return error.SslNew;
    // S1: postcondition - ssl is non-null (verified by orelse above)
    return ssl_obj;
}

/// Maps an OpenSSL `SSL_get_error`-style code to a human-readable constant name.
/// Returns string literals like `SSL_ERROR_WANT_READ` for known `SSL_ERROR_*` values.
/// For unrecognized codes, returns `"SSL_ERROR_UNKNOWN"` instead of failing.
/// The returned slice is static, requires no allocation, and is valid for the program lifetime.
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

/// Drains and logs entries from OpenSSL's per-thread error queue at error level (`"SSL: {s}"`).
/// Repeatedly calls `ERR_get_error()` until no error remains or `100` entries have been processed.
/// Formats each code with `ERR_error_string_n` into a zeroed 256-byte stack buffer before logging.
/// This function does not return errors; it only emits log output and has no ownership or lifetime effects.
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
