// lib/serval-tls/stream.zig
//! TLS stream abstraction
//!
//! Provides unified interface for TLS I/O operations with two modes:
//! - Userspace mode: TLS via BoringSSL SSL object (default after handshake)
//! - kTLS mode: Kernel TLS offload for symmetric crypto (upgrade from userspace)
//!
//! This module uses blocking SSL operations. The underlying socket is managed
//! by std.Io's async layer, so SSL can safely use blocking calls.
//! - initServer: Server-side TLS termination (client connections)
//! - initClient: Client-side TLS origination (upstream connections) with SNI
//! - read/write: Blocking TLS I/O (socket-level timeouts via std.Io)
//! - close: Graceful TLS shutdown

const std = @import("std");
const log = @import("serval-core").log.scoped(.tls);
const closeFd = @import("serval-core").closeFd;
const assert = std.debug.assert;
const posix = std.posix;
const ssl = @import("ssl.zig");
const ktls = @import("ktls.zig");
const handshake_info = @import("handshake_info.zig");
const Allocator = std.mem.Allocator;

/// Alias of `handshake_info.HandshakeInfo`, used by `TLSStream` to carry completed-handshake metadata.
/// Pure type alias: fields, methods, and invariants are exactly those defined in `handshake_info.zig`.
/// Values are plain struct data with fixed-size internal buffers and no heap ownership transfer.
/// Declaring or referencing this alias has no runtime side effects and no error behavior.
pub const HandshakeInfo = handshake_info.HandshakeInfo;

/// TLS operation mode.
/// TigerStyle: Tagged union for explicit mode handling (no default cases).
pub const Mode = union(enum) {
    /// Kernel TLS offload - read/write go directly to kernel.
    /// After kTLS setup, symmetric crypto is handled by the kernel.
    ktls: void,
    /// Userspace TLS via BoringSSL SSL object.
    /// All TLS operations go through the SSL library.
    userspace: *ssl.SSL,
};

/// Get monotonic timestamp in nanoseconds for timing measurements.
/// TigerStyle: Local helper to avoid serval-core dependency (layer isolation).
fn monotonicNanos() u64 {
    const ts = std.Io.Clock.awake.now(std.Options.debug_io);
    assert(ts.nanoseconds >= 0);
    return @intCast(ts.nanoseconds);
}

/// Represents an established TLS stream on `fd`, with runtime state for either userspace TLS or manual kTLS I/O.
/// `mode` selects backend behavior: `.userspace` carries an OpenSSL connection, while `.ktls` uses direct fd-based kernel offload semantics.
/// `info` holds handshake-derived metadata (including cached kTLS enablement) used for fast status checks without extra work.
/// Introspection methods on this type are non-throwing and return conservative fallbacks (`false`/`null`) when backend state is not available.
pub const TLSStream = struct {
    fd: c_int,
    mode: Mode,
    allocator: Allocator,
    info: HandshakeInfo,

    /// Check if stream is using kTLS (kernel TLS offload).
    /// Uses cached value from handshake - zero overhead.
    pub fn isKtls(self: *const TLSStream) bool {
        return self.info.ktls_enabled;
    }

    /// Check if stream is using manual kTLS mode (direct fd I/O).
    /// This mode is only used with BoringSSL where we extract keys manually.
    pub fn isManualKtls(self: *const TLSStream) bool {
        return self.mode == .ktls;
    }

    /// Query current kTLS status from OpenSSL BIO layer (for diagnostics).
    /// Slightly more overhead than isKtls() - use sparingly in hot paths.
    pub fn queryKtlsStatus(self: *const TLSStream) struct { tx: bool, rx: bool, manual: bool } {
        return switch (self.mode) {
            .ktls => .{ .tx = true, .rx = true, .manual = true },
            .userspace => |ssl_conn| .{
                .tx = if (ssl.SSL_get_wbio(ssl_conn)) |wbio| ssl.BIO_get_ktls_send(wbio) else false,
                .rx = if (ssl.SSL_get_rbio(ssl_conn)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false,
                .manual = false,
            },
        };
    }

    /// Returns true if the TLS library has decrypted plaintext buffered.
    /// When true, a subsequent `read()` will return data immediately even if
    /// the underlying fd would not be poll-readable.
    /// TigerStyle: Required for correct poll-based multiplexing on TLS sockets.
    pub fn hasPendingRead(self: *const TLSStream) bool {
        return switch (self.mode) {
            .ktls => false,
            .userspace => |ssl_conn| blk: {
                const pending = ssl.SSL_pending(ssl_conn);
                break :blk pending > 0;
            },
        };
    }

    /// Get underlying SSL object for userspace mode, null for kTLS.
    /// Useful for advanced operations (session tickets, renegotiation).
    pub fn getSSL(self: *TLSStream) ?*ssl.SSL {
        return switch (self.mode) {
            .ktls => null,
            .userspace => |ssl_conn| ssl_conn,
        };
    }

    /// Check native kTLS status after successful handshake.
    /// OpenSSL handles kernel TLS setup internally when SSL_OP_ENABLE_KTLS is set.
    /// Returns userspace mode always; OpenSSL BIO transparently uses kTLS when active.
    fn setupKtlsAfterHandshake(ssl_conn: *ssl.SSL, info: *HandshakeInfo, enable_ktls: bool) Mode {
        if (!enable_ktls) {
            info.ktls_enabled = false;
            return .{ .userspace = ssl_conn };
        }

        const tx_ktls = if (ssl.SSL_get_wbio(ssl_conn)) |wbio| ssl.BIO_get_ktls_send(wbio) else false;
        const rx_ktls = if (ssl.SSL_get_rbio(ssl_conn)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false;
        info.ktls_enabled = tx_ktls or rx_ktls;
        return .{ .userspace = ssl_conn };
    }

    /// Log kTLS status after handshake.
    fn logKtlsStatus(info: *const HandshakeInfo, is_server: bool) void {
        const role = if (is_server) "server" else "client";
        const ktls_status = if (info.ktls_enabled) "enabled" else "disabled";
        log.info("TLS handshake ({s}): ktls={s}, cipher={s}", .{ role, ktls_status, info.cipher() });
    }

    /// Server-side TLS handshake (client termination).
    /// Uses blocking SSL operations - socket timeouts handled by std.Io.
    pub fn initServer(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        allocator: Allocator,
    ) !TLSStream {
        // S1: preconditions
        assert(@intFromPtr(ctx) != 0); // S1: precondition - ctx is valid pointer
        assert(fd > 0); // S1: precondition

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        const enable_ktls: bool = ktls.isKtlsRuntimeAvailable();
        if (enable_ktls) {
            _ = ssl.SSL_set_options(ssl_conn, ssl.SSL_OP_ENABLE_KTLS);
        }
        ssl.SSL_set_accept_state(ssl_conn);

        // Capture handshake timing
        const start_ns: u64 = monotonicNanos();

        // Blocking handshake - std.Io handles socket-level async
        const ret = ssl.SSL_accept(ssl_conn);
        if (ret != 1) {
            ssl.printErrors();
            return error.HandshakeFailed;
        }

        const end_ns: u64 = monotonicNanos();
        assert(end_ns >= start_ns); // S1: monotonic clock invariant

        assert(ssl.SSL_is_init_finished(ssl_conn) == 1); // S1: postcondition

        // Populate handshake info
        var info = HandshakeInfo{};
        info.client_mode = false;
        info.handshake_duration_ns = @intCast(end_ns - start_ns);
        populateHandshakeInfo(ssl_conn, &info);

        // Setup kTLS and get appropriate mode
        const mode = setupKtlsAfterHandshake(ssl_conn, &info, enable_ktls);
        logKtlsStatus(&info, true);

        return .{
            .fd = fd,
            .mode = mode,
            .allocator = allocator,
            .info = info,
        };
    }

    /// Client-side TLS handshake (upstream origination) with SNI.
    /// Uses blocking SSL operations - socket timeouts handled by std.Io.
    /// TigerStyle S5: Caller must provide null-terminated SNI to avoid runtime allocation.
    pub fn initClient(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        sni_z: [*:0]const u8,
        allocator: Allocator,
        enable_ktls: bool,
        desired_alpn: ?[]const u8,
        verify_peer: bool,
    ) !TLSStream {
        // S1: preconditions
        assert(@intFromPtr(ctx) != 0); // S1: precondition - ctx is valid pointer
        assert(fd > 0); // S1: precondition

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        const should_enable_ktls: bool = enable_ktls and ktls.isKtlsRuntimeAvailable();
        if (should_enable_ktls) {
            _ = ssl.SSL_set_options(ssl_conn, ssl.SSL_OP_ENABLE_KTLS);
        }
        // Set SNI (caller provides null-terminated string - no allocation)
        if (ssl.SSL_set_tlsext_host_name(ssl_conn, sni_z) != 1) return error.SslSetSni;

        if (desired_alpn) |protocol| {
            try ssl.setClientAlpnProtocol(ssl_conn, protocol);
        }

        if (verify_peer) {
            ssl.SSL_set_verify(ssl_conn, ssl.SSL_VERIFY_PEER, null);
        } else {
            ssl.SSL_set_verify(ssl_conn, ssl.SSL_VERIFY_NONE, null);
        }
        ssl.SSL_set_connect_state(ssl_conn);

        // Capture handshake timing
        const start_ns: u64 = monotonicNanos();

        // Blocking handshake - std.Io handles socket-level async
        const ret = ssl.SSL_connect(ssl_conn);
        if (ret != 1) {
            ssl.printErrors();
            return error.HandshakeFailed;
        }

        const end_ns: u64 = monotonicNanos();
        assert(end_ns >= start_ns); // S1: monotonic clock invariant

        assert(ssl.SSL_is_init_finished(ssl_conn) == 1); // S1: postcondition

        // Populate handshake info
        var info = HandshakeInfo{};
        info.client_mode = true;
        info.handshake_duration_ns = @intCast(end_ns - start_ns);
        populateHandshakeInfo(ssl_conn, &info);

        // Setup kTLS and get appropriate mode (only if enabled and runtime support exists)
        const mode: Mode = if (should_enable_ktls) blk: {
            const m = setupKtlsAfterHandshake(ssl_conn, &info, true);
            logKtlsStatus(&info, false);
            break :blk m;
        } else .{ .userspace = ssl_conn };

        if (!should_enable_ktls) {
            info.ktls_enabled = false;
            logKtlsStatus(&info, false);
        }

        return .{
            .fd = fd,
            .mode = mode,
            .allocator = allocator,
            .info = info,
        };
    }

    /// Blocking TLS read.
    /// Returns number of bytes read, or 0 on clean shutdown.
    /// TigerStyle: Explicit switch on mode (no default case).
    pub fn read(self: *TLSStream, buf: []u8) !u32 {
        assert(buf.len > 0); // S1: precondition
        assert(self.fd > 0); // S1: precondition - fd is valid

        switch (self.mode) {
            .ktls => {
                // kTLS: read directly from kernel (kernel handles TLS decryption)
                const result = posix.read(self.fd, buf);
                const n = result catch |err| {
                    // Map posix errors to TLS errors for consistent API
                    return switch (err) {
                        error.ConnectionResetByPeer => error.ConnectionReset,
                        else => error.KtlsRead,
                    };
                };
                if (n == 0) return 0; // Clean shutdown (EOF)
                const bytes_read: u32 = @intCast(n);
                assert(bytes_read <= buf.len); // S1: postcondition
                return bytes_read;
            },
            .userspace => |ssl_conn| {
                // Userspace mode: read through OpenSSL (may use kTLS internally via BIO)
                // When kTLS is active, OpenSSL's BIO layer uses kernel TLS transparently
                const n = ssl.SSL_read(ssl_conn, buf.ptr, @intCast(buf.len));
                if (n <= 0) {
                    const err = ssl.SSL_get_error(ssl_conn, n);
                    switch (err) {
                        ssl.SSL_ERROR_ZERO_RETURN => {
                            log.info(
                                "TLS read closed: reason=close_notify fd={d} cipher={s}",
                                .{ self.fd, self.info.cipher() },
                            );
                            return 0;
                        },
                        ssl.SSL_ERROR_WANT_READ => return error.WantRead,
                        ssl.SSL_ERROR_WANT_WRITE => return error.WantWrite,
                        ssl.SSL_ERROR_SYSCALL => {
                            log.warn(
                                "TLS read failed: reason=peer_reset fd={d} cipher={s} ssl_error={s} ret={d}",
                                .{ self.fd, self.info.cipher(), ssl.sslErrorName(err), n },
                            );
                            ssl.printErrors();
                            return error.ConnectionReset;
                        },
                        ssl.SSL_ERROR_SSL => {
                            log.warn(
                                "TLS read failed: reason=tls_protocol fd={d} cipher={s} ssl_error={s} ret={d}",
                                .{ self.fd, self.info.cipher(), ssl.sslErrorName(err), n },
                            );
                            ssl.printErrors();
                            return error.SslRead;
                        },
                        else => {
                            log.warn(
                                "TLS read failed: reason=ssl_unexpected fd={d} cipher={s} ssl_error={s} ret={d}",
                                .{ self.fd, self.info.cipher(), ssl.sslErrorName(err), n },
                            );
                            ssl.printErrors();
                            return error.SslRead;
                        },
                    }
                }
                const bytes_read: u32 = @intCast(n);
                assert(bytes_read <= buf.len); // S1: postcondition
                return bytes_read;
            },
        }
    }

    /// TLS write with nonblocking-aware error mapping.
    /// Returns number of bytes written.
    /// TigerStyle: Explicit switch on mode (no default case).
    pub fn write(self: *TLSStream, data: []const u8) !u32 {
        assert(data.len > 0); // S1: precondition
        assert(self.fd > 0); // S1: precondition - fd is valid

        switch (self.mode) {
            .ktls => {
                // kTLS: write directly to kernel (kernel handles TLS encryption)
                const file: std.Io.File = .{
                    .handle = self.fd,
                    .flags = .{ .nonblocking = true },
                };
                const n = file.writeStreaming(std.Options.debug_io, &.{}, &.{data}, 1) catch |err| {
                    // Map write errors to TLS errors for consistent API.
                    // Nonblocking write can legitimately stall; caller retries with bounds.
                    return switch (err) {
                        error.BrokenPipe => error.ConnectionReset,
                        error.WouldBlock => error.WantRead,
                        else => error.KtlsWrite,
                    };
                };
                const bytes_written: u32 = @intCast(n);
                assert(bytes_written <= data.len); // S1: postcondition
                return bytes_written;
            },
            .userspace => |ssl_conn| {
                // Userspace: write through OpenSSL/BoringSSL.
                // On nonblocking fds, WANT_READ/WANT_WRITE are retryable, not fatal.
                const n = ssl.SSL_write(ssl_conn, data.ptr, @intCast(data.len));
                if (n <= 0) {
                    const ssl_err = ssl.SSL_get_error(ssl_conn, n);
                    switch (ssl_err) {
                        ssl.SSL_ERROR_WANT_READ, ssl.SSL_ERROR_WANT_WRITE => return error.WouldBlock,
                        ssl.SSL_ERROR_ZERO_RETURN => return error.ConnectionReset,
                        ssl.SSL_ERROR_SYSCALL => return error.ConnectionReset,
                        else => return error.SslWrite,
                    }
                }

                const bytes_written: u32 = @intCast(n);
                assert(bytes_written <= data.len); // S1: postcondition
                return bytes_written;
            },
        }
    }

    /// Graceful TLS shutdown.
    /// Caller owns fd and is responsible for closing it.
    /// TigerStyle: Explicit switch on mode (no default case).
    pub fn close(self: *TLSStream) void {
        switch (self.mode) {
            .ktls => {
                // kTLS: kernel handles TLS shutdown when fd is closed
                // No SSL resources to free, caller closes fd
            },
            .userspace => |ssl_conn| {
                // Userspace: quiet shutdown avoids writing close_notify into a
                // peer that already closed, which can otherwise raise SIGPIPE
                // during tunnel cleanup on OpenSSL's socket BIO path.
                ssl.SSL_set_quiet_shutdown(ssl_conn, 1);
                _ = ssl.SSL_shutdown(ssl_conn);
                ssl.SSL_free(ssl_conn);
            },
        }
        // Caller owns fd, don't close it here
    }
};

/// Extract TLS session info from completed handshake.
/// Populates version, cipher, resumed, ALPN, and peer certificate info.
fn populateHandshakeInfo(ssl_conn: *ssl.SSL, info: *HandshakeInfo) void {
    // S1: preconditions
    assert(@intFromPtr(ssl_conn) != 0);
    assert(ssl.SSL_is_init_finished(ssl_conn) == 1);

    // TLS version (e.g., "TLSv1.3")
    if (ssl.SSL_get_version(ssl_conn)) |version_ptr| {
        const version_str = std.mem.sliceTo(version_ptr, 0);
        const len: u8 = @intCast(@min(version_str.len, HandshakeInfo.VERSION_BUF_SIZE));
        @memcpy(info.version_buf[0..len], version_str[0..len]);
        info.version_len = len;
    }

    // Cipher suite (e.g., "TLS_AES_256_GCM_SHA384")
    if (ssl.SSL_get_current_cipher(ssl_conn)) |cipher| {
        if (ssl.SSL_CIPHER_get_name(cipher)) |name_ptr| {
            const cipher_str = std.mem.sliceTo(name_ptr, 0);
            const len: u8 = @intCast(@min(cipher_str.len, HandshakeInfo.CIPHER_BUF_SIZE));
            @memcpy(info.cipher_buf[0..len], cipher_str[0..len]);
            info.cipher_len = len;
        }
    }

    // Session resumption
    info.resumed = ssl.SSL_session_reused(ssl_conn) != 0;

    // ALPN protocol (e.g., "h2", "http/1.1")
    // Note: SSL_get0_alpn_selected sets data to NULL if no ALPN negotiated
    var alpn_data: ?[*]const u8 = null;
    var alpn_len: c_uint = 0;
    ssl.SSL_get0_alpn_selected(ssl_conn, &alpn_data, &alpn_len);
    if (alpn_len > 0) {
        if (alpn_data) |data| {
            const len: u8 = @intCast(@min(alpn_len, HandshakeInfo.ALPN_BUF_SIZE));
            @memcpy(info.alpn_buf[0..len], data[0..len]);
            info.alpn_len = len;
        }
    }

    // Peer certificate subject and issuer
    if (ssl.SSL_get1_peer_certificate(ssl_conn)) |cert| {
        defer ssl.X509_free(cert);

        // Subject
        if (ssl.X509_get_subject_name(cert)) |subject| {
            if (ssl.X509_NAME_oneline(subject, &info.cert_subject_buf, HandshakeInfo.CERT_NAME_BUF_SIZE)) |result| {
                const subject_str = std.mem.sliceTo(result, 0);
                info.cert_subject_len = @intCast(subject_str.len);
            }
        }

        // Issuer
        if (ssl.X509_get_issuer_name(cert)) |issuer| {
            if (ssl.X509_NAME_oneline(issuer, &info.cert_issuer_buf, HandshakeInfo.CERT_NAME_BUF_SIZE)) |result| {
                const issuer_str = std.mem.sliceTo(result, 0);
                info.cert_issuer_len = @intCast(issuer_str.len);
            }
        }
    }
}

// Tests
test "native kTLS BIO status after loopback handshake" {
    const builtin = @import("builtin");

    if (builtin.os.tag != .linux) return error.SkipZigTest;

    ssl.init();

    // Skip when TLS test fixtures are unavailable in this checkout.
    const cert_path = "experiments/tls-poc/cert.pem";
    const key_path = "experiments/tls-poc/key.pem";
    const cert_fd = posix.openat(posix.AT.FDCWD, cert_path, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    closeFd(cert_fd);
    const key_fd = posix.openat(posix.AT.FDCWD, key_path, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    closeFd(key_fd);

    const server_ctx = try ssl.createServerCtxFromPemFiles(cert_path, key_path);
    defer ssl.SSL_CTX_free(server_ctx);

    const client_ctx = try ssl.createClientCtx();
    defer ssl.SSL_CTX_free(client_ctx);

    // Nonblocking socketpair prevents single-threaded handshake deadlocks.
    const linux = std.os.linux;
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK, 0, &fds);
    if (posix.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const server_ssl = ssl.SSL_new(server_ctx) orelse return error.SslNew;
    defer ssl.SSL_free(server_ssl);
    _ = ssl.SSL_set_options(server_ssl, ssl.SSL_OP_ENABLE_KTLS);
    if (ssl.SSL_set_fd(server_ssl, fds[0]) != 1) return error.SslSetFd;
    ssl.SSL_set_accept_state(server_ssl);

    const client_ssl = ssl.SSL_new(client_ctx) orelse return error.SslNew;
    defer ssl.SSL_free(client_ssl);
    ssl.SSL_set_verify(client_ssl, ssl.SSL_VERIFY_NONE, null);
    _ = ssl.SSL_set_options(client_ssl, ssl.SSL_OP_ENABLE_KTLS);
    if (ssl.SSL_set_fd(client_ssl, fds[1]) != 1) return error.SslSetFd;
    ssl.SSL_set_connect_state(client_ssl);

    const max_handshake_rounds: u32 = 200;
    var rounds: u32 = 0;
    var client_done = false;
    var server_done = false;
    while (rounds < max_handshake_rounds and (!client_done or !server_done)) : (rounds += 1) {
        if (!client_done) {
            const client_rc = ssl.SSL_do_handshake(client_ssl);
            if (client_rc == 1) {
                client_done = true;
            } else {
                const client_err = ssl.SSL_get_error(client_ssl, client_rc);
                if (client_err != ssl.SSL_ERROR_WANT_READ and client_err != ssl.SSL_ERROR_WANT_WRITE) {
                    return error.HandshakeFailed;
                }
            }
        }

        if (!server_done) {
            const server_rc = ssl.SSL_do_handshake(server_ssl);
            if (server_rc == 1) {
                server_done = true;
            } else {
                const server_err = ssl.SSL_get_error(server_ssl, server_rc);
                if (server_err != ssl.SSL_ERROR_WANT_READ and server_err != ssl.SSL_ERROR_WANT_WRITE) {
                    return error.HandshakeFailed;
                }
            }
        }
    }
    if (!client_done or !server_done) return error.HandshakeFailed;

    const ktls_available = ktls.isKtlsRuntimeAvailable();
    const server_tx = if (ssl.SSL_get_wbio(server_ssl)) |wbio| ssl.BIO_get_ktls_send(wbio) else false;
    const server_rx = if (ssl.SSL_get_rbio(server_ssl)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false;

    if (server_rx) {
        try std.testing.expect(server_tx);
    }

    if (!ktls_available) {
        try std.testing.expect(!server_tx);
        try std.testing.expect(!server_rx);
    }

    if (server_tx or server_rx) {
        try std.testing.expect(ktls_available);
    }
}

test "TLSStream compiles" {
    // Basic compilation test
    _ = TLSStream;
}
