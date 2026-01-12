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
const posix = std.posix;
const ssl = @import("ssl.zig");
const ktls = @import("ktls.zig");
const handshake_info = @import("handshake_info.zig");
const Allocator = std.mem.Allocator;

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
    const ts = posix.clock_gettime(.MONOTONIC) catch return 0;
    std.debug.assert(ts.sec >= 0);
    const sec_ns: u64 = @as(u64, @intCast(ts.sec)) *% std.time.ns_per_s;
    const nsec: u64 = @intCast(ts.nsec);
    return sec_ns +% nsec;
}

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

    /// Get underlying SSL object for userspace mode, null for kTLS.
    /// Useful for advanced operations (session tickets, renegotiation).
    pub fn getSSL(self: *TLSStream) ?*ssl.SSL {
        return switch (self.mode) {
            .ktls => null,
            .userspace => |ssl_conn| ssl_conn,
        };
    }

    /// Setup kTLS after successful handshake.
    /// Tries OpenSSL native kTLS first, falls back to manual kTLS for BoringSSL.
    /// Returns the appropriate mode and updates info.ktls_enabled.
    fn setupKtlsAfterHandshake(ssl_conn: *ssl.SSL, fd: c_int, info: *HandshakeInfo) Mode {
        // Check if OpenSSL successfully enabled kTLS (set before handshake)
        // OpenSSL handles key extraction and setsockopt internally
        const openssl_ktls_tx = if (ssl.SSL_get_wbio(ssl_conn)) |wbio| ssl.BIO_get_ktls_send(wbio) else false;
        const openssl_ktls_rx = if (ssl.SSL_get_rbio(ssl_conn)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false;
        const openssl_ktls = openssl_ktls_tx and openssl_ktls_rx;

        // If OpenSSL native kTLS didn't work (e.g., BoringSSL), try manual kTLS setup
        var manual_ktls = false;
        if (!openssl_ktls) {
            const ktls_result = ktls.tryEnableKtls(ssl_conn, fd);
            manual_ktls = ktls_result.isKtls();
        }
        info.ktls_enabled = openssl_ktls or manual_ktls;

        // Select mode based on kTLS result:
        // - OpenSSL kTLS: stay in userspace mode (SSL_read/write use kTLS internally via BIO)
        // - Manual kTLS: switch to ktls mode (direct fd I/O, SSL object freed)
        // - No kTLS: userspace mode with full SSL encryption
        if (manual_ktls) {
            ssl.SSL_free(ssl_conn);
            return .ktls;
        }
        return .{ .userspace = ssl_conn };
    }

    /// Log kTLS status after handshake.
    fn logKtlsStatus(info: *const HandshakeInfo, is_server: bool) void {
        const role = if (is_server) "server" else "client";
        const ktls_status = if (info.ktls_enabled) "enabled" else "disabled";
        std.log.info("TLS handshake ({s}): ktls={s}, cipher={s}", .{ role, ktls_status, info.cipher() });
    }

    /// Server-side TLS handshake (client termination).
    /// Uses blocking SSL operations - socket timeouts handled by std.Io.
    pub fn initServer(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        allocator: Allocator,
    ) !TLSStream {
        // S1: preconditions
        std.debug.assert(@intFromPtr(ctx) != 0); // S1: precondition - ctx is valid pointer
        std.debug.assert(fd > 0); // S1: precondition

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        // Enable kTLS before handshake - OpenSSL will attempt kTLS setup automatically
        // This must be done before the handshake for OpenSSL to configure kTLS internally
        _ = ssl.SSL_set_options(ssl_conn, ssl.SSL_OP_ENABLE_KTLS);

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
        std.debug.assert(end_ns >= start_ns); // S1: monotonic clock invariant

        std.debug.assert(ssl.SSL_is_init_finished(ssl_conn) == 1); // S1: postcondition

        // Populate handshake info
        var info = HandshakeInfo{};
        info.client_mode = false;
        info.handshake_duration_ns = @intCast(end_ns - start_ns);
        populateHandshakeInfo(ssl_conn, &info);

        // Setup kTLS and get appropriate mode
        const mode = setupKtlsAfterHandshake(ssl_conn, fd, &info);
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
    ) !TLSStream {
        // S1: preconditions
        std.debug.assert(@intFromPtr(ctx) != 0); // S1: precondition - ctx is valid pointer
        std.debug.assert(fd > 0); // S1: precondition

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        // Enable kTLS before handshake if requested
        if (enable_ktls) {
            _ = ssl.SSL_set_options(ssl_conn, ssl.SSL_OP_ENABLE_KTLS);
        }

        // Set SNI (caller provides null-terminated string - no allocation)
        if (ssl.SSL_set_tlsext_host_name(ssl_conn, sni_z) != 1) return error.SslSetSni;

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
        std.debug.assert(end_ns >= start_ns); // S1: monotonic clock invariant

        std.debug.assert(ssl.SSL_is_init_finished(ssl_conn) == 1); // S1: postcondition

        // Populate handshake info
        var info = HandshakeInfo{};
        info.client_mode = true;
        info.handshake_duration_ns = @intCast(end_ns - start_ns);
        populateHandshakeInfo(ssl_conn, &info);

        // Setup kTLS and get appropriate mode (only if enabled)
        const mode: Mode = if (enable_ktls) blk: {
            const m = setupKtlsAfterHandshake(ssl_conn, fd, &info);
            logKtlsStatus(&info, false);
            break :blk m;
        } else .{ .userspace = ssl_conn };

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
        std.debug.assert(buf.len > 0); // S1: precondition
        std.debug.assert(self.fd > 0); // S1: precondition - fd is valid

        switch (self.mode) {
            .ktls => {
                // kTLS: read directly from kernel (kernel handles TLS decryption)
                const result = posix.read(self.fd, buf);
                const n = result catch |err| {
                    // Map posix errors to TLS errors for consistent API
                    return switch (err) {
                        error.ConnectionResetByPeer => error.ConnectionReset,
                        error.BrokenPipe => error.ConnectionReset,
                        else => error.KtlsRead,
                    };
                };
                if (n == 0) return 0; // Clean shutdown (EOF)
                const bytes_read: u32 = @intCast(n);
                std.debug.assert(bytes_read <= buf.len); // S1: postcondition
                return bytes_read;
            },
            .userspace => |ssl_conn| {
                // Userspace mode: read through OpenSSL (may use kTLS internally via BIO)
                // When kTLS is active, OpenSSL's BIO layer uses kernel TLS transparently
                const n = ssl.SSL_read(ssl_conn, buf.ptr, @intCast(buf.len));
                if (n <= 0) {
                    const err = ssl.SSL_get_error(ssl_conn, n);
                    if (err == ssl.SSL_ERROR_ZERO_RETURN) return 0; // Clean shutdown
                    return error.SslRead;
                }
                const bytes_read: u32 = @intCast(n);
                std.debug.assert(bytes_read <= buf.len); // S1: postcondition
                return bytes_read;
            },
        }
    }

    /// Blocking TLS write.
    /// Returns number of bytes written.
    /// TigerStyle: Explicit switch on mode (no default case).
    pub fn write(self: *TLSStream, data: []const u8) !u32 {
        std.debug.assert(data.len > 0); // S1: precondition
        std.debug.assert(self.fd > 0); // S1: precondition - fd is valid

        switch (self.mode) {
            .ktls => {
                // kTLS: write directly to kernel (kernel handles TLS encryption)
                const result = posix.write(self.fd, data);
                const n = result catch |err| {
                    // Map posix errors to TLS errors for consistent API
                    return switch (err) {
                        error.ConnectionResetByPeer => error.ConnectionReset,
                        error.BrokenPipe => error.ConnectionReset,
                        else => error.KtlsWrite,
                    };
                };
                const bytes_written: u32 = @intCast(n);
                std.debug.assert(bytes_written <= data.len); // S1: postcondition
                return bytes_written;
            },
            .userspace => |ssl_conn| {
                // Userspace: write through BoringSSL
                const n = ssl.SSL_write(ssl_conn, data.ptr, @intCast(data.len));
                if (n <= 0) return error.SslWrite;

                const bytes_written: u32 = @intCast(n);
                std.debug.assert(bytes_written <= data.len); // S1: postcondition
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
                // Userspace: graceful SSL shutdown and free resources
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
    std.debug.assert(@intFromPtr(ssl_conn) != 0);
    std.debug.assert(ssl.SSL_is_init_finished(ssl_conn) == 1);

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
test "TLSStream compiles" {
    // Basic compilation test
    _ = TLSStream;
}
