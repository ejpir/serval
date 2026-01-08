// lib/serval-tls/stream.zig
//! TLS stream abstraction
//!
//! Provides unified interface for TLS I/O operations.
//! Phase 1: Userspace-only implementation (kTLS deferred).
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
const handshake_info = @import("handshake_info.zig");
const Allocator = std.mem.Allocator;

pub const HandshakeInfo = handshake_info.HandshakeInfo;

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
    ssl: *ssl.SSL,
    allocator: Allocator,
    info: HandshakeInfo,

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

        return .{
            .fd = fd,
            .ssl = ssl_conn,
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
    ) !TLSStream {
        // S1: preconditions
        std.debug.assert(@intFromPtr(ctx) != 0); // S1: precondition - ctx is valid pointer
        std.debug.assert(fd > 0); // S1: precondition

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

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

        return .{
            .fd = fd,
            .ssl = ssl_conn,
            .allocator = allocator,
            .info = info,
        };
    }

    /// Blocking TLS read.
    /// Returns number of bytes read, or 0 on clean shutdown.
    pub fn read(self: *TLSStream, buf: []u8) !u32 {
        std.debug.assert(buf.len > 0); // S1: precondition

        const n = ssl.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (n <= 0) {
            const err = ssl.SSL_get_error(self.ssl, n);
            if (err == ssl.SSL_ERROR_ZERO_RETURN) return 0; // Clean shutdown
            return error.SslRead;
        }
        const bytes_read: u32 = @intCast(n);
        std.debug.assert(bytes_read <= buf.len); // S1: postcondition
        return bytes_read;
    }

    /// Blocking TLS write.
    /// Returns number of bytes written.
    pub fn write(self: *TLSStream, data: []const u8) !u32 {
        std.debug.assert(data.len > 0); // S1: precondition

        const n = ssl.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (n <= 0) return error.SslWrite;

        const bytes_written: u32 = @intCast(n);
        std.debug.assert(bytes_written <= data.len); // S1: postcondition
        return bytes_written;
    }

    /// Graceful TLS shutdown.
    /// Caller owns fd and is responsible for closing it.
    pub fn close(self: *TLSStream) void {
        _ = ssl.SSL_shutdown(self.ssl);
        ssl.SSL_free(self.ssl);
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
