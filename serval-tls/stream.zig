// lib/serval-tls/stream.zig
//! TLS stream abstraction
//!
//! Provides unified interface for TLS I/O operations.
//! Phase 1: Userspace-only implementation (kTLS deferred).
//!
//! This module implements async TLS I/O using BoringSSL with io_uring integration.
//! - initServer: Server-side TLS termination (client connections)
//! - initClient: Client-side TLS origination (upstream connections) with SNI
//! - read/write: Non-blocking TLS I/O with timeouts
//! - close: Graceful TLS shutdown

const std = @import("std");
const ssl = @import("ssl.zig");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const TlsStream = struct {
    fd: c_int,
    ssl: *ssl.SSL,
    allocator: Allocator,

    /// Server-side TLS handshake (client termination).
    /// Sets up non-blocking TLS socket and performs handshake with timeout.
    pub fn initServer(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        io: *Io,
        timeout_ns: i64,
        allocator: Allocator,
    ) !TlsStream {
        std.debug.assert(ctx != null); // S1: precondition
        std.debug.assert(fd > 0); // S1: precondition
        std.debug.assert(timeout_ns > 0); // S1: precondition

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        // Set non-blocking mode
        const flags: u32 = @intCast(try posix.fcntl(fd, posix.F.GETFL, 0));
        _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.O.NONBLOCK);

        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;
        ssl.SSL_set_accept_state(ssl_conn);

        try doHandshake(ssl_conn, fd, io, timeout_ns);

        std.debug.assert(ssl_conn != null); // S1: postcondition
        return .{
            .fd = fd,
            .ssl = ssl_conn,
            .allocator = allocator,
        };
    }

    /// Client-side TLS handshake (upstream origination) with SNI.
    /// Sets up non-blocking TLS socket and performs handshake with timeout.
    pub fn initClient(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        io: *Io,
        sni: []const u8,
        timeout_ns: i64,
        allocator: Allocator,
    ) !TlsStream {
        std.debug.assert(ctx != null); // S1: precondition
        std.debug.assert(fd > 0); // S1: precondition
        std.debug.assert(sni.len > 0); // S1: precondition
        std.debug.assert(timeout_ns > 0); // S1: precondition

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        // Set non-blocking mode
        const flags: u32 = @intCast(try posix.fcntl(fd, posix.F.GETFL, 0));
        _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.O.NONBLOCK);

        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        // Set SNI (init-time allocation)
        const sni_z = try allocator.dupeZ(u8, sni);
        defer allocator.free(sni_z);
        if (ssl.SSL_set_tlsext_host_name(ssl_conn, sni_z) != 1) return error.SslSetSni;

        ssl.SSL_set_connect_state(ssl_conn);

        try doHandshake(ssl_conn, fd, io, timeout_ns);

        std.debug.assert(ssl_conn != null); // S1: postcondition
        return .{
            .fd = fd,
            .ssl = ssl_conn,
            .allocator = allocator,
        };
    }

    /// Non-blocking TLS read with timeout.
    /// Returns number of bytes read, or 0 on clean shutdown.
    pub fn read(
        self: *TlsStream,
        io: *Io,
        buf: []u8,
        timeout_ns: i64,
    ) !usize {
        std.debug.assert(self.ssl != null); // S1: precondition
        std.debug.assert(buf.len > 0); // S1: precondition
        std.debug.assert(timeout_ns > 0); // S1: precondition

        const start_ns: i64 = std.time.nanoTimestamp();
        var iteration: u32 = 0;
        const max_iterations: u32 = 10000; // S3: bounded loop

        while (iteration < max_iterations) { // S3: explicit bound
            iteration += 1;

            const now_ns: i64 = std.time.nanoTimestamp();
            const elapsed_ns: i64 = now_ns - start_ns;
            std.debug.assert(elapsed_ns >= 0); // S1: monotonic clock invariant
            if (elapsed_ns > timeout_ns) return error.Timeout;

            const remaining_ns: i64 = timeout_ns - elapsed_ns;

            const ret: c_int = ssl.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
            if (ret > 0) {
                const bytes_read: usize = @intCast(ret);
                std.debug.assert(bytes_read <= buf.len); // S1: postcondition
                return bytes_read;
            }

            const err: c_int = ssl.SSL_get_error(self.ssl, ret);
            switch (err) { // S4: explicit error handling
                ssl.SSL_ERROR_WANT_READ => try io.pollIn(self.fd, remaining_ns),
                ssl.SSL_ERROR_ZERO_RETURN => return 0, // Clean shutdown
                else => return error.SslRead,
            }
        }

        return error.ReadMaxIterations; // S3: bounded loop exit
    }

    /// Non-blocking TLS write with timeout.
    /// Returns number of bytes written.
    pub fn write(
        self: *TlsStream,
        io: *Io,
        data: []const u8,
        timeout_ns: i64,
    ) !usize {
        std.debug.assert(self.ssl != null); // S1: precondition
        std.debug.assert(data.len > 0); // S1: precondition
        std.debug.assert(timeout_ns > 0); // S1: precondition

        const start_ns: i64 = std.time.nanoTimestamp();
        var written: usize = 0;
        var iteration: u32 = 0;
        const max_iterations: u32 = 10000; // S3: bounded loop

        while (written < data.len and iteration < max_iterations) { // S3: explicit bound
            iteration += 1;

            const now_ns: i64 = std.time.nanoTimestamp();
            const elapsed_ns: i64 = now_ns - start_ns;
            std.debug.assert(elapsed_ns >= 0); // S1: monotonic clock invariant
            if (elapsed_ns > timeout_ns) return error.Timeout;

            const remaining_ns: i64 = timeout_ns - elapsed_ns;
            const chunk = data[written..];
            std.debug.assert(chunk.len > 0); // S1: invariant

            const ret: c_int = ssl.SSL_write(self.ssl, chunk.ptr, @intCast(chunk.len));
            if (ret > 0) {
                const bytes_written: usize = @intCast(ret);
                std.debug.assert(bytes_written <= chunk.len); // S1: postcondition
                written += bytes_written;
                continue;
            }

            const err: c_int = ssl.SSL_get_error(self.ssl, ret);
            switch (err) { // S4: explicit error handling
                ssl.SSL_ERROR_WANT_WRITE => try io.pollOut(self.fd, remaining_ns),
                else => return error.SslWrite,
            }
        }

        if (written < data.len) return error.WriteMaxIterations; // S3: bounded loop exit
        std.debug.assert(written == data.len); // S1: postcondition
        return written;
    }

    /// Graceful TLS shutdown.
    /// Caller owns fd and is responsible for closing it.
    pub fn close(self: *TlsStream) void {
        std.debug.assert(self.ssl != null); // S1: precondition
        _ = ssl.SSL_shutdown(self.ssl);
        ssl.SSL_free(self.ssl);
        // Caller owns fd, don't close it here
    }
};

/// Private helper for async TLS handshake with timeout.
/// Used by both initServer and initClient.
fn doHandshake(
    ssl_conn: *ssl.SSL,
    fd: c_int,
    io: *Io,
    timeout_ns: i64,
) !void {
    std.debug.assert(ssl_conn != null); // S1: precondition
    std.debug.assert(fd > 0); // S1: precondition
    std.debug.assert(timeout_ns > 0); // S1: precondition

    const start_ns: i64 = std.time.nanoTimestamp();
    var iteration: u32 = 0;
    const max_iterations: u32 = 1000; // S3: bounded loop

    while (iteration < max_iterations) { // S3: explicit bound
        iteration += 1;

        const now_ns: i64 = std.time.nanoTimestamp();
        const elapsed_ns: i64 = now_ns - start_ns;
        std.debug.assert(elapsed_ns >= 0); // S1: monotonic clock invariant
        if (elapsed_ns > timeout_ns) return error.HandshakeTimeout;

        const remaining_ns: i64 = timeout_ns - elapsed_ns;

        const ret: c_int = ssl.SSL_do_handshake(ssl_conn);
        if (ret == 1) return; // Success

        const err: c_int = ssl.SSL_get_error(ssl_conn, ret);
        switch (err) { // S4: explicit error handling
            ssl.SSL_ERROR_WANT_READ => try io.pollIn(fd, remaining_ns),
            ssl.SSL_ERROR_WANT_WRITE => try io.pollOut(fd, remaining_ns),
            else => return error.HandshakeFailed,
        }
    }

    return error.HandshakeMaxIterations; // S3: bounded loop exit
}

// Tests
test "TlsStream compiles" {
    // Basic compilation test
    _ = TlsStream;
    _ = doHandshake;
}
