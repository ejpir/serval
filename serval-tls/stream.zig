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
const ssl = @import("ssl.zig");
const Allocator = std.mem.Allocator;

pub const TLSStream = struct {
    fd: c_int,
    ssl: *ssl.SSL,
    allocator: Allocator,

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

        // Blocking handshake - std.Io handles socket-level async
        const ret = ssl.SSL_accept(ssl_conn);
        if (ret != 1) {
            ssl.printErrors();
            return error.HandshakeFailed;
        }

        std.debug.assert(ssl.SSL_is_init_finished(ssl_conn) == 1); // S1: postcondition
        return .{
            .fd = fd,
            .ssl = ssl_conn,
            .allocator = allocator,
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

        // Blocking handshake - std.Io handles socket-level async
        const ret = ssl.SSL_connect(ssl_conn);
        if (ret != 1) {
            ssl.printErrors();
            return error.HandshakeFailed;
        }

        std.debug.assert(ssl.SSL_is_init_finished(ssl_conn) == 1); // S1: postcondition
        return .{
            .fd = fd,
            .ssl = ssl_conn,
            .allocator = allocator,
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

// Tests
test "TLSStream compiles" {
    // Basic compilation test
    _ = TLSStream;
}
