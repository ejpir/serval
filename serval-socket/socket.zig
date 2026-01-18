// serval-socket/socket.zig
//! Unified Socket Abstraction
//!
//! Tagged union providing a consistent interface for both plain TCP and TLS sockets.
//! TigerStyle: Explicit types, no generics, runtime dispatch is acceptable (P1: network >> CPU).

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;

pub const tls_socket = @import("tls_socket.zig");

// =============================================================================
// Error Types
// =============================================================================

/// Unified error type for socket operations.
/// TigerStyle: Explicit error set, no catch {}.
pub const SocketError = error{
    /// Connection was reset by peer (RST received).
    ConnectionReset,
    /// Connection was closed cleanly by peer.
    ConnectionClosed,
    /// Write to closed connection (SIGPIPE/EPIPE).
    BrokenPipe,
    /// Operation timed out.
    Timeout,
    /// TLS-specific error (handshake, encryption, certificate).
    TLSError,
    /// Unexpected error from underlying syscall or SSL.
    Unexpected,
};

// =============================================================================
// Plain Socket
// =============================================================================

/// Plain TCP socket (no encryption).
/// TigerStyle: Thin wrapper over fd with explicit lifecycle.
pub const PlainSocket = struct {
    fd: i32,

    /// Read data into buffer.
    /// Returns bytes read, 0 on EOF/clean close.
    /// TigerStyle S1: Assertions for preconditions.
    /// TigerStyle S2: Explicit u32 return type.
    pub fn read(self: *PlainSocket, buf: []u8) SocketError!u32 {
        assert(self.fd >= 0); // S1: precondition
        assert(buf.len > 0); // S1: precondition
        assert(buf.len <= std.math.maxInt(u32)); // S2: buffer fits in u32

        const n = posix.read(self.fd, buf) catch |err| {
            return map_posix_error(err);
        };

        // S2: explicit cast with bounds check
        assert(n <= std.math.maxInt(u32));
        return @intCast(n);
    }

    /// Write data to socket.
    /// Returns bytes written.
    /// TigerStyle S1: Assertions for preconditions.
    /// TigerStyle S2: Explicit u32 return type.
    pub fn write(self: *PlainSocket, data: []const u8) SocketError!u32 {
        assert(self.fd >= 0); // S1: precondition
        assert(data.len > 0); // S1: precondition
        assert(data.len <= std.math.maxInt(u32)); // S2: data fits in u32

        const n = posix.write(self.fd, data) catch |err| {
            return map_posix_error(err);
        };

        // S2: explicit cast with bounds check
        assert(n <= std.math.maxInt(u32));
        return @intCast(n);
    }

    /// Close the socket.
    /// TigerStyle: Explicit close, caller owns fd.
    pub fn close(self: *PlainSocket) void {
        assert(self.fd >= 0); // S1: precondition
        posix.close(self.fd);
        self.fd = -1; // Mark as closed
    }
};

// =============================================================================
// Socket Union
// =============================================================================

/// Unified socket type for both plain and TLS connections.
/// TigerStyle: Tagged union, explicit dispatch, no generics.
pub const Socket = union(enum) {
    plain: PlainSocket,
    tls: tls_socket.TLSSocket,

    /// Plain socket creation namespace.
    pub const Plain = struct {
        /// Create plain client socket from fd.
        /// TigerStyle: Consistent API with TLS.init_client.
        pub fn init_client(fd: i32) Socket {
            assert(fd >= 0); // S1: precondition
            return .{ .plain = .{ .fd = fd } };
        }

        /// Create plain server socket from fd.
        /// Same as init_client for plain TCP, but documents intent.
        /// TigerStyle: Symmetric API with TLS.init_server.
        pub fn init_server(fd: i32) Socket {
            assert(fd >= 0); // S1: precondition
            return .{ .plain = .{ .fd = fd } };
        }
    };

    /// TLS socket creation namespace.
    /// Delegates to tls_socket module.
    pub const TLS = tls_socket;

    /// Read data into buffer.
    /// Returns bytes read, 0 on EOF/clean close.
    /// TigerStyle: Dispatch to underlying implementation.
    /// TigerStyle S2: Explicit u32 return type.
    pub fn read(self: *Socket, buf: []u8) SocketError!u32 {
        assert(buf.len > 0); // S1: precondition

        return switch (self.*) {
            .plain => |*s| s.read(buf),
            .tls => |*s| s.read(buf),
        };
    }

    /// Write data to socket.
    /// Returns bytes written.
    /// TigerStyle: Dispatch to underlying implementation.
    /// TigerStyle S2: Explicit u32 return type.
    pub fn write(self: *Socket, data: []const u8) SocketError!u32 {
        assert(data.len > 0); // S1: precondition

        return switch (self.*) {
            .plain => |*s| s.write(data),
            .tls => |*s| s.write(data),
        };
    }

    /// Close the socket and free resources.
    /// TigerStyle: Single close path for both types.
    pub fn close(self: *Socket) void {
        const fd = self.get_fd();
        assert(fd >= 0);
        switch (self.*) {
            .plain => |*s| s.close(),
            .tls => |*s| s.close(),
        }
    }

    /// Get raw file descriptor.
    /// Useful for splice (plaintext only) and poll operations.
    /// TigerStyle: Zero-copy splice needs raw fd.
    pub fn get_fd(self: Socket) i32 {
        const fd = switch (self) {
            .plain => |s| s.fd,
            .tls => |s| s.fd,
        };
        assert(fd >= -1);
        return fd;
    }

    /// Check if this is a TLS socket.
    /// Useful for determining splice eligibility.
    /// TigerStyle: Explicit type check, no instanceof pattern.
    pub fn is_tls(self: Socket) bool {
        const fd = self.get_fd();
        assert(fd >= -1);
        return switch (self) {
            .plain => false,
            .tls => true,
        };
    }

    /// Returns true if this socket can use splice() for zero-copy I/O.
    /// Plain sockets always support splice. TLS sockets only support splice
    /// when kTLS kernel offload is enabled (kernel handles encryption).
    ///
    /// Why this matters: splice() moves data between file descriptors without
    /// copying through userspace. With plain TCP, the kernel handles all I/O.
    /// With userspace TLS, data must pass through OpenSSL for encryption,
    /// making splice() impossible. kTLS moves TLS encryption into the kernel,
    /// re-enabling splice() for encrypted connections.
    ///
    /// TigerStyle: Explicit switch on socket type (no default case).
    pub fn can_splice(self: *const Socket) bool {
        const fd = self.get_fd();
        assert(fd >= -1);
        return switch (self.*) {
            .plain => true, // Plain TCP: kernel handles I/O, splice always works
            .tls => |*s| s.stream.isKtls(), // TLS: only splice if kTLS enabled
        };
    }

    /// Check if this socket is using kTLS kernel offload.
    /// Always returns false for plain sockets.
    /// For TLS sockets, returns true if kTLS is enabled.
    /// TigerStyle: Explicit switch on socket type (no default case).
    pub fn is_ktls(self: *const Socket) bool {
        const fd = self.get_fd();
        assert(fd >= -1);
        return switch (self.*) {
            .plain => false, // Plain TCP: not TLS, so not kTLS
            .tls => |*s| s.stream.isKtls(), // TLS: check if kTLS mode
        };
    }

    // =========================================================================
    // Bulk Transfer Operations
    // =========================================================================

    /// Maximum iterations for write_all to prevent infinite loops.
    /// 1024 partial writes is far beyond any legitimate scenario.
    /// TigerStyle S3: Bounded loops with explicit max iterations.
    pub const max_write_iterations_count: u32 = 1024;

    /// Maximum iterations for read_at_least to prevent infinite loops.
    /// TigerStyle S3: Bounded loops with explicit max iterations.
    pub const max_read_iterations_count: u32 = 1024;

    /// Write all bytes to socket, handling partial writes.
    /// Returns error if unable to write all bytes within bounded iterations.
    /// TigerStyle: Bounded retry loop, explicit assertions.
    pub fn write_all(self: *Socket, data: []const u8) SocketError!void {
        // S1: Preconditions
        assert(data.len > 0); // Empty writes are programmer error
        assert(data.len <= std.math.maxInt(u32));

        const data_len: u32 = @intCast(data.len);
        var sent: u32 = 0;
        var iterations: u32 = 0;

        // S3: Bounded loop with explicit maximum
        while (sent < data_len and iterations < max_write_iterations_count) : (iterations += 1) {
            const offset: usize = @intCast(sent);
            const n: u32 = try self.write(data[offset..]);

            // Zero write means peer closed or unrecoverable error
            if (n == 0) return SocketError.ConnectionClosed;

            assert(n <= data_len);
            sent += n;
            assert(sent <= data_len);
        }

        // Check if loop exited due to iteration limit
        if (sent < data_len) return SocketError.Unexpected;

        // S2: Postcondition - all bytes written
        assert(sent == data_len);
    }

    /// Read at least min_bytes into buffer.
    /// Returns total bytes read (may be more than min_bytes, up to buffer.len).
    /// Returns error if unable to read minimum bytes within bounded iterations.
    /// TigerStyle: Bounded retry loop, explicit assertions.
    pub fn read_at_least(self: *Socket, buffer: []u8, min_bytes: u32) SocketError!u32 {
        // S1: Preconditions
        assert(buffer.len > 0); // Empty buffer is programmer error
        assert(buffer.len <= std.math.maxInt(u32));
        assert(min_bytes > 0); // Zero min_bytes is programmer error

        const buffer_len: u32 = @intCast(buffer.len);
        assert(min_bytes <= buffer_len); // min_bytes cannot exceed buffer capacity

        var total_bytes: u32 = 0;
        var iterations: u32 = 0;

        // S3: Bounded loop with explicit maximum
        while (total_bytes < min_bytes and iterations < max_read_iterations_count) : (iterations += 1) {
            const offset: usize = @intCast(total_bytes);
            const n: u32 = try self.read(buffer[offset..]);

            // Zero read means EOF before min_bytes reached
            if (n == 0) return SocketError.ConnectionClosed;

            assert(n <= buffer_len);
            total_bytes += n;
            assert(total_bytes <= buffer_len);
        }

        // Check if loop exited due to iteration limit
        if (total_bytes < min_bytes) return SocketError.Unexpected;

        // S2: Postcondition - read at least min_bytes
        assert(total_bytes >= min_bytes);
        assert(total_bytes <= buffer_len);
        return total_bytes;
    }
};

// =============================================================================
// Error Mapping
// =============================================================================

/// Map posix errors to SocketError.
/// TigerStyle S6: Explicit error handling, no catch {}.
fn map_posix_error(err: anyerror) SocketError {
    assert(@errorName(err).len > 0);
    return switch (err) {
        error.ConnectionResetByPeer => SocketError.ConnectionReset,
        error.BrokenPipe => SocketError.BrokenPipe,
        error.ConnectionTimedOut => SocketError.Timeout,
        error.WouldBlock => SocketError.Timeout,
        else => SocketError.Unexpected,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "Socket.Plain.init_client creates plain socket" {
    // Verify init_client returns a non-TLS socket with correct fd.
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(fd);

    var sock = Socket.Plain.init_client(fd);
    try std.testing.expect(!sock.is_tls());
    try std.testing.expectEqual(fd, sock.get_fd());
}

test "Socket.Plain.init_server creates plain socket" {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(fd);

    var sock = Socket.Plain.init_server(fd);
    try std.testing.expect(!sock.is_tls());
    try std.testing.expectEqual(fd, sock.get_fd());
}

test "Socket.is_tls returns correct value" {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(fd);

    const plain_sock = Socket.Plain.init_client(fd);
    try std.testing.expect(!plain_sock.is_tls());
}

test "Socket.get_fd returns underlying fd" {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(fd);

    const sock = Socket.Plain.init_client(fd);
    try std.testing.expectEqual(fd, sock.get_fd());
}

test "map_posix_error maps common errors" {
    try std.testing.expectEqual(SocketError.ConnectionReset, map_posix_error(error.ConnectionResetByPeer));
    try std.testing.expectEqual(SocketError.BrokenPipe, map_posix_error(error.BrokenPipe));
    try std.testing.expectEqual(SocketError.Timeout, map_posix_error(error.ConnectionTimedOut));
    try std.testing.expectEqual(SocketError.Timeout, map_posix_error(error.WouldBlock));
    try std.testing.expectEqual(SocketError.Unexpected, map_posix_error(error.OutOfMemory));
}

test "PlainSocket read/write require valid fd" {
    // Create socket pair for testing read/write
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var sock = Socket.Plain.init_client(fds[0]);

    // Inject data via raw posix to verify Socket.read() retrieves it.
    const msg = "hello";
    _ = try posix.write(fds[1], msg);

    // Socket.read must return the injected data.
    var buf: [16]u8 = undefined;
    const n = try sock.read(&buf);
    try std.testing.expectEqual(@as(u32, 5), n);
    try std.testing.expectEqualStrings("hello", buf[0..n]);
}

test "PlainSocket write sends data" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var sock = Socket.Plain.init_client(fds[0]);

    // Write through socket
    const msg = "world";
    const written = try sock.write(msg);
    try std.testing.expectEqual(@as(u32, 5), written);

    // Verify data written via Socket.write() arrives at the other end.
    var buf: [16]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualStrings("world", buf[0..n]);
}

test "Socket.can_splice returns true for plain sockets" {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(fd);

    const sock = Socket.Plain.init_client(fd);
    // Plain sockets always support splice (kernel handles I/O)
    try std.testing.expect(sock.can_splice());
}

test "Socket.is_ktls returns false for plain sockets" {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(fd);

    const sock = Socket.Plain.init_client(fd);
    // Plain sockets are not TLS, so cannot be kTLS
    try std.testing.expect(!sock.is_ktls());
}

// =============================================================================
// Bulk Transfer Operation Tests
// =============================================================================

test "Socket.write_all sends all bytes" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var sock = Socket.Plain.init_client(fds[0]);

    // Write all bytes via write_all
    const msg = "hello world test message";
    try sock.write_all(msg);

    // Read from other end and verify all bytes received
    var buf: [64]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try std.testing.expectEqual(msg.len, n);
    try std.testing.expectEqualStrings(msg, buf[0..n]);
}

test "Socket.write_all error on closed connection" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);

    var sock = Socket.Plain.init_client(fds[0]);

    // Close the read end to trigger broken pipe on write
    posix.close(fds[1]);

    // write_all should fail when peer is closed
    const result = sock.write_all("test data");
    try std.testing.expectError(SocketError.BrokenPipe, result);
}

test "Socket.read_at_least reads minimum bytes" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var sock = Socket.Plain.init_client(fds[0]);

    // Write data to be read - if socketpair works, write must work
    const msg = "hello world";
    _ = try posix.write(fds[1], msg);

    // Read at least 5 bytes (may get more)
    var buf: [32]u8 = undefined;
    const n = try sock.read_at_least(&buf, 5);
    const msg_len: u32 = @intCast(msg.len);
    try std.testing.expect(n >= 5);
    try std.testing.expect(n <= msg_len);
}

test "Socket.read_at_least error on EOF before min_bytes" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);

    var sock = Socket.Plain.init_client(fds[0]);

    // Write only 3 bytes then close - if socketpair works, write must work
    _ = try posix.write(fds[1], "abc");
    posix.close(fds[1]);

    // Try to read at least 10 bytes - should fail due to EOF
    var buf: [32]u8 = undefined;
    const result = sock.read_at_least(&buf, 10);
    try std.testing.expectError(SocketError.ConnectionClosed, result);
}

test "Socket.read_at_least reads exact minimum when available" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var sock = Socket.Plain.init_client(fds[0]);

    // Write exactly 5 bytes - if socketpair works, write must work
    _ = try posix.write(fds[1], "12345");

    // Read at least 5 bytes
    var buf: [32]u8 = undefined;
    const n = try sock.read_at_least(&buf, 5);
    try std.testing.expectEqual(@as(u32, 5), n);
    const n_usize: usize = @intCast(n);
    try std.testing.expectEqualStrings("12345", buf[0..n_usize]);
}
