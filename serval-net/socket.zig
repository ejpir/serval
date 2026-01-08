// serval-net/socket.zig
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
    pub fn read(self: *PlainSocket, buf: []u8) SocketError!usize {
        assert(self.fd >= 0); // S1: precondition
        assert(buf.len > 0); // S1: precondition

        const n = posix.read(self.fd, buf) catch |err| {
            return mapPosixError(err);
        };

        return n;
    }

    /// Write data to socket.
    /// Returns bytes written.
    /// TigerStyle S1: Assertions for preconditions.
    pub fn write(self: *PlainSocket, data: []const u8) SocketError!usize {
        assert(self.fd >= 0); // S1: precondition
        assert(data.len > 0); // S1: precondition

        const n = posix.write(self.fd, data) catch |err| {
            return mapPosixError(err);
        };

        return n;
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
        /// TigerStyle: Consistent API with TLS.initClient.
        pub fn initClient(fd: i32) Socket {
            assert(fd >= 0); // S1: precondition
            return .{ .plain = .{ .fd = fd } };
        }

        /// Create plain server socket from fd.
        /// Same as initClient for plain TCP, but documents intent.
        /// TigerStyle: Symmetric API with TLS.initServer.
        pub fn initServer(fd: i32) Socket {
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
    pub fn read(self: *Socket, buf: []u8) SocketError!usize {
        assert(buf.len > 0); // S1: precondition

        return switch (self.*) {
            .plain => |*s| s.read(buf),
            .tls => |*s| s.read(buf),
        };
    }

    /// Write data to socket.
    /// Returns bytes written.
    /// TigerStyle: Dispatch to underlying implementation.
    pub fn write(self: *Socket, data: []const u8) SocketError!usize {
        assert(data.len > 0); // S1: precondition

        return switch (self.*) {
            .plain => |*s| s.write(data),
            .tls => |*s| s.write(data),
        };
    }

    /// Close the socket and free resources.
    /// TigerStyle: Single close path for both types.
    pub fn close(self: *Socket) void {
        switch (self.*) {
            .plain => |*s| s.close(),
            .tls => |*s| s.close(),
        }
    }

    /// Get raw file descriptor.
    /// Useful for splice (plaintext only) and poll operations.
    /// TigerStyle: Zero-copy splice needs raw fd.
    pub fn getFd(self: Socket) i32 {
        return switch (self) {
            .plain => |s| s.fd,
            .tls => |s| s.fd,
        };
    }

    /// Check if this is a TLS socket.
    /// Useful for determining splice eligibility.
    /// TigerStyle: Explicit type check, no instanceof pattern.
    pub fn isTLS(self: Socket) bool {
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
    pub fn canSplice(self: *const Socket) bool {
        return switch (self.*) {
            .plain => true, // Plain TCP: kernel handles I/O, splice always works
            .tls => |*s| s.stream.isKtls(), // TLS: only splice if kTLS enabled
        };
    }

    /// Check if this socket is using kTLS kernel offload.
    /// Always returns false for plain sockets.
    /// For TLS sockets, returns true if kTLS is enabled.
    /// TigerStyle: Explicit switch on socket type (no default case).
    pub fn isKtls(self: *const Socket) bool {
        return switch (self.*) {
            .plain => false, // Plain TCP: not TLS, so not kTLS
            .tls => |*s| s.stream.isKtls(), // TLS: check if kTLS mode
        };
    }
};

// =============================================================================
// Error Mapping
// =============================================================================

/// Map posix errors to SocketError.
/// TigerStyle S6: Explicit error handling, no catch {}.
fn mapPosixError(err: anyerror) SocketError {
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

test "Socket.Plain.initClient creates plain socket" {
    // Use a real socket for testing
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return; // Skip if socket creation fails
    };
    defer posix.close(fd);

    var sock = Socket.Plain.initClient(fd);
    try std.testing.expect(!sock.isTLS());
    try std.testing.expectEqual(fd, sock.getFd());
}

test "Socket.Plain.initServer creates plain socket" {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return;
    };
    defer posix.close(fd);

    var sock = Socket.Plain.initServer(fd);
    try std.testing.expect(!sock.isTLS());
    try std.testing.expectEqual(fd, sock.getFd());
}

test "Socket.isTLS returns correct value" {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return;
    };
    defer posix.close(fd);

    const plain_sock = Socket.Plain.initClient(fd);
    try std.testing.expect(!plain_sock.isTLS());
}

test "Socket.getFd returns underlying fd" {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return;
    };
    defer posix.close(fd);

    const sock = Socket.Plain.initClient(fd);
    try std.testing.expectEqual(fd, sock.getFd());
}

test "mapPosixError maps common errors" {
    try std.testing.expectEqual(SocketError.ConnectionReset, mapPosixError(error.ConnectionResetByPeer));
    try std.testing.expectEqual(SocketError.BrokenPipe, mapPosixError(error.BrokenPipe));
    try std.testing.expectEqual(SocketError.Timeout, mapPosixError(error.ConnectionTimedOut));
    try std.testing.expectEqual(SocketError.Timeout, mapPosixError(error.WouldBlock));
    try std.testing.expectEqual(SocketError.Unexpected, mapPosixError(error.OutOfMemory));
}

test "PlainSocket read/write require valid fd" {
    // Create socket pair for testing read/write
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch {
        return; // Skip if socketpair not available
    };
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var sock = Socket.Plain.initClient(fds[0]);

    // Write to one end
    const msg = "hello";
    _ = posix.write(fds[1], msg) catch return;

    // Read from socket
    var buf: [16]u8 = undefined;
    const n = try sock.read(&buf);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualStrings("hello", buf[0..n]);
}

test "PlainSocket write sends data" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch {
        return;
    };
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var sock = Socket.Plain.initClient(fds[0]);

    // Write through socket
    const msg = "world";
    const written = try sock.write(msg);
    try std.testing.expectEqual(@as(usize, 5), written);

    // Read from other end
    var buf: [16]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch return;
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualStrings("world", buf[0..n]);
}

test "Socket.canSplice returns true for plain sockets" {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return;
    };
    defer posix.close(fd);

    const sock = Socket.Plain.initClient(fd);
    // Plain sockets always support splice (kernel handles I/O)
    try std.testing.expect(sock.canSplice());
}

test "Socket.isKtls returns false for plain sockets" {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return;
    };
    defer posix.close(fd);

    const sock = Socket.Plain.initClient(fd);
    // Plain sockets are not TLS, so cannot be kTLS
    try std.testing.expect(!sock.isKtls());
}
