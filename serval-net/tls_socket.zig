// serval-net/tls_socket.zig
//! TLS Socket Wrapper
//!
//! Wraps serval-tls TLSStream to provide a Socket-compatible interface.
//! TigerStyle: Explicit types, assertions, no runtime allocation after init.
//!
//! Design:
//! - initClient: Client-side TLS handshake with SNI (upstream connections)
//! - initServer: Server-side TLS handshake (client termination)
//! - read/write: Blocking TLS I/O through TLSStream
//! - close: Graceful TLS shutdown + fd close

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const tls = @import("serval-tls");
const TLSStream = tls.TLSStream;
const ssl = tls.ssl;

const socket_mod = @import("socket.zig");
pub const SocketError = socket_mod.SocketError;
pub const Socket = socket_mod.Socket;

/// Maximum hostname length for SNI (RFC 6066 limit).
/// TigerStyle: Named constant with clear meaning.
const MAX_SNI_LENGTH: u32 = 253;

/// TLS socket wrapping a TLSStream.
/// TigerStyle: Explicit struct, no hidden state.
pub const TLSSocket = struct {
    /// Underlying file descriptor (exposed for poll/splice operations).
    fd: i32,

    /// TLS stream for encrypted I/O.
    stream: TLSStream,

    /// Create client TLS socket with SNI.
    /// Performs TLS handshake with Server Name Indication.
    /// TigerStyle S1: Assertions for preconditions/postconditions.
    /// TigerStyle S5: SNI buffer zeroed, no allocation after init.
    /// enable_ktls: If true (default), attempt kernel TLS offload. If false, use userspace TLS.
    pub fn initClient(
        fd: i32,
        ctx: *ssl.SSL_CTX,
        host: []const u8,
        enable_ktls: bool,
    ) SocketError!Socket {
        // S1: preconditions
        assert(fd >= 0); // S1: valid fd
        assert(@intFromPtr(ctx) != 0); // S1: valid ctx pointer
        assert(host.len > 0); // S1: non-empty host
        assert(host.len <= MAX_SNI_LENGTH); // S1: host within RFC limit

        // S5: Stack buffer for null-terminated SNI, zeroed
        var sni_buf: [MAX_SNI_LENGTH + 1]u8 = std.mem.zeroes([MAX_SNI_LENGTH + 1]u8);
        const host_len: u32 = @intCast(host.len);
        @memcpy(sni_buf[0..host_len], host);
        // Buffer is zeroed, so sni_buf[host_len] is already 0 (null terminator)

        const sni_z: [*:0]const u8 = @ptrCast(&sni_buf);

        // TLSStream.initClient uses std.heap.page_allocator internally
        // but we pass a dummy allocator since it's only used for potential
        // future features (we use a non-allocating design)
        const stream = TLSStream.initClient(
            ctx,
            fd,
            sni_z,
            std.heap.page_allocator,
            enable_ktls,
        ) catch |err| {
            return mapTlsError(err);
        };

        // S1: postcondition - stream initialized with correct fd
        assert(stream.fd == fd);

        return .{
            .tls = .{
                .fd = fd,
                .stream = stream,
            },
        };
    }

    /// Create server TLS socket.
    /// Performs TLS handshake for incoming client connection.
    /// TigerStyle S1: Assertions for preconditions/postconditions.
    pub fn initServer(
        fd: i32,
        ctx: *ssl.SSL_CTX,
    ) SocketError!Socket {
        // S1: preconditions
        assert(fd >= 0); // S1: valid fd
        assert(@intFromPtr(ctx) != 0); // S1: valid ctx pointer

        const stream = TLSStream.initServer(
            ctx,
            fd,
            std.heap.page_allocator,
        ) catch |err| {
            return mapTlsError(err);
        };

        // S1: postcondition - stream initialized with correct fd
        assert(stream.fd == fd);

        return .{
            .tls = .{
                .fd = fd,
                .stream = stream,
            },
        };
    }

    /// Read data through TLS.
    /// Returns bytes read, 0 on clean shutdown.
    /// TigerStyle S1: Assertions for preconditions/postconditions.
    pub fn read(self: *TLSSocket, buf: []u8) SocketError!usize {
        // S1: preconditions
        assert(self.fd >= 0); // S1: socket not closed
        assert(buf.len > 0); // S1: non-empty buffer

        const n = self.stream.read(buf) catch |err| {
            return mapTlsError(err);
        };

        const bytes_read: usize = @intCast(n);

        // S1: postcondition - bytes read within buffer bounds
        assert(bytes_read <= buf.len);

        return bytes_read;
    }

    /// Write data through TLS.
    /// Returns bytes written.
    /// TigerStyle S1: Assertions for preconditions/postconditions.
    pub fn write(self: *TLSSocket, data: []const u8) SocketError!usize {
        // S1: preconditions
        assert(self.fd >= 0); // S1: socket not closed
        assert(data.len > 0); // S1: non-empty data

        const n = self.stream.write(data) catch |err| {
            return mapTlsError(err);
        };

        const bytes_written: usize = @intCast(n);

        // S1: postcondition - bytes written within data bounds
        assert(bytes_written <= data.len);

        return bytes_written;
    }

    /// Close TLS session and underlying fd.
    /// TigerStyle S1: Assertions for preconditions.
    pub fn close(self: *TLSSocket) void {
        // S1: precondition - socket not already closed
        assert(self.fd >= 0);

        // Graceful TLS shutdown
        self.stream.close();

        // Close underlying fd (TLSStream.close() doesn't close it)
        posix.close(self.fd);

        // Mark as closed
        self.fd = -1;
    }
};

/// Map TLS errors to SocketError.
/// TigerStyle S6: Explicit error handling, no catch {}.
fn mapTlsError(err: anyerror) SocketError {
    return switch (err) {
        error.SslNew => SocketError.TLSError,
        error.SslSetFd => SocketError.TLSError,
        error.SslSetSni => SocketError.TLSError,
        error.HandshakeFailed => SocketError.TLSError,
        error.SslRead => SocketError.TLSError,
        error.SslWrite => SocketError.TLSError,
        else => SocketError.Unexpected,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "TLSSocket struct has expected fields" {
    // Verify struct layout
    const info = @typeInfo(TLSSocket);
    try std.testing.expect(info == .@"struct");

    const fields = info.@"struct".fields;
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("fd", fields[0].name);
    try std.testing.expectEqualStrings("stream", fields[1].name);
}

test "MAX_SNI_LENGTH matches RFC 6066 limit" {
    // RFC 6066 specifies max hostname of 253 characters
    try std.testing.expectEqual(@as(u32, 253), MAX_SNI_LENGTH);
}

test "mapTlsError maps known errors to TLSError" {
    try std.testing.expectEqual(SocketError.TLSError, mapTlsError(error.SslNew));
    try std.testing.expectEqual(SocketError.TLSError, mapTlsError(error.SslSetFd));
    try std.testing.expectEqual(SocketError.TLSError, mapTlsError(error.SslSetSni));
    try std.testing.expectEqual(SocketError.TLSError, mapTlsError(error.HandshakeFailed));
    try std.testing.expectEqual(SocketError.TLSError, mapTlsError(error.SslRead));
    try std.testing.expectEqual(SocketError.TLSError, mapTlsError(error.SslWrite));
}

test "mapTlsError maps unknown errors to Unexpected" {
    try std.testing.expectEqual(SocketError.Unexpected, mapTlsError(error.OutOfMemory));
    try std.testing.expectEqual(SocketError.Unexpected, mapTlsError(error.AccessDenied));
}

test "Socket union accepts TLSSocket" {
    // Verify Socket union can hold TLSSocket
    const socket_info = @typeInfo(Socket);
    try std.testing.expect(socket_info == .@"union");

    // Check that tls variant exists using comptime iteration
    const found_tls = comptime blk: {
        for (socket_info.@"union".fields) |field| {
            if (std.mem.eql(u8, field.name, "tls")) {
                break :blk true;
            }
        }
        break :blk false;
    };
    try std.testing.expect(found_tls);
}
