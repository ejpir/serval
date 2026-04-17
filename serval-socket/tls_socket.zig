// serval-socket/tls_socket.zig
//! TLS Socket Wrapper
//!
//! Wraps serval-tls TLSStream to provide a Socket-compatible interface.
//! TigerStyle: Explicit types, assertions, no runtime allocation after init.
//!
//! Design:
//! - init_client: Client-side TLS handshake with SNI (upstream connections)
//! - init_server: Server-side TLS handshake (client termination)
//! - read/write: bounded request/response TLS I/O through TLSStream
//! - read_relay/write_all_relay: long-lived relay TLS I/O with cooperative std.Io waits
//! - close: Graceful TLS shutdown + fd close

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const serval_core = @import("serval-core");
const closeFd = serval_core.closeFd;
const tls = @import("serval-tls");
const TLSStream = tls.TLSStream;
const ssl = tls.ssl;

const socket_mod = @import("socket.zig");
/// Re-export of the unified socket error set from `socket.zig`.
/// Returned by plain and TLS socket operations when reads, writes, or handshakes fail.
/// Covers connection state errors, TLS-specific failures, timeouts, and unexpected syscall or SSL errors.
pub const SocketError = socket_mod.SocketError;
/// Re-export of the unified socket tagged union from `socket.zig`.
/// Use this type for plain TCP or TLS connections at higher layers.
/// Ownership, lifecycle, and method behavior are defined by the underlying socket implementation.
pub const Socket = socket_mod.Socket;

/// Maximum hostname length for SNI (RFC 6066 limit).
/// TigerStyle: Named constant with units suffix.
const max_sni_length_chars: u32 = 253;
const relay_read_wait_slice_ms: i64 = 1000;
const relay_retry_yield_ns: u64 = 1;
const relay_max_read_iterations: u32 = 1024;
const relay_max_write_iterations: u32 = 1024;

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
    pub fn init_client(
        fd: i32,
        ctx: *ssl.SSL_CTX,
        host: []const u8,
        enable_ktls: bool,
        desired_alpn: ?[]const u8,
        verify_peer: bool,
    ) SocketError!Socket {
        // S1: preconditions
        assert(fd >= 0); // S1: valid fd
        assert(@intFromPtr(ctx) != 0); // S1: valid ctx pointer
        assert(host.len > 0); // S1: non-empty host
        assert(host.len <= max_sni_length_chars); // S1: host within RFC limit

        // S5: Stack buffer for null-terminated SNI, zeroed
        var sni_buf: [max_sni_length_chars + 1]u8 = std.mem.zeroes([max_sni_length_chars + 1]u8);
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
            desired_alpn,
            verify_peer,
        ) catch |err| {
            return map_tls_error(err);
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
    pub fn init_server(
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
            return map_tls_error(err);
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

    /// Read data through bounded request/response TLS I/O.
    /// Returns bytes read, 0 on clean shutdown.
    /// TigerStyle S1: Assertions for preconditions/postconditions.
    /// TigerStyle S2: Explicit u32 return type.
    pub fn read(self: *TLSSocket, buf: []u8) SocketError!u32 {
        // S1: preconditions
        assert(self.fd >= 0); // S1: socket not closed
        assert(self.stream.fd == self.fd); // S1: fd invariant preserved
        assert(buf.len > 0); // S1: non-empty buffer
        assert(buf.len <= std.math.maxInt(u32)); // S2: buffer fits in u32

        const n = self.stream.readBounded(buf) catch |err| {
            return map_tls_error(err);
        };

        // S2: explicit cast with bounds check
        assert(n <= std.math.maxInt(u32));
        const bytes_read: u32 = @intCast(n);

        // S1: postcondition - bytes read within buffer bounds
        assert(bytes_read <= buf.len);

        return bytes_read;
    }

    /// Write data through bounded request/response TLS I/O.
    /// Returns bytes written.
    ///
    /// Ownership/lifetime: caller retains ownership of `self` and `data`; both
    /// must remain valid for the full duration of the call.
    /// Failure semantics: returns `SocketError` when TLS/backing-fd write fails
    /// or the bounded TLS write wrapper cannot make progress.
    /// TigerStyle S1: Assertions for preconditions/postconditions.
    /// TigerStyle S2: Explicit u32 return type.
    pub fn write(self: *TLSSocket, data: []const u8) SocketError!u32 {
        // S1: preconditions
        assert(self.fd >= 0); // S1: socket not closed
        assert(self.stream.fd == self.fd); // S1: fd invariant preserved
        assert(data.len > 0); // S1: non-empty data
        assert(data.len <= std.math.maxInt(u32)); // S2: data fits in u32

        const n = self.stream.writeBounded(data) catch |err| {
            return map_tls_error(err);
        };

        // S2: explicit cast with bounds check
        assert(n <= std.math.maxInt(u32));
        const bytes_written: u32 = @intCast(n);

        // S1: postcondition - bytes written within data bounds
        assert(bytes_written <= data.len);

        return bytes_written;
    }

    /// Read data through the relay/tunnel TLS path.
    /// Unlike `read()`, this keeps retrying across bounded readiness slices so
    /// long-lived upgraded tunnels are governed by caller cancellation and idle
    /// policy rather than request/response I/O deadlines.
    ///
    /// Contract: caller must pass a live `io` and a non-empty writable `buf`.
    /// Ownership/lifetime: caller retains ownership of `self` and `buf`; both
    /// must remain valid for the full duration of the call.
    /// Failure semantics: returns `error.Canceled` on cooperative cancellation,
    /// `SocketError.ConnectionClosed` on peer closure/reset, or
    /// `SocketError.Unexpected`/other `SocketError` on terminal TLS failures.
    pub fn read_relay(self: *TLSSocket, io: Io, buf: []u8) (SocketError || Io.Cancelable)!u32 {
        assert(self.fd >= 0);
        assert(self.stream.fd == self.fd);
        assert(buf.len > 0);
        assert(buf.len <= std.math.maxInt(u32));

        var want_write_retries: u32 = 0;
        while (true) {
            try std.Io.checkCancel(io);

            if (!self.has_pending_read()) {
                wait_until_readable(self.fd, io, timeout_for_milliseconds(relay_read_wait_slice_ms)) catch |err| switch (err) {
                    error.Timeout => continue,
                    error.Canceled => return error.Canceled,
                    error.ConnectionResetByPeer,
                    error.SocketUnconnected,
                    => return SocketError.ConnectionClosed,
                    else => return SocketError.Unexpected,
                };
            }

            const n = self.stream.read(buf) catch |err| switch (err) {
                error.WantRead => continue,
                error.WantWrite => {
                    want_write_retries += 1;
                    if (want_write_retries >= relay_max_read_iterations) return SocketError.Unexpected;
                    try yield_for_relay_retry(io);
                    continue;
                },
                else => return map_tls_relay_error(err),
            };
            assert(n <= std.math.maxInt(u32));
            assert(n <= buf.len);
            return n;
        }
    }

    /// Write all data through the relay/tunnel TLS path.
    /// Unlike `write()`, this preserves low-level TLS backpressure handling for
    /// long-lived upgraded tunnels instead of imposing request/response I/O
    /// deadlines on the post-upgrade relay stream.
    ///
    /// Contract: caller must provide non-empty `data`; the call only succeeds
    /// when the full slice is written.
    /// Ownership/lifetime: caller retains ownership of `self` and `data`; both
    /// must remain valid for the full duration of the call.
    /// Failure semantics: returns `error.Canceled` on cooperative cancellation,
    /// `SocketError.ConnectionClosed` for closure/reset, or a terminal
    /// `SocketError` when relay-mode TLS write progress fails.
    pub fn write_all_relay(self: *TLSSocket, io: Io, data: []const u8) (SocketError || Io.Cancelable)!void {
        assert(self.fd >= 0);
        assert(self.stream.fd == self.fd);
        assert(data.len > 0);
        assert(data.len <= std.math.maxInt(u32));

        var sent: usize = 0;
        var iterations: u32 = 0;
        while (sent < data.len and iterations < relay_max_write_iterations) : (iterations += 1) {
            try std.Io.checkCancel(io);

            const n = self.stream.write(data[sent..]) catch |err| switch (err) {
                error.WantRead => {
                    wait_until_readable(self.fd, io, timeout_for_milliseconds(relay_read_wait_slice_ms)) catch |wait_err| switch (wait_err) {
                        error.Timeout => {
                            try yield_for_relay_retry(io);
                            continue;
                        },
                        error.Canceled => return error.Canceled,
                        error.ConnectionResetByPeer,
                        error.SocketUnconnected,
                        => return SocketError.ConnectionClosed,
                        else => return SocketError.Unexpected,
                    };
                    continue;
                },
                error.WantWrite => {
                    try yield_for_relay_retry(io);
                    continue;
                },
                else => return map_tls_relay_error(err),
            };
            if (n == 0) return SocketError.ConnectionClosed;
            sent += n;
            assert(sent <= data.len);
        }

        if (sent < data.len) return SocketError.Unexpected;
        assert(sent == data.len);
    }

    /// Returns true if userspace TLS has decrypted bytes buffered internally.
    /// Needed for single-threaded tunnel relay correctness: SSL may hold plaintext
    /// even when the underlying socket fd is not poll-readable.
    pub fn has_pending_read(self: *const TLSSocket) bool {
        assert(self.fd >= 0);

        return switch (self.stream.mode) {
            .ktls => false,
            .userspace => |ssl_conn| blk: {
                const pending = ssl.SSL_pending(ssl_conn);
                assert(pending >= 0);
                break :blk pending > 0;
            },
        };
    }

    /// Close TLS session and underlying fd.
    /// TigerStyle S1: Assertions for preconditions.
    pub fn close(self: *TLSSocket) void {
        // S1: precondition - socket not already closed
        assert(self.fd >= 0);

        // Graceful TLS shutdown
        self.stream.close();

        // Close underlying fd (TLSStream.close() doesn't close it)
        closeFd(self.fd);

        // Mark as closed
        self.fd = -1;
    }
};

fn timeout_for_milliseconds(timeout_ms: i64) Io.Timeout {
    assert(timeout_ms > 0);

    return .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(timeout_ms),
        .clock = .awake,
    } };
}

fn wait_until_readable(fd: i32, io: Io, timeout: Io.Timeout) anyerror!void {
    assert(fd >= 0);

    var messages: [1]Io.net.IncomingMessage = .{Io.net.IncomingMessage.init};
    var peek_buf: [1]u8 = undefined;
    const maybe_err, _ = raw_stream_for_fd(fd).socket.receiveManyTimeout(
        io,
        &messages,
        &peek_buf,
        .{ .peek = true },
        timeout,
    );
    if (maybe_err) |err| return err;
}

fn yield_for_relay_retry(io: Io) Io.Cancelable!void {
    try std.Io.sleep(io, Io.Duration.fromNanoseconds(relay_retry_yield_ns), .awake);
}

fn raw_stream_for_fd(fd: i32) Io.net.Stream {
    assert(fd >= 0);
    return .{
        .socket = .{
            .handle = fd,
            .address = .{ .ip4 = .unspecified(0) },
        },
    };
}

/// Map low-level TLS relay errors to SocketError.
fn map_tls_relay_error(err: anyerror) SocketError {
    assert(@errorName(err).len > 0);
    return switch (err) {
        error.ConnectionReset => SocketError.ConnectionReset,
        else => map_tls_error(err),
    };
}

/// Map TLS errors to SocketError.
/// TigerStyle S6: Explicit error handling, no catch {}.
fn map_tls_error(err: anyerror) SocketError {
    assert(@errorName(err).len > 0);
    return switch (err) {
        error.ConnectionReset => SocketError.ConnectionReset,
        error.HandshakeTimeout,
        error.Timeout,
        => SocketError.Timeout,
        error.SslNew => SocketError.TLSError,
        error.SslSetFd => SocketError.TLSError,
        error.SslSetSni => SocketError.TLSError,
        error.SslSetAlpn => SocketError.TLSError,
        error.InvalidAlpnProtocol => SocketError.TLSError,
        error.HandshakeFailed => SocketError.TLSError,
        error.SslRead => SocketError.TLSError,
        error.SslWrite => SocketError.TLSError,
        error.KtlsRead => SocketError.TLSError,
        error.KtlsWrite => SocketError.TLSError,
        error.WouldBlock => SocketError.TLSError,
        error.WantRead => SocketError.TLSError,
        error.WantWrite => SocketError.TLSError,
        else => SocketError.Unexpected,
    };
}

// =============================================================================
// Tests
// =============================================================================

fn test_socket_pair() ![2]std.posix.socket_t {
    var fds: [2]std.posix.socket_t = undefined;

    while (true) {
        const rc = std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
        switch (std.c.errno(rc)) {
            .SUCCESS => return fds,
            .INTR => continue,
            else => return error.SocketFailed,
        }
    }
}

fn test_read(fd: std.posix.socket_t, buf: []u8) !usize {
    while (true) {
        const rc = std.c.read(fd, buf.ptr, buf.len);
        switch (std.c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return error.ReadFailed,
        }
    }
}

fn test_write(fd: std.posix.socket_t, data: []const u8) !usize {
    while (true) {
        const rc = std.c.write(fd, data.ptr, data.len);
        switch (std.c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

test "TLSSocket struct has expected fields" {
    // Verify struct layout
    const info = @typeInfo(TLSSocket);
    try std.testing.expect(info == .@"struct");

    const fields = info.@"struct".fields;
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("fd", fields[0].name);
    try std.testing.expectEqualStrings("stream", fields[1].name);
}

test "max_sni_length_chars matches RFC 6066 limit" {
    // RFC 6066 specifies max hostname of 253 characters
    try std.testing.expectEqual(@as(u32, 253), max_sni_length_chars);
}

test "TLSSocket exports relay-mode methods" {
    try std.testing.expect(@hasDecl(TLSSocket, "read_relay"));
    try std.testing.expect(@hasDecl(TLSSocket, "write_all_relay"));
}

test "wait_until_readable times out on idle fd" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const pair = try test_socket_pair();
    defer closeFd(pair[0]);
    defer closeFd(pair[1]);

    try std.testing.expectError(
        error.Timeout,
        wait_until_readable(pair[0], evented.io(), timeout_for_milliseconds(20)),
    );
}

test "wait_until_readable preserves peeked data" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const pair = try test_socket_pair();
    defer closeFd(pair[0]);
    defer closeFd(pair[1]);

    const payload = [_]u8{0x2a};
    try std.testing.expectEqual(@as(usize, 1), try test_write(pair[1], &payload));
    try wait_until_readable(pair[0], evented.io(), timeout_for_milliseconds(20));

    var out: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try test_read(pair[0], &out));
    try std.testing.expectEqual(payload[0], out[0]);
}

test "map_tls_error maps timeout reset and TLS failures" {
    try std.testing.expectEqual(SocketError.ConnectionReset, map_tls_error(error.ConnectionReset));
    try std.testing.expectEqual(SocketError.Timeout, map_tls_error(error.HandshakeTimeout));
    try std.testing.expectEqual(SocketError.Timeout, map_tls_error(error.Timeout));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.SslNew));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.SslSetFd));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.SslSetSni));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.SslSetAlpn));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.InvalidAlpnProtocol));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.HandshakeFailed));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.SslRead));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.SslWrite));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.KtlsRead));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.KtlsWrite));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.WouldBlock));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.WantRead));
    try std.testing.expectEqual(SocketError.TLSError, map_tls_error(error.WantWrite));
}

test "map_tls_error maps unknown errors to Unexpected" {
    try std.testing.expectEqual(SocketError.Unexpected, map_tls_error(error.OutOfMemory));
    try std.testing.expectEqual(SocketError.Unexpected, map_tls_error(error.AccessDenied));
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
