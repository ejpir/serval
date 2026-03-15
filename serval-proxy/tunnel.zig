//! WebSocket Tunnel Relay
//!
//! Bidirectional byte relay used after successful HTTP/1.1 upgrade.
//! TigerStyle: Cooperative fibers, explicit idle timeout, no poll(2).

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const posix = std.posix;

const serval_core = @import("serval-core");
const config = serval_core.config;
const time = serval_core.time;

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;

pub const Termination = enum {
    client_closed,
    upstream_closed,
    client_error,
    upstream_error,
    idle_timeout,
};

pub const TunnelStats = struct {
    client_to_upstream_bytes: u64 = 0,
    upstream_to_client_bytes: u64 = 0,
    duration_ns: u64 = 0,
    termination: Termination = .idle_timeout,
};

const Side = enum {
    client,
    upstream,
};

const RelayFailure = error{
    ClientClosed,
    UpstreamClosed,
    ClientError,
    UpstreamError,
    IdleTimeout,
};

const RelayShared = struct {
    mutex: Io.Mutex = .init,
    stats: TunnelStats = .{},
    start_ns: u64,
    last_progress_ns: u64,
    idle_timeout_ns: u64,
    client_read_open: bool = true,
    upstream_read_open: bool = true,
    first_close: ?Termination = null,
    final_termination: ?Termination = null,

    fn init(start_ns: u64, idle_timeout_ns: u64) RelayShared {
        assert(start_ns > 0);
        assert(idle_timeout_ns > 0);

        return .{
            .start_ns = start_ns,
            .last_progress_ns = start_ns,
            .idle_timeout_ns = idle_timeout_ns,
        };
    }

    fn noteProgress(self: *RelayShared, side: Side, bytes: u32, io: Io) void {
        assert(@intFromPtr(self) != 0);
        assert(bytes > 0);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        switch (side) {
            .client => self.stats.client_to_upstream_bytes +|= bytes,
            .upstream => self.stats.upstream_to_client_bytes +|= bytes,
        }
        self.last_progress_ns = time.monotonicNanos();
    }

    fn markClosed(self: *RelayShared, side: Side, io: Io) void {
        assert(@intFromPtr(self) != 0);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const close_term: Termination = switch (side) {
            .client => .client_closed,
            .upstream => .upstream_closed,
        };

        switch (side) {
            .client => self.client_read_open = false,
            .upstream => self.upstream_read_open = false,
        }
        if (self.first_close == null) self.first_close = close_term;
        if (!self.client_read_open and !self.upstream_read_open) {
            self.final_termination = self.first_close orelse close_term;
        }
    }

    fn finishTermination(self: *RelayShared, termination: Termination, io: Io) void {
        assert(@intFromPtr(self) != 0);
        assert(switch (termination) {
            .client_closed,
            .upstream_closed,
            .client_error,
            .upstream_error,
            .idle_timeout,
            => true,
        });

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        if (self.final_termination == null) self.final_termination = termination;
    }

    fn shouldStop(self: *RelayShared, side: Side, io: Io) ?Termination {
        assert(@intFromPtr(self) != 0);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        if (self.final_termination) |termination| return termination;

        const side_open = switch (side) {
            .client => self.client_read_open,
            .upstream => self.upstream_read_open,
        };
        if (!side_open) return self.first_close;

        const now_ns = time.monotonicNanos();
        const idle_elapsed_ns = time.elapsedNanos(self.last_progress_ns, now_ns);
        if (idle_elapsed_ns > self.idle_timeout_ns) {
            self.final_termination = .idle_timeout;
            return .idle_timeout;
        }

        return null;
    }

    fn snapshot(self: *RelayShared, io: Io) TunnelStats {
        assert(@intFromPtr(self) != 0);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var stats = self.stats;
        stats.duration_ns = time.elapsedNanos(self.start_ns, time.monotonicNanos());
        stats.termination = self.final_termination orelse self.first_close orelse .idle_timeout;
        return stats;
    }
};

pub fn relay(
    io: Io,
    client_socket: *Socket,
    upstream_socket: *Socket,
    initial_client_to_upstream: []const u8,
    initial_upstream_to_client: []const u8,
) TunnelStats {
    return relayWithConfig(
        io,
        client_socket,
        upstream_socket,
        initial_client_to_upstream,
        initial_upstream_to_client,
        config.WEBSOCKET_TUNNEL_IDLE_TIMEOUT_NS,
        config.WEBSOCKET_TUNNEL_POLL_TIMEOUT_MS,
    );
}

pub fn relayWithConfig(
    io: Io,
    client_socket: *Socket,
    upstream_socket: *Socket,
    initial_client_to_upstream: []const u8,
    initial_upstream_to_client: []const u8,
    idle_timeout_ns: u64,
    poll_timeout_ms: i32,
) TunnelStats {
    assert(@intFromPtr(client_socket) != 0);
    assert(@intFromPtr(upstream_socket) != 0);
    assert(idle_timeout_ns > 0);
    assert(poll_timeout_ms > 0);

    setSocketNonBlocking(client_socket);
    setSocketNonBlocking(upstream_socket);

    const start_ns = time.monotonicNanos();
    var shared = RelayShared.init(start_ns, idle_timeout_ns);
    var group: Io.Group = .init;
    defer {
        std.log.debug("tunnel: cancel relay group reason=relay_return", .{});
        group.cancel(io);
    }

    group.concurrent(io, relayDirection, .{
        &shared,
        io,
        client_socket,
        upstream_socket,
        initial_client_to_upstream,
        poll_timeout_ms,
        Side.client,
        Side.upstream,
    }) catch {
        // Evented test runtimes may not offer concurrent workers; keep the
        // original async fallback there while using real concurrent work in
        // the threaded server path.
        group.async(io, relayDirection, .{
            &shared,
            io,
            client_socket,
            upstream_socket,
            initial_client_to_upstream,
            poll_timeout_ms,
            Side.client,
            Side.upstream,
        });
    };

    relayDirection(
        &shared,
        io,
        upstream_socket,
        client_socket,
        initial_upstream_to_client,
        poll_timeout_ms,
        Side.upstream,
        Side.client,
    ) catch |err| switch (err) {
        error.Canceled => {},
    };

    return shared.snapshot(io);
}

fn relayDirection(
    shared: *RelayShared,
    io: Io,
    source: *Socket,
    destination: *Socket,
    initial_bytes: []const u8,
    timeout_ms: i32,
    read_side: Side,
    write_side: Side,
) Io.Cancelable!void {
    assert(@intFromPtr(shared) != 0);
    assert(@intFromPtr(source) != 0);
    assert(@intFromPtr(destination) != 0);
    assert(timeout_ms > 0);

    const timeout = timeoutForMilliseconds(timeout_ms);
    if (initial_bytes.len > 0) {
        writeAllSocket(destination, io, timeout, initial_bytes, write_side) catch |err| {
            logTunnelFailure(shared, io, "initial_write_failed", read_side, write_side, err, source, destination);
            shared.finishTermination(mapFailureToTermination(err), io);
            return;
        };
        shared.noteProgress(read_side, @intCast(initial_bytes.len), io);
    }

    var relay_buf: [config.COPY_CHUNK_SIZE_BYTES]u8 = undefined;
    while (true) {
        try std.Io.checkCancel(io);
        if (shared.shouldStop(read_side, io) != null) return;

        const bytes_read = readSomeSocket(source, io, timeout, &relay_buf, read_side) catch |err| switch (err) {
            error.ClientClosed, error.UpstreamClosed => {
                logTunnelClosure(shared, io, "read_closed", read_side, write_side, source, destination);
                shared.markClosed(read_side, io);
                return;
            },
            error.IdleTimeout => continue,
            else => {
                logTunnelFailure(shared, io, "read_failed", read_side, write_side, err, source, destination);
                shared.finishTermination(mapFailureToTermination(err), io);
                return;
            },
        };
        if (bytes_read == 0) {
            logTunnelClosure(shared, io, "read_eof", read_side, write_side, source, destination);
            shared.markClosed(read_side, io);
            return;
        }

        writeAllSocket(destination, io, timeout, relay_buf[0..bytes_read], write_side) catch |err| {
            logTunnelFailure(shared, io, "write_failed", read_side, write_side, err, source, destination);
            shared.finishTermination(mapFailureToTermination(err), io);
            return;
        };
        shared.noteProgress(read_side, bytes_read, io);
    }
}

fn readSomeSocket(
    socket: *Socket,
    io: Io,
    timeout: Io.Timeout,
    out: []u8,
    side: Side,
) RelayFailure!u32 {
    assert(@intFromPtr(socket) != 0);
    assert(out.len > 0);

    return switch (socket.*) {
        .plain => |*plain| blk: {
            waitUntilReadable(plain.fd, io, timeout) catch |err| return mapReadableWaitError(side, err);
            const n = plain.read(out) catch |err| return mapReadSocketError(side, err);
            break :blk n;
        },
        .tls => |*tls_socket| blk: {
            var read_attempts_count: u8 = 0;
            while (read_attempts_count < 8) : (read_attempts_count += 1) {
                if (!tls_socket.has_pending_read()) {
                    waitUntilReadable(tls_socket.fd, io, timeout) catch |err| return mapReadableWaitError(side, err);
                }
                const n = tls_socket.stream.read(out) catch |err| switch (err) {
                    error.WantRead => return error.IdleTimeout,
                    error.WantWrite => {
                        waitAfterTlsWouldBlock(tls_socket.fd, io, timeout) catch |wait_err| return mapWritableWaitError(side, wait_err);
                        continue;
                    },
                    error.ConnectionReset => return closeFailure(side),
                    else => return errorFailure(side),
                };
                break :blk n;
            }
            return errorFailure(side);
        },
    };
}

fn writeAllSocket(
    socket: *Socket,
    io: Io,
    timeout: Io.Timeout,
    data: []const u8,
    side: Side,
) RelayFailure!void {
    assert(@intFromPtr(socket) != 0);
    assert(data.len > 0);

    return switch (socket.*) {
        .plain => |plain| {
            var writer_buf: [config.SERVER_WRITE_BUFFER_SIZE_BYTES]u8 = undefined;
            var writer = rawStreamForFd(plain.fd).writer(io, &writer_buf);
            writer.interface.writeAll(data) catch return errorFailure(side);
            writer.interface.flush() catch return errorFailure(side);
        },
        .tls => |*tls_socket| {
            var sent: usize = 0;
            var iterations: u32 = 0;
            while (sent < data.len and iterations < Socket.max_write_iterations_count) : (iterations += 1) {
                const n = tls_socket.stream.write(data[sent..]) catch |err| switch (err) {
                    error.WouldBlock => {
                        waitAfterTlsWouldBlock(tls_socket.fd, io, timeout) catch |wait_err| return mapWritableWaitError(side, wait_err);
                        continue;
                    },
                    error.ConnectionReset => return closeFailure(side),
                    else => return errorFailure(side),
                };
                if (n == 0) return closeFailure(side);
                sent += n;
            }
            if (sent < data.len) return errorFailure(side);
        },
    };
}

fn setSocketNonBlocking(socket: *Socket) void {
    assert(@intFromPtr(socket) != 0);

    const fd = socket.get_fd();
    assert(fd >= 0);

    const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(rc) != .SUCCESS) return;

    var flags: usize = @intCast(rc);
    flags |= @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    _ = posix.system.fcntl(fd, posix.F.SETFL, flags);
}

fn timeoutForMilliseconds(timeout_ms: i32) Io.Timeout {
    assert(timeout_ms > 0);
    return .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(timeout_ms),
        .clock = .awake,
    } };
}

fn waitUntilReadable(fd: i32, io: Io, timeout: Io.Timeout) anyerror!void {
    assert(fd >= 0);

    var messages: [1]Io.net.IncomingMessage = .{Io.net.IncomingMessage.init};
    var peek_buf: [1]u8 = undefined;
    const maybe_err, _ = rawStreamForFd(fd).socket.receiveManyTimeout(
        io,
        &messages,
        &peek_buf,
        .{ .peek = true },
        timeout,
    );
    if (maybe_err) |err| return err;
}

fn waitAfterTlsWouldBlock(fd: i32, io: Io, timeout: Io.Timeout) anyerror!void {
    assert(fd >= 0);

    waitUntilReadable(fd, io, timeout) catch |err| switch (err) {
        error.Timeout => try std.Io.sleep(io, timeout.duration.raw, timeout.duration.clock),
        else => return err,
    };
}

fn rawStreamForFd(fd: i32) Io.net.Stream {
    assert(fd >= 0);
    return .{
        .socket = .{
            .handle = fd,
            .address = .{ .ip4 = .unspecified(0) },
        },
    };
}

fn closeTermination(side: Side) Termination {
    return switch (side) {
        .client => .client_closed,
        .upstream => .upstream_closed,
    };
}

fn closeFailure(side: Side) RelayFailure {
    return switch (side) {
        .client => error.ClientClosed,
        .upstream => error.UpstreamClosed,
    };
}

fn errorFailure(side: Side) RelayFailure {
    return switch (side) {
        .client => error.ClientError,
        .upstream => error.UpstreamError,
    };
}

fn mapReadSocketError(side: Side, err: anyerror) RelayFailure {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionReset,
        error.BrokenPipe,
        => closeFailure(side),
        else => errorFailure(side),
    };
}

fn mapReadableWaitError(side: Side, err: anyerror) RelayFailure {
    return switch (err) {
        error.Timeout => error.IdleTimeout,
        error.ConnectionResetByPeer => closeFailure(side),
        else => errorFailure(side),
    };
}

fn mapWritableWaitError(side: Side, err: anyerror) RelayFailure {
    return switch (err) {
        error.Timeout => error.IdleTimeout,
        error.ConnectionResetByPeer => closeFailure(side),
        else => errorFailure(side),
    };
}

fn mapFailureToTermination(err: RelayFailure) Termination {
    return switch (err) {
        error.ClientClosed => .client_closed,
        error.UpstreamClosed => .upstream_closed,
        error.ClientError => .client_error,
        error.UpstreamError => .upstream_error,
        error.IdleTimeout => .idle_timeout,
    };
}

fn logTunnelClosure(
    shared: *RelayShared,
    io: Io,
    event: []const u8,
    read_side: Side,
    write_side: Side,
    source: *const Socket,
    destination: *const Socket,
) void {
    assert(@intFromPtr(shared) != 0);
    assert(event.len > 0);
    assert(@intFromPtr(source) != 0);
    assert(@intFromPtr(destination) != 0);

    const stats = shared.snapshot(io);
    std.log.debug(
        "tunnel: {s} read_side={s} write_side={s} source_fd={d} destination_fd={d} client_to_upstream_bytes={d} upstream_to_client_bytes={d} duration_ns={d} termination={s}",
        .{
            event,
            @tagName(read_side),
            @tagName(write_side),
            source.get_fd(),
            destination.get_fd(),
            stats.client_to_upstream_bytes,
            stats.upstream_to_client_bytes,
            stats.duration_ns,
            @tagName(stats.termination),
        },
    );
}

fn logTunnelFailure(
    shared: *RelayShared,
    io: Io,
    event: []const u8,
    read_side: Side,
    write_side: Side,
    err: RelayFailure,
    source: *const Socket,
    destination: *const Socket,
) void {
    assert(@intFromPtr(shared) != 0);
    assert(event.len > 0);
    assert(@intFromPtr(source) != 0);
    assert(@intFromPtr(destination) != 0);

    const stats = shared.snapshot(io);
    std.log.warn(
        "tunnel: {s} read_side={s} write_side={s} err={s} source_fd={d} destination_fd={d} client_to_upstream_bytes={d} upstream_to_client_bytes={d} duration_ns={d} termination={s}",
        .{
            event,
            @tagName(read_side),
            @tagName(write_side),
            @errorName(err),
            source.get_fd(),
            destination.get_fd(),
            stats.client_to_upstream_bytes,
            stats.upstream_to_client_bytes,
            stats.duration_ns,
            @tagName(stats.termination),
        },
    );
}

test "relay forwards bytes in both directions" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const client_pair = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(client_pair[0]);

    const upstream_pair = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(upstream_pair[0]);

    var client_socket = Socket.Plain.init_client(client_pair[0]);
    var upstream_socket = Socket.Plain.init_client(upstream_pair[0]);

    const client_payload = "hello-upstream";
    const upstream_payload = "hello-client";

    _ = try std.posix.write(client_pair[1], client_payload);
    _ = try std.posix.write(upstream_pair[1], upstream_payload);
    std.posix.close(client_pair[1]);
    std.posix.close(upstream_pair[1]);

    const stats = relay(evented.io(), &client_socket, &upstream_socket, "", "");

    try std.testing.expectEqual(@as(u64, client_payload.len), stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, upstream_payload.len), stats.upstream_to_client_bytes);
    try std.testing.expect(stats.termination == .client_closed or stats.termination == .upstream_closed);
}

test "relay forwards initial buffered bytes before streaming" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const client_pair = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(client_pair[0]);

    const upstream_pair = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(upstream_pair[0]);

    var client_socket = Socket.Plain.init_client(client_pair[0]);
    var upstream_socket = Socket.Plain.init_client(upstream_pair[0]);

    std.posix.close(client_pair[1]);
    std.posix.close(upstream_pair[1]);

    const stats = relay(evented.io(), &client_socket, &upstream_socket, "pre-client", "pre-upstream");

    try std.testing.expectEqual(@as(u64, 10), stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, 12), stats.upstream_to_client_bytes);
}

test "finishTermination accepts closed-side termination" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const start_ns = time.monotonicNanos();
    var shared = RelayShared.init(start_ns, config.WEBSOCKET_TUNNEL_IDLE_TIMEOUT_NS);

    shared.finishTermination(.upstream_closed, evented.io());

    const stats = shared.snapshot(evented.io());
    try std.testing.expectEqual(Termination.upstream_closed, stats.termination);
    try std.testing.expectEqual(@as(u64, 0), stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.upstream_to_client_bytes);
}

test "relayDirection maps TLS destination reset during initial write to closed termination" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const source_pair = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(source_pair[0]);
    defer std.posix.close(source_pair[1]);

    var source_socket = Socket.Plain.init_client(source_pair[0]);
    var destination_socket = try createResetClosedTlsClientSocket();
    defer destination_socket.close();

    setSocketNonBlocking(&source_socket);
    setSocketNonBlocking(&destination_socket);

    const start_ns = time.monotonicNanos();
    var shared = RelayShared.init(start_ns, config.WEBSOCKET_TUNNEL_IDLE_TIMEOUT_NS);

    try relayDirection(
        &shared,
        evented.io(),
        &source_socket,
        &destination_socket,
        "trigger-reset",
        config.WEBSOCKET_TUNNEL_POLL_TIMEOUT_MS,
        .client,
        .upstream,
    );

    const stats = shared.snapshot(evented.io());
    try std.testing.expectEqual(Termination.upstream_closed, stats.termination);
    try std.testing.expectEqual(@as(u64, 0), stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.upstream_to_client_bytes);
}

const test_cert_path = "experiments/tls-poc/cert.pem";
const test_key_path = "experiments/tls-poc/key.pem";

const TlsServerCloseContext = struct {
    fd: i32,
    err: ?anyerror = null,
};

fn createResetClosedTlsClientSocket() !Socket {
    const tls = @import("serval-tls");
    const ssl = tls.ssl;

    const tls_pair = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    errdefer std.posix.close(tls_pair[0]);
    errdefer std.posix.close(tls_pair[1]);

    var server_ctx = TlsServerCloseContext{ .fd = tls_pair[1] };
    const thread = try std.Thread.spawn(.{}, tlsServerHandshakeAndResetClose, .{&server_ctx});

    ssl.init();
    const client_ctx = try ssl.createClientCtx();
    defer ssl.SSL_CTX_free(client_ctx);
    ssl.SSL_CTX_set_verify(client_ctx, ssl.SSL_VERIFY_NONE, null);

    const client_socket = try Socket.TLS.TLSSocket.init_client(
        tls_pair[0],
        client_ctx,
        "localhost",
        false,
        null,
    );

    thread.join();
    if (server_ctx.err) |err| return err;

    return client_socket;
}

fn tlsServerHandshakeAndResetClose(ctx: *TlsServerCloseContext) void {
    assert(@intFromPtr(ctx) != 0);
    assert(ctx.fd >= 0);

    tlsServerHandshakeAndResetCloseImpl(ctx) catch |err| {
        ctx.err = err;
    };
}

fn tlsServerHandshakeAndResetCloseImpl(ctx: *TlsServerCloseContext) !void {
    const tls = @import("serval-tls");
    const ssl = tls.ssl;

    const server_ctx = try ssl.createServerCtxFromPemFiles(test_cert_path, test_key_path);
    defer ssl.SSL_CTX_free(server_ctx);

    var socket = try Socket.TLS.TLSSocket.init_server(ctx.fd, server_ctx);
    abruptCloseTlsSocket(&socket);
}

fn abruptCloseTlsSocket(socket: *Socket) void {
    const tls = @import("serval-tls");
    const ssl = tls.ssl;

    assert(@intFromPtr(socket) != 0);
    assert(socket.get_fd() >= 0);

    switch (socket.*) {
        .plain => unreachable,
        .tls => |*tls_socket| {
            const linger_value = posix.linger{
                .onoff = 1,
                .linger = 0,
            };
            posix.setsockopt(
                tls_socket.fd,
                posix.SOL.SOCKET,
                posix.SO.LINGER,
                std.mem.asBytes(&linger_value),
            ) catch unreachable;

            switch (tls_socket.stream.mode) {
                .ktls => {},
                .userspace => |ssl_conn| ssl.SSL_free(ssl_conn),
            }
            posix.close(tls_socket.fd);
            tls_socket.fd = -1;
        },
    }
}
