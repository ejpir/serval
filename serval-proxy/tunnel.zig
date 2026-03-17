//! WebSocket Tunnel Relay
//!
//! Bidirectional byte relay used after successful HTTP/1.1 upgrade.
//! Uses fiber-safe Io.vtable.netRead/netWrite for plain sockets so the
//! Io scheduler can multiplex work while data is in-flight. TLS sockets
//! fall back to blocking read/write (fine for the Threaded backend).
//!
//! TigerStyle: Cooperative fibers, group cancellation for cleanup.

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
};

const RelayPhase = enum {
    startup,
    steady_state,
    closing,
};

const RelayShared = struct {
    mutex: Io.Mutex = .init,
    stats: TunnelStats = .{},
    start_ns: u64,
    phase: RelayPhase = .startup,
    client_startup_done: bool = false,
    upstream_startup_done: bool = false,
    first_close: ?Termination = null,
    final_termination: ?Termination = null,

    fn init(start_ns: u64) RelayShared {
        assert(start_ns > 0);
        return .{ .start_ns = start_ns };
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
    }

    fn markClosed(self: *RelayShared, side: Side, io: Io) void {
        assert(@intFromPtr(self) != 0);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const close_term: Termination = switch (side) {
            .client => .client_closed,
            .upstream => .upstream_closed,
        };
        if (self.first_close == null) self.first_close = close_term;
    }

    fn finishTermination(self: *RelayShared, termination: Termination, io: Io) void {
        assert(@intFromPtr(self) != 0);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        if (self.final_termination == null) self.final_termination = termination;
        self.phase = .closing;
    }

    fn noteStartupComplete(self: *RelayShared, side: Side, io: Io) void {
        assert(@intFromPtr(self) != 0);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        switch (side) {
            .client => self.client_startup_done = true,
            .upstream => self.upstream_startup_done = true,
        }

        if (self.client_startup_done and self.upstream_startup_done and self.phase == .startup) {
            self.phase = .steady_state;
        }
    }

    fn loadPhase(self: *RelayShared, io: Io) RelayPhase {
        assert(@intFromPtr(self) != 0);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        return self.phase;
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
    return relayImpl(io, client_socket, upstream_socket, initial_client_to_upstream, initial_upstream_to_client);
}

/// relayWithConfig keeps the previous signature for callers that pass
/// idle_timeout_ns / poll_timeout_ms.  Those parameters are no longer
/// used — idle detection now relies on TCP keepalive and Io group
/// cancellation — but the API stays compatible.
pub fn relayWithConfig(
    io: Io,
    client_socket: *Socket,
    upstream_socket: *Socket,
    initial_client_to_upstream: []const u8,
    initial_upstream_to_client: []const u8,
    idle_timeout_ns: u64,
    poll_timeout_ms: i32,
) TunnelStats {
    _ = idle_timeout_ns;
    _ = poll_timeout_ms;
    return relayImpl(io, client_socket, upstream_socket, initial_client_to_upstream, initial_upstream_to_client);
}

fn relayImpl(
    io: Io,
    client_socket: *Socket,
    upstream_socket: *Socket,
    initial_client_to_upstream: []const u8,
    initial_upstream_to_client: []const u8,
) TunnelStats {
    assert(@intFromPtr(client_socket) != 0);
    assert(@intFromPtr(upstream_socket) != 0);

    const start_ns = time.monotonicNanos();
    var shared = RelayShared.init(start_ns);
    var group: Io.Group = .init;
    defer group.cancel(io);

    // Run both directions with the same relay state machine. One side is
    // attached as a concurrent fiber; the other runs on the current fiber.
    // Startup gating keeps the model symmetric (both sides complete startup
    // before either enters steady-state forwarding).
    // Background fiber: upstream → client.
    group.concurrent(io, relayDirection, .{
        &shared,
        io,
        upstream_socket,
        client_socket,
        initial_upstream_to_client,
        Side.upstream,
        Side.client,
    }) catch {
        shared.finishTermination(.upstream_error, io);
        return shared.snapshot(io);
    };

    // Foreground: client → upstream.
    // This guarantees initial downstream bytes are forwarded before any
    // blocking upstream read can stall progress.
    relayDirection(
        &shared,
        io,
        client_socket,
        upstream_socket,
        initial_client_to_upstream,
        Side.client,
        Side.upstream,
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
    read_side: Side,
    write_side: Side,
) Io.Cancelable!void {
    assert(@intFromPtr(shared) != 0);
    assert(@intFromPtr(source) != 0);
    assert(@intFromPtr(destination) != 0);

    if (initial_bytes.len > 0) {
        ioWriteAll(destination, io, initial_bytes, write_side) catch |err| {
            logTunnelFailure(shared, io, "initial_write_failed", read_side, write_side, err, source, destination);
            shared.finishTermination(mapFailureToTermination(err), io);
            return;
        };
        shared.noteProgress(read_side, @intCast(initial_bytes.len), io);
    }

    // Startup phase: each direction declares its pre-buffer flush complete.
    // Steady-state starts only after both sides complete startup.
    shared.noteStartupComplete(read_side, io);
    try waitForSteadyState(shared, io);

    var relay_buf: [config.COPY_CHUNK_SIZE_BYTES]u8 = undefined;
    while (true) {
        try std.Io.checkCancel(io);

        const bytes_read = ioReadSome(source, io, &relay_buf, read_side) catch |err| {
            logTunnelFailure(shared, io, "read_failed", read_side, write_side, err, source, destination);
            shared.finishTermination(mapFailureToTermination(err), io);
            return;
        };
        if (bytes_read == 0) {
            logTunnelClosure(shared, io, "read_eof", read_side, write_side, source, destination);
            shared.markClosed(read_side, io);
            return;
        }

        ioWriteAll(destination, io, relay_buf[0..bytes_read], write_side) catch |err| {
            logTunnelFailure(shared, io, "write_failed", read_side, write_side, err, source, destination);
            shared.finishTermination(mapFailureToTermination(err), io);
            return;
        };
        shared.noteProgress(read_side, bytes_read, io);
    }
}

fn waitForSteadyState(shared: *RelayShared, io: Io) Io.Cancelable!void {
    assert(@intFromPtr(shared) != 0);

    const startup_poll_sleep_ms: u64 = 1;
    while (true) {
        try std.Io.checkCancel(io);

        const phase = shared.loadPhase(io);
        switch (phase) {
            .startup => try std.Io.sleep(io, Io.Duration.fromMilliseconds(startup_poll_sleep_ms), .awake),
            .steady_state, .closing => return,
        }
    }
}

// ---------------------------------------------------------------------------
// Fiber-safe read / write
// ---------------------------------------------------------------------------

/// Read some bytes from source. Returns 0 on EOF.
/// Plain sockets use io.vtable.netRead (fiber-safe); TLS uses blocking read.
fn ioReadSome(socket: *Socket, io: Io, buf: []u8, side: Side) RelayFailure!u32 {
    assert(@intFromPtr(socket) != 0);
    assert(buf.len > 0);

    return switch (socket.*) {
        .plain => |plain| {
            var read_bufs: [1][]u8 = .{buf};
            const n = io.vtable.netRead(io.userdata, plain.fd, &read_bufs) catch |err| {
                return mapNetError(side, err);
            };
            return @intCast(n);
        },
        .tls => {
            const n = socket.read(buf) catch |err| {
                return mapSocketError(side, err);
            };
            return n;
        },
    };
}

/// Write all bytes to destination.
/// Plain sockets use io.vtable.netWrite (fiber-safe); TLS uses blocking write.
fn ioWriteAll(socket: *Socket, io: Io, data: []const u8, side: Side) RelayFailure!void {
    assert(@intFromPtr(socket) != 0);
    assert(data.len > 0);

    return switch (socket.*) {
        .plain => |plain| {
            var sent: usize = 0;
            while (sent < data.len) {
                const pending = data[sent..];
                const write_slices = [_][]const u8{pending};
                const n = io.vtable.netWrite(io.userdata, plain.fd, &.{}, &write_slices, 1) catch |err| {
                    return mapNetError(side, err);
                };
                if (n == 0) return closeFailure(side);
                sent += n;
            }
        },
        .tls => {
            var sent: usize = 0;
            var iterations: u32 = 0;
            while (sent < data.len and iterations < Socket.max_write_iterations_count) : (iterations += 1) {
                const n = socket.write(data[sent..]) catch |err| {
                    return mapSocketError(side, err);
                };
                if (n == 0) return closeFailure(side);
                sent += n;
            }
            if (sent < data.len) return errorFailure(side);
        },
    };
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

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

fn mapSocketError(side: Side, err: serval_socket.SocketError) RelayFailure {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionReset,
        error.BrokenPipe,
        => closeFailure(side),
        error.Timeout,
        error.TLSError,
        error.Unexpected,
        => errorFailure(side),
    };
}

/// Map Io.net write/read errors to relay failures. Connection-oriented
/// errors become "closed"; everything else becomes "error".
fn mapNetError(side: Side, err: anyerror) RelayFailure {
    return switch (err) {
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.HostUnreachable,
        => closeFailure(side),
        else => errorFailure(side),
    };
}

fn mapFailureToTermination(err: RelayFailure) Termination {
    return switch (err) {
        error.ClientClosed => .client_closed,
        error.UpstreamClosed => .upstream_closed,
        error.ClientError => .client_error,
        error.UpstreamError => .upstream_error,
    };
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

fn logTunnelClosure(
    shared: *RelayShared,
    io: Io,
    event: []const u8,
    read_side: Side,
    write_side: Side,
    source: *const Socket,
    destination: *const Socket,
) void {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    var shared = RelayShared.init(start_ns);

    shared.finishTermination(.upstream_closed, evented.io());

    const stats = shared.snapshot(evented.io());
    try std.testing.expectEqual(Termination.upstream_closed, stats.termination);
    try std.testing.expectEqual(@as(u64, 0), stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.upstream_to_client_bytes);
}
