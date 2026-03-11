//! WebSocket Tunnel Relay
//!
//! Bidirectional byte relay used after successful HTTP/1.1 upgrade.
//! TigerStyle: Single-threaded relay, bounded by explicit idle timeout.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const config = serval_core.config;
const time = serval_core.time;
const log = serval_core.log.scoped(.proxy_tunnel);

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;
const SocketError = serval_socket.SocketError;

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

const IoOutcome = struct {
    progress: bool,
    termination: ?Termination,
};

const RelayBuffer = struct {
    bytes: [config.COPY_CHUNK_SIZE_BYTES]u8 = std.mem.zeroes([config.COPY_CHUNK_SIZE_BYTES]u8),
    start: u32 = 0,
    end: u32 = 0,

    fn pendingBytes(self: *const RelayBuffer) u32 {
        assert(self.end >= self.start);
        return self.end - self.start;
    }

    fn hasPending(self: *const RelayBuffer) bool {
        return self.pendingBytes() > 0;
    }

    fn compact(self: *RelayBuffer) void {
        assert(self.end >= self.start);

        if (self.start == 0) return;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
            return;
        }

        const pending: usize = @intCast(self.end - self.start);
        const start: usize = @intCast(self.start);
        std.mem.copyForwards(u8, self.bytes[0..pending], self.bytes[start..][0..pending]);
        self.start = 0;
        self.end = @intCast(pending);
    }

    fn writableSlice(self: *RelayBuffer) []u8 {
        self.compact();
        const end: usize = @intCast(self.end);
        return self.bytes[end..];
    }

    fn readableSlice(self: *const RelayBuffer) []const u8 {
        const start: usize = @intCast(self.start);
        const end: usize = @intCast(self.end);
        return self.bytes[start..end];
    }

    fn recordRead(self: *RelayBuffer, n: u32) void {
        assert(n > 0);
        assert(self.end + n <= self.bytes.len);
        self.end += n;
    }

    fn recordWrite(self: *RelayBuffer, n: u32) void {
        assert(n > 0);
        assert(self.start + n <= self.end);
        self.start += n;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }
};

pub fn relay(
    client_socket: *Socket,
    upstream_socket: *Socket,
    initial_client_to_upstream: []const u8,
    initial_upstream_to_client: []const u8,
) TunnelStats {
    return relayWithConfig(
        client_socket,
        upstream_socket,
        initial_client_to_upstream,
        initial_upstream_to_client,
        config.WEBSOCKET_TUNNEL_IDLE_TIMEOUT_NS,
        config.WEBSOCKET_TUNNEL_POLL_TIMEOUT_MS,
    );
}

pub fn relayWithConfig(
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

    const start_ns = time.monotonicNanos();
    var stats = TunnelStats{};

    if (sendInitialBytes(upstream_socket, initial_client_to_upstream, &stats.client_to_upstream_bytes, .upstream)) |termination| {
        return finalizeStats(start_ns, &stats, termination);
    }
    if (sendInitialBytes(client_socket, initial_upstream_to_client, &stats.upstream_to_client_bytes, .client)) |termination| {
        return finalizeStats(start_ns, &stats, termination);
    }

    var client_to_upstream = RelayBuffer{};
    var upstream_to_client = RelayBuffer{};
    var client_read_open = true;
    var upstream_read_open = true;
    var first_close: ?Termination = null;
    var last_progress_ns = start_ns;

    while (true) {
        if (!client_read_open and !upstream_read_open and
            !client_to_upstream.hasPending() and !upstream_to_client.hasPending())
        {
            return finalizeStats(start_ns, &stats, first_close orelse .upstream_closed);
        }

        const now_ns = time.monotonicNanos();
        if (time.elapsedNanos(last_progress_ns, now_ns) > idle_timeout_ns) {
            return finalizeStats(start_ns, &stats, .idle_timeout);
        }

        const immediate_client = if (client_read_open and client_socket.has_pending_read())
            transferRead(client_socket, &client_to_upstream, .client, &stats.client_to_upstream_bytes)
        else
            IoOutcome{ .progress = false, .termination = null };
        if (handleTermination(&first_close, &client_read_open, &upstream_read_open, immediate_client, .client)) |termination| {
            return finalizeStats(start_ns, &stats, termination);
        }

        const immediate_upstream = if (upstream_read_open and upstream_socket.has_pending_read())
            transferRead(upstream_socket, &upstream_to_client, .upstream, &stats.upstream_to_client_bytes)
        else
            IoOutcome{ .progress = false, .termination = null };
        if (handleTermination(&first_close, &client_read_open, &upstream_read_open, immediate_upstream, .upstream)) |termination| {
            return finalizeStats(start_ns, &stats, termination);
        }

        if (immediate_client.progress or immediate_upstream.progress) {
            last_progress_ns = time.monotonicNanos();
            continue;
        }

        const poll_result = pollAndTransfer(
            client_socket,
            upstream_socket,
            &client_to_upstream,
            &upstream_to_client,
            &stats,
            &client_read_open,
            &upstream_read_open,
            &first_close,
            poll_timeout_ms,
        );
        if (poll_result.progress) {
            last_progress_ns = time.monotonicNanos();
        }
        if (poll_result.termination) |termination| {
            return finalizeStats(start_ns, &stats, termination);
        }
    }
}

const Side = enum { client, upstream };

fn pollAndTransfer(
    client_socket: *Socket,
    upstream_socket: *Socket,
    client_to_upstream: *RelayBuffer,
    upstream_to_client: *RelayBuffer,
    stats: *TunnelStats,
    client_read_open: *bool,
    upstream_read_open: *bool,
    first_close: *?Termination,
    poll_timeout_ms: i32,
) IoOutcome {
    var poll_fds = [_]std.posix.pollfd{
        .{ .fd = client_socket.get_fd(), .events = 0, .revents = 0 },
        .{ .fd = upstream_socket.get_fd(), .events = 0, .revents = 0 },
    };

    if (client_read_open.* and client_to_upstream.writableSlice().len > 0) {
        poll_fds[0].events |= std.posix.POLL.IN;
    }
    if (upstream_read_open.* and upstream_to_client.writableSlice().len > 0) {
        poll_fds[1].events |= std.posix.POLL.IN;
    }
    if (upstream_to_client.hasPending()) {
        poll_fds[0].events |= std.posix.POLL.OUT;
    }
    if (client_to_upstream.hasPending()) {
        poll_fds[1].events |= std.posix.POLL.OUT;
    }

    const poll_count = std.posix.poll(
        &poll_fds,
        poll_timeout_ms,
    ) catch |err| {
        log.warn("poll failed: {s}", .{@errorName(err)});
        return .{ .progress = false, .termination = .client_error };
    };
    if (poll_count == 0) return .{ .progress = false, .termination = null };

    var progress = false;

    if (wantsRead(poll_fds[0].revents) and client_read_open.*) {
        const result = transferRead(client_socket, client_to_upstream, .client, &stats.client_to_upstream_bytes);
        if (handleTermination(first_close, client_read_open, upstream_read_open, result, .client)) |termination| {
            return .{ .progress = progress or result.progress, .termination = termination };
        }
        progress = progress or result.progress;
    }

    if (wantsRead(poll_fds[1].revents) and upstream_read_open.*) {
        const result = transferRead(upstream_socket, upstream_to_client, .upstream, &stats.upstream_to_client_bytes);
        if (handleTermination(first_close, client_read_open, upstream_read_open, result, .upstream)) |termination| {
            return .{ .progress = progress or result.progress, .termination = termination };
        }
        progress = progress or result.progress;
    }

    if (wantsWrite(poll_fds[1].revents) and client_to_upstream.hasPending()) {
        const result = transferWrite(upstream_socket, client_to_upstream, .upstream);
        if (result.termination) |termination| {
            return .{ .progress = progress or result.progress, .termination = termination };
        }
        progress = progress or result.progress;
    }

    if (wantsWrite(poll_fds[0].revents) and upstream_to_client.hasPending()) {
        const result = transferWrite(client_socket, upstream_to_client, .client);
        if (result.termination) |termination| {
            return .{ .progress = progress or result.progress, .termination = termination };
        }
        progress = progress or result.progress;
    }

    return .{ .progress = progress, .termination = null };
}

fn handleTermination(
    first_close: *?Termination,
    client_read_open: *bool,
    upstream_read_open: *bool,
    result: IoOutcome,
    side: Side,
) ?Termination {
    if (result.termination) |termination| {
        switch (termination) {
            .client_closed => {
                client_read_open.* = false;
                if (first_close.* == null) first_close.* = .client_closed;
                if (side == .client and !upstream_read_open.*) return termination;
                return null;
            },
            .upstream_closed => {
                upstream_read_open.* = false;
                if (first_close.* == null) first_close.* = .upstream_closed;
                if (side == .upstream and !client_read_open.*) return termination;
                return null;
            },
            else => return termination,
        }
    }
    return null;
}

fn transferRead(
    source: *Socket,
    buffer: *RelayBuffer,
    side: Side,
    counter_bytes: *u64,
) IoOutcome {
    const writable = buffer.writableSlice();
    if (writable.len == 0) return .{ .progress = false, .termination = null };

    const bytes_read = source.read(writable) catch |err| {
        return .{ .progress = false, .termination = mapReadError(side, err) };
    };
    if (bytes_read == 0) {
        return .{ .progress = false, .termination = closeTermination(side) };
    }

    buffer.recordRead(bytes_read);
    counter_bytes.* += bytes_read;
    return .{ .progress = true, .termination = null };
}

fn transferWrite(
    destination: *Socket,
    buffer: *RelayBuffer,
    side: Side,
) IoOutcome {
    const readable = buffer.readableSlice();
    if (readable.len == 0) return .{ .progress = false, .termination = null };

    const bytes_written = destination.write(readable) catch |err| {
        return .{ .progress = false, .termination = mapWriteError(side, err) };
    };
    if (bytes_written == 0) {
        return .{ .progress = false, .termination = closeTermination(side) };
    }

    buffer.recordWrite(bytes_written);
    return .{ .progress = true, .termination = null };
}

fn sendInitialBytes(
    destination: *Socket,
    data: []const u8,
    counter_bytes: *u64,
    side: Side,
) ?Termination {
    if (data.len == 0) return null;

    destination.write_all(data) catch |err| {
        return mapWriteError(side, err);
    };
    counter_bytes.* += data.len;
    return null;
}

fn wantsRead(revents: i16) bool {
    return (revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0;
}

fn wantsWrite(revents: i16) bool {
    return (revents & (std.posix.POLL.OUT | std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0;
}

fn closeTermination(side: Side) Termination {
    return switch (side) {
        .client => .client_closed,
        .upstream => .upstream_closed,
    };
}

fn mapReadError(side: Side, err: SocketError) Termination {
    return switch (err) {
        SocketError.ConnectionClosed,
        SocketError.ConnectionReset,
        SocketError.BrokenPipe,
        => closeTermination(side),
        SocketError.Timeout,
        SocketError.TLSError,
        SocketError.Unexpected,
        => switch (side) {
            .client => .client_error,
            .upstream => .upstream_error,
        },
    };
}

fn mapWriteError(side: Side, err: SocketError) Termination {
    return switch (err) {
        SocketError.ConnectionClosed,
        SocketError.ConnectionReset,
        SocketError.BrokenPipe,
        => closeTermination(side),
        SocketError.Timeout,
        SocketError.TLSError,
        SocketError.Unexpected,
        => switch (side) {
            .client => .client_error,
            .upstream => .upstream_error,
        },
    };
}

fn finalizeStats(start_ns: u64, stats: *TunnelStats, termination: Termination) TunnelStats {
    const end_ns = time.monotonicNanos();
    stats.duration_ns = time.elapsedNanos(start_ns, end_ns);
    stats.termination = termination;
    return stats.*;
}

test "relay forwards bytes in both directions" {
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

    const stats = relay(&client_socket, &upstream_socket, "", "");

    try std.testing.expectEqual(@as(u64, client_payload.len), stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, upstream_payload.len), stats.upstream_to_client_bytes);
    try std.testing.expect(stats.termination == .client_closed or stats.termination == .upstream_closed);
}

test "relay forwards initial buffered bytes before polling" {
    const client_pair = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(client_pair[0]);

    const upstream_pair = try std.posix.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(upstream_pair[0]);

    var client_socket = Socket.Plain.init_client(client_pair[0]);
    var upstream_socket = Socket.Plain.init_client(upstream_pair[0]);

    std.posix.close(client_pair[1]);
    std.posix.close(upstream_pair[1]);

    const stats = relay(&client_socket, &upstream_socket, "pre-client", "pre-upstream");

    try std.testing.expectEqual(@as(u64, 10), stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, 12), stats.upstream_to_client_bytes);
}
