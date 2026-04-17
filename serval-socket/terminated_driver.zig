// serval-socket/terminated_driver.zig
//! Bounded transport driver for terminated protocol loops.
//!
//! This module centralizes nonblocking readiness/deadline handling for
//! request/response protocol drivers (for example HTTP/1.1 and HTTP/2
//! terminated paths). It provides one plain+TLS contract where callers observe
//! progress/close/timeout outcomes without handling TLS WANT states directly.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const posix = std.posix;

const serval_core = @import("serval-core");
const time = serval_core.time;

const socket_mod = @import("socket.zig");
const Socket = socket_mod.Socket;
const PlainSocket = socket_mod.PlainSocket;

const ReadinessDirection = enum {
    read,
    write,
};

const WaitForReadyError = error{
    Timeout,
    Closed,
    ReadinessWaitFailed,
};

const PlainReadStep = union(enum) {
    bytes: u32,
    closed,
    need_read,
};

const PlainWriteStep = union(enum) {
    bytes: u32,
    closed,
    need_write,
};

/// Maximum step iterations inside one read/write driver call.
/// TigerStyle S3: explicit bounded loop cap.
const max_driver_iterations: u32 = 131_072;

/// Outcome of one bounded transport read operation.
///
/// `.bytes` means forward progress, `.closed` means peer shutdown/reset,
/// `.timeout` means the supplied deadline/timeout budget expired.
pub const ReadOutcome = union(enum) {
    bytes: u32,
    closed,
    timeout,
};

/// Outcome of one bounded transport write operation.
///
/// `.bytes` means forward progress, `.closed` means peer shutdown/reset,
/// `.timeout` means the supplied deadline/timeout budget expired.
pub const WriteOutcome = union(enum) {
    bytes: u32,
    closed,
    timeout,
};

/// Fatal driver-level transport error.
///
/// This is reserved for unrecoverable syscall/TLS failures that are neither
/// clean closure nor timeout-driven stalls.
pub const DriverError = error{
    TransportFailed,
};

fn monotonicNanos() u64 {
    const now_ns = time.monotonicNanos();
    assert(now_ns > 0);
    return now_ns;
}

/// Compute a monotonic deadline from a timeout budget in nanoseconds.
fn deadlineFromTimeout(timeout_ns: u64) u64 {
    assert(timeout_ns > 0);

    const start_ns = monotonicNanos();
    const deadline_ns, const overflow = @addWithOverflow(start_ns, timeout_ns);
    const result = if (overflow == 0) deadline_ns else std.math.maxInt(u64);
    assert(result >= start_ns);
    return result;
}

fn remainingTimeoutMs(deadline_ns: u64) ?i32 {
    const now_ns = monotonicNanos();
    if (now_ns >= deadline_ns) return null;

    const remaining_ns = deadline_ns - now_ns;
    const remaining_ms_u64 = std.math.divCeil(u64, remaining_ns, time.ns_per_ms) catch unreachable;
    const max_timeout_ms_u64: u64 = @intCast(std.math.maxInt(i32));
    const clamped_ms_u64 = @min(remaining_ms_u64, max_timeout_ms_u64);
    const timeout_ms: i32 = @intCast(@max(@as(u64, 1), clamped_ms_u64));
    assert(timeout_ms > 0);
    return timeout_ms;
}

fn waitForReady(io: Io, fd: i32, direction: ReadinessDirection, deadline_ns: u64) WaitForReadyError!void {
    assert(fd >= 0);

    const timeout_ms = remainingTimeoutMs(deadline_ns) orelse return error.Timeout;

    switch (direction) {
        .read => {
            var messages: [1]Io.net.IncomingMessage = .{Io.net.IncomingMessage.init};
            var peek_buf: [1]u8 = undefined;
            const timeout: Io.Timeout = .{ .duration = .{
                .raw = Io.Duration.fromMilliseconds(timeout_ms),
                .clock = .awake,
            } };
            const maybe_err, _ = rawStreamForFd(fd).socket.receiveManyTimeout(
                io,
                &messages,
                &peek_buf,
                .{ .peek = true },
                timeout,
            );
            if (maybe_err) |err| switch (err) {
                error.Timeout => return error.Timeout,
                error.ConnectionResetByPeer,
                error.SocketUnconnected,
                => return error.Closed,
                else => return error.ReadinessWaitFailed,
            };
        },
        .write => {
            const events: i16 = posix.POLL.OUT;
            var poll_fds = [_]posix.pollfd{.{
                .fd = fd,
                .events = events,
                .revents = 0,
            }};
            const polled = posix.poll(&poll_fds, timeout_ms) catch return error.ReadinessWaitFailed;
            if (polled == 0) return error.Timeout;

            const revents = poll_fds[0].revents;
            if ((revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) return error.ReadinessWaitFailed;
            if ((revents & posix.POLL.HUP) != 0) return error.Closed;
            if ((revents & events) == 0) return error.ReadinessWaitFailed;
        },
    }
}

fn plainReadStep(socket: *PlainSocket, io: Io, out: []u8) DriverError!PlainReadStep {
    assert(@intFromPtr(socket) != 0);
    assert(out.len > 0);

    var bufs: [1][]u8 = .{out};
    const n = io.vtable.netRead(io.userdata, socket.fd, &bufs) catch |err| switch (err) {
        error.SystemResources => return .need_read,
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        => return .closed,
        else => return error.TransportFailed,
    };

    if (n == 0) return .closed;
    const bytes: u32 = @intCast(n);
    assert(bytes <= out.len);
    return .{ .bytes = bytes };
}

fn plainWriteStep(socket: *PlainSocket, io: Io, data: []const u8) DriverError!PlainWriteStep {
    assert(@intFromPtr(socket) != 0);
    assert(data.len > 0);

    const write_slices = [_][]const u8{data};
    const n = io.vtable.netWrite(io.userdata, socket.fd, &.{}, &write_slices, 1) catch |err| switch (err) {
        error.SystemResources => return .need_write,
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        => return .closed,
        else => return error.TransportFailed,
    };

    if (n == 0) return .closed;
    const bytes: u32 = @intCast(n);
    assert(bytes <= data.len);
    return .{ .bytes = bytes };
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

/// Read bytes with a timeout budget in nanoseconds.
///
/// Contract: `socket` must be open, `out` must be non-empty, `timeout_ns > 0`.
/// Ownership/lifetime: caller retains ownership of `socket` and `out`.
/// Failure semantics: returns `DriverError.TransportFailed` on unrecoverable
/// syscall/TLS failures; otherwise returns `ReadOutcome`.
pub fn readWithTimeout(socket: *Socket, io: Io, out: []u8, timeout_ns: u64) DriverError!ReadOutcome {
    assert(@intFromPtr(socket) != 0);
    assert(out.len > 0);
    assert(timeout_ns > 0);

    const deadline_ns = deadlineFromTimeout(timeout_ns);
    return readWithDeadline(socket, io, out, deadline_ns);
}

/// Read bytes until progress, close, or absolute monotonic deadline.
///
/// Contract: `socket` must be open, `out` must be non-empty, `deadline_ns > 0`.
/// Ownership/lifetime: caller retains ownership of `socket` and `out`.
/// Failure semantics: returns `DriverError.TransportFailed` on unrecoverable
/// syscall/TLS failures; returns `.timeout` when deadline budget expires.
pub fn readWithDeadline(socket: *Socket, io: Io, out: []u8, deadline_ns: u64) DriverError!ReadOutcome {
    assert(@intFromPtr(socket) != 0);
    assert(out.len > 0);
    assert(deadline_ns > 0);

    var iterations: u32 = 0;
    while (iterations < max_driver_iterations) : (iterations += 1) {
        const fd = socket.get_fd();
        assert(fd >= 0);

        switch (socket.*) {
            .plain => |*plain_socket| {
                const step = try plainReadStep(plain_socket, io, out);
                switch (step) {
                    .bytes => |n| return .{ .bytes = n },
                    .closed => return .closed,
                    .need_read => {
                        waitForReady(io, fd, .read, deadline_ns) catch |wait_err| switch (wait_err) {
                            error.Timeout => return .timeout,
                            error.Closed => return .closed,
                            error.ReadinessWaitFailed => return error.TransportFailed,
                        };
                    },
                }
            },
            .tls => |*tls_socket| {
                const step = tls_socket.stream.readStep(out) catch |err| switch (err) {
                    error.ConnectionReset => return .closed,
                    error.KtlsRead,
                    error.SslRead,
                    => return error.TransportFailed,
                };
                switch (step) {
                    .bytes => |n| return .{ .bytes = n },
                    .closed => return .closed,
                    .need_read => {
                        waitForReady(io, fd, .read, deadline_ns) catch |wait_err| switch (wait_err) {
                            error.Timeout => return .timeout,
                            error.Closed => return .closed,
                            error.ReadinessWaitFailed => return error.TransportFailed,
                        };
                    },
                    .need_write => {
                        waitForReady(io, fd, .write, deadline_ns) catch |wait_err| switch (wait_err) {
                            error.Timeout => return .timeout,
                            error.Closed => return .closed,
                            error.ReadinessWaitFailed => return error.TransportFailed,
                        };
                    },
                }
            },
        }
    }

    return .timeout;
}

/// Write bytes with a timeout budget in nanoseconds.
///
/// Contract: `socket` must be open, `data` must be non-empty, `timeout_ns > 0`.
/// Ownership/lifetime: caller retains ownership of `socket` and `data`.
/// Failure semantics: returns `DriverError.TransportFailed` on unrecoverable
/// syscall/TLS failures; otherwise returns `WriteOutcome`.
pub fn writeWithTimeout(socket: *Socket, io: Io, data: []const u8, timeout_ns: u64) DriverError!WriteOutcome {
    assert(@intFromPtr(socket) != 0);
    assert(data.len > 0);
    assert(timeout_ns > 0);

    const deadline_ns = deadlineFromTimeout(timeout_ns);
    return writeWithDeadline(socket, io, data, deadline_ns);
}

/// Write bytes until progress, close, or absolute monotonic deadline.
///
/// Contract: `socket` must be open, `data` must be non-empty, `deadline_ns > 0`.
/// Ownership/lifetime: caller retains ownership of `socket` and `data`.
/// Failure semantics: returns `DriverError.TransportFailed` on unrecoverable
/// syscall/TLS failures; returns `.timeout` when deadline budget expires.
pub fn writeWithDeadline(socket: *Socket, io: Io, data: []const u8, deadline_ns: u64) DriverError!WriteOutcome {
    assert(@intFromPtr(socket) != 0);
    assert(data.len > 0);
    assert(deadline_ns > 0);

    var iterations: u32 = 0;
    while (iterations < max_driver_iterations) : (iterations += 1) {
        const fd = socket.get_fd();
        assert(fd >= 0);

        switch (socket.*) {
            .plain => |*plain_socket| {
                const step = try plainWriteStep(plain_socket, io, data);
                switch (step) {
                    .bytes => |n| return .{ .bytes = n },
                    .closed => return .closed,
                    .need_write => {
                        waitForReady(io, fd, .write, deadline_ns) catch |wait_err| switch (wait_err) {
                            error.Timeout => return .timeout,
                            error.Closed => return .closed,
                            error.ReadinessWaitFailed => return error.TransportFailed,
                        };
                    },
                }
            },
            .tls => |*tls_socket| {
                const step = tls_socket.stream.writeStep(data) catch |err| switch (err) {
                    error.ConnectionReset => return .closed,
                    error.KtlsWrite,
                    error.SslWrite,
                    => return error.TransportFailed,
                };
                switch (step) {
                    .bytes => |n| return .{ .bytes = n },
                    .closed => return .closed,
                    .need_read => {
                        waitForReady(io, fd, .read, deadline_ns) catch |wait_err| switch (wait_err) {
                            error.Timeout => return .timeout,
                            error.Closed => return .closed,
                            error.ReadinessWaitFailed => return error.TransportFailed,
                        };
                    },
                    .need_write => {
                        waitForReady(io, fd, .write, deadline_ns) catch |wait_err| switch (wait_err) {
                            error.Timeout => return .timeout,
                            error.Closed => return .closed,
                            error.ReadinessWaitFailed => return error.TransportFailed,
                        };
                    },
                }
            },
        }
    }

    return .timeout;
}

fn setNonblocking(fd: i32) !void {
    assert(fd >= 0);

    const flags_value = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (flags_value < 0) return error.Unexpected;
    const flags: usize = @intCast(flags_value);
    const nonblocking_flags = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    if ((flags & nonblocking_flags) != 0) return;

    const set_result = posix.system.fcntl(fd, posix.F.SETFL, flags | nonblocking_flags);
    if (set_result < 0) return error.Unexpected;
}

fn testWrite(fd: std.posix.socket_t, data: []const u8) !usize {
    while (true) {
        const rc = std.c.write(fd, data.ptr, data.len);
        switch (std.c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

test "readWithTimeout returns timeout on idle plain socket" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    try setNonblocking(fds[0]);

    var socket = Socket.Plain.init_client(fds[0]);
    var out: [8]u8 = undefined;
    const outcome = try readWithTimeout(&socket, evented.io(), &out, time.millisToNanos(20));
    try std.testing.expectEqual(ReadOutcome.timeout, outcome);
}

test "readWithTimeout returns bytes on plain socket" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    try setNonblocking(fds[0]);

    const payload = [_]u8{ 0x61, 0x62 };
    try std.testing.expectEqual(@as(usize, payload.len), try testWrite(fds[1], &payload));

    var socket = Socket.Plain.init_client(fds[0]);
    var out: [8]u8 = undefined;
    const outcome = try readWithTimeout(&socket, evented.io(), &out, time.millisToNanos(20));
    switch (outcome) {
        .bytes => |n| try std.testing.expectEqual(@as(u32, payload.len), n),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualSlices(u8, &payload, out[0..payload.len]);
}

test "writeWithTimeout writes bytes on plain socket" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    try setNonblocking(fds[0]);

    var socket = Socket.Plain.init_client(fds[0]);
    const payload = [_]u8{ 0x71, 0x72, 0x73 };
    const outcome = try writeWithTimeout(&socket, evented.io(), &payload, time.millisToNanos(20));
    switch (outcome) {
        .bytes => |n| try std.testing.expectEqual(@as(u32, payload.len), n),
        else => return error.TestUnexpectedResult,
    }

    var out: [3]u8 = undefined;
    try std.testing.expectEqual(@as(usize, payload.len), try posix.read(fds[1], &out));
    try std.testing.expectEqualSlices(u8, &payload, &out);
}

test "writeWithTimeout returns closed when peer is closed" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);

    try setNonblocking(fds[0]);
    posix.close(fds[1]);

    var socket = Socket.Plain.init_client(fds[0]);
    const payload = [_]u8{0x31};
    const outcome = try writeWithTimeout(&socket, evented.io(), &payload, time.millisToNanos(20));
    try std.testing.expectEqual(WriteOutcome.closed, outcome);
}
