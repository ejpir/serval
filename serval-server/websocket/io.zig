//! Native WebSocket Connection I/O
//!
//! Adapts accepted plain/TLS connections to the WebSocketSession transport API.
//! TigerStyle: Explicit TLS/plain dispatch, bounded write loops, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;

const serval_core = @import("serval-core");
const log = serval_core.log.scoped(.server_websocket);

const serval_tls = @import("serval-tls");
const TLSStream = serval_tls.TLSStream;
const ssl = serval_tls.ssl;

const session = @import("session.zig");
const Transport = session.Transport;
const TransportError = session.TransportError;

pub const max_write_iterations_count: u32 = 1024;

pub const ConnectionTransportContext = struct {
    fd: i32,
    maybe_tls: ?*TLSStream,
    connection_id: u64,
};

pub fn initConnectionTransport(ctx: *ConnectionTransportContext) Transport {
    assert(ctx.fd >= 0);

    return .{
        .ctx = @ptrCast(ctx),
        .read_fn = &read,
        .write_all_fn = &writeAll,
        .get_fd_fn = &getFd,
        .has_pending_read_fn = &hasPendingRead,
    };
}

fn read(ctx_ptr: *anyopaque, buf: []u8) TransportError!u32 {
    assert(buf.len > 0);

    const ctx: *ConnectionTransportContext = @ptrCast(@alignCast(ctx_ptr));
    assert(ctx.fd >= 0);

    if (ctx.maybe_tls) |tls| {
        var mutable_tls = tls.*;
        return mutable_tls.read(buf) catch |err| {
            log.debug("websocket read TLS error conn={d}: {s}", .{ ctx.connection_id, @errorName(err) });
            return mapTlsReadError(err);
        };
    }

    const n = posix.read(ctx.fd, buf) catch |err| {
        log.debug("websocket read fd error conn={d}: {s}", .{ ctx.connection_id, @errorName(err) });
        return mapPosixReadError(err);
    };
    return @intCast(n);
}

fn writeAll(ctx_ptr: *anyopaque, data: []const u8) TransportError!void {
    assert(data.len > 0);
    assert(data.len <= std.math.maxInt(u32));

    const ctx: *ConnectionTransportContext = @ptrCast(@alignCast(ctx_ptr));
    assert(ctx.fd >= 0);

    if (ctx.maybe_tls) |tls| {
        var mutable_tls = tls.*;
        return writeAllTls(&mutable_tls, data, ctx.connection_id);
    }

    return writeAllPlain(ctx.fd, data, ctx.connection_id);
}

fn getFd(ctx_ptr: *anyopaque) i32 {
    const ctx: *ConnectionTransportContext = @ptrCast(@alignCast(ctx_ptr));
    return ctx.fd;
}

fn hasPendingRead(ctx_ptr: *anyopaque) bool {
    const ctx: *ConnectionTransportContext = @ptrCast(@alignCast(ctx_ptr));
    assert(ctx.fd >= 0);

    if (ctx.maybe_tls) |tls| {
        return switch (tls.mode) {
            .ktls => false,
            .userspace => |ssl_conn| blk: {
                const pending = ssl.SSL_pending(ssl_conn);
                assert(pending >= 0);
                break :blk pending > 0;
            },
        };
    }

    return false;
}

fn writeAllTls(tls: *TLSStream, data: []const u8, connection_id: u64) TransportError!void {
    assert(data.len > 0);
    assert(data.len <= std.math.maxInt(u32));

    const total_len: u32 = @intCast(data.len);
    var sent: u32 = 0;
    var iterations: u32 = 0;

    while (sent < total_len and iterations < max_write_iterations_count) : (iterations += 1) {
        const offset: usize = @intCast(sent);
        const n = tls.write(data[offset..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => {
                log.debug("websocket TLS write error conn={d}: {s}", .{ connection_id, @errorName(err) });
                return mapTlsWriteError(err);
            },
        };
        if (n == 0) return error.ConnectionClosed;
        sent += n;
    }

    if (sent < total_len) return error.WriteFailed;
}

fn writeAllPlain(fd: i32, data: []const u8, connection_id: u64) TransportError!void {
    assert(fd >= 0);
    assert(data.len > 0);
    assert(data.len <= std.math.maxInt(u32));

    const total_len: u32 = @intCast(data.len);
    var sent: u32 = 0;
    var iterations: u32 = 0;

    while (sent < total_len and iterations < max_write_iterations_count) : (iterations += 1) {
        const offset: usize = @intCast(sent);
        const file: std.Io.File = .{
            .handle = fd,
            .flags = .{ .nonblocking = true },
        };
        const n = file.writeStreaming(std.Options.debug_io, &.{}, &.{data[offset..]}, 1) catch |err| {
            log.debug("websocket plain write error conn={d}: {s}", .{ connection_id, @errorName(err) });
            return mapPlainWriteError(err);
        };
        if (n == 0) return error.ConnectionClosed;
        sent += @intCast(n);
    }

    if (sent < total_len) return error.WriteFailed;
}

fn mapTlsReadError(err: anyerror) TransportError {
    return switch (err) {
        error.ConnectionReset => error.ConnectionReset,
        error.SslRead,
        error.KtlsRead,
        => error.ReadFailed,
        else => error.Unexpected,
    };
}

fn mapTlsWriteError(err: anyerror) TransportError {
    return switch (err) {
        error.ConnectionReset => error.ConnectionReset,
        error.SslWrite,
        error.KtlsWrite,
        => error.WriteFailed,
        else => error.Unexpected,
    };
}

fn mapPosixReadError(err: anyerror) TransportError {
    return switch (err) {
        error.ConnectionResetByPeer => error.ConnectionReset,
        else => error.ReadFailed,
    };
}

fn mapPlainWriteError(err: anyerror) TransportError {
    return switch (err) {
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        => error.ConnectionReset,
        else => error.WriteFailed,
    };
}

test "initConnectionTransport exposes valid fd and pending-read check" {
    var ctx = ConnectionTransportContext{
        .fd = 42,
        .maybe_tls = null,
        .connection_id = 7,
    };

    const transport = initConnectionTransport(&ctx);
    try std.testing.expectEqual(@as(i32, 42), transport.getFd());
    try std.testing.expect(!transport.hasPendingRead());
}
