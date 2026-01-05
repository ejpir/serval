// lib/serval-proxy/h1/body.zig
//! Body Transfer
//!
//! Zero-copy body streaming using splice (Linux) or buffered copy.
//! TigerStyle: Platform selection at comptime, bounded loops.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;

const proxy_types = @import("../types.zig");
const ForwardError = proxy_types.ForwardError;
const BodyInfo = proxy_types.BodyInfo;

const request_mod = @import("request.zig");
const sendBuffer = request_mod.sendBuffer;

const core = @import("serval-core");
const SPLICE_CHUNK_SIZE_BYTES = core.config.SPLICE_CHUNK_SIZE_BYTES;
const COPY_CHUNK_SIZE_BYTES = core.config.COPY_CHUNK_SIZE_BYTES;

// =============================================================================
// Splice Constants (Linux)
// =============================================================================

/// SPLICE_F_MOVE: Move pages instead of copying (hint to kernel).
const SPLICE_F_MOVE: u32 = 1;

/// SPLICE_F_MORE: More data will be coming (enables TCP cork optimization).
const SPLICE_F_MORE: u32 = 4;

// =============================================================================
// Platform-Specific Body Forwarding
// =============================================================================

/// Forward response body using zero-copy splice (Linux) or buffered copy.
/// TigerStyle: Uses raw fds for splice syscall.
pub fn forwardBody(
    upstream_fd: i32,
    client_fd: i32,
    length_bytes: u64,
) ForwardError!u64 {
    assert(upstream_fd >= 0);
    assert(client_fd >= 0);

    // Comptime select: Linux uses splice, others use buffered copy
    if (comptime builtin.os.tag == .linux) {
        return forwardBodySplice(upstream_fd, client_fd, length_bytes);
    } else {
        return forwardBodyCopy(upstream_fd, client_fd, length_bytes);
    }
}

// =============================================================================
// Linux Zero-Copy via Splice
// =============================================================================

/// Raw splice syscall - transfers data between fds without userspace copy.
/// Uses direct syscall because std.os.linux.splice was removed in Zig 0.16.
fn spliceSyscall(fd_in: i32, fd_out: i32, len: usize, flags: u32) isize {
    assert(fd_in >= 0);
    assert(fd_out >= 0);

    const linux = std.os.linux;
    return @bitCast(linux.syscall6(
        .splice,
        @as(usize, @bitCast(@as(isize, fd_in))),
        0, // off_in = null
        @as(usize, @bitCast(@as(isize, fd_out))),
        0, // off_out = null
        len,
        flags,
    ));
}

/// Forward body using Linux splice syscall for zero-copy transfer.
/// TigerStyle: Bounded loops, assertion on fd validity.
fn forwardBodySplice(upstream_fd: i32, client_fd: i32, length_bytes: u64) ForwardError!u64 {
    assert(upstream_fd >= 0);
    assert(client_fd >= 0);

    // Create pipe for splice
    const pipe_fds = posix.pipe() catch {
        return forwardBodyCopy(upstream_fd, client_fd, length_bytes);
    };
    defer {
        posix.close(pipe_fds[0]);
        posix.close(pipe_fds[1]);
    }

    var forwarded: u64 = 0;
    const max_iterations: u32 = 1024 * 1024;
    var iterations: u32 = 0;

    while (forwarded < length_bytes and iterations < max_iterations) : (iterations += 1) {
        const remaining = length_bytes - forwarded;
        const chunk_size: usize = @intCast(@min(remaining, SPLICE_CHUNK_SIZE_BYTES));

        // Splice from upstream to pipe
        const to_pipe = spliceSyscall(upstream_fd, pipe_fds[1], chunk_size, SPLICE_F_MOVE | SPLICE_F_MORE);

        if (to_pipe == 0) break;
        if (to_pipe < 0) return ForwardError.SpliceFailed;

        // Splice from pipe to client
        var pipe_sent: u64 = 0;
        var pipe_iterations: u32 = 0;
        const max_pipe_iterations: u32 = 1024;
        const to_pipe_u64: u64 = @intCast(to_pipe);
        while (pipe_sent < to_pipe_u64 and pipe_iterations < max_pipe_iterations) : (pipe_iterations += 1) {
            const from_pipe = spliceSyscall(pipe_fds[0], client_fd, @intCast(to_pipe_u64 - pipe_sent), SPLICE_F_MOVE | SPLICE_F_MORE);
            if (from_pipe == 0) return ForwardError.SendFailed;
            if (from_pipe < 0) return ForwardError.SpliceFailed;
            pipe_sent += @intCast(from_pipe);
        }

        forwarded += to_pipe_u64;
    }

    assert(forwarded <= length_bytes);
    return forwarded;
}

// =============================================================================
// Portable Buffered Copy Fallback
// =============================================================================

/// Forward body using buffered copy (portable fallback for non-Linux).
/// TigerStyle: Bounded loops, fixed buffer size.
fn forwardBodyCopy(upstream_fd: i32, client_fd: i32, length_bytes: u64) ForwardError!u64 {
    assert(upstream_fd >= 0);
    assert(client_fd >= 0);

    var buffer: [COPY_CHUNK_SIZE_BYTES]u8 = std.mem.zeroes([COPY_CHUNK_SIZE_BYTES]u8);
    var forwarded: u64 = 0;
    const max_iterations: u32 = 1024 * 1024;
    var iterations: u32 = 0;

    while (forwarded < length_bytes and iterations < max_iterations) : (iterations += 1) {
        const remaining = length_bytes - forwarded;
        const to_read: usize = @intCast(@min(remaining, buffer.len));

        const n = posix.recv(upstream_fd, buffer[0..to_read], 0) catch {
            return ForwardError.RecvFailed;
        };
        if (n == 0) break;

        var sent: usize = 0;
        var send_iterations: u32 = 0;
        const max_send_iterations: u32 = 1024;
        while (sent < n and send_iterations < max_send_iterations) : (send_iterations += 1) {
            const s = posix.send(client_fd, buffer[sent..n], 0) catch {
                return ForwardError.SendFailed;
            };
            if (s == 0) return ForwardError.SendFailed;
            sent += s;
        }

        forwarded += n;
    }

    assert(forwarded <= length_bytes);
    return forwarded;
}

// =============================================================================
// Request Body Streaming
// =============================================================================

/// Stream request body from client to upstream.
/// Sends already-read bytes first, then splices/copies remaining.
/// TigerStyle: Uses stream for initial bytes, raw fds for splice zero-copy.
pub fn streamRequestBody(
    client_fd: i32,
    upstream_stream: Io.net.Stream,
    io: Io,
    body_info: BodyInfo,
) ForwardError!u64 {
    assert(client_fd >= 0);

    const content_length = body_info.content_length orelse return 0;
    assert(body_info.bytes_already_read <= content_length);

    var total_sent: u64 = 0;

    // Send already-read body bytes via async stream
    if (body_info.initial_body.len > 0) {
        try sendBuffer(upstream_stream, io, body_info.initial_body);
        total_sent += body_info.initial_body.len;
    }

    // Stream remaining bytes using splice (extract raw fd for zero-copy)
    const remaining = content_length - body_info.bytes_already_read;
    if (remaining > 0) {
        const upstream_fd = upstream_stream.socket.handle;
        if (comptime builtin.os.tag == .linux) {
            total_sent += try forwardBodySplice(client_fd, upstream_fd, remaining);
        } else {
            total_sent += try forwardBodyCopy(client_fd, upstream_fd, remaining);
        }
    }

    // Postcondition: sent at most content_length bytes.
    // May be less if upstream closed early, client disconnected, or network error.
    assert(total_sent <= content_length);
    return total_sent;
}
