// lib/serval-proxy/h1/body.zig
//! Body Transfer
//!
//! Zero-copy body streaming using splice (Linux) or buffered copy.
//! Supports both Content-Length and chunked transfer encoding.
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

const chunked_transfer = @import("chunked.zig");
const forwardChunkedBody = chunked_transfer.forwardChunkedBody;

const core = @import("serval-core");
const SPLICE_CHUNK_SIZE_BYTES = core.config.SPLICE_CHUNK_SIZE_BYTES;
const COPY_CHUNK_SIZE_BYTES = core.config.COPY_CHUNK_SIZE_BYTES;

const pool_mod = @import("serval-pool").pool;
const Connection = pool_mod.Connection;

const net = @import("serval-net");
const Socket = net.Socket;

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
/// Uses Socket abstraction for unified TLS/plaintext handling.
/// TigerStyle: Explicit TLS check via isTLS(), splice only for both plain.
pub fn forwardBody(
    upstream: *Socket,
    client: *Socket,
    length_bytes: u64,
) ForwardError!u64 {
    // Precondition: sockets have valid fds.
    assert(upstream.getFd() >= 0);
    assert(client.getFd() >= 0);

    // Zero-copy splice only if BOTH sockets are plain (no TLS).
    // TigerStyle: Explicit check, splice cannot work with encrypted data.
    if (!upstream.isTLS() and !client.isTLS()) {
        if (comptime builtin.os.tag == .linux) {
            const result = try forwardBodySplice(upstream.getFd(), client.getFd(), length_bytes);
            // Postcondition: forwarded at most requested bytes (may be less on EOF/error).
            assert(result <= length_bytes);
            return result;
        }
    }

    // Userspace copy for any TLS involvement or non-Linux platforms.
    const result = try forwardBodyCopy(upstream, client, length_bytes);

    // Postcondition: forwarded at most requested bytes (may be less on EOF/error).
    assert(result <= length_bytes);
    return result;
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
        // Fallback to copy if pipe creation fails.
        // TigerStyle: Cannot use forwardBodyCopy here as we only have fds.
        return ForwardError.SpliceFailed;
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
// Socket-Based Buffered Copy
// =============================================================================

/// Forward body using Socket read/write (handles both TLS and plaintext).
/// TigerStyle: Bounded loops, fixed buffer size.
fn forwardBodyCopy(upstream: *Socket, client: *Socket, length_bytes: u64) ForwardError!u64 {
    // Precondition: sockets have valid fds.
    assert(upstream.getFd() >= 0);
    assert(client.getFd() >= 0);

    var buffer: [COPY_CHUNK_SIZE_BYTES]u8 = std.mem.zeroes([COPY_CHUNK_SIZE_BYTES]u8);
    var forwarded: u64 = 0;
    const max_iterations: u32 = 1024 * 1024;
    var iterations: u32 = 0;

    while (forwarded < length_bytes and iterations < max_iterations) : (iterations += 1) {
        const remaining = length_bytes - forwarded;
        const to_read: usize = @intCast(@min(remaining, buffer.len));

        // Read from upstream via Socket abstraction (TLS or plaintext).
        const n = upstream.read(buffer[0..to_read]) catch {
            return ForwardError.RecvFailed;
        };
        if (n == 0) break; // Clean shutdown or EOF.

        // Write all read bytes to client via Socket abstraction.
        var sent: usize = 0;
        var send_iterations: u32 = 0;
        const max_send_iterations: u32 = 1024;
        while (sent < n and send_iterations < max_send_iterations) : (send_iterations += 1) {
            const s = client.write(buffer[sent..n]) catch {
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
/// Supports Content-Length bodies (known size) and chunked transfer encoding.
/// Sends already-read bytes first, then streams remaining from client.
/// TigerStyle: Uses Socket for unified TLS/plaintext handling.
pub fn streamRequestBody(
    client: *Socket,
    upstream: *Socket,
    upstream_conn: *Connection,
    io: Io,
    body_info: BodyInfo,
) ForwardError!u64 {
    // Precondition: valid socket file descriptors.
    assert(client.getFd() >= 0);
    assert(upstream.getFd() >= 0);

    // Dispatch based on body framing mode.
    const result = switch (body_info.framing) {
        .none => 0, // No body to stream (GET, HEAD, etc.)
        .content_length => |length| try streamContentLengthBody(
            client,
            upstream,
            upstream_conn,
            io,
            length,
            body_info.bytes_already_read,
            body_info.initial_body,
        ),
        .chunked => try streamChunkedRequestBody(
            client,
            upstream,
            upstream_conn,
            io,
            body_info.initial_body,
        ),
    };

    // Postcondition: returned bytes is non-negative (always true for u64).
    // For content_length, result <= length; for chunked, result >= 5 (min "0\r\n\r\n").
    return result;
}

/// Stream Content-Length body from client to upstream.
/// Sends initial_body first, then transfers remaining bytes via Socket.
/// TigerStyle: Explicit length, bounded transfer.
fn streamContentLengthBody(
    client: *Socket,
    upstream: *Socket,
    upstream_conn: *Connection,
    io: Io,
    content_length: u64,
    bytes_already_read: u64,
    initial_body: []const u8,
) ForwardError!u64 {
    // Preconditions: valid sockets, bytes_already_read cannot exceed content_length.
    assert(client.getFd() >= 0);
    assert(upstream.getFd() >= 0);
    assert(bytes_already_read <= content_length);

    var total_sent: u64 = 0;

    // Send already-read body bytes via connection (TLS or plaintext).
    if (initial_body.len > 0) {
        try sendBuffer(upstream_conn, io, initial_body);
        total_sent += initial_body.len;
    }

    // Stream remaining bytes using Socket abstraction.
    const remaining = content_length - bytes_already_read;
    if (remaining > 0) {
        // Forward using Socket abstraction (handles TLS transparently).
        total_sent += try forwardBodyCopy(client, upstream, remaining);
    }

    // Postcondition: sent at most content_length bytes.
    // May be less if upstream closed early, client disconnected, or network error.
    assert(total_sent <= content_length);
    return total_sent;
}

/// Stream chunked request body from client to upstream.
/// Sends initial_body first (may contain partial chunk data), then streams
/// remaining chunks using forwardChunkedBody.
///
/// Design note: For chunked bodies, initial_body may contain partial chunk framing
/// read during header parsing. We send this first via the async stream, then
/// continue streaming the rest of the chunked body from the client socket.
///
/// TigerStyle: Bounded chunk iteration (in forwardChunkedBody), explicit error handling.
fn streamChunkedRequestBody(
    client: *Socket,
    upstream: *Socket,
    upstream_conn: *Connection,
    io: Io,
    initial_body: []const u8,
) ForwardError!u64 {
    // Precondition: valid socket file descriptors.
    assert(client.getFd() >= 0);
    assert(upstream.getFd() >= 0);

    var total_sent: u64 = 0;

    // Send already-read chunk data via connection (TLS or plaintext).
    // This may contain partial chunk headers/data read during request parsing.
    if (initial_body.len > 0) {
        try sendBuffer(upstream_conn, io, initial_body);
        total_sent += initial_body.len;
    }

    // Stream remaining chunks from client to upstream using Socket abstraction.
    // Direction: client (source) -> upstream (destination).
    total_sent += try forwardChunkedBody(client, upstream);

    // Postcondition: total_sent includes initial_body plus chunked stream bytes.
    // Minimum chunked body is "0\r\n\r\n" (5 bytes) if no initial_body.
    assert(total_sent >= initial_body.len);
    return total_sent;
}
