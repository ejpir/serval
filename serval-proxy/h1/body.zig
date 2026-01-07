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

const serval_tls = @import("serval-tls");
const TLSStream = serval_tls.TLSStream;

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
/// Supports TLS on either end:
/// - maybe_upstream_tls: When reading from TLS upstream (decrypts)
/// - maybe_client_tls: When writing to TLS client (encrypts)
/// TigerStyle: Explicit TLS handling, no implicit encryption bypass.
pub fn forwardBody(
    maybe_upstream_tls: ?*TLSStream,
    maybe_client_tls: ?*TLSStream,
    upstream_fd: i32,
    client_fd: i32,
    length_bytes: u64,
) ForwardError!u64 {
    assert(upstream_fd >= 0);
    assert(client_fd >= 0);

    // TLS path: any TLS on either end requires userspace copy
    if (maybe_upstream_tls != null or maybe_client_tls != null) {
        const result = try forwardBodyWithTLS(maybe_upstream_tls, maybe_client_tls, upstream_fd, client_fd, length_bytes);
        assert(result <= length_bytes);
        return result;
    }

    // Non-TLS path: use existing zero-copy splice (Linux) or buffered copy
    const result = if (comptime builtin.os.tag == .linux)
        try forwardBodySplice(upstream_fd, client_fd, length_bytes)
    else
        try forwardBodyCopy(upstream_fd, client_fd, length_bytes);

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
// TLS Body Forwarding
// =============================================================================

/// Forward body with optional TLS on read and/or write side.
/// Supports: TLS->plaintext, plaintext->TLS, TLS->TLS, or plaintext->plaintext.
/// TigerStyle: Bounded loop, fixed buffer size, explicit error handling.
fn forwardBodyWithTLS(
    maybe_upstream_tls: ?*TLSStream,
    maybe_client_tls: ?*TLSStream,
    upstream_fd: i32,
    client_fd: i32,
    length_bytes: u64,
) ForwardError!u64 {
    assert(upstream_fd >= 0);
    assert(client_fd >= 0);

    var buffer: [COPY_CHUNK_SIZE_BYTES]u8 = std.mem.zeroes([COPY_CHUNK_SIZE_BYTES]u8);
    var forwarded: u64 = 0;
    const max_iterations: u32 = 1024 * 1024;
    var iterations: u32 = 0;

    while (forwarded < length_bytes and iterations < max_iterations) : (iterations += 1) {
        const remaining = length_bytes - forwarded;
        const to_read: usize = @intCast(@min(remaining, buffer.len));

        // Read from upstream (TLS or plaintext)
        const n: usize = if (maybe_upstream_tls) |tls| blk: {
            const bytes_read = tls.read(buffer[0..to_read]) catch {
                return ForwardError.RecvFailed;
            };
            break :blk bytes_read;
        } else blk: {
            const bytes_read = posix.recv(upstream_fd, buffer[0..to_read], 0) catch {
                return ForwardError.RecvFailed;
            };
            break :blk bytes_read;
        };
        if (n == 0) break; // Clean shutdown or EOF

        // Write to client (TLS or plaintext)
        var sent: usize = 0;
        var send_iterations: u32 = 0;
        const max_send_iterations: u32 = 1024;
        while (sent < n and send_iterations < max_send_iterations) : (send_iterations += 1) {
            if (maybe_client_tls) |tls| {
                const s = tls.write(buffer[sent..n]) catch {
                    return ForwardError.SendFailed;
                };
                if (s == 0) return ForwardError.SendFailed;
                sent += s;
            } else {
                const s = posix.send(client_fd, buffer[sent..n], 0) catch {
                    return ForwardError.SendFailed;
                };
                if (s == 0) return ForwardError.SendFailed;
                sent += s;
            }
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
/// TigerStyle: Uses TLS write if connection encrypted, otherwise zero-copy splice.
/// NOTE: TLS connections cannot use splice (encrypted data), must use userspace copy.
pub fn streamRequestBody(
    client_fd: i32,
    upstream_conn: *Connection,
    io: Io,
    body_info: BodyInfo,
) ForwardError!u64 {
    // Precondition: valid client file descriptor.
    assert(client_fd >= 0);
    assert(upstream_conn.stream.socket.handle >= 0);

    // Dispatch based on body framing mode.
    const result = switch (body_info.framing) {
        .none => 0, // No body to stream (GET, HEAD, etc.)
        .content_length => |length| try streamContentLengthBody(
            client_fd,
            upstream_conn,
            io,
            length,
            body_info.bytes_already_read,
            body_info.initial_body,
        ),
        .chunked => try streamChunkedRequestBody(
            client_fd,
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
/// Sends initial_body first, then zero-copy transfers remaining bytes.
/// TigerStyle: Explicit length, bounded transfer.
fn streamContentLengthBody(
    client_fd: i32,
    upstream_conn: *Connection,
    io: Io,
    content_length: u64,
    bytes_already_read: u64,
    initial_body: []const u8,
) ForwardError!u64 {
    // Preconditions: valid fd, bytes_already_read cannot exceed content_length.
    assert(client_fd >= 0);
    assert(bytes_already_read <= content_length);

    var total_sent: u64 = 0;

    // Send already-read body bytes via connection (TLS or plaintext).
    if (initial_body.len > 0) {
        try sendBuffer(upstream_conn, io, initial_body);
        total_sent += initial_body.len;
    }

    // Stream remaining bytes.
    // TLS connections must use userspace copy (no splice for encrypted data).
    // Plaintext connections can use zero-copy splice on Linux.
    const remaining = content_length - bytes_already_read;
    if (remaining > 0) {
        if (upstream_conn.tls != null) {
            // TLS: userspace copy via read/write
            total_sent += try forwardBodyCopy(client_fd, upstream_conn.stream.socket.handle, remaining);
        } else {
            // Plaintext: zero-copy splice (Linux) or userspace copy (other platforms)
            const upstream_fd = upstream_conn.stream.socket.handle;
            if (comptime builtin.os.tag == .linux) {
                total_sent += try forwardBodySplice(client_fd, upstream_fd, remaining);
            } else {
                total_sent += try forwardBodyCopy(client_fd, upstream_fd, remaining);
            }
        }
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
/// continue streaming the rest of the chunked body from the raw client fd.
///
/// TigerStyle: Bounded chunk iteration (in forwardChunkedBody), explicit error handling.
fn streamChunkedRequestBody(
    client_fd: i32,
    upstream_conn: *Connection,
    io: Io,
    initial_body: []const u8,
) ForwardError!u64 {
    // Precondition: valid client file descriptor.
    assert(client_fd >= 0);

    // Derive upstream_fd from stream - single source of truth.
    const upstream_fd = upstream_conn.stream.socket.handle;
    assert(upstream_fd >= 0);

    var total_sent: u64 = 0;

    // Send already-read chunk data via connection (TLS or plaintext).
    // This may contain partial chunk headers/data read during request parsing.
    if (initial_body.len > 0) {
        try sendBuffer(upstream_conn, io, initial_body);
        total_sent += initial_body.len;
    }

    // Stream remaining chunks from client to upstream.
    // Direction: client_fd (source) -> upstream_fd (destination).
    // Read from plaintext client, write to upstream (TLS or plaintext).
    const maybe_upstream_tls = if (upstream_conn.tls) |*tls| tls else null;
    total_sent += try forwardChunkedBody(null, maybe_upstream_tls, client_fd, upstream_fd);

    // Postcondition: total_sent includes initial_body plus chunked stream bytes.
    // Minimum chunked body is "0\r\n\r\n" (5 bytes) if no initial_body.
    assert(total_sent >= initial_body.len);
    return total_sent;
}
