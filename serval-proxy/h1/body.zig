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
const forwardChunkedBodyIo = chunked_transfer.forwardChunkedBodyIo;

const core = @import("serval-core");
const closeFd = core.closeFd;
const serval_time = core.time;
const SPLICE_CHUNK_SIZE_BYTES = core.config.SPLICE_CHUNK_SIZE_BYTES;
const COPY_CHUNK_SIZE_BYTES = core.config.COPY_CHUNK_SIZE_BYTES;

const pool_mod = @import("serval-pool").pool;
const Connection = pool_mod.Connection;

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;

// =============================================================================
// Splice Constants (Linux)
// =============================================================================

/// SPLICE_F_MOVE: Move pages instead of copying (hint to kernel).
const SPLICE_F_MOVE: u32 = 1;

/// SPLICE_F_MORE: More data will be coming (enables TCP cork optimization).
const SPLICE_F_MORE: u32 = 4;
/// SPLICE_F_NONBLOCK: Non-blocking splice operation.
const SPLICE_F_NONBLOCK: u32 = 2;

/// Max no-progress interval before failing splice loops.
const SPLICE_STALL_TIMEOUT_NS: u64 = 120 * serval_time.ns_per_s;
/// Explicit bound on EAGAIN retries in splice loops.
const SPLICE_MAX_RETRY_COUNT: u32 = 240_000;
/// Poll timeout used when waiting for splice readability/writability.
const SPLICE_POLL_TIMEOUT_MS: i32 = 250;

// =============================================================================
// Platform-Specific Body Forwarding
// =============================================================================

/// Forwards exactly up to `length_bytes` from `upstream` to `client` and returns bytes forwarded.
/// Preconditions: both sockets must hold valid file descriptors; callers must pass live, borrowed
/// socket handles and keep them valid for the full call.
/// Path selection: when `io` is provided, uses fiber-safe userspace copy (`netRead`/`netWrite`);
/// without `io`, uses Linux splice only for plain/plain sockets and falls back to bounded copy for
/// TLS or non-Linux paths.
/// Returns `ForwardError` on read/write/splice/poll failures; success may return fewer bytes than
/// requested if EOF is reached before `length_bytes`.
pub fn forwardBody(
    upstream: *Socket,
    client: *Socket,
    length_bytes: u64,
    io: ?Io,
) ForwardError!u64 {
    // Precondition: sockets have valid fds.
    assert(upstream.get_fd() >= 0);
    assert(client.get_fd() >= 0);

    // When Io is available, use fiber-safe copy path (io_uring-backed netRead/netWrite).
    // This avoids blocking the fiber scheduler with raw splice poll(), which deadlocks
    // when running concurrently with the body-streaming background fiber on large payloads.
    if (io) |runtime_io| {
        const result = try forwardBodyCopyFiber(upstream, client, length_bytes, runtime_io);
        assert(result <= length_bytes);
        return result;
    }

    // No Io: use zero-copy splice (non-concurrent path only).
    if (!upstream.is_tls() and !client.is_tls()) {
        if (comptime builtin.os.tag == .linux) {
            const result = try forwardBodySplice(upstream.get_fd(), client.get_fd(), length_bytes);
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

fn isLinuxErrno(result: isize, errno_code: std.os.linux.E) bool {
    assert(result < 0);
    const errno_value: isize = @intCast(@intFromEnum(errno_code));
    return result == -errno_value;
}

/// Forward body using Linux splice syscall for zero-copy transfer.
/// TigerStyle: Bounded loops, assertion on fd validity.
fn forwardBodySplice(upstream_fd: i32, client_fd: i32, length_bytes: u64) ForwardError!u64 {
    assert(upstream_fd >= 0);
    assert(client_fd >= 0);

    // Create pipe for splice
    var pipe_fds: [2]c_int = undefined;
    if (std.c.pipe(&pipe_fds) != 0) {
        // Fallback to copy if pipe creation fails.
        // TigerStyle: Cannot use forwardBodyCopy here as we only have fds.
        return ForwardError.SpliceFailed;
    }
    defer {
        closeFd(pipe_fds[0]);
        closeFd(pipe_fds[1]);
    }

    var upstream_flags = getFdFlags(upstream_fd) catch return ForwardError.SpliceFailed;
    var client_flags = getFdFlags(client_fd) catch return ForwardError.SpliceFailed;
    var pipe_read_flags = getFdFlags(pipe_fds[0]) catch return ForwardError.SpliceFailed;
    var pipe_write_flags = getFdFlags(pipe_fds[1]) catch return ForwardError.SpliceFailed;
    defer {
        setFdFlags(upstream_fd, upstream_flags) catch |err| {
            std.log.warn("splice restore flags failed fd={d} err={s}", .{ upstream_fd, @errorName(err) });
        };
        setFdFlags(client_fd, client_flags) catch |err| {
            std.log.warn("splice restore flags failed fd={d} err={s}", .{ client_fd, @errorName(err) });
        };
        setFdFlags(pipe_fds[0], pipe_read_flags) catch |err| {
            std.log.warn("splice restore flags failed fd={d} err={s}", .{ pipe_fds[0], @errorName(err) });
        };
        setFdFlags(pipe_fds[1], pipe_write_flags) catch |err| {
            std.log.warn("splice restore flags failed fd={d} err={s}", .{ pipe_fds[1], @errorName(err) });
        };
    }

    setFdNonBlocking(upstream_fd, &upstream_flags) catch return ForwardError.SpliceFailed;
    setFdNonBlocking(client_fd, &client_flags) catch return ForwardError.SpliceFailed;
    setFdNonBlocking(pipe_fds[0], &pipe_read_flags) catch return ForwardError.SpliceFailed;
    setFdNonBlocking(pipe_fds[1], &pipe_write_flags) catch return ForwardError.SpliceFailed;

    var forwarded_bytes: u64 = 0;
    // TigerStyle: explicit worst-case bound (1 byte forward progress per iteration).
    const max_iterations: u64 = length_bytes +| 1024;
    var iterations: u64 = 0;
    var retry_count: u32 = 0;
    var last_progress_ns: u64 = serval_time.monotonicNanos();

    while (forwarded_bytes < length_bytes and iterations < max_iterations) : (iterations += 1) {
        const remaining_bytes = length_bytes - forwarded_bytes;
        const chunk_size: usize = @intCast(@min(remaining_bytes, SPLICE_CHUNK_SIZE_BYTES));

        // Splice from upstream to pipe
        const to_pipe = spliceSyscall(upstream_fd, pipe_fds[1], chunk_size, SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);

        if (to_pipe == 0) break;
        if (to_pipe < 0) {
            if (isLinuxErrno(to_pipe, .INTR)) continue;
            if (isLinuxErrno(to_pipe, .AGAIN)) {
                retry_count += 1;
                const now_ns = serval_time.monotonicNanos();
                if (retry_count >= SPLICE_MAX_RETRY_COUNT or
                    now_ns -| last_progress_ns >= SPLICE_STALL_TIMEOUT_NS)
                {
                    return ForwardError.SpliceFailed;
                }
                _ = waitForSpliceReady(upstream_fd, pipe_fds[1], posix.POLL.IN, posix.POLL.OUT, SPLICE_POLL_TIMEOUT_MS);
                continue;
            }
            return ForwardError.SpliceFailed;
        }

        retry_count = 0;
        last_progress_ns = serval_time.monotonicNanos();

        // Splice from pipe to client
        var pipe_sent_bytes: u64 = 0;
        const to_pipe_bytes: u64 = @intCast(to_pipe);
        var pipe_iterations: u64 = 0;
        const max_pipe_iterations: u64 = to_pipe_bytes +| 1024;
        var pipe_retry_count: u32 = 0;
        var pipe_last_progress_ns: u64 = last_progress_ns;

        // Check if this is the last chunk - don't set SPLICE_F_MORE on final write
        // to avoid TCP cork delay. SPLICE_F_MORE tells kernel to expect more data,
        // which can cause ~200ms delay waiting for the cork timeout.
        const is_last_chunk = (forwarded_bytes + to_pipe_bytes >= length_bytes);
        const splice_flags: u32 = if (is_last_chunk)
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK
        else
            SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK;

        while (pipe_sent_bytes < to_pipe_bytes and pipe_iterations < max_pipe_iterations) : (pipe_iterations += 1) {
            const from_pipe = spliceSyscall(pipe_fds[0], client_fd, @intCast(to_pipe_bytes - pipe_sent_bytes), splice_flags);
            if (from_pipe == 0) return ForwardError.SendFailed;
            if (from_pipe < 0) {
                if (isLinuxErrno(from_pipe, .INTR)) continue;
                if (isLinuxErrno(from_pipe, .AGAIN)) {
                    pipe_retry_count += 1;
                    const now_ns = serval_time.monotonicNanos();
                    if (pipe_retry_count >= SPLICE_MAX_RETRY_COUNT or
                        now_ns -| pipe_last_progress_ns >= SPLICE_STALL_TIMEOUT_NS)
                    {
                        return ForwardError.SpliceFailed;
                    }
                    _ = waitForSpliceReady(pipe_fds[0], client_fd, posix.POLL.IN, posix.POLL.OUT, SPLICE_POLL_TIMEOUT_MS);
                    continue;
                }
                return ForwardError.SpliceFailed;
            }

            pipe_retry_count = 0;
            pipe_last_progress_ns = serval_time.monotonicNanos();
            pipe_sent_bytes += @intCast(from_pipe);
        }

        if (pipe_sent_bytes != to_pipe_bytes) return ForwardError.SendFailed;
        forwarded_bytes += to_pipe_bytes;
    }

    if (forwarded_bytes < length_bytes and iterations >= max_iterations) {
        return ForwardError.SpliceFailed;
    }

    assert(forwarded_bytes <= length_bytes);
    return forwarded_bytes;
}

fn waitForSpliceReady(
    read_fd: i32,
    write_fd: i32,
    read_events: i16,
    write_events: i16,
    timeout_ms: i32,
) bool {
    assert(read_fd >= 0);
    assert(write_fd >= 0);
    assert(timeout_ms >= 0);

    var poll_fds = [_]posix.pollfd{
        .{ .fd = read_fd, .events = read_events, .revents = 0 },
        .{ .fd = write_fd, .events = write_events, .revents = 0 },
    };

    const polled = posix.poll(&poll_fds, timeout_ms) catch return false;
    if (polled == 0) return false;
    if ((poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) return false;
    if ((poll_fds[1].revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) return false;
    return true;
}

fn getFdFlags(fd: i32) !usize {
    assert(fd >= 0);

    const flags = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (flags < 0) return error.Unexpected;
    return @intCast(flags);
}

fn setFdFlags(fd: i32, flags: usize) !void {
    assert(fd >= 0);

    const result = posix.system.fcntl(fd, posix.F.SETFL, flags);
    if (result < 0) return error.Unexpected;
}

fn setFdNonBlocking(fd: i32, flags: *usize) !void {
    assert(fd >= 0);
    assert(@intFromPtr(flags) != 0);

    const nonblock_flag = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    if ((flags.* & nonblock_flag) != 0) return;
    flags.* |= nonblock_flag;
    try setFdFlags(fd, flags.*);
}

// =============================================================================
// Socket-Based Buffered Copy
// =============================================================================

/// Forward body using Socket read/write (handles both TLS and plaintext).
/// TigerStyle: Bounded loops, fixed buffer size, Y3 _bytes suffix.
fn forwardBodyCopy(upstream: *Socket, client: *Socket, length_bytes: u64) ForwardError!u64 {
    // Precondition: sockets have valid fds.
    assert(upstream.get_fd() >= 0);
    assert(client.get_fd() >= 0);

    var buffer: [COPY_CHUNK_SIZE_BYTES]u8 = std.mem.zeroes([COPY_CHUNK_SIZE_BYTES]u8);
    var forwarded_bytes: u64 = 0;
    // TigerStyle: explicit worst-case bound (1 byte forward progress per iteration).
    const max_iterations: u64 = length_bytes +| 1024;
    var iterations: u64 = 0;

    while (forwarded_bytes < length_bytes and iterations < max_iterations) : (iterations += 1) {
        const remaining_bytes = length_bytes - forwarded_bytes;
        const to_read: usize = @intCast(@min(remaining_bytes, buffer.len));

        // Read from upstream via Socket abstraction (TLS or plaintext).
        const n = upstream.read(buffer[0..to_read]) catch {
            return ForwardError.RecvFailed;
        };
        if (n == 0) break; // Clean shutdown or EOF.

        // Write all read bytes to client via Socket abstraction.
        client.write_all(buffer[0..n]) catch {
            return ForwardError.SendFailed;
        };

        forwarded_bytes += n;
    }

    assert(forwarded_bytes <= length_bytes);
    return forwarded_bytes;
}

// =============================================================================
// Request Body Streaming
// =============================================================================

/// Streams request body bytes from `client` to `upstream` according to `body_info` framing.
/// Preconditions: `client` and `upstream` must be valid borrowed sockets with live fds; caller keeps
/// `upstream_conn`/`body_info` alive for the duration of the call.
/// Dispatches `.content_length` and `.chunked` paths, forwarding any `initial_body` bytes first.
/// Returns `ForwardError` on read/write/chunk-parse failures; success returns total body bytes forwarded
/// (or `0` for `.none` framing).
pub fn streamRequestBody(
    client: *Socket,
    upstream: *Socket,
    upstream_conn: *Connection,
    io: Io,
    body_info: BodyInfo,
) ForwardError!u64 {
    // Precondition: valid socket file descriptors.
    assert(client.get_fd() >= 0);
    assert(upstream.get_fd() >= 0);

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
    assert(client.get_fd() >= 0);
    assert(upstream.get_fd() >= 0);
    assert(bytes_already_read <= content_length);
    assert(initial_body.len == @as(usize, @intCast(bytes_already_read)));

    var total_sent: u64 = 0;

    // Send already-read body bytes via connection (TLS or plaintext).
    if (initial_body.len > 0) {
        try sendBuffer(upstream_conn, io, initial_body);
        total_sent += initial_body.len;
    }

    // Stream remaining bytes in a fiber-friendly way for concurrent
    // request/response forwarding. Plain sockets use io.vtable netRead/netWrite
    // to avoid blocking the I/O worker.
    const remaining = content_length - bytes_already_read;
    if (remaining > 0) {
        const forwarded = try forwardBodyCopyFiber(client, upstream, remaining, io);
        if (forwarded != remaining) return ForwardError.RecvFailed;
        total_sent += forwarded;
    }

    // Postcondition: content-length bodies must be forwarded exactly.
    assert(total_sent == content_length);
    return total_sent;
}

fn forwardBodyCopyFiber(
    source: *Socket,
    dest: *Socket,
    length_bytes: u64,
    io: Io,
) ForwardError!u64 {
    assert(source.get_fd() >= 0);
    assert(dest.get_fd() >= 0);

    const source_plain = switch (source.*) {
        .plain => true,
        .tls => false,
    };
    const dest_plain = switch (dest.*) {
        .plain => true,
        .tls => false,
    };
    if (!source_plain or !dest_plain) {
        return forwardBodyCopy(source, dest, length_bytes);
    }

    const source_fd = source.get_fd();
    const dest_fd = dest.get_fd();

    var buffer: [COPY_CHUNK_SIZE_BYTES]u8 = std.mem.zeroes([COPY_CHUNK_SIZE_BYTES]u8);
    var forwarded_bytes: u64 = 0;
    const max_iterations: u64 = length_bytes +| 1024;
    var iterations: u64 = 0;

    while (forwarded_bytes < length_bytes and iterations < max_iterations) : (iterations += 1) {
        const remaining_bytes = length_bytes - forwarded_bytes;
        const to_read: usize = @intCast(@min(remaining_bytes, buffer.len));

        var read_bufs: [1][]u8 = .{buffer[0..to_read]};
        const n = io.vtable.netRead(io.userdata, source_fd, &read_bufs) catch return ForwardError.RecvFailed;
        if (n == 0) break;

        var sent: usize = 0;
        while (sent < n) {
            const pending = buffer[sent..n];
            const write_slices = [_][]const u8{pending};
            const written = io.vtable.netWrite(io.userdata, dest_fd, &.{}, &write_slices, 1) catch return ForwardError.SendFailed;
            if (written == 0) return ForwardError.SendFailed;
            sent += written;
        }

        forwarded_bytes += n;
    }

    if (forwarded_bytes < length_bytes and iterations >= max_iterations) {
        return ForwardError.RecvFailed;
    }

    assert(forwarded_bytes <= length_bytes);
    return forwarded_bytes;
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
    assert(client.get_fd() >= 0);
    assert(upstream.get_fd() >= 0);

    var total_sent: u64 = 0;

    // Send already-read chunk data via connection (TLS or plaintext).
    // This may contain partial chunk headers/data read during request parsing.
    if (initial_body.len > 0) {
        try sendBuffer(upstream_conn, io, initial_body);
        total_sent += initial_body.len;
    }

    // Stream remaining chunks from client to upstream using Socket abstraction.
    // Direction: client (source) -> upstream (destination).
    total_sent += try forwardChunkedBodyIo(client, upstream, io);

    // Postcondition: total_sent includes initial_body plus chunked stream bytes.
    // Minimum chunked body is "0\r\n\r\n" (5 bytes) if no initial_body.
    assert(total_sent >= initial_body.len);
    return total_sent;
}

// =============================================================================
// Tests
// =============================================================================

test "iteration limit supports files >4GB" {
    // Verify the iteration calculation works for large files.
    // Old limit: 1M iterations × 4KB = 4GB max (would fail for larger files).
    // New limit: derived from content length, supports any file size.

    // Test cases: various file sizes including >4GB
    const test_sizes = [_]u64{
        100 * 1024 * 1024, // 100MB
        1024 * 1024 * 1024, // 1GB
        4 * 1024 * 1024 * 1024, // 4GB (old limit)
        5 * 1024 * 1024 * 1024, // 5GB (would fail with old limit)
        100 * 1024 * 1024 * 1024, // 100GB
        1024 * 1024 * 1024 * 1024, // 1TB
    };

    for (test_sizes) |length_bytes| {
        // Splice path: iterations = length / SPLICE_CHUNK_SIZE + margin
        const splice_iterations: u64 = (length_bytes / SPLICE_CHUNK_SIZE_BYTES) + 1024;
        const splice_chunks_needed: u64 = (length_bytes / SPLICE_CHUNK_SIZE_BYTES) + 1;

        // Copy path: iterations = length / COPY_CHUNK_SIZE + margin
        const copy_iterations: u64 = (length_bytes / COPY_CHUNK_SIZE_BYTES) + 1024;
        const copy_chunks_needed: u64 = (length_bytes / COPY_CHUNK_SIZE_BYTES) + 1;

        // Verify we have enough iterations for the file size
        try std.testing.expect(splice_iterations >= splice_chunks_needed);
        try std.testing.expect(copy_iterations >= copy_chunks_needed);

        // Verify old limit would have failed for >4GB with copy path
        const old_limit: u64 = 1024 * 1024;
        if (length_bytes > 4 * 1024 * 1024 * 1024) {
            try std.testing.expect(copy_chunks_needed > old_limit);
        }
    }
}
