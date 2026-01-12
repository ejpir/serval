// serval-client/body.zig
//! HTTP Response Body Reader
//!
//! Composable HTTP response body reader with multiple consumption patterns:
//! - Buffer: readAll() for JSON APIs, small responses
//! - Stream: readChunk() for large files, incremental processing
//! - Forward: forwardTo() for proxy/gateway with zero-copy splice
//!
//! TigerStyle: Caller-owned buffers, bounded iterations, no allocation after init.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const posix = std.posix;

const serval_core = @import("serval-core");
const config = serval_core.config;
const types = serval_core.types;
const BodyFraming = types.BodyFraming;
const debugLog = serval_core.debugLog;

const serval_net = @import("serval-net");
const Socket = serval_net.Socket;
const SocketError = serval_net.SocketError;

const serval_http = @import("serval-http");
const chunked = serval_http.chunked;
const parseChunkSize = chunked.parseChunkSize;
const isLastChunk = chunked.isLastChunk;
const ChunkParseError = chunked.ChunkParseError;

// =============================================================================
// Constants
// =============================================================================

/// Maximum iterations for body read loops.
/// TigerStyle S4: All loops bounded.
/// Why 1,000,000: Allows reading up to 1TB at 1MB chunks while preventing infinite loops.
pub const MAX_BODY_READ_ITERATIONS: u32 = 1_000_000;

/// Maximum single chunk size for chunked encoding.
/// TigerStyle S7: Bounded to prevent memory exhaustion.
pub const MAX_CHUNK_SIZE_BYTES: u32 = 16 * 1024 * 1024; // 16MB

/// Minimum buffer size for chunked decoding.
/// Must hold chunk size line: hex digits + extensions + CRLF.
/// TigerStyle: Explicit minimum for caller validation.
pub const MIN_CHUNK_BUFFER_SIZE: u32 = 32;

/// Splice flags for zero-copy transfer (Linux).
const SPLICE_F_MOVE: u32 = 1;
const SPLICE_F_MORE: u32 = 4;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during body reading operations.
/// TigerStyle S6: Explicit error set, no catch {}.
pub const BodyError = error{
    /// Socket read operation failed.
    ReadFailed,
    /// Socket write operation failed.
    WriteFailed,
    /// Connection closed before expected body bytes received.
    UnexpectedEof,
    /// Provided buffer too small for body content.
    BufferTooSmall,
    /// Exceeded MAX_BODY_READ_ITERATIONS during read loop.
    IterationLimitExceeded,
    /// Invalid chunked encoding format (bad hex, missing CRLF).
    InvalidChunkedEncoding,
    /// Single chunk exceeds MAX_CHUNK_SIZE_BYTES limit.
    ChunkTooLarge,
    /// Splice syscall failed during zero-copy transfer.
    SpliceFailed,
    /// Pipe creation failed during splice operation.
    PipeCreationFailed,
};

// =============================================================================
// BodyReader
// =============================================================================

/// HTTP response body reader with multiple consumption patterns.
///
/// Provides three ways to consume response bodies:
/// - readAll(): Buffer entire body for JSON parsing, small responses
/// - readChunk(): Stream chunks for large files, memory-constrained processing
/// - forwardTo(): Zero-copy splice for proxy/gateway forwarding
///
/// TigerStyle: Caller-owned buffers, bounded iterations, no allocation after init.
pub const BodyReader = struct {
    /// Source socket to read from.
    socket: *Socket,
    /// Body framing from response headers.
    framing: BodyFraming,
    /// Bytes remaining for content_length, null for chunked/none.
    bytes_remaining: ?u64,
    /// True if body fully consumed (last chunk received or all bytes read).
    done: bool,
    /// Iteration counter for bounded loops (TigerStyle S4).
    iterations: u32,
    /// Buffer for incomplete chunk header data between reads.
    /// Used when chunk size line spans multiple socket reads.
    chunk_header_buf: [64]u8,
    /// Bytes currently in chunk_header_buf.
    chunk_header_len: u8,
    /// Bytes remaining in current chunk (for chunked encoding).
    current_chunk_remaining: u64,
    /// True if we need to skip CRLF after chunk data.
    awaiting_chunk_crlf: bool,

    const Self = @This();

    /// Initialize body reader from socket and framing info.
    ///
    /// Preconditions:
    /// - socket must be valid and connected
    /// - framing must be from parsed response headers
    ///
    /// TigerStyle S1: Precondition assertions.
    pub fn init(socket: *Socket, framing: BodyFraming) Self {
        assert(socket.getFd() >= 0); // S1: socket must be valid

        const bytes_remaining: ?u64 = switch (framing) {
            .content_length => |len| len,
            .chunked, .none => null,
        };

        return Self{
            .socket = socket,
            .framing = framing,
            .bytes_remaining = bytes_remaining,
            .done = switch (framing) {
                .content_length => |len| len == 0,
                .chunked => false,
                .none => true, // No body to read
            },
            .iterations = 0,
            .chunk_header_buf = std.mem.zeroes([64]u8),
            .chunk_header_len = 0,
            .current_chunk_remaining = 0,
            .awaiting_chunk_crlf = false,
        };
    }

    /// Read entire body into caller-owned buffer.
    /// Returns slice of buffer containing body data.
    ///
    /// Preconditions:
    /// - buf must be large enough for expected body
    /// - For content_length: buf.len >= content_length
    /// - For chunked: buf.len >= total decoded size (unknown upfront)
    ///
    /// TigerStyle:
    /// - S1: Precondition assertions
    /// - S3: Bounded loop with MAX_BODY_READ_ITERATIONS
    /// - S6: Explicit error handling
    pub fn readAll(self: *Self, buf: []u8) BodyError![]u8 {
        // S1: Preconditions
        assert(buf.len > 0); // Buffer must have capacity

        if (self.done) return buf[0..0];

        return switch (self.framing) {
            .content_length => self.readAllContentLength(buf),
            .chunked => self.readAllChunked(buf),
            .none => buf[0..0], // No body
        };
    }

    /// Read next chunk into caller-owned buffer.
    /// Returns slice with chunk data, or null when complete.
    ///
    /// For chunked encoding: Returns decoded chunk data (without framing).
    /// For content_length: Returns next read of up to buf.len bytes.
    ///
    /// TigerStyle:
    /// - S1: Precondition assertions
    /// - S3: Bounded iterations
    pub fn readChunk(self: *Self, buf: []u8) BodyError!?[]u8 {
        // S1: Preconditions
        assert(buf.len > 0); // Buffer must have capacity

        if (self.done) return null;

        return switch (self.framing) {
            .content_length => self.readChunkContentLength(buf),
            .chunked => self.readChunkChunked(buf),
            .none => null, // No body
        };
    }

    /// Forward body to destination socket.
    /// Uses splice (zero-copy) when both sockets support it.
    /// Returns total bytes forwarded.
    ///
    /// Preconditions:
    /// - dst must be valid and connected
    /// - scratch must be at least MIN_CHUNK_BUFFER_SIZE for chunked bodies
    ///
    /// TigerStyle:
    /// - S1: Precondition assertions
    /// - S3: Bounded iterations
    /// - P1: Zero-copy splice when possible (network > CPU)
    pub fn forwardTo(self: *Self, dst: *Socket, scratch: []u8) BodyError!u64 {
        // S1: Preconditions
        assert(dst.getFd() >= 0); // Destination socket must be valid
        assert(scratch.len >= MIN_CHUNK_BUFFER_SIZE); // Buffer for chunked framing

        if (self.done) return 0;

        // Check if zero-copy splice is possible
        const can_splice = self.socket.canSplice() and dst.canSplice();

        return switch (self.framing) {
            .content_length => |len| {
                if (can_splice) {
                    return self.forwardContentLengthSplice(dst.getFd(), len);
                } else {
                    return self.forwardContentLengthCopy(dst, scratch, len);
                }
            },
            .chunked => {
                // Chunked always uses copy path (need to parse framing)
                return self.forwardChunkedCopy(dst, scratch);
            },
            .none => 0,
        };
    }

    // =========================================================================
    // Content-Length Body Reading
    // =========================================================================

    /// Read entire content-length body into buffer.
    fn readAllContentLength(self: *Self, buf: []u8) BodyError![]u8 {
        const content_length = self.bytes_remaining orelse return buf[0..0];

        // S1: Buffer must fit entire body
        if (buf.len < content_length) {
            return BodyError.BufferTooSmall;
        }

        var total_read: u64 = 0;

        // S3: Bounded loop
        while (total_read < content_length and self.iterations < MAX_BODY_READ_ITERATIONS) {
            self.iterations += 1;

            const remaining: usize = @intCast(content_length - total_read);
            const n = self.socket.read(buf[total_read..][0..remaining]) catch |err| {
                return mapSocketError(err);
            };

            if (n == 0) {
                // EOF before all bytes received
                return BodyError.UnexpectedEof;
            }

            total_read += n;
        }

        if (self.iterations >= MAX_BODY_READ_ITERATIONS) {
            return BodyError.IterationLimitExceeded;
        }

        // S2: Postconditions
        assert(total_read == content_length);
        self.done = true;
        self.bytes_remaining = 0;

        return buf[0..@intCast(total_read)];
    }

    /// Read next chunk of content-length body.
    fn readChunkContentLength(self: *Self, buf: []u8) BodyError!?[]u8 {
        const remaining = self.bytes_remaining orelse return null;

        if (remaining == 0) {
            self.done = true;
            return null;
        }

        // S3: Iteration bound check
        if (self.iterations >= MAX_BODY_READ_ITERATIONS) {
            return BodyError.IterationLimitExceeded;
        }
        self.iterations += 1;

        const to_read: usize = @intCast(@min(remaining, buf.len));
        const n = self.socket.read(buf[0..to_read]) catch |err| {
            return mapSocketError(err);
        };

        if (n == 0) {
            return BodyError.UnexpectedEof;
        }

        self.bytes_remaining = remaining - n;
        if (self.bytes_remaining.? == 0) {
            self.done = true;
        }

        return buf[0..n];
    }

    // =========================================================================
    // Chunked Body Reading
    // =========================================================================

    /// Read entire chunked body into buffer (decoded).
    fn readAllChunked(self: *Self, buf: []u8) BodyError![]u8 {
        var total_written: usize = 0;

        // S3: Bounded loop
        while (!self.done and self.iterations < MAX_BODY_READ_ITERATIONS) {
            // Read next chunk into remaining buffer space
            const chunk = try self.readChunkChunked(buf[total_written..]) orelse break;
            total_written += chunk.len;
        }

        if (self.iterations >= MAX_BODY_READ_ITERATIONS and !self.done) {
            return BodyError.IterationLimitExceeded;
        }

        return buf[0..total_written];
    }

    /// Read next decoded chunk from chunked encoding.
    fn readChunkChunked(self: *Self, buf: []u8) BodyError!?[]u8 {
        if (self.done) return null;

        // S3: Iteration bound check
        if (self.iterations >= MAX_BODY_READ_ITERATIONS) {
            return BodyError.IterationLimitExceeded;
        }
        self.iterations += 1;

        // If we have remaining data in current chunk, read it
        if (self.current_chunk_remaining > 0) {
            return self.readCurrentChunkData(buf);
        }

        // Skip CRLF after previous chunk data if needed
        if (self.awaiting_chunk_crlf) {
            try self.skipChunkCrlf();
            self.awaiting_chunk_crlf = false;
        }

        // Read next chunk size
        const chunk_size = try self.readChunkSize();

        if (isLastChunk(chunk_size)) {
            // Read trailing CRLF after 0-chunk
            try self.skipChunkCrlf();
            self.done = true;
            return null;
        }

        if (chunk_size > MAX_CHUNK_SIZE_BYTES) {
            return BodyError.ChunkTooLarge;
        }

        self.current_chunk_remaining = chunk_size;
        return self.readCurrentChunkData(buf);
    }

    /// Read data from current chunk.
    fn readCurrentChunkData(self: *Self, buf: []u8) BodyError!?[]u8 {
        if (self.current_chunk_remaining == 0) return null;

        const to_read: usize = @intCast(@min(self.current_chunk_remaining, buf.len));
        var bytes_read: usize = 0;

        // First, consume any buffered data from chunk_header_buf
        // (readChunkSize may have read past the size line into chunk data)
        if (self.chunk_header_len > 0) {
            const from_buf: usize = @min(@as(usize, self.chunk_header_len), to_read);
            @memcpy(buf[0..from_buf], self.chunk_header_buf[0..from_buf]);
            bytes_read = from_buf;

            // Shift remaining data in chunk_header_buf
            const remaining: u8 = self.chunk_header_len - @as(u8, @intCast(from_buf));
            if (remaining > 0) {
                std.mem.copyForwards(
                    u8,
                    self.chunk_header_buf[0..remaining],
                    self.chunk_header_buf[from_buf..self.chunk_header_len],
                );
            }
            self.chunk_header_len = remaining;
        }

        // Read remaining bytes from socket if needed
        if (bytes_read < to_read) {
            const n = self.socket.read(buf[bytes_read..to_read]) catch |err| {
                return mapSocketError(err);
            };

            if (n == 0 and bytes_read == 0) {
                return BodyError.UnexpectedEof;
            }

            bytes_read += n;
        }

        self.current_chunk_remaining -= bytes_read;

        // If chunk fully read, mark that we need to skip CRLF next time
        if (self.current_chunk_remaining == 0) {
            self.awaiting_chunk_crlf = true;
        }

        return buf[0..bytes_read];
    }

    /// Read and parse chunk size line.
    fn readChunkSize(self: *Self) BodyError!u64 {
        // Read bytes until we have a complete chunk size line
        // TigerStyle: Bounded loop with explicit iteration limit
        var iterations: u32 = 0;
        const max_iterations: u32 = 100;

        while (iterations < max_iterations) : (iterations += 1) {
            // Try to parse what we have (need at least 3 bytes: "0\r\n")
            if (self.chunk_header_len >= 3) {
                const header_slice = self.chunk_header_buf[0..self.chunk_header_len];
                if (parseChunkSize(header_slice)) |parse_result| {
                    // Successfully parsed - save unconsumed bytes
                    const consumed = parse_result.consumed;
                    const remaining = self.chunk_header_len - @as(u8, @intCast(consumed));
                    if (remaining > 0) {
                        std.mem.copyForwards(
                            u8,
                            self.chunk_header_buf[0..remaining],
                            self.chunk_header_buf[consumed..self.chunk_header_len],
                        );
                    }
                    self.chunk_header_len = remaining;

                    return parse_result.size;
                } else |err| {
                    // If incomplete and buffer not full, read more
                    if (err == ChunkParseError.IncompleteChunk) {
                        if (self.chunk_header_len >= self.chunk_header_buf.len) {
                            // Buffer full but chunk incomplete - protocol error
                            debugLog("chunked: buffer full, incomplete chunk", .{});
                            return BodyError.InvalidChunkedEncoding;
                        }
                        // Fall through to read more data below
                    } else {
                        // Debug: log the invalid chunk header bytes
                        debugLog("chunked: parse error {s}, header_len={d}, bytes={any}", .{
                            @errorName(err),
                            self.chunk_header_len,
                            header_slice[0..@min(header_slice.len, 32)],
                        });
                        return BodyError.InvalidChunkedEncoding;
                    }
                }
            }

            // Check if buffer has space for more data
            if (self.chunk_header_len >= self.chunk_header_buf.len) {
                debugLog("chunked: buffer full before valid parse, bytes={any}", .{
                    self.chunk_header_buf[0..@min(self.chunk_header_buf.len, 32)],
                });
                return BodyError.InvalidChunkedEncoding;
            }

            // Read more data
            const n = self.socket.read(self.chunk_header_buf[self.chunk_header_len..]) catch |err| {
                debugLog("chunked: socket read error: {s}", .{@errorName(err)});
                return mapSocketError(err);
            };
            if (n == 0) return BodyError.UnexpectedEof;
            self.chunk_header_len += @intCast(n);
        }

        // Exceeded iteration limit
        return BodyError.IterationLimitExceeded;
    }

    /// Skip CRLF after chunk data.
    fn skipChunkCrlf(self: *Self) BodyError!void {
        var crlf_buf: [2]u8 = undefined;
        var read_count: usize = 0;

        // May have CRLF bytes already in chunk_header_buf
        if (self.chunk_header_len >= 2) {
            if (self.chunk_header_buf[0] == '\r' and self.chunk_header_buf[1] == '\n') {
                // Consume from buffer
                const remaining = self.chunk_header_len - 2;
                if (remaining > 0) {
                    std.mem.copyForwards(
                        u8,
                        self.chunk_header_buf[0..remaining],
                        self.chunk_header_buf[2..self.chunk_header_len],
                    );
                }
                self.chunk_header_len = remaining;
                return;
            }
        }

        // Read CRLF from socket
        while (read_count < 2) {
            const n = self.socket.read(crlf_buf[read_count..]) catch |err| {
                return mapSocketError(err);
            };
            if (n == 0) return BodyError.UnexpectedEof;
            read_count += n;
        }

        if (crlf_buf[0] != '\r' or crlf_buf[1] != '\n') {
            return BodyError.InvalidChunkedEncoding;
        }
    }

    // =========================================================================
    // Forwarding (Zero-Copy and Copy Paths)
    // =========================================================================

    /// Forward content-length body using splice (zero-copy).
    fn forwardContentLengthSplice(self: *Self, dst_fd: i32, length: u64) BodyError!u64 {
        if (comptime builtin.os.tag != .linux) {
            // Splice only on Linux - shouldn't reach here due to canSplice check
            return BodyError.SpliceFailed;
        }

        // Create pipe for splice
        const pipe_fds = posix.pipe() catch {
            return BodyError.PipeCreationFailed;
        };
        defer {
            posix.close(pipe_fds[0]);
            posix.close(pipe_fds[1]);
        }

        const src_fd = self.socket.getFd();
        var forwarded: u64 = 0;

        // S3: Bounded loop
        while (forwarded < length and self.iterations < MAX_BODY_READ_ITERATIONS) {
            self.iterations += 1;

            const remaining = length - forwarded;
            const chunk_size: usize = @intCast(@min(remaining, config.SPLICE_CHUNK_SIZE_BYTES));

            // Splice from source to pipe
            const to_pipe = spliceSyscall(src_fd, pipe_fds[1], chunk_size, SPLICE_F_MOVE | SPLICE_F_MORE);
            if (to_pipe == 0) break; // EOF
            if (to_pipe < 0) return BodyError.SpliceFailed;

            // Splice from pipe to destination
            var pipe_sent: u64 = 0;
            const to_pipe_bytes: u64 = @intCast(to_pipe);
            const is_last = (forwarded + to_pipe_bytes >= length);
            const flags: u32 = if (is_last) SPLICE_F_MOVE else SPLICE_F_MOVE | SPLICE_F_MORE;

            var pipe_iterations: u32 = 0;
            while (pipe_sent < to_pipe_bytes and pipe_iterations < 1024) {
                pipe_iterations += 1;
                const from_pipe = spliceSyscall(pipe_fds[0], dst_fd, @intCast(to_pipe_bytes - pipe_sent), flags);
                if (from_pipe == 0) return BodyError.WriteFailed;
                if (from_pipe < 0) return BodyError.SpliceFailed;
                pipe_sent += @intCast(from_pipe);
            }

            forwarded += to_pipe_bytes;
        }

        if (self.iterations >= MAX_BODY_READ_ITERATIONS and forwarded < length) {
            return BodyError.IterationLimitExceeded;
        }

        self.done = true;
        self.bytes_remaining = 0;

        // S2: Postcondition
        assert(forwarded <= length);
        return forwarded;
    }

    /// Forward content-length body using userspace copy.
    fn forwardContentLengthCopy(self: *Self, dst: *Socket, scratch: []u8, length: u64) BodyError!u64 {
        var forwarded: u64 = 0;

        // S3: Bounded loop
        while (forwarded < length and self.iterations < MAX_BODY_READ_ITERATIONS) {
            self.iterations += 1;

            const remaining: usize = @intCast(length - forwarded);
            const to_read = @min(remaining, scratch.len);

            const n = self.socket.read(scratch[0..to_read]) catch |err| {
                return mapSocketError(err);
            };
            if (n == 0) break; // EOF

            dst.writeAll(scratch[0..n]) catch {
                return BodyError.WriteFailed;
            };

            forwarded += n;
        }

        if (self.iterations >= MAX_BODY_READ_ITERATIONS and forwarded < length) {
            return BodyError.IterationLimitExceeded;
        }

        self.done = true;
        self.bytes_remaining = 0;

        assert(forwarded <= length);
        return forwarded;
    }

    /// Forward chunked body (always uses copy - need to parse framing).
    fn forwardChunkedCopy(self: *Self, dst: *Socket, scratch: []u8) BodyError!u64 {
        var forwarded: u64 = 0;

        // S3: Bounded loop
        while (!self.done and self.iterations < MAX_BODY_READ_ITERATIONS) {
            // Read decoded chunk data
            const chunk = try self.readChunkChunked(scratch) orelse break;

            // Forward to destination
            dst.writeAll(chunk) catch {
                return BodyError.WriteFailed;
            };

            forwarded += chunk.len;
        }

        if (self.iterations >= MAX_BODY_READ_ITERATIONS and !self.done) {
            return BodyError.IterationLimitExceeded;
        }

        return forwarded;
    }
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Map SocketError to BodyError.
/// TigerStyle S6: Explicit error handling.
fn mapSocketError(err: SocketError) BodyError {
    return switch (err) {
        SocketError.ConnectionReset => BodyError.UnexpectedEof,
        SocketError.ConnectionClosed => BodyError.UnexpectedEof,
        SocketError.BrokenPipe => BodyError.WriteFailed,
        SocketError.Timeout => BodyError.ReadFailed,
        SocketError.TLSError => BodyError.ReadFailed,
        SocketError.Unexpected => BodyError.ReadFailed,
    };
}

/// Raw splice syscall (Linux only).
fn spliceSyscall(fd_in: i32, fd_out: i32, len: usize, flags: u32) isize {
    if (comptime builtin.os.tag != .linux) {
        return -1;
    }

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

// =============================================================================
// Tests
// =============================================================================

test "BodyReader.init content_length" {
    // Create a mock socket for testing
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .{ .content_length = 100 });

    try std.testing.expect(!reader.done);
    try std.testing.expectEqual(@as(?u64, 100), reader.bytes_remaining);
    try std.testing.expectEqual(@as(u32, 0), reader.iterations);
}

test "BodyReader.init content_length zero" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .{ .content_length = 0 });

    // Zero content-length means body already done
    try std.testing.expect(reader.done);
    try std.testing.expectEqual(@as(?u64, 0), reader.bytes_remaining);
}

test "BodyReader.init chunked" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .chunked);

    try std.testing.expect(!reader.done);
    try std.testing.expect(reader.bytes_remaining == null);
}

test "BodyReader.init none" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .none);

    // No body means already done
    try std.testing.expect(reader.done);
}

test "BodyReader.readAll content_length" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    // Write test data to one end
    const body = "Hello, World!";
    _ = posix.write(fds[1], body) catch return;

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .{ .content_length = body.len });

    var buf: [64]u8 = undefined;
    const result = try reader.readAll(&buf);

    try std.testing.expectEqualStrings(body, result);
    try std.testing.expect(reader.done);
}

test "BodyReader.readAll content_length buffer too small" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .{ .content_length = 100 });

    var buf: [10]u8 = undefined; // Too small for 100 bytes
    const result = reader.readAll(&buf);

    try std.testing.expectError(BodyError.BufferTooSmall, result);
}

test "BodyReader.readChunk content_length" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    const body = "Hello, World!";
    _ = posix.write(fds[1], body) catch return;

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .{ .content_length = body.len });

    var buf: [5]u8 = undefined; // Small buffer to force multiple chunks
    var total: usize = 0;
    var result_buf: [64]u8 = undefined;

    while (try reader.readChunk(&buf)) |chunk| {
        @memcpy(result_buf[total..][0..chunk.len], chunk);
        total += chunk.len;
    }

    try std.testing.expectEqualStrings(body, result_buf[0..total]);
    try std.testing.expect(reader.done);
}

test "BodyReader.readAll none returns empty" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .none);

    var buf: [64]u8 = undefined;
    const result = try reader.readAll(&buf);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "BodyReader.readChunk none returns null" {
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .none);

    var buf: [64]u8 = undefined;
    const result = try reader.readChunk(&buf);

    try std.testing.expect(result == null);
}

test "BodyError error set complete" {
    const errors_list = [_]BodyError{
        BodyError.ReadFailed,
        BodyError.WriteFailed,
        BodyError.UnexpectedEof,
        BodyError.BufferTooSmall,
        BodyError.IterationLimitExceeded,
        BodyError.InvalidChunkedEncoding,
        BodyError.ChunkTooLarge,
        BodyError.SpliceFailed,
        BodyError.PipeCreationFailed,
    };

    // Verify all errors are distinct
    for (errors_list, 0..) |err1, i| {
        for (errors_list[i + 1 ..]) |err2| {
            try std.testing.expect(err1 != err2);
        }
    }
}

test "mapSocketError maps all variants" {
    try std.testing.expectEqual(BodyError.UnexpectedEof, mapSocketError(SocketError.ConnectionReset));
    try std.testing.expectEqual(BodyError.UnexpectedEof, mapSocketError(SocketError.ConnectionClosed));
    try std.testing.expectEqual(BodyError.WriteFailed, mapSocketError(SocketError.BrokenPipe));
    try std.testing.expectEqual(BodyError.ReadFailed, mapSocketError(SocketError.Timeout));
    try std.testing.expectEqual(BodyError.ReadFailed, mapSocketError(SocketError.TLSError));
    try std.testing.expectEqual(BodyError.ReadFailed, mapSocketError(SocketError.Unexpected));
}

test "Constants have expected values" {
    try std.testing.expectEqual(@as(u32, 1_000_000), MAX_BODY_READ_ITERATIONS);
    try std.testing.expectEqual(@as(u32, 16 * 1024 * 1024), MAX_CHUNK_SIZE_BYTES);
    try std.testing.expectEqual(@as(u32, 32), MIN_CHUNK_BUFFER_SIZE);
}

// =============================================================================
// Chunked Encoding Tests
// =============================================================================

test "BodyReader.readAll chunked single chunk" {
    // Test reading a single chunk body: "5\r\nHello\r\n0\r\n\r\n"
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);

    // Write chunked data: single chunk of "Hello" followed by terminator
    const chunked_body = "5\r\nHello\r\n0\r\n\r\n";
    const written = posix.write(fds[1], chunked_body) catch {
        posix.close(fds[1]);
        return;
    };
    // Close write end to signal EOF after all data written
    posix.close(fds[1]);

    try std.testing.expectEqual(chunked_body.len, written);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .chunked);

    // Precondition: reader not done initially
    try std.testing.expect(!reader.done);

    var buf: [64]u8 = undefined;
    const result = try reader.readAll(&buf);

    // Verify exact content and length
    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqualStrings("Hello", result);
    try std.testing.expect(reader.done);
}

test "BodyReader.readAll chunked multiple chunks" {
    // Test reading multiple chunks: "5\r\nHello\r\n7\r\n World!\r\n0\r\n\r\n"
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);

    // Write chunked data: two chunks followed by terminator
    // "Hello" (5 bytes) + " World!" (7 bytes) = "Hello World!" (12 bytes)
    const chunked_body = "5\r\nHello\r\n7\r\n World!\r\n0\r\n\r\n";
    const written = posix.write(fds[1], chunked_body) catch {
        posix.close(fds[1]);
        return;
    };
    // Close write end to signal EOF after all data written
    posix.close(fds[1]);

    try std.testing.expectEqual(chunked_body.len, written);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .chunked);

    var buf: [64]u8 = undefined;
    const result = try reader.readAll(&buf);

    // Verify exact content and length
    try std.testing.expectEqual(@as(usize, 12), result.len);
    try std.testing.expectEqualStrings("Hello World!", result);
    try std.testing.expect(reader.done);
}

test "BodyReader.readChunk chunked streaming" {
    // Test streaming chunks one at a time with a small buffer
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);

    // Write chunked data with multiple chunks
    // Chunk 1: "ABC" (3 bytes), Chunk 2: "DEFGH" (5 bytes)
    const chunked_body = "3\r\nABC\r\n5\r\nDEFGH\r\n0\r\n\r\n";
    const written = posix.write(fds[1], chunked_body) catch {
        posix.close(fds[1]);
        return;
    };
    // Close write end to signal EOF after all data written
    posix.close(fds[1]);

    try std.testing.expectEqual(chunked_body.len, written);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .chunked);

    // Use a 4-byte buffer - large enough for first chunk but smaller than second
    var buf: [4]u8 = undefined;
    var total_bytes: usize = 0;
    var result_buf: [64]u8 = undefined;
    var chunk_count: u32 = 0;
    const max_chunks: u32 = 10; // TigerStyle: bounded loop

    while (chunk_count < max_chunks) {
        chunk_count += 1;
        const maybe_chunk = try reader.readChunk(&buf);
        if (maybe_chunk) |chunk_data| {
            @memcpy(result_buf[total_bytes..][0..chunk_data.len], chunk_data);
            total_bytes += chunk_data.len;
        } else {
            break;
        }
    }

    // Verify we got all data
    try std.testing.expectEqual(@as(usize, 8), total_bytes);
    try std.testing.expectEqualStrings("ABCDEFGH", result_buf[0..total_bytes]);
    try std.testing.expect(reader.done);
    // Should have taken multiple reads due to buffer size
    try std.testing.expect(chunk_count >= 2);
}

test "BodyReader.readAll chunked with extensions" {
    // Test chunks with extensions: "5;name=value\r\nHello\r\n0\r\n\r\n"
    const fds = posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(fds[0]);

    // Write chunked data with chunk extension (extensions are parsed but ignored)
    const chunked_body = "5;name=value\r\nHello\r\n0\r\n\r\n";
    const written = posix.write(fds[1], chunked_body) catch {
        posix.close(fds[1]);
        return;
    };
    // Close write end to signal EOF after all data written
    posix.close(fds[1]);

    try std.testing.expectEqual(chunked_body.len, written);

    var socket = Socket.Plain.initClient(fds[0]);
    var reader = BodyReader.init(&socket, .chunked);

    var buf: [64]u8 = undefined;
    const result = try reader.readAll(&buf);

    // Verify extensions are correctly skipped and data is read
    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqualStrings("Hello", result);
    try std.testing.expect(reader.done);
}
