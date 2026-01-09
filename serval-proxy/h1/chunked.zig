// lib/serval-proxy/h1/chunked.zig
//! Chunked Transfer Encoding Forwarding
//!
//! Forwards chunked transfer-encoded bodies from upstream to client as pass-through,
//! preserving original chunk boundaries. Does NOT dechunk - maintains wire format.
//! Per RFC 9112 Section 7: trailer section is discarded (proxy MAY discard).
//!
//! TigerStyle: Bounded loops, explicit overflow checks, ~2 assertions per function.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;

const proxy_types = @import("../types.zig");
const ForwardError = proxy_types.ForwardError;

const chunked = @import("serval-http").chunked;
const parseChunkSize = chunked.parseChunkSize;
const isLastChunk = chunked.isLastChunk;
const ChunkParseError = chunked.ChunkParseError;

const net = @import("serval-net");
const Socket = net.Socket;

const core = @import("serval-core");
const config = core.config;

// Re-export from config for backward compatibility.
pub const MAX_CHUNK_ITERATIONS = config.MAX_CHUNK_ITERATIONS;
pub const CHUNK_BUFFER_SIZE_BYTES = config.CHUNK_BUFFER_SIZE_BYTES;

// =============================================================================
// Public API
// =============================================================================

/// Forward chunked body preserving chunk format.
/// Uses Socket abstraction for unified TLS/plaintext handling.
/// Returns total bytes forwarded (including chunk framing).
/// TigerStyle: Bounded main loop, explicit Socket read/write.
pub fn forwardChunkedBody(
    source: *Socket,
    dest: *Socket,
) ForwardError!u64 {
    // Precondition: valid socket file descriptors.
    assert(source.getFd() >= 0);
    assert(dest.getFd() >= 0);

    // Zero buffer for defense-in-depth (don't leak stale data on partial reads).
    var buffer: [CHUNK_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([CHUNK_BUFFER_SIZE_BYTES]u8);
    var buffer_len: u32 = 0;
    var total_forwarded: u64 = 0;
    var chunk_iterations: u32 = 0;

    // Main loop: process one chunk per iteration (bounded).
    while (chunk_iterations < MAX_CHUNK_ITERATIONS) : (chunk_iterations += 1) {
        // Ensure buffer has enough data to parse chunk header.
        buffer_len = try ensureBufferHasChunkHeader(source, &buffer, buffer_len);

        // Parse chunk size from buffer.
        const parse_result = parseChunkSize(buffer[0..buffer_len]) catch |err| {
            return mapChunkParseError(err);
        };

        const chunk_size = parse_result.size;
        const header_consumed: u32 = @intCast(parse_result.consumed);

        // Forward chunk header (size + extensions + CRLF) to destination.
        dest.writeAll(buffer[0..header_consumed]) catch {
            return ForwardError.SendFailed;
        };
        total_forwarded += header_consumed;

        // Consume header from buffer.
        shiftBuffer(&buffer, &buffer_len, header_consumed);

        // Check for last chunk (size 0).
        if (isLastChunk(chunk_size)) {
            // Forward trailing CRLF after last chunk.
            total_forwarded += try forwardTrailerSection(source, dest, &buffer, &buffer_len);
            break;
        }

        // Forward chunk data + trailing CRLF.
        total_forwarded += try forwardChunkData(source, dest, chunk_size, &buffer, &buffer_len);
    }

    // Postcondition: forwarded some bytes or detected empty chunked body.
    assert(total_forwarded >= 5); // Minimum: "0\r\n\r\n"
    return total_forwarded;
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Ensure buffer contains enough data to parse chunk header.
/// Reads from source socket if needed.
/// Returns updated buffer length, or error if insufficient data after max iterations.
fn ensureBufferHasChunkHeader(
    source: *Socket,
    buffer: *[CHUNK_BUFFER_SIZE_BYTES]u8,
    buffer_len: u32,
) ForwardError!u32 {
    assert(source.getFd() >= 0);

    var current_len = buffer_len;

    // Need at least 3 bytes for minimal chunk header "0\r\n".
    const min_header_bytes: u32 = 3;
    var read_iterations: u32 = 0;
    const max_read_iterations: u32 = 64;

    while (current_len < min_header_bytes and read_iterations < max_read_iterations) : (read_iterations += 1) {
        const bytes_read = try recvToBuffer(source, buffer, current_len);
        if (bytes_read == 0) return ForwardError.RecvFailed; // Unexpected EOF.
        current_len += bytes_read;
    }

    // Postcondition: must have minimum header bytes, else fail.
    if (current_len < min_header_bytes) return ForwardError.RecvFailed;

    assert(current_len >= min_header_bytes);
    return current_len;
}

/// Forward chunk data and trailing CRLF to destination.
/// Reads from buffer first, then directly from source for remaining bytes.
/// Returns bytes forwarded (chunk_size + 2 for CRLF).
fn forwardChunkData(
    source: *Socket,
    dest: *Socket,
    chunk_size: u64,
    buffer: *[CHUNK_BUFFER_SIZE_BYTES]u8,
    buffer_len: *u32,
) ForwardError!u64 {
    assert(source.getFd() >= 0);
    assert(dest.getFd() >= 0);
    assert(chunk_size > 0); // Caller handles last-chunk case.

    var bytes_remaining = chunk_size;
    var forwarded: u64 = 0;

    // Forward any buffered data first.
    if (buffer_len.* > 0) {
        const to_send: u32 = @intCast(@min(buffer_len.*, bytes_remaining));
        dest.writeAll(buffer[0..to_send]) catch {
            return ForwardError.SendFailed;
        };
        forwarded += to_send;
        bytes_remaining -= to_send;
        shiftBuffer(buffer, buffer_len, to_send);
    }

    // Forward remaining chunk data directly from source.
    forwarded += try forwardBytes(source, dest, bytes_remaining, buffer);

    // Forward trailing CRLF after chunk data.
    forwarded += try forwardCRLF(source, dest, buffer, buffer_len);

    assert(forwarded == chunk_size + 2);
    return forwarded;
}

/// Forward exactly byte_count bytes from source to destination.
/// Uses buffer for intermediate storage.
/// Returns bytes forwarded.
fn forwardBytes(
    source: *Socket,
    dest: *Socket,
    byte_count: u64,
    buffer: *[CHUNK_BUFFER_SIZE_BYTES]u8,
) ForwardError!u64 {
    assert(source.getFd() >= 0);
    assert(dest.getFd() >= 0);

    var remaining = byte_count;
    var forwarded: u64 = 0;
    var iterations: u32 = 0;
    const max_iterations: u32 = MAX_CHUNK_ITERATIONS;

    while (remaining > 0 and iterations < max_iterations) : (iterations += 1) {
        const to_read: usize = @intCast(@min(remaining, CHUNK_BUFFER_SIZE_BYTES));

        // Read from source socket.
        const n = source.read(buffer[0..to_read]) catch {
            return ForwardError.RecvFailed;
        };

        if (n == 0) return ForwardError.RecvFailed; // Unexpected EOF.

        // Write to destination socket.
        dest.writeAll(buffer[0..n]) catch {
            return ForwardError.SendFailed;
        };
        forwarded += n;
        remaining -= n;
    }

    assert(forwarded == byte_count);
    return forwarded;
}

/// Forward CRLF sequence (reads from buffer or source as needed).
/// Returns 2 (bytes forwarded).
fn forwardCRLF(
    source: *Socket,
    dest: *Socket,
    buffer: *[CHUNK_BUFFER_SIZE_BYTES]u8,
    buffer_len: *u32,
) ForwardError!u64 {
    assert(source.getFd() >= 0);
    assert(dest.getFd() >= 0);

    // Ensure we have 2 bytes for CRLF.
    var iterations: u32 = 0;
    const max_iterations: u32 = 8;
    while (buffer_len.* < 2 and iterations < max_iterations) : (iterations += 1) {
        const bytes_read = try recvToBuffer(source, buffer, buffer_len.*);
        if (bytes_read == 0) return ForwardError.RecvFailed;
        buffer_len.* += bytes_read;
    }

    if (buffer_len.* < 2) return ForwardError.RecvFailed;

    // Validate CRLF (defense-in-depth: malformed input).
    if (buffer[0] != '\r' or buffer[1] != '\n') {
        return ForwardError.InvalidResponse;
    }

    dest.writeAll(buffer[0..2]) catch {
        return ForwardError.SendFailed;
    };
    shiftBuffer(buffer, buffer_len, 2);

    // Postcondition: CRLF is exactly 2 bytes.
    const forwarded: u64 = 2;
    assert(forwarded == 2);
    return forwarded;
}

/// Forward trailer section after last chunk.
/// Per RFC 9112: trailer = *( header-field CRLF ) CRLF
/// We discard trailer headers but must forward the final CRLF.
/// Returns bytes forwarded (at least 2 for final CRLF).
fn forwardTrailerSection(
    source: *Socket,
    dest: *Socket,
    buffer: *[CHUNK_BUFFER_SIZE_BYTES]u8,
    buffer_len: *u32,
) ForwardError!u64 {
    assert(source.getFd() >= 0);
    assert(dest.getFd() >= 0);

    var forwarded: u64 = 0;
    var iterations: u32 = 0;
    const max_iterations: u32 = 256; // Limit trailer parsing iterations.

    // Read until we find empty line (CRLF CRLF pattern after last chunk header).
    while (iterations < max_iterations) : (iterations += 1) {
        // Ensure buffer has data to scan.
        if (buffer_len.* < 2) {
            const bytes_read = try recvToBuffer(source, buffer, buffer_len.*);
            if (bytes_read == 0) return ForwardError.RecvFailed;
            buffer_len.* += bytes_read;
        }

        // Check for empty line (end of trailers).
        if (buffer_len.* >= 2 and buffer[0] == '\r' and buffer[1] == '\n') {
            // Forward final CRLF and done.
            dest.writeAll(buffer[0..2]) catch {
                return ForwardError.SendFailed;
            };
            shiftBuffer(buffer, buffer_len, 2);
            forwarded += 2;
            break;
        }

        // Discard trailer line (find CRLF and skip past it).
        const crlf_pos = findCRLF(buffer[0..buffer_len.*]);
        if (crlf_pos) |pos| {
            // Discard trailer header (don't forward).
            const to_discard: u32 = @intCast(pos + 2);
            shiftBuffer(buffer, buffer_len, to_discard);
        } else {
            // Need more data to find line end.
            const bytes_read = try recvToBuffer(source, buffer, buffer_len.*);
            if (bytes_read == 0) return ForwardError.RecvFailed;
            buffer_len.* += bytes_read;
        }
    }

    // Postcondition: forwarded at least the final CRLF.
    assert(forwarded >= 2);
    return forwarded;
}

/// Read data from source socket into buffer at given offset.
/// Returns number of bytes read.
fn recvToBuffer(
    source: *Socket,
    buffer: *[CHUNK_BUFFER_SIZE_BYTES]u8,
    offset: u32,
) ForwardError!u32 {
    assert(source.getFd() >= 0);
    assert(offset < CHUNK_BUFFER_SIZE_BYTES);

    const space_remaining = CHUNK_BUFFER_SIZE_BYTES - offset;

    // Read from socket via Socket abstraction.
    const n = source.read(buffer[offset..]) catch {
        return ForwardError.RecvFailed;
    };

    // Postcondition: read within buffer bounds.
    assert(n <= space_remaining);
    return @intCast(n);
}

/// Shift buffer contents left by `count` bytes.
fn shiftBuffer(buffer: *[CHUNK_BUFFER_SIZE_BYTES]u8, buffer_len: *u32, count: u32) void {
    assert(count <= buffer_len.*);

    const old_len = buffer_len.*;
    const remaining = old_len - count;
    if (remaining > 0) {
        // Use a loop instead of memcpy for overlapping regions.
        var i: u32 = 0;
        while (i < remaining) : (i += 1) {
            buffer[i] = buffer[count + i];
        }
    }
    buffer_len.* = remaining;

    // Postcondition: buffer length reduced by exactly count bytes.
    assert(buffer_len.* == old_len - count);
}

/// Find CRLF in buffer, return position of '\r' or null if not found.
fn findCRLF(data: []const u8) ?usize {
    // Precondition: data slice is bounded by chunk buffer size.
    assert(data.len <= CHUNK_BUFFER_SIZE_BYTES);

    if (data.len < 2) return null;

    var i: usize = 0;
    while (i + 1 < data.len) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n') {
            // Postcondition: returned position is valid index with room for LF.
            assert(i + 1 < data.len);
            return i;
        }
    }
    return null;
}

/// Map chunk parse errors to ForwardError.
/// TigerStyle: Pure error mapping function, assertion-exempt.
fn mapChunkParseError(err: ChunkParseError) ForwardError {
    return switch (err) {
        error.IncompleteChunk => ForwardError.RecvFailed,
        error.InvalidHexDigit,
        error.ChunkSizeOverflow,
        error.MissingCRLF,
        error.ExtensionTooLong,
        => ForwardError.InvalidResponse,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "shiftBuffer: shifts data correctly" {
    var buffer: [CHUNK_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([CHUNK_BUFFER_SIZE_BYTES]u8);
    buffer[0] = 'a';
    buffer[1] = 'b';
    buffer[2] = 'c';
    buffer[3] = 'd';
    var len: u32 = 4;

    shiftBuffer(&buffer, &len, 2);

    try std.testing.expectEqual(@as(u32, 2), len);
    try std.testing.expectEqual(@as(u8, 'c'), buffer[0]);
    try std.testing.expectEqual(@as(u8, 'd'), buffer[1]);
}

test "shiftBuffer: shift entire buffer" {
    var buffer: [CHUNK_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([CHUNK_BUFFER_SIZE_BYTES]u8);
    buffer[0] = 'x';
    var len: u32 = 1;

    shiftBuffer(&buffer, &len, 1);

    try std.testing.expectEqual(@as(u32, 0), len);
}

test "findCRLF: finds CRLF at start" {
    const data = "\r\nrest";
    const pos = findCRLF(data);
    try std.testing.expectEqual(@as(?usize, 0), pos);
}

test "findCRLF: finds CRLF in middle" {
    const data = "abc\r\ndef";
    const pos = findCRLF(data);
    try std.testing.expectEqual(@as(?usize, 3), pos);
}

test "findCRLF: returns null when no CRLF" {
    const data = "abcdef";
    const pos = findCRLF(data);
    try std.testing.expectEqual(@as(?usize, null), pos);
}

test "findCRLF: returns null for empty buffer" {
    const data = "";
    const pos = findCRLF(data);
    try std.testing.expectEqual(@as(?usize, null), pos);
}

test "findCRLF: returns null for single byte" {
    const data = "\r";
    const pos = findCRLF(data);
    try std.testing.expectEqual(@as(?usize, null), pos);
}

test "mapChunkParseError: maps errors correctly" {
    try std.testing.expectEqual(ForwardError.RecvFailed, mapChunkParseError(error.IncompleteChunk));
    try std.testing.expectEqual(ForwardError.InvalidResponse, mapChunkParseError(error.InvalidHexDigit));
    try std.testing.expectEqual(ForwardError.InvalidResponse, mapChunkParseError(error.ChunkSizeOverflow));
    try std.testing.expectEqual(ForwardError.InvalidResponse, mapChunkParseError(error.MissingCRLF));
    try std.testing.expectEqual(ForwardError.InvalidResponse, mapChunkParseError(error.ExtensionTooLong));
}

// =============================================================================
// Chunk Sequence Parsing Tests
// =============================================================================

/// Helper: Parse complete chunked body and extract assembled content.
/// Returns total payload bytes (excluding framing) and verifies integrity.
fn parseCompleteChunkedBody(data: []const u8) !struct { payload_size: u64, chunk_count: u32 } {
    var pos: usize = 0;
    var payload_size: u64 = 0;
    var chunk_count: u32 = 0;
    const max_chunks: u32 = 1024;

    while (chunk_count < max_chunks) : (chunk_count += 1) {
        if (pos >= data.len) return error.UnexpectedEOF;

        const result = try parseChunkSize(data[pos..]);
        pos += result.consumed;

        if (isLastChunk(result.size)) {
            // Skip trailer section (find final CRLF)
            while (pos + 1 < data.len) {
                if (data[pos] == '\r' and data[pos + 1] == '\n') {
                    if (pos >= 2 and data[pos - 2] == '\r' and data[pos - 1] == '\n') {
                        // Empty trailer - just CRLF
                        break;
                    }
                    pos += 2;
                    if (pos + 1 < data.len and data[pos] == '\r' and data[pos + 1] == '\n') {
                        break;
                    }
                } else {
                    pos += 1;
                }
            }
            break;
        }

        // Skip chunk data
        const chunk_data_end = pos + result.size;
        if (chunk_data_end > data.len) return error.UnexpectedEOF;
        payload_size += result.size;
        pos = chunk_data_end;

        // Skip trailing CRLF after chunk data
        if (pos + 1 >= data.len) return error.UnexpectedEOF;
        if (data[pos] != '\r' or data[pos + 1] != '\n') return error.MissingChunkCRLF;
        pos += 2;
    }

    return .{ .payload_size = payload_size, .chunk_count = chunk_count + 1 };
}

const ParseError = error{
    UnexpectedEOF,
    MissingChunkCRLF,
} || ChunkParseError;

test "parse complete chunked body: single chunk" {
    // "5\r\nHello\r\n0\r\n\r\n" should extract 5 bytes payload
    const data = "5\r\nHello\r\n0\r\n\r\n";
    const result = try parseCompleteChunkedBody(data);
    try std.testing.expectEqual(@as(u64, 5), result.payload_size);
    try std.testing.expectEqual(@as(u32, 2), result.chunk_count); // data chunk + terminator
}

test "parse complete chunked body: multiple chunks" {
    // "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n" should extract 11 bytes payload
    const data = "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
    const result = try parseCompleteChunkedBody(data);
    try std.testing.expectEqual(@as(u64, 11), result.payload_size);
    try std.testing.expectEqual(@as(u32, 3), result.chunk_count); // 2 data chunks + terminator
}

test "parse complete chunked body: empty body" {
    // "0\r\n\r\n" should extract 0 bytes payload
    const data = "0\r\n\r\n";
    const result = try parseCompleteChunkedBody(data);
    try std.testing.expectEqual(@as(u64, 0), result.payload_size);
    try std.testing.expectEqual(@as(u32, 1), result.chunk_count); // just terminator
}

test "parse complete chunked body: hex sizes" {
    // "a\r\n0123456789\r\nf\r\n0123456789abcde\r\n0\r\n\r\n"
    const data = "a\r\n0123456789\r\nf\r\n0123456789abcde\r\n0\r\n\r\n";
    const result = try parseCompleteChunkedBody(data);
    try std.testing.expectEqual(@as(u64, 25), result.payload_size); // 10 + 15
    try std.testing.expectEqual(@as(u32, 3), result.chunk_count);
}

test "parse complete chunked body: with extension" {
    // "5;ext=val\r\nHello\r\n0\r\n\r\n"
    const data = "5;ext=val\r\nHello\r\n0\r\n\r\n";
    const result = try parseCompleteChunkedBody(data);
    try std.testing.expectEqual(@as(u64, 5), result.payload_size);
    try std.testing.expectEqual(@as(u32, 2), result.chunk_count);
}

// =============================================================================
// Forwarding Integration Tests (using pipes)
// =============================================================================

/// Test helper: Create a pipe pair and return (read_fd, write_fd).
fn createPipePair() !struct { read_fd: i32, write_fd: i32 } {
    const fds = try posix.pipe();
    return .{ .read_fd = fds[0], .write_fd = fds[1] };
}

/// Test helper: Write data to pipe.
fn writeToPipe(fd: i32, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const n = posix.write(fd, data[written..]) catch |err| {
            return err;
        };
        if (n == 0) return error.WriteFailed;
        written += n;
    }
}

/// Test helper: Read all available data from pipe (non-blocking, with timeout).
fn readFromPipe(fd: i32, buffer: []u8) !usize {
    var total: usize = 0;
    var iterations: u32 = 0;
    const max_iterations: u32 = 1000;

    while (iterations < max_iterations) : (iterations += 1) {
        const n = posix.read(fd, buffer[total..]) catch |err| {
            if (err == error.WouldBlock) break;
            return err;
        };
        if (n == 0) break;
        total += n;
        if (total >= buffer.len) break;
    }
    return total;
}

test "forwardChunkedBody: single chunk" {
    // Create input pipe (upstream) and output pipe (client)
    const input = try createPipePair();
    defer posix.close(input.read_fd);
    defer posix.close(input.write_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);
    defer posix.close(output.write_fd);

    // Write chunked data to input pipe
    const chunked_data = "5\r\nHello\r\n0\r\n\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd); // Signal EOF

    // Forward from input.read_fd to output.write_fd
    // Note: We need to reinstantiate the pipe since we closed write_fd
    const input2 = try createPipePair();
    defer posix.close(input2.read_fd);
    defer posix.close(input2.write_fd);

    const output2 = try createPipePair();
    defer posix.close(output2.read_fd);
    defer posix.close(output2.write_fd);

    try writeToPipe(input2.write_fd, chunked_data);
    posix.close(input2.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input2.read_fd);
    var dest_socket = Socket.Plain.initClient(output2.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);

    // Read output and verify
    var out_buffer: [256]u8 = undefined;
    posix.close(output2.write_fd);
    const bytes_read = try readFromPipe(output2.read_fd, &out_buffer);

    try std.testing.expectEqual(chunked_data.len, bytes_read);
    try std.testing.expectEqualSlices(u8, chunked_data, out_buffer[0..bytes_read]);
    try std.testing.expectEqual(@as(u64, chunked_data.len), bytes_forwarded);
}

test "forwardChunkedBody: multiple chunks" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // "7\r\nchunk 1\r\n7\r\nchunk 2\r\n0\r\n\r\n"
    const chunked_data = "7\r\nchunk 1\r\n7\r\nchunk 2\r\n0\r\n\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    var out_buffer: [256]u8 = undefined;
    const bytes_read = try readFromPipe(output.read_fd, &out_buffer);

    try std.testing.expectEqual(chunked_data.len, bytes_read);
    try std.testing.expectEqualSlices(u8, chunked_data, out_buffer[0..bytes_read]);
    try std.testing.expectEqual(@as(u64, chunked_data.len), bytes_forwarded);
}

test "forwardChunkedBody: empty body" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    const chunked_data = "0\r\n\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    var out_buffer: [256]u8 = undefined;
    const bytes_read = try readFromPipe(output.read_fd, &out_buffer);

    try std.testing.expectEqual(@as(usize, 5), bytes_read);
    try std.testing.expectEqualSlices(u8, chunked_data, out_buffer[0..bytes_read]);
    try std.testing.expectEqual(@as(u64, 5), bytes_forwarded);
}

test "forwardChunkedBody: large chunk exceeding buffer size" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // Create chunk larger than CHUNK_BUFFER_SIZE_BYTES (8192)
    const large_size: usize = 10000;
    var large_data: [large_size]u8 = undefined;
    for (&large_data) |*b| {
        b.* = 'X';
    }

    // Build chunked message: "2710\r\n" + 10000 X's + "\r\n0\r\n\r\n"
    // 2710 hex = 10000 decimal
    const header = "2710\r\n";
    const trailer = "\r\n0\r\n\r\n";

    try writeToPipe(input.write_fd, header);
    try writeToPipe(input.write_fd, &large_data);
    try writeToPipe(input.write_fd, trailer);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    const expected_total = header.len + large_size + trailer.len;
    try std.testing.expectEqual(@as(u64, expected_total), bytes_forwarded);

    // Verify output by reading in chunks
    var total_read: usize = 0;
    var read_buffer: [4096]u8 = undefined;
    while (total_read < expected_total) {
        const n = posix.read(output.read_fd, &read_buffer) catch break;
        if (n == 0) break;
        total_read += n;
    }
    try std.testing.expectEqual(expected_total, total_read);
}

test "forwardChunkedBody: many small chunks" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // Build 50 small chunks: "1\r\nX\r\n" repeated
    var chunks_data: [50 * 6 + 5]u8 = undefined; // 50 * "1\r\nX\r\n" + "0\r\n\r\n"
    var pos: usize = 0;
    for (0..50) |_| {
        @memcpy(chunks_data[pos..][0..6], "1\r\nX\r\n");
        pos += 6;
    }
    @memcpy(chunks_data[pos..][0..5], "0\r\n\r\n");
    pos += 5;

    try writeToPipe(input.write_fd, chunks_data[0..pos]);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    try std.testing.expectEqual(@as(u64, pos), bytes_forwarded);
}

test "forwardChunkedBody: chunk with extension" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // "5;ext=val\r\nHello\r\n0\r\n\r\n"
    const chunked_data = "5;ext=val\r\nHello\r\n0\r\n\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    var out_buffer: [256]u8 = undefined;
    const bytes_read = try readFromPipe(output.read_fd, &out_buffer);

    try std.testing.expectEqual(chunked_data.len, bytes_read);
    try std.testing.expectEqualSlices(u8, chunked_data, out_buffer[0..bytes_read]);
    try std.testing.expectEqual(@as(u64, chunked_data.len), bytes_forwarded);
}

test "forwardChunkedBody: with trailer section discarded" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // "5\r\nHello\r\n0\r\nX-Checksum: abc\r\n\r\n"
    // Trailer headers are discarded, only final CRLF forwarded
    const chunked_data = "5\r\nHello\r\n0\r\nX-Checksum: abc\r\n\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    // Expect: "5\r\nHello\r\n0\r\n" + "\r\n" (trailer discarded, final CRLF kept)
    // The forwarder discards trailer headers but forwards final CRLF
    var out_buffer: [256]u8 = undefined;
    const bytes_read = try readFromPipe(output.read_fd, &out_buffer);

    // Should have forwarded chunk header + data + CRLF + last chunk + final CRLF
    // "5\r\nHello\r\n0\r\n\r\n" = 17 bytes (trailer discarded)
    const expected_output = "5\r\nHello\r\n0\r\n\r\n";
    try std.testing.expectEqual(expected_output.len, bytes_read);
    try std.testing.expectEqualSlices(u8, expected_output, out_buffer[0..bytes_read]);
    try std.testing.expectEqual(@as(u64, expected_output.len), bytes_forwarded);
}

// =============================================================================
// Error Handling Tests
// =============================================================================

test "forwardChunkedBody: error on invalid hex" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);
    defer posix.close(output.write_fd);

    // "XYZ\r\ndata\r\n0\r\n\r\n" - invalid hex
    const chunked_data = "XYZ\r\ndata\r\n0\r\n\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const result = forwardChunkedBody(&source_socket, &dest_socket);
    try std.testing.expectError(ForwardError.InvalidResponse, result);
}

test "forwardChunkedBody: error on truncated input (EOF before chunk data)" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);
    defer posix.close(output.write_fd);

    // "5\r\nHel" - missing chunk data (only 3 bytes instead of 5)
    const chunked_data = "5\r\nHel";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const result = forwardChunkedBody(&source_socket, &dest_socket);
    try std.testing.expectError(ForwardError.RecvFailed, result);
}

test "forwardChunkedBody: error on missing CRLF after chunk data" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);
    defer posix.close(output.write_fd);

    // "5\r\nHello0\r\n\r\n" - missing \r\n after "Hello", "0" becomes invalid
    const chunked_data = "5\r\nHello0\r\n\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const result = forwardChunkedBody(&source_socket, &dest_socket);
    try std.testing.expectError(ForwardError.InvalidResponse, result);
}

test "forwardChunkedBody: error on missing terminator" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);
    defer posix.close(output.write_fd);

    // "5\r\nHello\r\n" - missing "0\r\n\r\n" terminator
    const chunked_data = "5\r\nHello\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const result = forwardChunkedBody(&source_socket, &dest_socket);
    try std.testing.expectError(ForwardError.RecvFailed, result);
}

// =============================================================================
// Boundary Condition Tests
// =============================================================================

test "forwardChunkedBody: exact buffer boundary chunk" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // Create chunk that exactly fills buffer (8192 - header overhead)
    // Header "1FFC\r\n" = 6 bytes, so data = 8186 bytes fits nicely
    const chunk_size: usize = 8186;
    var chunk_data: [chunk_size]u8 = undefined;
    for (&chunk_data) |*b| {
        b.* = 'Y';
    }

    // "1FFA\r\n" + 8186 Y's + "\r\n0\r\n\r\n"
    // 1FFA hex = 8186 decimal
    const header = "1FFA\r\n";
    const trailer = "\r\n0\r\n\r\n";

    try writeToPipe(input.write_fd, header);
    try writeToPipe(input.write_fd, &chunk_data);
    try writeToPipe(input.write_fd, trailer);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    const expected_total = header.len + chunk_size + trailer.len;
    try std.testing.expectEqual(@as(u64, expected_total), bytes_forwarded);
}

test "forwardChunkedBody: chunk data spans multiple reads" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // Create chunk that requires multiple recv calls (3x buffer size)
    const chunk_size: usize = CHUNK_BUFFER_SIZE_BYTES * 3;
    var chunk_data: [chunk_size]u8 = undefined;
    for (&chunk_data) |*b| {
        b.* = 'Z';
    }

    // "6000\r\n" + 24576 Z's + "\r\n0\r\n\r\n"
    // 6000 hex = 24576 decimal
    const header = "6000\r\n";
    const trailer = "\r\n0\r\n\r\n";

    try writeToPipe(input.write_fd, header);
    try writeToPipe(input.write_fd, &chunk_data);
    try writeToPipe(input.write_fd, trailer);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    const expected_total = header.len + chunk_size + trailer.len;
    try std.testing.expectEqual(@as(u64, expected_total), bytes_forwarded);

    // Verify all data was forwarded
    var total_read: usize = 0;
    var read_buffer: [8192]u8 = undefined;
    while (total_read < expected_total) {
        const n = posix.read(output.read_fd, &read_buffer) catch break;
        if (n == 0) break;
        total_read += n;
    }
    try std.testing.expectEqual(expected_total, total_read);
}

test "forwardChunkedBody: single byte chunks" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // 10 single-byte chunks: "1\r\nA\r\n" repeated
    const chunk_count: usize = 10;
    var chunks_data: [chunk_count * 6 + 5]u8 = undefined;
    var pos: usize = 0;
    for (0..chunk_count) |i| {
        @memcpy(chunks_data[pos..][0..3], "1\r\n");
        pos += 3;
        chunks_data[pos] = @as(u8, @intCast('A' + i));
        pos += 1;
        @memcpy(chunks_data[pos..][0..2], "\r\n");
        pos += 2;
    }
    @memcpy(chunks_data[pos..][0..5], "0\r\n\r\n");
    pos += 5;

    try writeToPipe(input.write_fd, chunks_data[0..pos]);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    try std.testing.expectEqual(@as(u64, pos), bytes_forwarded);
}

test "forwardChunkedBody: uppercase hex in chunk size" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // "A\r\n0123456789\r\n0\r\n\r\n" - uppercase A = 10
    const chunked_data = "A\r\n0123456789\r\n0\r\n\r\n";
    try writeToPipe(input.write_fd, chunked_data);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    var out_buffer: [256]u8 = undefined;
    const bytes_read = try readFromPipe(output.read_fd, &out_buffer);

    try std.testing.expectEqual(chunked_data.len, bytes_read);
    try std.testing.expectEqual(@as(u64, chunked_data.len), bytes_forwarded);
}

test "forwardChunkedBody: mixed case hex in chunk size" {
    const input = try createPipePair();
    defer posix.close(input.read_fd);

    const output = try createPipePair();
    defer posix.close(output.read_fd);

    // "aB\r\n" + 171 bytes + "\r\n0\r\n\r\n"
    // aB hex = 171 decimal
    const chunk_size: usize = 171;
    var chunk_data: [chunk_size]u8 = undefined;
    for (&chunk_data) |*b| {
        b.* = 'M';
    }

    const header = "aB\r\n";
    const trailer = "\r\n0\r\n\r\n";

    try writeToPipe(input.write_fd, header);
    try writeToPipe(input.write_fd, &chunk_data);
    try writeToPipe(input.write_fd, trailer);
    posix.close(input.write_fd);

    // Create Socket wrappers for pipes.
    var source_socket = Socket.Plain.initClient(input.read_fd);
    var dest_socket = Socket.Plain.initClient(output.write_fd);

    const bytes_forwarded = try forwardChunkedBody(&source_socket, &dest_socket);
    posix.close(output.write_fd);

    const expected_total = header.len + chunk_size + trailer.len;
    try std.testing.expectEqual(@as(u64, expected_total), bytes_forwarded);
}
