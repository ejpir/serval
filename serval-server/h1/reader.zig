// lib/serval-server/h1/reader.zig
//! HTTP/1.1 Request Reading Utilities
//!
//! Zero-allocation request reading for HTTP/1.1 connections.
//! Handles partial header accumulation and body length extraction.
//! TigerStyle: Explicit parameters, bounded operations.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const config = serval_core.config;
const debugLog = serval_core.debugLog;
const types = serval_core.types;
const Request = types.Request;

const serval_http = @import("serval-http");
const parseContentLengthValue = serval_http.parseContentLengthValue;

/// Buffer size for reading HTTP requests (from centralized config).
const REQUEST_BUFFER_SIZE_BYTES = config.REQUEST_BUFFER_SIZE_BYTES;

/// Reads request bytes from `stream` into caller-owned fixed buffer `recv_buf`.
/// Preconditions: `recv_buf` is a valid borrowed buffer pointer.
/// This helper performs one read attempt and does not retain ownership of stream/buffer state.
/// Returns byte count on success, or `null` on EOF/read error paths.
pub fn readRequest(io: Io, stream: Io.net.Stream, recv_buf: *[REQUEST_BUFFER_SIZE_BYTES]u8) ?usize {
    // Precondition: buffer pointer must be valid
    assert(@intFromPtr(recv_buf) != 0);

    var reader_buf: [1]u8 = std.mem.zeroes([1]u8);
    var reader = stream.reader(io, &reader_buf);
    var bufs: [1][]u8 = .{recv_buf};
    const n = reader.interface.readVec(&bufs) catch |err| {
        if (err != error.EndOfStream) {
            debugLog("Read error: {s}", .{@errorName(err)});
        }
        return null;
    };

    // Postcondition: return null if no bytes read (client closed)
    if (n == 0) return null;
    return n;
}

/// Reads additional bytes into `remaining_buf` during partial header accumulation.
/// Preconditions: `remaining_buf.len > 0`; caller keeps buffer and stream alive for this read.
/// Performs a single read attempt and does not retain ownership of any input state.
/// Returns bytes read (possibly `0` on EOF) or `null` on read error paths.
pub fn readMoreData(io: Io, stream: Io.net.Stream, remaining_buf: []u8) ?usize {
    // Precondition: buffer must have space for more data
    assert(remaining_buf.len > 0);

    var reader_buf: [1]u8 = std.mem.zeroes([1]u8);
    var reader = stream.reader(io, &reader_buf);
    var bufs: [1][]u8 = .{remaining_buf};
    const n = reader.interface.readVec(&bufs) catch |err| {
        if (err != error.EndOfStream) {
            debugLog("Read more error: {s}", .{@errorName(err)});
        }
        return null;
    };

    // Postcondition: returns actual bytes read (may be 0 on EOF)
    return n;
}

/// Parses `Content-Length` from `request` and returns body length in bytes.
/// Preconditions: `request` is a valid borrowed pointer.
/// Missing, invalid, or out-of-range values are treated as `0` (no body) rather than errors.
/// Infallible helper: ownership remains with caller; no allocation or retained state.
pub fn getBodyLength(request: *const Request) usize {
    // Precondition: request must be valid
    assert(@intFromPtr(request) != 0);

    const cl_header = request.headers.get("Content-Length") orelse return 0;
    const cl_value = parseContentLengthValue(cl_header) orelse return 0;

    // Postcondition: result fits in usize (bounded cast)
    return if (cl_value <= std.math.maxInt(usize)) @intCast(cl_value) else 0;
}

// =============================================================================
// Tests
// =============================================================================

test "getBodyLength returns 0 for missing Content-Length" {
    const request = Request{};
    try std.testing.expectEqual(@as(usize, 0), getBodyLength(&request));
}

test "getBodyLength parses valid Content-Length" {
    var request = Request{};
    try request.headers.put("Content-Length", "1234");

    try std.testing.expectEqual(@as(usize, 1234), getBodyLength(&request));
}

test "getBodyLength returns 0 for invalid Content-Length" {
    var request = Request{};
    try request.headers.put("Content-Length", "invalid");

    try std.testing.expectEqual(@as(usize, 0), getBodyLength(&request));
}

test "getBodyLength returns 0 for empty Content-Length" {
    var request = Request{};
    try request.headers.put("Content-Length", "");

    try std.testing.expectEqual(@as(usize, 0), getBodyLength(&request));
}

test "getBodyLength handles zero Content-Length" {
    var request = Request{};
    try request.headers.put("Content-Length", "0");

    try std.testing.expectEqual(@as(usize, 0), getBodyLength(&request));
}
