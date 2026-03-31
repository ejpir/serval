//! gRPC Message Envelope Helpers
//!
//! TigerStyle: Fixed-size 5-byte prefix, bounded lengths, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const max_message_size_bytes: u32 = 4 * 1024 * 1024;

/// The fixed size, in bytes, of a gRPC wire prefix.
/// This includes the 1-byte compression flag and 4-byte big-endian length field.
/// All frame parsing and encoding helpers assume this constant is 5.
/// It is used to keep prefix arithmetic explicit and consistent.
pub const prefix_size_bytes: u32 = 5;

/// The decoded 5-byte gRPC message prefix.
/// `compressed` reflects the wire flag, and `length_bytes` is the payload size.
/// `length_bytes` is validated against the configured maximum before returning.
/// This type carries no ownership; it is a plain value.
pub const MessagePrefix = struct {
    compressed: bool,
    length_bytes: u32,
};

/// A parsed gRPC frame view backed by the original input buffer.
/// `prefix` describes the frame header and `payload` borrows from the source bytes.
/// `frame_size_bytes` records the full frame length, including prefix and payload.
/// No memory is owned by this struct.
pub const FrameView = struct {
    prefix: MessagePrefix,
    payload: []const u8,
    frame_size_bytes: u32,
};

/// Errors returned by gRPC wire parsing and frame construction helpers.
/// `NeedMoreData` means the provided buffer ended before a complete prefix or frame.
/// `BufferTooSmall` means the output buffer cannot hold the encoded frame.
/// `InvalidCompressionFlag` and `MessageTooLarge` indicate malformed input.
pub const Error = error{
    NeedMoreData,
    BufferTooSmall,
    InvalidCompressionFlag,
    MessageTooLarge,
};

/// Parses the 5-byte gRPC message prefix from `raw`.
/// The prefix is `compressed` flag byte plus a big-endian 32-bit payload length.
/// Returns `error.NeedMoreData` if fewer than 5 bytes are available.
/// Returns `error.InvalidCompressionFlag` or `error.MessageTooLarge` for invalid input.
pub fn parsePrefix(raw: []const u8) Error!MessagePrefix {
    assert(prefix_size_bytes == 5);
    if (raw.len < prefix_size_bytes) return error.NeedMoreData;
    assert(raw.len >= prefix_size_bytes);

    const compression_flag = raw[0];
    if (compression_flag != 0 and compression_flag != 1) return error.InvalidCompressionFlag;

    const length_bytes = std.mem.readInt(u32, raw[1..5], .big);
    if (length_bytes > max_message_size_bytes) return error.MessageTooLarge;
    assert(length_bytes <= max_message_size_bytes);

    return .{
        .compressed = compression_flag == 1,
        .length_bytes = length_bytes,
    };
}

/// Returns the total size, in bytes, of the gRPC frame described by `raw`.
/// This validates the frame prefix before computing the frame length.
/// The result includes the 5-byte gRPC prefix and the message payload.
/// Returns the same errors as `parsePrefix` when the prefix is incomplete or invalid.
pub fn frameLengthBytes(raw: []const u8) Error!u32 {
    const prefix = try parsePrefix(raw);
    return totalFrameSizeBytes(prefix.length_bytes);
}

/// Parses a complete gRPC frame from `raw` and returns a borrowed frame view.
/// The payload slice aliases `raw` and spans exactly `prefix.length_bytes` bytes.
/// Returns `error.NeedMoreData` when `raw` does not contain the full frame.
/// Returns prefix parsing errors if the compression flag or message length is invalid.
pub fn parseFrame(raw: []const u8) Error!FrameView {
    const prefix = try parsePrefix(raw);
    const frame_size_bytes_u32 = totalFrameSizeBytes(prefix.length_bytes);
    const frame_size_bytes: usize = @intCast(frame_size_bytes_u32);

    if (raw.len < frame_size_bytes) return error.NeedMoreData;
    assert(frame_size_bytes <= raw.len);

    const payload_end: usize = frame_size_bytes;
    const payload = raw[prefix_size_bytes..payload_end];
    assert(payload.len == prefix.length_bytes);

    return .{
        .prefix = prefix,
        .payload = payload,
        .frame_size_bytes = frame_size_bytes_u32,
    };
}

/// Builds a gRPC message frame into `out` and returns the written prefix of `out`.
/// The returned slice aliases `out`; the payload bytes are copied into the buffer.
/// Returns `error.MessageTooLarge` if `payload` exceeds the configured maximum.
/// Returns `error.BufferTooSmall` if `out` cannot hold the 5-byte prefix plus payload.
pub fn buildMessage(out: []u8, compressed: bool, payload: []const u8) Error![]const u8 {
    assert(prefix_size_bytes == 5);
    if (payload.len > max_message_size_bytes) return error.MessageTooLarge;

    const total_len: usize = prefix_size_bytes + payload.len;
    if (out.len < total_len) return error.BufferTooSmall;
    assert(total_len >= prefix_size_bytes);

    out[0] = if (compressed) 1 else 0;
    std.mem.writeInt(u32, out[1..5], @intCast(payload.len), .big);
    @memcpy(out[5..][0..payload.len], payload);
    return out[0..total_len];
}

/// Parses `raw` as a complete gRPC frame and returns only the message payload.
/// The returned slice aliases `raw` and is valid only while `raw` remains valid.
/// Returns `error.NeedMoreData` if `raw` does not contain a full frame.
/// Returns other `Error` values if the prefix is invalid or the message is too large.
pub fn parseMessage(raw: []const u8) Error![]const u8 {
    const frame = try parseFrame(raw);
    return frame.payload;
}

/// Returns the next gRPC frame starting at `cursor_bytes` within `raw`.
/// On success, advances `cursor_bytes` by the full frame size in bytes.
/// Returns `null` when the cursor is already at the end of `raw`.
/// The returned view borrows from `raw`; it does not copy payload data.
pub fn nextFrame(raw: []const u8, cursor_bytes: *u32) Error!?FrameView {
    assert(@intFromPtr(cursor_bytes) != 0);
    assert(raw.len <= std.math.maxInt(u32));
    assert(cursor_bytes.* <= raw.len);

    if (cursor_bytes.* == raw.len) return null;

    const offset: usize = @intCast(cursor_bytes.*);
    const frame = try parseFrame(raw[offset..]);

    cursor_bytes.* += frame.frame_size_bytes;
    assert(cursor_bytes.* <= raw.len);

    return frame;
}

fn totalFrameSizeBytes(length_bytes: u32) u32 {
    assert(length_bytes <= max_message_size_bytes);
    const total = prefix_size_bytes + length_bytes;
    assert(total >= prefix_size_bytes);
    return total;
}

test "buildMessage and parseMessage round-trip" {
    var buf: [64]u8 = undefined;
    const built = try buildMessage(&buf, false, "ping");
    const payload = try parseMessage(built);
    try std.testing.expectEqualStrings("ping", payload);
}

test "parsePrefix returns NeedMoreData for empty and partial input" {
    var partial: [4]u8 = .{ 0, 0, 0, 0 };
    try std.testing.expectError(error.NeedMoreData, parsePrefix(""));
    try std.testing.expectError(error.NeedMoreData, parsePrefix(&partial));
}

test "parsePrefix rejects invalid compression flag" {
    var raw: [5]u8 = .{ 2, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidCompressionFlag, parsePrefix(&raw));
}

test "parsePrefix rejects oversized message length" {
    var raw: [5]u8 = .{ 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, raw[1..5], max_message_size_bytes + 1, .big);
    try std.testing.expectError(error.MessageTooLarge, parsePrefix(&raw));
}

test "frameLengthBytes reports prefix plus payload size" {
    var raw: [5]u8 = .{ 1, 0, 0, 0, 7 };
    const frame_len = try frameLengthBytes(&raw);
    try std.testing.expectEqual(@as(u32, 12), frame_len);
}

test "parseFrame returns payload and metadata" {
    var raw: [9]u8 = .{ 1, 0, 0, 0, 4, 'p', 'o', 'n', 'g' };
    const frame = try parseFrame(&raw);

    try std.testing.expect(frame.prefix.compressed);
    try std.testing.expectEqual(@as(u32, 4), frame.prefix.length_bytes);
    try std.testing.expectEqual(@as(u32, 9), frame.frame_size_bytes);
    try std.testing.expectEqualStrings("pong", frame.payload);
}

test "buildMessage rejects small output buffer" {
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, buildMessage(&out, false, "ping"));
}

test "buildMessage rejects oversized payload" {
    const oversize_len: usize = @as(usize, max_message_size_bytes) + 1;
    const payload = try std.testing.allocator.alloc(u8, oversize_len);
    defer std.testing.allocator.free(payload);

    var out: [prefix_size_bytes]u8 = undefined;
    try std.testing.expectError(error.MessageTooLarge, buildMessage(&out, false, payload));
}

test "boundary zero-length payload builds and parses" {
    var out: [prefix_size_bytes]u8 = undefined;
    const built = try buildMessage(&out, false, "");
    try std.testing.expectEqual(@as(usize, prefix_size_bytes), built.len);

    const frame = try parseFrame(built);
    try std.testing.expectEqual(@as(u32, 0), frame.prefix.length_bytes);
    try std.testing.expectEqual(@as(usize, 0), frame.payload.len);
}

test "boundary max payload builds and parses" {
    const payload_len: usize = max_message_size_bytes;
    const payload = try std.testing.allocator.alloc(u8, payload_len);
    defer std.testing.allocator.free(payload);

    var index: usize = 0;
    while (index < payload.len) : (index += 1) payload[index] = @intCast(index % 251);

    const out_len: usize = prefix_size_bytes + payload_len;
    const out = try std.testing.allocator.alloc(u8, out_len);
    defer std.testing.allocator.free(out);

    const built = try buildMessage(out, true, payload);
    const frame = try parseFrame(built);
    try std.testing.expect(frame.prefix.compressed);
    try std.testing.expectEqual(@as(u32, max_message_size_bytes), frame.prefix.length_bytes);
    try std.testing.expect(std.mem.eql(u8, payload, frame.payload));
}

test "parseMessage returns NeedMoreData for truncated payload" {
    var raw: [8]u8 = .{ 0, 0, 0, 0, 4, 'p', 'i', 'n' };
    try std.testing.expectError(error.NeedMoreData, parseMessage(&raw));
}

test "parseMessage propagates invalid prefix errors" {
    var raw: [6]u8 = .{ 9, 0, 0, 0, 1, 'x' };
    try std.testing.expectError(error.InvalidCompressionFlag, parseMessage(&raw));
}

test "nextFrame iterates concatenated frames" {
    var raw: [14]u8 = .{ 0, 0, 0, 0, 2, 'o', 'k', 1, 0, 0, 0, 2, 'n', 'o' };

    var cursor_bytes: u32 = 0;
    const frame1 = (try nextFrame(&raw, &cursor_bytes)).?;
    try std.testing.expect(!frame1.prefix.compressed);
    try std.testing.expectEqualStrings("ok", frame1.payload);

    const frame2 = (try nextFrame(&raw, &cursor_bytes)).?;
    try std.testing.expect(frame2.prefix.compressed);
    try std.testing.expectEqualStrings("no", frame2.payload);

    const end = try nextFrame(&raw, &cursor_bytes);
    try std.testing.expect(end == null);
    try std.testing.expectEqual(@as(u32, raw.len), cursor_bytes);
}

test "nextFrame returns NeedMoreData for truncated trailing frame" {
    var raw: [13]u8 = .{ 0, 0, 0, 0, 2, 'o', 'k', 1, 0, 0, 0, 2, 'n' };

    var cursor_bytes: u32 = 0;
    _ = (try nextFrame(&raw, &cursor_bytes)).?;
    try std.testing.expectError(error.NeedMoreData, nextFrame(&raw, &cursor_bytes));
}

test "property random buildMessage parseFrame round-trip" {
    var prng = std.Random.DefaultPrng.init(0x7d2f_a11c_9921_4410);
    const random = prng.random();

    var iteration: u32 = 0;
    while (iteration < 512) : (iteration += 1) {
        const payload_len: usize = random.uintLessThan(usize, 256);

        var payload: [256]u8 = undefined;
        random.bytes(payload[0..payload_len]);

        var out: [prefix_size_bytes + 256]u8 = undefined;
        const compressed = random.boolean();

        const built = try buildMessage(&out, compressed, payload[0..payload_len]);
        const frame = try parseFrame(built);

        try std.testing.expectEqual(compressed, frame.prefix.compressed);
        try std.testing.expectEqual(@as(u32, @intCast(payload_len)), frame.prefix.length_bytes);
        try std.testing.expect(std.mem.eql(u8, payload[0..payload_len], frame.payload));
    }
}

test "fuzz arbitrary bytes parse helpers do not violate contracts" {
    var prng = std.Random.DefaultPrng.init(0xa91e_04ef_32a1_88d4);
    const random = prng.random();

    var input: [512]u8 = undefined;

    var iteration: u32 = 0;
    while (iteration < 1024) : (iteration += 1) {
        const len: usize = random.uintLessThan(usize, input.len + 1);
        random.bytes(input[0..len]);
        const raw = input[0..len];

        if (parsePrefix(raw)) |_| {} else |_| {}
        if (frameLengthBytes(raw)) |_| {} else |_| {}
        if (parseFrame(raw)) |_| {} else |_| {}
        if (parseMessage(raw)) |_| {} else |_| {}

        var cursor_bytes: u32 = 0;
        var frame_count: u32 = 0;
        const max_frames: u32 = 16;
        while (frame_count < max_frames) : (frame_count += 1) {
            const next_result = nextFrame(raw, &cursor_bytes);
            if (next_result) |maybe_frame| {
                if (maybe_frame == null) break;
                continue;
            } else |err| {
                switch (err) {
                    error.NeedMoreData,
                    error.InvalidCompressionFlag,
                    error.MessageTooLarge,
                    => break,
                    else => return err,
                }
            }
        }
    }
}
