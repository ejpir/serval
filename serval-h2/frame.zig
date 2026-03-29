//! HTTP/2 Frame Header Helpers
//!
//! Minimal bounded frame parsing/encoding for h2c request inspection.
//! TigerStyle: Fixed-size parsing, explicit bounds, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

/// Size of an HTTP/2 frame header in bytes.
/// Frame headers are fixed at 9 bytes on the wire.
/// Parsing and serialization helpers use this constant to validate buffer lengths.
pub const frame_header_size_bytes: u32 = 9;

/// `END_STREAM` frame flag bit.
/// This value is the raw wire bit mask for the end-of-stream flag.
/// It shares the same bit position as `flags_ack`, but applies to different frame types.
pub const flags_end_stream: u8 = 0x1;
/// `ACK` frame flag bit.
/// This value is the raw wire bit mask for the acknowledgement flag.
/// It shares the same bit position as `flags_end_stream`, but applies to different frame types.
pub const flags_ack: u8 = 0x1;
/// `END_HEADERS` frame flag bit.
/// This value is the raw wire bit mask for the end-of-headers flag.
/// Combine it with a frame header's `flags` field using bitwise operations.
pub const flags_end_headers: u8 = 0x4;
/// `PADDED` frame flag bit.
/// This value is the raw wire bit mask for the padded flag.
/// Combine it with a frame header's `flags` field using bitwise operations.
pub const flags_padded: u8 = 0x8;
/// `PRIORITY` frame flag bit.
/// This value is the raw wire bit mask for the priority flag.
/// Combine it with a frame header's `flags` field using bitwise operations.
pub const flags_priority: u8 = 0x20;

/// HTTP/2 frame type codes used on the wire.
/// The numeric values match the protocol encoding for standard frame types.
/// `.extension` is used for unknown or extension frame types.
/// This enum is stored as `u8` so it can be written to and read from frame headers directly.
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    extension = 0xff,
};

/// Decoded HTTP/2 frame header fields.
/// `length` is the payload length in bytes, `frame_type` is the frame type, and `flags` is the raw flags octet.
/// `stream_id` is the 31-bit stream identifier with the reserved bit cleared.
/// This struct owns no memory and is copied by value.
pub const FrameHeader = struct {
    length: u32,
    frame_type: FrameType,
    flags: u8,
    stream_id: u32,
};

/// Errors returned by frame header parsing and encoding helpers.
/// `NeedMoreData` indicates the input buffer is incomplete.
/// `FrameTooLarge` and `BufferTooSmall` report protocol-size and output-buffer validation failures.
/// `InvalidFrameType` and `ReservedBitSet` are reserved for callers that perform stricter validation.
pub const Error = error{
    NeedMoreData,
    InvalidFrameType,
    ReservedBitSet,
    FrameTooLarge,
    BufferTooSmall,
};

/// Parses a 9-byte HTTP/2 frame header from `raw` and returns its decoded fields.
/// Returns `error.NeedMoreData` if `raw` is shorter than the fixed header size, or `error.FrameTooLarge` if the encoded length exceeds `config.H2_MAX_FRAME_SIZE_BYTES`.
/// Unknown frame-type codes are mapped to `.extension` rather than failing the parse.
/// The reserved bit in the stream identifier is masked off in the returned `FrameHeader`.
pub fn parseFrameHeader(raw: []const u8) Error!FrameHeader {
    assert(raw.len > 0);
    assert(frame_header_size_bytes == 9);

    if (raw.len < frame_header_size_bytes) return error.NeedMoreData;

    const length = (@as(u32, raw[0]) << 16) |
        (@as(u32, raw[1]) << 8) |
        @as(u32, raw[2]);
    if (length > config.H2_MAX_FRAME_SIZE_BYTES) return error.FrameTooLarge;

    const frame_type: FrameType = switch (raw[3]) {
        0...9 => @enumFromInt(raw[3]),
        else => .extension,
    };

    const stream_id_with_reserved = std.mem.readInt(u32, raw[5..9], .big);
    const stream_id = stream_id_with_reserved & 0x7fff_ffff;

    return .{
        .length = length,
        .frame_type = frame_type,
        .flags = raw[4],
        .stream_id = stream_id,
    };
}

/// Serializes `header` into the HTTP/2 wire-format frame header in `out`.
/// Returns a slice backed by `out` containing exactly 9 bytes when successful.
/// Fails with `error.BufferTooSmall` if `out` cannot hold the fixed-size header, or `error.FrameTooLarge` if `header.length` exceeds `config.H2_MAX_FRAME_SIZE_BYTES`.
/// The caller must ensure `header.stream_id` fits in 31 bits; the reserved bit is not written.
pub fn buildFrameHeader(out: []u8, header: FrameHeader) Error![]const u8 {
    assert(out.len > 0);
    assert(header.stream_id <= 0x7fff_ffff);

    if (out.len < frame_header_size_bytes) return error.BufferTooSmall;
    if (header.length > config.H2_MAX_FRAME_SIZE_BYTES) return error.FrameTooLarge;

    out[0] = @intCast((header.length >> 16) & 0xff);
    out[1] = @intCast((header.length >> 8) & 0xff);
    out[2] = @intCast(header.length & 0xff);
    out[3] = @intFromEnum(header.frame_type);
    out[4] = header.flags;
    std.mem.writeInt(u32, out[5..9], header.stream_id, .big);

    return out[0..frame_header_size_bytes];
}

test "parseFrameHeader parses HEADERS frame" {
    const raw = [_]u8{ 0x00, 0x00, 0x05, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01 };
    const header = try parseFrameHeader(&raw);

    try std.testing.expectEqual(@as(u32, 5), header.length);
    try std.testing.expectEqual(FrameType.headers, header.frame_type);
    try std.testing.expectEqual(flags_end_headers, header.flags);
    try std.testing.expectEqual(@as(u32, 1), header.stream_id);
}

test "buildFrameHeader encodes frame header" {
    var out: [frame_header_size_bytes]u8 = undefined;
    const encoded = try buildFrameHeader(&out, .{
        .length = 8,
        .frame_type = .ping,
        .flags = flags_ack,
        .stream_id = 0,
    });

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x08, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00 }, encoded);
}

test "parseFrameHeader maps unknown frame type to extension" {
    const raw = [_]u8{ 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const header = try parseFrameHeader(&raw);

    try std.testing.expectEqual(FrameType.extension, header.frame_type);
    try std.testing.expectEqual(@as(u32, 0), header.length);
}

test "parseFrameHeader rejects oversized frame" {
    const raw = [_]u8{ 0x01, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expectError(error.FrameTooLarge, parseFrameHeader(&raw));
}

test "parseFrameHeader ignores reserved stream-id bit" {
    const raw = [_]u8{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x00, 0x00 };
    const header = try parseFrameHeader(&raw);
    try std.testing.expectEqual(@as(u32, 0), header.stream_id);
}

test "frame header roundtrip property over deterministic corpus" {
    var prng = std.Random.DefaultPrng.init(0xf12e_42aa);
    const random = prng.random();

    var buf: [frame_header_size_bytes]u8 = undefined;
    var iteration: u32 = 0;
    while (iteration < 512) : (iteration += 1) {
        const frame_type_raw = random.intRangeAtMost(u8, 0, 10);
        const frame_type: FrameType = if (frame_type_raw <= 9)
            @enumFromInt(frame_type_raw)
        else
            .extension;

        const header = FrameHeader{
            .length = random.intRangeAtMost(u32, 0, config.H2_MAX_FRAME_SIZE_BYTES),
            .frame_type = frame_type,
            .flags = random.int(u8),
            .stream_id = random.intRangeAtMost(u32, 0, 0x7fff_ffff),
        };
        const encoded = try buildFrameHeader(&buf, header);
        const decoded = try parseFrameHeader(encoded);

        try std.testing.expectEqual(header.length, decoded.length);
        try std.testing.expectEqual(header.flags, decoded.flags);
        try std.testing.expectEqual(header.stream_id, decoded.stream_id);
        try std.testing.expectEqual(header.frame_type, decoded.frame_type);
    }
}

test "parseFrameHeader fuzz corpus maintains invariants" {
    var prng = std.Random.DefaultPrng.init(0xface_b00c);
    const random = prng.random();

    var raw: [frame_header_size_bytes]u8 = undefined;
    var iteration: u32 = 0;
    while (iteration < 1024) : (iteration += 1) {
        random.bytes(&raw);
        _ = parseFrameHeader(&raw) catch |err| switch (err) {
            error.FrameTooLarge => continue,
            else => return err,
        };
    }
}
