//! HTTP/2 Frame Header Helpers
//!
//! Minimal bounded frame parsing/encoding for h2c request inspection.
//! TigerStyle: Fixed-size parsing, explicit bounds, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

pub const frame_header_size_bytes: u32 = 9;

pub const flags_end_stream: u8 = 0x1;
pub const flags_ack: u8 = 0x1;
pub const flags_end_headers: u8 = 0x4;
pub const flags_padded: u8 = 0x8;
pub const flags_priority: u8 = 0x20;

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
};

pub const FrameHeader = struct {
    length: u32,
    frame_type: FrameType,
    flags: u8,
    stream_id: u32,
};

pub const Error = error{
    NeedMoreData,
    InvalidFrameType,
    ReservedBitSet,
    FrameTooLarge,
    BufferTooSmall,
};

pub fn parseFrameHeader(raw: []const u8) Error!FrameHeader {
    assert(raw.len > 0);

    if (raw.len < frame_header_size_bytes) return error.NeedMoreData;

    const length = (@as(u32, raw[0]) << 16) |
        (@as(u32, raw[1]) << 8) |
        @as(u32, raw[2]);
    if (length > config.H2_MAX_FRAME_SIZE_BYTES) return error.FrameTooLarge;

    const frame_type: FrameType = switch (raw[3]) {
        0...9 => @enumFromInt(raw[3]),
        else => return error.InvalidFrameType,
    };

    const stream_id_with_reserved = std.mem.readInt(u32, raw[5..9], .big);
    if ((stream_id_with_reserved & 0x8000_0000) != 0) return error.ReservedBitSet;

    return .{
        .length = length,
        .frame_type = frame_type,
        .flags = raw[4],
        .stream_id = stream_id_with_reserved,
    };
}

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

test "parseFrameHeader rejects oversized frame" {
    const raw = [_]u8{ 0x01, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expectError(error.FrameTooLarge, parseFrameHeader(&raw));
}
