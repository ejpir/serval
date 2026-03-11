//! HTTP/2 Control-Frame Helpers
//!
//! Bounded parsing and encoding for connection-level control frames used by the
//! server/client HTTP/2 runtimes.
//! TigerStyle: Fixed-size payloads, explicit validation, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const frame = @import("frame.zig");

pub const ping_payload_size_bytes: u32 = 8;
pub const rst_stream_payload_size_bytes: u32 = 4;
pub const window_update_payload_size_bytes: u32 = 4;
pub const goaway_min_payload_size_bytes: u32 = 8;

pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
};

pub const GoAway = struct {
    last_stream_id: u32,
    error_code_raw: u32,
    debug_data: []const u8,

    pub fn errorCode(self: GoAway) ?ErrorCode {
        return std.meta.intToEnum(ErrorCode, self.error_code_raw) catch null;
    }
};

pub const Error = error{
    InvalidStreamId,
    InvalidPayloadLength,
    InvalidIncrement,
} || frame.Error;

pub fn buildSettingsAckFrame(out: []u8) Error![]const u8 {
    assert(out.len > 0);
    return buildFrame(out, .settings, frame.flags_ack, 0, &[_]u8{});
}

pub fn parsePingFrame(header: frame.FrameHeader, payload: []const u8) Error![ping_payload_size_bytes]u8 {
    assert(header.length == payload.len);
    assert(header.frame_type == .ping);

    if (header.stream_id != 0) return error.InvalidStreamId;
    if (payload.len != ping_payload_size_bytes) return error.InvalidPayloadLength;

    var opaque_data: [ping_payload_size_bytes]u8 = undefined;
    @memcpy(opaque_data[0..], payload);
    return opaque_data;
}

pub fn buildPingFrame(out: []u8, flags: u8, opaque_data: [ping_payload_size_bytes]u8) Error![]const u8 {
    assert(out.len > 0);
    return buildFrame(out, .ping, flags, 0, &opaque_data);
}

pub fn parseWindowUpdateFrame(header: frame.FrameHeader, payload: []const u8) Error!u32 {
    assert(header.length == payload.len);
    assert(header.frame_type == .window_update);

    if (payload.len != window_update_payload_size_bytes) return error.InvalidPayloadLength;

    const raw_increment = std.mem.readInt(u32, payload[0..window_update_payload_size_bytes], .big);
    if ((raw_increment & 0x8000_0000) != 0) return error.ReservedBitSet;

    const increment = raw_increment & 0x7fff_ffff;
    if (increment == 0 or increment > config.H2_MAX_WINDOW_SIZE_BYTES) {
        return error.InvalidIncrement;
    }
    return increment;
}

pub fn buildWindowUpdateFrame(out: []u8, stream_id: u32, increment: u32) Error![]const u8 {
    assert(out.len > 0);
    assert(stream_id <= 0x7fff_ffff);

    if (increment == 0 or increment > config.H2_MAX_WINDOW_SIZE_BYTES) {
        return error.InvalidIncrement;
    }

    var payload: [window_update_payload_size_bytes]u8 = undefined;
    std.mem.writeInt(u32, payload[0..window_update_payload_size_bytes], increment, .big);
    return buildFrame(out, .window_update, 0, stream_id, &payload);
}

pub fn parseRstStreamFrame(header: frame.FrameHeader, payload: []const u8) Error!u32 {
    assert(header.length == payload.len);
    assert(header.frame_type == .rst_stream);

    if (header.stream_id == 0) return error.InvalidStreamId;
    if (payload.len != rst_stream_payload_size_bytes) return error.InvalidPayloadLength;

    return std.mem.readInt(u32, payload[0..rst_stream_payload_size_bytes], .big);
}

pub fn buildRstStreamFrame(out: []u8, stream_id: u32, error_code_raw: u32) Error![]const u8 {
    assert(out.len > 0);
    assert(stream_id > 0);

    var payload: [rst_stream_payload_size_bytes]u8 = undefined;
    std.mem.writeInt(u32, payload[0..rst_stream_payload_size_bytes], error_code_raw, .big);
    return buildFrame(out, .rst_stream, 0, stream_id, &payload);
}

pub fn parseGoAwayFrame(header: frame.FrameHeader, payload: []const u8) Error!GoAway {
    assert(header.length == payload.len);
    assert(header.frame_type == .goaway);

    if (header.stream_id != 0) return error.InvalidStreamId;
    if (payload.len < goaway_min_payload_size_bytes) return error.InvalidPayloadLength;

    const raw_last_stream_id = std.mem.readInt(u32, payload[0..4], .big);
    if ((raw_last_stream_id & 0x8000_0000) != 0) return error.ReservedBitSet;

    return .{
        .last_stream_id = raw_last_stream_id,
        .error_code_raw = std.mem.readInt(u32, payload[4..8], .big),
        .debug_data = payload[8..],
    };
}

pub fn buildGoAwayFrame(
    out: []u8,
    last_stream_id: u32,
    error_code_raw: u32,
    debug_data: []const u8,
) Error![]const u8 {
    assert(out.len > 0);
    assert(last_stream_id <= 0x7fff_ffff);

    const payload_len = goaway_min_payload_size_bytes + debug_data.len;
    if (frame.frame_header_size_bytes + payload_len > out.len) return error.BufferTooSmall;

    const header = try frame.buildFrameHeader(out[0..frame.frame_header_size_bytes], .{
        .length = @intCast(payload_len),
        .frame_type = .goaway,
        .flags = 0,
        .stream_id = 0,
    });
    std.mem.writeInt(u32, out[header.len..][0..4], last_stream_id, .big);
    std.mem.writeInt(u32, out[header.len + 4 ..][0..4], error_code_raw, .big);
    @memcpy(out[header.len + goaway_min_payload_size_bytes ..][0..debug_data.len], debug_data);
    return out[0 .. header.len + payload_len];
}

fn buildFrame(
    out: []u8,
    frame_type: frame.FrameType,
    flags: u8,
    stream_id: u32,
    payload: []const u8,
) Error![]const u8 {
    assert(out.len > 0);
    assert(stream_id <= 0x7fff_ffff);

    if (frame.frame_header_size_bytes + payload.len > out.len) return error.BufferTooSmall;

    const header = try frame.buildFrameHeader(out[0..frame.frame_header_size_bytes], .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    @memcpy(out[header.len..][0..payload.len], payload);
    return out[0 .. header.len + payload.len];
}

test "buildSettingsAckFrame encodes empty ACK settings frame" {
    var buf: [frame.frame_header_size_bytes]u8 = undefined;
    const encoded = try buildSettingsAckFrame(&buf);
    const header = try frame.parseFrameHeader(encoded);

    try std.testing.expectEqual(frame.FrameType.settings, header.frame_type);
    try std.testing.expectEqual(frame.flags_ack, header.flags);
    try std.testing.expectEqual(@as(u32, 0), header.length);
}

test "ping frame round-trips opaque payload" {
    var buf: [frame.frame_header_size_bytes + ping_payload_size_bytes]u8 = undefined;
    const opaque_data = [ping_payload_size_bytes]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const encoded = try buildPingFrame(&buf, frame.flags_ack, opaque_data);
    const header = try frame.parseFrameHeader(encoded);
    const decoded = try parsePingFrame(header, encoded[frame.frame_header_size_bytes..]);

    try std.testing.expectEqualSlices(u8, &opaque_data, &decoded);
}

test "parseWindowUpdateFrame rejects zero increment" {
    const header = frame.FrameHeader{
        .length = window_update_payload_size_bytes,
        .frame_type = .window_update,
        .flags = 0,
        .stream_id = 0,
    };
    const payload = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

    try std.testing.expectError(error.InvalidIncrement, parseWindowUpdateFrame(header, &payload));
}

test "goaway frame round-trips last stream and error code" {
    var buf: [frame.frame_header_size_bytes + goaway_min_payload_size_bytes + 3]u8 = undefined;
    const encoded = try buildGoAwayFrame(&buf, 7, @intFromEnum(ErrorCode.protocol_error), "dbg");
    const header = try frame.parseFrameHeader(encoded);
    const goaway = try parseGoAwayFrame(header, encoded[frame.frame_header_size_bytes..]);

    try std.testing.expectEqual(@as(u32, 7), goaway.last_stream_id);
    try std.testing.expectEqual(@as(u32, @intFromEnum(ErrorCode.protocol_error)), goaway.error_code_raw);
    try std.testing.expectEqualStrings("dbg", goaway.debug_data);
}
