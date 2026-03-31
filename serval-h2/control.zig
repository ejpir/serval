//! HTTP/2 Control-Frame Helpers
//!
//! Bounded parsing and encoding for connection-level control frames used by the
//! server/client HTTP/2 runtimes.
//! TigerStyle: Fixed-size payloads, explicit validation, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const frame = @import("frame.zig");
const limits = @import("limits.zig");

/// Size, in bytes, of an HTTP/2 PING payload.
/// HTTP/2 requires PING frames to carry exactly 8 octets of opaque data.
/// Use this constant when validating or constructing PING frame payload buffers.
/// No allocation or ownership is involved.
pub const ping_payload_size_bytes: u32 = 8;
/// Fixed RST_STREAM payload size in bytes.
/// The payload contains a single 4-byte error code.
pub const rst_stream_payload_size_bytes: u32 = 4;
/// Fixed WINDOW_UPDATE payload size in bytes.
/// The payload contains a single 4-byte window increment.
pub const window_update_payload_size_bytes: u32 = 4;
/// Minimum GOAWAY payload size in bytes before optional debug data.
/// This covers the 4-byte last-stream-id field and the 4-byte error-code field.
pub const goaway_min_payload_size_bytes: u32 = 8;

comptime {
    assert(ping_payload_size_bytes == 8);
}

/// HTTP/2 error codes used by GOAWAY and RST_STREAM frames.
/// The numeric values are the on-wire 32-bit codes defined by the protocol.
/// Unknown raw codes are intentionally left out of the enum.
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

/// Parsed or constructed GOAWAY frame data.
/// `debug_data` borrows from frame storage; it is not owned by this struct.
/// Use `errorCode()` to convert `error_code_raw` to a typed `ErrorCode` when possible.
pub const GoAway = struct {
    last_stream_id: u32,
    error_code_raw: u32,
    debug_data: []const u8,

    /// Map a GOAWAY error code to the corresponding `ErrorCode` value.
    /// Returns `null` when `error_code_raw` is not one of the known enum tags.
    /// The method asserts that `last_stream_id` is 31-bit clean and that `debug_data` fits in the HTTP/2 wire-format frame-length field.
    pub fn errorCode(self: GoAway) ?ErrorCode {
        assert(self.last_stream_id <= 0x7fff_ffff);
        assert(self.debug_data.len <= frame.max_frame_payload_size_bytes);
        return std.meta.intToEnum(ErrorCode, self.error_code_raw) catch null;
    }
};

/// Errors returned by the control-frame parse and build helpers in this module.
/// `InvalidStreamId` reports a frame that uses a forbidden stream identifier.
/// `InvalidPayloadLength` reports a payload with the wrong size, and `InvalidIncrement` reports an invalid WINDOW_UPDATE increment.
pub const Error = error{
    InvalidStreamId,
    InvalidPayloadLength,
    InvalidIncrement,
} || frame.Error;

/// Build an ACK-only SETTINGS frame into `out`.
/// The frame is sent on stream 0 with an empty payload.
/// Returns the written frame prefix in the caller-provided buffer.
pub fn buildSettingsAckFrame(out: []u8) Error![]const u8 {
    assert(out.len > 0);
    return buildFrame(out, .settings, frame.flags_ack, 0, &[_]u8{});
}

/// Parse a PING frame from the supplied header and payload.
/// The header must describe a PING frame on stream 0 with an 8-byte payload.
/// Returns `error.InvalidStreamId` or `error.InvalidPayloadLength` when the frame is malformed.
/// On success, returns a copied 8-byte opaque payload array.
pub fn parsePingFrame(header: frame.FrameHeader, payload: []const u8) Error![ping_payload_size_bytes]u8 {
    assert(header.length == payload.len);
    assert(header.frame_type == .ping);

    if (header.stream_id != 0) return error.InvalidStreamId;
    if (payload.len != ping_payload_size_bytes) return error.InvalidPayloadLength;

    var opaque_data: [ping_payload_size_bytes]u8 = undefined;
    @memcpy(opaque_data[0..], payload);
    return opaque_data;
}

/// Build a PING frame into `out` with the provided flags and opaque payload.
/// `flags` may only set the ACK bit; the frame is always sent on stream 0.
/// `opaque_data` is copied verbatim into the caller-provided buffer.
pub fn buildPingFrame(out: []u8, flags: u8, opaque_data: [ping_payload_size_bytes]u8) Error![]const u8 {
    assert(out.len > 0);
    assert(flags & ~frame.flags_ack == 0);
    return buildFrame(out, .ping, flags, 0, &opaque_data);
}

/// Parse a WINDOW_UPDATE frame from the supplied header and payload.
/// The payload must be exactly 4 bytes and encode a nonzero 31-bit increment.
/// Returns `error.InvalidPayloadLength` for the wrong size and `error.InvalidIncrement` for an invalid value.
/// On success, returns the parsed window increment.
pub fn parseWindowUpdateFrame(header: frame.FrameHeader, payload: []const u8) Error!u32 {
    assert(header.length == payload.len);
    assert(header.frame_type == .window_update);

    if (payload.len != window_update_payload_size_bytes) return error.InvalidPayloadLength;

    const raw_increment = std.mem.readInt(u32, payload[0..window_update_payload_size_bytes], .big);
    const increment = raw_increment & 0x7fff_ffff;
    if (increment == 0 or increment > config.H2_MAX_WINDOW_SIZE_BYTES) {
        return error.InvalidIncrement;
    }
    return increment;
}

/// Build a WINDOW_UPDATE frame into `out` for the given stream.
/// `stream_id` must fit in 31 bits and `increment` must be in the range `1..=config.H2_MAX_WINDOW_SIZE_BYTES`.
/// Returns `error.InvalidIncrement` when the window increment is zero or exceeds the configured maximum.
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

/// Parse an RST_STREAM frame from the supplied header and payload.
/// The header must describe an RST_STREAM frame with a nonzero `stream_id` and a 4-byte payload.
/// Returns `error.InvalidStreamId` or `error.InvalidPayloadLength` when the frame is malformed.
/// On success, returns the raw 32-bit error code stored in the payload.
pub fn parseRstStreamFrame(header: frame.FrameHeader, payload: []const u8) Error!u32 {
    assert(header.length == payload.len);
    assert(header.frame_type == .rst_stream);

    if (header.stream_id == 0) return error.InvalidStreamId;
    if (payload.len != rst_stream_payload_size_bytes) return error.InvalidPayloadLength;

    return std.mem.readInt(u32, payload[0..rst_stream_payload_size_bytes], .big);
}

/// Build an RST_STREAM frame into `out` for the given stream.
/// `stream_id` must be nonzero; `error_code_raw` is written as a 4-byte big-endian payload.
/// Returns the written frame prefix in the caller-provided buffer.
pub fn buildRstStreamFrame(out: []u8, stream_id: u32, error_code_raw: u32) Error![]const u8 {
    assert(out.len > 0);
    assert(stream_id > 0);

    var payload: [rst_stream_payload_size_bytes]u8 = undefined;
    std.mem.writeInt(u32, payload[0..rst_stream_payload_size_bytes], error_code_raw, .big);
    return buildFrame(out, .rst_stream, 0, stream_id, &payload);
}

/// Parse a GOAWAY frame from the supplied header and payload.
/// The header must describe a GOAWAY frame with `stream_id == 0`, and the payload must be at least 8 bytes.
/// Returns `error.InvalidStreamId` or `error.InvalidPayloadLength` when the frame is malformed.
/// The returned `debug_data` slice borrows from `payload` and does not allocate.
pub fn parseGoAwayFrame(header: frame.FrameHeader, payload: []const u8) Error!GoAway {
    assert(header.length == payload.len);
    assert(header.frame_type == .goaway);

    if (header.stream_id != 0) return error.InvalidStreamId;
    if (payload.len < goaway_min_payload_size_bytes) return error.InvalidPayloadLength;

    const raw_last_stream_id = std.mem.readInt(u32, payload[0..4], .big);
    const last_stream_id = raw_last_stream_id & 0x7fff_ffff;

    return .{
        .last_stream_id = last_stream_id,
        .error_code_raw = std.mem.readInt(u32, payload[4..8], .big),
        .debug_data = payload[8..],
    };
}

/// Build a GOAWAY frame into `out` and return the written prefix.
/// `last_stream_id` must fit in 31 bits; `debug_data` is copied into the caller-provided buffer.
/// Returns `error.BufferTooSmall` if `out` cannot hold the header and payload.
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

test "parseWindowUpdateFrame ignores reserved increment bit" {
    const header = frame.FrameHeader{
        .length = window_update_payload_size_bytes,
        .frame_type = .window_update,
        .flags = 0,
        .stream_id = 0,
    };
    const payload = [_]u8{ 0x80, 0x00, 0x00, 0x01 };

    const increment = try parseWindowUpdateFrame(header, &payload);
    try std.testing.expectEqual(@as(u32, 1), increment);
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

test "parseGoAwayFrame ignores reserved last-stream-id bit" {
    const header = frame.FrameHeader{
        .length = goaway_min_payload_size_bytes,
        .frame_type = .goaway,
        .flags = 0,
        .stream_id = 0,
    };
    const payload = [_]u8{
        0x80, 0x00, 0x00, 0x07,
        0x00, 0x00, 0x00, 0x00,
    };

    const goaway = try parseGoAwayFrame(header, &payload);
    try std.testing.expectEqual(@as(u32, 7), goaway.last_stream_id);
}
