//! WebSocket Close Frame Validation
//!
//! RFC 6455 Sections 5.5.1 and 7.4 close-code helpers.
//! TigerStyle: Zero allocation, explicit validation, bounded parsing.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const config = serval_core.config;

pub const normal_closure: u16 = 1000;
pub const going_away: u16 = 1001;
pub const protocol_error: u16 = 1002;
pub const unsupported_data: u16 = 1003;
pub const invalid_frame_payload_data: u16 = 1007;
pub const policy_violation: u16 = 1008;
pub const message_too_big: u16 = 1009;
pub const mandatory_extension: u16 = 1010;
pub const internal_error: u16 = 1011;
pub const service_restart: u16 = 1012;
pub const try_again_later: u16 = 1013;
pub const bad_gateway: u16 = 1014;

pub const CloseInfo = struct {
    code: ?u16,
    reason: []const u8,
};

pub const CloseError = error{
    InvalidClosePayload,
    InvalidCloseCode,
    InvalidCloseReason,
    PayloadTooLarge,
    BufferTooSmall,
};

pub fn validateCloseCode(code: u16) CloseError!void {
    if (code < 1000) return error.InvalidCloseCode;

    switch (code) {
        1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014 => return,
        1004, 1005, 1006, 1015 => return error.InvalidCloseCode,
        else => {
            if (code >= 3000 and code <= 4999) return;
            return error.InvalidCloseCode;
        },
    }
}

pub fn parseClosePayload(payload: []const u8) CloseError!CloseInfo {
    if (payload.len == 0) {
        return .{ .code = null, .reason = "" };
    }
    if (payload.len == 1) return error.InvalidClosePayload;
    if (payload.len > config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES) {
        return error.PayloadTooLarge;
    }

    const code = readBigEndianU16(payload[0..2]);
    try validateCloseCode(code);

    const reason = payload[2..];
    if (!std.unicode.utf8ValidateSlice(reason)) {
        return error.InvalidCloseReason;
    }

    return .{ .code = code, .reason = reason };
}

pub fn buildClosePayload(out: []u8, code: u16, reason: []const u8) CloseError![]const u8 {
    assert(out.len > 0);

    try validateCloseCode(code);
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidCloseReason;

    const total_len: usize = 2 + reason.len;
    if (total_len > config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES) {
        return error.PayloadTooLarge;
    }
    if (out.len < total_len) return error.BufferTooSmall;

    writeBigEndianU16(out[0..2], code);
    if (reason.len > 0) {
        @memcpy(out[2..][0..reason.len], reason);
    }

    return out[0..total_len];
}

fn readBigEndianU16(bytes: []const u8) u16 {
    assert(bytes.len == 2);

    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

fn writeBigEndianU16(out: []u8, value: u16) void {
    assert(out.len == 2);

    out[0] = @intCast((value >> 8) & 0xFF);
    out[1] = @intCast(value & 0xFF);
}

test "validateCloseCode accepts normal and private-use codes" {
    try validateCloseCode(normal_closure);
    try validateCloseCode(3999);
    try validateCloseCode(4500);
}

test "validateCloseCode rejects reserved codes" {
    try std.testing.expectError(error.InvalidCloseCode, validateCloseCode(1005));
    try std.testing.expectError(error.InvalidCloseCode, validateCloseCode(1006));
    try std.testing.expectError(error.InvalidCloseCode, validateCloseCode(1015));
}

test "parseClosePayload accepts empty payload" {
    const info = try parseClosePayload(&[_]u8{});
    try std.testing.expectEqual(@as(?u16, null), info.code);
    try std.testing.expectEqualStrings("", info.reason);
}

test "parseClosePayload accepts code and UTF-8 reason" {
    const payload = [_]u8{ 0x03, 0xE8, 'o', 'k' };
    const info = try parseClosePayload(&payload);
    try std.testing.expectEqual(@as(?u16, normal_closure), info.code);
    try std.testing.expectEqualStrings("ok", info.reason);
}

test "parseClosePayload rejects one-byte payload" {
    const payload = [_]u8{0x03};
    try std.testing.expectError(error.InvalidClosePayload, parseClosePayload(&payload));
}

test "parseClosePayload rejects invalid close code" {
    const payload = [_]u8{ 0x03, 0xED };
    try std.testing.expectError(error.InvalidCloseCode, parseClosePayload(&payload));
}

test "parseClosePayload rejects invalid UTF-8 reason" {
    const payload = [_]u8{ 0x03, 0xE8, 0xFF };
    try std.testing.expectError(error.InvalidCloseReason, parseClosePayload(&payload));
}

test "buildClosePayload encodes code and reason" {
    var out: [config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;
    const encoded = try buildClosePayload(&out, normal_closure, "bye");

    try std.testing.expectEqual(@as(usize, 5), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x03), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0xE8), encoded[1]);
    try std.testing.expectEqual(@as(u8, 'b'), encoded[2]);
}
