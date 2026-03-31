//! WebSocket Close Frame Validation
//!
//! RFC 6455 Sections 5.5.1 and 7.4 close-code helpers.
//! TigerStyle: Zero allocation, explicit validation, bounded parsing.

const std = @import("std");
const assert = std.debug.assert;

const limits = @import("limits.zig");

/// WebSocket close code `1000`, indicating a normal, graceful shutdown.
/// Use this when the connection is ending without error and no further frames are expected.
/// This is a constant status code value; it does not allocate or fail.
pub const normal_closure: u16 = 1000;
/// WebSocket close code `1001` (`going_away`).
/// Use this when the endpoint is shutting down or otherwise leaving the connection.
pub const going_away: u16 = 1001;
/// WebSocket close code `1002` (`protocol_error`).
/// Use this when the connection must be closed because the peer violated the WebSocket protocol.
pub const protocol_error: u16 = 1002;
/// WebSocket close code `1003` (`unsupported_data`).
/// Use this when the peer sent a data type that this endpoint does not support.
pub const unsupported_data: u16 = 1003;
/// WebSocket close code `1007` (`invalid_frame_payload_data`).
/// Use this when the peer sent payload data that is not valid for the negotiated message type.
pub const invalid_frame_payload_data: u16 = 1007;
/// WebSocket close code `1008` (`policy_violation`).
/// Use this when the endpoint is closing the connection because a policy rule was violated.
pub const policy_violation: u16 = 1008;
/// WebSocket close code `1009` (`message_too_big`).
/// Use this when the received message exceeds the implementation's supported size.
pub const message_too_big: u16 = 1009;
/// WebSocket close code `1010` (`mandatory_extension`).
/// Use this when the peer did not negotiate an extension that is required for the connection.
pub const mandatory_extension: u16 = 1010;
/// WebSocket close code `1011` (`internal_error`).
/// Use this when the endpoint is terminating the connection because of an unexpected internal failure.
pub const internal_error: u16 = 1011;
/// WebSocket close code `1012` (`service_restart`).
/// Use this when the service is restarting and the connection should be re-established later.
pub const service_restart: u16 = 1012;
/// WebSocket close code `1013` (`try_again_later`).
/// Use this to signal that the peer should retry the operation later.
pub const try_again_later: u16 = 1013;
/// WebSocket close code `1014` (`bad_gateway`).
/// Use this when a gateway or proxy received an invalid response from an upstream peer.
pub const bad_gateway: u16 = 1014;

/// Parsed WebSocket close information.
/// `code` is `null` when the close frame carried no code, and `reason` aliases the original payload bytes.
/// The `reason` slice is only valid while the source payload remains alive.
pub const CloseInfo = struct {
    code: ?u16,
    reason: []const u8,
};

/// Errors returned by close-payload parsing, validation, and encoding helpers.
/// `InvalidClosePayload` covers structurally malformed payloads, while `InvalidCloseCode` and `InvalidCloseReason` cover semantic validation failures.
/// `PayloadTooLarge` is returned when the control-frame size limit would be exceeded, and `BufferTooSmall` indicates the destination buffer cannot hold the payload.
pub const CloseError = error{
    InvalidClosePayload,
    InvalidCloseCode,
    InvalidCloseReason,
    PayloadTooLarge,
    BufferTooSmall,
};

/// Validates that `code` is an acceptable WebSocket close code.
/// Accepts the standard registered close codes and any private-use code in the `3000..=4999` range.
/// Rejects reserved codes such as `1004`, `1005`, `1006`, and `1015`, as well as values below `1000`.
/// Returns `error.InvalidCloseCode` when the code cannot be used in a close frame.
pub fn validateCloseCode(code: u16) CloseError!void {
    const is_reserved = switch (code) {
        1004, 1005, 1006, 1015 => true,
        else => false,
    };
    const is_private = code >= 3000 and code <= 4999;
    assert(!(is_reserved and is_private));
    assert(!(code < 1000 and is_private));

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

/// Parses a WebSocket close control payload into a `CloseInfo` value.
/// Returns a null code and empty reason for an empty payload; a 1-byte payload is rejected as invalid.
/// The returned reason slice aliases the input payload, so the payload must remain alive for as long as the result is used.
/// Fails with `error.InvalidClosePayload`, `error.InvalidCloseCode`, `error.InvalidCloseReason`, or `error.PayloadTooLarge`.
pub fn parseClosePayload(payload: []const u8) CloseError!CloseInfo {
    assert(payload.len <= std.math.maxInt(u32));

    if (payload.len == 0) {
        return .{ .code = null, .reason = "" };
    }
    if (payload.len == 1) return error.InvalidClosePayload;
    if (payload.len > limits.max_control_payload_size_bytes) {
        return error.PayloadTooLarge;
    }

    const code = readBigEndianU16(payload[0..2]);
    try validateCloseCode(code);

    assert(payload.len >= 2);
    const reason = payload[2..];
    if (!std.unicode.utf8ValidateSlice(reason)) {
        return error.InvalidCloseReason;
    }

    return .{ .code = code, .reason = reason };
}

/// Builds a WebSocket close control payload into `out`.
/// Writes the 2-byte close code followed by the UTF-8 reason, and returns the initialized slice.
/// The returned slice aliases `out`; the caller owns the buffer and must keep it alive for the result's lifetime.
/// Fails with `error.InvalidCloseCode`, `error.InvalidCloseReason`, `error.PayloadTooLarge`, or `error.BufferTooSmall`.
pub fn buildClosePayload(out: []u8, code: u16, reason: []const u8) CloseError![]const u8 {
    assert(out.len > 0);
    assert(out.len <= std.math.maxInt(u32));
    assert(reason.len <= std.math.maxInt(u32));

    try validateCloseCode(code);
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidCloseReason;

    const reason_len_bytes: u32 = @intCast(reason.len);
    const total_len_bytes: u32 = 2 + reason_len_bytes;
    if (total_len_bytes > limits.max_control_payload_size_bytes) {
        return error.PayloadTooLarge;
    }
    if (out.len < @as(usize, @intCast(total_len_bytes))) return error.BufferTooSmall;

    writeBigEndianU16(out[0..2], code);
    if (reason.len > 0) {
        @memcpy(out[2..][0..reason.len], reason);
    }

    return out[0..@intCast(total_len_bytes)];
}

fn readBigEndianU16(bytes: []const u8) u16 {
    assert(bytes.len == 2);

    const value = (@as(u16, bytes[0]) << 8) | bytes[1];
    assert(@as(u8, @intCast((value >> 8) & 0xFF)) == bytes[0]);
    return value;
}

fn writeBigEndianU16(out: []u8, value: u16) void {
    assert(out.len == 2);

    out[0] = @intCast((value >> 8) & 0xFF);
    out[1] = @intCast(value & 0xFF);
    assert(readBigEndianU16(out) == value);
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

test "parseClosePayload rejects payload larger than control frame maximum" {
    var payload: [limits.max_control_payload_size_bytes + 1]u8 = undefined;
    payload[0] = 0x03;
    payload[1] = 0xE8;
    @memset(payload[2..], 'a');

    try std.testing.expectError(error.PayloadTooLarge, parseClosePayload(&payload));
}

test "buildClosePayload encodes code and reason" {
    var out: [limits.max_control_payload_size_bytes]u8 = undefined;
    const encoded = try buildClosePayload(&out, normal_closure, "bye");

    try std.testing.expectEqual(@as(usize, 5), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x03), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0xE8), encoded[1]);
    try std.testing.expectEqual(@as(u8, 'b'), encoded[2]);
}

test "buildClosePayload rejects too-small output buffer" {
    var out: [4]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        buildClosePayload(&out, normal_closure, "hello"),
    );
}

test "buildClosePayload rejects payload larger than control frame maximum" {
    var out: [limits.max_control_payload_size_bytes]u8 = undefined;
    var reason: [124]u8 = undefined;
    @memset(&reason, 'a');

    try std.testing.expectError(
        error.PayloadTooLarge,
        buildClosePayload(&out, normal_closure, &reason),
    );
}
