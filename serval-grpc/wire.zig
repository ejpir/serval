//! gRPC Message Envelope Helpers
//!
//! TigerStyle: Fixed-size 5-byte prefix, bounded lengths, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

pub const prefix_size_bytes: u32 = 5;

pub const MessagePrefix = struct {
    compressed: bool,
    length_bytes: u32,
};

pub const Error = error{
    NeedMoreData,
    BufferTooSmall,
    InvalidCompressionFlag,
    MessageTooLarge,
};

pub fn parsePrefix(raw: []const u8) Error!MessagePrefix {
    assert(prefix_size_bytes == 5);
    if (raw.len < prefix_size_bytes) return error.NeedMoreData;
    assert(raw.len >= prefix_size_bytes);

    const compression_flag = raw[0];
    if (compression_flag != 0 and compression_flag != 1) return error.InvalidCompressionFlag;

    const length_bytes = std.mem.readInt(u32, raw[1..5], .big);
    if (length_bytes > config.GRPC_MAX_MESSAGE_SIZE_BYTES) return error.MessageTooLarge;
    assert(length_bytes <= config.GRPC_MAX_MESSAGE_SIZE_BYTES);

    return .{
        .compressed = compression_flag == 1,
        .length_bytes = length_bytes,
    };
}

pub fn buildMessage(out: []u8, compressed: bool, payload: []const u8) Error![]const u8 {
    assert(prefix_size_bytes == 5);
    if (payload.len > config.GRPC_MAX_MESSAGE_SIZE_BYTES) return error.MessageTooLarge;

    const total_len: usize = prefix_size_bytes + payload.len;
    if (out.len < total_len) return error.BufferTooSmall;
    assert(total_len >= prefix_size_bytes);

    out[0] = if (compressed) 1 else 0;
    std.mem.writeInt(u32, out[1..5], @intCast(payload.len), .big);
    @memcpy(out[5..][0..payload.len], payload);
    return out[0..total_len];
}

pub fn parseMessage(raw: []const u8) Error![]const u8 {
    const prefix = try parsePrefix(raw);
    const total_len_u32: u32 = prefix_size_bytes + prefix.length_bytes;
    const total_len: usize = @intCast(total_len_u32);
    assert(prefix.length_bytes <= config.GRPC_MAX_MESSAGE_SIZE_BYTES);
    assert(total_len >= prefix_size_bytes);
    if (raw.len < total_len) return error.NeedMoreData;
    assert(total_len <= raw.len);
    return raw[prefix_size_bytes..total_len];
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
    std.mem.writeInt(u32, raw[1..5], config.GRPC_MAX_MESSAGE_SIZE_BYTES + 1, .big);
    try std.testing.expectError(error.MessageTooLarge, parsePrefix(&raw));
}

test "buildMessage rejects small output buffer" {
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, buildMessage(&out, false, "ping"));
}

test "buildMessage rejects oversized payload" {
    const oversize_len: usize = @as(usize, config.GRPC_MAX_MESSAGE_SIZE_BYTES) + 1;
    const payload = try std.testing.allocator.alloc(u8, oversize_len);
    defer std.testing.allocator.free(payload);

    var out: [prefix_size_bytes]u8 = undefined;
    try std.testing.expectError(error.MessageTooLarge, buildMessage(&out, false, payload));
}

test "parseMessage returns NeedMoreData for truncated payload" {
    var raw: [8]u8 = .{ 0, 0, 0, 0, 4, 'p', 'i', 'n' };
    try std.testing.expectError(error.NeedMoreData, parseMessage(&raw));
}

test "parseMessage propagates invalid prefix errors" {
    var raw: [6]u8 = .{ 9, 0, 0, 0, 1, 'x' };
    try std.testing.expectError(error.InvalidCompressionFlag, parseMessage(&raw));
}
