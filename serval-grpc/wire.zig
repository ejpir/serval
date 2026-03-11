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
    assert(raw.len > 0);
    if (raw.len < prefix_size_bytes) return error.NeedMoreData;
    if (raw[0] != 0 and raw[0] != 1) return error.InvalidCompressionFlag;

    const length_bytes = std.mem.readInt(u32, raw[1..5], .big);
    if (length_bytes > config.GRPC_MAX_MESSAGE_SIZE_BYTES) return error.MessageTooLarge;

    return .{
        .compressed = raw[0] == 1,
        .length_bytes = length_bytes,
    };
}

pub fn buildMessage(out: []u8, compressed: bool, payload: []const u8) Error![]const u8 {
    assert(payload.len <= config.GRPC_MAX_MESSAGE_SIZE_BYTES);

    if (out.len < prefix_size_bytes + payload.len) return error.BufferTooSmall;
    if (payload.len > config.GRPC_MAX_MESSAGE_SIZE_BYTES) return error.MessageTooLarge;

    out[0] = if (compressed) 1 else 0;
    std.mem.writeInt(u32, out[1..5], @intCast(payload.len), .big);
    @memcpy(out[5..][0..payload.len], payload);
    return out[0 .. prefix_size_bytes + payload.len];
}

pub fn parseMessage(raw: []const u8) Error![]const u8 {
    const prefix = try parsePrefix(raw);
    const total_len: usize = prefix_size_bytes + prefix.length_bytes;
    if (raw.len < total_len) return error.NeedMoreData;
    return raw[prefix_size_bytes..total_len];
}

test "buildMessage and parseMessage round-trip" {
    var buf: [64]u8 = undefined;
    const built = try buildMessage(&buf, false, "ping");
    const payload = try parseMessage(built);
    try std.testing.expectEqualStrings("ping", payload);
}
