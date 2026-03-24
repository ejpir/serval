//! WebSocket Subprotocol Negotiation Helpers
//!
//! RFC 6455 Section 4.2.2 subprotocol token validation.
//! TigerStyle: Zero allocation, bounded token parsing, explicit validation.

const std = @import("std");
const assert = std.debug.assert;

pub const SubprotocolError = error{
    InvalidToken,
    EmptyToken,
    TooManyTokens,
    ProtocolNotOffered,
};

pub fn validateHeaderValue(value: []const u8) SubprotocolError!void {
    assert(value.len > 0);
    assert(value.len <= std.math.maxInt(u32));

    var tokens = std.mem.splitScalar(u8, value, ',');
    var count: u32 = 0;
    const max_tokens: u32 = 64;

    while (tokens.next()) |token| : (count += 1) {
        if (count >= max_tokens) return error.TooManyTokens;

        const trimmed = std.mem.trim(u8, token, " \t");
        if (trimmed.len == 0) return error.EmptyToken;
        if (!isToken(trimmed)) return error.InvalidToken;
    }
    assert(count <= max_tokens);
}

pub fn headerOffersProtocol(value: []const u8, protocol: []const u8) bool {
    assert(protocol.len > 0);
    assert(value.len <= std.math.maxInt(u32));

    var tokens = std.mem.splitScalar(u8, value, ',');
    var count: u32 = 0;
    const max_tokens: u32 = 64;
    assert(max_tokens > 0);

    while (tokens.next()) |token| : (count += 1) {
        if (count >= max_tokens) break;

        const trimmed = std.mem.trim(u8, token, " \t");
        if (std.mem.eql(u8, trimmed, protocol)) return true;
    }

    return false;
}

pub fn validateSelection(offered_header_value: ?[]const u8, selected_protocol: ?[]const u8) SubprotocolError!void {
    assert(selected_protocol == null or selected_protocol.?.len <= std.math.maxInt(u32));

    if (selected_protocol == null) return;

    const selected = selected_protocol.?;
    assert(selected.len > 0);

    if (!isToken(selected)) return error.InvalidToken;

    const offered = offered_header_value orelse return error.ProtocolNotOffered;
    try validateHeaderValue(offered);

    if (!headerOffersProtocol(offered, selected)) return error.ProtocolNotOffered;
}

pub fn isToken(value: []const u8) bool {
    assert(value.len <= std.math.maxInt(u32));

    if (value.len == 0) return false;
    assert(value.len > 0);

    for (value) |ch| {
        const valid = switch (ch) {
            '!',
            '#',
            '$',
            '%',
            '&',
            '\'',
            '*',
            '+',
            '-',
            '.',
            '0'...'9',
            'A'...'Z',
            '^',
            '_',
            '`',
            'a'...'z',
            '|',
            '~',
            => true,
            else => false,
        };
        if (!valid) return false;
    }

    return true;
}

test "validateHeaderValue accepts valid token list" {
    try validateHeaderValue("chat, superchat, jsonrpc");
}

test "validateHeaderValue rejects empty token" {
    try std.testing.expectError(error.EmptyToken, validateHeaderValue("chat, ,jsonrpc"));
}

test "validateHeaderValue rejects invalid token" {
    try std.testing.expectError(error.InvalidToken, validateHeaderValue("chat, bad token"));
}

test "headerOffersProtocol finds exact offered protocol" {
    try std.testing.expect(headerOffersProtocol("chat, superchat", "superchat"));
    try std.testing.expect(!headerOffersProtocol("chat, superchat", "graphql-ws"));
}

test "validateSelection accepts offered protocol" {
    try validateSelection("chat, superchat", "chat");
}

test "validateSelection rejects protocol not offered" {
    try std.testing.expectError(error.ProtocolNotOffered, validateSelection("chat, superchat", "graphql-ws"));
}

test "validateHeaderValue matrix" {
    const cases = [_]struct {
        value: []const u8,
        expected_error: ?SubprotocolError,
    }{
        .{ .value = "chat, superchat", .expected_error = null },
        .{ .value = "chat", .expected_error = null },
        .{ .value = "chat, ,jsonrpc", .expected_error = error.EmptyToken },
        .{ .value = "chat, bad token", .expected_error = error.InvalidToken },
        .{ .value = " chat", .expected_error = null },
    };

    var index: usize = 0;
    while (index < cases.len) : (index += 1) {
        const result = validateHeaderValue(cases[index].value);
        if (cases[index].expected_error) |expected_error| {
            try std.testing.expectError(expected_error, result);
        } else {
            try result;
        }
    }
}

test "fuzz isToken and headerOffersProtocol remain bounded" {
    var prng = std.Random.DefaultPrng.init(0xc149_00d1_11ef_92a4);
    const random = prng.random();

    var token_buf: [128]u8 = undefined;
    var header_buf: [512]u8 = undefined;

    var iteration: u32 = 0;
    while (iteration < 1024) : (iteration += 1) {
        const token_len = random.uintLessThan(usize, token_buf.len + 1);
        random.bytes(token_buf[0..token_len]);
        _ = isToken(token_buf[0..token_len]);

        const header_len = random.uintLessThan(usize, header_buf.len + 1);
        random.bytes(header_buf[0..header_len]);
        _ = headerOffersProtocol(header_buf[0..header_len], "chat");
    }
}
