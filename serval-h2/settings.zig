//! HTTP/2 SETTINGS Helpers
//!
//! Bounded parsing, encoding, and validation for SETTINGS payloads and
//! connection-level peer configuration.
//! TigerStyle: Fixed-capacity parsing, explicit validation, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const frame = @import("frame.zig");

pub const setting_size_bytes: u32 = 6;
pub const default_header_table_size_bytes: u32 = 4096;
pub const max_concurrent_streams_unbounded: u32 = std.math.maxInt(u32);
pub const max_header_list_size_unbounded: u32 = std.math.maxInt(u32);
pub const min_max_frame_size_bytes: u32 = 16_384;
pub const max_max_frame_size_bytes: u32 = 16_777_215;

pub const SettingId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
};

pub const Setting = struct {
    id: u16,
    value: u32,

    pub fn knownId(self: Setting) ?SettingId {
        return decodeSettingId(self.id);
    }
};

pub const Settings = struct {
    header_table_size_bytes: u32 = default_header_table_size_bytes,
    enable_push: bool = true,
    max_concurrent_streams: u32 = max_concurrent_streams_unbounded,
    initial_window_size_bytes: u32 = config.H2_INITIAL_WINDOW_SIZE_BYTES,
    max_frame_size_bytes: u32 = config.H2_MAX_FRAME_SIZE_BYTES,
    max_header_list_size_bytes: u32 = max_header_list_size_unbounded,
};

pub const Error = error{
    InvalidFrameType,
    InvalidStreamId,
    InvalidPayloadLength,
    AckMustBeEmpty,
    TooManySettings,
    BufferTooSmall,
    InvalidEnablePush,
    InvalidInitialWindowSize,
    InvalidMaxFrameSize,
};

pub fn validateFrame(header: frame.FrameHeader, payload: []const u8) Error!void {
    assert(header.length == payload.len);
    assert(header.frame_type == .settings);

    if (header.stream_id != 0) return error.InvalidStreamId;
    if ((header.flags & frame.flags_ack) != 0) {
        if (payload.len != 0) return error.AckMustBeEmpty;
        return;
    }

    if (!isPayloadLengthValid(payload.len)) return error.InvalidPayloadLength;
    if (payload.len / setting_size_bytes > config.H2_MAX_SETTINGS_PER_FRAME) {
        return error.TooManySettings;
    }
}

pub fn parseFrame(
    header: frame.FrameHeader,
    payload: []const u8,
    out_settings: []Setting,
) Error![]const Setting {
    assert(header.frame_type == .settings);

    try validateFrame(header, payload);
    if (payload.len == 0) return out_settings[0..0];
    return parsePayload(payload, out_settings);
}

pub fn parsePayload(payload: []const u8, out_settings: []Setting) Error![]const Setting {
    assert(out_settings.len >= config.H2_MAX_SETTINGS_PER_FRAME or out_settings.len > 0);

    if (!isPayloadLengthValid(payload.len)) return error.InvalidPayloadLength;

    const count: usize = payload.len / setting_size_bytes;
    if (count > config.H2_MAX_SETTINGS_PER_FRAME) return error.TooManySettings;
    if (count > out_settings.len) return error.TooManySettings;

    var cursor: usize = 0;
    var index: usize = 0;
    while (cursor < payload.len) : (index += 1) {
        const raw_id = std.mem.readInt(u16, payload[cursor..][0..2], .big);
        const value = std.mem.readInt(u32, payload[cursor + 2 ..][0..4], .big);
        const setting = Setting{ .id = raw_id, .value = value };
        try validateSetting(setting);
        out_settings[index] = setting;
        cursor += setting_size_bytes;
    }

    return out_settings[0..count];
}

pub fn buildPayload(out: []u8, settings: []const Setting) Error![]const u8 {
    assert(settings.len <= config.H2_MAX_SETTINGS_PER_FRAME);

    const needed = settings.len * setting_size_bytes;
    if (needed > out.len) return error.BufferTooSmall;

    var cursor: usize = 0;
    for (settings) |setting| {
        try validateSetting(setting);
        std.mem.writeInt(u16, out[cursor..][0..2], setting.id, .big);
        std.mem.writeInt(u32, out[cursor + 2 ..][0..4], setting.value, .big);
        cursor += setting_size_bytes;
    }

    return out[0..needed];
}

pub fn applySettings(target: *Settings, settings: []const Setting) Error!void {
    assert(@intFromPtr(target) != 0);
    assert(settings.len <= config.H2_MAX_SETTINGS_PER_FRAME);

    for (settings) |setting| {
        try applySetting(target, setting);
    }
}

fn applySetting(target: *Settings, setting: Setting) Error!void {
    assert(@intFromPtr(target) != 0);

    try validateSetting(setting);

    switch (decodeSettingId(setting.id) orelse return) {
        .header_table_size => target.header_table_size_bytes = setting.value,
        .enable_push => target.enable_push = setting.value == 1,
        .max_concurrent_streams => target.max_concurrent_streams = setting.value,
        .initial_window_size => target.initial_window_size_bytes = setting.value,
        .max_frame_size => target.max_frame_size_bytes = setting.value,
        .max_header_list_size => target.max_header_list_size_bytes = setting.value,
    }
}

fn validateSetting(setting: Setting) Error!void {
    switch (decodeSettingId(setting.id) orelse return) {
        .enable_push => {
            if (setting.value > 1) return error.InvalidEnablePush;
        },
        .initial_window_size => {
            if (setting.value > config.H2_MAX_WINDOW_SIZE_BYTES) return error.InvalidInitialWindowSize;
        },
        .max_frame_size => {
            if (setting.value < min_max_frame_size_bytes or setting.value > max_max_frame_size_bytes) {
                return error.InvalidMaxFrameSize;
            }
        },
        else => {},
    }
}

fn decodeSettingId(raw_id: u16) ?SettingId {
    return switch (raw_id) {
        0x1 => .header_table_size,
        0x2 => .enable_push,
        0x3 => .max_concurrent_streams,
        0x4 => .initial_window_size,
        0x5 => .max_frame_size,
        0x6 => .max_header_list_size,
        else => null,
    };
}

fn isPayloadLengthValid(payload_len: usize) bool {
    return payload_len % setting_size_bytes == 0;
}

test "parsePayload parses canonical settings payload" {
    const payload = [_]u8{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
    };
    var out: [config.H2_MAX_SETTINGS_PER_FRAME]Setting = undefined;

    const parsed = try parsePayload(&payload, &out);
    try std.testing.expectEqual(@as(usize, 2), parsed.len);
    try std.testing.expectEqual(@as(u16, 0x2), parsed[0].id);
    try std.testing.expectEqual(@as(u32, 0), parsed[0].value);
    try std.testing.expectEqual(@as(u16, 0x3), parsed[1].id);
    try std.testing.expectEqual(@as(u32, 100), parsed[1].value);
}

test "buildPayload round-trips settings" {
    const settings = [_]Setting{
        .{ .id = 0x2, .value = 0 },
        .{ .id = 0x4, .value = 65_535 },
    };
    var payload: [settings.len * setting_size_bytes]u8 = undefined;
    var out: [config.H2_MAX_SETTINGS_PER_FRAME]Setting = undefined;

    const encoded = try buildPayload(&payload, &settings);
    const parsed = try parsePayload(encoded, &out);

    try std.testing.expectEqual(@as(usize, settings.len), parsed.len);
    try std.testing.expectEqualDeep(settings[0], parsed[0]);
    try std.testing.expectEqualDeep(settings[1], parsed[1]);
}

test "validateFrame rejects ack payload" {
    const header = frame.FrameHeader{
        .length = setting_size_bytes,
        .frame_type = .settings,
        .flags = frame.flags_ack,
        .stream_id = 0,
    };
    const payload = [_]u8{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 };

    try std.testing.expectError(error.AckMustBeEmpty, validateFrame(header, &payload));
}

test "parsePayload rejects invalid enable_push" {
    const payload = [_]u8{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x02 };
    var out: [config.H2_MAX_SETTINGS_PER_FRAME]Setting = undefined;

    try std.testing.expectError(error.InvalidEnablePush, parsePayload(&payload, &out));
}

test "parsePayload rejects invalid max_frame_size" {
    const payload = [_]u8{ 0x00, 0x05, 0x00, 0x00, 0x10, 0x00 };
    var out: [config.H2_MAX_SETTINGS_PER_FRAME]Setting = undefined;

    try std.testing.expectError(error.InvalidMaxFrameSize, parsePayload(&payload, &out));
}

test "applySettings updates target state" {
    const input = [_]Setting{
        .{ .id = 0x2, .value = 0 },
        .{ .id = 0x3, .value = 32 },
        .{ .id = 0x4, .value = 70_000 },
    };
    var settings = Settings{};

    try applySettings(&settings, &input);

    try std.testing.expect(!settings.enable_push);
    try std.testing.expectEqual(@as(u32, 32), settings.max_concurrent_streams);
    try std.testing.expectEqual(@as(u32, 70_000), settings.initial_window_size_bytes);
}
