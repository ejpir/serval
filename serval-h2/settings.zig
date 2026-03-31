//! HTTP/2 SETTINGS Helpers
//!
//! Bounded parsing, encoding, and validation for SETTINGS payloads and
//! connection-level peer configuration.
//! TigerStyle: Fixed-capacity parsing, explicit validation, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const limits = @import("limits.zig");
const frame = @import("frame.zig");

/// Size in bytes of one HTTP/2 SETTINGS entry on the wire.
/// Each entry is encoded as a 2-byte identifier followed by a 4-byte value.
/// Used by parsing and encoding helpers to validate payload lengths and advance fixed-width cursors.
pub const setting_size_bytes: u32 = 6;
/// Default HPACK header table size in bytes used for new connection state.
/// This value matches the HTTP/2 default dynamic table size.
pub const default_header_table_size_bytes: u32 = 4096;
/// Sentinel meaning the peer did not advertise a `u32`-bounded limit.
/// This uses the maximum `u32` value to represent an effectively unbounded setting.
const unbounded_limit_u32: u32 = std.math.maxInt(u32);
/// Minimum legal HTTP/2 `MAX_FRAME_SIZE` value in bytes.
/// This is the protocol lower bound for the `max_frame_size_bytes` setting.
pub const min_max_frame_size_bytes: u32 = 16_384;
/// Maximum legal HTTP/2 `MAX_FRAME_SIZE` value in bytes.
/// This is the protocol upper bound for the `max_frame_size_bytes` setting.
pub const max_max_frame_size_bytes: u32 = 16_777_215;

/// Named HTTP/2 SETTINGS identifiers defined by the protocol.
/// These values are encoded on the wire as `u16` identifiers and are used by `Setting.knownId` and validation helpers.
pub const SettingId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    enable_connect_protocol = 0x8,
};

/// A raw HTTP/2 SETTINGS entry with a numeric identifier and 32-bit value.
/// Use `knownId` to map `id` to a typed `SettingId` when the identifier is recognized.
/// The struct stores the wire-format fields without allocating or owning external resources.
pub const Setting = struct {
    id: u16,
    value: u32,

    /// Returns the known `SettingId` for this setting number, if one is defined.
    /// The mapping is based only on `self.id`; unknown identifiers yield `null`.
    /// This asserts the enum discriminants expected by the decoder before calling `decodeSettingId`.
    pub fn knownId(self: Setting) ?SettingId {
        assert(@intFromEnum(SettingId.header_table_size) == 0x1);
        assert(@intFromEnum(SettingId.enable_connect_protocol) == 0x8);
        return decodeSettingId(self.id);
    }
};

/// In-memory representation of HTTP/2 connection settings.
/// Field values default to the protocol or Serval-configured initial state used when constructing a SETTINGS frame.
/// `enable_push` and `enable_connect_protocol` are boolean feature toggles; the remaining fields are size or count limits.
pub const Settings = struct {
    header_table_size_bytes: u32 = default_header_table_size_bytes,
    enable_push: bool = true,
    max_concurrent_streams: u32 = unbounded_limit_u32,
    initial_window_size_bytes: u32 = config.H2_INITIAL_WINDOW_SIZE_BYTES,
    max_frame_size_bytes: u32 = config.H2_MAX_FRAME_SIZE_BYTES,
    max_header_list_size_bytes: u32 = unbounded_limit_u32,
    enable_connect_protocol: bool = true,
};

/// Errors returned by SETTINGS frame parsing, validation, and encoding helpers.
/// These cover frame-shape violations, buffer sizing failures, and invalid setting values.
/// Callers should treat these as protocol or caller-input errors, not transport failures.
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

/// Validates HTTP/2 SETTINGS frame invariants for `header` and `payload`.
/// The frame must use stream 0, and ACK frames must have an empty payload.
/// Non-ACK payloads must have a valid SETTINGS length and stay within `limits.max_settings_per_frame`.
/// Returns the relevant `Error` when a frame-level constraint is violated.
pub fn validateFrame(header: frame.FrameHeader, payload: []const u8) Error!void {
    assert(header.length == payload.len);
    assert(header.frame_type == .settings);

    if (header.stream_id != 0) return error.InvalidStreamId;
    if ((header.flags & frame.flags_ack) != 0) {
        if (payload.len != 0) return error.AckMustBeEmpty;
        return;
    }

    if (!isPayloadLengthValid(payload.len)) return error.InvalidPayloadLength;
    if (payload.len / setting_size_bytes > limits.max_settings_per_frame) {
        return error.TooManySettings;
    }
}

/// Validates and parses a SETTINGS frame header and payload into `out_settings`.
/// `header` must describe a SETTINGS frame whose length matches `payload.len`.
/// ACK frames must carry an empty payload; otherwise this returns `error.AckMustBeEmpty`.
/// For non-empty payloads, this delegates to `parsePayload` and returns its errors.
pub fn parseFrame(
    header: frame.FrameHeader,
    payload: []const u8,
    out_settings: []Setting,
) Error![]const Setting {
    assert(header.frame_type == .settings);
    assert(header.length == payload.len);

    try validateFrame(header, payload);
    if (payload.len == 0) return out_settings[0..0];
    return parsePayload(payload, out_settings);
}

/// Parses an HTTP/2 SETTINGS payload into `out_settings`.
/// `payload.len` must be a valid SETTINGS payload length and `out_settings` must have room for every decoded entry.
/// Each decoded setting is validated before being stored; invalid entries return the corresponding `Error`.
/// On success, returns the initialized prefix of `out_settings` containing the decoded settings.
pub fn parsePayload(payload: []const u8, out_settings: []Setting) Error![]const Setting {
    assert(out_settings.len >= limits.max_settings_per_frame or out_settings.len > 0);
    assert(payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);

    if (!isPayloadLengthValid(payload.len)) return error.InvalidPayloadLength;

    const count: usize = payload.len / setting_size_bytes;
    if (count > limits.max_settings_per_frame) return error.TooManySettings;
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

/// Encodes `settings` into HTTP/2 SETTINGS payload bytes in network byte order.
/// `out` must be large enough for `settings.len * 6` bytes, and `settings.len` must not exceed `limits.max_settings_per_frame`.
/// Each setting is validated before it is written; invalid settings return the corresponding `Error`.
/// On success, returns the initialized prefix of `out` containing the encoded payload.
pub fn buildPayload(out: []u8, settings: []const Setting) Error![]const u8 {
    assert(settings.len <= limits.max_settings_per_frame);
    assert(setting_size_bytes == 6);

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

/// Applies each SETTINGS entry in `settings` to `target` in order.
/// `target` must be a valid pointer, and `settings.len` must not exceed `limits.max_settings_per_frame`.
/// Returns the first validation or application error raised by `applySetting`.
pub fn applySettings(target: *Settings, settings: []const Setting) Error!void {
    assert(@intFromPtr(target) != 0);
    assert(settings.len <= limits.max_settings_per_frame);

    for (settings) |setting| {
        try applySetting(target, setting);
    }
}

fn applySetting(target: *Settings, setting: Setting) Error!void {
    assert(@intFromPtr(target) != 0);
    assert(setting_size_bytes == 6);

    try validateSetting(setting);

    switch (decodeSettingId(setting.id) orelse return) {
        .header_table_size => target.header_table_size_bytes = setting.value,
        .enable_push => target.enable_push = setting.value == 1,
        .max_concurrent_streams => target.max_concurrent_streams = setting.value,
        .initial_window_size => target.initial_window_size_bytes = setting.value,
        .max_frame_size => target.max_frame_size_bytes = setting.value,
        .max_header_list_size => target.max_header_list_size_bytes = setting.value,
        .enable_connect_protocol => target.enable_connect_protocol = setting.value == 1,
    }
}

fn validateSetting(setting: Setting) Error!void {
    assert(setting_size_bytes == 6);
    assert(std.math.maxInt(u32) == 0xffff_ffff);

    switch (decodeSettingId(setting.id) orelse return) {
        .enable_push => {
            if (setting.value > 1) return error.InvalidEnablePush;
        },
        .enable_connect_protocol => {
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
    assert(@intFromEnum(SettingId.header_table_size) == 0x1);
    assert(@intFromEnum(SettingId.enable_connect_protocol) == 0x8);
    return switch (raw_id) {
        0x1 => .header_table_size,
        0x2 => .enable_push,
        0x3 => .max_concurrent_streams,
        0x4 => .initial_window_size,
        0x5 => .max_frame_size,
        0x6 => .max_header_list_size,
        0x8 => .enable_connect_protocol,
        else => null,
    };
}

fn isPayloadLengthValid(payload_len: usize) bool {
    assert(payload_len <= config.H2_MAX_FRAME_SIZE_BYTES);
    assert(setting_size_bytes == 6);
    return payload_len % setting_size_bytes == 0;
}

test "parsePayload parses canonical settings payload" {
    const payload = [_]u8{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
    };
    var out: [limits.max_settings_per_frame]Setting = undefined;

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
        .{ .id = 0x8, .value = 1 },
    };
    var payload: [settings.len * setting_size_bytes]u8 = undefined;
    var out: [limits.max_settings_per_frame]Setting = undefined;

    const encoded = try buildPayload(&payload, &settings);
    const parsed = try parsePayload(encoded, &out);

    try std.testing.expectEqual(@as(usize, settings.len), parsed.len);
    try std.testing.expectEqualDeep(settings[0], parsed[0]);
    try std.testing.expectEqualDeep(settings[1], parsed[1]);
    try std.testing.expectEqualDeep(settings[2], parsed[2]);
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
    var out: [limits.max_settings_per_frame]Setting = undefined;

    try std.testing.expectError(error.InvalidEnablePush, parsePayload(&payload, &out));
}

test "parsePayload rejects invalid max_frame_size" {
    const payload = [_]u8{ 0x00, 0x05, 0x00, 0x00, 0x10, 0x00 };
    var out: [limits.max_settings_per_frame]Setting = undefined;

    try std.testing.expectError(error.InvalidMaxFrameSize, parsePayload(&payload, &out));
}

test "applySettings updates target state" {
    const input = [_]Setting{
        .{ .id = 0x2, .value = 0 },
        .{ .id = 0x3, .value = 32 },
        .{ .id = 0x4, .value = 70_000 },
        .{ .id = 0x8, .value = 1 },
    };
    var settings = Settings{};

    try applySettings(&settings, &input);

    try std.testing.expect(!settings.enable_push);
    try std.testing.expectEqual(@as(u32, 32), settings.max_concurrent_streams);
    try std.testing.expectEqual(@as(u32, 70_000), settings.initial_window_size_bytes);
    try std.testing.expect(settings.enable_connect_protocol);
}

test "settings payload roundtrip property over deterministic corpus" {
    var prng = std.Random.DefaultPrng.init(0x51e7_5100);
    const random = prng.random();

    var settings_in: [limits.max_settings_per_frame]Setting = undefined;
    var settings_out: [limits.max_settings_per_frame]Setting = undefined;
    var payload_buf: [limits.max_settings_per_frame * setting_size_bytes]u8 = undefined;

    const valid_ids = [_]u16{ 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x8 };

    var iteration: u32 = 0;
    while (iteration < 256) : (iteration += 1) {
        const count = random.intRangeAtMost(u8, 0, 8);

        var index: u8 = 0;
        while (index < count) : (index += 1) {
            const id = valid_ids[random.intRangeAtMost(u8, 0, valid_ids.len - 1)];
            const value: u32 = switch (id) {
                0x2, 0x8 => random.intRangeAtMost(u1, 0, 1),
                0x4 => random.intRangeAtMost(u32, 0, config.H2_MAX_WINDOW_SIZE_BYTES),
                0x5 => random.intRangeAtMost(u32, min_max_frame_size_bytes, max_max_frame_size_bytes),
                else => random.int(u32),
            };
            settings_in[index] = .{ .id = id, .value = value };
        }

        const encoded = try buildPayload(&payload_buf, settings_in[0..count]);
        const decoded = try parsePayload(encoded, &settings_out);

        try std.testing.expectEqual(@as(usize, count), decoded.len);

        var compare_index: u8 = 0;
        while (compare_index < count) : (compare_index += 1) {
            try std.testing.expectEqualDeep(settings_in[compare_index], decoded[compare_index]);
        }
    }
}

test "settings parsePayload fuzz corpus maintains validation boundaries" {
    var prng = std.Random.DefaultPrng.init(0x9999_1024);
    const random = prng.random();

    var payload: [96]u8 = undefined;
    var out: [limits.max_settings_per_frame]Setting = undefined;

    var iteration: u32 = 0;
    while (iteration < 512) : (iteration += 1) {
        const len = random.intRangeAtMost(u8, 0, @as(u8, @intCast(payload.len)));
        random.bytes(payload[0..len]);

        const parsed = parsePayload(payload[0..len], &out) catch |err| switch (err) {
            error.InvalidPayloadLength,
            error.TooManySettings,
            error.InvalidEnablePush,
            error.InvalidInitialWindowSize,
            error.InvalidMaxFrameSize,
            => continue,
            else => return err,
        };

        try std.testing.expect(parsed.len <= limits.max_settings_per_frame);
    }
}
