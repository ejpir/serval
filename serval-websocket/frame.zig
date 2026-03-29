//! WebSocket Frame Header Parsing and Encoding
//!
//! RFC 6455 Section 5 framing helpers.
//! TigerStyle: Zero allocation, explicit bounds, protocol invariants enforced.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const config = serval_core.config;

/// Maximum number of bytes needed to represent any header handled by this module.
/// This covers the base header, extended payload length, and optional 4-byte mask key.
pub const max_header_size_bytes: u32 = 14;

/// Identifies the peer role used when validating a received frame header.
/// Clients are expected to receive masked frames; servers are expected to receive unmasked frames.
pub const PeerRole = enum {
    client,
    server,
};

/// WebSocket opcodes supported by this module.
/// `continuation`, `text`, and `binary` are data frames; `close`, `ping`, and `pong` are control frames.
pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

/// Parsed WebSocket frame header state returned by `parseHeader`.
/// It records the frame flags, opcode, masking state, payload length, and any 4-byte mask key.
/// `header_len_bytes` is the number of bytes consumed from the input buffer.
/// Use `isControl()` to test whether the opcode is a control frame.
pub const Header = struct {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: Opcode,
    masked: bool,
    payload_len: u64,
    mask_key: ?[4]u8,
    header_len_bytes: u8,

    /// Reports whether this parsed header carries a control-frame opcode.
    /// The method asserts that the stored header length is within the supported header-size bounds.
    pub fn isControl(self: Header) bool {
        assert(self.header_len_bytes >= 2);
        assert(self.header_len_bytes <= max_header_size_bytes);
        return isControlOpcode(self.opcode);
    }
};

/// Describes the fields needed to encode an outbound WebSocket header.
/// `opcode` and `payload_len` are required; `fin` defaults to `true`.
/// Set `mask_key` to `null` for an unmasked frame or to a 4-byte key to emit a masked header.
/// This struct is consumed by `buildHeader` and does not own heap memory.
pub const OutboundHeader = struct {
    fin: bool = true,
    opcode: Opcode,
    payload_len: u64,
    mask_key: ?[4]u8 = null,
};

/// Errors that can be returned while parsing or validating a WebSocket frame header.
/// `IncompleteHeader` and `HeaderTooLarge` describe truncated or oversized header input.
/// The remaining errors report unsupported opcodes, invalid reserved bits or payload length,
/// and masking or control-frame rule violations.
pub const FrameError = error{
    IncompleteHeader,
    UnsupportedOpcode,
    UnmaskedClientFrame,
    MaskedServerFrame,
    InvalidReservedBits,
    InvalidPayloadLength,
    InvalidControlFrame,
    HeaderTooLarge,
};

/// Parse a single WebSocket frame header from `input`.
/// `input` must contain header bytes only (max 14 bytes), not payload bytes.
pub fn parseHeader(input: []const u8, role: PeerRole) FrameError!Header {
    assert(input.len > 0);

    if (input.len < 2) return error.IncompleteHeader;
    if (input.len > max_header_size_bytes) return error.HeaderTooLarge;

    const first = input[0];
    const second = input[1];

    const header_len = try parseHeaderLen(input, second);

    const header = Header{
        .fin = (first & 0x80) != 0,
        .rsv1 = (first & 0x40) != 0,
        .rsv2 = (first & 0x20) != 0,
        .rsv3 = (first & 0x10) != 0,
        .opcode = try parseOpcode(@intCast(first & 0x0F)),
        .masked = (second & 0x80) != 0,
        .payload_len = try parsePayloadLen(input, second),
        .mask_key = try parseMaskKey(input, second, header_len),
        .header_len_bytes = header_len,
    };

    if (header.rsv1 or header.rsv2 or header.rsv3) return error.InvalidReservedBits;

    switch (role) {
        .client => if (!header.masked) return error.UnmaskedClientFrame,
        .server => if (header.masked) return error.MaskedServerFrame,
    }

    if (header.isControl()) {
        if (!header.fin) return error.InvalidControlFrame;
        if (header.payload_len > config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES) {
            return error.InvalidControlFrame;
        }
    }

    assert(header.header_len_bytes >= 2);
    assert(header.header_len_bytes <= max_header_size_bytes);
    return header;
}

/// Builds a WebSocket frame header into `out` and returns the written prefix.
/// Returns `null` when `out` is too small or `frame.payload_len` cannot be encoded.
/// If `frame.mask_key` is set, the mask bit is emitted and the 4-byte key is appended.
/// The returned slice aliases `out`; no allocation is performed.
pub fn buildHeader(out: []u8, frame: OutboundHeader) ?[]const u8 {
    assert(out.len > 0);
    assert(out.len <= std.math.maxInt(u32));

    if (frame.payload_len > std.math.maxInt(u63)) return null;

    var pos_bytes: u32 = 0;
    if (out.len < 2) return null;

    out[@intCast(pos_bytes)] = buildFirstByte(frame.fin, frame.opcode);
    pos_bytes += 1;

    const masked = frame.mask_key != null;
    const mask_bit: u8 = if (masked) 0x80 else 0x00;

    if (frame.payload_len <= 125) {
        out[@intCast(pos_bytes)] = mask_bit | @as(u8, @intCast(frame.payload_len));
        pos_bytes += 1;
    } else if (frame.payload_len <= std.math.maxInt(u16)) {
        const needed_bytes: u32 = pos_bytes + 3;
        if (out.len < @as(usize, @intCast(needed_bytes))) return null;
        out[@intCast(pos_bytes)] = mask_bit | 126;
        pos_bytes += 1;
        writeBigEndianU16(out[@intCast(pos_bytes)..][0..2], @intCast(frame.payload_len));
        pos_bytes += 2;
    } else {
        const needed_bytes: u32 = pos_bytes + 9;
        if (out.len < @as(usize, @intCast(needed_bytes))) return null;
        out[@intCast(pos_bytes)] = mask_bit | 127;
        pos_bytes += 1;
        writeBigEndianU64(out[@intCast(pos_bytes)..][0..8], frame.payload_len);
        pos_bytes += 8;
    }

    if (frame.mask_key) |mask_key| {
        const needed_bytes: u32 = pos_bytes + 4;
        if (out.len < @as(usize, @intCast(needed_bytes))) return null;
        @memcpy(out[@intCast(pos_bytes)..][0..4], &mask_key);
        pos_bytes += 4;
    }

    assert(@as(usize, @intCast(pos_bytes)) <= out.len);
    return out[0..@intCast(pos_bytes)];
}

/// Applies the 4-byte WebSocket masking key to `payload` in place.
/// The key is repeated across the payload bytes; the operation is its own inverse.
/// No allocation occurs and the slice is modified directly.
pub fn applyMask(payload: []u8, mask_key: [4]u8) void {
    assert(payload.len <= std.math.maxInt(u32));
    assert(mask_key.len == 4);

    var idx: u32 = 0;
    const payload_len: u32 = @intCast(payload.len);
    while (idx < payload_len) : (idx += 1) {
        const offset: usize = @intCast(idx);
        payload[offset] ^= mask_key[idx % mask_key.len];
    }
}

/// Returns `true` when `opcode` is one of the WebSocket control opcodes.
/// This is a pure classification check with no allocation or error return.
pub fn isControlOpcode(opcode: Opcode) bool {
    const opcode_bits: u8 = @intFromEnum(opcode);
    assert(opcode_bits <= 0xF);

    const is_control = switch (opcode) {
        .close, .ping, .pong => true,
        .continuation, .text, .binary => false,
    };
    assert(is_control == ((opcode_bits & 0x8) != 0));
    return is_control;
}

fn parseOpcode(raw_opcode: u4) FrameError!Opcode {
    assert(raw_opcode <= 0xF);

    const opcode: Opcode = switch (raw_opcode) {
        0x0 => .continuation,
        0x1 => .text,
        0x2 => .binary,
        0x8 => .close,
        0x9 => .ping,
        0xA => .pong,
        else => return error.UnsupportedOpcode,
    };
    assert(@intFromEnum(opcode) == raw_opcode);
    return opcode;
}

fn parsePayloadLen(input: []const u8, second: u8) FrameError!u64 {
    assert(input.len >= 2);
    assert(input.len <= max_header_size_bytes);

    const len_code: u8 = second & 0x7F;
    return switch (len_code) {
        0...125 => len_code,
        126 => blk: {
            if (input.len < 4) return error.IncompleteHeader;
            break :blk readBigEndianU16(input[2..][0..2]);
        },
        127 => blk: {
            if (input.len < 10) return error.IncompleteHeader;
            if ((input[2] & 0x80) != 0) return error.InvalidPayloadLength;
            break :blk readBigEndianU64(input[2..][0..8]);
        },
        else => unreachable,
    };
}

fn parseMaskKey(input: []const u8, second: u8, header_len: u8) FrameError!?[4]u8 {
    assert(input.len >= 2);
    assert(input.len <= max_header_size_bytes);

    const masked = (second & 0x80) != 0;
    if (!masked) return null;

    assert(header_len >= 6);
    assert(header_len <= max_header_size_bytes);
    const mask_offset = header_len - 4;
    if (input.len < header_len) return error.IncompleteHeader;

    return .{
        input[mask_offset],
        input[mask_offset + 1],
        input[mask_offset + 2],
        input[mask_offset + 3],
    };
}

fn parseHeaderLen(input: []const u8, second: u8) FrameError!u8 {
    assert(input.len >= 2);
    assert(input.len <= max_header_size_bytes);

    const total_len = headerLenFromSecondByte(second);
    assert(total_len >= 2);
    assert(total_len <= max_header_size_bytes);
    if (input.len < total_len) return error.IncompleteHeader;
    return total_len;
}

fn headerLenFromSecondByte(second: u8) u8 {
    const len_code: u8 = second & 0x7F;
    const masked = (second & 0x80) != 0;

    const base_len: u8 = switch (len_code) {
        0...125 => 2,
        126 => 4,
        127 => 10,
        else => unreachable,
    };

    const total_len: u8 = base_len + if (masked) @as(u8, 4) else @as(u8, 0);
    assert(total_len >= 2);
    assert(total_len <= max_header_size_bytes);
    return total_len;
}

fn buildFirstByte(fin: bool, opcode: Opcode) u8 {
    assert(@intFromEnum(opcode) <= 0xF);

    const fin_bit: u8 = if (fin) 0x80 else 0x00;
    const opcode_bits: u8 = @intFromEnum(opcode);
    const first_byte = fin_bit | opcode_bits;
    assert((first_byte & 0x0F) == opcode_bits);
    return first_byte;
}

fn readBigEndianU16(bytes: []const u8) u16 {
    assert(bytes.len == 2);

    var value: u16 = 0;
    for (bytes) |byte| {
        value = (value << 8) | byte;
    }
    assert(@as(u8, @intCast(value >> 8)) == bytes[0]);
    return value;
}

fn readBigEndianU64(bytes: []const u8) u64 {
    assert(bytes.len == 8);

    var value: u64 = 0;
    for (bytes) |byte| {
        value = (value << 8) | byte;
    }
    assert(@as(u8, @intCast((value >> 56) & 0xFF)) == bytes[0]);
    return value;
}

fn writeBigEndianU16(out: []u8, value: u16) void {
    assert(out.len == 2);

    out[0] = @intCast((value >> 8) & 0xFF);
    out[1] = @intCast(value & 0xFF);
    assert(readBigEndianU16(out) == value);
}

fn writeBigEndianU64(out: []u8, value: u64) void {
    assert(out.len == 8);

    var shift: u6 = 56;
    var idx: u32 = 0;
    while (idx < 8) : (idx += 1) {
        const out_idx: usize = @intCast(idx);
        out[out_idx] = @intCast((value >> shift) & 0xFF);
        if (shift == 0) break;
        shift -= 8;
    }
    assert(readBigEndianU64(out) == value);
}

test "parseHeader accepts masked client text frame" {
    const raw = [_]u8{ 0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D };
    const header = try parseHeader(&raw, .client);

    try std.testing.expect(header.fin);
    try std.testing.expectEqual(Opcode.text, header.opcode);
    try std.testing.expect(header.masked);
    try std.testing.expectEqual(@as(u64, 5), header.payload_len);
    try std.testing.expectEqual(@as(?[4]u8, .{ 0x37, 0xFA, 0x21, 0x3D }), header.mask_key);
    try std.testing.expectEqual(@as(u8, 6), header.header_len_bytes);
}

test "parseHeader accepts 16-bit extended payload length" {
    const raw = [_]u8{ 0x82, 0xFE, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD };
    const header = try parseHeader(&raw, .client);

    try std.testing.expectEqual(Opcode.binary, header.opcode);
    try std.testing.expectEqual(@as(u64, 256), header.payload_len);
    try std.testing.expectEqual(@as(u8, 8), header.header_len_bytes);
}

test "parseHeader accepts 64-bit extended payload length" {
    const raw = [_]u8{ 0x82, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44 };
    const header = try parseHeader(&raw, .client);

    try std.testing.expectEqual(@as(u64, 65536), header.payload_len);
    try std.testing.expectEqual(@as(u8, 14), header.header_len_bytes);
}

test "parseHeader rejects unmasked client frame" {
    const raw = [_]u8{ 0x81, 0x01 };
    try std.testing.expectError(error.UnmaskedClientFrame, parseHeader(&raw, .client));
}

test "parseHeader rejects masked server frame" {
    const raw = [_]u8{ 0x81, 0x81, 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectError(error.MaskedServerFrame, parseHeader(&raw, .server));
}

test "parseHeader rejects incomplete header bytes" {
    const raw = [_]u8{0x81};
    try std.testing.expectError(error.IncompleteHeader, parseHeader(&raw, .client));
}

test "headerLenFromSecondByte computes bounded sizes" {
    try std.testing.expectEqual(@as(u8, 2), headerLenFromSecondByte(0x00));
    try std.testing.expectEqual(@as(u8, 6), headerLenFromSecondByte(0x80));
    try std.testing.expectEqual(@as(u8, 4), headerLenFromSecondByte(126));
    try std.testing.expectEqual(@as(u8, 8), headerLenFromSecondByte(0x80 | 126));
    try std.testing.expectEqual(@as(u8, 10), headerLenFromSecondByte(127));
    try std.testing.expectEqual(@as(u8, 14), headerLenFromSecondByte(0x80 | 127));
}

test "parseHeader rejects unsupported opcode" {
    const raw = [_]u8{ 0x83, 0x80, 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectError(error.UnsupportedOpcode, parseHeader(&raw, .client));
}

test "parseHeader rejects invalid 64-bit payload length with high bit set" {
    const raw = [_]u8{ 0x82, 0x7F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expectError(error.InvalidPayloadLength, parseHeader(&raw, .server));
}

test "parseHeader rejects input larger than maximum header size" {
    const raw = [_]u8{
        0x82, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x99,
    };
    try std.testing.expectError(error.HeaderTooLarge, parseHeader(&raw, .client));
}

test "parseHeader rejects reserved bits without negotiated extension" {
    const raw = [_]u8{ 0xC1, 0x81, 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectError(error.InvalidReservedBits, parseHeader(&raw, .client));
}

test "parseHeader rejects fragmented control frame" {
    const raw = [_]u8{ 0x09, 0x80, 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectError(error.InvalidControlFrame, parseHeader(&raw, .client));
}

test "applyMask round trip restores payload" {
    var payload = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    const original = payload;
    const mask = [4]u8{ 0x37, 0xFA, 0x21, 0x3D };

    applyMask(&payload, mask);
    try std.testing.expect(!std.mem.eql(u8, &payload, &original));

    applyMask(&payload, mask);
    try std.testing.expectEqualSlices(u8, &original, &payload);
}

test "buildHeader encodes unmasked server text frame header" {
    var out: [max_header_size_bytes]u8 = undefined;
    const encoded = buildHeader(&out, .{
        .opcode = .text,
        .payload_len = 5,
    }).?;

    try std.testing.expectEqual(@as(usize, 2), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x81), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x05), encoded[1]);
}

test "buildHeader encodes masked client binary frame header" {
    var out: [max_header_size_bytes]u8 = undefined;
    const encoded = buildHeader(&out, .{
        .opcode = .binary,
        .payload_len = 126,
        .mask_key = .{ 0x01, 0x02, 0x03, 0x04 },
    }).?;

    try std.testing.expectEqual(@as(usize, 8), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x82), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0xFE), encoded[1]);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[2]);
    try std.testing.expectEqual(@as(u8, 0x7E), encoded[3]);
    try std.testing.expectEqual(@as(u8, 0x01), encoded[4]);
    try std.testing.expectEqual(@as(u8, 0x04), encoded[7]);
}

test "buildHeader and parseHeader round trip across bounded random inputs" {
    var prng = std.Random.DefaultPrng.init(0x1dea_f00d);
    const random = prng.random();

    var out: [max_header_size_bytes]u8 = undefined;
    var iterations: u32 = 0;
    const max_iterations: u32 = 256;

    while (iterations < max_iterations) : (iterations += 1) {
        const fin = random.uintLessThan(u8, 2) == 1;
        const opcode = if (random.uintLessThan(u8, 2) == 0) Opcode.text else Opcode.binary;
        const payload_bucket = random.uintLessThan(u8, 3);
        const payload_len: u64 = switch (payload_bucket) {
            0 => random.uintLessThan(u8, 126),
            1 => @as(u64, 126) + random.uintLessThan(u16, 1024),
            2 => @as(u64, 65_536) + random.uintLessThan(u32, 1_000_000),
            else => unreachable,
        };

        const encoded_server = buildHeader(&out, .{
            .fin = fin,
            .opcode = opcode,
            .payload_len = payload_len,
        }).?;
        const parsed_server = try parseHeader(encoded_server, .server);
        try std.testing.expectEqual(fin, parsed_server.fin);
        try std.testing.expectEqual(opcode, parsed_server.opcode);
        try std.testing.expectEqual(payload_len, parsed_server.payload_len);
        try std.testing.expectEqual(@as(?[4]u8, null), parsed_server.mask_key);

        const mask_key = [4]u8{
            random.int(u8),
            random.int(u8),
            random.int(u8),
            random.int(u8),
        };
        const encoded_client = buildHeader(&out, .{
            .fin = fin,
            .opcode = opcode,
            .payload_len = payload_len,
            .mask_key = mask_key,
        }).?;
        const parsed_client = try parseHeader(encoded_client, .client);
        try std.testing.expectEqual(fin, parsed_client.fin);
        try std.testing.expectEqual(opcode, parsed_client.opcode);
        try std.testing.expectEqual(payload_len, parsed_client.payload_len);
        try std.testing.expectEqual(@as(?[4]u8, mask_key), parsed_client.mask_key);
    }
}
