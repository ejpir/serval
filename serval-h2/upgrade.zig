//! HTTP/2 Upgrade Helpers
//!
//! Validates HTTP/1.1 `Upgrade: h2c` requests and translates the upgraded
//! request into a prior-knowledge HTTP/2 preface + SETTINGS + HEADERS preamble.
//! TigerStyle: Bounded parsing, fixed buffers, no socket ownership.

const std = @import("std");
const assert = std.debug.assert;

const core = @import("serval-core");
const config = core.config;
const eqlIgnoreCase = core.eqlIgnoreCase;
const types = core.types;
const BodyFraming = types.BodyFraming;
const Method = types.Method;
const Request = types.Request;
const Version = types.Version;

const frame = @import("frame.zig");
const settings = @import("settings.zig");
const hpack = @import("hpack.zig");
const preface = @import("preface.zig");

pub const upgrade_response =
    "HTTP/1.1 101 Switching Protocols\r\n" ++
    "Connection: Upgrade\r\n" ++
    "Upgrade: h2c\r\n" ++
    "\r\n";

pub const Error = error{
    InvalidVersion,
    MissingConnectionHeader,
    MissingUpgradeHeader,
    InvalidUpgradeHeader,
    MissingHttp2SettingsHeader,
    DuplicateHttp2SettingsHeader,
    InvalidHttp2Settings,
    InvalidSettingsPayload,
    UnsupportedBodyFraming,
    MissingPath,
    MissingAuthority,
    InvalidTeHeader,
    HeadersTooLarge,
} || frame.Error || settings.Error || hpack.Error;

pub fn looksLikeUpgradeRequest(request: *const Request) bool {
    assert(@intFromPtr(request) != 0);

    if (request.headers.get("HTTP2-Settings") != null) return true;

    if (request.headers.get("Upgrade")) |upgrade| {
        if (eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "h2c")) return true;
    }

    if (request.headers.getConnection()) |connection| {
        if (headerHasToken(connection, "http2-settings")) return true;
    }

    return false;
}

pub fn validateUpgradeRequest(
    request: *const Request,
    body_framing: BodyFraming,
    decoded_settings_out: []u8,
) Error![]const u8 {
    assert(@intFromPtr(request) != 0);
    assert(decoded_settings_out.len >= config.H2_MAX_FRAME_SIZE_BYTES);

    if (request.version != .@"HTTP/1.1") return error.InvalidVersion;
    if (body_framing == .chunked) return error.UnsupportedBodyFraming;

    const connection = request.headers.getConnection() orelse
        return error.MissingConnectionHeader;
    if (!headerHasToken(connection, "upgrade") or !headerHasToken(connection, "http2-settings")) {
        return error.MissingConnectionHeader;
    }

    const upgrade = request.headers.get("Upgrade") orelse
        return error.MissingUpgradeHeader;
    if (!eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "h2c")) {
        return error.InvalidUpgradeHeader;
    }

    const settings_value = try findUniqueHeaderValue(&request.headers, "HTTP2-Settings");
    const decoded = try decodeSettingsValue(settings_value, decoded_settings_out);

    var parsed_settings: [config.H2_MAX_SETTINGS_PER_FRAME]settings.Setting = undefined;
    _ = try settings.parsePayload(decoded, &parsed_settings);
    return decoded;
}

pub fn buildUpgradeResponse(out: []u8) Error![]const u8 {
    assert(out.len > 0);

    if (out.len < upgrade_response.len) return error.BufferTooSmall;
    @memcpy(out[0..upgrade_response.len], upgrade_response);
    return out[0..upgrade_response.len];
}

pub fn buildPriorKnowledgePreambleFromUpgrade(
    out: []u8,
    request: *const Request,
    effective_path: ?[]const u8,
    settings_payload: []const u8,
    end_stream: bool,
) Error![]const u8 {
    assert(@intFromPtr(request) != 0);
    assert(settings_payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);

    const path = effective_path orelse request.path;
    if (path.len == 0) return error.MissingPath;

    const authority = request.headers.getHost() orelse return error.MissingAuthority;
    const connection = request.headers.getConnection();

    var header_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const header_block = try encodeHeaderBlock(&header_block_buf, request, path, authority, connection);

    var cursor: usize = 0;
    cursor = try appendBytes(out, cursor, preface.client_connection_preface);
    cursor = try appendFrame(out, cursor, .settings, 0, 0, settings_payload);

    const flags = frame.flags_end_headers | if (end_stream) frame.flags_end_stream else 0;
    cursor = try appendFrame(out, cursor, .headers, flags, 1, header_block);
    return out[0..cursor];
}

fn findUniqueHeaderValue(headers: *const types.HeaderMap, name: []const u8) Error![]const u8 {
    assert(@intFromPtr(headers) != 0);
    assert(name.len > 0);

    var value: ?[]const u8 = null;
    var count: u32 = 0;

    for (headers.headers[0..headers.count]) |header| {
        if (!eqlIgnoreCase(header.name, name)) continue;
        count += 1;
        if (count > 1) return error.DuplicateHttp2SettingsHeader;
        value = std.mem.trim(u8, header.value, " \t");
    }

    return value orelse error.MissingHttp2SettingsHeader;
}

fn decodeSettingsValue(value: []const u8, out: []u8) Error![]const u8 {
    assert(out.len >= config.H2_MAX_FRAME_SIZE_BYTES);

    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(value) catch {
        return error.InvalidHttp2Settings;
    };
    if (decoded_len > config.H2_MAX_FRAME_SIZE_BYTES) return error.InvalidHttp2Settings;
    if (decoded_len % 6 != 0) return error.InvalidSettingsPayload;

    std.base64.url_safe_no_pad.Decoder.decode(out[0..decoded_len], value) catch {
        return error.InvalidHttp2Settings;
    };
    return out[0..decoded_len];
}

fn encodeHeaderBlock(
    out: []u8,
    request: *const Request,
    path: []const u8,
    authority: []const u8,
    connection: ?[]const u8,
) Error![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);

    var cursor: usize = 0;
    cursor = try appendHeader(out, cursor, ":method", methodToBytes(request.method));
    cursor = try appendHeader(out, cursor, ":path", path);
    cursor = try appendHeader(out, cursor, ":authority", authority);

    for (request.headers.headers[0..request.headers.count]) |header| {
        if (!shouldForwardHeader(header.name, connection)) continue;
        if (eqlIgnoreCase(header.name, "host")) continue;
        if (eqlIgnoreCase(header.name, "te") and !eqlIgnoreCase(std.mem.trim(u8, header.value, " \t"), "trailers")) {
            return error.InvalidTeHeader;
        }
        cursor = try appendHeader(out, cursor, header.name, header.value);
    }

    return out[0..cursor];
}

fn shouldForwardHeader(name: []const u8, connection: ?[]const u8) bool {
    if (eqlIgnoreCase(name, "connection")) return false;
    if (eqlIgnoreCase(name, "upgrade")) return false;
    if (eqlIgnoreCase(name, "http2-settings")) return false;
    if (eqlIgnoreCase(name, "keep-alive")) return false;
    if (eqlIgnoreCase(name, "proxy-connection")) return false;
    if (eqlIgnoreCase(name, "transfer-encoding")) return false;

    if (connection) |value| {
        if (headerHasToken(value, name)) return false;
    }

    return true;
}

fn appendHeader(out: []u8, cursor: usize, name: []const u8, value: []const u8) Error!usize {
    const encoded = hpack.encodeLiteralHeaderWithoutIndexing(out[cursor..], name, value) catch |err| switch (err) {
        error.BufferTooSmall => return error.HeadersTooLarge,
        else => return err,
    };
    return cursor + encoded.len;
}

fn appendBytes(out: []u8, cursor: usize, data: []const u8) Error!usize {
    if (cursor > out.len) return error.BufferTooSmall;
    if (out.len - cursor < data.len) return error.BufferTooSmall;
    @memcpy(out[cursor..][0..data.len], data);
    return cursor + data.len;
}

fn appendFrame(
    out: []u8,
    cursor: usize,
    frame_type: frame.FrameType,
    flags: u8,
    stream_id: u32,
    payload: []const u8,
) Error!usize {
    if (cursor > out.len) return error.BufferTooSmall;

    const header = try frame.buildFrameHeader(out[cursor..], .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    const after_header = cursor + header.len;
    return try appendBytes(out, after_header, payload);
}

fn methodToBytes(method: Method) []const u8 {
    return switch (method) {
        .GET => "GET",
        .HEAD => "HEAD",
        .POST => "POST",
        .PUT => "PUT",
        .DELETE => "DELETE",
        .CONNECT => "CONNECT",
        .OPTIONS => "OPTIONS",
        .TRACE => "TRACE",
        .PATCH => "PATCH",
    };
}

fn headerHasToken(value: []const u8, token: []const u8) bool {
    assert(token.len > 0);

    var parts = std.mem.splitScalar(u8, value, ',');
    var count: u32 = 0;
    const max_count: u32 = 64;

    while (parts.next()) |part| : (count += 1) {
        if (count >= max_count) break;
        if (eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

test "looksLikeUpgradeRequest detects h2c candidate" {
    var request = Request{ .version = .@"HTTP/1.1" };
    try request.headers.put("Upgrade", "h2c");

    try std.testing.expect(looksLikeUpgradeRequest(&request));
}

test "looksLikeUpgradeRequest ignores websocket upgrade" {
    var request = Request{ .version = .@"HTTP/1.1" };
    try request.headers.put("Upgrade", "websocket");
    try request.headers.put("Connection", "Upgrade");

    try std.testing.expect(!looksLikeUpgradeRequest(&request));
}

test "validateUpgradeRequest decodes HTTP2-Settings" {
    var settings_raw = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x64 };
    var settings_encoded_buf: [16]u8 = undefined;
    const settings_encoded = std.base64.url_safe_no_pad.Encoder.encode(&settings_encoded_buf, &settings_raw);

    var request = Request{
        .method = .POST,
        .path = "/grpc.test.Echo/Unary",
        .version = .@"HTTP/1.1",
    };
    try request.headers.put("Host", "127.0.0.1:8080");
    try request.headers.put("Connection", "Upgrade, HTTP2-Settings");
    try request.headers.put("Upgrade", "h2c");
    try request.headers.put("HTTP2-Settings", settings_encoded);
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    var decoded_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;
    const decoded = try validateUpgradeRequest(&request, .{ .content_length = 5 }, &decoded_buf);
    try std.testing.expectEqualSlices(u8, &settings_raw, decoded);
}

test "validateUpgradeRequest rejects chunked request body" {
    var request = Request{
        .method = .POST,
        .path = "/grpc.test.Echo/Unary",
        .version = .@"HTTP/1.1",
    };
    try request.headers.put("Host", "127.0.0.1:8080");
    try request.headers.put("Connection", "Upgrade, HTTP2-Settings");
    try request.headers.put("Upgrade", "h2c");
    try request.headers.put("HTTP2-Settings", "");

    var decoded_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;
    try std.testing.expectError(error.UnsupportedBodyFraming, validateUpgradeRequest(&request, .chunked, &decoded_buf));
}

test "buildPriorKnowledgePreambleFromUpgrade translates request into h2 preamble" {
    var settings_raw = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x64 };
    var request = Request{
        .method = .POST,
        .path = "/grpc.test.Echo/Unary",
        .version = .@"HTTP/1.1",
    };
    try request.headers.put("Host", "127.0.0.1:8080");
    try request.headers.put("Connection", "Upgrade, HTTP2-Settings");
    try request.headers.put("Upgrade", "h2c");
    try request.headers.put("HTTP2-Settings", "AAMAAABk");
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");
    try request.headers.put("content-length", "5");

    var out: [preface.client_connection_preface.len + 2 * frame.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES + config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;
    const preamble = try buildPriorKnowledgePreambleFromUpgrade(&out, &request, "/rewritten", &settings_raw, false);
    const parsed = try @import("request.zig").parseInitialRequest(preamble);

    try std.testing.expectEqual(Version.@"HTTP/1.1", parsed.request.version);
    try std.testing.expectEqual(Method.POST, parsed.request.method);
    try std.testing.expectEqualStrings("/rewritten", parsed.request.path);
    try std.testing.expectEqualStrings("application/grpc", parsed.request.headers.get("content-type").?);
    try std.testing.expectEqualStrings("trailers", parsed.request.headers.get("te").?);
}

test "buildUpgradeResponse returns canonical 101 response" {
    var out: [upgrade_response.len]u8 = undefined;
    const response = try buildUpgradeResponse(&out);
    try std.testing.expectEqualStrings(upgrade_response, response);
}
