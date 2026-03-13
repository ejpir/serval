//! Initial h2c Request Parsing
//!
//! Parses the client connection preface plus the first HEADERS frame block so
//! Serval can select an upstream before switching into raw h2c tunneling.

const std = @import("std");
const assert = std.debug.assert;

const core = @import("serval-core");
const config = core.config;
const types = core.types;
const HeaderMap = types.HeaderMap;
const Method = types.Method;
const Request = types.Request;

const frame = @import("frame.zig");
const settings = @import("settings.zig");
const hpack = @import("hpack.zig");
const preface = @import("preface.zig");

pub const RequestHead = struct {
    request: Request,
    stream_id: u32,
};

pub const InitialRequest = struct {
    request: Request,
    stream_id: u32,
    consumed_bytes: u32,
};

const priority_field_size_bytes: usize = 5;

pub const Error = error{
    NeedMoreData,
    InvalidPreface,
    InvalidFrame,
    InvalidStreamId,
    HeadersTooLarge,
    UnsupportedContinuation,
    UnsupportedPadding,
    UnsupportedPriority,
    MissingMethod,
    MissingPath,
    MissingScheme,
    MissingAuthority,
    InvalidMethod,
    InvalidTe,
    InvalidHeaderName,
    UnexpectedPseudoHeader,
    PseudoHeaderAfterRegularHeader,
    DuplicatePseudoHeader,
    ConnectionSpecificHeader,
    ConnectPathNotAllowed,
    ConnectSchemeNotAllowed,
    AuthorityHostMismatch,
    TooManyFrames,
    TooManyHeaders,
    DuplicateContentLength,
} || frame.Error || settings.Error || hpack.Error;

pub fn parseInitialRequest(input: []const u8) Error!InitialRequest {
    assert(input.len > 0);

    if (!preface.looksLikeClientConnectionPrefacePrefix(input)) return error.InvalidPreface;
    if (input.len < preface.client_connection_preface.len) return error.NeedMoreData;

    var cursor: usize = preface.client_connection_preface.len;
    var frames_seen: u32 = 0;

    var assembling_header_block = false;
    var header_stream_id: u32 = 0;
    var continuation_frames: u8 = 0;
    var header_block_len: usize = 0;
    var header_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;

    while (cursor < input.len and frames_seen < config.H2_MAX_INITIAL_PARSE_FRAMES) : (frames_seen += 1) {
        if (cursor + frame.frame_header_size_bytes > input.len) return error.NeedMoreData;

        const header = try frame.parseFrameHeader(input[cursor..]);
        const payload_start = cursor + frame.frame_header_size_bytes;
        const payload_end = payload_start + header.length;
        if (payload_end > input.len) return error.NeedMoreData;
        const payload = input[payload_start..payload_end];

        if (assembling_header_block and header.frame_type != .continuation) {
            return error.InvalidFrame;
        }

        switch (header.frame_type) {
            .settings => {
                settings.validateFrame(header, payload) catch |err| switch (err) {
                    error.InvalidStreamId,
                    error.InvalidPayloadLength,
                    error.AckMustBeEmpty,
                    error.TooManySettings,
                    error.InvalidEnablePush,
                    error.InvalidInitialWindowSize,
                    error.InvalidMaxFrameSize,
                    => return error.InvalidFrame,
                    else => return err,
                };
            },
            .window_update => {
                if (header.length != 4) return error.InvalidFrame;
            },
            .ping => {
                if (header.stream_id != 0 or header.length != 8) return error.InvalidFrame;
            },
            .priority => {
                if (header.stream_id == 0) return error.InvalidStreamId;
                if (header.length != priority_field_size_bytes) return error.InvalidFrame;
            },
            .headers => {
                if (header.stream_id == 0) return error.InvalidStreamId;
                if ((header.flags & frame.flags_padded) != 0) return error.UnsupportedPadding;

                var header_fragment = payload;
                if ((header.flags & frame.flags_priority) != 0) {
                    if (payload.len < priority_field_size_bytes) return error.InvalidFrame;
                    header_fragment = payload[priority_field_size_bytes..];
                }

                if ((header.flags & frame.flags_end_headers) != 0) {
                    if (header_fragment.len > config.H2_MAX_HEADER_BLOCK_SIZE_BYTES) return error.HeadersTooLarge;
                    return try buildInitialRequest(header_fragment, header.stream_id, @intCast(payload_end));
                }

                assembling_header_block = true;
                header_stream_id = header.stream_id;
                continuation_frames = 0;
                header_block_len = 0;
                try appendHeaderFragment(&header_block_buf, &header_block_len, header_fragment);
            },
            .continuation => {
                if (!assembling_header_block) return error.UnsupportedContinuation;
                if (header.stream_id != header_stream_id) return error.InvalidStreamId;
                if ((header.flags & ~frame.flags_end_headers) != 0) return error.InvalidFrame;

                if (continuation_frames >= config.H2_MAX_CONTINUATION_FRAMES) return error.TooManyFrames;
                continuation_frames += 1;
                try appendHeaderFragment(&header_block_buf, &header_block_len, payload);

                if ((header.flags & frame.flags_end_headers) != 0) {
                    return try buildInitialRequest(
                        header_block_buf[0..header_block_len],
                        header_stream_id,
                        @intCast(payload_end),
                    );
                }
            },
            else => {},
        }

        cursor = payload_end;
    }

    if (frames_seen >= config.H2_MAX_INITIAL_PARSE_FRAMES) return error.TooManyFrames;
    return error.NeedMoreData;
}

fn appendHeaderFragment(
    buf: *[config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8,
    len: *usize,
    fragment: []const u8,
) Error!void {
    assert(@intFromPtr(len) != 0);
    assert(len.* <= config.H2_MAX_HEADER_BLOCK_SIZE_BYTES);

    if (len.* + fragment.len > config.H2_MAX_HEADER_BLOCK_SIZE_BYTES) return error.HeadersTooLarge;
    @memcpy(buf[len.* .. len.* + fragment.len], fragment);
    len.* += fragment.len;
}

fn buildInitialRequest(header_block: []const u8, stream_id: u32, consumed_bytes: u32) Error!InitialRequest {
    assert(header_block.len <= config.H2_MAX_HEADER_BLOCK_SIZE_BYTES);
    assert(stream_id > 0);

    const head = try decodeRequestHeaderBlock(header_block, stream_id);
    return .{
        .request = head.request,
        .stream_id = head.stream_id,
        .consumed_bytes = consumed_bytes,
    };
}

pub fn decodeRequestHeaderBlock(header_block: []const u8, stream_id: u32) Error!RequestHead {
    var decoder = hpack.Decoder.init();
    return decodeRequestHeaderBlockWithDecoder(&decoder, header_block, stream_id);
}

pub fn decodeRequestHeaderBlockWithDecoder(
    decoder: *hpack.Decoder,
    header_block: []const u8,
    stream_id: u32,
) Error!RequestHead {
    assert(@intFromPtr(decoder) != 0);
    assert(header_block.len <= config.H2_MAX_HEADER_BLOCK_SIZE_BYTES);
    assert(stream_id > 0);

    var fields_buf: [config.MAX_HEADERS]hpack.HeaderField = undefined;
    const fields = try decoder.decodeHeaderBlock(header_block, &fields_buf);

    var request = Request{
        .method = .GET,
        .path = "",
        .version = .@"HTTP/1.1",
        .headers = HeaderMap.init(),
        .body = null,
    };

    var method_found = false;
    var path_found = false;
    var scheme_found = false;
    var authority_found = false;
    var regular_headers_seen = false;
    var connect_method = false;
    var authority_value: []const u8 = "";

    for (fields) |field| {
        if (!isHeaderNameLowercase(field.name)) return error.InvalidHeaderName;

        if (field.name.len > 0 and field.name[0] == ':') {
            if (regular_headers_seen) return error.PseudoHeaderAfterRegularHeader;

            if (std.mem.eql(u8, field.name, ":method")) {
                if (method_found) return error.DuplicatePseudoHeader;
                request.method = parseMethod(field.value) orelse return error.InvalidMethod;
                method_found = true;
                connect_method = request.method == .CONNECT;
            } else if (std.mem.eql(u8, field.name, ":path")) {
                if (path_found) return error.DuplicatePseudoHeader;
                request.path = field.value;
                path_found = true;
            } else if (std.mem.eql(u8, field.name, ":scheme")) {
                if (scheme_found) return error.DuplicatePseudoHeader;
                if (field.value.len == 0) return error.MissingScheme;
                scheme_found = true;

                request.headers.put("x-forwarded-proto", field.value) catch |err| switch (err) {
                    error.TooManyHeaders => return error.TooManyHeaders,
                    error.DuplicateContentLength => return error.DuplicateContentLength,
                };
            } else if (std.mem.eql(u8, field.name, ":authority")) {
                if (authority_found) return error.DuplicatePseudoHeader;
                try request.headers.put("host", field.value);
                authority_found = true;
                authority_value = field.value;
            } else {
                return error.UnexpectedPseudoHeader;
            }
            continue;
        }

        regular_headers_seen = true;

        if (isConnectionSpecificHeader(field.name)) return error.ConnectionSpecificHeader;

        if (std.mem.eql(u8, field.name, "te") and !isTeTrailersOnly(field.value)) {
            return error.InvalidTe;
        }

        if (authority_found and std.mem.eql(u8, field.name, "host")) {
            if (!std.ascii.eqlIgnoreCase(field.value, authority_value)) return error.AuthorityHostMismatch;
            continue;
        }

        request.headers.put(field.name, field.value) catch |err| switch (err) {
            error.TooManyHeaders => return error.TooManyHeaders,
            error.DuplicateContentLength => return error.DuplicateContentLength,
        };
    }

    if (!method_found) return error.MissingMethod;
    if (!authority_found and request.headers.getHost() == null) return error.MissingAuthority;

    if (connect_method) {
        if (path_found) return error.ConnectPathNotAllowed;
        if (scheme_found) return error.ConnectSchemeNotAllowed;
    } else {
        if (!path_found or request.path.len == 0) return error.MissingPath;
        if (!scheme_found) return error.MissingScheme;
    }

    return .{ .request = request, .stream_id = stream_id };
}

fn parseMethod(token: []const u8) ?Method {
    const map = std.StaticStringMap(Method).initComptime(.{
        .{ "GET", .GET },
        .{ "HEAD", .HEAD },
        .{ "POST", .POST },
        .{ "PUT", .PUT },
        .{ "DELETE", .DELETE },
        .{ "CONNECT", .CONNECT },
        .{ "OPTIONS", .OPTIONS },
        .{ "TRACE", .TRACE },
        .{ "PATCH", .PATCH },
    });
    return map.get(token);
}

fn isHeaderNameLowercase(name: []const u8) bool {
    if (name.len == 0) return false;

    var index: usize = 0;
    while (index < name.len) : (index += 1) {
        const c = name[index];
        if (c >= 'A' and c <= 'Z') return false;
    }
    return true;
}

fn isConnectionSpecificHeader(name: []const u8) bool {
    if (std.mem.eql(u8, name, "connection")) return true;
    if (std.mem.eql(u8, name, "proxy-connection")) return true;
    if (std.mem.eql(u8, name, "keep-alive")) return true;
    if (std.mem.eql(u8, name, "transfer-encoding")) return true;
    if (std.mem.eql(u8, name, "upgrade")) return true;
    return false;
}

fn isTeTrailersOnly(value: []const u8) bool {
    const trimmed = std.mem.trim(u8, value, " \t");
    if (trimmed.len == 0) return false;

    var tokens = std.mem.splitScalar(u8, trimmed, ',');
    var seen_any = false;
    var token_count: u8 = 0;
    const token_count_max: u8 = 16;

    while (tokens.next()) |token| {
        if (token_count >= token_count_max) return false;
        token_count += 1;

        const token_trimmed = std.mem.trim(u8, token, " \t");
        if (token_trimmed.len == 0) return false;
        if (!std.ascii.eqlIgnoreCase(token_trimmed, "trailers")) return false;
        seen_any = true;
    }

    return seen_any;
}

const TestHeaderPair = struct {
    name: []const u8,
    value: []const u8,
};

fn encodeHeaderPairs(pairs: []const TestHeaderPair, out: []u8) ![]const u8 {
    var len: usize = 0;
    for (pairs) |pair| {
        const encoded = try hpack.encodeLiteralHeaderWithoutIndexing(out[len..], pair.name, pair.value);
        len += encoded.len;
    }
    return out[0..len];
}

test "parseInitialRequest parses preface and first HEADERS request" {
    var block_buf: [256]u8 = undefined;
    var block_len: usize = 0;

    const pairs = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.health.v1.Health/Check" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    for (pairs) |pair| {
        const encoded = try hpack.encodeLiteralHeaderWithoutIndexing(block_buf[block_len..], pair.name, pair.value);
        block_len += encoded.len;
    }

    var frame_header_buf: [frame.frame_header_size_bytes]u8 = undefined;
    const headers_header = try frame.buildFrameHeader(&frame_header_buf, .{
        .length = @intCast(block_len),
        .frame_type = .headers,
        .flags = frame.flags_end_headers | frame.flags_end_stream,
        .stream_id = 1,
    });

    var input_buf: [512]u8 = undefined;
    var pos: usize = 0;
    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;
    @memcpy(input_buf[pos..][0..headers_header.len], headers_header);
    pos += headers_header.len;
    @memcpy(input_buf[pos..][0..block_len], block_buf[0..block_len]);
    pos += block_len;

    const parsed = try parseInitialRequest(input_buf[0..pos]);
    try std.testing.expectEqual(Method.POST, parsed.request.method);
    try std.testing.expectEqualStrings("/grpc.health.v1.Health/Check", parsed.request.path);
    try std.testing.expectEqualStrings("application/grpc", parsed.request.headers.get("content-type").?);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
}

test "parseInitialRequest reassembles HEADERS and CONTINUATION" {
    var block_buf: [512]u8 = undefined;
    var block_len: usize = 0;

    const pairs = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Continuation" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    for (pairs) |pair| {
        const encoded = try hpack.encodeLiteralHeaderWithoutIndexing(block_buf[block_len..], pair.name, pair.value);
        block_len += encoded.len;
    }

    const split: usize = block_len / 2;
    std.debug.assert(split > 0);
    std.debug.assert(split < block_len);

    var input_buf: [1024]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;

    const headers_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = @intCast(split),
        .frame_type = .headers,
        .flags = 0,
        .stream_id = 1,
    });
    pos += headers_header.len;
    @memcpy(input_buf[pos..][0..split], block_buf[0..split]);
    pos += split;

    const continuation_payload_len = block_len - split;
    const continuation_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = @intCast(continuation_payload_len),
        .frame_type = .continuation,
        .flags = frame.flags_end_headers,
        .stream_id = 1,
    });
    pos += continuation_header.len;
    @memcpy(input_buf[pos..][0..continuation_payload_len], block_buf[split..block_len]);
    pos += continuation_payload_len;

    const parsed = try parseInitialRequest(input_buf[0..pos]);
    try std.testing.expectEqual(Method.POST, parsed.request.method);
    try std.testing.expectEqualStrings("/grpc.test.Echo/Continuation", parsed.request.path);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
    try std.testing.expectEqual(@as(u32, @intCast(pos)), parsed.consumed_bytes);
}

test "parseInitialRequest accepts PRIORITY frame before request HEADERS" {
    var block_buf: [256]u8 = undefined;
    var block_len: usize = 0;

    const pairs = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/PriorityFrame" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    for (pairs) |pair| {
        const encoded = try hpack.encodeLiteralHeaderWithoutIndexing(block_buf[block_len..], pair.name, pair.value);
        block_len += encoded.len;
    }

    var input_buf: [1024]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;

    const priority_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = priority_field_size_bytes,
        .frame_type = .priority,
        .flags = 0,
        .stream_id = 1,
    });
    pos += priority_header.len;
    std.mem.writeInt(u32, input_buf[pos..][0..4], 0, .big);
    input_buf[pos + 4] = 15;
    pos += priority_field_size_bytes;

    const headers_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = @intCast(block_len),
        .frame_type = .headers,
        .flags = frame.flags_end_headers,
        .stream_id = 1,
    });
    pos += headers_header.len;
    @memcpy(input_buf[pos..][0..block_len], block_buf[0..block_len]);
    pos += block_len;

    const parsed = try parseInitialRequest(input_buf[0..pos]);
    try std.testing.expectEqualStrings("/grpc.test.Echo/PriorityFrame", parsed.request.path);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
}

test "parseInitialRequest accepts HEADERS with PRIORITY flag" {
    var block_buf: [256]u8 = undefined;
    var block_len: usize = 0;

    const pairs = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/HeadersPriority" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    for (pairs) |pair| {
        const encoded = try hpack.encodeLiteralHeaderWithoutIndexing(block_buf[block_len..], pair.name, pair.value);
        block_len += encoded.len;
    }

    var input_buf: [1024]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;

    const headers_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = @intCast(priority_field_size_bytes + block_len),
        .frame_type = .headers,
        .flags = frame.flags_end_headers | frame.flags_priority,
        .stream_id = 1,
    });
    pos += headers_header.len;
    std.mem.writeInt(u32, input_buf[pos..][0..4], 0, .big);
    input_buf[pos + 4] = 9;
    pos += priority_field_size_bytes;
    @memcpy(input_buf[pos..][0..block_len], block_buf[0..block_len]);
    pos += block_len;

    const parsed = try parseInitialRequest(input_buf[0..pos]);
    try std.testing.expectEqualStrings("/grpc.test.Echo/HeadersPriority", parsed.request.path);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
}

test "parseInitialRequest rejects interleaved non-continuation while assembling headers" {
    var block_buf: [512]u8 = undefined;
    var block_len: usize = 0;

    const pairs = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Interleave" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    for (pairs) |pair| {
        const encoded = try hpack.encodeLiteralHeaderWithoutIndexing(block_buf[block_len..], pair.name, pair.value);
        block_len += encoded.len;
    }

    const split: usize = block_len / 2;
    try std.testing.expect(split > 0);

    var input_buf: [1024]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;

    const headers_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = @intCast(split),
        .frame_type = .headers,
        .flags = 0,
        .stream_id = 1,
    });
    pos += headers_header.len;
    @memcpy(input_buf[pos..][0..split], block_buf[0..split]);
    pos += split;

    const data_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 1,
        .frame_type = .data,
        .flags = frame.flags_end_stream,
        .stream_id = 1,
    });
    pos += data_header.len;
    input_buf[pos] = 'x';
    pos += 1;

    try std.testing.expectError(error.InvalidFrame, parseInitialRequest(input_buf[0..pos]));
}

test "parseInitialRequest rejects continuation stream mismatch" {
    var block_buf: [512]u8 = undefined;
    var block_len: usize = 0;

    const pairs = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Mismatch" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    for (pairs) |pair| {
        const encoded = try hpack.encodeLiteralHeaderWithoutIndexing(block_buf[block_len..], pair.name, pair.value);
        block_len += encoded.len;
    }

    const split: usize = block_len / 2;

    var input_buf: [1024]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;

    const headers_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = @intCast(split),
        .frame_type = .headers,
        .flags = 0,
        .stream_id = 1,
    });
    pos += headers_header.len;
    @memcpy(input_buf[pos..][0..split], block_buf[0..split]);
    pos += split;

    const continuation_payload_len = block_len - split;
    const continuation_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = @intCast(continuation_payload_len),
        .frame_type = .continuation,
        .flags = frame.flags_end_headers,
        .stream_id = 3,
    });
    pos += continuation_header.len;
    @memcpy(input_buf[pos..][0..continuation_payload_len], block_buf[split..block_len]);
    pos += continuation_payload_len;

    try std.testing.expectError(error.InvalidStreamId, parseInitialRequest(input_buf[0..pos]));
}

test "parseInitialRequest rejects unexpected CONTINUATION before HEADERS" {
    var input_buf: [512]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;

    const continuation_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 1,
        .frame_type = .continuation,
        .flags = frame.flags_end_headers,
        .stream_id = 1,
    });
    pos += continuation_header.len;
    input_buf[pos] = 'x';
    pos += 1;

    try std.testing.expectError(error.UnsupportedContinuation, parseInitialRequest(input_buf[0..pos]));
}

test "parseInitialRequest rejects CONTINUATION with invalid flags" {
    var input_buf: [512]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;

    const headers_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 1,
        .frame_type = .headers,
        .flags = 0,
        .stream_id = 1,
    });
    pos += headers_header.len;
    input_buf[pos] = 0x00;
    pos += 1;

    const continuation_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 1,
        .frame_type = .continuation,
        .flags = frame.flags_end_headers | frame.flags_end_stream,
        .stream_id = 1,
    });
    pos += continuation_header.len;
    input_buf[pos] = 0x00;
    pos += 1;

    try std.testing.expectError(error.InvalidFrame, parseInitialRequest(input_buf[0..pos]));
}

test "parseInitialRequest enforces continuation frame bound" {
    var input_buf: [4096]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    pos += settings_header.len;

    const headers_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 1,
        .frame_type = .headers,
        .flags = 0,
        .stream_id = 1,
    });
    pos += headers_header.len;
    input_buf[pos] = 0x00;
    pos += 1;

    var count: u8 = 0;
    while (count < config.H2_MAX_CONTINUATION_FRAMES + 1) : (count += 1) {
        const continuation_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
            .length = 1,
            .frame_type = .continuation,
            .flags = 0,
            .stream_id = 1,
        });
        pos += continuation_header.len;
        input_buf[pos] = 0x00;
        pos += 1;
    }

    try std.testing.expectError(error.TooManyFrames, parseInitialRequest(input_buf[0..pos]));
}

test "decodeRequestHeaderBlock rejects pseudo header after regular header" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Unary" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
    }, &block_buf);

    try std.testing.expectError(error.PseudoHeaderAfterRegularHeader, decodeRequestHeaderBlock(block, 1));
}

test "decodeRequestHeaderBlock rejects missing scheme" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Unary" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
    }, &block_buf);

    try std.testing.expectError(error.MissingScheme, decodeRequestHeaderBlock(block, 1));
}

test "decodeRequestHeaderBlock rejects empty path" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
    }, &block_buf);

    try std.testing.expectError(error.MissingPath, decodeRequestHeaderBlock(block, 1));
}

test "decodeRequestHeaderBlock rejects connection specific headers" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Unary" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "connection", .value = "keep-alive" },
    }, &block_buf);

    try std.testing.expectError(error.ConnectionSpecificHeader, decodeRequestHeaderBlock(block, 1));
}

test "decodeRequestHeaderBlock rejects invalid te token" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Unary" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "te", .value = "gzip" },
    }, &block_buf);

    try std.testing.expectError(error.InvalidTe, decodeRequestHeaderBlock(block, 1));
}

test "decodeRequestHeaderBlock rejects CONNECT with :path" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
    }, &block_buf);

    try std.testing.expectError(error.ConnectPathNotAllowed, decodeRequestHeaderBlock(block, 1));
}
