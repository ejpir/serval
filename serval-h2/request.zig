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
    MissingAuthority,
    InvalidMethod,
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
            .headers => {
                if (header.stream_id == 0) return error.InvalidStreamId;
                if ((header.flags & frame.flags_padded) != 0) return error.UnsupportedPadding;
                if ((header.flags & frame.flags_priority) != 0) return error.UnsupportedPriority;

                if ((header.flags & frame.flags_end_headers) != 0) {
                    if (header.length > config.H2_MAX_HEADER_BLOCK_SIZE_BYTES) return error.HeadersTooLarge;
                    return try buildInitialRequest(payload, header.stream_id, @intCast(payload_end));
                }

                assembling_header_block = true;
                header_stream_id = header.stream_id;
                continuation_frames = 0;
                header_block_len = 0;
                try appendHeaderFragment(&header_block_buf, &header_block_len, payload);
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
    var authority_found = false;

    for (fields) |field| {
        if (field.name.len > 0 and field.name[0] == ':') {
            if (std.mem.eql(u8, field.name, ":method")) {
                request.method = parseMethod(field.value) orelse return error.InvalidMethod;
                method_found = true;
            } else if (std.mem.eql(u8, field.name, ":path")) {
                request.path = field.value;
                path_found = true;
            } else if (std.mem.eql(u8, field.name, ":authority")) {
                try request.headers.put("host", field.value);
                authority_found = true;
            }
            continue;
        }

        request.headers.put(field.name, field.value) catch |err| switch (err) {
            error.TooManyHeaders => return error.TooManyHeaders,
            error.DuplicateContentLength => return error.DuplicateContentLength,
        };
    }

    if (!method_found) return error.MissingMethod;
    if (!path_found) return error.MissingPath;
    if (!authority_found and request.headers.getHost() == null) return error.MissingAuthority;

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

test "parseInitialRequest parses preface and first HEADERS request" {
    var block_buf: [256]u8 = undefined;
    var block_len: usize = 0;

    const pairs = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.health.v1.Health/Check" },
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

test "parseInitialRequest rejects interleaved non-continuation while assembling headers" {
    var block_buf: [512]u8 = undefined;
    var block_len: usize = 0;

    const pairs = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Interleave" },
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
