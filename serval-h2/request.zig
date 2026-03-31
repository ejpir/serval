//! Initial h2c Request Parsing
//!
//! Parses the client connection preface plus the first HEADERS frame block so
//! Serval can select an upstream before switching into raw h2c tunneling.

const std = @import("std");
const assert = std.debug.assert;

const core = @import("serval-core");
const config = core.config;
const log = core.log.scoped(.h2_request);
const types = core.types;
const limits = @import("limits.zig");
const HeaderMap = types.HeaderMap;
const Method = types.Method;
const Request = types.Request;

const frame = @import("frame.zig");
const settings = @import("settings.zig");
const hpack = @import("hpack.zig");
const preface = @import("preface.zig");

/// Result of decoding a single request header block.
/// `request` contains the decoded request and `stream_id` identifies the HTTP/2 stream.
/// The request data is zero-copy and points into caller-provided stable storage.
pub const RequestHead = struct {
    request: Request,
    stream_id: u32,
};

/// Result of parsing the initial HTTP/2 request sequence.
/// `request` contains the decoded request, `stream_id` is the request stream, and
/// `consumed_bytes` is the number of input bytes consumed up to the end of the request headers.
/// All request slices point into caller-provided stable storage.
pub const InitialRequest = struct {
    request: Request,
    stream_id: u32,
    consumed_bytes: u32,
};

const HeaderAssembly = struct {
    active: bool = false,
    stream_id: u32 = 0,
    continuation_frames: u8 = 0,
    block_len: u32 = 0,
    block_buf: [limits.header_block_capacity_bytes]u8 = undefined,
};

const priority_field_size_bytes: u32 = 5;
const header_block_storage_budget_bytes: u32 = limits.header_block_capacity_bytes;

// Reserve one header-block budget for copied names and one for copied values.
/// Minimum caller-provided stable storage, in bytes, required to decode one request.
/// This is currently sized as two full header-block budgets: one for copied header names and one
/// for copied header values.
pub const request_stable_storage_size_bytes: u32 = header_block_storage_budget_bytes * 2;

/// Error set returned by HTTP/2 request parsing and header decoding.
/// It covers preface, frame, HPACK, header-validation, and storage-capacity failures, including
/// errors forwarded from `frame`, `settings`, and `hpack`.
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
    StableStorageTooSmall,
} || frame.Error || settings.Error || hpack.Error;

/// Parses the client connection preface and the initial HTTP/2 frame sequence for the first request.
/// Returns an `InitialRequest` once the request header block has been fully assembled and decoded.
/// `input` must begin with the HTTP/2 client preface prefix, and the first frame after the preface
/// must be a SETTINGS frame. Incomplete input returns `error.NeedMoreData`.
/// The returned request uses slices backed by `request_storage_out`; those slices are valid only
/// while that storage remains intact. `consumed_bytes` reports how many input bytes were consumed
/// through the end of the request header block.
pub fn parseInitialRequest(input: []const u8, request_storage_out: []u8) Error!InitialRequest {
    var decoder = hpack.Decoder.init();
    return parseInitialRequestWithDecoder(&decoder, input, request_storage_out);
}

/// Parses the client connection preface and the initial HTTP/2 frame sequence using a caller-owned HPACK decoder.
/// Returns an `InitialRequest` once the request header block has been fully assembled and decoded.
/// `decoder` retains dynamic-table state across calls, so callers can keep it alive when they want to avoid constructing a large decoder on a small stack.
/// The returned request uses slices backed by `request_storage_out`; those slices are valid only while that storage remains intact.
pub fn parseInitialRequestWithDecoder(
    decoder: *hpack.Decoder,
    input: []const u8,
    request_storage_out: []u8,
) Error!InitialRequest {
    var initial_request: InitialRequest = undefined;
    try parseInitialRequestWithDecoderInto(decoder, input, request_storage_out, &initial_request);
    return initial_request;
}

pub fn parseInitialRequestWithDecoderInto(
    decoder: *hpack.Decoder,
    input: []const u8,
    request_storage_out: []u8,
    initial_request_out: *InitialRequest,
) Error!void {
    assert(@intFromPtr(decoder) != 0);
    assert(@intFromPtr(initial_request_out) != 0);
    assert(input.len > 0);
    assert(preface.client_connection_preface.len > 0);
    if (request_storage_out.len < request_stable_storage_size_bytes) return error.StableStorageTooSmall;

    if (!preface.looksLikeClientConnectionPrefacePrefix(input)) return error.InvalidPreface;
    if (input.len < preface.client_connection_preface.len) return error.NeedMoreData;

    log.debug("h2 request: parseInitialRequestWithDecoder input_len={d}", .{input.len});

    var cursor: usize = preface.client_connection_preface.len;
    var frames_seen: u32 = 0;
    const header_assembly = std.heap.page_allocator.create(HeaderAssembly) catch return error.StableStorageTooSmall;
    defer std.heap.page_allocator.destroy(header_assembly);
    header_assembly.* = .{};

    while (cursor < input.len and frames_seen < limits.max_initial_parse_frames) : (frames_seen += 1) {
        if (cursor + frame.frame_header_size_bytes > input.len) return error.NeedMoreData;

        const header = try frame.parseFrameHeader(input[cursor..]);
        if (frames_seen == 0 and header.frame_type != .settings) return error.InvalidFrame;
        const payload_start = cursor + frame.frame_header_size_bytes;
        const payload_end = payload_start + header.length;
        if (payload_end > input.len) return error.NeedMoreData;
        const payload = input[payload_start..payload_end];

        log.debug(
            "h2 request: frame[{d}] type={s} stream={d} len={d}",
            .{ frames_seen, @tagName(header.frame_type), header.stream_id, header.length },
        );

        const found_request = try parseInitialFrameInto(
            decoder,
            header,
            payload,
            frames_seen,
            payload_end,
            header_assembly,
            request_storage_out,
            initial_request_out,
        );
        if (found_request) {
            log.debug("h2 request: parseInitialRequestWithDecoder completed request", .{});
            return;
        }

        cursor = payload_end;
    }

    if (frames_seen >= limits.max_initial_parse_frames) return error.TooManyFrames;
    return error.NeedMoreData;
}

fn parseInitialFrameInto(
    decoder: *hpack.Decoder,
    header: frame.FrameHeader,
    payload: []const u8,
    frames_seen: u32,
    payload_end: usize,
    header_assembly: *HeaderAssembly,
    request_storage_out: []u8,
    initial_request_out: *InitialRequest,
) Error!bool {
    assert(@intFromPtr(decoder) != 0);
    assert(@intFromPtr(header_assembly) != 0);
    assert(@intFromPtr(initial_request_out) != 0);
    assert(payload_end >= payload.len);

    if (header_assembly.active and header.frame_type != .continuation) return error.InvalidFrame;

    switch (header.frame_type) {
        .settings => try validateInitialSettingsFrame(header, payload, frames_seen),
        .window_update => if (header.length != 4) return error.InvalidFrame,
        .ping => if (header.stream_id != 0 or header.length != 8) return error.InvalidFrame,
        .priority => {
            if (header.stream_id == 0) return error.InvalidStreamId;
            if (header.length != priority_field_size_bytes) return error.InvalidFrame;
        },
        .headers => {
            return handleInitialHeadersFrameInto(
                decoder,
                header,
                payload,
                payload_end,
                header_assembly,
                request_storage_out,
                initial_request_out,
            );
        },
        .continuation => {
            return handleInitialContinuationFrameInto(
                decoder,
                header,
                payload,
                payload_end,
                header_assembly,
                request_storage_out,
                initial_request_out,
            );
        },
        else => {},
    }

    return false;
}

fn validateInitialSettingsFrame(header: frame.FrameHeader, payload: []const u8, frames_seen: u32) Error!void {
    assert(header.frame_type == .settings);
    assert(header.length == payload.len);

    if (frames_seen == 0 and (header.flags & frame.flags_ack) != 0) return error.InvalidFrame;
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
}

fn handleInitialHeadersFrameInto(
    decoder: *hpack.Decoder,
    header: frame.FrameHeader,
    payload: []const u8,
    payload_end: usize,
    header_assembly: *HeaderAssembly,
    request_storage_out: []u8,
    initial_request_out: *InitialRequest,
) Error!bool {
    assert(@intFromPtr(decoder) != 0);
    assert(header.frame_type == .headers);
    assert(@intFromPtr(header_assembly) != 0);
    assert(@intFromPtr(initial_request_out) != 0);

    if (header.stream_id == 0) return error.InvalidStreamId;
    if ((header.stream_id & 1) == 0) return error.InvalidStreamId;
    if ((header.flags & frame.flags_padded) != 0) return error.UnsupportedPadding;

    var header_fragment = payload;
    if ((header.flags & frame.flags_priority) != 0) {
        const priority_size: usize = @intCast(priority_field_size_bytes);
        if (payload.len < priority_size) return error.InvalidFrame;
        header_fragment = payload[priority_size..];
    }

    if ((header.flags & frame.flags_end_headers) != 0) {
        if (header_fragment.len > limits.header_block_capacity_bytes) return error.HeadersTooLarge;
        try buildInitialRequestInto(
            decoder,
            header_fragment,
            header.stream_id,
            @intCast(payload_end),
            request_storage_out,
            initial_request_out,
        );
        log.debug("h2 request: initial HEADERS request built", .{});
        return true;
    }

    header_assembly.active = true;
    header_assembly.stream_id = header.stream_id;
    header_assembly.continuation_frames = 0;
    header_assembly.block_len = 0;
    try appendHeaderFragment(&header_assembly.block_buf, &header_assembly.block_len, header_fragment);
    return false;
}

fn handleInitialContinuationFrameInto(
    decoder: *hpack.Decoder,
    header: frame.FrameHeader,
    payload: []const u8,
    payload_end: usize,
    header_assembly: *HeaderAssembly,
    request_storage_out: []u8,
    initial_request_out: *InitialRequest,
) Error!bool {
    assert(@intFromPtr(decoder) != 0);
    assert(header.frame_type == .continuation);
    assert(@intFromPtr(header_assembly) != 0);
    assert(@intFromPtr(initial_request_out) != 0);

    if (!header_assembly.active) return error.UnsupportedContinuation;
    if (header.stream_id != header_assembly.stream_id) return error.InvalidStreamId;
    if ((header.flags & ~frame.flags_end_headers) != 0) return error.InvalidFrame;
    if (header_assembly.continuation_frames >= limits.max_continuation_frames) return error.TooManyFrames;

    header_assembly.continuation_frames += 1;
    try appendHeaderFragment(&header_assembly.block_buf, &header_assembly.block_len, payload);
    if ((header.flags & frame.flags_end_headers) == 0) return false;

    const block_len: usize = @intCast(header_assembly.block_len);
    try buildInitialRequestInto(
        decoder,
        header_assembly.block_buf[0..block_len],
        header_assembly.stream_id,
        @intCast(payload_end),
        request_storage_out,
        initial_request_out,
    );
    log.debug("h2 request: continuation request built", .{});
    return true;
}

fn appendHeaderFragment(
    buf: *[limits.header_block_capacity_bytes]u8,
    len: *u32,
    fragment: []const u8,
) Error!void {
    assert(@intFromPtr(len) != 0);
    const current_len: usize = @intCast(len.*);
    assert(current_len <= limits.header_block_capacity_bytes);

    if (fragment.len > limits.header_block_capacity_bytes - current_len) return error.HeadersTooLarge;
    @memcpy(buf[current_len .. current_len + fragment.len], fragment);
    len.* = @intCast(current_len + fragment.len);
}

fn buildInitialRequest(
    decoder: *hpack.Decoder,
    header_block: []const u8,
    stream_id: u32,
    consumed_bytes: u32,
    request_storage_out: []u8,
) Error!InitialRequest {
    var initial_request: InitialRequest = undefined;
    try buildInitialRequestInto(
        decoder,
        header_block,
        stream_id,
        consumed_bytes,
        request_storage_out,
        &initial_request,
    );
    return initial_request;
}

fn buildInitialRequestInto(
    decoder: *hpack.Decoder,
    header_block: []const u8,
    stream_id: u32,
    consumed_bytes: u32,
    request_storage_out: []u8,
    initial_request_out: *InitialRequest,
) Error!void {
    assert(@intFromPtr(decoder) != 0);
    assert(@intFromPtr(initial_request_out) != 0);
    assert(header_block.len <= limits.header_block_capacity_bytes);
    assert(stream_id > 0);
    if (request_storage_out.len < request_stable_storage_size_bytes) return error.StableStorageTooSmall;

    log.debug(
        "h2 request: buildInitialRequest stream={d} header_block_len={d}",
        .{ stream_id, header_block.len },
    );

    initial_request_out.stream_id = stream_id;
    initial_request_out.consumed_bytes = consumed_bytes;
    try decodeRequestHeaderBlockWithDecoderIntoRequest(
        decoder,
        header_block,
        request_storage_out,
        &initial_request_out.request,
    );
    log.debug("h2 request: buildInitialRequestInto decode complete", .{});
}

/// Decodes an HPACK request header block using a fresh decoder instance.
/// This is a convenience wrapper around `decodeRequestHeaderBlockWithDecoder` for callers that do
/// not need to reuse HPACK decoder state across requests.
/// The same bounds and storage requirements apply: `stream_id` must be non-zero, the header block
/// must fit within `limits.header_block_capacity_bytes`, and `request_storage_out` must be
/// large enough for stable request storage.
pub fn decodeRequestHeaderBlock(
    header_block: []const u8,
    stream_id: u32,
    request_storage_out: []u8,
) Error!RequestHead {
    assert(header_block.len <= limits.header_block_capacity_bytes);
    assert(stream_id > 0);

    var decoder = hpack.Decoder.init();
    return decodeRequestHeaderBlockWithDecoder(&decoder, header_block, stream_id, request_storage_out);
}

const HeaderDecodeState = struct {
    request: *Request,
    method_found: bool = false,
    path_found: bool = false,
    scheme_found: bool = false,
    authority_found: bool = false,
    protocol_found: bool = false,
    regular_headers_seen: bool = false,
    connect_method: bool = false,
    authority_value: []const u8 = "",
    storage_cursor: u32 = 0,
};

/// Decodes an HPACK request header block into a zero-copy `RequestHead`.
/// The decoder must be valid, `stream_id` must be non-zero, and `header_block` must not exceed
/// `limits.header_block_capacity_bytes`. `request_storage_out` must be large enough for stable
/// header and path storage, or the call fails with `error.StableStorageTooSmall`.
/// Header names must already be lowercase and pseudo headers must satisfy HTTP/2 request rules.
/// Slices stored in the returned request reference `request_storage_out` and remain valid until that
/// storage is overwritten or reused.
pub fn decodeRequestHeaderBlockWithDecoder(
    decoder: *hpack.Decoder,
    header_block: []const u8,
    stream_id: u32,
    request_storage_out: []u8,
) Error!RequestHead {
    var head: RequestHead = undefined;
    try decodeRequestHeaderBlockWithDecoderInto(
        decoder,
        header_block,
        stream_id,
        request_storage_out,
        &head,
    );
    return head;
}

pub fn decodeRequestHeaderBlockWithDecoderInto(
    decoder: *hpack.Decoder,
    header_block: []const u8,
    stream_id: u32,
    request_storage_out: []u8,
    head_out: *RequestHead,
) Error!void {
    assert(@intFromPtr(decoder) != 0);
    assert(@intFromPtr(head_out) != 0);
    assert(header_block.len <= limits.header_block_capacity_bytes);
    assert(stream_id > 0);
    if (request_storage_out.len < request_stable_storage_size_bytes) return error.StableStorageTooSmall;

    head_out.stream_id = stream_id;
    try decodeRequestHeaderBlockWithDecoderIntoRequest(
        decoder,
        header_block,
        request_storage_out,
        &head_out.request,
    );
}

fn decodeRequestHeaderBlockWithDecoderIntoRequest(
    decoder: *hpack.Decoder,
    header_block: []const u8,
    request_storage_out: []u8,
    request_out: *Request,
) Error!void {
    assert(@intFromPtr(decoder) != 0);
    assert(@intFromPtr(request_out) != 0);
    assert(header_block.len <= limits.header_block_capacity_bytes);
    if (request_storage_out.len < request_stable_storage_size_bytes) return error.StableStorageTooSmall;

    log.debug(
        "h2 request: decodeRequestHeaderBlockWithDecoder header_block_len={d}",
        .{header_block.len},
    );

    const fields_buf = std.heap.page_allocator.alloc(hpack.HeaderField, config.MAX_HEADERS) catch {
        return error.StableStorageTooSmall;
    };
    defer std.heap.page_allocator.free(fields_buf);
    const fields = try decoder.decodeHeaderBlock(header_block, fields_buf);

    const state = std.heap.page_allocator.create(HeaderDecodeState) catch {
        return error.StableStorageTooSmall;
    };
    defer std.heap.page_allocator.destroy(state);
    request_out.* = .{
        .method = .GET,
        .path = "",
        .version = .@"HTTP/1.1",
        .headers = HeaderMap.init(),
        .body = null,
    };
    state.* = .{
        .request = request_out,
    };

    for (fields, 0..) |field, index| {
        log.debug(
            "h2 request: materialize field[{d}] name={s} value_len={d}",
            .{ index, field.name, field.value.len },
        );
        if (!isHeaderNameLowercase(field.name)) return error.InvalidHeaderName;

        if (field.name.len > 0 and field.name[0] == ':') {
            try decodePseudoHeader(state, field, request_storage_out);
            continue;
        }

        try decodeRegularHeader(state, field, request_storage_out);
    }

    log.debug(
        "h2 request: validating request method_found={} path_found={} scheme_found={} authority_found={} protocol_found={}",
        .{ state.method_found, state.path_found, state.scheme_found, state.authority_found, state.protocol_found },
    );
    try validateDecodedRequestState(state);
    log.debug("h2 request: request validation complete", .{});
}

fn decodePseudoHeader(
    state: *HeaderDecodeState,
    field: hpack.HeaderField,
    request_storage_out: []u8,
) Error!void {
    assert(@intFromPtr(state) != 0);
    assert(field.name.len > 0 and field.name[0] == ':');

    if (state.regular_headers_seen) return error.PseudoHeaderAfterRegularHeader;

    if (std.mem.eql(u8, field.name, ":method")) {
        if (state.method_found) return error.DuplicatePseudoHeader;
        state.request.method = parseMethod(field.value) orelse return error.InvalidMethod;
        state.method_found = true;
        state.connect_method = state.request.method == .CONNECT;
        return;
    }

    if (std.mem.eql(u8, field.name, ":path")) {
        if (state.path_found) return error.DuplicatePseudoHeader;
        state.request.path = try copyIntoStableStorage(
            request_storage_out,
            &state.storage_cursor,
            field.value,
        );
        state.path_found = true;
        return;
    }

    if (std.mem.eql(u8, field.name, ":scheme")) {
        if (state.scheme_found) return error.DuplicatePseudoHeader;
        if (field.value.len == 0) return error.MissingScheme;

        const proto_value = try copyIntoStableStorage(
            request_storage_out,
            &state.storage_cursor,
            field.value,
        );
        try putRequestHeader(state.request, "x-forwarded-proto", proto_value);
        state.scheme_found = true;
        return;
    }

    if (std.mem.eql(u8, field.name, ":authority")) {
        if (state.authority_found) return error.DuplicatePseudoHeader;
        const authority = try copyIntoStableStorage(
            request_storage_out,
            &state.storage_cursor,
            field.value,
        );
        try putRequestHeader(state.request, "host", authority);
        state.authority_found = true;
        state.authority_value = authority;
        return;
    }

    if (std.mem.eql(u8, field.name, ":protocol")) return decodeProtocolPseudoHeader(state, field, request_storage_out);

    return error.UnexpectedPseudoHeader;
}

fn decodeProtocolPseudoHeader(
    state: *HeaderDecodeState,
    field: hpack.HeaderField,
    request_storage_out: []u8,
) Error!void {
    assert(@intFromPtr(state) != 0);
    assert(std.mem.eql(u8, field.name, ":protocol"));

    if (state.protocol_found) return error.DuplicatePseudoHeader;
    if (!state.connect_method) return error.UnexpectedPseudoHeader;
    if (field.value.len == 0) return error.UnexpectedPseudoHeader;

    const protocol_value = try copyIntoStableStorage(
        request_storage_out,
        &state.storage_cursor,
        field.value,
    );
    try putRequestHeader(state.request, "x-http2-protocol", protocol_value);
    state.protocol_found = true;
}

fn decodeRegularHeader(
    state: *HeaderDecodeState,
    field: hpack.HeaderField,
    request_storage_out: []u8,
) Error!void {
    assert(@intFromPtr(state) != 0);
    assert(field.name.len == 0 or field.name[0] != ':');

    state.regular_headers_seen = true;

    if (isConnectionSpecificHeader(field.name)) return error.ConnectionSpecificHeader;
    if (std.mem.eql(u8, field.name, "te") and !isTeTrailersOnly(field.value)) return error.InvalidTe;

    if (state.authority_found and std.mem.eql(u8, field.name, "host")) {
        if (!std.ascii.eqlIgnoreCase(field.value, state.authority_value)) return error.AuthorityHostMismatch;
        return;
    }

    const stable_name = try copyIntoStableStorage(
        request_storage_out,
        &state.storage_cursor,
        field.name,
    );
    const stable_value = try copyIntoStableStorage(
        request_storage_out,
        &state.storage_cursor,
        field.value,
    );
    try putRequestHeader(state.request, stable_name, stable_value);
}

fn putRequestHeader(request: *Request, name: []const u8, value: []const u8) Error!void {
    assert(@intFromPtr(request) != 0);
    assert(name.len > 0);

    request.headers.put(name, value) catch |err| switch (err) {
        error.TooManyHeaders => return error.TooManyHeaders,
        error.DuplicateContentLength => return error.DuplicateContentLength,
    };
}

fn validateDecodedRequestState(state: *const HeaderDecodeState) Error!void {
    assert(@intFromPtr(state) != 0);
    assert(state.storage_cursor <= request_stable_storage_size_bytes);

    if (!state.method_found) return error.MissingMethod;
    if (!state.authority_found and state.request.headers.getHost() == null) return error.MissingAuthority;

    if (state.connect_method) {
        if (state.protocol_found) {
            if (!state.path_found or state.request.path.len == 0) return error.MissingPath;
            if (!state.scheme_found) return error.MissingScheme;
            return;
        }

        if (state.path_found) return error.ConnectPathNotAllowed;
        if (state.scheme_found) return error.ConnectSchemeNotAllowed;
        return;
    }

    if (state.protocol_found) return error.UnexpectedPseudoHeader;
    if (!state.path_found or state.request.path.len == 0) return error.MissingPath;
    if (!state.scheme_found) return error.MissingScheme;
}

fn copyIntoStableStorage(storage: []u8, cursor: *u32, data: []const u8) Error![]const u8 {
    assert(@intFromPtr(cursor) != 0);
    assert(storage.len <= std.math.maxInt(u32));
    const cursor_usize: usize = @intCast(cursor.*);
    assert(cursor_usize <= storage.len);

    if (data.len == 0) return "";
    if (storage.len - cursor_usize < data.len) return error.StableStorageTooSmall;

    const start = cursor_usize;
    @memcpy(storage[start .. start + data.len], data);
    const next_cursor = start + data.len;
    cursor.* = @intCast(next_cursor);
    return storage[start .. start + data.len];
}

fn parseMethod(token: []const u8) ?Method {
    assert(token.len <= limits.header_block_capacity_bytes);
    assert(limits.header_block_capacity_bytes > 0);

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
    assert(name.len <= limits.header_block_capacity_bytes);

    if (name.len == 0) return false;

    var index: usize = 0;
    while (index < name.len) : (index += 1) {
        const c = name[index];
        if (c >= 'A' and c <= 'Z') return false;
    }
    assert(index == name.len);
    return true;
}

fn isConnectionSpecificHeader(name: []const u8) bool {
    assert(name.len <= limits.header_block_capacity_bytes);
    assert(limits.header_block_capacity_bytes > 0);

    if (std.mem.eql(u8, name, "connection")) return true;
    if (std.mem.eql(u8, name, "proxy-connection")) return true;
    if (std.mem.eql(u8, name, "keep-alive")) return true;
    if (std.mem.eql(u8, name, "transfer-encoding")) return true;
    if (std.mem.eql(u8, name, "upgrade")) return true;
    return false;
}

fn isTeTrailersOnly(value: []const u8) bool {
    assert(value.len <= limits.header_block_capacity_bytes);
    assert(limits.header_block_capacity_bytes > 0);

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
    assert(pairs.len <= config.MAX_HEADERS);
    assert(out.len > 0);

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
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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

    const parsed = try parseInitialRequest(input_buf[0..pos], &request_storage_buf);
    try std.testing.expectEqual(Method.POST, parsed.request.method);
    try std.testing.expectEqualStrings("/grpc.health.v1.Health/Check", parsed.request.path);
    try std.testing.expectEqualStrings("application/grpc", parsed.request.headers.get("content-type").?);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
}

test "parseInitialRequest rejects non-settings first frame after preface" {
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    var input_buf: [preface.client_connection_preface.len + frame.frame_header_size_bytes + 8]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const ping_header = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 8,
        .frame_type = .ping,
        .flags = 0,
        .stream_id = 0,
    });
    pos += ping_header.len;
    @memset(input_buf[pos..][0..8], 0);
    pos += 8;

    try std.testing.expectError(error.InvalidFrame, parseInitialRequest(input_buf[0..pos], &request_storage_buf));
}

test "parseInitialRequest rejects ACK as first settings frame" {
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    var input_buf: [preface.client_connection_preface.len + frame.frame_header_size_bytes]u8 = undefined;
    var pos: usize = 0;

    @memcpy(input_buf[pos..][0..preface.client_connection_preface.len], preface.client_connection_preface);
    pos += preface.client_connection_preface.len;

    const settings_ack = try frame.buildFrameHeader(input_buf[pos..][0..frame.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = frame.flags_ack,
        .stream_id = 0,
    });
    pos += settings_ack.len;

    try std.testing.expectError(error.InvalidFrame, parseInitialRequest(input_buf[0..pos], &request_storage_buf));
}

test "parseInitialRequest rejects even-numbered client request stream id" {
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    var block_buf: [256]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/EvenStreamId" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, &block_buf);

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
        .length = @intCast(block.len),
        .frame_type = .headers,
        .flags = frame.flags_end_headers,
        .stream_id = 2,
    });
    pos += headers_header.len;
    @memcpy(input_buf[pos..][0..block.len], block);
    pos += block.len;

    try std.testing.expectError(error.InvalidStreamId, parseInitialRequest(input_buf[0..pos], &request_storage_buf));
}

test "parseInitialRequest reassembles HEADERS and CONTINUATION" {
    var block_buf: [512]u8 = undefined;
    var block_len: usize = 0;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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

    const parsed = try parseInitialRequest(input_buf[0..pos], &request_storage_buf);
    try std.testing.expectEqual(Method.POST, parsed.request.method);
    try std.testing.expectEqualStrings("/grpc.test.Echo/Continuation", parsed.request.path);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
    try std.testing.expectEqual(@as(u32, @intCast(pos)), parsed.consumed_bytes);
}

test "parseInitialRequest accepts PRIORITY frame before request HEADERS" {
    var block_buf: [256]u8 = undefined;
    var block_len: usize = 0;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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

    const parsed = try parseInitialRequest(input_buf[0..pos], &request_storage_buf);
    try std.testing.expectEqualStrings("/grpc.test.Echo/PriorityFrame", parsed.request.path);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
}

test "parseInitialRequest accepts HEADERS with PRIORITY flag" {
    var block_buf: [256]u8 = undefined;
    var block_len: usize = 0;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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

    const parsed = try parseInitialRequest(input_buf[0..pos], &request_storage_buf);
    try std.testing.expectEqualStrings("/grpc.test.Echo/HeadersPriority", parsed.request.path);
    try std.testing.expectEqual(@as(u32, 1), parsed.stream_id);
}

test "parseInitialRequest rejects interleaved non-continuation while assembling headers" {
    var block_buf: [512]u8 = undefined;
    var block_len: usize = 0;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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

    try std.testing.expectError(error.InvalidFrame, parseInitialRequest(input_buf[0..pos], &request_storage_buf));
}

test "parseInitialRequest rejects continuation stream mismatch" {
    var block_buf: [512]u8 = undefined;
    var block_len: usize = 0;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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

    try std.testing.expectError(error.InvalidStreamId, parseInitialRequest(input_buf[0..pos], &request_storage_buf));
}

test "parseInitialRequest rejects unexpected CONTINUATION before HEADERS" {
    var input_buf: [512]u8 = undefined;
    var pos: usize = 0;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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

    try std.testing.expectError(error.UnsupportedContinuation, parseInitialRequest(input_buf[0..pos], &request_storage_buf));
}

test "parseInitialRequest rejects CONTINUATION with invalid flags" {
    var input_buf: [512]u8 = undefined;
    var pos: usize = 0;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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

    try std.testing.expectError(error.InvalidFrame, parseInitialRequest(input_buf[0..pos], &request_storage_buf));
}

test "parseInitialRequest enforces continuation frame bound" {
    var input_buf: [4096]u8 = undefined;
    var pos: usize = 0;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

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
    while (count < limits.max_continuation_frames + 1) : (count += 1) {
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

    try std.testing.expectError(error.TooManyFrames, parseInitialRequest(input_buf[0..pos], &request_storage_buf));
}

test "decodeRequestHeaderBlock rejects pseudo header after regular header" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Unary" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
    }, &block_buf);

    try std.testing.expectError(error.PseudoHeaderAfterRegularHeader, decodeRequestHeaderBlock(block, 1, &request_storage_buf));
}

test "decodeRequestHeaderBlock rejects missing scheme" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Unary" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
    }, &block_buf);

    try std.testing.expectError(error.MissingScheme, decodeRequestHeaderBlock(block, 1, &request_storage_buf));
}

test "decodeRequestHeaderBlock rejects empty path" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
    }, &block_buf);

    try std.testing.expectError(error.MissingPath, decodeRequestHeaderBlock(block, 1, &request_storage_buf));
}

test "decodeRequestHeaderBlock rejects connection specific headers" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Unary" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "connection", .value = "keep-alive" },
    }, &block_buf);

    try std.testing.expectError(error.ConnectionSpecificHeader, decodeRequestHeaderBlock(block, 1, &request_storage_buf));
}

test "decodeRequestHeaderBlock rejects invalid te token" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/grpc.test.Echo/Unary" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "te", .value = "gzip" },
    }, &block_buf);

    try std.testing.expectError(error.InvalidTe, decodeRequestHeaderBlock(block, 1, &request_storage_buf));
}

test "decodeRequestHeaderBlock rejects CONNECT with :path" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
    }, &block_buf);

    try std.testing.expectError(error.ConnectPathNotAllowed, decodeRequestHeaderBlock(block, 1, &request_storage_buf));
}

test "decodeRequestHeaderBlock accepts extended CONNECT websocket" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":path", .value = "/ws-proxy/signal" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "sec-websocket-key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
        .{ .name = "sec-websocket-version", .value = "13" },
    }, &block_buf);

    const parsed = try decodeRequestHeaderBlock(block, 1, &request_storage_buf);
    try std.testing.expectEqual(Method.CONNECT, parsed.request.method);
    try std.testing.expectEqualStrings("/ws-proxy/signal", parsed.request.path);
    try std.testing.expectEqualStrings("https", parsed.request.headers.get("x-forwarded-proto").?);
    try std.testing.expectEqualStrings("websocket", parsed.request.headers.get("x-http2-protocol").?);
}

test "decodeRequestHeaderBlock rejects :protocol on non-CONNECT" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":path", .value = "/ws" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    }, &block_buf);

    try std.testing.expectError(error.UnexpectedPseudoHeader, decodeRequestHeaderBlock(block, 1, &request_storage_buf));
}

test "decodeRequestHeaderBlock stores decoded slices in caller storage" {
    var block_buf: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/stable/path" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-type", .value = "application/grpc" },
    }, &block_buf);

    const parsed = try decodeRequestHeaderBlock(block, 1, &request_storage_buf);

    const storage_start = @intFromPtr(&request_storage_buf[0]);
    const storage_end = storage_start + request_storage_buf.len;
    const path_ptr = @intFromPtr(parsed.request.path.ptr);
    const content_type_ptr = @intFromPtr(parsed.request.headers.get("content-type").?.ptr);

    try std.testing.expect(path_ptr >= storage_start and path_ptr < storage_end);
    try std.testing.expect(content_type_ptr >= storage_start and content_type_ptr < storage_end);
}

test "decodeRequestHeaderBlock rejects undersized stable storage" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeHeaderPairs(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/small-storage" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-type", .value = "application/grpc" },
    }, &block_buf);

    var tiny_storage: [8]u8 = undefined;
    try std.testing.expectError(error.StableStorageTooSmall, decodeRequestHeaderBlock(block, 1, &tiny_storage));
}

test "parseInitialRequest fuzz corpus maintains parser invariants" {
    var prng = std.Random.DefaultPrng.init(0x1234_abcd);
    const random = prng.random();

    var input: [256]u8 = undefined;
    var request_storage_buf: [request_stable_storage_size_bytes]u8 = undefined;

    var iteration: u32 = 0;
    while (iteration < 512) : (iteration += 1) {
        const len: usize = random.intRangeAtMost(usize, 1, input.len);
        random.bytes(input[0..len]);

        const parsed = parseInitialRequest(input[0..len], &request_storage_buf) catch |err| {
            switch (err) {
                error.NeedMoreData,
                error.InvalidPreface,
                error.InvalidFrame,
                error.InvalidFrameType,
                error.InvalidStreamId,
                error.HeadersTooLarge,
                error.UnsupportedContinuation,
                error.UnsupportedPadding,
                error.UnsupportedPriority,
                error.MissingMethod,
                error.MissingPath,
                error.MissingScheme,
                error.MissingAuthority,
                error.InvalidMethod,
                error.InvalidTe,
                error.InvalidHeaderName,
                error.UnexpectedPseudoHeader,
                error.PseudoHeaderAfterRegularHeader,
                error.DuplicatePseudoHeader,
                error.ConnectionSpecificHeader,
                error.ConnectPathNotAllowed,
                error.ConnectSchemeNotAllowed,
                error.AuthorityHostMismatch,
                error.TooManyFrames,
                error.TooManyHeaders,
                error.DuplicateContentLength,
                error.StableStorageTooSmall,
                error.FrameTooLarge,
                error.BufferTooSmall,
                error.InvalidPayloadLength,
                error.ReservedBitSet,
                error.AckMustBeEmpty,
                error.TooManySettings,
                error.InvalidEnablePush,
                error.InvalidInitialWindowSize,
                error.InvalidMaxFrameSize,
                error.IntegerOverflow,
                error.InvalidStringLength,
                error.InvalidIndex,
                error.UnsupportedDynamicTableIndex,
                error.DynamicTableSizeTooLarge,
                error.InvalidDynamicTableSizeUpdate,
                error.InvalidHuffman,
                => continue,
            }
        };

        try std.testing.expect(parsed.consumed_bytes <= len);
        try std.testing.expect(parsed.stream_id > 0);
        try std.testing.expect(parsed.request.path.len > 0);
    }
}
