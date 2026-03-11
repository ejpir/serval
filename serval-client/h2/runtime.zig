//! HTTP/2 Client Runtime Primitives
//!
//! Bounded outbound per-frame runtime for prior-knowledge h2c upstream sessions.
//! This file does not own sockets; it validates frame sequencing, updates
//! connection state, and exposes explicit actions for higher-level clients.
//! TigerStyle: Explicit state transitions, fixed buffers, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const types = @import("serval-core").types;
const h2 = @import("serval-h2");
const session = @import("session.zig");

const Method = types.Method;
const Request = types.Request;
const Response = types.Response;
const Header = types.Header;
const HeaderMap = types.HeaderMap;

pub const Error = error{
    MissingInitialSettings,
    MissingAuthority,
    HeaderBlockTooLarge,
    MissingStatus,
    DuplicateStatus,
    InvalidStatus,
    UnexpectedPseudoHeader,
    PseudoHeaderAfterRegularHeader,
    ResponseHeadersTooMany,
    DuplicateResponseContentLength,
    TrailersTooMany,
    DuplicateTrailerContentLength,
    InvalidHeadersStream,
    InvalidDataStream,
    TrailersMustEndStream,
    UnsupportedContinuation,
    UnexpectedContinuation,
    ContinuationStreamMismatch,
    TooManyContinuationFrames,
    UnsupportedPadding,
    UnsupportedPriority,
    UnsupportedPushPromise,
    ResponseStateTableFull,
} || session.Error || h2.ControlError || h2.FlowControlError || h2.HpackError || h2.StreamError || h2.FrameError;

pub const RequestHeadersWrite = struct {
    stream_id: u32,
    frame: []const u8,
};

pub const ResponseHeadersAction = struct {
    stream_id: u32,
    end_stream: bool,
    response: Response,
};

pub const ResponseDataAction = struct {
    stream_id: u32,
    end_stream: bool,
    payload: []const u8,
};

pub const ResponseTrailersAction = struct {
    stream_id: u32,
    trailers: HeaderMap,
};

pub const StreamResetAction = struct {
    stream_id: u32,
    error_code_raw: u32,
};

pub const ReceiveAction = union(enum) {
    none,
    send_settings_ack,
    send_ping_ack: [h2.control.ping_payload_size_bytes]u8,
    response_headers: ResponseHeadersAction,
    response_data: ResponseDataAction,
    response_trailers: ResponseTrailersAction,
    stream_reset: StreamResetAction,
    connection_close: h2.GoAway,
};

const PendingResponseHeaders = struct {
    active: bool = false,
    stream_id: u32 = 0,
    end_stream: bool = false,
    is_trailers: bool = false,
    continuation_frames: u8 = 0,
    block_len: u32 = 0,
    block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined,
};

pub const Runtime = struct {
    state: session.SessionState,
    header_decoder: h2.HpackDecoder = h2.HpackDecoder.init(),
    response_states: ResponseStateTable = .{},
    pending_response_headers: PendingResponseHeaders = .{},

    pub fn init() Error!Runtime {
        return .{
            .state = try session.SessionState.init(),
            .header_decoder = h2.HpackDecoder.init(),
        };
    }

    pub fn writeClientPrefaceAndSettings(self: *Runtime, out: []u8) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(out.len >= h2.client_connection_preface.len + h2.frame_header_size_bytes);

        const header_offset = h2.client_connection_preface.len;
        const payload_offset = header_offset + h2.frame_header_size_bytes;

        @memcpy(out[0..h2.client_connection_preface.len], h2.client_connection_preface);
        const payload = try buildLocalSettingsPayload(self.state.local_settings, out[payload_offset..]);
        _ = try h2.buildFrameHeader(out[header_offset..payload_offset], .{
            .length = @intCast(payload.len),
            .frame_type = .settings,
            .flags = 0,
            .stream_id = 0,
        });
        try self.state.markPrefaceSent();
        return out[0 .. payload_offset + payload.len];
    }

    pub fn writePendingSettingsAck(self: *Runtime, out: []u8) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.state.peer_settings_ack_pending);

        const frame = try h2.buildSettingsAckFrame(out);
        self.state.markPeerSettingsAckSent();
        return frame;
    }

    pub fn writePingAckFrame(out: []u8, opaque_data: [h2.control.ping_payload_size_bytes]u8) Error![]const u8 {
        assert(out.len >= h2.frame_header_size_bytes + h2.control.ping_payload_size_bytes);
        return try h2.buildPingFrame(out, h2.flags_ack, opaque_data);
    }

    pub fn writeRstStreamFrame(self: *Runtime, out: []u8, reset: StreamResetAction) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(reset.stream_id > 0);

        const frame = try h2.buildRstStreamFrame(out, reset.stream_id, reset.error_code_raw);
        self.state.resetStream(reset.stream_id) catch |err| switch (err) {
            error.StreamNotFound => {},
            else => return err,
        };
        self.response_states.remove(reset.stream_id);
        return frame;
    }

    pub fn writeGoAwayFrame(self: *Runtime, out: []u8, goaway: h2.GoAway) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(goaway.last_stream_id <= 0x7fff_ffff);

        const frame = try h2.buildGoAwayFrame(
            out,
            goaway.last_stream_id,
            goaway.error_code_raw,
            goaway.debug_data,
        );
        self.state.markGoAwaySent(goaway.last_stream_id);
        return frame;
    }

    pub fn writeRequestHeadersFrame(
        self: *Runtime,
        out: []u8,
        request: *const Request,
        effective_path: ?[]const u8,
        end_stream: bool,
    ) Error!RequestHeadersWrite {
        assert(@intFromPtr(self) != 0);
        assert(request.path.len > 0);
        assert(out.len >= h2.frame_header_size_bytes);

        const path = effective_path orelse request.path;
        assert(path.len > 0);
        const authority = request.headers.getHost() orelse return error.MissingAuthority;

        const header_block = try buildRequestHeaderBlock(request, path, authority, out[h2.frame_header_size_bytes..]);
        const stream = try self.state.openRequestStream(end_stream);
        const flags: u8 = h2.flags_end_headers | if (end_stream) h2.flags_end_stream else 0;

        _ = try h2.buildFrameHeader(out[0..h2.frame_header_size_bytes], .{
            .length = @intCast(header_block.len),
            .frame_type = .headers,
            .flags = flags,
            .stream_id = stream.id,
        });

        return .{
            .stream_id = stream.id,
            .frame = out[0 .. h2.frame_header_size_bytes + header_block.len],
        };
    }

    pub fn writeRequestDataFrame(
        self: *Runtime,
        out: []u8,
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
    ) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const stream = self.state.getStream(stream_id) orelse return error.StreamNotFound;
        if (!stream.localCanSend()) return error.InvalidDataStream;

        if (payload.len > self.state.peer_settings.max_frame_size_bytes) return error.FrameTooLarge;
        if (payload.len > 0) {
            const payload_len: u32 = @intCast(payload.len);
            try self.state.consumeSendWindow(payload_len);
            try self.state.consumeStreamSendWindow(stream_id, payload_len);
        }

        const flags: u8 = if (end_stream) h2.flags_end_stream else 0;
        const frame = try appendFrame(out, .data, flags, stream_id, payload);

        if (end_stream) {
            try self.state.endLocalStream(stream_id);
        }

        return frame;
    }

    pub fn receiveFrame(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(header.length == payload.len);

        try ensureConnectionReady(self, header.frame_type);

        if (self.pending_response_headers.active and header.frame_type != .continuation) {
            return error.UnsupportedContinuation;
        }

        return switch (header.frame_type) {
            .settings => try handleSettings(self, header, payload),
            .headers => try handleHeaders(self, header, payload),
            .data => try handleData(self, header, payload),
            .ping => try handlePing(header, payload),
            .window_update => try handleWindowUpdate(self, header, payload),
            .rst_stream => try handleRstStream(self, header, payload),
            .goaway => try handleGoAway(self, header, payload),
            .continuation => try handleContinuation(self, header, payload),
            .priority => error.UnsupportedPriority,
            .push_promise => error.UnsupportedPushPromise,
        };
    }
};

const response_state_capacity: usize = config.H2_MAX_CONCURRENT_STREAMS;

const ResponseState = struct {
    stream_id: u32 = 0,
    headers_received: bool = false,
};

const ResponseStateSlot = struct {
    used: bool = false,
    state: ResponseState = .{},
};

const ResponseStateTable = struct {
    slots: [response_state_capacity]ResponseStateSlot = [_]ResponseStateSlot{.{}} ** response_state_capacity,
    count: u16 = 0,

    fn get(self: *ResponseStateTable, stream_id: u32) ?*ResponseState {
        assert(stream_id > 0);

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.state.stream_id == stream_id) return &self.slots[index].state;
        }
        return null;
    }

    fn getOrInsert(self: *ResponseStateTable, stream_id: u32) Error!*ResponseState {
        assert(stream_id > 0);

        if (self.get(stream_id)) |existing| return existing;
        const index = self.allocSlot() orelse return error.ResponseStateTableFull;

        self.slots[index] = .{ .used = true, .state = .{ .stream_id = stream_id } };
        self.count += 1;
        return &self.slots[index].state;
    }

    fn remove(self: *ResponseStateTable, stream_id: u32) void {
        assert(stream_id > 0);

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.state.stream_id != stream_id) continue;

            self.slots[index] = .{};
            assert(self.count > 0);
            self.count -= 1;
            return;
        }
    }

    fn allocSlot(self: *const ResponseStateTable) ?usize {
        if (self.count >= config.H2_MAX_CONCURRENT_STREAMS) return null;

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) return index;
        }
        return null;
    }
};

fn ensureConnectionReady(self: *const Runtime, frame_type: h2.FrameType) Error!void {
    assert(@intFromPtr(self) != 0);

    if (!self.state.preface_sent) return error.PrefaceNotSent;
    if (!self.state.peer_settings_received and frame_type != .settings) {
        return error.MissingInitialSettings;
    }
}

fn handleSettings(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .settings);

    const is_ack = (header.flags & h2.flags_ack) != 0;
    try self.state.receivePeerSettings(header, payload);
    if (is_ack) return .none;

    try self.header_decoder.setMaxDynamicTableSize(self.state.peer_settings.header_table_size_bytes);
    return .send_settings_ack;
}

fn handleHeaders(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .headers);

    if (header.stream_id == 0) return error.InvalidHeadersStream;
    if ((header.flags & h2.flags_padded) != 0) return error.UnsupportedPadding;
    if ((header.flags & h2.flags_priority) != 0) return error.UnsupportedPriority;

    const stream = self.state.getStream(header.stream_id) orelse return error.StreamNotFound;
    if (!stream.remoteCanSend()) return error.InvalidHeadersStream;

    const end_stream = (header.flags & h2.flags_end_stream) != 0;
    const state_entry = try self.response_states.getOrInsert(header.stream_id);

    if (!state_entry.headers_received) {
        if ((header.flags & h2.flags_end_headers) == 0) {
            try startResponseHeaderContinuation(self, header.stream_id, end_stream, false, payload);
            return .none;
        }

        const response = try decodeResponseHeaderBlock(&self.header_decoder, payload);
        state_entry.headers_received = true;

        if (end_stream) {
            try self.state.endRemoteStream(header.stream_id);
            self.response_states.remove(header.stream_id);
        }

        return .{ .response_headers = .{
            .stream_id = header.stream_id,
            .end_stream = end_stream,
            .response = response,
        } };
    }

    if (!end_stream) return error.TrailersMustEndStream;

    if ((header.flags & h2.flags_end_headers) == 0) {
        try startResponseHeaderContinuation(self, header.stream_id, true, true, payload);
        return .none;
    }

    const trailers = try decodeTrailerHeaderBlock(&self.header_decoder, payload);
    try self.state.endRemoteStream(header.stream_id);
    self.response_states.remove(header.stream_id);
    return .{ .response_trailers = .{ .stream_id = header.stream_id, .trailers = trailers } };
}

fn handleContinuation(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .continuation);
    assert(header.length == payload.len);

    if (!self.pending_response_headers.active) return error.UnexpectedContinuation;
    if (header.stream_id != self.pending_response_headers.stream_id) return error.ContinuationStreamMismatch;
    if ((header.flags & ~(h2.flags_end_headers)) != 0) return error.UnsupportedContinuation;

    if (self.pending_response_headers.continuation_frames >= config.H2_MAX_CONTINUATION_FRAMES) {
        return error.TooManyContinuationFrames;
    }
    self.pending_response_headers.continuation_frames += 1;

    try appendPendingResponseHeaderFragment(self, payload);

    if ((header.flags & h2.flags_end_headers) == 0) return .none;
    return try finishPendingResponseHeaders(self);
}

fn startResponseHeaderContinuation(
    self: *Runtime,
    stream_id: u32,
    end_stream: bool,
    is_trailers: bool,
    payload: []const u8,
) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);

    self.pending_response_headers.active = true;
    self.pending_response_headers.stream_id = stream_id;
    self.pending_response_headers.end_stream = end_stream;
    self.pending_response_headers.is_trailers = is_trailers;
    self.pending_response_headers.continuation_frames = 0;
    self.pending_response_headers.block_len = 0;

    try appendPendingResponseHeaderFragment(self, payload);
}

fn appendPendingResponseHeaderFragment(self: *Runtime, payload: []const u8) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(self.pending_response_headers.active);

    const current_len: usize = @intCast(self.pending_response_headers.block_len);
    if (current_len + payload.len > config.H2_MAX_HEADER_BLOCK_SIZE_BYTES) return error.HeaderBlockTooLarge;

    @memcpy(
        self.pending_response_headers.block_buf[current_len .. current_len + payload.len],
        payload,
    );
    self.pending_response_headers.block_len = @intCast(current_len + payload.len);
}

fn finishPendingResponseHeaders(self: *Runtime) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(self.pending_response_headers.active);

    const stream_id = self.pending_response_headers.stream_id;
    const end_stream = self.pending_response_headers.end_stream;
    const is_trailers = self.pending_response_headers.is_trailers;
    const block_len: usize = @intCast(self.pending_response_headers.block_len);
    errdefer resetPendingResponseHeaders(self);

    const block = self.pending_response_headers.block_buf[0..block_len];
    if (is_trailers) {
        const trailers = try decodeTrailerHeaderBlock(&self.header_decoder, block);
        try self.state.endRemoteStream(stream_id);
        self.response_states.remove(stream_id);
        resetPendingResponseHeaders(self);
        return .{ .response_trailers = .{
            .stream_id = stream_id,
            .trailers = trailers,
        } };
    }

    const response = try decodeResponseHeaderBlock(&self.header_decoder, block);
    const state_entry = try self.response_states.getOrInsert(stream_id);
    state_entry.headers_received = true;

    if (end_stream) {
        try self.state.endRemoteStream(stream_id);
        self.response_states.remove(stream_id);
    }

    resetPendingResponseHeaders(self);
    return .{ .response_headers = .{
        .stream_id = stream_id,
        .end_stream = end_stream,
        .response = response,
    } };
}

fn resetPendingResponseHeaders(self: *Runtime) void {
    assert(@intFromPtr(self) != 0);

    self.pending_response_headers.active = false;
    self.pending_response_headers.stream_id = 0;
    self.pending_response_headers.end_stream = false;
    self.pending_response_headers.is_trailers = false;
    self.pending_response_headers.continuation_frames = 0;
    self.pending_response_headers.block_len = 0;
}

fn handleData(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .data);

    if (header.stream_id == 0) return error.InvalidDataStream;

    const stream = self.state.getStream(header.stream_id) orelse return error.StreamNotFound;
    if (!stream.remoteCanSend()) return error.InvalidDataStream;

    const payload_len: u32 = @intCast(payload.len);
    try self.state.consumeRecvWindow(payload_len);
    try self.state.consumeStreamRecvWindow(header.stream_id, payload_len);

    const end_stream = (header.flags & h2.flags_end_stream) != 0;
    if (end_stream) {
        try self.state.endRemoteStream(header.stream_id);
        self.response_states.remove(header.stream_id);
    }

    return .{ .response_data = .{
        .stream_id = header.stream_id,
        .end_stream = end_stream,
        .payload = payload,
    } };
}

fn handlePing(header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(header.frame_type == .ping);

    const opaque_data = try h2.parsePingFrame(header, payload);
    if ((header.flags & h2.flags_ack) != 0) return .none;
    return .{ .send_ping_ack = opaque_data };
}

fn handleWindowUpdate(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .window_update);

    const increment = try h2.parseWindowUpdateFrame(header, payload);
    if (header.stream_id == 0) {
        try self.state.incrementSendWindow(increment);
    } else {
        try self.state.incrementStreamSendWindow(header.stream_id, increment);
    }

    return .none;
}

fn handleRstStream(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .rst_stream);

    const error_code_raw = try h2.parseRstStreamFrame(header, payload);
    try self.state.resetStream(header.stream_id);
    self.response_states.remove(header.stream_id);
    return .{ .stream_reset = .{ .stream_id = header.stream_id, .error_code_raw = error_code_raw } };
}

fn handleGoAway(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .goaway);

    const goaway = try h2.parseGoAwayFrame(header, payload);
    self.state.markGoAwayReceived(goaway.last_stream_id);
    return .{ .connection_close = goaway };
}

fn buildLocalSettingsPayload(local_settings: h2.Settings, out: []u8) Error![]const u8 {
    const settings = [_]h2.Setting{
        .{ .id = @intFromEnum(h2.SettingId.enable_push), .value = if (local_settings.enable_push) 1 else 0 },
        .{ .id = @intFromEnum(h2.SettingId.max_concurrent_streams), .value = local_settings.max_concurrent_streams },
        .{ .id = @intFromEnum(h2.SettingId.initial_window_size), .value = local_settings.initial_window_size_bytes },
        .{ .id = @intFromEnum(h2.SettingId.max_frame_size), .value = local_settings.max_frame_size_bytes },
    };
    return try h2.buildSettingsPayload(out, &settings);
}

fn buildRequestHeaderBlock(
    request: *const Request,
    path: []const u8,
    authority: []const u8,
    out: []u8,
) Error![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);

    var cursor: usize = 0;
    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":method", methodToken(request.method))).len;
    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":path", path)).len;
    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":authority", authority)).len;

    for (request.headers.headers[0..request.headers.count]) |header| {
        if (skipRequestHeaderForH2(header.name, header.value)) continue;

        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value);
        cursor += encoded.len;

        if (cursor > config.H2_MAX_HEADER_BLOCK_SIZE_BYTES) return error.HeaderBlockTooLarge;
    }

    return out[0..cursor];
}

fn skipRequestHeaderForH2(name: []const u8, value: []const u8) bool {
    if (name.len > 0 and name[0] == ':') return true;

    if (std.ascii.eqlIgnoreCase(name, "host")) return true;
    if (std.ascii.eqlIgnoreCase(name, "connection")) return true;
    if (std.ascii.eqlIgnoreCase(name, "proxy-connection")) return true;
    if (std.ascii.eqlIgnoreCase(name, "upgrade")) return true;
    if (std.ascii.eqlIgnoreCase(name, "http2-settings")) return true;
    if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return true;

    if (!std.ascii.eqlIgnoreCase(name, "te")) return false;
    return !std.ascii.eqlIgnoreCase(trimAsciiWhitespace(value), "trailers");
}

fn trimAsciiWhitespace(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

fn methodToken(method: Method) []const u8 {
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

fn decodeResponseHeaderBlock(decoder: *h2.HpackDecoder, header_block: []const u8) Error!Response {
    assert(@intFromPtr(decoder) != 0);

    var fields_buf: [config.MAX_HEADERS]h2.HeaderField = undefined;
    const fields = try h2.decodeHeaderBlockWithDecoder(decoder, header_block, &fields_buf);

    var response = Response{
        .status = 200,
        .headers = HeaderMap.init(),
        .body = null,
    };
    var status_found = false;
    var regular_headers_seen = false;

    for (fields) |field| {
        if (field.name.len > 0 and field.name[0] == ':') {
            if (regular_headers_seen) return error.PseudoHeaderAfterRegularHeader;

            if (!std.mem.eql(u8, field.name, ":status")) {
                return error.UnexpectedPseudoHeader;
            }
            if (status_found) return error.DuplicateStatus;

            response.status = try parseStatusCode(field.value);
            status_found = true;
            continue;
        }

        regular_headers_seen = true;
        response.headers.put(field.name, field.value) catch |err| switch (err) {
            error.TooManyHeaders => return error.ResponseHeadersTooMany,
            error.DuplicateContentLength => return error.DuplicateResponseContentLength,
        };
    }

    if (!status_found) return error.MissingStatus;
    return response;
}

fn decodeTrailerHeaderBlock(decoder: *h2.HpackDecoder, header_block: []const u8) Error!HeaderMap {
    assert(@intFromPtr(decoder) != 0);

    var fields_buf: [config.MAX_HEADERS]h2.HeaderField = undefined;
    const fields = try h2.decodeHeaderBlockWithDecoder(decoder, header_block, &fields_buf);

    var trailers = HeaderMap.init();
    for (fields) |field| {
        if (field.name.len > 0 and field.name[0] == ':') return error.UnexpectedPseudoHeader;

        trailers.put(field.name, field.value) catch |err| switch (err) {
            error.TooManyHeaders => return error.TrailersTooMany,
            error.DuplicateContentLength => return error.DuplicateTrailerContentLength,
        };
    }

    return trailers;
}

fn parseStatusCode(token: []const u8) Error!u16 {
    if (token.len != 3) return error.InvalidStatus;

    const status = std.fmt.parseUnsigned(u16, token, 10) catch {
        return error.InvalidStatus;
    };
    if (status < 100 or status > 599) return error.InvalidStatus;
    return status;
}

fn appendFrame(out: []u8, frame_type: h2.FrameType, flags: u8, stream_id: u32, payload: []const u8) Error![]const u8 {
    assert(out.len >= h2.frame_header_size_bytes);

    const header = try h2.buildFrameHeader(out[0..h2.frame_header_size_bytes], .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });

    @memcpy(out[header.len..][0..payload.len], payload);
    return out[0 .. header.len + payload.len];
}

fn buildResponseHeaderBlock(status: u16, headers: []const Header, out: []u8) ![]const u8 {
    assert(status >= 100);

    var cursor: usize = 0;
    var status_buf: [3]u8 = undefined;
    const status_text = try std.fmt.bufPrint(&status_buf, "{d}", .{status});

    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":status", status_text)).len;
    for (headers) |header| {
        cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value)).len;
    }

    return out[0..cursor];
}

fn buildHeaderBlock(headers: []const Header, out: []u8) ![]const u8 {
    var cursor: usize = 0;
    for (headers) |header| {
        cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value)).len;
    }
    return out[0..cursor];
}

fn makeGrpcRequest(path: []const u8) !Request {
    var request = Request{
        .method = .POST,
        .path = path,
        .version = .@"HTTP/1.1",
        .headers = HeaderMap.init(),
        .body = null,
    };
    try request.headers.put("host", "127.0.0.1:19000");
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");
    return request;
}

fn initRuntimeReadyForStreams() !Runtime {
    var runtime = try Runtime.init();

    var preface_buf: [h2.client_connection_preface.len + h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
    _ = try runtime.writeClientPrefaceAndSettings(&preface_buf);

    const peer_settings = h2.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    const action = try runtime.receiveFrame(peer_settings, &[_]u8{});
    switch (action) {
        .send_settings_ack => {},
        else => return error.UnexpectedAction,
    }

    var ack_buf: [h2.frame_header_size_bytes]u8 = undefined;
    _ = try runtime.writePendingSettingsAck(&ack_buf);
    return runtime;
}

test "Runtime writes client preface and SETTINGS" {
    var runtime = try Runtime.init();

    var out: [h2.client_connection_preface.len + h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
    const encoded = try runtime.writeClientPrefaceAndSettings(&out);

    try std.testing.expectEqualSlices(u8, h2.client_connection_preface, encoded[0..h2.client_connection_preface.len]);

    const settings_header = try h2.parseFrameHeader(encoded[h2.client_connection_preface.len..]);
    try std.testing.expectEqual(h2.FrameType.settings, settings_header.frame_type);
    try std.testing.expect(runtime.state.preface_sent);
    try std.testing.expect(runtime.state.local_settings_ack_pending);
}

test "Runtime requires peer settings before non-settings frames" {
    var runtime = try Runtime.init();

    var preface_buf: [h2.client_connection_preface.len + h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
    _ = try runtime.writeClientPrefaceAndSettings(&preface_buf);

    const ping_header = h2.FrameHeader{
        .length = h2.control.ping_payload_size_bytes,
        .frame_type = .ping,
        .flags = 0,
        .stream_id = 0,
    };

    try std.testing.expectError(
        error.MissingInitialSettings,
        runtime.receiveFrame(ping_header, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }),
    );
}

test "Runtime receives peer settings, sends ACK, and accepts SETTINGS ACK" {
    var runtime = try Runtime.init();

    var preface_buf: [h2.client_connection_preface.len + h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
    _ = try runtime.writeClientPrefaceAndSettings(&preface_buf);

    const peer_settings = h2.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    const action = try runtime.receiveFrame(peer_settings, &[_]u8{});
    switch (action) {
        .send_settings_ack => {},
        else => return error.UnexpectedAction,
    }

    try std.testing.expect(runtime.state.peer_settings_received);
    try std.testing.expect(runtime.state.peer_settings_ack_pending);

    var ack_buf: [h2.frame_header_size_bytes]u8 = undefined;
    const ack_frame = try runtime.writePendingSettingsAck(&ack_buf);
    const ack_header = try h2.parseFrameHeader(ack_frame);
    try std.testing.expectEqual(h2.FrameType.settings, ack_header.frame_type);
    try std.testing.expectEqual(h2.flags_ack, ack_header.flags);

    const settings_ack = h2.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = h2.flags_ack,
        .stream_id = 0,
    };
    const ack_action = try runtime.receiveFrame(settings_ack, &[_]u8{});
    try std.testing.expect(ack_action == .none);
    try std.testing.expect(!runtime.state.local_settings_ack_pending);
}

test "Runtime writes request HEADERS and DATA with stream lifecycle" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var headers_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const headers_write = try runtime.writeRequestHeadersFrame(&headers_buf, &request, null, false);
    try std.testing.expectEqual(@as(u32, 1), headers_write.stream_id);

    const headers_header = try h2.parseFrameHeader(headers_write.frame);
    try std.testing.expectEqual(h2.FrameType.headers, headers_header.frame_type);
    try std.testing.expect((headers_header.flags & h2.flags_end_headers) != 0);
    try std.testing.expect((headers_header.flags & h2.flags_end_stream) == 0);

    var data_buf: [h2.frame_header_size_bytes + 16]u8 = undefined;
    const data_frame = try runtime.writeRequestDataFrame(&data_buf, headers_write.stream_id, "ping", true);
    const data_header = try h2.parseFrameHeader(data_frame);

    try std.testing.expectEqual(h2.FrameType.data, data_header.frame_type);
    try std.testing.expect((data_header.flags & h2.flags_end_stream) != 0);
    try std.testing.expect(!runtime.state.getStream(headers_write.stream_id).?.localCanSend());
}

test "Runtime decodes response HEADERS, DATA, and trailers" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, true);

    var header_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &header_block_buf,
    );

    var response_headers_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        h2.flags_end_headers,
        request_headers.stream_id,
        response_block,
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    const headers_action = try runtime.receiveFrame(
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );

    switch (headers_action) {
        .response_headers => |resp| {
            try std.testing.expectEqual(@as(u32, request_headers.stream_id), resp.stream_id);
            try std.testing.expectEqual(@as(u16, 200), resp.response.status);
            try std.testing.expect(!resp.end_stream);
        },
        else => return error.UnexpectedAction,
    }

    const data_header = h2.FrameHeader{
        .length = 4,
        .frame_type = .data,
        .flags = 0,
        .stream_id = request_headers.stream_id,
    };
    const data_action = try runtime.receiveFrame(data_header, "pong");
    switch (data_action) {
        .response_data => |resp_data| {
            try std.testing.expectEqualStrings("pong", resp_data.payload);
            try std.testing.expect(!resp_data.end_stream);
        },
        else => return error.UnexpectedAction,
    }

    var trailer_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const trailer_block = try buildHeaderBlock(&.{.{ .name = "grpc-status", .value = "0" }}, &trailer_block_buf);

    var trailer_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const trailer_frame = try appendFrame(
        &trailer_frame_buf,
        .headers,
        h2.flags_end_headers | h2.flags_end_stream,
        request_headers.stream_id,
        trailer_block,
    );
    const trailer_header = try h2.parseFrameHeader(trailer_frame);
    const trailer_action = try runtime.receiveFrame(
        trailer_header,
        trailer_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + trailer_header.length],
    );

    switch (trailer_action) {
        .response_trailers => |trailers| {
            try std.testing.expectEqualStrings("0", trailers.trailers.get("grpc-status").?);
        },
        else => return error.UnexpectedAction,
    }

    try std.testing.expect(runtime.state.getStream(request_headers.stream_id) == null);
}

test "Runtime reassembles response HEADERS and trailers with CONTINUATION" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, true);

    var response_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &response_block_buf,
    );
    const response_split: usize = response_block.len / 2;
    try std.testing.expect(response_split > 0);
    try std.testing.expect(response_split < response_block.len);

    var response_headers_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        0,
        request_headers.stream_id,
        response_block[0..response_split],
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    const first_headers_action = try runtime.receiveFrame(
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );
    try std.testing.expect(first_headers_action == .none);
    try std.testing.expect(runtime.pending_response_headers.active);

    var response_cont_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_continuation = try appendFrame(
        &response_cont_frame_buf,
        .continuation,
        h2.flags_end_headers,
        request_headers.stream_id,
        response_block[response_split..],
    );
    const response_cont_header = try h2.parseFrameHeader(response_continuation);
    const second_headers_action = try runtime.receiveFrame(
        response_cont_header,
        response_continuation[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_cont_header.length],
    );

    switch (second_headers_action) {
        .response_headers => |resp| {
            try std.testing.expectEqual(@as(u32, request_headers.stream_id), resp.stream_id);
            try std.testing.expectEqual(@as(u16, 200), resp.response.status);
            try std.testing.expect(!resp.end_stream);
        },
        else => return error.UnexpectedAction,
    }
    try std.testing.expect(!runtime.pending_response_headers.active);

    var trailer_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const trailer_block = try buildHeaderBlock(&.{.{ .name = "grpc-status", .value = "0" }}, &trailer_block_buf);
    const trailer_split: usize = trailer_block.len / 2;
    try std.testing.expect(trailer_split > 0);
    try std.testing.expect(trailer_split < trailer_block.len);

    var trailer_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const trailer_frame = try appendFrame(
        &trailer_frame_buf,
        .headers,
        h2.flags_end_stream,
        request_headers.stream_id,
        trailer_block[0..trailer_split],
    );
    const trailer_header = try h2.parseFrameHeader(trailer_frame);
    const first_trailer_action = try runtime.receiveFrame(
        trailer_header,
        trailer_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + trailer_header.length],
    );
    try std.testing.expect(first_trailer_action == .none);
    try std.testing.expect(runtime.pending_response_headers.active);

    var trailer_cont_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const trailer_continuation = try appendFrame(
        &trailer_cont_frame_buf,
        .continuation,
        h2.flags_end_headers,
        request_headers.stream_id,
        trailer_block[trailer_split..],
    );
    const trailer_cont_header = try h2.parseFrameHeader(trailer_continuation);
    const second_trailer_action = try runtime.receiveFrame(
        trailer_cont_header,
        trailer_continuation[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + trailer_cont_header.length],
    );

    switch (second_trailer_action) {
        .response_trailers => |trailers| {
            try std.testing.expectEqualStrings("0", trailers.trailers.get("grpc-status").?);
        },
        else => return error.UnexpectedAction,
    }

    try std.testing.expect(runtime.state.getStream(request_headers.stream_id) == null);
}

test "Runtime rejects interleaved frame while waiting for response CONTINUATION" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, true);

    var response_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &response_block_buf,
    );

    var response_headers_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        0,
        request_headers.stream_id,
        response_block[0 .. response_block.len / 2],
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    _ = try runtime.receiveFrame(
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );

    const data_header = h2.FrameHeader{ .length = 1, .frame_type = .data, .flags = h2.flags_end_stream, .stream_id = request_headers.stream_id };
    try std.testing.expectError(error.UnsupportedContinuation, runtime.receiveFrame(data_header, "x"));
}

test "Runtime rejects unexpected CONTINUATION without pending response headers" {
    var runtime = try initRuntimeReadyForStreams();

    var continuation_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    const continuation_frame = try appendFrame(
        &continuation_frame_buf,
        .continuation,
        h2.flags_end_headers,
        1,
        "x",
    );
    const continuation_header = try h2.parseFrameHeader(continuation_frame);

    try std.testing.expectError(
        error.UnexpectedContinuation,
        runtime.receiveFrame(
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime rejects unexpected CONTINUATION stream" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, true);

    var response_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &response_block_buf,
    );
    const split: usize = response_block.len / 2;

    var response_headers_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        0,
        request_headers.stream_id,
        response_block[0..split],
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    _ = try runtime.receiveFrame(
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );

    var continuation_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const continuation_frame = try appendFrame(
        &continuation_frame_buf,
        .continuation,
        h2.flags_end_headers,
        request_headers.stream_id + 2,
        response_block[split..],
    );
    const continuation_header = try h2.parseFrameHeader(continuation_frame);

    try std.testing.expectError(
        error.ContinuationStreamMismatch,
        runtime.receiveFrame(
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime rejects response CONTINUATION with invalid flags" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, true);

    var response_headers_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        0,
        request_headers.stream_id,
        "x",
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    _ = try runtime.receiveFrame(
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );

    var continuation_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    const continuation_frame = try appendFrame(
        &continuation_frame_buf,
        .continuation,
        h2.flags_end_headers | h2.flags_end_stream,
        request_headers.stream_id,
        "x",
    );
    const continuation_header = try h2.parseFrameHeader(continuation_frame);

    try std.testing.expectError(
        error.UnsupportedContinuation,
        runtime.receiveFrame(
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime enforces response continuation frame bound" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, true);

    var response_headers_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        0,
        request_headers.stream_id,
        "x",
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    _ = try runtime.receiveFrame(
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );

    var continuation_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    var count: u8 = 0;
    while (count < config.H2_MAX_CONTINUATION_FRAMES + 1) : (count += 1) {
        const continuation_frame = try appendFrame(
            &continuation_frame_buf,
            .continuation,
            0,
            request_headers.stream_id,
            "x",
        );
        const continuation_header = try h2.parseFrameHeader(continuation_frame);
        const result = runtime.receiveFrame(
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        );

        if (count == config.H2_MAX_CONTINUATION_FRAMES) {
            try std.testing.expectError(error.TooManyContinuationFrames, result);
            return;
        }
        _ = try result;
    }

    return error.ExpectedTooManyContinuationFrames;
}

test "Runtime handles upstream RST_STREAM and clears stream state" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, true);

    var rst_buf: [h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst_frame = try h2.buildRstStreamFrame(&rst_buf, request_headers.stream_id, @intFromEnum(h2.ErrorCode.cancel));
    const rst_header = try h2.parseFrameHeader(rst_frame);
    const action = try runtime.receiveFrame(rst_header, rst_frame[h2.frame_header_size_bytes..]);

    switch (action) {
        .stream_reset => |reset| {
            try std.testing.expectEqual(request_headers.stream_id, reset.stream_id);
            try std.testing.expectEqual(@as(u32, @intFromEnum(h2.ErrorCode.cancel)), reset.error_code_raw);
        },
        else => return error.UnexpectedAction,
    }

    try std.testing.expect(runtime.state.getStream(request_headers.stream_id) == null);
}

test "Runtime tracks GOAWAY bound and rejects new streams above last_stream_id" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    _ = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, false);

    var goaway_buf: [h2.frame_header_size_bytes + h2.control.goaway_min_payload_size_bytes]u8 = undefined;
    const goaway_frame = try h2.buildGoAwayFrame(
        &goaway_buf,
        1,
        @intFromEnum(h2.ErrorCode.no_error),
        &[_]u8{},
    );
    const goaway_header = try h2.parseFrameHeader(goaway_frame);
    const goaway_action = try runtime.receiveFrame(goaway_header, goaway_frame[h2.frame_header_size_bytes..]);

    switch (goaway_action) {
        .connection_close => |goaway| try std.testing.expectEqual(@as(u32, 1), goaway.last_stream_id),
        else => return error.UnexpectedAction,
    }

    var second_request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    try std.testing.expectError(
        error.ConnectionClosing,
        runtime.writeRequestHeadersFrame(&second_request_frame_buf, &request, null, false),
    );
}

test "Runtime applies WINDOW_UPDATE increments to send windows" {
    var runtime = try initRuntimeReadyForStreams();
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request, null, false);

    const connection_send_before = runtime.state.flow.send_window.available_bytes;
    const stream_send_before = runtime.state.getStream(request_headers.stream_id).?.send_window.available_bytes;

    var connection_update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const connection_update_frame = try h2.buildWindowUpdateFrame(&connection_update_buf, 0, 32);
    const connection_update_header = try h2.parseFrameHeader(connection_update_frame);
    const connection_action = try runtime.receiveFrame(connection_update_header, connection_update_frame[h2.frame_header_size_bytes..]);
    try std.testing.expect(connection_action == .none);

    var stream_update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const stream_update_frame = try h2.buildWindowUpdateFrame(&stream_update_buf, request_headers.stream_id, 16);
    const stream_update_header = try h2.parseFrameHeader(stream_update_frame);
    const stream_action = try runtime.receiveFrame(stream_update_header, stream_update_frame[h2.frame_header_size_bytes..]);
    try std.testing.expect(stream_action == .none);

    try std.testing.expectEqual(connection_send_before + 32, runtime.state.flow.send_window.available_bytes);
    try std.testing.expectEqual(
        stream_send_before + 16,
        runtime.state.getStream(request_headers.stream_id).?.send_window.available_bytes,
    );
}

test "Runtime emits ping ACK action and frame" {
    var runtime = try initRuntimeReadyForStreams();

    const ping_header = h2.FrameHeader{
        .length = h2.control.ping_payload_size_bytes,
        .frame_type = .ping,
        .flags = 0,
        .stream_id = 0,
    };
    const action = try runtime.receiveFrame(ping_header, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });

    switch (action) {
        .send_ping_ack => |opaque_data| {
            var ack_buf: [h2.frame_header_size_bytes + h2.control.ping_payload_size_bytes]u8 = undefined;
            const ack_frame = try Runtime.writePingAckFrame(&ack_buf, opaque_data);
            const ack_header = try h2.parseFrameHeader(ack_frame);
            try std.testing.expectEqual(h2.FrameType.ping, ack_header.frame_type);
            try std.testing.expectEqual(h2.flags_ack, ack_header.flags);
        },
        else => return error.UnexpectedAction,
    }
}
