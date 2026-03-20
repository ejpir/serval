//! HTTP/2 Server Runtime Primitives
//!
//! Bounded per-frame runtime for inbound HTTP/2 server connections. This file
//! does not own sockets; it only validates frame order, updates connection
//! state, and emits explicit actions for the future stream-aware server loop.
//! TigerStyle: Explicit state transitions, fixed buffers, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const types = @import("serval-core").types;
const h2 = @import("serval-h2");

pub const initial_settings_count: usize = 5;
pub const initial_settings_frame_buffer_size_bytes: usize =
    h2.frame_header_size_bytes + (initial_settings_count * h2.setting_size_bytes);
const connection = @import("connection.zig");

pub const Error = error{
    PrefaceNotReceived,
    MissingInitialSettings,
    UnsupportedContinuation,
    UnsupportedPriority,
    UnsupportedPushPromise,
    InvalidDataStream,
    ConnectionClosing,
    StreamProtocolError,
    StreamRefused,
    StreamFlowControlError,
    StreamClosedError,
    ConnectionProtocolError,
    ConnectionStreamClosedError,
} || connection.Error || h2.InitialRequestError || h2.ControlError || h2.FlowControlError || h2.FrameError;

pub const RequestHeadersAction = struct {
    stream_id: u32,
    end_stream: bool,
    request: types.Request,
};

pub const RequestDataAction = struct {
    stream_id: u32,
    end_stream: bool,
    payload: []const u8,
};

pub const StreamResetAction = struct {
    stream_id: u32,
    error_code_raw: u32,
};

pub const ReceiveAction = union(enum) {
    none,
    send_settings_ack,
    send_ping_ack: [h2.control.ping_payload_size_bytes]u8,
    request_headers: RequestHeadersAction,
    request_data: RequestDataAction,
    stream_reset: StreamResetAction,
    connection_close: h2.GoAway,
};

const PendingRequestHeaders = struct {
    active: bool = false,
    stream_id: u32 = 0,
    end_stream: bool = false,
    continuation_frames: u8 = 0,
    block_len: u32 = 0,
    block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined,
};

const request_body_tracker_capacity: usize = config.H2_MAX_CONCURRENT_STREAMS;

const RequestBodyTracker = struct {
    used: bool = false,
    stream_id: u32 = 0,
    expected_content_length: ?u64 = null,
    received_data_bytes: u64 = 0,
};

const priority_field_size_bytes: usize = 5;

pub const Runtime = struct {
    state: connection.ConnectionState,
    header_decoder: h2.HpackDecoder = h2.HpackDecoder.init(),
    pending_request_headers: PendingRequestHeaders = .{},
    request_body_trackers: [request_body_tracker_capacity]RequestBodyTracker = [_]RequestBodyTracker{.{}} ** request_body_tracker_capacity,
    last_peer_reset_stream_id: u32 = 0,

    pub fn init() Error!Runtime {
        return .{
            .state = try connection.ConnectionState.init(),
            .header_decoder = h2.HpackDecoder.init(),
        };
    }

    pub fn receiveClientPreface(self: *Runtime) Error!void {
        assert(@intFromPtr(self) != 0);
        try self.state.markPrefaceReceived();
    }

    pub fn writeInitialSettingsFrame(self: *Runtime, out: []u8) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(out.len >= h2.frame_header_size_bytes);

        const payload = try buildLocalSettingsPayload(self.state.local_settings, out[h2.frame_header_size_bytes..]);
        const header = try h2.buildFrameHeader(out[0..h2.frame_header_size_bytes], .{
            .length = @intCast(payload.len),
            .frame_type = .settings,
            .flags = 0,
            .stream_id = 0,
        });
        try self.state.markLocalSettingsSent();
        return out[0 .. header.len + payload.len];
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

    pub fn writeGoAwayFrame(self: *Runtime, out: []u8, goaway: h2.GoAway) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(goaway.last_stream_id <= 0x7fff_ffff);

        const frame = try h2.buildGoAwayFrame(out, goaway.last_stream_id, goaway.error_code_raw, goaway.debug_data);
        self.state.markGoAwaySent(goaway.last_stream_id);
        return frame;
    }

    pub fn writeRstStreamFrame(self: *Runtime, out: []u8, reset: StreamResetAction) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(reset.stream_id > 0);

        const frame = try h2.buildRstStreamFrame(out, reset.stream_id, reset.error_code_raw);
        self.state.resetStream(reset.stream_id) catch |err| switch (err) {
            error.StreamNotFound => {},
            else => return err,
        };
        return frame;
    }

    pub fn receiveFrame(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(header.length == payload.len);

        if (header.length > self.state.local_settings.max_frame_size_bytes) return error.FrameTooLarge;
        try ensureConnectionReady(self, header.frame_type);

        if (self.pending_request_headers.active and header.frame_type != .continuation) {
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
            .priority => try handlePriority(header, payload),
            .push_promise => error.UnsupportedPushPromise,
            .extension => .none,
        };
    }
};

fn ensureConnectionReady(self: *const Runtime, frame_type: h2.FrameType) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(frame_type != .continuation or self.state.preface_received);

    if (!self.state.preface_received) return error.PrefaceNotReceived;
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
    assert(header.length == payload.len);

    if (header.stream_id == 0) return error.InvalidStreamId;
    if (!self.state.canAcceptRemoteStream(header.stream_id)) return error.ConnectionClosing;

    var header_payload = payload;
    if ((header.flags & h2.flags_padded) != 0) {
        header_payload = try trimPaddedPayload(payload);
    }

    var header_block = header_payload;
    if ((header.flags & h2.flags_priority) != 0) {
        if (header_payload.len < priority_field_size_bytes) return error.InvalidFrame;

        const dependency_stream_id = parsePriorityDependency(header_payload[0..priority_field_size_bytes]);
        if (dependency_stream_id == header.stream_id) return error.StreamProtocolError;
        header_block = header_payload[priority_field_size_bytes..];
    }

    const end_stream = (header.flags & h2.flags_end_stream) != 0;

    if (self.state.getStream(header.stream_id)) |stream| {
        if (!stream.remoteCanSend()) return error.StreamClosedError;
        if ((header.flags & h2.flags_end_headers) == 0) return error.StreamProtocolError;
        if (!end_stream) return error.StreamProtocolError;

        try validateTrailerHeaderBlock(self, header_block);
        try finalizeRequestBodyOnEndStream(self, header.stream_id);
        try self.state.endRemoteStream(header.stream_id);

        return .{ .request_data = .{
            .stream_id = header.stream_id,
            .end_stream = true,
            .payload = &[_]u8{},
        } };
    }

    const last_remote_stream_id = self.state.streams.last_remote_stream_id;
    if (header.stream_id <= last_remote_stream_id) {
        if (header.stream_id == self.last_peer_reset_stream_id) return error.StreamClosedError;
        if (header.stream_id == last_remote_stream_id) return error.ConnectionStreamClosedError;
        return error.ConnectionProtocolError;
    }

    if ((header.flags & h2.flags_end_headers) == 0) {
        try startHeaderBlockContinuation(self, header.stream_id, end_stream, header_block);
        return .none;
    }

    const request_head = h2.decodeRequestHeaderBlockWithDecoder(
        &self.header_decoder,
        header_block,
        header.stream_id,
    ) catch |err| switch (err) {
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
        error.TooManyHeaders,
        error.DuplicateContentLength,
        => return error.StreamProtocolError,
        else => return err,
    };

    _ = self.state.openRemoteStream(header.stream_id, end_stream) catch |err| switch (err) {
        error.StreamTableFull => return error.StreamRefused,
        error.StreamAlreadyExists => return error.StreamClosedError,
        error.WrongStreamParity,
        error.StreamIdRegression,
        error.InvalidTransition,
        => return error.ConnectionProtocolError,
        else => return err,
    };

    try startRequestBodyTracking(self, header.stream_id, &request_head.request, end_stream);

    return .{ .request_headers = .{
        .stream_id = request_head.stream_id,
        .end_stream = end_stream,
        .request = request_head.request,
    } };
}

fn handleContinuation(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .continuation);
    assert(header.length == payload.len);

    if (!self.pending_request_headers.active) return error.UnsupportedContinuation;
    if (header.stream_id != self.pending_request_headers.stream_id) return error.InvalidStreamId;
    if ((header.flags & ~(h2.flags_end_headers)) != 0) return error.InvalidFrame;

    if (self.pending_request_headers.continuation_frames >= config.H2_MAX_CONTINUATION_FRAMES) {
        return error.TooManyFrames;
    }
    self.pending_request_headers.continuation_frames += 1;

    try appendPendingHeaderFragment(self, payload);

    if ((header.flags & h2.flags_end_headers) == 0) return .none;
    return try finishPendingRequestHeaders(self);
}

fn startHeaderBlockContinuation(
    self: *Runtime,
    stream_id: u32,
    end_stream: bool,
    payload: []const u8,
) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);

    self.pending_request_headers.active = true;
    self.pending_request_headers.stream_id = stream_id;
    self.pending_request_headers.end_stream = end_stream;
    self.pending_request_headers.continuation_frames = 0;
    self.pending_request_headers.block_len = 0;

    try appendPendingHeaderFragment(self, payload);
}

fn appendPendingHeaderFragment(self: *Runtime, payload: []const u8) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(self.pending_request_headers.active);

    const current_len: usize = @intCast(self.pending_request_headers.block_len);
    if (current_len + payload.len > config.H2_MAX_HEADER_BLOCK_SIZE_BYTES) {
        return error.HeadersTooLarge;
    }

    @memcpy(
        self.pending_request_headers.block_buf[current_len .. current_len + payload.len],
        payload,
    );
    self.pending_request_headers.block_len = @intCast(current_len + payload.len);
}

fn finishPendingRequestHeaders(self: *Runtime) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(self.pending_request_headers.active);

    const block_len: usize = @intCast(self.pending_request_headers.block_len);
    const stream_id = self.pending_request_headers.stream_id;
    const end_stream = self.pending_request_headers.end_stream;

    if (self.state.getStream(stream_id) != null) {
        resetPendingRequestHeaders(self);
        return error.StreamClosedError;
    }

    const last_remote_stream_id = self.state.streams.last_remote_stream_id;
    if (stream_id <= last_remote_stream_id) {
        resetPendingRequestHeaders(self);
        if (stream_id == self.last_peer_reset_stream_id) return error.StreamClosedError;
        if (stream_id == last_remote_stream_id) return error.ConnectionStreamClosedError;
        return error.ConnectionProtocolError;
    }

    const request_head = h2.decodeRequestHeaderBlockWithDecoder(
        &self.header_decoder,
        self.pending_request_headers.block_buf[0..block_len],
        stream_id,
    ) catch |err| switch (err) {
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
        error.TooManyHeaders,
        error.DuplicateContentLength,
        => {
            resetPendingRequestHeaders(self);
            return error.StreamProtocolError;
        },
        else => return err,
    };

    _ = self.state.openRemoteStream(stream_id, end_stream) catch |err| switch (err) {
        error.StreamTableFull => {
            resetPendingRequestHeaders(self);
            return error.StreamRefused;
        },
        error.StreamAlreadyExists => {
            resetPendingRequestHeaders(self);
            return error.StreamClosedError;
        },
        error.StreamIdRegression,
        error.WrongStreamParity,
        error.InvalidTransition,
        => {
            resetPendingRequestHeaders(self);
            return error.ConnectionProtocolError;
        },
        else => return err,
    };

    resetPendingRequestHeaders(self);
    try startRequestBodyTracking(self, stream_id, &request_head.request, end_stream);

    return .{ .request_headers = .{
        .stream_id = request_head.stream_id,
        .end_stream = end_stream,
        .request = request_head.request,
    } };
}

fn resetPendingRequestHeaders(self: *Runtime) void {
    assert(@intFromPtr(self) != 0);

    self.pending_request_headers.active = false;
    self.pending_request_headers.stream_id = 0;
    self.pending_request_headers.end_stream = false;
    self.pending_request_headers.continuation_frames = 0;
    self.pending_request_headers.block_len = 0;
}

fn trimPaddedPayload(payload: []const u8) Error![]const u8 {
    if (payload.len == 0) return error.InvalidFrame;

    const pad_len: usize = payload[0];
    if (pad_len + 1 > payload.len) return error.InvalidFrame;

    return payload[1 .. payload.len - pad_len];
}

fn parsePriorityDependency(priority_payload: []const u8) u32 {
    assert(priority_payload.len == priority_field_size_bytes);

    const raw_dependency = std.mem.readInt(u32, priority_payload[0..4], .big);
    return raw_dependency & 0x7fff_ffff;
}

fn startRequestBodyTracking(self: *Runtime, stream_id: u32, request: *const types.Request, end_stream: bool) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);
    assert(@intFromPtr(request) != 0);

    const expected_content_length = try parseExpectedContentLength(request);

    var tracker = getOrInsertRequestBodyTracker(self, stream_id);
    tracker.expected_content_length = expected_content_length;
    tracker.received_data_bytes = 0;

    if (end_stream) {
        if (expected_content_length) |expected| {
            if (expected != 0) return error.StreamProtocolError;
        }
        removeRequestBodyTracker(self, stream_id);
    }
}

fn noteRequestData(self: *Runtime, stream_id: u32, data_len: usize, end_stream: bool) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);

    var tracker = getOrInsertRequestBodyTracker(self, stream_id);
    const data_len_u64: u64 = @intCast(data_len);
    const next_bytes = tracker.received_data_bytes +| data_len_u64;
    if (next_bytes < tracker.received_data_bytes) return error.StreamProtocolError;
    tracker.received_data_bytes = next_bytes;

    if (tracker.expected_content_length) |expected| {
        if (tracker.received_data_bytes > expected) return error.StreamProtocolError;
        if (end_stream and tracker.received_data_bytes != expected) return error.StreamProtocolError;
    }

    if (end_stream) removeRequestBodyTracker(self, stream_id);
}

fn finalizeRequestBodyOnEndStream(self: *Runtime, stream_id: u32) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);

    if (getRequestBodyTracker(self, stream_id)) |tracker| {
        if (tracker.expected_content_length) |expected| {
            if (tracker.received_data_bytes != expected) return error.StreamProtocolError;
        }
    }
    removeRequestBodyTracker(self, stream_id);
}

fn parseExpectedContentLength(request: *const types.Request) Error!?u64 {
    assert(@intFromPtr(request) != 0);

    const raw = request.headers.get("content-length") orelse return null;
    const parsed = std.fmt.parseInt(u64, raw, 10) catch return error.StreamProtocolError;
    return parsed;
}

fn validateTrailerHeaderBlock(self: *Runtime, header_block: []const u8) Error!void {
    assert(@intFromPtr(self) != 0);

    var fields_buf: [config.MAX_HEADERS]h2.HeaderField = undefined;
    const fields = try h2.decodeHeaderBlockWithDecoder(&self.header_decoder, header_block, &fields_buf);
    for (fields) |field| {
        if (field.name.len == 0) return error.StreamProtocolError;
        if (field.name[0] == ':') return error.StreamProtocolError;
    }
}

fn getRequestBodyTracker(self: *Runtime, stream_id: u32) ?*RequestBodyTracker {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);

    for (self.request_body_trackers[0..]) |*tracker| {
        if (!tracker.used) continue;
        if (tracker.stream_id != stream_id) continue;
        return tracker;
    }
    return null;
}

fn getOrInsertRequestBodyTracker(self: *Runtime, stream_id: u32) *RequestBodyTracker {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);

    if (getRequestBodyTracker(self, stream_id)) |tracker| return tracker;

    for (self.request_body_trackers[0..]) |*tracker| {
        if (tracker.used) continue;
        tracker.* = .{ .used = true, .stream_id = stream_id };
        return tracker;
    }

    const idx: usize = @intCast(stream_id % @as(u32, request_body_tracker_capacity));
    self.request_body_trackers[idx] = .{ .used = true, .stream_id = stream_id };
    return &self.request_body_trackers[idx];
}

fn removeRequestBodyTracker(self: *Runtime, stream_id: u32) void {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);

    for (self.request_body_trackers[0..]) |*tracker| {
        if (!tracker.used) continue;
        if (tracker.stream_id != stream_id) continue;
        tracker.* = .{};
        return;
    }
}

fn handleData(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .data);

    if (header.stream_id == 0) return error.InvalidDataStream;

    const stream = self.state.getStream(header.stream_id) orelse return error.StreamNotFound;
    if (!stream.remoteCanSend()) return error.InvalidDataStream;

    const data_payload = if ((header.flags & h2.flags_padded) != 0)
        try trimPaddedPayload(payload)
    else
        payload;

    const payload_len: u32 = @intCast(payload.len);

    // RFC 9113 flow-control: classify stream-level exhaustion distinctly and
    // avoid mutating connection window on stream-local underflow.
    if (payload_len > self.state.flow.recv_window.available_bytes) return error.WindowUnderflow;
    if (payload_len > stream.recv_window.available_bytes) return error.StreamFlowControlError;

    try self.state.consumeRecvWindow(payload_len);
    self.state.consumeStreamRecvWindow(header.stream_id, payload_len) catch |err| switch (err) {
        error.WindowUnderflow,
        error.WindowOverflow,
        error.InvalidIncrement,
        => return error.StreamFlowControlError,
        else => return err,
    };

    const end_stream = (header.flags & h2.flags_end_stream) != 0;
    try noteRequestData(self, header.stream_id, data_payload.len, end_stream);
    if (end_stream) try self.state.endRemoteStream(header.stream_id);
    return .{ .request_data = .{ .stream_id = header.stream_id, .end_stream = end_stream, .payload = data_payload } };
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

    const increment = h2.parseWindowUpdateFrame(header, payload) catch |err| switch (err) {
        error.InvalidIncrement => {
            if (header.stream_id == 0) return error.InvalidIncrement;
            return error.StreamProtocolError;
        },
        else => return err,
    };

    if (header.stream_id == 0) {
        try self.state.incrementSendWindow(increment);
    } else {
        self.state.incrementStreamSendWindow(header.stream_id, increment) catch |err| switch (err) {
            error.StreamNotFound => {
                if (header.stream_id > self.state.streams.last_remote_stream_id) {
                    return error.ConnectionProtocolError;
                }
                return .none;
            },
            error.WindowOverflow => return error.StreamFlowControlError,
            else => return err,
        };
    }
    return .none;
}

fn handlePriority(header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(header.frame_type == .priority);
    assert(header.length == payload.len);

    if (header.stream_id == 0) return error.InvalidStreamId;
    if (payload.len != priority_field_size_bytes) return error.InvalidFrame;

    const dependency_stream_id = parsePriorityDependency(payload);
    if (dependency_stream_id == header.stream_id) return error.StreamProtocolError;

    return .none;
}

fn handleRstStream(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .rst_stream);

    const error_code_raw = try h2.parseRstStreamFrame(header, payload);

    if (self.state.getStream(header.stream_id) == null) {
        if (header.stream_id > self.state.streams.last_remote_stream_id) {
            return error.ConnectionProtocolError;
        }

        removeRequestBodyTracker(self, header.stream_id);
        self.last_peer_reset_stream_id = header.stream_id;
        return .none;
    }

    try self.state.resetStream(header.stream_id);
    removeRequestBodyTracker(self, header.stream_id);
    self.last_peer_reset_stream_id = header.stream_id;
    return .{ .stream_reset = .{ .stream_id = header.stream_id, .error_code_raw = error_code_raw } };
}

fn handleGoAway(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .goaway);

    const goaway = try h2.parseGoAwayFrame(header, payload);
    self.state.markGoAwayReceived(goaway.last_stream_id);
    return .none;
}

fn buildLocalSettingsPayload(local_settings: h2.Settings, out: []u8) Error![]const u8 {
    const settings = [_]h2.Setting{
        .{ .id = @intFromEnum(h2.SettingId.enable_push), .value = if (local_settings.enable_push) 1 else 0 },
        .{ .id = @intFromEnum(h2.SettingId.max_concurrent_streams), .value = local_settings.max_concurrent_streams },
        .{ .id = @intFromEnum(h2.SettingId.initial_window_size), .value = local_settings.initial_window_size_bytes },
        .{ .id = @intFromEnum(h2.SettingId.max_frame_size), .value = local_settings.max_frame_size_bytes },
        .{ .id = @intFromEnum(h2.SettingId.enable_connect_protocol), .value = if (local_settings.enable_connect_protocol) 1 else 0 },
    };
    return try h2.buildSettingsPayload(out, &settings);
}

fn buildHeaderBlock(path: []const u8, out: []u8) ![]const u8 {
    assert(path.len > 0);
    var len: usize = 0;
    const fields = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "127.0.0.1:8080" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    for (fields) |field| {
        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[len..], field.name, field.value);
        len += encoded.len;
    }
    return out[0..len];
}

fn appendFrame(out: []u8, frame_type: h2.FrameType, flags: u8, stream_id: u32, payload: []const u8) ![]const u8 {
    assert(out.len > 0);
    const header = try h2.buildFrameHeader(out[0..h2.frame_header_size_bytes], .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    @memcpy(out[header.len..][0..payload.len], payload);
    return out[0 .. header.len + payload.len];
}

test "Runtime requires preface before frames" {
    var runtime = try Runtime.init();
    const header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    try std.testing.expectError(error.PrefaceNotReceived, runtime.receiveFrame(header, &[_]u8{}));
}

test "Runtime writes initial settings and requires peer settings before headers" {
    var runtime = try Runtime.init();
    var settings_buf: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    const encoded = try runtime.writeInitialSettingsFrame(&settings_buf);
    const header = try h2.parseFrameHeader(encoded);

    try std.testing.expect(runtime.state.local_settings_sent);
    try std.testing.expect(runtime.state.local_settings_ack_pending);
    try std.testing.expectEqual(h2.FrameType.settings, header.frame_type);

    try runtime.receiveClientPreface();

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/Unary", &header_block_buf);
    var frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(&frame_buf, .headers, h2.flags_end_headers, 1, header_block);
    const headers_header = try h2.parseFrameHeader(headers_frame);
    try std.testing.expectError(
        error.MissingInitialSettings,
        runtime.receiveFrame(headers_header, headers_frame[h2.frame_header_size_bytes..]),
    );
}

test "Runtime decodes request headers and data on one stream" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    const settings_action = try runtime.receiveFrame(settings_header, &[_]u8{});
    switch (settings_action) {
        .send_settings_ack => {},
        else => return error.InvalidFrame,
    }

    var ack_buf: [h2.frame_header_size_bytes]u8 = undefined;
    _ = try runtime.writePendingSettingsAck(&ack_buf);
    try std.testing.expect(!runtime.state.peer_settings_ack_pending);

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/Unary", &header_block_buf);
    var headers_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(&headers_frame_buf, .headers, h2.flags_end_headers, 1, header_block);
    const headers_header = try h2.parseFrameHeader(headers_frame);
    const headers_action = try runtime.receiveFrame(headers_header, headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length]);

    switch (headers_action) {
        .request_headers => |req| {
            try std.testing.expectEqual(@as(u32, 1), req.stream_id);
            try std.testing.expectEqualStrings("/grpc.test.Echo/Unary", req.request.path);
            try std.testing.expect(!req.end_stream);
        },
        else => return error.InvalidFrame,
    }

    const data_header = h2.FrameHeader{
        .length = 4,
        .frame_type = .data,
        .flags = h2.flags_end_stream,
        .stream_id = 1,
    };
    const data_action = try runtime.receiveFrame(data_header, "ping");
    switch (data_action) {
        .request_data => |data| {
            try std.testing.expectEqual(@as(u32, 1), data.stream_id);
            try std.testing.expectEqualStrings("ping", data.payload);
            try std.testing.expect(data.end_stream);
        },
        else => return error.InvalidFrame,
    }

    try std.testing.expect(!runtime.state.getStream(1).?.remoteCanSend());
}

test "Runtime ignores PRIORITY frame after initial settings" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var priority_frame_buf: [h2.frame_header_size_bytes + priority_field_size_bytes]u8 = undefined;
    const priority_frame = try appendFrame(
        &priority_frame_buf,
        .priority,
        0,
        3,
        &[_]u8{ 0, 0, 0, 0, 15 },
    );
    const priority_header = try h2.parseFrameHeader(priority_frame);

    const action = try runtime.receiveFrame(
        priority_header,
        priority_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + priority_header.length],
    );
    try std.testing.expect(action == .none);
}

test "Runtime decodes HEADERS with PRIORITY flag" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/HeadersPriority", &header_block_buf);

    var payload_buf: [priority_field_size_bytes + 256]u8 = undefined;
    @memcpy(payload_buf[0..priority_field_size_bytes], &[_]u8{ 0, 0, 0, 0, 9 });
    @memcpy(payload_buf[priority_field_size_bytes .. priority_field_size_bytes + header_block.len], header_block);
    const payload = payload_buf[0 .. priority_field_size_bytes + header_block.len];

    var headers_frame_buf: [h2.frame_header_size_bytes + priority_field_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(
        &headers_frame_buf,
        .headers,
        h2.flags_end_headers | h2.flags_priority,
        1,
        payload,
    );
    const headers_header = try h2.parseFrameHeader(headers_frame);
    const action = try runtime.receiveFrame(
        headers_header,
        headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length],
    );

    switch (action) {
        .request_headers => |req| {
            try std.testing.expectEqual(@as(u32, 1), req.stream_id);
            try std.testing.expectEqualStrings("/grpc.test.Echo/HeadersPriority", req.request.path);
        },
        else => return error.InvalidFrame,
    }
}

test "Runtime decodes padded HEADERS" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/PaddedHeaders", &header_block_buf);

    const pad_len: usize = 2;
    var payload_buf: [1 + 256 + pad_len]u8 = undefined;
    payload_buf[0] = @intCast(pad_len);
    @memcpy(payload_buf[1 .. 1 + header_block.len], header_block);
    @memset(payload_buf[1 + header_block.len .. 1 + header_block.len + pad_len], 0);

    var frame_buf: [h2.frame_header_size_bytes + 1 + 256 + pad_len]u8 = undefined;
    const frame = try appendFrame(
        &frame_buf,
        .headers,
        h2.flags_end_headers | h2.flags_padded,
        1,
        payload_buf[0 .. 1 + header_block.len + pad_len],
    );
    const header = try h2.parseFrameHeader(frame);
    const action = try runtime.receiveFrame(
        header,
        frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + header.length],
    );

    switch (action) {
        .request_headers => |req| try std.testing.expectEqualStrings("/grpc.test.Echo/PaddedHeaders", req.request.path),
        else => return error.InvalidFrame,
    }
}

test "Runtime rejects self-dependent PRIORITY as stream protocol error" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    const priority_payload = [_]u8{ 0x00, 0x00, 0x00, 0x01, 16 };
    const priority_header = h2.FrameHeader{
        .length = priority_payload.len,
        .frame_type = .priority,
        .flags = 0,
        .stream_id = 1,
    };

    try std.testing.expectError(error.StreamProtocolError, runtime.receiveFrame(priority_header, &priority_payload));
}

test "Runtime rejects idle RST_STREAM as connection protocol error" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var rst_buf: [h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst_frame = try h2.buildRstStreamFrame(&rst_buf, 1, @intFromEnum(h2.ErrorCode.cancel));
    const rst_header = try h2.parseFrameHeader(rst_frame);

    try std.testing.expectError(
        error.ConnectionProtocolError,
        runtime.receiveFrame(rst_header, rst_frame[h2.frame_header_size_bytes..]),
    );
}

test "Runtime reassembles request HEADERS with CONTINUATION" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/Continuation", &header_block_buf);
    const split: usize = header_block.len / 2;
    try std.testing.expect(split > 0);
    try std.testing.expect(split < header_block.len);

    var headers_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(
        &headers_frame_buf,
        .headers,
        0,
        1,
        header_block[0..split],
    );
    const headers_header = try h2.parseFrameHeader(headers_frame);
    const first_action = try runtime.receiveFrame(
        headers_header,
        headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length],
    );
    try std.testing.expect(first_action == .none);
    try std.testing.expect(runtime.pending_request_headers.active);

    var continuation_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const continuation_frame = try appendFrame(
        &continuation_frame_buf,
        .continuation,
        h2.flags_end_headers,
        1,
        header_block[split..],
    );
    const continuation_header = try h2.parseFrameHeader(continuation_frame);
    const final_action = try runtime.receiveFrame(
        continuation_header,
        continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
    );

    switch (final_action) {
        .request_headers => |req| {
            try std.testing.expectEqual(@as(u32, 1), req.stream_id);
            try std.testing.expectEqualStrings("/grpc.test.Echo/Continuation", req.request.path);
            try std.testing.expect(!req.end_stream);
        },
        else => return error.InvalidFrame,
    }
    try std.testing.expect(!runtime.pending_request_headers.active);
}

test "Runtime rejects interleaved frame while waiting for CONTINUATION" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/Interleave", &header_block_buf);
    const split: usize = header_block.len / 2;

    var headers_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(&headers_frame_buf, .headers, 0, 1, header_block[0..split]);
    const headers_header = try h2.parseFrameHeader(headers_frame);
    _ = try runtime.receiveFrame(headers_header, headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length]);

    const data_header = h2.FrameHeader{ .length = 1, .frame_type = .data, .flags = h2.flags_end_stream, .stream_id = 1 };
    try std.testing.expectError(error.UnsupportedContinuation, runtime.receiveFrame(data_header, "x"));
}

test "Runtime rejects unexpected CONTINUATION without pending headers" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

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
        error.UnsupportedContinuation,
        runtime.receiveFrame(
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime rejects CONTINUATION stream mismatch" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/Mismatch", &header_block_buf);
    const split: usize = header_block.len / 2;

    var headers_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(&headers_frame_buf, .headers, 0, 1, header_block[0..split]);
    const headers_header = try h2.parseFrameHeader(headers_frame);
    _ = try runtime.receiveFrame(headers_header, headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length]);

    var continuation_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const continuation_frame = try appendFrame(&continuation_frame_buf, .continuation, h2.flags_end_headers, 3, header_block[split..]);
    const continuation_header = try h2.parseFrameHeader(continuation_frame);

    try std.testing.expectError(
        error.InvalidStreamId,
        runtime.receiveFrame(
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime rejects CONTINUATION with invalid flags" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var headers_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    const headers_frame = try appendFrame(&headers_frame_buf, .headers, 0, 1, "x");
    const headers_header = try h2.parseFrameHeader(headers_frame);
    _ = try runtime.receiveFrame(
        headers_header,
        headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length],
    );

    var continuation_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    const continuation_frame = try appendFrame(
        &continuation_frame_buf,
        .continuation,
        h2.flags_end_headers | h2.flags_end_stream,
        1,
        "x",
    );
    const continuation_header = try h2.parseFrameHeader(continuation_frame);

    try std.testing.expectError(
        error.InvalidFrame,
        runtime.receiveFrame(
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime enforces continuation frame bound" {
    var runtime = try Runtime.init();
    var settings_out: [initial_settings_frame_buffer_size_bytes]u8 = undefined;
    _ = try runtime.writeInitialSettingsFrame(&settings_out);
    try runtime.receiveClientPreface();

    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var headers_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    const headers_frame = try appendFrame(&headers_frame_buf, .headers, 0, 1, "x");
    const headers_header = try h2.parseFrameHeader(headers_frame);
    _ = try runtime.receiveFrame(headers_header, headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length]);

    var continuation_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    var count: u8 = 0;
    while (count < config.H2_MAX_CONTINUATION_FRAMES + 1) : (count += 1) {
        const continuation = try appendFrame(&continuation_frame_buf, .continuation, 0, 1, "x");
        const continuation_header = try h2.parseFrameHeader(continuation);
        const result = runtime.receiveFrame(
            continuation_header,
            continuation[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        );

        if (count == config.H2_MAX_CONTINUATION_FRAMES) {
            try std.testing.expectError(error.TooManyFrames, result);
            return;
        }
        _ = try result;
    }

    return error.ExpectedTooManyFrames;
}

test "Runtime emits ping acknowledgements" {
    var runtime = try Runtime.init();
    try runtime.receiveClientPreface();
    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

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
        else => return error.InvalidFrame,
    }
}

test "Runtime applies WINDOW_UPDATE and RST_STREAM" {
    var runtime = try Runtime.init();
    try runtime.receiveClientPreface();
    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/Unary", &header_block_buf);
    var headers_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(&headers_frame_buf, .headers, h2.flags_end_headers, 1, header_block);
    const headers_header = try h2.parseFrameHeader(headers_frame);
    _ = try runtime.receiveFrame(headers_header, headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length]);

    const send_before = runtime.state.flow.send_window.available_bytes;
    var update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const update_frame = try h2.buildWindowUpdateFrame(&update_buf, 1, 16);
    const update_header = try h2.parseFrameHeader(update_frame);
    _ = try runtime.receiveFrame(update_header, update_frame[h2.frame_header_size_bytes..]);
    try std.testing.expectEqual(send_before, runtime.state.flow.send_window.available_bytes);
    try std.testing.expectEqual(config.H2_INITIAL_WINDOW_SIZE_BYTES + 16, runtime.state.getStream(1).?.send_window.available_bytes);

    var rst_buf: [h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst_frame = try h2.buildRstStreamFrame(&rst_buf, 1, @intFromEnum(h2.ErrorCode.cancel));
    const rst_header = try h2.parseFrameHeader(rst_frame);
    const action = try runtime.receiveFrame(rst_header, rst_frame[h2.frame_header_size_bytes..]);
    switch (action) {
        .stream_reset => |reset| try std.testing.expectEqual(@as(u32, 1), reset.stream_id),
        else => return error.InvalidFrame,
    }
    try std.testing.expect(runtime.state.getStream(1) == null);
}

test "Runtime classifies stream DATA window underflow as StreamFlowControlError" {
    var runtime = try Runtime.init();
    try runtime.receiveClientPreface();
    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/FlowUnderflow", &header_block_buf);
    var headers_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(&headers_frame_buf, .headers, h2.flags_end_headers, 1, header_block);
    const headers_header = try h2.parseFrameHeader(headers_frame);
    _ = try runtime.receiveFrame(headers_header, headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length]);

    const conn_window_before = runtime.state.flow.recv_window.available_bytes;
    const stream_window_before = runtime.state.getStream(1).?.recv_window.available_bytes;

    try runtime.state.getStream(1).?.recv_window.set(1);

    const data_header = h2.FrameHeader{
        .length = 2,
        .frame_type = .data,
        .flags = 0,
        .stream_id = 1,
    };
    try std.testing.expectError(error.StreamFlowControlError, runtime.receiveFrame(data_header, "ab"));

    try std.testing.expectEqual(conn_window_before, runtime.state.flow.recv_window.available_bytes);
    try std.testing.expectEqual(@as(u32, 1), runtime.state.getStream(1).?.recv_window.available_bytes);
    try std.testing.expect(stream_window_before >= runtime.state.getStream(1).?.recv_window.available_bytes);
}

test "Runtime randomized frame sequence preserves bounded invariants" {
    var runtime = try Runtime.init();
    try runtime.receiveClientPreface();
    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var prng = std.Random.DefaultPrng.init(0x9c41_5be2_d3a7_f00d);
    const random = prng.random();

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/Fuzz", &header_block_buf);

    var frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    var step: u32 = 0;
    while (step < 512) : (step += 1) {
        const opcode: u8 = random.uintLessThan(u8, 6);
        const stream_id: u32 = (@as(u32, random.uintLessThan(u8, 8)) * 2) + 1;

        const frame = switch (opcode) {
            0 => appendFrame(
                &frame_buf,
                .headers,
                if (random.boolean()) h2.flags_end_headers | h2.flags_end_stream else h2.flags_end_headers,
                stream_id,
                header_block,
            ) catch continue,
            1 => appendFrame(
                &frame_buf,
                .data,
                if (random.boolean()) h2.flags_end_stream else 0,
                stream_id,
                "x",
            ) catch continue,
            2 => h2.buildWindowUpdateFrame(&frame_buf, 0, 1 + random.uintLessThan(u32, 1024)) catch continue,
            3 => h2.buildWindowUpdateFrame(&frame_buf, stream_id, 1 + random.uintLessThan(u32, 1024)) catch continue,
            4 => h2.buildRstStreamFrame(&frame_buf, stream_id, @intFromEnum(h2.ErrorCode.cancel)) catch continue,
            5 => h2.buildPingFrame(
                &frame_buf,
                if (random.boolean()) 0 else h2.flags_ack,
                [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
            ) catch continue,
            else => unreachable,
        };

        const header = h2.parseFrameHeader(frame) catch continue;
        if (runtime.receiveFrame(header, frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + header.length])) |action| {
            _ = action;
        } else |_| {}

        try std.testing.expect(runtime.state.streams.active_count <= config.H2_MAX_CONCURRENT_STREAMS);
        try std.testing.expect(runtime.state.flow.recv_window.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try std.testing.expect(runtime.state.flow.send_window.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
    }
}

test "Runtime tracks peer GOAWAY and rejects higher streams" {
    var runtime = try Runtime.init();
    try runtime.receiveClientPreface();
    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var goaway_buf: [h2.frame_header_size_bytes + h2.control.goaway_min_payload_size_bytes]u8 = undefined;
    const goaway_frame = try h2.buildGoAwayFrame(&goaway_buf, 1, @intFromEnum(h2.ErrorCode.no_error), &[_]u8{});
    const goaway_header = try h2.parseFrameHeader(goaway_frame);
    const goaway_action = try runtime.receiveFrame(goaway_header, goaway_frame[h2.frame_header_size_bytes..]);
    try std.testing.expect(goaway_action == .none);
    try std.testing.expect(runtime.state.goaway_received);
    try std.testing.expectEqual(@as(u32, 1), runtime.state.peer_goaway_last_stream_id);

    var header_block_buf: [256]u8 = undefined;
    const header_block = try buildHeaderBlock("/grpc.test.Echo/Unary", &header_block_buf);
    var headers_frame_buf: [h2.frame_header_size_bytes + 256]u8 = undefined;
    const headers_frame = try appendFrame(&headers_frame_buf, .headers, h2.flags_end_headers, 3, header_block);
    const headers_header = try h2.parseFrameHeader(headers_frame);
    try std.testing.expectError(
        error.ConnectionClosing,
        runtime.receiveFrame(headers_header, headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + headers_header.length]),
    );
}
