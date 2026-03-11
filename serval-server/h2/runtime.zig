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
const connection = @import("connection.zig");

pub const Error = error{
    PrefaceNotReceived,
    MissingInitialSettings,
    UnsupportedContinuation,
    UnsupportedPadding,
    UnsupportedPriority,
    UnsupportedPushPromise,
    InvalidDataStream,
    ConnectionClosing,
} || connection.Error || h2.InitialRequestError || h2.ControlError || h2.FlowControlError;

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

pub const Runtime = struct {
    state: connection.ConnectionState,
    header_decoder: h2.HpackDecoder = h2.HpackDecoder.init(),
    pending_request_headers: PendingRequestHeaders = .{},

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
            .priority => error.UnsupportedPriority,
            .push_promise => error.UnsupportedPushPromise,
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
    if ((header.flags & h2.flags_padded) != 0) return error.UnsupportedPadding;
    if ((header.flags & h2.flags_priority) != 0) return error.UnsupportedPriority;
    if (!self.state.canAcceptRemoteStream(header.stream_id)) return error.ConnectionClosing;

    const end_stream = (header.flags & h2.flags_end_stream) != 0;
    if ((header.flags & h2.flags_end_headers) == 0) {
        try startHeaderBlockContinuation(self, header.stream_id, end_stream, payload);
        return .none;
    }

    const request_head = try h2.decodeRequestHeaderBlockWithDecoder(
        &self.header_decoder,
        payload,
        header.stream_id,
    );
    _ = try self.state.openRemoteStream(header.stream_id, end_stream);
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
    errdefer resetPendingRequestHeaders(self);

    const request_head = try h2.decodeRequestHeaderBlockWithDecoder(
        &self.header_decoder,
        self.pending_request_headers.block_buf[0..block_len],
        stream_id,
    );
    _ = try self.state.openRemoteStream(stream_id, end_stream);
    resetPendingRequestHeaders(self);

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
    if (end_stream) try self.state.endRemoteStream(header.stream_id);
    return .{ .request_data = .{ .stream_id = header.stream_id, .end_stream = end_stream, .payload = payload } };
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

fn buildHeaderBlock(path: []const u8, out: []u8) ![]const u8 {
    assert(path.len > 0);
    var len: usize = 0;
    const fields = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
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
    var settings_buf: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
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
    var settings_out: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
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

test "Runtime reassembles request HEADERS with CONTINUATION" {
    var runtime = try Runtime.init();
    var settings_out: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
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
    var settings_out: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
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
    var settings_out: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
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
    var settings_out: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
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
    var settings_out: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
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
    var settings_out: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
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

test "Runtime tracks peer GOAWAY and rejects higher streams" {
    var runtime = try Runtime.init();
    try runtime.receiveClientPreface();
    const settings_header = h2.FrameHeader{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
    _ = try runtime.receiveFrame(settings_header, &[_]u8{});

    var goaway_buf: [h2.frame_header_size_bytes + h2.control.goaway_min_payload_size_bytes]u8 = undefined;
    const goaway_frame = try h2.buildGoAwayFrame(&goaway_buf, 1, @intFromEnum(h2.ErrorCode.no_error), &[_]u8{});
    const goaway_header = try h2.parseFrameHeader(goaway_frame);
    const goaway_action = try runtime.receiveFrame(goaway_header, goaway_frame[h2.frame_header_size_bytes..]);
    switch (goaway_action) {
        .connection_close => |goaway| try std.testing.expectEqual(@as(u32, 1), goaway.last_stream_id),
        else => return error.InvalidFrame,
    }

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
