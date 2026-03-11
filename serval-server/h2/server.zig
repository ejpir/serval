//! HTTP/2 Plain Connection Driver
//!
//! Runs a bounded terminating HTTP/2 connection over a plain file descriptor.
//! This is the first server-side runtime driver for Phase B: it owns the
//! connection loop, emits server SETTINGS / ACK / PING / GOAWAY / RST_STREAM,
//! and dispatches request HEADERS / DATA frames to a streaming handler.
//! TigerStyle: Explicit frame loop, fixed buffers, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;

const config = @import("serval-core").config;
const types = @import("serval-core").types;
const time = @import("serval-core").time;
const h2 = @import("serval-h2");
const runtime_mod = @import("runtime.zig");

const Request = types.Request;

const read_buffer_size_bytes: usize = h2.client_connection_preface.len + h2.frame_header_size_bytes + config.H2_MAX_FRAME_SIZE_BYTES;
const frame_buffer_size_bytes: usize = h2.frame_header_size_bytes + config.H2_MAX_FRAME_SIZE_BYTES;
const response_table_capacity: usize = config.H2_MAX_CONCURRENT_STREAMS;
const upgrade_preamble_size_bytes: usize =
    h2.client_connection_preface.len +
    (2 * h2.frame_header_size_bytes) +
    config.H2_MAX_FRAME_SIZE_BYTES +
    config.H2_MAX_HEADER_BLOCK_SIZE_BYTES;
const write_retry_sleep_ns: u64 = time.ns_per_ms;
const write_stall_timeout_ns: u64 = 30 * time.ns_per_s;
const write_max_retry_count: u32 = 30_000;

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const StreamCloseReason = enum {
    local_end_stream,
    peer_reset,
    local_reset,
    connection_close,
};

pub const StreamSummary = struct {
    connection_id: u64,
    stream_id: u32,
    response_status: u16,
    request_data_bytes: u64,
    response_data_bytes: u64,
    duration_ns: u64,
    close_reason: StreamCloseReason,
    reset_error_code_raw: u32,
};

pub const Error = error{
    InvalidPreface,
    ReadFailed,
    WriteFailed,
    ConnectionClosed,
    HeadersAlreadySent,
    HeadersNotSent,
    ResponseClosed,
    ResponseStateNotFound,
    ResponseTableFull,
    StreamTrackerNotFound,
    StreamTrackerTableFull,
    InvalidStatusCode,
    InvalidFrame,
    HeaderBlockTooLarge,
    FrameLimitExceeded,
} || runtime_mod.Error || h2.FrameError || h2.HpackError || h2.H2cUpgradeError;

const ResponseState = struct {
    used: bool = false,
    stream_id: u32 = 0,
    headers_sent: bool = false,
    closed: bool = false,
};

const ResponseStateTable = struct {
    slots: [response_table_capacity]ResponseState = [_]ResponseState{.{}} ** response_table_capacity,
    count: u16 = 0,

    fn get(self: *ResponseStateTable, stream_id: u32) ?*ResponseState {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        for (self.slots[0..]) |*slot| {
            if (!slot.used) continue;
            if (slot.stream_id == stream_id) return slot;
        }
        return null;
    }

    fn getOrInsert(self: *ResponseStateTable, stream_id: u32) Error!*ResponseState {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        if (self.get(stream_id)) |state| return state;
        if (self.count >= config.H2_MAX_CONCURRENT_STREAMS) return error.ResponseTableFull;

        for (self.slots[0..]) |*slot| {
            if (slot.used) continue;
            slot.* = .{ .used = true, .stream_id = stream_id };
            self.count += 1;
            return slot;
        }

        return error.ResponseTableFull;
    }

    fn remove(self: *ResponseStateTable, stream_id: u32) void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        for (self.slots[0..]) |*slot| {
            if (!slot.used) continue;
            if (slot.stream_id != stream_id) continue;
            slot.* = .{};
            assert(self.count > 0);
            self.count -= 1;
            return;
        }
    }
};

const StreamTracker = struct {
    used: bool = false,
    stream_id: u32 = 0,
    start_time_ns: u64 = 0,
    request_data_bytes: u64 = 0,
    response_data_bytes: u64 = 0,
    response_status: u16 = 0,
    remote_end_stream: bool = false,
    local_end_stream: bool = false,
};

const StreamTrackerTable = struct {
    slots: [response_table_capacity]StreamTracker = [_]StreamTracker{.{}} ** response_table_capacity,
    count: u16 = 0,

    fn get(self: *StreamTrackerTable, stream_id: u32) ?*StreamTracker {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        for (self.slots[0..]) |*slot| {
            if (!slot.used) continue;
            if (slot.stream_id == stream_id) return slot;
        }
        return null;
    }

    fn getOrInsert(self: *StreamTrackerTable, stream_id: u32) Error!*StreamTracker {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        if (self.get(stream_id)) |tracker| return tracker;
        if (self.count >= config.H2_MAX_CONCURRENT_STREAMS) return error.StreamTrackerTableFull;

        for (self.slots[0..]) |*slot| {
            if (slot.used) continue;
            slot.* = .{
                .used = true,
                .stream_id = stream_id,
                .start_time_ns = time.monotonicNanos(),
            };
            self.count += 1;
            return slot;
        }

        return error.StreamTrackerTableFull;
    }

    fn markRequestHeaders(self: *StreamTrackerTable, stream_id: u32, end_stream: bool) Error!bool {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const existing = self.get(stream_id);
        const tracker = if (existing) |stream_tracker|
            stream_tracker
        else
            try self.getOrInsert(stream_id);

        if (end_stream) tracker.remote_end_stream = true;
        return existing == null;
    }

    fn markRequestData(self: *StreamTrackerTable, stream_id: u32, payload_len: usize, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const tracker = try self.getOrInsert(stream_id);
        tracker.request_data_bytes += @intCast(payload_len);
        if (end_stream) tracker.remote_end_stream = true;
    }

    fn markResponseHeaders(self: *StreamTrackerTable, stream_id: u32, status: u16, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const tracker = self.get(stream_id) orelse return error.StreamTrackerNotFound;
        tracker.response_status = status;
        if (end_stream) tracker.local_end_stream = true;
    }

    fn markResponseData(self: *StreamTrackerTable, stream_id: u32, payload_len: usize, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const tracker = self.get(stream_id) orelse return error.StreamTrackerNotFound;
        tracker.response_data_bytes += @intCast(payload_len);
        if (end_stream) tracker.local_end_stream = true;
    }

    fn markResponseEnd(self: *StreamTrackerTable, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const tracker = self.get(stream_id) orelse return error.StreamTrackerNotFound;
        tracker.local_end_stream = true;
    }

    fn popIfClosed(self: *StreamTrackerTable) ?StreamTracker {
        assert(@intFromPtr(self) != 0);

        for (self.slots[0..], 0..) |*slot, index| {
            if (!slot.used) continue;
            if (!slot.remote_end_stream or !slot.local_end_stream) continue;
            return self.popByIndex(index);
        }
        return null;
    }

    fn pop(self: *StreamTrackerTable, stream_id: u32) ?StreamTracker {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        for (self.slots[0..], 0..) |*slot, index| {
            if (!slot.used) continue;
            if (slot.stream_id != stream_id) continue;
            return self.popByIndex(index);
        }
        return null;
    }

    fn popAny(self: *StreamTrackerTable) ?StreamTracker {
        assert(@intFromPtr(self) != 0);

        for (self.slots[0..], 0..) |*slot, index| {
            if (!slot.used) continue;
            return self.popByIndex(index);
        }
        return null;
    }

    fn popByIndex(self: *StreamTrackerTable, index: usize) StreamTracker {
        assert(@intFromPtr(self) != 0);
        assert(index < self.slots.len);
        assert(self.slots[index].used);

        const tracker = self.slots[index];
        self.slots[index] = .{};
        assert(self.count > 0);
        self.count -= 1;
        return tracker;
    }
};

pub const ResponseWriter = struct {
    fd: i32,
    connection_id: u64,
    stream_id: u32,
    runtime: *runtime_mod.Runtime,
    states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,

    pub fn sendHeaders(self: *ResponseWriter, status: u16, headers: []const Header, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(status >= 100);
        assert(self.stream_id > 0);

        var state = try self.states.getOrInsert(self.stream_id);
        if (state.headers_sent) return error.HeadersAlreadySent;
        if (state.closed) return error.ResponseClosed;

        var block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
        const block = try buildResponseHeaderBlock(status, headers, &block_buf);

        var frame_buf: [frame_buffer_size_bytes]u8 = undefined;
        const flags: u8 = h2.flags_end_headers | if (end_stream) h2.flags_end_stream else 0;
        const frame = try appendFrame(&frame_buf, .headers, flags, self.stream_id, block);
        try writeAll(self.fd, frame);

        state.headers_sent = true;
        try self.stream_trackers.markResponseHeaders(self.stream_id, status, end_stream);
        if (end_stream) try self.finishStream(state);
    }

    pub fn sendData(self: *ResponseWriter, payload: []const u8, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.stream_id > 0);

        const state = self.states.get(self.stream_id) orelse return error.ResponseStateNotFound;
        if (!state.headers_sent) return error.HeadersNotSent;
        if (state.closed) return error.ResponseClosed;

        if (payload.len == 0) {
            if (end_stream) {
                var empty_frame_buf: [frame_buffer_size_bytes]u8 = undefined;
                const empty_frame = try appendFrame(&empty_frame_buf, .data, h2.flags_end_stream, self.stream_id, &[_]u8{});
                try writeAll(self.fd, empty_frame);
                try self.stream_trackers.markResponseData(self.stream_id, 0, true);
                try self.finishStream(state);
            }
            return;
        }

        const max_payload_size_bytes: usize = config.H2_MAX_FRAME_SIZE_BYTES;
        var cursor: usize = 0;
        while (cursor < payload.len) {
            const remaining = payload.len - cursor;
            const chunk_len = @min(remaining, max_payload_size_bytes);
            const is_last_chunk = cursor + chunk_len == payload.len;
            const flags: u8 = if (end_stream and is_last_chunk) h2.flags_end_stream else 0;

            var frame_buf: [frame_buffer_size_bytes]u8 = undefined;
            const frame = try appendFrame(&frame_buf, .data, flags, self.stream_id, payload[cursor .. cursor + chunk_len]);
            try writeAll(self.fd, frame);
            cursor += chunk_len;
        }

        try self.stream_trackers.markResponseData(self.stream_id, payload.len, end_stream);
        if (end_stream) try self.finishStream(state);
    }

    pub fn sendTrailers(self: *ResponseWriter, trailers: []const Header) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.stream_id > 0);

        const state = self.states.get(self.stream_id) orelse return error.ResponseStateNotFound;
        if (!state.headers_sent) return error.HeadersNotSent;
        if (state.closed) return error.ResponseClosed;

        var block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
        const block = try buildHeaderBlock(trailers, false, 0, &block_buf);

        var frame_buf: [frame_buffer_size_bytes]u8 = undefined;
        const frame = try appendFrame(&frame_buf, .headers, h2.flags_end_headers | h2.flags_end_stream, self.stream_id, block);
        try writeAll(self.fd, frame);
        try self.stream_trackers.markResponseEnd(self.stream_id);
        try self.finishStream(state);
    }

    fn finishStream(self: *ResponseWriter, state: *ResponseState) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(state) != 0);

        try self.runtime.state.endLocalStream(self.stream_id);
        state.closed = true;
        self.states.remove(self.stream_id);
    }
};

pub fn verifyHandler(comptime Handler: type) void {
    if (!@hasDecl(Handler, "handleH2Headers")) {
        @compileError(@typeName(Handler) ++ " must declare handleH2Headers(self, stream_id, request, end_stream, writer)");
    }
    if (!@hasDecl(Handler, "handleH2Data")) {
        @compileError(@typeName(Handler) ++ " must declare handleH2Data(self, stream_id, payload, end_stream, writer)");
    }

    verifyOptionalHook(Handler, "handleH2StreamOpen", &[_]type{ *Handler, u32, *const Request }, void);
    verifyOptionalHook(Handler, "handleH2StreamClose", &[_]type{ *Handler, StreamSummary }, void);
}

fn verifyOptionalHook(
    comptime Handler: type,
    comptime hook_name: []const u8,
    comptime expected_params: []const type,
    comptime expected_return: type,
) void {
    if (!@hasDecl(Handler, hook_name)) return;

    const HookFn = @TypeOf(@field(Handler, hook_name));
    const info = @typeInfo(HookFn);
    if (info != .@"fn") {
        @compileError(hook_name ++ " must be a function");
    }

    const fn_info = info.@"fn";
    if (fn_info.return_type != expected_return) {
        @compileError(hook_name ++ " must return " ++ @typeName(expected_return));
    }

    if (fn_info.params.len != expected_params.len) {
        @compileError(hook_name ++ " has invalid parameter count");
    }

    inline for (expected_params, 0..) |expected_type, idx| {
        if (fn_info.params[idx].type != expected_type) {
            @compileError(hook_name ++ " has invalid parameter types");
        }
    }
}

pub fn servePlainConnection(comptime Handler: type, handler: *Handler, fd: i32, connection_id: u64) Error!void {
    return servePlainConnectionWithInitialBytes(Handler, handler, fd, connection_id, &[_]u8{});
}

pub const PlainConnectionOptions = struct {
    /// Caller has already sent server SETTINGS for this connection.
    /// Runtime still expects an ACK and will validate it.
    local_settings_already_sent: bool = false,
};

pub fn servePlainConnectionWithInitialBytes(
    comptime Handler: type,
    handler: *Handler,
    fd: i32,
    connection_id: u64,
    initial_bytes: []const u8,
) Error!void {
    return servePlainConnectionWithInitialBytesOptions(
        Handler,
        handler,
        fd,
        connection_id,
        initial_bytes,
        .{},
    );
}

pub fn servePlainConnectionWithInitialBytesOptions(
    comptime Handler: type,
    handler: *Handler,
    fd: i32,
    connection_id: u64,
    initial_bytes: []const u8,
    options: PlainConnectionOptions,
) Error!void {
    comptime verifyHandler(Handler);

    assert(@intFromPtr(handler) != 0);
    assert(fd >= 0);
    assert(initial_bytes.len <= read_buffer_size_bytes);

    var runtime = try runtime_mod.Runtime.init();
    var response_states = ResponseStateTable{};
    var stream_trackers = StreamTrackerTable{};

    if (options.local_settings_already_sent) {
        try runtime.state.markLocalSettingsSent();
    } else {
        var settings_buf: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
        const initial_settings = try runtime.writeInitialSettingsFrame(&settings_buf);
        try writeAll(fd, initial_settings);
    }

    var recv_buf: [read_buffer_size_bytes]u8 = undefined;
    var buffer_len: usize = 0;
    if (initial_bytes.len > 0) {
        @memcpy(recv_buf[0..initial_bytes.len], initial_bytes);
        buffer_len = initial_bytes.len;
    }

    try fillBuffer(fd, &recv_buf, &buffer_len, h2.client_connection_preface.len);
    if (!h2.looksLikeClientConnectionPreface(recv_buf[0..buffer_len])) return error.InvalidPreface;
    try runtime.receiveClientPreface();
    discardPrefix(&recv_buf, &buffer_len, h2.client_connection_preface.len);

    var frame_count: u32 = 0;
    while (frame_count < config.H2_SERVER_MAX_FRAME_COUNT) : (frame_count += 1) {
        if (!try ensureFrame(fd, &recv_buf, &buffer_len)) {
            closeAllTrackedStreams(Handler, handler, connection_id, &stream_trackers, .connection_close, 0);
            return;
        }

        const header = try h2.parseFrameHeader(recv_buf[0..h2.frame_header_size_bytes]);
        const frame_len: usize = h2.frame_header_size_bytes + header.length;
        try fillBuffer(fd, &recv_buf, &buffer_len, frame_len);

        const payload = recv_buf[h2.frame_header_size_bytes..frame_len];
        const action = runtime.receiveFrame(header, payload) catch |err| {
            try sendRuntimeErrorGoAway(&runtime, fd, header.stream_id, err);
            closeAllTrackedStreams(
                Handler,
                handler,
                connection_id,
                &stream_trackers,
                .connection_close,
                @intFromEnum(mapGoAwayError(err)),
            );
            return err;
        };
        handleAction(Handler, handler, fd, connection_id, &runtime, &response_states, &stream_trackers, action) catch |err| {
            closeAllTrackedStreams(
                Handler,
                handler,
                connection_id,
                &stream_trackers,
                .connection_close,
                @intFromEnum(mapGoAwayError(err)),
            );
            return err;
        };
        discardPrefix(&recv_buf, &buffer_len, frame_len);

        if (action == .connection_close) return;
    }

    var goaway_buf: [frame_buffer_size_bytes]u8 = undefined;
    const goaway = try runtime.writeGoAwayFrame(&goaway_buf, .{
        .last_stream_id = runtime.state.local_goaway_last_stream_id,
        .error_code_raw = @intFromEnum(h2.ErrorCode.enhance_your_calm),
        .debug_data = "frame_limit",
    });
    writeAll(fd, goaway) catch |write_err| switch (write_err) {
        error.ConnectionClosed => {},
        else => {},
    };
    closeAllTrackedStreams(
        Handler,
        handler,
        connection_id,
        &stream_trackers,
        .connection_close,
        @intFromEnum(h2.ErrorCode.enhance_your_calm),
    );
    return error.FrameLimitExceeded;
}

pub fn serveUpgradedConnection(
    comptime Handler: type,
    handler: *Handler,
    fd: i32,
    connection_id: u64,
    request: *const Request,
    settings_payload: []const u8,
    initial_body: []const u8,
    remaining_body_bytes: u64,
    initial_client_h2_bytes: []const u8,
) Error!void {
    comptime verifyHandler(Handler);

    assert(@intFromPtr(handler) != 0);
    assert(fd >= 0);
    assert(@intFromPtr(request) != 0);
    assert(settings_payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);
    assert(initial_client_h2_bytes.len <= read_buffer_size_bytes);

    var runtime = try runtime_mod.Runtime.init();
    var response_states = ResponseStateTable{};
    var stream_trackers = StreamTrackerTable{};

    var settings_buf: [h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
    const initial_settings = try runtime.writeInitialSettingsFrame(&settings_buf);
    try writeAll(fd, initial_settings);

    try runtime.receiveClientPreface();

    const peer_settings_header = h2.FrameHeader{
        .length = @intCast(settings_payload.len),
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    const peer_settings_action = runtime.receiveFrame(peer_settings_header, settings_payload) catch |err| {
        try sendRuntimeErrorGoAway(&runtime, fd, 0, err);
        closeAllTrackedStreams(
            Handler,
            handler,
            connection_id,
            &stream_trackers,
            .connection_close,
            @intFromEnum(mapGoAwayError(err)),
        );
        return err;
    };
    handleAction(Handler, handler, fd, connection_id, &runtime, &response_states, &stream_trackers, peer_settings_action) catch |err| {
        closeAllTrackedStreams(
            Handler,
            handler,
            connection_id,
            &stream_trackers,
            .connection_close,
            @intFromEnum(mapGoAwayError(err)),
        );
        return err;
    };

    const total_body_bytes: u64 = @as(u64, @intCast(initial_body.len)) + remaining_body_bytes;
    var preamble_buf: [upgrade_preamble_size_bytes]u8 = undefined;
    const preamble = try h2.buildPriorKnowledgePreambleFromUpgrade(
        &preamble_buf,
        request,
        null,
        settings_payload,
        total_body_bytes == 0,
    );

    var cursor: usize = h2.client_connection_preface.len;
    const preamble_settings_header = try h2.parseFrameHeader(preamble[cursor..]);
    if (preamble_settings_header.frame_type != .settings) return error.InvalidFrame;
    cursor += h2.frame_header_size_bytes + preamble_settings_header.length;

    if (cursor + h2.frame_header_size_bytes > preamble.len) return error.InvalidFrame;
    const headers_header = try h2.parseFrameHeader(preamble[cursor..]);
    if (headers_header.frame_type != .headers) return error.InvalidFrame;

    const headers_payload_start = cursor + h2.frame_header_size_bytes;
    const headers_payload_end = headers_payload_start + headers_header.length;
    if (headers_payload_end > preamble.len) return error.InvalidFrame;

    const headers_action = runtime.receiveFrame(headers_header, preamble[headers_payload_start..headers_payload_end]) catch |err| {
        try sendRuntimeErrorGoAway(&runtime, fd, headers_header.stream_id, err);
        closeAllTrackedStreams(
            Handler,
            handler,
            connection_id,
            &stream_trackers,
            .connection_close,
            @intFromEnum(mapGoAwayError(err)),
        );
        return err;
    };
    handleAction(Handler, handler, fd, connection_id, &runtime, &response_states, &stream_trackers, headers_action) catch |err| {
        closeAllTrackedStreams(
            Handler,
            handler,
            connection_id,
            &stream_trackers,
            .connection_close,
            @intFromEnum(mapGoAwayError(err)),
        );
        return err;
    };

    processUpgradeBody(
        Handler,
        handler,
        fd,
        connection_id,
        &runtime,
        &response_states,
        &stream_trackers,
        initial_body,
        remaining_body_bytes,
    ) catch |err| {
        closeAllTrackedStreams(
            Handler,
            handler,
            connection_id,
            &stream_trackers,
            .connection_close,
            @intFromEnum(mapGoAwayError(err)),
        );
        return err;
    };

    var recv_buf: [read_buffer_size_bytes]u8 = undefined;
    var buffer_len: usize = 0;
    if (initial_client_h2_bytes.len > 0) {
        @memcpy(recv_buf[0..initial_client_h2_bytes.len], initial_client_h2_bytes);
        buffer_len = initial_client_h2_bytes.len;
    }

    consumeOptionalUpgradeClientPreface(fd, &recv_buf, &buffer_len) catch |err| {
        try sendRuntimeErrorGoAway(&runtime, fd, 0, err);
        closeAllTrackedStreams(Handler, handler, connection_id, &stream_trackers, .connection_close, @intFromEnum(mapGoAwayError(err)));
        return err;
    };

    var frame_count: u32 = 0;
    while (frame_count < config.H2_SERVER_MAX_FRAME_COUNT) : (frame_count += 1) {
        if (!try ensureFrame(fd, &recv_buf, &buffer_len)) {
            closeAllTrackedStreams(Handler, handler, connection_id, &stream_trackers, .connection_close, 0);
            return;
        }

        const header = try h2.parseFrameHeader(recv_buf[0..h2.frame_header_size_bytes]);
        const frame_len: usize = h2.frame_header_size_bytes + header.length;
        try fillBuffer(fd, &recv_buf, &buffer_len, frame_len);

        const payload = recv_buf[h2.frame_header_size_bytes..frame_len];
        const action = runtime.receiveFrame(header, payload) catch |err| {
            try sendRuntimeErrorGoAway(&runtime, fd, header.stream_id, err);
            closeAllTrackedStreams(
                Handler,
                handler,
                connection_id,
                &stream_trackers,
                .connection_close,
                @intFromEnum(mapGoAwayError(err)),
            );
            return err;
        };
        handleAction(Handler, handler, fd, connection_id, &runtime, &response_states, &stream_trackers, action) catch |err| {
            closeAllTrackedStreams(
                Handler,
                handler,
                connection_id,
                &stream_trackers,
                .connection_close,
                @intFromEnum(mapGoAwayError(err)),
            );
            return err;
        };
        discardPrefix(&recv_buf, &buffer_len, frame_len);

        if (action == .connection_close) return;
    }

    var goaway_buf: [frame_buffer_size_bytes]u8 = undefined;
    const goaway = try runtime.writeGoAwayFrame(&goaway_buf, .{
        .last_stream_id = runtime.state.local_goaway_last_stream_id,
        .error_code_raw = @intFromEnum(h2.ErrorCode.enhance_your_calm),
        .debug_data = "frame_limit",
    });
    writeAll(fd, goaway) catch |write_err| switch (write_err) {
        error.ConnectionClosed => {},
        else => {},
    };
    closeAllTrackedStreams(
        Handler,
        handler,
        connection_id,
        &stream_trackers,
        .connection_close,
        @intFromEnum(h2.ErrorCode.enhance_your_calm),
    );
    return error.FrameLimitExceeded;
}

fn handleAction(
    comptime Handler: type,
    handler: *Handler,
    fd: i32,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    action: runtime_mod.ReceiveAction,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(fd >= 0);
    assert(@intFromPtr(stream_trackers) != 0);

    switch (action) {
        .none => {},
        .send_settings_ack => {
            var ack_buf: [h2.frame_header_size_bytes]u8 = undefined;
            const ack = try runtime.writePendingSettingsAck(&ack_buf);
            try writeAll(fd, ack);
        },
        .send_ping_ack => |opaque_data| {
            var ack_buf: [h2.frame_header_size_bytes + h2.control.ping_payload_size_bytes]u8 = undefined;
            const ack = try runtime_mod.Runtime.writePingAckFrame(&ack_buf, opaque_data);
            try writeAll(fd, ack);
        },
        .request_headers => |headers| {
            const opened = try stream_trackers.markRequestHeaders(headers.stream_id, headers.end_stream);
            if (opened) {
                if (comptime @hasDecl(Handler, "handleH2StreamOpen")) {
                    handler.handleH2StreamOpen(headers.stream_id, &headers.request);
                }
            }

            var writer = ResponseWriter{
                .fd = fd,
                .connection_id = connection_id,
                .stream_id = headers.stream_id,
                .runtime = runtime,
                .states = response_states,
                .stream_trackers = stream_trackers,
            };
            handler.handleH2Headers(headers.stream_id, &headers.request, headers.end_stream, &writer) catch |err| {
                const reset_error_code_raw = mapHandlerErrorToResetCodeRaw(err);
                response_states.remove(headers.stream_id);
                closeStreamWithReason(
                    Handler,
                    handler,
                    connection_id,
                    stream_trackers,
                    headers.stream_id,
                    .local_reset,
                    reset_error_code_raw,
                );
                try sendErrorReset(fd, runtime, headers.stream_id, reset_error_code_raw);
            };
            closeCompletedStreams(Handler, handler, connection_id, stream_trackers);
        },
        .request_data => |data| {
            try stream_trackers.markRequestData(data.stream_id, data.payload.len, data.end_stream);
            try replenishReceiveWindows(fd, runtime, data.stream_id, data.payload.len);

            var writer = ResponseWriter{
                .fd = fd,
                .connection_id = connection_id,
                .stream_id = data.stream_id,
                .runtime = runtime,
                .states = response_states,
                .stream_trackers = stream_trackers,
            };
            handler.handleH2Data(data.stream_id, data.payload, data.end_stream, &writer) catch |err| {
                const reset_error_code_raw = mapHandlerErrorToResetCodeRaw(err);
                response_states.remove(data.stream_id);
                closeStreamWithReason(
                    Handler,
                    handler,
                    connection_id,
                    stream_trackers,
                    data.stream_id,
                    .local_reset,
                    reset_error_code_raw,
                );
                try sendErrorReset(fd, runtime, data.stream_id, reset_error_code_raw);
            };
            closeCompletedStreams(Handler, handler, connection_id, stream_trackers);
        },
        .stream_reset => |reset| {
            response_states.remove(reset.stream_id);
            if (comptime @hasDecl(Handler, "handleH2StreamReset")) {
                handler.handleH2StreamReset(reset.stream_id, reset.error_code_raw);
            }
            closeStreamWithReason(
                Handler,
                handler,
                connection_id,
                stream_trackers,
                reset.stream_id,
                .peer_reset,
                reset.error_code_raw,
            );
        },
        .connection_close => |goaway| {
            closeAllTrackedStreams(
                Handler,
                handler,
                connection_id,
                stream_trackers,
                .connection_close,
                goaway.error_code_raw,
            );
            if (comptime @hasDecl(Handler, "handleH2ConnectionClose")) {
                handler.handleH2ConnectionClose(goaway);
            }
        },
    }
}

fn closeCompletedStreams(
    comptime Handler: type,
    handler: *Handler,
    connection_id: u64,
    stream_trackers: *StreamTrackerTable,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(stream_trackers) != 0);

    while (stream_trackers.popIfClosed()) |tracker| {
        emitStreamCloseHook(Handler, handler, connection_id, tracker, .local_end_stream, 0);
    }
}

fn closeStreamWithReason(
    comptime Handler: type,
    handler: *Handler,
    connection_id: u64,
    stream_trackers: *StreamTrackerTable,
    stream_id: u32,
    reason: StreamCloseReason,
    reset_error_code_raw: u32,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(stream_trackers) != 0);
    assert(stream_id > 0);

    const tracker = stream_trackers.pop(stream_id) orelse return;
    emitStreamCloseHook(Handler, handler, connection_id, tracker, reason, reset_error_code_raw);
}

fn closeAllTrackedStreams(
    comptime Handler: type,
    handler: *Handler,
    connection_id: u64,
    stream_trackers: *StreamTrackerTable,
    reason: StreamCloseReason,
    reset_error_code_raw: u32,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(stream_trackers) != 0);

    while (stream_trackers.popAny()) |tracker| {
        emitStreamCloseHook(Handler, handler, connection_id, tracker, reason, reset_error_code_raw);
    }
}

fn emitStreamCloseHook(
    comptime Handler: type,
    handler: *Handler,
    connection_id: u64,
    tracker: StreamTracker,
    reason: StreamCloseReason,
    reset_error_code_raw: u32,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(tracker.stream_id > 0);

    if (comptime !@hasDecl(Handler, "handleH2StreamClose")) return;

    const now_ns = time.monotonicNanos();
    const summary = StreamSummary{
        .connection_id = connection_id,
        .stream_id = tracker.stream_id,
        .response_status = tracker.response_status,
        .request_data_bytes = tracker.request_data_bytes,
        .response_data_bytes = tracker.response_data_bytes,
        .duration_ns = time.elapsedNanos(tracker.start_time_ns, now_ns),
        .close_reason = reason,
        .reset_error_code_raw = reset_error_code_raw,
    };
    handler.handleH2StreamClose(summary);
}

fn processUpgradeBody(
    comptime Handler: type,
    handler: *Handler,
    fd: i32,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    initial_body: []const u8,
    remaining_body_bytes: u64,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(fd >= 0);

    var initial_cursor: usize = 0;
    var remaining: u64 = remaining_body_bytes;

    while (initial_cursor < initial_body.len) {
        const chunk_len = @min(initial_body.len - initial_cursor, config.H2_MAX_FRAME_SIZE_BYTES);
        const is_last_chunk = (initial_cursor + chunk_len == initial_body.len) and (remaining == 0);

        try processUpgradeBodyChunk(
            Handler,
            handler,
            fd,
            connection_id,
            runtime,
            response_states,
            stream_trackers,
            initial_body[initial_cursor .. initial_cursor + chunk_len],
            is_last_chunk,
        );
        initial_cursor += chunk_len;
    }

    if (remaining == 0) return;

    var body_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;
    while (remaining > 0) {
        const max_read: usize = @intCast(@min(remaining, config.H2_MAX_FRAME_SIZE_BYTES));
        const n = posix.read(fd, body_buf[0..max_read]) catch |err| switch (err) {
            error.ConnectionResetByPeer => return error.ConnectionClosed,
            else => return error.ReadFailed,
        };
        if (n == 0) return error.ConnectionClosed;

        const read_bytes: u64 = @intCast(n);
        assert(read_bytes <= remaining);
        remaining -= read_bytes;

        try processUpgradeBodyChunk(
            Handler,
            handler,
            fd,
            connection_id,
            runtime,
            response_states,
            stream_trackers,
            body_buf[0..n],
            remaining == 0,
        );
    }
}

fn processUpgradeBodyChunk(
    comptime Handler: type,
    handler: *Handler,
    fd: i32,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    payload: []const u8,
    end_stream: bool,
) Error!void {
    assert(payload.len > 0);
    assert(payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);

    const data_header = h2.FrameHeader{
        .length = @intCast(payload.len),
        .frame_type = .data,
        .flags = if (end_stream) h2.flags_end_stream else 0,
        .stream_id = 1,
    };

    const action = runtime.receiveFrame(data_header, payload) catch |err| {
        try sendRuntimeErrorGoAway(runtime, fd, 1, err);
        closeAllTrackedStreams(
            Handler,
            handler,
            connection_id,
            stream_trackers,
            .connection_close,
            @intFromEnum(mapGoAwayError(err)),
        );
        return err;
    };
    handleAction(Handler, handler, fd, connection_id, runtime, response_states, stream_trackers, action) catch |err| {
        closeAllTrackedStreams(
            Handler,
            handler,
            connection_id,
            stream_trackers,
            .connection_close,
            @intFromEnum(mapGoAwayError(err)),
        );
        return err;
    };
}

fn replenishReceiveWindows(fd: i32, runtime: *runtime_mod.Runtime, stream_id: u32, consumed_bytes: usize) Error!void {
    assert(fd >= 0);
    assert(@intFromPtr(runtime) != 0);
    assert(stream_id > 0);
    assert(consumed_bytes <= config.H2_MAX_FRAME_SIZE_BYTES);

    if (consumed_bytes == 0) return;

    const increment_bytes: u32 = @intCast(consumed_bytes);
    try runtime.state.incrementRecvWindow(increment_bytes);
    try runtime.state.incrementStreamRecvWindow(stream_id, increment_bytes);

    var conn_update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const conn_update = try h2.buildWindowUpdateFrame(&conn_update_buf, 0, increment_bytes);
    try writeAll(fd, conn_update);

    var stream_update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const stream_update = try h2.buildWindowUpdateFrame(&stream_update_buf, stream_id, increment_bytes);
    try writeAll(fd, stream_update);
}

fn sendErrorReset(fd: i32, runtime: *runtime_mod.Runtime, stream_id: u32, error_code_raw: u32) Error!void {
    assert(fd >= 0);
    assert(stream_id > 0);

    var rst_buf: [h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst = try runtime.writeRstStreamFrame(&rst_buf, .{
        .stream_id = stream_id,
        .error_code_raw = error_code_raw,
    });
    try writeAll(fd, rst);
}

fn mapHandlerErrorToResetCodeRaw(err: anyerror) u32 {
    return switch (err) {
        error.UpstreamConnectionClosing,
        error.ConnectionClosing,
        error.ConnectionClosed,
        error.ReadFailed,
        error.WriteFailed,
        => @intFromEnum(h2.ErrorCode.cancel),
        error.MissingGrpcStatus,
        error.InvalidGrpcStatus,
        => @intFromEnum(h2.ErrorCode.protocol_error),
        else => @intFromEnum(h2.ErrorCode.internal_error),
    };
}

fn sendRuntimeErrorGoAway(runtime: *runtime_mod.Runtime, fd: i32, stream_id: u32, err: anyerror) Error!void {
    assert(@intFromPtr(runtime) != 0);
    assert(fd >= 0);
    assert(stream_id <= 0x7fff_ffff);

    var goaway_buf: [frame_buffer_size_bytes]u8 = undefined;
    const goaway = try runtime.writeGoAwayFrame(&goaway_buf, .{
        .last_stream_id = stream_id,
        .error_code_raw = @intFromEnum(mapGoAwayError(err)),
        .debug_data = @errorName(err),
    });
    try writeAll(fd, goaway);
}

fn mapGoAwayError(err: anyerror) h2.ErrorCode {
    return switch (err) {
        error.WindowOverflow,
        error.WindowUnderflow,
        error.InvalidIncrement,
        => .flow_control_error,
        error.ConnectionClosing,
        error.InvalidDataStream,
        error.UnsupportedContinuation,
        error.UnsupportedPadding,
        error.UnsupportedPriority,
        error.UnsupportedPushPromise,
        error.InvalidFrame,
        error.InvalidFrameType,
        error.InvalidPayloadLength,
        error.InvalidStreamId,
        error.StreamIdRegression,
        error.StreamAlreadyExists,
        error.StreamNotFound,
        error.WrongStreamParity,
        error.InvalidTransition,
        error.DuplicatePreface,
        error.MissingInitialSettings,
        error.UnexpectedSettingsAck,
        error.InvalidPreface,
        => .protocol_error,
        else => .internal_error,
    };
}

fn consumeOptionalUpgradeClientPreface(fd: i32, recv_buf: *[read_buffer_size_bytes]u8, buffer_len: *usize) Error!void {
    assert(fd >= 0);
    assert(buffer_len.* <= recv_buf.len);

    if (buffer_len.* == 0) {
        const n = try readIntoBuffer(fd, recv_buf, buffer_len);
        if (n == 0) return;
    }

    if (buffer_len.* == 0) return;
    if (!h2.looksLikeClientConnectionPrefacePrefix(recv_buf[0..1])) return;

    fillBuffer(fd, recv_buf, buffer_len, h2.client_connection_preface.len) catch |err| switch (err) {
        error.ConnectionClosed => return error.InvalidPreface,
        else => return err,
    };
    if (!h2.looksLikeClientConnectionPreface(recv_buf[0..buffer_len.*])) return error.InvalidPreface;

    discardPrefix(recv_buf, buffer_len, h2.client_connection_preface.len);
}

fn ensureFrame(fd: i32, recv_buf: *[read_buffer_size_bytes]u8, buffer_len: *usize) Error!bool {
    assert(fd >= 0);
    assert(@intFromPtr(recv_buf) != 0);

    if (buffer_len.* == 0) {
        const n = try readIntoBuffer(fd, recv_buf, buffer_len);
        if (n == 0) return false;
    }

    try fillBuffer(fd, recv_buf, buffer_len, h2.frame_header_size_bytes);
    const header = try h2.parseFrameHeader(recv_buf[0..h2.frame_header_size_bytes]);
    const frame_len: usize = h2.frame_header_size_bytes + header.length;
    try fillBuffer(fd, recv_buf, buffer_len, frame_len);
    return true;
}

fn fillBuffer(fd: i32, recv_buf: *[read_buffer_size_bytes]u8, buffer_len: *usize, needed_len: usize) Error!void {
    assert(fd >= 0);
    assert(needed_len <= recv_buf.len);

    var reads: usize = 0;
    while (buffer_len.* < needed_len and reads < recv_buf.len) : (reads += 1) {
        const n = try readIntoBuffer(fd, recv_buf, buffer_len);
        if (n == 0) return error.ConnectionClosed;
    }

    if (buffer_len.* < needed_len) return error.ReadFailed;
}

fn readIntoBuffer(fd: i32, recv_buf: *[read_buffer_size_bytes]u8, buffer_len: *usize) Error!usize {
    assert(fd >= 0);
    assert(buffer_len.* <= recv_buf.len);

    const n = posix.read(fd, recv_buf[buffer_len.*..]) catch |err| switch (err) {
        error.ConnectionResetByPeer => return error.ConnectionClosed,
        else => return error.ReadFailed,
    };
    buffer_len.* += n;
    return n;
}

fn discardPrefix(recv_buf: *[read_buffer_size_bytes]u8, buffer_len: *usize, prefix_len: usize) void {
    assert(prefix_len <= buffer_len.*);

    if (prefix_len == buffer_len.*) {
        buffer_len.* = 0;
        return;
    }

    std.mem.copyForwards(u8, recv_buf[0 .. buffer_len.* - prefix_len], recv_buf[prefix_len..buffer_len.*]);
    buffer_len.* -= prefix_len;
}

fn writeAll(fd: i32, data: []const u8) Error!void {
    assert(fd >= 0);

    if (data.len == 0) return;

    var written: usize = 0;
    var writes: usize = 0;
    const max_writes: usize = data.len + 1024;
    var retry_count: u32 = 0;
    var last_progress_ns: u64 = time.monotonicNanos();

    while (written < data.len and writes < max_writes) : (writes += 1) {
        const file: std.Io.File = .{
            .handle = fd,
            .flags = .{ .nonblocking = true },
        };
        const n = file.writeStreaming(std.Options.debug_io, &.{}, &.{data[written..]}, 1) catch |err| switch (err) {
            error.BrokenPipe => return error.ConnectionClosed,
            error.WouldBlock => {
                retry_count += 1;
                const now_ns = time.monotonicNanos();
                if (retry_count >= write_max_retry_count or
                    now_ns -| last_progress_ns >= write_stall_timeout_ns)
                {
                    return error.WriteFailed;
                }
                time.sleep(write_retry_sleep_ns);
                continue;
            },
            else => return error.WriteFailed,
        };
        if (n == 0) return error.ConnectionClosed;

        written += @intCast(n);
        retry_count = 0;
        last_progress_ns = time.monotonicNanos();
    }

    if (written < data.len) return error.WriteFailed;
}

fn buildResponseHeaderBlock(status: u16, headers: []const Header, out: []u8) Error![]const u8 {
    assert(status >= 100);
    assert(out.len > 0);

    if (status > 999) return error.InvalidStatusCode;
    return try buildHeaderBlock(headers, true, status, out);
}

fn buildHeaderBlock(headers: []const Header, include_status: bool, status: u16, out: []u8) Error![]const u8 {
    assert(out.len > 0);
    assert(!include_status or status >= 100);

    var cursor: usize = 0;
    if (include_status) {
        var status_buf: [3]u8 = undefined;
        const status_text = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.InvalidStatusCode;
        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":status", status_text);
        cursor += encoded.len;
    }

    for (headers) |header| {
        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value);
        cursor += encoded.len;
        if (cursor > config.H2_MAX_HEADER_BLOCK_SIZE_BYTES) return error.HeaderBlockTooLarge;
    }

    return out[0..cursor];
}

fn appendFrame(out: []u8, frame_type: h2.FrameType, flags: u8, stream_id: u32, payload: []const u8) Error![]const u8 {
    assert(out.len >= h2.frame_header_size_bytes);
    assert(payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);

    const header = try h2.buildFrameHeader(out[0..h2.frame_header_size_bytes], .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    @memcpy(out[header.len..][0..payload.len], payload);
    return out[0 .. header.len + payload.len];
}

test "buildResponseHeaderBlock encodes :status and application headers" {
    var out: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const block = try buildResponseHeaderBlock(200, &.{.{ .name = "content-type", .value = "application/grpc" }}, &out);

    var fields_buf: [config.MAX_HEADERS]h2.HeaderField = undefined;
    const fields = try h2.decodeHeaderBlock(block, &fields_buf);
    try std.testing.expectEqualStrings(":status", fields[0].name);
    try std.testing.expectEqualStrings("200", fields[0].value);
    try std.testing.expectEqualStrings("content-type", fields[1].name);
    try std.testing.expectEqualStrings("application/grpc", fields[1].value);
}

test "ResponseStateTable inserts and removes response state" {
    var table = ResponseStateTable{};
    const state = try table.getOrInsert(1);
    state.headers_sent = true;

    try std.testing.expectEqual(@as(u16, 1), table.count);
    try std.testing.expect(table.get(1).?.headers_sent);
    table.remove(1);
    try std.testing.expectEqual(@as(u16, 0), table.count);
    try std.testing.expect(table.get(1) == null);
}

test "mapGoAwayError maps flow-control violations distinctly" {
    try std.testing.expectEqual(h2.ErrorCode.flow_control_error, mapGoAwayError(error.WindowOverflow));
    try std.testing.expectEqual(h2.ErrorCode.protocol_error, mapGoAwayError(error.InvalidPreface));
}
