//! HTTP/2 Client Session State
//!
//! Bounded outbound HTTP/2 session state for stream-aware upstream h2c use.
//! TigerStyle: Explicit state, fixed-capacity tables, no socket ownership.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const h2 = @import("serval-h2");

pub const Error = error{
    PrefaceAlreadySent,
    PrefaceNotSent,
    UnexpectedSettingsAck,
    MaxConcurrentStreamsExceeded,
    ConnectionClosing,
} || h2.SettingsError || h2.StreamError || h2.flow_control.Error;

pub const SessionState = struct {
    preface_sent: bool = false,
    next_local_stream_id: u32 = 1,
    peer_settings_received: bool = false,
    peer_settings: h2.Settings = .{},
    local_settings: h2.Settings = defaultLocalSettings(),
    peer_settings_ack_pending: bool = false,
    local_settings_ack_pending: bool = false,
    goaway_received: bool = false,
    goaway_sent: bool = false,
    peer_goaway_last_stream_id: u32 = 0,
    local_goaway_last_stream_id: u32 = 0,
    streams: h2.StreamTable = h2.StreamTable.init(.client),
    flow: h2.ConnectionFlowControl,

    pub fn init() Error!SessionState {
        assert(config.H2_CONNECTION_WINDOW_SIZE_BYTES > 0);
        assert(config.H2_CONNECTION_WINDOW_SIZE_BYTES <= config.H2_MAX_WINDOW_SIZE_BYTES);
        const flow = try h2.ConnectionFlowControl.init(config.H2_CONNECTION_WINDOW_SIZE_BYTES);
        return .{ .flow = flow };
    }

    pub fn markPrefaceSent(self: *SessionState) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.next_local_stream_id > 0);

        if (self.preface_sent) return error.PrefaceAlreadySent;
        self.preface_sent = true;
        self.local_settings_ack_pending = true;
    }

    pub fn receivePeerSettings(
        self: *SessionState,
        header: h2.FrameHeader,
        payload: []const u8,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(header.frame_type == .settings);

        var parsed_buf: [config.H2_MAX_SETTINGS_PER_FRAME]h2.Setting = undefined;
        const parsed = try h2.parseSettingsFrame(header, payload, &parsed_buf);

        if ((header.flags & h2.flags_ack) != 0) {
            if (!self.local_settings_ack_pending) return error.UnexpectedSettingsAck;
            self.local_settings_ack_pending = false;
            return;
        }

        try h2.applySettings(&self.peer_settings, parsed);
        self.peer_settings_received = true;
        self.peer_settings_ack_pending = true;
    }

    pub fn markPeerSettingsAckSent(self: *SessionState) void {
        assert(@intFromPtr(self) != 0);
        assert(self.peer_settings_ack_pending);
        self.peer_settings_ack_pending = false;
    }

    pub fn openRequestStream(self: *SessionState, end_stream: bool) Error!*h2.H2Stream {
        assert(@intFromPtr(self) != 0);
        assert(self.next_local_stream_id > 0);

        if (!self.preface_sent) return error.PrefaceNotSent;

        const stream_id = self.next_local_stream_id;
        if (!self.canOpenLocalStream(stream_id)) {
            if (self.goaway_received and stream_id > self.peer_goaway_last_stream_id) {
                return error.ConnectionClosing;
            }
            if (peerConcurrentStreamLimitReached(self)) {
                return error.MaxConcurrentStreamsExceeded;
            }
            return error.ConnectionClosing;
        }

        const stream = try self.streams.openLocal(stream_id, end_stream);
        try stream.configureWindows(
            self.local_settings.initial_window_size_bytes,
            self.peer_settings.initial_window_size_bytes,
        );
        self.next_local_stream_id += 2;
        return stream;
    }

    pub fn getStream(self: *SessionState, stream_id: u32) ?*h2.H2Stream {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        return self.streams.get(stream_id);
    }

    pub fn endLocalStream(self: *SessionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.endLocal(stream_id);
    }

    pub fn endRemoteStream(self: *SessionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.endRemote(stream_id);
    }

    pub fn resetStream(self: *SessionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.reset(stream_id);
    }

    pub fn consumeSendWindow(self: *SessionState, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.send_window.consume(bytes);
    }

    pub fn consumeStreamSendWindow(self: *SessionState, stream_id: u32, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        const stream = self.streams.get(stream_id) orelse return error.StreamNotFound;
        try stream.send_window.consume(bytes);
    }

    pub fn consumeRecvWindow(self: *SessionState, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.recv_window.consume(bytes);
    }

    pub fn consumeStreamRecvWindow(self: *SessionState, stream_id: u32, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.consumeRecvWindow(stream_id, bytes);
    }

    pub fn incrementSendWindow(self: *SessionState, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.send_window.increment(delta_bytes);
    }

    pub fn incrementStreamSendWindow(self: *SessionState, stream_id: u32, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.incrementSendWindow(stream_id, delta_bytes);
    }

    pub fn incrementRecvWindow(self: *SessionState, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.recv_window.increment(delta_bytes);
    }

    pub fn incrementStreamRecvWindow(self: *SessionState, stream_id: u32, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.incrementRecvWindow(stream_id, delta_bytes);
    }

    pub fn markGoAwayReceived(self: *SessionState, last_stream_id: u32) void {
        assert(@intFromPtr(self) != 0);
        assert(last_stream_id <= 0x7fff_ffff);

        if (!self.goaway_received or last_stream_id < self.peer_goaway_last_stream_id) {
            self.peer_goaway_last_stream_id = last_stream_id;
        }
        self.goaway_received = true;
    }

    pub fn markGoAwaySent(self: *SessionState, last_stream_id: u32) void {
        assert(@intFromPtr(self) != 0);
        assert(last_stream_id <= 0x7fff_ffff);

        if (!self.goaway_sent or last_stream_id < self.local_goaway_last_stream_id) {
            self.local_goaway_last_stream_id = last_stream_id;
        }
        self.goaway_sent = true;
    }

    pub fn canOpenLocalStream(self: *const SessionState, stream_id: u32) bool {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        if (!self.preface_sent) return false;
        if (peerConcurrentStreamLimitReached(self)) return false;
        if (!self.goaway_received) return true;
        return stream_id <= self.peer_goaway_last_stream_id;
    }
};

fn defaultLocalSettings() h2.Settings {
    assert(config.H2_MAX_CONCURRENT_STREAMS > 0);
    assert(config.H2_INITIAL_WINDOW_SIZE_BYTES <= config.H2_MAX_WINDOW_SIZE_BYTES);

    const defaults: h2.Settings = .{
        .enable_push = false,
        .max_concurrent_streams = config.H2_MAX_CONCURRENT_STREAMS,
        .initial_window_size_bytes = config.H2_INITIAL_WINDOW_SIZE_BYTES,
        .max_frame_size_bytes = config.H2_MAX_FRAME_SIZE_BYTES,
    };
    assert(defaults.max_frame_size_bytes >= h2.settings.min_max_frame_size_bytes);
    return defaults;
}

fn peerConcurrentStreamLimitReached(self: *const SessionState) bool {
    assert(@intFromPtr(self) != 0);
    assert(self.streams.active_count <= config.H2_MAX_CONCURRENT_STREAMS);
    const peer_limit = self.peer_settings.max_concurrent_streams;
    if (peer_limit == std.math.maxInt(u32)) return false;
    return @as(u32, self.streams.active_count) >= peer_limit;
}

test "SessionState marks preface only once" {
    var state = try SessionState.init();
    try state.markPrefaceSent();
    try std.testing.expect(state.local_settings_ack_pending);
    try std.testing.expectError(error.PrefaceAlreadySent, state.markPrefaceSent());
}

test "SessionState rejects stream open before preface" {
    var state = try SessionState.init();
    try std.testing.expectError(error.PrefaceNotSent, state.openRequestStream(false));
}

test "SessionState opens odd-numbered local streams" {
    var state = try SessionState.init();
    try state.markPrefaceSent();
    state.peer_settings.initial_window_size_bytes = 4096;
    state.local_settings.initial_window_size_bytes = 2048;

    const first = try state.openRequestStream(false);
    const second = try state.openRequestStream(true);

    try std.testing.expectEqual(@as(u32, 1), first.id);
    try std.testing.expectEqual(@as(u32, 3), second.id);
    try std.testing.expectEqual(@as(u16, 2), state.streams.active_count);
    try std.testing.expectEqual(@as(u32, 2048), first.recv_window.available_bytes);
    try std.testing.expectEqual(@as(u32, 4096), first.send_window.available_bytes);
}

test "SessionState applies peer settings and marks ack pending" {
    var payload: [12]u8 = undefined;
    const built = try h2.buildSettingsPayload(&payload, &.{
        .{ .id = @intFromEnum(h2.SettingId.max_concurrent_streams), .value = 32 },
        .{ .id = @intFromEnum(h2.SettingId.initial_window_size), .value = 70_000 },
    });
    const header = h2.FrameHeader{
        .length = @intCast(built.len),
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };

    var state = try SessionState.init();
    try state.receivePeerSettings(header, built);

    try std.testing.expectEqual(@as(u32, 32), state.peer_settings.max_concurrent_streams);
    try std.testing.expectEqual(@as(u32, 70_000), state.peer_settings.initial_window_size_bytes);
    try std.testing.expect(state.peer_settings_received);
    try std.testing.expect(state.peer_settings_ack_pending);
}

test "SessionState validates ack ordering" {
    const ack_header = h2.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = h2.flags_ack,
        .stream_id = 0,
    };

    var state = try SessionState.init();
    try std.testing.expectError(error.UnexpectedSettingsAck, state.receivePeerSettings(ack_header, &[_]u8{}));
    try state.markPrefaceSent();
    try state.receivePeerSettings(ack_header, &[_]u8{});
    try std.testing.expect(!state.local_settings_ack_pending);
}

test "SessionState enforces peer max concurrent streams" {
    var state = try SessionState.init();
    try state.markPrefaceSent();
    state.peer_settings.max_concurrent_streams = 1;

    _ = try state.openRequestStream(false);
    try std.testing.expectError(error.MaxConcurrentStreamsExceeded, state.openRequestStream(false));
}

test "SessionState GOAWAY bounds new streams" {
    var state = try SessionState.init();
    try state.markPrefaceSent();

    _ = try state.openRequestStream(false);
    state.markGoAwayReceived(1);

    try std.testing.expectError(error.ConnectionClosing, state.openRequestStream(false));
}

test "SessionState window helpers delegate to flow control" {
    var state = try SessionState.init();
    try state.markPrefaceSent();
    _ = try state.openRequestStream(false);

    try state.consumeSendWindow(1);
    try state.consumeStreamSendWindow(1, 2);
    try state.consumeRecvWindow(1);
    try state.consumeStreamRecvWindow(1, 2);
    try state.incrementSendWindow(1);
    try state.incrementStreamSendWindow(1, 3);
    try state.incrementRecvWindow(1);
    try state.incrementStreamRecvWindow(1, 3);

    try std.testing.expectEqual(config.H2_CONNECTION_WINDOW_SIZE_BYTES, state.flow.send_window.available_bytes);
    try std.testing.expectEqual(config.H2_CONNECTION_WINDOW_SIZE_BYTES, state.flow.recv_window.available_bytes);
    try std.testing.expectEqual(config.H2_INITIAL_WINDOW_SIZE_BYTES + 1, state.getStream(1).?.send_window.available_bytes);
    try std.testing.expectEqual(config.H2_INITIAL_WINDOW_SIZE_BYTES + 1, state.getStream(1).?.recv_window.available_bytes);
}
