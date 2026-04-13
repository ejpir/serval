//! HTTP/2 Client Session State
//!
//! Bounded outbound HTTP/2 session state for stream-aware upstream h2c use.
//! TigerStyle: Explicit state, fixed-capacity tables, no socket ownership.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const h2 = @import("serval-h2");
const default_h2_cfg = config.H2Config{};

/// Errors returned by session state transitions and peer frame handling.
/// These cover invalid preface sequencing, unexpected SETTINGS acknowledgements, stream-limit failures, and connection shutdown.
/// Callers should treat them as protocol-level or session-state failures rather than successful no-op outcomes.
pub const Error = error{
    PrefaceAlreadySent,
    PrefaceNotSent,
    UnexpectedSettingsAck,
    MaxConcurrentStreamsExceeded,
    ConnectionClosing,
} || h2.SettingsError || h2.StreamError || h2.flow_control.Error;

/// Connection-scoped HTTP/2 session state for a client endpoint.
/// It tracks preface and GOAWAY state, peer and local settings, stream allocation, and connection-level flow control.
/// Instances are intended to be initialized with `initInto` and then mutated in place by the session helpers.
pub const SessionState = struct {
    runtime_cfg: config.H2Config,
    preface_sent: bool = false,
    next_local_stream_id: u32 = 1,
    peer_settings_received: bool = false,
    peer_settings: h2.Settings = .{},
    local_settings: h2.Settings,
    peer_settings_ack_pending: bool = false,
    local_settings_ack_pending: bool = false,
    goaway_received: bool = false,
    goaway_sent: bool = false,
    peer_goaway_last_stream_id: u32 = 0,
    local_goaway_last_stream_id: u32 = 0,
    streams: h2.StreamTable = h2.StreamTable.init(.client),
    flow: h2.ConnectionFlowControl,

    /// Initializes caller-owned session storage in place with connection flow control sized from the configured HTTP/2 connection window.
    /// The configuration window must be positive and no larger than the configured maximum window size.
    /// On success, all protocol flags, stream bookkeeping, and flow-control state are reset to a fresh connection baseline.
    pub fn initInto(self: *SessionState, runtime_cfg: config.H2Config) Error!void {
        assert(runtime_cfg.connection_window_size_bytes > 0);
        assert(runtime_cfg.connection_window_size_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        assert(@intFromPtr(self) != 0);
        self.runtime_cfg = runtime_cfg;
        self.preface_sent = false;
        self.next_local_stream_id = 1;
        self.peer_settings_received = false;
        self.peer_settings = .{};
        self.local_settings = defaultLocalSettings(runtime_cfg);
        self.peer_settings_ack_pending = false;
        self.local_settings_ack_pending = false;
        self.goaway_received = false;
        self.goaway_sent = false;
        self.peer_goaway_last_stream_id = 0;
        self.local_goaway_last_stream_id = 0;
        self.streams = h2.StreamTable.init(.client);
        self.flow = try h2.ConnectionFlowControl.init(runtime_cfg.connection_window_size_bytes);
    }

    /// Records that the client connection preface has been sent.
    /// This may only be called once; a second call returns `PrefaceAlreadySent`.
    /// On success, it marks the local SETTINGS ACK as pending so the session can track the peer's acknowledgement.
    pub fn markPrefaceSent(self: *SessionState) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.next_local_stream_id > 0);

        if (self.preface_sent) return error.PrefaceAlreadySent;
        self.preface_sent = true;
        self.local_settings_ack_pending = true;
    }

    /// Processes an incoming HTTP/2 SETTINGS frame for the peer side of the session.
    /// The `header` must describe a SETTINGS frame; `payload` is parsed into a fixed stack buffer before settings are applied.
    /// If the ACK flag is present, this clears `local_settings_ack_pending` and returns `UnexpectedSettingsAck` when no local ACK was pending.
    /// For non-ACK frames, the parsed settings are merged into `peer_settings` and the peer ACK becomes pending.
    pub fn receivePeerSettings(
        self: *SessionState,
        header: h2.FrameHeader,
        payload: []const u8,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(header.frame_type == .settings);

        var parsed_buf: [h2.max_settings_per_frame]h2.Setting = undefined;
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

    /// Clears the pending peer SETTINGS ACK flag after the ACK has been emitted.
    /// The caller must only invoke this when `peer_settings_ack_pending` is set; the function asserts that precondition.
    /// This mutates session state in place and does not return an error.
    pub fn markPeerSettingsAckSent(self: *SessionState) void {
        assert(@intFromPtr(self) != 0);
        assert(self.peer_settings_ack_pending);
        self.peer_settings_ack_pending = false;
    }

    /// Opens a new local request stream and configures its flow-control windows.
    /// Returns `error.PrefaceNotSent` if the HTTP/2 preface has not been sent yet.
    /// Returns `error.ConnectionClosing` or `error.MaxConcurrentStreamsExceeded` when the session can no longer accept a local stream; on success, the next local stream id advances by 2.
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

    /// Returns the stream for `stream_id` if it exists in this session.
    /// `stream_id` must identify a valid nonzero stream id.
    /// The returned pointer is borrowed from the session and remains valid only while the stream stays present in `self.streams`.
    pub fn getStream(self: *SessionState, stream_id: u32) ?*h2.H2Stream {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        return self.streams.get(stream_id);
    }

    /// Marks the local side of `stream_id` as ended.
    /// `stream_id` must identify a valid nonzero stream in this session.
    /// Returns any error raised by the stream table while updating stream state.
    pub fn endLocalStream(self: *SessionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.endLocal(stream_id);
    }

    /// Marks the remote side of `stream_id` as ended.
    /// `stream_id` must identify a valid nonzero stream in this session.
    /// Returns any error raised by the stream table while updating stream state.
    pub fn endRemoteStream(self: *SessionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.endRemote(stream_id);
    }

    /// Resets the stream identified by `stream_id`.
    /// `stream_id` must identify a valid nonzero stream in this session.
    /// Returns any error raised by the stream table while applying the reset.
    pub fn resetStream(self: *SessionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.reset(stream_id);
    }

    /// Consumes `bytes` from the connection-level send window.
    /// `bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// Returns any error raised by the flow-control window implementation.
    pub fn consumeSendWindow(self: *SessionState, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.send_window.consume(bytes);
    }

    /// Consumes `bytes` from the send window tracked for `stream_id`.
    /// `stream_id` must identify an existing stream or the call fails with `error.StreamNotFound`.
    /// Returns any additional error raised by the stream's send-window bookkeeping.
    pub fn consumeStreamSendWindow(self: *SessionState, stream_id: u32, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        const stream = self.streams.get(stream_id) orelse return error.StreamNotFound;
        try stream.send_window.consume(bytes);
    }

    /// Consumes `bytes` from the connection-level receive window.
    /// `bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// Returns any error raised by the flow-control window implementation.
    pub fn consumeRecvWindow(self: *SessionState, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.recv_window.consume(bytes);
    }

    /// Consumes `bytes` from the receive window tracked for `stream_id`.
    /// `stream_id` must identify a valid nonzero stream in this session.
    /// Returns any error raised by the stream window bookkeeping, including failures from the underlying stream table.
    pub fn consumeStreamRecvWindow(self: *SessionState, stream_id: u32, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.consumeRecvWindow(stream_id, bytes);
    }

    /// Adds `delta_bytes` to the connection-level send window.
    /// `delta_bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// Returns any error raised by the flow-control window implementation.
    pub fn incrementSendWindow(self: *SessionState, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.send_window.increment(delta_bytes);
    }

    /// Adds `delta_bytes` to the send window tracked for `stream_id`.
    /// `stream_id` must identify a valid nonzero stream in this session.
    /// Returns any error raised by the stream window bookkeeping, including failures from the underlying stream table.
    pub fn incrementStreamSendWindow(self: *SessionState, stream_id: u32, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.incrementSendWindow(stream_id, delta_bytes);
    }

    /// Adds `delta_bytes` to the connection-level receive window.
    /// `delta_bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// Returns any error raised by the flow-control window implementation.
    pub fn incrementRecvWindow(self: *SessionState, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.recv_window.increment(delta_bytes);
    }

    /// Adds `delta_bytes` to the receive window tracked for `stream_id`.
    /// `stream_id` must identify a valid nonzero stream in this session.
    /// Returns any error raised by the stream window bookkeeping, including failures from the underlying stream table.
    pub fn incrementStreamRecvWindow(self: *SessionState, stream_id: u32, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.incrementRecvWindow(stream_id, delta_bytes);
    }

    /// Records that a GOAWAY frame has been received from the peer.
    /// `last_stream_id` must fit the HTTP/2 stream-id range and is kept as the lowest value observed so far.
    /// Once set, `goaway_received` is marked true and the stored peer last-stream id is only lowered, never raised.
    pub fn markGoAwayReceived(self: *SessionState, last_stream_id: u32) void {
        assert(@intFromPtr(self) != 0);
        assert(last_stream_id <= 0x7fff_ffff);

        if (!self.goaway_received or last_stream_id < self.peer_goaway_last_stream_id) {
            self.peer_goaway_last_stream_id = last_stream_id;
        }
        self.goaway_received = true;
    }

    /// Records that a GOAWAY frame has been sent for this session.
    /// `last_stream_id` must fit the HTTP/2 stream-id range and is kept as the lowest value observed so far.
    /// Once set, `goaway_sent` is marked true and the stored last-stream id is only lowered, never raised.
    pub fn markGoAwaySent(self: *SessionState, last_stream_id: u32) void {
        assert(@intFromPtr(self) != 0);
        assert(last_stream_id <= 0x7fff_ffff);

        if (!self.goaway_sent or last_stream_id < self.local_goaway_last_stream_id) {
            self.local_goaway_last_stream_id = last_stream_id;
        }
        self.goaway_sent = true;
    }

    /// Returns whether `stream_id` may be opened as a new local stream on this session.
    /// Requires a nonzero stream id and a session pointer that is already initialized.
    /// Refuses new local streams until the HTTP/2 preface has been sent, after the peer concurrent-stream limit is reached, or after a GOAWAY when the id is greater than the peer's advertised last stream id.
    pub fn canOpenLocalStream(self: *const SessionState, stream_id: u32) bool {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        if (!self.preface_sent) return false;
        if (peerConcurrentStreamLimitReached(self)) return false;
        if (!self.goaway_received) return true;
        return stream_id <= self.peer_goaway_last_stream_id;
    }
};

fn defaultLocalSettings(runtime_cfg: config.H2Config) h2.Settings {
    assert(runtime_cfg.max_concurrent_streams > 0);
    assert(runtime_cfg.initial_window_size_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
    assert(runtime_cfg.max_frame_size_bytes <= h2.frame_payload_capacity_bytes);

    const defaults: h2.Settings = .{
        .enable_push = false,
        .max_concurrent_streams = runtime_cfg.max_concurrent_streams,
        .initial_window_size_bytes = runtime_cfg.initial_window_size_bytes,
        .max_frame_size_bytes = runtime_cfg.max_frame_size_bytes,
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
    var state: SessionState = undefined;
    try state.initInto(.{});
    try state.markPrefaceSent();
    try std.testing.expect(state.local_settings_ack_pending);
    try std.testing.expectError(error.PrefaceAlreadySent, state.markPrefaceSent());
}

test "SessionState rejects stream open before preface" {
    var state: SessionState = undefined;
    try state.initInto(.{});
    try std.testing.expectError(error.PrefaceNotSent, state.openRequestStream(false));
}

test "SessionState opens odd-numbered local streams" {
    var state: SessionState = undefined;
    try state.initInto(.{});
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

    var state: SessionState = undefined;
    try state.initInto(.{});
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

    var state: SessionState = undefined;
    try state.initInto(.{});
    try std.testing.expectError(error.UnexpectedSettingsAck, state.receivePeerSettings(ack_header, &[_]u8{}));
    try state.markPrefaceSent();
    try state.receivePeerSettings(ack_header, &[_]u8{});
    try std.testing.expect(!state.local_settings_ack_pending);
}

test "SessionState enforces peer max concurrent streams" {
    var state: SessionState = undefined;
    try state.initInto(.{});
    try state.markPrefaceSent();
    state.peer_settings.max_concurrent_streams = 1;

    _ = try state.openRequestStream(false);
    try std.testing.expectError(error.MaxConcurrentStreamsExceeded, state.openRequestStream(false));
}

test "SessionState GOAWAY bounds new streams" {
    var state: SessionState = undefined;
    try state.initInto(.{});
    try state.markPrefaceSent();

    _ = try state.openRequestStream(false);
    state.markGoAwayReceived(1);

    try std.testing.expectError(error.ConnectionClosing, state.openRequestStream(false));
}

test "SessionState window helpers delegate to flow control" {
    var state: SessionState = undefined;
    try state.initInto(.{});
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

    try std.testing.expectEqual(default_h2_cfg.connection_window_size_bytes, state.flow.send_window.available_bytes);
    try std.testing.expectEqual(default_h2_cfg.connection_window_size_bytes, state.flow.recv_window.available_bytes);
    try std.testing.expectEqual(default_h2_cfg.initial_window_size_bytes + 1, state.getStream(1).?.send_window.available_bytes);
    try std.testing.expectEqual(default_h2_cfg.initial_window_size_bytes + 1, state.getStream(1).?.recv_window.available_bytes);
}
