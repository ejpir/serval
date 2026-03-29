//! HTTP/2 Server Connection State
//!
//! Bounded per-connection HTTP/2 state for the future stream-aware server
//! transport.
//! TigerStyle: Explicit state, fixed-capacity tables, no socket ownership.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const h2 = @import("serval-h2");

/// Errors returned by `ConnectionState` state-transition methods.
/// `DuplicatePreface` means the connection preface was already recorded.
/// `LocalSettingsAlreadySent` means local SETTINGS were marked sent more than once, and `UnexpectedSettingsAck` means an ACK arrived when none was pending.
pub const Error = error{
    DuplicatePreface,
    LocalSettingsAlreadySent,
    UnexpectedSettingsAck,
} || h2.SettingsError || h2.StreamError || h2.flow_control.Error;

/// Per-connection HTTP/2 state for the server-side connection lifecycle.
/// Tracks preface, SETTINGS, GOAWAY, stream table, and connection-level flow-control state.
/// Use `init()` to construct a valid instance before calling the transition methods on it.
pub const ConnectionState = struct {
    preface_received: bool = false,
    peer_settings_received: bool = false,
    local_settings_sent: bool = false,
    peer_settings: h2.Settings = .{},
    local_settings: h2.Settings = defaultLocalSettings(),
    peer_settings_ack_pending: bool = false,
    local_settings_ack_pending: bool = false,
    goaway_received: bool = false,
    goaway_sent: bool = false,
    peer_goaway_last_stream_id: u32 = 0,
    local_goaway_last_stream_id: u32 = 0,
    streams: h2.StreamTable = h2.StreamTable.init(.server),
    flow: h2.ConnectionFlowControl,

    /// Initializes a new `ConnectionState` with default flags and connection flow control.
    /// Uses `config.H2_CONNECTION_WINDOW_SIZE_BYTES` as the initial connection receive window.
    /// Returns any error reported by `h2.ConnectionFlowControl.init` if the flow-control state cannot be created.
    pub fn init() Error!ConnectionState {
        assert(config.H2_CONNECTION_WINDOW_SIZE_BYTES > 0);
        assert(config.H2_CONNECTION_WINDOW_SIZE_BYTES <= config.H2_MAX_WINDOW_SIZE_BYTES);
        const flow = try h2.ConnectionFlowControl.init(config.H2_CONNECTION_WINDOW_SIZE_BYTES);
        return .{ .flow = flow };
    }

    /// Records that the HTTP/2 connection preface has been received.
    /// Returns `error.DuplicatePreface` if the preface was already marked as received.
    /// On success, flips `preface_received` to `true` and leaves the flow-control state unchanged.
    pub fn markPrefaceReceived(self: *ConnectionState) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.flow.recv_window.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);

        if (self.preface_received) return error.DuplicatePreface;
        self.preface_received = true;
    }

    /// Records that the local SETTINGS frame has been sent.
    /// Returns `error.LocalSettingsAlreadySent` if this connection has already sent its local settings.
    /// On success, marks `local_settings_sent` and sets `local_settings_ack_pending` so the peer's acknowledgment is expected.
    pub fn markLocalSettingsSent(self: *ConnectionState) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.local_settings.max_frame_size_bytes <= config.H2_MAX_FRAME_SIZE_BYTES);

        if (self.local_settings_sent) return error.LocalSettingsAlreadySent;
        self.local_settings_sent = true;
        self.local_settings_ack_pending = true;
    }

    /// Processes an incoming HTTP/2 SETTINGS frame for the peer connection state.
    /// The `header` must describe a SETTINGS frame; ACK frames clear `local_settings_ack_pending` and otherwise apply the parsed settings.
    /// If the peer changes `initial_window_size`, all active stream send windows are adjusted by the resulting delta.
    /// Returns parse, settings-application, or stream-window update errors, and `error.UnexpectedSettingsAck` when an ACK arrives with no ACK pending.
    pub fn receivePeerSettings(
        self: *ConnectionState,
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

        const old_initial_window_size_bytes = self.peer_settings.initial_window_size_bytes;
        try h2.applySettings(&self.peer_settings, parsed);

        const new_initial_window_size_bytes = self.peer_settings.initial_window_size_bytes;
        if (new_initial_window_size_bytes != old_initial_window_size_bytes) {
            const delta_i64: i64 = @as(i64, new_initial_window_size_bytes) - @as(i64, old_initial_window_size_bytes);
            try self.streams.adjustAllSendWindows(delta_i64);
        }

        self.peer_settings_received = true;
        self.peer_settings_ack_pending = true;
    }

    /// Marks the peer SETTINGS acknowledgment as sent.
    /// Requires that a peer SETTINGS ACK is currently pending; this function asserts that precondition.
    /// On success, clears `peer_settings_ack_pending` so the connection no longer expects to transmit that ACK.
    pub fn markPeerSettingsAckSent(self: *ConnectionState) void {
        assert(@intFromPtr(self) != 0);
        assert(self.peer_settings_ack_pending);
        self.peer_settings_ack_pending = false;
    }

    /// Opens a remotely initiated stream and configures its flow-control windows.
    /// The HTTP/2 connection preface must already have been received before calling this function.
    /// On success, the returned stream pointer is owned by the connection's stream table.
    /// Errors are propagated from stream opening or window configuration.
    pub fn openRemoteStream(self: *ConnectionState, stream_id: u32, end_stream: bool) Error!*h2.H2Stream {
        assert(@intFromPtr(self) != 0);
        assert(self.preface_received);

        const stream = try self.streams.openRemote(stream_id, end_stream);
        try stream.configureWindows(
            self.local_settings.initial_window_size_bytes,
            self.peer_settings.initial_window_size_bytes,
        );
        return stream;
    }

    /// Returns the stream for `stream_id` if it is currently tracked.
    /// The returned pointer is borrowed from the connection state and remains owned by it.
    /// Returns `null` when no matching stream exists.
    /// `stream_id` must identify a nonzero stream ID.
    pub fn getStream(self: *ConnectionState, stream_id: u32) ?*h2.H2Stream {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        return self.streams.get(stream_id);
    }

    /// Marks a remotely initiated stream as ended in the stream table.
    /// This forwards the operation to the stream manager and returns any resulting error.
    /// `stream_id` must identify a nonzero stream ID.
    /// The connection state pointer must be valid.
    pub fn endRemoteStream(self: *ConnectionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.endRemote(stream_id);
    }

    /// Marks a locally initiated stream as ended in the stream table.
    /// This forwards the operation to the stream manager and returns any resulting error.
    /// `stream_id` must identify a nonzero stream ID.
    /// The connection state pointer must be valid.
    pub fn endLocalStream(self: *ConnectionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.endLocal(stream_id);
    }

    /// Resets the given stream in the stream table.
    /// This forwards the operation to the stream manager and returns any resulting error.
    /// `stream_id` must identify a nonzero stream ID.
    /// The connection state pointer must be valid.
    pub fn resetStream(self: *ConnectionState, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.reset(stream_id);
    }

    /// Decreases the connection-level receive window by `bytes`.
    /// The consumption is applied to the shared flow-control window and any error is propagated.
    /// `bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// The connection state pointer must be valid.
    pub fn consumeRecvWindow(self: *ConnectionState, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.recv_window.consume(bytes);
    }

    /// Decreases the receive window for a specific stream by `bytes`.
    /// This delegates to the stream table and propagates any window-management error it returns.
    /// `stream_id` must identify a nonzero stream ID.
    /// `bytes` is passed through unchanged to the underlying stream window update.
    pub fn consumeStreamRecvWindow(self: *ConnectionState, stream_id: u32, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.consumeRecvWindow(stream_id, bytes);
    }

    /// Increases the connection-level receive window by `delta_bytes`.
    /// The increment is applied to the shared flow-control window and any error is propagated.
    /// `delta_bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// The connection state pointer must be valid.
    pub fn incrementRecvWindow(self: *ConnectionState, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.recv_window.increment(delta_bytes);
    }

    /// Increases the receive window for a specific stream by `delta_bytes`.
    /// This delegates to the stream table and propagates any window-management error it returns.
    /// `stream_id` must identify a nonzero stream ID.
    /// `delta_bytes` is passed through unchanged to the underlying stream window update.
    pub fn incrementStreamRecvWindow(self: *ConnectionState, stream_id: u32, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.incrementRecvWindow(stream_id, delta_bytes);
    }

    /// Decreases the connection-level send window by `bytes`.
    /// The consumption is applied to the shared flow-control window and any error is propagated.
    /// `bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// The connection state pointer must be valid.
    pub fn consumeSendWindow(self: *ConnectionState, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.send_window.consume(bytes);
    }

    /// Decreases the send window for a specific stream by `bytes`.
    /// This delegates to the stream table and propagates any window-management error it returns.
    /// `stream_id` must identify a nonzero stream ID.
    /// `bytes` is passed through unchanged to the underlying stream window update.
    pub fn consumeStreamSendWindow(self: *ConnectionState, stream_id: u32, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.consumeSendWindow(stream_id, bytes);
    }

    /// Increases the connection-level send window by `delta_bytes`.
    /// The increment is applied to the shared flow-control window and any error is propagated.
    /// `delta_bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// The connection state pointer must be valid.
    pub fn incrementSendWindow(self: *ConnectionState, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(delta_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        try self.flow.send_window.increment(delta_bytes);
    }

    /// Increases the send window for a specific stream by `delta_bytes`.
    /// This delegates to the stream table and propagates any window-management error it returns.
    /// `stream_id` must identify a nonzero stream ID.
    /// `delta_bytes` is passed through unchanged to the underlying stream window update.
    pub fn incrementStreamSendWindow(self: *ConnectionState, stream_id: u32, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        try self.streams.incrementSendWindow(stream_id, delta_bytes);
    }

    /// Records that a GOAWAY frame has been received from the peer.
    /// The stored peer last-stream ID is updated only when this is the first GOAWAY or the new ID is smaller.
    /// This keeps the peer GOAWAY limit monotonic for later stream admission checks.
    /// `last_stream_id` must be within the HTTP/2 peer-initiated stream ID range.
    pub fn markGoAwayReceived(self: *ConnectionState, last_stream_id: u32) void {
        assert(@intFromPtr(self) != 0);
        assert(last_stream_id <= 0x7fff_ffff);

        if (!self.goaway_received or last_stream_id < self.peer_goaway_last_stream_id) {
            self.peer_goaway_last_stream_id = last_stream_id;
        }
        self.goaway_received = true;
    }

    /// Records that a GOAWAY frame has been sent on this connection.
    /// The stored last-stream ID is updated only when this is the first GOAWAY or the new ID is smaller.
    /// This keeps the connection's outgoing GOAWAY limit monotonic.
    /// `last_stream_id` must be within the HTTP/2 peer-initiated stream ID range.
    pub fn markGoAwaySent(self: *ConnectionState, last_stream_id: u32) void {
        assert(@intFromPtr(self) != 0);
        assert(last_stream_id <= 0x7fff_ffff);

        if (!self.goaway_sent or last_stream_id < self.local_goaway_last_stream_id) {
            self.local_goaway_last_stream_id = last_stream_id;
        }
        self.goaway_sent = true;
    }

    /// Returns whether a remote peer is still allowed to open the given stream ID.
    /// Before a GOAWAY frame is received, this accepts every valid remote stream ID.
    /// After GOAWAY, only stream IDs at or below `peer_goaway_last_stream_id` are accepted.
    /// `stream_id` must be nonzero and this state pointer must be valid.
    pub fn canAcceptRemoteStream(self: *const ConnectionState, stream_id: u32) bool {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

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

test "ConnectionState accepts first preface only once" {
    var state = try ConnectionState.init();
    try state.markPrefaceReceived();
    try std.testing.expectError(error.DuplicatePreface, state.markPrefaceReceived());
}

test "ConnectionState requires local settings to be sent before ack" {
    const header = h2.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = h2.flags_ack,
        .stream_id = 0,
    };

    var state = try ConnectionState.init();
    try std.testing.expectError(error.UnexpectedSettingsAck, state.receivePeerSettings(header, &[_]u8{}));
    try state.markLocalSettingsSent();
    try state.receivePeerSettings(header, &[_]u8{});
    try std.testing.expect(!state.local_settings_ack_pending);
}

test "ConnectionState applies peer settings and marks ack pending" {
    var payload: [12]u8 = undefined;
    const built = try h2.buildSettingsPayload(&payload, &.{
        .{ .id = @intFromEnum(h2.SettingId.enable_push), .value = 0 },
        .{ .id = @intFromEnum(h2.SettingId.initial_window_size), .value = 70_000 },
    });
    const header = h2.FrameHeader{
        .length = @intCast(built.len),
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };

    var state = try ConnectionState.init();
    try state.receivePeerSettings(header, built);

    try std.testing.expect(!state.peer_settings.enable_push);
    try std.testing.expectEqual(@as(u32, 70_000), state.peer_settings.initial_window_size_bytes);
    try std.testing.expect(state.peer_settings_received);
    try std.testing.expect(state.peer_settings_ack_pending);
    try std.testing.expectEqual(config.H2_CONNECTION_WINDOW_SIZE_BYTES, state.flow.recv_window.available_bytes);
}

test "ConnectionState opens odd-numbered remote streams with configured windows" {
    var state = try ConnectionState.init();
    try state.markPrefaceReceived();
    state.peer_settings.initial_window_size_bytes = 4096;
    state.local_settings.initial_window_size_bytes = 2048;

    const stream = try state.openRemoteStream(1, false);
    try std.testing.expectEqual(@as(u16, 1), state.streams.active_count);
    try std.testing.expectEqual(@as(u32, 2048), stream.recv_window.available_bytes);
    try std.testing.expectEqual(@as(u32, 4096), stream.send_window.available_bytes);
    try std.testing.expectError(h2.StreamError.WrongStreamParity, state.openRemoteStream(2, false));
}

test "ConnectionState window helpers delegate to flow control" {
    var state = try ConnectionState.init();
    try state.markPrefaceReceived();
    _ = try state.openRemoteStream(1, false);

    try state.consumeRecvWindow(1);
    try state.consumeStreamRecvWindow(1, 2);
    try state.incrementRecvWindow(1);
    try state.incrementStreamRecvWindow(1, 2);
    try state.incrementSendWindow(1);
    try state.incrementStreamSendWindow(1, 3);

    try std.testing.expectEqual(config.H2_CONNECTION_WINDOW_SIZE_BYTES, state.flow.recv_window.available_bytes);
    try std.testing.expectEqual(config.H2_CONNECTION_WINDOW_SIZE_BYTES + 1, state.flow.send_window.available_bytes);
    try std.testing.expectEqual(config.H2_INITIAL_WINDOW_SIZE_BYTES, state.getStream(1).?.recv_window.available_bytes);
    try std.testing.expectEqual(config.H2_INITIAL_WINDOW_SIZE_BYTES + 3, state.getStream(1).?.send_window.available_bytes);
}

test "ConnectionState tracks peer GOAWAY bound for new streams" {
    var state = try ConnectionState.init();
    try std.testing.expect(state.canAcceptRemoteStream(1));
    state.markGoAwayReceived(3);
    try std.testing.expect(state.canAcceptRemoteStream(1));
    try std.testing.expect(!state.canAcceptRemoteStream(5));
}
