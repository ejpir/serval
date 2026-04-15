//! HTTP/2 Client Connection Driver
//!
//! Bounded socket-owning driver for outbound prior-knowledge h2c sessions.
//! Wraps Runtime frame actions with fixed-buffer socket I/O.
//! TigerStyle: Explicit frame loop bounds, no allocation, no recursion.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const posix = std.posix;

const config = @import("serval-core").config;
const log = @import("serval-core").log.scoped(.client_h2_conn);
const types = @import("serval-core").types;
const h2 = @import("serval-h2");
const serval_socket = @import("serval-socket");
const runtime_mod = @import("runtime.zig");

const Request = types.Request;
const Socket = serval_socket.Socket;
const SocketError = serval_socket.SocketError;

const read_buffer_size_bytes: usize = h2.frame_header_size_bytes + h2.frame_payload_capacity_bytes;
const preface_settings_buffer_size_bytes: usize =
    h2.client_connection_preface.len +
    h2.frame_header_size_bytes +
    (4 * h2.setting_size_bytes);
const request_headers_frame_overhead_bytes: usize = h2.frame_header_size_bytes * (@as(usize, h2.max_continuation_frames) + 1);
const request_headers_frame_buffer_size_bytes: usize = h2.header_block_capacity_bytes + request_headers_frame_overhead_bytes;
const data_frame_buffer_size_bytes: usize = h2.frame_header_size_bytes + h2.frame_payload_capacity_bytes;
const window_update_frame_size_bytes: usize = h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes;
const local_data_frame_payload_capacity_bytes: u32 = h2.frame_payload_capacity_bytes;

/// Caller-owned fixed storage for a `ClientConnection`.
/// Keep this storage alive for at least as long as the associated connection.
pub const ConnectionStorage = struct {
    pending_response_headers_storage: [h2.header_block_capacity_bytes]u8 = undefined,
    response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined,
    request_header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined,
    recv_buf: [read_buffer_size_bytes]u8 = undefined,
    plain_write_buf: [config.STREAM_WRITE_BUFFER_SIZE_BYTES]u8 = undefined,
    preface_settings_buf: [preface_settings_buffer_size_bytes]u8 = undefined,
    settings_ack_buf: [h2.frame_header_size_bytes]u8 = undefined,
    ping_ack_buf: [h2.frame_header_size_bytes + h2.control.ping_payload_size_bytes]u8 = undefined,
    request_headers_frame_buf: [request_headers_frame_buffer_size_bytes]u8 = undefined,
    data_frame_buf: [data_frame_buffer_size_bytes]u8 = undefined,
    rst_stream_buf: [h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes]u8 = undefined,
    conn_window_update_buf: [window_update_frame_size_bytes]u8 = undefined,
    stream_window_update_buf: [window_update_frame_size_bytes]u8 = undefined,
};

/// Errors returned by HTTP/2 client connection setup and frame I/O.
/// `ReadFailed` and `WriteFailed` report socket-level I/O failures.
/// `ConnectionClosed` and `ConnectionClosing` indicate that the peer or local side is no longer accepting traffic.
/// `WouldBlock`, `FrameLimitExceeded`, `SendWindowExhausted`, and `UnexpectedHandshakeFrame` cover transport, framing, and handshake conditions.
pub const Error = error{
    ReadFailed,
    WriteFailed,
    ConnectionClosed,
    WouldBlock,
    FrameLimitExceeded,
    SendWindowExhausted,
    UnexpectedHandshakeFrame,
    ConnectionClosing,
} || runtime_mod.Error || h2.FrameError;

/// Client-side HTTP/2 connection state tied to one socket.
/// The socket pointer is borrowed; the caller retains ownership and must keep it valid for the lifetime of the connection.
/// `initInto` and `initWithIoInto` initialize the runtime and can fail with `Error` if setup cannot be completed.
/// Sending methods write directly to the underlying connection and propagate `Error` on I/O, protocol, or flow-control failures.
pub const ClientConnection = struct {
    runtime_cfg: config.H2Config,
    socket: *Socket,
    io: ?Io = null,
    runtime: runtime_mod.Runtime,
    pending_response_headers_storage: []u8,
    request_header_block_buf: []u8,
    recv_buf: []u8,
    plain_write_buf: []u8,
    preface_settings_buf: []u8,
    settings_ack_buf: []u8,
    ping_ack_buf: []u8,
    request_headers_frame_buf: []u8,
    data_frame_buf: []u8,
    rst_stream_buf: []u8,
    conn_window_update_buf: []u8,
    stream_window_update_buf: []u8,
    recv_len: usize = 0,
    pending_discard_len: usize = 0,
    frame_count: u32 = 0,

    /// Initialize caller-owned client connection storage that uses the socket's default I/O path.
    /// Requires a non-null socket pointer with an open file descriptor; the socket remains owned by the caller.
    /// Propagates any error returned by shared connection initialization.
    pub fn initInto(self: *ClientConnection, socket: *Socket, runtime_cfg: config.H2Config, storage: *ConnectionStorage) Error!void {
        assert(@intFromPtr(socket) != 0);
        assert(socket.get_fd() >= 0);
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(storage) != 0);
        try initMaybeIoInto(self, socket, null, runtime_cfg, storage);
    }

    /// Initialize caller-owned client connection storage that uses the provided I/O object for network operations.
    /// Requires a non-null socket pointer with an open file descriptor; the socket remains owned by the caller.
    /// Propagates any error returned by shared connection initialization.
    pub fn initWithIoInto(self: *ClientConnection, socket: *Socket, io: Io, runtime_cfg: config.H2Config, storage: *ConnectionStorage) Error!void {
        assert(@intFromPtr(socket) != 0);
        assert(socket.get_fd() >= 0);
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(storage) != 0);
        try initMaybeIoInto(self, socket, io, runtime_cfg, storage);
    }

    fn initMaybeIoInto(
        self: *ClientConnection,
        socket: *Socket,
        io: ?Io,
        runtime_cfg: config.H2Config,
        storage: *ConnectionStorage,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(socket) != 0);
        assert(socket.get_fd() >= 0);
        assert(@intFromPtr(storage) != 0);
        assert(runtime_cfg.max_frame_size_bytes <= h2.frame_payload_capacity_bytes);
        assert(runtime_cfg.max_header_block_size_bytes <= h2.header_block_capacity_bytes);
        assert(storage.pending_response_headers_storage.len >= runtime_cfg.max_header_block_size_bytes);
        assert(storage.response_fields_storage.len >= config.MAX_HEADERS);
        assert(storage.request_header_block_buf.len >= runtime_cfg.max_header_block_size_bytes);
        assert(storage.recv_buf.len == read_buffer_size_bytes);
        assert(storage.plain_write_buf.len == config.STREAM_WRITE_BUFFER_SIZE_BYTES);
        assert(storage.preface_settings_buf.len == preface_settings_buffer_size_bytes);
        assert(storage.settings_ack_buf.len == h2.frame_header_size_bytes);
        assert(storage.ping_ack_buf.len == h2.frame_header_size_bytes + h2.control.ping_payload_size_bytes);
        assert(storage.request_headers_frame_buf.len == request_headers_frame_buffer_size_bytes);
        assert(storage.data_frame_buf.len == data_frame_buffer_size_bytes);
        assert(storage.rst_stream_buf.len == h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes);
        assert(storage.conn_window_update_buf.len == window_update_frame_size_bytes);
        assert(storage.stream_window_update_buf.len == window_update_frame_size_bytes);

        self.runtime_cfg = runtime_cfg;
        self.socket = socket;
        self.io = io;
        self.pending_response_headers_storage = &storage.pending_response_headers_storage;
        self.request_header_block_buf = &storage.request_header_block_buf;
        self.recv_buf = &storage.recv_buf;
        self.plain_write_buf = &storage.plain_write_buf;
        self.preface_settings_buf = &storage.preface_settings_buf;
        self.settings_ack_buf = &storage.settings_ack_buf;
        self.ping_ack_buf = &storage.ping_ack_buf;
        self.request_headers_frame_buf = &storage.request_headers_frame_buf;
        self.data_frame_buf = &storage.data_frame_buf;
        self.rst_stream_buf = &storage.rst_stream_buf;
        self.conn_window_update_buf = &storage.conn_window_update_buf;
        self.stream_window_update_buf = &storage.stream_window_update_buf;
        self.recv_len = 0;
        self.pending_discard_len = 0;
        self.frame_count = 0;
        try self.runtime.initInto(runtime_cfg, &storage.response_fields_storage);
    }

    /// Send the client connection preface followed by the initial SETTINGS frame.
    /// Requires an open socket and writes the runtime-encoded preface/settings bytes to the connection.
    /// Propagates any error from frame encoding or writing.
    pub fn sendClientPrefaceAndSettings(self: *ClientConnection) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.socket.get_fd() >= 0);
        assert(self.preface_settings_buf.len == preface_settings_buffer_size_bytes);

        const frame = try self.runtime.writeClientPrefaceAndSettings(self.preface_settings_buf);
        assert(frame.len <= self.preface_settings_buf.len);
        try self.writeAll(frame);
    }

    /// Send the pending SETTINGS acknowledgment frame.
    /// Requires that the peer settings ACK is still pending and writes the runtime's encoded ACK frame to the connection.
    /// Propagates any error from frame encoding or writing.
    pub fn sendPendingSettingsAck(self: *ClientConnection) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.runtime.state.peer_settings_ack_pending);

        const frame = try self.runtime.writePendingSettingsAck(self.settings_ack_buf);
        try self.writeAll(frame);
    }

    /// Send an HTTP/2 `PING` acknowledgment frame with the provided opaque payload.
    /// Requires an 8-byte payload and writes a frame whose length matches the preallocated buffer.
    /// Propagates any error from frame encoding or writing.
    pub fn sendPingAck(
        self: *ClientConnection,
        opaque_data: [h2.control.ping_payload_size_bytes]u8,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(h2.control.ping_payload_size_bytes == 8);

        const frame = try runtime_mod.Runtime.writePingAckFrame(self.ping_ack_buf, opaque_data);
        assert(frame.len == self.ping_ack_buf.len);
        try self.writeAll(frame);
    }

    /// Complete the HTTP/2 client handshake by sending the preface and waiting for the peer's settings state.
    /// Loops until peer settings are received and acknowledged, or until `h2.max_initial_parse_frames` frames have been parsed.
    /// Returns `error.ConnectionClosing`, `error.UnexpectedHandshakeFrame`, `error.MissingInitialSettings`, or `error.WriteFailed` for the corresponding handshake failure.
    pub fn completeHandshake(self: *ClientConnection) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(h2.max_initial_parse_frames > 0);

        try self.sendClientPrefaceAndSettings();

        var frames: u32 = 0;
        while (frames < h2.max_initial_parse_frames) : (frames += 1) {
            if (self.runtime.state.peer_settings_received and !self.runtime.state.peer_settings_ack_pending) {
                return;
            }

            const action = try self.receiveAction();
            if (try self.handleControlAction(action)) continue;

            switch (action) {
                .none => {},
                .connection_close => return error.ConnectionClosing,
                else => return error.UnexpectedHandshakeFrame,
            }
        }

        if (!self.runtime.state.peer_settings_received) return error.MissingInitialSettings;
        if (self.runtime.state.peer_settings_ack_pending) return error.WriteFailed;
    }

    /// Serialize request headers for a new request stream and write them to the connection.
    /// Requires a non-empty request path; `request` and `effective_path` are borrowed inputs and are not retained.
    /// Returns the allocated stream ID on success and propagates any error from header encoding or writing.
    pub fn sendRequestHeaders(
        self: *ClientConnection,
        request: *const Request,
        effective_path: ?[]const u8,
        end_stream: bool,
    ) Error!u32 {
        assert(@intFromPtr(self) != 0);
        assert(request.path.len > 0);
        assert(self.request_headers_frame_buf.len == request_headers_frame_buffer_size_bytes);
        assert(self.request_header_block_buf.len >= self.runtime_cfg.max_header_block_size_bytes);

        const write = try self.runtime.writeRequestHeadersFrame(
            self.request_headers_frame_buf,
            self.request_header_block_buf,
            request,
            effective_path,
            end_stream,
        );
        try self.writeAll(write.frame);
        return write.stream_id;
    }

    /// Send request body data for an existing stream.
    /// Requires `stream_id > 0` and a payload length that fits in `u32`; an empty payload only sends a frame when `end_stream` is true.
    /// Propagates any error from frame chunking or writing, and does not transfer ownership of `payload`.
    pub fn sendRequestData(
        self: *ClientConnection,
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        assert(payload.len <= std.math.maxInt(u32));

        if (payload.len == 0) {
            if (!end_stream) return;
            try self.sendEmptyRequestDataFrame(stream_id);
            return;
        }

        try self.sendRequestDataChunks(stream_id, payload, end_stream);
    }

    fn sendEmptyRequestDataFrame(self: *ClientConnection, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);
        assert(self.data_frame_buf.len == data_frame_buffer_size_bytes);

        const frame = try self.runtime.writeRequestDataFrame(self.data_frame_buf, stream_id, &[_]u8{}, true);
        assert(frame.len == h2.frame_header_size_bytes);
        try self.writeAll(frame);
    }

    fn sendRequestDataChunks(
        self: *ClientConnection,
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(payload.len > 0);
        assert(payload.len <= std.math.maxInt(u32));

        const payload_len: u32 = @intCast(payload.len);
        var sent: u32 = 0;
        var frames: u32 = 0;

        while (sent < payload_len and frames < self.runtime_cfg.client_max_frame_count) : (frames += 1) {
            const stream = self.runtime.state.getStream(stream_id) orelse return logAndReturnMissingStream(self, stream_id, sent, payload_len, frames);
            if (self.runtime.state.goaway_received and stream_id > self.runtime.state.peer_goaway_last_stream_id) {
                return error.ConnectionClosing;
            }
            const chunk_len = computeDataChunkLen(self, stream, sent, payload_len);
            if (chunk_len == 0) return error.SendWindowExhausted;
            try self.sendDataChunk(stream_id, payload, sent, chunk_len, payload_len, end_stream);
            sent += chunk_len;
        }

        if (sent < payload_len) return error.FrameLimitExceeded;
        assert(sent == payload_len);
    }

    fn sendDataChunk(
        self: *ClientConnection,
        stream_id: u32,
        payload: []const u8,
        sent: u32,
        chunk_len: u32,
        payload_len: u32,
        end_stream: bool,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(chunk_len > 0);
        assert(sent + chunk_len <= payload_len);

        const offset: usize = @intCast(sent);
        const limit: usize = @intCast(sent + chunk_len);
        const chunk = payload[offset..limit];
        const is_last_chunk = sent + chunk_len == payload_len;
        assert(self.data_frame_buf.len == data_frame_buffer_size_bytes);

        const frame = try self.runtime.writeRequestDataFrame(
            self.data_frame_buf,
            stream_id,
            chunk,
            end_stream and is_last_chunk,
        );
        assert(frame.len >= h2.frame_header_size_bytes);
        try self.writeAll(frame);
    }

    fn computeDataChunkLen(
        self: *const ClientConnection,
        stream: *const h2.H2Stream,
        sent: u32,
        payload_len: u32,
    ) u32 {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(stream) != 0);
        assert(sent <= payload_len);

        const connection_window = self.runtime.state.flow.send_window.available_bytes;
        const stream_window = stream.send_window.available_bytes;
        const window_budget = @min(connection_window, stream_window);
        const remaining = payload_len - sent;
        const peer_max_frame = self.runtime.state.peer_settings.max_frame_size_bytes;
        const effective_max_frame = effectiveLocalDataFramePayloadSizeBytes(peer_max_frame);
        const chunk_len = @min(remaining, @min(window_budget, effective_max_frame));
        assert(chunk_len <= remaining);
        return chunk_len;
    }

    fn effectiveLocalDataFramePayloadSizeBytes(peer_max_frame_size_bytes: u32) u32 {
        assert(peer_max_frame_size_bytes >= h2.settings.min_max_frame_size_bytes);
        assert(peer_max_frame_size_bytes <= h2.settings.max_max_frame_size_bytes);
        assert(local_data_frame_payload_capacity_bytes > 0);

        const effective = @min(peer_max_frame_size_bytes, local_data_frame_payload_capacity_bytes);
        assert(effective > 0);
        assert(effective <= local_data_frame_payload_capacity_bytes);
        return effective;
    }

    fn logAndReturnMissingStream(
        self: *const ClientConnection,
        stream_id: u32,
        sent: u32,
        payload_len: u32,
        frames: u32,
    ) Error {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        log.warn(
            "client h2 connection: missing stream in sendRequestData stream={d} sent={d}/{d} frames={d} active={d} last_local={d} last_remote={d} goaway={any} last_stream_id={d}",
            .{
                stream_id,
                sent,
                payload_len,
                frames,
                self.runtime.state.streams.active_count,
                self.runtime.state.streams.last_local_stream_id,
                self.runtime.state.streams.last_remote_stream_id,
                self.runtime.state.goaway_received,
                self.runtime.state.peer_goaway_last_stream_id,
            },
        );
        return error.StreamNotFound;
    }

    /// Send an HTTP/2 `RST_STREAM` frame for the given stream.
    /// Requires `stream_id > 0` and writes the frame using the runtime's frame encoder.
    /// Propagates any error returned by frame construction or by the underlying write.
    pub fn sendStreamReset(self: *ClientConnection, stream_id: u32, error_code_raw: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const frame = try self.runtime.writeRstStreamFrame(self.rst_stream_buf, .{
            .stream_id = stream_id,
            .error_code_raw = error_code_raw,
        });
        try self.writeAll(frame);
    }

    /// Replenish the connection and stream receive windows after bytes have been consumed.
    /// A `consumed_bytes` value of zero is a no-op; otherwise both window counters are incremented and WINDOW_UPDATE frames are sent.
    /// Propagates any error from window accounting, frame निर्माण, or writing either update frame.
    pub fn replenishReceiveWindows(self: *ClientConnection, stream_id: u32, consumed_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        if (consumed_bytes == 0) return;

        try self.runtime.state.incrementRecvWindow(consumed_bytes);
        try self.runtime.state.incrementStreamRecvWindow(stream_id, consumed_bytes);
        assert(self.conn_window_update_buf.len == window_update_frame_size_bytes);
        assert(self.stream_window_update_buf.len == window_update_frame_size_bytes);

        const conn_window_update = try h2.buildWindowUpdateFrame(self.conn_window_update_buf, 0, consumed_bytes);
        try self.writeAll(conn_window_update);

        const stream_window_update = try h2.buildWindowUpdateFrame(self.stream_window_update_buf, stream_id, consumed_bytes);
        try self.writeAll(stream_window_update);
    }

    /// Receive and dispatch the next frame using the connection's default I/O path.
    /// Requires that the discard bookkeeping is already consistent with the buffered receive data.
    /// Propagates any error returned by the timeout-based receive path.
    pub fn receiveAction(self: *ClientConnection) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(self.pending_discard_len <= self.recv_len);
        return self.receiveActionTimeout(null, .none);
    }

    /// Receive and dispatch the next frame using the provided I/O source.
    /// Requires an open socket and delegates to `receiveActionTimeout` with no receive timeout.
    /// Propagates any error returned by the timeout-based receive path.
    pub fn receiveActionIo(self: *ClientConnection, io: Io) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(self.socket.get_fd() >= 0);
        return self.receiveActionTimeout(io, .none);
    }

    /// Read the next HTTP/2 frame, finalize any pending discard state, and dispatch the frame to the runtime.
    /// Requires that `pending_discard_len` does not exceed the buffered receive length and that the frame budget has not been exhausted.
    /// Returns `error.FrameLimitExceeded` when the frame limit is reached, `error.ConnectionClosed` when no more data can be read, and propagates parse or runtime errors.
    pub fn receiveActionTimeout(self: *ClientConnection, maybe_io: ?Io, timeout: Io.Timeout) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(self.pending_discard_len <= self.recv_len);

        self.finalizePendingFrame();
        if (self.frame_count >= self.runtime_cfg.client_max_frame_count) return error.FrameLimitExceeded;
        if (!try self.ensureFrame(maybe_io, timeout)) return error.ConnectionClosed;

        const header = try h2.parseFrameHeader(self.recv_buf[0..h2.frame_header_size_bytes]);
        const frame_len: usize = @as(usize, h2.frame_header_size_bytes) + @as(usize, header.length);
        const payload_start: usize = h2.frame_header_size_bytes;
        const payload_end: usize = frame_len;
        const action = try self.runtime.receiveFrame(
            self.pending_response_headers_storage,
            header,
            self.recv_buf[payload_start..payload_end],
        );

        self.pending_discard_len = frame_len;
        self.frame_count += 1;
        return action;
    }

    /// Receive and dispatch the next frame while skipping over control frames.
    /// Uses the connection's default I/O path and no timeout, and stops after `config.H2_CLIENT_MAX_FRAME_COUNT` frames.
    /// Returns `error.FrameLimitExceeded` if the control-frame bound is reached, and otherwise propagates receive or runtime errors.
    pub fn receiveActionHandlingControl(self: *ClientConnection) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(self.runtime_cfg.client_max_frame_count > 0);
        return self.receiveActionHandlingControlTimeout(null, .none);
    }

    /// Receive and dispatch the next frame using the provided I/O source.
    /// Requires an open socket and delegates to `receiveActionHandlingControlTimeout` with no receive timeout.
    /// Propagates any error returned by the timeout-based receive path.
    pub fn receiveActionHandlingControlIo(self: *ClientConnection, io: Io) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(self.socket.get_fd() >= 0);
        return self.receiveActionHandlingControlTimeout(io, .none);
    }

    /// Receive and dispatch the next frame while continuing past control frames.
    /// Stops after `config.H2_CLIENT_MAX_FRAME_COUNT` control frames and returns `error.FrameLimitExceeded` if that bound is reached.
    /// Uses `maybe_io` and `timeout` for frame reads, and propagates any I/O, parse, or runtime errors from the underlying receive path.
    pub fn receiveActionHandlingControlTimeout(
        self: *ClientConnection,
        maybe_io: ?Io,
        timeout: Io.Timeout,
    ) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(self.runtime_cfg.client_max_frame_count > 0);

        var frames: u32 = 0;
        while (frames < self.runtime_cfg.client_max_frame_count) : (frames += 1) {
            const action = try self.receiveActionTimeout(maybe_io, timeout);
            if (try self.handleControlAction(action)) continue;
            return action;
        }

        return error.FrameLimitExceeded;
    }

    fn handleControlAction(self: *ClientConnection, action: runtime_mod.ReceiveAction) Error!bool {
        assert(@intFromPtr(self) != 0);
        assert(self.socket.get_fd() >= 0);

        switch (action) {
            .send_settings_ack => {
                self.sendPendingSettingsAck() catch |err| switch (err) {
                    error.ConnectionClosed => {},
                    else => return err,
                };
            },
            .send_ping_ack => |opaque_data| {
                self.sendPingAck(opaque_data) catch |err| switch (err) {
                    error.ConnectionClosed => {},
                    else => return err,
                };
            },
            else => return false,
        }

        return true;
    }

    fn ensureFrame(self: *ClientConnection, maybe_io: ?Io, timeout: Io.Timeout) Error!bool {
        assert(@intFromPtr(self) != 0);
        assert(self.recv_len <= self.recv_buf.len);

        if (self.recv_len == 0) {
            const n = try self.readIntoBuffer(maybe_io, timeout);
            if (n == 0) return false;
        }

        try self.fillBuffer(maybe_io, timeout, h2.frame_header_size_bytes);
        const header = try h2.parseFrameHeader(self.recv_buf[0..h2.frame_header_size_bytes]);
        const frame_len: usize = @as(usize, h2.frame_header_size_bytes) + @as(usize, header.length);
        try self.fillBuffer(maybe_io, timeout, frame_len);
        return true;
    }

    fn fillBuffer(self: *ClientConnection, maybe_io: ?Io, timeout: Io.Timeout, needed_len: usize) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(needed_len <= self.recv_buf.len);

        var reads: u32 = 0;
        while (self.recv_len < needed_len and reads < self.recv_buf.len) : (reads += 1) {
            const n = try self.readIntoBuffer(maybe_io, timeout);
            if (n == 0) return error.ConnectionClosed;
        }

        if (self.recv_len < needed_len) return error.ReadFailed;
    }

    fn readIntoBuffer(self: *ClientConnection, maybe_io: ?Io, timeout: Io.Timeout) Error!usize {
        assert(@intFromPtr(self) != 0);
        assert(self.recv_len <= self.recv_buf.len);

        const n = try readSome(self.socket, maybe_io, timeout, self.recv_buf[self.recv_len..]);
        if (n == 0) return 0;

        self.recv_len += n;
        assert(self.recv_len <= self.recv_buf.len);
        return n;
    }

    fn finalizePendingFrame(self: *ClientConnection) void {
        assert(@intFromPtr(self) != 0);
        assert(self.pending_discard_len <= self.recv_len);

        if (self.pending_discard_len == 0) return;
        self.discardPrefix(self.pending_discard_len);
        self.pending_discard_len = 0;
    }

    fn discardPrefix(self: *ClientConnection, prefix_len: usize) void {
        assert(@intFromPtr(self) != 0);
        assert(prefix_len <= self.recv_len);

        if (prefix_len == self.recv_len) {
            self.recv_len = 0;
            return;
        }

        std.mem.copyForwards(u8, self.recv_buf[0 .. self.recv_len - prefix_len], self.recv_buf[prefix_len..self.recv_len]);
        self.recv_len -= prefix_len;
    }

    fn writeAll(self: *ClientConnection, data: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.socket.get_fd() >= 0);

        switch (self.socket.*) {
            .plain => |plain| {
                if (self.io) |io| {
                    var writer = rawStreamForFd(plain.fd).writer(io, self.plain_write_buf);
                    writer.interface.writeAll(data) catch return mapIoWriteError(writer.err orelse error.WriteFailed);
                    writer.interface.flush() catch return mapIoWriteError(writer.err orelse error.WriteFailed);
                    return;
                }

                self.socket.write_all(data) catch |err| return mapWriteError(err);
            },
            .tls => {
                self.socket.write_all(data) catch |err| return mapWriteError(err);
            },
        }
    }
};

fn readSome(socket: *Socket, maybe_io: ?Io, timeout: Io.Timeout, out: []u8) Error!u32 {
    assert(@intFromPtr(socket) != 0);
    assert(out.len > 0);

    return switch (socket.*) {
        .plain => |*plain| blk: {
            if (maybe_io) |io| {
                if (timeout != .none) {
                    try waitUntilReadable(plain.fd, io, timeout);
                }
                var bufs: [1][]u8 = .{out};
                const n = io.vtable.netRead(io.userdata, plain.fd, &bufs) catch |err| switch (err) {
                    error.ConnectionResetByPeer,
                    error.SocketUnconnected,
                    => return error.ConnectionClosed,
                    error.SystemResources => return error.WouldBlock,
                    else => return error.ReadFailed,
                };
                break :blk @intCast(n);
            }
            const n = plain.read(out) catch |err| return mapReadError(err);
            break :blk n;
        },
        .tls => |*tls_socket| blk: {
            if (tls_socket.has_pending_read()) {
                const n = tls_socket.stream.read(out) catch |err| switch (err) {
                    error.WantRead, error.WantWrite => return error.WouldBlock,
                    else => return error.ReadFailed,
                };
                break :blk n;
            }

            if (maybe_io) |io| {
                try waitUntilReadable(tls_socket.fd, io, timeout);
            }
            const n = tls_socket.stream.read(out) catch |err| switch (err) {
                error.WantRead, error.WantWrite => return error.WouldBlock,
                error.ConnectionReset => return error.ConnectionClosed,
                else => return error.ReadFailed,
            };
            break :blk n;
        },
    };
}

fn waitUntilReadable(fd: i32, io: Io, timeout: Io.Timeout) Error!void {
    assert(fd >= 0);
    assert(rawStreamForFd(fd).socket.handle == fd);
    var messages: [1]Io.net.IncomingMessage = .{Io.net.IncomingMessage.init};
    var peek_buf: [1]u8 = undefined;
    const maybe_err, _ = rawStreamForFd(fd).socket.receiveManyTimeout(
        io,
        &messages,
        &peek_buf,
        .{ .peek = true },
        timeout,
    );
    if (maybe_err) |err| switch (err) {
        error.Timeout => return error.WouldBlock,
        error.ConnectionResetByPeer => return error.ConnectionClosed,
        else => return error.ReadFailed,
    };
}

fn rawStreamForFd(fd: i32) Io.net.Stream {
    assert(fd >= 0);
    const stream: Io.net.Stream = .{
        .socket = .{
            .handle = fd,
            .address = .{ .ip4 = .unspecified(0) },
        },
    };
    assert(stream.socket.handle == fd);
    return stream;
}

fn mapReadError(err: SocketError) Error {
    const mapped: Error = switch (err) {
        error.ConnectionClosed,
        error.ConnectionReset,
        => error.ConnectionClosed,
        else => error.ReadFailed,
    };
    assert(mapped != error.WriteFailed);
    assert(mapped == error.ConnectionClosed or mapped == error.ReadFailed);
    return mapped;
}

fn mapWriteError(err: SocketError) Error {
    const mapped: Error = switch (err) {
        error.ConnectionClosed,
        error.ConnectionReset,
        error.BrokenPipe,
        => error.ConnectionClosed,
        else => error.WriteFailed,
    };
    assert(mapped != error.ReadFailed);
    assert(mapped == error.ConnectionClosed or mapped == error.WriteFailed);
    return mapped;
}

fn mapIoReadError(err: anyerror) Error {
    const mapped: Error = switch (err) {
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        => error.ConnectionClosed,
        else => error.ReadFailed,
    };
    assert(mapped != error.WriteFailed);
    assert(mapped == error.ConnectionClosed or mapped == error.ReadFailed);
    return mapped;
}

fn mapIoWriteError(err: anyerror) Error {
    const mapped: Error = switch (err) {
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.SocketUnconnected,
        => error.ConnectionClosed,
        else => error.WriteFailed,
    };
    assert(mapped != error.ReadFailed);
    assert(mapped == error.ConnectionClosed or mapped == error.WriteFailed);
    return mapped;
}

fn appendFrame(
    out: []u8,
    frame_type: h2.FrameType,
    flags: u8,
    stream_id: u32,
    payload: []const u8,
) ![]const u8 {
    assert(out.len >= h2.frame_header_size_bytes);
    assert(payload.len <= std.math.maxInt(u24));
    assert(out.len >= h2.frame_header_size_bytes + payload.len);

    const header = try h2.buildFrameHeader(out[0..h2.frame_header_size_bytes], .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    @memcpy(out[header.len..][0..payload.len], payload);
    return out[0 .. header.len + payload.len];
}

fn buildHeaderBlock(headers: []const types.Header, out: []u8) ![]const u8 {
    assert(out.len > 0);
    assert(headers.len <= config.MAX_HEADERS);

    var cursor: usize = 0;
    for (headers) |header| {
        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value);
        cursor += encoded.len;
    }
    assert(cursor <= out.len);
    return out[0..cursor];
}

fn buildResponseHeaderBlock(status: u16, headers: []const types.Header, out: []u8) ![]const u8 {
    assert(status >= 100 and status <= 599);
    assert(out.len > 0);

    var cursor: usize = 0;
    var status_buf: [3]u8 = undefined;
    const status_text = try std.fmt.bufPrint(&status_buf, "{d}", .{status});

    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":status", status_text)).len;
    for (headers) |header| {
        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value);
        cursor += encoded.len;
    }
    assert(cursor <= out.len);
    return out[0..cursor];
}

fn readExact(fd: i32, out: []u8) !void {
    assert(fd >= 0);

    var offset: usize = 0;
    var reads: usize = 0;
    const max_reads: usize = std.math.add(usize, out.len, 32) catch return error.ReadFailed;

    while (offset < out.len and reads < max_reads) : (reads += 1) {
        const n = posix.read(fd, out[offset..]) catch return error.ReadFailed;
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }

    if (offset < out.len) return error.ReadFailed;
    assert(offset == out.len);
}

fn writeAllFd(fd: i32, data: []const u8) !void {
    assert(fd >= 0);
    if (data.len == 0) return;

    var socket = Socket.Plain.init_client(fd);
    assert(socket.get_fd() == fd);
    socket.write_all(data) catch return error.WriteFailed;
}

fn testSocketPair(domain: u32, sock_type: u32, protocol: u32) ![2]posix.socket_t {
    assert(domain <= std.math.maxInt(c_int));
    assert(sock_type <= std.math.maxInt(c_int));

    var fds: [2]posix.socket_t = undefined;
    var attempts: u32 = 0;
    const max_attempts: u32 = 1024;

    while (attempts < max_attempts) : (attempts += 1) {
        const rc = std.c.socketpair(@intCast(domain), @intCast(sock_type), @intCast(protocol), &fds);
        switch (std.c.errno(rc)) {
            .SUCCESS => return fds,
            .INTR => continue,
            else => return error.SocketFailed,
        }
    }
    return error.SocketFailed;
}

fn buildPeerSettingsFrame(out: []u8) ![]const u8 {
    assert(out.len >= h2.frame_header_size_bytes);
    const frame = try appendFrame(out, .settings, 0, 0, &[_]u8{});
    assert(frame.len == h2.frame_header_size_bytes);
    return frame;
}

fn makeGrpcRequest(path: []const u8) !Request {
    assert(path.len > 0);
    assert(path[0] == '/');

    var request = Request{
        .method = .POST,
        .path = path,
        .version = .@"HTTP/1.1",
        .headers = .{},
        .body = null,
    };
    try request.headers.put("host", "127.0.0.1:19000");
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");
    assert(request.headers.get("te") != null);
    return request;
}

test "waitUntilReadable returns WouldBlock when timeout expires" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    const timeout: Io.Timeout = .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(20),
        .clock = .awake,
    } };
    try std.testing.expectError(error.WouldBlock, waitUntilReadable(fds[0], std.Options.debug_io, timeout));
}

test "waitUntilReadable preserves peeked data" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    const payload = [_]u8{0x42};
    try std.testing.expectEqual(@as(usize, 1), try posix.write(fds[1], &payload));

    const timeout: Io.Timeout = .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(50),
        .clock = .awake,
    } };
    try waitUntilReadable(fds[0], std.Options.debug_io, timeout);

    var out: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try posix.read(fds[0], &out));
    try std.testing.expectEqual(payload[0], out[0]);
}

test "ClientConnection sends client preface and initial settings" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    var socket = Socket.Plain.init_client(fds[0]);
    var storage = ConnectionStorage{};
    var conn: ClientConnection = undefined;
    try conn.initInto(&socket, .{}, &storage);
    try conn.sendClientPrefaceAndSettings();

    var expected_response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var expected_runtime: runtime_mod.Runtime = undefined;
    try expected_runtime.initInto(.{}, &expected_response_fields_storage);
    var expected_buf: [preface_settings_buffer_size_bytes]u8 = undefined;
    const expected = try expected_runtime.writeClientPrefaceAndSettings(&expected_buf);

    var received_buf: [preface_settings_buffer_size_bytes]u8 = undefined;
    try readExact(fds[1], received_buf[0..expected.len]);
    try std.testing.expectEqualSlices(u8, expected, received_buf[0..expected.len]);
}

test "ClientConnection completeHandshake sends settings ACK" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    var peer_settings_buf: [h2.frame_header_size_bytes]u8 = undefined;
    const peer_settings = try buildPeerSettingsFrame(&peer_settings_buf);
    try writeAllFd(fds[1], peer_settings);

    var socket = Socket.Plain.init_client(fds[0]);
    var storage = ConnectionStorage{};
    var conn: ClientConnection = undefined;
    try conn.initInto(&socket, .{}, &storage);
    try conn.completeHandshake();

    var expected_response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var expected_runtime: runtime_mod.Runtime = undefined;
    try expected_runtime.initInto(.{}, &expected_response_fields_storage);
    var expected_preface_buf: [preface_settings_buffer_size_bytes]u8 = undefined;
    const expected_preface = try expected_runtime.writeClientPrefaceAndSettings(&expected_preface_buf);

    var wire_buf: [preface_settings_buffer_size_bytes + h2.frame_header_size_bytes]u8 = undefined;
    try readExact(fds[1], wire_buf[0 .. expected_preface.len + h2.frame_header_size_bytes]);

    try std.testing.expectEqualSlices(u8, expected_preface, wire_buf[0..expected_preface.len]);

    const ack_offset = expected_preface.len;
    const ack_header = try h2.parseFrameHeader(wire_buf[ack_offset .. ack_offset + h2.frame_header_size_bytes]);
    try std.testing.expectEqual(h2.FrameType.settings, ack_header.frame_type);
    try std.testing.expectEqual(h2.flags_ack, ack_header.flags);
    try std.testing.expectEqual(@as(u32, 0), ack_header.length);
}

test "ClientConnection replenishes receive windows for active stream" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    var peer_settings_buf: [h2.frame_header_size_bytes]u8 = undefined;
    const peer_settings = try buildPeerSettingsFrame(&peer_settings_buf);
    try writeAllFd(fds[1], peer_settings);

    var socket = Socket.Plain.init_client(fds[0]);
    var storage = ConnectionStorage{};
    var conn: ClientConnection = undefined;
    try conn.initInto(&socket, .{}, &storage);
    try conn.completeHandshake();

    var expected_response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var expected_runtime: runtime_mod.Runtime = undefined;
    try expected_runtime.initInto(.{}, &expected_response_fields_storage);
    var expected_preface_buf: [preface_settings_buffer_size_bytes]u8 = undefined;
    const expected_preface = try expected_runtime.writeClientPrefaceAndSettings(&expected_preface_buf);
    var handshake_wire: [preface_settings_buffer_size_bytes + h2.frame_header_size_bytes]u8 = undefined;
    try readExact(fds[1], handshake_wire[0 .. expected_preface.len + h2.frame_header_size_bytes]);

    var request = try makeGrpcRequest("/grpc.test.Echo/WindowUpdate");
    const stream_id = try conn.sendRequestHeaders(&request, null, false);
    try std.testing.expectEqual(@as(u32, 1), stream_id);

    var request_headers_wire_header: [h2.frame_header_size_bytes]u8 = undefined;
    try readExact(fds[1], &request_headers_wire_header);
    const request_headers_header = try h2.parseFrameHeader(&request_headers_wire_header);
    try std.testing.expectEqual(h2.FrameType.headers, request_headers_header.frame_type);

    var request_header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const request_header_block_len: usize = @intCast(request_headers_header.length);
    try readExact(fds[1], request_header_block_buf[0..request_header_block_len]);

    try conn.replenishReceiveWindows(stream_id, 16);

    var conn_update_frame_buf: [window_update_frame_size_bytes]u8 = undefined;
    try readExact(fds[1], &conn_update_frame_buf);
    const conn_update_header = try h2.parseFrameHeader(&conn_update_frame_buf);
    try std.testing.expectEqual(h2.FrameType.window_update, conn_update_header.frame_type);
    try std.testing.expectEqual(@as(u32, 0), conn_update_header.stream_id);
    const conn_update_increment = try h2.parseWindowUpdateFrame(
        conn_update_header,
        conn_update_frame_buf[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes],
    );
    try std.testing.expectEqual(@as(u32, 16), conn_update_increment);

    var stream_update_frame_buf: [window_update_frame_size_bytes]u8 = undefined;
    try readExact(fds[1], &stream_update_frame_buf);
    const stream_update_header = try h2.parseFrameHeader(&stream_update_frame_buf);
    try std.testing.expectEqual(h2.FrameType.window_update, stream_update_header.frame_type);
    try std.testing.expectEqual(stream_id, stream_update_header.stream_id);
    const stream_update_increment = try h2.parseWindowUpdateFrame(
        stream_update_header,
        stream_update_frame_buf[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes],
    );
    try std.testing.expectEqual(@as(u32, 16), stream_update_increment);
}

test "ClientConnection request send and response receive round-trip" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    var peer_settings_buf: [h2.frame_header_size_bytes]u8 = undefined;
    const peer_settings = try buildPeerSettingsFrame(&peer_settings_buf);
    try writeAllFd(fds[1], peer_settings);

    var socket = Socket.Plain.init_client(fds[0]);
    var storage = ConnectionStorage{};
    var conn: ClientConnection = undefined;
    try conn.initInto(&socket, .{}, &storage);
    try conn.completeHandshake();

    var expected_response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var expected_runtime: runtime_mod.Runtime = undefined;
    try expected_runtime.initInto(.{}, &expected_response_fields_storage);
    var expected_preface_buf: [preface_settings_buffer_size_bytes]u8 = undefined;
    const expected_preface = try expected_runtime.writeClientPrefaceAndSettings(&expected_preface_buf);
    var handshake_wire: [preface_settings_buffer_size_bytes + h2.frame_header_size_bytes]u8 = undefined;
    try readExact(fds[1], handshake_wire[0 .. expected_preface.len + h2.frame_header_size_bytes]);

    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");
    const stream_id = try conn.sendRequestHeaders(&request, null, false);
    try std.testing.expectEqual(@as(u32, 1), stream_id);
    try conn.sendRequestData(stream_id, "ping", true);

    var request_headers_wire_header: [h2.frame_header_size_bytes]u8 = undefined;
    try readExact(fds[1], &request_headers_wire_header);
    const request_headers_header = try h2.parseFrameHeader(&request_headers_wire_header);
    try std.testing.expectEqual(h2.FrameType.headers, request_headers_header.frame_type);
    try std.testing.expectEqual(stream_id, request_headers_header.stream_id);

    var request_header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const request_header_block_len: usize = @intCast(request_headers_header.length);
    try readExact(fds[1], request_header_block_buf[0..request_header_block_len]);

    var request_fields_buf: [config.MAX_HEADERS]h2.HeaderField = undefined;
    const request_fields = try h2.decodeHeaderBlock(request_header_block_buf[0..request_header_block_len], &request_fields_buf);
    try std.testing.expectEqualStrings(":method", request_fields[0].name);
    try std.testing.expectEqualStrings("POST", request_fields[0].value);

    var request_data_wire_header: [h2.frame_header_size_bytes]u8 = undefined;
    try readExact(fds[1], &request_data_wire_header);
    const request_data_header = try h2.parseFrameHeader(&request_data_wire_header);
    try std.testing.expectEqual(h2.FrameType.data, request_data_header.frame_type);
    try std.testing.expect((request_data_header.flags & h2.flags_end_stream) != 0);

    var request_data_payload_buf: [16]u8 = undefined;
    const request_data_len: usize = @intCast(request_data_header.length);
    try readExact(fds[1], request_data_payload_buf[0..request_data_len]);
    try std.testing.expectEqualStrings("ping", request_data_payload_buf[0..request_data_len]);

    var response_header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const response_header_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &response_header_block_buf,
    );

    var response_headers_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        h2.flags_end_headers,
        stream_id,
        response_header_block,
    );
    try writeAllFd(fds[1], response_headers_frame);

    var response_data_frame_buf: [h2.frame_header_size_bytes + 16]u8 = undefined;
    const response_data_frame = try appendFrame(&response_data_frame_buf, .data, 0, stream_id, "pong");
    const response_data_header_check = try h2.parseFrameHeader(response_data_frame);
    try std.testing.expectEqual(h2.FrameType.data, response_data_header_check.frame_type);
    try std.testing.expectEqualStrings("pong", response_data_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + 4]);
    try writeAllFd(fds[1], response_data_frame);

    var trailer_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const trailer_block = try buildHeaderBlock(&.{.{ .name = "grpc-status", .value = "0" }}, &trailer_block_buf);

    var trailers_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const trailers_frame = try appendFrame(
        &trailers_frame_buf,
        .headers,
        h2.flags_end_headers | h2.flags_end_stream,
        stream_id,
        trailer_block,
    );
    try writeAllFd(fds[1], trailers_frame);

    const action1 = try conn.receiveActionHandlingControl();
    switch (action1) {
        .response_headers => |response_headers| {
            try std.testing.expectEqual(stream_id, response_headers.stream_id);
            try std.testing.expectEqual(@as(u16, 200), response_headers.response.status);
            try std.testing.expect(!response_headers.end_stream);
        },
        else => return error.UnexpectedAction,
    }

    const action2 = try conn.receiveActionHandlingControl();
    switch (action2) {
        .response_data => |response_data| {
            try std.testing.expectEqual(stream_id, response_data.stream_id);
            try std.testing.expectEqualStrings("pong", response_data.payload);
            try std.testing.expect(!response_data.end_stream);
        },
        else => return error.UnexpectedAction,
    }

    const action3 = try conn.receiveActionHandlingControl();
    switch (action3) {
        .response_trailers => |response_trailers| {
            try std.testing.expectEqual(stream_id, response_trailers.stream_id);
            try std.testing.expectEqualStrings("0", response_trailers.trailers.get("grpc-status").?);
        },
        else => return error.UnexpectedAction,
    }

    try std.testing.expect(conn.runtime.state.getStream(stream_id) == null);
}

test "effectiveLocalDataFramePayloadSizeBytes clamps peer max to local capacity" {
    try std.testing.expectEqual(
        local_data_frame_payload_capacity_bytes,
        ClientConnection.effectiveLocalDataFramePayloadSizeBytes(h2.settings.max_max_frame_size_bytes),
    );
    try std.testing.expectEqual(
        h2.settings.min_max_frame_size_bytes,
        ClientConnection.effectiveLocalDataFramePayloadSizeBytes(h2.settings.min_max_frame_size_bytes),
    );
}
