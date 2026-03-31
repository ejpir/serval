//! Native WebSocket Session API
//!
//! Owns server-side WebSocket message processing after HTTP upgrade.
//! TigerStyle: Zero allocation, caller-owned message buffers, bounded loops.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const config = serval_core.config;
const time = serval_core.time;
const types = serval_core.types;

const serval_websocket = @import("serval-websocket");
const frame = serval_websocket.frame;
const close_mod = serval_websocket.close;
const default_websocket_cfg = config.WebSocketConfig{};

/// High-level classification of a WebSocket message payload.
/// `text` messages are expected to contain valid UTF-8, while `binary` messages carry opaque bytes.
/// The kind is derived from the initial data frame opcode for the message.
pub const WebSocketMessageKind = enum {
    text,
    binary,
};

/// A complete WebSocket message returned by the session reader.
/// `kind` identifies the message opcode class, `payload` borrows the assembled bytes, and `fragmented` reports whether the message spanned multiple frames.
/// The payload slice is owned by the caller-provided buffer used during reading.
pub const WebSocketMessage = struct {
    kind: WebSocketMessageKind,
    payload: []const u8,
    fragmented: bool,
};

/// Parameters used to accept a WebSocket upgrade and configure the resulting session.
/// `subprotocol` is echoed when selected, `extra_headers` are appended to the upgrade response, and `max_message_size_bytes` and `idle_timeout_ns` constrain session behavior.
/// `auto_pong` controls whether ping control frames are answered automatically by the session.
pub const WebSocketAccept = struct {
    subprotocol: ?[]const u8 = null,
    extra_headers: []const u8 = "",
    max_message_size_bytes: u32 = default_websocket_cfg.max_message_size_bytes,
    max_fragments_per_message: u32 = default_websocket_cfg.max_fragments_per_message,
    idle_timeout_ns: u64 = default_websocket_cfg.session_idle_timeout_ns,
    close_timeout_ns: u64 = default_websocket_cfg.close_timeout_ns,
    auto_pong: bool = true,

    /// Applies server defaults from `runtime_cfg` while preserving explicit route-level overrides.
    pub fn withRuntimeDefaults(self: WebSocketAccept, runtime_cfg: config.WebSocketConfig) WebSocketAccept {
        assert(runtime_cfg.max_message_size_bytes > 0);
        assert(runtime_cfg.max_fragments_per_message > 0);

        var merged = self;
        if (merged.max_message_size_bytes == default_websocket_cfg.max_message_size_bytes) {
            merged.max_message_size_bytes = runtime_cfg.max_message_size_bytes;
        }
        if (merged.max_fragments_per_message == default_websocket_cfg.max_fragments_per_message) {
            merged.max_fragments_per_message = runtime_cfg.max_fragments_per_message;
        }
        if (merged.idle_timeout_ns == default_websocket_cfg.session_idle_timeout_ns) {
            merged.idle_timeout_ns = runtime_cfg.session_idle_timeout_ns;
        }
        if (merged.close_timeout_ns == default_websocket_cfg.close_timeout_ns) {
            merged.close_timeout_ns = runtime_cfg.close_timeout_ns;
        }
        return merged;
    }
};

/// Result of routing a WebSocket request.
/// `decline` leaves the request unhandled, `accept` carries the parameters needed to start a session, and `reject` carries an HTTP rejection response.
/// The route layer uses this to separate policy decisions from session setup.
pub const WebSocketRouteAction = union(enum) {
    decline,
    accept: WebSocketAccept,
    reject: types.RejectResponse,
};

/// Current lifecycle state of a WebSocket session.
/// `open` means normal message processing is allowed, `close_sent` means a close frame has been sent, and `closed` means the session is finished.
/// Callers should not continue message reads once the session is no longer `open`.
pub const SessionState = enum {
    open,
    close_sent,
    closed,
};

/// Per-session accounting and close-state information.
/// `bytes_received` and `bytes_sent` track payload movement, while `close_code` records the last close code seen or sent.
/// `peer_closed` indicates whether the remote side has initiated close processing.
pub const SessionStats = struct {
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    close_code: ?u16 = null,
    peer_closed: bool = false,
};

/// Transport-level I/O errors reported by the callback adapter.
/// These cover connection closure, connection reset, read and write failures, and unexpected backend conditions.
/// WebSocket code may map these into higher-level session errors.
pub const TransportError = error{
    ConnectionClosed,
    ConnectionReset,
    ReadFailed,
    WriteFailed,
    Unexpected,
};

/// Function table and context pointer used to adapt a concrete I/O backend to the WebSocket session code.
/// The callbacks must remain valid for as long as the transport value is used and must interpret `ctx` consistently.
/// `read`, `writeAll`, `getFd`, and `hasPendingRead` are thin wrappers around these callbacks.
pub const Transport = struct {
    ctx: *anyopaque,
    read_fn: *const fn (ctx: *anyopaque, buf: []u8) TransportError!u32,
    write_all_fn: *const fn (ctx: *anyopaque, data: []const u8) TransportError!void,
    get_fd_fn: *const fn (ctx: *anyopaque) i32,
    has_pending_read_fn: *const fn (ctx: *anyopaque) bool,

    /// Reads up to `buf.len` bytes from the underlying transport.
    /// `buf` must be non-empty; the call forwards to the transport callback and returns the number of bytes read.
    /// A return value of `0` is transport-defined and may indicate end-of-stream or a closed connection.
    pub fn read(self: *const Transport, buf: []u8) TransportError!u32 {
        assert(buf.len > 0);
        return self.read_fn(self.ctx, buf);
    }

    /// Writes the full `data` buffer through the underlying transport.
    /// `data` must be non-empty; the call forwards to the transport callback and may fail with a transport error.
    /// The buffer is borrowed for the duration of the call and is not retained by this API.
    pub fn writeAll(self: *const Transport, data: []const u8) TransportError!void {
        assert(data.len > 0);
        return self.write_all_fn(self.ctx, data);
    }

    /// Returns the file descriptor associated with the transport.
    /// This is a thin delegation to the transport callback.
    /// The returned descriptor is owned by the transport implementation and is not transferred.
    pub fn getFd(self: *const Transport) i32 {
        return self.get_fd_fn(self.ctx);
    }

    /// Returns whether the underlying transport reports unread input pending.
    /// This is a thin delegation to the transport callback and does not consume data.
    /// The result depends on the transport implementation and its current state.
    pub fn hasPendingRead(self: *const Transport) bool {
        return self.has_pending_read_fn(self.ctx);
    }
};

/// Errors reported by WebSocket session operations.
/// These cover protocol validation, payload limits, UTF-8 checks, connection and I/O failures, timeouts, and invalid close information.
/// Callers should treat `SessionClosed` and `ConnectionClosed` as terminal for the session.
pub const SessionError = error{
    ProtocolViolation,
    InvalidUtf8,
    MessageTooLarge,
    ConnectionClosed,
    ReadFailed,
    WriteFailed,
    Timeout,
    CloseHandshakeTimeout,
    SessionClosed,
    InvalidCloseCode,
    InvalidCloseReason,
};

/// Represents a live WebSocket session bound to a transport and accept policy.
/// `init` requires `accept.max_message_size_bytes > 0` and `accept.idle_timeout_ns > 0` and stores borrowed input slices.
/// `readMessage` only operates while the session is open; it may consume initial input and network frames, and it can fail with session, protocol, timeout, UTF-8, close-handshake, read, or write errors.
pub const WebSocketSession = struct {
    transport: Transport,
    accept: WebSocketAccept,
    selected_subprotocol: ?[]const u8,
    state_value: SessionState = .open,
    initial_input: []const u8,
    initial_offset: usize = 0,
    stats_value: SessionStats = .{},

    /// Initializes a `WebSocketSession` from the transport and negotiated accept parameters.
    /// `accept.max_message_size_bytes` and `accept.idle_timeout_ns` must both be greater than zero.
    /// The returned session stores the provided transport, accept settings, selected subprotocol, and initial input slice.
    /// This function performs no allocation and takes no ownership of the input slices.
    pub fn init(
        transport: Transport,
        accept: WebSocketAccept,
        selected_subprotocol: ?[]const u8,
        initial_input: []const u8,
    ) WebSocketSession {
        assert(accept.max_message_size_bytes > 0);
        assert(accept.max_fragments_per_message > 0);
        assert(accept.idle_timeout_ns > 0);
        assert(accept.close_timeout_ns > 0);

        return .{
            .transport = transport,
            .accept = accept,
            .selected_subprotocol = selected_subprotocol,
            .initial_input = initial_input,
        };
    }

    /// Reads the next complete WebSocket message into `buf` and returns it.
    /// `buf` must be non-empty and fit within `u32`; otherwise this function asserts.
    /// The session must be open; a closed session returns `error.SessionClosed`.
    /// Ping, pong, and close control frames are handled internally; close returns `null`.
    /// Returns `error.MessageTooLarge`, `error.ProtocolViolation`, or transport/read errors when the message cannot be completed safely.
    pub fn readMessage(self: *WebSocketSession, buf: []u8) SessionError!?WebSocketMessage {
        assert(buf.len > 0);
        assert(buf.len <= std.math.maxInt(u32));

        if (self.state_value != .open) return error.SessionClosed;

        const buf_len_u32: u32 = @intCast(buf.len);
        const message_limit_bytes: u32 = @min(buf_len_u32, self.accept.max_message_size_bytes);
        if (message_limit_bytes == 0) return error.MessageTooLarge;

        var total_len_bytes: u32 = 0;
        var fragments: u32 = 0;
        var fragmented = false;
        var message_opcode: ?frame.Opcode = null;

        while (fragments < self.accept.max_fragments_per_message) {
            const header = try self.readFrameHeader(self.accept.idle_timeout_ns);
            var control_buf: [config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;

            switch (header.opcode) {
                .ping => {
                    const payload = try self.readControlPayloadInto(
                        header,
                        self.accept.idle_timeout_ns,
                        &control_buf,
                    );
                    if (self.accept.auto_pong and self.state_value == .open) {
                        try self.sendControlFrame(.pong, payload);
                    }
                    continue;
                },
                .pong => {
                    _ = try self.readControlPayloadInto(
                        header,
                        self.accept.idle_timeout_ns,
                        &control_buf,
                    );
                    continue;
                },
                .close => {
                    const payload = try self.readControlPayloadInto(
                        header,
                        self.accept.idle_timeout_ns,
                        &control_buf,
                    );
                    try self.handlePeerClose(payload);
                    return null;
                },
                .text, .binary => {
                    if (message_opcode != null) {
                        self.abortWithClose(close_mod.protocol_error);
                        return error.ProtocolViolation;
                    }

                    fragmented = !header.fin;
                    message_opcode = header.opcode;
                    total_len_bytes = try self.readDataFragment(header, buf, total_len_bytes, message_limit_bytes, self.accept.idle_timeout_ns);
                    fragments += 1;

                    if (!header.fin) continue;
                    return try self.finishMessage(message_opcode.?, buf[0..total_len_bytes], fragmented);
                },
                .continuation => {
                    if (message_opcode == null) {
                        self.abortWithClose(close_mod.protocol_error);
                        return error.ProtocolViolation;
                    }

                    fragmented = true;
                    total_len_bytes = try self.readDataFragment(header, buf, total_len_bytes, message_limit_bytes, self.accept.idle_timeout_ns);
                    fragments += 1;

                    if (!header.fin) continue;
                    return try self.finishMessage(message_opcode.?, buf[0..total_len_bytes], fragmented);
                },
            }
        }

        self.abortWithClose(close_mod.message_too_big);
        return error.MessageTooLarge;
    }

    /// Sends `payload` as a WebSocket text frame on this session.
    /// `payload` must be valid UTF-8; otherwise this returns `error.InvalidUtf8`.
    /// The session must be in a writable state, or `ensureWritableState` returns an error.
    /// Propagates transport/frame encoding failures from the underlying send path.
    pub fn sendText(self: *WebSocketSession, payload: []const u8) SessionError!void {
        assert(payload.len <= std.math.maxInt(u32));

        if (!std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
        try self.ensureWritableState();
        try self.sendFrameRaw(.text, payload);
    }

    /// Sends a websocket binary frame with the given payload.
    /// The payload length must fit in a `u32`, matching the frame length encoding limit.
    /// The session must be writable before the frame is sent.
    /// The payload slice is borrowed for the duration of the call and is not retained.
    pub fn sendBinary(self: *WebSocketSession, payload: []const u8) SessionError!void {
        assert(payload.len <= std.math.maxInt(u32));

        try self.ensureWritableState();
        try self.sendFrameRaw(.binary, payload);
    }

    /// Sends a websocket ping control frame with the given payload.
    /// The payload length must not exceed `config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES`.
    /// The session must be in a writable state; otherwise `ensureWritableState` returns an error.
    /// The payload slice is borrowed for the duration of the call and is not retained.
    pub fn sendPing(self: *WebSocketSession, payload: []const u8) SessionError!void {
        assert(payload.len <= config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES);

        try self.ensureWritableState();
        try self.sendControlFrame(.ping, payload);
    }

    /// Sends a websocket close frame with the provided code and reason.
    /// Returns `error.SessionClosed` if the session is already closed.
    /// If a close frame has already been sent, this is a no-op.
    /// On success, the session transitions to `.close_sent` and the close code is recorded in stats.
    pub fn close(self: *WebSocketSession, code: u16, reason: []const u8) SessionError!void {
        if (self.state_value == .closed) return error.SessionClosed;
        if (self.state_value == .close_sent) return;

        var payload_buf: [config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;
        const payload = close_mod.buildClosePayload(&payload_buf, code, reason) catch |err| {
            return mapCloseBuildError(err);
        };

        try self.sendFrameRaw(.close, payload);
        self.state_value = .close_sent;
        self.stats_value.close_code = code;
    }

    /// Completes the websocket close handshake after a close frame has been sent.
    /// If the session is not in `.close_sent`, this returns immediately without changing state.
    /// The method waits until the configured close timeout, handling control frames and auto-pong replies when enabled.
    /// On protocol violation or timeout, the session is transitioned to `.closed` and an error is returned.
    pub fn finishCloseHandshake(self: *WebSocketSession) SessionError!void {
        if (self.state_value != .close_sent) return;

        const start_ns = time.monotonicNanos();
        const deadline_ns = start_ns + self.accept.close_timeout_ns;
        var control_buf: [config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;

        while (time.elapsedNanos(start_ns, time.monotonicNanos()) <= self.accept.close_timeout_ns) {
            const header = self.readFrameHeaderUntil(deadline_ns) catch |err| {
                return switch (err) {
                    error.Timeout => error.CloseHandshakeTimeout,
                    else => err,
                };
            };

            switch (header.opcode) {
                .close => {
                    const payload = try self.readControlPayloadUntil(header, deadline_ns, &control_buf);
                    const close_info = close_mod.parseClosePayload(payload) catch {
                        self.state_value = .closed;
                        return error.ProtocolViolation;
                    };
                    self.stats_value.close_code = close_info.code orelse self.stats_value.close_code;
                    self.stats_value.peer_closed = true;
                    self.state_value = .closed;
                    return;
                },
                .ping => {
                    const payload = try self.readControlPayloadUntil(header, deadline_ns, &control_buf);
                    if (self.accept.auto_pong) {
                        try self.sendControlFrame(.pong, payload);
                    }
                },
                .pong => {
                    _ = try self.readControlPayloadUntil(header, deadline_ns, &control_buf);
                },
                .text, .binary, .continuation => {
                    self.state_value = .closed;
                    return error.ProtocolViolation;
                },
            }
        }

        self.state_value = .closed;
        return error.CloseHandshakeTimeout;
    }

    /// Returns the negotiated subprotocol, if one was selected.
    /// The returned slice points into session-owned state and must not be freed by the caller.
    /// The value remains valid only while the session keeps the underlying storage alive.
    /// Returns `null` when no subprotocol was selected during the handshake.
    pub fn subprotocol(self: *const WebSocketSession) ?[]const u8 {
        return self.selected_subprotocol;
    }

    /// Returns the current websocket session state.
    /// The value is read directly from the session and does not change state.
    /// This is a cheap snapshot accessor with no allocation or I/O.
    /// Use this to inspect lifecycle transitions before calling mutating methods.
    pub fn state(self: *const WebSocketSession) SessionState {
        return self.state_value;
    }

    /// Returns the current session statistics snapshot.
    /// The returned value is read from the session's internal stats state.
    /// This does not mutate the session or allocate.
    /// The caller receives a copy of the stats structure.
    pub fn stats(self: *const WebSocketSession) SessionStats {
        return self.stats_value;
    }

    fn ensureWritableState(self: *WebSocketSession) SessionError!void {
        if (self.state_value != .open) return error.SessionClosed;
    }

    fn finishMessage(
        self: *WebSocketSession,
        opcode: frame.Opcode,
        payload: []const u8,
        fragmented: bool,
    ) SessionError!WebSocketMessage {
        assert(payload.len <= self.accept.max_message_size_bytes);

        return switch (opcode) {
            .text => blk: {
                if (!std.unicode.utf8ValidateSlice(payload)) {
                    self.abortWithClose(close_mod.invalid_frame_payload_data);
                    return error.InvalidUtf8;
                }
                break :blk .{ .kind = .text, .payload = payload, .fragmented = fragmented };
            },
            .binary => .{ .kind = .binary, .payload = payload, .fragmented = fragmented },
            .close, .ping, .pong, .continuation => unreachable,
        };
    }

    fn handlePeerClose(self: *WebSocketSession, payload: []const u8) SessionError!void {
        const close_info = close_mod.parseClosePayload(payload) catch {
            self.abortWithClose(close_mod.protocol_error);
            return error.ProtocolViolation;
        };

        self.stats_value.close_code = close_info.code;
        self.stats_value.peer_closed = true;

        if (self.state_value == .open) {
            try self.sendFrameRaw(.close, payload);
        }

        self.state_value = .closed;
    }

    fn readDataFragment(
        self: *WebSocketSession,
        header: frame.Header,
        buf: []u8,
        current_len_bytes: u32,
        max_len_bytes: u32,
        timeout_ns: u64,
    ) SessionError!u32 {
        assert(current_len_bytes <= max_len_bytes);

        const payload_len_u64 = header.payload_len;
        const remaining_u64: u64 = max_len_bytes - current_len_bytes;
        if (payload_len_u64 > remaining_u64) {
            self.abortWithClose(close_mod.message_too_big);
            return error.MessageTooLarge;
        }

        const payload_len_u32: u32 = @intCast(payload_len_u64);
        if (payload_len_u32 == 0) return current_len_bytes;

        const start: usize = @intCast(current_len_bytes);
        const end: usize = @intCast(current_len_bytes + payload_len_u32);
        try self.readExact(buf[start..end], timeout_ns);

        if (header.mask_key) |mask_key| {
            frame.applyMask(buf[start..end], mask_key);
        }

        return current_len_bytes + payload_len_u32;
    }

    fn readControlPayload(self: *WebSocketSession, header: frame.Header, timeout_ns: u64) SessionError![]const u8 {
        var control_buf: [config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;
        return self.readControlPayloadInto(header, timeout_ns, &control_buf);
    }

    fn readControlPayloadInto(
        self: *WebSocketSession,
        header: frame.Header,
        timeout_ns: u64,
        control_buf: *[config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8,
    ) SessionError![]const u8 {
        assert(header.payload_len <= config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES);

        const payload_len_u32: u32 = @intCast(header.payload_len);
        if (payload_len_u32 == 0) return control_buf[0..0];

        const payload_len: usize = @intCast(payload_len_u32);
        try self.readExact(control_buf[0..payload_len], timeout_ns);
        if (header.mask_key) |mask_key| {
            frame.applyMask(control_buf[0..payload_len], mask_key);
        }
        return control_buf[0..payload_len];
    }

    fn readControlPayloadUntil(
        self: *WebSocketSession,
        header: frame.Header,
        deadline_ns: u64,
        control_buf: *[config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8,
    ) SessionError![]const u8 {
        assert(header.payload_len <= config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES);

        const payload_len_u32: u32 = @intCast(header.payload_len);
        if (payload_len_u32 == 0) return control_buf[0..0];

        const payload_len: usize = @intCast(payload_len_u32);
        try self.readExactUntil(control_buf[0..payload_len], deadline_ns);
        if (header.mask_key) |mask_key| {
            frame.applyMask(control_buf[0..payload_len], mask_key);
        }
        return control_buf[0..payload_len];
    }

    fn readFrameHeader(self: *WebSocketSession, timeout_ns: u64) SessionError!frame.Header {
        var raw: [frame.max_header_size_bytes]u8 = undefined;
        try self.readExact(raw[0..2], timeout_ns);

        const total_len: usize = switch (raw[1] & 0x7F) {
            0...125 => @as(usize, 2) + if ((raw[1] & 0x80) != 0) @as(usize, 4) else @as(usize, 0),
            126 => @as(usize, 4) + if ((raw[1] & 0x80) != 0) @as(usize, 4) else @as(usize, 0),
            127 => @as(usize, 10) + if ((raw[1] & 0x80) != 0) @as(usize, 4) else @as(usize, 0),
            else => unreachable,
        };
        if (total_len > 2) {
            try self.readExact(raw[2..total_len], timeout_ns);
        }

        return frame.parseHeader(raw[0..total_len], .client) catch {
            self.abortWithClose(close_mod.protocol_error);
            return error.ProtocolViolation;
        };
    }

    fn readFrameHeaderUntil(self: *WebSocketSession, deadline_ns: u64) SessionError!frame.Header {
        var raw: [frame.max_header_size_bytes]u8 = undefined;
        try self.readExactUntil(raw[0..2], deadline_ns);

        const total_len: usize = switch (raw[1] & 0x7F) {
            0...125 => @as(usize, 2) + if ((raw[1] & 0x80) != 0) @as(usize, 4) else @as(usize, 0),
            126 => @as(usize, 4) + if ((raw[1] & 0x80) != 0) @as(usize, 4) else @as(usize, 0),
            127 => @as(usize, 10) + if ((raw[1] & 0x80) != 0) @as(usize, 4) else @as(usize, 0),
            else => unreachable,
        };
        if (total_len > 2) {
            try self.readExactUntil(raw[2..total_len], deadline_ns);
        }

        return frame.parseHeader(raw[0..total_len], .client) catch {
            self.state_value = .closed;
            return error.ProtocolViolation;
        };
    }

    fn readExact(self: *WebSocketSession, buf: []u8, timeout_ns: u64) SessionError!void {
        assert(buf.len > 0);
        assert(timeout_ns > 0);
        assert(buf.len <= std.math.maxInt(u32));

        var total: u32 = 0;
        const target_len: u32 = @intCast(buf.len);
        var iterations: u32 = 0;
        const max_iterations: u32 = target_len;

        while (total < target_len and iterations < max_iterations) : (iterations += 1) {
            const copied = self.copyPreread(buf[@intCast(total)..]);
            if (copied > 0) {
                total += copied;
                continue;
            }

            try self.waitReadable(timeout_ns);
            const n = self.transport.read(buf[@intCast(total)..]) catch |err| {
                const mapped = mapReadTransportError(err);
                if (mapped == error.ConnectionClosed) {
                    self.state_value = .closed;
                }
                return mapped;
            };
            if (n == 0) {
                self.state_value = .closed;
                return error.ConnectionClosed;
            }

            total += n;
            self.stats_value.bytes_received += n;
        }

        if (total < target_len) return error.ReadFailed;
    }

    fn readExactUntil(self: *WebSocketSession, buf: []u8, deadline_ns: u64) SessionError!void {
        assert(buf.len > 0);
        assert(buf.len <= std.math.maxInt(u32));

        var total: u32 = 0;
        const target_len: u32 = @intCast(buf.len);
        var iterations: u32 = 0;
        const max_iterations: u32 = target_len;

        while (total < target_len and iterations < max_iterations) : (iterations += 1) {
            const copied = self.copyPreread(buf[@intCast(total)..]);
            if (copied > 0) {
                total += copied;
                continue;
            }

            const now_ns = time.monotonicNanos();
            if (now_ns >= deadline_ns) return error.Timeout;
            try self.waitReadable(deadline_ns - now_ns);

            const n = self.transport.read(buf[@intCast(total)..]) catch |err| {
                const mapped = mapReadTransportError(err);
                if (mapped == error.ConnectionClosed) {
                    self.state_value = .closed;
                }
                return mapped;
            };
            if (n == 0) {
                self.state_value = .closed;
                return error.ConnectionClosed;
            }

            total += n;
            self.stats_value.bytes_received += n;
        }

        if (total < target_len) return error.ReadFailed;
    }

    fn copyPreread(self: *WebSocketSession, out: []u8) u32 {
        assert(out.len > 0);

        const remaining = self.initial_input.len - self.initial_offset;
        if (remaining == 0) return 0;

        const copy_len: usize = @min(out.len, remaining);
        @memcpy(out[0..copy_len], self.initial_input[self.initial_offset..][0..copy_len]);
        self.initial_offset += copy_len;
        const copied: u32 = @intCast(copy_len);
        self.stats_value.bytes_received += copied;
        return copied;
    }

    fn waitReadable(self: *WebSocketSession, timeout_ns: u64) SessionError!void {
        assert(timeout_ns > 0);

        if (self.initial_offset < self.initial_input.len) return;
        if (self.transport.hasPendingRead()) return;

        const fd = self.transport.getFd();
        if (fd < 0) return error.ReadFailed;

        const poll_interval_ms_u64: u64 = @intCast(config.WEBSOCKET_SESSION_POLL_TIMEOUT_MS);
        const poll_interval_ns: u64 = time.millisToNanos(poll_interval_ms_u64);
        const max_iterations_u64 = @max(@as(u64, 1), (timeout_ns / poll_interval_ns) + 2);
        const max_iterations: u32 = if (max_iterations_u64 > std.math.maxInt(u32))
            std.math.maxInt(u32)
        else
            @intCast(max_iterations_u64);

        const start_ns = time.monotonicNanos();
        var iterations: u32 = 0;
        while (iterations < max_iterations) : (iterations += 1) {
            if (self.transport.hasPendingRead()) return;

            const now_ns = time.monotonicNanos();
            const elapsed_ns = time.elapsedNanos(start_ns, now_ns);
            if (elapsed_ns >= timeout_ns) return error.Timeout;

            const remaining_ns = timeout_ns - elapsed_ns;
            const timeout_ms = computePollTimeoutMs(remaining_ns);
            var poll_fds = [_]std.posix.pollfd{
                .{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 },
            };

            const ready = std.posix.poll(&poll_fds, timeout_ms) catch {
                return error.ReadFailed;
            };
            if (ready == 0) continue;
            if (wantsRead(poll_fds[0].revents)) return;
        }

        return error.Timeout;
    }

    fn sendControlFrame(self: *WebSocketSession, opcode: frame.Opcode, payload: []const u8) SessionError!void {
        assert(frame.isControlOpcode(opcode));
        if (payload.len > config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES) {
            return error.MessageTooLarge;
        }
        try self.sendFrameRaw(opcode, payload);
    }

    fn sendFrameRaw(self: *WebSocketSession, opcode: frame.Opcode, payload: []const u8) SessionError!void {
        assert(payload.len <= std.math.maxInt(u32));

        var header_buf: [frame.max_header_size_bytes]u8 = undefined;
        const header = frame.buildHeader(&header_buf, .{
            .opcode = opcode,
            .payload_len = payload.len,
        }) orelse return error.WriteFailed;

        try self.writeAllTracked(header);
        if (payload.len > 0) {
            try self.writeAllTracked(payload);
        }
    }

    fn writeAllTracked(self: *WebSocketSession, data: []const u8) SessionError!void {
        assert(data.len > 0);
        assert(data.len <= std.math.maxInt(u32));

        self.transport.writeAll(data) catch |err| {
            return mapWriteTransportError(err);
        };
        self.stats_value.bytes_sent += data.len;
    }

    fn abortWithClose(self: *WebSocketSession, close_code: u16) void {
        if (self.state_value == .closed) return;

        var payload_buf: [config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;
        const payload = close_mod.buildClosePayload(&payload_buf, close_code, "") catch |err| switch (err) {
            error.InvalidCloseCode,
            error.InvalidCloseReason,
            error.PayloadTooLarge,
            error.BufferTooSmall,
            error.InvalidClosePayload,
            => {
                self.state_value = .closed;
                return;
            },
        };

        self.sendFrameRaw(.close, payload) catch |err| switch (err) {
            error.ProtocolViolation,
            error.InvalidUtf8,
            error.MessageTooLarge,
            error.ConnectionClosed,
            error.ReadFailed,
            error.WriteFailed,
            error.Timeout,
            error.CloseHandshakeTimeout,
            error.SessionClosed,
            error.InvalidCloseCode,
            error.InvalidCloseReason,
            => {},
        };

        self.stats_value.close_code = close_code;
        self.state_value = .closed;
    }
};

fn mapCloseBuildError(err: close_mod.CloseError) SessionError {
    return switch (err) {
        error.InvalidCloseCode => error.InvalidCloseCode,
        error.InvalidCloseReason => error.InvalidCloseReason,
        error.PayloadTooLarge => error.MessageTooLarge,
        error.BufferTooSmall => error.WriteFailed,
        error.InvalidClosePayload => error.ProtocolViolation,
    };
}

fn mapReadTransportError(err: TransportError) SessionError {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionReset,
        => error.ConnectionClosed,
        error.ReadFailed,
        error.Unexpected,
        => error.ReadFailed,
        error.WriteFailed => error.ReadFailed,
    };
}

fn mapWriteTransportError(err: TransportError) SessionError {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionReset,
        => error.ConnectionClosed,
        error.WriteFailed,
        error.Unexpected,
        => error.WriteFailed,
        error.ReadFailed => error.WriteFailed,
    };
}

fn computePollTimeoutMs(remaining_ns: u64) i32 {
    const remaining_ms_u64 = time.nanosToMillis(remaining_ns);
    const clamped_ms_u64 = @min(@as(u64, @intCast(config.WEBSOCKET_SESSION_POLL_TIMEOUT_MS)), remaining_ms_u64);
    if (clamped_ms_u64 == 0) return 1;
    return @intCast(@min(clamped_ms_u64, @as(u64, std.math.maxInt(i32))));
}

fn wantsRead(revents: i16) bool {
    return (revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0;
}

const MockTransportContext = struct {
    input: []const u8,
    input_offset: usize = 0,
    output: [4096]u8 = std.mem.zeroes([4096]u8),
    output_len: usize = 0,
    max_read_size: u8 = 255,

    fn read(ctx_ptr: *anyopaque, buf: []u8) TransportError!u32 {
        const ctx: *MockTransportContext = @ptrCast(@alignCast(ctx_ptr));
        if (ctx.input_offset >= ctx.input.len) return error.ConnectionClosed;

        const remaining = ctx.input.len - ctx.input_offset;
        const read_len: usize = @min(@min(buf.len, remaining), ctx.max_read_size);
        @memcpy(buf[0..read_len], ctx.input[ctx.input_offset..][0..read_len]);
        ctx.input_offset += read_len;
        return @intCast(read_len);
    }

    fn writeAll(ctx_ptr: *anyopaque, data: []const u8) TransportError!void {
        const ctx: *MockTransportContext = @ptrCast(@alignCast(ctx_ptr));
        if (ctx.output_len + data.len > ctx.output.len) return error.WriteFailed;
        @memcpy(ctx.output[ctx.output_len..][0..data.len], data);
        ctx.output_len += data.len;
    }

    fn getFd(ctx_ptr: *anyopaque) i32 {
        _ = ctx_ptr;
        return 0;
    }

    fn hasPendingRead(ctx_ptr: *anyopaque) bool {
        const ctx: *MockTransportContext = @ptrCast(@alignCast(ctx_ptr));
        return ctx.input_offset < ctx.input.len;
    }

    fn transport(self: *MockTransportContext) Transport {
        return .{
            .ctx = @ptrCast(self),
            .read_fn = &read,
            .write_all_fn = &writeAll,
            .get_fd_fn = &getFd,
            .has_pending_read_fn = &hasPendingRead,
        };
    }
};

fn buildMaskedClientFrame(
    opcode: frame.Opcode,
    fin: bool,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    var header_buf: [frame.max_header_size_bytes]u8 = undefined;
    const mask_key = [4]u8{ 0x37, 0xFA, 0x21, 0x3D };
    const header = frame.buildHeader(&header_buf, .{
        .fin = fin,
        .opcode = opcode,
        .payload_len = payload.len,
        .mask_key = mask_key,
    }).?;

    if (out.len < header.len + payload.len) return error.BufferTooSmall;
    @memcpy(out[0..header.len], header);
    @memcpy(out[header.len..][0..payload.len], payload);
    frame.applyMask(out[header.len .. header.len + payload.len], mask_key);
    return out[0 .. header.len + payload.len];
}

test "WebSocketSession readMessage reassembles fragmented text with interleaved ping" {
    var input: [256]u8 = undefined;
    const part1 = try buildMaskedClientFrame(.text, false, "hel", input[0..]);
    const ping = try buildMaskedClientFrame(.ping, true, "!", input[part1.len..]);
    const part2 = try buildMaskedClientFrame(.continuation, true, "lo", input[part1.len + ping.len ..]);
    const total_len = part1.len + ping.len + part2.len;

    var mock = MockTransportContext{ .input = input[0..total_len] };
    var session = WebSocketSession.init(mock.transport(), .{}, null, &[_]u8{});

    var msg_buf: [32]u8 = undefined;
    const message = (try session.readMessage(&msg_buf)).?;

    try std.testing.expectEqual(WebSocketMessageKind.text, message.kind);
    try std.testing.expect(message.fragmented);
    try std.testing.expectEqualStrings("hello", message.payload);
    try std.testing.expect(mock.output_len > 0); // auto-pong sent
}

test "WebSocketSession readMessage returns binary message" {
    var input: [128]u8 = undefined;
    const frame_bytes = try buildMaskedClientFrame(.binary, true, "\x01\x02\x03", &input);

    var mock = MockTransportContext{ .input = frame_bytes };
    var session = WebSocketSession.init(mock.transport(), .{}, null, &[_]u8{});

    var msg_buf: [32]u8 = undefined;
    const message = (try session.readMessage(&msg_buf)).?;

    try std.testing.expectEqual(WebSocketMessageKind.binary, message.kind);
    try std.testing.expectEqual(@as(usize, 3), message.payload.len);
    try std.testing.expectEqual(@as(u8, 0x01), message.payload[0]);
}

test "WebSocketSession readMessage rejects invalid UTF-8 text payload" {
    var input: [128]u8 = undefined;
    const frame_bytes = try buildMaskedClientFrame(.text, true, "\xFF", &input);

    var mock = MockTransportContext{ .input = frame_bytes };
    var session = WebSocketSession.init(mock.transport(), .{}, null, &[_]u8{});

    var msg_buf: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidUtf8, session.readMessage(&msg_buf));
    try std.testing.expectEqual(SessionState.closed, session.state());
}

test "WebSocketSession readMessage rejects oversized message" {
    var payload: [8]u8 = .{ 't', 'o', 'o', '-', 'b', 'i', 'g', '!' };
    var input: [128]u8 = undefined;
    const frame_bytes = try buildMaskedClientFrame(.text, true, &payload, &input);

    var mock = MockTransportContext{ .input = frame_bytes };
    var session = WebSocketSession.init(mock.transport(), .{ .max_message_size_bytes = 4 }, null, &[_]u8{});

    var msg_buf: [32]u8 = undefined;
    try std.testing.expectError(error.MessageTooLarge, session.readMessage(&msg_buf));
}

test "WebSocketSession sendText writes unmasked server frame" {
    var mock = MockTransportContext{ .input = &[_]u8{} };
    var session = WebSocketSession.init(mock.transport(), .{}, "chat", &[_]u8{});

    try session.sendText("hello");

    try std.testing.expectEqual(@as(u8, 0x81), mock.output[0]);
    try std.testing.expectEqual(@as(u8, 0x05), mock.output[1]);
    try std.testing.expectEqualStrings("hello", mock.output[2..7]);
    try std.testing.expectEqualStrings("chat", session.subprotocol().?);
}

test "WebSocketSession peer close returns null and sends mirrored close" {
    var payload_buf: [config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;
    const close_payload = try close_mod.buildClosePayload(&payload_buf, close_mod.normal_closure, "bye");

    var input: [128]u8 = undefined;
    const frame_bytes = try buildMaskedClientFrame(.close, true, close_payload, &input);

    var mock = MockTransportContext{ .input = frame_bytes };
    var session = WebSocketSession.init(mock.transport(), .{}, null, &[_]u8{});

    var msg_buf: [32]u8 = undefined;
    const result = try session.readMessage(&msg_buf);

    try std.testing.expectEqual(@as(?WebSocketMessage, null), result);
    try std.testing.expectEqual(SessionState.closed, session.state());
    try std.testing.expect(mock.output_len > 0);
}
