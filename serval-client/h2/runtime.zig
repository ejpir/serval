//! HTTP/2 Client Runtime Primitives
//!
//! Bounded outbound per-frame runtime for prior-knowledge h2c upstream sessions.
//! This file does not own sockets; it validates frame sequencing, updates
//! connection state, and exposes explicit actions for higher-level clients.
//! TigerStyle: Explicit state transitions, fixed buffers, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;
const log = @import("serval-core").log.scoped(.client_h2_runtime);
const types = @import("serval-core").types;
const h2 = @import("serval-h2");
const session = @import("session.zig");

const Method = types.Method;
const Request = types.Request;
const Response = types.Response;
const Header = types.Header;
const HeaderMap = types.HeaderMap;

/// Errors returned by the HTTP/2 runtime when validating frames, headers, and stream state.
/// These cases cover missing required pseudo-headers, invalid or duplicate header fields,
/// stream/type mismatches, and unsupported protocol features such as padding, priority,
/// push promises, and continuation sequences.
/// Callers should treat these as protocol- or state-level failures; no ownership is involved.
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

/// Encoded request headers returned by `writeRequestHeadersFrame`.
/// `stream_id` is the newly opened request stream used for the outbound HEADERS sequence.
/// `frame` aliases the caller-provided output buffer and contains the complete HEADERS/CONTINUATION byte sequence.
pub const RequestHeadersWrite = struct {
    stream_id: u32,
    frame: []const u8,
};

/// Decoded response HEADERS for an active response stream.
/// `response` carries the parsed status and header map for the response.
/// `end_stream` reports whether the peer closed the stream on this HEADERS frame.
pub const ResponseHeadersAction = struct {
    stream_id: u32,
    end_stream: bool,
    response: Response,
};

/// Decoded DATA received for an active response stream.
/// `payload` aliases the frame payload slice supplied to `receiveFrame`; callers must copy it if they need to retain it.
/// `end_stream` reports whether this frame closed the remote side of the stream.
pub const ResponseDataAction = struct {
    stream_id: u32,
    end_stream: bool,
    payload: []const u8,
};

/// Decoded trailers received at the end of a response stream.
/// `stream_id` identifies the response stream the trailers belong to.
/// `trailers` contains the decoded header map and owns no external storage.
pub const ResponseTrailersAction = struct {
    stream_id: u32,
    trailers: HeaderMap,
};

/// Describes a peer-initiated or locally generated stream reset.
/// `stream_id` identifies the affected stream, and `error_code_raw` preserves the raw 32-bit HTTP/2 error code.
/// The raw error code is kept so higher layers can map it without losing information.
pub const StreamResetAction = struct {
    stream_id: u32,
    error_code_raw: u32,
};

/// Result of feeding a peer frame into `receiveFrame`.
/// Variants either report that no outbound frame is needed or carry the exact action needed to continue the HTTP/2 exchange.
/// The response variants surface decoded headers, data, trailers, stream resets, and connection shutdown notifications.
/// `send_ping_ack` preserves the received 8-byte opaque payload so the caller can echo it back verbatim.
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
};

/// Public HTTP/2 client runtime state for prior-knowledge upstream sessions.
/// The runtime does not own sockets; it tracks session flow control, stream bookkeeping, and HPACK decoding state.
/// Use `init()` to create a fresh instance before sending or receiving frames.
/// Public methods on this type expose explicit frame-building and frame-receive actions.
pub const Runtime = struct {
    runtime_cfg: config.H2Config,
    state: session.SessionState,
    header_decoder: h2.HpackDecoder = h2.HpackDecoder.init(),
    response_fields_storage: []h2.HeaderField,
    response_states: ResponseStateTable = .{},
    pending_response_headers: PendingResponseHeaders = .{},

    /// Initializes caller-owned runtime storage in place with a fresh session state, HPACK decoder,
    /// and caller-owned bounded response/trailer decode scratch.
    /// The configuration must provide a positive connection window and header block capacity,
    /// and `response_fields_storage` must have room for `config.MAX_HEADERS` decoded fields.
    /// Returns any error raised while initializing the underlying session state.
    pub fn initInto(self: *Runtime, runtime_cfg: config.H2Config, response_fields_storage: []h2.HeaderField) Error!void {
        assert(runtime_cfg.connection_window_size_bytes > 0);
        assert(runtime_cfg.max_header_block_size_bytes > 0);
        assert(runtime_cfg.max_frame_size_bytes <= h2.frame_payload_capacity_bytes);
        assert(runtime_cfg.max_header_block_size_bytes <= h2.header_block_capacity_bytes);
        assert(response_fields_storage.len >= config.MAX_HEADERS);
        assert(@intFromPtr(self) != 0);
        self.runtime_cfg = runtime_cfg;
        self.state = try session.SessionState.init(runtime_cfg);
        self.header_decoder = h2.HpackDecoder.init();
        self.response_fields_storage = response_fields_storage;
        self.response_states = .{};
        self.pending_response_headers = .{};
    }

    /// Writes the HTTP/2 client connection preface followed by the local SETTINGS frame.
    /// `out` must hold the preface plus one frame header and the encoded SETTINGS payload.
    /// This also marks the runtime preface as sent so later inbound frames can be validated against connection state.
    /// The returned slice aliases `out` and ends exactly after the SETTINGS payload.
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

    /// Encodes a SETTINGS acknowledgement for a pending peer SETTINGS frame.
    /// Callers must only use this after `peer_settings_ack_pending` has been set by the runtime.
    /// The returned slice aliases `out`, and the runtime marks the peer SETTINGS ACK as sent before returning.
    pub fn writePendingSettingsAck(self: *Runtime, out: []u8) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.state.peer_settings_ack_pending);

        const frame = try h2.buildSettingsAckFrame(out);
        self.state.markPeerSettingsAckSent();
        return frame;
    }

    /// Builds an ACK PING frame from the 8-byte opaque payload received from the peer.
    /// `out` must have room for the HTTP/2 frame header and the fixed ping payload size.
    /// The returned slice aliases `out` and carries the ACK flag set.
    pub fn writePingAckFrame(out: []u8, opaque_data: [h2.control.ping_payload_size_bytes]u8) Error![]const u8 {
        assert(out.len >= h2.frame_header_size_bytes + h2.control.ping_payload_size_bytes);
        assert(h2.control.ping_payload_size_bytes == 8);
        return try h2.buildPingFrame(out, h2.flags_ack, opaque_data);
    }

    /// Encodes an RST_STREAM frame for the given stream and removes any matching local response state.
    /// `reset.stream_id` must be nonzero; missing stream state is tolerated when the runtime is already past that stream.
    /// Only `error.StreamNotFound` from the stream reset path is ignored; other session errors are returned to the caller.
    /// The returned slice aliases `out`.
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

    /// Encodes a GOAWAY frame and records that the connection is shutting down for streams above `last_stream_id`.
    /// `goaway.last_stream_id` must fit in the HTTP/2 31-bit stream-id range.
    /// The returned slice aliases `out`; the `debug_data` slice is forwarded unchanged into the frame payload.
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

    /// Encodes request HEADERS for a new outbound stream and returns the stream id with the encoded frame bytes.
    /// `request.path` must be non-empty; `effective_path`, when present, overrides it, and a `host` header is required to form `:authority`.
    /// The header block is HPACK-encoded into a fixed caller buffer and may be split into CONTINUATION frames when it exceeds the negotiated payload size.
    /// The returned frame slice aliases `out`, and the stream is opened in session state before serialization completes.
    pub fn writeRequestHeadersFrame(
        self: *Runtime,
        out: []u8,
        header_block_storage: []u8,
        request: *const Request,
        effective_path: ?[]const u8,
        end_stream: bool,
    ) Error!RequestHeadersWrite {
        assert(@intFromPtr(self) != 0);
        assert(request.path.len > 0);
        assert(out.len >= h2.frame_header_size_bytes);
        assert(self.runtime_cfg.max_header_block_size_bytes <= header_block_storage.len);
        assert(header_block_storage.len <= h2.header_block_capacity_bytes);

        const path = effective_path orelse request.path;
        assert(path.len > 0);
        const authority = request.headers.getHost() orelse return error.MissingAuthority;

        const header_block = try buildRequestHeaderBlock(request, path, authority, header_block_storage);

        const stream = try self.state.openRequestStream(end_stream);
        const peer_max_frame_size_bytes: usize = @intCast(self.state.peer_settings.max_frame_size_bytes);
        const max_payload_size_bytes: usize = @min(@as(usize, self.runtime_cfg.max_frame_size_bytes), peer_max_frame_size_bytes);
        const frame = try appendHeaderBlockFrames(
            out,
            stream.id,
            header_block,
            end_stream,
            max_payload_size_bytes,
        );

        return .{
            .stream_id = stream.id,
            .frame = frame,
        };
    }

    /// Encodes one outbound DATA frame for an existing local stream into `out`.
    /// The stream must exist and still be allowed to send; non-empty payloads consume
    /// both the connection send window and the stream send window before serialization.
    /// The returned slice aliases `out`; `error.StreamNotFound`, `error.InvalidDataStream`, and `error.FrameTooLarge` cover the main failure cases.
    pub fn writeRequestDataFrame(
        self: *Runtime,
        out: []u8,
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
    ) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const stream = self.state.getStream(stream_id) orelse {
            log.warn(
                "client h2 runtime: missing stream in writeRequestDataFrame stream={d} active={d} last_local={d} last_remote={d} payload={d} end_stream={any}",
                .{
                    stream_id,
                    self.state.streams.active_count,
                    self.state.streams.last_local_stream_id,
                    self.state.streams.last_remote_stream_id,
                    payload.len,
                    end_stream,
                },
            );
            return error.StreamNotFound;
        };
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

    /// Processes one received HTTP/2 frame and updates runtime state.
    /// `pending_response_headers_storage` is caller-owned scratch space used to
    /// assemble HEADERS/CONTINUATION fragments for a single in-flight response
    /// header block.
    /// `payload.len` must match `header.length`, and the connection must already have
    /// sent the client preface; non-SETTINGS frames before peer settings raise `error.MissingInitialSettings`.
    /// Returns a `ReceiveAction` for peer events that require an outbound response, or an error for unsupported or invalid frame sequencing.
    pub fn receiveFrame(
        self: *Runtime,
        pending_response_headers_storage: []u8,
        header: h2.FrameHeader,
        payload: []const u8,
    ) Error!ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(header.length == payload.len);
        assert(self.runtime_cfg.max_header_block_size_bytes <= pending_response_headers_storage.len);
        assert(pending_response_headers_storage.len <= h2.header_block_capacity_bytes);

        try ensureConnectionReady(self, header.frame_type);

        if (self.pending_response_headers.active and header.frame_type != .continuation) {
            return error.UnsupportedContinuation;
        }

        return switch (header.frame_type) {
            .settings => try handleSettings(self, header, payload),
            .headers => try handleHeaders(self, pending_response_headers_storage, header, payload),
            .data => try handleData(self, header, payload),
            .ping => try handlePing(header, payload),
            .window_update => try handleWindowUpdate(self, header, payload),
            .rst_stream => try handleRstStream(self, header, payload),
            .goaway => try handleGoAway(self, header, payload),
            .continuation => try handleContinuation(self, pending_response_headers_storage, header, payload),
            .priority => error.UnsupportedPriority,
            .push_promise => error.UnsupportedPushPromise,
            .extension => .none,
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
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) continue;
            if (slot.state.stream_id == stream_id) return &self.slots[index].state;
        }
        return null;
    }

    fn getOrInsert(self: *ResponseStateTable, stream_id: u32) Error!*ResponseState {
        assert(@intFromPtr(self) != 0);
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
        assert(@intFromPtr(self) != 0);
        assert(self.count <= config.H2_MAX_CONCURRENT_STREAMS);
        if (self.count >= config.H2_MAX_CONCURRENT_STREAMS) return null;

        for (self.slots, 0..) |slot, index| {
            if (!slot.used) return index;
        }
        return null;
    }
};

fn ensureConnectionReady(self: *const Runtime, frame_type: h2.FrameType) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(@intFromEnum(frame_type) <= @intFromEnum(h2.FrameType.extension));

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

fn handleHeaders(
    self: *Runtime,
    pending_response_headers_storage: []u8,
    header: h2.FrameHeader,
    payload: []const u8,
) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .headers);

    if (header.stream_id == 0) return error.InvalidHeadersStream;
    if ((header.flags & h2.flags_padded) != 0) return error.UnsupportedPadding;
    if ((header.flags & h2.flags_priority) != 0) return error.UnsupportedPriority;

    const stream = self.state.getStream(header.stream_id) orelse {
        log.warn(
            "client h2 runtime: missing stream in response HEADERS stream={d} active={d} last_local={d} last_remote={d} flags=0x{x}",
            .{
                header.stream_id,
                self.state.streams.active_count,
                self.state.streams.last_local_stream_id,
                self.state.streams.last_remote_stream_id,
                header.flags,
            },
        );
        return error.StreamNotFound;
    };
    if (!stream.remoteCanSend()) return error.InvalidHeadersStream;

    const end_stream = (header.flags & h2.flags_end_stream) != 0;
    const state_entry = try self.response_states.getOrInsert(header.stream_id);

    if (!state_entry.headers_received) {
        if ((header.flags & h2.flags_end_headers) == 0) {
            try startResponseHeaderContinuation(self, pending_response_headers_storage, header.stream_id, end_stream, false, payload);
            return .none;
        }

        const response = try decodeResponseHeaderBlock(self, payload);
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
        try startResponseHeaderContinuation(self, pending_response_headers_storage, header.stream_id, true, true, payload);
        return .none;
    }

    const trailers = try decodeTrailerHeaderBlock(self, payload);
    try self.state.endRemoteStream(header.stream_id);
    self.response_states.remove(header.stream_id);
    return .{ .response_trailers = .{ .stream_id = header.stream_id, .trailers = trailers } };
}

fn handleContinuation(
    self: *Runtime,
    pending_response_headers_storage: []u8,
    header: h2.FrameHeader,
    payload: []const u8,
) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .continuation);
    assert(header.length == payload.len);

    if (!self.pending_response_headers.active) return error.UnexpectedContinuation;
    if (header.stream_id != self.pending_response_headers.stream_id) return error.ContinuationStreamMismatch;
    if ((header.flags & ~(h2.flags_end_headers)) != 0) return error.UnsupportedContinuation;

    if (self.pending_response_headers.continuation_frames >= h2.max_continuation_frames) {
        return error.TooManyContinuationFrames;
    }
    self.pending_response_headers.continuation_frames += 1;

    try appendPendingResponseHeaderFragment(self, pending_response_headers_storage, payload);

    if ((header.flags & h2.flags_end_headers) == 0) return .none;
    return try finishPendingResponseHeaders(self, pending_response_headers_storage);
}

fn startResponseHeaderContinuation(
    self: *Runtime,
    pending_response_headers_storage: []u8,
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

    try appendPendingResponseHeaderFragment(self, pending_response_headers_storage, payload);
}

fn appendPendingResponseHeaderFragment(
    self: *Runtime,
    pending_response_headers_storage: []u8,
    payload: []const u8,
) Error!void {
    assert(@intFromPtr(self) != 0);
    assert(self.pending_response_headers.active);

    const current_len: usize = @intCast(self.pending_response_headers.block_len);
    if (current_len + payload.len > pending_response_headers_storage.len) return error.HeaderBlockTooLarge;

    @memcpy(
        pending_response_headers_storage[current_len .. current_len + payload.len],
        payload,
    );
    self.pending_response_headers.block_len = @intCast(current_len + payload.len);
}

fn finishPendingResponseHeaders(
    self: *Runtime,
    pending_response_headers_storage: []const u8,
) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(self.pending_response_headers.active);

    const stream_id = self.pending_response_headers.stream_id;
    const end_stream = self.pending_response_headers.end_stream;
    const is_trailers = self.pending_response_headers.is_trailers;
    const block_len: usize = @intCast(self.pending_response_headers.block_len);
    errdefer resetPendingResponseHeaders(self);

    const block = pending_response_headers_storage[0..block_len];
    if (is_trailers) {
        const trailers = try decodeTrailerHeaderBlock(self, block);
        try self.state.endRemoteStream(stream_id);
        self.response_states.remove(stream_id);
        resetPendingResponseHeaders(self);
        return .{ .response_trailers = .{
            .stream_id = stream_id,
            .trailers = trailers,
        } };
    }

    const response = try decodeResponseHeaderBlock(self, block);
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
    assert(self.pending_response_headers.block_len <= h2.header_block_capacity_bytes);

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

    const stream = self.state.getStream(header.stream_id) orelse {
        log.warn(
            "client h2 runtime: missing stream in response DATA stream={d} active={d} last_local={d} last_remote={d} flags=0x{x} len={d}",
            .{
                header.stream_id,
                self.state.streams.active_count,
                self.state.streams.last_local_stream_id,
                self.state.streams.last_remote_stream_id,
                header.flags,
                header.length,
            },
        );
        return error.StreamNotFound;
    };
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
    assert(header.length == payload.len);

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
        self.state.incrementStreamSendWindow(header.stream_id, increment) catch |err| switch (err) {
            error.StreamNotFound => {
                log.warn(
                    "client h2 runtime: missing stream in WINDOW_UPDATE stream={d} active={d} last_local={d} last_remote={d} increment={d}",
                    .{
                        header.stream_id,
                        self.state.streams.active_count,
                        self.state.streams.last_local_stream_id,
                        self.state.streams.last_remote_stream_id,
                        increment,
                    },
                );
                if (header.stream_id > self.state.streams.last_remote_stream_id) {
                    return error.InvalidStreamId;
                }
                return .none;
            },
            else => return err,
        };
    }

    return .none;
}

fn handleRstStream(self: *Runtime, header: h2.FrameHeader, payload: []const u8) Error!ReceiveAction {
    assert(@intFromPtr(self) != 0);
    assert(header.frame_type == .rst_stream);

    const error_code_raw = try h2.parseRstStreamFrame(header, payload);
    self.state.resetStream(header.stream_id) catch |err| switch (err) {
        error.StreamNotFound => {
            if (header.stream_id > self.state.streams.last_local_stream_id and
                header.stream_id > self.state.streams.last_remote_stream_id)
            {
                log.warn(
                    "client h2 runtime: missing unknown stream in RST_STREAM stream={d} active={d} last_local={d} last_remote={d} error_code_raw={d}",
                    .{
                        header.stream_id,
                        self.state.streams.active_count,
                        self.state.streams.last_local_stream_id,
                        self.state.streams.last_remote_stream_id,
                        error_code_raw,
                    },
                );
                return error.InvalidStreamId;
            }

            log.debug(
                "client h2 runtime: ignoring duplicate/late RST_STREAM for retired stream={d} active={d} last_local={d} last_remote={d} error_code_raw={d}",
                .{
                    header.stream_id,
                    self.state.streams.active_count,
                    self.state.streams.last_local_stream_id,
                    self.state.streams.last_remote_stream_id,
                    error_code_raw,
                },
            );
            return .none;
        },
        else => return err,
    };
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
    assert(local_settings.max_frame_size_bytes >= h2.settings.min_max_frame_size_bytes);
    assert(local_settings.max_frame_size_bytes <= h2.frame_payload_capacity_bytes);

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
    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":scheme", requestScheme(request))).len;
    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":authority", authority)).len;

    for (request.headers.headers[0..request.headers.count]) |header| {
        if (skipRequestHeaderForH2(header.name, header.value)) continue;

        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value);
        cursor += encoded.len;

        if (cursor > h2.header_block_capacity_bytes) return error.HeaderBlockTooLarge;
    }

    return out[0..cursor];
}

fn skipRequestHeaderForH2(name: []const u8, value: []const u8) bool {
    assert(name.len <= config.MAX_HEADER_SIZE_BYTES);
    assert(value.len <= config.MAX_HEADER_SIZE_BYTES);

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
    const trimmed = std.mem.trim(u8, value, " \t");
    assert(trimmed.len <= value.len);
    const trimmed_ptr: usize = @intFromPtr(trimmed.ptr);
    const value_ptr: usize = @intFromPtr(value.ptr);
    assert(trimmed_ptr >= value_ptr and trimmed_ptr <= value_ptr + value.len);
    return trimmed;
}

fn requestScheme(request: *const Request) []const u8 {
    assert(@intFromPtr(request) != 0);
    assert(request.path.len > 0);

    if (request.headers.get("x-forwarded-proto")) |proto| {
        const trimmed = trimAsciiWhitespace(proto);
        if (std.ascii.eqlIgnoreCase(trimmed, "https")) return "https";
    }
    return "http";
}

fn methodToken(method: Method) []const u8 {
    assert(@intFromEnum(method) <= @intFromEnum(Method.PATCH));
    const token = switch (method) {
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
    assert(token.len > 0);
    return token;
}

fn decodeResponseHeaderBlock(self: *Runtime, header_block: []const u8) Error!Response {
    assert(@intFromPtr(self) != 0);
    assert(header_block.len <= h2.header_block_capacity_bytes);
    assert(self.response_fields_storage.len >= config.MAX_HEADERS);

    const fields = try h2.decodeHeaderBlockWithDecoder(
        &self.header_decoder,
        header_block,
        self.response_fields_storage,
    );

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

fn decodeTrailerHeaderBlock(self: *Runtime, header_block: []const u8) Error!HeaderMap {
    assert(@intFromPtr(self) != 0);
    assert(header_block.len <= h2.header_block_capacity_bytes);
    assert(self.response_fields_storage.len >= config.MAX_HEADERS);

    const fields = try h2.decodeHeaderBlockWithDecoder(
        &self.header_decoder,
        header_block,
        self.response_fields_storage,
    );

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
    assert(token.len > 0);
    assert(token.len <= 3);
    if (token.len != 3) return error.InvalidStatus;

    const status = std.fmt.parseUnsigned(u16, token, 10) catch {
        return error.InvalidStatus;
    };
    if (status < 100 or status > 599) return error.InvalidStatus;
    return status;
}

fn appendHeaderBlockFrames(
    out: []u8,
    stream_id: u32,
    header_block: []const u8,
    end_stream: bool,
    max_payload_size_bytes: usize,
) Error![]const u8 {
    assert(stream_id > 0);
    assert(max_payload_size_bytes > 0);

    var cursor: usize = 0;
    var block_cursor: usize = 0;

    const first_chunk_len: usize = @min(header_block.len, max_payload_size_bytes);
    const first_end_headers = first_chunk_len == header_block.len;
    const first_flags: u8 =
        (if (first_end_headers) h2.flags_end_headers else 0) |
        (if (end_stream) h2.flags_end_stream else 0);

    const first_frame_len: usize = h2.frame_header_size_bytes + first_chunk_len;
    if (cursor + first_frame_len > out.len) return error.HeaderBlockTooLarge;
    _ = try appendFrame(
        out[cursor .. cursor + first_frame_len],
        .headers,
        first_flags,
        stream_id,
        header_block[0..first_chunk_len],
    );
    cursor += first_frame_len;
    block_cursor = first_chunk_len;

    var continuation_frames: u8 = 0;
    while (block_cursor < header_block.len) {
        if (continuation_frames >= h2.max_continuation_frames) return error.HeaderBlockTooLarge;

        const chunk_len: usize = @min(header_block.len - block_cursor, max_payload_size_bytes);
        const is_last_chunk = block_cursor + chunk_len == header_block.len;
        const flags: u8 = if (is_last_chunk) h2.flags_end_headers else 0;

        const frame_len: usize = h2.frame_header_size_bytes + chunk_len;
        if (cursor + frame_len > out.len) return error.HeaderBlockTooLarge;
        _ = try appendFrame(
            out[cursor .. cursor + frame_len],
            .continuation,
            flags,
            stream_id,
            header_block[block_cursor .. block_cursor + chunk_len],
        );
        cursor += frame_len;
        block_cursor += chunk_len;
        continuation_frames += 1;
    }

    return out[0..cursor];
}

fn appendFrame(out: []u8, frame_type: h2.FrameType, flags: u8, stream_id: u32, payload: []const u8) Error![]const u8 {
    assert(out.len >= h2.frame_header_size_bytes);
    assert(payload.len <= std.math.maxInt(u24));

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
    assert(status <= 599);

    var cursor: usize = 0;
    var status_buf: [3]u8 = undefined;
    const status_text = try std.fmt.bufPrint(&status_buf, "{d}", .{status});

    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":status", status_text)).len;
    for (headers) |header| {
        cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value)).len;
    }

    assert(cursor <= out.len);
    return out[0..cursor];
}

fn buildHeaderBlock(headers: []const Header, out: []u8) ![]const u8 {
    assert(headers.len <= config.MAX_HEADERS);
    assert(out.len > 0);

    var cursor: usize = 0;
    for (headers) |header| {
        cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value)).len;
    }
    assert(cursor <= out.len);
    return out[0..cursor];
}

fn makeGrpcRequest(path: []const u8) !Request {
    assert(path.len > 0);
    assert(path[0] == '/');

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
    assert(request.headers.get("te") != null);
    return request;
}

var test_pending_response_headers_storage: [h2.header_block_capacity_bytes]u8 = undefined;

fn initRuntimeReadyForStreams(response_fields_storage: []h2.HeaderField) !Runtime {
    assert(h2.max_settings_per_frame > 0);
    assert(h2.client_connection_preface.len > 0);
    assert(response_fields_storage.len >= config.MAX_HEADERS);

    var runtime: Runtime = undefined;
    try runtime.initInto(.{}, response_fields_storage);

    var preface_buf: [h2.client_connection_preface.len + h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
    _ = try runtime.writeClientPrefaceAndSettings(&preface_buf);

    const peer_settings = h2.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    const action = try runtime.receiveFrame(&test_pending_response_headers_storage, peer_settings, &[_]u8{});
    switch (action) {
        .send_settings_ack => {},
        else => return error.UnexpectedAction,
    }

    var ack_buf: [h2.frame_header_size_bytes]u8 = undefined;
    _ = try runtime.writePendingSettingsAck(&ack_buf);
    return runtime;
}

test "Runtime writes client preface and SETTINGS" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime: Runtime = undefined;
    try runtime.initInto(.{}, &response_fields_storage);

    var out: [h2.client_connection_preface.len + h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
    const encoded = try runtime.writeClientPrefaceAndSettings(&out);

    try std.testing.expectEqualSlices(u8, h2.client_connection_preface, encoded[0..h2.client_connection_preface.len]);

    const settings_header = try h2.parseFrameHeader(encoded[h2.client_connection_preface.len..]);
    try std.testing.expectEqual(h2.FrameType.settings, settings_header.frame_type);
    try std.testing.expect(runtime.state.preface_sent);
    try std.testing.expect(runtime.state.local_settings_ack_pending);
}

test "Runtime requires peer settings before non-settings frames" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime: Runtime = undefined;
    try runtime.initInto(.{}, &response_fields_storage);

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
        runtime.receiveFrame(&test_pending_response_headers_storage, ping_header, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }),
    );
}

test "Runtime receives peer settings, sends ACK, and accepts SETTINGS ACK" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime: Runtime = undefined;
    try runtime.initInto(.{}, &response_fields_storage);

    var preface_buf: [h2.client_connection_preface.len + h2.frame_header_size_bytes + (4 * h2.setting_size_bytes)]u8 = undefined;
    _ = try runtime.writeClientPrefaceAndSettings(&preface_buf);

    const peer_settings = h2.FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    const action = try runtime.receiveFrame(&test_pending_response_headers_storage, peer_settings, &[_]u8{});
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
    const ack_action = try runtime.receiveFrame(&test_pending_response_headers_storage, settings_ack, &[_]u8{});
    try std.testing.expect(ack_action == .none);
    try std.testing.expect(!runtime.state.local_settings_ack_pending);
}

test "Runtime writes request HEADERS and DATA with stream lifecycle" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var headers_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const headers_write = try runtime.writeRequestHeadersFrame(&headers_buf, &header_block_buf, &request, null, false);
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

test "Runtime fragments outbound request HEADERS with CONTINUATION when peer max frame is reduced" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    runtime.state.peer_settings.max_frame_size_bytes = 64;

    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");
    try request.headers.put("x-long-header", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789");

    const frame_overhead_bytes: usize = h2.frame_header_size_bytes * (@as(usize, h2.max_continuation_frames) + 1);
    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var headers_buf: [h2.header_block_capacity_bytes + frame_overhead_bytes]u8 = undefined;
    const headers_write = try runtime.writeRequestHeadersFrame(&headers_buf, &header_block_buf, &request, null, true);

    var cursor: usize = 0;
    var frame_count: u8 = 0;
    var saw_continuation = false;
    var last_flags: u8 = 0;

    while (cursor < headers_write.frame.len) {
        try std.testing.expect(frame_count < h2.max_continuation_frames + 1);

        const header = try h2.parseFrameHeader(headers_write.frame[cursor .. cursor + h2.frame_header_size_bytes]);
        const frame_len: usize = h2.frame_header_size_bytes + header.length;
        try std.testing.expect(cursor + frame_len <= headers_write.frame.len);
        try std.testing.expectEqual(headers_write.stream_id, header.stream_id);

        if (frame_count == 0) {
            try std.testing.expectEqual(h2.FrameType.headers, header.frame_type);
            try std.testing.expect((header.flags & h2.flags_end_stream) != 0);
            try std.testing.expect((header.flags & h2.flags_end_headers) == 0);
        } else {
            saw_continuation = true;
            try std.testing.expectEqual(h2.FrameType.continuation, header.frame_type);
            try std.testing.expect((header.flags & h2.flags_end_stream) == 0);
        }

        last_flags = header.flags;
        cursor += frame_len;
        frame_count += 1;
    }

    try std.testing.expect(saw_continuation);
    try std.testing.expectEqual(headers_write.frame.len, cursor);
    try std.testing.expect((last_flags & h2.flags_end_headers) != 0);
}

test "Runtime decodes response HEADERS, DATA, and trailers" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var request_header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &request_header_block_buf, &request, null, true);

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const response_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &header_block_buf,
    );

    var response_headers_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        h2.flags_end_headers,
        request_headers.stream_id,
        response_block,
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    const headers_action = try runtime.receiveFrame(
        &test_pending_response_headers_storage,
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
    const data_action = try runtime.receiveFrame(&test_pending_response_headers_storage, data_header, "pong");
    switch (data_action) {
        .response_data => |resp_data| {
            try std.testing.expectEqualStrings("pong", resp_data.payload);
            try std.testing.expect(!resp_data.end_stream);
        },
        else => return error.UnexpectedAction,
    }

    var trailer_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const trailer_block = try buildHeaderBlock(&.{.{ .name = "grpc-status", .value = "0" }}, &trailer_block_buf);

    var trailer_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const trailer_frame = try appendFrame(
        &trailer_frame_buf,
        .headers,
        h2.flags_end_headers | h2.flags_end_stream,
        request_headers.stream_id,
        trailer_block,
    );
    const trailer_header = try h2.parseFrameHeader(trailer_frame);
    const trailer_action = try runtime.receiveFrame(
        &test_pending_response_headers_storage,
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
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, true);

    var response_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const response_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &response_block_buf,
    );
    const response_split: usize = response_block.len / 2;
    try std.testing.expect(response_split > 0);
    try std.testing.expect(response_split < response_block.len);

    var response_headers_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        0,
        request_headers.stream_id,
        response_block[0..response_split],
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    const first_headers_action = try runtime.receiveFrame(
        &test_pending_response_headers_storage,
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );
    try std.testing.expect(first_headers_action == .none);
    try std.testing.expect(runtime.pending_response_headers.active);

    var response_cont_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const response_continuation = try appendFrame(
        &response_cont_frame_buf,
        .continuation,
        h2.flags_end_headers,
        request_headers.stream_id,
        response_block[response_split..],
    );
    const response_cont_header = try h2.parseFrameHeader(response_continuation);
    const second_headers_action = try runtime.receiveFrame(
        &test_pending_response_headers_storage,
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

    var trailer_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const trailer_block = try buildHeaderBlock(&.{.{ .name = "grpc-status", .value = "0" }}, &trailer_block_buf);
    const trailer_split: usize = trailer_block.len / 2;
    try std.testing.expect(trailer_split > 0);
    try std.testing.expect(trailer_split < trailer_block.len);

    var trailer_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const trailer_frame = try appendFrame(
        &trailer_frame_buf,
        .headers,
        h2.flags_end_stream,
        request_headers.stream_id,
        trailer_block[0..trailer_split],
    );
    const trailer_header = try h2.parseFrameHeader(trailer_frame);
    const first_trailer_action = try runtime.receiveFrame(
        &test_pending_response_headers_storage,
        trailer_header,
        trailer_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + trailer_header.length],
    );
    try std.testing.expect(first_trailer_action == .none);
    try std.testing.expect(runtime.pending_response_headers.active);

    var trailer_cont_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const trailer_continuation = try appendFrame(
        &trailer_cont_frame_buf,
        .continuation,
        h2.flags_end_headers,
        request_headers.stream_id,
        trailer_block[trailer_split..],
    );
    const trailer_cont_header = try h2.parseFrameHeader(trailer_continuation);
    const second_trailer_action = try runtime.receiveFrame(
        &test_pending_response_headers_storage,
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
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, true);

    var response_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const response_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &response_block_buf,
    );

    var response_headers_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        0,
        request_headers.stream_id,
        response_block[0 .. response_block.len / 2],
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    _ = try runtime.receiveFrame(
        &test_pending_response_headers_storage,
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );

    const data_header = h2.FrameHeader{ .length = 1, .frame_type = .data, .flags = h2.flags_end_stream, .stream_id = request_headers.stream_id };
    try std.testing.expectError(error.UnsupportedContinuation, runtime.receiveFrame(&test_pending_response_headers_storage, data_header, "x"));
}

test "Runtime rejects unexpected CONTINUATION without pending response headers" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);

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
            &test_pending_response_headers_storage,
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime rejects unexpected CONTINUATION stream" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, true);

    var response_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const response_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &response_block_buf,
    );
    const split: usize = response_block.len / 2;

    var response_headers_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const response_headers_frame = try appendFrame(
        &response_headers_frame_buf,
        .headers,
        0,
        request_headers.stream_id,
        response_block[0..split],
    );
    const response_headers_header = try h2.parseFrameHeader(response_headers_frame);
    _ = try runtime.receiveFrame(
        &test_pending_response_headers_storage,
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );

    var continuation_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
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
            &test_pending_response_headers_storage,
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime rejects response CONTINUATION with invalid flags" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, true);

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
        &test_pending_response_headers_storage,
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
            &test_pending_response_headers_storage,
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        ),
    );
}

test "Runtime enforces response continuation frame bound" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, true);

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
        &test_pending_response_headers_storage,
        response_headers_header,
        response_headers_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + response_headers_header.length],
    );

    var continuation_frame_buf: [h2.frame_header_size_bytes + 1]u8 = undefined;
    var count: u8 = 0;
    while (count < h2.max_continuation_frames + 1) : (count += 1) {
        const continuation_frame = try appendFrame(
            &continuation_frame_buf,
            .continuation,
            0,
            request_headers.stream_id,
            "x",
        );
        const continuation_header = try h2.parseFrameHeader(continuation_frame);
        const result = runtime.receiveFrame(
            &test_pending_response_headers_storage,
            continuation_header,
            continuation_frame[h2.frame_header_size_bytes .. h2.frame_header_size_bytes + continuation_header.length],
        );

        if (count == h2.max_continuation_frames) {
            try std.testing.expectError(error.TooManyContinuationFrames, result);
            return;
        }
        _ = try result;
    }

    return error.ExpectedTooManyContinuationFrames;
}

test "Runtime handles upstream RST_STREAM and clears stream state" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, true);

    var rst_buf: [h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst_frame = try h2.buildRstStreamFrame(&rst_buf, request_headers.stream_id, @intFromEnum(h2.ErrorCode.cancel));
    const rst_header = try h2.parseFrameHeader(rst_frame);
    const action = try runtime.receiveFrame(&test_pending_response_headers_storage, rst_header, rst_frame[h2.frame_header_size_bytes..]);

    switch (action) {
        .stream_reset => |reset| {
            try std.testing.expectEqual(request_headers.stream_id, reset.stream_id);
            try std.testing.expectEqual(@as(u32, @intFromEnum(h2.ErrorCode.cancel)), reset.error_code_raw);
        },
        else => return error.UnexpectedAction,
    }

    try std.testing.expect(runtime.state.getStream(request_headers.stream_id) == null);
}

test "Runtime ignores duplicate upstream RST_STREAM for retired known stream" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime: Runtime = undefined;
    try runtime.initInto(.{}, &response_fields_storage);
    var request = try makeGrpcRequest("/svc.Method/Foo");

    var preface_buf: [256]u8 = undefined;
    _ = try runtime.writeClientPrefaceAndSettings(&preface_buf);

    var settings_frame: [64]u8 = undefined;
    const settings = try h2.buildFrameHeader(settings_frame[0..h2.frame_header_size_bytes], .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    });
    const settings_header = try h2.parseFrameHeader(settings[0..h2.frame_header_size_bytes]);
    const settings_action = try runtime.receiveFrame(&test_pending_response_headers_storage, settings_header, settings[h2.frame_header_size_bytes..]);
    try std.testing.expect(settings_action == .send_settings_ack);

    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    const request_write = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, false);
    try std.testing.expectEqual(@as(u32, 1), request_write.stream_id);

    var rst_buf: [64]u8 = undefined;
    const rst_frame = try h2.buildRstStreamFrame(&rst_buf, request_write.stream_id, @intFromEnum(h2.ErrorCode.cancel));
    const rst_header = try h2.parseFrameHeader(rst_frame[0..h2.frame_header_size_bytes]);

    const first_action = try runtime.receiveFrame(&test_pending_response_headers_storage, rst_header, rst_frame[h2.frame_header_size_bytes..]);
    switch (first_action) {
        .stream_reset => |reset| {
            try std.testing.expectEqual(request_write.stream_id, reset.stream_id);
            try std.testing.expectEqual(@as(u32, @intFromEnum(h2.ErrorCode.cancel)), reset.error_code_raw);
        },
        else => return error.TestUnexpectedResult,
    }

    const second_action = try runtime.receiveFrame(&test_pending_response_headers_storage, rst_header, rst_frame[h2.frame_header_size_bytes..]);
    try std.testing.expect(second_action == .none);
}

test "Runtime tracks GOAWAY bound and rejects new streams above last_stream_id" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    _ = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, false);

    var goaway_buf: [h2.frame_header_size_bytes + h2.control.goaway_min_payload_size_bytes]u8 = undefined;
    const goaway_frame = try h2.buildGoAwayFrame(
        &goaway_buf,
        1,
        @intFromEnum(h2.ErrorCode.no_error),
        &[_]u8{},
    );
    const goaway_header = try h2.parseFrameHeader(goaway_frame);
    const goaway_action = try runtime.receiveFrame(&test_pending_response_headers_storage, goaway_header, goaway_frame[h2.frame_header_size_bytes..]);

    switch (goaway_action) {
        .connection_close => |goaway| try std.testing.expectEqual(@as(u32, 1), goaway.last_stream_id),
        else => return error.UnexpectedAction,
    }

    var second_request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    try std.testing.expectError(
        error.ConnectionClosing,
        runtime.writeRequestHeadersFrame(&second_request_frame_buf, &header_block_buf, &request, null, false),
    );
}

test "Runtime applies WINDOW_UPDATE increments to send windows" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);
    var request = try makeGrpcRequest("/grpc.test.Echo/Unary");

    var header_block_buf: [h2.header_block_capacity_bytes]u8 = undefined;
    var request_frame_buf: [h2.frame_header_size_bytes + h2.header_block_capacity_bytes]u8 = undefined;
    const request_headers = try runtime.writeRequestHeadersFrame(&request_frame_buf, &header_block_buf, &request, null, false);

    const connection_send_before = runtime.state.flow.send_window.available_bytes;
    const stream_send_before = runtime.state.getStream(request_headers.stream_id).?.send_window.available_bytes;

    var connection_update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const connection_update_frame = try h2.buildWindowUpdateFrame(&connection_update_buf, 0, 32);
    const connection_update_header = try h2.parseFrameHeader(connection_update_frame);
    const connection_action = try runtime.receiveFrame(&test_pending_response_headers_storage, connection_update_header, connection_update_frame[h2.frame_header_size_bytes..]);
    try std.testing.expect(connection_action == .none);

    var stream_update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const stream_update_frame = try h2.buildWindowUpdateFrame(&stream_update_buf, request_headers.stream_id, 16);
    const stream_update_header = try h2.parseFrameHeader(stream_update_frame);
    const stream_action = try runtime.receiveFrame(&test_pending_response_headers_storage, stream_update_header, stream_update_frame[h2.frame_header_size_bytes..]);
    try std.testing.expect(stream_action == .none);

    try std.testing.expectEqual(connection_send_before + 32, runtime.state.flow.send_window.available_bytes);
    try std.testing.expectEqual(
        stream_send_before + 16,
        runtime.state.getStream(request_headers.stream_id).?.send_window.available_bytes,
    );
}

test "Runtime emits ping ACK action and frame" {
    var response_fields_storage: [config.MAX_HEADERS]h2.HeaderField = undefined;
    var runtime = try initRuntimeReadyForStreams(&response_fields_storage);

    const ping_header = h2.FrameHeader{
        .length = h2.control.ping_payload_size_bytes,
        .frame_type = .ping,
        .flags = 0,
        .stream_id = 0,
    };
    const action = try runtime.receiveFrame(&test_pending_response_headers_storage, ping_header, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });

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
