//! HTTP/2 Connection Driver
//!
//! Runs a bounded terminating HTTP/2 connection over plain file descriptors
//! or TLS streams.
//! This is the first server-side runtime driver for Phase B: it owns the
//! connection loop, emits server SETTINGS / ACK / PING / GOAWAY / RST_STREAM,
//! and dispatches request HEADERS / DATA frames to a streaming handler.
//! TigerStyle: Explicit frame loop, fixed buffers, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const posix = std.posix;

const serval_core = @import("serval-core");
const config = serval_core.config;
const types = serval_core.types;
const time = serval_core.time;
const log = serval_core.log.scoped(.server);
const h2 = @import("serval-h2");
const runtime_mod = @import("runtime.zig");
const h2_bootstrap = @import("bootstrap.zig");
const frontend = @import("../frontend/mod.zig");
const serval_net = @import("serval-net");
const set_tcp_no_delay = serval_net.set_tcp_no_delay;
const serval_tls = @import("serval-tls");
const TLSStream = serval_tls.TLSStream;
const ssl = serval_tls.ssl;

const Request = types.Request;

const read_buffer_size_bytes: usize = h2.client_connection_preface.len + h2.frame_header_size_bytes + config.H2_MAX_FRAME_SIZE_BYTES;
const frame_buffer_size_bytes: usize = h2.frame_header_size_bytes + config.H2_MAX_FRAME_SIZE_BYTES;
const header_block_frame_overhead_bytes: usize = h2.frame_header_size_bytes * (@as(usize, h2.max_continuation_frames) + 1);
const header_block_frame_buffer_size_bytes: usize = config.H2_MAX_HEADER_BLOCK_SIZE_BYTES + header_block_frame_overhead_bytes;
const response_table_capacity: usize = config.H2_MAX_CONCURRENT_STREAMS;
const upgrade_preamble_size_bytes: usize =
    h2.client_connection_preface.len +
    (2 * h2.frame_header_size_bytes) +
    config.H2_MAX_FRAME_SIZE_BYTES +
    config.H2_MAX_HEADER_BLOCK_SIZE_BYTES;
const read_max_retry_count: u32 = 30_000;
const tls_read_readiness_timeout_ns: u64 = config.H2_SERVER_IDLE_TIMEOUT_NS;
const write_retry_sleep_ns: u64 = time.ns_per_ms;
const write_stall_timeout_ns: u64 = 30 * time.ns_per_s;
const write_max_retry_count: u32 = 30_000;
const response_send_chunk_size_bytes: usize = config.H2_MAX_FRAME_SIZE_BYTES;

const ConnectionIo = union(enum) {
    plain_fd: i32,
    tls_stream: *TLSStream,

    fn initPlain(fd: i32) ConnectionIo {
        assert(fd >= 0);
        assert(fd <= std.math.maxInt(i32));
        return .{ .plain_fd = fd };
    }

    fn initTls(tls_stream: *TLSStream) ConnectionIo {
        assert(@intFromPtr(tls_stream) != 0);
        assert(tls_stream.fd >= 0);
        return .{ .tls_stream = tls_stream };
    }
};

/// A single HTTP/2 header field as a borrowed name/value pair.
/// Both slices are read during header-block encoding; this type does not own
/// the bytes and does not impose any normalization beyond what callers provide.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Describes why a tracked HTTP/2 stream was closed.
/// `local_end_stream` and `local_reset` indicate server-initiated completion,
/// while `peer_reset` and `connection_close` indicate remote or connection-level termination.
pub const StreamCloseReason = enum {
    local_end_stream,
    peer_reset,
    local_reset,
    connection_close,
};

/// Per-stream accounting captured when a stream is closed.
/// `duration_ns` is measured from stream start to close using monotonic time,
/// and `reset_error_code_raw` preserves the raw HTTP/2 reset or GOAWAY code.
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

/// Errors returned by HTTP/2 server connection and response-writing routines.
/// This set combines server-local state errors with runtime, frame, HPACK,
/// and h2c-upgrade failures from the imported subsystems.
pub const Error = error{
    InvalidPreface,
    ReadFailed,
    WriteFailed,
    WouldBlock,
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
    ResponsePayloadTooLarge,
    PendingResponseData,
    FrameLimitExceeded,
} || runtime_mod.Error || h2.FrameError || h2.HpackError || h2.H2cUpgradeError;

const ResponseState = struct {
    used: bool = false,
    stream_id: u32 = 0,
    headers_sent: bool = false,
    closed: bool = false,
    pending_payload_len: u32 = 0,
    pending_payload_sent: u32 = 0,
    pending_end_stream: bool = false,
    pending_payload_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined,
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
            log.debug("h2: tracker insert stream={d} count={d}", .{ stream_id, self.count });
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
        log.debug(
            "h2: tracker mark request headers stream={d} end_stream={any} opened={any} count={d}",
            .{ stream_id, end_stream, existing == null, self.count },
        );
        return existing == null;
    }

    fn markRequestData(self: *StreamTrackerTable, stream_id: u32, payload_len: usize, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const tracker = try self.getOrInsert(stream_id);
        tracker.request_data_bytes += @intCast(payload_len);
        if (end_stream) tracker.remote_end_stream = true;
        log.debug(
            "h2: tracker mark request data stream={d} bytes={d} end_stream={any} count={d}",
            .{ stream_id, payload_len, end_stream, self.count },
        );
    }

    fn markResponseHeaders(self: *StreamTrackerTable, stream_id: u32, status: u16, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const tracker = self.get(stream_id) orelse {
            log.debug("h2: tracker miss response headers stream={d} count={d}", .{ stream_id, self.count });
            return error.StreamTrackerNotFound;
        };
        log.debug(
            "h2: tracker mark response headers stream={d} status={d} end_stream={any} count={d}",
            .{ stream_id, status, end_stream, self.count },
        );
        tracker.response_status = status;
        if (end_stream) tracker.local_end_stream = true;
    }

    fn markResponseData(self: *StreamTrackerTable, stream_id: u32, payload_len: usize, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const tracker = self.get(stream_id) orelse {
            log.debug("h2: tracker miss response data stream={d} count={d}", .{ stream_id, self.count });
            return error.StreamTrackerNotFound;
        };
        log.debug(
            "h2: tracker mark response data stream={d} bytes={d} end_stream={any} count={d}",
            .{ stream_id, payload_len, end_stream, self.count },
        );
        tracker.response_data_bytes += @intCast(payload_len);
        if (end_stream) tracker.local_end_stream = true;
    }

    fn markResponseEnd(self: *StreamTrackerTable, stream_id: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        const tracker = self.get(stream_id) orelse {
            log.debug("h2: tracker miss response end stream={d} count={d}", .{ stream_id, self.count });
            return error.StreamTrackerNotFound;
        };
        log.debug(
            "h2: tracker mark response end stream={d} count={d}",
            .{ stream_id, self.count },
        );
        tracker.local_end_stream = true;
    }

    fn popIfClosed(self: *StreamTrackerTable) ?StreamTracker {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= config.H2_MAX_CONCURRENT_STREAMS);

        for (self.slots[0..], 0..) |*slot, index| {
            if (!slot.used) continue;
            if (!slot.remote_end_stream or !slot.local_end_stream) continue;
            log.debug(
                "h2: tracker pop if closed stream={d} index={d} count={d}",
                .{ slot.stream_id, index, self.count },
            );
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
            log.debug("h2: tracker pop stream={d} index={d} count={d}", .{ stream_id, index, self.count });
            return self.popByIndex(index);
        }
        return null;
    }

    fn popAny(self: *StreamTrackerTable) ?StreamTracker {
        assert(@intFromPtr(self) != 0);
        assert(self.count <= config.H2_MAX_CONCURRENT_STREAMS);

        for (self.slots[0..], 0..) |*slot, index| {
            if (!slot.used) continue;
            log.debug("h2: tracker pop any stream={d} index={d} count={d}", .{ slot.stream_id, index, self.count });
            return self.popByIndex(index);
        }
        return null;
    }

    fn popByIndex(self: *StreamTrackerTable, index: usize) StreamTracker {
        assert(@intFromPtr(self) != 0);
        assert(index < self.slots.len);
        assert(self.slots[index].used);

        const tracker = self.slots[index];
        log.debug(
            "h2: tracker pop by index stream={d} index={d} count={d}",
            .{ tracker.stream_id, index, self.count },
        );
        self.slots[index] = .{};
        assert(self.count > 0);
        self.count -= 1;
        return tracker;
    }
};

/// Writer for sending HTTP/2 response frames on a single stream.
/// Holds borrowed pointers to connection I/O, runtime state, and tracking tables; those pointed-to values must outlive the writer.
/// `stream_id` must be set to a positive stream id before calling the send methods.
/// Use the public send methods to drive the stream lifecycle and emit response frames.
pub const ResponseWriter = struct {
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    stream_id: u32,
    runtime: *runtime_mod.Runtime,
    states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,

    /// Send the response HEADERS for an open stream.
    /// Requires `status >= 100` and fails if headers were already sent or the stream is closed.
    /// Encodes the response headers, writes the frame sequence, records stream state, and finalizes the stream when `end_stream` is true.
    /// Returns errors from header encoding, frame assembly, write, or stream tracking.
    pub fn sendHeaders(self: *ResponseWriter, status: u16, headers: []const Header, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(status >= 100);
        assert(self.stream_id > 0);

        var state = try self.states.getOrInsert(self.stream_id);
        if (state.headers_sent) return error.HeadersAlreadySent;
        if (state.closed) return error.ResponseClosed;

        var block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
        const block = try buildResponseHeaderBlock(status, headers, &block_buf);
        const peer_max_frame_size_bytes = responsePeerMaxFrameSizeBytes(self.runtime);
        const max_payload_size_bytes: usize = @min(@as(usize, config.H2_MAX_FRAME_SIZE_BYTES), peer_max_frame_size_bytes);

        var frame_buf: [header_block_frame_buffer_size_bytes]u8 = undefined;
        const frame = try appendHeaderBlockFrames(
            &frame_buf,
            self.stream_id,
            block,
            end_stream,
            max_payload_size_bytes,
        );
        try writeAll(self.io_conn, self.io, frame);

        state.headers_sent = true;
        try self.stream_trackers.markResponseHeaders(self.stream_id, status, end_stream);
        if (end_stream) try self.finishStream(state);
    }

    /// Send response DATA on an open stream after response headers have been sent.
    /// Rejects payloads larger than one frame and returns `PendingResponseData` if buffered data is still outstanding.
    /// An empty payload only emits an empty final DATA frame when `end_stream` is true.
    /// Otherwise the payload is buffered, flushed according to flow control, and the stream is finalized when the end of stream is reached.
    pub fn sendData(self: *ResponseWriter, payload: []const u8, end_stream: bool) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.stream_id > 0);

        var state = self.states.get(self.stream_id) orelse return error.ResponseStateNotFound;
        if (!state.headers_sent) return error.HeadersNotSent;
        if (state.closed) return error.ResponseClosed;

        if (state.pending_payload_len > state.pending_payload_sent) return error.PendingResponseData;

        if (payload.len == 0) {
            if (end_stream) {
                var empty_frame_buf: [frame_buffer_size_bytes]u8 = undefined;
                const empty_frame = try appendFrame(&empty_frame_buf, .data, h2.flags_end_stream, self.stream_id, &[_]u8{});
                try writeAll(self.io_conn, self.io, empty_frame);
                try self.stream_trackers.markResponseData(self.stream_id, 0, true);
                try self.finishStream(state);
            }
            return;
        }

        if (payload.len > config.H2_MAX_FRAME_SIZE_BYTES) return error.ResponsePayloadTooLarge;

        @memcpy(state.pending_payload_buf[0..payload.len], payload);
        state.pending_payload_len = @intCast(payload.len);
        state.pending_payload_sent = 0;
        state.pending_end_stream = end_stream;

        const ended_stream = try flushResponseStatePendingData(self.io_conn, self.io, self.runtime, state, self.stream_trackers);
        if (ended_stream) try self.finishStream(state);
    }

    /// Send trailer headers on an open stream after response headers have been sent.
    /// Fails if the stream state is missing, already closed, or has not emitted headers yet.
    /// Encodes the trailers into HEADERS/CONTINUATION frames, writes them, marks response end, and finalizes the stream.
    /// Returns errors from header encoding, frame assembly, write, tracking, or stream finalization.
    pub fn sendTrailers(self: *ResponseWriter, trailers: []const Header) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.stream_id > 0);

        const state = self.states.get(self.stream_id) orelse return error.ResponseStateNotFound;
        if (!state.headers_sent) return error.HeadersNotSent;
        if (state.closed) return error.ResponseClosed;

        var block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
        const block = try buildHeaderBlock(trailers, false, 0, &block_buf);
        const peer_max_frame_size_bytes = responsePeerMaxFrameSizeBytes(self.runtime);
        const max_payload_size_bytes: usize = @min(@as(usize, config.H2_MAX_FRAME_SIZE_BYTES), peer_max_frame_size_bytes);

        var frame_buf: [header_block_frame_buffer_size_bytes]u8 = undefined;
        const frame = try appendHeaderBlockFrames(
            &frame_buf,
            self.stream_id,
            block,
            true,
            max_payload_size_bytes,
        );
        try writeAll(self.io_conn, self.io, frame);
        try self.stream_trackers.markResponseEnd(self.stream_id);
        try self.finishStream(state);
    }

    /// Send a stream reset using the raw HTTP/2 error code value.
    /// Requires a live response writer with a positive `stream_id`.
    /// If response state is still tracked for the stream, the stream is finalized locally after the reset is sent.
    /// Returns any I/O or runtime error raised while emitting the reset.
    pub fn sendReset(self: *ResponseWriter, error_code_raw: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.stream_id > 0);

        try sendErrorReset(self.io_conn, self.io, self.runtime, self.stream_id, error_code_raw);

        if (self.states.get(self.stream_id)) |state| {
            try self.finishStream(state);
        }
    }

    fn finishStream(self: *ResponseWriter, state: *ResponseState) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(state) != 0);

        try self.runtime.state.endLocalStream(self.stream_id);
        state.closed = true;
        self.states.remove(self.stream_id);
    }
};

fn flushResponseStatePendingData(
    io_conn: *ConnectionIo,
    io: Io,
    runtime: *runtime_mod.Runtime,
    state: *ResponseState,
    stream_trackers: *StreamTrackerTable,
) Error!bool {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);
    assert(@intFromPtr(state) != 0);
    assert(@intFromPtr(stream_trackers) != 0);

    if (state.pending_payload_len == 0) return false;
    if (state.pending_payload_sent >= state.pending_payload_len) return false;

    const stream = runtime.state.getStream(state.stream_id) orelse return false;
    if (!stream.localCanSend()) return false;

    const conn_window_bytes: usize = runtime.state.flow.send_window.available_bytes;
    const stream_window_bytes: usize = stream.send_window.available_bytes;
    const peer_max_frame_size_bytes = responsePeerMaxFrameSizeBytes(runtime);
    const pending_remaining_bytes: usize = @intCast(state.pending_payload_len - state.pending_payload_sent);

    const allowed_bytes = @min(
        @min(conn_window_bytes, stream_window_bytes),
        @min(peer_max_frame_size_bytes, pending_remaining_bytes),
    );
    if (allowed_bytes == 0) return false;

    const small_window_mode = stream_window_bytes <= 3 or conn_window_bytes <= 3;
    const chunk_len = if (small_window_mode)
        @min(allowed_bytes, response_send_chunk_size_bytes)
    else
        allowed_bytes;
    const start: usize = @intCast(state.pending_payload_sent);
    const end = start + chunk_len;
    const finished_payload = end == state.pending_payload_len;
    const send_end_stream = finished_payload and state.pending_end_stream;

    var frame_buf: [frame_buffer_size_bytes]u8 = undefined;
    const frame = try appendFrame(
        &frame_buf,
        .data,
        if (send_end_stream) h2.flags_end_stream else 0,
        state.stream_id,
        state.pending_payload_buf[start..end],
    );
    try writeAll(io_conn, io, frame);

    const sent_u32: u32 = @intCast(chunk_len);
    try runtime.state.consumeSendWindow(sent_u32);
    try runtime.state.consumeStreamSendWindow(state.stream_id, sent_u32);
    state.pending_payload_sent += sent_u32;

    try stream_trackers.markResponseData(state.stream_id, chunk_len, send_end_stream);

    if (finished_payload) {
        state.pending_payload_len = 0;
        state.pending_payload_sent = 0;
        state.pending_end_stream = false;
    }

    return send_end_stream;
}

fn responsePeerMaxFrameSizeBytes(runtime: *const runtime_mod.Runtime) usize {
    assert(@intFromPtr(runtime) != 0);

    const peer_max_frame_size_bytes: u32 = runtime.state.peer_settings.max_frame_size_bytes;
    assert(peer_max_frame_size_bytes >= h2.settings.min_max_frame_size_bytes);
    assert(peer_max_frame_size_bytes <= h2.settings.max_max_frame_size_bytes);
    return @intCast(peer_max_frame_size_bytes);
}

/// Validate that `Handler` satisfies the HTTP/2 handler contract at comptime.
/// The type must be a struct that declares `handleH2Headers` and `handleH2Data`.
/// Optional hooks are accepted only when their parameter and return types match the expected signatures.
/// Violations are reported as compile errors rather than runtime errors.
pub fn verifyHandler(comptime Handler: type) void {
    assert(@typeInfo(Handler) == .@"struct");
    assert(@typeName(Handler).len > 0);

    if (!@hasDecl(Handler, "handleH2Headers")) {
        @compileError(@typeName(Handler) ++ " must declare handleH2Headers(self, stream_id, request, end_stream, writer)");
    }
    if (!@hasDecl(Handler, "handleH2Data")) {
        @compileError(@typeName(Handler) ++ " must declare handleH2Data(self, stream_id, payload, end_stream, writer)");
    }

    verifyOptionalHook(Handler, "handleH2StreamOpen", &[_]type{ *Handler, u32, *const Request }, void);
    verifyOptionalHook(Handler, "handleH2StreamClose", &[_]type{ *Handler, StreamSummary }, void);
    verifyOptionalHook(Handler, "startH2BackgroundTasks", &[_]type{ *Handler, *ResponseWriter, *Io.Mutex }, void);
    verifyOptionalHook(Handler, "stopH2BackgroundTasks", &[_]type{*Handler}, void);
}

fn verifyOptionalHook(
    comptime Handler: type,
    comptime hook_name: []const u8,
    comptime expected_params: []const type,
    comptime expected_return: type,
) void {
    assert(hook_name.len > 0);
    assert(expected_params.len <= 8);

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

const InboundFrame = struct {
    header: h2.FrameHeader,
    frame_len: usize,
    payload: []const u8,
};

fn closeTrackedStreamsForFatalError(
    comptime Handler: type,
    handler: *Handler,
    connection_id: u64,
    stream_trackers: *StreamTrackerTable,
    err: anyerror,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(stream_trackers) != 0);

    closeAllTrackedStreams(
        Handler,
        handler,
        connection_id,
        stream_trackers,
        .connection_close,
        @intFromEnum(mapGoAwayError(err)),
    );
}

fn readInboundFrame(
    io_conn: *ConnectionIo,
    maybe_plain_reader: ?*Io.net.Stream.Reader,
    io: Io,
    connection_id: u64,
    frame_count: u32,
    recv_buf: *[read_buffer_size_bytes]u8,
    buffer_len: *usize,
) Error!?InboundFrame {
    assert(@intFromPtr(io_conn) != 0);
    assert(buffer_len.* <= recv_buf.len);

    log.debug("server: conn={d} h2 waiting for frame frame_count={d} buffered_bytes={d}", .{
        connection_id,
        frame_count,
        buffer_len.*,
    });
    const have_frame = try ensureFrame(io_conn, maybe_plain_reader, io, recv_buf, buffer_len);
    if (!have_frame) return null;

    const header = try h2.parseFrameHeader(recv_buf[0..h2.frame_header_size_bytes]);
    const frame_len: usize = h2.frame_header_size_bytes + header.length;
    try fillBuffer(io_conn, maybe_plain_reader, io, recv_buf, buffer_len, frame_len);
    log.debug("server: conn={d} h2 parsed frame count={d} type={s} stream={d} flags=0x{x} payload_bytes={d} buffered_bytes={d}", .{
        connection_id,
        frame_count,
        @tagName(header.frame_type),
        header.stream_id,
        header.flags,
        header.length,
        buffer_len.*,
    });

    return .{
        .header = header,
        .frame_len = frame_len,
        .payload = recv_buf[h2.frame_header_size_bytes..frame_len],
    };
}

fn processInboundFrame(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    recv_buf: *[read_buffer_size_bytes]u8,
    buffer_len: *usize,
    frame: InboundFrame,
) Error!bool {
    assert(@intFromPtr(handler) != 0);
    assert(frame.frame_len <= recv_buf.len);

    const action = runtime.receiveFrame(frame.header, frame.payload) catch |err| {
        if (try tryHandleRecoverableStreamError(
            Handler,
            handler,
            io_conn,
            io,
            connection_id,
            runtime,
            response_states,
            stream_trackers,
            frame.header,
            err,
        )) {
            discardPrefix(recv_buf, buffer_len, frame.frame_len);
            return false;
        }

        logRuntimeFrameError(connection_id, frame.header, err);
        return err;
    };
    log.debug("server: conn={d} h2 runtime action={s} frame_type={s} stream={d}", .{
        connection_id,
        @tagName(action),
        @tagName(frame.header.frame_type),
        frame.header.stream_id,
    });
    try handleAction(Handler, handler, io_conn, io, connection_id, runtime, response_states, stream_trackers, action);
    try flushPendingResponseData(runtime, io_conn, io, response_states, stream_trackers);
    closeCompletedStreams(Handler, handler, connection_id, stream_trackers);
    discardPrefix(recv_buf, buffer_len, frame.frame_len);
    return action == .connection_close;
}

fn writeFrameLimitGoAway(
    io_conn: *ConnectionIo,
    io: Io,
    runtime: *runtime_mod.Runtime,
) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);

    var goaway_buf: [frame_buffer_size_bytes]u8 = undefined;
    const goaway = try runtime.writeGoAwayFrame(&goaway_buf, .{
        .last_stream_id = runtime.state.local_goaway_last_stream_id,
        .error_code_raw = @intFromEnum(h2.ErrorCode.enhance_your_calm),
        .debug_data = "frame_limit",
    });
    writeAll(io_conn, io, goaway) catch |write_err| switch (write_err) {
        error.ConnectionClosed => {},
        else => {},
    };
}

fn runConnectionFrameLoop(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    maybe_plain_reader: ?*Io.net.Stream.Reader,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    connection_mutex: *Io.Mutex,
    recv_buf: *[read_buffer_size_bytes]u8,
    buffer_len: *usize,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(connection_mutex) != 0);

    var frame_count: u32 = 0;
    while (frame_count < config.H2_SERVER_MAX_FRAME_COUNT) : (frame_count += 1) {
        const frame = readInboundFrame(io_conn, maybe_plain_reader, io, connection_id, frame_count, recv_buf, buffer_len) catch |err| {
            try sendRuntimeErrorGoAway(runtime, io_conn, io, runtime.state.local_goaway_last_stream_id, err);
            closeTrackedStreamsForFatalError(Handler, handler, connection_id, stream_trackers, err);
            return err;
        };
        if (frame == null) {
            log.debug("server: conn={d} h2 peer closed before next frame", .{connection_id});
            closeAllTrackedStreams(Handler, handler, connection_id, stream_trackers, .connection_close, 0);
            return;
        }

        connection_mutex.lockUncancelable(io);
        defer connection_mutex.unlock(io);

        const should_close = processInboundFrame(Handler, handler, io_conn, io, connection_id, runtime, response_states, stream_trackers, recv_buf, buffer_len, frame.?) catch |err| {
            try sendRuntimeErrorGoAway(runtime, io_conn, io, frame.?.header.stream_id, err);
            closeTrackedStreamsForFatalError(Handler, handler, connection_id, stream_trackers, err);
            return err;
        };
        if (should_close) return;
    }

    try writeFrameLimitGoAway(io_conn, io, runtime);
    closeAllTrackedStreams(
        Handler,
        handler,
        connection_id,
        stream_trackers,
        .connection_close,
        @intFromEnum(h2.ErrorCode.enhance_your_calm),
    );
    return error.FrameLimitExceeded;
}

fn initMaybePlainReader(
    io_conn: *ConnectionIo,
    io: Io,
    plain_read_buf: *[config.STREAM_READ_BUFFER_SIZE_BYTES]u8,
    plain_reader: *Io.net.Stream.Reader,
) ?*Io.net.Stream.Reader {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(plain_reader) != 0);

    switch (io_conn.*) {
        .plain_fd => |fd| {
            plain_reader.* = rawStreamForFd(fd).reader(io, plain_read_buf);
            return plain_reader;
        },
        .tls_stream => return null,
    }
}

fn sendInitialServerSettings(
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    local_settings_already_sent: bool,
) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);

    if (local_settings_already_sent) return runtime.state.markLocalSettingsSent();

    log.debug("server: conn={d} h2 building initial settings frame", .{connection_id});
    var settings_buf: [runtime_mod.initial_settings_frame_buffer_size_bytes]u8 = undefined;
    const initial_settings = try runtime.writeInitialSettingsFrame(&settings_buf);
    log.debug("server: conn={d} h2 writing initial settings bytes={d} fd={d}", .{
        connection_id,
        initial_settings.len,
        connectionIoFd(io_conn),
    });
    writeAll(io_conn, io, initial_settings) catch |err| {
        log.warn("server: conn={d} h2 initial settings write failed: {s}", .{ connection_id, @errorName(err) });
        return err;
    };
    log.debug("server: conn={d} h2 sent initial settings bytes={d}", .{ connection_id, initial_settings.len });
}

fn consumeClientPrefaceFromBuffer(
    io_conn: *ConnectionIo,
    maybe_plain_reader: ?*Io.net.Stream.Reader,
    io: Io,
    runtime: *runtime_mod.Runtime,
    recv_buf: *[read_buffer_size_bytes]u8,
    buffer_len: *usize,
    connection_id: u64,
) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);
    assert(buffer_len.* <= recv_buf.len);

    try fillBuffer(io_conn, maybe_plain_reader, io, recv_buf, buffer_len, h2.client_connection_preface.len);
    if (!h2.looksLikeClientConnectionPreface(recv_buf[0..buffer_len.*])) return error.InvalidPreface;
    try runtime.receiveClientPreface();
    discardPrefix(recv_buf, buffer_len, h2.client_connection_preface.len);
    log.debug("server: conn={d} h2 consumed client preface buffered_bytes={d}", .{ connection_id, buffer_len.* });
}

fn initReceiveBuffer(recv_buf: *[read_buffer_size_bytes]u8, buffer_len: *usize, initial_bytes: []const u8) void {
    assert(initial_bytes.len <= recv_buf.len);
    assert(@intFromPtr(buffer_len) != 0);

    buffer_len.* = 0;
    if (initial_bytes.len == 0) return;
    @memcpy(recv_buf[0..initial_bytes.len], initial_bytes);
    buffer_len.* = initial_bytes.len;
}

fn startBackgroundTasksIfPresent(
    comptime Handler: type,
    handler: *Handler,
    background_writer: *ResponseWriter,
    connection_mutex: *Io.Mutex,
    connection_id: u64,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(background_writer) != 0);

    if (comptime @hasDecl(Handler, "startH2BackgroundTasks")) {
        log.debug("server: conn={d} h2 starting background tasks", .{connection_id});
        handler.startH2BackgroundTasks(background_writer, connection_mutex);
        log.debug("server: conn={d} h2 started background tasks", .{connection_id});
    }
}

fn stopBackgroundTasksIfPresent(comptime Handler: type, handler: *Handler) void {
    assert(@intFromPtr(handler) != 0);
    assert(@sizeOf(Handler) >= 0);

    if (comptime @hasDecl(Handler, "stopH2BackgroundTasks")) handler.stopH2BackgroundTasks();
}

fn bootstrapUpgradedConnection(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    settings_payload: []const u8,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(settings_payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);

    var settings_buf: [runtime_mod.initial_settings_frame_buffer_size_bytes]u8 = undefined;
    const initial_settings = try runtime.writeInitialSettingsFrame(&settings_buf);
    try writeAll(io_conn, io, initial_settings);
    try runtime.receiveClientPreface();
    try applyUpgradePeerSettings(
        Handler,
        handler,
        io_conn,
        io,
        connection_id,
        runtime,
        response_states,
        stream_trackers,
        settings_payload,
    );
}

fn processUpgradeSyntheticRequestAndBody(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    plain_reader: *Io.net.Stream.Reader,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    request: *const Request,
    settings_payload: []const u8,
    initial_body: []const u8,
    remaining_body_bytes: u64,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(request) != 0);

    const total_body_bytes: u64 = @as(u64, @intCast(initial_body.len)) + remaining_body_bytes;
    try applyUpgradeSyntheticHeaders(
        Handler,
        handler,
        io_conn,
        io,
        connection_id,
        runtime,
        response_states,
        stream_trackers,
        request,
        settings_payload,
        total_body_bytes,
    );
    try processUpgradeBody(
        Handler,
        handler,
        io_conn,
        plain_reader,
        io,
        connection_id,
        runtime,
        response_states,
        stream_trackers,
        initial_body,
        remaining_body_bytes,
    );
}

/// Serve a plain connection without any extra initial bytes.
/// Equivalent to calling `servePlainConnectionWithInitialBytes(..., &[_]u8{})`.
/// `fd` must be a valid non-negative descriptor and remains owned by the caller.
/// Propagates any error from the underlying plain connection driver.
pub fn servePlainConnection(
    comptime Handler: type,
    handler: *Handler,
    runtime_cfg: config.H2Config,
    fd: i32,
    io: Io,
    connection_id: u64,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(fd >= 0);
    return servePlainConnectionWithInitialBytes(Handler, handler, runtime_cfg, fd, io, connection_id, &[_]u8{});
}

/// Serve a TLS connection without any extra initial bytes.
/// Equivalent to calling `serveTlsConnectionWithInitialBytes(..., &[_]u8{})`.
/// `tls_stream` is borrowed for the call and is not closed by this helper.
/// Propagates any error from the underlying TLS connection driver.
pub fn serveTlsConnection(
    comptime Handler: type,
    handler: *Handler,
    runtime_cfg: config.H2Config,
    tls_stream: *TLSStream,
    io: Io,
    connection_id: u64,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(tls_stream) != 0);
    return serveTlsConnectionWithInitialBytes(Handler, handler, runtime_cfg, tls_stream, io, connection_id, &[_]u8{});
}

/// Error set returned by `run`.
/// Combines HTTP/2 bootstrap errors, frontend-orchestrator errors, and server-startup failures.
/// Includes listener creation failure plus TLS certificate, key, and context creation failures.
/// Use this type when starting the server accept loop or preparing TLS state can fail.
pub const RunError = h2_bootstrap.H2BootstrapError || frontend.FrontendOrchestratorError || error{
    ListenFailed,
    LoadCertFailed,
    LoadKeyFailed,
    NoTlsMethod,
    SslCtxNew,
    OutOfMemory,
};

/// Start the server accept loop for the configured HTTP/2 listener.
/// Resolves the listen address, starts the frontend runtime orchestrator, and records the listener fd when `listener_fd_out` is provided.
/// Accepted connections are handed to per-connection tasks until `shutdown` becomes true.
/// Returns setup, TLS-configuration, listen, or orchestrator errors from server startup and accept-loop processing.
pub fn run(
    comptime Handler: type,
    handler: *Handler,
    cfg: config.Config,
    io: Io,
    shutdown: *std.atomic.Value(bool),
    listener_fd_out: ?*std.atomic.Value(i32),
) RunError!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(shutdown) != 0);
    assert(cfg.port > 0);
    assert(cfg.listen_host.len > 0);

    const addr = try h2_bootstrap.preflightAndResolveListenAddress(&cfg);

    const verify_upstream_tls = if (cfg.tls) |tls_cfg| tls_cfg.verify_upstream else true;

    var runtime_orchestrator: frontend.RuntimeOrchestrator = undefined;
    runtime_orchestrator.init(
        shutdown,
        .{},
        null,
        verify_upstream_tls,
    );
    try runtime_orchestrator.start(&cfg);
    defer runtime_orchestrator.stop();

    var tcp_server = addr.listen(io, .{
        .kernel_backlog = cfg.kernel_backlog,
        .reuse_address = true,
    }) catch return error.ListenFailed;

    if (listener_fd_out) |fd_out| {
        fd_out.store(@intCast(tcp_server.socket.handle), .release);
    }
    defer {
        if (listener_fd_out) |fd_out| {
            fd_out.store(-1, .release);
        }
        tcp_server.deinit(io);
    }

    const server_tls_ctx: ?*ssl.SSL_CTX = if (cfg.tls) |tls_cfg| blk: {
        const cert_path = tls_cfg.cert_path orelse break :blk null;
        const key_path = tls_cfg.key_path orelse break :blk null;

        const ctx = ssl.createServerCtxFromPemFiles(cert_path, key_path) catch |err| switch (err) {
            error.InvalidCertPath, error.LoadCertFailed => return error.LoadCertFailed,
            error.InvalidKeyPath, error.LoadKeyFailed => return error.LoadKeyFailed,
            error.NoTlsMethod => return error.NoTlsMethod,
            error.SslCtxNew => return error.SslCtxNew,
            error.OutOfMemory => return error.OutOfMemory,
        };
        break :blk ctx;
    } else null;
    defer if (server_tls_ctx) |ctx| ssl.SSL_CTX_free(ctx);

    var group: Io.Group = .init;
    defer group.await(io) catch |err| {
        log.warn("h2 server: task group await failed during shutdown: {s}", .{@errorName(err)});
    };

    var next_connection_id: u64 = 1;

    while (!shutdown.load(.acquire)) {
        const stream = tcp_server.accept(io) catch |err| {
            if (shutdown.load(.acquire)) break;
            log.err("h2 server: accept failed: {s}", .{@errorName(err)});
            continue;
        };

        const connection_id = next_connection_id;
        next_connection_id +%= 1;
        if (next_connection_id == 0) next_connection_id = 1;

        group.concurrent(io, handleAcceptedConnection, .{ Handler, handler, cfg.h2, stream, io, connection_id, server_tls_ctx }) catch |err| {
            log.err("h2 server: failed to spawn connection task: {s}", .{@errorName(err)});
            stream.close(io);
        };
    }
}

fn handleAcceptedConnection(
    comptime Handler: type,
    handler: *Handler,
    runtime_cfg: config.H2Config,
    stream: Io.net.Stream,
    io: Io,
    connection_id: u64,
    server_tls_ctx: ?*ssl.SSL_CTX,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(stream.socket.handle >= 0);
    assert(connection_id > 0);

    _ = set_tcp_no_delay(stream.socket.handle);
    defer stream.close(io);

    if (server_tls_ctx) |ctx| {
        var tls_stream = TLSStream.initServer(ctx, @intCast(stream.socket.handle), std.heap.c_allocator) catch |err| {
            log.warn("h2 server: conn={d} tls handshake failed: {s}", .{ connection_id, @errorName(err) });
            return;
        };
        defer tls_stream.close();

        serveTlsConnection(Handler, handler, runtime_cfg, &tls_stream, io, connection_id) catch |err| switch (err) {
            error.ConnectionClosed => {},
            else => log.warn("h2 server: conn={d} tls driver failed: {s}", .{ connection_id, @errorName(err) }),
        };
        return;
    }

    servePlainConnection(Handler, handler, runtime_cfg, @intCast(stream.socket.handle), io, connection_id) catch |err| switch (err) {
        error.ConnectionClosed => {},
        else => log.warn("h2 server: conn={d} plain driver failed: {s}", .{ connection_id, @errorName(err) }),
    };
}

/// Options that adjust plain-connection bootstrap behavior.
/// Set `local_settings_already_sent` when the server SETTINGS frame has already been written before entering the driver.
/// The runtime still expects the peer ACK and validates it either way.
/// Defaults to `false`.
pub const PlainConnectionOptions = struct {
    /// Caller has already sent server SETTINGS for this connection.
    /// Runtime still expects an ACK and will validate it.
    local_settings_already_sent: bool = false,
};

/// Serve a plain connection with pre-read bytes and default plain-connection options.
/// Equivalent to calling `servePlainConnectionWithInitialBytesOptions(..., .{})`.
/// `fd` must be non-negative and remains owned by the caller.
/// Propagates any error returned by the optioned wrapper.
pub fn servePlainConnectionWithInitialBytes(
    comptime Handler: type,
    handler: *Handler,
    runtime_cfg: config.H2Config,
    fd: i32,
    io: Io,
    connection_id: u64,
    initial_bytes: []const u8,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(fd >= 0);

    return servePlainConnectionWithInitialBytesOptions(
        Handler,
        handler,
        runtime_cfg,
        fd,
        io,
        connection_id,
        initial_bytes,
        .{},
    );
}

/// Serve a TLS connection with pre-read bytes and default plain-connection options.
/// Equivalent to calling `serveTlsConnectionWithInitialBytesOptions(..., .{})`.
/// `tls_stream` is borrowed for the duration of the call and is not closed by this helper.
/// Propagates any error returned by the optioned wrapper.
pub fn serveTlsConnectionWithInitialBytes(
    comptime Handler: type,
    handler: *Handler,
    runtime_cfg: config.H2Config,
    tls_stream: *TLSStream,
    io: Io,
    connection_id: u64,
    initial_bytes: []const u8,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(tls_stream) != 0);

    return serveTlsConnectionWithInitialBytesOptions(
        Handler,
        handler,
        runtime_cfg,
        tls_stream,
        io,
        connection_id,
        initial_bytes,
        .{},
    );
}

/// Serve a plain connection with pre-read bytes and explicit plain-connection options.
/// `fd` must be a non-negative, open file descriptor and remains owned by the caller.
/// Initializes plain connection I/O and forwards to the shared connection driver without closing the descriptor.
/// Returns any error raised by the shared driver.
pub fn servePlainConnectionWithInitialBytesOptions(
    comptime Handler: type,
    handler: *Handler,
    runtime_cfg: config.H2Config,
    fd: i32,
    io: Io,
    connection_id: u64,
    initial_bytes: []const u8,
    options: PlainConnectionOptions,
) Error!void {
    assert(fd >= 0);
    assert(@intFromPtr(handler) != 0);
    var io_conn = ConnectionIo.initPlain(fd);
    return serveConnectionWithInitialBytesOptions(
        Handler,
        handler,
        runtime_cfg,
        &io_conn,
        io,
        connection_id,
        initial_bytes,
        options,
    );
}

/// Serve a TLS connection with pre-read bytes and explicit plain-connection options.
/// `tls_stream` is borrowed for the call; this wrapper does not take ownership of the TLS stream.
/// Initializes a connection I/O view over the TLS stream and forwards to the shared connection driver.
/// Returns any error raised by the shared driver.
pub fn serveTlsConnectionWithInitialBytesOptions(
    comptime Handler: type,
    handler: *Handler,
    runtime_cfg: config.H2Config,
    tls_stream: *TLSStream,
    io: Io,
    connection_id: u64,
    initial_bytes: []const u8,
    options: PlainConnectionOptions,
) Error!void {
    assert(@intFromPtr(tls_stream) != 0);
    assert(@intFromPtr(handler) != 0);
    var io_conn = ConnectionIo.initTls(tls_stream);
    return serveConnectionWithInitialBytesOptions(
        Handler,
        handler,
        runtime_cfg,
        &io_conn,
        io,
        connection_id,
        initial_bytes,
        options,
    );
}

fn serveConnectionWithInitialBytesOptions(
    comptime Handler: type,
    handler: *Handler,
    runtime_cfg: config.H2Config,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    initial_bytes: []const u8,
    options: PlainConnectionOptions,
) Error!void {
    comptime verifyHandler(Handler);

    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(io_conn) != 0);
    assert(initial_bytes.len <= read_buffer_size_bytes);

    var runtime = try runtime_mod.Runtime.init(runtime_cfg);
    var response_states = ResponseStateTable{};
    var stream_trackers = StreamTrackerTable{};
    var connection_mutex: Io.Mutex = .init;
    var plain_read_buf: [config.STREAM_READ_BUFFER_SIZE_BYTES]u8 = undefined;
    var plain_reader: Io.net.Stream.Reader = undefined;
    const maybe_plain_reader = initMaybePlainReader(io_conn, io, &plain_read_buf, &plain_reader);

    log.debug("server: conn={d} h2 server driver start initial_bytes={d} settings_already_sent={}", .{
        connection_id,
        initial_bytes.len,
        options.local_settings_already_sent,
    });
    try sendInitialServerSettings(io_conn, io, connection_id, &runtime, options.local_settings_already_sent);

    var recv_buf: [read_buffer_size_bytes]u8 = undefined;
    var buffer_len: usize = undefined;
    initReceiveBuffer(&recv_buf, &buffer_len, initial_bytes);
    try consumeClientPrefaceFromBuffer(
        io_conn,
        maybe_plain_reader,
        io,
        &runtime,
        &recv_buf,
        &buffer_len,
        connection_id,
    );

    var background_writer = ResponseWriter{
        .io_conn = io_conn,
        .io = io,
        .connection_id = connection_id,
        .stream_id = 0,
        .runtime = &runtime,
        .states = &response_states,
        .stream_trackers = &stream_trackers,
    };
    startBackgroundTasksIfPresent(Handler, handler, &background_writer, &connection_mutex, connection_id);
    defer stopBackgroundTasksIfPresent(Handler, handler);

    try runConnectionFrameLoop(
        Handler,
        handler,
        io_conn,
        maybe_plain_reader,
        io,
        connection_id,
        &runtime,
        &response_states,
        &stream_trackers,
        &connection_mutex,
        &recv_buf,
        &buffer_len,
    );
}

fn applyUpgradePeerSettings(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    settings_payload: []const u8,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(settings_payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);

    const peer_settings_header = h2.FrameHeader{
        .length = @intCast(settings_payload.len),
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    };
    const peer_settings_action = runtime.receiveFrame(peer_settings_header, settings_payload) catch |err| {
        try sendRuntimeErrorGoAway(runtime, io_conn, io, 0, err);
        closeTrackedStreamsForFatalError(Handler, handler, connection_id, stream_trackers, err);
        return err;
    };
    handleAction(Handler, handler, io_conn, io, connection_id, runtime, response_states, stream_trackers, peer_settings_action) catch |err| {
        closeTrackedStreamsForFatalError(Handler, handler, connection_id, stream_trackers, err);
        return err;
    };
    try flushPendingResponseData(runtime, io_conn, io, response_states, stream_trackers);
    closeCompletedStreams(Handler, handler, connection_id, stream_trackers);
}

fn applyUpgradeSyntheticHeaders(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    request: *const Request,
    settings_payload: []const u8,
    total_body_bytes: u64,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(request) != 0);

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
        try sendRuntimeErrorGoAway(runtime, io_conn, io, headers_header.stream_id, err);
        closeTrackedStreamsForFatalError(Handler, handler, connection_id, stream_trackers, err);
        return err;
    };
    try handleAction(Handler, handler, io_conn, io, connection_id, runtime, response_states, stream_trackers, headers_action);
    try flushPendingResponseData(runtime, io_conn, io, response_states, stream_trackers);
    closeCompletedStreams(Handler, handler, connection_id, stream_trackers);
}

/// Serve an upgraded HTTP/2 connection on a plain file descriptor.
/// `request`, `settings_payload`, `initial_body`, and `initial_client_h2_bytes` are borrowed inputs and must stay valid for the duration of the call.
/// Validates the handler at comptime, initializes per-connection runtime state, and starts background tasks when the handler provides them.
/// Returns bootstrap, frame-processing, I/O, or runtime errors encountered while driving the upgraded body and frame loop.
pub fn serveUpgradedConnection(
    comptime Handler: type,
    handler: *Handler,
    fd: i32,
    io: Io,
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

    var io_conn = ConnectionIo.initPlain(fd);
    var plain_read_buf: [config.STREAM_READ_BUFFER_SIZE_BYTES]u8 = undefined;
    var plain_reader = rawStreamForFd(fd).reader(io, &plain_read_buf);

    var runtime = try runtime_mod.Runtime.init(.{});
    var response_states = ResponseStateTable{};
    var stream_trackers = StreamTrackerTable{};
    var connection_mutex: Io.Mutex = .init;
    try bootstrapUpgradedConnection(Handler, handler, &io_conn, io, connection_id, &runtime, &response_states, &stream_trackers, settings_payload);

    var background_writer = ResponseWriter{
        .io_conn = &io_conn,
        .io = io,
        .connection_id = connection_id,
        .stream_id = 0,
        .runtime = &runtime,
        .states = &response_states,
        .stream_trackers = &stream_trackers,
    };
    startBackgroundTasksIfPresent(Handler, handler, &background_writer, &connection_mutex, connection_id);
    defer stopBackgroundTasksIfPresent(Handler, handler);

    try runUpgradedBodyAndFrameLoop(
        Handler,
        handler,
        &io_conn,
        &plain_reader,
        io,
        connection_id,
        &runtime,
        &response_states,
        &stream_trackers,
        request,
        settings_payload,
        initial_body,
        remaining_body_bytes,
        &connection_mutex,
        initial_client_h2_bytes,
    );
}

fn runUpgradedBodyAndFrameLoop(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    plain_reader: *Io.net.Stream.Reader,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    request: *const Request,
    settings_payload: []const u8,
    initial_body: []const u8,
    remaining_body_bytes: u64,
    connection_mutex: *Io.Mutex,
    initial_client_h2_bytes: []const u8,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(request) != 0);
    assert(initial_client_h2_bytes.len <= read_buffer_size_bytes);

    processUpgradeSyntheticRequestAndBody(
        Handler,
        handler,
        io_conn,
        plain_reader,
        io,
        connection_id,
        runtime,
        response_states,
        stream_trackers,
        request,
        settings_payload,
        initial_body,
        remaining_body_bytes,
    ) catch |err| {
        closeTrackedStreamsForFatalError(Handler, handler, connection_id, stream_trackers, err);
        return err;
    };

    var recv_buf: [read_buffer_size_bytes]u8 = undefined;
    var buffer_len: usize = undefined;
    initReceiveBuffer(&recv_buf, &buffer_len, initial_client_h2_bytes);
    consumeOptionalUpgradeClientPreface(io_conn, plain_reader, io, &recv_buf, &buffer_len) catch |err| {
        try sendRuntimeErrorGoAway(runtime, io_conn, io, 0, err);
        closeTrackedStreamsForFatalError(Handler, handler, connection_id, stream_trackers, err);
        return err;
    };
    try runConnectionFrameLoop(
        Handler,
        handler,
        io_conn,
        plain_reader,
        io,
        connection_id,
        runtime,
        response_states,
        stream_trackers,
        connection_mutex,
        &recv_buf,
        &buffer_len,
    );
}

fn handleAction(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    action: runtime_mod.ReceiveAction,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);
    assert(@intFromPtr(stream_trackers) != 0);

    switch (action) {
        .none => {},
        .send_settings_ack => try handleSendSettingsAckAction(io_conn, io, connection_id, runtime),
        .send_ping_ack => |opaque_data| try handleSendPingAckAction(io_conn, io, connection_id, opaque_data),
        .request_headers => |headers| try handleRequestHeadersAction(
            Handler,
            handler,
            io_conn,
            io,
            connection_id,
            runtime,
            response_states,
            stream_trackers,
            headers,
        ),
        .request_data => |data| try handleRequestDataAction(
            Handler,
            handler,
            io_conn,
            io,
            connection_id,
            runtime,
            response_states,
            stream_trackers,
            data,
        ),
        .stream_reset => |reset| handleStreamResetAction(
            Handler,
            handler,
            connection_id,
            response_states,
            stream_trackers,
            reset,
        ),
        .connection_close => |goaway| handleConnectionCloseAction(
            Handler,
            handler,
            connection_id,
            stream_trackers,
            goaway,
        ),
    }
}

fn handleSendSettingsAckAction(
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);

    log.debug("server: conn={d} h2 sending settings ack", .{connection_id});
    var ack_buf: [h2.frame_header_size_bytes]u8 = undefined;
    const ack = try runtime.writePendingSettingsAck(&ack_buf);
    try writeAll(io_conn, io, ack);
}

fn handleSendPingAckAction(
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    opaque_data: [h2.control.ping_payload_size_bytes]u8,
) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(h2.control.ping_payload_size_bytes == 8);

    log.debug("server: conn={d} h2 sending ping ack", .{connection_id});
    var ack_buf: [h2.frame_header_size_bytes + h2.control.ping_payload_size_bytes]u8 = undefined;
    const ack = try runtime_mod.Runtime.writePingAckFrame(&ack_buf, opaque_data);
    try writeAll(io_conn, io, ack);
}

fn makeResponseWriter(
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    stream_id: u32,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
) ResponseWriter {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);
    assert(stream_id > 0);

    return .{
        .io_conn = io_conn,
        .io = io,
        .connection_id = connection_id,
        .stream_id = stream_id,
        .runtime = runtime,
        .states = response_states,
        .stream_trackers = stream_trackers,
    };
}

fn handleRequestHeadersAction(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    headers: runtime_mod.RequestHeadersAction,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(headers.stream_id > 0);

    log.debug("server: conn={d} h2 dispatch request headers stream={d} end_stream={} method={s} path={s}", .{
        connection_id,
        headers.stream_id,
        headers.end_stream,
        @tagName(headers.request.method),
        headers.request.path,
    });
    const opened = try stream_trackers.markRequestHeaders(headers.stream_id, headers.end_stream);
    if (opened and comptime @hasDecl(Handler, "handleH2StreamOpen")) {
        handler.handleH2StreamOpen(headers.stream_id, &headers.request);
    }

    var writer = makeResponseWriter(io_conn, io, connection_id, headers.stream_id, runtime, response_states, stream_trackers);
    handler.handleH2Headers(headers.stream_id, &headers.request, headers.end_stream, &writer) catch |err| {
        try handleHandlerFailure(Handler, handler, io_conn, io, connection_id, runtime, response_states, stream_trackers, headers.stream_id, "headers", err);
    };
    closeCompletedStreams(Handler, handler, connection_id, stream_trackers);
}

fn handleRequestDataAction(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    data: runtime_mod.RequestDataAction,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(data.stream_id > 0);

    log.debug("server: conn={d} h2 dispatch request data stream={d} payload_bytes={d} end_stream={}", .{
        connection_id,
        data.stream_id,
        data.payload.len,
        data.end_stream,
    });
    try stream_trackers.markRequestData(data.stream_id, data.payload.len, data.end_stream);
    try replenishReceiveWindows(io_conn, io, runtime, data.stream_id, data.payload.len);

    var writer = makeResponseWriter(io_conn, io, connection_id, data.stream_id, runtime, response_states, stream_trackers);
    handler.handleH2Data(data.stream_id, data.payload, data.end_stream, &writer) catch |err| {
        try handleHandlerFailure(Handler, handler, io_conn, io, connection_id, runtime, response_states, stream_trackers, data.stream_id, "data", err);
    };
    closeCompletedStreams(Handler, handler, connection_id, stream_trackers);
}

fn handleHandlerFailure(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    stream_id: u32,
    phase: []const u8,
    err: anyerror,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(stream_id > 0);

    const reset_error_code_raw = mapHandlerErrorToResetCodeRaw(err);
    log.debug(
        "server: conn={d} h2 request {s} handler failed stream={d} err={s} reset=0x{x}",
        .{ connection_id, phase, stream_id, @errorName(err), reset_error_code_raw },
    );
    response_states.remove(stream_id);
    closeStreamWithReason(
        Handler,
        handler,
        connection_id,
        stream_trackers,
        stream_id,
        .local_reset,
        reset_error_code_raw,
    );
    try sendErrorReset(io_conn, io, runtime, stream_id, reset_error_code_raw);
}

fn handleStreamResetAction(
    comptime Handler: type,
    handler: *Handler,
    connection_id: u64,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    reset: runtime_mod.StreamResetAction,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(reset.stream_id > 0);

    log.debug("server: conn={d} h2 received stream reset stream={d} error_code=0x{x}", .{
        connection_id,
        reset.stream_id,
        reset.error_code_raw,
    });
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
}

fn handleConnectionCloseAction(
    comptime Handler: type,
    handler: *Handler,
    connection_id: u64,
    stream_trackers: *StreamTrackerTable,
    goaway: h2.GoAway,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(goaway.last_stream_id <= 0x7fff_ffff);

    log.debug("server: conn={d} h2 received goaway last_stream={d} error_code=0x{x}", .{
        connection_id,
        goaway.last_stream_id,
        goaway.error_code_raw,
    });
    closeTrackedStreamsForGoAway(
        Handler,
        handler,
        connection_id,
        stream_trackers,
        goaway,
    );
    if (comptime @hasDecl(Handler, "handleH2ConnectionClose")) {
        handler.handleH2ConnectionClose(goaway);
    }
}

fn flushPendingResponseData(
    runtime: *runtime_mod.Runtime,
    io_conn: *ConnectionIo,
    io: Io,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
) Error!void {
    assert(@intFromPtr(runtime) != 0);
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(response_states) != 0);
    assert(@intFromPtr(stream_trackers) != 0);

    var index: usize = 0;
    while (index < response_states.slots.len) : (index += 1) {
        var state = &response_states.slots[index];
        if (!state.used) continue;
        if (state.closed) continue;

        const ended_stream = try flushResponseStatePendingData(io_conn, io, runtime, state, stream_trackers);
        if (!ended_stream) continue;

        const stream_id = state.stream_id;
        try runtime.state.endLocalStream(stream_id);
        state.closed = true;
        response_states.remove(stream_id);
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
        log.debug(
            "h2: conn={d} close completed stream={d} remote_end={any} local_end={any} status={d} req_bytes={d} resp_bytes={d}",
            .{
                connection_id,
                tracker.stream_id,
                tracker.remote_end_stream,
                tracker.local_end_stream,
                tracker.response_status,
                tracker.request_data_bytes,
                tracker.response_data_bytes,
            },
        );
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
    log.debug(
        "h2: conn={d} close stream with reason stream={d} reason={s} remote_end={any} local_end={any} reset=0x{x}",
        .{
            connection_id,
            tracker.stream_id,
            @tagName(reason),
            tracker.remote_end_stream,
            tracker.local_end_stream,
            reset_error_code_raw,
        },
    );
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
        log.debug(
            "h2: conn={d} close all tracked stream={d} reason={s} remote_end={any} local_end={any} reset=0x{x}",
            .{
                connection_id,
                tracker.stream_id,
                @tagName(reason),
                tracker.remote_end_stream,
                tracker.local_end_stream,
                reset_error_code_raw,
            },
        );
        emitStreamCloseHook(Handler, handler, connection_id, tracker, reason, reset_error_code_raw);
    }
}

fn closeTrackedStreamsForGoAway(
    comptime Handler: type,
    handler: *Handler,
    connection_id: u64,
    stream_trackers: *StreamTrackerTable,
    goaway: h2.GoAway,
) void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(stream_trackers) != 0);
    assert(goaway.last_stream_id <= 0x7fff_ffff);

    if (goaway.error_code_raw != @intFromEnum(h2.ErrorCode.no_error)) {
        closeAllTrackedStreams(
            Handler,
            handler,
            connection_id,
            stream_trackers,
            .connection_close,
            goaway.error_code_raw,
        );
        return;
    }

    for (stream_trackers.slots[0..], 0..) |*slot, index| {
        if (!slot.used) continue;
        if (slot.stream_id <= goaway.last_stream_id) continue;

        const tracker = stream_trackers.popByIndex(index);
        log.debug(
            "h2: conn={d} close goaway affected stream={d} last_stream_id={d} remote_end={any} local_end={any}",
            .{
                connection_id,
                tracker.stream_id,
                goaway.last_stream_id,
                tracker.remote_end_stream,
                tracker.local_end_stream,
            },
        );
        emitStreamCloseHook(
            Handler,
            handler,
            connection_id,
            tracker,
            .connection_close,
            @intFromEnum(h2.ErrorCode.refused_stream),
        );
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
    io_conn: *ConnectionIo,
    plain_reader: *Io.net.Stream.Reader,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    initial_body: []const u8,
    remaining_body_bytes: u64,
) Error!void {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(plain_reader) != 0);

    var initial_cursor: usize = 0;
    var remaining: u64 = remaining_body_bytes;

    while (initial_cursor < initial_body.len) {
        const chunk_len = @min(initial_body.len - initial_cursor, config.H2_MAX_FRAME_SIZE_BYTES);
        const is_last_chunk = (initial_cursor + chunk_len == initial_body.len) and (remaining == 0);

        try processUpgradeBodyChunk(
            Handler,
            handler,
            io_conn,
            io,
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
        const n = try readSome(io_conn, plain_reader, io, body_buf[0..max_read]);
        if (n == 0) return error.ConnectionClosed;

        const read_bytes: u64 = @intCast(n);
        assert(read_bytes <= remaining);
        remaining -= read_bytes;

        try processUpgradeBodyChunk(
            Handler,
            handler,
            io_conn,
            io,
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
    io_conn: *ConnectionIo,
    io: Io,
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
        if (try tryHandleRecoverableStreamError(
            Handler,
            handler,
            io_conn,
            io,
            connection_id,
            runtime,
            response_states,
            stream_trackers,
            data_header,
            err,
        )) {
            return;
        }

        try sendRuntimeErrorGoAway(runtime, io_conn, io, 1, err);
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
    handleAction(Handler, handler, io_conn, io, connection_id, runtime, response_states, stream_trackers, action) catch |err| {
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

    try flushPendingResponseData(runtime, io_conn, io, response_states, stream_trackers);
    closeCompletedStreams(Handler, handler, connection_id, stream_trackers);
}

fn replenishReceiveWindows(io_conn: *ConnectionIo, io: Io, runtime: *runtime_mod.Runtime, stream_id: u32, consumed_bytes: usize) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);
    assert(stream_id > 0);
    assert(consumed_bytes <= config.H2_MAX_FRAME_SIZE_BYTES);

    if (consumed_bytes == 0) return;

    const increment_bytes: u32 = @intCast(consumed_bytes);
    try runtime.state.incrementRecvWindow(increment_bytes);
    try runtime.state.incrementStreamRecvWindow(stream_id, increment_bytes);

    var conn_update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const conn_update = try h2.buildWindowUpdateFrame(&conn_update_buf, 0, increment_bytes);
    try writeAll(io_conn, io, conn_update);

    var stream_update_buf: [h2.frame_header_size_bytes + h2.control.window_update_payload_size_bytes]u8 = undefined;
    const stream_update = try h2.buildWindowUpdateFrame(&stream_update_buf, stream_id, increment_bytes);
    try writeAll(io_conn, io, stream_update);
}

fn sendErrorReset(io_conn: *ConnectionIo, io: Io, runtime: *runtime_mod.Runtime, stream_id: u32, error_code_raw: u32) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(stream_id > 0);

    var rst_buf: [h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst = try runtime.writeRstStreamFrame(&rst_buf, .{
        .stream_id = stream_id,
        .error_code_raw = error_code_raw,
    });
    try writeAll(io_conn, io, rst);
}

fn mapHandlerErrorToResetCodeRaw(err: anyerror) u32 {
    assert(@intFromEnum(h2.ErrorCode.cancel) != 0);
    assert(@intFromEnum(h2.ErrorCode.internal_error) != 0);

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

fn tryHandleRecoverableStreamError(
    comptime Handler: type,
    handler: *Handler,
    io_conn: *ConnectionIo,
    io: Io,
    connection_id: u64,
    runtime: *runtime_mod.Runtime,
    response_states: *ResponseStateTable,
    stream_trackers: *StreamTrackerTable,
    header: h2.FrameHeader,
    err: anyerror,
) Error!bool {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(runtime) != 0);
    assert(@intFromPtr(response_states) != 0);
    assert(@intFromPtr(stream_trackers) != 0);

    if (header.stream_id == 0) return false;

    const reset_error_code_raw: u32 = switch (err) {
        error.StreamProtocolError => @intFromEnum(h2.ErrorCode.protocol_error),
        error.StreamRefused => @intFromEnum(h2.ErrorCode.refused_stream),
        error.StreamFlowControlError => @intFromEnum(h2.ErrorCode.flow_control_error),
        error.StreamClosedError => @intFromEnum(h2.ErrorCode.stream_closed),
        else => return false,
    };

    response_states.remove(header.stream_id);
    closeStreamWithReason(
        Handler,
        handler,
        connection_id,
        stream_trackers,
        header.stream_id,
        .local_reset,
        reset_error_code_raw,
    );
    sendErrorReset(io_conn, io, runtime, header.stream_id, reset_error_code_raw) catch |write_err| switch (write_err) {
        error.ConnectionClosed => {},
        else => return write_err,
    };

    return true;
}

fn sendRuntimeErrorGoAway(runtime: *runtime_mod.Runtime, io_conn: *ConnectionIo, io: Io, stream_id: u32, err: anyerror) Error!void {
    assert(@intFromPtr(runtime) != 0);
    assert(@intFromPtr(io_conn) != 0);
    assert(stream_id <= 0x7fff_ffff);

    var goaway_buf: [frame_buffer_size_bytes]u8 = undefined;
    const goaway = try runtime.writeGoAwayFrame(&goaway_buf, .{
        .last_stream_id = stream_id,
        .error_code_raw = @intFromEnum(mapGoAwayError(err)),
        .debug_data = @errorName(err),
    });
    try writeAll(io_conn, io, goaway);
}

fn logRuntimeFrameError(connection_id: u64, header: h2.FrameHeader, err: anyerror) void {
    assert(header.stream_id <= 0x7fff_ffff);
    assert(header.length <= config.H2_MAX_FRAME_SIZE_BYTES);

    log.warn(
        "h2: conn={d} frame_err frame_type={s} stream_id={d} flags=0x{x} length={d} err={s} goaway={s}",
        .{
            connection_id,
            @tagName(header.frame_type),
            header.stream_id,
            header.flags,
            header.length,
            @errorName(err),
            @tagName(mapGoAwayError(err)),
        },
    );
}

fn mapGoAwayError(err: anyerror) h2.ErrorCode {
    assert(@intFromEnum(h2.ErrorCode.internal_error) != 0);
    assert(@intFromEnum(h2.ErrorCode.protocol_error) != 0);

    return switch (err) {
        error.FrameTooLarge => .frame_size_error,
        error.WindowOverflow,
        error.WindowUnderflow,
        error.InvalidIncrement,
        error.StreamFlowControlError,
        => .flow_control_error,
        error.ConnectionStreamClosedError => .stream_closed,
        error.ConnectionProtocolError,
        error.ConnectionClosing,
        error.InvalidDataStream,
        error.UnsupportedContinuation,
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

fn consumeOptionalUpgradeClientPreface(
    io_conn: *ConnectionIo,
    maybe_plain_reader: ?*Io.net.Stream.Reader,
    io: Io,
    recv_buf: *[read_buffer_size_bytes]u8,
    buffer_len: *usize,
) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(buffer_len.* <= recv_buf.len);

    if (buffer_len.* == 0) {
        const n = try readIntoBuffer(io_conn, maybe_plain_reader, io, recv_buf, buffer_len);
        if (n == 0) return;
    }

    if (buffer_len.* == 0) return;
    if (!h2.looksLikeClientConnectionPrefacePrefix(recv_buf[0..1])) return;

    fillBuffer(io_conn, maybe_plain_reader, io, recv_buf, buffer_len, h2.client_connection_preface.len) catch |err| switch (err) {
        error.ConnectionClosed => return error.InvalidPreface,
        else => return err,
    };
    if (!h2.looksLikeClientConnectionPreface(recv_buf[0..buffer_len.*])) return error.InvalidPreface;

    discardPrefix(recv_buf, buffer_len, h2.client_connection_preface.len);
}

fn ensureFrame(
    io_conn: *ConnectionIo,
    maybe_plain_reader: ?*Io.net.Stream.Reader,
    io: Io,
    recv_buf: *[read_buffer_size_bytes]u8,
    buffer_len: *usize,
) Error!bool {
    assert(@intFromPtr(io_conn) != 0);
    assert(@intFromPtr(recv_buf) != 0);

    if (buffer_len.* == 0) {
        const n = try readIntoBuffer(io_conn, maybe_plain_reader, io, recv_buf, buffer_len);
        if (n == 0) return false;
    }

    try fillBuffer(io_conn, maybe_plain_reader, io, recv_buf, buffer_len, h2.frame_header_size_bytes);
    const header = try h2.parseFrameHeader(recv_buf[0..h2.frame_header_size_bytes]);
    const frame_len: usize = h2.frame_header_size_bytes + header.length;
    try fillBuffer(io_conn, maybe_plain_reader, io, recv_buf, buffer_len, frame_len);
    return true;
}

fn fillBuffer(
    io_conn: *ConnectionIo,
    maybe_plain_reader: ?*Io.net.Stream.Reader,
    io: Io,
    recv_buf: *[read_buffer_size_bytes]u8,
    buffer_len: *usize,
    needed_len: usize,
) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(needed_len <= recv_buf.len);

    var reads: usize = 0;
    while (buffer_len.* < needed_len and reads < recv_buf.len) : (reads += 1) {
        const n = try readIntoBuffer(io_conn, maybe_plain_reader, io, recv_buf, buffer_len);
        if (n == 0) return error.ConnectionClosed;
    }

    if (buffer_len.* < needed_len) return error.ReadFailed;
}

fn readIntoBuffer(
    io_conn: *ConnectionIo,
    maybe_plain_reader: ?*Io.net.Stream.Reader,
    io: Io,
    recv_buf: *[read_buffer_size_bytes]u8,
    buffer_len: *usize,
) Error!usize {
    assert(@intFromPtr(io_conn) != 0);
    assert(buffer_len.* <= recv_buf.len);

    const n = try readSome(io_conn, maybe_plain_reader, io, recv_buf[buffer_len.*..]);
    buffer_len.* += n;
    return n;
}

fn discardPrefix(recv_buf: *[read_buffer_size_bytes]u8, buffer_len: *usize, prefix_len: usize) void {
    assert(prefix_len <= buffer_len.*);
    assert(buffer_len.* <= recv_buf.len);

    if (prefix_len == buffer_len.*) {
        buffer_len.* = 0;
        return;
    }

    std.mem.copyForwards(u8, recv_buf[0 .. buffer_len.* - prefix_len], recv_buf[prefix_len..buffer_len.*]);
    buffer_len.* -= prefix_len;
}

fn readSome(
    io_conn: *ConnectionIo,
    maybe_plain_reader: ?*Io.net.Stream.Reader,
    io: Io,
    out: []u8,
) Error!usize {
    assert(@intFromPtr(io_conn) != 0);
    assert(out.len > 0);

    return switch (io_conn.*) {
        .plain_fd => |fd| blk: {
            _ = maybe_plain_reader;
            var bufs: [1][]u8 = .{out};
            const n = io.vtable.netRead(io.userdata, fd, &bufs) catch |read_err| {
                return switch (read_err) {
                    error.ConnectionResetByPeer,
                    error.SocketUnconnected,
                    => error.ConnectionClosed,
                    else => error.ReadFailed,
                };
            };
            break :blk n;
        },
        .tls_stream => |tls_stream| blk: {
            const readiness_timeout = timeoutForNanoseconds(tls_read_readiness_timeout_ns);
            var retry_count: u32 = 0;
            while (retry_count < read_max_retry_count) : (retry_count += 1) {
                if (!tls_stream.hasPendingRead()) {
                    try waitUntilReadableTls(tls_stream.fd, io, readiness_timeout);
                }

                const n: u32 = tls_stream.read(out) catch |err| switch (err) {
                    error.WantRead, error.WantWrite => continue,
                    error.ConnectionReset => return error.ConnectionClosed,
                    else => return error.ReadFailed,
                };
                break :blk @intCast(n);
            }

            return error.ReadFailed;
        },
    };
}

fn timeoutForNanoseconds(timeout_ns: u64) Io.Timeout {
    assert(timeout_ns > 0);
    return .{ .duration = .{
        .raw = Io.Duration.fromNanoseconds(@intCast(timeout_ns)),
        .clock = .awake,
    } };
}

fn waitUntilReadable(fd: i32, io: Io, timeout: Io.Timeout) Error!void {
    assert(fd >= 0);
    assert(tls_read_readiness_timeout_ns > 0);

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
        error.Timeout => return error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        => return error.ConnectionClosed,
        else => return error.ReadFailed,
    };
}

const tls_readiness_poll_sleep_ms: i64 = 1;
const tls_readiness_max_poll_iterations: u32 = 120_000;

fn waitUntilReadableTls(fd: i32, io: Io, timeout: Io.Timeout) Error!void {
    assert(fd >= 0);
    assert(tls_readiness_max_poll_iterations > 0);

    var poll_fds = [_]posix.pollfd{
        .{
            .fd = fd,
            .events = posix.POLL.IN,
            .revents = 0,
        },
    };
    const maybe_deadline = timeout.toTimestamp(io);
    var iterations: u32 = 0;
    while (iterations < tls_readiness_max_poll_iterations) : (iterations += 1) {
        poll_fds[0].revents = 0;
        const polled = posix.poll(&poll_fds, 0) catch return error.ReadFailed;
        if (polled > 0) {
            const revents = poll_fds[0].revents;
            if ((revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) return error.ReadFailed;
            if ((revents & posix.POLL.HUP) != 0) return error.ConnectionClosed;
            if ((revents & posix.POLL.IN) != 0) return;
        }

        if (maybe_deadline) |deadline| {
            const remaining = deadline.durationFromNow(io);
            if (remaining.raw.toNanoseconds() <= 0) return error.ConnectionClosed;
        }

        std.Io.sleep(io, Io.Duration.fromMilliseconds(tls_readiness_poll_sleep_ms), .awake) catch {
            return error.ReadFailed;
        };
    }

    return error.ReadFailed;
}

fn writeSome(io_conn: *ConnectionIo, io: Io, out: []const u8) Error!usize {
    assert(@intFromPtr(io_conn) != 0);
    assert(out.len > 0);

    return switch (io_conn.*) {
        .plain_fd => |fd| blk: {
            var write_buf: [config.SERVER_WRITE_BUFFER_SIZE_BYTES]u8 = undefined;
            var writer = rawStreamForFd(fd).writer(io, &write_buf);
            writer.interface.writeAll(out) catch {
                const write_err = writer.err orelse error.Unexpected;
                return switch (write_err) {
                    error.SystemResources => error.WouldBlock,
                    error.ConnectionResetByPeer,
                    error.SocketUnconnected,
                    => error.ConnectionClosed,
                    else => error.WriteFailed,
                };
            };
            if (writer.interface.buffered().len > 0) {
                writer.interface.flush() catch {
                    const flush_err = writer.err orelse error.Unexpected;
                    return switch (flush_err) {
                        error.SystemResources => error.WouldBlock,
                        error.ConnectionResetByPeer,
                        error.SocketUnconnected,
                        => error.ConnectionClosed,
                        else => error.WriteFailed,
                    };
                };
            }
            break :blk out.len;
        },
        .tls_stream => |tls_stream| blk: {
            const n: u32 = tls_stream.write(out) catch |err| switch (err) {
                error.WouldBlock => return error.WouldBlock,
                error.ConnectionReset => return error.ConnectionClosed,
                else => {
                    log.warn(
                        "h2: writeSome failed transport=tls fd={d} tls_err={s} bytes={d}",
                        .{ tls_stream.fd, @errorName(err), out.len },
                    );
                    return error.WriteFailed;
                },
            };
            break :blk @intCast(n);
        },
    };
}

fn rawStreamForFd(fd: i32) Io.net.Stream {
    assert(fd >= 0);
    assert(fd <= std.math.maxInt(i32));
    return .{
        .socket = .{
            .handle = fd,
            .address = .{ .ip4 = .unspecified(0) },
        },
    };
}

fn connectionIoTransportName(io_conn: *const ConnectionIo) []const u8 {
    assert(@intFromPtr(io_conn) != 0);
    assert(@sizeOf(ConnectionIo) > 0);

    return switch (io_conn.*) {
        .plain_fd => "plain",
        .tls_stream => "tls",
    };
}

fn connectionIoFd(io_conn: *const ConnectionIo) i32 {
    assert(@intFromPtr(io_conn) != 0);
    assert(@sizeOf(ConnectionIo) > 0);

    return switch (io_conn.*) {
        .plain_fd => |fd| fd,
        .tls_stream => |tls_stream| tls_stream.fd,
    };
}

fn writeAll(io_conn: *ConnectionIo, io: Io, data: []const u8) Error!void {
    assert(@intFromPtr(io_conn) != 0);
    assert(write_max_retry_count > 0);

    if (data.len == 0) return;

    var written: usize = 0;
    var writes: usize = 0;
    const max_writes: usize = data.len + 1024;
    var retry_count: u32 = 0;
    var last_progress_ns: u64 = time.monotonicNanos();

    while (written < data.len and writes < max_writes) : (writes += 1) {
        const n = writeSome(io_conn, io, data[written..]) catch |err| switch (err) {
            error.WouldBlock => {
                retry_count += 1;
                const now_ns = time.monotonicNanos();
                const since_progress_ns = now_ns -| last_progress_ns;
                if (retry_count >= write_max_retry_count or since_progress_ns >= write_stall_timeout_ns) {
                    log.warn(
                        "h2: writeAll stalled transport={s} fd={d} written={d}/{d} retries={d} since_progress_ns={d}",
                        .{
                            connectionIoTransportName(io_conn),
                            connectionIoFd(io_conn),
                            written,
                            data.len,
                            retry_count,
                            since_progress_ns,
                        },
                    );
                    return error.WriteFailed;
                }
                std.Io.sleep(io, std.Io.Duration.fromNanoseconds(write_retry_sleep_ns), .awake) catch return error.WriteFailed;
                continue;
            },
            else => return err,
        };

        if (n == 0) return error.ConnectionClosed;
        written += n;
        retry_count = 0;
        last_progress_ns = time.monotonicNanos();
    }

    if (written < data.len) {
        log.warn(
            "h2: writeAll incomplete transport={s} fd={d} written={d}/{d} writes={d}",
            .{ connectionIoTransportName(io_conn), connectionIoFd(io_conn), written, data.len, writes },
        );
        return error.WriteFailed;
    }
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
    if (cursor + first_frame_len > out.len) return error.FrameLimitExceeded;
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
        if (continuation_frames >= h2.max_continuation_frames) return error.FrameLimitExceeded;

        const chunk_len: usize = @min(header_block.len - block_cursor, max_payload_size_bytes);
        const is_last_chunk = block_cursor + chunk_len == header_block.len;
        const flags: u8 = if (is_last_chunk) h2.flags_end_headers else 0;

        const frame_len: usize = h2.frame_header_size_bytes + chunk_len;
        if (cursor + frame_len > out.len) return error.FrameLimitExceeded;
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

test "appendHeaderBlockFrames emits HEADERS plus CONTINUATION fragments" {
    const header_block = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    var out: [header_block_frame_buffer_size_bytes]u8 = undefined;
    const frames = try appendHeaderBlockFrames(
        &out,
        1,
        header_block,
        true,
        16,
    );

    var cursor: usize = 0;
    var frame_count: u8 = 0;
    var saw_continuation = false;
    var last_flags: u8 = 0;
    while (cursor < frames.len) {
        try std.testing.expect(frame_count < h2.max_continuation_frames + 1);
        const header = try h2.parseFrameHeader(frames[cursor .. cursor + h2.frame_header_size_bytes]);
        const frame_len: usize = h2.frame_header_size_bytes + header.length;
        try std.testing.expect(cursor + frame_len <= frames.len);
        try std.testing.expectEqual(@as(u32, 1), header.stream_id);

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
    try std.testing.expectEqual(frames.len, cursor);
    try std.testing.expect((last_flags & h2.flags_end_headers) != 0);
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
    try std.testing.expectEqual(h2.ErrorCode.flow_control_error, mapGoAwayError(error.StreamFlowControlError));
    try std.testing.expectEqual(h2.ErrorCode.protocol_error, mapGoAwayError(error.InvalidPreface));
}
