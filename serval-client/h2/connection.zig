//! HTTP/2 Client Connection Driver
//!
//! Bounded socket-owning driver for outbound prior-knowledge h2c sessions.
//! Wraps Runtime frame actions with fixed-buffer socket I/O.
//! TigerStyle: Explicit frame loop bounds, no allocation, no recursion.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;

const config = @import("serval-core").config;
const types = @import("serval-core").types;
const h2 = @import("serval-h2");
const serval_socket = @import("serval-socket");
const runtime_mod = @import("runtime.zig");

const Request = types.Request;
const Socket = serval_socket.Socket;
const SocketError = serval_socket.SocketError;

const read_buffer_size_bytes: usize = h2.frame_header_size_bytes + config.H2_MAX_FRAME_SIZE_BYTES;
const preface_settings_buffer_size_bytes: usize =
    h2.client_connection_preface.len +
    h2.frame_header_size_bytes +
    (4 * h2.setting_size_bytes);
const request_headers_frame_overhead_bytes: usize = h2.frame_header_size_bytes * (@as(usize, config.H2_MAX_CONTINUATION_FRAMES) + 1);
const request_headers_frame_buffer_size_bytes: usize = config.H2_MAX_HEADER_BLOCK_SIZE_BYTES + request_headers_frame_overhead_bytes;
const data_frame_buffer_size_bytes: usize = h2.frame_header_size_bytes + config.H2_MAX_FRAME_SIZE_BYTES;

pub const Error = error{
    ReadFailed,
    WriteFailed,
    ConnectionClosed,
    FrameLimitExceeded,
    SendWindowExhausted,
    UnexpectedHandshakeFrame,
    ConnectionClosing,
} || runtime_mod.Error || h2.FrameError;

pub const ClientConnection = struct {
    socket: *Socket,
    runtime: runtime_mod.Runtime,
    recv_buf: [read_buffer_size_bytes]u8 = undefined,
    recv_len: usize = 0,
    pending_discard_len: usize = 0,
    frame_count: u32 = 0,

    pub fn init(socket: *Socket) Error!ClientConnection {
        assert(@intFromPtr(socket) != 0);
        assert(socket.get_fd() >= 0);

        return .{
            .socket = socket,
            .runtime = try runtime_mod.Runtime.init(),
        };
    }

    pub fn sendClientPrefaceAndSettings(self: *ClientConnection) Error!void {
        assert(@intFromPtr(self) != 0);

        var out: [preface_settings_buffer_size_bytes]u8 = undefined;
        const frame = try self.runtime.writeClientPrefaceAndSettings(&out);
        try self.writeAll(frame);
    }

    pub fn sendPendingSettingsAck(self: *ClientConnection) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.runtime.state.peer_settings_ack_pending);

        var out: [h2.frame_header_size_bytes]u8 = undefined;
        const frame = try self.runtime.writePendingSettingsAck(&out);
        try self.writeAll(frame);
    }

    pub fn sendPingAck(
        self: *ClientConnection,
        opaque_data: [h2.control.ping_payload_size_bytes]u8,
    ) Error!void {
        assert(@intFromPtr(self) != 0);

        var out: [h2.frame_header_size_bytes + h2.control.ping_payload_size_bytes]u8 = undefined;
        const frame = try runtime_mod.Runtime.writePingAckFrame(&out, opaque_data);
        try self.writeAll(frame);
    }

    pub fn completeHandshake(self: *ClientConnection) Error!void {
        assert(@intFromPtr(self) != 0);

        try self.sendClientPrefaceAndSettings();

        var frames: u32 = 0;
        while (frames < config.H2_MAX_INITIAL_PARSE_FRAMES) : (frames += 1) {
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

    pub fn sendRequestHeaders(
        self: *ClientConnection,
        request: *const Request,
        effective_path: ?[]const u8,
        end_stream: bool,
    ) Error!u32 {
        assert(@intFromPtr(self) != 0);
        assert(request.path.len > 0);

        var out: [request_headers_frame_buffer_size_bytes]u8 = undefined;
        const write = try self.runtime.writeRequestHeadersFrame(&out, request, effective_path, end_stream);
        try self.writeAll(write.frame);
        return write.stream_id;
    }

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

            var frame_out: [data_frame_buffer_size_bytes]u8 = undefined;
            const frame = try self.runtime.writeRequestDataFrame(&frame_out, stream_id, &[_]u8{}, true);
            try self.writeAll(frame);
            return;
        }

        const payload_len: u32 = @intCast(payload.len);
        var sent: u32 = 0;
        var frames: u32 = 0;

        while (sent < payload_len and frames < config.H2_CLIENT_MAX_FRAME_COUNT) : (frames += 1) {
            const stream = self.runtime.state.getStream(stream_id) orelse return error.StreamNotFound;
            if (self.runtime.state.goaway_received and stream_id > self.runtime.state.peer_goaway_last_stream_id) {
                return error.ConnectionClosing;
            }

            const connection_window = self.runtime.state.flow.send_window.available_bytes;
            const stream_window = stream.send_window.available_bytes;
            const window_budget = @min(connection_window, stream_window);
            if (window_budget == 0) return error.SendWindowExhausted;

            const remaining = payload_len - sent;
            const max_frame = self.runtime.state.peer_settings.max_frame_size_bytes;
            const chunk_len = @min(remaining, @min(window_budget, max_frame));
            assert(chunk_len > 0);

            const offset: usize = @intCast(sent);
            const limit: usize = @intCast(sent + chunk_len);
            const chunk = payload[offset..limit];
            const is_last_chunk = sent + chunk_len == payload_len;

            var frame_out: [data_frame_buffer_size_bytes]u8 = undefined;
            const frame = try self.runtime.writeRequestDataFrame(
                &frame_out,
                stream_id,
                chunk,
                end_stream and is_last_chunk,
            );
            try self.writeAll(frame);
            sent += chunk_len;
        }

        if (sent < payload_len) return error.FrameLimitExceeded;
    }

    pub fn sendStreamReset(self: *ClientConnection, stream_id: u32, error_code_raw: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        var out: [h2.frame_header_size_bytes + h2.control.rst_stream_payload_size_bytes]u8 = undefined;
        const frame = try self.runtime.writeRstStreamFrame(&out, .{
            .stream_id = stream_id,
            .error_code_raw = error_code_raw,
        });
        try self.writeAll(frame);
    }

    pub fn receiveAction(self: *ClientConnection) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);

        self.finalizePendingFrame();
        if (self.frame_count >= config.H2_CLIENT_MAX_FRAME_COUNT) return error.FrameLimitExceeded;
        if (!try self.ensureFrame()) return error.ConnectionClosed;

        const header = try h2.parseFrameHeader(self.recv_buf[0..h2.frame_header_size_bytes]);
        const frame_len: usize = @as(usize, h2.frame_header_size_bytes) + @as(usize, header.length);
        const payload_start: usize = h2.frame_header_size_bytes;
        const payload_end: usize = frame_len;
        const action = try self.runtime.receiveFrame(header, self.recv_buf[payload_start..payload_end]);

        self.pending_discard_len = frame_len;
        self.frame_count += 1;
        return action;
    }

    pub fn receiveActionHandlingControl(self: *ClientConnection) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);

        var frames: u32 = 0;
        while (frames < config.H2_CLIENT_MAX_FRAME_COUNT) : (frames += 1) {
            const action = try self.receiveAction();
            if (try self.handleControlAction(action)) continue;
            return action;
        }

        return error.FrameLimitExceeded;
    }

    fn handleControlAction(self: *ClientConnection, action: runtime_mod.ReceiveAction) Error!bool {
        assert(@intFromPtr(self) != 0);

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

    fn ensureFrame(self: *ClientConnection) Error!bool {
        assert(@intFromPtr(self) != 0);

        if (self.recv_len == 0) {
            const n = try self.readIntoBuffer();
            if (n == 0) return false;
        }

        try self.fillBuffer(h2.frame_header_size_bytes);
        const header = try h2.parseFrameHeader(self.recv_buf[0..h2.frame_header_size_bytes]);
        const frame_len: usize = @as(usize, h2.frame_header_size_bytes) + @as(usize, header.length);
        try self.fillBuffer(frame_len);
        return true;
    }

    fn fillBuffer(self: *ClientConnection, needed_len: usize) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(needed_len <= self.recv_buf.len);

        var reads: u32 = 0;
        while (self.recv_len < needed_len and reads < self.recv_buf.len) : (reads += 1) {
            const n = try self.readIntoBuffer();
            if (n == 0) return error.ConnectionClosed;
        }

        if (self.recv_len < needed_len) return error.ReadFailed;
    }

    fn readIntoBuffer(self: *ClientConnection) Error!usize {
        assert(@intFromPtr(self) != 0);
        assert(self.recv_len <= self.recv_buf.len);

        const n = self.socket.read(self.recv_buf[self.recv_len..]) catch |err| {
            return mapReadError(err);
        };
        if (n == 0) return 0;

        self.recv_len += n;
        assert(self.recv_len <= self.recv_buf.len);
        return n;
    }

    fn finalizePendingFrame(self: *ClientConnection) void {
        assert(@intFromPtr(self) != 0);

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

        self.socket.write_all(data) catch |err| {
            return mapWriteError(err);
        };
    }
};

fn mapReadError(err: SocketError) Error {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionReset,
        => error.ConnectionClosed,
        else => error.ReadFailed,
    };
}

fn mapWriteError(err: SocketError) Error {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionReset,
        error.BrokenPipe,
        => error.ConnectionClosed,
        else => error.WriteFailed,
    };
}

fn appendFrame(
    out: []u8,
    frame_type: h2.FrameType,
    flags: u8,
    stream_id: u32,
    payload: []const u8,
) ![]const u8 {
    assert(out.len >= h2.frame_header_size_bytes);

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
    var cursor: usize = 0;
    for (headers) |header| {
        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value);
        cursor += encoded.len;
    }
    return out[0..cursor];
}

fn buildResponseHeaderBlock(status: u16, headers: []const types.Header, out: []u8) ![]const u8 {
    assert(status >= 100 and status <= 599);

    var cursor: usize = 0;
    var status_buf: [3]u8 = undefined;
    const status_text = try std.fmt.bufPrint(&status_buf, "{d}", .{status});

    cursor += (try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], ":status", status_text)).len;
    for (headers) |header| {
        const encoded = try h2.encodeLiteralHeaderWithoutIndexing(out[cursor..], header.name, header.value);
        cursor += encoded.len;
    }
    return out[0..cursor];
}

fn readExact(fd: i32, out: []u8) !void {
    assert(fd >= 0);

    var offset: usize = 0;
    var reads: usize = 0;
    const max_reads: usize = out.len + 32;

    while (offset < out.len and reads < max_reads) : (reads += 1) {
        const n = posix.read(fd, out[offset..]) catch return error.ReadFailed;
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }

    if (offset < out.len) return error.ReadFailed;
}

fn writeAllFd(fd: i32, data: []const u8) !void {
    assert(fd >= 0);

    var offset: usize = 0;
    var writes: usize = 0;
    const max_writes: usize = data.len + 32;

    while (offset < data.len and writes < max_writes) : (writes += 1) {
        const rc = std.c.write(fd, data[offset..].ptr, data.len - offset);
        switch (std.c.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.WriteFailed;
                offset += n;
            },
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }

    if (offset < data.len) return error.WriteFailed;
}

fn testSocketPair(domain: u32, sock_type: u32, protocol: u32) ![2]posix.socket_t {
    var fds: [2]posix.socket_t = undefined;

    while (true) {
        const rc = std.c.socketpair(@intCast(domain), @intCast(sock_type), @intCast(protocol), &fds);
        switch (std.c.errno(rc)) {
            .SUCCESS => return fds,
            .INTR => continue,
            else => return error.SocketFailed,
        }
    }
}

fn buildPeerSettingsFrame(out: []u8) ![]const u8 {
    return appendFrame(out, .settings, 0, 0, &[_]u8{});
}

fn makeGrpcRequest(path: []const u8) !Request {
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
    return request;
}

test "ClientConnection sends client preface and initial settings" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var socket = Socket.Plain.init_client(fds[0]);
    var conn = try ClientConnection.init(&socket);
    try conn.sendClientPrefaceAndSettings();

    var expected_runtime = try runtime_mod.Runtime.init();
    var expected_buf: [preface_settings_buffer_size_bytes]u8 = undefined;
    const expected = try expected_runtime.writeClientPrefaceAndSettings(&expected_buf);

    var received_buf: [preface_settings_buffer_size_bytes]u8 = undefined;
    try readExact(fds[1], received_buf[0..expected.len]);
    try std.testing.expectEqualSlices(u8, expected, received_buf[0..expected.len]);
}

test "ClientConnection completeHandshake sends settings ACK" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var peer_settings_buf: [h2.frame_header_size_bytes]u8 = undefined;
    const peer_settings = try buildPeerSettingsFrame(&peer_settings_buf);
    try writeAllFd(fds[1], peer_settings);

    var socket = Socket.Plain.init_client(fds[0]);
    var conn = try ClientConnection.init(&socket);
    try conn.completeHandshake();

    var expected_runtime = try runtime_mod.Runtime.init();
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

test "ClientConnection request send and response receive round-trip" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var peer_settings_buf: [h2.frame_header_size_bytes]u8 = undefined;
    const peer_settings = try buildPeerSettingsFrame(&peer_settings_buf);
    try writeAllFd(fds[1], peer_settings);

    var socket = Socket.Plain.init_client(fds[0]);
    var conn = try ClientConnection.init(&socket);
    try conn.completeHandshake();

    var expected_runtime = try runtime_mod.Runtime.init();
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

    var request_header_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
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

    var response_header_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const response_header_block = try buildResponseHeaderBlock(
        200,
        &.{.{ .name = "content-type", .value = "application/grpc" }},
        &response_header_block_buf,
    );

    var response_headers_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
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

    var trailer_block_buf: [config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
    const trailer_block = try buildHeaderBlock(&.{.{ .name = "grpc-status", .value = "0" }}, &trailer_block_buf);

    var trailers_frame_buf: [h2.frame_header_size_bytes + config.H2_MAX_HEADER_BLOCK_SIZE_BYTES]u8 = undefined;
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
