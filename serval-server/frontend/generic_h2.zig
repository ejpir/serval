//! Generic frontend HTTP/2 adapter.
//!
//! Adapts TLS ALPN h2 frontend streams into existing handler contract and
//! bridges gRPC streams via provided BridgeHandler type.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const config = serval_core.config;
const hooks = serval_core.hooks;
const types = serval_core.types;
const context = serval_core.context;

const serval_client = @import("serval-client");
const serval_grpc = @import("serval-grpc");
const serval_tls = @import("serval-tls");
const TLSStream = serval_tls.TLSStream;
const forwarder_mod = @import("serval-proxy").forwarder;
const h2_server = @import("../h2/server.zig");
const log = serval_core.log.scoped(.server);

const Request = types.Request;
const Context = context.Context;

pub fn GenericTlsH2FrontendHandler(
    comptime Handler: type,
    comptime Pool: type,
    comptime Tracer: type,
    comptime BridgeHandler: type,
) type {
    const Forwarder = forwarder_mod.Forwarder(Pool, Tracer);

    return struct {
        const Self = @This();

        pub const Error = error{
            TooManyTrackedGrpcStreams,
            HeaderForwardingFailed,
            UnsupportedChunkedWithPreRead,
            UpstreamResponseBodyReadFailed,
            UpstreamConnectFailed,
            UpstreamSendFailed,
            UpstreamResponseHeadersFailed,
            UnsupportedProtocol,
            ResponseFrameLimitExceeded,
        } || BridgeHandler.BridgeError || h2_server.Error;

        inner: *Handler,
        io: Io,
        forwarder: *Forwarder,
        connection_ctx: *Context,
        grpc_handler: BridgeHandler,
        tracked_grpc_streams: [config.H2_MAX_CONCURRENT_STREAMS]u32 = [_]u32{0} ** config.H2_MAX_CONCURRENT_STREAMS,
        tracked_grpc_stream_count: u16 = 0,

        pub fn init(
            inner: *Handler,
            io: Io,
            forwarder: *Forwarder,
            connection_ctx: *Context,
            grpc_handler: BridgeHandler,
        ) Self {
            assert(@intFromPtr(inner) != 0);
            assert(@intFromPtr(forwarder) != 0);
            assert(@intFromPtr(connection_ctx) != 0);

            return .{
                .inner = inner,
                .io = io,
                .forwarder = forwarder,
                .connection_ctx = connection_ctx,
                .grpc_handler = grpc_handler,
            };
        }

        pub fn deinit(self: *Self) void {
            assert(@intFromPtr(self) != 0);
            self.grpc_handler.deinit();
        }

        pub fn handleH2Headers(
            self: *Self,
            stream_id: u32,
            request: *const Request,
            end_stream: bool,
            writer: *h2_server.ResponseWriter,
        ) Error!void {
            assert(@intFromPtr(self) != 0);
            assert(stream_id > 0);

            if (isGrpcRequest(request)) {
                try self.trackGrpcStream(stream_id);
                self.grpc_handler.handleH2Headers(stream_id, request, end_stream, writer) catch |err| {
                    self.untrackGrpcStream(stream_id);
                    return err;
                };
                if (end_stream) self.untrackGrpcStream(stream_id);
                return;
            }

            if (!end_stream) {
                try sendSimpleTextResponse(writer, 413, "request body over generic h2 frontend not supported");
                return;
            }

            if (comptime hooks.hasHook(Handler, "onRequest")) {
                var stream_ctx = self.makeStreamContext();
                var response_buf: [config.RESPONSE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([config.RESPONSE_BUFFER_SIZE_BYTES]u8);
                var mutable_request = request.*;

                switch (self.inner.onRequest(&stream_ctx, &mutable_request, response_buf[0..])) {
                    .continue_request => {},
                    .send_response => |direct_response| {
                        try self.sendDirectResponse(writer, direct_response);
                        return;
                    },
                    .reject => |reject| {
                        try sendSimpleTextResponse(writer, reject.status, reject.reason);
                        return;
                    },
                    .stream => {
                        try sendSimpleStatusResponse(writer, 501);
                        return;
                    },
                }
            }

            const upstream = try self.selectUpstream(request, writer);
            if (upstream == null) return;
            try self.forwardHttpRequest(request, upstream.?, writer);
        }

        pub fn handleH2Data(
            self: *Self,
            stream_id: u32,
            payload: []const u8,
            end_stream: bool,
            writer: *h2_server.ResponseWriter,
        ) Error!void {
            assert(@intFromPtr(self) != 0);

            if (self.isTrackedGrpcStream(stream_id)) {
                self.grpc_handler.handleH2Data(stream_id, payload, end_stream, writer) catch |err| {
                    if (end_stream) self.untrackGrpcStream(stream_id);
                    return err;
                };
                if (end_stream) self.untrackGrpcStream(stream_id);
                return;
            }

            try sendSimpleTextResponse(writer, 413, "request body over generic h2 frontend not supported");
        }

        pub fn handleH2StreamReset(self: *Self, stream_id: u32, error_code_raw: u32) void {
            assert(@intFromPtr(self) != 0);

            if (self.isTrackedGrpcStream(stream_id)) {
                self.untrackGrpcStream(stream_id);
                self.grpc_handler.handleH2StreamReset(stream_id, error_code_raw);
            }
        }

        pub fn handleH2ConnectionClose(self: *Self, goaway: @import("serval-h2").GoAway) void {
            assert(@intFromPtr(self) != 0);
            _ = goaway;
        }

        pub fn handleH2StreamClose(self: *Self, summary: h2_server.StreamSummary) void {
            assert(@intFromPtr(self) != 0);
            self.untrackGrpcStream(summary.stream_id);
        }

        fn makeStreamContext(self: *Self) Context {
            assert(@intFromPtr(self) != 0);

            var stream_ctx = Context.init();
            stream_ctx.connection_id = self.connection_ctx.connection_id;
            stream_ctx.connection_start_ns = self.connection_ctx.connection_start_ns;
            stream_ctx.client_addr = self.connection_ctx.client_addr;
            stream_ctx.client_port = self.connection_ctx.client_port;
            stream_ctx.start_time_ns = self.connection_ctx.start_time_ns;
            return stream_ctx;
        }

        fn sendDirectResponse(self: *Self, writer: *h2_server.ResponseWriter, direct_response: types.DirectResponse) h2_server.Error!void {
            _ = self;
            assert(@intFromPtr(writer) != 0);

            const body = direct_response.body;
            const send_body = body.len > 0;
            try writer.sendHeaders(
                direct_response.status,
                &.{.{ .name = "content-type", .value = direct_response.content_type }},
                !send_body,
            );
            if (send_body) try writer.sendData(body, true);
        }

        fn selectUpstream(self: *Self, request: *const Request, writer: *h2_server.ResponseWriter) Error!?types.Upstream {
            assert(@intFromPtr(self) != 0);
            assert(@intFromPtr(request) != 0);

            var stream_ctx = self.makeStreamContext();
            const action_result = self.inner.selectUpstream(&stream_ctx, request);
            if (comptime hooks.hasUpstreamAction(Handler)) {
                return switch (action_result) {
                    .forward => |upstream| upstream,
                    .reject => |reject| blk: {
                        try sendSimpleStatusResponse(writer, reject.status);
                        break :blk null;
                    },
                };
            }
            return action_result;
        }

        fn forwardHttpRequest(self: *Self, request: *const Request, upstream: types.Upstream, writer: *h2_server.ResponseWriter) Error!void {
            assert(@intFromPtr(self) != 0);

            if (upstream.http_protocol != .h1) {
                try sendSimpleStatusResponse(writer, 502);
                return;
            }

            var client = serval_client.Client.init(
                std.heap.page_allocator,
                &self.forwarder.dns_resolver,
                self.forwarder.client_ctx,
                self.forwarder.verify_upstream_tls,
            );
            var connect_result = client.connect(upstream, self.io) catch return error.UpstreamConnectFailed;
            defer connect_result.conn.close();

            client.sendRequest(&connect_result.conn, request, null) catch return error.UpstreamSendFailed;

            var header_buf: [config.MAX_HEADER_SIZE_BYTES]u8 = undefined;
            const response_headers = client.readResponseHeaders(&connect_result.conn, header_buf[0..]) catch return error.UpstreamResponseHeadersFailed;

            var h2_headers_buf: [config.MAX_HEADERS]h2_server.Header = undefined;
            const h2_headers = try filterResponseHeaders(&response_headers.headers, &h2_headers_buf);

            const header_bytes: usize = @intCast(response_headers.header_bytes);
            const total_bytes: usize = @intCast(response_headers.total_bytes_read);
            assert(total_bytes >= header_bytes);
            const pre_read = header_buf[header_bytes..total_bytes];

            switch (response_headers.body_framing) {
                .none => try writer.sendHeaders(response_headers.status, h2_headers, true),
                .content_length => |content_length| {
                    if (pre_read.len > content_length) return error.UpstreamResponseBodyReadFailed;

                    var remaining: u64 = content_length - pre_read.len;
                    if (content_length == 0) {
                        try writer.sendHeaders(response_headers.status, h2_headers, true);
                        return;
                    }

                    try writer.sendHeaders(response_headers.status, h2_headers, false);
                    if (pre_read.len > 0) try writer.sendData(pre_read, remaining == 0);

                    var response_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;
                    var frame_count: u32 = 0;
                    while (remaining > 0 and frame_count < config.H2_SERVER_MAX_FRAME_COUNT) : (frame_count += 1) {
                        const to_read: usize = @intCast(@min(@as(u64, response_buf.len), remaining));
                        const n = connect_result.conn.socket.read(response_buf[0..to_read]) catch return error.UpstreamResponseBodyReadFailed;
                        if (n == 0) return error.UpstreamResponseBodyReadFailed;

                        remaining -= n;
                        try writer.sendData(response_buf[0..n], remaining == 0);
                    }

                    if (remaining > 0) return error.ResponseFrameLimitExceeded;
                },
                .chunked => {
                    if (pre_read.len != 0) return error.UnsupportedChunkedWithPreRead;

                    try writer.sendHeaders(response_headers.status, h2_headers, false);
                    var body_reader = serval_client.BodyReader.init(&connect_result.conn.socket, response_headers.body_framing);
                    var response_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;

                    var frame_count: u32 = 0;
                    while (frame_count < config.H2_SERVER_MAX_FRAME_COUNT) : (frame_count += 1) {
                        const maybe_chunk = body_reader.readChunk(response_buf[0..]) catch return error.UpstreamResponseBodyReadFailed;
                        if (maybe_chunk) |chunk| {
                            try writer.sendData(chunk, false);
                            continue;
                        }
                        try writer.sendData(&[_]u8{}, true);
                        return;
                    }

                    return error.ResponseFrameLimitExceeded;
                },
            }
        }

        fn filterResponseHeaders(source_headers: *const types.HeaderMap, out: *[config.MAX_HEADERS]h2_server.Header) Error![]const h2_server.Header {
            assert(@intFromPtr(source_headers) != 0);

            var out_count: usize = 0;
            var index: usize = 0;
            while (index < source_headers.count) : (index += 1) {
                const header = source_headers.headers[index];
                if (isConnectionSpecificHeaderName(header.name)) continue;
                if (out_count >= out.len) return error.HeaderForwardingFailed;
                out[out_count] = .{ .name = header.name, .value = header.value };
                out_count += 1;
            }

            return out[0..out_count];
        }

        fn isConnectionSpecificHeaderName(name: []const u8) bool {
            if (std.ascii.eqlIgnoreCase(name, "connection")) return true;
            if (std.ascii.eqlIgnoreCase(name, "proxy-connection")) return true;
            if (std.ascii.eqlIgnoreCase(name, "keep-alive")) return true;
            if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return true;
            if (std.ascii.eqlIgnoreCase(name, "upgrade")) return true;
            return false;
        }

        fn sendSimpleStatusResponse(writer: *h2_server.ResponseWriter, status: u16) h2_server.Error!void {
            assert(@intFromPtr(writer) != 0);
            try writer.sendHeaders(status, &.{.{ .name = "content-type", .value = "text/plain" }}, true);
        }

        fn sendSimpleTextResponse(writer: *h2_server.ResponseWriter, status: u16, message: []const u8) h2_server.Error!void {
            assert(@intFromPtr(writer) != 0);
            assert(message.len <= config.H2_MAX_FRAME_SIZE_BYTES);
            try writer.sendHeaders(status, &.{.{ .name = "content-type", .value = "text/plain" }}, false);
            try writer.sendData(message, true);
        }

        fn isGrpcRequest(request: *const Request) bool {
            serval_grpc.validateRequest(request) catch return false;
            return true;
        }

        fn trackGrpcStream(self: *Self, stream_id: u32) Error!void {
            assert(stream_id > 0);

            if (self.isTrackedGrpcStream(stream_id)) return;
            if (self.tracked_grpc_stream_count >= config.H2_MAX_CONCURRENT_STREAMS) return error.TooManyTrackedGrpcStreams;

            var index: usize = 0;
            while (index < self.tracked_grpc_streams.len) : (index += 1) {
                if (self.tracked_grpc_streams[index] != 0) continue;
                self.tracked_grpc_streams[index] = stream_id;
                self.tracked_grpc_stream_count += 1;
                return;
            }

            return error.TooManyTrackedGrpcStreams;
        }

        fn untrackGrpcStream(self: *Self, stream_id: u32) void {
            if (stream_id == 0) return;

            var index: usize = 0;
            while (index < self.tracked_grpc_streams.len) : (index += 1) {
                if (self.tracked_grpc_streams[index] != stream_id) continue;
                self.tracked_grpc_streams[index] = 0;
                if (self.tracked_grpc_stream_count > 0) self.tracked_grpc_stream_count -= 1;
                return;
            }
        }

        fn isTrackedGrpcStream(self: *Self, stream_id: u32) bool {
            if (stream_id == 0) return false;

            var index: usize = 0;
            while (index < self.tracked_grpc_streams.len) : (index += 1) {
                if (self.tracked_grpc_streams[index] == stream_id) return true;
            }
            return false;
        }
    };
}

pub fn tryServeTlsAlpnConnection(
    comptime Handler: type,
    comptime Pool: type,
    comptime Tracer: type,
    comptime BridgeHandler: type,
    handler: *Handler,
    forwarder: *forwarder_mod.Forwarder(Pool, Tracer),
    connection_ctx: *Context,
    maybe_tls: ?*TLSStream,
    io: Io,
    connection_id: u64,
    frontend_mode: config.TlsH2FrontendMode,
) bool {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(forwarder) != 0);
    assert(@intFromPtr(connection_ctx) != 0);

    if (frontend_mode != .generic) return false;

    const tls_stream = maybe_tls orelse return false;
    if (comptime @hasDecl(Handler, "handleH2Headers") and @hasDecl(Handler, "handleH2Data")) {
        // Explicit terminated handlers keep ownership of ALPN h2 dispatch.
        return false;
    }

    const alpn = tls_stream.info.alpn() orelse return false;
    if (!std.mem.eql(u8, alpn, "h2")) return false;

    var bridge_client = serval_client.Client.init(
        std.heap.page_allocator,
        &forwarder.dns_resolver,
        forwarder.client_ctx,
        forwarder.verify_upstream_tls,
    );
    const bridge_sessions = std.heap.page_allocator.create(serval_client.H2UpstreamSessionPool) catch {
        log.err("server: conn={d} generic h2 bridge pool allocation failed", .{connection_id});
        return false;
    };
    bridge_sessions.* = serval_client.H2UpstreamSessionPool.init();
    defer {
        bridge_sessions.deinit();
        std.heap.page_allocator.destroy(bridge_sessions);
    }

    const bridge_handler = BridgeHandler.init(
        handler,
        io,
        &bridge_client,
        bridge_sessions,
        connection_ctx,
    );

    const GenericHandler = GenericTlsH2FrontendHandler(Handler, Pool, Tracer, BridgeHandler);
    var generic_handler = GenericHandler.init(
        handler,
        io,
        forwarder,
        connection_ctx,
        bridge_handler,
    );
    defer generic_handler.deinit();

    log.debug("server: conn={d} dispatching ALPN h2 to generic frontend h2 driver", .{connection_id});

    h2_server.serveTlsConnection(
        @TypeOf(generic_handler),
        &generic_handler,
        tls_stream,
        connection_id,
    ) catch |err| switch (err) {
        error.ConnectionClosed => {},
        else => log.warn("server: conn={d} generic frontend TLS h2 driver failed: {s}", .{ connection_id, @errorName(err) }),
    };
    return true;
}
