//! Generic frontend HTTP/2 adapter.
//!
//! Adapts TLS ALPN h2 frontend streams into existing handler contract and
//! bridges gRPC streams via provided BridgeHandler type.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const posix = std.posix;

const serval_core = @import("serval-core");
const config = serval_core.config;
const hooks = serval_core.hooks;
const types = serval_core.types;
const context = serval_core.context;

const serval_client = @import("serval-client");
const client_request = serval_client.request;
const Connection = serval_client.Connection;
const serval_grpc = @import("serval-grpc");
const serval_h2 = @import("serval-h2");
const serval_http = @import("serval-http");
const parseContentLengthValue = serval_http.parseContentLengthValue;
const serval_proxy = @import("serval-proxy");
const serval_proxy_h1 = serval_proxy.h1;
const Socket = @import("serval-socket").Socket;
const serval_tls = @import("serval-tls");
const TLSStream = serval_tls.TLSStream;
const forwarder_mod = @import("serval-proxy").forwarder;
const h2_server = @import("../h2/server.zig");
const log = serval_core.log.scoped(.server);

const Request = types.Request;
const Context = context.Context;

/// Builds the stateful generic TLS HTTP/2 frontend adapter type.
/// The returned type routes gRPC, WebSocket, and generic HTTP requests while preserving the caller's handler contract.
/// Built-in WebSocket and generic request tracking tables are bounded by `config.H2_MAX_CONCURRENT_STREAMS`.
pub fn GenericTlsH2FrontendHandler(
    comptime Handler: type,
    comptime Pool: type,
    comptime Tracer: type,
    comptime BridgeHandler: type,
) type {
    const Forwarder = forwarder_mod.Forwarder(Pool, Tracer);

    return struct {
        const Self = @This();
        const websocket_stream_capacity: usize = config.H2_MAX_CONCURRENT_STREAMS;
        const websocket_read_timeout_ms: i64 = 1000;
        const generic_request_stream_capacity: usize = config.H2_MAX_CONCURRENT_STREAMS;

        const GenericRequestBodyMode = enum {
            content_length,
            chunked,
        };

        const GenericRequestStreamState = struct {
            used: bool = false,
            stream_id: u32 = 0,
            body_mode: GenericRequestBodyMode = .content_length,
            expected_content_length: u64 = 0,
            forwarded_body_bytes: u64 = 0,
            upstream_conn: Connection = undefined,
        };

        const WebSocketStreamState = struct {
            used: bool = false,
            closing: bool = false,
            stream_id: u32 = 0,
            upstream_conn: Connection = undefined,
        };

        /// Error set returned by generic h2 frontend operations.
        /// Includes stream tracking limits, request validation failures, upstream forwarding failures, WebSocket validation failures, and bridge or h2 server errors.
        /// Callers should treat these as operational failures from header, body, or connection setup paths.
        pub const Error = error{
            TooManyTrackedGrpcStreams,
            TooManyTrackedWebSocketStreams,
            TooManyTrackedGenericRequestStreams,
            GenericRequestStreamNotFound,
            InvalidContentLength,
            UnexpectedRequestBodyLength,
            HeaderForwardingFailed,
            UnsupportedChunkedWithPreRead,
            UpstreamResponseBodyReadFailed,
            UpstreamConnectFailed,
            UpstreamSendFailed,
            UpstreamResponseHeadersFailed,
            UnsupportedProtocol,
            ResponseFrameLimitExceeded,
            MissingWebSocketKey,
            InvalidWebSocketRequest,
        } || BridgeHandler.BridgeError || h2_server.Error;

        inner: *Handler,
        io: Io,
        forwarder: *Forwarder,
        connection_ctx: *Context,
        grpc_handler: *BridgeHandler,
        tracked_grpc_streams: [config.H2_MAX_CONCURRENT_STREAMS]u32 = [_]u32{0} ** config.H2_MAX_CONCURRENT_STREAMS,
        tracked_grpc_stream_count: u16 = 0,
        tracked_h2_bridge_streams: [config.H2_MAX_CONCURRENT_STREAMS]u32 = [_]u32{0} ** config.H2_MAX_CONCURRENT_STREAMS,
        tracked_h2_bridge_stream_count: u16 = 0,
        websocket_mutex: Io.Mutex = .init,
        websocket_reader_group: Io.Group = .init,
        websocket_reader_started: bool = false,
        writer_template: ?*h2_server.ResponseWriter = null,
        connection_mutex: ?*Io.Mutex = null,
        websocket_streams: [websocket_stream_capacity]WebSocketStreamState = [_]WebSocketStreamState{.{}} ** websocket_stream_capacity,
        tracked_websocket_stream_count: u16 = 0,
        generic_request_streams: [generic_request_stream_capacity]GenericRequestStreamState = [_]GenericRequestStreamState{.{}} ** generic_request_stream_capacity,
        tracked_generic_request_stream_count: u16 = 0,

        /// Initializes a generic h2 frontend handler directly into caller-owned storage.
        /// Stores the provided pointers and I/O handle without taking ownership of them.
        /// The referenced handler, forwarder, and connection context must outlive `self`.
        pub fn initInto(
            self: *Self,
            inner: *Handler,
            io: Io,
            forwarder: *Forwarder,
            connection_ctx: *Context,
            grpc_handler: *BridgeHandler,
        ) void {
            assert(@intFromPtr(self) != 0);
            assert(@intFromPtr(inner) != 0);
            assert(@intFromPtr(forwarder) != 0);
            assert(@intFromPtr(connection_ctx) != 0);
            assert(@intFromPtr(grpc_handler) != 0);

            self.inner = inner;
            self.io = io;
            self.forwarder = forwarder;
            self.connection_ctx = connection_ctx;
            self.grpc_handler = grpc_handler;

            @memset(self.tracked_grpc_streams[0..], 0);
            self.tracked_grpc_stream_count = 0;
            @memset(self.tracked_h2_bridge_streams[0..], 0);
            self.tracked_h2_bridge_stream_count = 0;
            self.websocket_mutex = .init;
            self.websocket_reader_group = .init;
            self.websocket_reader_started = false;
            self.writer_template = null;
            self.connection_mutex = null;
            for (self.websocket_streams[0..]) |*slot| resetWebSocketStreamState(slot);
            self.tracked_websocket_stream_count = 0;
            for (self.generic_request_streams[0..]) |*slot| resetGenericRequestStreamState(slot);
            self.tracked_generic_request_stream_count = 0;
        }

        /// Releases all background-task state and then deinitializes the embedded bridge handler.
        /// Callers should not use the handler after this returns.
        pub fn deinit(self: *Self) void {
            assert(@intFromPtr(self) != 0);
            self.stopH2BackgroundTasks();
            self.grpc_handler.deinit();
        }

        /// Stores the shared response writer template and connection mutex used by background tasks.
        /// Also starts the bridge handler's background tasks with the same shared state.
        /// The supplied pointers must remain valid until `stopH2BackgroundTasks` or `deinit` clears them.
        pub fn startH2BackgroundTasks(
            self: *Self,
            writer_template: *h2_server.ResponseWriter,
            connection_mutex: *Io.Mutex,
        ) void {
            assert(@intFromPtr(self) != 0);
            assert(@intFromPtr(writer_template) != 0);
            assert(@intFromPtr(connection_mutex) != 0);

            log.debug("generic h2: start background tasks", .{});
            self.writer_template = writer_template;
            self.connection_mutex = connection_mutex;
            self.grpc_handler.startH2BackgroundTasks(writer_template, connection_mutex);
            log.debug("generic h2: started grpc bridge background tasks", .{});
        }

        /// Stops background work associated with the generic h2 frontend.
        /// Cancels the WebSocket reader group, stops the gRPC bridge tasks, clears stored writer and mutex pointers, and closes all tracked upstream connections.
        /// After this call, tracked WebSocket and generic request slots are reset and their counters are cleared.
        pub fn stopH2BackgroundTasks(self: *Self) void {
            assert(@intFromPtr(self) != 0);

            if (self.websocket_reader_started) {
                log.debug("generic h2: cancel websocket reader group reason=stop_background_tasks", .{});
                self.websocket_reader_group.cancel(self.io);
                self.websocket_reader_started = false;
            }
            log.debug("generic h2: stop grpc bridge background tasks", .{});
            self.grpc_handler.stopH2BackgroundTasks();
            self.writer_template = null;
            self.connection_mutex = null;

            self.websocket_mutex.lockUncancelable(self.io);
            defer self.websocket_mutex.unlock(self.io);

            var index: usize = 0;
            while (index < self.websocket_streams.len) : (index += 1) {
                if (!self.websocket_streams[index].used) continue;
                self.websocket_streams[index].upstream_conn.close();
                resetWebSocketStreamState(&self.websocket_streams[index]);
            }
            self.tracked_websocket_stream_count = 0;

            index = 0;
            while (index < self.generic_request_streams.len) : (index += 1) {
                if (!self.generic_request_streams[index].used) continue;
                self.generic_request_streams[index].upstream_conn.close();
                resetGenericRequestStreamState(&self.generic_request_streams[index]);
            }
            self.tracked_generic_request_stream_count = 0;
        }

        /// Processes HEADERS for a new HTTP/2 stream and routes it by request type.
        /// gRPC requests are tracked and delegated to the bridge handler; extended CONNECT WebSocket requests use the WebSocket path.
        /// Generic requests may be handled directly by `onRequest`, rejected with a response, or forwarded to an upstream selected from the request context.
        /// Errors from tracking, upstream setup, or forwarding are returned unless they are translated into an HTTP response.
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

            if (isExtendedConnectWebSocketRequest(request)) {
                try self.handleWebSocketConnect(stream_id, request, writer);
                return;
            }

            // Generic (non-gRPC) requests with body are supported via stream-aware
            // h2->h1 forwarding state tracked per stream.

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

            if (supportsH2BridgeUpstream(upstream.?)) {
                try self.trackH2BridgeStream(stream_id);
                self.grpc_handler.handleH2Headers(stream_id, request, end_stream, writer) catch |err| {
                    self.untrackH2BridgeStream(stream_id);
                    return err;
                };
                return;
            }

            if (end_stream) {
                self.forwardHttpRequest(request, upstream.?, writer) catch |err| switch (err) {
                    error.UpstreamConnectFailed,
                    error.UpstreamSendFailed,
                    error.UpstreamResponseHeadersFailed,
                    error.UpstreamResponseBodyReadFailed,
                    error.HeaderForwardingFailed,
                    error.UnsupportedChunkedWithPreRead,
                    error.ResponseFrameLimitExceeded,
                    => {
                        log.warn("generic h2: stream={d} upstream request failed err={s}; returning 502", .{ stream_id, @errorName(err) });
                        try sendSimpleStatusResponse(writer, 502);
                    },
                    else => return err,
                };
                return;
            }

            self.startGenericRequestBodyStream(stream_id, request, upstream.?) catch |err| switch (err) {
                error.InvalidContentLength => try sendSimpleTextResponse(writer, 400, "invalid content-length header"),
                error.TooManyTrackedGenericRequestStreams => try sendSimpleStatusResponse(writer, 503),
                error.UpstreamConnectFailed,
                error.UpstreamSendFailed,
                => {
                    log.warn("generic h2: stream={d} upstream request stream setup failed err={s}; returning 502", .{ stream_id, @errorName(err) });
                    try sendSimpleStatusResponse(writer, 502);
                },
                else => return err,
            };
        }

        /// Processes DATA frames for tracked gRPC, bridge, WebSocket, and generic request streams.
        /// gRPC and bridge streams delegate to the bridge handler; WebSocket data is forwarded upstream; generic request bodies are streamed to the selected upstream.
        /// When no stream state is tracked, a `413` text response is sent for the unexpected body.
        /// Errors from downstream forwarding or response writing are returned to the caller.
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

            if (self.isTrackedH2BridgeStream(stream_id)) {
                self.grpc_handler.handleH2Data(stream_id, payload, end_stream, writer) catch |err| {
                    return err;
                };
                return;
            }

            if (self.isTrackedWebSocketStream(stream_id)) {
                try self.forwardWebSocketData(stream_id, payload);
                if (end_stream) self.markWebSocketStreamClosing(stream_id);
                return;
            }

            if (self.getGenericRequestStreamState(stream_id) != null) {
                try self.forwardGenericRequestBodyData(stream_id, payload, end_stream, writer);
                return;
            }

            try sendSimpleTextResponse(writer, 413, "request body over generic h2 frontend not supported");
        }

        /// Handles an HTTP/2 stream reset by clearing any tracked state for the stream.
        /// For tracked gRPC or h2-bridge streams, the reset is forwarded to the bridge handler after untracking.
        /// WebSocket and generic request state is marked closed or removed without returning an error.
        pub fn handleH2StreamReset(self: *Self, stream_id: u32, error_code_raw: u32) void {
            assert(@intFromPtr(self) != 0);

            if (self.isTrackedGrpcStream(stream_id)) {
                self.untrackGrpcStream(stream_id);
                self.grpc_handler.handleH2StreamReset(stream_id, error_code_raw);
            }
            if (self.isTrackedH2BridgeStream(stream_id)) {
                self.untrackH2BridgeStream(stream_id);
                self.grpc_handler.handleH2StreamReset(stream_id, error_code_raw);
            }
            self.markWebSocketStreamClosing(stream_id);
            self.removeGenericRequestStream(stream_id);
        }

        /// Receives the connection-level GOAWAY notification for this frontend.
        /// The current implementation intentionally ignores the frame payload and leaves state unchanged.
        /// This hook exists so connection-close handling can be extended without changing callers.
        pub fn handleH2ConnectionClose(self: *Self, goaway: @import("serval-h2").GoAway) void {
            assert(@intFromPtr(self) != 0);
            _ = goaway;
        }

        /// Updates per-stream tracking after an HTTP/2 stream closes.
        /// Removes the stream from gRPC and h2-bridge tracking, marks WebSocket streams as closing, and drops generic request state.
        /// This is a best-effort cleanup hook and does not report errors.
        pub fn handleH2StreamClose(self: *Self, summary: h2_server.StreamSummary) void {
            assert(@intFromPtr(self) != 0);
            self.untrackGrpcStream(summary.stream_id);
            self.untrackH2BridgeStream(summary.stream_id);
            self.markWebSocketStreamClosing(summary.stream_id);
            self.removeGenericRequestStream(summary.stream_id);
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

            try self.forwardHttpResponseFromConnection(&connect_result.conn, writer);
        }

        fn forwardHttpResponseFromConnection(self: *Self, conn: *Connection, writer: *h2_server.ResponseWriter) Error!void {
            _ = self;
            assert(@intFromPtr(conn) != 0);

            var header_buf: [config.MAX_HEADER_SIZE_BYTES]u8 = undefined;
            const response_headers = serval_client.readResponseHeaders(&conn.socket, header_buf[0..]) catch return error.UpstreamResponseHeadersFailed;

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

                    var response_buf: [serval_h2.frame_payload_capacity_bytes]u8 = undefined;
                    var frame_count: u32 = 0;
                    while (remaining > 0 and frame_count < config.H2_SERVER_MAX_FRAME_COUNT) : (frame_count += 1) {
                        const to_read: usize = @intCast(@min(@as(u64, response_buf.len), remaining));
                        const n = conn.socket.read(response_buf[0..to_read]) catch return error.UpstreamResponseBodyReadFailed;
                        if (n == 0) return error.UpstreamResponseBodyReadFailed;

                        remaining -= n;
                        try writer.sendData(response_buf[0..n], remaining == 0);
                    }

                    if (remaining > 0) return error.ResponseFrameLimitExceeded;
                },
                .chunked => {
                    try writer.sendHeaders(response_headers.status, h2_headers, false);
                    var body_reader = serval_client.BodyReader.init(&conn.socket, response_headers.body_framing);
                    body_reader.preloadChunkedBytes(pre_read) catch return error.UpstreamResponseBodyReadFailed;
                    var response_buf: [serval_h2.frame_payload_capacity_bytes]u8 = undefined;

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

        fn startGenericRequestBodyStream(self: *Self, stream_id: u32, request: *const Request, upstream: types.Upstream) Error!void {
            assert(@intFromPtr(self) != 0);
            assert(stream_id > 0);

            if (upstream.http_protocol != .h1) return error.UnsupportedProtocol;

            const body_mode: GenericRequestBodyMode, const content_length: u64 = blk: {
                if (request.headers.getContentLength()) |content_length_value| {
                    const parsed = parseContentLengthValue(content_length_value) orelse return error.InvalidContentLength;
                    break :blk .{ .content_length, parsed };
                }
                break :blk .{ .chunked, 0 };
            };

            var client = serval_client.Client.init(
                std.heap.page_allocator,
                &self.forwarder.dns_resolver,
                self.forwarder.client_ctx,
                self.forwarder.verify_upstream_tls,
            );
            var connect_result = client.connect(upstream, self.io) catch return error.UpstreamConnectFailed;
            errdefer connect_result.conn.close();

            switch (body_mode) {
                .content_length => {
                    client.sendRequest(&connect_result.conn, request, null) catch return error.UpstreamSendFailed;
                },
                .chunked => {
                    sendChunkedRequestHeaders(&connect_result.conn, self.io, request) catch return error.UpstreamSendFailed;
                },
            }

            try self.trackGenericRequestStream(stream_id, connect_result.conn, body_mode, content_length);
        }

        fn forwardGenericRequestBodyData(
            self: *Self,
            stream_id: u32,
            payload: []const u8,
            end_stream: bool,
            writer: *h2_server.ResponseWriter,
        ) Error!void {
            assert(@intFromPtr(self) != 0);
            assert(stream_id > 0);
            assert(@intFromPtr(writer) != 0);

            const state = self.getGenericRequestStreamState(stream_id) orelse return error.GenericRequestStreamNotFound;

            switch (state.body_mode) {
                .content_length => {
                    if (payload.len > 0) {
                        writeAllConnection(&state.upstream_conn, self.io, payload) catch return error.UpstreamSendFailed;
                        state.forwarded_body_bytes += payload.len;
                    }

                    if (state.forwarded_body_bytes > state.expected_content_length) {
                        self.removeGenericRequestStream(stream_id);
                        try sendSimpleTextResponse(writer, 400, "request body exceeded declared content-length");
                        return;
                    }

                    if (!end_stream) return;
                    if (state.forwarded_body_bytes != state.expected_content_length) {
                        self.removeGenericRequestStream(stream_id);
                        try sendSimpleTextResponse(writer, 400, "request body shorter than declared content-length");
                        return;
                    }
                },
                .chunked => {
                    if (payload.len > 0) {
                        sendChunkedBodyData(&state.upstream_conn, self.io, payload) catch return error.UpstreamSendFailed;
                        state.forwarded_body_bytes += payload.len;
                    }

                    if (!end_stream) return;
                    sendChunkedBodyTerminator(&state.upstream_conn, self.io) catch return error.UpstreamSendFailed;
                },
            }

            const local_conn = state.upstream_conn;
            self.removeGenericRequestStreamWithoutClose(stream_id);
            var conn = local_conn;
            defer conn.close();

            try self.forwardHttpResponseFromConnection(&conn, writer);
        }

        fn trackGenericRequestStream(
            self: *Self,
            stream_id: u32,
            conn: Connection,
            body_mode: GenericRequestBodyMode,
            expected_content_length: u64,
        ) Error!void {
            assert(stream_id > 0);

            var mutable_conn = conn;
            if (self.getGenericRequestStreamState(stream_id) != null) {
                mutable_conn.close();
                return error.TooManyTrackedGenericRequestStreams;
            }

            if (self.tracked_generic_request_stream_count >= config.H2_MAX_CONCURRENT_STREAMS) {
                mutable_conn.close();
                return error.TooManyTrackedGenericRequestStreams;
            }

            var index: usize = 0;
            while (index < self.generic_request_streams.len) : (index += 1) {
                if (self.generic_request_streams[index].used) continue;
                self.generic_request_streams[index] = .{
                    .used = true,
                    .stream_id = stream_id,
                    .body_mode = body_mode,
                    .expected_content_length = expected_content_length,
                    .upstream_conn = mutable_conn,
                };
                self.tracked_generic_request_stream_count += 1;
                return;
            }

            mutable_conn.close();
            return error.TooManyTrackedGenericRequestStreams;
        }

        fn getGenericRequestStreamState(self: *Self, stream_id: u32) ?*GenericRequestStreamState {
            if (stream_id == 0) return null;

            var index: usize = 0;
            while (index < self.generic_request_streams.len) : (index += 1) {
                if (!self.generic_request_streams[index].used) continue;
                if (self.generic_request_streams[index].stream_id == stream_id) return &self.generic_request_streams[index];
            }
            return null;
        }

        fn removeGenericRequestStreamWithoutClose(self: *Self, stream_id: u32) void {
            if (stream_id == 0) return;

            var index: usize = 0;
            while (index < self.generic_request_streams.len) : (index += 1) {
                if (!self.generic_request_streams[index].used) continue;
                if (self.generic_request_streams[index].stream_id != stream_id) continue;
                resetGenericRequestStreamState(&self.generic_request_streams[index]);
                if (self.tracked_generic_request_stream_count > 0) self.tracked_generic_request_stream_count -= 1;
                return;
            }
        }

        fn removeGenericRequestStream(self: *Self, stream_id: u32) void {
            if (stream_id == 0) return;

            var index: usize = 0;
            while (index < self.generic_request_streams.len) : (index += 1) {
                if (!self.generic_request_streams[index].used) continue;
                if (self.generic_request_streams[index].stream_id != stream_id) continue;
                self.generic_request_streams[index].upstream_conn.close();
                resetGenericRequestStreamState(&self.generic_request_streams[index]);
                if (self.tracked_generic_request_stream_count > 0) self.tracked_generic_request_stream_count -= 1;
                return;
            }
        }

        fn handleWebSocketConnect(self: *Self, stream_id: u32, request: *const Request, writer: *h2_server.ResponseWriter) Error!void {
            assert(@intFromPtr(self) != 0);
            assert(stream_id > 0);

            const request_key = request.headers.get("sec-websocket-key") orelse
                request.headers.get("Sec-WebSocket-Key") orelse
                return error.MissingWebSocketKey;

            var accept_key_buf: [@import("serval-websocket").websocket_accept_key_size_bytes]u8 = undefined;
            const expected_accept = @import("serval-websocket").computeAcceptKey(request_key, &accept_key_buf) catch {
                return error.InvalidWebSocketRequest;
            };

            const upstream = try self.selectUpstream(request, writer);
            if (upstream == null) return;
            if (upstream.?.http_protocol != .h1) return error.UnsupportedProtocol;

            var upgrade_request = request.*;
            upgrade_request.method = .GET;

            var client = serval_client.Client.init(
                std.heap.page_allocator,
                &self.forwarder.dns_resolver,
                self.forwarder.client_ctx,
                self.forwarder.verify_upstream_tls,
            );
            var connect_result = client.connect(upstream.?, self.io) catch return error.UpstreamConnectFailed;

            serval_proxy_h1.sendUpgradeRequest(&connect_result.conn, self.io, &upgrade_request, null, .{}) catch {
                connect_result.conn.close();
                return error.UpstreamSendFailed;
            };

            const upgrade_result = serval_proxy_h1.websocket.receiveUpgradeResponse(
                self.io,
                &connect_result.conn,
                false,
                expected_accept,
            ) catch {
                connect_result.conn.close();
                return error.UpstreamResponseHeadersFailed;
            };
            if (!upgrade_result.upgraded) {
                connect_result.conn.close();
                try sendSimpleStatusResponse(writer, 502);
                return;
            }

            try self.trackWebSocketStream(stream_id, connect_result.conn);
            writer.sendHeaders(200, &.{}, false) catch |err| {
                self.markWebSocketStreamClosing(stream_id);
                return err;
            };

            self.websocket_reader_group.concurrent(self.io, websocketReaderTask, .{ self, stream_id }) catch |err| {
                self.markWebSocketStreamClosing(stream_id);
                log.err("generic h2: failed to start websocket reader task stream={d}: {s}", .{
                    stream_id,
                    @errorName(err),
                });
                return error.UpstreamResponseBodyReadFailed;
            };
            self.websocket_reader_started = true;
        }

        fn forwardWebSocketData(self: *Self, stream_id: u32, payload: []const u8) Error!void {
            assert(@intFromPtr(self) != 0);
            assert(stream_id > 0);

            if (payload.len == 0) return;

            const state = self.getWebSocketStreamState(stream_id) orelse return error.UnsupportedProtocol;
            if (state.closing) return error.UnsupportedProtocol;

            writeAllConnection(&state.upstream_conn, self.io, payload) catch return error.UpstreamSendFailed;
        }

        fn websocketReaderTask(self: *Self, stream_id: u32) Io.Cancelable!void {
            assert(@intFromPtr(self) != 0);
            assert(stream_id > 0);

            var read_buf: [serval_h2.frame_payload_capacity_bytes]u8 = undefined;
            const timeout = timeoutForMilliseconds(websocket_read_timeout_ms);

            while (true) {
                try std.Io.checkCancel(self.io);

                const state = self.getWebSocketStreamState(stream_id) orelse return;
                if (state.closing) break;

                const bytes_read = readSomeConnection(&state.upstream_conn, self.io, timeout, &read_buf) catch |err| switch (err) {
                    error.Timeout => continue,
                    error.ConnectionClosed => break,
                    else => {
                        self.markWebSocketStreamClosing(stream_id);
                        break;
                    },
                };
                if (bytes_read == 0) break;

                const writer_template = self.writer_template orelse break;
                const connection_mutex = self.connection_mutex orelse break;
                connection_mutex.lockUncancelable(self.io);
                defer connection_mutex.unlock(self.io);

                var stream_writer = streamWriterFor(writer_template, stream_id);
                stream_writer.sendData(read_buf[0..bytes_read], false) catch {
                    self.markWebSocketStreamClosing(stream_id);
                    break;
                };
            }

            const writer_template = self.writer_template;
            const connection_mutex = self.connection_mutex;
            self.removeWebSocketStream(stream_id);

            if (writer_template == null or connection_mutex == null) return;
            connection_mutex.?.lockUncancelable(self.io);
            defer connection_mutex.?.unlock(self.io);

            var stream_writer = streamWriterFor(writer_template.?, stream_id);
            _ = stream_writer.sendData(&[_]u8{}, true) catch |err| {
                log.warn("generic h2 websocket stream close frame failed stream={d} err={s}", .{ stream_id, @errorName(err) });
            };
        }

        fn trackWebSocketStream(self: *Self, stream_id: u32, conn: Connection) Error!void {
            assert(@intFromPtr(self) != 0);
            assert(stream_id > 0);

            self.websocket_mutex.lockUncancelable(self.io);
            defer self.websocket_mutex.unlock(self.io);

            if (self.tracked_websocket_stream_count >= config.H2_MAX_CONCURRENT_STREAMS) return error.TooManyTrackedWebSocketStreams;

            var index: usize = 0;
            while (index < self.websocket_streams.len) : (index += 1) {
                if (self.websocket_streams[index].used) continue;
                self.websocket_streams[index] = .{
                    .used = true,
                    .stream_id = stream_id,
                    .upstream_conn = conn,
                };
                self.tracked_websocket_stream_count += 1;
                return;
            }

            return error.TooManyTrackedWebSocketStreams;
        }

        fn markWebSocketStreamClosing(self: *Self, stream_id: u32) void {
            assert(@intFromPtr(self) != 0);
            if (stream_id == 0) return;

            self.websocket_mutex.lockUncancelable(self.io);
            defer self.websocket_mutex.unlock(self.io);

            var index: usize = 0;
            while (index < self.websocket_streams.len) : (index += 1) {
                if (!self.websocket_streams[index].used) continue;
                if (self.websocket_streams[index].stream_id != stream_id) continue;
                self.websocket_streams[index].closing = true;
                return;
            }
        }

        fn removeWebSocketStream(self: *Self, stream_id: u32) void {
            assert(@intFromPtr(self) != 0);
            if (stream_id == 0) return;

            self.websocket_mutex.lockUncancelable(self.io);
            defer self.websocket_mutex.unlock(self.io);

            var index: usize = 0;
            while (index < self.websocket_streams.len) : (index += 1) {
                if (!self.websocket_streams[index].used) continue;
                if (self.websocket_streams[index].stream_id != stream_id) continue;
                self.websocket_streams[index].upstream_conn.close();
                resetWebSocketStreamState(&self.websocket_streams[index]);
                if (self.tracked_websocket_stream_count > 0) self.tracked_websocket_stream_count -= 1;
                return;
            }
        }

        fn resetWebSocketStreamState(slot: *WebSocketStreamState) void {
            assert(@intFromPtr(slot) != 0);
            slot.used = false;
            slot.closing = false;
            slot.stream_id = 0;
        }

        fn resetGenericRequestStreamState(slot: *GenericRequestStreamState) void {
            assert(@intFromPtr(slot) != 0);
            slot.used = false;
            slot.stream_id = 0;
            slot.body_mode = .content_length;
            slot.expected_content_length = 0;
            slot.forwarded_body_bytes = 0;
        }

        fn getWebSocketStreamState(self: *Self, stream_id: u32) ?*WebSocketStreamState {
            assert(@intFromPtr(self) != 0);
            if (stream_id == 0) return null;

            self.websocket_mutex.lockUncancelable(self.io);
            defer self.websocket_mutex.unlock(self.io);

            var index: usize = 0;
            while (index < self.websocket_streams.len) : (index += 1) {
                if (!self.websocket_streams[index].used) continue;
                if (self.websocket_streams[index].stream_id == stream_id) return &self.websocket_streams[index];
            }
            return null;
        }

        fn isTrackedWebSocketStream(self: *Self, stream_id: u32) bool {
            return self.getWebSocketStreamState(stream_id) != null;
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
            assert(message.len <= serval_h2.frame_payload_capacity_bytes);
            try writer.sendHeaders(status, &.{.{ .name = "content-type", .value = "text/plain" }}, false);
            try writer.sendData(message, true);
        }

        fn isGrpcRequest(request: *const Request) bool {
            const request_class = serval_grpc.classifyRequest(request);
            return request_class == .grpc;
        }

        fn supportsH2BridgeUpstream(upstream: types.Upstream) bool {
            const supports_h2c_plain = upstream.http_protocol == .h2c and !upstream.tls;
            const supports_h2_tls = upstream.http_protocol == .h2 and upstream.tls;
            return supports_h2c_plain or supports_h2_tls;
        }

        fn isExtendedConnectWebSocketRequest(request: *const Request) bool {
            assert(@intFromPtr(request) != 0);

            if (request.method != .CONNECT) return false;
            if (request.path.len == 0) return false;
            if (request.headers.get("x-forwarded-proto") == null) return false;

            const protocol = request.headers.get("x-http2-protocol") orelse return false;
            if (!std.ascii.eqlIgnoreCase(protocol, "websocket")) return false;

            return request.headers.get("sec-websocket-key") != null or
                request.headers.get("Sec-WebSocket-Key") != null;
        }

        fn trackH2BridgeStream(self: *Self, stream_id: u32) Error!void {
            assert(stream_id > 0);

            if (self.isTrackedH2BridgeStream(stream_id)) return;
            if (self.tracked_h2_bridge_stream_count >= config.H2_MAX_CONCURRENT_STREAMS) return error.TooManyTrackedGenericRequestStreams;

            var index: usize = 0;
            while (index < self.tracked_h2_bridge_streams.len) : (index += 1) {
                if (self.tracked_h2_bridge_streams[index] != 0) continue;
                self.tracked_h2_bridge_streams[index] = stream_id;
                self.tracked_h2_bridge_stream_count += 1;
                return;
            }

            return error.TooManyTrackedGenericRequestStreams;
        }

        fn untrackH2BridgeStream(self: *Self, stream_id: u32) void {
            if (stream_id == 0) return;

            var index: usize = 0;
            while (index < self.tracked_h2_bridge_streams.len) : (index += 1) {
                if (self.tracked_h2_bridge_streams[index] != stream_id) continue;
                self.tracked_h2_bridge_streams[index] = 0;
                if (self.tracked_h2_bridge_stream_count > 0) self.tracked_h2_bridge_stream_count -= 1;
                return;
            }
        }

        fn isTrackedH2BridgeStream(self: *Self, stream_id: u32) bool {
            if (stream_id == 0) return false;

            var index: usize = 0;
            while (index < self.tracked_h2_bridge_streams.len) : (index += 1) {
                if (self.tracked_h2_bridge_streams[index] == stream_id) return true;
            }
            return false;
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

fn sendChunkedRequestHeaders(conn: *Connection, io: Io, request: *const Request) WebSocketIoError!void {
    assert(@intFromPtr(conn) != 0);
    assert(@intFromPtr(request) != 0);
    assert(request.path.len > 0);

    var buffer: [config.MAX_HEADER_SIZE_BYTES]u8 = std.mem.zeroes([config.MAX_HEADER_SIZE_BYTES]u8);
    const header_len = buildChunkedRequestHeaderBuffer(&buffer, request) orelse return error.WriteFailed;
    try writeAllConnection(conn, io, buffer[0..header_len]);
}

fn buildChunkedRequestHeaderBuffer(buffer: []u8, request: *const Request) ?usize {
    assert(buffer.len > 0);
    assert(request.path.len > 0);

    var pos: usize = 0;

    const method_str = client_request.methodToString(request.method);
    const version_str = " HTTP/1.1\r\n";
    const line_len = method_str.len + 1 + request.path.len + version_str.len;
    if (pos + line_len > buffer.len) return null;

    @memcpy(buffer[pos..][0..method_str.len], method_str);
    pos += method_str.len;
    buffer[pos] = ' ';
    pos += 1;
    @memcpy(buffer[pos..][0..request.path.len], request.path);
    pos += request.path.len;
    @memcpy(buffer[pos..][0..version_str.len], version_str);
    pos += version_str.len;

    var index: u8 = 0;
    while (index < request.headers.count) : (index += 1) {
        const header = request.headers.headers[index];
        if (client_request.isHopByHopHeader(header.name)) continue;
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;

        const needed = header.name.len + 2 + header.value.len + 2;
        if (pos + needed > buffer.len) return null;

        @memcpy(buffer[pos..][0..header.name.len], header.name);
        pos += header.name.len;
        @memcpy(buffer[pos..][0..2], ": ");
        pos += 2;
        @memcpy(buffer[pos..][0..header.value.len], header.value);
        pos += header.value.len;
        @memcpy(buffer[pos..][0..2], "\r\n");
        pos += 2;
    }

    const transfer_encoding_header = "Transfer-Encoding: chunked\r\n";
    if (pos + transfer_encoding_header.len > buffer.len) return null;
    @memcpy(buffer[pos..][0..transfer_encoding_header.len], transfer_encoding_header);
    pos += transfer_encoding_header.len;

    if (pos + client_request.VIA_HEADER.len > buffer.len) return null;
    @memcpy(buffer[pos..][0..client_request.VIA_HEADER.len], client_request.VIA_HEADER);
    pos += client_request.VIA_HEADER.len;

    if (pos + 2 > buffer.len) return null;
    @memcpy(buffer[pos..][0..2], "\r\n");
    pos += 2;

    return pos;
}

fn sendChunkedBodyData(conn: *Connection, io: Io, payload: []const u8) WebSocketIoError!void {
    assert(@intFromPtr(conn) != 0);
    if (payload.len == 0) return;

    var chunk_size_buf: [18]u8 = undefined;
    const chunk_size = std.fmt.bufPrint(&chunk_size_buf, "{x}\r\n", .{payload.len}) catch return error.WriteFailed;

    try writeAllConnection(conn, io, chunk_size);
    try writeAllConnection(conn, io, payload);
    try writeAllConnection(conn, io, "\r\n");
}

fn sendChunkedBodyTerminator(conn: *Connection, io: Io) WebSocketIoError!void {
    assert(@intFromPtr(conn) != 0);
    try writeAllConnection(conn, io, "0\r\n\r\n");
}

/// Attempts to dispatch a TLS connection with negotiated ALPN `h2` to the generic HTTP/2 frontend.
/// Returns `false` when no TLS stream is present, the peer did not negotiate `h2`, or the handler type already owns explicit `handleH2Headers`/`handleH2Data` termination.
/// When a bridge session pool is needed, it is allocated from the page allocator and released before return.
/// Logs and returns `false` on bridge pool allocation failure; otherwise serves the connection through `h2_server.serveTlsConnection`.
pub fn tryServeTlsAlpnConnection(
    comptime Handler: type,
    comptime Pool: type,
    comptime Tracer: type,
    comptime BridgeHandler: type,
    handler: *Handler,
    forwarder: *forwarder_mod.Forwarder(Pool, Tracer),
    connection_ctx: *Context,
    runtime_cfg: config.H2Config,
    maybe_tls: ?*TLSStream,
    io: Io,
    connection_id: u64,
    frontend_mode: config.TlsH2FrontendMode,
) bool {
    assert(@intFromPtr(handler) != 0);
    assert(@intFromPtr(forwarder) != 0);
    assert(@intFromPtr(connection_ctx) != 0);

    if (frontend_mode == .disabled) {
        // Dispatcher may still route ALPN h2 here as protocol-safety fallback.
        // Keep serving generic h2 rather than attempting h1 on a negotiated h2 conn.
    }

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
    bridge_sessions.initInto(runtime_cfg);
    defer {
        bridge_sessions.deinit();
        std.heap.page_allocator.destroy(bridge_sessions);
    }

    const bridge_handler = std.heap.page_allocator.create(BridgeHandler) catch {
        log.err("server: conn={d} generic h2 bridge handler allocation failed", .{connection_id});
        return false;
    };
    bridge_handler.initInto(
        handler,
        io,
        &bridge_client,
        bridge_sessions,
        connection_ctx,
    );

    const GenericHandler = GenericTlsH2FrontendHandler(Handler, Pool, Tracer, BridgeHandler);
    const generic_handler = std.heap.page_allocator.create(GenericHandler) catch {
        std.heap.page_allocator.destroy(bridge_handler);
        log.err("server: conn={d} generic frontend h2 handler allocation failed", .{connection_id});
        return false;
    };
    GenericHandler.initInto(
        generic_handler,
        handler,
        io,
        forwarder,
        connection_ctx,
        bridge_handler,
    );
    defer {
        generic_handler.deinit();
        std.heap.page_allocator.destroy(generic_handler);
        std.heap.page_allocator.destroy(bridge_handler);
    }

    log.debug("server: conn={d} dispatching ALPN h2 to generic frontend h2 driver", .{connection_id});

    h2_server.serveTlsConnection(
        GenericHandler,
        generic_handler,
        runtime_cfg,
        tls_stream,
        io,
        connection_id,
    ) catch |err| switch (err) {
        error.ConnectionClosed => {},
        else => log.warn("server: conn={d} generic frontend TLS h2 driver failed: {s}", .{ connection_id, @errorName(err) }),
    };
    return true;
}

const WebSocketIoError = error{
    Timeout,
    ConnectionClosed,
    ReadFailed,
    WriteFailed,
};

fn streamWriterFor(template: *h2_server.ResponseWriter, stream_id: u32) h2_server.ResponseWriter {
    assert(@intFromPtr(template) != 0);
    assert(stream_id > 0);

    var writer = template.*;
    writer.stream_id = stream_id;
    return writer;
}

fn timeoutForMilliseconds(timeout_ms: i64) Io.Timeout {
    assert(timeout_ms > 0);
    return .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(timeout_ms),
        .clock = .awake,
    } };
}

fn readSomeConnection(conn: *Connection, io: Io, timeout: Io.Timeout, out: []u8) WebSocketIoError!u32 {
    assert(@intFromPtr(conn) != 0);
    assert(out.len > 0);

    return switch (conn.socket) {
        .plain => |*plain| blk: {
            try waitUntilReadable(plain.fd, io, timeout);
            const n = plain.read(out) catch return error.ReadFailed;
            break :blk n;
        },
        .tls => |*tls_socket| blk: {
            if (!tls_socket.has_pending_read()) try waitUntilReadableTls(tls_socket.fd, io, timeout);
            const n = tls_socket.stream.read(out) catch |err| switch (err) {
                error.WantRead, error.WantWrite => return error.Timeout,
                error.ConnectionReset => return error.ConnectionClosed,
                else => return error.ReadFailed,
            };
            break :blk n;
        },
    };
}

fn writeAllConnection(conn: *Connection, io: Io, data: []const u8) WebSocketIoError!void {
    assert(@intFromPtr(conn) != 0);
    if (data.len == 0) return;

    return switch (conn.socket) {
        .plain => |plain| {
            var writer_buf: [config.SERVER_WRITE_BUFFER_SIZE_BYTES]u8 = undefined;
            var writer = rawStreamForFd(plain.fd).writer(io, &writer_buf);
            writer.interface.writeAll(data) catch return error.WriteFailed;
            writer.interface.flush() catch return error.WriteFailed;
        },
        .tls => |*tls_socket| {
            var sent: usize = 0;
            var iterations: u32 = 0;
            while (sent < data.len and iterations < Socket.max_write_iterations_count) : (iterations += 1) {
                const n = tls_socket.stream.write(data[sent..]) catch |err| switch (err) {
                    error.WouldBlock => {
                        std.Io.sleep(io, Io.Duration.fromMilliseconds(1), .awake) catch return error.WriteFailed;
                        continue;
                    },
                    error.ConnectionReset => return error.ConnectionClosed,
                    else => return error.WriteFailed,
                };
                if (n == 0) return error.ConnectionClosed;
                sent += n;
            }
            if (sent < data.len) return error.WriteFailed;
        },
    };
}

fn waitUntilReadable(fd: i32, io: Io, timeout: Io.Timeout) WebSocketIoError!void {
    assert(fd >= 0);

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
        error.Timeout => return error.Timeout,
        error.ConnectionResetByPeer => return error.ConnectionClosed,
        else => return error.ReadFailed,
    };
}

const tls_readiness_poll_sleep_ms: i64 = 1;
const tls_readiness_max_poll_iterations: u32 = 120_000;

fn waitUntilReadableTls(fd: i32, io: Io, timeout: Io.Timeout) WebSocketIoError!void {
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
            if (remaining.raw.toNanoseconds() <= 0) return error.Timeout;
        }

        std.Io.sleep(io, Io.Duration.fromMilliseconds(tls_readiness_poll_sleep_ms), .awake) catch {
            return error.ReadFailed;
        };
    }

    return error.ReadFailed;
}

fn rawStreamForFd(fd: i32) Io.net.Stream {
    assert(fd >= 0);
    return .{
        .socket = .{
            .handle = fd,
            .address = .{ .ip4 = .unspecified(0) },
        },
    };
}
