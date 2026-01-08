// lib/serval-server/h1/server.zig
//! HTTP/1.1 Server
//!
//! Generic server parameterized by Handler, Pool, Metrics, Tracer.
//! TigerStyle: Comptime verification, explicit dependencies.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const types = serval_core.types;
const context = serval_core.context;
const config = serval_core.config;
const errors = serval_core.errors;
const log = serval_core.log;
const hooks = serval_core.hooks;
const debugLog = serval_core.debugLog;

const serval_net = @import("serval-net");
const setTcpNoDelay = serval_net.setTcpNoDelay;

const pool_mod = @import("serval-pool").pool;
const metrics_mod = @import("serval-metrics").metrics;
const tracing_mod = @import("serval-tracing").tracing;
const SpanHandle = tracing_mod.SpanHandle;
const serval_http = @import("serval-http");
const parser_mod = serval_http.parser;
const parseContentLengthValue = serval_http.parseContentLengthValue;
const forwarder_mod = @import("serval-proxy").forwarder;
const serval_tls = @import("serval-tls");
const ssl = serval_tls.ssl;
const TLSStream = serval_tls.TLSStream;
const HandshakeInfo = serval_tls.HandshakeInfo;

// Local h1 modules
const connection = @import("connection.zig");
const response = @import("response.zig");
const reader = @import("reader.zig");

// Use extracted utilities
const ProcessResult = connection.ProcessResult;
const clientWantsClose = connection.clientWantsClose;
const nextConnectionId = connection.nextConnectionId;
const sendErrorResponse = response.sendErrorResponse;
const sendDirectResponse = response.sendDirectResponse;
const send100Continue = response.send100Continue;
const send501NotImplemented = response.send501NotImplemented;
const readRequest = reader.readRequest;
const readMoreData = reader.readMoreData;
const getBodyLength = reader.getBodyLength;

const Request = types.Request;
const Response = types.Response;
const Context = context.Context;
const Config = config.Config;
const posix = std.posix;

// Time utilities from serval-core
const time = serval_core.time;
const realtimeNanos = time.realtimeNanos;

const Parser = parser_mod.Parser;
const HeaderMap = types.HeaderMap;
const BodyInfo = forwarder_mod.BodyInfo;
const ConnectionInfo = types.ConnectionInfo;

// Buffer sizes from centralized config
const REQUEST_BUFFER_SIZE_BYTES = config.REQUEST_BUFFER_SIZE_BYTES;
const DIRECT_RESPONSE_BUFFER_SIZE_BYTES = config.DIRECT_RESPONSE_BUFFER_SIZE_BYTES;

// =============================================================================
// Server
// =============================================================================

pub fn Server(
    comptime Handler: type,
    comptime Pool: type,
    comptime Metrics: type,
    comptime Tracer: type,
) type {
    // Compile-time interface verification
    comptime {
        hooks.verifyHandler(Handler);
        pool_mod.verifyPool(Pool);
        metrics_mod.verifyMetrics(Metrics);
        tracing_mod.verifyTracer(Tracer);
    }

    return struct {
        const Self = @This();

        handler: *Handler,
        pool: *Pool,
        metrics: *Metrics,
        tracer: *Tracer,
        config: Config,
        forwarder: forwarder_mod.Forwarder(Pool, Tracer),

        pub fn init(
            handler: *Handler,
            pool: *Pool,
            metrics: *Metrics,
            tracer: *Tracer,
            cfg: Config,
        ) Self {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(pool) != 0);
            assert(@intFromPtr(metrics) != 0);
            assert(@intFromPtr(tracer) != 0);

            // Get verify_upstream setting from TlsConfig (default: true)
            const verify_upstream = if (cfg.tls) |tls_cfg| tls_cfg.verify_upstream else true;

            return .{
                .handler = handler,
                .pool = pool,
                .metrics = metrics,
                .tracer = tracer,
                .config = cfg,
                .forwarder = forwarder_mod.Forwarder(Pool, Tracer).init(pool, tracer, verify_upstream),
            };
        }

        /// Run the server with concurrent connection handling.
        /// TigerStyle: Explicit resource cleanup with defer.
        pub fn run(self: *Self, io: Io, shutdown: *std.atomic.Value(bool)) !void {
            assert(self.config.port > 0);

            const addr = Io.net.IpAddress.parse("0.0.0.0", self.config.port) catch
                return error.InvalidAddress;

            var tcp_server = addr.listen(io, .{
                .kernel_backlog = self.config.kernel_backlog,
                .reuse_address = true,
            }) catch return error.ListenFailed;
            defer tcp_server.deinit(io);

            // TLS: Initialize SSL_CTX if TLS is configured
            // TigerStyle: C5 - Resource grouping with immediate defer
            const tls_ctx: ?*ssl.SSL_CTX = if (self.config.tls) |tls_cfg| blk: {
                ssl.init();
                const ctx = try ssl.createServerCtx();
                // S1: postcondition - ctx is non-null (verified in createServerCtx)

                // TigerStyle: Use c_allocator for long-lived TLS resources (already linking libc)
                const allocator = std.heap.c_allocator;

                // Load certificate chain
                const cert_z = try allocator.dupeZ(u8, tls_cfg.cert_path.?);
                defer allocator.free(cert_z);
                assert(cert_z.len > 0); // S1: precondition
                if (ssl.SSL_CTX_use_certificate_chain_file(ctx, cert_z) != 1) {
                    ssl.printErrors();
                    return error.LoadCertFailed;
                }

                // Load private key
                const key_z = try allocator.dupeZ(u8, tls_cfg.key_path.?);
                defer allocator.free(key_z);
                assert(key_z.len > 0); // S1: precondition
                if (ssl.SSL_CTX_use_PrivateKey_file(ctx, key_z, ssl.SSL_FILETYPE_PEM) != 1) {
                    ssl.printErrors();
                    return error.LoadKeyFailed;
                }

                break :blk ctx;
            } else null;
            defer if (tls_ctx) |ctx| ssl.SSL_CTX_free(ctx);

            var group: Io.Group = .init;
            defer group.cancel(io);

            while (!shutdown.load(.acquire)) {
                const stream = tcp_server.accept(io) catch |err| {
                    if (shutdown.load(.acquire)) break;
                    std.log.err("Accept failed: {s}", .{@errorName(err)});
                    continue;
                };

                group.concurrent(io, handleConnectionImpl, .{
                    self.handler,
                    &self.forwarder,
                    self.metrics,
                    self.tracer,
                    self.config,
                    tls_ctx,
                    io,
                    stream,
                }) catch |err| {
                    std.log.err("Failed to spawn handler: {s}", .{@errorName(err)});
                    stream.close(io);
                };
            }
        }

        // =========================================================================
        // I/O Wrapper Functions (TLS or Plain)
        // TigerStyle: Abstract TLS vs plain socket I/O
        // =========================================================================

        /// Read from connection (TLS or plain).
        /// TigerStyle: Runtime dispatch based on TLS availability.
        fn connectionRead(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            buf: []u8,
        ) ?usize {
            assert(buf.len > 0); // S1: precondition

            if (maybe_tls) |tls| {
                // TLS read (blocking - std.Io handles socket-level async)
                // SslRead error includes normal client disconnect, don't log as error.
                var mutable_tls = tls.*;
                const n = mutable_tls.read(buf) catch return null;
                return n;
            } else {
                // Plain socket read
                var reader_buf: [1]u8 = std.mem.zeroes([1]u8);
                var stream_reader = stream.reader(io.*, &reader_buf);
                var bufs: [1][]u8 = .{buf};
                const n = stream_reader.interface.readVec(&bufs) catch |err| {
                    if (err != error.EndOfStream) {
                        debugLog("Read error: {s}", .{@errorName(err)});
                    }
                    return null;
                };
                if (n == 0) return null; // S1: postcondition
                return n;
            }
        }

        /// Write to connection (TLS or plain).
        /// TigerStyle: Runtime dispatch based on TLS availability.
        fn connectionWrite(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            data: []const u8,
        ) !void {
            assert(data.len > 0); // S1: precondition

            if (maybe_tls) |tls| {
                // TLS write (blocking - std.Io handles socket-level async)
                var mutable_tls = tls.*;
                _ = try mutable_tls.write(data);
            } else {
                // Plain socket write
                var write_buf: [config.SERVER_WRITE_BUFFER_SIZE_BYTES]u8 =
                    std.mem.zeroes([config.SERVER_WRITE_BUFFER_SIZE_BYTES]u8);
                var writer = stream.writer(io.*, &write_buf);
                try writer.interface.writeAll(data);
                try writer.interface.flush();
            }
        }

        // =========================================================================
        // Helper Functions for handleConnectionImpl
        // TigerStyle: Extract to keep functions under 70 lines
        // =========================================================================

        /// Accumulate reads until complete headers (\r\n\r\n) are received.
        /// Returns true if headers complete, false on error (already sent error response).
        /// TigerStyle: Bounded loop with explicit iteration limit.
        fn accumulateHeaders(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            recv_buf: *[REQUEST_BUFFER_SIZE_BYTES]u8,
            buffer_offset: usize,
            buffer_len: *usize,
            cfg: Config,
        ) bool {
            // TigerStyle: Bounded loop - max 16 iterations to receive complete headers
            const max_read_iterations: u32 = 16;
            var read_iterations: u32 = 0;
            _ = cfg; // Unused after removing timeout logic

            while (std.mem.indexOf(u8, recv_buf[buffer_offset..buffer_len.*], "\r\n\r\n") == null) {
                read_iterations += 1;
                if (read_iterations >= max_read_iterations) {
                    sendErrorResponseTls(maybe_tls, io, stream, 400, "Bad Request");
                    return false;
                }
                if (buffer_len.* >= recv_buf.len) {
                    sendErrorResponseTls(maybe_tls, io, stream, 431, "Request Header Fields Too Large");
                    return false;
                }
                const n = connectionRead(maybe_tls, io, stream, recv_buf[buffer_len.*..]) orelse return false;
                if (n == 0) return false;
                buffer_len.* += n;
            }
            return true;
        }

        /// Send error response (TLS-aware).
        /// TigerStyle: Wrapper for response.sendErrorResponse with TLS support.
        fn sendErrorResponseTls(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            status: u16,
            message: []const u8,
        ) void {
            assert(status >= 400 and status < 600); // S1: precondition
            assert(message.len > 0); // S1: precondition

            // Format error response
            var response_buf: [config.RESPONSE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([config.RESPONSE_BUFFER_SIZE_BYTES]u8);
            const response_text = std.fmt.bufPrint(
                &response_buf,
                "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
                .{ status, response.statusText(status), message.len, message },
            ) catch return;

            connectionWrite(maybe_tls, io, stream, response_text) catch return;
        }

        /// Send 100 Continue response (TLS-aware).
        /// TigerStyle: Wrapper for response.send100Continue with TLS support.
        fn send100ContinueTls(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
        ) void {
            const response_text = "HTTP/1.1 100 Continue\r\n\r\n";
            assert(std.mem.endsWith(u8, response_text, "\r\n\r\n")); // S2: postcondition
            connectionWrite(maybe_tls, io, stream, response_text) catch return;
        }

        /// Send 501 Not Implemented response (TLS-aware).
        /// TigerStyle: Wrapper for response.send501NotImplemented with TLS support.
        fn send501NotImplementedTls(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            message: []const u8,
        ) void {
            assert(message.len > 0); // S1: precondition

            var response_buf: [config.RESPONSE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([config.RESPONSE_BUFFER_SIZE_BYTES]u8);
            const response_text = std.fmt.bufPrint(
                &response_buf,
                "HTTP/1.1 501 {s}\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
                .{ response.statusText(501), message.len, message },
            ) catch return;

            connectionWrite(maybe_tls, io, stream, response_text) catch return;
        }

        /// Send direct response from handler (TLS-aware).
        /// TigerStyle: Wrapper for response.sendDirectResponse with TLS support.
        fn sendDirectResponseTls(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            resp: types.DirectResponse,
        ) void {
            assert(resp.status >= 100 and resp.status < 600); // S1: precondition
            assert(resp.content_type.len > 0); // S1: precondition

            // Format headers
            var header_buf: [config.DIRECT_RESPONSE_HEADER_SIZE_BYTES]u8 =
                std.mem.zeroes([config.DIRECT_RESPONSE_HEADER_SIZE_BYTES]u8);

            const headers = switch (resp.response_mode) {
                .content_length => std.fmt.bufPrint(
                    &header_buf,
                    "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n{s}\r\n",
                    .{ resp.status, response.statusText(resp.status), resp.content_type, resp.body.len, resp.extra_headers },
                ) catch return,
                .chunked => blk: {
                    // Format chunk header for chunked encoding
                    var chunk_header_buf: [20]u8 = std.mem.zeroes([20]u8);
                    const chunk_header = std.fmt.bufPrint(
                        &chunk_header_buf,
                        "{x}\r\n",
                        .{resp.body.len},
                    ) catch return;

                    const headers_text = std.fmt.bufPrint(
                        &header_buf,
                        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nTransfer-Encoding: chunked\r\n{s}\r\n{s}",
                        .{ resp.status, response.statusText(resp.status), resp.content_type, resp.extra_headers, chunk_header },
                    ) catch return;
                    break :blk headers_text;
                },
            };

            // Write headers and body
            connectionWrite(maybe_tls, io, stream, headers) catch return;
            connectionWrite(maybe_tls, io, stream, resp.body) catch return;

            // Add chunk terminator for chunked encoding
            if (resp.response_mode == .chunked) {
                const terminator = "\r\n0\r\n\r\n";
                connectionWrite(maybe_tls, io, stream, terminator) catch return;
            }
        }

        /// Build tracing span name from request method and path.
        /// Format: "METHOD /path" (e.g., "GET /api/users")
        /// TigerStyle: Bounded copy, no allocation.
        fn buildSpanName(
            method: types.Method,
            path: []const u8,
            buf: *[config.OTEL_MAX_NAME_LEN]u8,
        ) []const u8 {
            const method_str = @tagName(method);
            const span_name_len = @min(method_str.len + 1 + path.len, buf.len);

            // TigerStyle: Explicit bounded copies
            @memcpy(buf[0..method_str.len], method_str);
            buf[method_str.len] = ' ';
            const path_copy_len = @min(path.len, buf.len - method_str.len - 1);
            @memcpy(buf[method_str.len + 1 ..][0..path_copy_len], path[0..path_copy_len]);

            return buf[0..span_name_len];
        }

        /// Extract body info for request forwarding.
        /// Uses parser's body_framing to determine Content-Length vs chunked vs none.
        /// TigerStyle: Explicit calculation, bounded by content_length or chunk structure.
        fn buildBodyInfo(
            parser: *const Parser,
            recv_buf: []const u8,
            buffer_offset: usize,
            buffer_len: usize,
        ) BodyInfo {
            const headers_end = parser.headers_end;
            const data_after_headers = buffer_len - buffer_offset - headers_end;

            // Calculate bytes already read based on framing mode.
            // For Content-Length: bounded by actual length.
            // For chunked: all data after headers is partial chunk data.
            // For none: no body expected.
            const body_bytes_in_buffer: u64 = switch (parser.body_framing) {
                .content_length => |cl| @min(data_after_headers, cl),
                .chunked => data_after_headers, // May contain partial chunk
                .none => 0,
            };

            return BodyInfo{
                .framing = parser.body_framing,
                .bytes_already_read = body_bytes_in_buffer,
                .initial_body = if (body_bytes_in_buffer > 0)
                    recv_buf[buffer_offset + headers_end ..][0..@intCast(body_bytes_in_buffer)]
                else
                    &[_]u8{},
            };
        }

        /// Handle HTTP/1.1 connection with keep-alive and pipelining support.
        /// Processes multiple requests until: client sends Connection: close,
        /// max requests reached, or error occurs.
        /// TigerStyle: All 8 dependencies explicit at call site, no hidden state.
        /// Supports HTTP pipelining: multiple requests in single TCP read are processed.
        fn handleConnectionImpl(
            handler: *Handler,
            forwarder: *forwarder_mod.Forwarder(Pool, Tracer),
            metrics: *Metrics,
            tracer: *Tracer,
            cfg: Config,
            tls_ctx: ?*ssl.SSL_CTX,
            io: Io,
            stream: Io.net.Stream,
        ) void {
            // TigerStyle: Precondition assertions
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(forwarder) != 0);
            assert(@intFromPtr(metrics) != 0);
            assert(@intFromPtr(tracer) != 0);
            assert(cfg.max_requests_per_connection > 0);

            // Setup: TCP_NODELAY, connection ID, metrics
            _ = setTcpNoDelay(stream.socket.handle);
            const connection_id = nextConnectionId();
            const connection_start_ns = realtimeNanos();
            defer stream.close(io);
            metrics.connectionOpened();
            defer metrics.connectionClosed();

            // TLS: Perform handshake if TLS is configured
            // TigerStyle: Blocking handshake - std.Io handles socket-level async
            var maybe_tls_stream: ?TLSStream = if (tls_ctx) |ctx| blk: {
                // S1: precondition - ctx is non-null (enforced by if guard above)
                const allocator = std.heap.c_allocator;

                // Start TLS handshake span for tracing
                const tls_span = tracer.startSpan("tls.handshake.server", null);

                const tls_stream = TLSStream.initServer(
                    ctx,
                    @intCast(stream.socket.handle),
                    allocator,
                ) catch |err| {
                    // End span with error
                    tracer.endSpan(tls_span, @errorName(err));
                    std.log.err("TLS handshake failed: {s}", .{@errorName(err)});
                    return;
                };

                // Add handshake attributes to span
                const info = &tls_stream.info;
                tracer.setStringAttribute(tls_span, "tls.version", info.version());
                tracer.setStringAttribute(tls_span, "tls.cipher", info.cipher());
                tracer.setIntAttribute(tls_span, "tls.handshake_duration_ns", @intCast(info.handshake_duration_ns));
                tracer.setStringAttribute(tls_span, "tls.resumed", if (info.resumed) "true" else "false");
                tracer.setStringAttribute(tls_span, "tls.client_mode", "false");
                if (info.alpn()) |alpn_proto| {
                    tracer.setStringAttribute(tls_span, "tls.alpn_protocol", alpn_proto);
                }
                if (info.certSubject()) |subj| {
                    tracer.setStringAttribute(tls_span, "tls.peer_cert.subject", subj);
                }
                if (info.certIssuer()) |issuer| {
                    tracer.setStringAttribute(tls_span, "tls.peer_cert.issuer", issuer);
                }
                tracer.endSpan(tls_span, null);

                break :blk tls_stream;
            } else null;
            defer if (maybe_tls_stream) |*tls_stream| tls_stream.close();

            // Initialize context with connection-scoped fields
            var ctx = Context.init();
            ctx.connection_id = connection_id;
            ctx.connection_start_ns = connection_start_ns;
            ctx.request_number = 0;

            // Connection lifecycle hooks
            if (comptime hooks.hasHook(Handler, "onConnectionOpen")) {
                handler.onConnectionOpen(&ConnectionInfo{
                    .connection_id = connection_id,
                    .client_addr = ctx.client_addr,
                    .client_port = ctx.client_port,
                    .local_port = cfg.port,
                    .tcp_rtt_us = 0,
                    .tcp_rtt_var_us = 0,
                });
            }
            defer {
                if (comptime hooks.hasHook(Handler, "onConnectionClose")) {
                    const elapsed = realtimeNanos() - connection_start_ns;
                    handler.onConnectionClose(connection_id, ctx.request_number, if (elapsed >= 0) @intCast(elapsed) else 0);
                }
            }

            // Mutable io for TLS operations (io is passed by value)
            var io_mut = io;

            // Get mutable pointer to TLS stream for I/O operations (if TLS is active)
            // TigerStyle: Mutable pointer needed for forwarder to write TLS responses.
            const maybe_tls_ptr: ?*TLSStream = if (maybe_tls_stream) |*tls| tls else null;

            // Request processing state
            var parser = Parser.init();
            var recv_buf: [REQUEST_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([REQUEST_BUFFER_SIZE_BYTES]u8);
            var request_count: u32 = 0;
            var buffer_offset: usize = 0;
            var buffer_len: usize = 0;

            // Direct response buffer - only allocated if handler has onRequest hook.
            // TigerStyle: Comptime conditional eliminates overhead for pure proxy handlers.
            const has_on_request = comptime hooks.hasHook(Handler, "onRequest");
            const ResponseBufType = if (has_on_request) [DIRECT_RESPONSE_BUFFER_SIZE_BYTES]u8 else void;
            var response_buf: ResponseBufType = if (has_on_request)
                std.mem.zeroes([DIRECT_RESPONSE_BUFFER_SIZE_BYTES]u8)
            else {};

            while (request_count < cfg.max_requests_per_connection) {
                request_count += 1;
                ctx.reset();
                parser.reset();

                // Pipelining: reuse leftover data or read new data
                if (buffer_offset >= buffer_len) {
                    const n = connectionRead(maybe_tls_ptr, &io_mut, stream, &recv_buf) orelse return;
                    buffer_len = n;
                    buffer_offset = 0;
                }

                // Accumulate reads until complete headers received
                if (!accumulateHeaders(maybe_tls_ptr, &io_mut, stream, &recv_buf, buffer_offset, &buffer_len, cfg)) return;

                ctx.bytes_received = @intCast(buffer_len - buffer_offset);
                metrics.requestStart();

                // Parse headers
                const parse_start = realtimeNanos();
                parser.parseHeaders(recv_buf[buffer_offset..buffer_len]) catch {
                    sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, 400, "Bad Request");
                    metrics.requestEnd(400, @intCast(realtimeNanos() - ctx.start_time_ns));
                    return;
                };
                ctx.parse_duration_ns = @intCast(@max(0, realtimeNanos() - parse_start));

                // RFC 7231: CONNECT is a forward proxy feature, not reverse proxy
                if (parser.request.method == .CONNECT) {
                    send501NotImplementedTls(maybe_tls_ptr, &io_mut, stream, "CONNECT method not supported");
                    metrics.requestEnd(501, @intCast(realtimeNanos() - ctx.start_time_ns));
                    const body_length = getBodyLength(&parser.request);
                    buffer_offset += parser.headers_end + body_length;
                    continue;
                }

                // RFC 7231 Section 5.1.1: Handle Expect: 100-continue
                if (parser.request.headers.get("Expect")) |expect| {
                    if (std.ascii.eqlIgnoreCase(expect, "100-continue")) {
                        send100ContinueTls(maybe_tls_ptr, &io_mut, stream);
                    }
                }

                // Start a tracing span for this request
                var span_name_buf: [config.OTEL_MAX_NAME_LEN]u8 = std.mem.zeroes([config.OTEL_MAX_NAME_LEN]u8);
                const span_name = buildSpanName(parser.request.method, parser.request.path, &span_name_buf);
                const span_handle = tracer.startSpan(span_name, null);
                ctx.span_handle = span_handle;

                // Call onRequest hook if present
                if (comptime has_on_request) {
                    switch (handler.onRequest(&ctx, &parser.request, &response_buf)) {
                        .continue_request => {}, // Fall through to selectUpstream
                        .send_response => |resp| {
                            // Handler wants to send direct response without forwarding
                            sendDirectResponseTls(maybe_tls_ptr, &io_mut, stream, resp);
                            const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                            metrics.requestEnd(resp.status, duration_ns);
                            tracer.endSpan(span_handle, null);
                            const body_length = getBodyLength(&parser.request);
                            buffer_offset += parser.headers_end + body_length;
                            continue;
                        },
                    }
                }

                // Select upstream and forward
                var upstream = handler.selectUpstream(&ctx, &parser.request);
                ctx.upstream = upstream;

                // Extract body info and forward
                const body_info = buildBodyInfo(&parser, &recv_buf, buffer_offset, buffer_len);
                const forward_result = forwarder.forward(io, stream, maybe_tls_ptr, &parser.request, &upstream, body_info, span_handle);

                const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                ctx.duration_ns = duration_ns;

                // Calculate where this request ends for pipelining
                const body_length = getBodyLength(&parser.request);
                const request_end = buffer_offset + parser.headers_end + body_length;

                // Process result and determine connection state
                const result: ProcessResult = if (forward_result) |fwd_result| blk: {
                    handleForwardSuccessImpl(handler, metrics, &ctx, &parser.request, fwd_result, duration_ns);
                    tracer.endSpan(span_handle, null);

                    const should_close = clientWantsClose(&parser.request.headers) or
                        request_count >= cfg.max_requests_per_connection;

                    break :blk if (should_close) .close_connection else .keep_alive;
                } else |err| blk: {
                    handleForwardErrorImpl(handler, metrics, maybe_tls_ptr, &io_mut, stream, &ctx, &parser.request, upstream, err, duration_ns);
                    tracer.endSpan(span_handle, @errorName(err));
                    break :blk .fatal_error;
                };

                buffer_offset = request_end;

                if (result != .keep_alive) return;
            }
        }

        /// Handle successful forward: update metrics and call onLog hook.
        /// TigerStyle: Standalone function with explicit dependencies.
        fn handleForwardSuccessImpl(
            handler: *Handler,
            metrics: *Metrics,
            ctx: *Context,
            request: *const Request,
            result: forwarder_mod.ForwardResult,
            duration_ns: u64,
        ) void {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(metrics) != 0);

            ctx.response_status = result.status;
            ctx.bytes_sent = result.response_bytes;

            // Track per-upstream stats if metrics supports it and upstream is set
            if (comptime @hasDecl(Metrics, "requestEndWithUpstream")) {
                if (ctx.upstream) |up| {
                    metrics.requestEndWithUpstream(result.status, duration_ns, up.idx);
                } else {
                    metrics.requestEnd(result.status, duration_ns);
                }
            } else {
                metrics.requestEnd(result.status, duration_ns);
            }

            if (comptime hooks.hasHook(Handler, "onLog")) {
                const log_entry = log.LogEntry{
                    .timestamp_s = @intCast(@divFloor(ctx.start_time_ns, std.time.ns_per_s)),
                    .start_time_ns = ctx.start_time_ns,
                    .duration_ns = duration_ns,
                    .method = request.method,
                    .path = request.path,
                    .request_bytes = ctx.bytes_received,
                    .status = result.status,
                    .response_bytes = result.response_bytes,
                    .upstream = ctx.upstream,
                    .upstream_duration_ns = duration_ns,
                    .error_phase = null,
                    .error_name = null,
                    .connection_reused = result.connection_reused,
                    .keepalive = true,
                    .parse_duration_ns = ctx.parse_duration_ns,
                    .connect_duration_ns = result.tcp_connect_duration_ns,
                    .send_duration_ns = result.send_duration_ns,
                    .recv_duration_ns = result.recv_duration_ns,
                    .dns_duration_ns = result.dns_duration_ns,
                    .tcp_connect_duration_ns = result.tcp_connect_duration_ns,
                    .pool_wait_ns = result.pool_wait_ns,
                    .connection_id = ctx.connection_id,
                    .request_number = ctx.request_number,
                    .client_addr = ctx.client_addr,
                    .upstream_local_port = result.upstream_local_port,
                };
                handler.onLog(ctx, log_entry);
            }
        }

        /// Handle forward error: call onError hook, send 502, update metrics.
        /// TigerStyle: Standalone function with explicit dependencies.
        fn handleForwardErrorImpl(
            handler: *Handler,
            metrics: *Metrics,
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            ctx: *Context,
            request: *const Request,
            upstream: types.Upstream,
            err: forwarder_mod.ForwardError,
            duration_ns: u64,
        ) void {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(metrics) != 0);

            const error_phase = forwardErrorToPhase(err);

            if (comptime hooks.hasHook(Handler, "onError")) {
                const error_ctx = errors.ErrorContext{
                    .err = forwardErrorToRequestError(err),
                    .phase = error_phase,
                    .upstream = upstream,
                    .is_retry = false,
                };
                handler.onError(ctx, error_ctx);
            }

            sendErrorResponseTls(maybe_tls, io, stream, 502, "Bad Gateway");
            ctx.response_status = 502;

            // Track per-upstream stats if metrics supports it
            if (comptime @hasDecl(Metrics, "requestEndWithUpstream")) {
                metrics.requestEndWithUpstream(502, duration_ns, upstream.idx);
            } else {
                metrics.requestEnd(502, duration_ns);
            }

            if (comptime hooks.hasHook(Handler, "onLog")) {
                const log_entry = log.LogEntry{
                    .timestamp_s = @intCast(@divFloor(ctx.start_time_ns, std.time.ns_per_s)),
                    .start_time_ns = ctx.start_time_ns,
                    .duration_ns = duration_ns,
                    .method = request.method,
                    .path = request.path,
                    .request_bytes = ctx.bytes_received,
                    .status = 502,
                    .response_bytes = 0,
                    .upstream = ctx.upstream,
                    .upstream_duration_ns = duration_ns,
                    .error_phase = error_phase,
                    .error_name = @errorName(err),
                    .connection_reused = false,
                    .keepalive = false,
                    .parse_duration_ns = ctx.parse_duration_ns,
                    .connection_id = ctx.connection_id,
                    .request_number = ctx.request_number,
                    .client_addr = ctx.client_addr,
                };
                handler.onLog(ctx, log_entry);
            }
        }

        /// Map ForwardError to ErrorContext.Phase
        fn forwardErrorToPhase(err: forwarder_mod.ForwardError) errors.ErrorContext.Phase {
            return switch (err) {
                forwarder_mod.ForwardError.ConnectFailed,
                forwarder_mod.ForwardError.InvalidAddress,
                => .connect,
                forwarder_mod.ForwardError.SendFailed,
                forwarder_mod.ForwardError.StaleConnection,
                forwarder_mod.ForwardError.RequestBodyTooLarge,
                => .send,
                forwarder_mod.ForwardError.RecvFailed,
                forwarder_mod.ForwardError.HeadersTooLarge,
                forwarder_mod.ForwardError.InvalidResponse,
                forwarder_mod.ForwardError.SpliceFailed,
                => .recv,
            };
        }

        /// Map ForwardError to RequestError for error context
        fn forwardErrorToRequestError(err: forwarder_mod.ForwardError) errors.RequestError {
            return switch (err) {
                forwarder_mod.ForwardError.ConnectFailed => error.ConnectFailed,
                forwarder_mod.ForwardError.InvalidAddress => error.ConnectFailed,
                forwarder_mod.ForwardError.SendFailed => error.SendFailed,
                forwarder_mod.ForwardError.StaleConnection => error.StaleConnection,
                forwarder_mod.ForwardError.RequestBodyTooLarge => error.BodyTooLarge,
                forwarder_mod.ForwardError.RecvFailed => error.RecvFailed,
                forwarder_mod.ForwardError.HeadersTooLarge => error.InvalidResponse,
                forwarder_mod.ForwardError.InvalidResponse => error.InvalidResponse,
                forwarder_mod.ForwardError.SpliceFailed => error.RecvFailed,
            };
        }
    };
}

/// Convenience: Server with minimal overhead
pub fn MinimalServer(comptime Handler: type) type {
    return Server(Handler, pool_mod.SimplePool, metrics_mod.NoopMetrics, tracing_mod.NoopTracer);
}

// =============================================================================
// Tests
// =============================================================================

const TestHandler = struct {
    call_count: u32 = 0,

    pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) types.Upstream {
        _ = ctx;
        _ = request;
        self.call_count += 1;
        return .{ .host = "127.0.0.1", .port = 8001, .idx = 0 };
    }
};

test "Server compiles with valid handler" {
    var handler = TestHandler{};
    var pool = pool_mod.SimplePool.init();
    var metrics = metrics_mod.NoopMetrics{};
    var tracer = tracing_mod.NoopTracer{};

    const server = Server(TestHandler, pool_mod.SimplePool, metrics_mod.NoopMetrics, tracing_mod.NoopTracer)
        .init(&handler, &pool, &metrics, &tracer, .{});

    try std.testing.expectEqual(@as(u16, 8080), server.config.port);
}

test "MinimalServer compiles" {
    var handler = TestHandler{};
    var pool = pool_mod.SimplePool.init();
    var metrics = metrics_mod.NoopMetrics{};
    var tracer = tracing_mod.NoopTracer{};

    _ = MinimalServer(TestHandler).init(&handler, &pool, &metrics, &tracer, .{});
}

test "parseContentLengthValue valid" {
    try std.testing.expectEqual(@as(?u64, 0), parseContentLengthValue("0"));
    try std.testing.expectEqual(@as(?u64, 1234), parseContentLengthValue("1234"));
    try std.testing.expectEqual(@as(?u64, 18446744073709551615), parseContentLengthValue("18446744073709551615"));
}

test "parseContentLengthValue rejects leading zeros" {
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("007"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("00"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("0123"));
    try std.testing.expectEqual(@as(?u64, 0), parseContentLengthValue("0"));
}

test "parseContentLengthValue invalid" {
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue(""));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("abc"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("12a34"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("18446744073709551616"));
}
