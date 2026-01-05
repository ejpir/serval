// lib/serval-server/http1.zig
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

/// Global connection counter for unique connection IDs.
/// TigerStyle: Module-level state with atomic access, monotonic ordering sufficient.
var global_connection_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// Buffer sizes from centralized config
const REQUEST_BUFFER_SIZE_BYTES = config.REQUEST_BUFFER_SIZE_BYTES;
const RESPONSE_BUFFER_SIZE_BYTES = config.RESPONSE_BUFFER_SIZE_BYTES;
const WRITE_BUFFER_SIZE_BYTES = config.SERVER_WRITE_BUFFER_SIZE_BYTES;

// =============================================================================
// Connection Handling (RFC 9112)
// =============================================================================

/// Result of processing a single HTTP request.
/// TigerStyle: Explicit enum for control flow, no magic booleans.
const ProcessResult = enum {
    keep_alive,
    close_connection,
    fatal_error,
};

/// Check if client requested connection close (RFC 9112).
/// HTTP/1.1 defaults to keep-alive, only close if explicitly requested.
fn clientWantsClose(headers: *const HeaderMap) bool {
    assert(@intFromPtr(headers) != 0);
    const conn = headers.get("Connection") orelse return false;
    if (conn.len != 5) return false;
    return std.ascii.eqlIgnoreCase(conn, "close");
}

/// Get HTTP status text for status code.
fn statusText(status: u16) []const u8 {
    return switch (status) {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        else => "Error",
    };
}

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

            return .{
                .handler = handler,
                .pool = pool,
                .metrics = metrics,
                .tracer = tracer,
                .config = cfg,
                .forwarder = forwarder_mod.Forwarder(Pool, Tracer).init(pool, tracer),
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
                    io,
                    stream,
                }) catch |err| {
                    std.log.err("Failed to spawn handler: {s}", .{@errorName(err)});
                    stream.close(io);
                };
            }
        }

        /// Handle HTTP/1.1 connection with keep-alive and pipelining support.
        /// Processes multiple requests until: client sends Connection: close,
        /// max requests reached, or error occurs.
        /// TigerStyle: All 7 dependencies explicit at call site, no hidden state.
        /// Supports HTTP pipelining: multiple requests in single TCP read are processed.
        fn handleConnectionImpl(
            handler: *Handler,
            forwarder: *forwarder_mod.Forwarder(Pool, Tracer),
            metrics: *Metrics,
            tracer: *Tracer,
            cfg: Config,
            io: Io,
            stream: Io.net.Stream,
        ) void {
            // Precondition assertions
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(forwarder) != 0);
            assert(@intFromPtr(metrics) != 0);
            assert(@intFromPtr(tracer) != 0); // Reserved for future tracing integration
            assert(cfg.max_requests_per_connection > 0);

            // Disable Nagle's algorithm for low-latency responses
            // TigerStyle: Explicit discard - TCP_NODELAY is optimization, not required
            _ = setTcpNoDelay(stream.socket.handle);

            // Generate unique connection ID
            const connection_id = global_connection_id.fetchAdd(1, .monotonic);
            const connection_start_ns = realtimeNanos();

            defer stream.close(io);

            metrics.connectionOpened();
            defer metrics.connectionClosed();

            var ctx = Context.init();

            // Set connection-scoped context fields
            ctx.connection_id = connection_id;
            ctx.connection_start_ns = connection_start_ns;
            ctx.request_number = 0;
            // Client address extraction would require socket options (SO_PEERNAME)
            // Left zeroed for now; can be extracted in future enhancement

            // Call onConnectionOpen hook if handler implements it
            if (comptime hooks.hasHook(Handler, "onConnectionOpen")) {
                const info = ConnectionInfo{
                    .connection_id = connection_id,
                    .client_addr = ctx.client_addr,
                    .client_port = ctx.client_port,
                    .local_port = cfg.port,
                    .tcp_rtt_us = 0, // Could be extracted from TCP_INFO socket option
                    .tcp_rtt_var_us = 0,
                };
                handler.onConnectionOpen(&info);
            }

            // Call onConnectionClose hook when connection ends
            defer {
                if (comptime hooks.hasHook(Handler, "onConnectionClose")) {
                    const duration_ns: u64 = blk: {
                        const now = realtimeNanos();
                        const elapsed = now - connection_start_ns;
                        break :blk if (elapsed >= 0) @intCast(elapsed) else 0;
                    };
                    handler.onConnectionClose(connection_id, ctx.request_number, duration_ns);
                }
            }

            var parser = Parser.init();
            var recv_buf: [REQUEST_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([REQUEST_BUFFER_SIZE_BYTES]u8);
            var request_count: u32 = 0;

            // Pipelining support: track unprocessed data in buffer
            // buffer_offset: start of unprocessed data
            // buffer_len: total valid bytes in buffer
            var buffer_offset: usize = 0;
            var buffer_len: usize = 0;

            while (request_count < cfg.max_requests_per_connection) {
                request_count += 1;
                ctx.reset();
                parser.reset();

                // Read and parse request
                debugLog("server: conn={d} waiting for request", .{connection_id});
                const read_start = realtimeNanos();

                // Pipelining: if no leftover data from previous request, read new data
                if (buffer_offset >= buffer_len) {
                    const n = readRequestImpl(io, stream, &recv_buf) orelse return;
                    buffer_len = n;
                    buffer_offset = 0;
                }

                // Accumulate reads until complete headers are received (\r\n\r\n)
                // TigerStyle: bounded loop - max iterations limited by buffer size
                const max_read_iterations: u32 = 16; // Prevent infinite loop on pathological input
                var read_iterations: u32 = 0;
                while (std.mem.indexOf(u8, recv_buf[buffer_offset..buffer_len], "\r\n\r\n") == null) {
                    read_iterations += 1;
                    if (read_iterations >= max_read_iterations) {
                        // Too many reads without complete headers - likely attack or broken client
                        sendErrorResponseImpl(io, stream, 400, "Bad Request");
                        return;
                    }
                    if (buffer_len >= recv_buf.len) {
                        // Headers too large - cannot fit in buffer
                        sendErrorResponseImpl(io, stream, 431, "Request Header Fields Too Large");
                        return;
                    }
                    // Read more data into remaining buffer space
                    const n = readMoreDataImpl(io, stream, recv_buf[buffer_len..]) orelse return;
                    if (n == 0) return; // Client closed connection
                    buffer_len += n;
                }

                const read_elapsed = realtimeNanos() - read_start;
                const read_duration_us: u64 = if (read_elapsed >= 0) @intCast(@divFloor(read_elapsed, 1000)) else 0;
                debugLog("server: conn={d} received bytes={d} read_us={d}", .{ connection_id, buffer_len - buffer_offset, read_duration_us });
                ctx.bytes_received = @intCast(buffer_len - buffer_offset);
                metrics.requestStart();

                // Time the parse phase - parse from current offset
                const parse_start = realtimeNanos();
                parser.parseHeaders(recv_buf[buffer_offset..buffer_len]) catch |err| {
                    sendErrorResponseImpl(io, stream, 400, "Bad Request");
                    metrics.requestEnd(400, @intCast(realtimeNanos() - ctx.start_time_ns));
                    debugLog("Parse error: {s}", .{@errorName(err)});
                    return; // fatal_error: close connection after parse error
                };
                const parse_elapsed = realtimeNanos() - parse_start;
                ctx.parse_duration_ns = if (parse_elapsed >= 0) @intCast(parse_elapsed) else 0;

                // RFC 7231: CONNECT is a forward proxy feature, not reverse proxy
                // Return 501 Not Implemented
                if (parser.request.method == .CONNECT) {
                    send501NotImplementedImpl(io, stream, "CONNECT method not supported");
                    metrics.requestEnd(501, @intCast(realtimeNanos() - ctx.start_time_ns));
                    // Advance buffer offset past this request for pipelining
                    const body_length = getBodyLength(&parser.request);
                    buffer_offset += parser.headers_end + body_length;
                    continue; // Next request in keep-alive loop
                }

                // RFC 7231 Section 5.1.1: Handle Expect: 100-continue
                // Client expects 100 Continue before sending body
                if (parser.request.headers.get("Expect")) |expect| {
                    if (std.ascii.eqlIgnoreCase(expect, "100-continue")) {
                        send100ContinueImpl(io, stream);
                    }
                }

                // Start a tracing span for this request
                // Format: "METHOD /path" (e.g., "GET /api/users")
                var span_name_buf: [config.OTEL_MAX_NAME_LEN]u8 = undefined;
                const method_str = @tagName(parser.request.method);
                const span_name_len = @min(method_str.len + 1 + parser.request.path.len, span_name_buf.len);
                @memcpy(span_name_buf[0..method_str.len], method_str);
                span_name_buf[method_str.len] = ' ';
                const path_copy_len = @min(parser.request.path.len, span_name_buf.len - method_str.len - 1);
                @memcpy(span_name_buf[method_str.len + 1 ..][0..path_copy_len], parser.request.path[0..path_copy_len]);
                const span_handle = tracer.startSpan(span_name_buf[0..span_name_len], null);
                ctx.span_handle = span_handle; // Store in context for handlers

                // Call onRequest hook if present
                if (comptime hooks.hasHook(Handler, "onRequest")) {
                    if (handler.onRequest(&ctx, &parser.request) == .send_response) {
                        tracer.endSpan(span_handle, null);
                        // Advance buffer offset past this request for pipelining
                        const body_length = getBodyLength(&parser.request);
                        buffer_offset += parser.headers_end + body_length;
                        continue;
                    }
                }

                // Select upstream and forward
                var upstream = handler.selectUpstream(&ctx, &parser.request);
                ctx.upstream = upstream;

                // Extract body info for streaming
                const content_length_header = parser.request.headers.get("Content-Length");
                const content_length_value: ?u64 = if (content_length_header) |cl|
                    parseContentLengthValue(cl)
                else
                    null;

                // Calculate body bytes available in current buffer (relative to buffer_offset)
                const data_after_headers = buffer_len - buffer_offset - parser.headers_end;
                const body_bytes_in_buffer = if (content_length_value) |cl|
                    @min(data_after_headers, cl)
                else
                    0; // No Content-Length means no body for requests

                const body_info = BodyInfo{
                    .content_length = content_length_value,
                    .bytes_already_read = @intCast(body_bytes_in_buffer),
                    .initial_body = if (body_bytes_in_buffer > 0)
                        recv_buf[buffer_offset + parser.headers_end ..][0..body_bytes_in_buffer]
                    else
                        &[_]u8{},
                };
                // Forward using async stream I/O (creates child spans for pool/connect/send/recv)
                const forward_result = forwarder.forward(io, stream, &parser.request, &upstream, body_info, span_handle);

                const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                ctx.duration_ns = duration_ns;

                // Calculate where this request ends for pipelining
                const body_length = getBodyLength(&parser.request);
                const request_end = buffer_offset + parser.headers_end + body_length;

                // Process result and determine connection state
                const result: ProcessResult = if (forward_result) |fwd_result| blk: {
                    handleForwardSuccessImpl(handler, metrics, &ctx, &parser.request, fwd_result, duration_ns);

                    // End span on success
                    tracer.endSpan(span_handle, null);

                    // RFC 9112: close if client requested or max requests reached
                    const should_close = clientWantsClose(&parser.request.headers) or
                        request_count >= cfg.max_requests_per_connection;

                    break :blk if (should_close) .close_connection else .keep_alive;
                } else |err| blk: {
                    handleForwardErrorImpl(handler, metrics, io, stream, &ctx, &parser.request, upstream, err, duration_ns);

                    // End span on error with error description
                    tracer.endSpan(span_handle, @errorName(err));

                    break :blk .fatal_error;
                };

                // Advance buffer offset past this request for pipelining
                buffer_offset = request_end;

                // Exit loop if connection should close
                if (result != .keep_alive) return;
            }
        }

        /// Get body length from Content-Length header, or 0 if not present.
        /// TigerStyle: explicit handling of missing header (no body).
        fn getBodyLength(request: *const Request) usize {
            const cl_header = request.headers.get("Content-Length") orelse return 0;
            const cl_value = parseContentLengthValue(cl_header) orelse return 0;
            // TigerStyle: bounded cast - Content-Length should fit in usize
            return if (cl_value <= std.math.maxInt(usize)) @intCast(cl_value) else 0;
        }

        /// Read request bytes from stream. Returns byte count or null on error/EOF.
        /// TigerStyle: Standalone function with explicit parameters.
        fn readRequestImpl(io: Io, stream: Io.net.Stream, recv_buf: *[REQUEST_BUFFER_SIZE_BYTES]u8) ?usize {
            assert(@intFromPtr(recv_buf) != 0);

            var reader_buf: [1]u8 = std.mem.zeroes([1]u8);
            var reader = stream.reader(io, &reader_buf);
            var bufs: [1][]u8 = .{recv_buf};
            const n = reader.interface.readVec(&bufs) catch |err| {
                if (err != error.EndOfStream) {
                    debugLog("Read error: {s}", .{@errorName(err)});
                }
                return null;
            };
            if (n == 0) return null;
            return n;
        }

        /// Read additional data into remaining buffer space for partial header accumulation.
        /// Used when headers span multiple TCP segments (partial header reads).
        /// Returns byte count or null on error/EOF.
        /// TigerStyle: Standalone function for partial read accumulation.
        fn readMoreDataImpl(io: Io, stream: Io.net.Stream, remaining_buf: []u8) ?usize {
            assert(remaining_buf.len > 0);

            var reader_buf: [1]u8 = std.mem.zeroes([1]u8);
            var reader = stream.reader(io, &reader_buf);
            var bufs: [1][]u8 = .{remaining_buf};
            const n = reader.interface.readVec(&bufs) catch |err| {
                if (err != error.EndOfStream) {
                    debugLog("Read more error: {s}", .{@errorName(err)});
                }
                return null;
            };
            return n;
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
            metrics.requestEnd(result.status, duration_ns);

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
                    // Phase timing from context and ForwardResult
                    .parse_duration_ns = ctx.parse_duration_ns,
                    .connect_duration_ns = result.tcp_connect_duration_ns,
                    .send_duration_ns = result.send_duration_ns,
                    .recv_duration_ns = result.recv_duration_ns,
                    // Network-level timing from ForwardResult
                    .dns_duration_ns = result.dns_duration_ns,
                    .tcp_connect_duration_ns = result.tcp_connect_duration_ns,
                    .pool_wait_ns = result.pool_wait_ns,
                    // Connection context from ctx
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
            io: Io,
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

            sendErrorResponseImpl(io, stream, 502, "Bad Gateway");
            ctx.response_status = 502;
            metrics.requestEnd(502, duration_ns);

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
                    // Phase timing from context (forwarder timing unavailable on error)
                    .parse_duration_ns = ctx.parse_duration_ns,
                    // Connection context from ctx
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

        /// Send HTTP response to client.
        /// If close_after is true, includes Connection: close header (RFC 9112).
        /// TigerStyle: Standalone function with explicit parameters.
        fn sendResponseImpl(
            io: Io,
            stream: Io.net.Stream,
            status: u16,
            content_type: []const u8,
            body: []const u8,
            close_after: bool,
        ) void {
            assert(status >= 100 and status < 600);
            assert(body.len <= 512); // Ensure fits in response buffer with headers

            var response_buf: [RESPONSE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([RESPONSE_BUFFER_SIZE_BYTES]u8);

            const response = if (close_after)
                std.fmt.bufPrint(
                    &response_buf,
                    "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
                    .{ status, statusText(status), content_type, body.len, body },
                )
            else
                std.fmt.bufPrint(
                    &response_buf,
                    "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n\r\n{s}",
                    .{ status, statusText(status), content_type, body.len, body },
                );

            const response_data = response catch return;

            var write_buf: [WRITE_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([WRITE_BUFFER_SIZE_BYTES]u8);
            var writer = stream.writer(io, &write_buf);
            writer.interface.writeAll(response_data) catch return;
            writer.interface.flush() catch return;
        }

        /// Send error response and close connection (RFC 9112: errors close connection).
        /// TigerStyle: Standalone function with explicit parameters.
        fn sendErrorResponseImpl(io: Io, stream: Io.net.Stream, status: u16, message: []const u8) void {
            assert(status >= 400 and status < 600); // Error responses only
            assert(message.len > 0);

            sendResponseImpl(io, stream, status, "text/plain", message, true);
        }

        /// Send 100 Continue interim response (RFC 7231 Section 5.1.1).
        /// Client can then proceed to send request body.
        /// TigerStyle: Standalone function with explicit parameters.
        fn send100ContinueImpl(io: Io, stream: Io.net.Stream) void {
            const response = "HTTP/1.1 100 Continue\r\n\r\n";
            var write_buf: [64]u8 = std.mem.zeroes([64]u8);
            var writer = stream.writer(io, &write_buf);
            writer.interface.writeAll(response) catch return;
            writer.interface.flush() catch return;
        }

        /// Send 501 Not Implemented response (RFC 7231 Section 6.6.2).
        /// Used for methods the server does not support (e.g., CONNECT).
        /// TigerStyle: Standalone function with explicit parameters.
        fn send501NotImplementedImpl(io: Io, stream: Io.net.Stream, message: []const u8) void {
            assert(message.len > 0);
            sendResponseImpl(io, stream, 501, "text/plain", message, true);
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
    try std.testing.expectEqual(@as(?u64, 18446744073709551615), parseContentLengthValue("18446744073709551615")); // u64 max
}

test "parseContentLengthValue rejects leading zeros" {
    // RFC 7230: Leading zeros are ambiguous (could be octal interpretation)
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("007"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("00"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("0123"));
    // Single zero is valid
    try std.testing.expectEqual(@as(?u64, 0), parseContentLengthValue("0"));
}

test "parseContentLengthValue invalid" {
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue(""));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("abc"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("12a34"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("18446744073709551616")); // overflow
}
