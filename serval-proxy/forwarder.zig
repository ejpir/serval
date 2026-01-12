// lib/serval-proxy/forwarder.zig
//! Upstream Forwarder
//!
//! Forwards HTTP/1.1 requests to upstream servers with connection pooling.
//! TigerStyle: Zero-copy where possible, bounded loops, ~2 assertions per function.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const config = serval_core.config;
const types = serval_core.types;
const debugLog = serval_core.debugLog;
const time = serval_core.time;
const SpanHandle = serval_core.SpanHandle;

const serval_tracing = @import("serval-tracing");
const verifyTracer = serval_tracing.verifyTracer;

const pool_mod = @import("serval-pool").pool;

const proxy_types = @import("types.zig");
pub const ForwardError = proxy_types.ForwardError;
pub const ForwardResult = proxy_types.ForwardResult;
pub const BodyInfo = proxy_types.BodyInfo;
const Protocol = proxy_types.Protocol;

const connect = @import("connect.zig");
const ConnectResult = connect.ConnectResult;
const ConnectConfig = connect.ConnectConfig;
const connectUpstream = connect.connectUpstream;
const getLocalPortFromSocket = connect.getLocalPortFromSocket;

const h1 = @import("h1/mod.zig");
const sendRequest = h1.sendRequest;
const methodToString = h1.methodToString;
const streamRequestBody = h1.streamRequestBody;
const forwardResponse = h1.forwardResponse;

const serval_tls = @import("serval-tls");
const TLSStream = serval_tls.TLSStream;
const ssl = serval_tls.ssl;

const serval_net = @import("serval-net");
const Socket = serval_net.Socket;
const DnsResolver = serval_net.DnsResolver;
const DnsConfig = serval_net.DnsConfig;

const Request = types.Request;
const Upstream = types.Upstream;
const Method = types.Method;
const Connection = pool_mod.Connection;

// =============================================================================
// Forwarder
// =============================================================================

pub fn Forwarder(comptime Pool: type, comptime Tracer: type) type {
    pool_mod.verifyPool(Pool);
    verifyTracer(Tracer);

    return struct {
        const Self = @This();

        pool: *Pool,
        tracer: *Tracer,
        verify_upstream_tls: bool,
        /// Optional SSL context for upstream TLS connections.
        /// Caller provides and owns lifecycle; null means no TLS to upstreams.
        /// TigerStyle: Explicit ownership, caller manages context.
        client_ctx: ?*ssl.SSL_CTX,
        /// DNS resolver with TTL caching for hostname resolution.
        /// TigerStyle: Fixed-size cache, thread-safe, no runtime allocation.
        dns_resolver: DnsResolver,

        pub fn init(
            p: *Pool,
            t: *Tracer,
            verify_upstream_tls: bool,
            client_ctx: ?*ssl.SSL_CTX,
            dns_config: DnsConfig,
        ) Self {
            // S1: preconditions - pointers must be valid
            assert(@intFromPtr(p) != 0);
            assert(@intFromPtr(t) != 0);

            return .{
                .pool = p,
                .tracer = t,
                .verify_upstream_tls = verify_upstream_tls,
                .client_ctx = client_ctx,
                .dns_resolver = DnsResolver.init(dns_config),
            };
        }

        /// Maximum stale connection retries - imported from config.
        /// TigerStyle: Single source of truth for tunables.
        const MAX_STALE_RETRIES = config.MAX_STALE_RETRIES;

        /// Forward request to upstream, returning response metadata.
        /// Auto-retries up to MAX_STALE_RETRIES on stale pooled connections.
        /// body_info contains metadata for streaming request body from client.
        /// parent_span is the root request span for creating child trace spans.
        /// client_tls is the TLS stream for client connection (for encrypted responses).
        /// effective_path: If set, use this path instead of request.path (for path rewriting).
        /// TigerStyle: Takes client stream for async I/O, bounded retries.
        pub fn forward(
            self: *Self,
            io: Io,
            client_stream: Io.net.Stream,
            client_tls: ?*TLSStream,
            request: *const Request,
            upstream: *const Upstream,
            body_info: BodyInfo,
            parent_span: SpanHandle,
            effective_path: ?[]const u8,
        ) ForwardError!ForwardResult {
            assert(upstream.port > 0);
            // S1: precondition - path must not be empty (use effective_path if provided)
            const path = effective_path orelse request.path;
            assert(path.len > 0);

            // Create forward span as child of request span
            const forward_span = self.tracer.startSpan("forward_to_upstream", parent_span);
            errdefer self.tracer.endSpan(forward_span, "forward_error");

            debugLog("forward: start {s} {s} upstream={s}:{d}", .{
                methodToString(request.method),
                path,
                upstream.host,
                upstream.port,
            });

            // Pool acquire phase with span
            // TigerStyle: End span only after we know if connection actually worked,
            // not immediately after acquire. Tracks stale_retries for observability.
            const pool_span = self.tracer.startSpan("pool_acquire", forward_span);
            const pool_start_ns = time.monotonicNanos();
            var stale_retries: u8 = 0;

            // Try pooled connections with bounded retry on stale
            while (stale_retries < MAX_STALE_RETRIES) : (stale_retries += 1) {
                if (self.pool.acquire(upstream.idx)) |pooled_conn| {
                    const pool_end_ns = time.monotonicNanos();
                    const pool_wait_ns = time.elapsedNanos(pool_start_ns, pool_end_ns);

                    // Check for unusable connection before using pooled connection
                    // TigerStyle: Detect stale data, closed by peer, socket errors.
                    if (pooled_conn.isUnusable()) {
                        debugLog("forward: pool hit but STALE (retry {d}/{d}), closing", .{ stale_retries + 1, MAX_STALE_RETRIES });
                        var stale_conn = pooled_conn;
                        stale_conn.close();
                        continue; // Try next pooled connection
                    }

                    // DON'T end span here - wait until we know connection works
                    debugLog("forward: pool HIT, reusing connection fd={d}", .{pooled_conn.socket.getFd()});

                    // Get local port from pooled connection
                    const local_port = getLocalPortFromSocket(pooled_conn.socket);

                    const result = self.forwardWithConnection(
                        io,
                        client_stream,
                        client_tls,
                        request,
                        upstream,
                        pooled_conn,
                        true,
                        body_info,
                        0, // dns_duration_ns: 0 for pooled connection
                        0, // tcp_connect_duration_ns: 0 for pooled connection
                        local_port,
                        pool_wait_ns,
                        forward_span,
                        effective_path,
                    ) catch |err| {
                        if (err == ForwardError.StaleConnection and stale_retries + 1 < MAX_STALE_RETRIES) {
                            debugLog("forward: StaleConnection during send (retry {d}/{d})", .{ stale_retries + 1, MAX_STALE_RETRIES });
                            // Note: connection is closed by errdefer in forwardWithConnection
                            continue; // Try next pooled connection
                        }
                        // Failed for real - end span with error and stale_retries count
                        self.tracer.setIntAttribute(pool_span, "stale_retries", stale_retries);
                        self.tracer.setIntAttribute(pool_span, "hit", 0);
                        self.tracer.endSpan(pool_span, @errorName(err));
                        return err;
                    };

                    // SUCCESS - NOW record hit and end span
                    self.tracer.setIntAttribute(pool_span, "wait_ns", @intCast(pool_wait_ns));
                    self.tracer.setIntAttribute(pool_span, "hit", 1);
                    self.tracer.setIntAttribute(pool_span, "stale_retries", stale_retries);
                    self.tracer.endSpan(pool_span, null);

                    self.tracer.endSpan(forward_span, null);
                    return result;
                } else {
                    break; // No more pooled connections, fall through to fresh
                }
            }

            // Pool miss case - end span with hit=0
            const pool_end_ns = time.monotonicNanos();
            const pool_wait_ns = time.elapsedNanos(pool_start_ns, pool_end_ns);
            self.tracer.setIntAttribute(pool_span, "wait_ns", @intCast(pool_wait_ns));
            self.tracer.setIntAttribute(pool_span, "hit", 0);
            self.tracer.setIntAttribute(pool_span, "stale_retries", stale_retries);
            self.tracer.endSpan(pool_span, null);

            // No pooled connection or all stale, create fresh
            debugLog("forward: pool MISS or exhausted stale, connecting fresh", .{});
            const result = try self.forwardFresh(io, client_stream, client_tls, request, upstream, body_info, pool_wait_ns, forward_span, effective_path);
            self.tracer.endSpan(forward_span, null);
            return result;
        }

        fn forwardFresh(
            self: *Self,
            io: Io,
            client_stream: Io.net.Stream,
            client_tls: ?*TLSStream,
            request: *const Request,
            upstream: *const Upstream,
            body_info: BodyInfo,
            pool_wait_ns: u64,
            forward_span: SpanHandle,
            effective_path: ?[]const u8,
        ) ForwardError!ForwardResult {
            assert(upstream.port > 0);

            // TCP connect phase with span
            const connect_span = self.tracer.startSpan("tcp_connect", forward_span);
            const connect_config = ConnectConfig{
                .timeout_ns = config.CONNECT_TIMEOUT_NS,
                .verify_upstream_tls = self.verify_upstream_tls,
                .client_ctx = self.client_ctx,
            };
            const connect_result = connectUpstream(upstream, io, connect_config, &self.dns_resolver) catch |err| {
                self.tracer.endSpan(connect_span, @errorName(err));
                return err;
            };
            self.tracer.setIntAttribute(connect_span, "duration_ns", @intCast(connect_result.tcp_connect_duration_ns));
            self.tracer.setIntAttribute(connect_span, "port", connect_result.local_port);
            self.tracer.endSpan(connect_span, null);

            // TLS handshake span (if TLS was used)
            // Access TLS stream info from Socket union if TLS variant.
            if (connect_result.socket.isTLS()) {
                const tls_socket = connect_result.socket.tls;
                const tls_span = self.tracer.startSpan("tls.handshake.client", forward_span);
                const info = &tls_socket.stream.info;
                self.tracer.setStringAttribute(tls_span, "tls.version", info.version());
                self.tracer.setStringAttribute(tls_span, "tls.cipher", info.cipher());
                self.tracer.setIntAttribute(tls_span, "tls.handshake_duration_ns", @intCast(info.handshake_duration_ns));
                self.tracer.setStringAttribute(tls_span, "tls.resumed", if (info.resumed) "true" else "false");
                self.tracer.setStringAttribute(tls_span, "tls.client_mode", "true");
                self.tracer.setStringAttribute(tls_span, "tls.sni_hostname", upstream.host);
                if (info.alpn()) |alpn_proto| {
                    self.tracer.setStringAttribute(tls_span, "tls.alpn_protocol", alpn_proto);
                }
                if (info.certSubject()) |subj| {
                    self.tracer.setStringAttribute(tls_span, "tls.peer_cert.subject", subj);
                }
                if (info.certIssuer()) |issuer| {
                    self.tracer.setStringAttribute(tls_span, "tls.peer_cert.issuer", issuer);
                }
                self.tracer.endSpan(tls_span, null);
            }

            // Create Connection struct for pool compatibility
            // TigerStyle: Connection now uses Socket directly.
            const conn = Connection{
                .socket = connect_result.socket,
                .created_ns = connect_result.created_ns,
            };

            return self.forwardWithConnection(
                io,
                client_stream,
                client_tls,
                request,
                upstream,
                conn,
                false,
                body_info,
                connect_result.dns_duration_ns,
                connect_result.tcp_connect_duration_ns,
                connect_result.local_port,
                pool_wait_ns,
                forward_span,
                effective_path,
            );
        }

        /// Forward request using an established upstream connection.
        /// effective_path: If set, use this path instead of request.path (for path rewriting).
        /// TigerStyle: Explicit io parameter, streams for async I/O.
        fn forwardWithConnection(
            self: *Self,
            io: Io,
            client_stream: Io.net.Stream,
            client_tls: ?*TLSStream,
            request: *const Request,
            upstream: *const Upstream,
            conn: Connection,
            is_pooled: bool,
            body_info: BodyInfo,
            dns_duration_ns: u64,
            tcp_connect_duration_ns: u64,
            local_port: u16,
            pool_wait_ns: u64,
            forward_span: SpanHandle,
            effective_path: ?[]const u8,
        ) ForwardError!ForwardResult {
            var mutable_conn = conn;
            errdefer {
                // TigerStyle: Maintain accounting integrity on error path
                // If connection came from pool, must call release() to decrement checked_out_counts
                // Otherwise stats show phantom "checked out" connections forever
                if (is_pooled) {
                    // Release with healthy=false (don't return to pool, but update counts)
                    self.pool.release(upstream.idx, mutable_conn, false);
                } else {
                    // Fresh connection never entered pool, just close it
                    mutable_conn.close();
                }
            }

            // Send phase span (headers + body)
            const send_span = self.tracer.startSpan("send_request", forward_span);
            const send_start_ns = time.monotonicNanos();
            debugLog("send: start headers", .{});

            // Send request headers to upstream via connection (TLS or plaintext)
            // Pass effective_path for path rewriting support
            sendRequest(&mutable_conn, io, request, effective_path) catch |err| {
                debugLog("send: FAILED err={s}", .{@errorName(err)});
                self.tracer.endSpan(send_span, @errorName(err));
                if (is_pooled and err == ForwardError.SendFailed) {
                    return ForwardError.StaleConnection;
                }
                return err;
            };

            // Create Socket wrappers for body forwarding.
            // TigerStyle: Connection.socket is already a Socket, use it directly for upstream.
            // For client, create Socket from client_tls or plaintext fd.
            var client_socket = if (client_tls) |tls|
                Socket{ .tls = .{ .fd = client_stream.socket.handle, .stream = tls.* } }
            else
                Socket.Plain.initClient(client_stream.socket.handle);

            // Stream request body if present
            if (body_info.getContentLength()) |content_length| {
                if (content_length > config.MAX_BODY_SIZE_BYTES) {
                    self.tracer.endSpan(send_span, "RequestBodyTooLarge");
                    return ForwardError.RequestBodyTooLarge;
                }
                debugLog("send: streaming body content_length={d}", .{content_length});
                // Use Socket abstraction for unified TLS/plaintext handling.
                // Connection.socket is already a Socket.
                _ = streamRequestBody(&client_socket, &mutable_conn.socket, &mutable_conn, io, body_info) catch |err| {
                    self.tracer.endSpan(send_span, @errorName(err));
                    return err;
                };
            }

            const send_end_ns = time.monotonicNanos();
            const send_duration_ns = time.elapsedNanos(send_start_ns, send_end_ns);
            self.tracer.setIntAttribute(send_span, "duration_ns", @intCast(send_duration_ns));
            self.tracer.endSpan(send_span, null);
            debugLog("send: complete duration_us={d}", .{send_duration_ns / 1000});

            // Recv phase span (response headers + body)
            const recv_span = self.tracer.startSpan("recv_response", forward_span);
            debugLog("recv: awaiting response headers", .{});
            // Use Socket abstraction for unified TLS/plaintext body forwarding.
            // Connection.socket is already a Socket.
            var result = forwardResponse(io, &mutable_conn, client_stream, &mutable_conn.socket, &client_socket, is_pooled) catch |err| {
                self.tracer.endSpan(recv_span, @errorName(err));
                return err;
            };
            self.tracer.setIntAttribute(recv_span, "duration_ns", @intCast(result.recv_duration_ns));
            self.tracer.setIntAttribute(recv_span, "status", result.status);
            self.tracer.setIntAttribute(recv_span, "bytes", @intCast(result.response_bytes));
            self.tracer.endSpan(recv_span, null);

            result.connection_reused = is_pooled;
            result.dns_duration_ns = dns_duration_ns;
            result.tcp_connect_duration_ns = tcp_connect_duration_ns;
            result.send_duration_ns = send_duration_ns;
            result.pool_wait_ns = pool_wait_ns;
            result.upstream_local_port = local_port;

            // RFC 9112 recommends checking upstream's Connection: close header and not
            // pooling if present. Current implementation relies on StaleConnection retry
            // (Pingora-style). Consider adding explicit header check if retry overhead
            // becomes measurable.
            self.pool.release(upstream.idx, mutable_conn, true);

            debugLog("forward: complete status={d} pooled={}", .{ result.status, is_pooled });
            return result;
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

test "Forwarder init with NoPool" {
    var no_pool = pool_mod.NoPool{};
    var tracer = serval_tracing.NoopTracer{};
    // TigerStyle: null client_ctx for tests without TLS upstreams.
    // DnsConfig{} uses default TTL and timeout values.
    const forwarder = Forwarder(pool_mod.NoPool, serval_tracing.NoopTracer).init(&no_pool, &tracer, true, null, DnsConfig{});
    // S1: postcondition - dns_resolver is initialized with default config
    try std.testing.expectEqual(serval_core.config.DNS_DEFAULT_TTL_NS, forwarder.dns_resolver.cfg.ttl_ns);
}

test "Forwarder init with SimplePool" {
    var simple_pool = pool_mod.SimplePool.init();
    var tracer = serval_tracing.NoopTracer{};
    // TigerStyle: null client_ctx for tests without TLS upstreams.
    // DnsConfig{} uses default TTL and timeout values.
    const forwarder = Forwarder(pool_mod.SimplePool, serval_tracing.NoopTracer).init(&simple_pool, &tracer, true, null, DnsConfig{});
    // S1: postcondition - dns_resolver is initialized with default config
    try std.testing.expectEqual(serval_core.config.DNS_DEFAULT_TTL_NS, forwarder.dns_resolver.cfg.ttl_ns);
}

// =============================================================================
// Forwarder Config Tests
// =============================================================================
// Note: Tests for h1 functions are in h1/request.zig
// Note: Tests for ForwardError, ForwardResult, BodyInfo are in types.zig

test "CRITICAL: MAX_STALE_RETRIES is bounded (no infinite retry)" {
    // TigerStyle: All loops must be bounded
    const MAX = config.MAX_STALE_RETRIES;

    // Document current value
    try std.testing.expectEqual(@as(u8, 2), MAX);

    // Verify it's a reasonable limit (not 0, not huge)
    try std.testing.expect(MAX > 0);
    try std.testing.expect(MAX < 10);
}

test "CRITICAL: Request body size limit enforced" {
    // Prevent memory exhaustion from huge uploads
    const limit = config.MAX_BODY_SIZE_BYTES;

    // Document current limit: 1MB
    try std.testing.expectEqual(@as(u32, 1024 * 1024), limit);
}

test "CRITICAL: Response buffer size documented" {
    // Fixed buffer for response headers - prevents unbounded allocation
    const buf_size = config.RESPONSE_BUFFER_SIZE_BYTES;

    // Document current size: 1KB
    try std.testing.expectEqual(@as(usize, 1024), buf_size);

    // Verify it's reasonable for typical responses
    try std.testing.expect(buf_size >= 512); // Not too small
    try std.testing.expect(buf_size <= 8192); // Not too large
}
