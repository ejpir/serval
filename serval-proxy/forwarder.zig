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
/// Public alias of [`proxy_types.ForwardError`], the canonical error set for forwarding operations.
/// Use this type in proxy-facing APIs so callers can handle forwarder failures consistently.
/// This declaration adds no new variants; semantics and handling are defined by `proxy_types.ForwardError`.
pub const ForwardError = proxy_types.ForwardError;
/// Public alias of `proxy_types.ForwardResult`, returned by forwarder APIs on successful upstream forwarding.
/// Carries response metadata (`status`, `response_bytes`, `connection_reused`) and per-phase timing metrics in nanoseconds.
/// Timing fields and `upstream_local_port` may be `0` when a phase is not measured or not populated.
/// This declaration is a pure type alias: it performs no allocation, ownership transfer, lifetime coupling, or error-producing work.
pub const ForwardResult = proxy_types.ForwardResult;
/// Alias of [`proxy_types.BodyInfo`] used by forwarder APIs for request-body streaming metadata.
/// Encodes body framing (`content_length`, `chunked`, or `none`), bytes already consumed, and any initial body bytes.
/// `initial_body` is a borrowed `[]const u8` (typically a parser-buffer slice), so callers must keep backing memory valid while forwarding uses it.
/// This declaration adds no behavior or errors; helper methods and semantics come from `proxy_types.BodyInfo`.
pub const BodyInfo = proxy_types.BodyInfo;
const Protocol = proxy_types.Protocol;

const connect = @import("connect.zig");
const ConnectResult = connect.ConnectResult;
const ConnectConfig = connect.ConnectConfig;
const connectUpstream = connect.connectUpstream;
const getLocalPortFromSocket = connect.getLocalPortFromSocket;

const h1 = @import("h1/mod.zig");
const sendRequest = h1.sendRequest;
const sendUpgradeRequest = h1.sendUpgradeRequest;
const ForwardedHeaders = h1.ForwardedHeaders;
const methodToString = h1.methodToString;
const streamRequestBody = h1.streamRequestBody;
const forwardResponse = h1.forwardResponse;
const forwardUpgradeResponse = h1.forwardUpgradeResponse;

const tunnel_mod = @import("tunnel.zig");

const serval_websocket = @import("serval-websocket");
const serval_h2 = @import("serval-h2");
const serval_grpc = @import("serval-grpc");

const serval_tls = @import("serval-tls");
const TLSStream = serval_tls.TLSStream;
const ssl = serval_tls.ssl;

const serval_net = @import("serval-net");
const DnsResolver = serval_net.DnsResolver;
const DnsConfig = serval_net.DnsConfig;

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;

const Request = types.Request;
const Upstream = types.Upstream;
const Method = types.Method;
const Connection = pool_mod.Connection;
const max_stale_retries: u8 = 2;
const connect_timeout_ns: u64 = 30 * 1000 * 1000 * 1000;
const h2c_tunnel_poll_timeout_ms: i32 = 1000;
const h2_proxy_frame_capacity_bytes: u32 = 64 * 1024;
const h2_proxy_frame_capacity_usize: usize = h2_proxy_frame_capacity_bytes;

// =============================================================================
// Forwarder
// =============================================================================

/// Returns a concrete forwarder type parameterized by `Pool` and `Tracer`.
/// At comptime, validates `Pool` (`pool_mod.verifyPool`) and `Tracer` (`verifyTracer`);
/// invalid component types fail compilation.
/// Instances of the returned type hold pointers to the caller-owned pool and tracer,
/// optional caller-owned upstream `ssl.SSL_CTX`, and an internal DNS resolver state.
pub fn Forwarder(comptime Pool: type, comptime Tracer: type) type {
    pool_mod.verifyPool(Pool);
    verifyTracer(Tracer);

    return struct {
        const Self = @This();

        pool: *Pool,
        tracer: *Tracer,
        verify_upstream_tls: bool,
        h2_cfg: config.H2Config,
        /// Optional SSL context for upstream TLS connections.
        /// Caller provides and owns lifecycle; null means no TLS to upstreams.
        /// TigerStyle: Explicit ownership, caller manages context.
        client_ctx: ?*ssl.SSL_CTX,
        /// DNS resolver with TTL caching for hostname resolution.
        /// TigerStyle: Fixed-size cache, thread-safe, no runtime allocation.
        dns_resolver: DnsResolver,

        /// Initializes a `Self` forwarder with the provided pool, tracer, TLS settings, and DNS configuration.
        /// Preconditions: `p` and `t` must be valid non-null pointers (enforced with `assert`).
        /// The returned value stores `p`, `t`, and `client_ctx` by pointer; those pointed-to objects must remain alive for the forwarder lifetime.
        /// `dns_resolver` is initialized via `DnsResolver.init(&dns_resolver, dns_config)` before being embedded in the result.
        /// This initializer does not return errors; violated preconditions terminate via assertion.
        pub fn init(
            p: *Pool,
            t: *Tracer,
            verify_upstream_tls: bool,
            client_ctx: ?*ssl.SSL_CTX,
            h2_cfg: config.H2Config,
            dns_config: DnsConfig,
        ) Self {
            // S1: preconditions - pointers must be valid
            assert(@intFromPtr(p) != 0);
            assert(@intFromPtr(t) != 0);
            assert(h2_cfg.max_frame_size_bytes >= config.H2_MAX_FRAME_SIZE_BYTES);
            assert(h2_cfg.max_frame_size_bytes <= h2_proxy_frame_capacity_bytes);
            assert(h2_cfg.tunnel_idle_timeout_ns > 0);

            var dns_resolver: DnsResolver = undefined;
            DnsResolver.init(&dns_resolver, dns_config);

            return .{
                .pool = p,
                .tracer = t,
                .verify_upstream_tls = verify_upstream_tls,
                .h2_cfg = h2_cfg,
                .client_ctx = client_ctx,
                .dns_resolver = dns_resolver,
            };
        }

        /// Forward request to upstream, returning response metadata.
        /// Auto-retries up to `max_stale_retries` on stale pooled connections.
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
            while (stale_retries < max_stale_retries) : (stale_retries += 1) {
                if (self.pool.acquire(upstream.idx)) |pooled_conn| {
                    const pool_end_ns = time.monotonicNanos();
                    const pool_wait_ns = time.elapsedNanos(pool_start_ns, pool_end_ns);

                    // Check for unusable connection before using pooled connection
                    // TigerStyle: Detect stale data, closed by peer, socket errors.
                    if (pooled_conn.isUnusable()) {
                        debugLog("forward: pool hit but STALE (retry {d}/{d}), closing", .{ stale_retries + 1, max_stale_retries });
                        var stale_conn = pooled_conn;
                        stale_conn.close();
                        continue; // Try next pooled connection
                    }

                    // DON'T end span here - wait until we know connection works
                    debugLog("forward: pool HIT, reusing connection fd={d}", .{pooled_conn.socket.get_fd()});

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
                        if (err == ForwardError.StaleConnection and stale_retries + 1 < max_stale_retries) {
                            debugLog("forward: StaleConnection during send (retry {d}/{d})", .{ stale_retries + 1, max_stale_retries });
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

        /// Forward a WebSocket upgrade request and switch to tunnel mode on 101.
        /// Upgraded upstream connections are always closed, never returned to the pool.
        pub fn forwardWebSocket(
            self: *Self,
            io: Io,
            client_stream: Io.net.Stream,
            client_tls: ?*TLSStream,
            request: *const Request,
            upstream: *const Upstream,
            initial_client_bytes: []const u8,
            parent_span: SpanHandle,
            effective_path: ?[]const u8,
        ) ForwardError!ForwardResult {
            assert(upstream.port > 0);
            assert(request.path.len > 0);
            const request_key = request.headers.get("Sec-WebSocket-Key") orelse return ForwardError.InvalidResponse;
            const forwarded = ForwardedHeaders{
                .host = request.headers.get("Host") orelse "",
                .proto = if (client_tls != null) "https" else "http",
                .client_ip = "",
            };

            var accept_key_buf: [serval_websocket.websocket_accept_key_size_bytes]u8 = undefined;
            const expected_accept = serval_websocket.computeAcceptKey(request_key, &accept_key_buf) catch {
                return ForwardError.InvalidResponse;
            };

            debugLog("websocket forward start path={s} upstream={s}:{d} upstream_tls={any} protocol={s}", .{
                request.path,
                upstream.host,
                upstream.port,
                upstream.tls,
                @tagName(upstream.http_protocol),
            });

            const forward_span = self.tracer.startSpan("forward_websocket_upgrade", parent_span);
            errdefer self.tracer.endSpan(forward_span, "forward_error");

            const pool_span = self.tracer.startSpan("pool_acquire", forward_span);
            const pool_start_ns = time.monotonicNanos();
            var stale_retries: u8 = 0;

            while (stale_retries < max_stale_retries) : (stale_retries += 1) {
                if (self.pool.acquire(upstream.idx)) |pooled_conn| {
                    const pool_wait_ns = time.elapsedNanos(pool_start_ns, time.monotonicNanos());
                    if (pooled_conn.isUnusable()) {
                        var stale_conn = pooled_conn;
                        stale_conn.close();
                        continue;
                    }

                    const result = self.forwardWebSocketWithConnection(
                        io,
                        client_stream,
                        client_tls,
                        request,
                        upstream,
                        pooled_conn,
                        true,
                        initial_client_bytes,
                        expected_accept,
                        0,
                        0,
                        getLocalPortFromSocket(pooled_conn.socket),
                        pool_wait_ns,
                        forward_span,
                        effective_path,
                        forwarded,
                    ) catch |err| {
                        if (err == ForwardError.StaleConnection and stale_retries + 1 < max_stale_retries) {
                            continue;
                        }
                        self.tracer.setIntAttribute(pool_span, "wait_ns", @intCast(pool_wait_ns));
                        self.tracer.setIntAttribute(pool_span, "hit", 0);
                        self.tracer.setIntAttribute(pool_span, "stale_retries", stale_retries);
                        self.tracer.endSpan(pool_span, @errorName(err));
                        return err;
                    };

                    self.tracer.setIntAttribute(pool_span, "wait_ns", @intCast(pool_wait_ns));
                    self.tracer.setIntAttribute(pool_span, "hit", 1);
                    self.tracer.setIntAttribute(pool_span, "stale_retries", stale_retries);
                    self.tracer.endSpan(pool_span, null);
                    self.tracer.endSpan(forward_span, null);
                    return result;
                }
                break;
            }

            const pool_wait_ns = time.elapsedNanos(pool_start_ns, time.monotonicNanos());
            self.tracer.setIntAttribute(pool_span, "wait_ns", @intCast(pool_wait_ns));
            self.tracer.setIntAttribute(pool_span, "hit", 0);
            self.tracer.setIntAttribute(pool_span, "stale_retries", stale_retries);
            self.tracer.endSpan(pool_span, null);

            const result = try self.forwardFreshWebSocket(
                io,
                client_stream,
                client_tls,
                request,
                upstream,
                initial_client_bytes,
                expected_accept,
                pool_wait_ns,
                forward_span,
                effective_path,
                forwarded,
            );
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
                .timeout_ns = connect_timeout_ns,
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
            if (connect_result.socket.is_tls()) {
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

        fn forwardFreshWebSocket(
            self: *Self,
            io: Io,
            client_stream: Io.net.Stream,
            client_tls: ?*TLSStream,
            request: *const Request,
            upstream: *const Upstream,
            initial_client_bytes: []const u8,
            expected_accept: []const u8,
            pool_wait_ns: u64,
            forward_span: SpanHandle,
            effective_path: ?[]const u8,
            forwarded: ForwardedHeaders,
        ) ForwardError!ForwardResult {
            assert(upstream.port > 0);

            const connect_span = self.tracer.startSpan("tcp_connect", forward_span);
            const connect_config = ConnectConfig{
                .timeout_ns = connect_timeout_ns,
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

            const conn = Connection{
                .socket = connect_result.socket,
                .created_ns = connect_result.created_ns,
            };

            return self.forwardWebSocketWithConnection(
                io,
                client_stream,
                client_tls,
                request,
                upstream,
                conn,
                false,
                initial_client_bytes,
                expected_accept,
                connect_result.dns_duration_ns,
                connect_result.tcp_connect_duration_ns,
                connect_result.local_port,
                pool_wait_ns,
                forward_span,
                effective_path,
                forwarded,
            );
        }

        fn forwardWebSocketWithConnection(
            self: *Self,
            io: Io,
            client_stream: Io.net.Stream,
            client_tls: ?*TLSStream,
            request: *const Request,
            upstream: *const Upstream,
            conn: Connection,
            is_pooled: bool,
            initial_client_bytes: []const u8,
            expected_accept: []const u8,
            dns_duration_ns: u64,
            tcp_connect_duration_ns: u64,
            local_port: u16,
            pool_wait_ns: u64,
            forward_span: SpanHandle,
            effective_path: ?[]const u8,
            forwarded: ForwardedHeaders,
        ) ForwardError!ForwardResult {
            var mutable_conn = conn;
            defer {
                if (is_pooled) {
                    self.pool.release(upstream.idx, mutable_conn, false);
                } else {
                    mutable_conn.close();
                }
            }

            const send_span = self.tracer.startSpan("send_request", forward_span);
            const send_start_ns = time.monotonicNanos();
            sendUpgradeRequest(&mutable_conn, io, request, effective_path, forwarded) catch |err| {
                self.tracer.endSpan(send_span, @errorName(err));
                if (is_pooled and err == ForwardError.SendFailed) {
                    return ForwardError.StaleConnection;
                }
                return err;
            };
            const send_duration_ns = time.elapsedNanos(send_start_ns, time.monotonicNanos());
            self.tracer.setIntAttribute(send_span, "duration_ns", @intCast(send_duration_ns));
            self.tracer.endSpan(send_span, null);

            var client_socket = if (client_tls) |tls|
                Socket{ .tls = .{ .fd = client_stream.socket.handle, .stream = tls.* } }
            else
                Socket.Plain.init_client(client_stream.socket.handle);

            const recv_span = self.tracer.startSpan("recv_response", forward_span);
            const recv_start_ns = time.monotonicNanos();
            const upgrade_result = forwardUpgradeResponse(
                io,
                &mutable_conn,
                &client_socket,
                is_pooled,
                expected_accept,
            ) catch |err| {
                self.tracer.endSpan(recv_span, @errorName(err));
                return err;
            };
            const recv_duration_ns = time.elapsedNanos(recv_start_ns, time.monotonicNanos());
            self.tracer.setIntAttribute(recv_span, "duration_ns", @intCast(recv_duration_ns));
            self.tracer.setIntAttribute(recv_span, "status", upgrade_result.status);
            self.tracer.endSpan(recv_span, null);

            debugLog("websocket upgrade response path={s} status={d} upgraded={any} reused={any} upstream={s}:{d}", .{
                request.path,
                upgrade_result.status,
                upgrade_result.upgraded,
                is_pooled,
                upstream.host,
                upstream.port,
            });

            var result = ForwardResult{
                .status = upgrade_result.status,
                .response_bytes = upgrade_result.response_bytes,
                .connection_reused = is_pooled,
                .dns_duration_ns = dns_duration_ns,
                .tcp_connect_duration_ns = tcp_connect_duration_ns,
                .send_duration_ns = send_duration_ns,
                .recv_duration_ns = recv_duration_ns,
                .pool_wait_ns = pool_wait_ns,
                .upstream_local_port = local_port,
            };

            if (!upgrade_result.upgraded) {
                return result;
            }

            const tunnel_span = self.tracer.startSpan("websocket_tunnel", forward_span);
            const tunnel_stats = tunnel_mod.relay(
                io,
                &client_socket,
                &mutable_conn.socket,
                initial_client_bytes,
                &[_]u8{},
            );
            self.tracer.setIntAttribute(tunnel_span, "duration_ns", @intCast(tunnel_stats.duration_ns));
            self.tracer.setIntAttribute(tunnel_span, "client_to_upstream_bytes", @intCast(tunnel_stats.client_to_upstream_bytes));
            self.tracer.setIntAttribute(tunnel_span, "upstream_to_client_bytes", @intCast(tunnel_stats.upstream_to_client_bytes));
            self.tracer.setStringAttribute(tunnel_span, "termination", @tagName(tunnel_stats.termination));
            self.tracer.endSpan(tunnel_span, null);

            debugLog("websocket tunnel complete termination={s} up_bytes={d} down_bytes={d}", .{
                @tagName(tunnel_stats.termination),
                tunnel_stats.client_to_upstream_bytes,
                tunnel_stats.upstream_to_client_bytes,
            });

            result.response_bytes += tunnel_stats.upstream_to_client_bytes;
            result.recv_duration_ns += tunnel_stats.duration_ns;
            return result;
        }

        /// Forward a gRPC HTTP/2 connection by selecting an upstream from the
        /// first request and then tunneling the full HTTP/2 byte stream
        /// transparently.
        ///
        /// Supported upstream protocol combinations:
        /// - `.h2c` + plaintext
        /// - `.h2` + TLS
        ///
        /// TigerStyle: Bounded upfront parsing happens in serval-server; this
        /// path performs raw relay only and never returns the upstream
        /// connection to the pool.
        pub fn forwardGrpcH2c(
            self: *Self,
            io: Io,
            client_stream: Io.net.Stream,
            client_tls: ?*TLSStream,
            request: *const Request,
            upstream: *const Upstream,
            initial_client_bytes: []const u8,
            parent_span: SpanHandle,
        ) ForwardError!ForwardResult {
            assert(initial_client_bytes.len > 0);
            assert(upstream.port > 0);

            const supports_h2c_plain = upstream.http_protocol == .h2c and !upstream.tls;
            const supports_h2_tls = upstream.http_protocol == .h2 and upstream.tls;
            if (!supports_h2c_plain and !supports_h2_tls) return ForwardError.UnsupportedProtocol;

            const request_class = serval_grpc.classifyRequest(request);
            if (request_class != .grpc) return ForwardError.UnsupportedProtocol;
            _ = serval_h2.looksLikeClientConnectionPreface(initial_client_bytes);

            const forward_span = self.tracer.startSpan("forward_grpc_h2", parent_span);
            errdefer self.tracer.endSpan(forward_span, "forward_error");

            const connect_span = self.tracer.startSpan("connect_upstream", forward_span);
            const connect_cfg = ConnectConfig{
                .timeout_ns = connect_timeout_ns,
                .verify_upstream_tls = self.verify_upstream_tls,
                .client_ctx = self.client_ctx,
            };
            const connect_result = connectUpstream(
                upstream,
                io,
                connect_cfg,
                &self.dns_resolver,
            ) catch |err| {
                self.tracer.endSpan(connect_span, @errorName(err));
                return err;
            };
            self.tracer.setIntAttribute(connect_span, "dns_duration_ns", @intCast(connect_result.dns_duration_ns));
            self.tracer.setIntAttribute(connect_span, "tcp_connect_duration_ns", @intCast(connect_result.tcp_connect_duration_ns));
            self.tracer.endSpan(connect_span, null);

            var upstream_socket = connect_result.socket;
            defer upstream_socket.close();
            var client_socket = if (client_tls) |tls|
                Socket{ .tls = .{ .fd = client_stream.socket.handle, .stream = tls.* } }
            else
                Socket.Plain.init_client(client_stream.socket.handle);

            const tunnel_span = self.tracer.startSpan("grpc_h2_tunnel", forward_span);
            const tunnel_stats = tunnel_mod.relayWithConfig(
                io,
                &client_socket,
                &upstream_socket,
                initial_client_bytes,
                &[_]u8{},
                self.h2_cfg.tunnel_idle_timeout_ns,
                h2c_tunnel_poll_timeout_ms,
            );
            self.tracer.setIntAttribute(tunnel_span, "duration_ns", @intCast(tunnel_stats.duration_ns));
            self.tracer.setIntAttribute(tunnel_span, "client_to_upstream_bytes", @intCast(tunnel_stats.client_to_upstream_bytes));
            self.tracer.setIntAttribute(tunnel_span, "upstream_to_client_bytes", @intCast(tunnel_stats.upstream_to_client_bytes));
            self.tracer.setStringAttribute(tunnel_span, "termination", @tagName(tunnel_stats.termination));
            self.tracer.endSpan(tunnel_span, null);
            self.tracer.endSpan(forward_span, null);

            debugLog("grpc h2 tunnel complete termination={s} up_bytes={d} down_bytes={d}", .{
                @tagName(tunnel_stats.termination),
                tunnel_stats.client_to_upstream_bytes,
                tunnel_stats.upstream_to_client_bytes,
            });

            return .{
                .status = 200,
                .response_bytes = tunnel_stats.upstream_to_client_bytes,
                .connection_reused = false,
                .dns_duration_ns = connect_result.dns_duration_ns,
                .tcp_connect_duration_ns = connect_result.tcp_connect_duration_ns,
                .send_duration_ns = 0,
                .recv_duration_ns = tunnel_stats.duration_ns,
                .pool_wait_ns = 0,
                .upstream_local_port = connect_result.local_port,
            };
        }

        const H2C_UPGRADE_STREAM_ID: u32 = 1;
        const H2C_UPGRADE_PREAMBLE_BUFFER_SIZE_BYTES: usize =
            serval_h2.client_connection_preface.len +
            (2 * serval_h2.frame_header_size_bytes) +
            h2_proxy_frame_capacity_usize +
            config.H2_MAX_HEADER_BLOCK_SIZE_BYTES;

        /// Forward an HTTP/1.1 `Upgrade: h2c` gRPC request by translating the
        /// upgrade exchange into an upstream prior-knowledge h2c session.
        /// After the initial request is translated, all further HTTP/2 bytes are
        /// tunneled transparently end-to-end.
        pub fn forwardGrpcH2cUpgrade(
            self: *Self,
            io: Io,
            client_stream: Io.net.Stream,
            client_tls: ?*TLSStream,
            request: *const Request,
            upstream: *const Upstream,
            body_info: BodyInfo,
            initial_client_bytes_after_body: []const u8,
            decoded_settings_payload: []const u8,
            parent_span: SpanHandle,
            effective_path: ?[]const u8,
        ) ForwardError!ForwardResult {
            assert(upstream.port > 0);
            assert(decoded_settings_payload.len <= h2_proxy_frame_capacity_usize);

            if (client_tls != null) return ForwardError.UnsupportedProtocol;
            if (upstream.http_protocol != .h2c) return ForwardError.UnsupportedProtocol;
            if (upstream.tls) return ForwardError.UnsupportedProtocol;
            if (body_info.framing == .chunked) return ForwardError.UnsupportedProtocol;

            const request_class = serval_grpc.classifyRequest(request);
            if (request_class != .grpc) return ForwardError.UnsupportedProtocol;

            const forward_span = self.tracer.startSpan("forward_grpc_h2c_upgrade", parent_span);
            errdefer self.tracer.endSpan(forward_span, "forward_error");

            const connect_span = self.tracer.startSpan("connect_upstream", forward_span);
            const connect_cfg = ConnectConfig{
                .timeout_ns = connect_timeout_ns,
                .verify_upstream_tls = self.verify_upstream_tls,
                .client_ctx = self.client_ctx,
            };
            const connect_result = connectUpstream(
                upstream,
                io,
                connect_cfg,
                &self.dns_resolver,
            ) catch |err| {
                self.tracer.endSpan(connect_span, @errorName(err));
                return err;
            };
            self.tracer.setIntAttribute(connect_span, "dns_duration_ns", @intCast(connect_result.dns_duration_ns));
            self.tracer.setIntAttribute(connect_span, "tcp_connect_duration_ns", @intCast(connect_result.tcp_connect_duration_ns));
            self.tracer.endSpan(connect_span, null);

            var upstream_socket = connect_result.socket;
            defer upstream_socket.close();
            var client_socket = Socket.Plain.init_client(client_stream.socket.handle);

            const content_length = body_info.getContentLength() orelse 0;
            assert(body_info.bytes_already_read <= content_length);
            const remaining_body_bytes = content_length - body_info.bytes_already_read;
            const has_request_body = content_length > 0;

            var preamble_buf: [H2C_UPGRADE_PREAMBLE_BUFFER_SIZE_BYTES]u8 = undefined;
            const preamble = serval_h2.buildPriorKnowledgePreambleFromUpgrade(
                &preamble_buf,
                request,
                effective_path,
                decoded_settings_payload,
                !has_request_body,
            ) catch return ForwardError.UnsupportedProtocol;
            upstream_socket.write_all(preamble) catch return ForwardError.SendFailed;

            if (body_info.initial_body.len > 0) {
                sendH2DataFrames(
                    &upstream_socket,
                    body_info.initial_body,
                    remaining_body_bytes == 0,
                    self.h2_cfg.max_frame_size_bytes,
                ) catch return ForwardError.SendFailed;
            }

            client_socket.write_all(serval_h2.h2c_upgrade_response) catch return ForwardError.SendFailed;

            const tunnel_span = self.tracer.startSpan("grpc_h2c_upgrade_tunnel", forward_span);
            const tunnel_stats = relayGrpcH2cUpgradeSession(
                self.h2_cfg,
                io,
                &client_socket,
                &upstream_socket,
                remaining_body_bytes,
                initial_client_bytes_after_body,
            );
            self.tracer.setIntAttribute(tunnel_span, "duration_ns", @intCast(tunnel_stats.duration_ns));
            self.tracer.setIntAttribute(tunnel_span, "client_to_upstream_bytes", @intCast(tunnel_stats.client_to_upstream_bytes));
            self.tracer.setIntAttribute(tunnel_span, "upstream_to_client_bytes", @intCast(tunnel_stats.upstream_to_client_bytes));
            self.tracer.setStringAttribute(tunnel_span, "termination", @tagName(tunnel_stats.termination));
            self.tracer.endSpan(tunnel_span, null);
            self.tracer.endSpan(forward_span, null);

            debugLog("grpc h2c upgrade tunnel complete termination={s} up_bytes={d} down_bytes={d}", .{
                @tagName(tunnel_stats.termination),
                tunnel_stats.client_to_upstream_bytes,
                tunnel_stats.upstream_to_client_bytes,
            });

            return .{
                .status = 101,
                .response_bytes = serval_h2.h2c_upgrade_response.len + tunnel_stats.upstream_to_client_bytes,
                .connection_reused = false,
                .dns_duration_ns = connect_result.dns_duration_ns,
                .tcp_connect_duration_ns = connect_result.tcp_connect_duration_ns,
                .send_duration_ns = 0,
                .recv_duration_ns = tunnel_stats.duration_ns,
                .pool_wait_ns = 0,
                .upstream_local_port = connect_result.local_port,
            };
        }

        fn relayGrpcH2cUpgradeSession(
            runtime_cfg: config.H2Config,
            io: Io,
            client_socket: *Socket,
            upstream_socket: *Socket,
            remaining_body_bytes: u64,
            initial_client_bytes_after_body: []const u8,
        ) tunnel_mod.TunnelStats {
            assert(runtime_cfg.max_frame_size_bytes >= config.H2_MAX_FRAME_SIZE_BYTES);
            assert(runtime_cfg.max_frame_size_bytes <= h2_proxy_frame_capacity_bytes);
            assert(runtime_cfg.tunnel_idle_timeout_ns > 0);
            const start_ns = time.monotonicNanos();
            var stats = tunnel_mod.TunnelStats{};

            if (remaining_body_bytes > 0) {
                if (streamGrpcH2cUpgradeBody(client_socket, upstream_socket, remaining_body_bytes, runtime_cfg.max_frame_size_bytes, &stats.client_to_upstream_bytes)) |termination| {
                    stats.duration_ns = @intCast(time.elapsedNanos(start_ns, time.monotonicNanos()));
                    stats.termination = termination;
                    return stats;
                }
            }

            const tunnel_stats = tunnel_mod.relayWithConfig(
                io,
                client_socket,
                upstream_socket,
                initial_client_bytes_after_body,
                &[_]u8{},
                runtime_cfg.tunnel_idle_timeout_ns,
                h2c_tunnel_poll_timeout_ms,
            );
            stats.client_to_upstream_bytes += tunnel_stats.client_to_upstream_bytes;
            stats.upstream_to_client_bytes += tunnel_stats.upstream_to_client_bytes;
            stats.duration_ns = @intCast(time.elapsedNanos(start_ns, time.monotonicNanos()));
            stats.termination = tunnel_stats.termination;
            return stats;
        }

        fn streamGrpcH2cUpgradeBody(
            client_socket: *Socket,
            upstream_socket: *Socket,
            remaining_body_bytes: u64,
            max_frame_size_bytes: u32,
            counter_bytes: *u64,
        ) ?tunnel_mod.Termination {
            assert(remaining_body_bytes > 0);
            assert(max_frame_size_bytes >= config.H2_MAX_FRAME_SIZE_BYTES);
            assert(max_frame_size_bytes <= h2_proxy_frame_capacity_bytes);

            var body_buf: [h2_proxy_frame_capacity_usize]u8 = undefined;
            var remaining = remaining_body_bytes;

            while (remaining > 0) {
                const to_read: usize = @intCast(@min(remaining, max_frame_size_bytes));
                const bytes_read = client_socket.read(body_buf[0..to_read]) catch |err| {
                    return mapClientReadTermination(err);
                };
                if (bytes_read == 0) return .client_closed;

                const end_stream = remaining == bytes_read;
                sendH2DataFrames(upstream_socket, body_buf[0..bytes_read], end_stream, max_frame_size_bytes) catch |err| {
                    return mapUpstreamWriteTermination(err);
                };
                counter_bytes.* += bytes_read;
                remaining -= bytes_read;
            }

            return null;
        }

        fn sendH2DataFrames(
            upstream_socket: *Socket,
            payload: []const u8,
            end_stream: bool,
            max_frame_size_bytes: u32,
        ) serval_socket.SocketError!void {
            assert(max_frame_size_bytes >= config.H2_MAX_FRAME_SIZE_BYTES);
            assert(max_frame_size_bytes <= h2_proxy_frame_capacity_bytes);
            if (payload.len == 0) {
                if (end_stream) try sendH2Frame(upstream_socket, .data, serval_h2.flags_end_stream, H2C_UPGRADE_STREAM_ID, &[_]u8{});
                return;
            }

            var cursor: usize = 0;
            while (cursor < payload.len) {
                const remaining = payload.len - cursor;
                const chunk_len: usize = @intCast(@min(remaining, max_frame_size_bytes));
                const chunk = payload[cursor .. cursor + chunk_len];
                const is_last_chunk = cursor + chunk_len == payload.len;
                const flags: u8 = if (end_stream and is_last_chunk) serval_h2.flags_end_stream else 0;
                try sendH2Frame(upstream_socket, .data, flags, H2C_UPGRADE_STREAM_ID, chunk);
                cursor += chunk_len;
            }
        }

        fn sendH2Frame(
            upstream_socket: *Socket,
            frame_type: serval_h2.FrameType,
            flags: u8,
            stream_id: u32,
            payload: []const u8,
        ) serval_socket.SocketError!void {
            var header_buf: [serval_h2.frame_header_size_bytes]u8 = undefined;
            const header = buildProxyH2FrameHeader(&header_buf, .{
                .length = @intCast(payload.len),
                .frame_type = frame_type,
                .flags = flags,
                .stream_id = stream_id,
            });
            try upstream_socket.write_all(header);
            if (payload.len > 0) try upstream_socket.write_all(payload);
        }

        fn buildProxyH2FrameHeader(
            out: *[serval_h2.frame_header_size_bytes]u8,
            header: serval_h2.FrameHeader,
        ) []const u8 {
            assert(@intFromPtr(out) != 0);
            assert(header.length <= h2_proxy_frame_capacity_bytes);
            assert(header.stream_id <= 0x7fff_ffff);

            out[0] = @truncate((header.length >> 16) & 0xff);
            out[1] = @truncate((header.length >> 8) & 0xff);
            out[2] = @truncate(header.length & 0xff);
            out[3] = @intFromEnum(header.frame_type);
            out[4] = header.flags;

            const stream_id = header.stream_id & 0x7fff_ffff;
            out[5] = @truncate((stream_id >> 24) & 0x7f);
            out[6] = @truncate((stream_id >> 16) & 0xff);
            out[7] = @truncate((stream_id >> 8) & 0xff);
            out[8] = @truncate(stream_id & 0xff);
            return out[0..];
        }

        fn mapClientReadTermination(err: serval_socket.SocketError) tunnel_mod.Termination {
            return switch (err) {
                error.ConnectionClosed => .client_closed,
                else => .client_error,
            };
        }

        fn mapUpstreamWriteTermination(err: serval_socket.SocketError) tunnel_mod.Termination {
            return switch (err) {
                error.ConnectionClosed => .upstream_closed,
                else => .upstream_error,
            };
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
                Socket.Plain.init_client(client_stream.socket.handle);

            // Stream request body concurrently with reading the upstream response.
            //
            // Sequential body-then-response causes a TCP deadlock when the upstream
            // echoes or streams back a response while receiving the request body:
            //   - proxy blocks writing body (upstream TCP recv buffer full)
            //   - upstream blocks sending response (proxy not reading)
            // Running both directions concurrently breaks the deadlock.
            //
            // Context struct for the background body-streaming task.
            // All fields are pointers into the current stack frame, so we must
            // ensure the task completes before forwardWithConnection returns.
            const BodyCtx = struct {
                client: *Socket,
                upstream: *Socket,
                conn: *Connection,
                io: Io,
                body_info: BodyInfo,
                result: ForwardError!u64 = 0,

                fn run(bctx: *@This()) Io.Cancelable!void {
                    debugLog("send: body stream task start", .{});
                    bctx.result = streamRequestBody(
                        bctx.client,
                        bctx.upstream,
                        bctx.conn,
                        bctx.io,
                        bctx.body_info,
                    );
                    if (bctx.result) |bytes_sent| {
                        debugLog("send: body stream task complete bytes={d}", .{bytes_sent});
                    } else |err| {
                        debugLog("send: body stream task failed err={s}", .{@errorName(err)});
                    }
                }
            };

            var body_ctx: BodyCtx = undefined;
            var body_group: Io.Group = .init;
            // LIFO errdefer: runs BEFORE the pool-release errdefer defined above,
            // ensuring the background task releases its references to mutable_conn
            // before the connection is returned to the pool on any error path.
            errdefer body_group.cancel(io);

            const has_body = if (body_info.getContentLength()) |content_length| blk: {
                if (content_length > config.MAX_BODY_SIZE_BYTES) {
                    self.tracer.endSpan(send_span, "RequestBodyTooLarge");
                    return ForwardError.RequestBodyTooLarge;
                }
                debugLog("send: streaming body concurrently content_length={d}", .{content_length});
                body_ctx = .{
                    .client = &client_socket,
                    .upstream = &mutable_conn.socket,
                    .conn = &mutable_conn,
                    .io = io,
                    .body_info = body_info,
                    .result = 0,
                };
                body_group.async(io, BodyCtx.run, .{&body_ctx});
                break :blk true;
            } else false;

            const send_end_ns = time.monotonicNanos();
            const send_duration_ns = time.elapsedNanos(send_start_ns, send_end_ns);
            self.tracer.setIntAttribute(send_span, "duration_ns", @intCast(send_duration_ns));
            self.tracer.endSpan(send_span, null);
            debugLog("send: complete duration_us={d}", .{send_duration_ns / 1000});

            // Recv phase span (response headers + body).
            // Runs concurrently with body streaming when has_body is true.
            const recv_span = self.tracer.startSpan("recv_response", forward_span);
            debugLog("recv: awaiting response headers", .{});
            const is_head = request.method == .HEAD;
            var result = forwardResponse(io, &mutable_conn, client_stream, &mutable_conn.socket, &client_socket, is_pooled, is_head) catch |err| {
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

            // Wait for body streaming to finish before releasing the connection.
            // Must happen before pool.release so the background task no longer
            // holds references to mutable_conn.
            var body_stream_ok = true;
            body_group.await(io) catch |err| {
                debugLog("send: body group await failed err={s}", .{@errorName(err)});
                body_stream_ok = false;
            };
            if (has_body) {
                _ = body_ctx.result catch |err| {
                    debugLog("send: body stream error={s}", .{@errorName(err)});
                    body_stream_ok = false;
                };
            }

            // Mark unhealthy when body streaming fails to avoid pooling a
            // potentially poisoned keep-alive connection.
            // RFC 9112 recommends checking upstream's Connection: close header and not
            // pooling if present. Current implementation relies on StaleConnection retry
            // (Pingora-style). Consider adding explicit header check if retry overhead
            // becomes measurable.
            self.pool.release(upstream.idx, mutable_conn, body_stream_ok);

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
    const forwarder = Forwarder(pool_mod.NoPool, serval_tracing.NoopTracer).init(&no_pool, &tracer, true, null, .{}, DnsConfig{});
    // S1: postcondition - dns_resolver is initialized with default config
    try std.testing.expectEqual(serval_core.config.DNS_DEFAULT_TTL_NS, forwarder.dns_resolver.cfg.ttl_ns);
}

test "Forwarder init with SimplePool" {
    var simple_pool = pool_mod.SimplePool.init();
    var tracer = serval_tracing.NoopTracer{};
    // TigerStyle: null client_ctx for tests without TLS upstreams.
    // DnsConfig{} uses default TTL and timeout values.
    const forwarder = Forwarder(pool_mod.SimplePool, serval_tracing.NoopTracer).init(&simple_pool, &tracer, true, null, .{}, DnsConfig{});
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
    const MAX = max_stale_retries;

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
