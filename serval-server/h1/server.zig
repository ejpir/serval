// lib/serval-server/h1/server.zig
//! HTTP/1.1 Server
//!
//! Generic server parameterized by Handler, Pool, Metrics, Tracer.
//! TigerStyle: Comptime verification, explicit dependencies.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const log = serval_core.log.scoped(.server);
const types = serval_core.types;
const context = serval_core.context;
const config = serval_core.config;
const errors = serval_core.errors;
const hooks = serval_core.hooks;

const serval_net = @import("serval-net");
const set_tcp_no_delay = serval_net.set_tcp_no_delay;
const DnsConfig = serval_net.DnsConfig;

const pool_mod = @import("serval-pool").pool;
const metrics_mod = @import("serval-metrics").metrics;
const tracing_mod = @import("serval-tracing").tracing;
const SpanHandle = tracing_mod.SpanHandle;
const serval_http = @import("serval-http");
const parser_mod = serval_http.parser;
const parseContentLengthValue = serval_http.parseContentLengthValue;
const serval_websocket = @import("serval-websocket");
const serval_h2 = @import("serval-h2");
const serval_grpc = @import("serval-grpc");
const websocket_server = @import("../websocket/mod.zig");
const frontend = @import("../frontend/mod.zig");
const RuntimeProvider = frontend.RuntimeProvider;
const h2_server = @import("../h2/server.zig");
const h2_runtime = @import("../h2/runtime.zig");
const serval_proxy = @import("serval-proxy");
const forwarder_mod = serval_proxy.forwarder;
const serval_client = @import("serval-client");
const serval_tls = @import("serval-tls");
const ssl = serval_tls.ssl;
const TLSStream = serval_tls.TLSStream;
const ReloadableServerCtx = serval_tls.ReloadableServerCtx;
const ReloadableServerCtxError = serval_tls.ReloadableServerCtxError;
const HandshakeInfo = serval_tls.HandshakeInfo;

// Local h1 modules
const connection = @import("connection.zig");
const response = @import("response.zig");
const reader = @import("reader.zig");

// Use extracted utilities
const ProcessResult = connection.ProcessResult;
const clientWantsClose = connection.clientWantsClose;
const nextConnectionId = connection.nextConnectionId;
const sendStreamHeaders = response.sendStreamHeaders;
const sendChunk = response.sendChunk;
const sendFinalChunk = response.sendFinalChunk;
const StreamResponse = types.StreamResponse;
const getBodyLength = reader.getBodyLength;

const Request = types.Request;
const Response = types.Response;
const Context = context.Context;
const BodyReader = context.BodyReader;
const Config = config.Config;

// Time utilities from serval-core
const time = serval_core.time;
const realtimeNanos = time.realtimeNanos;

const Parser = parser_mod.Parser;
const HeaderMap = types.HeaderMap;
const BodyInfo = forwarder_mod.BodyInfo;
const ConnectionInfo = types.ConnectionInfo;

// Buffer sizes from centralized config
const REQUEST_BUFFER_SIZE_BYTES = config.REQUEST_BUFFER_SIZE_BYTES;
const H2C_INITIAL_READ_BUFFER_SIZE_BYTES = config.H2C_INITIAL_READ_BUFFER_SIZE_BYTES;
const CONNECTION_RECV_BUFFER_SIZE_BYTES = if (REQUEST_BUFFER_SIZE_BYTES > H2C_INITIAL_READ_BUFFER_SIZE_BYTES)
    REQUEST_BUFFER_SIZE_BYTES
else
    H2C_INITIAL_READ_BUFFER_SIZE_BYTES;
// Must be 0: a non-zero reader buffer causes readv to steal bytes into the
// reader's internal buffer. The body-forwarding fiber reads directly from the
// socket (bypassing the reader), so those stolen bytes are never seen — causing
// an off-by-N EOF on Content-Length bodies.
const PLAIN_STREAM_READER_BUFFER_SIZE_BYTES: usize = 0;
const DIRECT_RESPONSE_BUFFER_SIZE_BYTES = config.DIRECT_RESPONSE_BUFFER_SIZE_BYTES;
const DIRECT_REQUEST_BODY_SIZE_BYTES = config.DIRECT_REQUEST_BODY_SIZE_BYTES;

/// Maximum attempts when taking TLS reload-control mutex.
/// TigerStyle: Bounded spin loop for control-plane activation path.
const TLS_RELOAD_CONTROL_LOCK_MAX_ATTEMPTS: u32 = 1_000_000;

fn lockTlsReloadControlMutex(mutex: *std.atomic.Mutex) void {
    assert(@intFromPtr(mutex) != 0);

    var attempts: u32 = 0;
    while (attempts < TLS_RELOAD_CONTROL_LOCK_MAX_ATTEMPTS) : (attempts += 1) {
        if (mutex.tryLock()) return;
        std.atomic.spinLoopHint();
    }

    @panic("Server TLS reload control mutex lock timeout");
}

const EndpointResolveError = error{
    GetPeerNameFailed,
    ShortPeerSockaddr,
    UnsupportedPeerFamily,
    AddressRenderTooLong,
};

fn write_client_addr_ipv4(client_addr: *[46]u8, addr_be: *const [4]u8) EndpointResolveError!void {
    assert(@intFromPtr(client_addr) != 0);
    assert(@intFromPtr(addr_be) != 0);

    @memset(client_addr, 0);
    const rendered = std.fmt.bufPrint(
        client_addr[0 .. client_addr.len - 1],
        "{d}.{d}.{d}.{d}",
        .{ addr_be[0], addr_be[1], addr_be[2], addr_be[3] },
    ) catch return error.AddressRenderTooLong;
    client_addr[rendered.len] = 0;
}

fn write_client_addr_ipv6(client_addr: *[46]u8, addr_be: *const [16]u8) EndpointResolveError!void {
    assert(@intFromPtr(client_addr) != 0);
    assert(@intFromPtr(addr_be) != 0);

    const g0: u16 = (@as(u16, addr_be[0]) << 8) | @as(u16, addr_be[1]);
    const g1: u16 = (@as(u16, addr_be[2]) << 8) | @as(u16, addr_be[3]);
    const g2: u16 = (@as(u16, addr_be[4]) << 8) | @as(u16, addr_be[5]);
    const g3: u16 = (@as(u16, addr_be[6]) << 8) | @as(u16, addr_be[7]);
    const g4: u16 = (@as(u16, addr_be[8]) << 8) | @as(u16, addr_be[9]);
    const g5: u16 = (@as(u16, addr_be[10]) << 8) | @as(u16, addr_be[11]);
    const g6: u16 = (@as(u16, addr_be[12]) << 8) | @as(u16, addr_be[13]);
    const g7: u16 = (@as(u16, addr_be[14]) << 8) | @as(u16, addr_be[15]);

    @memset(client_addr, 0);
    const rendered = std.fmt.bufPrint(
        client_addr[0 .. client_addr.len - 1],
        "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}",
        .{ g0, g1, g2, g3, g4, g5, g6, g7 },
    ) catch return error.AddressRenderTooLong;
    client_addr[rendered.len] = 0;
}

fn set_client_endpoint_from_socket(ctx: *Context, socket_fd: i32) EndpointResolveError!void {
    assert(@intFromPtr(ctx) != 0);
    assert(socket_fd >= 0);

    var storage: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
    var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    std.posix.getpeername(socket_fd, @ptrCast(&storage), &addr_len) catch {
        return error.GetPeerNameFailed;
    };

    switch (storage.family) {
        std.posix.AF.INET => {
            if (addr_len < @sizeOf(std.posix.sockaddr.in)) return error.ShortPeerSockaddr;
            const peer4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&storage));
            const addr_be: *const [4]u8 = @ptrCast(&peer4.addr);
            try write_client_addr_ipv4(&ctx.client_addr, addr_be);
            ctx.client_port = std.mem.bigToNative(u16, peer4.port);
        },
        std.posix.AF.INET6 => {
            if (addr_len < @sizeOf(std.posix.sockaddr.in6)) return error.ShortPeerSockaddr;
            const peer6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
            try write_client_addr_ipv6(&ctx.client_addr, &peer6.addr);
            ctx.client_port = std.mem.bigToNative(u16, peer6.port);
        },
        else => return error.UnsupportedPeerFamily,
    }
}

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
        websocket_server.verifyHandlerExtensions(Handler);
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
        /// Client SSL context for upstream TLS connections.
        /// Created once at init, shared across all connections.
        /// TigerStyle: Caller owns lifecycle via deinit.
        client_ctx: ?*ssl.SSL_CTX,
        /// DNS configuration retained for transport runtime orchestration.
        dns_config: DnsConfig,
        /// Optional external runtime-provider adapter.
        /// Enables generation-aware orchestration without hard coupling.
        runtime_provider: ?RuntimeProvider,

        /// Protects publish/unpublish of the server TLS manager pointer.
        /// TigerStyle: Explicit synchronization for control-plane activation path.
        tls_reload_control_mutex: std.atomic.Mutex = .unlocked,

        /// Pointer to active server TLS generation manager while run() is executing.
        /// Null when server-side TLS is disabled or run() is not active.
        tls_ctx_manager_ptr: ?*ReloadableServerCtx = null,

        pub const ReloadServerTlsError = error{
            TlsReloadUnavailable,
        } || ReloadableServerCtxError || ssl.CreateServerCtxFromPemFilesError;

        /// Atomically activate a new server TLS context generation from PEM paths.
        /// Returns the activated generation number.
        pub fn reloadServerTlsFromPemFiles(
            self: *Self,
            cert_path: []const u8,
            key_path: []const u8,
        ) ReloadServerTlsError!u32 {
            assert(@intFromPtr(self) != 0);
            assert(cert_path.len <= std.math.maxInt(u16));
            assert(key_path.len <= std.math.maxInt(u16));

            lockTlsReloadControlMutex(&self.tls_reload_control_mutex);
            defer self.tls_reload_control_mutex.unlock();

            const manager = self.tls_ctx_manager_ptr orelse return error.TlsReloadUnavailable;
            const generation = try manager.activateFromPemFiles(cert_path, key_path);
            assert(generation > 0);
            return generation;
        }

        /// Read current active server TLS generation.
        pub fn activeServerTlsGeneration(self: *Self) error{TlsReloadUnavailable}!u32 {
            assert(@intFromPtr(self) != 0);

            lockTlsReloadControlMutex(&self.tls_reload_control_mutex);
            defer self.tls_reload_control_mutex.unlock();

            const manager = self.tls_ctx_manager_ptr orelse return error.TlsReloadUnavailable;
            const generation = manager.activeGeneration();
            assert(generation > 0);
            return generation;
        }

        fn publishTlsCtxManager(self: *Self, manager: *ReloadableServerCtx) void {
            assert(@intFromPtr(self) != 0);
            assert(@intFromPtr(manager) != 0);

            lockTlsReloadControlMutex(&self.tls_reload_control_mutex);
            defer self.tls_reload_control_mutex.unlock();

            assert(self.tls_ctx_manager_ptr == null);
            self.tls_ctx_manager_ptr = manager;
        }

        fn unpublishTlsCtxManager(self: *Self) void {
            assert(@intFromPtr(self) != 0);

            lockTlsReloadControlMutex(&self.tls_reload_control_mutex);
            defer self.tls_reload_control_mutex.unlock();

            self.tls_ctx_manager_ptr = null;
        }

        pub fn init(
            handler: *Handler,
            pool: *Pool,
            metrics: *Metrics,
            tracer: *Tracer,
            cfg: Config,
            client_ctx: ?*ssl.SSL_CTX,
            dns_config: DnsConfig,
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
                .forwarder = forwarder_mod.Forwarder(Pool, Tracer).init(pool, tracer, verify_upstream, client_ctx, dns_config),
                .client_ctx = client_ctx,
                .dns_config = dns_config,
                .runtime_provider = null,
            };
        }

        /// Configure optional runtime provider adapter.
        /// Keeps server standalone while allowing external orchestration integration.
        pub fn setRuntimeProvider(self: *Self, runtime_provider: ?RuntimeProvider) void {
            assert(@intFromPtr(self) != 0);
            if (runtime_provider) |provider| {
                const generation = provider.activeGeneration();
                if (generation) |value| assert(value > 0);
            }
            self.runtime_provider = runtime_provider;
        }

        pub fn getRuntimeProvider(self: *const Self) ?RuntimeProvider {
            assert(@intFromPtr(self) != 0);
            return self.runtime_provider;
        }

        /// Clean up server resources.
        /// TigerStyle: Explicit deinit, pairs with init.
        pub fn deinit(self: *Self) void {
            // TigerStyle: Client context is owned by caller, not freed here.
            // Defensive reset of published TLS manager pointer for reuse-after-stop flows.
            self.unpublishTlsCtxManager();
        }

        /// Run the server with concurrent connection handling.
        /// TigerStyle: Explicit resource cleanup with defer.
        ///
        /// Parameters:
        ///   - io: The async I/O runtime
        ///   - shutdown: Atomic flag to signal shutdown (checked between accepts)
        ///   - listener_fd_out: Optional pointer to store listener socket FD for external shutdown.
        ///                      Close this FD from another thread to interrupt accept() and trigger shutdown.
        ///                      TigerStyle: Explicit shutdown mechanism for testability.
        pub fn run(
            self: *Self,
            io: Io,
            shutdown: *std.atomic.Value(bool),
            listener_fd_out: ?*std.atomic.Value(i32),
        ) !void {
            assert(self.config.port > 0);
            assert(self.config.listen_host.len > 0);
            if (self.runtime_provider) |provider| {
                const generation = provider.activeGeneration();
                if (generation) |value| assert(value > 0);
            }

            const addr = frontend.preflightAndResolveListenAddress(&self.config) catch |err| {
                log.err("server: frontend preflight failed: {s}", .{@errorName(err)});
                return err;
            };

            var runtime_orchestrator: frontend.RuntimeOrchestrator = undefined;
            runtime_orchestrator.init(
                shutdown,
                self.dns_config,
                self.client_ctx,
                self.forwarder.verify_upstream_tls,
            );
            runtime_orchestrator.start(&self.config) catch |err| {
                log.err("server: frontend runtime orchestration start failed: {s}", .{@errorName(err)});
                return err;
            };
            defer runtime_orchestrator.stop();

            var tcp_server = addr.listen(io, .{
                .kernel_backlog = self.config.kernel_backlog,
                .reuse_address = true,
            }) catch return error.ListenFailed;

            // Store listener FD for external shutdown (if requested)
            // TigerStyle: Atomic store for cross-thread access
            if (listener_fd_out) |fd_out| {
                fd_out.store(@intCast(tcp_server.socket.handle), .release);
            }
            defer {
                // Clear listener FD on exit
                if (listener_fd_out) |fd_out| {
                    fd_out.store(-1, .release);
                }
                tcp_server.deinit(io);
            }

            // TLS ALPN policy is process-global for all server contexts.
            // Apply configured policy before creating or reloading server contexts.
            ssl.setServerAlpnMixedOfferPolicy(self.config.alpn_mixed_offer_policy);

            // TLS: Initialize SSL_CTX if server-side TLS is configured (cert + key).
            // Note: tls_config may be set for upstream verification only; in that case
            // cert/key are absent and listener stays plaintext.
            const initial_tls_ctx: ?*ssl.SSL_CTX = if (self.config.tls) |tls_cfg| blk: {
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

            var maybe_reloadable_tls_ctx: ?ReloadableServerCtx = if (initial_tls_ctx) |ctx|
                ReloadableServerCtx.init(ctx)
            else
                null;
            defer if (maybe_reloadable_tls_ctx) |*reloadable_ctx| reloadable_ctx.deinit();

            const tls_ctx_manager: ?*ReloadableServerCtx = if (maybe_reloadable_tls_ctx) |*reloadable_ctx|
                reloadable_ctx
            else
                null;

            self.unpublishTlsCtxManager();
            if (tls_ctx_manager) |manager| {
                self.publishTlsCtxManager(manager);
            }
            defer self.unpublishTlsCtxManager();

            var group: Io.Group = .init;

            while (!shutdown.load(.acquire)) {
                const accept_start_ns = realtimeNanos();
                const stream = tcp_server.accept(io) catch |err| {
                    if (shutdown.load(.acquire)) break;
                    log.err("Accept failed: {s}", .{@errorName(err)});
                    continue;
                };
                const accept_elapsed_ns = realtimeNanos() - accept_start_ns;
                const accept_us: u64 = if (accept_elapsed_ns >= 0) @intCast(@divFloor(accept_elapsed_ns, 1000)) else 0;
                const accept_done_ns = realtimeNanos();
                log.debug("server: accept completed accept_us={d} timestamp={d}", .{ accept_us, @as(u64, @intCast(accept_done_ns)) });

                group.concurrent(io, handleConnectionImpl, .{
                    self.handler,
                    &self.forwarder,
                    self.metrics,
                    self.tracer,
                    self.config,
                    tls_ctx_manager,
                    self.runtime_provider,
                    io,
                    stream,
                }) catch |err| {
                    log.err("Failed to spawn handler: {s}", .{@errorName(err)});
                    stream.close(io);
                };
            }

            group.await(io) catch |err| switch (err) {
                error.Canceled => {},
            };
        }

        // =========================================================================
        // I/O Wrapper Functions (TLS or Plain)
        // TigerStyle: Abstract TLS vs plain socket I/O
        // =========================================================================

        /// Context for BodyReader read operations.
        /// Captures all state needed to read from TLS or plain socket.
        /// TigerStyle: Stack-allocated, no runtime allocation, no hidden buffering.
        const BodyReadContext = struct {
            maybe_tls: ?*TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            plain_reader: ?*Io.net.Stream.Reader,
            conn_id: u64,
        };

        /// Read function for BodyReader - reads from TLS or plain socket.
        /// This function signature matches BodyReader.read_fn.
        /// TigerStyle: Type-erased wrapper for connectionRead.
        fn bodyReadFn(ctx_ptr: *anyopaque, buf: []u8) ?usize {
            // S1: Preconditions (buf.len checked in connectionRead)
            assert(@intFromPtr(ctx_ptr) != 0);

            const ctx: *BodyReadContext = @ptrCast(@alignCast(ctx_ptr));
            return connectionRead(ctx.maybe_tls, ctx.io, ctx.stream, ctx.plain_reader, buf, ctx.conn_id);
        }

        /// Read from connection (TLS or plain socket).
        /// Plain sockets stay on std.Io so fibers, readiness, and cancellation remain intact.
        /// TigerStyle: Explicit reads, deterministic behavior, no raw syscall bypass.
        fn connectionRead(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            plain_reader: ?*Io.net.Stream.Reader,
            buf: []u8,
            conn_id: u64,
        ) ?usize {
            assert(buf.len > 0); // S1: precondition
            assert(@intFromPtr(io) != 0); // S1: precondition

            if (maybe_tls) |tls| {
                // TLS read (blocking - std.Io handles socket-level async)
                var mutable_tls = tls.*;
                const n = mutable_tls.read(buf) catch |err| {
                    // Log TLS errors (includes client disconnect, handshake issues, etc.)
                    log.debug("server: conn={d} TLS read error: {s}", .{ conn_id, @errorName(err) });
                    return null;
                };
                return n;
            } else {
                var fallback_reader_buf: [PLAIN_STREAM_READER_BUFFER_SIZE_BYTES]u8 = undefined;
                var fallback_stream_reader = stream.reader(io.*, &fallback_reader_buf);
                const stream_reader = plain_reader orelse &fallback_stream_reader;
                var bufs: [1][]u8 = .{buf};
                const n = stream_reader.interface.readVec(&bufs) catch |err| switch (err) {
                    error.EndOfStream => return null,
                    error.ReadFailed => {
                        const read_err = stream_reader.err orelse unreachable;
                        log.debug("server: conn={d} recv error: {s}", .{ conn_id, @errorName(read_err) });
                        return null;
                    },
                };
                if (n == 0) return null;
                return n;
            }
        }

        fn buildH2HandoffBytes(
            plain_reader: ?*Io.net.Stream.Reader,
            visible_bytes: []const u8,
            handoff_buf: []u8,
        ) []const u8 {
            assert(visible_bytes.len <= handoff_buf.len);

            const plain_stream_reader = plain_reader orelse return visible_bytes;
            if (plain_stream_reader.interface.seek >= plain_stream_reader.interface.end) return visible_bytes;

            const pending = plain_stream_reader.interface.end - plain_stream_reader.interface.seek;
            assert(visible_bytes.len + pending <= handoff_buf.len);
            @memcpy(handoff_buf[0..visible_bytes.len], visible_bytes);
            const buffered = plain_stream_reader.interface.buffer[plain_stream_reader.interface.seek..plain_stream_reader.interface.end];
            @memcpy(handoff_buf[visible_bytes.len .. visible_bytes.len + pending], buffered);
            plain_stream_reader.interface.seek = plain_stream_reader.interface.end;
            return handoff_buf[0 .. visible_bytes.len + pending];
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
                // Plain socket write (blocking - fiber yields to scheduler until send buffer accepts data)
                var write_buf: [config.SERVER_WRITE_BUFFER_SIZE_BYTES]u8 =
                    std.mem.zeroes([config.SERVER_WRITE_BUFFER_SIZE_BYTES]u8);
                var writer = stream.writer(io.*, &write_buf);
                try writer.interface.writeAll(data);
                try writer.interface.flush();
            }
        }

        /// TLS-aware write wrapper for streaming response helpers.
        /// Implements writeAll interface that sendStreamHeaders/sendChunk/sendFinalChunk expect.
        /// TigerStyle: Stack-allocated context, no runtime allocation.
        const TlsWriter = struct {
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,

            /// Write all data to connection (TLS or plain).
            /// TigerStyle: Maps to connectionWrite with error handling.
            pub fn writeAll(self: *TlsWriter, data: []const u8) !void {
                // S1: Precondition - data must be non-empty for write
                // Note: Allow empty writes for flexibility (e.g., empty extra_headers)
                if (data.len == 0) return;
                try connectionWrite(self.maybe_tls, self.io, self.stream, data);
            }
        };

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
            recv_buf: []u8,
            buffer_offset: usize,
            buffer_len: *usize,
            conn_id: u64,
        ) bool {
            // TigerStyle: Bounded loop - max 16 iterations to receive complete headers
            const max_read_iterations: u32 = 16;
            var read_iterations: u32 = 0;

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
                const n = connectionRead(maybe_tls, io, stream, null, recv_buf[buffer_len.*..], conn_id) orelse return false;
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

        const H2_ERROR_PROTOCOL: u32 = 0x1;
        const H2_ERROR_INTERNAL: u32 = 0x2;

        fn sendH2GoAway(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            last_stream_id: u32,
            error_code: u32,
        ) void {
            assert(last_stream_id <= 0x7fff_ffff);

            var frame_buf: [serval_h2.frame_header_size_bytes + 8]u8 = undefined;
            const header = serval_h2.buildFrameHeader(frame_buf[0..serval_h2.frame_header_size_bytes], .{
                .length = 8,
                .frame_type = .goaway,
                .flags = 0,
                .stream_id = 0,
            }) catch return;
            std.mem.writeInt(u32, frame_buf[header.len..][0..4], last_stream_id, .big);
            std.mem.writeInt(u32, frame_buf[header.len + 4 ..][0..4], error_code, .big);
            connectionWrite(maybe_tls, io, stream, frame_buf[0 .. header.len + 8]) catch return;
        }

        fn sendH2InitialSettings(
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
        ) bool {
            assert(@intFromPtr(io) != 0);
            assert(stream.socket.handle >= 0);

            var runtime = h2_runtime.Runtime.init() catch return false;
            var settings_buf: [h2_runtime.initial_settings_frame_buffer_size_bytes]u8 = undefined;
            const settings_frame = runtime.writeInitialSettingsFrame(&settings_buf) catch return false;
            connectionWrite(maybe_tls, io, stream, settings_frame) catch return false;
            return true;
        }

        const H2_STREAM_METRICS_FALLBACK_STATUS: u16 = 500;
        const H2_STREAM_CLIENT_CLOSED_STATUS: u16 = 499;
        const H2_STREAM_SLOT_TABLE_CAPACITY: usize = config.H2_MAX_CONCURRENT_STREAMS;
        /// Fixed-capacity path snapshot for stream-scoped onLog entries.
        /// Long paths are truncated to preserve bounded memory per connection.
        const H2_STREAM_LOG_PATH_BUFFER_SIZE_BYTES: usize = @intCast(config.OTEL_MAX_NAME_LEN);

        const H2StreamSlot = struct {
            used: bool = false,
            stream_id: u32 = 0,
            span_handle: SpanHandle = .{},
            method: types.Method = .GET,
            path_len: u16 = 0,
            path_buf: [H2_STREAM_LOG_PATH_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([H2_STREAM_LOG_PATH_BUFFER_SIZE_BYTES]u8),
            start_time_ns: i128 = 0,
            request_number: u32 = 0,
        };

        const TerminatedH2TelemetryAdapter = struct {
            inner: *Handler,
            metrics: *Metrics,
            tracer: *Tracer,
            parent_span: ?SpanHandle,
            emit_stream_metrics: bool,
            connection_id: u64,
            connection_start_ns: i128,
            client_addr: [46]u8,
            client_port: u16,
            next_request_number: u32,
            stream_slots: [H2_STREAM_SLOT_TABLE_CAPACITY]H2StreamSlot = [_]H2StreamSlot{.{}} ** H2_STREAM_SLOT_TABLE_CAPACITY,

            fn init(
                inner: *Handler,
                metrics: *Metrics,
                tracer: *Tracer,
                connection_ctx: *const Context,
                parent_span: ?SpanHandle,
                emit_stream_metrics: bool,
            ) @This() {
                assert(@intFromPtr(inner) != 0);
                assert(@intFromPtr(metrics) != 0);
                assert(@intFromPtr(tracer) != 0);
                assert(@intFromPtr(connection_ctx) != 0);

                const normalized_parent_span: ?SpanHandle = if (parent_span) |span|
                    if (span.isValid()) span else null
                else
                    null;

                return .{
                    .inner = inner,
                    .metrics = metrics,
                    .tracer = tracer,
                    .parent_span = normalized_parent_span,
                    .emit_stream_metrics = emit_stream_metrics,
                    .connection_id = connection_ctx.connection_id,
                    .connection_start_ns = connection_ctx.connection_start_ns,
                    .client_addr = connection_ctx.client_addr,
                    .client_port = connection_ctx.client_port,
                    .next_request_number = connection_ctx.request_number,
                };
            }

            pub fn handleH2Headers(
                self: *@This(),
                stream_id: u32,
                request: *const Request,
                end_stream: bool,
                writer: *h2_server.ResponseWriter,
            ) !void {
                return self.inner.handleH2Headers(stream_id, request, end_stream, writer);
            }

            pub fn handleH2Data(
                self: *@This(),
                stream_id: u32,
                payload: []const u8,
                end_stream: bool,
                writer: *h2_server.ResponseWriter,
            ) !void {
                return self.inner.handleH2Data(stream_id, payload, end_stream, writer);
            }

            pub fn handleH2StreamReset(self: *@This(), stream_id: u32, error_code_raw: u32) void {
                if (comptime @hasDecl(Handler, "handleH2StreamReset")) {
                    self.inner.handleH2StreamReset(stream_id, error_code_raw);
                }
            }

            pub fn handleH2ConnectionClose(self: *@This(), goaway: serval_h2.GoAway) void {
                if (comptime @hasDecl(Handler, "handleH2ConnectionClose")) {
                    self.inner.handleH2ConnectionClose(goaway);
                }
            }

            pub fn handleH2StreamOpen(self: *@This(), stream_id: u32, request: *const Request) void {
                if (self.emit_stream_metrics) {
                    self.metrics.requestStart();
                }

                var span_name_buf: [config.OTEL_MAX_NAME_LEN]u8 = std.mem.zeroes([config.OTEL_MAX_NAME_LEN]u8);
                const span_name = buildSpanName(request.method, request.path, &span_name_buf);
                const span_handle = self.tracer.startSpan(span_name, self.parent_span);
                const stream_start_ns = time.realtimeNanos();
                const request_number = self.nextRequestNumber();
                self.upsertStream(
                    stream_id,
                    span_handle,
                    request.method,
                    request.path,
                    stream_start_ns,
                    request_number,
                );

                if (span_handle.isValid()) {
                    if (comptime @hasDecl(Tracer, "setStringAttribute")) {
                        self.tracer.setStringAttribute(span_handle, "http.request.method", @tagName(request.method));
                        self.tracer.setStringAttribute(span_handle, "url.path", request.path);
                    }
                    if (comptime @hasDecl(Tracer, "setIntAttribute")) {
                        self.tracer.setIntAttribute(span_handle, "h2.stream_id", @intCast(stream_id));
                    }
                }

                if (comptime @hasDecl(Handler, "handleH2StreamOpen")) {
                    self.inner.handleH2StreamOpen(stream_id, request);
                }
            }

            pub fn handleH2StreamClose(self: *@This(), summary: h2_server.StreamSummary) void {
                const status = streamSummaryStatus(summary);
                if (self.emit_stream_metrics) {
                    self.metrics.requestEnd(status, summary.duration_ns);
                }

                const stream_error_name = streamSummaryError(summary);
                const stream_slot = self.popStream(summary.stream_id);
                if (stream_slot) |slot| {
                    if (slot.span_handle.isValid()) {
                        if (comptime @hasDecl(Tracer, "setIntAttribute")) {
                            self.tracer.setIntAttribute(slot.span_handle, "http.response.status_code", @intCast(status));
                            self.tracer.setIntAttribute(slot.span_handle, "h2.stream_id", @intCast(summary.stream_id));
                            self.tracer.setIntAttribute(slot.span_handle, "h2.request_data_bytes", saturatingI64(summary.request_data_bytes));
                            self.tracer.setIntAttribute(slot.span_handle, "h2.response_data_bytes", saturatingI64(summary.response_data_bytes));
                        }
                        self.tracer.endSpan(slot.span_handle, stream_error_name);
                    }

                    if (comptime hooks.hasHook(Handler, "onLog")) {
                        const path_len: usize = @intCast(slot.path_len);
                        const stream_path = slot.path_buf[0..path_len];

                        var stream_ctx = Context.init();
                        stream_ctx.start_time_ns = slot.start_time_ns;
                        stream_ctx.connection_id = self.connection_id;
                        stream_ctx.connection_start_ns = self.connection_start_ns;
                        stream_ctx.client_addr = self.client_addr;
                        stream_ctx.client_port = self.client_port;
                        stream_ctx.request_number = slot.request_number;
                        stream_ctx.bytes_received = summary.request_data_bytes;
                        stream_ctx.bytes_sent = summary.response_data_bytes;
                        stream_ctx.response_status = status;
                        stream_ctx.duration_ns = summary.duration_ns;
                        stream_ctx.error_name = stream_error_name;

                        const log_entry = serval_core.log.LogEntry{
                            .timestamp_s = time.nanosToSecondsI128(slot.start_time_ns),
                            .start_time_ns = slot.start_time_ns,
                            .duration_ns = summary.duration_ns,
                            .method = slot.method,
                            .path = stream_path,
                            .request_bytes = summary.request_data_bytes,
                            .status = status,
                            .response_bytes = summary.response_data_bytes,
                            .upstream = null,
                            .upstream_duration_ns = 0,
                            .error_phase = streamSummaryErrorPhase(summary),
                            .error_name = stream_error_name,
                            .connection_reused = false,
                            .keepalive = false,
                            .parse_duration_ns = 0,
                            .connection_id = self.connection_id,
                            .request_number = slot.request_number,
                            .client_addr = self.client_addr,
                        };
                        self.inner.onLog(&stream_ctx, log_entry);
                    }
                }

                if (comptime @hasDecl(Handler, "handleH2StreamClose")) {
                    self.inner.handleH2StreamClose(summary);
                }
            }

            fn streamSummaryStatus(summary: h2_server.StreamSummary) u16 {
                if (summary.response_status >= 100 and summary.response_status <= 599) {
                    return summary.response_status;
                }

                return switch (summary.close_reason) {
                    .local_reset => H2_STREAM_METRICS_FALLBACK_STATUS,
                    .peer_reset => H2_STREAM_CLIENT_CLOSED_STATUS,
                    .connection_close => if (summary.reset_error_code_raw == @intFromEnum(serval_h2.ErrorCode.no_error))
                        H2_STREAM_CLIENT_CLOSED_STATUS
                    else
                        H2_STREAM_METRICS_FALLBACK_STATUS,
                    .local_end_stream => H2_STREAM_METRICS_FALLBACK_STATUS,
                };
            }

            fn streamSummaryError(summary: h2_server.StreamSummary) ?[]const u8 {
                return switch (summary.close_reason) {
                    .local_end_stream => if (summary.reset_error_code_raw == @intFromEnum(serval_h2.ErrorCode.no_error))
                        null
                    else
                        "h2_local_end_stream_error",
                    .peer_reset => "h2_peer_reset",
                    .local_reset => "h2_local_reset",
                    .connection_close => if (summary.reset_error_code_raw == @intFromEnum(serval_h2.ErrorCode.no_error))
                        null
                    else
                        "h2_connection_close",
                };
            }

            fn streamSummaryErrorPhase(summary: h2_server.StreamSummary) ?errors.ErrorContext.Phase {
                return switch (summary.close_reason) {
                    .local_end_stream => if (summary.reset_error_code_raw == @intFromEnum(serval_h2.ErrorCode.no_error))
                        null
                    else
                        .handler_response,
                    .peer_reset => .recv,
                    .local_reset => .handler_response,
                    .connection_close => if (summary.reset_error_code_raw == @intFromEnum(serval_h2.ErrorCode.no_error))
                        null
                    else
                        .recv,
                };
            }

            fn findStreamSlot(self: *@This(), stream_id: u32) ?*H2StreamSlot {
                assert(stream_id > 0);

                for (self.stream_slots[0..]) |*slot| {
                    if (!slot.used) continue;
                    if (slot.stream_id == stream_id) return slot;
                }
                return null;
            }

            fn upsertStream(
                self: *@This(),
                stream_id: u32,
                span_handle: SpanHandle,
                method: types.Method,
                path: []const u8,
                start_time_ns: i128,
                request_number: u32,
            ) void {
                assert(stream_id > 0);
                assert(start_time_ns > 0);

                const copy_len: usize = @min(path.len, H2_STREAM_LOG_PATH_BUFFER_SIZE_BYTES);
                assert(copy_len <= std.math.maxInt(u16));

                if (self.findStreamSlot(stream_id)) |slot| {
                    slot.span_handle = span_handle;
                    slot.method = method;
                    slot.start_time_ns = start_time_ns;
                    slot.request_number = request_number;
                    slot.path_len = @intCast(copy_len);
                    if (copy_len > 0) {
                        @memcpy(slot.path_buf[0..copy_len], path[0..copy_len]);
                    }
                    return;
                }

                for (self.stream_slots[0..]) |*slot| {
                    if (slot.used) continue;
                    slot.* = .{
                        .used = true,
                        .stream_id = stream_id,
                        .span_handle = span_handle,
                        .method = method,
                        .path_len = @intCast(copy_len),
                        .start_time_ns = start_time_ns,
                        .request_number = request_number,
                    };
                    if (copy_len > 0) {
                        @memcpy(slot.path_buf[0..copy_len], path[0..copy_len]);
                    }
                    return;
                }
            }

            fn popStream(self: *@This(), stream_id: u32) ?H2StreamSlot {
                assert(stream_id > 0);

                for (self.stream_slots[0..]) |*slot| {
                    if (!slot.used) continue;
                    if (slot.stream_id != stream_id) continue;
                    const stream_slot = slot.*;
                    slot.* = .{};
                    return stream_slot;
                }
                return null;
            }

            fn nextRequestNumber(self: *@This()) u32 {
                const request_number = self.next_request_number;
                if (self.next_request_number < std.math.maxInt(u32)) {
                    self.next_request_number += 1;
                }
                return request_number;
            }

            fn saturatingI64(value: u64) i64 {
                const i64_max_as_u64: u64 = @intCast(std.math.maxInt(i64));
                if (value >= i64_max_as_u64) return std.math.maxInt(i64);
                return @intCast(value);
            }
        };

        const GrpcCompletionPolicy = struct {
            tracked_streams: [config.H2_MAX_CONCURRENT_STREAMS]u32 = [_]u32{0} ** config.H2_MAX_CONCURRENT_STREAMS,
            tracked_stream_count: u16 = 0,

            const PolicyError = error{TooManyTrackedGrpcCompletionStreams};

            fn isGrpcRequest(self: *const @This(), request: *const Request) bool {
                assert(@intFromPtr(self) != 0);
                assert(@intFromPtr(request) != 0);

                const request_class = serval_grpc.classifyRequest(request);
                return request_class == .grpc;
            }

            fn trackStream(self: *@This(), stream_id: u32) PolicyError!void {
                assert(@intFromPtr(self) != 0);
                assert(stream_id > 0);

                if (self.isTrackedStream(stream_id)) return;
                if (self.tracked_stream_count >= config.H2_MAX_CONCURRENT_STREAMS) {
                    return error.TooManyTrackedGrpcCompletionStreams;
                }

                var index: usize = 0;
                while (index < self.tracked_streams.len) : (index += 1) {
                    if (self.tracked_streams[index] != 0) continue;
                    self.tracked_streams[index] = stream_id;
                    self.tracked_stream_count += 1;
                    return;
                }

                return error.TooManyTrackedGrpcCompletionStreams;
            }

            fn untrackStream(self: *@This(), stream_id: u32) void {
                assert(@intFromPtr(self) != 0);
                if (stream_id == 0) return;

                var index: usize = 0;
                while (index < self.tracked_streams.len) : (index += 1) {
                    if (self.tracked_streams[index] != stream_id) continue;
                    self.tracked_streams[index] = 0;
                    if (self.tracked_stream_count > 0) {
                        self.tracked_stream_count -= 1;
                    }
                    return;
                }
            }

            fn isTrackedStream(self: *@This(), stream_id: u32) bool {
                assert(@intFromPtr(self) != 0);
                if (stream_id == 0) return false;

                var index: usize = 0;
                while (index < self.tracked_streams.len) : (index += 1) {
                    if (self.tracked_streams[index] == stream_id) return true;
                }
                return false;
            }
        };

        const H2cBridgeHandler = struct {
            const pending_reset_capacity: usize = @intCast(config.H2_MAX_CONCURRENT_STREAMS);
            const upstream_reader_idle_ms: i64 = 10;
            const upstream_read_timeout_ms: i64 = 50;
            const PendingReset = struct {
                used: bool = false,
                downstream_stream_id: u32 = 0,
                error_code_raw: u32 = @intFromEnum(serval_h2.ErrorCode.cancel),
            };

            inner: *Handler,
            io: Io,
            bridge: serval_proxy.H2StreamBridge,
            connection_ctx: *Context,
            response_status: u16 = 200,
            response_bytes: u64 = 0,
            connection_reused: bool = false,
            dns_duration_ns: u64 = 0,
            tcp_connect_duration_ns: u64 = 0,
            upstream_local_port: u16 = 0,
            bridge_mutex: Io.Mutex = .init,
            connection_mutex: ?*Io.Mutex = null,
            writer_template: ?*h2_server.ResponseWriter = null,
            upstream_reader_group: Io.Group = .init,
            upstream_reader_started: bool = false,
            upstream_reader_stop: bool = false,
            pending_resets: [pending_reset_capacity]PendingReset = [_]PendingReset{.{}} ** pending_reset_capacity,
            grpc_completion_policy: GrpcCompletionPolicy = .{},

            pub const BridgeError = error{
                UpstreamRejected,
                UnsupportedProtocol,
                MissingBinding,
                UpstreamConnectionClosing,
                FrameLimitExceeded,
                MissingGrpcStatus,
                InvalidGrpcStatus,
                TooManyTrackedGrpcCompletionStreams,
            } || serval_proxy.H2StreamBridgeError || h2_server.Error;

            pub fn init(
                inner: *Handler,
                io: Io,
                bridge_client: *serval_client.Client,
                bridge_sessions: *serval_client.H2UpstreamSessionPool,
                connection_ctx: *Context,
            ) @This() {
                assert(@intFromPtr(inner) != 0);
                assert(@intFromPtr(bridge_client) != 0);
                assert(@intFromPtr(bridge_sessions) != 0);
                assert(@intFromPtr(connection_ctx) != 0);

                var instance = @This(){
                    .inner = inner,
                    .io = io,
                    .bridge = serval_proxy.H2StreamBridge.init(bridge_client, bridge_sessions),
                    .connection_ctx = connection_ctx,
                };
                instance.bridge.setDebugConnectionId(connection_ctx.connection_id);
                return instance;
            }

            pub fn deinit(self: *@This()) void {
                assert(@intFromPtr(self) != 0);
                if (self.upstream_reader_started) {
                    self.upstream_reader_stop = true;
                    log.debug(
                        "h2 bridge: conn={d} cancel upstream reader group reason=deinit",
                        .{self.connection_ctx.connection_id},
                    );
                    self.upstream_reader_group.cancel(self.io);
                    self.upstream_reader_started = false;
                }
                self.bridge.deinit();
            }

            pub fn startH2BackgroundTasks(
                self: *@This(),
                writer_template: *h2_server.ResponseWriter,
                connection_mutex: *Io.Mutex,
            ) void {
                assert(@intFromPtr(self) != 0);
                assert(@intFromPtr(writer_template) != 0);
                assert(@intFromPtr(connection_mutex) != 0);

                log.debug("h2 bridge: conn={d} start background tasks", .{self.connection_ctx.connection_id});
                self.writer_template = writer_template;
                self.connection_mutex = connection_mutex;
                self.upstream_reader_stop = false;
                if (self.upstream_reader_started) return;
                self.upstream_reader_group.concurrent(self.io, upstreamReaderTask, .{self}) catch |err| {
                    log.err(
                        "h2 bridge: conn={d} failed to start upstream reader task: {s}",
                        .{ self.connection_ctx.connection_id, @errorName(err) },
                    );
                    return;
                };
                self.upstream_reader_started = true;
                log.debug("h2 bridge: conn={d} started upstream reader task", .{self.connection_ctx.connection_id});
            }

            pub fn stopH2BackgroundTasks(self: *@This()) void {
                assert(@intFromPtr(self) != 0);

                if (!self.upstream_reader_started) return;
                self.upstream_reader_stop = true;
                log.debug(
                    "h2 bridge: conn={d} cancel upstream reader group reason=stop_background_tasks",
                    .{self.connection_ctx.connection_id},
                );
                self.upstream_reader_group.cancel(self.io);
                self.upstream_reader_started = false;
            }

            fn notePendingReset(self: *@This(), downstream_stream_id: u32, error_code_raw: u32) void {
                assert(@intFromPtr(self) != 0);
                assert(downstream_stream_id > 0);

                var first_free_index: ?usize = null;
                var index: usize = 0;
                while (index < self.pending_resets.len) : (index += 1) {
                    const entry = self.pending_resets[index];
                    if (!entry.used) {
                        if (first_free_index == null) first_free_index = index;
                        continue;
                    }
                    if (entry.downstream_stream_id == downstream_stream_id) {
                        self.pending_resets[index].error_code_raw = error_code_raw;
                        return;
                    }
                }

                if (first_free_index) |slot_index| {
                    self.pending_resets[slot_index] = .{
                        .used = true,
                        .downstream_stream_id = downstream_stream_id,
                        .error_code_raw = error_code_raw,
                    };
                    return;
                }

                const capacity_u32: u32 = @intCast(self.pending_resets.len);
                assert(capacity_u32 > 0);
                const fallback_slot: usize = @intCast(downstream_stream_id % capacity_u32);
                self.pending_resets[fallback_slot] = .{
                    .used = true,
                    .downstream_stream_id = downstream_stream_id,
                    .error_code_raw = error_code_raw,
                };
            }

            fn takePendingReset(self: *@This(), downstream_stream_id: u32) ?u32 {
                assert(@intFromPtr(self) != 0);
                assert(downstream_stream_id > 0);

                var index: usize = 0;
                while (index < self.pending_resets.len) : (index += 1) {
                    const entry = self.pending_resets[index];
                    if (!entry.used) continue;
                    if (entry.downstream_stream_id != downstream_stream_id) continue;

                    self.pending_resets[index] = .{};
                    return entry.error_code_raw;
                }

                return null;
            }

            pub fn handleH2Headers(
                self: *@This(),
                stream_id: u32,
                request: *const Request,
                end_stream: bool,
                _: *h2_server.ResponseWriter,
            ) BridgeError!void {
                assert(@intFromPtr(self) != 0);
                assert(stream_id > 0);

                if (self.takePendingReset(stream_id)) |error_code_raw| {
                    _ = error_code_raw;
                    return error.UpstreamConnectionClosing;
                }

                const expects_grpc_completion = self.grpc_completion_policy.isGrpcRequest(request);

                const upstream = try self.selectUpstream(request);
                if (!supportsBridgeUpstreamProtocol(upstream)) return error.UnsupportedProtocol;
                log.debug(
                    "h2 bridge: conn={d} open downstream_stream={d} path={s} upstream={s}:{d} tls={any} proto={s} end_stream={any}",
                    .{
                        self.connection_ctx.connection_id,
                        stream_id,
                        request.path,
                        upstream.host,
                        upstream.port,
                        upstream.tls,
                        @tagName(upstream.http_protocol),
                        end_stream,
                    },
                );

                self.bridge_mutex.lockUncancelable(self.io);
                defer self.bridge_mutex.unlock(self.io);

                const opened = try self.bridge.openDownstreamStream(
                    self.io,
                    upstream,
                    stream_id,
                    request,
                    null,
                    end_stream,
                );
                self.connection_reused = self.connection_reused or opened.connect.reused;
                self.dns_duration_ns +|= opened.connect.dns_duration_ns;
                self.tcp_connect_duration_ns +|= opened.connect.tcp_connect_duration_ns;
                if (self.upstream_local_port == 0 and opened.connect.local_port > 0) {
                    self.upstream_local_port = opened.connect.local_port;
                }
                log.debug(
                    "h2 bridge: conn={d} opened downstream_stream={d} reused={any} dns_ns={d} tcp_ns={d} local_port={d}",
                    .{
                        self.connection_ctx.connection_id,
                        stream_id,
                        opened.connect.reused,
                        opened.connect.dns_duration_ns,
                        opened.connect.tcp_connect_duration_ns,
                        opened.connect.local_port,
                    },
                );

                if (expects_grpc_completion) {
                    try self.grpc_completion_policy.trackStream(stream_id);
                } else {
                    self.grpc_completion_policy.untrackStream(stream_id);
                }
            }

            pub fn handleH2Data(
                self: *@This(),
                stream_id: u32,
                payload: []const u8,
                end_stream: bool,
                writer: *h2_server.ResponseWriter,
            ) BridgeError!void {
                assert(@intFromPtr(self) != 0);
                assert(stream_id > 0);
                _ = writer;

                if (self.takePendingReset(stream_id)) |error_code_raw| {
                    _ = error_code_raw;
                    return error.UpstreamConnectionClosing;
                }

                self.bridge_mutex.lockUncancelable(self.io);
                defer self.bridge_mutex.unlock(self.io);
                _ = self.bridge.bindingForDownstream(stream_id) orelse return error.MissingBinding;
                log.debug(
                    "h2 bridge: conn={d} downstream data stream={d} bytes={d} end_stream={any}",
                    .{ self.connection_ctx.connection_id, stream_id, payload.len, end_stream },
                );
                try self.bridge.sendDownstreamData(stream_id, payload, end_stream);
            }

            pub fn handleH2StreamReset(self: *@This(), stream_id: u32, error_code_raw: u32) void {
                assert(@intFromPtr(self) != 0);
                if (stream_id == 0) return;

                _ = self.takePendingReset(stream_id);
                self.grpc_completion_policy.untrackStream(stream_id);
                self.bridge_mutex.lockUncancelable(self.io);
                defer self.bridge_mutex.unlock(self.io);
                self.bridge.cancelDownstreamStream(stream_id, error_code_raw) catch |err| switch (err) {
                    error.BindingNotFound,
                    error.StreamNotFound,
                    error.SessionNotFound,
                    => {},
                    else => {},
                };
            }

            fn selectUpstream(self: *@This(), request: *const Request) BridgeError!types.Upstream {
                assert(@intFromPtr(self) != 0);
                assert(@intFromPtr(request) != 0);

                var stream_ctx = Context.init();
                stream_ctx.connection_id = self.connection_ctx.connection_id;
                stream_ctx.connection_start_ns = self.connection_ctx.connection_start_ns;
                stream_ctx.client_addr = self.connection_ctx.client_addr;
                stream_ctx.client_port = self.connection_ctx.client_port;
                stream_ctx.start_time_ns = self.connection_ctx.start_time_ns;

                const action_result = self.inner.selectUpstream(&stream_ctx, request);
                if (comptime hooks.hasUpstreamAction(Handler)) {
                    return switch (action_result) {
                        .forward => |upstream| upstream,
                        .reject => error.UpstreamRejected,
                    };
                }

                return action_result;
            }

            fn emitResponseHeaders(
                self: *@This(),
                action: serval_proxy.h2.bridge.ResponseHeadersAction,
                writer_template: *h2_server.ResponseWriter,
            ) BridgeError!void {
                assert(@intFromPtr(self) != 0);
                assert(action.downstream_stream_id > 0);

                const requires_grpc_completion = self.grpc_completion_policy.isTrackedStream(action.downstream_stream_id);
                if (action.end_stream) {
                    defer self.grpc_completion_policy.untrackStream(action.downstream_stream_id);
                    if (requires_grpc_completion) {
                        try mapGrpcStatusValidationError(serval_grpc.requireGrpcStatus(&action.response.headers));
                    }
                }
                log.debug(
                    "h2 bridge: conn={d} response headers stream={d} end_stream={any} status={d}",
                    .{
                        self.connection_ctx.connection_id,
                        action.downstream_stream_id,
                        action.end_stream,
                        action.response.status,
                    },
                );

                var writer = streamWriterFor(writer_template, action.downstream_stream_id);
                var headers_buf: [config.MAX_HEADERS]h2_server.Header = undefined;
                const source_headers = action.response.headers.headers[0..action.response.headers.count];
                const h2_headers = copyHeaders(source_headers, &headers_buf);
                try writer.sendHeaders(action.response.status, h2_headers, action.end_stream);
                self.response_status = action.response.status;
            }

            fn emitResponseData(
                self: *@This(),
                action: serval_proxy.h2.bridge.ResponseDataAction,
                writer_template: *h2_server.ResponseWriter,
            ) BridgeError!void {
                assert(@intFromPtr(self) != 0);
                assert(action.downstream_stream_id > 0);

                if (action.end_stream) {
                    defer self.grpc_completion_policy.untrackStream(action.downstream_stream_id);
                }

                log.debug(
                    "h2 bridge: conn={d} response data stream={d} end_stream={any} bytes={d}",
                    .{
                        self.connection_ctx.connection_id,
                        action.downstream_stream_id,
                        action.end_stream,
                        action.payload.len,
                    },
                );
                var writer = streamWriterFor(writer_template, action.downstream_stream_id);
                try writer.sendData(action.payload, action.end_stream);
                self.response_bytes +|= action.payload.len;
            }

            fn emitResponseTrailers(
                self: *@This(),
                action: serval_proxy.h2.bridge.ResponseTrailersAction,
                writer_template: *h2_server.ResponseWriter,
            ) BridgeError!void {
                assert(@intFromPtr(self) != 0);
                assert(action.downstream_stream_id > 0);

                const requires_grpc_completion = self.grpc_completion_policy.isTrackedStream(action.downstream_stream_id);
                defer self.grpc_completion_policy.untrackStream(action.downstream_stream_id);

                log.debug(
                    "h2 bridge: conn={d} response trailers stream={d} trailer_count={d} grpc_status_present={any} grpc_status_value={s} grpc_expected={any}",
                    .{
                        self.connection_ctx.connection_id,
                        action.downstream_stream_id,
                        action.trailers.count,
                        action.trailers.get("grpc-status") != null,
                        action.trailers.get("grpc-status") orelse "<missing>",
                        requires_grpc_completion,
                    },
                );
                if (requires_grpc_completion) {
                    try mapGrpcStatusValidationError(serval_grpc.requireGrpcStatus(&action.trailers));
                }

                var writer = streamWriterFor(writer_template, action.downstream_stream_id);
                var trailers_buf: [config.MAX_HEADERS]h2_server.Header = undefined;
                const source_trailers = action.trailers.headers[0..action.trailers.count];
                const h2_trailers = copyHeaders(source_trailers, &trailers_buf);
                try writer.sendTrailers(h2_trailers);
            }

            fn emitDownstreamReset(
                self: *@This(),
                downstream_stream_id: u32,
                error_code_raw: u32,
                writer_template: *h2_server.ResponseWriter,
            ) BridgeError!void {
                assert(@intFromPtr(self) != 0);
                assert(downstream_stream_id > 0);

                log.debug(
                    "h2 bridge: conn={d} emit downstream reset stream={d} error_code=0x{x}",
                    .{ self.connection_ctx.connection_id, downstream_stream_id, error_code_raw },
                );
                var writer = streamWriterFor(writer_template, downstream_stream_id);
                try writer.sendReset(error_code_raw);
            }

            fn mapGrpcStatusValidationError(result: serval_grpc.MetadataError!void) BridgeError!void {
                result catch |err| switch (err) {
                    error.MissingGrpcStatus => return error.MissingGrpcStatus,
                    error.InvalidGrpcStatusFormat,
                    error.InvalidGrpcStatusRange,
                    => return error.InvalidGrpcStatus,
                    else => unreachable,
                };
            }

            fn supportsBridgeUpstreamProtocol(upstream: types.Upstream) bool {
                const supports_h2c_plain = upstream.http_protocol == .h2c and !upstream.tls;
                const supports_h2_tls = upstream.http_protocol == .h2 and upstream.tls;
                return supports_h2c_plain or supports_h2_tls;
            }

            fn streamWriterFor(template: *h2_server.ResponseWriter, stream_id: u32) h2_server.ResponseWriter {
                assert(@intFromPtr(template) != 0);
                assert(stream_id > 0);

                var writer = template.*;
                writer.stream_id = stream_id;
                return writer;
            }

            fn copyHeaders(
                source: []const types.Header,
                out: *[config.MAX_HEADERS]h2_server.Header,
            ) []const h2_server.Header {
                assert(source.len <= config.MAX_HEADERS);

                var index: usize = 0;
                while (index < source.len) : (index += 1) {
                    out[index] = .{
                        .name = source[index].name,
                        .value = source[index].value,
                    };
                }

                return out[0..source.len];
            }

            fn upstreamReaderTask(self: *@This()) Io.Cancelable!void {
                assert(@intFromPtr(self) != 0);
                while (!self.upstream_reader_stop) {
                    try std.Io.checkCancel(self.io);

                    const action = self.receiveAnyUpstreamAction() catch |err| switch (err) {
                        error.BindingNotFound,
                        error.SessionNotFound,
                        error.WouldBlock,
                        => {
                            try std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(upstream_reader_idle_ms), .awake);
                            continue;
                        },
                        error.ConnectionClosed,
                        error.ConnectionClosing,
                        error.ReadFailed,
                        error.WriteFailed,
                        => {
                            try std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(upstream_reader_idle_ms), .awake);
                            continue;
                        },
                        else => {
                            try std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(upstream_reader_idle_ms), .awake);
                            continue;
                        },
                    };

                    self.dispatchUpstreamAction(action);
                }
            }

            fn receiveAnyUpstreamAction(self: *@This()) BridgeError!serval_proxy.h2.bridge.ReceiveAction {
                assert(@intFromPtr(self) != 0);

                self.bridge_mutex.lockUncancelable(self.io);
                defer self.bridge_mutex.unlock(self.io);

                const timeout: Io.Timeout = .{ .duration = .{
                    .raw = Io.Duration.fromMilliseconds(upstream_read_timeout_ms),
                    .clock = .awake,
                } };

                return self.bridge.pollNextAction(self.io, timeout);
            }

            fn dispatchUpstreamAction(self: *@This(), action: serval_proxy.h2.bridge.ReceiveAction) void {
                assert(@intFromPtr(self) != 0);

                const connection_mutex = self.connection_mutex orelse return;
                const writer_template = self.writer_template orelse return;

                connection_mutex.lockUncancelable(self.io);
                defer connection_mutex.unlock(self.io);
                log.debug(
                    "h2 bridge: conn={d} dispatch upstream action={s}",
                    .{ self.connection_ctx.connection_id, @tagName(action) },
                );

                switch (action) {
                    .none => {},
                    .response_headers => |headers| {
                        self.emitResponseHeaders(headers, writer_template) catch |err| switch (err) {
                            error.UpstreamConnectionClosing,
                            error.ConnectionClosing,
                            error.ConnectionClosed,
                            error.ReadFailed,
                            error.WriteFailed,
                            error.FrameLimitExceeded,
                            error.MissingGrpcStatus,
                            error.InvalidGrpcStatus,
                            => {
                                log.debug(
                                    "h2 bridge: conn={d} response headers failed stream={d} err={s}",
                                    .{
                                        self.connection_ctx.connection_id,
                                        headers.downstream_stream_id,
                                        @errorName(err),
                                    },
                                );
                                switch (err) {
                                    error.UpstreamConnectionClosing,
                                    error.ConnectionClosing,
                                    error.ConnectionClosed,
                                    error.ReadFailed,
                                    error.WriteFailed,
                                    error.FrameLimitExceeded,
                                    => self.emitOrNotePendingReset(headers.downstream_stream_id, @intFromEnum(serval_h2.ErrorCode.cancel), writer_template),
                                    error.MissingGrpcStatus,
                                    error.InvalidGrpcStatus,
                                    => self.emitOrNotePendingReset(headers.downstream_stream_id, @intFromEnum(serval_h2.ErrorCode.protocol_error), writer_template),
                                    else => unreachable,
                                }
                            },
                            else => {
                                log.debug(
                                    "h2 bridge: conn={d} response headers failed stream={d} err={s}",
                                    .{
                                        self.connection_ctx.connection_id,
                                        headers.downstream_stream_id,
                                        @errorName(err),
                                    },
                                );
                                self.emitOrNotePendingReset(headers.downstream_stream_id, @intFromEnum(serval_h2.ErrorCode.internal_error), writer_template);
                            },
                        };
                    },
                    .response_data => |data| {
                        self.emitResponseData(data, writer_template) catch |err| switch (err) {
                            error.UpstreamConnectionClosing,
                            error.ConnectionClosing,
                            error.ConnectionClosed,
                            error.ReadFailed,
                            error.WriteFailed,
                            error.FrameLimitExceeded,
                            => {
                                log.debug(
                                    "h2 bridge: conn={d} response data failed stream={d} err={s}",
                                    .{
                                        self.connection_ctx.connection_id,
                                        data.downstream_stream_id,
                                        @errorName(err),
                                    },
                                );
                                self.emitOrNotePendingReset(data.downstream_stream_id, @intFromEnum(serval_h2.ErrorCode.cancel), writer_template);
                            },
                            else => {
                                log.debug(
                                    "h2 bridge: conn={d} response data failed stream={d} err={s}",
                                    .{
                                        self.connection_ctx.connection_id,
                                        data.downstream_stream_id,
                                        @errorName(err),
                                    },
                                );
                                self.emitOrNotePendingReset(data.downstream_stream_id, @intFromEnum(serval_h2.ErrorCode.internal_error), writer_template);
                            },
                        };
                    },
                    .response_trailers => |trailers| {
                        self.emitResponseTrailers(trailers, writer_template) catch |err| switch (err) {
                            error.MissingGrpcStatus,
                            error.InvalidGrpcStatus,
                            => {
                                log.debug(
                                    "h2 bridge: conn={d} response trailers failed stream={d} err={s}",
                                    .{
                                        self.connection_ctx.connection_id,
                                        trailers.downstream_stream_id,
                                        @errorName(err),
                                    },
                                );
                                self.emitOrNotePendingReset(trailers.downstream_stream_id, @intFromEnum(serval_h2.ErrorCode.protocol_error), writer_template);
                            },
                            else => {
                                log.debug(
                                    "h2 bridge: conn={d} response trailers failed stream={d} err={s}",
                                    .{
                                        self.connection_ctx.connection_id,
                                        trailers.downstream_stream_id,
                                        @errorName(err),
                                    },
                                );
                                self.emitOrNotePendingReset(trailers.downstream_stream_id, @intFromEnum(serval_h2.ErrorCode.internal_error), writer_template);
                            },
                        };
                    },
                    .stream_reset => |reset| {
                        self.emitOrNotePendingReset(reset.downstream_stream_id, reset.error_code_raw, writer_template);
                    },
                    .connection_close => |close| {
                        self.handleUpstreamConnectionClose(close, writer_template);
                    },
                }
            }

            fn emitOrNotePendingReset(
                self: *@This(),
                downstream_stream_id: u32,
                error_code_raw: u32,
                writer_template: *h2_server.ResponseWriter,
            ) void {
                assert(@intFromPtr(self) != 0);
                assert(downstream_stream_id > 0);
                assert(@intFromPtr(writer_template) != 0);

                self.grpc_completion_policy.untrackStream(downstream_stream_id);
                self.emitDownstreamReset(downstream_stream_id, error_code_raw, writer_template) catch {
                    log.debug(
                        "h2 bridge: conn={d} defer downstream reset stream={d} error_code=0x{x}",
                        .{ self.connection_ctx.connection_id, downstream_stream_id, error_code_raw },
                    );
                    self.notePendingReset(downstream_stream_id, error_code_raw);
                };
            }

            fn handleUpstreamConnectionClose(
                self: *@This(),
                close: serval_proxy.h2.bridge.ConnectionCloseAction,
                writer_template: *h2_server.ResponseWriter,
            ) void {
                assert(@intFromPtr(self) != 0);

                var downstream_ids: [config.H2_MAX_CONCURRENT_STREAMS]u32 = [_]u32{0} ** config.H2_MAX_CONCURRENT_STREAMS;
                var downstream_count: u16 = 0;

                {
                    self.bridge_mutex.lockUncancelable(self.io);
                    defer self.bridge_mutex.unlock(self.io);

                    downstream_count = self.bridge.takeAffectedDownstreamsForConnectionClose(close, downstream_ids[0..]);
                }

                const reset_error_code_raw: u32 = if (close.goaway.error_code_raw == @intFromEnum(serval_h2.ErrorCode.no_error))
                    @intFromEnum(serval_h2.ErrorCode.cancel)
                else
                    close.goaway.error_code_raw;

                log.debug(
                    "h2 bridge: conn={d} upstream close last_stream_id={d} error_code=0x{x} affected_streams={d}",
                    .{
                        self.connection_ctx.connection_id,
                        close.goaway.last_stream_id,
                        close.goaway.error_code_raw,
                        downstream_count,
                    },
                );

                var emit_index: u16 = 0;
                while (emit_index < downstream_count) : (emit_index += 1) {
                    const downstream_stream_id = downstream_ids[emit_index];
                    self.grpc_completion_policy.untrackStream(downstream_stream_id);
                    self.emitDownstreamReset(downstream_stream_id, reset_error_code_raw, writer_template) catch {
                        self.notePendingReset(downstream_stream_id, reset_error_code_raw);
                    };
                }
            }
        };

        fn forwardH2cWithBridge(
            handler: *Handler,
            forwarder: *forwarder_mod.Forwarder(Pool, Tracer),
            io: Io,
            stream: Io.net.Stream,
            ctx: *Context,
            initial_client_bytes: []const u8,
            connection_id: u64,
            local_settings_already_sent: bool,
        ) forwarder_mod.ForwardError!forwarder_mod.ForwardResult {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(forwarder) != 0);
            assert(@intFromPtr(ctx) != 0);
            assert(initial_client_bytes.len > 0);

            var bridge_client = serval_client.Client.init(
                std.heap.page_allocator,
                &forwarder.dns_resolver,
                forwarder.client_ctx,
                forwarder.verify_upstream_tls,
            );
            const bridge_sessions = std.heap.page_allocator.create(serval_client.H2UpstreamSessionPool) catch {
                return forwarder_mod.ForwardError.ConnectFailed;
            };
            bridge_sessions.* = serval_client.H2UpstreamSessionPool.init();
            defer {
                bridge_sessions.deinit();
                std.heap.page_allocator.destroy(bridge_sessions);
            }

            var bridge_handler = H2cBridgeHandler.init(
                handler,
                io,
                &bridge_client,
                bridge_sessions,
                ctx,
            );
            defer bridge_handler.deinit();

            const start_ns = time.monotonicNanos();
            h2_server.servePlainConnectionWithInitialBytesOptions(
                H2cBridgeHandler,
                &bridge_handler,
                @intCast(stream.socket.handle),
                io,
                connection_id,
                initial_client_bytes,
                .{ .local_settings_already_sent = local_settings_already_sent },
            ) catch |err| {
                log.warn("server: conn={d} grpc h2 bridge driver failed: {s}", .{
                    connection_id,
                    @errorName(err),
                });
                switch (err) {
                    error.ConnectionClosed => {},
                    error.ReadFailed => return forwarder_mod.ForwardError.RecvFailed,
                    error.WriteFailed => return forwarder_mod.ForwardError.SendFailed,
                    else => return forwarder_mod.ForwardError.InvalidResponse,
                }
            };
            const end_ns = time.monotonicNanos();

            return .{
                .status = bridge_handler.response_status,
                .response_bytes = bridge_handler.response_bytes,
                .connection_reused = bridge_handler.connection_reused,
                .dns_duration_ns = bridge_handler.dns_duration_ns,
                .tcp_connect_duration_ns = bridge_handler.tcp_connect_duration_ns,
                .send_duration_ns = 0,
                .recv_duration_ns = time.elapsedNanos(start_ns, end_ns),
                .pool_wait_ns = 0,
                .upstream_local_port = bridge_handler.upstream_local_port,
            };
        }

        fn forwardH2cUpgradeWithBridge(
            handler: *Handler,
            forwarder: *forwarder_mod.Forwarder(Pool, Tracer),
            io: Io,
            maybe_tls: ?*const TLSStream,
            stream: Io.net.Stream,
            parser: *const Parser,
            recv_buf: []const u8,
            buffer_offset: usize,
            buffer_len: usize,
            settings_payload: []const u8,
            ctx: *Context,
            connection_id: u64,
        ) forwarder_mod.ForwardError!forwarder_mod.ForwardResult {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(forwarder) != 0);
            assert(@intFromPtr(parser) != 0);
            assert(@intFromPtr(ctx) != 0);
            assert(buffer_offset <= buffer_len);
            assert(settings_payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);

            if (maybe_tls != null) return forwarder_mod.ForwardError.UnsupportedProtocol;

            const body_info = buildBodyInfo(parser, recv_buf, buffer_offset, buffer_len);
            const content_length = body_info.getContentLength() orelse 0;
            assert(body_info.bytes_already_read <= content_length);
            const remaining_body_bytes = content_length - body_info.bytes_already_read;

            const initial_h2_offset = buffer_offset + parser.headers_end + @as(usize, @intCast(body_info.bytes_already_read));
            assert(initial_h2_offset <= buffer_len);
            const initial_client_h2_bytes = recv_buf[initial_h2_offset..buffer_len];

            var io_mut = io;
            connectionWrite(maybe_tls, &io_mut, stream, serval_h2.h2c_upgrade_response) catch {
                return forwarder_mod.ForwardError.SendFailed;
            };

            var bridge_client = serval_client.Client.init(
                std.heap.page_allocator,
                &forwarder.dns_resolver,
                forwarder.client_ctx,
                forwarder.verify_upstream_tls,
            );
            const bridge_sessions = std.heap.page_allocator.create(serval_client.H2UpstreamSessionPool) catch {
                return forwarder_mod.ForwardError.ConnectFailed;
            };
            bridge_sessions.* = serval_client.H2UpstreamSessionPool.init();
            defer {
                bridge_sessions.deinit();
                std.heap.page_allocator.destroy(bridge_sessions);
            }

            var bridge_handler = H2cBridgeHandler.init(
                handler,
                io,
                &bridge_client,
                bridge_sessions,
                ctx,
            );
            defer bridge_handler.deinit();

            const start_ns = time.monotonicNanos();
            h2_server.serveUpgradedConnection(
                H2cBridgeHandler,
                &bridge_handler,
                @intCast(stream.socket.handle),
                io,
                connection_id,
                &parser.request,
                settings_payload,
                body_info.initial_body,
                remaining_body_bytes,
                initial_client_h2_bytes,
            ) catch |err| switch (err) {
                error.ConnectionClosed => {},
                error.ReadFailed => return forwarder_mod.ForwardError.RecvFailed,
                error.WriteFailed => return forwarder_mod.ForwardError.SendFailed,
                else => return forwarder_mod.ForwardError.InvalidResponse,
            };
            const end_ns = time.monotonicNanos();

            return .{
                .status = 101,
                .response_bytes = @as(u64, @intCast(serval_h2.h2c_upgrade_response.len)) + bridge_handler.response_bytes,
                .connection_reused = bridge_handler.connection_reused,
                .dns_duration_ns = bridge_handler.dns_duration_ns,
                .tcp_connect_duration_ns = bridge_handler.tcp_connect_duration_ns,
                .send_duration_ns = 0,
                .recv_duration_ns = time.elapsedNanos(start_ns, end_ns),
                .pool_wait_ns = 0,
                .upstream_local_port = bridge_handler.upstream_local_port,
            };
        }

        fn tryHandleTerminatedH2TlsAlpn(
            handler: *Handler,
            metrics: *Metrics,
            tracer: *Tracer,
            ctx: *const Context,
            maybe_tls: ?*TLSStream,
            io: Io,
            connection_id: u64,
            frontend_mode: config.TlsH2FrontendMode,
        ) bool {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(metrics) != 0);
            assert(@intFromPtr(tracer) != 0);
            assert(@intFromPtr(ctx) != 0);

            if (frontend_mode == .disabled) return false;

            const tls_stream = maybe_tls orelse return false;
            if (comptime !@hasDecl(Handler, "handleH2Headers")) return false;
            if (comptime !@hasDecl(Handler, "handleH2Data")) return false;

            const alpn = tls_stream.info.alpn() orelse return false;
            if (!std.mem.eql(u8, alpn, "h2")) return false;

            log.debug("server: conn={d} dispatching ALPN h2 to terminated h2 driver", .{connection_id});

            var telemetry_handler = TerminatedH2TelemetryAdapter.init(
                handler,
                metrics,
                tracer,
                ctx,
                null,
                true,
            );
            h2_server.serveTlsConnection(
                @TypeOf(telemetry_handler),
                &telemetry_handler,
                tls_stream,
                io,
                connection_id,
            ) catch |err| switch (err) {
                error.ConnectionClosed => {},
                else => log.warn("server: conn={d} terminated TLS h2 driver failed: {s}", .{ connection_id, @errorName(err) }),
            };
            return true;
        }

        fn tryHandleTerminatedH2PriorKnowledge(
            handler: *Handler,
            metrics: *Metrics,
            tracer: *Tracer,
            ctx: *const Context,
            maybe_tls: ?*const TLSStream,
            io: Io,
            stream: Io.net.Stream,
            plain_reader: ?*Io.net.Stream.Reader,
            recv_buf: []u8,
            buffer_len: *usize,
            connection_id: u64,
        ) bool {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(metrics) != 0);
            assert(@intFromPtr(tracer) != 0);
            assert(@intFromPtr(ctx) != 0);
            assert(recv_buf.len >= H2C_INITIAL_READ_BUFFER_SIZE_BYTES);

            if (maybe_tls != null) return false;
            if (buffer_len.* == 0) return false;
            if (comptime !@hasDecl(Handler, "handleH2Headers")) return false;
            if (comptime !@hasDecl(Handler, "handleH2Data")) return false;

            const initial_bytes = recv_buf[0..buffer_len.*];
            const looks_h2_prefix = serval_h2.looksLikeClientConnectionPrefacePrefix(initial_bytes);
            const looks_h2_attempt = std.mem.startsWith(u8, initial_bytes, "PRI");
            if (!looks_h2_prefix and !looks_h2_attempt) return false;
            var handoff_buf: [CONNECTION_RECV_BUFFER_SIZE_BYTES + PLAIN_STREAM_READER_BUFFER_SIZE_BYTES]u8 = undefined;
            const handoff_bytes = buildH2HandoffBytes(plain_reader, recv_buf[0..buffer_len.*], &handoff_buf);

            log.debug("server: conn={d} dispatching prior-knowledge h2c to terminated h2 driver", .{connection_id});

            var telemetry_handler = TerminatedH2TelemetryAdapter.init(
                handler,
                metrics,
                tracer,
                ctx,
                null,
                true,
            );
            h2_server.servePlainConnectionWithInitialBytes(
                @TypeOf(telemetry_handler),
                &telemetry_handler,
                @intCast(stream.socket.handle),
                io,
                connection_id,
                handoff_bytes,
            ) catch |err| switch (err) {
                error.ConnectionClosed => {},
                else => log.warn("server: conn={d} terminated h2 driver failed: {s}", .{ connection_id, @errorName(err) }),
            };
            return true;
        }

        fn tryHandleTerminatedH2Upgrade(
            handler: *Handler,
            metrics: *Metrics,
            tracer: *Tracer,
            maybe_tls: ?*const TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            ctx: *Context,
            parser: *const Parser,
            recv_buf: []const u8,
            buffer_offset: usize,
            buffer_len: usize,
            connection_id: u64,
            settings_payload: []const u8,
            span_handle: SpanHandle,
        ) bool {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(metrics) != 0);
            assert(@intFromPtr(tracer) != 0);
            assert(@intFromPtr(ctx) != 0);
            assert(@intFromPtr(parser) != 0);
            assert(buffer_offset <= buffer_len);
            assert(settings_payload.len <= config.H2_MAX_FRAME_SIZE_BYTES);

            if (maybe_tls != null) return false;
            if (comptime !@hasDecl(Handler, "handleH2Headers")) return false;
            if (comptime !@hasDecl(Handler, "handleH2Data")) return false;

            const body_info = buildBodyInfo(parser, recv_buf, buffer_offset, buffer_len);
            const content_length = body_info.getContentLength() orelse 0;
            assert(body_info.bytes_already_read <= content_length);
            const remaining_body_bytes = content_length - body_info.bytes_already_read;

            const initial_h2_offset = buffer_offset + parser.headers_end + @as(usize, @intCast(body_info.bytes_already_read));
            assert(initial_h2_offset <= buffer_len);
            const initial_client_h2_bytes = recv_buf[initial_h2_offset..buffer_len];

            connectionWrite(maybe_tls, io, stream, serval_h2.h2c_upgrade_response) catch |err| {
                log.warn("server: conn={d} failed to send terminated h2 upgrade response: {s}", .{ connection_id, @errorName(err) });
                const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                ctx.duration_ns = duration_ns;
                handleTerminatedH2UpgradeCompleteImpl(
                    handler,
                    metrics,
                    ctx,
                    &parser.request,
                    500,
                    0,
                    duration_ns,
                    @errorName(err),
                );
                tracer.setIntAttribute(span_handle, "http.response.status_code", 500);
                tracer.endSpan(span_handle, @errorName(err));
                return true;
            };

            var h2_error_name: ?[]const u8 = null;
            const parent_span: ?SpanHandle = if (span_handle.isValid()) span_handle else null;
            var telemetry_handler = TerminatedH2TelemetryAdapter.init(
                handler,
                metrics,
                tracer,
                ctx,
                parent_span,
                true,
            );
            h2_server.serveUpgradedConnection(
                @TypeOf(telemetry_handler),
                &telemetry_handler,
                @intCast(stream.socket.handle),
                io.*,
                connection_id,
                &parser.request,
                settings_payload,
                body_info.initial_body,
                remaining_body_bytes,
                initial_client_h2_bytes,
            ) catch |err| switch (err) {
                error.ConnectionClosed => {},
                else => {
                    h2_error_name = @errorName(err);
                    log.warn("server: conn={d} terminated h2 upgrade driver failed: {s}", .{ connection_id, @errorName(err) });
                },
            };

            const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
            ctx.duration_ns = duration_ns;
            handleTerminatedH2UpgradeCompleteImpl(
                handler,
                metrics,
                ctx,
                &parser.request,
                101,
                serval_h2.h2c_upgrade_response.len,
                duration_ns,
                h2_error_name,
            );
            tracer.setIntAttribute(span_handle, "http.response.status_code", 101);
            tracer.endSpan(span_handle, h2_error_name);
            return true;
        }

        fn tryHandleH2cPriorKnowledge(
            handler: *Handler,
            forwarder: *forwarder_mod.Forwarder(Pool, Tracer),
            metrics: *Metrics,
            tracer: *Tracer,
            maybe_tls: ?*TLSStream,
            io: *Io,
            stream: Io.net.Stream,
            plain_reader: ?*Io.net.Stream.Reader,
            ctx: *Context,
            recv_buf: []u8,
            buffer_len: *usize,
            connection_id: u64,
        ) bool {
            assert(recv_buf.len >= H2C_INITIAL_READ_BUFFER_SIZE_BYTES);

            if (buffer_len.* == 0) return false;
            if (!serval_h2.looksLikeClientConnectionPrefacePrefix(recv_buf[0..buffer_len.*])) return false;
            log.debug(
                "server: conn={d} detected grpc prior-knowledge preface bytes={d} tls_frontend={}",
                .{ connection_id, buffer_len.*, maybe_tls != null },
            );

            const parse_start_ns = realtimeNanos();
            var parsed: serval_h2.InitialRequest = undefined;
            var initial_request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;
            var local_settings_already_sent = false;
            while (true) {
                parsed = serval_h2.parseInitialRequest(
                    recv_buf[0..buffer_len.*],
                    &initial_request_storage_buf,
                ) catch |err| switch (err) {
                    error.NeedMoreData => {
                        if (!local_settings_already_sent and
                            buffer_len.* >= serval_h2.client_connection_preface.len and
                            serval_h2.looksLikeClientConnectionPreface(recv_buf[0..buffer_len.*]))
                        {
                            if (!sendH2InitialSettings(maybe_tls, io, stream)) {
                                sendH2GoAway(maybe_tls, io, stream, 0, H2_ERROR_INTERNAL);
                                return true;
                            }
                            local_settings_already_sent = true;
                        }

                        if (buffer_len.* >= recv_buf.len) {
                            sendH2GoAway(maybe_tls, io, stream, 0, H2_ERROR_PROTOCOL);
                            return true;
                        }
                        const n = connectionRead(maybe_tls, io, stream, plain_reader, recv_buf[buffer_len.*..], connection_id) orelse return true;
                        buffer_len.* += n;
                        continue;
                    },
                    else => {
                        log.warn("server: conn={d} invalid h2c preface/request: {s}", .{ connection_id, @errorName(err) });
                        sendH2GoAway(maybe_tls, io, stream, 0, H2_ERROR_PROTOCOL);
                        return true;
                    },
                };
                break;
            }
            ctx.parse_duration_ns = @intCast(@max(0, realtimeNanos() - parse_start_ns));

            const request_is_grpc = serval_grpc.classifyRequest(&parsed.request) == .grpc;
            if (!request_is_grpc) {
                log.debug(
                    "server: conn={d} prior-knowledge stream={d} classified as non-gRPC; bridge completion uses generic semantics",
                    .{ connection_id, parsed.stream_id },
                );
            }

            metrics.requestStart();
            ctx.bytes_received = @intCast(buffer_len.*);

            var span_name_buf: [config.OTEL_MAX_NAME_LEN]u8 = std.mem.zeroes([config.OTEL_MAX_NAME_LEN]u8);
            const span_name = buildSpanName(parsed.request.method, parsed.request.path, &span_name_buf);
            const span_handle = tracer.startSpan(span_name, null);
            ctx.span_handle = span_handle;
            tracer.setStringAttribute(span_handle, "http.request.method", @tagName(parsed.request.method));
            tracer.setStringAttribute(span_handle, "url.path", parsed.request.path);

            const action_result = handler.selectUpstream(ctx, &parsed.request);
            const upstream: types.Upstream = blk: {
                if (comptime hooks.hasUpstreamAction(Handler)) {
                    switch (action_result) {
                        .forward => |up| break :blk up,
                        .reject => |rej| {
                            const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                            metrics.requestEnd(rej.status, duration_ns);
                            sendH2GoAway(maybe_tls, io, stream, parsed.stream_id, H2_ERROR_PROTOCOL);
                            tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(rej.status));
                            tracer.endSpan(span_handle, "h2c_reject");
                            return true;
                        },
                    }
                } else {
                    break :blk action_result;
                }
            };
            ctx.upstream = upstream;

            const supports_h2c_plain = upstream.http_protocol == .h2c and !upstream.tls;
            const supports_h2_tls = upstream.http_protocol == .h2 and upstream.tls;

            // Stream-aware bridge is the steady-state path for supported h2 upstreams.
            // Keep plaintext-downstream guard: this entry point dispatches into the
            // plain-fd h2 server driver and cannot run over frontend TLS bytes.
            const use_stream_bridge = maybe_tls == null and (supports_h2c_plain or supports_h2_tls);

            const forward_result = if (use_stream_bridge)
                forwardH2cWithBridge(
                    handler,
                    forwarder,
                    io.*,
                    stream,
                    ctx,
                    blk: {
                        var handoff_buf: [CONNECTION_RECV_BUFFER_SIZE_BYTES + PLAIN_STREAM_READER_BUFFER_SIZE_BYTES]u8 = undefined;
                        break :blk buildH2HandoffBytes(plain_reader, recv_buf[0..buffer_len.*], &handoff_buf);
                    },
                    connection_id,
                    local_settings_already_sent,
                )
            else
                forwarder.forwardGrpcH2c(
                    io.*,
                    stream,
                    maybe_tls,
                    &parsed.request,
                    &upstream,
                    recv_buf[0..buffer_len.*],
                    span_handle,
                );
            const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
            ctx.duration_ns = duration_ns;

            if (forward_result) |result| {
                handleForwardSuccessImpl(handler, metrics, ctx, &parsed.request, result, duration_ns, false);
                tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(result.status));
                tracer.endSpan(span_handle, null);
            } else |err| {
                if (comptime hooks.hasHook(Handler, "onError")) {
                    const error_ctx = errors.ErrorContext{
                        .err = forwardErrorToRequestError(err),
                        .phase = forwardErrorToPhase(err),
                        .upstream = upstream,
                        .is_retry = false,
                    };
                    _ = handler.onError(ctx, &error_ctx);
                }
                metrics.requestEnd(502, duration_ns);
                sendH2GoAway(maybe_tls, io, stream, parsed.stream_id, H2_ERROR_INTERNAL);
                tracer.setIntAttribute(span_handle, "http.response.status_code", 502);
                tracer.endSpan(span_handle, @errorName(err));
            }
            return true;
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
            tls_ctx_manager: ?*ReloadableServerCtx,
            runtime_provider: ?RuntimeProvider,
            io: Io,
            stream: Io.net.Stream,
        ) void {
            // TigerStyle: Precondition assertions
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(forwarder) != 0);
            assert(@intFromPtr(metrics) != 0);
            assert(@intFromPtr(tracer) != 0);
            assert(cfg.max_requests_per_connection > 0);

            if (runtime_provider) |provider| {
                const generation = provider.activeGeneration();
                if (generation) |value| {
                    assert(value > 0);
                    log.debug("server: runtime_provider active_generation={d}", .{value});
                }
            }

            // Setup: TCP_NODELAY, connection ID, metrics
            _ = set_tcp_no_delay(stream.socket.handle);
            const connection_id = nextConnectionId();
            const connection_start_ns = realtimeNanos();
            defer stream.close(io);
            metrics.connectionOpened();
            defer metrics.connectionClosed();

            // TLS: Perform handshake if TLS is configured
            // TigerStyle: Blocking handshake - std.Io handles socket-level async
            // TLS span stays open for connection lifetime - request spans are children
            var tls_span: SpanHandle = .{};
            var maybe_tls_stream: ?TLSStream = if (tls_ctx_manager) |manager| blk: {
                const allocator = std.heap.c_allocator;
                const tls_ctx_lease = manager.acquire() catch |err| {
                    log.err("TLS context acquire failed: {s}", .{@errorName(err)});
                    return;
                };
                defer manager.release(tls_ctx_lease);

                // Start TLS handshake span (root for this connection's trace)
                tls_span = tracer.startSpan("tls.handshake.server", null);
                tracer.setIntAttribute(tls_span, "tls.ctx_generation", @intCast(tls_ctx_lease.generation));

                const tls_stream = TLSStream.initServer(
                    tls_ctx_lease.ctx,
                    @intCast(stream.socket.handle),
                    allocator,
                ) catch |err| {
                    tracer.endSpan(tls_span, @errorName(err));
                    log.err("TLS handshake failed: {s}", .{@errorName(err)});
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
                // Don't end span here - stays open for connection lifetime

                break :blk tls_stream;
            } else null;
            defer if (maybe_tls_stream) |*tls_stream| tls_stream.close();
            // End TLS span when connection closes
            defer if (tls_span.isValid()) tracer.endSpan(tls_span, null);

            // Initialize context with connection-scoped fields
            var ctx = Context.init();
            ctx.connection_id = connection_id;
            ctx.connection_start_ns = connection_start_ns;
            ctx.request_number = 0;
            set_client_endpoint_from_socket(&ctx, stream.socket.handle) catch |err| {
                const unknown_addr: []const u8 = "unknown";
                @memset(&ctx.client_addr, 0);
                @memcpy(ctx.client_addr[0..unknown_addr.len], unknown_addr);
                ctx.client_port = 0;
                log.warn(
                    "server: conn={d} client endpoint unavailable err={s}",
                    .{ connection_id, @errorName(err) },
                );
            };
            log.debug(
                "server: conn={d} client={s}:{d}",
                .{ connection_id, std.mem.sliceTo(&ctx.client_addr, 0), ctx.client_port },
            );

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
            var plain_reader_buf: [PLAIN_STREAM_READER_BUFFER_SIZE_BYTES]u8 = undefined;
            var plain_stream_reader = stream.reader(io_mut, &plain_reader_buf);
            const maybe_plain_reader: ?*Io.net.Stream.Reader = if (maybe_tls_ptr == null) &plain_stream_reader else null;

            const has_terminated_h2_handler = comptime @hasDecl(Handler, "handleH2Headers") and @hasDecl(Handler, "handleH2Data");
            switch (frontend.selectTlsAlpnDispatchAction(
                maybe_tls_ptr,
                cfg.tls_h2_frontend_mode,
                has_terminated_h2_handler,
            )) {
                .generic_h2 => {
                    if (cfg.tls_h2_frontend_mode != .generic) {
                        log.warn(
                            "server: conn={d} ALPN h2 generic frontend fallback active mode={s} has_terminated_h2_handler={} (protocol-safety override)",
                            .{ connection_id, @tagName(cfg.tls_h2_frontend_mode), has_terminated_h2_handler },
                        );
                    }

                    if (frontend.tryServeTlsAlpnConnection(
                        Handler,
                        Pool,
                        Tracer,
                        H2cBridgeHandler,
                        handler,
                        forwarder,
                        &ctx,
                        maybe_tls_ptr,
                        io,
                        connection_id,
                        cfg.tls_h2_frontend_mode,
                    )) return;
                },
                .terminated_h2 => {
                    if (tryHandleTerminatedH2TlsAlpn(
                        handler,
                        metrics,
                        tracer,
                        &ctx,
                        maybe_tls_ptr,
                        io_mut,
                        connection_id,
                        cfg.tls_h2_frontend_mode,
                    )) return;
                },
                .continue_h1 => {},
            }

            // Request processing state
            var parser = Parser.init();
            var recv_buf: [CONNECTION_RECV_BUFFER_SIZE_BYTES]u8 = std.mem.zeroes([CONNECTION_RECV_BUFFER_SIZE_BYTES]u8);
            var request_count: u32 = 0;
            var buffer_offset: usize = 0;
            var buffer_len: usize = 0;

            // Direct response buffer - only allocated if handler has onRequest hook.
            // TigerStyle: Comptime conditional eliminates overhead for pure proxy handlers.
            // Heap-allocated to support large payloads (128MB+) without stack overflow.
            const has_on_request = comptime hooks.hasHook(Handler, "onRequest");
            const has_select_websocket = comptime websocket_server.hasHook(Handler, "selectWebSocket");
            const response_buf: []u8 = if (has_on_request)
                std.heap.page_allocator.alloc(u8, DIRECT_RESPONSE_BUFFER_SIZE_BYTES) catch {
                    log.err("server: conn={d} failed to allocate response buffer", .{connection_id});
                    return;
                }
            else
                &[_]u8{};
            defer if (has_on_request) std.heap.page_allocator.free(response_buf);

            // Note: Request body buffer removed - handlers use ctx.readBody() with their own buffer.
            // This enables lazy body reading - body only read when handler explicitly requests it.
            // TigerStyle: Caller provides buffer, bounded by Content-Length.

            while (request_count < cfg.max_requests_per_connection) {
                request_count += 1;
                ctx.reset();
                parser.reset();

                // Pipelining: reuse leftover data or read new data
                const handler_start_ns = realtimeNanos();
                log.debug("server: conn={d} waiting for request handler_start={d}", .{ connection_id, @as(u64, @intCast(handler_start_ns)) });
                const read_start_ns = realtimeNanos();
                if (buffer_offset >= buffer_len) {
                    const n = connectionRead(maybe_tls_ptr, &io_mut, stream, maybe_plain_reader, &recv_buf, connection_id) orelse return;
                    buffer_len = n;
                    buffer_offset = 0;
                }

                if (tryHandleTerminatedH2PriorKnowledge(
                    handler,
                    metrics,
                    tracer,
                    &ctx,
                    maybe_tls_ptr,
                    io_mut,
                    stream,
                    maybe_plain_reader,
                    recv_buf[0..],
                    &buffer_len,
                    connection_id,
                )) return;

                if (tryHandleH2cPriorKnowledge(
                    handler,
                    forwarder,
                    metrics,
                    tracer,
                    maybe_tls_ptr,
                    &io_mut,
                    stream,
                    maybe_plain_reader,
                    &ctx,
                    recv_buf[0..],
                    &buffer_len,
                    connection_id,
                )) return;

                const terminated_h2_handler = comptime @hasDecl(Handler, "handleH2Headers") and @hasDecl(Handler, "handleH2Data");
                if (cfg.h2c_prior_knowledge_only and maybe_tls_ptr == null and terminated_h2_handler) {
                    return;
                }

                // Accumulate reads until complete headers received
                if (!accumulateHeaders(maybe_tls_ptr, &io_mut, stream, recv_buf[0..], buffer_offset, &buffer_len, connection_id)) return;
                const read_elapsed_ns = realtimeNanos() - read_start_ns;
                const read_duration_us: u64 = if (read_elapsed_ns >= 0) @intCast(@divFloor(read_elapsed_ns, 1000)) else 0;
                log.debug("server: conn={d} received bytes={d} read_us={d}", .{ connection_id, buffer_len - buffer_offset, read_duration_us });

                ctx.bytes_received = @intCast(buffer_len - buffer_offset);
                metrics.requestStart();

                // Parse headers
                const parse_start = realtimeNanos();
                const header_len = std.mem.indexOf(u8, recv_buf[buffer_offset..buffer_len], "\r\n\r\n").? + 4;
                parser.parseHeaders(recv_buf[buffer_offset .. buffer_offset + header_len]) catch {
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

                const websocket_candidate = serval_websocket.looksLikeWebSocketUpgradeRequest(&parser.request);
                const h2c_upgrade_candidate = serval_h2.looksLikeUpgradeRequest(&parser.request);

                // Start a tracing span for this request (child of TLS span if present)
                var span_name_buf: [config.OTEL_MAX_NAME_LEN]u8 = std.mem.zeroes([config.OTEL_MAX_NAME_LEN]u8);
                const span_name = buildSpanName(parser.request.method, parser.request.path, &span_name_buf);
                const parent_span: ?SpanHandle = if (tls_span.isValid()) tls_span else null;
                const span_handle = tracer.startSpan(span_name, parent_span);
                ctx.span_handle = span_handle;

                // Add HTTP semantic convention attributes for Jaeger SPM (spanmetrics connector)
                // These attributes enable RED (Request, Error, Duration) metrics generation
                tracer.setStringAttribute(span_handle, "http.request.method", @tagName(parser.request.method));
                tracer.setStringAttribute(span_handle, "url.path", parser.request.path);

                // Call onRequest hook if present
                if (comptime has_on_request) {
                    // Set up lazy body reader for handlers to read body on demand.
                    // Industry standard pattern: body only read when handler explicitly requests it.
                    // TigerStyle: No eager reading, bounded by Content-Length when read.
                    const body_length_for_offset = getBodyLength(&parser.request);

                    // Calculate initial body bytes already in recv_buf (after headers)
                    const headers_end = parser.headers_end;
                    const data_after_headers = buffer_len - buffer_offset - headers_end;
                    const initial_body_bytes: u64 = switch (parser.body_framing) {
                        .content_length => |cl| @min(data_after_headers, cl),
                        .chunked => data_after_headers,
                        .none => 0,
                    };

                    // Set up BodyReadContext for the read function
                    var body_read_ctx = BodyReadContext{
                        .maybe_tls = maybe_tls_ptr,
                        .io = &io_mut,
                        .stream = stream,
                        .plain_reader = maybe_plain_reader,
                        .conn_id = connection_id,
                    };

                    // Set up BodyReader with lazy read capability
                    var body_reader = BodyReader{
                        .framing = parser.body_framing,
                        .bytes_already_read = initial_body_bytes,
                        .initial_body = if (initial_body_bytes > 0)
                            recv_buf[buffer_offset + headers_end ..][0..@intCast(initial_body_bytes)]
                        else
                            &[_]u8{},
                        .read_ctx = @ptrCast(&body_read_ctx),
                        .read_fn = &bodyReadFn,
                    };

                    // Attach body reader to context for handler access
                    ctx._body_reader = &body_reader;

                    switch (handler.onRequest(&ctx, &parser.request, response_buf)) {
                        .continue_request => {}, // Fall through to selectUpstream
                        .send_response => |resp| {
                            // Handler wants to send direct response without forwarding
                            sendDirectResponseTls(maybe_tls_ptr, &io_mut, stream, resp);
                            const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                            metrics.requestEnd(resp.status, duration_ns);
                            tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(resp.status));
                            tracer.endSpan(span_handle, null);
                            buffer_offset += parser.headers_end + body_length_for_offset;
                            const should_close = clientWantsClose(&parser.request.headers) or
                                request_count >= cfg.max_requests_per_connection;
                            if (should_close) return;
                            continue;
                        },
                        .reject => |reject| {
                            // Handler wants to reject request (WAF, rate limiting, auth)
                            sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, reject.status, reject.reason);
                            const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                            metrics.requestEnd(reject.status, duration_ns);
                            tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(reject.status));
                            tracer.endSpan(span_handle, reject.reason);
                            buffer_offset += parser.headers_end + body_length_for_offset;
                            const should_close = clientWantsClose(&parser.request.headers) or
                                request_count >= cfg.max_requests_per_connection;
                            if (should_close) return;
                            continue;
                        },
                        .stream => |stream_resp| {
                            // Streaming response: call handler.nextChunk() in bounded loop.
                            // TigerStyle: Comptime check for nextChunk method.
                            if (comptime !@hasDecl(Handler, "nextChunk")) {
                                // Handler returns .stream but has no nextChunk method.
                                // Send 501 Not Implemented at runtime.
                                sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, 501, "Handler missing nextChunk method");
                                const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                                metrics.requestEnd(501, duration_ns);
                                tracer.setIntAttribute(span_handle, "http.response.status_code", 501);
                                tracer.endSpan(span_handle, "missing_nextChunk");
                                buffer_offset += parser.headers_end + body_length_for_offset;
                                continue;
                            } else {
                                // Create TLS-aware writer for streaming helpers
                                var tls_writer = TlsWriter{
                                    .maybe_tls = maybe_tls_ptr,
                                    .io = &io_mut,
                                    .stream = stream,
                                };

                                // 1. Send headers (chunked encoding)
                                sendStreamHeaders(&tls_writer, stream_resp) catch |err| {
                                    log.err("streaming response: failed to send headers: {s}", .{@errorName(err)});
                                    const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                                    metrics.requestEnd(500, duration_ns);
                                    tracer.setIntAttribute(span_handle, "http.response.status_code", 500);
                                    tracer.endSpan(span_handle, "stream_headers_failed");
                                    buffer_offset += parser.headers_end + body_length_for_offset;
                                    continue;
                                };

                                // 2. Bounded streaming loop
                                var chunk_count: u32 = 0;
                                const max_chunk_count: u32 = config.MAX_STREAM_CHUNK_COUNT;
                                var stream_error: bool = false;

                                while (chunk_count < max_chunk_count) : (chunk_count += 1) {
                                    const maybe_len = handler.nextChunk(&ctx, response_buf) catch |err| {
                                        // S6: Log error before terminating stream
                                        log.err("streaming response failed at chunk {d}: {s}", .{ chunk_count, @errorName(err) });
                                        sendFinalChunk(&tls_writer) catch |final_err| {
                                            log.warn("streaming response: failed to send final chunk after chunk error: {s}", .{@errorName(final_err)});
                                        };
                                        stream_error = true;
                                        break;
                                    };

                                    if (maybe_len) |len| {
                                        assert(len <= response_buf.len); // S1: postcondition
                                        if (len > 0) {
                                            sendChunk(&tls_writer, response_buf[0..len]) catch |err| {
                                                log.err("streaming response: failed to send chunk {d}: {s}", .{ chunk_count, @errorName(err) });
                                                stream_error = true;
                                                break;
                                            };
                                        }
                                    } else {
                                        // null = done
                                        sendFinalChunk(&tls_writer) catch |final_err| {
                                            log.err("streaming response: failed to send final chunk: {s}", .{@errorName(final_err)});
                                            stream_error = true;
                                        };
                                        break;
                                    }
                                }

                                // TigerStyle: if we hit max_chunk_count, log and terminate cleanly
                                if (chunk_count >= max_chunk_count) {
                                    log.warn("streaming response hit max chunk count: {d}", .{max_chunk_count});
                                    sendFinalChunk(&tls_writer) catch |final_err| {
                                        log.warn("streaming response: failed to send final chunk at chunk limit: {s}", .{@errorName(final_err)});
                                        stream_error = true;
                                    };
                                }

                                const final_status: u16 = if (stream_error) 500 else stream_resp.status;
                                const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                                metrics.requestEnd(final_status, duration_ns);
                                tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(final_status));
                                if (stream_error) {
                                    tracer.endSpan(span_handle, "stream_error");
                                } else {
                                    tracer.endSpan(span_handle, null);
                                }
                                buffer_offset += parser.headers_end + body_length_for_offset;
                                const should_close = clientWantsClose(&parser.request.headers) or
                                    request_count >= cfg.max_requests_per_connection;
                                if (should_close) return;
                                continue;
                            }
                        },
                    }
                }

                var h2c_upgrade_settings_buf: [config.H2_MAX_FRAME_SIZE_BYTES]u8 = undefined;
                const h2c_upgrade_settings: ?[]const u8 = if (h2c_upgrade_candidate) blk: {
                    if (maybe_tls_ptr != null) {
                        sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, 400, "Bad h2c Upgrade Request");
                        const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                        metrics.requestEnd(400, duration_ns);
                        tracer.setIntAttribute(span_handle, "http.response.status_code", 400);
                        tracer.endSpan(span_handle, "TlsH2cUpgradeNotAllowed");
                        return;
                    }

                    const settings_payload = serval_h2.validateUpgradeRequest(
                        &parser.request,
                        parser.body_framing,
                        &h2c_upgrade_settings_buf,
                    ) catch |err| {
                        sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, 400, "Bad h2c Upgrade Request");
                        const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                        metrics.requestEnd(400, duration_ns);
                        tracer.setIntAttribute(span_handle, "http.response.status_code", 400);
                        tracer.endSpan(span_handle, @errorName(err));
                        return;
                    };

                    const upgrade_request_is_grpc = serval_grpc.classifyRequest(&parser.request) == .grpc;
                    if (!upgrade_request_is_grpc) {
                        log.debug(
                            "server: conn={d} upgrade stream classified as non-gRPC; bridge completion uses generic semantics",
                            .{ctx.connection_id},
                        );
                    }

                    break :blk settings_payload;
                } else null;

                if (h2c_upgrade_settings) |settings_payload| {
                    if (tryHandleTerminatedH2Upgrade(
                        handler,
                        metrics,
                        tracer,
                        maybe_tls_ptr,
                        &io_mut,
                        stream,
                        &ctx,
                        &parser,
                        recv_buf[0..],
                        buffer_offset,
                        buffer_len,
                        connection_id,
                        settings_payload,
                        span_handle,
                    )) return;
                }

                if (websocket_candidate) {
                    serval_websocket.validateClientRequest(&parser.request, parser.body_framing) catch |err| {
                        sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, 400, "Bad WebSocket Request");
                        const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                        metrics.requestEnd(400, duration_ns);
                        tracer.setIntAttribute(span_handle, "http.response.status_code", 400);
                        tracer.endSpan(span_handle, @errorName(err));
                        return;
                    };

                    if (comptime has_select_websocket) {
                        switch (handler.selectWebSocket(&ctx, &parser.request)) {
                            .decline => {},
                            .reject => |reject| {
                                sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, reject.status, reject.reason);
                                const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                                ctx.duration_ns = duration_ns;
                                ctx.response_status = reject.status;
                                metrics.requestEnd(reject.status, duration_ns);
                                if (comptime hooks.hasHook(Handler, "onLog")) {
                                    const log_entry = serval_core.log.LogEntry{
                                        .timestamp_s = time.nanosToSecondsI128(ctx.start_time_ns),
                                        .start_time_ns = ctx.start_time_ns,
                                        .duration_ns = duration_ns,
                                        .method = parser.request.method,
                                        .path = parser.request.path,
                                        .request_bytes = @intCast(parser.headers_end),
                                        .status = reject.status,
                                        .response_bytes = 0,
                                        .upstream = null,
                                        .upstream_duration_ns = 0,
                                        .error_phase = null,
                                        .error_name = null,
                                        .connection_reused = false,
                                        .keepalive = false,
                                        .parse_duration_ns = ctx.parse_duration_ns,
                                        .connection_id = ctx.connection_id,
                                        .request_number = ctx.request_number,
                                        .client_addr = ctx.client_addr,
                                    };
                                    handler.onLog(&ctx, log_entry);
                                }
                                tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(reject.status));
                                tracer.endSpan(span_handle, reject.reason);
                                return;
                            },
                            .accept => |accept_cfg| {
                                var transport_ctx = websocket_server.ConnectionTransportContext{
                                    .fd = @intCast(stream.socket.handle),
                                    .maybe_tls = maybe_tls_ptr,
                                    .connection_id = connection_id,
                                };
                                const transport = websocket_server.initConnectionTransport(&transport_ctx);

                                const handshake_bytes = websocket_server.sendSwitchingProtocols(
                                    &transport,
                                    &parser.request,
                                    accept_cfg,
                                ) catch |err| {
                                    if (err != error.WriteFailed) {
                                        sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, 500, "WebSocket Accept Failed");
                                    }
                                    const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                                    ctx.duration_ns = duration_ns;
                                    ctx.response_status = 500;
                                    metrics.requestEnd(500, duration_ns);
                                    if (comptime hooks.hasHook(Handler, "onLog")) {
                                        const log_entry = serval_core.log.LogEntry{
                                            .timestamp_s = time.nanosToSecondsI128(ctx.start_time_ns),
                                            .start_time_ns = ctx.start_time_ns,
                                            .duration_ns = duration_ns,
                                            .method = parser.request.method,
                                            .path = parser.request.path,
                                            .request_bytes = @intCast(parser.headers_end),
                                            .status = 500,
                                            .response_bytes = 0,
                                            .upstream = null,
                                            .upstream_duration_ns = 0,
                                            .error_phase = null,
                                            .error_name = @errorName(err),
                                            .connection_reused = false,
                                            .keepalive = false,
                                            .parse_duration_ns = ctx.parse_duration_ns,
                                            .connection_id = ctx.connection_id,
                                            .request_number = ctx.request_number,
                                            .client_addr = ctx.client_addr,
                                        };
                                        handler.onLog(&ctx, log_entry);
                                    }
                                    tracer.setIntAttribute(span_handle, "http.response.status_code", 500);
                                    tracer.endSpan(span_handle, @errorName(err));
                                    return;
                                };

                                const initial_client_bytes = if (buffer_len > buffer_offset + parser.headers_end)
                                    recv_buf[buffer_offset + parser.headers_end .. buffer_len]
                                else
                                    &[_]u8{};

                                var ws_session = websocket_server.WebSocketSession.init(
                                    transport,
                                    accept_cfg,
                                    accept_cfg.subprotocol,
                                    initial_client_bytes,
                                );
                                var websocket_error_name: ?[]const u8 = null;

                                handler.handleWebSocket(&ctx, &parser.request, &ws_session) catch |err| {
                                    websocket_error_name = @errorName(err);
                                    if (ws_session.state() == .open) {
                                        ws_session.close(serval_websocket.close_internal_error, "") catch |close_err| {
                                            if (websocket_error_name == null) websocket_error_name = @errorName(close_err);
                                        };
                                    }
                                };

                                if (ws_session.state() == .open) {
                                    ws_session.close(serval_websocket.close_normal_closure, "") catch |err| {
                                        if (websocket_error_name == null) websocket_error_name = @errorName(err);
                                    };
                                }
                                if (ws_session.state() == .close_sent) {
                                    ws_session.finishCloseHandshake() catch |err| {
                                        if (websocket_error_name == null) websocket_error_name = @errorName(err);
                                    };
                                }

                                const websocket_duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                                const websocket_stats = ws_session.stats();
                                ctx.duration_ns = websocket_duration_ns;
                                ctx.response_status = 101;
                                ctx.bytes_received = @as(u64, @intCast(parser.headers_end)) + websocket_stats.bytes_received;
                                ctx.bytes_sent = handshake_bytes + websocket_stats.bytes_sent;

                                handleNativeWebSocketCompleteImpl(
                                    handler,
                                    metrics,
                                    &ctx,
                                    &parser.request,
                                    ctx.bytes_sent,
                                    websocket_duration_ns,
                                    websocket_error_name,
                                );
                                tracer.setIntAttribute(span_handle, "http.response.status_code", 101);
                                tracer.endSpan(span_handle, websocket_error_name);
                                return;
                            },
                        }
                    }
                }

                if (runtime_provider) |provider| {
                    if (provider.lookupRoute(&parser.request)) |route_snapshot| {
                        log.debug(
                            "server: runtime_provider matched generation={d} route={s} pool={s} chain={s}",
                            .{
                                route_snapshot.generation_id,
                                route_snapshot.route_id,
                                route_snapshot.pool_id,
                                route_snapshot.chain_id,
                            },
                        );
                    }
                }

                // Select upstream and forward (or reject if handler returns action)
                const action_result = handler.selectUpstream(&ctx, &parser.request);

                // Handle action-style return (Router.Action) vs plain Upstream
                const upstream: types.Upstream = blk: {
                    if (comptime hooks.hasUpstreamAction(Handler)) {
                        // Handler returns Action union (e.g., Router)
                        switch (action_result) {
                            .forward => |up| break :blk up,
                            .reject => |rej| {
                                // Handler rejected request (e.g., 404 Not Found, 421 Misdirected)
                                ctx.response_status = rej.status;
                                const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                                ctx.duration_ns = duration_ns;

                                // Send reject response (TLS-aware)
                                sendDirectResponseTls(
                                    maybe_tls_ptr,
                                    &io_mut,
                                    stream,
                                    .{
                                        .status = rej.status,
                                        .body = rej.body,
                                        .content_type = "text/plain",
                                    },
                                );

                                metrics.requestEnd(rej.status, duration_ns);
                                if (comptime hooks.hasHook(Handler, "onLog")) {
                                    const log_entry = serval_core.log.LogEntry{
                                        .timestamp_s = time.nanosToSecondsI128(ctx.start_time_ns),
                                        .start_time_ns = ctx.start_time_ns,
                                        .duration_ns = duration_ns,
                                        .method = parser.request.method,
                                        .path = parser.request.path,
                                        .request_bytes = ctx.bytes_received,
                                        .status = rej.status,
                                        .response_bytes = @intCast(rej.body.len),
                                        .upstream = null,
                                        .upstream_duration_ns = 0,
                                        .error_phase = null,
                                        .error_name = null,
                                        .connection_reused = false,
                                        .keepalive = true,
                                        .parse_duration_ns = ctx.parse_duration_ns,
                                        .connection_id = ctx.connection_id,
                                        .request_number = ctx.request_number,
                                        .client_addr = ctx.client_addr,
                                    };
                                    handler.onLog(&ctx, log_entry);
                                }
                                tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(rej.status));
                                tracer.endSpan(span_handle, null);

                                // Advance buffer past this request and continue with next
                                const body_length = getBodyLength(&parser.request);
                                buffer_offset += parser.headers_end + body_length;
                                continue;
                            },
                        }
                    } else {
                        // Handler returns plain Upstream (e.g., LbHandler)
                        break :blk action_result;
                    }
                };
                ctx.upstream = upstream;

                if (h2c_upgrade_settings) |settings_payload| {
                    const body_info = buildBodyInfo(&parser, &recv_buf, buffer_offset, buffer_len);
                    const initial_h2_offset = buffer_offset + parser.headers_end + @as(usize, @intCast(body_info.bytes_already_read));
                    assert(initial_h2_offset <= buffer_len);
                    const initial_client_bytes_after_body = recv_buf[initial_h2_offset..buffer_len];

                    const supports_h2c_plain = upstream.http_protocol == .h2c and !upstream.tls;
                    const supports_h2_tls = upstream.http_protocol == .h2 and upstream.tls;
                    const h2c_upgrade_result = if (supports_h2c_plain or supports_h2_tls)
                        forwardH2cUpgradeWithBridge(
                            handler,
                            forwarder,
                            io,
                            maybe_tls_ptr,
                            stream,
                            &parser,
                            recv_buf[0..],
                            buffer_offset,
                            buffer_len,
                            settings_payload,
                            &ctx,
                            connection_id,
                        )
                    else
                        forwarder.forwardGrpcH2cUpgrade(
                            io,
                            stream,
                            maybe_tls_ptr,
                            &parser.request,
                            &upstream,
                            body_info,
                            initial_client_bytes_after_body,
                            settings_payload,
                            span_handle,
                            ctx.rewritten_path,
                        );

                    const h2c_upgrade_duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                    ctx.duration_ns = h2c_upgrade_duration_ns;

                    if (h2c_upgrade_result) |fwd_result| {
                        handleForwardSuccessImpl(handler, metrics, &ctx, &parser.request, fwd_result, h2c_upgrade_duration_ns, false);
                        tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(fwd_result.status));
                        tracer.endSpan(span_handle, null);
                    } else |err| {
                        handleForwardErrorImpl(handler, metrics, maybe_tls_ptr, &io_mut, stream, &ctx, &parser.request, upstream, err, h2c_upgrade_duration_ns);
                        tracer.setIntAttribute(span_handle, "http.response.status_code", 502);
                        tracer.endSpan(span_handle, @errorName(err));
                    }
                    return;
                }

                if (websocket_candidate) {
                    const initial_client_bytes = if (buffer_len > buffer_offset + parser.headers_end)
                        recv_buf[buffer_offset + parser.headers_end .. buffer_len]
                    else
                        &[_]u8{};

                    const websocket_result = forwarder.forwardWebSocket(
                        io,
                        stream,
                        maybe_tls_ptr,
                        &parser.request,
                        &upstream,
                        initial_client_bytes,
                        span_handle,
                        ctx.rewritten_path,
                    );

                    const websocket_duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                    ctx.duration_ns = websocket_duration_ns;

                    if (websocket_result) |fwd_result| {
                        handleForwardSuccessImpl(handler, metrics, &ctx, &parser.request, fwd_result, websocket_duration_ns, false);
                        tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(fwd_result.status));
                        tracer.endSpan(span_handle, null);
                    } else |err| {
                        handleForwardErrorImpl(handler, metrics, maybe_tls_ptr, &io_mut, stream, &ctx, &parser.request, upstream, err, websocket_duration_ns);
                        tracer.setIntAttribute(span_handle, "http.response.status_code", 502);
                        tracer.endSpan(span_handle, @errorName(err));
                    }
                    return;
                }

                // Extract body info and forward
                // Pass ctx.rewritten_path for path rewriting support (e.g., strip_prefix in router)
                const body_info = buildBodyInfo(&parser, &recv_buf, buffer_offset, buffer_len);
                const forward_result = forwarder.forward(io, stream, maybe_tls_ptr, &parser.request, &upstream, body_info, span_handle, ctx.rewritten_path);

                const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                ctx.duration_ns = duration_ns;

                // Calculate where this request ends for pipelining
                const body_length = getBodyLength(&parser.request);
                const request_end = buffer_offset + parser.headers_end + body_length;

                // Process result and determine connection state
                const result: ProcessResult = if (forward_result) |fwd_result| blk: {
                    handleForwardSuccessImpl(handler, metrics, &ctx, &parser.request, fwd_result, duration_ns, true);
                    tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(fwd_result.status));
                    tracer.endSpan(span_handle, null);

                    const should_close = clientWantsClose(&parser.request.headers) or
                        request_count >= cfg.max_requests_per_connection;

                    break :blk if (should_close) .close_connection else .keep_alive;
                } else |err| blk: {
                    handleForwardErrorImpl(handler, metrics, maybe_tls_ptr, &io_mut, stream, &ctx, &parser.request, upstream, err, duration_ns);
                    tracer.setIntAttribute(span_handle, "http.response.status_code", 502);
                    tracer.endSpan(span_handle, @errorName(err));
                    break :blk .fatal_error;
                };

                buffer_offset = request_end;

                if (result != .keep_alive) return;
            }
        }

        /// Handle completed native WebSocket session: update metrics and call onLog hook.
        /// TigerStyle: HTTP status stays 101 for the full upgraded session lifetime.
        fn handleNativeWebSocketCompleteImpl(
            handler: *Handler,
            metrics: *Metrics,
            ctx: *Context,
            request: *const Request,
            response_bytes: u64,
            duration_ns: u64,
            error_name: ?[]const u8,
        ) void {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(metrics) != 0);

            ctx.response_status = 101;
            ctx.bytes_sent = response_bytes;
            metrics.requestEnd(101, duration_ns);

            if (comptime hooks.hasHook(Handler, "onLog")) {
                const log_entry = serval_core.log.LogEntry{
                    .timestamp_s = time.nanosToSecondsI128(ctx.start_time_ns),
                    .start_time_ns = ctx.start_time_ns,
                    .duration_ns = duration_ns,
                    .method = request.method,
                    .path = request.path,
                    .request_bytes = ctx.bytes_received,
                    .status = 101,
                    .response_bytes = response_bytes,
                    .upstream = null,
                    .upstream_duration_ns = 0,
                    .error_phase = null,
                    .error_name = error_name,
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

        fn handleTerminatedH2UpgradeCompleteImpl(
            handler: *Handler,
            metrics: *Metrics,
            ctx: *Context,
            request: *const Request,
            status: u16,
            response_bytes: u64,
            duration_ns: u64,
            error_name: ?[]const u8,
        ) void {
            assert(@intFromPtr(handler) != 0);
            assert(@intFromPtr(metrics) != 0);
            assert(status >= 100);

            ctx.response_status = status;
            ctx.bytes_sent = response_bytes;
            metrics.requestEnd(status, duration_ns);

            if (comptime hooks.hasHook(Handler, "onLog")) {
                const log_entry = serval_core.log.LogEntry{
                    .timestamp_s = time.nanosToSecondsI128(ctx.start_time_ns),
                    .start_time_ns = ctx.start_time_ns,
                    .duration_ns = duration_ns,
                    .method = request.method,
                    .path = request.path,
                    .request_bytes = ctx.bytes_received,
                    .status = status,
                    .response_bytes = response_bytes,
                    .upstream = null,
                    .upstream_duration_ns = 0,
                    .error_phase = null,
                    .error_name = error_name,
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

        /// Handle successful forward: update metrics and call onLog hook.
        /// TigerStyle: Standalone function with explicit dependencies.
        fn handleForwardSuccessImpl(
            handler: *Handler,
            metrics: *Metrics,
            ctx: *Context,
            request: *const Request,
            result: forwarder_mod.ForwardResult,
            duration_ns: u64,
            keepalive: bool,
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
                const log_entry = serval_core.log.LogEntry{
                    .timestamp_s = time.nanosToSecondsI128(ctx.start_time_ns),
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
                    .keepalive = keepalive,
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
                _ = handler.onError(ctx, &error_ctx);
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
                const log_entry = serval_core.log.LogEntry{
                    .timestamp_s = time.nanosToSecondsI128(ctx.start_time_ns),
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
                forwarder_mod.ForwardError.DnsResolutionFailed,
                => .connect,
                forwarder_mod.ForwardError.SendFailed,
                forwarder_mod.ForwardError.StaleConnection,
                forwarder_mod.ForwardError.RequestBodyTooLarge,
                => .send,
                forwarder_mod.ForwardError.UnsupportedProtocol => .handler_request,
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
                forwarder_mod.ForwardError.DnsResolutionFailed => error.ConnectFailed,
                forwarder_mod.ForwardError.SendFailed => error.SendFailed,
                forwarder_mod.ForwardError.StaleConnection => error.StaleConnection,
                forwarder_mod.ForwardError.RequestBodyTooLarge => error.BodyTooLarge,
                forwarder_mod.ForwardError.UnsupportedProtocol => error.InvalidResponse,
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

fn createServerCtxForTest() !*ssl.SSL_CTX {
    ssl.init();
    return ssl.createServerCtx();
}

test "Server reload API returns unavailable when manager is not published" {
    var handler = TestHandler{};
    var pool = pool_mod.SimplePool.init();
    var metrics = metrics_mod.NoopMetrics{};
    var tracer = tracing_mod.NoopTracer{};

    var server = Server(TestHandler, pool_mod.SimplePool, metrics_mod.NoopMetrics, tracing_mod.NoopTracer)
        .init(&handler, &pool, &metrics, &tracer, .{}, null, DnsConfig{});

    try std.testing.expectError(
        error.TlsReloadUnavailable,
        server.reloadServerTlsFromPemFiles("/tmp/non-empty-cert.pem", "/tmp/non-empty-key.pem"),
    );
    try std.testing.expectError(error.TlsReloadUnavailable, server.activeServerTlsGeneration());
}

test "Server reload API activates through published manager" {
    var handler = TestHandler{};
    var pool = pool_mod.SimplePool.init();
    var metrics = metrics_mod.NoopMetrics{};
    var tracer = tracing_mod.NoopTracer{};

    var server = Server(TestHandler, pool_mod.SimplePool, metrics_mod.NoopMetrics, tracing_mod.NoopTracer)
        .init(&handler, &pool, &metrics, &tracer, .{}, null, DnsConfig{});

    const first_ctx = try createServerCtxForTest();
    var manager = ReloadableServerCtx.init(first_ctx);
    defer manager.deinit();

    server.publishTlsCtxManager(&manager);
    defer server.unpublishTlsCtxManager();

    try std.testing.expectEqual(@as(u32, 1), try server.activeServerTlsGeneration());
    try std.testing.expectError(
        error.InvalidCertPath,
        server.reloadServerTlsFromPemFiles("", "/tmp/non-empty-key.pem"),
    );
    try std.testing.expectEqual(@as(u32, 1), try server.activeServerTlsGeneration());
}

test "Server compiles with valid handler" {
    var handler = TestHandler{};
    var pool = pool_mod.SimplePool.init();
    var metrics = metrics_mod.NoopMetrics{};
    var tracer = tracing_mod.NoopTracer{};

    // TigerStyle: null client_ctx for tests without TLS upstreams.
    // DnsConfig{} uses default TTL and timeout values.
    const server = Server(TestHandler, pool_mod.SimplePool, metrics_mod.NoopMetrics, tracing_mod.NoopTracer)
        .init(&handler, &pool, &metrics, &tracer, .{}, null, DnsConfig{});

    try std.testing.expectEqual(@as(u16, 8080), server.config.port);
}

test "MinimalServer compiles" {
    var handler = TestHandler{};
    var pool = pool_mod.SimplePool.init();
    var metrics = metrics_mod.NoopMetrics{};
    var tracer = tracing_mod.NoopTracer{};

    // TigerStyle: null client_ctx for tests without TLS upstreams.
    // DnsConfig{} uses default TTL and timeout values.
    _ = MinimalServer(TestHandler).init(&handler, &pool, &metrics, &tracer, .{}, null, DnsConfig{});
}

test "Server runtime provider is optional and defaults to null" {
    var handler = TestHandler{};
    var pool = pool_mod.SimplePool.init();
    var metrics = metrics_mod.NoopMetrics{};
    var tracer = tracing_mod.NoopTracer{};

    var server = Server(TestHandler, pool_mod.SimplePool, metrics_mod.NoopMetrics, tracing_mod.NoopTracer)
        .init(&handler, &pool, &metrics, &tracer, .{}, null, DnsConfig{});

    try std.testing.expect(server.getRuntimeProvider() == null);
}

test "Server accepts runtime provider adapter without reverseproxy hard dependency" {
    const FakeProvider = struct {
        pub fn activeGeneration(self: *const @This()) ?u64 {
            _ = self;
            return 7;
        }

        pub fn lookupRoute(self: *const @This(), request: *const Request) ?frontend.RouteSnapshot {
            _ = self;
            _ = request;
            return .{
                .generation_id = 7,
                .route_id = "route-a",
                .pool_id = "pool-a",
                .chain_id = "chain-a",
            };
        }
    };

    var handler = TestHandler{};
    var pool = pool_mod.SimplePool.init();
    var metrics = metrics_mod.NoopMetrics{};
    var tracer = tracing_mod.NoopTracer{};

    var server = Server(TestHandler, pool_mod.SimplePool, metrics_mod.NoopMetrics, tracing_mod.NoopTracer)
        .init(&handler, &pool, &metrics, &tracer, .{}, null, DnsConfig{});

    var fake_provider = FakeProvider{};
    server.setRuntimeProvider(frontend.fromRuntimeProvider(&fake_provider));

    const configured = server.getRuntimeProvider() orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(?u64, 7), configured.activeGeneration());
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

test "h2 bridge adapter avoids proxy binding table internals" {
    const source = @embedFile("server.zig");
    const needle = "bridge." ++ "binding_table";
    try std.testing.expect(std.mem.indexOf(u8, source, needle) == null);
}
