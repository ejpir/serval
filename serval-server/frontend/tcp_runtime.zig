//! TCP transport runtime primitives.
//!
//! Provides bounded accept/concurrency enforcement and upstream connect attempts
//! using shared strategy selection.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const core_config = serval_core.config;
const core_types = serval_core.types;
const time = serval_core.time;
const log = serval_core.log.scoped(.tcp_runtime);
const serval_net = @import("serval-net");
const serval_client = @import("serval-client");
const set_tcp_no_delay = serval_net.set_tcp_no_delay;
const serval_lb = @import("serval-lb");
const serval_proxy = @import("serval-proxy");
const serval_socket = @import("serval-socket");
const serval_tls = @import("serval-tls");

const Upstream = core_types.Upstream;
const L4Target = core_config.L4Target;
const TcpTransportConfig = core_config.TcpTransportConfig;
const TcpTlsMode = core_config.TcpTlsMode;
const UpstreamIndex = core_config.UpstreamIndex;
const DnsConfig = serval_net.DnsConfig;
const DnsResolver = serval_net.DnsResolver;
const Client = serval_client.Client;
const RoundRobinStrategy = serval_lb.RoundRobinStrategy;
const StrategyConfig = serval_lb.StrategyConfig;
const Socket = serval_socket.Socket;
const tunnel = serval_proxy.tunnel;
const ssl = serval_tls.ssl;

const capacity_rejection_log_sample_interval: u64 = 32;
const connect_failure_log_sample_interval: u64 = 16;
const timeout_closure_log_sample_interval: u64 = 16;

pub const RuntimeError = error{
    InvalidConfig,
    InvalidAddress,
    ListenFailed,
};

pub const Runtime = struct {
    transport_cfg: TcpTransportConfig,
    upstream_storage: [core_config.MAX_UPSTREAMS]Upstream,
    upstreams: []const Upstream,
    strategy: RoundRobinStrategy,
    active_connections: std.atomic.Value(u32),
    accepted_connections: std.atomic.Value(u64),
    rejected_at_capacity: std.atomic.Value(u64),
    connect_failures: std.atomic.Value(u64),
    timeout_closures: std.atomic.Value(u64),
    upstream_bytes: std.atomic.Value(u64),
    downstream_bytes: std.atomic.Value(u64),
    dns_resolver: DnsResolver,
    client_ctx: ?*ssl.SSL_CTX,
    verify_upstream_tls: bool,

    const Self = @This();

    pub fn init(
        self: *Self,
        transport_cfg: TcpTransportConfig,
        dns_cfg: DnsConfig,
        client_ctx: ?*ssl.SSL_CTX,
        verify_upstream_tls: bool,
    ) RuntimeError!void {
        assert(@intFromPtr(self) != 0);
        assert(transport_cfg.enabled);

        if (transport_cfg.listener_host.len == 0) return error.InvalidConfig;
        if (transport_cfg.listener_port == 0) return error.InvalidConfig;
        if (transport_cfg.upstreams.len == 0) return error.InvalidConfig;
        if (transport_cfg.upstreams.len > core_config.MAX_UPSTREAMS) return error.InvalidConfig;
        if (transport_cfg.max_concurrent_connections == 0) return error.InvalidConfig;

        self.* = .{
            .transport_cfg = transport_cfg,
            .upstream_storage = undefined,
            .upstreams = &.{},
            .strategy = undefined,
            .active_connections = std.atomic.Value(u32).init(0),
            .accepted_connections = std.atomic.Value(u64).init(0),
            .rejected_at_capacity = std.atomic.Value(u64).init(0),
            .connect_failures = std.atomic.Value(u64).init(0),
            .timeout_closures = std.atomic.Value(u64).init(0),
            .upstream_bytes = std.atomic.Value(u64).init(0),
            .downstream_bytes = std.atomic.Value(u64).init(0),
            .dns_resolver = undefined,
            .client_ctx = client_ctx,
            .verify_upstream_tls = verify_upstream_tls,
        };

        DnsResolver.init(&self.dns_resolver, dns_cfg);

        var idx: usize = 0;
        while (idx < transport_cfg.upstreams.len) : (idx += 1) {
            const target = transport_cfg.upstreams[idx];
            if (target.host.len == 0 or target.port == 0) return error.InvalidConfig;
            self.upstream_storage[idx] = buildUpstream(target, transport_cfg.tls_mode, @intCast(idx));
        }
        self.upstreams = self.upstream_storage[0..transport_cfg.upstreams.len];

        self.strategy.init(self.upstreams, StrategyConfig{
            .unhealthy_threshold = core_config.DEFAULT_UNHEALTHY_THRESHOLD,
            .healthy_threshold = core_config.DEFAULT_HEALTHY_THRESHOLD,
        });
    }

    pub fn run(self: *Self, io: Io, shutdown: *std.atomic.Value(bool), listener_fd_out: ?*std.atomic.Value(i32)) RuntimeError!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(shutdown) != 0);
        assert(self.transport_cfg.enabled);

        const addr = Io.net.IpAddress.parse(self.transport_cfg.listener_host, self.transport_cfg.listener_port) catch {
            return error.InvalidAddress;
        };

        var tcp_server = addr.listen(io, .{
            .kernel_backlog = 128,
            .reuse_address = true,
        }) catch return error.ListenFailed;

        if (listener_fd_out) |fd_out| {
            fd_out.store(@intCast(tcp_server.socket.handle), .release);
        }
        defer {
            if (listener_fd_out) |fd_out| fd_out.store(-1, .release);
            tcp_server.deinit(io);
        }

        var group: Io.Group = .init;
        defer group.await(io) catch |err| {
            log.warn("tcp runtime: connection group await failed: {s}", .{@errorName(err)});
        };

        while (!shutdown.load(.acquire)) {
            const stream = tcp_server.accept(io) catch |err| {
                if (shutdown.load(.acquire)) break;
                log.warn("tcp runtime: accept failed: {s}", .{@errorName(err)});
                continue;
            };

            if (!self.tryAcquireSlot()) {
                stream.close(io);
                continue;
            }

            group.concurrent(io, handleAcceptedConnection, .{ self, stream, io }) catch |err| {
                self.releaseSlot();
                stream.close(io);
                log.warn("tcp runtime: spawn failed: {s}", .{@errorName(err)});
            };
        }
    }

    pub fn rejectedCount(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.rejected_at_capacity.load(.acquire);
    }

    pub fn acceptedCount(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.accepted_connections.load(.acquire);
    }

    pub fn connectFailureCount(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.connect_failures.load(.acquire);
    }

    pub fn timeoutClosureCount(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.timeout_closures.load(.acquire);
    }

    pub fn upstreamBytes(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.upstream_bytes.load(.acquire);
    }

    pub fn downstreamBytes(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.downstream_bytes.load(.acquire);
    }

    pub fn activeCount(self: *const Self) u32 {
        assert(@intFromPtr(self) != 0);
        return self.active_connections.load(.acquire);
    }

    fn tryAcquireSlot(self: *Self) bool {
        assert(@intFromPtr(self) != 0);

        const previous = self.active_connections.fetchAdd(1, .acq_rel);
        if (previous >= self.transport_cfg.max_concurrent_connections) {
            _ = self.active_connections.fetchSub(1, .acq_rel);
            const rejection_count = self.rejected_at_capacity.fetchAdd(1, .monotonic) + 1;
            if (shouldLogSampled(rejection_count, capacity_rejection_log_sample_interval)) {
                log.warn(
                    "event=tcp_capacity_rejection count={d} active={d} limit={d}",
                    .{ rejection_count, previous, self.transport_cfg.max_concurrent_connections },
                );
            }
            return false;
        }

        _ = self.accepted_connections.fetchAdd(1, .monotonic);
        return true;
    }

    fn releaseSlot(self: *Self) void {
        assert(@intFromPtr(self) != 0);
        const previous = self.active_connections.fetchSub(1, .acq_rel);
        assert(previous > 0);
    }
};

fn handleAcceptedConnection(runtime: *Runtime, stream: Io.net.Stream, io: Io) void {
    assert(@intFromPtr(runtime) != 0);

    defer runtime.releaseSlot();

    var downstream_socket = Socket.Plain.init_server(stream.socket.handle);
    defer downstream_socket.close();

    _ = set_tcp_no_delay(stream.socket.handle);

    const upstream = runtime.strategy.select();
    assert(upstream.idx < runtime.upstreams.len);

    var client = Client.init(std.heap.page_allocator, &runtime.dns_resolver, runtime.client_ctx, runtime.verify_upstream_tls);
    const connect_timeout = timeoutForMilliseconds(runtime.transport_cfg.connect_timeout_ms);
    var connect_result = client.connectWithTimeout(upstream, io, connect_timeout) catch {
        const failure_count = runtime.connect_failures.fetchAdd(1, .monotonic) + 1;
        if (shouldLogSampled(failure_count, connect_failure_log_sample_interval)) {
            log.warn(
                "event=tcp_connect_failed count={d} upstream_idx={d} upstream_host={s} upstream_port={d}",
                .{ failure_count, upstream.idx, upstream.host, upstream.port },
            );
        }
        runtime.strategy.recordFailure(upstream.idx);
        return;
    };
    defer connect_result.conn.close();

    runtime.strategy.recordSuccess(upstream.idx);
    log.info(
        "event=tcp_tunnel_established upstream_idx={d} upstream_host={s} upstream_port={d}",
        .{ upstream.idx, upstream.host, upstream.port },
    );

    const poll_timeout_ms_u32: u32 = @max(@as(u32, 1), @min(runtime.transport_cfg.idle_timeout_ms, 1000));
    const idle_timeout_ns = time.millisToNanos(@intCast(runtime.transport_cfg.idle_timeout_ms));
    const tunnel_stats = tunnel.relayWithConfig(
        io,
        &downstream_socket,
        &connect_result.conn.socket,
        "",
        "",
        idle_timeout_ns,
        @intCast(poll_timeout_ms_u32),
    );

    _ = runtime.upstream_bytes.fetchAdd(tunnel_stats.client_to_upstream_bytes, .monotonic);
    _ = runtime.downstream_bytes.fetchAdd(tunnel_stats.upstream_to_client_bytes, .monotonic);
    if (tunnel_stats.termination == .idle_timeout) {
        const timeout_count = runtime.timeout_closures.fetchAdd(1, .monotonic) + 1;
        if (shouldLogSampled(timeout_count, timeout_closure_log_sample_interval)) {
            log.warn(
                "event=tcp_tunnel_idle_timeout count={d} upstream_idx={d}",
                .{ timeout_count, upstream.idx },
            );
        }
    }

    log.info(
        "event=tcp_tunnel_closed upstream_idx={d} term={s} bytes_up={d} bytes_down={d}",
        .{
            upstream.idx,
            @tagName(tunnel_stats.termination),
            tunnel_stats.client_to_upstream_bytes,
            tunnel_stats.upstream_to_client_bytes,
        },
    );
}

fn buildUpstream(target: L4Target, tls_mode: TcpTlsMode, idx: UpstreamIndex) Upstream {
    assert(target.host.len > 0);
    assert(target.port > 0);

    const tls_enabled = switch (tls_mode) {
        .passthrough => target.tls,
        .originate_tls => true,
    };

    return .{
        .host = target.host,
        .port = target.port,
        .idx = idx,
        .tls = tls_enabled,
        .http_protocol = .h1,
    };
}

fn timeoutForMilliseconds(timeout_ms: u32) Io.Timeout {
    assert(timeout_ms > 0);

    return .{ .duration = .{
        .raw = Io.Duration.fromMilliseconds(@intCast(timeout_ms)),
        .clock = .awake,
    } };
}

fn shouldLogSampled(counter: u64, interval: u64) bool {
    assert(counter > 0);
    assert(interval > 0);
    return counter % interval == 0;
}

test "buildUpstream respects tls mode" {
    const plain_target = L4Target{ .host = "upstream", .port = 9000, .tls = false };
    const passthrough_plain = buildUpstream(plain_target, .passthrough, 0);
    try std.testing.expect(!passthrough_plain.tls);

    const tls_target = L4Target{ .host = "upstream", .port = 9000, .tls = true };
    const passthrough_tls = buildUpstream(tls_target, .passthrough, 1);
    try std.testing.expect(passthrough_tls.tls);

    const originated_tls = buildUpstream(plain_target, .originate_tls, 2);
    try std.testing.expect(originated_tls.tls);
}

test "timeoutForMilliseconds builds awake duration timeout" {
    const timeout = timeoutForMilliseconds(250);
    switch (timeout) {
        .duration => |duration| {
            try std.testing.expect(duration.clock == .awake);
            try std.testing.expectEqual(Io.Duration.fromMilliseconds(250), duration.raw);
        },
        else => return error.TestExpectedEqual,
    }
}

test "shouldLogSampled logs only at interval boundaries" {
    try std.testing.expect(!shouldLogSampled(1, 16));
    try std.testing.expect(!shouldLogSampled(15, 16));
    try std.testing.expect(shouldLogSampled(16, 16));
    try std.testing.expect(shouldLogSampled(32, 16));
}

test "tryAcquireSlot enforces max concurrent connections" {
    const targets = [_]L4Target{.{ .host = "127.0.0.1", .port = 9000 }};
    var runtime: Runtime = undefined;

    try runtime.init(
        .{
            .enabled = true,
            .listener_host = "127.0.0.1",
            .listener_port = 7000,
            .upstreams = &targets,
            .max_concurrent_connections = 1,
        },
        .{},
        null,
        true,
    );

    try std.testing.expect(runtime.tryAcquireSlot());
    try std.testing.expectEqual(@as(u64, 1), runtime.acceptedCount());
    try std.testing.expect(!runtime.tryAcquireSlot());
    try std.testing.expectEqual(@as(u64, 1), runtime.rejectedCount());
    runtime.releaseSlot();
    try std.testing.expectEqual(@as(u32, 0), runtime.activeCount());
}

test "tcp runtime telemetry counters initialize to zero" {
    const targets = [_]L4Target{.{ .host = "127.0.0.1", .port = 9000 }};
    var runtime: Runtime = undefined;

    try runtime.init(
        .{
            .enabled = true,
            .listener_host = "127.0.0.1",
            .listener_port = 7000,
            .upstreams = &targets,
            .max_concurrent_connections = 1,
        },
        .{},
        null,
        true,
    );

    try std.testing.expectEqual(@as(u64, 0), runtime.connectFailureCount());
    try std.testing.expectEqual(@as(u64, 0), runtime.timeoutClosureCount());
    try std.testing.expectEqual(@as(u64, 0), runtime.upstreamBytes());
    try std.testing.expectEqual(@as(u64, 0), runtime.downstreamBytes());
}
