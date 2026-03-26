//! UDP transport runtime primitives.
//!
//! Provides datagram-preserving ingress/egress forwarding using bounded
//! per-session upstream sockets and shared strategy selection.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const core_config = serval_core.config;
const core_types = serval_core.types;
const log = serval_core.log.scoped(.udp_runtime);
const serval_net = @import("serval-net");
const serval_lb = @import("serval-lb");

const UdpTransportConfig = core_config.UdpTransportConfig;
const L4Target = core_config.L4Target;
const Upstream = core_types.Upstream;
const UpstreamIndex = core_config.UpstreamIndex;
const UdpSessionKeyMode = core_config.UdpSessionKeyMode;
const DnsConfig = serval_net.DnsConfig;
const DnsResolver = serval_net.DnsResolver;
const RoundRobinStrategy = serval_lb.RoundRobinStrategy;
const StrategyConfig = serval_lb.StrategyConfig;

const session_read_timeout_ms: u32 = 100;
const session_datagram_buffer_bytes: u32 = 2048;
const max_sessions_expired_per_sweep: u32 = 256;
const session_capacity_log_sample_interval: u64 = 64;
const datagram_drop_log_sample_interval: u64 = 64;
const forwarding_error_log_sample_interval: u64 = 32;
const session_create_log_sample_interval: u64 = 128;

const SessionKey = struct {
    mode: UdpSessionKeyMode,
    protocol: u8,
    src_family: u8,
    src_bytes: [16]u8,
    src_port: u16,
    dst_family: u8,
    dst_bytes: [16]u8,
    dst_port: u16,
};

const EndpointFields = struct {
    family: u8,
    bytes: [16]u8,
    port: u16,
};

const Session = struct {
    client_addr: Io.net.IpAddress,
    upstream_addr: Io.net.IpAddress,
    upstream_idx: UpstreamIndex,
    socket: Io.net.Socket,
    last_activity_ns: std.atomic.Value(u64),
    refs: std.atomic.Value(u32),
    close_requested: std.atomic.Value(bool),
    closed: std.atomic.Value(bool),
};

pub const RuntimeError = error{
    InvalidConfig,
    InvalidAddress,
    BindFailed,
    DnsResolutionFailed,
};

pub const Runtime = struct {
    transport_cfg: UdpTransportConfig,
    upstream_storage: [core_config.MAX_UPSTREAMS]Upstream,
    upstreams: []const Upstream,
    upstream_addr_storage: [core_config.MAX_UPSTREAMS]Io.net.IpAddress,
    upstream_addrs: []const Io.net.IpAddress,
    strategy: RoundRobinStrategy,
    dns_resolver: DnsResolver,
    sessions: std.AutoHashMapUnmanaged(SessionKey, *Session),
    packets_received: std.atomic.Value(u64),
    packets_forwarded_upstream: std.atomic.Value(u64),
    packets_forwarded_downstream: std.atomic.Value(u64),
    packets_dropped: std.atomic.Value(u64),
    session_creations: std.atomic.Value(u64),
    session_expirations: std.atomic.Value(u64),
    upstream_forward_errors: std.atomic.Value(u64),
    drop_session_capacity: std.atomic.Value(u64),
    drop_ingress_truncated: std.atomic.Value(u64),
    drop_egress_truncated: std.atomic.Value(u64),
    drop_session_create_failed: std.atomic.Value(u64),

    const Self = @This();

    pub fn init(self: *Self, transport_cfg: UdpTransportConfig, dns_cfg: DnsConfig) RuntimeError!void {
        assert(@intFromPtr(self) != 0);
        assert(transport_cfg.enabled);

        if (transport_cfg.listener_host.len == 0) return error.InvalidConfig;
        if (transport_cfg.listener_port == 0) return error.InvalidConfig;
        if (transport_cfg.upstreams.len == 0) return error.InvalidConfig;
        if (transport_cfg.upstreams.len > core_config.MAX_UPSTREAMS) return error.InvalidConfig;
        if (transport_cfg.max_active_sessions == 0) return error.InvalidConfig;

        self.* = .{
            .transport_cfg = transport_cfg,
            .upstream_storage = undefined,
            .upstreams = &.{},
            .upstream_addr_storage = undefined,
            .upstream_addrs = &.{},
            .strategy = undefined,
            .dns_resolver = undefined,
            .sessions = .{},
            .packets_received = std.atomic.Value(u64).init(0),
            .packets_forwarded_upstream = std.atomic.Value(u64).init(0),
            .packets_forwarded_downstream = std.atomic.Value(u64).init(0),
            .packets_dropped = std.atomic.Value(u64).init(0),
            .session_creations = std.atomic.Value(u64).init(0),
            .session_expirations = std.atomic.Value(u64).init(0),
            .upstream_forward_errors = std.atomic.Value(u64).init(0),
            .drop_session_capacity = std.atomic.Value(u64).init(0),
            .drop_ingress_truncated = std.atomic.Value(u64).init(0),
            .drop_egress_truncated = std.atomic.Value(u64).init(0),
            .drop_session_create_failed = std.atomic.Value(u64).init(0),
        };

        DnsResolver.init(&self.dns_resolver, dns_cfg);

        var idx: usize = 0;
        while (idx < transport_cfg.upstreams.len) : (idx += 1) {
            const target = transport_cfg.upstreams[idx];
            if (target.host.len == 0 or target.port == 0) return error.InvalidConfig;
            self.upstream_storage[idx] = buildUpstream(target, @intCast(idx));
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

        try self.resolveUpstreamAddresses(io);

        const listen_addr = Io.net.IpAddress.parse(self.transport_cfg.listener_host, self.transport_cfg.listener_port) catch {
            return error.InvalidAddress;
        };

        var listener_socket = listen_addr.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch return error.BindFailed;
        defer listener_socket.close(io);

        if (listener_fd_out) |fd_out| {
            fd_out.store(@intCast(listener_socket.handle), .release);
        }
        defer if (listener_fd_out) |fd_out| {
            fd_out.store(-1, .release);
        };

        var group: Io.Group = .init;
        defer {
            group.cancel(io);
            group.await(io) catch |err| {
                log.warn("udp runtime: session group await failed: {s}", .{@errorName(err)});
            };
            self.closeAllSessions(io);
            self.sessions.deinit(std.heap.page_allocator);
        }

        var datagram_buf: [session_datagram_buffer_bytes]u8 = undefined;
        const timeout = timeoutForMilliseconds(session_read_timeout_ms);
        const idle_timeout_ns = serval_core.time.millisToNanos(@intCast(self.transport_cfg.session_idle_timeout_ms));

        while (!shutdown.load(.acquire)) {
            const message = listener_socket.receiveTimeout(io, &datagram_buf, timeout) catch |err| {
                
                switch (err) {
                    error.Timeout => {
                        self.sweepExpiredSessions(io, idle_timeout_ns);
                        continue;
                    },
                    else => {
                        log.warn("udp runtime: receive failed: {s}", .{@errorName(err)});
                        self.sweepExpiredSessions(io, idle_timeout_ns);
                        continue;
                    },
                }
            };

            _ = self.packets_received.fetchAdd(1, .monotonic);

            if (message.flags.trunc) {
                const truncated_count = self.drop_ingress_truncated.fetchAdd(1, .monotonic) + 1;
                const dropped_count = self.packets_dropped.fetchAdd(1, .monotonic) + 1;
                if (shouldLogSampled(truncated_count, datagram_drop_log_sample_interval)) {
                    const client = endpointFields(message.from);
                    log.warn(
                        "event=udp_drop_ingress_truncated truncated_count={d} dropped_count={d} client_family={d} client_port={d} client_prefix={d}.{d}",
                        .{ truncated_count, dropped_count, client.family, client.port, client.bytes[0], client.bytes[1] },
                    );
                }
                self.sweepExpiredSessions(io, idle_timeout_ns);
                continue;
            }

            self.forwardIngressDatagram(io, &group, shutdown, &listener_socket, listen_addr, message.from, message.data);
            self.sweepExpiredSessions(io, idle_timeout_ns);
        }
    }

    pub fn packetsReceived(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.packets_received.load(.acquire);
    }

    pub fn packetsForwardedUpstream(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.packets_forwarded_upstream.load(.acquire);
    }

    pub fn packetsForwardedDownstream(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.packets_forwarded_downstream.load(.acquire);
    }

    pub fn packetsDropped(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.packets_dropped.load(.acquire);
    }

    pub fn activeSessionCount(self: *const Self) u32 {
        assert(@intFromPtr(self) != 0);
        assert(self.sessions.count() <= std.math.maxInt(u32));
        return @intCast(self.sessions.count());
    }

    pub fn sessionCreationCount(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.session_creations.load(.acquire);
    }

    pub fn sessionExpirationCount(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.session_expirations.load(.acquire);
    }

    pub fn upstreamForwardErrorCount(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.upstream_forward_errors.load(.acquire);
    }

    pub fn droppedAtSessionCapacity(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.drop_session_capacity.load(.acquire);
    }

    pub fn droppedIngressTruncated(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.drop_ingress_truncated.load(.acquire);
    }

    pub fn droppedEgressTruncated(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.drop_egress_truncated.load(.acquire);
    }

    pub fn droppedSessionCreateFailed(self: *const Self) u64 {
        assert(@intFromPtr(self) != 0);
        return self.drop_session_create_failed.load(.acquire);
    }

    fn forwardIngressDatagram(
        self: *Self,
        io: Io,
        group: *Io.Group,
        shutdown: *std.atomic.Value(bool),
        listener_socket: *Io.net.Socket,
        listener_addr: Io.net.IpAddress,
        client_addr: Io.net.IpAddress,
        payload: []const u8,
    ) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(group) != 0);
        assert(@intFromPtr(shutdown) != 0);
        assert(@intFromPtr(listener_socket) != 0);
        assert(payload.len > 0);

        const key = makeSessionKey(self.transport_cfg.session_key_mode, client_addr, listener_addr);
        if (self.sessions.get(key)) |session| {
            session.socket.send(io, &session.upstream_addr, payload) catch {
                const forwarding_error_count = self.upstream_forward_errors.fetchAdd(1, .monotonic) + 1;
                const dropped_count = self.packets_dropped.fetchAdd(1, .monotonic) + 1;
                if (shouldLogSampled(forwarding_error_count, forwarding_error_log_sample_interval)) {
                    const client = endpointFields(client_addr);
                    log.warn(
                        "event=udp_forward_ingress_failed count={d} dropped_count={d} upstream_idx={d} client_family={d} client_port={d}",
                        .{ forwarding_error_count, dropped_count, session.upstream_idx, client.family, client.port },
                    );
                }
                self.strategy.recordFailure(session.upstream_idx);
                return;
            };
            touchSession(session);
            _ = self.packets_forwarded_upstream.fetchAdd(1, .monotonic);
            self.strategy.recordSuccess(session.upstream_idx);
            return;
        }

        if (self.sessions.count() >= self.transport_cfg.max_active_sessions) {
            const capacity_drop_count = self.drop_session_capacity.fetchAdd(1, .monotonic) + 1;
            const dropped_count = self.packets_dropped.fetchAdd(1, .monotonic) + 1;
            if (shouldLogSampled(capacity_drop_count, session_capacity_log_sample_interval)) {
                const client = endpointFields(client_addr);
                log.warn(
                    "event=udp_drop_session_capacity count={d} dropped_count={d} active_sessions={d} limit={d} client_family={d} client_port={d}",
                    .{
                        capacity_drop_count,
                        dropped_count,
                        self.sessions.count(),
                        self.transport_cfg.max_active_sessions,
                        client.family,
                        client.port,
                    },
                );
            }
            return;
        }

        const upstream = self.strategy.select();
        assert(upstream.idx < self.upstream_addrs.len);

        const session = self.createSession(io, client_addr, upstream.idx) catch {
            _ = self.drop_session_create_failed.fetchAdd(1, .monotonic);
            _ = self.upstream_forward_errors.fetchAdd(1, .monotonic);
            _ = self.packets_dropped.fetchAdd(1, .monotonic);
            self.strategy.recordFailure(upstream.idx);
            return;
        };

        self.sessions.put(std.heap.page_allocator, key, session) catch {
            _ = self.drop_session_create_failed.fetchAdd(1, .monotonic);
            _ = self.upstream_forward_errors.fetchAdd(1, .monotonic);
            _ = self.packets_dropped.fetchAdd(1, .monotonic);
            closeSessionSocket(session, io);
            releaseSessionRef(session);
            self.strategy.recordFailure(upstream.idx);
            return;
        };

        _ = session.refs.fetchAdd(1, .acq_rel);
        group.concurrent(io, sessionEgressLoop, .{
            listener_socket,
            shutdown,
            session,
            &self.drop_egress_truncated,
            &self.packets_forwarded_downstream,
            &self.packets_dropped,
            &self.upstream_forward_errors,
            io,
        }) catch {
            _ = self.drop_session_create_failed.fetchAdd(1, .monotonic);
            _ = self.upstream_forward_errors.fetchAdd(1, .monotonic);
            _ = self.packets_dropped.fetchAdd(1, .monotonic);
            releaseSessionRef(session);
            if (self.sessions.fetchRemove(key)) |removed| {
                closeSessionSocket(removed.value, io);
                releaseSessionRef(removed.value);
            }
            self.strategy.recordFailure(upstream.idx);
            return;
        };

        const session_creation_count = self.session_creations.fetchAdd(1, .monotonic) + 1;
        if (shouldLogSampled(session_creation_count, session_create_log_sample_interval)) {
            const client = endpointFields(client_addr);
            log.info(
                "event=udp_session_created count={d} upstream_idx={d} client_family={d} client_port={d}",
                .{ session_creation_count, upstream.idx, client.family, client.port },
            );
        }

        session.socket.send(io, &session.upstream_addr, payload) catch {
            const forwarding_error_count = self.upstream_forward_errors.fetchAdd(1, .monotonic) + 1;
            const dropped_count = self.packets_dropped.fetchAdd(1, .monotonic) + 1;
            if (shouldLogSampled(forwarding_error_count, forwarding_error_log_sample_interval)) {
                const client = endpointFields(client_addr);
                log.warn(
                    "event=udp_forward_new_session_failed count={d} dropped_count={d} upstream_idx={d} client_family={d} client_port={d}",
                    .{ forwarding_error_count, dropped_count, upstream.idx, client.family, client.port },
                );
            }
            self.strategy.recordFailure(upstream.idx);
            return;
        };
        touchSession(session);
        _ = self.packets_forwarded_upstream.fetchAdd(1, .monotonic);
        self.strategy.recordSuccess(upstream.idx);
    }

    fn createSession(self: *Self, io: Io, client_addr: Io.net.IpAddress, upstream_idx: UpstreamIndex) error{ OutOfMemory, BindFailed }!*Session {
        assert(@intFromPtr(self) != 0);
        assert(upstream_idx < self.upstream_addrs.len);

        const upstream_addr = self.upstream_addrs[upstream_idx];
        const bind_addr = bindAddressFor(upstream_addr);
        var upstream_socket = bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch return error.BindFailed;

        const session = std.heap.page_allocator.create(Session) catch {
            upstream_socket.close(io);
            return error.OutOfMemory;
        };

        const now_ns = serval_core.time.monotonicNanos();
        session.* = .{
            .client_addr = client_addr,
            .upstream_addr = upstream_addr,
            .upstream_idx = upstream_idx,
            .socket = upstream_socket,
            .last_activity_ns = std.atomic.Value(u64).init(now_ns),
            .refs = std.atomic.Value(u32).init(1),
            .close_requested = std.atomic.Value(bool).init(false),
            .closed = std.atomic.Value(bool).init(false),
        };

        return session;
    }

    fn closeAllSessions(self: *Self, io: Io) void {
        assert(@intFromPtr(self) != 0);

        var iter = self.sessions.valueIterator();
        while (iter.next()) |entry_ptr| {
            const session = entry_ptr.*;
            closeSessionSocket(session, io);
            releaseSessionRef(session);
        }
        self.sessions.clearRetainingCapacity();
    }

    fn sweepExpiredSessions(self: *Self, io: Io, idle_timeout_ns: u64) void {
        _ = io;
        assert(@intFromPtr(self) != 0);
        assert(idle_timeout_ns > 0);

        const now_ns = serval_core.time.monotonicNanos();
        var expired_keys: [max_sessions_expired_per_sweep]SessionKey = undefined;
        var expired_count: u32 = 0;

        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            if (expired_count >= max_sessions_expired_per_sweep) break;

            const session = entry.value_ptr.*;
            if (sessionExpired(session, now_ns, idle_timeout_ns)) {
                expired_keys[expired_count] = entry.key_ptr.*;
                expired_count += 1;
            }
        }

        var idx: u32 = 0;
        while (idx < expired_count) : (idx += 1) {
            const key = expired_keys[idx];
            if (self.sessions.fetchRemove(key)) |removed| {
                _ = self.session_expirations.fetchAdd(1, .monotonic);
                requestSessionClose(removed.value);
                releaseSessionRef(removed.value);
            }
        }
    }

    fn resolveUpstreamAddresses(self: *Self, io: Io) RuntimeError!void {
        assert(@intFromPtr(self) != 0);

        var idx: usize = 0;
        while (idx < self.upstreams.len) : (idx += 1) {
            const upstream = self.upstreams[idx];
            const resolve = self.dns_resolver.resolve(upstream.host, upstream.port, io) catch {
                return error.DnsResolutionFailed;
            };
            self.upstream_addr_storage[idx] = resolve.address;
        }

        self.upstream_addrs = self.upstream_addr_storage[0..self.upstreams.len];
    }
};

fn sessionEgressLoop(
    listener_socket: *Io.net.Socket,
    shutdown: *std.atomic.Value(bool),
    session: *Session,
    drop_egress_truncated: *std.atomic.Value(u64),
    packets_forwarded_downstream: *std.atomic.Value(u64),
    packets_dropped: *std.atomic.Value(u64),
    upstream_forward_errors: *std.atomic.Value(u64),
    io: Io,
) void {
    assert(@intFromPtr(listener_socket) != 0);
    assert(@intFromPtr(shutdown) != 0);
    assert(@intFromPtr(session) != 0);
    assert(@intFromPtr(drop_egress_truncated) != 0);
    assert(@intFromPtr(packets_forwarded_downstream) != 0);
    assert(@intFromPtr(packets_dropped) != 0);
    assert(@intFromPtr(upstream_forward_errors) != 0);

    defer releaseSessionRef(session);

    var datagram_buf: [session_datagram_buffer_bytes]u8 = undefined;
    const timeout = timeoutForMilliseconds(session_read_timeout_ms);

    while (!shutdown.load(.acquire)) {
        if (session.close_requested.load(.acquire)) {
            closeSessionSocket(session, io);
            return;
        }

        const message = session.socket.receiveTimeout(io, &datagram_buf, timeout) catch |err| {
            switch (err) {
                error.Timeout => continue,
                error.Canceled => return,
                error.SocketUnconnected => return,
                else => {
                    const forwarding_error_count = upstream_forward_errors.fetchAdd(1, .monotonic) + 1;
                    if (shouldLogSampled(forwarding_error_count, forwarding_error_log_sample_interval)) {
                        const client = endpointFields(session.client_addr);
                        log.warn(
                            "event=udp_session_receive_failed count={d} error={s} client_family={d} client_port={d}",
                            .{ forwarding_error_count, @errorName(err), client.family, client.port },
                        );
                    }
                    continue;
                },
            }
        };

        if (message.flags.trunc) {
            const truncated_count = drop_egress_truncated.fetchAdd(1, .monotonic) + 1;
            const dropped_count = packets_dropped.fetchAdd(1, .monotonic) + 1;
            if (shouldLogSampled(truncated_count, datagram_drop_log_sample_interval)) {
                const client = endpointFields(session.client_addr);
                log.warn(
                    "event=udp_drop_egress_truncated truncated_count={d} dropped_count={d} client_family={d} client_port={d}",
                    .{ truncated_count, dropped_count, client.family, client.port },
                );
            }
            continue;
        }

        listener_socket.send(io, &session.client_addr, message.data) catch |err| {
            const forwarding_error_count = upstream_forward_errors.fetchAdd(1, .monotonic) + 1;
            const dropped_count = packets_dropped.fetchAdd(1, .monotonic) + 1;
            if (shouldLogSampled(forwarding_error_count, forwarding_error_log_sample_interval)) {
                const client = endpointFields(session.client_addr);
                log.warn(
                    "event=udp_session_send_failed count={d} dropped_count={d} error={s} client_family={d} client_port={d}",
                    .{ forwarding_error_count, dropped_count, @errorName(err), client.family, client.port },
                );
            }
            continue;
        };

        _ = packets_forwarded_downstream.fetchAdd(1, .monotonic);
        touchSession(session);
    }
}

fn touchSession(session: *Session) void {
    assert(@intFromPtr(session) != 0);

    const now_ns = serval_core.time.monotonicNanos();
    session.last_activity_ns.store(now_ns, .release);
}

fn sessionExpired(session: *Session, now_ns: u64, idle_timeout_ns: u64) bool {
    assert(@intFromPtr(session) != 0);
    assert(now_ns > 0);
    assert(idle_timeout_ns > 0);

    const last_ns = session.last_activity_ns.load(.acquire);
    return serval_core.time.elapsedNanos(last_ns, now_ns) >= idle_timeout_ns;
}

fn requestSessionClose(session: *Session) void {
    assert(@intFromPtr(session) != 0);
    session.close_requested.store(true, .release);
}

fn closeSessionSocket(session: *Session, io: Io) void {
    assert(@intFromPtr(session) != 0);

    if (session.closed.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
        session.socket.close(io);
    }
}

fn releaseSessionRef(session: *Session) void {
    assert(@intFromPtr(session) != 0);

    const previous = session.refs.fetchSub(1, .acq_rel);
    assert(previous > 0);
    if (previous == 1) {
        std.heap.page_allocator.destroy(session);
    }
}

fn buildUpstream(target: L4Target, idx: UpstreamIndex) Upstream {
    assert(target.host.len > 0);
    assert(target.port > 0);

    return .{
        .host = target.host,
        .port = target.port,
        .idx = idx,
        .tls = false,
        .http_protocol = .h1,
    };
}

fn makeSessionKey(mode: UdpSessionKeyMode, source_addr: Io.net.IpAddress, destination_addr: Io.net.IpAddress) SessionKey {
    const source = endpointFields(source_addr);
    const destination = endpointFields(destination_addr);

    var key: SessionKey = .{
        .mode = mode,
        .protocol = 17,
        .src_family = source.family,
        .src_bytes = source.bytes,
        .src_port = source.port,
        .dst_family = destination.family,
        .dst_bytes = destination.bytes,
        .dst_port = destination.port,
    };

    switch (mode) {
        .five_tuple => {},
        .source_endpoint => {
            key.dst_family = 0;
            key.dst_bytes = [_]u8{0} ** 16;
            key.dst_port = 0;
        },
        .source_ip => {
            key.src_port = 0;
            key.dst_family = 0;
            key.dst_bytes = [_]u8{0} ** 16;
            key.dst_port = 0;
        },
    }

    return key;
}

fn endpointFields(addr: Io.net.IpAddress) EndpointFields {
    return switch (addr) {
        .ip4 => |ip4| blk: {
            var bytes: [16]u8 = [_]u8{0} ** 16;
            bytes[0] = ip4.bytes[0];
            bytes[1] = ip4.bytes[1];
            bytes[2] = ip4.bytes[2];
            bytes[3] = ip4.bytes[3];
            break :blk .{ .family = 4, .bytes = bytes, .port = ip4.port };
        },
        .ip6 => |ip6| .{ .family = 6, .bytes = ip6.bytes, .port = ip6.port },
    };
}

fn bindAddressFor(addr: Io.net.IpAddress) Io.net.IpAddress {
    return switch (addr) {
        .ip4 => .{ .ip4 = Io.net.Ip4Address.unspecified(0) },
        .ip6 => .{ .ip6 = Io.net.Ip6Address.unspecified(0) },
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

test "buildUpstream for udp disables tls" {
    const upstream = buildUpstream(.{ .host = "up", .port = 8053, .tls = true }, 0);
    try std.testing.expect(!upstream.tls);
}

test "makeSessionKey differentiates address family" {
    const src4 = Io.net.IpAddress.parse("127.0.0.1", 8080) catch unreachable;
    const dst4 = Io.net.IpAddress.parse("10.0.0.1", 7000) catch unreachable;
    const src6 = Io.net.IpAddress.parse("::1", 8080) catch unreachable;
    const dst6 = Io.net.IpAddress.parse("2001:db8::1", 7000) catch unreachable;

    const k4 = makeSessionKey(.five_tuple, src4, dst4);
    const k6 = makeSessionKey(.five_tuple, src6, dst6);

    try std.testing.expect(k4.src_family == 4);
    try std.testing.expect(k6.src_family == 6);
}

test "makeSessionKey mode controls grouping" {
    const src_a = Io.net.IpAddress.parse("127.0.0.1", 10001) catch unreachable;
    const src_b = Io.net.IpAddress.parse("127.0.0.1", 10002) catch unreachable;
    const dst = Io.net.IpAddress.parse("0.0.0.0", 7001) catch unreachable;

    const five_a = makeSessionKey(.five_tuple, src_a, dst);
    const five_b = makeSessionKey(.five_tuple, src_b, dst);
    try std.testing.expect(five_a.src_port != five_b.src_port);

    const src_ip_a = makeSessionKey(.source_ip, src_a, dst);
    const src_ip_b = makeSessionKey(.source_ip, src_b, dst);
    try std.testing.expectEqual(src_ip_a, src_ip_b);

    const src_ep_a = makeSessionKey(.source_endpoint, src_a, dst);
    const src_ep_b = makeSessionKey(.source_endpoint, src_b, dst);
    try std.testing.expect(src_ep_a != src_ep_b);
}

test "shouldLogSampled logs only at interval boundaries" {
    try std.testing.expect(!shouldLogSampled(1, 32));
    try std.testing.expect(!shouldLogSampled(31, 32));
    try std.testing.expect(shouldLogSampled(32, 32));
    try std.testing.expect(shouldLogSampled(64, 32));
}

test "udp runtime telemetry counters initialize to zero" {
    const upstreams = [_]L4Target{.{ .host = "127.0.0.1", .port = 9001 }};
    var runtime: Runtime = undefined;

    try runtime.init(
        .{
            .enabled = true,
            .listener_host = "127.0.0.1",
            .listener_port = 7001,
            .upstreams = &upstreams,
            .max_active_sessions = 1,
        },
        .{},
    );

    try std.testing.expectEqual(@as(u64, 0), runtime.packetsReceived());
    try std.testing.expectEqual(@as(u64, 0), runtime.packetsForwardedUpstream());
    try std.testing.expectEqual(@as(u64, 0), runtime.packetsForwardedDownstream());
    try std.testing.expectEqual(@as(u64, 0), runtime.packetsDropped());
    try std.testing.expectEqual(@as(u32, 0), runtime.activeSessionCount());
    try std.testing.expectEqual(@as(u64, 0), runtime.sessionCreationCount());
    try std.testing.expectEqual(@as(u64, 0), runtime.sessionExpirationCount());
    try std.testing.expectEqual(@as(u64, 0), runtime.upstreamForwardErrorCount());

    try std.testing.expectEqual(@as(u64, 0), runtime.droppedAtSessionCapacity());
    try std.testing.expectEqual(@as(u64, 0), runtime.droppedIngressTruncated());
    try std.testing.expectEqual(@as(u64, 0), runtime.droppedEgressTruncated());
    try std.testing.expectEqual(@as(u64, 0), runtime.droppedSessionCreateFailed());
}

test "udp runtime expires idle sessions and reclaims map entry" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const upstreams = [_]L4Target{.{ .host = "127.0.0.1", .port = 9001 }};
    var runtime: Runtime = undefined;
    try runtime.init(
        .{
            .enabled = true,
            .listener_host = "127.0.0.1",
            .listener_port = 7001,
            .upstreams = &upstreams,
            .max_active_sessions = 4,
            .session_idle_timeout_ms = 1,
        },
        .{},
    );
    defer {
        runtime.closeAllSessions(evented.io());
        runtime.sessions.deinit(std.heap.page_allocator);
    }

    runtime.upstream_addr_storage[0] = Io.net.IpAddress.parse("127.0.0.1", 9001) catch unreachable;
    runtime.upstream_addrs = runtime.upstream_addr_storage[0..1];

    const client_addr = Io.net.IpAddress.parse("127.0.0.1", 12000) catch unreachable;
    const listener_addr = Io.net.IpAddress.parse("127.0.0.1", 7001) catch unreachable;

    const session = try runtime.createSession(evented.io(), client_addr, 0);
    session.last_activity_ns.store(1, .release);

    const key = makeSessionKey(.five_tuple, client_addr, listener_addr);
    try runtime.sessions.put(std.heap.page_allocator, key, session);

    runtime.sweepExpiredSessions(evented.io(), serval_core.time.millisToNanos(1));

    try std.testing.expectEqual(@as(u32, 0), runtime.activeSessionCount());
    try std.testing.expectEqual(@as(u64, 1), runtime.sessionExpirationCount());
}

test "udp runtime drops new session at capacity without removing existing session" {
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const upstreams = [_]L4Target{.{ .host = "127.0.0.1", .port = 9001 }};
    var runtime: Runtime = undefined;
    try runtime.init(
        .{
            .enabled = true,
            .listener_host = "127.0.0.1",
            .listener_port = 7001,
            .upstreams = &upstreams,
            .max_active_sessions = 1,
        },
        .{},
    );
    defer {
        runtime.closeAllSessions(evented.io());
        runtime.sessions.deinit(std.heap.page_allocator);
    }

    runtime.upstream_addr_storage[0] = Io.net.IpAddress.parse("127.0.0.1", 9001) catch unreachable;
    runtime.upstream_addrs = runtime.upstream_addr_storage[0..1];

    const listener_addr = Io.net.IpAddress.parse("127.0.0.1", 7001) catch unreachable;
    const existing_client = Io.net.IpAddress.parse("127.0.0.1", 12001) catch unreachable;
    const new_client = Io.net.IpAddress.parse("127.0.0.1", 12002) catch unreachable;

    const session = try runtime.createSession(evented.io(), existing_client, 0);
    const existing_key = makeSessionKey(.five_tuple, existing_client, listener_addr);
    try runtime.sessions.put(std.heap.page_allocator, existing_key, session);

    var group: Io.Group = .init;
    defer group.cancel(evented.io());
    var shutdown = std.atomic.Value(bool).init(false);

    const bind_addr = Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    var listener_socket = try bind_addr.bind(evented.io(), .{ .mode = .dgram, .protocol = .udp });
    defer listener_socket.close(evented.io());

    runtime.forwardIngressDatagram(
        evented.io(),
        &group,
        &shutdown,
        &listener_socket,
        listener_addr,
        new_client,
        "payload",
    );

    try std.testing.expectEqual(@as(u64, 1), runtime.droppedAtSessionCapacity());
    try std.testing.expectEqual(@as(u64, 1), runtime.packetsDropped());
    try std.testing.expectEqual(@as(u32, 1), runtime.activeSessionCount());
}
