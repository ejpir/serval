//! HTTP/2 Upstream Session Pool
//!
//! Fixed-capacity cache of socket-owning outbound h2c sessions keyed by
//! upstream index. Wires `serval-client.Client.connect()` into outbound
//! preface/settings emission so callers can reuse upstream HTTP/2 sessions
//! while peer SETTINGS synchronization completes lazily during receive handling.
//! TigerStyle: Explicit state, fixed-size slots, bounded behavior, no runtime
//! allocation.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const posix = std.posix;

const core = @import("serval-core");
const config = core.config;
const time = core.time;
const types = core.types;

const net = @import("serval-net");
const pool_mod = @import("serval-pool");
const client_mod = @import("../client.zig");
const connection_mod = @import("connection.zig");
const runtime_mod = @import("runtime.zig");
const socket_mod = @import("serval-socket");

const Connection = pool_mod.Connection;
const Client = client_mod.Client;
const Upstream = types.Upstream;
const HttpProtocol = types.HttpProtocol;
const Socket = socket_mod.Socket;

const slot_count: usize = config.MAX_UPSTREAMS;

pub const Error = error{
    UnsupportedProtocol,
    UpstreamSessionPoolExhausted,
} || client_mod.ClientError || connection_mod.Error;

pub const ConnectStats = struct {
    reused: bool,
    dns_duration_ns: u64,
    tcp_connect_duration_ns: u64,
    tls_handshake_duration_ns: u64,
    local_port: u16,
};

pub const AcquireResult = struct {
    session: *UpstreamSession,
    connect: ConnectStats,
};

pub const UpstreamSession = struct {
    upstream_idx: config.UpstreamIndex,
    generation: u32,
    connection: Connection,
    h2: connection_mod.ClientConnection,
    last_used_ns: u64,

    pub fn sendRequestHeaders(
        self: *UpstreamSession,
        request: *const types.Request,
        effective_path: ?[]const u8,
        end_stream: bool,
    ) Error!u32 {
        assert(@intFromPtr(self) != 0);
        assert(request.path.len > 0);

        const stream_id = try self.h2.sendRequestHeaders(request, effective_path, end_stream);
        self.last_used_ns = time.monotonicNanos();
        return stream_id;
    }

    pub fn sendRequestData(
        self: *UpstreamSession,
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        try self.h2.sendRequestData(stream_id, payload, end_stream);
        self.last_used_ns = time.monotonicNanos();
    }

    pub fn sendStreamReset(self: *UpstreamSession, stream_id: u32, error_code_raw: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(stream_id > 0);

        try self.h2.sendStreamReset(stream_id, error_code_raw);
        self.last_used_ns = time.monotonicNanos();
    }

    pub fn receiveAction(self: *UpstreamSession) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);

        const action = try self.h2.receiveAction();
        self.last_used_ns = time.monotonicNanos();
        return action;
    }

    pub fn receiveActionTimeout(self: *UpstreamSession, io: Io, timeout: Io.Timeout) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);

        const action = try self.h2.receiveActionTimeout(io, timeout);
        self.last_used_ns = time.monotonicNanos();
        return action;
    }

    pub fn receiveActionHandlingControl(self: *UpstreamSession) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);

        const action = try self.h2.receiveActionHandlingControl();
        self.last_used_ns = time.monotonicNanos();
        return action;
    }

    pub fn receiveActionHandlingControlTimeout(self: *UpstreamSession, io: Io, timeout: Io.Timeout) Error!runtime_mod.ReceiveAction {
        assert(@intFromPtr(self) != 0);

        const action = try self.h2.receiveActionHandlingControlTimeout(io, timeout);
        self.last_used_ns = time.monotonicNanos();
        return action;
    }

    pub fn close(self: *UpstreamSession) void {
        assert(@intFromPtr(self) != 0);
        self.connection.close();
    }
};

const Slot = struct {
    upstream_port: u16 = 0,
    upstream_tls: bool = false,
    upstream_protocol: HttpProtocol = .h1,
    next_generation: u32 = 1,
    active_session: ?UpstreamSession = null,
    draining_session: ?UpstreamSession = null,
};

pub const UpstreamSessionPool = struct {
    slots: [slot_count]Slot = [_]Slot{.{}} ** slot_count,

    pub fn init() UpstreamSessionPool {
        return .{};
    }

    pub fn deinit(self: *UpstreamSessionPool) void {
        assert(@intFromPtr(self) != 0);
        self.closeAll();
    }

    pub fn acquireOrConnect(
        self: *UpstreamSessionPool,
        client: *Client,
        upstream: Upstream,
        io: Io,
    ) Error!AcquireResult {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(client) != 0);
        assert(upstream.port > 0);

        try validateUpstream(upstream);

        const slot_index: usize = @intCast(upstream.idx);
        assert(slot_index < slot_count);
        var slot = &self.slots[slot_index];

        if (slotHasAnySession(slot) and !slotMatchesUpstream(slot, upstream)) {
            closeSlot(slot);
        }

        cleanupUnusableSessions(slot);
        try rotateActiveSessionForRollover(slot);

        if (slot.active_session) |*existing| {
            if (sessionAcceptsNewStreams(existing)) {
                existing.last_used_ns = time.monotonicNanos();
                return .{
                    .session = existing,
                    .connect = .{
                        .reused = true,
                        .dns_duration_ns = 0,
                        .tcp_connect_duration_ns = 0,
                        .tls_handshake_duration_ns = 0,
                        .local_port = 0,
                    },
                };
            }
        }

        if (slot.draining_session) |*draining| {
            if (!sessionHasActiveStreams(draining) or sessionNeedsReconnect(draining)) {
                closeSession(&slot.draining_session);
            }
        }

        if (slot.active_session == null and slot.draining_session != null and !sessionHasActiveStreams(&slot.draining_session.?)) {
            closeSession(&slot.draining_session);
        }

        if (slot.active_session != null and slot.draining_session != null and
            sessionHasActiveStreams(&slot.active_session.?) and
            sessionHasActiveStreams(&slot.draining_session.?))
        {
            return error.UpstreamSessionPoolExhausted;
        }

        const connected = try client.connect(upstream, io);

        slot.upstream_port = upstream.port;
        slot.upstream_tls = upstream.tls;
        slot.upstream_protocol = upstream.http_protocol;

        if (slot.active_session != null) {
            if (slot.draining_session) |*draining| {
                if (!sessionHasActiveStreams(draining) or sessionNeedsReconnect(draining)) {
                    closeSession(&slot.draining_session);
                } else {
                    return error.UpstreamSessionPoolExhausted;
                }
            }
            slot.draining_session = slot.active_session;
            slot.active_session = null;
        }

        const generation = nextGeneration(slot);
        slot.active_session = .{
            .upstream_idx = upstream.idx,
            .generation = generation,
            .connection = connected.conn,
            .h2 = undefined,
            .last_used_ns = time.monotonicNanos(),
        };

        var session = &slot.active_session.?;
        errdefer {
            session.connection.close();
            slot.active_session = null;
        }

        session.h2 = try connection_mod.ClientConnection.init(&session.connection.socket);
        try session.h2.sendClientPrefaceAndSettings();
        session.last_used_ns = time.monotonicNanos();

        return .{
            .session = session,
            .connect = .{
                .reused = false,
                .dns_duration_ns = connected.dns_duration_ns,
                .tcp_connect_duration_ns = connected.tcp_connect_duration_ns,
                .tls_handshake_duration_ns = connected.tls_handshake_duration_ns,
                .local_port = connected.local_port,
            },
        };
    }

    pub fn get(self: *UpstreamSessionPool, upstream_idx: config.UpstreamIndex) ?*UpstreamSession {
        assert(@intFromPtr(self) != 0);

        const slot_index: usize = @intCast(upstream_idx);
        assert(slot_index < slot_count);

        const slot = &self.slots[slot_index];
        if (slot.active_session) |*active| return active;
        if (slot.draining_session) |*draining| return draining;
        return null;
    }

    pub fn getByGeneration(
        self: *UpstreamSessionPool,
        upstream_idx: config.UpstreamIndex,
        generation: u32,
    ) ?*UpstreamSession {
        assert(@intFromPtr(self) != 0);
        assert(generation > 0);

        const slot_index: usize = @intCast(upstream_idx);
        assert(slot_index < slot_count);

        const slot = &self.slots[slot_index];
        if (slot.active_session) |*active| {
            if (active.generation == generation) return active;
        }
        if (slot.draining_session) |*draining| {
            if (draining.generation == generation) return draining;
        }
        return null;
    }

    pub fn close(self: *UpstreamSessionPool, upstream_idx: config.UpstreamIndex) void {
        assert(@intFromPtr(self) != 0);

        const slot_index: usize = @intCast(upstream_idx);
        assert(slot_index < slot_count);
        closeSlot(&self.slots[slot_index]);
    }

    pub fn closeGeneration(self: *UpstreamSessionPool, upstream_idx: config.UpstreamIndex, generation: u32) void {
        assert(@intFromPtr(self) != 0);
        assert(generation > 0);

        const slot_index: usize = @intCast(upstream_idx);
        assert(slot_index < slot_count);
        var slot = &self.slots[slot_index];

        if (slot.active_session) |*active| {
            if (active.generation == generation) {
                closeSession(&slot.active_session);
            }
        }
        if (slot.draining_session) |*draining| {
            if (draining.generation == generation) {
                closeSession(&slot.draining_session);
            }
        }
    }

    pub fn closeAll(self: *UpstreamSessionPool) void {
        assert(@intFromPtr(self) != 0);

        var index: usize = 0;
        while (index < self.slots.len) : (index += 1) {
            closeSlot(&self.slots[index]);
        }
    }
};

fn validateUpstream(upstream: Upstream) Error!void {
    assert(upstream.port > 0);

    const supports_h2c_plain = upstream.http_protocol == .h2c and !upstream.tls;
    const supports_h2_tls = upstream.http_protocol == .h2 and upstream.tls;
    if (!supports_h2c_plain and !supports_h2_tls) return error.UnsupportedProtocol;
}

fn slotMatchesUpstream(slot: *const Slot, upstream: Upstream) bool {
    assert(@intFromPtr(slot) != 0);
    assert(upstream.port > 0);

    if (slot.upstream_port != upstream.port) return false;
    if (slot.upstream_tls != upstream.tls) return false;
    if (slot.upstream_protocol != upstream.http_protocol) return false;
    return true;
}

fn slotHasAnySession(slot: *const Slot) bool {
    assert(@intFromPtr(slot) != 0);
    return slot.active_session != null or slot.draining_session != null;
}

fn cleanupUnusableSessions(slot: *Slot) void {
    assert(@intFromPtr(slot) != 0);

    if (slot.active_session) |*active| {
        if (sessionNeedsReconnect(active)) {
            closeSession(&slot.active_session);
        }
    }

    if (slot.draining_session) |*draining| {
        if (sessionNeedsReconnect(draining)) {
            closeSession(&slot.draining_session);
        }
    }
}

fn rotateActiveSessionForRollover(slot: *Slot) Error!void {
    assert(@intFromPtr(slot) != 0);

    if (slot.active_session) |*active| {
        if (sessionAcceptsNewStreams(active)) return;

        if (!sessionHasActiveStreams(active)) {
            closeSession(&slot.active_session);
            return;
        }

        if (slot.draining_session) |*draining| {
            if (!sessionHasActiveStreams(draining) or sessionNeedsReconnect(draining)) {
                closeSession(&slot.draining_session);
            } else {
                return error.UpstreamSessionPoolExhausted;
            }
        }

        slot.draining_session = slot.active_session;
        slot.active_session = null;
    }
}

fn sessionHasActiveStreams(session: *const UpstreamSession) bool {
    assert(@intFromPtr(session) != 0);
    return session.h2.runtime.state.streams.active_count > 0;
}

fn sessionAcceptsNewStreams(session: *const UpstreamSession) bool {
    assert(@intFromPtr(session) != 0);

    if (sessionNeedsReconnect(session)) return false;

    const state = &session.h2.runtime.state;
    const next_stream_id = state.next_local_stream_id;
    return state.canOpenLocalStream(next_stream_id);
}

fn nextGeneration(slot: *Slot) u32 {
    assert(@intFromPtr(slot) != 0);

    const generation = slot.next_generation;
    if (slot.next_generation < std.math.maxInt(u32)) {
        slot.next_generation += 1;
    }
    if (generation == 0) return 1;
    return generation;
}

fn sessionNeedsReconnect(session: *const UpstreamSession) bool {
    assert(@intFromPtr(session) != 0);

    if (!session.h2.runtime.state.preface_sent) return true;

    if (session.h2.runtime.state.goaway_sent) return true;
    if (session.h2.runtime.state.goaway_received) {
        const next_stream_id = session.h2.runtime.state.next_local_stream_id;
        if (next_stream_id > session.h2.runtime.state.peer_goaway_last_stream_id and
            session.h2.runtime.state.streams.active_count == 0)
        {
            return true;
        }
    }

    if (session.h2.frame_count >= config.H2_CLIENT_MAX_FRAME_COUNT) return true;
    return sessionSocketHasTerminalPollState(session);
}

fn sessionSocketHasTerminalPollState(session: *const UpstreamSession) bool {
    assert(@intFromPtr(session) != 0);

    const fd = session.connection.socket.get_fd();
    if (fd < 0) return true;

    const terminal_flags = posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL;
    var poll_fds = [_]posix.pollfd{
        .{
            .fd = fd,
            .events = terminal_flags,
            .revents = 0,
        },
    };

    const polled = posix.poll(&poll_fds, 0) catch {
        return true;
    };
    if (polled == 0) return false;

    return (poll_fds[0].revents & terminal_flags) != 0;
}

fn closeSession(session: *?UpstreamSession) void {
    assert(@intFromPtr(session) != 0);

    if (session.*) |*inner| {
        inner.close();
    }
    session.* = null;
}

fn closeSlot(slot: *Slot) void {
    assert(@intFromPtr(slot) != 0);

    closeSession(&slot.active_session);
    closeSession(&slot.draining_session);
    slot.* = .{};
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

test "validateUpstream accepts h2c plaintext and h2 tls combinations" {
    const h2c_plain = Upstream{ .host = "127.0.0.1", .port = 8080, .idx = 0, .http_protocol = .h2c, .tls = false };
    try validateUpstream(h2c_plain);

    const h2_tls = Upstream{ .host = "127.0.0.1", .port = 8443, .idx = 1, .http_protocol = .h2, .tls = true };
    try validateUpstream(h2_tls);

    const h1_upstream = Upstream{ .host = "127.0.0.1", .port = 8081, .idx = 2, .http_protocol = .h1, .tls = false };
    try std.testing.expectError(error.UnsupportedProtocol, validateUpstream(h1_upstream));

    const h2c_tls = Upstream{ .host = "127.0.0.1", .port = 8444, .idx = 3, .http_protocol = .h2c, .tls = true };
    try std.testing.expectError(error.UnsupportedProtocol, validateUpstream(h2c_tls));

    const h2_plain = Upstream{ .host = "127.0.0.1", .port = 8082, .idx = 4, .http_protocol = .h2, .tls = false };
    try std.testing.expectError(error.UnsupportedProtocol, validateUpstream(h2_plain));
}

test "UpstreamSessionPool reuses healthy cached session" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[1]);

    var conn = Connection{
        .socket = Socket.Plain.init_client(fds[0]),
        .created_ns = time.monotonicNanos(),
        .last_used_ns = time.monotonicNanos(),
    };

    var h2_conn = try connection_mod.ClientConnection.init(&conn.socket);
    h2_conn.runtime.state.preface_sent = true;
    h2_conn.runtime.state.peer_settings_received = true;
    h2_conn.runtime.state.local_settings_ack_pending = false;
    h2_conn.runtime.state.peer_settings_ack_pending = false;

    var pool = UpstreamSessionPool.init();
    defer pool.deinit();

    const upstream_idx: config.UpstreamIndex = 5;
    const slot_index: usize = @intCast(upstream_idx);

    pool.slots[slot_index] = .{
        .upstream_port = 19000,
        .upstream_tls = false,
        .upstream_protocol = .h2c,
        .next_generation = 2,
        .active_session = .{
            .upstream_idx = upstream_idx,
            .generation = 1,
            .connection = conn,
            .h2 = h2_conn,
            .last_used_ns = time.monotonicNanos(),
        },
    };

    var dns_resolver: net.DnsResolver = undefined;
    net.DnsResolver.init(&dns_resolver, .{});
    var client = Client.init(std.testing.allocator, &dns_resolver, null, false);

    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();

    const upstream = Upstream{
        .host = "127.0.0.1",
        .port = 19000,
        .idx = upstream_idx,
        .tls = false,
        .http_protocol = .h2c,
    };

    const acquired = try pool.acquireOrConnect(&client, upstream, evented.io());
    try std.testing.expect(acquired.connect.reused);
    try std.testing.expectEqual(@as(u64, 0), acquired.connect.dns_duration_ns);
    try std.testing.expectEqual(@as(u64, 0), acquired.connect.tcp_connect_duration_ns);
    try std.testing.expectEqual(@as(usize, @intFromPtr(&pool.slots[slot_index].active_session.?)), @as(usize, @intFromPtr(acquired.session)));
}

test "sessionNeedsReconnect defers goaway reconnect while active streams remain" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[1]);

    var conn = Connection{
        .socket = Socket.Plain.init_client(fds[0]),
        .created_ns = time.monotonicNanos(),
        .last_used_ns = time.monotonicNanos(),
    };

    var h2_conn = try connection_mod.ClientConnection.init(&conn.socket);
    h2_conn.runtime.state.preface_sent = true;
    h2_conn.runtime.state.peer_settings_received = true;
    h2_conn.runtime.state.local_settings_ack_pending = false;
    h2_conn.runtime.state.peer_settings_ack_pending = false;

    _ = try h2_conn.runtime.state.openRequestStream(false);
    h2_conn.runtime.state.markGoAwayReceived(1);

    var session = UpstreamSession{
        .upstream_idx = 0,
        .generation = 1,
        .connection = conn,
        .h2 = h2_conn,
        .last_used_ns = time.monotonicNanos(),
    };
    defer session.connection.socket.close();

    try std.testing.expect(!sessionNeedsReconnect(&session));
}

test "sessionNeedsReconnect reconnects goaway session after active streams drain" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[1]);

    var conn = Connection{
        .socket = Socket.Plain.init_client(fds[0]),
        .created_ns = time.monotonicNanos(),
        .last_used_ns = time.monotonicNanos(),
    };

    var h2_conn = try connection_mod.ClientConnection.init(&conn.socket);
    h2_conn.runtime.state.preface_sent = true;
    h2_conn.runtime.state.peer_settings_received = true;
    h2_conn.runtime.state.local_settings_ack_pending = false;
    h2_conn.runtime.state.peer_settings_ack_pending = false;

    _ = try h2_conn.runtime.state.openRequestStream(true);
    try h2_conn.runtime.state.endRemoteStream(1);
    h2_conn.runtime.state.markGoAwayReceived(1);

    var session = UpstreamSession{
        .upstream_idx = 0,
        .generation = 1,
        .connection = conn,
        .h2 = h2_conn,
        .last_used_ns = time.monotonicNanos(),
    };
    defer session.connection.socket.close();

    try std.testing.expect(sessionNeedsReconnect(&session));
}

test "rotateActiveSessionForRollover keeps draining session for in-flight stream" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[1]);

    var conn = Connection{
        .socket = Socket.Plain.init_client(fds[0]),
        .created_ns = time.monotonicNanos(),
        .last_used_ns = time.monotonicNanos(),
    };

    var h2_conn = try connection_mod.ClientConnection.init(&conn.socket);
    h2_conn.runtime.state.preface_sent = true;
    h2_conn.runtime.state.peer_settings_received = true;
    h2_conn.runtime.state.local_settings_ack_pending = false;
    h2_conn.runtime.state.peer_settings_ack_pending = false;

    _ = try h2_conn.runtime.state.openRequestStream(false);
    h2_conn.runtime.state.markGoAwayReceived(1);

    var slot = Slot{
        .upstream_port = 19000,
        .upstream_tls = false,
        .upstream_protocol = .h2c,
        .next_generation = 2,
        .active_session = .{
            .upstream_idx = 0,
            .generation = 1,
            .connection = conn,
            .h2 = h2_conn,
            .last_used_ns = time.monotonicNanos(),
        },
    };
    defer closeSlot(&slot);

    try rotateActiveSessionForRollover(&slot);
    try std.testing.expect(slot.active_session == null);
    try std.testing.expect(slot.draining_session != null);
    try std.testing.expectEqual(@as(u32, 1), slot.draining_session.?.generation);
}

test "UpstreamSessionPool getByGeneration resolves active and draining sessions" {
    const active_fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(active_fds[1]);
    const draining_fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(draining_fds[1]);

    var active_conn = Connection{
        .socket = Socket.Plain.init_client(active_fds[0]),
        .created_ns = time.monotonicNanos(),
        .last_used_ns = time.monotonicNanos(),
    };
    var draining_conn = Connection{
        .socket = Socket.Plain.init_client(draining_fds[0]),
        .created_ns = time.monotonicNanos(),
        .last_used_ns = time.monotonicNanos(),
    };

    var active_h2 = try connection_mod.ClientConnection.init(&active_conn.socket);
    active_h2.runtime.state.preface_sent = true;
    active_h2.runtime.state.peer_settings_received = true;

    var draining_h2 = try connection_mod.ClientConnection.init(&draining_conn.socket);
    draining_h2.runtime.state.preface_sent = true;
    draining_h2.runtime.state.peer_settings_received = true;

    var pool = UpstreamSessionPool.init();
    defer pool.deinit();

    const upstream_idx: config.UpstreamIndex = 6;
    const slot_index: usize = @intCast(upstream_idx);

    pool.slots[slot_index] = .{
        .upstream_port = 19000,
        .upstream_tls = false,
        .upstream_protocol = .h2c,
        .next_generation = 3,
        .active_session = .{
            .upstream_idx = upstream_idx,
            .generation = 2,
            .connection = active_conn,
            .h2 = active_h2,
            .last_used_ns = time.monotonicNanos(),
        },
        .draining_session = .{
            .upstream_idx = upstream_idx,
            .generation = 1,
            .connection = draining_conn,
            .h2 = draining_h2,
            .last_used_ns = time.monotonicNanos(),
        },
    };

    try std.testing.expect(pool.getByGeneration(upstream_idx, 2) != null);
    try std.testing.expect(pool.getByGeneration(upstream_idx, 1) != null);
    try std.testing.expect(pool.getByGeneration(upstream_idx, 3) == null);
}

test "UpstreamSessionPool closeAll clears all slots" {
    const fds = try testSocketPair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(fds[1]);

    var conn = Connection{
        .socket = Socket.Plain.init_client(fds[0]),
        .created_ns = time.monotonicNanos(),
        .last_used_ns = time.monotonicNanos(),
    };
    const h2_conn = try connection_mod.ClientConnection.init(&conn.socket);

    var pool = UpstreamSessionPool.init();
    const upstream_idx: config.UpstreamIndex = 2;
    const slot_index: usize = @intCast(upstream_idx);

    pool.slots[slot_index] = .{
        .upstream_port = 19001,
        .upstream_tls = false,
        .upstream_protocol = .h2c,
        .next_generation = 2,
        .active_session = .{
            .upstream_idx = upstream_idx,
            .generation = 1,
            .connection = conn,
            .h2 = h2_conn,
            .last_used_ns = time.monotonicNanos(),
        },
    };

    pool.closeAll();
    try std.testing.expect(pool.get(upstream_idx) == null);
    try std.testing.expectEqual(@as(u16, 0), pool.slots[slot_index].upstream_port);
    try std.testing.expect(pool.slots[slot_index].upstream_protocol == .h1);
}
