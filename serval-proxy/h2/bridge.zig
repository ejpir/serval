//! Stream-Aware HTTP/2 Proxy Bridge
//!
//! Bounded downstream↔upstream stream mapping helpers that use
//! `serval-client` outbound h2 sessions.
//!
//! This is an initial Phase D bridge: it does not own downstream sockets yet.
//! It opens upstream streams, binds stream ids, forwards DATA for bound streams,
//! and maps upstream receive actions back to downstream stream ids.
//! TigerStyle: Fixed-capacity tables, explicit errors, no allocation.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const core = @import("serval-core");
const config = core.config;
const types = core.types;
const log = core.log.scoped(.proxy);

const h2 = @import("serval-h2");
const serval_client = @import("serval-client");
const bindings = @import("bindings.zig");

const Upstream = types.Upstream;
const Request = types.Request;
const Response = types.Response;
const HeaderMap = types.HeaderMap;

pub const Error = error{
    SessionNotFound,
    UnexpectedReceiveAction,
} || bindings.Error || serval_client.H2UpstreamSessionError;

pub const OpenResult = struct {
    binding: bindings.Binding,
    connect: serval_client.H2UpstreamConnectStats,
};

pub const ResponseHeadersAction = struct {
    downstream_stream_id: u32,
    end_stream: bool,
    response: Response,
};

pub const ResponseDataAction = struct {
    downstream_stream_id: u32,
    end_stream: bool,
    payload: []const u8,
};

pub const ResponseTrailersAction = struct {
    downstream_stream_id: u32,
    trailers: HeaderMap,
};

pub const StreamResetAction = struct {
    downstream_stream_id: u32,
    error_code_raw: u32,
};

pub const ConnectionCloseAction = struct {
    upstream_index: config.UpstreamIndex,
    upstream_session_generation: u32,
    goaway: h2.GoAway,
};

pub const ReceiveAction = union(enum) {
    none,
    response_headers: ResponseHeadersAction,
    response_data: ResponseDataAction,
    response_trailers: ResponseTrailersAction,
    stream_reset: StreamResetAction,
    connection_close: ConnectionCloseAction,
};

pub const StreamBridge = struct {
    client: *serval_client.Client,
    sessions: *serval_client.H2UpstreamSessionPool,
    binding_table: bindings.BindingTable = bindings.BindingTable.init(),

    pub fn init(client: *serval_client.Client, sessions: *serval_client.H2UpstreamSessionPool) StreamBridge {
        assert(@intFromPtr(client) != 0);
        assert(@intFromPtr(sessions) != 0);

        return .{
            .client = client,
            .sessions = sessions,
        };
    }

    pub fn deinit(self: *StreamBridge) void {
        assert(@intFromPtr(self) != 0);

        self.binding_table = bindings.BindingTable.init();
        self.sessions.closeAll();
    }

    pub fn openDownstreamStream(
        self: *StreamBridge,
        io: Io,
        upstream: Upstream,
        downstream_stream_id: u32,
        request: *const Request,
        effective_path: ?[]const u8,
        end_stream: bool,
    ) Error!OpenResult {
        assert(@intFromPtr(self) != 0);
        assert(downstream_stream_id > 0);
        assert(upstream.port > 0);
        assert(request.path.len > 0);

        if (self.binding_table.getByDownstream(downstream_stream_id) != null) {
            return error.DuplicateDownstreamStream;
        }

        const max_open_attempts: u8 = config.H2_MAX_SESSIONS_PER_UPSTREAM;
        var attempts: u8 = 0;

        while (attempts < max_open_attempts) : (attempts += 1) {
            const acquired = try self.sessions.acquireOrConnect(self.client, upstream, io);
            const upstream_stream_id = acquired.session.sendRequestHeaders(request, effective_path, end_stream) catch |err| switch (err) {
                error.ConnectionClosing => {
                    self.sessions.closeGeneration(upstream.idx, acquired.session.generation);
                    if (attempts + 1 >= max_open_attempts) return err;
                    continue;
                },
                else => return err,
            };

            const binding = bindings.Binding{
                .downstream_stream_id = downstream_stream_id,
                .upstream_stream_id = upstream_stream_id,
                .upstream_index = upstream.idx,
                .upstream_session_generation = acquired.session.generation,
            };
            try self.binding_table.put(binding);

            return .{
                .binding = binding,
                .connect = acquired.connect,
            };
        }

        return error.ConnectionClosing;
    }

    pub fn sendDownstreamData(
        self: *StreamBridge,
        downstream_stream_id: u32,
        payload: []const u8,
        end_stream: bool,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(downstream_stream_id > 0);

        const binding = self.binding_table.getByDownstream(downstream_stream_id) orelse return error.BindingNotFound;
        const session = self.sessions.getByGeneration(binding.upstream_index, binding.upstream_session_generation) orelse return error.SessionNotFound;

        session.sendRequestData(binding.upstream_stream_id, payload, end_stream) catch |err| switch (err) {
            error.ConnectionClosed => {
                if (!end_stream) return err;

                log.warn(
                    "h2 bridge: downstream={d} upstream={d} idx={d} gen={d} final sendRequestData saw ConnectionClosed; preserving binding for in-flight response",
                    .{
                        downstream_stream_id,
                        binding.upstream_stream_id,
                        binding.upstream_index,
                        binding.upstream_session_generation,
                    },
                );
                return;
            },
            error.ConnectionClosing => {
                if (end_stream) {
                    log.warn(
                        "h2 bridge: downstream={d} upstream={d} idx={d} gen={d} final sendRequestData saw ConnectionClosing; goaway_received={any} last_stream_id={d} preserving binding",
                        .{
                            downstream_stream_id,
                            binding.upstream_stream_id,
                            binding.upstream_index,
                            binding.upstream_session_generation,
                            session.h2.runtime.state.goaway_received,
                            session.h2.runtime.state.peer_goaway_last_stream_id,
                        },
                    );
                    return;
                }

                log.warn(
                    "h2 bridge: downstream={d} upstream={d} idx={d} gen={d} sendRequestData failed with ConnectionClosing; goaway_received={any} last_stream_id={d} failing closed",
                    .{
                        downstream_stream_id,
                        binding.upstream_stream_id,
                        binding.upstream_index,
                        binding.upstream_session_generation,
                        session.h2.runtime.state.goaway_received,
                        session.h2.runtime.state.peer_goaway_last_stream_id,
                    },
                );

                _ = self.binding_table.removeByDownstream(downstream_stream_id) catch |remove_err| switch (remove_err) {
                    error.BindingNotFound => return err,
                    else => return remove_err,
                };
                self.sessions.closeGeneration(binding.upstream_index, binding.upstream_session_generation);
                return err;
            },
            error.WriteFailed => {
                if (end_stream) {
                    log.warn(
                        "h2 bridge: downstream={d} upstream={d} idx={d} gen={d} final sendRequestData saw WriteFailed; preserving binding for in-flight response",
                        .{
                            downstream_stream_id,
                            binding.upstream_stream_id,
                            binding.upstream_index,
                            binding.upstream_session_generation,
                        },
                    );
                    return;
                }

                _ = self.binding_table.removeByDownstream(downstream_stream_id) catch |remove_err| switch (remove_err) {
                    error.BindingNotFound => return err,
                    else => return remove_err,
                };
                self.sessions.closeGeneration(binding.upstream_index, binding.upstream_session_generation);
                return err;
            },
            else => return err,
        };
    }

    pub fn bindingForDownstream(self: *const StreamBridge, downstream_stream_id: u32) ?bindings.Binding {
        assert(@intFromPtr(self) != 0);
        assert(downstream_stream_id > 0);

        return self.binding_table.getByDownstream(downstream_stream_id);
    }

    pub fn cancelDownstreamStream(
        self: *StreamBridge,
        downstream_stream_id: u32,
        error_code_raw: u32,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(downstream_stream_id > 0);

        const binding = self.binding_table.removeByDownstream(downstream_stream_id) catch |err| switch (err) {
            error.BindingNotFound => return,
            else => return err,
        };

        const session = self.sessions.getByGeneration(binding.upstream_index, binding.upstream_session_generation) orelse return error.SessionNotFound;
        session.sendStreamReset(binding.upstream_stream_id, error_code_raw) catch |err| switch (err) {
            error.StreamNotFound => {},
            else => return err,
        };
    }

    pub fn receiveForUpstream(
        self: *StreamBridge,
        upstream_index: config.UpstreamIndex,
    ) Error!ReceiveAction {
        assert(@intFromPtr(self) != 0);

        const session = self.sessions.get(upstream_index) orelse return error.SessionNotFound;
        const action = try session.receiveActionHandlingControl();
        return self.mapReceiveAction(upstream_index, session.generation, action);
    }

    pub fn receiveForDownstream(
        self: *StreamBridge,
        io: Io,
        timeout: Io.Timeout,
        downstream_stream_id: u32,
    ) Error!ReceiveAction {
        assert(@intFromPtr(self) != 0);
        assert(downstream_stream_id > 0);

        const binding = self.binding_table.getByDownstream(downstream_stream_id) orelse return error.BindingNotFound;
        const session = self.sessions.getByGeneration(binding.upstream_index, binding.upstream_session_generation) orelse return error.SessionNotFound;

        const action = try session.receiveActionHandlingControlTimeout(io, timeout);
        return self.mapReceiveAction(binding.upstream_index, binding.upstream_session_generation, action);
    }

    pub fn closeUpstream(self: *StreamBridge, upstream_index: config.UpstreamIndex) void {
        assert(@intFromPtr(self) != 0);

        _ = self.binding_table.removeAllForUpstream(upstream_index);
        self.sessions.close(upstream_index);
    }

    pub fn activeBindingCount(self: *const StreamBridge) u16 {
        assert(@intFromPtr(self) != 0);
        return self.binding_table.count;
    }

    fn mapReceiveAction(
        self: *StreamBridge,
        upstream_index: config.UpstreamIndex,
        upstream_session_generation: u32,
        action: serval_client.H2ReceiveAction,
    ) Error!ReceiveAction {
        assert(@intFromPtr(self) != 0);

        return switch (action) {
            .none => .none,
            .response_headers => |response_headers| {
                const binding = self.binding_table.getByUpstreamForSession(upstream_index, upstream_session_generation, response_headers.stream_id) orelse return error.BindingNotFound;
                if (response_headers.end_stream) {
                    _ = try self.binding_table.removeByDownstream(binding.downstream_stream_id);
                }
                return .{ .response_headers = .{
                    .downstream_stream_id = binding.downstream_stream_id,
                    .end_stream = response_headers.end_stream,
                    .response = response_headers.response,
                } };
            },
            .response_data => |response_data| {
                const binding = self.binding_table.getByUpstreamForSession(upstream_index, upstream_session_generation, response_data.stream_id) orelse return error.BindingNotFound;
                if (response_data.end_stream) {
                    _ = try self.binding_table.removeByDownstream(binding.downstream_stream_id);
                }
                return .{ .response_data = .{
                    .downstream_stream_id = binding.downstream_stream_id,
                    .end_stream = response_data.end_stream,
                    .payload = response_data.payload,
                } };
            },
            .response_trailers => |response_trailers| {
                const binding = self.binding_table.getByUpstreamForSession(upstream_index, upstream_session_generation, response_trailers.stream_id) orelse return error.BindingNotFound;
                _ = try self.binding_table.removeByDownstream(binding.downstream_stream_id);
                return .{ .response_trailers = .{
                    .downstream_stream_id = binding.downstream_stream_id,
                    .trailers = response_trailers.trailers,
                } };
            },
            .stream_reset => |stream_reset| {
                const binding = self.binding_table.getByUpstreamForSession(upstream_index, upstream_session_generation, stream_reset.stream_id) orelse return error.BindingNotFound;
                _ = try self.binding_table.removeByDownstream(binding.downstream_stream_id);
                return .{ .stream_reset = .{
                    .downstream_stream_id = binding.downstream_stream_id,
                    .error_code_raw = stream_reset.error_code_raw,
                } };
            },
            .connection_close => |goaway| {
                if (goaway.error_code_raw != @intFromEnum(h2.ErrorCode.no_error)) {
                    _ = self.binding_table.removeAllForUpstreamSession(upstream_index, upstream_session_generation);
                    self.sessions.closeGeneration(upstream_index, upstream_session_generation);
                }
                return .{ .connection_close = .{
                    .upstream_index = upstream_index,
                    .upstream_session_generation = upstream_session_generation,
                    .goaway = goaway,
                } };
            },
            else => return error.UnexpectedReceiveAction,
        };
    }
};

test "StreamBridge bindingForDownstream returns stored mapping" {
    var dns_resolver: @import("serval-net").DnsResolver = undefined;
    @import("serval-net").DnsResolver.init(&dns_resolver, .{});
    var client = serval_client.Client.init(std.testing.allocator, &dns_resolver, null, false);
    var sessions = serval_client.H2UpstreamSessionPool.init();
    defer sessions.deinit();

    var bridge = StreamBridge.init(&client, &sessions);
    defer bridge.deinit();

    try bridge.binding_table.put(.{
        .downstream_stream_id = 9,
        .upstream_stream_id = 7,
        .upstream_index = 1,
        .upstream_session_generation = 1,
    });

    const binding = bridge.bindingForDownstream(9) orelse return error.MissingBinding;
    try std.testing.expectEqual(@as(u32, 7), binding.upstream_stream_id);
}

test "StreamBridge maps response_data and removes binding on end_stream" {
    var dns_resolver: @import("serval-net").DnsResolver = undefined;
    @import("serval-net").DnsResolver.init(&dns_resolver, .{});
    var client = serval_client.Client.init(std.testing.allocator, &dns_resolver, null, false);
    var sessions = serval_client.H2UpstreamSessionPool.init();
    defer sessions.deinit();

    var bridge = StreamBridge.init(&client, &sessions);
    defer bridge.deinit();

    const upstream_index: config.UpstreamIndex = 2;
    try bridge.binding_table.put(.{
        .downstream_stream_id = 11,
        .upstream_stream_id = 1,
        .upstream_index = upstream_index,
        .upstream_session_generation = 1,
    });

    const mapped = try bridge.mapReceiveAction(upstream_index, 1, .{ .response_data = .{
        .stream_id = 1,
        .end_stream = true,
        .payload = "pong",
    } });

    switch (mapped) {
        .response_data => |data| {
            try std.testing.expectEqual(@as(u32, 11), data.downstream_stream_id);
            try std.testing.expect(data.end_stream);
            try std.testing.expectEqualStrings("pong", data.payload);
        },
        else => return error.UnexpectedAction,
    }

    try std.testing.expectEqual(@as(u16, 0), bridge.activeBindingCount());
}

test "StreamBridge maps stream_reset and clears binding" {
    var dns_resolver: @import("serval-net").DnsResolver = undefined;
    @import("serval-net").DnsResolver.init(&dns_resolver, .{});
    var client = serval_client.Client.init(std.testing.allocator, &dns_resolver, null, false);
    var sessions = serval_client.H2UpstreamSessionPool.init();
    defer sessions.deinit();

    var bridge = StreamBridge.init(&client, &sessions);
    defer bridge.deinit();

    const upstream_index: config.UpstreamIndex = 3;
    try bridge.binding_table.put(.{
        .downstream_stream_id = 17,
        .upstream_stream_id = 5,
        .upstream_index = upstream_index,
        .upstream_session_generation = 1,
    });

    const mapped = try bridge.mapReceiveAction(upstream_index, 1, .{ .stream_reset = .{
        .stream_id = 5,
        .error_code_raw = @intFromEnum(h2.ErrorCode.cancel),
    } });

    switch (mapped) {
        .stream_reset => |reset| {
            try std.testing.expectEqual(@as(u32, 17), reset.downstream_stream_id);
            try std.testing.expectEqual(@as(u32, @intFromEnum(h2.ErrorCode.cancel)), reset.error_code_raw);
        },
        else => return error.UnexpectedAction,
    }

    try std.testing.expectEqual(@as(u16, 0), bridge.activeBindingCount());
}

test "StreamBridge maps by upstream index when stream ids overlap" {
    var dns_resolver: @import("serval-net").DnsResolver = undefined;
    @import("serval-net").DnsResolver.init(&dns_resolver, .{});
    var client = serval_client.Client.init(std.testing.allocator, &dns_resolver, null, false);
    var sessions = serval_client.H2UpstreamSessionPool.init();
    defer sessions.deinit();

    var bridge = StreamBridge.init(&client, &sessions);
    defer bridge.deinit();

    try bridge.binding_table.put(.{
        .downstream_stream_id = 1,
        .upstream_stream_id = 3,
        .upstream_index = 0,
        .upstream_session_generation = 1,
    });
    try bridge.binding_table.put(.{
        .downstream_stream_id = 5,
        .upstream_stream_id = 3,
        .upstream_index = 1,
        .upstream_session_generation = 1,
    });

    const mapped = try bridge.mapReceiveAction(1, 1, .{ .response_data = .{
        .stream_id = 3,
        .end_stream = false,
        .payload = "ok",
    } });

    switch (mapped) {
        .response_data => |data| {
            try std.testing.expectEqual(@as(u32, 5), data.downstream_stream_id);
            try std.testing.expectEqualStrings("ok", data.payload);
        },
        else => return error.UnexpectedAction,
    }
}

test "StreamBridge maps by upstream session generation when ids overlap" {
    var dns_resolver: @import("serval-net").DnsResolver = undefined;
    @import("serval-net").DnsResolver.init(&dns_resolver, .{});
    var client = serval_client.Client.init(std.testing.allocator, &dns_resolver, null, false);
    var sessions = serval_client.H2UpstreamSessionPool.init();
    defer sessions.deinit();

    var bridge = StreamBridge.init(&client, &sessions);
    defer bridge.deinit();

    const upstream_index: config.UpstreamIndex = 3;
    try bridge.binding_table.put(.{
        .downstream_stream_id = 21,
        .upstream_stream_id = 1,
        .upstream_index = upstream_index,
        .upstream_session_generation = 1,
    });
    try bridge.binding_table.put(.{
        .downstream_stream_id = 23,
        .upstream_stream_id = 1,
        .upstream_index = upstream_index,
        .upstream_session_generation = 2,
    });

    const mapped = try bridge.mapReceiveAction(upstream_index, 2, .{ .response_data = .{
        .stream_id = 1,
        .end_stream = false,
        .payload = "generation-two",
    } });

    switch (mapped) {
        .response_data => |data| {
            try std.testing.expectEqual(@as(u32, 23), data.downstream_stream_id);
            try std.testing.expectEqualStrings("generation-two", data.payload);
        },
        else => return error.UnexpectedAction,
    }
}

test "StreamBridge keeps bindings on no-error connection_close" {
    var dns_resolver: @import("serval-net").DnsResolver = undefined;
    @import("serval-net").DnsResolver.init(&dns_resolver, .{});
    var client = serval_client.Client.init(std.testing.allocator, &dns_resolver, null, false);
    var sessions = serval_client.H2UpstreamSessionPool.init();
    defer sessions.deinit();

    var bridge = StreamBridge.init(&client, &sessions);
    defer bridge.deinit();

    const upstream_index: config.UpstreamIndex = 7;
    try bridge.binding_table.put(.{
        .downstream_stream_id = 9,
        .upstream_stream_id = 1,
        .upstream_index = upstream_index,
        .upstream_session_generation = 1,
    });

    const mapped = try bridge.mapReceiveAction(upstream_index, 1, .{ .connection_close = .{
        .last_stream_id = 1,
        .error_code_raw = @intFromEnum(h2.ErrorCode.no_error),
        .debug_data = "graceful",
    } });

    switch (mapped) {
        .connection_close => |close| {
            try std.testing.expectEqual(upstream_index, close.upstream_index);
            try std.testing.expectEqual(@as(u32, 1), close.upstream_session_generation);
            try std.testing.expectEqual(@as(u32, 1), close.goaway.last_stream_id);
        },
        else => return error.UnexpectedAction,
    }

    try std.testing.expectEqual(@as(u16, 1), bridge.activeBindingCount());
}

test "StreamBridge keeps all bindings on no-error connection_close" {
    var dns_resolver: @import("serval-net").DnsResolver = undefined;
    @import("serval-net").DnsResolver.init(&dns_resolver, .{});
    var client = serval_client.Client.init(std.testing.allocator, &dns_resolver, null, false);
    var sessions = serval_client.H2UpstreamSessionPool.init();
    defer sessions.deinit();

    var bridge = StreamBridge.init(&client, &sessions);
    defer bridge.deinit();

    const upstream_index: config.UpstreamIndex = 9;
    try bridge.binding_table.put(.{
        .downstream_stream_id = 17,
        .upstream_stream_id = 1,
        .upstream_index = upstream_index,
        .upstream_session_generation = 3,
    });
    try bridge.binding_table.put(.{
        .downstream_stream_id = 19,
        .upstream_stream_id = 3,
        .upstream_index = upstream_index,
        .upstream_session_generation = 3,
    });

    _ = try bridge.mapReceiveAction(upstream_index, 3, .{ .connection_close = .{
        .last_stream_id = 1,
        .error_code_raw = @intFromEnum(h2.ErrorCode.no_error),
        .debug_data = "graceful",
    } });

    try std.testing.expect(bridge.binding_table.getByDownstream(17) != null);
    try std.testing.expect(bridge.binding_table.getByDownstream(19) != null);
    try std.testing.expectEqual(@as(u16, 2), bridge.activeBindingCount());
}

test "StreamBridge clears only matching generation bindings on error connection_close" {
    var dns_resolver: @import("serval-net").DnsResolver = undefined;
    @import("serval-net").DnsResolver.init(&dns_resolver, .{});
    var client = serval_client.Client.init(std.testing.allocator, &dns_resolver, null, false);
    var sessions = serval_client.H2UpstreamSessionPool.init();
    defer sessions.deinit();

    var bridge = StreamBridge.init(&client, &sessions);
    defer bridge.deinit();

    const upstream_index: config.UpstreamIndex = 8;
    try bridge.binding_table.put(.{
        .downstream_stream_id = 13,
        .upstream_stream_id = 3,
        .upstream_index = upstream_index,
        .upstream_session_generation = 1,
    });
    try bridge.binding_table.put(.{
        .downstream_stream_id = 15,
        .upstream_stream_id = 3,
        .upstream_index = upstream_index,
        .upstream_session_generation = 2,
    });

    _ = try bridge.mapReceiveAction(upstream_index, 1, .{ .connection_close = .{
        .last_stream_id = 3,
        .error_code_raw = @intFromEnum(h2.ErrorCode.internal_error),
        .debug_data = "boom",
    } });

    try std.testing.expect(bridge.binding_table.getByDownstream(13) == null);
    try std.testing.expect(bridge.binding_table.getByDownstream(15) != null);
    try std.testing.expectEqual(@as(u16, 1), bridge.activeBindingCount());
}
