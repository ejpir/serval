// integration/tests.zig
//! Integration Tests for Serval
//!
//! Spawns actual server binaries and tests them end-to-end.
//! Tests cover HTTP and HTTPS scenarios including TLS termination,
//! TLS origination, and mixed HTTP/HTTPS backend pools.
//!
//! ## Test Categories
//!
//! 1. Harness Utility Tests - Verify test infrastructure works
//! 2. HTTP Integration Tests - Plain HTTP forwarding
//! 3. TLS Integration Tests - HTTPS frontend and/or backend
//!
//! ## Running Tests
//!
//! ```bash
//! zig build test-integration --summary all
//! ```

const std = @import("std");
const testing = std.testing;
const serval = @import("serval");
const serval_net = @import("serval-net");
const posix = @import("posix_compat.zig");
const harness = @import("harness.zig");

// =============================================================================
// Test Constants (TigerStyle C1/C4)
// =============================================================================

/// Number of requests to verify round-robin distribution.
const ROUND_ROBIN_TEST_REQUESTS: u32 = 10;

/// Address buffer length for formatting backend addresses.
const ADDR_BUF_LEN: u32 = 32;

/// Number of requests to send to trigger passive health marking.
/// Must exceed unhealthy_threshold (3) with round-robin (5 requests to b1 = 10 total).
const PASSIVE_HEALTH_TRIGGER_REQUESTS: u32 = 12;

/// Time to wait for prober to mark backend healthy after restart (ms).
/// Must exceed healthy_threshold (2) * probe_interval (5s) = 10s minimum.
/// Add buffer for timing variance.
const HEALTHY_SETTLE_MS: u64 = 12000;

/// Number of requests to verify backend exclusion after health stabilization.
const FAILURE_TEST_REQUESTS: u32 = 5;

/// Performance test: total requests to send with hey.
const PERF_TEST_REQUESTS: u32 = 60000;

/// Performance test: concurrent connections.
const PERF_TEST_CONCURRENCY: u32 = 50;

/// Performance test: minimum acceptable requests per second.
const PERF_TEST_MIN_RPS: f64 = 8000.0;

/// Big payload test: 1MB payload size.
const BIG_PAYLOAD_SIZE_1MB: usize = 1024 * 1024;

/// Big payload test: 100KB payload size.
const BIG_PAYLOAD_SIZE_100KB: usize = 100 * 1024;

/// Big payload test: 100MB payload size.
const BIG_PAYLOAD_SIZE_100MB: usize = 100 * 1024 * 1024;

/// Big payload test: 5GB payload size (exceeds 4GB iteration limit).
/// TigerStyle: Explicit constant for >4GB file support validation.
const BIG_PAYLOAD_SIZE_5GB: usize = 5 * 1024 * 1024 * 1024;

// =============================================================================
// HTTP Integration Tests
// =============================================================================

test "integration: echo backend responds with 200" {
    const allocator = testing.allocator;
    const port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(port, "test-backend", .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(port, "/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
}

test "integration: lb forwards to single backend" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "b1", .{});

    var backend_addr_buf: [32]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(lb_port, "/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
}

test "integration: lb round-robins across 2 backends" {
    const allocator = testing.allocator;
    const b1_port = harness.getPort();
    const b2_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(b1_port, "b1", .{});
    try pm.startEchoBackend(b2_port, "b2", .{});

    var b1_addr_buf: [32]u8 = undefined;
    var b2_addr_buf: [32]u8 = undefined;
    const b1_addr = std.fmt.bufPrint(&b1_addr_buf, "127.0.0.1:{d}", .{b1_port}) catch unreachable;
    const b2_addr = std.fmt.bufPrint(&b2_addr_buf, "127.0.0.1:{d}", .{b2_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{ b1_addr, b2_addr }, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    var b1_count: u32 = 0;
    var b2_count: u32 = 0;

    // TigerStyle C4: Named constant for iteration count
    var i: u32 = 0;
    while (i < ROUND_ROBIN_TEST_REQUESTS) : (i += 1) {
        const response = try client.get(lb_port, "/test");
        defer response.deinit();

        try testing.expectEqual(@as(u16, 200), response.status);

        if (response.backend_id) |id| {
            if (std.mem.eql(u8, id, "b1")) b1_count += 1;
            if (std.mem.eql(u8, id, "b2")) b2_count += 1;
        }
    }

    try testing.expect(b1_count > 0);
    try testing.expect(b2_count > 0);
}

test "integration: lb forwards POST body correctly" {
    // Test: POST request with body is forwarded through LB to backend
    //
    // The echo backend echoes request metadata including method, path, and headers.
    // We verify the POST method and Content-Length/Content-Type headers are forwarded.

    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "post-backend", .{});

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    // Send POST with JSON body
    const request_body = "{\"key\":\"value\",\"number\":42}";
    const response = try client.post(lb_port, "/api/data", request_body, "application/json");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);

    // Echo backend echoes request metadata
    // Verify POST method was forwarded correctly
    try testing.expect(response.body.len > 0);
    try testing.expect(std.mem.indexOf(u8, response.body, "Method: POST") != null);
    // Verify path was forwarded correctly
    try testing.expect(std.mem.indexOf(u8, response.body, "Path: /api/data") != null);
    // Verify Content-Type header was forwarded
    try testing.expect(std.mem.indexOf(u8, response.body, "Content-Type: application/json") != null);
    // Verify Content-Length header was forwarded (body size = 27 bytes)
    try testing.expect(std.mem.indexOf(u8, response.body, "Content-Length: 27") != null);
}

// =============================================================================
// Chunked Transfer Encoding Integration Tests
// =============================================================================

test "integration: echo backend responds with chunked encoding" {
    // Test: Direct request to echo backend with --chunked flag
    //
    // Verifies that the echo backend correctly sends responses using
    // Transfer-Encoding: chunked, and that the TestClient correctly
    // detects and decodes the chunked body.

    const allocator = testing.allocator;
    const port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start echo backend with chunked encoding enabled
    try pm.startEchoBackend(port, "chunked-backend", .{ .chunked = true });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(port, "/test");
    defer response.deinit();

    // Verify 200 status
    try testing.expectEqual(@as(u16, 200), response.status);

    // Verify body was decoded and contains expected echo content
    // The echo backend should include method and path in the response
    try testing.expect(response.body.len > 0);
    try testing.expect(std.mem.indexOf(u8, response.body, "Method: GET") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "Path: /test") != null);
}

test "integration: lb forwards chunked response correctly" {
    // Test: LB correctly forwards chunked responses from backend to client
    //
    // This verifies that when a backend sends Transfer-Encoding: chunked,
    // the LB correctly forwards the response to the client.

    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start echo backend with chunked encoding enabled
    try pm.startEchoBackend(backend_port, "chunked-backend", .{ .chunked = true });

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    // Start LB pointing to chunked backend
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(lb_port, "/test");
    defer response.deinit();

    // Verify 200 status
    try testing.expectEqual(@as(u16, 200), response.status);

    // Verify X-Backend-Id header is present (proves LB forwarded correctly)
    try testing.expect(response.backend_id != null);
    try testing.expectEqualStrings("chunked-backend", response.backend_id.?);

    // Verify body contains expected echo content (decoded from chunks)
    try testing.expect(response.body.len > 0);
    try testing.expect(std.mem.indexOf(u8, response.body, "Method: GET") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "Path: /test") != null);
}

// =============================================================================
// WebSocket Integration Tests
// =============================================================================

const c = std.c;

/// Loopback IPv4 address in big-endian form.
const LOOPBACK_IPV4_BE: u32 = 0x7F000001;

/// Fixed RFC 6455 sample key for deterministic tests.
const WS_TEST_KEY: []const u8 = "dGhlIHNhbXBsZSBub25jZQ==";

/// RFC 6455 sample accept value for WS_TEST_KEY.
const WS_TEST_ACCEPT: []const u8 = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// Maximum bytes for WebSocket HTTP handshake + immediate frame data in tests.
const WS_TEST_BUFFER_SIZE_BYTES: u32 = 2048;

/// Maximum payload size for simple text-frame test helpers.
const WS_TEST_MAX_PAYLOAD_BYTES: u32 = 125;

/// Maximum recv iterations for bounded read loops in websocket tests.
const WS_TEST_MAX_READS: u32 = 64;

/// Listener backlog for raw websocket test backend.
const WS_TEST_LISTENER_BACKLOG: c_int = 8;

/// Startup delay for in-process native websocket test server.
const WS_NATIVE_SERVER_STARTUP_DELAY_MS: u64 = 100;

const WebSocketBackendMode = enum {
    echo_after_upgrade,
    immediate_frame_after_upgrade,
    invalid_accept,
};

const WebSocketBackendConfig = struct {
    port: u16,
    mode: WebSocketBackendMode,
    path: []const u8,
    payload: []const u8,
};

fn startWebSocketBackend(config: WebSocketBackendConfig) !std.Thread {
    return try std.Thread.spawn(.{}, websocketBackendMain, .{config});
}

fn websocketBackendMain(config: WebSocketBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_len = try readUntilHeadersComplete(conn, &request_buf);
    const request = request_buf[0..request_len];

    try testing.expect(std.mem.indexOf(u8, request, "GET ") != null);
    try testing.expect(std.mem.indexOf(u8, request, config.path) != null);
    try testing.expect(std.mem.indexOf(u8, request, "Upgrade: websocket") != null);
    try testing.expect(std.mem.indexOf(u8, request, "Sec-WebSocket-Key: " ++ WS_TEST_KEY) != null);

    switch (config.mode) {
        .echo_after_upgrade => {
            var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
            const response = try buildSwitchingProtocolsResponse(WS_TEST_ACCEPT, &response_buf);
            try sendAllTcp(conn, response);

            var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
            const payload = try readMaskedClientTextFrame(conn, &frame_buf);

            var response_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
            const frame = try buildServerTextFrame(payload, &response_frame_buf);
            try sendAllTcp(conn, frame);
        },
        .immediate_frame_after_upgrade => {
            var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
            const frame = try buildServerTextFrame(config.payload, &frame_buf);

            var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
            const response = try std.fmt.bufPrint(
                &response_buf,
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Upgrade: websocket\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Sec-WebSocket-Accept: {s}\r\n" ++
                    "\r\n{s}",
                .{ WS_TEST_ACCEPT, frame },
            );
            try sendAllTcp(conn, response);
        },
        .invalid_accept => {
            var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
            const response = try buildSwitchingProtocolsResponse("invalid-accept-value", &response_buf);
            try sendAllTcp(conn, response);
        },
    }
}

fn createTcpListener(port: u16) !posix.socket_t {
    const listener = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    errdefer posix.close(listener);

    const reuse_addr: c_int = 1;
    try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse_addr));

    const addr: std.posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, LOOPBACK_IPV4_BE),
    };

    while (true) {
        const rc = c.bind(listener, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.in));
        switch (c.errno(rc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.BindFailed,
        }
    }

    while (true) {
        const rc = c.listen(listener, WS_TEST_LISTENER_BACKLOG);
        switch (c.errno(rc)) {
            .SUCCESS => return listener,
            .INTR => continue,
            else => return error.ListenFailed,
        }
    }
}

fn acceptTcp(listener: posix.socket_t) !posix.socket_t {
    while (true) {
        const rc = c.accept(listener, null, null);
        switch (c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return error.AcceptFailed,
        }
    }
}

fn connectTcp(port: u16) !posix.socket_t {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    errdefer posix.close(sock);

    const addr: posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, LOOPBACK_IPV4_BE),
    };
    try posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    return sock;
}

fn sendAllTcp(sock: posix.socket_t, data: []const u8) !void {
    var sent: usize = 0;
    var iterations: u32 = 0;

    while (sent < data.len and iterations < WS_TEST_MAX_READS) : (iterations += 1) {
        const n = try posix.send(sock, data[sent..], 0);
        if (n == 0) return error.ConnectionClosed;
        sent += n;
    }

    if (sent < data.len) return error.SendFailed;
}

fn readUntilHeadersComplete(sock: posix.socket_t, buf: []u8) !usize {
    var total: usize = 0;
    var iterations: u32 = 0;

    while (total < buf.len and iterations < WS_TEST_MAX_READS) : (iterations += 1) {
        const n = try posix.recv(sock, buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) return total;
    }

    return error.HeadersTooLarge;
}

fn buildSwitchingProtocolsResponse(accept_key: []const u8, out: []u8) ![]const u8 {
    return std.fmt.bufPrint(
        out,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n" ++
            "\r\n",
        .{accept_key},
    );
}

fn buildClientHandshake(path: []const u8, port: u16, out: []u8) ![]const u8 {
    return std.fmt.bufPrint(
        out,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:{d}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
        .{ path, port, WS_TEST_KEY },
    );
}

fn buildMaskedClientTextFrame(payload: []const u8, out: []u8) ![]const u8 {
    if (payload.len > WS_TEST_MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
    if (out.len < payload.len + 6) return error.BufferTooSmall;

    const mask = [_]u8{ 0x37, 0xfa, 0x21, 0x3d };
    out[0] = 0x81;
    out[1] = 0x80 | @as(u8, @intCast(payload.len));
    @memcpy(out[2..6], &mask);

    for (payload, 0..) |byte, idx| {
        out[idx + 6] = byte ^ mask[idx % mask.len];
    }

    return out[0 .. payload.len + 6];
}

fn buildServerTextFrame(payload: []const u8, out: []u8) ![]const u8 {
    if (payload.len > WS_TEST_MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
    if (out.len < payload.len + 2) return error.BufferTooSmall;

    out[0] = 0x81;
    out[1] = @intCast(payload.len);
    @memcpy(out[2..][0..payload.len], payload);
    return out[0 .. payload.len + 2];
}

fn readMaskedClientTextFrame(sock: posix.socket_t, out: []u8) ![]const u8 {
    const total = try readFrameBytes(sock, out);
    if (total < 6) return error.ShortFrame;
    if (out[0] != 0x81) return error.InvalidFrame;
    if ((out[1] & 0x80) == 0) return error.InvalidFrame;

    const payload_len: usize = out[1] & 0x7f;
    if (payload_len > WS_TEST_MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
    if (total < payload_len + 6) return error.ShortFrame;

    const mask = [_]u8{ out[2], out[3], out[4], out[5] };
    for (0..payload_len) |idx| {
        out[idx] = out[idx + 6] ^ mask[idx % mask.len];
    }

    return out[0..payload_len];
}

fn readServerTextFrame(sock: posix.socket_t, initial: []const u8, out: []u8) ![]const u8 {
    var total: usize = 0;
    if (initial.len > 0) {
        if (initial.len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..initial.len], initial);
        total = initial.len;
    }

    while (total < 2) {
        const n = try posix.recv(sock, out[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }

    if (out[0] != 0x81) return error.InvalidFrame;
    if ((out[1] & 0x80) != 0) return error.InvalidFrame;

    const payload_len: usize = out[1] & 0x7f;
    if (payload_len > WS_TEST_MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
    while (total < payload_len + 2) {
        const n = try posix.recv(sock, out[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }

    return out[2 .. 2 + payload_len];
}

fn readFrameBytes(sock: posix.socket_t, out: []u8) !usize {
    var total: usize = 0;
    var iterations: u32 = 0;

    while (total < out.len and iterations < WS_TEST_MAX_READS) : (iterations += 1) {
        const n = try posix.recv(sock, out[total..], 0);
        if (n == 0) break;
        total += n;
        if (total >= 2) {
            const masked = (out[1] & 0x80) != 0;
            const header_len: usize = if (masked) 6 else 2;
            const payload_len: usize = out[1] & 0x7f;
            if (total >= header_len + payload_len) return total;
        }
    }

    return total;
}

const WS_CLIENT_MASK = [4]u8{ 0x37, 0xFA, 0x21, 0x3D };

const NativeWebSocketHandler = struct {
    native_path: []const u8,
    selected_subprotocol: ?[]const u8 = null,
    upstream: ?serval.Upstream = null,

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = ctx;
        _ = request;
        return self.upstream orelse .{ .host = "127.0.0.1", .port = 1, .idx = 0 };
    }

    pub fn selectWebSocket(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.WebSocketRouteAction {
        _ = ctx;

        if (!std.mem.eql(u8, request.path, self.native_path)) {
            return .decline;
        }

        return .{ .accept = .{
            .subprotocol = self.selected_subprotocol,
        } };
    }

    pub fn handleWebSocket(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
        session: *serval.WebSocketSession,
    ) !void {
        _ = self;
        _ = ctx;
        _ = request;

        var msg_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        while (try session.readMessage(&msg_buf)) |message| {
            switch (message.kind) {
                .text => try session.sendText(message.payload),
                .binary => try session.sendBinary(message.payload),
            }
        }
    }
};

const NativeWebSocketServerConfig = struct {
    port: u16,
    native_path: []const u8,
    selected_subprotocol: ?[]const u8 = null,
    upstream: ?serval.Upstream = null,
};

const NativeWebSocketServerShared = struct {
    port: u16,
    shutdown: std.atomic.Value(bool),
    listener_fd: std.atomic.Value(i32),
};

const NativeWebSocketServer = struct {
    shared: *NativeWebSocketServerShared,
    thread: ?std.Thread,

    fn start(config: NativeWebSocketServerConfig) !NativeWebSocketServer {
        const shared = try std.heap.page_allocator.create(NativeWebSocketServerShared);
        errdefer std.heap.page_allocator.destroy(shared);

        shared.* = .{
            .port = config.port,
            .shutdown = std.atomic.Value(bool).init(false),
            .listener_fd = std.atomic.Value(i32).init(-1),
        };

        var server = NativeWebSocketServer{
            .shared = shared,
            .thread = null,
        };
        server.thread = try std.Thread.spawn(.{}, nativeWebSocketServerMain, .{ shared, config });
        posix.nanosleep(0, WS_NATIVE_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
        return server;
    }

    fn stop(self: *NativeWebSocketServer) void {
        self.shared.shutdown.store(true, .release);

        const wake_sock = connectTcp(self.shared.port) catch null;
        if (wake_sock) |sock| {
            posix.close(sock);
        }

        _ = self.shared.listener_fd.swap(-1, .acq_rel);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        std.heap.page_allocator.destroy(self.shared);
    }
};

fn nativeWebSocketServerMain(
    shared: *NativeWebSocketServerShared,
    config: NativeWebSocketServerConfig,
) void {
    var handler = NativeWebSocketHandler{
        .native_path = config.native_path,
        .selected_subprotocol = config.selected_subprotocol,
        .upstream = config.upstream,
    };
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();

    const ServerType = serval.Server(
        NativeWebSocketHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    var server = ServerType.init(
        &handler,
        &pool,
        &metrics,
        &tracer,
        .{ .port = config.port },
        null,
        serval_net.DnsConfig{},
    );

    server.run(threaded.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
        std.log.err("native websocket test server failed: {s}", .{@errorName(err)});
    };
}

fn buildClientHandshakeWithSubprotocol(
    path: []const u8,
    port: u16,
    subprotocol: ?[]const u8,
    out: []u8,
) ![]const u8 {
    if (subprotocol) |selected| {
        return std.fmt.bufPrint(
            out,
            "GET {s} HTTP/1.1\r\n" ++
                "Host: 127.0.0.1:{d}\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: {s}\r\n" ++
                "Sec-WebSocket-Version: 13\r\n" ++
                "Sec-WebSocket-Protocol: {s}\r\n" ++
                "\r\n",
            .{ path, port, WS_TEST_KEY, selected },
        );
    }

    return buildClientHandshake(path, port, out);
}

fn buildMaskedClientFrameWithOpcode(
    opcode: serval.WebSocketOpcode,
    fin: bool,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    var header_buf: [serval.websocket.max_frame_header_size_bytes]u8 = undefined;
    const header = serval.buildWebSocketFrameHeader(&header_buf, .{
        .fin = fin,
        .opcode = opcode,
        .payload_len = payload.len,
        .mask_key = WS_CLIENT_MASK,
    }) orelse return error.BufferTooSmall;

    if (out.len < header.len + payload.len) return error.BufferTooSmall;
    @memcpy(out[0..header.len], header);
    @memcpy(out[header.len..][0..payload.len], payload);

    const payload_slice = out[header.len .. header.len + payload.len];
    serval.applyWebSocketMask(payload_slice, WS_CLIENT_MASK);
    return out[0 .. header.len + payload.len];
}

const ServerFrame = struct {
    opcode: serval.WebSocketOpcode,
    fin: bool,
    payload: []const u8,
    remaining: []const u8,
};

fn readServerFrame(sock: posix.socket_t, initial: []const u8, out: []u8) !ServerFrame {
    var total: usize = 0;
    if (initial.len > 0) {
        if (initial.len > out.len) return error.BufferTooSmall;
        std.mem.copyForwards(u8, out[0..initial.len], initial);
        total = initial.len;
    }

    while (total < 2) {
        const n = try posix.recv(sock, out[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }

    const payload_code = out[1] & 0x7F;
    const header_len: usize = switch (payload_code) {
        0...125 => 2,
        126 => 4,
        127 => 10,
        else => unreachable,
    };

    while (total < header_len) {
        const n = try posix.recv(sock, out[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }

    const header = try serval.parseWebSocketFrameHeader(out[0..header_len], .server);
    const frame_len: usize = header_len + @as(usize, @intCast(header.payload_len));

    while (total < frame_len) {
        const n = try posix.recv(sock, out[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }

    return .{
        .opcode = header.opcode,
        .fin = header.fin,
        .payload = out[header_len..frame_len],
        .remaining = out[frame_len..total],
    };
}

fn sendClientClose(sock: posix.socket_t) !void {
    var payload_buf: [serval.config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;
    const payload = try serval.buildWebSocketClosePayload(
        &payload_buf,
        serval.websocket.close_normal_closure,
        "",
    );

    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const frame_bytes = try buildMaskedClientFrameWithOpcode(.close, true, payload, &frame_buf);
    try sendAllTcp(sock, frame_bytes);
}

fn performClientCloseHandshake(sock: posix.socket_t) !void {
    try sendClientClose(sock);

    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const server_frame = readServerFrame(sock, &[_]u8{}, &frame_buf) catch |err| switch (err) {
        error.ConnectionClosed => return,
        else => return err,
    };
    if (server_frame.opcode != .close) return error.InvalidFrame;
}

test "integration: lb proxies websocket upgrade and relays client text frame" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    const backend_thread = try startWebSocketBackend(.{
        .port = backend_port,
        .mode = .echo_after_upgrade,
        .path = "/ws",
        .payload = "",
    });
    defer backend_thread.join();

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    const sock = try connectTcp(lb_port);
    defer posix.close(sock);

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake("/ws", lb_port, &handshake_buf);

    var client_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const client_frame = try buildMaskedClientTextFrame("hello-through-lb", &client_frame_buf);

    var request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf, "{s}{s}", .{ handshake, client_frame });
    try sendAllTcp(sock, request);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);

    const header_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const frame_payload = try readServerTextFrame(sock, response_buf[header_end..response_len], &frame_buf);
    try testing.expectEqualStrings("hello-through-lb", frame_payload);
}

test "integration: lb forwards websocket 101 with immediate upstream bytes" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    const backend_thread = try startWebSocketBackend(.{
        .port = backend_port,
        .mode = .immediate_frame_after_upgrade,
        .path = "/ws-push",
        .payload = "server-push",
    });
    defer backend_thread.join();

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    const sock = try connectTcp(lb_port);
    defer posix.close(sock);

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake("/ws-push", lb_port, &handshake_buf);
    try sendAllTcp(sock, handshake);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);

    const header_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const frame_payload = try readServerTextFrame(sock, response_buf[header_end..response_len], &frame_buf);
    try testing.expectEqualStrings("server-push", frame_payload);
}

test "integration: lb rejects invalid upstream websocket switching-protocols response" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    const backend_thread = try startWebSocketBackend(.{
        .port = backend_port,
        .mode = .invalid_accept,
        .path = "/ws-bad",
        .payload = "",
    });
    defer backend_thread.join();

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    const sock = try connectTcp(lb_port);
    defer posix.close(sock);

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake("/ws-bad", lb_port, &handshake_buf);
    try sendAllTcp(sock, handshake);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 502), status);
}

test "integration: native websocket endpoint echoes text frame with preread payload" {
    const port = harness.getPort();
    var server = try NativeWebSocketServer.start(.{
        .port = port,
        .native_path = "/ws-native",
    });
    defer server.stop();

    const sock = try connectTcp(port);
    defer posix.close(sock);

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake("/ws-native", port, &handshake_buf);

    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const frame_bytes = try buildMaskedClientFrameWithOpcode(.text, true, "hello-native", &frame_buf);

    var request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf, "{s}{s}", .{ handshake, frame_bytes });
    try sendAllTcp(sock, request);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);

    const header_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var server_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const server_frame = try readServerFrame(sock, response_buf[header_end..response_len], &server_frame_buf);
    try testing.expectEqual(serval.WebSocketOpcode.text, server_frame.opcode);
    try testing.expectEqualStrings("hello-native", server_frame.payload);
    try performClientCloseHandshake(sock);
}

test "integration: native websocket endpoint auto-pongs and reassembles fragmented text" {
    const port = harness.getPort();
    var server = try NativeWebSocketServer.start(.{
        .port = port,
        .native_path = "/ws-fragmented",
    });
    defer server.stop();

    const sock = try connectTcp(port);
    defer posix.close(sock);

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake("/ws-fragmented", port, &handshake_buf);
    try sendAllTcp(sock, handshake);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);

    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const first = try buildMaskedClientFrameWithOpcode(.text, false, "hel", frame_buf[0..]);
    const ping = try buildMaskedClientFrameWithOpcode(.ping, true, "!", frame_buf[first.len..]);
    const second = try buildMaskedClientFrameWithOpcode(.continuation, true, "lo", frame_buf[first.len + ping.len ..]);
    try sendAllTcp(sock, frame_buf[0 .. first.len + ping.len + second.len]);

    var server_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const first_server_frame = try readServerFrame(sock, &[_]u8{}, &server_frame_buf);
    try testing.expectEqual(serval.WebSocketOpcode.pong, first_server_frame.opcode);
    try testing.expectEqualStrings("!", first_server_frame.payload);

    const second_server_frame = try readServerFrame(sock, first_server_frame.remaining, &server_frame_buf);
    try testing.expectEqual(serval.WebSocketOpcode.text, second_server_frame.opcode);
    try testing.expectEqualStrings("hello", second_server_frame.payload);
    try performClientCloseHandshake(sock);
}

test "integration: native websocket endpoint negotiates subprotocol" {
    const port = harness.getPort();
    var server = try NativeWebSocketServer.start(.{
        .port = port,
        .native_path = "/ws-subprotocol",
        .selected_subprotocol = "chat",
    });
    defer server.stop();

    const sock = try connectTcp(port);
    defer posix.close(sock);

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshakeWithSubprotocol("/ws-subprotocol", port, "chat, superchat", &handshake_buf);
    try sendAllTcp(sock, handshake);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);
    try testing.expect(std.mem.indexOf(u8, response_buf[0..response_len], "Sec-WebSocket-Protocol: chat\r\n") != null);
    try performClientCloseHandshake(sock);
}

test "integration: native websocket endpoint and proxy websocket fallback coexist" {
    const backend_port = harness.getPort();
    const server_port = harness.getPort();

    const backend_thread = try startWebSocketBackend(.{
        .port = backend_port,
        .mode = .echo_after_upgrade,
        .path = "/ws-proxy",
        .payload = "",
    });
    defer backend_thread.join();

    var server = try NativeWebSocketServer.start(.{
        .port = server_port,
        .native_path = "/ws-local",
        .upstream = .{ .host = "127.0.0.1", .port = backend_port, .idx = 0 },
    });
    defer server.stop();

    const local_sock = try connectTcp(server_port);
    defer posix.close(local_sock);

    var local_handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const local_handshake = try buildClientHandshake("/ws-local", server_port, &local_handshake_buf);
    var local_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const local_frame = try buildMaskedClientFrameWithOpcode(.text, true, "local-echo", &local_frame_buf);
    var local_request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const local_request = try std.fmt.bufPrint(&local_request_buf, "{s}{s}", .{ local_handshake, local_frame });
    try sendAllTcp(local_sock, local_request);

    var local_response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const local_response_len = try readUntilHeadersComplete(local_sock, &local_response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(local_response_buf[0..local_response_len]).?);
    const local_header_end = std.mem.indexOf(u8, local_response_buf[0..local_response_len], "\r\n\r\n").? + 4;
    var local_server_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const local_server_frame = try readServerFrame(local_sock, local_response_buf[local_header_end..local_response_len], &local_server_frame_buf);
    try testing.expectEqualStrings("local-echo", local_server_frame.payload);
    try performClientCloseHandshake(local_sock);

    const proxy_sock = try connectTcp(server_port);
    defer posix.close(proxy_sock);

    var proxy_handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const proxy_handshake = try buildClientHandshake("/ws-proxy", server_port, &proxy_handshake_buf);
    var proxy_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const proxy_frame = try buildMaskedClientFrameWithOpcode(.text, true, "proxy-echo", &proxy_frame_buf);
    var proxy_request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const proxy_request = try std.fmt.bufPrint(&proxy_request_buf, "{s}{s}", .{ proxy_handshake, proxy_frame });
    try sendAllTcp(proxy_sock, proxy_request);

    var proxy_response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const proxy_response_len = try readUntilHeadersComplete(proxy_sock, &proxy_response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(proxy_response_buf[0..proxy_response_len]).?);
    const proxy_header_end = std.mem.indexOf(u8, proxy_response_buf[0..proxy_response_len], "\r\n\r\n").? + 4;
    var proxy_server_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const proxy_server_frame = try readServerFrame(proxy_sock, proxy_response_buf[proxy_header_end..proxy_response_len], &proxy_server_frame_buf);
    try testing.expectEqualStrings("proxy-echo", proxy_server_frame.payload);
}

// =============================================================================
// TLS Integration Tests
// =============================================================================

/// Response from curl HTTPS request.
pub const CurlResponse = struct {
    status: u16,
    body: []const u8,
    backend_id: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const CurlResponse) void {
        if (self.body.len > 0) self.allocator.free(self.body);
        if (self.backend_id) |id| self.allocator.free(id);
    }
};

// =============================================================================
// Curl Constants (TigerStyle C1/C4)
// =============================================================================

/// Curl request timeout in seconds.
const CURL_TIMEOUT_S: u32 = 10;

/// Maximum curl output buffer size in bytes.
const CURL_OUTPUT_MAX_BYTES: u32 = 8192;

/// Maximum read iterations for curl output (bounded loop).
const CURL_MAX_READS: u32 = 100;

/// Maximum URL length for curl requests.
const CURL_URL_MAX_BYTES: u32 = 128;

/// Helper to make HTTPS requests using curl (subprocess with fork+exec).
/// TigerStyle: Returns owned response, caller must call deinit().
fn curlHttps(allocator: std.mem.Allocator, port: u16, path: []const u8) !CurlResponse {
    // TigerStyle S1: Preconditions
    std.debug.assert(port > 0);
    std.debug.assert(path.len > 0);

    // TigerStyle S7: Use sentinel-terminated buffer for URL to avoid UB
    var url_buf: [CURL_URL_MAX_BYTES:0]u8 = undefined;
    const url_len = std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}{s}", .{ port, path }) catch {
        return error.UrlTooLong;
    };
    url_buf[url_len.len] = 0; // Ensure NUL termination
    const url_z: [*:0]const u8 = @ptrCast(&url_buf);

    // Create pipe for capturing stdout
    const pipe = try posix.pipe();
    const read_fd = pipe[0];
    const write_fd = pipe[1];
    defer posix.close(read_fd);

    // Fork and exec curl
    const pid = try posix.fork();
    if (pid == 0) {
        // Child process
        posix.close(read_fd);

        // Redirect stdout to pipe
        posix.dup2(write_fd, posix.STDOUT_FILENO) catch std.process.exit(126);
        if (write_fd != posix.STDOUT_FILENO) posix.close(write_fd);

        // Redirect stderr to /dev/null
        const devnull = posix.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0) catch std.process.exit(126);
        posix.dup2(devnull, posix.STDERR_FILENO) catch std.process.exit(126);
        posix.close(devnull);

        // Run curl with:
        // -k: ignore self-signed cert
        // -s: silent mode
        // -S: show errors
        // -i: include headers in output
        // -m: timeout in seconds
        const argv = [_:null]?[*:0]const u8{
            "curl",
            "-k",
            "-s",
            "-S",
            "-i",
            "-m",
            std.fmt.comptimePrint("{d}", .{CURL_TIMEOUT_S}),
            url_z,
            null,
        };
        const env = posix.environPtr();
        // TigerStyle S5: execvpeZ returns error (noreturn on success)
        // If we get here, exec failed - exit with error code
        posix.execvpeZ("curl", &argv, env) catch {
            std.process.exit(127);
        };
        unreachable; // execvpeZ only returns on error
    }

    // Parent process
    posix.close(write_fd);

    // Read output from pipe
    var output_buf: [CURL_OUTPUT_MAX_BYTES]u8 = undefined;
    var total: u32 = 0;
    var read_count: u32 = 0;

    // TigerStyle S3: Bounded loop with explicit iteration limit
    while (total < CURL_OUTPUT_MAX_BYTES and read_count < CURL_MAX_READS) : (read_count += 1) {
        const n = posix.read(read_fd, output_buf[total..]) catch |err| {
            // TigerStyle S5: Handle EINTR by continuing, others break
            if (err == error.Interrupted) continue;
            break;
        };
        if (n == 0) break;
        total += @intCast(n);
    }

    // Wait for curl to exit
    const wait_result = posix.waitpid(pid, 0);
    // Extract exit status from raw status (WEXITSTATUS macro)
    // On Linux: exit_code = (status >> 8) & 0xff if WIFEXITED(status)
    const exit_code = (wait_result.status >> 8) & 0xff;
    const exited_normally = (wait_result.status & 0x7f) == 0;
    if (!exited_normally or exit_code != 0) {
        return error.CurlFailed;
    }

    if (total == 0) return error.EmptyResponse;

    const data = output_buf[0..total];

    // Parse status
    const status = harness.TestClient.parseStatusCode(data) orelse return error.InvalidResponse;

    // Parse body
    const body_slice = harness.TestClient.findBody(data) orelse "";
    const body = if (body_slice.len > 0)
        try allocator.dupe(u8, body_slice)
    else
        &[_]u8{};
    // TigerStyle S5: errdefer to free body if backend_id allocation fails
    errdefer if (body.len > 0) allocator.free(body);

    // Parse backend ID header
    const backend_id_slice = harness.TestClient.findHeader(data, "X-Backend-Id");
    const backend_id = if (backend_id_slice) |id|
        try allocator.dupe(u8, id)
    else
        null;

    return .{
        .status = status,
        .body = body,
        .backend_id = backend_id,
        .allocator = allocator,
    };
}

test "integration: TLS termination - HTTPS frontend, HTTP backend" {
    // Test: Client -> HTTPS -> LB -> HTTP -> Backend
    //
    // This tests TLS termination at the load balancer.
    // The LB accepts HTTPS connections and forwards to HTTP backends.

    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start HTTP backend (no TLS)
    try pm.startEchoBackend(backend_port, "http-backend", .{});

    var backend_addr_buf: [32]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    // Start LB with TLS termination (HTTPS frontend)
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
        .debug = false,
    });

    // Make HTTPS request using curl
    const response = try curlHttps(allocator, lb_port, "/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expect(response.backend_id != null);
    try testing.expectEqualStrings("http-backend", response.backend_id.?);
}

test "integration: TLS origination - HTTP frontend, HTTPS backend" {
    // Test: Client -> HTTP -> LB -> HTTPS -> Backend
    //
    // This tests TLS origination at the load balancer.
    // The LB accepts HTTP connections and forwards to HTTPS backends.

    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start HTTPS backend (with TLS)
    try pm.startEchoBackend(backend_port, "https-backend", .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
    });

    var backend_addr_buf: [32]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    // Start LB with TLS origination (HTTP frontend, HTTPS upstream)
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{
        .upstream_tls = &.{backend_addr},
        .insecure_skip_verify = true, // Self-signed cert
        .debug = false,
    });

    // Make HTTP request (LB will connect to backend via HTTPS)
    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(lb_port, "/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expect(response.backend_id != null);
    try testing.expectEqualStrings("https-backend", response.backend_id.?);
}

test "integration: TLS full path - HTTPS frontend, HTTPS backend" {
    // Test: Client -> HTTPS -> LB -> HTTPS -> Backend
    //
    // This tests full TLS path: TLS termination + TLS origination.
    // The LB terminates client TLS and originates new TLS to backend.

    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start HTTPS backend (with TLS)
    try pm.startEchoBackend(backend_port, "https-backend", .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
    });

    var backend_addr_buf: [32]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    // Start LB with both TLS termination and origination
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
        .upstream_tls = &.{backend_addr},
        .insecure_skip_verify = true, // Self-signed cert
        .debug = false,
    });

    // Make HTTPS request using curl
    const response = try curlHttps(allocator, lb_port, "/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expect(response.backend_id != null);
    try testing.expectEqualStrings("https-backend", response.backend_id.?);
}

test "integration: mixed backends - HTTP and HTTPS round-robin" {
    // Test: LB round-robins across both HTTP and HTTPS backends
    //
    // This tests that health probes and forwarding work correctly
    // when some backends are HTTP and some are HTTPS.

    const allocator = testing.allocator;
    const http_backend_port = harness.getPort();
    const https_backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start HTTP backend
    try pm.startEchoBackend(http_backend_port, "http-b1", .{});

    // Start HTTPS backend
    try pm.startEchoBackend(https_backend_port, "https-b2", .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
    });

    var http_addr_buf: [32]u8 = undefined;
    var https_addr_buf: [32]u8 = undefined;
    const http_addr = std.fmt.bufPrint(&http_addr_buf, "127.0.0.1:{d}", .{http_backend_port}) catch unreachable;
    const https_addr = std.fmt.bufPrint(&https_addr_buf, "127.0.0.1:{d}", .{https_backend_port}) catch unreachable;

    // Start LB with mixed backends (HTTP frontend)
    try pm.startLoadBalancer(lb_port, &.{ http_addr, https_addr }, .{
        .upstream_tls = &.{https_addr}, // Only https_addr uses TLS
        .insecure_skip_verify = true,
        .debug = false,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    var http_count: u32 = 0;
    var https_count: u32 = 0;

    // TigerStyle C4: Named constant for iteration count
    var i: u32 = 0;
    while (i < ROUND_ROBIN_TEST_REQUESTS) : (i += 1) {
        const response = try client.get(lb_port, "/test");
        defer response.deinit();

        try testing.expectEqual(@as(u16, 200), response.status);

        if (response.backend_id) |id| {
            if (std.mem.eql(u8, id, "http-b1")) http_count += 1;
            if (std.mem.eql(u8, id, "https-b2")) https_count += 1;
        }
    }

    // Both backends should receive traffic
    try testing.expect(http_count > 0);
    try testing.expect(https_count > 0);
}

test "integration: health probe over HTTPS" {
    // Test: LB health-probes an HTTPS backend and marks it healthy
    //
    // This verifies that the prober performs TLS handshake for HTTPS backends.

    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start HTTPS backend
    try pm.startEchoBackend(backend_port, "https-probed", .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
    });

    var backend_addr_buf: [32]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    // Start LB - backend should become healthy via HTTPS probe
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{
        .upstream_tls = &.{backend_addr},
        .insecure_skip_verify = true,
        .debug = false,
    });

    // Wait a bit for health probe to mark backend healthy
    posix.nanosleep(2, 0);

    // Make request - should succeed if backend is healthy
    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(lb_port, "/health-test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqualStrings("https-probed", response.backend_id.?);
}

test "integration: all backends unhealthy - returns 502" {
    // Test: When all backends are down, LB should return 502 Bad Gateway
    //
    // This tests the "everything is on fire" scenario.
    // The LB must not hang and must return a deterministic error.

    const allocator = testing.allocator;
    const lb_port = harness.getPort();

    // Use ports that nothing is listening on (no backends started)
    const fake_backend1_port = harness.getPort();
    const fake_backend2_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Format backend addresses (no actual backends started!)
    var b1_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    var b2_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const b1_addr = std.fmt.bufPrint(&b1_addr_buf, "127.0.0.1:{d}", .{fake_backend1_port}) catch unreachable;
    const b2_addr = std.fmt.bufPrint(&b2_addr_buf, "127.0.0.1:{d}", .{fake_backend2_port}) catch unreachable;

    // Start LB - but don't start any backends!
    try pm.startLoadBalancer(lb_port, &.{ b1_addr, b2_addr }, .{});

    // Give LB time to realize backends are unreachable
    posix.nanosleep(2, 0);

    // Make request - should get 502 (not hang)
    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(lb_port, "/test");
    defer response.deinit();

    // Expect 502 Bad Gateway when all backends are unhealthy
    try testing.expectEqual(@as(u16, 502), response.status);
}

// =============================================================================
// Backend Failure/Recovery Integration Tests
// =============================================================================

test "integration: backend failure - requests skip unhealthy backend" {
    // Test: When a backend dies, the LB should stop sending traffic to it
    // after passive health checking marks it unhealthy via 502 responses.
    //
    // Design: Uses PASSIVE health checking (via 502 responses on connect failure)
    // rather than waiting for the active prober. This is faster and more deterministic.
    //
    // Setup: 2 backends + LB
    // 1. Start 2 echo backends (b1, b2)
    // 2. Start LB pointing to both
    // 3. Verify both backends receive traffic (round-robin works)
    // 4. Kill b1 process
    // 5. Send requests to trigger passive health updates (some will be 502)
    // 6. After b1 is marked unhealthy, verify all 200s go to b2

    const allocator = testing.allocator;
    const b1_port = harness.getPort();
    const b2_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Step 1: Start both backends
    try pm.startEchoBackend(b1_port, "b1", .{});
    try pm.startEchoBackend(b2_port, "b2", .{});

    var b1_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    var b2_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const b1_addr = std.fmt.bufPrint(&b1_addr_buf, "127.0.0.1:{d}", .{b1_port}) catch unreachable;
    const b2_addr = std.fmt.bufPrint(&b2_addr_buf, "127.0.0.1:{d}", .{b2_port}) catch unreachable;

    // Step 2: Start LB
    try pm.startLoadBalancer(lb_port, &.{ b1_addr, b2_addr }, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    // Step 3: Verify both backends receive traffic
    var b1_initial: u32 = 0;
    var b2_initial: u32 = 0;

    // S3: Bounded loop with named constant
    var i: u32 = 0;
    while (i < ROUND_ROBIN_TEST_REQUESTS) : (i += 1) {
        const response = try client.get(lb_port, "/test");
        defer response.deinit();

        try testing.expectEqual(@as(u16, 200), response.status);

        if (response.backend_id) |id| {
            if (std.mem.eql(u8, id, "b1")) b1_initial += 1;
            if (std.mem.eql(u8, id, "b2")) b2_initial += 1;
        }
    }

    // S1: Assert both backends received traffic initially
    try testing.expect(b1_initial > 0);
    try testing.expect(b2_initial > 0);

    // Step 4: Kill b1
    try pm.killProcess("echo_backend_b1");

    // Step 5: Send requests to trigger passive health marking.
    // With round-robin and unhealthy_threshold=3, we need ~6 requests to b1 (12 total)
    // to accumulate 3 consecutive failures. Some requests will return 502.
    var failures_502: u32 = 0;
    var k: u32 = 0;
    while (k < PASSIVE_HEALTH_TRIGGER_REQUESTS) : (k += 1) {
        const response = try client.get(lb_port, "/test");
        defer response.deinit();

        if (response.status == 502) {
            failures_502 += 1;
        }
        // Don't assert 200 here - we expect some 502s while b1 is being marked unhealthy
    }

    // We should have seen some 502s (requests that tried b1)
    try testing.expect(failures_502 > 0);

    // Step 6: After passive health marking, verify all requests succeed to b2
    var b1_after: u32 = 0;
    var b2_after: u32 = 0;

    // S3: Bounded loop with named constant
    var j: u32 = 0;
    while (j < FAILURE_TEST_REQUESTS) : (j += 1) {
        const response = try client.get(lb_port, "/test");
        defer response.deinit();

        try testing.expectEqual(@as(u16, 200), response.status);

        if (response.backend_id) |id| {
            if (std.mem.eql(u8, id, "b1")) b1_after += 1;
            if (std.mem.eql(u8, id, "b2")) b2_after += 1;
        }
    }

    // S1: Assert b1 received no traffic (it's dead and marked unhealthy)
    try testing.expectEqual(@as(u32, 0), b1_after);
    // S1: Assert b2 received all traffic
    try testing.expectEqual(FAILURE_TEST_REQUESTS, b2_after);
}

test "integration: backend recovery - prober marks backend healthy" {
    // Test: When a dead backend comes back, the prober should mark it healthy
    // and traffic should resume going to it.
    //
    // Design: Uses PASSIVE health checking to mark b1 unhealthy quickly,
    // then waits for the ACTIVE prober to mark b1 healthy after restart.
    // Recovery MUST use the prober since traffic doesn't flow to unhealthy backends.
    //
    // Setup: 2 backends + LB, then failure + recovery
    // 1. Start 2 echo backends (b1, b2)
    // 2. Start LB
    // 3. Kill b1
    // 4. Send requests to trigger passive health marking (some 502s expected)
    // 5. Verify traffic only goes to b2
    // 6. Restart b1 on same port
    // 7. Wait for prober to mark b1 healthy (needs 2 probe successes at 5s interval)
    // 8. Send requests
    // 9. Verify both backends receive traffic again

    const allocator = testing.allocator;
    const b1_port = harness.getPort();
    const b2_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Step 1: Start both backends
    try pm.startEchoBackend(b1_port, "b1", .{});
    try pm.startEchoBackend(b2_port, "b2", .{});

    var b1_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    var b2_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const b1_addr = std.fmt.bufPrint(&b1_addr_buf, "127.0.0.1:{d}", .{b1_port}) catch unreachable;
    const b2_addr = std.fmt.bufPrint(&b2_addr_buf, "127.0.0.1:{d}", .{b2_port}) catch unreachable;

    // Step 2: Start LB
    try pm.startLoadBalancer(lb_port, &.{ b1_addr, b2_addr }, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    // Step 3: Kill b1
    try pm.killProcess("echo_backend_b1");

    // Step 4: Send requests to trigger passive health marking (expect some 502s)
    var k: u32 = 0;
    while (k < PASSIVE_HEALTH_TRIGGER_REQUESTS) : (k += 1) {
        const response = try client.get(lb_port, "/test");
        defer response.deinit();
        // Don't assert - expect mix of 200s (b2) and 502s (b1 attempts)
    }

    // Step 5: Verify traffic only goes to b2 now that b1 is marked unhealthy
    var b2_only: u32 = 0;
    var b1_while_dead: u32 = 0;

    // S3: Bounded loop
    var i: u32 = 0;
    while (i < FAILURE_TEST_REQUESTS) : (i += 1) {
        const response = try client.get(lb_port, "/test");
        defer response.deinit();

        try testing.expectEqual(@as(u16, 200), response.status);

        if (response.backend_id) |id| {
            if (std.mem.eql(u8, id, "b1")) b1_while_dead += 1;
            if (std.mem.eql(u8, id, "b2")) b2_only += 1;
        }
    }

    // S1: Assert b1 received no traffic while dead
    try testing.expectEqual(@as(u32, 0), b1_while_dead);
    try testing.expectEqual(FAILURE_TEST_REQUESTS, b2_only);

    // Step 6: Restart b1 on same port
    try pm.restartEchoBackend(b1_port, "b1", .{});

    // Step 7: Wait for prober to mark b1 healthy
    // Prober needs 2 successful probes (healthy_threshold=2) at 5s interval = 10s minimum
    const healthy_settle_s: u64 = HEALTHY_SETTLE_MS / 1000;
    const healthy_settle_ns: u64 = (HEALTHY_SETTLE_MS % 1000) * std.time.ns_per_ms;
    posix.nanosleep(healthy_settle_s, healthy_settle_ns);

    // Step 8 & 9: Send requests and verify both backends receive traffic
    var b1_recovered: u32 = 0;
    var b2_recovered: u32 = 0;

    // S3: Bounded loop with named constant
    var j: u32 = 0;
    while (j < ROUND_ROBIN_TEST_REQUESTS) : (j += 1) {
        const response = try client.get(lb_port, "/test");
        defer response.deinit();

        try testing.expectEqual(@as(u16, 200), response.status);

        if (response.backend_id) |id| {
            if (std.mem.eql(u8, id, "b1")) b1_recovered += 1;
            if (std.mem.eql(u8, id, "b2")) b2_recovered += 1;
        }
    }

    // S1: Assert both backends receive traffic after recovery
    // Note: We allow for slight imbalance due to timing, but both should receive some traffic
    try testing.expect(b1_recovered > 0);
    try testing.expect(b2_recovered > 0);
}

// =============================================================================
// Performance Tests
// =============================================================================

test "performance: lb achieves minimum throughput with hey" {
    // Test: Load balancer achieves at least PERF_TEST_MIN_RPS requests/second
    //
    // Uses 'hey' load testing tool to measure throughput.
    // Requires 'hey' to be installed: go install github.com/rakyll/hey@latest

    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start backend and load balancer
    try pm.startEchoBackend(backend_port, "perf-backend", .{});

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    // Format hey arguments
    var url_buf: [64]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/test", .{lb_port}) catch unreachable;

    var n_buf: [16]u8 = undefined;
    const n_arg = std.fmt.bufPrint(&n_buf, "{d}", .{PERF_TEST_REQUESTS}) catch unreachable;

    var c_buf: [16]u8 = undefined;
    const c_arg = std.fmt.bufPrint(&c_buf, "{d}", .{PERF_TEST_CONCURRENCY}) catch unreachable;

    // Run hey and capture output using fork+exec with pipe
    const stdout = runCommandWithOutput(allocator, &.{ "hey", "-n", n_arg, "-c", c_arg, url }) catch |err| {
        if (err == error.CommandNotFound) {
            std.debug.print("SKIP: 'hey' not installed\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer allocator.free(stdout);

    // Parse "Requests/sec: XXXX.XXXX" from output
    const rps = parseRequestsPerSec(stdout) orelse {
        std.debug.print("Failed to parse hey output:\n{s}\n", .{stdout});
        return error.TestUnexpectedResult;
    };

    std.debug.print("\nPerformance: {d:.2} req/s (minimum: {d:.2})\n", .{ rps, PERF_TEST_MIN_RPS });

    // Assert minimum throughput
    try testing.expect(rps >= PERF_TEST_MIN_RPS);
}

/// Run a command and capture its stdout output.
/// Returns allocated buffer that caller must free.
fn runCommandWithOutput(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    // Create pipe for stdout capture
    const pipe = try posix.pipe();
    const read_fd = pipe[0];
    const write_fd = pipe[1];

    // Convert argv to null-terminated array for execve
    const argv_buf = try allocator.allocSentinel(?[*:0]const u8, argv.len, null);
    defer allocator.free(argv_buf);

    for (argv, 0..) |arg, i| {
        argv_buf[i] = (try allocator.dupeZ(u8, arg)).ptr;
    }
    defer {
        for (argv_buf) |ptr| {
            if (ptr) |p| {
                const len = std.mem.len(p);
                allocator.free(p[0 .. len + 1]);
            }
        }
    }

    const pid = posix.fork() catch return error.ForkFailed;
    if (pid == 0) {
        // Child process
        posix.close(read_fd);

        // Redirect stdout to pipe
        posix.dup2(write_fd, posix.STDOUT_FILENO) catch std.process.exit(126);
        posix.close(write_fd);

        // Redirect stderr to /dev/null
        const devnull = posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0) catch std.process.exit(126);
        posix.dup2(devnull, posix.STDERR_FILENO) catch std.process.exit(126);
        posix.close(devnull);

        // Execute command - inherit environment from parent
        const env = posix.environPtr();
        _ = posix.execvpeZ(argv_buf[0].?, argv_buf, env) catch {
            std.process.exit(127); // Exec failed
        };
        std.process.exit(127); // Command not found
    }

    // Parent process
    posix.close(write_fd);
    defer posix.close(read_fd);

    // Read all stdout
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(read_fd, &buf) catch break;
        if (n == 0) break;
        try output.appendSlice(allocator, buf[0..n]);
    }

    // Wait for child
    const wait_result = posix.waitpid(pid, 0);
    const status = wait_result.status;

    if (posix.W.IFEXITED(status)) {
        const exit_code = posix.W.EXITSTATUS(status);
        if (exit_code == 127) {
            output.deinit(allocator);
            return error.CommandNotFound;
        }
        if (exit_code != 0) {
            output.deinit(allocator);
            return error.CommandFailed;
        }
    }

    return output.toOwnedSlice(allocator);
}

/// Parse "Requests/sec: XXXX.XXXX" from hey output.
/// Note: hey uses TAB as separator, not space.
fn parseRequestsPerSec(output: []const u8) ?f64 {
    const marker = "Requests/sec:";
    const idx = std.mem.indexOf(u8, output, marker) orelse return null;
    const after_marker = output[idx + marker.len ..];

    // Skip whitespace (spaces and tabs)
    var start: usize = 0;
    while (start < after_marker.len and (after_marker[start] == ' ' or after_marker[start] == '\t')) : (start += 1) {}

    // Find end of number
    var end: usize = start;
    while (end < after_marker.len and (after_marker[end] == '.' or (after_marker[end] >= '0' and after_marker[end] <= '9'))) : (end += 1) {}

    if (end == start) return null;

    return std.fmt.parseFloat(f64, after_marker[start..end]) catch null;
}

// =============================================================================
// Big Payload Tests
// =============================================================================

test "integration: lb forwards 100KB payload correctly" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start echo backend with --echo-body mode
    try pm.startEchoBackend(backend_port, "big-payload-backend", .{ .echo_body = true });

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    // Generate 100KB payload with pattern for verification
    const payload = try allocator.alloc(u8, BIG_PAYLOAD_SIZE_100KB);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    // Send through load balancer
    const response = try client.postLarge(lb_port, "/big-payload", payload, "application/octet-stream");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqual(payload.len, response.body.len);
    try testing.expectEqualSlices(u8, payload, response.body);
}

test "integration: lb forwards 1MB payload correctly" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start echo backend with --echo-body mode
    try pm.startEchoBackend(backend_port, "1mb-backend", .{ .echo_body = true });

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    // Generate 1MB payload with pattern for verification
    const payload = try allocator.alloc(u8, BIG_PAYLOAD_SIZE_1MB);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    // Send through load balancer
    const response = try client.postLarge(lb_port, "/big-payload", payload, "application/octet-stream");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqual(payload.len, response.body.len);
    try testing.expectEqualSlices(u8, payload, response.body);
}

test "integration: lb forwards 100MB payload correctly" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start echo backend with --echo-body mode
    try pm.startEchoBackend(backend_port, "100mb-backend", .{ .echo_body = true });

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    // Generate 100MB payload with pattern for verification
    const payload = try allocator.alloc(u8, BIG_PAYLOAD_SIZE_100MB);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    // Send through load balancer
    const response = try client.postLarge(lb_port, "/big-payload", payload, "application/octet-stream");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqual(payload.len, response.body.len);
    try testing.expectEqualSlices(u8, payload, response.body);
}

test "integration: lb forwards 5GB payload correctly" {
    // This test validates that files >4GB work correctly.
    // The previous iteration limit (1M iterations × 4KB chunks = 4GB max) would fail here.
    // Uses drain-body mode: backend reads body in chunks via readBodyChunk(), returns byte count.
    // TigerStyle: Explicit test for >4GB file support with bounded memory usage.
    std.debug.print("[DEBUG 5GB test] starting\n", .{});
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start echo backend with --drain-body mode (reads body in chunks, returns byte count)
    std.debug.print("[DEBUG 5GB test] starting echo backend on port {d}\n", .{backend_port});
    try pm.startEchoBackend(backend_port, "5gb-backend", .{ .drain_body = true });

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    std.debug.print("[DEBUG 5GB test] starting load balancer on port {d}\n", .{lb_port});
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    // Generate 5GB payload (pattern not needed since we verify byte count, not content)
    std.debug.print("[DEBUG 5GB test] allocating {d} bytes\n", .{BIG_PAYLOAD_SIZE_5GB});
    const payload = try allocator.alloc(u8, BIG_PAYLOAD_SIZE_5GB);
    defer allocator.free(payload);
    std.debug.print("[DEBUG 5GB test] filling payload\n", .{});
    @memset(payload, 0xAB); // Simple fill pattern
    std.debug.print("[DEBUG 5GB test] payload ready\n", .{});

    // Send through load balancer
    std.debug.print("[DEBUG 5GB test] sending request\n", .{});
    const response = try client.postLarge(lb_port, "/big-payload", payload, "application/octet-stream");
    defer response.deinit();
    std.debug.print("[DEBUG 5GB test] got response, status={d}\n", .{response.status});

    try testing.expectEqual(@as(u16, 200), response.status);

    // Verify backend received all 5GB - response body is "drained N bytes\n"
    const expected_response = std.fmt.allocPrint(allocator, "drained {d} bytes\n", .{BIG_PAYLOAD_SIZE_5GB}) catch unreachable;
    defer allocator.free(expected_response);
    try testing.expectEqualStrings(expected_response, response.body);
}

// =============================================================================
// HTTP 100 Continue Tests
// =============================================================================

test "integration: lb handles Expect 100-continue correctly" {
    // Test: Client sends request with Expect: 100-continue header through LB
    //
    // This tests that the proxy correctly handles 100 Continue responses from
    // backends. When a backend receives Expect: 100-continue, it may respond with:
    // 1. HTTP/1.1 100 Continue\r\n\r\n
    // 2. Then the actual response: HTTP/1.1 200 OK\r\n...
    //
    // The proxy must skip the 100 Continue and forward only the final response.

    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start echo backend with --echo-body mode to echo back the body
    try pm.startEchoBackend(backend_port, "continue-backend", .{ .echo_body = true });

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    // Give the LB extra time to mark backend healthy for this test
    posix.nanosleep(1, 0);

    // Use curl with Expect: 100-continue header to trigger the 100 Continue flow
    // curl -X POST with data > 1024 bytes automatically sends Expect: 100-continue
    // We explicitly set it with --header to ensure the behavior
    const response = try curlPostWithExpect100(allocator, lb_port, "/test-continue", "test-body-data");
    defer response.deinit();

    // Verify we got the final 200 response (not 100 Continue)
    try testing.expectEqual(@as(u16, 200), response.status);

    // Verify the body was echoed back correctly
    try testing.expectEqualStrings("test-body-data", response.body);

    // Verify backend ID header is present (proves LB forwarded correctly)
    try testing.expect(response.backend_id != null);
    try testing.expectEqualStrings("continue-backend", response.backend_id.?);
}

/// Curl constants for Expect: 100-continue test.
const CURL_EXPECT100_TIMEOUT_S: u32 = 10;

/// Maximum body buffer length for curl POST with Expect: 100-continue.
const CURL_BODY_MAX_BYTES: u32 = 256;

/// Helper to make HTTP POST request with Expect: 100-continue using curl.
/// TigerStyle: Returns owned response, caller must call deinit().
fn curlPostWithExpect100(allocator: std.mem.Allocator, port: u16, path: []const u8, body: []const u8) !CurlResponse {
    // TigerStyle S1: Preconditions
    std.debug.assert(port > 0);
    std.debug.assert(path.len > 0);
    std.debug.assert(body.len > 0);
    std.debug.assert(body.len < CURL_BODY_MAX_BYTES);

    // TigerStyle S7: Use sentinel-terminated buffer for URL to avoid UB
    var url_buf: [CURL_URL_MAX_BYTES:0]u8 = undefined;
    const url_len = std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}{s}", .{ port, path }) catch {
        return error.UrlTooLong;
    };
    url_buf[url_len.len] = 0; // Ensure NUL termination
    const url_z: [*:0]const u8 = @ptrCast(&url_buf);

    // NUL-terminate body for argv
    var body_buf: [CURL_BODY_MAX_BYTES:0]u8 = undefined;
    @memcpy(body_buf[0..body.len], body);
    body_buf[body.len] = 0;
    const body_z: [*:0]const u8 = @ptrCast(&body_buf);

    // Create pipe for capturing stdout
    const pipe = try posix.pipe();
    const read_fd = pipe[0];
    const write_fd = pipe[1];
    defer posix.close(read_fd);

    // Fork and exec curl
    const pid = try posix.fork();
    if (pid == 0) {
        // Child process
        posix.close(read_fd);

        // Redirect stdout to pipe
        posix.dup2(write_fd, posix.STDOUT_FILENO) catch std.process.exit(126);
        if (write_fd != posix.STDOUT_FILENO) posix.close(write_fd);

        // Redirect stderr to /dev/null
        const devnull = posix.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0) catch std.process.exit(126);
        posix.dup2(devnull, posix.STDERR_FILENO) catch std.process.exit(126);
        posix.close(devnull);

        // Run curl with:
        // -X POST: POST method
        // -d: request body
        // -H "Expect: 100-continue": explicitly request 100 Continue
        // -s: silent mode
        // -S: show errors
        // -i: include headers in output
        // -m: timeout in seconds
        // --expect100-timeout 1: wait 1 second for 100 Continue before sending body
        const argv = [_:null]?[*:0]const u8{
            "curl",
            "-X",
            "POST",
            "-d",
            body_z,
            "-H",
            "Expect: 100-continue",
            "-H",
            "Content-Type: application/octet-stream",
            "-s",
            "-S",
            "-i",
            "-m",
            std.fmt.comptimePrint("{d}", .{CURL_EXPECT100_TIMEOUT_S}),
            "--expect100-timeout",
            "1",
            url_z,
            null,
        };
        const env = posix.environPtr();
        // TigerStyle S5: execvpeZ returns error (noreturn on success)
        // If we get here, exec failed - exit with error code
        posix.execvpeZ("curl", &argv, env) catch {
            std.process.exit(127);
        };
        unreachable; // execvpeZ only returns on error
    }

    // Parent process
    posix.close(write_fd);

    // Read output from pipe
    var output_buf: [CURL_OUTPUT_MAX_BYTES]u8 = undefined;
    var total: u32 = 0;
    var read_count: u32 = 0;

    // TigerStyle S3: Bounded loop with explicit iteration limit
    while (total < CURL_OUTPUT_MAX_BYTES and read_count < CURL_MAX_READS) : (read_count += 1) {
        const n = posix.read(read_fd, output_buf[total..]) catch |err| {
            // TigerStyle S5: Handle EINTR by continuing, others break
            if (err == error.Interrupted) continue;
            break;
        };
        if (n == 0) break;
        total += @intCast(n);
    }

    // Wait for curl to exit
    const wait_result = posix.waitpid(pid, 0);
    // Extract exit status from raw status (WEXITSTATUS macro)
    // On Linux: exit_code = (status >> 8) & 0xff if WIFEXITED(status)
    const exit_code = (wait_result.status >> 8) & 0xff;
    const exited_normally = (wait_result.status & 0x7f) == 0;
    if (!exited_normally or exit_code != 0) {
        return error.CurlFailed;
    }

    if (total == 0) return error.EmptyResponse;

    var data = output_buf[0..total];

    // Skip any 100 Continue responses (curl includes them in output)
    // TigerStyle S3: Bounded loop to prevent infinite loop on malformed data
    var skip_count: u32 = 0;
    const max_skips: u32 = 10;
    while (skip_count < max_skips) : (skip_count += 1) {
        const status = harness.TestClient.parseStatusCode(data) orelse return error.InvalidResponse;
        if (status >= 200) break; // Got final response

        // Skip 1xx response - find next response after \r\n\r\n
        if (std.mem.indexOf(u8, data, "\r\n\r\n")) |end| {
            const next_start = end + 4;
            if (next_start >= data.len) return error.InvalidResponse;
            data = data[next_start..];
        } else {
            return error.InvalidResponse;
        }
    }

    // Parse final status
    const status = harness.TestClient.parseStatusCode(data) orelse return error.InvalidResponse;

    // Parse body
    const body_slice = harness.TestClient.findBody(data) orelse "";
    const resp_body = if (body_slice.len > 0)
        try allocator.dupe(u8, body_slice)
    else
        &[_]u8{};
    // TigerStyle S5: errdefer to free body if backend_id allocation fails
    errdefer if (resp_body.len > 0) allocator.free(resp_body);

    // Parse backend ID header
    const backend_id_slice = harness.TestClient.findHeader(data, "X-Backend-Id");
    const backend_id = if (backend_id_slice) |id|
        try allocator.dupe(u8, id)
    else
        null;

    return .{
        .status = status,
        .body = resp_body,
        .backend_id = backend_id,
        .allocator = allocator,
    };
}
