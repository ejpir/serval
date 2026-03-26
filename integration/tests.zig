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
const assert = std.debug.assert;
const testing = std.testing;
const serval = @import("serval");
const serval_h2 = @import("serval-h2");
const serval_grpc = @import("serval-grpc");
const serval_client = @import("serval-client");
const serval_net = @import("serval-net");
const serval_tls = @import("serval-tls");
const posix = @import("posix_compat.zig");
const harness = @import("harness.zig");
const custom_filter = @import("filters/custom_filter.zig");

const ssl = serval_tls.ssl;

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

/// Performance test (HTTP/1.1): total requests to send.
const PERF_TEST_REQUESTS_H1: u32 = 60000;

/// Performance test (HTTP/1.1): concurrent connections.
const PERF_TEST_CONCURRENCY_H1: u32 = 50;

/// Performance test (HTTP/2): total requests to send.
const PERF_TEST_REQUESTS_H2: u32 = 5000;

/// Performance test (HTTP/2): concurrent connections.
const PERF_TEST_CONCURRENCY_H2: u32 = 10;

/// Performance test (HTTP/2): h2load worker threads.
const PERF_TEST_H2LOAD_THREADS: u32 = 1;

/// Performance test (HTTP/2): h2load max concurrent streams per connection.
const PERF_TEST_H2LOAD_MAX_CONCURRENT_STREAMS: u32 = 10;

/// Performance test (HTTP/2): h2load duration in seconds (0 => request-count mode).
const PERF_TEST_H2LOAD_DURATION_S: u32 = 0;

/// Performance test (HTTP/1.1): minimum acceptable requests per second.
const PERF_TEST_MIN_RPS_H1: f64 = 8000.0;

/// Performance test (HTTP/2): minimum acceptable requests per second.
const PERF_TEST_MIN_RPS_H2: f64 = 1000.0;

/// Performance test: opt-in environment flag.
const PERF_TEST_ENV_ENABLE: []const u8 = "SERVAL_ENABLE_PERF_TEST";

/// Performance test (HTTP/1.1): override request count environment variable.
const PERF_TEST_ENV_REQUESTS_H1: []const u8 = "SERVAL_PERF_TEST_REQUESTS_H1";

/// Performance test (HTTP/2): override request count environment variable.
const PERF_TEST_ENV_REQUESTS_H2: []const u8 = "SERVAL_PERF_TEST_REQUESTS_H2";

/// Performance test (HTTP/1.1): override concurrency environment variable.
const PERF_TEST_ENV_CONCURRENCY_H1: []const u8 = "SERVAL_PERF_TEST_CONCURRENCY_H1";

/// Performance test (HTTP/2): override concurrency environment variable.
const PERF_TEST_ENV_CONCURRENCY_H2: []const u8 = "SERVAL_PERF_TEST_CONCURRENCY_H2";

/// Performance test (HTTP/1.1): override minimum throughput environment variable.
const PERF_TEST_ENV_MIN_RPS_H1: []const u8 = "SERVAL_PERF_TEST_MIN_RPS_H1";

/// Performance test (HTTP/2): override minimum throughput environment variable.
const PERF_TEST_ENV_MIN_RPS_H2: []const u8 = "SERVAL_PERF_TEST_MIN_RPS_H2";

/// Performance test (HTTP/2): override h2load worker-thread count.
const PERF_TEST_ENV_H2LOAD_THREADS: []const u8 = "SERVAL_PERF_TEST_H2LOAD_THREADS";

/// Performance test (HTTP/2): override h2load max streams per connection.
const PERF_TEST_ENV_H2LOAD_MAX_STREAMS: []const u8 = "SERVAL_PERF_TEST_H2LOAD_MAX_STREAMS";

/// Performance test (HTTP/2): override h2load duration in seconds (0 => request-count mode).
const PERF_TEST_ENV_H2LOAD_DURATION_S: []const u8 = "SERVAL_PERF_TEST_H2LOAD_DURATION_S";

/// Big payload test: 1MB payload size.
const BIG_PAYLOAD_SIZE_1MB: usize = 1024 * 1024;

/// Big payload test: 100KB payload size.
const BIG_PAYLOAD_SIZE_100KB: usize = 100 * 1024;

/// Big payload test: 100MB payload size.
const BIG_PAYLOAD_SIZE_100MB: usize = 100 * 1024 * 1024;

/// Generated-stream payload sanity size for non-skip coverage.
const BIG_PAYLOAD_SIZE_16MB: usize = 16 * 1024 * 1024;

/// Big payload test: 5GB payload size (exceeds 4GB iteration limit).
/// TigerStyle: Explicit constant for >4GB file support validation.
const BIG_PAYLOAD_SIZE_5GB: usize = 5 * 1024 * 1024 * 1024;

/// Default receive timeout applied to integration TCP client sockets.
/// Prevents indefinite hangs on blocking recv() when a frame never arrives.
const TCP_RECV_TIMEOUT_SEC: isize = 20;

fn init_test_io_runtime(runtime: *std.Io.Evented, allocator: std.mem.Allocator) !void {
    try runtime.init(allocator, .{ .thread_limit = 0 });
}

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
    tls: bool = false,
};

fn startWebSocketBackend(config: WebSocketBackendConfig) !std.Thread {
    return try std.Thread.spawn(.{}, websocketBackendMain, .{config});
}

fn websocketBackendMain(config: WebSocketBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    if (config.tls) {
        const tls_ctx = try createTestServerTlsCtx();
        defer ssl.SSL_CTX_free(tls_ctx);

        const conn = try acceptTcp(listener);
        var socket = serval.Socket.TLS.TLSSocket.init_server(conn, tls_ctx) catch |err| {
            posix.close(conn);
            return err;
        };
        defer socket.close();

        var request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const request_len = try readUntilHeadersCompleteSocket(&socket, &request_buf);
        const request = request_buf[0..request_len];

        try testing.expect(std.mem.indexOf(u8, request, "GET ") != null);
        try testing.expect(std.mem.indexOf(u8, request, config.path) != null);
        try testing.expect(std.mem.indexOf(u8, request, "Upgrade: websocket") != null);
        try testing.expect(std.mem.indexOf(u8, request, "Sec-WebSocket-Key: " ++ WS_TEST_KEY) != null);

        switch (config.mode) {
            .echo_after_upgrade => {
                var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
                const response = try buildSwitchingProtocolsResponse(WS_TEST_ACCEPT, &response_buf);
                try sendAllSocket(&socket, response);

                var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
                const payload = try readMaskedClientTextFrameSocket(&socket, &frame_buf);

                var response_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
                const frame = try buildServerTextFrame(payload, &response_frame_buf);
                try sendAllSocket(&socket, frame);
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
                try sendAllSocket(&socket, response);
            },
            .invalid_accept => {
                var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
                const response = try buildSwitchingProtocolsResponse("invalid-accept-value", &response_buf);
                try sendAllSocket(&socket, response);
            },
        }
        return;
    }

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

    const recv_timeout = posix.timeval{
        .sec = TCP_RECV_TIMEOUT_SEC,
        .usec = 0,
    };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&recv_timeout));

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

fn createTestServerTlsCtx() !*ssl.SSL_CTX {
    ssl.init();
    const ctx = try ssl.createServerCtx();
    errdefer ssl.SSL_CTX_free(ctx);

    const allocator = std.heap.c_allocator;

    const cert_path = try allocator.dupeZ(u8, harness.TEST_CERT_PATH);
    defer allocator.free(cert_path);
    if (ssl.SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
        ssl.printErrors();
        return error.LoadCertFailed;
    }

    const key_path = try allocator.dupeZ(u8, harness.TEST_KEY_PATH);
    defer allocator.free(key_path);
    if (ssl.SSL_CTX_use_PrivateKey_file(ctx, key_path, ssl.SSL_FILETYPE_PEM) != 1) {
        ssl.printErrors();
        return error.LoadKeyFailed;
    }

    return ctx;
}

fn connectTcpTls(port: u16, desired_alpn: ?[]const u8) !serval.Socket {
    const sock = try connectTcp(port);
    errdefer posix.close(sock);

    ssl.init();
    const ctx = try ssl.createClientCtx();
    defer ssl.SSL_CTX_free(ctx);

    ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_NONE, null);

    return serval.Socket.TLS.TLSSocket.init_client(
        sock,
        ctx,
        "127.0.0.1",
        false,
        desired_alpn,
    );
}

fn sendAllSocket(socket: *serval.Socket, data: []const u8) !void {
    try socket.write_all(data);
}

fn readUntilHeadersCompleteSocket(socket: *serval.Socket, buf: []u8) !usize {
    var total: usize = 0;
    var iterations: u32 = 0;

    while (total < buf.len and iterations < WS_TEST_MAX_READS) : (iterations += 1) {
        const n_u32 = try socket.read(buf[total..]);
        if (n_u32 == 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_u32);
        total += n;
        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) return total;
    }

    return error.HeadersTooLarge;
}

fn readFrameBytesSocket(socket: *serval.Socket, out: []u8) !usize {
    var total: usize = 0;
    var iterations: u32 = 0;

    while (total < out.len and iterations < WS_TEST_MAX_READS) : (iterations += 1) {
        const n_u32 = try socket.read(out[total..]);
        if (n_u32 == 0) break;
        const n: usize = @intCast(n_u32);
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

fn readMaskedClientTextFrameSocket(socket: *serval.Socket, out: []u8) ![]const u8 {
    const total = try readFrameBytesSocket(socket, out);
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

fn readServerTextFrameSocket(socket: *serval.Socket, initial: []const u8, out: []u8) ![]const u8 {
    var total: usize = 0;
    if (initial.len > 0) {
        if (initial.len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..initial.len], initial);
        total = initial.len;
    }

    while (total < 2) {
        const n_u32 = try socket.read(out[total..]);
        if (n_u32 == 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_u32);
        total += n;
    }

    if (out[0] != 0x81) return error.InvalidFrame;
    if ((out[1] & 0x80) != 0) return error.InvalidFrame;

    const payload_len: usize = out[1] & 0x7f;
    if (payload_len > WS_TEST_MAX_PAYLOAD_BYTES) return error.PayloadTooLarge;
    while (total < payload_len + 2) {
        const n_u32 = try socket.read(out[total..]);
        if (n_u32 == 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_u32);
        total += n;
    }

    return out[2 .. 2 + payload_len];
}

fn readServerFrameSocket(socket: *serval.Socket, initial: []const u8, out: []u8) !struct {
    opcode: serval.WebSocketOpcode,
    fin: bool,
    payload: []const u8,
    remaining: []const u8,
} {
    var total: usize = 0;
    if (initial.len > 0) {
        if (initial.len > out.len) return error.BufferTooSmall;
        std.mem.copyForwards(u8, out[0..initial.len], initial);
        total = initial.len;
    }

    while (total < 2) {
        const n_u32 = try socket.read(out[total..]);
        if (n_u32 == 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_u32);
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
        const n_u32 = try socket.read(out[total..]);
        if (n_u32 == 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_u32);
        total += n;
    }

    const header = try serval.parseWebSocketFrameHeader(out[0..header_len], .server);
    const frame_len: usize = header_len + @as(usize, @intCast(header.payload_len));

    while (total < frame_len) {
        const n_u32 = try socket.read(out[total..]);
        if (n_u32 == 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_u32);
        total += n;
    }

    return .{
        .opcode = header.opcode,
        .fin = header.fin,
        .payload = out[header_len..frame_len],
        .remaining = out[frame_len..total],
    };
}

fn sendClientCloseSocket(socket: *serval.Socket) !void {
    var payload_buf: [serval.config.WEBSOCKET_MAX_CONTROL_PAYLOAD_SIZE_BYTES]u8 = undefined;
    const payload = try serval.buildWebSocketClosePayload(
        &payload_buf,
        serval.websocket.close_normal_closure,
        "",
    );

    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const frame_bytes = try buildMaskedClientFrameWithOpcode(.close, true, payload, &frame_buf);
    try sendAllSocket(socket, frame_bytes);
}

fn performClientCloseHandshakeSocket(socket: *serval.Socket) !void {
    try sendClientCloseSocket(socket);

    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const server_frame = readServerFrameSocket(socket, &[_]u8{}, &frame_buf) catch |err| switch (err) {
        error.ConnectionClosed, error.TLSError => return,
        else => return err,
    };
    if (server_frame.opcode != .close) return error.InvalidFrame;
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
    var evented: std.Io.Evented = undefined;
    init_test_io_runtime(&evented, std.heap.page_allocator) catch |err| {
        std.log.err("native websocket test io init failed: {s}", .{@errorName(err)});
        return;
    };
    defer evented.deinit();

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

    server.run(evented.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
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

test "integration: lb proxies websocket over wss frontend and relays client text frame" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    const backend_thread = try startWebSocketBackend(.{
        .port = backend_port,
        .mode = .echo_after_upgrade,
        .path = "/ws-tls-frontend",
        .payload = "",
    });
    defer backend_thread.join();

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
    });

    var socket = try connectTcpTls(lb_port, "http/1.1");
    defer socket.close();

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake("/ws-tls-frontend", lb_port, &handshake_buf);

    var client_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const client_frame = try buildMaskedClientTextFrame("hello-wss-frontend", &client_frame_buf);

    var request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf, "{s}{s}", .{ handshake, client_frame });
    try sendAllSocket(&socket, request);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersCompleteSocket(&socket, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);

    const header_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const payload = try readServerTextFrameSocket(&socket, response_buf[header_end..response_len], &frame_buf);
    try testing.expectEqualStrings("hello-wss-frontend", payload);
}

test "integration: lb proxies websocket to wss upstream backend" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    const backend_thread = try startWebSocketBackend(.{
        .port = backend_port,
        .mode = .echo_after_upgrade,
        .path = "/ws-tls-upstream",
        .payload = "",
        .tls = true,
    });
    defer backend_thread.join();

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{
        .upstream_tls = &.{backend_addr},
        .insecure_skip_verify = true,
    });

    const sock = try connectTcp(lb_port);
    defer posix.close(sock);

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake("/ws-tls-upstream", lb_port, &handshake_buf);

    var client_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const client_frame = try buildMaskedClientTextFrame("hello-wss-upstream", &client_frame_buf);

    var request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf, "{s}{s}", .{ handshake, client_frame });
    try sendAllTcp(sock, request);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);

    const header_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const payload = try readServerTextFrame(sock, response_buf[header_end..response_len], &frame_buf);
    try testing.expectEqualStrings("hello-wss-upstream", payload);
}

test "integration: lb proxies websocket over wss frontend to wss backend" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    const backend_thread = try startWebSocketBackend(.{
        .port = backend_port,
        .mode = .echo_after_upgrade,
        .path = "/ws-tls-both",
        .payload = "",
        .tls = true,
    });
    defer backend_thread.join();

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
        .upstream_tls = &.{backend_addr},
        .insecure_skip_verify = true,
    });

    var socket = try connectTcpTls(lb_port, "http/1.1");
    defer socket.close();

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake("/ws-tls-both", lb_port, &handshake_buf);

    var client_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const client_frame = try buildMaskedClientTextFrame("hello-wss-both", &client_frame_buf);

    var request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf, "{s}{s}", .{ handshake, client_frame });
    try sendAllSocket(&socket, request);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersCompleteSocket(&socket, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);

    const header_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const payload = try readServerTextFrameSocket(&socket, response_buf[header_end..response_len], &frame_buf);
    try testing.expectEqualStrings("hello-wss-both", payload);
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
// gRPC / h2c Integration Tests
// =============================================================================

const H2_TEST_BUFFER_SIZE_BYTES: u32 = 16 * 1024;
const H2_MAX_HEADER_FIELDS: u32 = 16;
const H2_SERVER_STARTUP_DELAY_MS: u64 = 100;
const H2_MAX_FRAME_READS: u32 = 16;
const H2_FLOW_CONTROL_CHUNK_SIZE_BYTES: u32 = 9000;
const H2_FLOW_CONTROL_CHUNK_COUNT: u32 = 8;
const H2_FLOW_CONTROL_REQUEST_BUFFER_SIZE_BYTES: u32 = 96 * 1024;
const H2_TELEMETRY_WAIT_POLL_MS: u64 = 2;
const H2_TELEMETRY_WAIT_TIMEOUT_MS: u64 = 500;

fn waitForAtomicU32Equals(value: *const std.atomic.Value(u32), expected: u32, timeout_ms: u64) !void {
    var elapsed_ms: u64 = 0;
    while (elapsed_ms <= timeout_ms) : (elapsed_ms += H2_TELEMETRY_WAIT_POLL_MS) {
        if (value.load(.monotonic) == expected) return;
        posix.nanosleep(0, H2_TELEMETRY_WAIT_POLL_MS * std.time.ns_per_ms);
    }

    return error.Timeout;
}

const H2MainServerTelemetryShared = struct {
    request_starts: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    request_ends: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    spans_started: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    spans_ended: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    stream_status_attrs: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    span_error_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    last_status: std.atomic.Value(u16) = std.atomic.Value(u16).init(0),
    stream_log_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    stream_log_2xx_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    stream_log_last_status: std.atomic.Value(u16) = std.atomic.Value(u16).init(0),
    stream_log_last_request_number: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

const H2MainServerTelemetryMetrics = struct {
    shared: *H2MainServerTelemetryShared,

    pub fn requestStart(self: *@This()) void {
        _ = self.shared.request_starts.fetchAdd(1, .monotonic);
    }

    pub fn requestEnd(self: *@This(), status: u16, duration_ns: u64) void {
        _ = duration_ns;
        self.shared.last_status.store(status, .monotonic);
        _ = self.shared.request_ends.fetchAdd(1, .monotonic);
    }

    pub fn connectionOpened(self: *@This()) void {
        _ = self;
    }

    pub fn connectionClosed(self: *@This()) void {
        _ = self;
    }
};

const H2MainServerTelemetryTracer = struct {
    shared: *H2MainServerTelemetryShared,

    pub fn startSpan(self: *@This(), name: []const u8, parent: ?serval.SpanHandle) serval.SpanHandle {
        _ = name;
        _ = parent;
        _ = self.shared.spans_started.fetchAdd(1, .monotonic);

        var span = serval.SpanHandle{};
        span.trace_id[0] = 1;
        span.span_id[7] = 1;
        return span;
    }

    pub fn endSpan(self: *@This(), handle: serval.SpanHandle, err: ?[]const u8) void {
        _ = handle;
        _ = self.shared.spans_ended.fetchAdd(1, .monotonic);
        if (err != null) {
            _ = self.shared.span_error_count.fetchAdd(1, .monotonic);
        }
    }

    pub fn setStringAttribute(self: *@This(), handle: serval.SpanHandle, key: []const u8, value: []const u8) void {
        _ = self;
        _ = handle;
        _ = key;
        _ = value;
    }

    pub fn setIntAttribute(self: *@This(), handle: serval.SpanHandle, key: []const u8, value: i64) void {
        _ = handle;
        _ = value;
        if (std.mem.eql(u8, key, "http.response.status_code")) {
            _ = self.shared.stream_status_attrs.fetchAdd(1, .monotonic);
        }
    }
};

const H2HeaderPair = struct {
    name: []const u8,
    value: []const u8,
};

const H2FrameView = struct {
    header: serval_h2.FrameHeader,
    payload: []const u8,
    remaining: []const u8,
};

const GrpcH2BackendMode = enum {
    unary,
    server_streaming,
};

const GrpcH2BackendConfig = struct {
    port: u16,
    path: []const u8,
    mode: GrpcH2BackendMode,
    tls: bool = false,
    first_response: []const u8,
    second_response: ?[]const u8 = null,
    omit_grpc_status: bool = false,
    split_response_headers_continuation: bool = false,
    split_response_trailers_continuation: bool = false,
    response_headers_use_incremental_indexing: bool = false,
    response_headers_add_huffman_header: bool = false,
    trailers_include_dynamic_indexed_content_type: bool = false,
    trailers_only_response: bool = false,
    expected_request_header_name: ?[]const u8 = null,
    expected_request_header_value: ?[]const u8 = null,
    response_header_name: ?[]const u8 = null,
    response_header_value: ?[]const u8 = null,
    response_trailer_name: ?[]const u8 = null,
    response_trailer_value: ?[]const u8 = null,
    drain_request_until_end_stream: bool = false,
};

const GenericH2BackendConfig = struct {
    port: u16,
    path: []const u8,
    response_status: []const u8 = "200",
    response_content_type: ?[]const u8 = "text/plain",
    response_payload: ?[]const u8 = "generic-h2-backend-response",
    headers_end_stream: bool = false,
    send_response_trailers: bool = false,
    response_trailer_name: ?[]const u8 = null,
    response_trailer_value: ?[]const u8 = null,
};

const MinimalH2BridgeBackendConfig = struct {
    port: u16,
};

const GrpcH2ResetBackendConfig = struct {
    port: u16,
    path: []const u8,
    error_code_raw: u32,
};

const GrpcH2GoAwayBackendConfig = struct {
    port: u16,
    path: []const u8,
    last_stream_id: u32,
    error_code_raw: u32,
    response_payload: ?[]const u8 = null,
};

const ParsedGrpcStreamRequest = struct {
    stream_id: u32,
    path: []const u8,
    payload: []const u8,
};

fn buildH2HeaderBlock(pairs: []const H2HeaderPair, out: []u8) ![]const u8 {
    var len: usize = 0;
    for (pairs) |pair| {
        const encoded = try serval_h2.encodeLiteralHeaderWithoutIndexing(out[len..], pair.name, pair.value);
        len += encoded.len;
    }
    return out[0..len];
}

fn appendLiteralHeaderWithoutIndexingHuffmanValue(
    out: []u8,
    name: []const u8,
    huffman_value: []const u8,
) ![]const u8 {
    if (name.len == 0) return error.InvalidHeaderName;
    if (name.len > 0x7f) return error.HeaderTooLarge;
    if (huffman_value.len > 0x7f) return error.HeaderTooLarge;

    const needed = 1 + 1 + name.len + 1 + huffman_value.len;
    if (out.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    out[pos] = 0x00; // literal without indexing, literal name
    pos += 1;

    out[pos] = @intCast(name.len); // plain-name length
    pos += 1;

    @memcpy(out[pos..][0..name.len], name);
    pos += name.len;

    out[pos] = 0x80 | @as(u8, @intCast(huffman_value.len)); // Huffman value
    pos += 1;

    @memcpy(out[pos..][0..huffman_value.len], huffman_value);
    pos += huffman_value.len;

    return out[0..pos];
}

fn buildGrpcBackendResponseHeaders(
    use_incremental_indexing: bool,
    add_huffman_header: bool,
    response_header_name: ?[]const u8,
    response_header_value: ?[]const u8,
    out: []u8,
) ![]const u8 {
    var len: usize = 0;

    const status = try serval_h2.encodeIndexedHeaderField(out[len..], 8); // :status 200
    len += status.len;

    if (use_incremental_indexing) {
        const content_type = try serval_h2.encodeLiteralHeaderWithIncrementalIndexing(
            out[len..],
            "content-type",
            "application/grpc",
        );
        len += content_type.len;
    } else {
        const content_type = try serval_h2.encodeLiteralHeaderWithoutIndexing(
            out[len..],
            "content-type",
            "application/grpc",
        );
        len += content_type.len;
    }

    if (response_header_name) |header_name| {
        const header_value = response_header_value orelse return error.MissingResponseHeaderValue;
        const extra_header = try serval_h2.encodeLiteralHeaderWithoutIndexing(
            out[len..],
            header_name,
            header_value,
        );
        len += extra_header.len;
    } else if (response_header_value != null) {
        return error.MissingResponseHeaderName;
    }

    if (add_huffman_header) {
        const huffman_www_example_com = [_]u8{
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
            0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        };
        const huffman_header = try appendLiteralHeaderWithoutIndexingHuffmanValue(
            out[len..],
            "x-hpack-huf",
            &huffman_www_example_com,
        );
        len += huffman_header.len;
    }

    return out[0..len];
}

fn appendH2Frame(
    out: []u8,
    frame_type: serval_h2.FrameType,
    flags: u8,
    stream_id: u32,
    payload: []const u8,
) ![]const u8 {
    if (out.len < serval_h2.frame_header_size_bytes + payload.len) return error.BufferTooSmall;

    const header = try serval_h2.buildFrameHeader(out[0..serval_h2.frame_header_size_bytes], .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    @memcpy(out[header.len..][0..payload.len], payload);
    return out[0 .. header.len + payload.len];
}

fn buildGrpcH2StreamFrames(
    path: []const u8,
    authority: []const u8,
    payload: []const u8,
    stream_id: u32,
    out: []u8,
) ![]const u8 {
    var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const grpc_message = try serval_grpc.buildMessage(&grpc_buf, false, payload);

    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, &header_block_buf);

    var pos: usize = 0;
    const headers_frame = try appendH2Frame(out[pos..], .headers, serval_h2.flags_end_headers, stream_id, header_block);
    pos += headers_frame.len;

    const data_frame = try appendH2Frame(out[pos..], .data, serval_h2.flags_end_stream, stream_id, grpc_message);
    pos += data_frame.len;

    return out[0..pos];
}

fn buildGrpcH2Request(path: []const u8, authority: []const u8, payload: []const u8, out: []u8) ![]const u8 {
    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const stream_frames = try buildGrpcH2StreamFrames(path, authority, payload, 1, out[pos..]);
    pos += stream_frames.len;

    return out[0..pos];
}

fn buildSimpleH2GetRequest(path: []const u8, authority: []const u8, scheme: []const u8, out: []u8) ![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);
    assert(scheme.len > 0);

    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = scheme },
        .{ .name = ":authority", .value = authority },
    }, &header_block_buf);

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const headers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers | serval_h2.flags_end_stream,
        1,
        header_block,
    );
    pos += headers_frame.len;

    return out[0..pos];
}

fn buildSimpleH2GetRequestWithInvalidTe(path: []const u8, authority: []const u8, scheme: []const u8, out: []u8) ![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);
    assert(scheme.len > 0);

    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = scheme },
        .{ .name = ":authority", .value = authority },
        .{ .name = "te", .value = "gzip" },
    }, &header_block_buf);

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const headers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers | serval_h2.flags_end_stream,
        1,
        header_block,
    );
    pos += headers_frame.len;

    return out[0..pos];
}

fn buildSimpleH2PostRequest(
    path: []const u8,
    authority: []const u8,
    scheme: []const u8,
    body: []const u8,
    out: []u8,
) ![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);
    assert(scheme.len > 0);

    var content_length_buf: [20]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&content_length_buf, "{d}", .{body.len});

    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = scheme },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "content-length", .value = content_length },
    }, &header_block_buf);

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const headers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers,
        1,
        header_block,
    );
    pos += headers_frame.len;

    const data_frame = try appendH2Frame(
        out[pos..],
        .data,
        serval_h2.flags_end_stream,
        1,
        body,
    );
    pos += data_frame.len;

    return out[0..pos];
}

fn buildSimpleH2PostStreamFrames(
    path: []const u8,
    authority: []const u8,
    scheme: []const u8,
    body: []const u8,
    stream_id: u32,
    out: []u8,
) ![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);
    assert(scheme.len > 0);
    assert(stream_id > 0);

    var content_length_buf: [20]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&content_length_buf, "{d}", .{body.len});

    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = scheme },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "content-length", .value = content_length },
    }, &header_block_buf);

    var pos: usize = 0;

    const headers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers,
        stream_id,
        header_block,
    );
    pos += headers_frame.len;

    const data_frame = try appendH2Frame(
        out[pos..],
        .data,
        serval_h2.flags_end_stream,
        stream_id,
        body,
    );
    pos += data_frame.len;

    return out[0..pos];
}

fn buildSimpleH2PostRequestWithoutContentLength(
    path: []const u8,
    authority: []const u8,
    scheme: []const u8,
    body_part1: []const u8,
    body_part2: []const u8,
    out: []u8,
) ![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);
    assert(scheme.len > 0);
    assert(body_part1.len + body_part2.len > 0);

    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = scheme },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "text/plain" },
    }, &header_block_buf);

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const headers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers,
        1,
        header_block,
    );
    pos += headers_frame.len;

    const data_frame_1 = try appendH2Frame(
        out[pos..],
        .data,
        0,
        1,
        body_part1,
    );
    pos += data_frame_1.len;

    const data_frame_2 = try appendH2Frame(
        out[pos..],
        .data,
        serval_h2.flags_end_stream,
        1,
        body_part2,
    );
    pos += data_frame_2.len;

    return out[0..pos];
}

fn buildSimpleH2PostStreamWithTrailersFrames(
    path: []const u8,
    authority: []const u8,
    scheme: []const u8,
    body: []const u8,
    stream_id: u32,
    out: []u8,
) ![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);
    assert(scheme.len > 0);
    assert(stream_id > 0);

    var content_length_buf: [20]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&content_length_buf, "{d}", .{body.len});

    var request_header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = scheme },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "content-length", .value = content_length },
    }, &request_header_block_buf);

    var trailer_header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const trailer_header_block = try buildH2HeaderBlock(&.{
        .{ .name = "x-extra-trailer", .value = "trailer-value" },
    }, &trailer_header_block_buf);

    var pos: usize = 0;

    const headers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers,
        stream_id,
        request_header_block,
    );
    pos += headers_frame.len;

    const data_frame = try appendH2Frame(
        out[pos..],
        .data,
        0,
        stream_id,
        body,
    );
    pos += data_frame.len;

    const trailers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers | serval_h2.flags_end_stream,
        stream_id,
        trailer_header_block,
    );
    pos += trailers_frame.len;

    return out[0..pos];
}

fn buildSimpleH2PostRequestWithTrailers(
    path: []const u8,
    authority: []const u8,
    scheme: []const u8,
    body: []const u8,
    out: []u8,
) ![]const u8 {
    assert(path.len > 0);
    assert(authority.len > 0);
    assert(scheme.len > 0);

    var content_length_buf: [20]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&content_length_buf, "{d}", .{body.len});

    var request_header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = scheme },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "content-length", .value = content_length },
    }, &request_header_block_buf);

    var trailer_header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const trailer_header_block = try buildH2HeaderBlock(&.{
        .{ .name = "x-extra-trailer", .value = "trailer-value" },
    }, &trailer_header_block_buf);

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const headers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers,
        1,
        request_header_block,
    );
    pos += headers_frame.len;

    const data_frame = try appendH2Frame(
        out[pos..],
        .data,
        0,
        1,
        body,
    );
    pos += data_frame.len;

    const trailers_frame = try appendH2Frame(
        out[pos..],
        .headers,
        serval_h2.flags_end_headers | serval_h2.flags_end_stream,
        1,
        trailer_header_block,
    );
    pos += trailers_frame.len;

    return out[0..pos];
}

fn buildGrpcH2RequestWithExtraHeaders(
    path: []const u8,
    authority: []const u8,
    payload: []const u8,
    extra_headers: []const H2HeaderPair,
    out: []u8,
) ![]const u8 {
    var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const grpc_message = try serval_grpc.buildMessage(&grpc_buf, false, payload);

    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var header_len: usize = 0;

    const base_headers = [_]H2HeaderPair{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    };

    for (base_headers) |pair| {
        const encoded = try serval_h2.encodeLiteralHeaderWithoutIndexing(header_block_buf[header_len..], pair.name, pair.value);
        header_len += encoded.len;
    }

    for (extra_headers) |pair| {
        const encoded = try serval_h2.encodeLiteralHeaderWithoutIndexing(header_block_buf[header_len..], pair.name, pair.value);
        header_len += encoded.len;
    }

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[pos..][0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const headers_frame = try appendH2Frame(out[pos..], .headers, serval_h2.flags_end_headers, 1, header_block_buf[0..header_len]);
    pos += headers_frame.len;

    const data_frame = try appendH2Frame(out[pos..], .data, serval_h2.flags_end_stream, 1, grpc_message);
    pos += data_frame.len;

    return out[0..pos];
}

fn buildGrpcH2RequestWithPing(path: []const u8, authority: []const u8, payload: []const u8, out: []u8) ![]const u8 {
    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const ping_payload = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const ping_frame = try appendH2Frame(out[pos..], .ping, 0, 0, &ping_payload);
    pos += ping_frame.len;

    const stream_frames = try buildGrpcH2StreamFrames(path, authority, payload, 1, out[pos..]);
    pos += stream_frames.len;

    return out[0..pos];
}

fn buildH2DataBeforeHeadersRequest(payload: []const u8, out: []u8) ![]const u8 {
    assert(payload.len > 0);

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const data_frame = try appendH2Frame(out[pos..], .data, serval_h2.flags_end_stream, 1, payload);
    pos += data_frame.len;

    return out[0..pos];
}

fn buildH2UpgradeDataBeforeHeadersFrames(payload: []const u8, include_preface: bool, out: []u8) ![]const u8 {
    assert(payload.len > 0);

    var pos: usize = 0;
    if (include_preface) {
        if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
        @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
        pos += serval_h2.client_connection_preface.len;
    }

    const data_frame = try appendH2Frame(out[pos..], .data, serval_h2.flags_end_stream, 3, payload);
    pos += data_frame.len;

    return out[0..pos];
}

fn buildGrpcH2ResetThenUnaryRequest(
    reset_path: []const u8,
    next_path: []const u8,
    authority: []const u8,
    next_payload: []const u8,
    out: []u8,
) ![]const u8 {
    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    var reset_header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const reset_header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = reset_path },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, &reset_header_block_buf);
    const reset_headers = try appendH2Frame(out[pos..], .headers, serval_h2.flags_end_headers, 1, reset_header_block);
    pos += reset_headers.len;

    var rst_payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &rst_payload, @intFromEnum(serval_h2.ErrorCode.cancel), .big);
    const rst_frame = try appendH2Frame(out[pos..], .rst_stream, 0, 1, &rst_payload);
    pos += rst_frame.len;

    const next_frames = try buildGrpcH2StreamFrames(next_path, authority, next_payload, 3, out[pos..]);
    pos += next_frames.len;

    return out[0..pos];
}

fn buildH2FlowControlRequest(path: []const u8, authority: []const u8, out: []u8) ![]const u8 {
    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, &header_block_buf);

    var payload_buf: [H2_FLOW_CONTROL_CHUNK_SIZE_BYTES]u8 = undefined;
    @memset(&payload_buf, 'x');

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const headers_frame = try appendH2Frame(out[pos..], .headers, serval_h2.flags_end_headers, 1, header_block);
    pos += headers_frame.len;

    var chunk_idx: u32 = 0;
    while (chunk_idx < H2_FLOW_CONTROL_CHUNK_COUNT) : (chunk_idx += 1) {
        const flags: u8 = if (chunk_idx + 1 == H2_FLOW_CONTROL_CHUNK_COUNT)
            serval_h2.flags_end_stream
        else
            0;
        const data_frame = try appendH2Frame(out[pos..], .data, flags, 1, &payload_buf);
        pos += data_frame.len;
    }

    return out[0..pos];
}

fn buildGrpcH2InterleavedTwoUnaryRequest(
    first_path: []const u8,
    second_path: []const u8,
    authority: []const u8,
    first_payload: []const u8,
    second_payload: []const u8,
    out: []u8,
) ![]const u8 {
    var first_grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const first_message = try serval_grpc.buildMessage(&first_grpc_buf, false, first_payload);

    var second_grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const second_message = try serval_grpc.buildMessage(&second_grpc_buf, false, second_payload);

    var first_header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const first_header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = first_path },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, &first_header_block_buf);

    var second_header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const second_header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = second_path },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, &second_header_block_buf);

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    const first_headers = try appendH2Frame(out[pos..], .headers, serval_h2.flags_end_headers, 1, first_header_block);
    pos += first_headers.len;

    const second_headers = try appendH2Frame(out[pos..], .headers, serval_h2.flags_end_headers, 3, second_header_block);
    pos += second_headers.len;

    const first_data = try appendH2Frame(out[pos..], .data, serval_h2.flags_end_stream, 1, first_message);
    pos += first_data.len;

    const second_data = try appendH2Frame(out[pos..], .data, serval_h2.flags_end_stream, 3, second_message);
    pos += second_data.len;

    return out[0..pos];
}

fn buildGrpcH2InterleavedManyUnaryRequest(
    path: []const u8,
    authority: []const u8,
    payload: []const u8,
    stream_count: u8,
    out: []u8,
) ![]const u8 {
    assert(stream_count > 0);

    var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const grpc_message = try serval_grpc.buildMessage(&grpc_buf, false, payload);

    var header_block_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const header_block = try buildH2HeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, &header_block_buf);

    var pos: usize = 0;
    if (out.len < serval_h2.client_connection_preface.len) return error.BufferTooSmall;
    @memcpy(out[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);
    pos += serval_h2.client_connection_preface.len;

    const settings_frame = try appendH2Frame(out[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings_frame.len;

    var index: u8 = 0;
    while (index < stream_count) : (index += 1) {
        const stream_id: u32 = 1 + (@as(u32, index) * 2);
        const headers_frame = try appendH2Frame(out[pos..], .headers, serval_h2.flags_end_headers, stream_id, header_block);
        pos += headers_frame.len;
    }

    index = 0;
    while (index < stream_count) : (index += 1) {
        const stream_id: u32 = 1 + (@as(u32, index) * 2);
        const data_frame = try appendH2Frame(out[pos..], .data, serval_h2.flags_end_stream, stream_id, grpc_message);
        pos += data_frame.len;
    }

    return out[0..pos];
}

fn buildGrpcH2UpgradeRequest(path: []const u8, authority: []const u8, payload: []const u8, out: []u8) ![]const u8 {
    var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const grpc_message = try serval_grpc.buildMessage(&grpc_buf, false, payload);

    const settings_payload = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x64 };
    var settings_buf: [16]u8 = undefined;
    const settings_encoded = std.base64.url_safe_no_pad.Encoder.encode(&settings_buf, &settings_payload);

    const headers = try std.fmt.bufPrint(
        out,
        "POST {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Connection: Upgrade, HTTP2-Settings\r\n" ++
            "Upgrade: h2c\r\n" ++
            "HTTP2-Settings: {s}\r\n" ++
            "Content-Type: application/grpc\r\n" ++
            "TE: trailers\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n",
        .{ path, authority, settings_encoded, grpc_message.len },
    );
    if (out.len - headers.len < grpc_message.len) return error.BufferTooSmall;
    @memcpy(out[headers.len..][0..grpc_message.len], grpc_message);
    return out[0 .. headers.len + grpc_message.len];
}

fn buildTextH2UpgradeRequest(path: []const u8, authority: []const u8, payload: []const u8, out: []u8) ![]const u8 {
    const settings_payload = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x64 };
    var settings_buf: [16]u8 = undefined;
    const settings_encoded = std.base64.url_safe_no_pad.Encoder.encode(&settings_buf, &settings_payload);

    const headers = try std.fmt.bufPrint(
        out,
        "POST {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Connection: Upgrade, HTTP2-Settings\r\n" ++
            "Upgrade: h2c\r\n" ++
            "HTTP2-Settings: {s}\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n",
        .{ path, authority, settings_encoded, payload.len },
    );
    if (out.len - headers.len < payload.len) return error.BufferTooSmall;
    @memcpy(out[headers.len..][0..payload.len], payload);
    return out[0 .. headers.len + payload.len];
}

fn readH2Frame(sock: posix.socket_t, initial: []const u8, out: []u8) !H2FrameView {
    var total: usize = 0;
    if (initial.len > 0) {
        if (initial.len > out.len) return error.BufferTooSmall;
        std.mem.copyForwards(u8, out[0..initial.len], initial);
        total = initial.len;
    }

    while (total < serval_h2.frame_header_size_bytes) {
        const n = posix.recv(sock, out[total..], 0) catch |err| switch (err) {
            error.WouldBlock => return error.ReadTimeout,
            else => return err,
        };
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }

    const header = try serval_h2.parseFrameHeader(out[0..serval_h2.frame_header_size_bytes]);
    const frame_len: usize = serval_h2.frame_header_size_bytes + header.length;
    while (total < frame_len) {
        const n = posix.recv(sock, out[total..], 0) catch |err| switch (err) {
            error.WouldBlock => return error.ReadTimeout,
            else => return err,
        };
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }

    return .{
        .header = header,
        .payload = out[serval_h2.frame_header_size_bytes..frame_len],
        .remaining = out[frame_len..total],
    };
}

fn readH2FrameSocket(socket: *serval.Socket, initial: []const u8, out: []u8) !H2FrameView {
    var total: usize = 0;
    if (initial.len > 0) {
        if (initial.len > out.len) return error.BufferTooSmall;
        std.mem.copyForwards(u8, out[0..initial.len], initial);
        total = initial.len;
    }

    while (total < serval_h2.frame_header_size_bytes) {
        const n_u32 = try readSocketRetry(socket, out[total..]);
        if (n_u32 == 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_u32);
        total += n;
    }

    const header = try serval_h2.parseFrameHeader(out[0..serval_h2.frame_header_size_bytes]);
    const frame_len: usize = serval_h2.frame_header_size_bytes + header.length;
    while (total < frame_len) {
        const n_u32 = try readSocketRetry(socket, out[total..]);
        if (n_u32 == 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_u32);
        total += n;
    }

    return .{
        .header = header,
        .payload = out[serval_h2.frame_header_size_bytes..frame_len],
        .remaining = out[frame_len..total],
    };
}

fn readSocketRetry(socket: *serval.Socket, out: []u8) !u32 {
    assert(@intFromPtr(socket) != 0);
    assert(out.len > 0);

    const max_retry_count: u16 = 2000;
    const retry_sleep_ns: u64 = 1 * std.time.ns_per_ms;

    var retry_count: u16 = 0;
    while (retry_count < max_retry_count) : (retry_count += 1) {
        const n = socket.read(out) catch |err| switch (err) {
            error.Timeout, error.Unexpected => {
                posix.nanosleep(0, retry_sleep_ns);
                continue;
            },
            else => return err,
        };
        return n;
    }

    return error.ReadTimeout;
}

fn decodeH2Fields(payload: []const u8, out: []serval_h2.HeaderField) ![]const serval_h2.HeaderField {
    return serval_h2.decodeHeaderBlock(payload, out);
}

fn sendH2SettingsAck(sock: posix.socket_t) !void {
    var buf: [serval_h2.frame_header_size_bytes]u8 = undefined;
    const frame = try appendH2Frame(&buf, .settings, serval_h2.flags_ack, 0, &[_]u8{});
    try sendAllTcp(sock, frame);
}

fn sendH2SettingsAckSocket(socket: *serval.Socket) !void {
    var buf: [serval_h2.frame_header_size_bytes]u8 = undefined;
    const frame = try appendH2Frame(&buf, .settings, serval_h2.flags_ack, 0, &[_]u8{});
    try sendAllSocket(socket, frame);
}

fn sendH2ClientPrefaceAndSettings(sock: posix.socket_t) !void {
    var buf: [serval_h2.client_connection_preface.len + serval_h2.frame_header_size_bytes]u8 = undefined;
    @memcpy(buf[0..serval_h2.client_connection_preface.len], serval_h2.client_connection_preface);

    const settings_frame = try appendH2Frame(
        buf[serval_h2.client_connection_preface.len..],
        .settings,
        0,
        0,
        &[_]u8{},
    );
    const total_len = serval_h2.client_connection_preface.len + settings_frame.len;
    try sendAllTcp(sock, buf[0..total_len]);
}

fn readGrpcPayloadFromDataFrame(frame_view: H2FrameView, out: []u8) ![]const u8 {
    if (frame_view.header.frame_type != .data) return error.InvalidFrame;
    if (frame_view.payload.len > out.len) return error.BufferTooSmall;
    @memcpy(out[0..frame_view.payload.len], frame_view.payload);
    return serval_grpc.parseMessage(out[0..frame_view.payload.len]);
}

fn expectGrpcStatusTrailer(fields: []const serval_h2.HeaderField, expected: []const u8) !void {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, "grpc-status")) {
            try testing.expectEqualStrings(expected, field.value);
            return;
        }
    }
    return error.MissingGrpcStatus;
}

fn findH2FieldValue(fields: []const serval_h2.HeaderField, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

fn sendGrpcUnaryViaUpstreamSession(
    session: *serval_client.H2UpstreamSession,
    path: []const u8,
    authority: []const u8,
    request_payload_text: []const u8,
    expected_response_payload_text: []const u8,
) !void {
    assert(path.len > 0);
    assert(authority.len > 0);

    var request = serval.Request{
        .method = .POST,
        .path = path,
        .version = .@"HTTP/1.1",
        .headers = serval.HeaderMap.init(),
        .body = null,
    };
    try request.headers.put("host", authority);
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    const stream_id = try session.sendRequestHeaders(&request, null, false);

    var request_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_payload = try serval_grpc.buildMessage(&request_payload_buf, false, request_payload_text);
    try session.sendRequestData(stream_id, request_payload, true);

    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const action = session.receiveActionHandlingControl() catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };

        switch (action) {
            .response_headers => |response_headers| {
                try testing.expectEqual(stream_id, response_headers.stream_id);
                try testing.expectEqual(@as(u16, 200), response_headers.response.status);
                saw_headers = true;
            },
            .response_data => |response_data| {
                try testing.expectEqual(stream_id, response_data.stream_id);
                const grpc_payload = try serval_grpc.parseMessage(response_data.payload);
                try testing.expectEqualStrings(expected_response_payload_text, grpc_payload);
                saw_data = true;
            },
            .response_trailers => |response_trailers| {
                try testing.expectEqual(stream_id, response_trailers.stream_id);
                try testing.expectEqualStrings("0", response_trailers.trailers.get("grpc-status").?);
                saw_trailers = true;
                break;
            },
            .stream_reset => return error.UnexpectedAction,
            .connection_close => return error.UnexpectedAction,
            else => {},
        }
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
}

fn sendGrpcUnaryViaStreamBridge(
    bridge: *serval.proxy.H2StreamBridge,
    io: std.Io,
    upstream: serval.Upstream,
    downstream_stream_id: u32,
    authority: []const u8,
    path: []const u8,
    request_payload_text: []const u8,
    expected_response_payload_text: []const u8,
    expect_reused: bool,
    expected_upstream_stream_id: u32,
) !void {
    assert(path.len > 0);
    assert(authority.len > 0);
    assert(downstream_stream_id > 0);

    var request = serval.Request{
        .method = .POST,
        .path = path,
        .version = .@"HTTP/1.1",
        .headers = serval.HeaderMap.init(),
        .body = null,
    };
    try request.headers.put("host", authority);
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    const opened = try bridge.openDownstreamStream(io, upstream, downstream_stream_id, &request, null, false);
    try testing.expectEqual(expect_reused, opened.connect.reused);
    try testing.expectEqual(downstream_stream_id, opened.binding.downstream_stream_id);
    try testing.expectEqual(expected_upstream_stream_id, opened.binding.upstream_stream_id);

    var request_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_payload = try serval_grpc.buildMessage(&request_payload_buf, false, request_payload_text);
    try bridge.sendDownstreamData(downstream_stream_id, request_payload, true);

    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const action = bridge.receiveForUpstream(upstream.idx) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };

        switch (action) {
            .none => {},
            .response_headers => |response_headers| {
                try testing.expectEqual(downstream_stream_id, response_headers.downstream_stream_id);
                try testing.expectEqual(@as(u16, 200), response_headers.response.status);
                saw_headers = true;
            },
            .response_data => |response_data| {
                try testing.expectEqual(downstream_stream_id, response_data.downstream_stream_id);
                const grpc_payload = try serval_grpc.parseMessage(response_data.payload);
                try testing.expectEqualStrings(expected_response_payload_text, grpc_payload);
                saw_data = true;
            },
            .response_trailers => |response_trailers| {
                try testing.expectEqual(downstream_stream_id, response_trailers.downstream_stream_id);
                try testing.expectEqualStrings("0", response_trailers.trailers.get("grpc-status").?);
                saw_trailers = true;
                break;
            },
            .stream_reset => return error.UnexpectedAction,
            .connection_close => return error.UnexpectedAction,
        }
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
    try testing.expectEqual(@as(u16, 0), bridge.activeBindingCount());
}

const TerminatedH2ServerConfig = struct {
    port: u16,
    expected_path: []const u8,
    expected_request_payload: []const u8,
    response_payload: []const u8,
};

const TerminatedH2TelemetryServerConfig = struct {
    port: u16,
    expected_path: []const u8,
    expected_request_payload: []const u8,
    response_payload: []const u8,
    telemetry_shared: *H2MainServerTelemetryShared,
};

const TerminatedH2UnaryHandler = struct {
    expected_path: []const u8,
    expected_request_payload: []const u8,
    response_payload: []const u8,
    telemetry_shared: ?*H2MainServerTelemetryShared = null,
    active_stream_id: u32 = 0,
    stream_open_count: u32 = 0,
    stream_close_count: u32 = 0,
    last_stream_summary: ?serval.server.H2StreamSummary = null,

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        @panic("terminated h2 handler should not select an upstream");
    }

    pub fn handleH2Headers(
        self: *@This(),
        stream_id: u32,
        request: *const serval.Request,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = writer;
        try testing.expectEqualStrings(self.expected_path, request.path);
        try serval_grpc.validateRequest(request);
        try testing.expect(!end_stream);
        self.active_stream_id = stream_id;
    }

    pub fn handleH2Data(
        self: *@This(),
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        try testing.expectEqual(self.active_stream_id, stream_id);
        try testing.expect(end_stream);

        const grpc_payload = try serval_grpc.parseMessage(payload);
        try testing.expectEqualStrings(self.expected_request_payload, grpc_payload);

        var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const response_message = try serval_grpc.buildMessage(&grpc_buf, false, self.response_payload);
        try writer.sendHeaders(200, &.{.{ .name = "content-type", .value = "application/grpc" }}, false);
        try writer.sendData(response_message, false);
        try writer.sendTrailers(&.{.{ .name = "grpc-status", .value = "0" }});
    }

    pub fn handleH2StreamOpen(self: *@This(), stream_id: u32, request: *const serval.Request) void {
        _ = request;
        self.stream_open_count += 1;
        self.active_stream_id = stream_id;
    }

    pub fn handleH2StreamClose(self: *@This(), summary: serval.server.H2StreamSummary) void {
        self.stream_close_count += 1;
        self.last_stream_summary = summary;
    }

    pub fn onLog(self: *@This(), ctx: *serval.Context, entry: serval.LogEntry) void {
        _ = ctx;
        if (self.telemetry_shared) |shared| {
            _ = shared.stream_log_count.fetchAdd(1, .monotonic);
            if (entry.status >= 200 and entry.status < 300) {
                _ = shared.stream_log_2xx_count.fetchAdd(1, .monotonic);
            }
            shared.stream_log_last_status.store(entry.status, .monotonic);
            shared.stream_log_last_request_number.store(entry.request_number, .monotonic);
        }
    }
};

const TerminatedH2ResetServerConfig = struct {
    port: u16,
    reset_path: []const u8,
    next_path: []const u8,
    expected_request_payload: []const u8,
    response_payload: []const u8,
};

const TerminatedH2MultiServerConfig = struct {
    port: u16,
    first_path: []const u8,
    second_path: []const u8,
    first_request_payload: []const u8,
    second_request_payload: []const u8,
    first_response_payload: []const u8,
    second_response_payload: []const u8,
};

const TerminatedH2ResetHandler = struct {
    reset_path: []const u8,
    next_path: []const u8,
    expected_request_payload: []const u8,
    response_payload: []const u8,
    reset_stream_id: u32 = 0,
    active_stream_id: u32 = 0,
    stream_close_count: u32 = 0,
    reset_stream_summary: ?serval.server.H2StreamSummary = null,
    next_stream_summary: ?serval.server.H2StreamSummary = null,

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        @panic("terminated h2 reset handler should not select an upstream");
    }

    pub fn handleH2Headers(
        self: *@This(),
        stream_id: u32,
        request: *const serval.Request,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = writer;
        try serval_grpc.validateRequest(request);
        try testing.expect(!end_stream);

        if (std.mem.eql(u8, request.path, self.reset_path)) {
            self.reset_stream_id = stream_id;
            return;
        }
        try testing.expectEqualStrings(self.next_path, request.path);
        self.active_stream_id = stream_id;
    }

    pub fn handleH2Data(
        self: *@This(),
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        try testing.expectEqual(self.active_stream_id, stream_id);
        try testing.expect(end_stream);

        const grpc_payload = try serval_grpc.parseMessage(payload);
        try testing.expectEqualStrings(self.expected_request_payload, grpc_payload);

        var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const response_message = try serval_grpc.buildMessage(&grpc_buf, false, self.response_payload);
        try writer.sendHeaders(200, &.{.{ .name = "content-type", .value = "application/grpc" }}, false);
        try writer.sendData(response_message, false);
        try writer.sendTrailers(&.{.{ .name = "grpc-status", .value = "0" }});
    }

    pub fn handleH2StreamReset(self: *@This(), stream_id: u32, error_code_raw: u32) void {
        assert(error_code_raw == @intFromEnum(serval_h2.ErrorCode.cancel));
        self.reset_stream_id = stream_id;
    }

    pub fn handleH2StreamClose(self: *@This(), summary: serval.server.H2StreamSummary) void {
        self.stream_close_count += 1;
        if (summary.stream_id == self.reset_stream_id) {
            self.reset_stream_summary = summary;
            return;
        }
        if (summary.stream_id == self.active_stream_id) {
            self.next_stream_summary = summary;
        }
    }
};

const TerminatedH2MultiHandler = struct {
    first_path: []const u8,
    second_path: []const u8,
    first_request_payload: []const u8,
    second_request_payload: []const u8,
    first_response_payload: []const u8,
    second_response_payload: []const u8,
    first_stream_id: u32 = 0,
    second_stream_id: u32 = 0,

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        @panic("terminated h2 multi handler should not select an upstream");
    }

    pub fn handleH2Headers(
        self: *@This(),
        stream_id: u32,
        request: *const serval.Request,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = writer;
        try serval_grpc.validateRequest(request);
        try testing.expect(!end_stream);

        if (std.mem.eql(u8, request.path, self.first_path)) {
            self.first_stream_id = stream_id;
            return;
        }
        if (std.mem.eql(u8, request.path, self.second_path)) {
            self.second_stream_id = stream_id;
            return;
        }

        return error.InvalidPath;
    }

    pub fn handleH2Data(
        self: *@This(),
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        try testing.expect(end_stream);
        const grpc_payload = try serval_grpc.parseMessage(payload);

        var response_payload: []const u8 = undefined;
        if (stream_id == self.first_stream_id) {
            try testing.expectEqualStrings(self.first_request_payload, grpc_payload);
            response_payload = self.first_response_payload;
        } else if (stream_id == self.second_stream_id) {
            try testing.expectEqualStrings(self.second_request_payload, grpc_payload);
            response_payload = self.second_response_payload;
        } else {
            return error.InvalidStreamId;
        }

        var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const response_message = try serval_grpc.buildMessage(&grpc_buf, false, response_payload);
        try writer.sendHeaders(200, &.{.{ .name = "content-type", .value = "application/grpc" }}, false);
        try writer.sendData(response_message, false);
        try writer.sendTrailers(&.{.{ .name = "grpc-status", .value = "0" }});
    }
};

const TerminatedH2ChurnServerConfig = struct {
    port: u16,
    path: []const u8,
    expected_request_payload: []const u8,
    response_payload: []const u8,
    expected_stream_count: u8,
};

const TerminatedH2ChurnHandler = struct {
    path: []const u8,
    expected_request_payload: []const u8,
    response_payload: []const u8,
    expected_stream_count: u8,
    seen_stream_count: u8 = 0,
    completed_stream_count: u8 = 0,
    stream_ids: [serval.config.H2_MAX_CONCURRENT_STREAMS]u32 = [_]u32{0} ** serval.config.H2_MAX_CONCURRENT_STREAMS,

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        @panic("terminated h2 churn handler should not select an upstream");
    }

    pub fn handleH2Headers(
        self: *@This(),
        stream_id: u32,
        request: *const serval.Request,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = writer;
        try testing.expectEqualStrings(self.path, request.path);
        try serval_grpc.validateRequest(request);
        try testing.expect(!end_stream);

        if (self.seen_stream_count >= serval.config.H2_MAX_CONCURRENT_STREAMS) return error.TooManyStreams;
        self.stream_ids[self.seen_stream_count] = stream_id;
        self.seen_stream_count += 1;
    }

    pub fn handleH2Data(
        self: *@This(),
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        try testing.expect(end_stream);

        var found_stream = false;
        var index: u8 = 0;
        while (index < self.seen_stream_count) : (index += 1) {
            if (self.stream_ids[index] != stream_id) continue;
            found_stream = true;
            break;
        }
        try testing.expect(found_stream);

        const grpc_payload = try serval_grpc.parseMessage(payload);
        try testing.expectEqualStrings(self.expected_request_payload, grpc_payload);

        var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const response_message = try serval_grpc.buildMessage(&grpc_buf, false, self.response_payload);
        try writer.sendHeaders(200, &.{.{ .name = "content-type", .value = "application/grpc" }}, false);
        try writer.sendData(response_message, false);
        try writer.sendTrailers(&.{.{ .name = "grpc-status", .value = "0" }});

        self.completed_stream_count += 1;
    }
};

const TerminatedH2FlowControlServerConfig = struct {
    port: u16,
    path: []const u8,
    expected_total_bytes: usize,
};

const TerminatedH2FlowControlHandler = struct {
    path: []const u8,
    expected_total_bytes: usize,
    stream_id: u32 = 0,
    total_bytes: usize = 0,

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        @panic("terminated h2 flow-control handler should not select an upstream");
    }

    pub fn handleH2Headers(
        self: *@This(),
        stream_id: u32,
        request: *const serval.Request,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = writer;
        try testing.expectEqualStrings(self.path, request.path);
        try testing.expect(!end_stream);
        self.stream_id = stream_id;
    }

    pub fn handleH2Data(
        self: *@This(),
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        try testing.expectEqual(self.stream_id, stream_id);
        self.total_bytes += payload.len;
        if (!end_stream) return;

        try testing.expectEqual(self.expected_total_bytes, self.total_bytes);

        var body_buf: [64]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf, "received={d}", .{self.total_bytes});
        try writer.sendHeaders(200, &.{.{ .name = "content-type", .value = "text/plain" }}, false);
        try writer.sendData(body, true);
    }
};

fn terminatedH2ServerMain(config: TerminatedH2ServerConfig) void {
    terminatedH2ServerMainImpl(config) catch |err| {
        std.log.err("terminated h2 server failed: {s}", .{@errorName(err)});
    };
}

fn terminatedH2ServerMainImpl(config: TerminatedH2ServerConfig) !void {
    var evented: std.Io.Evented = undefined;
    try init_test_io_runtime(&evented, testing.allocator);
    defer evented.deinit();

    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var handler = TerminatedH2UnaryHandler{
        .expected_path = config.expected_path,
        .expected_request_payload = config.expected_request_payload,
        .response_payload = config.response_payload,
    };
    serval.server.servePlainH2Connection(TerminatedH2UnaryHandler, &handler, conn, evented.io(), 1) catch |err| {
        // Allow the peer to drain fail-closed control frames (GOAWAY) before close.
        posix.nanosleep(0, 10 * std.time.ns_per_ms);
        return err;
    };

    var request_msg_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_message = try serval_grpc.buildMessage(&request_msg_buf, false, config.expected_request_payload);

    var response_msg_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_message = try serval_grpc.buildMessage(&response_msg_buf, false, config.response_payload);

    try testing.expectEqual(@as(u32, 1), handler.stream_open_count);
    try testing.expectEqual(@as(u32, 1), handler.stream_close_count);

    const summary = handler.last_stream_summary orelse return error.MissingStreamSummary;
    try testing.expectEqual(@as(u64, 1), summary.connection_id);
    try testing.expectEqual(@as(u32, 1), summary.stream_id);
    try testing.expectEqual(@as(u16, 200), summary.response_status);
    try testing.expectEqual(@as(u64, @intCast(request_message.len)), summary.request_data_bytes);
    try testing.expectEqual(@as(u64, @intCast(response_message.len)), summary.response_data_bytes);
    try testing.expect(summary.duration_ns > 0);
    try testing.expectEqual(serval.server.H2StreamCloseReason.local_end_stream, summary.close_reason);
    try testing.expectEqual(@as(u32, 0), summary.reset_error_code_raw);
}

fn startTerminatedH2Server(config: TerminatedH2ServerConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, terminatedH2ServerMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

const TerminatedH2AcceptLoopServerShared = struct {
    port: u16,
    shutdown: std.atomic.Value(bool),
    listener_fd: std.atomic.Value(i32),
};

const TerminatedH2AcceptLoopServer = struct {
    shared: *TerminatedH2AcceptLoopServerShared,
    thread: ?std.Thread,

    fn start(config: TerminatedH2ServerConfig) !TerminatedH2AcceptLoopServer {
        const shared = try std.heap.page_allocator.create(TerminatedH2AcceptLoopServerShared);
        errdefer std.heap.page_allocator.destroy(shared);

        shared.* = .{
            .port = config.port,
            .shutdown = std.atomic.Value(bool).init(false),
            .listener_fd = std.atomic.Value(i32).init(-1),
        };

        var server = TerminatedH2AcceptLoopServer{ .shared = shared, .thread = null };
        server.thread = try std.Thread.spawn(.{}, terminatedH2AcceptLoopServerMain, .{ shared, config });
        posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
        return server;
    }

    fn stop(self: *TerminatedH2AcceptLoopServer) void {
        self.shared.shutdown.store(true, .release);
        const wake_sock = connectTcp(self.shared.port) catch null;
        if (wake_sock) |sock| posix.close(sock);
        _ = self.shared.listener_fd.swap(-1, .acq_rel);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        std.heap.page_allocator.destroy(self.shared);
    }
};

const TerminatedH2TelemetryServer = struct {
    shared: *TerminatedH2AcceptLoopServerShared,
    thread: ?std.Thread,

    fn start(config: TerminatedH2TelemetryServerConfig) !TerminatedH2TelemetryServer {
        const shared = try std.heap.page_allocator.create(TerminatedH2AcceptLoopServerShared);
        errdefer std.heap.page_allocator.destroy(shared);

        shared.* = .{
            .port = config.port,
            .shutdown = std.atomic.Value(bool).init(false),
            .listener_fd = std.atomic.Value(i32).init(-1),
        };

        var server = TerminatedH2TelemetryServer{ .shared = shared, .thread = null };
        server.thread = try std.Thread.spawn(.{}, terminatedH2TelemetryServerMain, .{ shared, config });
        posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
        return server;
    }

    fn stop(self: *TerminatedH2TelemetryServer) void {
        self.shared.shutdown.store(true, .release);
        const wake_sock = connectTcp(self.shared.port) catch null;
        if (wake_sock) |sock| posix.close(sock);
        _ = self.shared.listener_fd.swap(-1, .acq_rel);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        std.heap.page_allocator.destroy(self.shared);
    }
};

fn terminatedH2AcceptLoopServerMain(shared: *TerminatedH2AcceptLoopServerShared, config: TerminatedH2ServerConfig) void {
    var handler = TerminatedH2UnaryHandler{
        .expected_path = config.expected_path,
        .expected_request_payload = config.expected_request_payload,
        .response_payload = config.response_payload,
    };
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};
    var evented: std.Io.Evented = undefined;
    init_test_io_runtime(&evented, std.heap.page_allocator) catch |err| {
        std.log.err("terminated h2 accept loop io init failed: {s}", .{@errorName(err)});
        return;
    };
    defer evented.deinit();

    const ServerType = serval.Server(
        TerminatedH2UnaryHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    var server = ServerType.init(
        &handler,
        &pool,
        &metrics,
        &tracer,
        .{ .port = shared.port },
        null,
        serval_net.DnsConfig{},
    );

    server.run(evented.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
        std.log.err("terminated h2 accept-loop server failed: {s}", .{@errorName(err)});
    };
}

fn terminatedH2TelemetryServerMain(shared: *TerminatedH2AcceptLoopServerShared, config: TerminatedH2TelemetryServerConfig) void {
    var handler = TerminatedH2UnaryHandler{
        .expected_path = config.expected_path,
        .expected_request_payload = config.expected_request_payload,
        .response_payload = config.response_payload,
        .telemetry_shared = config.telemetry_shared,
    };
    var pool = serval.SimplePool.init();
    var metrics = H2MainServerTelemetryMetrics{ .shared = config.telemetry_shared };
    var tracer = H2MainServerTelemetryTracer{ .shared = config.telemetry_shared };
    var evented: std.Io.Evented = undefined;
    init_test_io_runtime(&evented, std.heap.page_allocator) catch |err| {
        std.log.err("terminated h2 telemetry io init failed: {s}", .{@errorName(err)});
        return;
    };
    defer evented.deinit();

    const ServerType = serval.Server(
        TerminatedH2UnaryHandler,
        serval.SimplePool,
        H2MainServerTelemetryMetrics,
        H2MainServerTelemetryTracer,
    );
    var server = ServerType.init(
        &handler,
        &pool,
        &metrics,
        &tracer,
        .{ .port = shared.port },
        null,
        serval_net.DnsConfig{},
    );

    server.run(evented.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
        std.log.err("terminated h2 telemetry server failed: {s}", .{@errorName(err)});
    };
}

fn terminatedH2ResetServerMain(config: TerminatedH2ResetServerConfig) void {
    terminatedH2ResetServerMainImpl(config) catch |err| {
        std.log.err("terminated h2 reset server failed: {s}", .{@errorName(err)});
    };
}

fn terminatedH2ResetServerMainImpl(config: TerminatedH2ResetServerConfig) !void {
    var evented: std.Io.Evented = undefined;
    try init_test_io_runtime(&evented, testing.allocator);
    defer evented.deinit();

    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var handler = TerminatedH2ResetHandler{
        .reset_path = config.reset_path,
        .next_path = config.next_path,
        .expected_request_payload = config.expected_request_payload,
        .response_payload = config.response_payload,
    };
    try serval.server.servePlainH2Connection(TerminatedH2ResetHandler, &handler, conn, evented.io(), 2);

    var request_msg_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_message = try serval_grpc.buildMessage(&request_msg_buf, false, config.expected_request_payload);

    var response_msg_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_message = try serval_grpc.buildMessage(&response_msg_buf, false, config.response_payload);

    try testing.expectEqual(@as(u32, 1), handler.reset_stream_id);
    try testing.expectEqual(@as(u32, 2), handler.stream_close_count);

    const reset_summary = handler.reset_stream_summary orelse return error.MissingResetStreamSummary;
    try testing.expectEqual(@as(u64, 2), reset_summary.connection_id);
    try testing.expectEqual(@as(u32, 1), reset_summary.stream_id);
    try testing.expectEqual(@as(u16, 0), reset_summary.response_status);
    try testing.expectEqual(@as(u64, 0), reset_summary.request_data_bytes);
    try testing.expectEqual(@as(u64, 0), reset_summary.response_data_bytes);
    try testing.expect(reset_summary.duration_ns > 0);
    try testing.expectEqual(serval.server.H2StreamCloseReason.peer_reset, reset_summary.close_reason);
    try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.cancel)), reset_summary.reset_error_code_raw);

    const next_summary = handler.next_stream_summary orelse return error.MissingNextStreamSummary;
    try testing.expectEqual(@as(u64, 2), next_summary.connection_id);
    try testing.expectEqual(handler.active_stream_id, next_summary.stream_id);
    try testing.expectEqual(@as(u16, 200), next_summary.response_status);
    try testing.expectEqual(@as(u64, @intCast(request_message.len)), next_summary.request_data_bytes);
    try testing.expectEqual(@as(u64, @intCast(response_message.len)), next_summary.response_data_bytes);
    try testing.expect(next_summary.duration_ns > 0);
    try testing.expectEqual(serval.server.H2StreamCloseReason.local_end_stream, next_summary.close_reason);
    try testing.expectEqual(@as(u32, 0), next_summary.reset_error_code_raw);
}

fn startTerminatedH2ResetServer(config: TerminatedH2ResetServerConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, terminatedH2ResetServerMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

fn terminatedH2MultiServerMain(config: TerminatedH2MultiServerConfig) void {
    terminatedH2MultiServerMainImpl(config) catch |err| {
        std.log.err("terminated h2 multi server failed: {s}", .{@errorName(err)});
    };
}

fn terminatedH2MultiServerMainImpl(config: TerminatedH2MultiServerConfig) !void {
    var evented: std.Io.Evented = undefined;
    try init_test_io_runtime(&evented, testing.allocator);
    defer evented.deinit();

    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var handler = TerminatedH2MultiHandler{
        .first_path = config.first_path,
        .second_path = config.second_path,
        .first_request_payload = config.first_request_payload,
        .second_request_payload = config.second_request_payload,
        .first_response_payload = config.first_response_payload,
        .second_response_payload = config.second_response_payload,
    };
    try serval.server.servePlainH2Connection(TerminatedH2MultiHandler, &handler, conn, evented.io(), 3);
}

fn startTerminatedH2MultiServer(config: TerminatedH2MultiServerConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, terminatedH2MultiServerMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

fn terminatedH2ChurnServerMain(config: TerminatedH2ChurnServerConfig) void {
    terminatedH2ChurnServerMainImpl(config) catch |err| {
        std.log.err("terminated h2 churn server failed: {s}", .{@errorName(err)});
    };
}

fn terminatedH2ChurnServerMainImpl(config: TerminatedH2ChurnServerConfig) !void {
    var evented: std.Io.Evented = undefined;
    try init_test_io_runtime(&evented, testing.allocator);
    defer evented.deinit();

    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var handler = TerminatedH2ChurnHandler{
        .path = config.path,
        .expected_request_payload = config.expected_request_payload,
        .response_payload = config.response_payload,
        .expected_stream_count = config.expected_stream_count,
    };
    try serval.server.servePlainH2Connection(TerminatedH2ChurnHandler, &handler, conn, evented.io(), 5);

    try testing.expectEqual(config.expected_stream_count, handler.completed_stream_count);
}

fn startTerminatedH2ChurnServer(config: TerminatedH2ChurnServerConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, terminatedH2ChurnServerMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

fn terminatedH2FlowControlServerMain(config: TerminatedH2FlowControlServerConfig) void {
    terminatedH2FlowControlServerMainImpl(config) catch |err| {
        std.log.err("terminated h2 flow-control server failed: {s}", .{@errorName(err)});
    };
}

fn terminatedH2FlowControlServerMainImpl(config: TerminatedH2FlowControlServerConfig) !void {
    var evented: std.Io.Evented = undefined;
    try init_test_io_runtime(&evented, testing.allocator);
    defer evented.deinit();

    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var handler = TerminatedH2FlowControlHandler{
        .path = config.path,
        .expected_total_bytes = config.expected_total_bytes,
    };
    try serval.server.servePlainH2Connection(TerminatedH2FlowControlHandler, &handler, conn, evented.io(), 4);
}

fn startTerminatedH2FlowControlServer(config: TerminatedH2FlowControlServerConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, terminatedH2FlowControlServerMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

const GrpcBackendIo = struct {
    plain_fd: ?posix.socket_t = null,
    tls_socket: ?*serval.Socket = null,

    fn read(self: *GrpcBackendIo, out: []u8) !usize {
        if (self.tls_socket) |socket| {
            const n_u32 = try socket.read(out);
            if (n_u32 == 0) return error.ConnectionClosed;
            return @intCast(n_u32);
        }

        const fd = self.plain_fd orelse return error.ConnectionClosed;
        const n = try posix.recv(fd, out, 0);
        if (n == 0) return error.ConnectionClosed;
        return n;
    }

    fn writeAll(self: *GrpcBackendIo, data: []const u8) !void {
        if (self.tls_socket) |socket| {
            try socket.write_all(data);
            return;
        }

        const fd = self.plain_fd orelse return error.ConnectionClosed;
        try sendAllTcp(fd, data);
    }
};

fn grpcH2BackendMain(config: GrpcH2BackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    var conn_io = GrpcBackendIo{};
    var maybe_tls_socket: ?serval.Socket = null;
    var maybe_tls_ctx: ?*ssl.SSL_CTX = null;
    defer if (maybe_tls_socket) |*socket| socket.close();
    defer if (conn_io.plain_fd) |fd| posix.close(fd);
    defer if (maybe_tls_ctx) |ctx| ssl.SSL_CTX_free(ctx);

    if (config.tls) {
        const tls_ctx = try createTestServerTlsCtx();
        maybe_tls_ctx = tls_ctx;

        const conn = try acceptTcp(listener);
        const tls_socket = serval.Socket.TLS.TLSSocket.init_server(conn, tls_ctx) catch |err| {
            posix.close(conn);
            return err;
        };
        maybe_tls_socket = tls_socket;
        conn_io.tls_socket = &maybe_tls_socket.?;
    } else {
        const conn = try acceptTcp(listener);
        conn_io.plain_fd = conn;
    }

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var parsed: serval_h2.InitialRequest = undefined;
    var request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;

    while (true) {
        const n = try conn_io.read(request_buf[total..]);
        total += n;
        parsed = serval_h2.parseInitialRequest(request_buf[0..total], &request_storage_buf) catch |err| switch (err) {
            error.NeedMoreData => continue,
            else => return err,
        };
        break;
    }

    try serval_grpc.validateRequest(&parsed.request);
    try testing.expectEqualStrings(config.path, parsed.request.path);

    if (config.expected_request_header_name) |header_name| {
        const expected_value = config.expected_request_header_value orelse return error.MissingExpectedHeaderValue;
        const actual_value = parsed.request.headers.get(header_name) orelse return error.MissingExpectedRequestHeader;
        try testing.expectEqualStrings(expected_value, actual_value);
    } else if (config.expected_request_header_value != null) {
        return error.MissingExpectedHeaderName;
    }

    if (config.drain_request_until_end_stream) {
        var cursor: usize = parsed.consumed_bytes;
        var saw_end_stream = false;
        var frame_reads: u32 = 0;
        while (!saw_end_stream and frame_reads < H2_MAX_FRAME_READS) : (frame_reads += 1) {
            while (total - cursor < serval_h2.frame_header_size_bytes) {
                const n = try conn_io.read(request_buf[total..]);
                total += n;
            }

            const header = try serval_h2.parseFrameHeader(request_buf[cursor..]);
            const payload_start = cursor + serval_h2.frame_header_size_bytes;
            const payload_end = payload_start + header.length;
            while (total < payload_end) {
                const n = try conn_io.read(request_buf[total..]);
                total += n;
            }

            if (header.stream_id == parsed.stream_id and (header.flags & serval_h2.flags_end_stream) != 0) {
                saw_end_stream = true;
            }

            cursor = payload_end;
        }
        if (!saw_end_stream) return error.ReadTimeout;
    }

    if (config.response_trailer_name != null and config.response_trailer_value == null) {
        return error.MissingResponseTrailerValue;
    }
    if (config.response_trailer_name == null and config.response_trailer_value != null) {
        return error.MissingResponseTrailerName;
    }

    var send_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var pos: usize = 0;

    const settings = try appendH2Frame(send_buf[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings.len;
    const settings_ack = try appendH2Frame(send_buf[pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    pos += settings_ack.len;

    var response_headers_buf: [256]u8 = undefined;
    const response_headers = try buildGrpcBackendResponseHeaders(
        config.response_headers_use_incremental_indexing,
        config.response_headers_add_huffman_header,
        config.response_header_name,
        config.response_header_value,
        &response_headers_buf,
    );

    if (config.trailers_only_response) {
        var trailers_only_buf: [256]u8 = undefined;
        var trailers_only_len: usize = 0;

        const status = try serval_h2.encodeIndexedHeaderField(trailers_only_buf[trailers_only_len..], 8);
        trailers_only_len += status.len;

        const content_type = try serval_h2.encodeLiteralHeaderWithoutIndexing(
            trailers_only_buf[trailers_only_len..],
            "content-type",
            "application/grpc",
        );
        trailers_only_len += content_type.len;

        if (config.response_trailer_name) |trailer_name| {
            const trailer_value = config.response_trailer_value orelse return error.MissingResponseTrailerValue;
            const extra_trailer = try serval_h2.encodeLiteralHeaderWithoutIndexing(
                trailers_only_buf[trailers_only_len..],
                trailer_name,
                trailer_value,
            );
            trailers_only_len += extra_trailer.len;
        }

        if (config.omit_grpc_status) {
            const invalid_header = try serval_h2.encodeLiteralHeaderWithoutIndexing(
                trailers_only_buf[trailers_only_len..],
                "x-invalid",
                "missing-grpc-status",
            );
            trailers_only_len += invalid_header.len;
        } else {
            const grpc_status = try serval_h2.encodeLiteralHeaderWithoutIndexing(
                trailers_only_buf[trailers_only_len..],
                "grpc-status",
                "0",
            );
            trailers_only_len += grpc_status.len;
        }

        const trailers_only_frame = try appendH2Frame(
            send_buf[pos..],
            .headers,
            serval_h2.flags_end_headers | serval_h2.flags_end_stream,
            parsed.stream_id,
            trailers_only_buf[0..trailers_only_len],
        );
        pos += trailers_only_frame.len;

        try conn_io.writeAll(send_buf[0..pos]);
        return;
    }

    if (config.split_response_headers_continuation and response_headers.len > 1) {
        const split: usize = response_headers.len / 2;
        const headers_frame = try appendH2Frame(
            send_buf[pos..],
            .headers,
            0,
            parsed.stream_id,
            response_headers[0..split],
        );
        pos += headers_frame.len;

        const continuation_frame = try appendH2Frame(
            send_buf[pos..],
            .continuation,
            serval_h2.flags_end_headers,
            parsed.stream_id,
            response_headers[split..],
        );
        pos += continuation_frame.len;
    } else {
        const headers_frame = try appendH2Frame(
            send_buf[pos..],
            .headers,
            serval_h2.flags_end_headers,
            parsed.stream_id,
            response_headers,
        );
        pos += headers_frame.len;
    }

    var grpc_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const first_message = try serval_grpc.buildMessage(&grpc_payload_buf, false, config.first_response);
    const first_data = try appendH2Frame(send_buf[pos..], .data, 0, parsed.stream_id, first_message);
    pos += first_data.len;

    if (config.mode == .server_streaming) {
        const second_payload = config.second_response orelse return error.MissingResponse;
        const second_message = try serval_grpc.buildMessage(&grpc_payload_buf, false, second_payload);
        const second_data = try appendH2Frame(send_buf[pos..], .data, 0, parsed.stream_id, second_message);
        pos += second_data.len;
    }

    var trailer_buf: [128]u8 = undefined;
    var trailer_len: usize = 0;

    if (config.trailers_include_dynamic_indexed_content_type) {
        const indexed_content_type = try serval_h2.encodeIndexedHeaderField(trailer_buf[trailer_len..], 62);
        trailer_len += indexed_content_type.len;
    }

    if (config.response_trailer_name) |trailer_name| {
        const trailer_value = config.response_trailer_value orelse return error.MissingResponseTrailerValue;
        const extra_trailer = try serval_h2.encodeLiteralHeaderWithoutIndexing(
            trailer_buf[trailer_len..],
            trailer_name,
            trailer_value,
        );
        trailer_len += extra_trailer.len;
    }

    if (config.omit_grpc_status) {
        const invalid_trailer = try buildH2HeaderBlock(&.{
            .{ .name = "x-invalid", .value = "missing-grpc-status" },
        }, trailer_buf[trailer_len..]);
        trailer_len += invalid_trailer.len;
    } else {
        const grpc_status_trailer = try buildH2HeaderBlock(&.{
            .{ .name = "grpc-status", .value = "0" },
        }, trailer_buf[trailer_len..]);
        trailer_len += grpc_status_trailer.len;
    }

    const trailers = trailer_buf[0..trailer_len];

    if (config.split_response_trailers_continuation and trailers.len > 1) {
        const split: usize = trailers.len / 2;
        const trailer_headers_frame = try appendH2Frame(
            send_buf[pos..],
            .headers,
            serval_h2.flags_end_stream,
            parsed.stream_id,
            trailers[0..split],
        );
        pos += trailer_headers_frame.len;

        const trailer_continuation = try appendH2Frame(
            send_buf[pos..],
            .continuation,
            serval_h2.flags_end_headers,
            parsed.stream_id,
            trailers[split..],
        );
        pos += trailer_continuation.len;
    } else {
        const trailer_frame = try appendH2Frame(
            send_buf[pos..],
            .headers,
            serval_h2.flags_end_headers | serval_h2.flags_end_stream,
            parsed.stream_id,
            trailers,
        );
        pos += trailer_frame.len;
    }

    try conn_io.writeAll(send_buf[0..pos]);
}

fn startGrpcH2Backend(config: GrpcH2BackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, grpcH2BackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

fn genericH2BackendMain(config: GenericH2BackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var parsed: serval_h2.InitialRequest = undefined;
    var request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;

    while (true) {
        const n = try posix.recv(conn, request_buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
        parsed = serval_h2.parseInitialRequest(request_buf[0..total], &request_storage_buf) catch |err| switch (err) {
            error.NeedMoreData => continue,
            else => return err,
        };
        break;
    }

    try testing.expectEqualStrings(config.path, parsed.request.path);

    if (config.send_response_trailers and config.headers_end_stream) {
        return error.InvalidConfiguration;
    }
    if (config.response_trailer_name != null and config.response_trailer_value == null) {
        return error.MissingResponseTrailerValue;
    }
    if (config.response_trailer_name == null and config.response_trailer_value != null) {
        return error.MissingResponseTrailerName;
    }

    var send_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var pos: usize = 0;

    const settings = try appendH2Frame(send_buf[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings.len;

    const settings_ack = try appendH2Frame(send_buf[pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    pos += settings_ack.len;

    var response_headers_buf: [256]u8 = undefined;
    const response_headers = if (config.response_content_type) |content_type|
        try buildH2HeaderBlock(&.{
            .{ .name = ":status", .value = config.response_status },
            .{ .name = "content-type", .value = content_type },
        }, &response_headers_buf)
    else
        try buildH2HeaderBlock(&.{
            .{ .name = ":status", .value = config.response_status },
        }, &response_headers_buf);

    const headers_flags: u8 = if (config.headers_end_stream)
        serval_h2.flags_end_headers | serval_h2.flags_end_stream
    else
        serval_h2.flags_end_headers;

    const headers_frame = try appendH2Frame(
        send_buf[pos..],
        .headers,
        headers_flags,
        parsed.stream_id,
        response_headers,
    );
    pos += headers_frame.len;

    if (!config.headers_end_stream) {
        const payload = config.response_payload orelse "";
        if (payload.len > 0 or !config.send_response_trailers) {
            const data_flags: u8 = if (config.send_response_trailers) 0 else serval_h2.flags_end_stream;
            const data_frame = try appendH2Frame(send_buf[pos..], .data, data_flags, parsed.stream_id, payload);
            pos += data_frame.len;
        }

        if (config.send_response_trailers) {
            const trailer_name = config.response_trailer_name orelse "x-generic-trailer";
            const trailer_value = config.response_trailer_value orelse "ok";

            var trailer_buf: [128]u8 = undefined;
            const trailers = try buildH2HeaderBlock(&.{.{ .name = trailer_name, .value = trailer_value }}, &trailer_buf);
            const trailer_frame = try appendH2Frame(
                send_buf[pos..],
                .headers,
                serval_h2.flags_end_headers | serval_h2.flags_end_stream,
                parsed.stream_id,
                trailers,
            );
            pos += trailer_frame.len;
        }
    }

    try sendAllTcp(conn, send_buf[0..pos]);
}

fn startGenericH2Backend(config: GenericH2BackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, genericH2BackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

fn minimalH2BridgeBackendMain(config: MinimalH2BridgeBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var recv_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const n = try posix.recv(conn, &recv_buf, 0);
    if (n == 0) return;

    var send_buf: [128]u8 = undefined;
    var pos: usize = 0;

    const settings = try appendH2Frame(send_buf[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings.len;

    const settings_ack = try appendH2Frame(send_buf[pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    pos += settings_ack.len;

    try sendAllTcp(conn, send_buf[0..pos]);
    posix.nanosleep(0, 200 * std.time.ns_per_ms);
}

fn startMinimalH2BridgeBackend(config: MinimalH2BridgeBackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, minimalH2BridgeBackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

fn grpcH2ResetBackendMain(config: GrpcH2ResetBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var parsed: serval_h2.InitialRequest = undefined;
    var request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;

    while (true) {
        const n = try posix.recv(conn, request_buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
        parsed = serval_h2.parseInitialRequest(request_buf[0..total], &request_storage_buf) catch |err| switch (err) {
            error.NeedMoreData => continue,
            else => return err,
        };
        break;
    }

    try serval_grpc.validateRequest(&parsed.request);
    try testing.expectEqualStrings(config.path, parsed.request.path);

    var send_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var pos: usize = 0;

    const settings = try appendH2Frame(send_buf[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings.len;

    const settings_ack = try appendH2Frame(send_buf[pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    pos += settings_ack.len;

    var rst_buf: [serval_h2.frame_header_size_bytes + serval_h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst = try serval_h2.buildRstStreamFrame(&rst_buf, parsed.stream_id, config.error_code_raw);
    @memcpy(send_buf[pos..][0..rst.len], rst);
    pos += rst.len;

    try sendAllTcp(conn, send_buf[0..pos]);
}

fn startGrpcH2ResetBackend(config: GrpcH2ResetBackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, grpcH2ResetBackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

fn grpcH2GoAwayBackendMain(config: GrpcH2GoAwayBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var parsed: serval_h2.InitialRequest = undefined;
    var request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;

    while (true) {
        const n = try posix.recv(conn, request_buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
        parsed = serval_h2.parseInitialRequest(request_buf[0..total], &request_storage_buf) catch |err| switch (err) {
            error.NeedMoreData => continue,
            else => return err,
        };
        break;
    }

    try serval_grpc.validateRequest(&parsed.request);
    try testing.expectEqualStrings(config.path, parsed.request.path);

    var send_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var pos: usize = 0;

    const settings = try appendH2Frame(send_buf[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings.len;

    const settings_ack = try appendH2Frame(send_buf[pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    pos += settings_ack.len;

    var goaway_buf: [serval_h2.frame_header_size_bytes + 32]u8 = undefined;
    const goaway = try serval_h2.buildGoAwayFrame(
        &goaway_buf,
        config.last_stream_id,
        config.error_code_raw,
        "upstream-goaway",
    );
    @memcpy(send_buf[pos..][0..goaway.len], goaway);
    pos += goaway.len;

    if (config.response_payload) |response_payload| {
        var response_headers_buf: [256]u8 = undefined;
        const response_headers = try buildH2HeaderBlock(&.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "application/grpc" },
        }, &response_headers_buf);
        const headers_frame = try appendH2Frame(send_buf[pos..], .headers, serval_h2.flags_end_headers, parsed.stream_id, response_headers);
        pos += headers_frame.len;

        var grpc_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const message = try serval_grpc.buildMessage(&grpc_payload_buf, false, response_payload);
        const data_frame = try appendH2Frame(send_buf[pos..], .data, 0, parsed.stream_id, message);
        pos += data_frame.len;

        var trailer_buf: [128]u8 = undefined;
        const trailers = try buildH2HeaderBlock(&.{
            .{ .name = "grpc-status", .value = "0" },
        }, &trailer_buf);
        const trailer_frame = try appendH2Frame(
            send_buf[pos..],
            .headers,
            serval_h2.flags_end_headers | serval_h2.flags_end_stream,
            parsed.stream_id,
            trailers,
        );
        pos += trailer_frame.len;
    }

    try sendAllTcp(conn, send_buf[0..pos]);
}

fn startGrpcH2GoAwayBackend(config: GrpcH2GoAwayBackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, grpcH2GoAwayBackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

fn parseGrpcStreamRequestFrames(input: []const u8, payload_out: []u8) !ParsedGrpcStreamRequest {
    assert(input.len > 0);
    assert(payload_out.len > 0);

    var cursor: usize = 0;
    var iterations: u32 = 0;
    var stream_id: u32 = 0;
    var path: []const u8 = "";
    var request = serval.Request{};
    var saw_headers = false;

    while (cursor < input.len and iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        if (input.len - cursor < serval_h2.frame_header_size_bytes) return error.NeedMoreData;

        const header = try serval_h2.parseFrameHeader(input[cursor..]);
        const payload_start = cursor + serval_h2.frame_header_size_bytes;
        const payload_end = payload_start + header.length;
        if (payload_end > input.len) return error.NeedMoreData;
        const payload = input[payload_start..payload_end];

        switch (header.frame_type) {
            .settings => {
                if ((header.flags & serval_h2.flags_ack) == 0) return error.InvalidFrame;
            },
            .window_update => {},
            .headers => {
                if (saw_headers) return error.InvalidFrame;
                if ((header.flags & serval_h2.flags_end_headers) == 0) return error.InvalidFrame;
                stream_id = header.stream_id;
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(payload, &fields_buf);
                for (fields) |field| {
                    if (std.mem.eql(u8, field.name, ":method")) {
                        if (!std.mem.eql(u8, field.value, "POST")) return error.InvalidMethod;
                        request.method = .POST;
                    } else if (std.mem.eql(u8, field.name, ":path")) {
                        path = field.value;
                        request.path = field.value;
                    } else if (std.mem.eql(u8, field.name, ":authority")) {
                        try request.headers.put("host", field.value);
                    } else {
                        try request.headers.put(field.name, field.value);
                    }
                }
                if (path.len == 0) return error.MissingPath;
                try serval_grpc.validateRequest(&request);
                saw_headers = true;
            },
            .data => {
                if (!saw_headers) {
                    if (header.stream_id == 1) {
                        cursor = payload_end;
                        continue;
                    }
                    return error.InvalidFrame;
                }
                if (header.stream_id != stream_id) return error.InvalidFrame;
                if (payload.len > payload_out.len) return error.BufferTooSmall;
                @memcpy(payload_out[0..payload.len], payload);
                const grpc_payload = try serval_grpc.parseMessage(payload_out[0..payload.len]);
                if ((header.flags & serval_h2.flags_end_stream) == 0) return error.InvalidFrame;
                return .{
                    .stream_id = stream_id,
                    .path = path,
                    .payload = grpc_payload,
                };
            },
            else => return error.InvalidFrame,
        }

        cursor = payload_end;
    }

    return error.NeedMoreData;
}

const GrpcH2MultiBackendConfig = struct {
    port: u16,
    first_path: []const u8,
    second_path: []const u8,
    first_response: []const u8,
    second_response: []const u8,
};

fn sendGrpcUnaryResponse(conn: posix.socket_t, stream_id: u32, payload: []const u8) !void {
    var send_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var pos: usize = 0;

    var response_headers_buf: [256]u8 = undefined;
    const response_headers = try buildH2HeaderBlock(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
    }, &response_headers_buf);
    const headers_frame = try appendH2Frame(send_buf[pos..], .headers, serval_h2.flags_end_headers, stream_id, response_headers);
    pos += headers_frame.len;

    var grpc_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const message = try serval_grpc.buildMessage(&grpc_payload_buf, false, payload);
    const data_frame = try appendH2Frame(send_buf[pos..], .data, 0, stream_id, message);
    pos += data_frame.len;

    var trailer_buf: [128]u8 = undefined;
    const trailers = try buildH2HeaderBlock(&.{.{ .name = "grpc-status", .value = "0" }}, &trailer_buf);
    const trailer_frame = try appendH2Frame(send_buf[pos..], .headers, serval_h2.flags_end_headers | serval_h2.flags_end_stream, stream_id, trailers);
    pos += trailer_frame.len;

    try sendAllTcp(conn, send_buf[0..pos]);
}

fn grpcH2MultiBackendMain(config: GrpcH2MultiBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var parsed: serval_h2.InitialRequest = undefined;
    var request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;

    while (true) {
        const n = try posix.recv(conn, request_buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
        parsed = serval_h2.parseInitialRequest(request_buf[0..total], &request_storage_buf) catch |err| switch (err) {
            error.NeedMoreData => continue,
            else => return err,
        };
        break;
    }

    try serval_grpc.validateRequest(&parsed.request);
    try testing.expectEqualStrings(config.first_path, parsed.request.path);

    var settings_buf: [2 * serval_h2.frame_header_size_bytes]u8 = undefined;
    var settings_pos: usize = 0;
    const settings = try appendH2Frame(settings_buf[settings_pos..], .settings, 0, 0, &[_]u8{});
    settings_pos += settings.len;
    const settings_ack = try appendH2Frame(settings_buf[settings_pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    settings_pos += settings_ack.len;
    try sendAllTcp(conn, settings_buf[0..settings_pos]);
    try sendGrpcUnaryResponse(conn, parsed.stream_id, config.first_response);

    var second_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var second_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var second_total: usize = 0;

    const consumed_bytes: usize = @intCast(parsed.consumed_bytes);
    assert(consumed_bytes <= total);
    if (total > consumed_bytes) {
        const carried_len = total - consumed_bytes;
        assert(carried_len <= second_request_buf.len);
        @memcpy(second_request_buf[0..carried_len], request_buf[consumed_bytes..total]);
        second_total = carried_len;
    }

    while (true) {
        if (second_total > 0) {
            const parsed_second = parseGrpcStreamRequestFrames(second_request_buf[0..second_total], &second_payload_buf) catch |err| switch (err) {
                error.NeedMoreData => null,
                else => return err,
            };
            if (parsed_second) |second| {
                try testing.expectEqualStrings(config.second_path, second.path);
                try sendGrpcUnaryResponse(conn, second.stream_id, config.second_response);
                break;
            }
        }

        const n = try posix.recv(conn, second_request_buf[second_total..], 0);
        if (n == 0) return error.ConnectionClosed;
        second_total += n;
    }
}

fn startGrpcH2MultiBackend(config: GrpcH2MultiBackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, grpcH2MultiBackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

const MixedGrpcGenericBackendConfig = struct {
    port: u16,
    grpc_path: []const u8,
    grpc_response: []const u8,
    generic_path: []const u8,
};

const ParsedRequestClass = struct {
    stream_id: u32,
    path: []const u8,
    request_class: serval_grpc.RequestClass,
    consumed_bytes: u32,
};

fn parseSingleRequestClass(input: []const u8) !ParsedRequestClass {
    assert(input.len > 0);

    var cursor: usize = 0;
    var iterations: u32 = 0;
    var stream_id: u32 = 0;
    var request = serval.Request{};
    var saw_headers = false;

    while (cursor < input.len and iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        if (input.len - cursor < serval_h2.frame_header_size_bytes) return error.NeedMoreData;

        const header = try serval_h2.parseFrameHeader(input[cursor..]);
        const payload_start = cursor + serval_h2.frame_header_size_bytes;
        const payload_end = payload_start + header.length;
        if (payload_end > input.len) return error.NeedMoreData;
        const payload = input[payload_start..payload_end];

        switch (header.frame_type) {
            .settings => {
                if ((header.flags & serval_h2.flags_ack) == 0) return error.InvalidFrame;
            },
            .window_update => {},
            .headers => {
                if (saw_headers) return error.InvalidFrame;
                if ((header.flags & serval_h2.flags_end_headers) == 0) return error.InvalidFrame;
                if (header.stream_id == 0) return error.InvalidFrame;

                stream_id = header.stream_id;
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(payload, &fields_buf);
                for (fields) |field| {
                    if (std.mem.eql(u8, field.name, ":method")) {
                        if (std.mem.eql(u8, field.value, "POST")) {
                            request.method = .POST;
                        } else if (std.mem.eql(u8, field.value, "GET")) {
                            request.method = .GET;
                        }
                    } else if (std.mem.eql(u8, field.name, ":path")) {
                        request.path = field.value;
                    } else if (std.mem.eql(u8, field.name, ":authority")) {
                        try request.headers.put("host", field.value);
                    } else {
                        try request.headers.put(field.name, field.value);
                    }
                }
                if (request.path.len == 0) return error.MissingPath;
                saw_headers = true;

                if ((header.flags & serval_h2.flags_end_stream) != 0) {
                    return .{
                        .stream_id = stream_id,
                        .path = request.path,
                        .request_class = serval_grpc.classifyRequest(&request),
                        .consumed_bytes = @intCast(payload_end),
                    };
                }
            },
            .data => {
                if (!saw_headers) {
                    if (header.stream_id == 1) {
                        cursor = payload_end;
                        continue;
                    }
                    return error.InvalidFrame;
                }
                if (header.stream_id != stream_id) return error.InvalidFrame;
                if ((header.flags & serval_h2.flags_end_stream) == 0) {
                    cursor = payload_end;
                    continue;
                }

                return .{
                    .stream_id = stream_id,
                    .path = request.path,
                    .request_class = serval_grpc.classifyRequest(&request),
                    .consumed_bytes = @intCast(payload_end),
                };
            },
            else => return error.InvalidFrame,
        }

        cursor = payload_end;
    }

    return error.NeedMoreData;
}

fn sendGenericHeadersOnlyResponse(conn: posix.socket_t, stream_id: u32) !void {
    assert(stream_id > 0);

    var send_buf: [256]u8 = undefined;
    var pos: usize = 0;

    var response_headers_buf: [128]u8 = undefined;
    const response_headers = try buildH2HeaderBlock(&.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "content-type", .value = "text/plain" },
    }, &response_headers_buf);

    const headers_frame = try appendH2Frame(
        send_buf[pos..],
        .headers,
        serval_h2.flags_end_headers | serval_h2.flags_end_stream,
        stream_id,
        response_headers,
    );
    pos += headers_frame.len;

    try sendAllTcp(conn, send_buf[0..pos]);
}

fn mixedGrpcGenericBackendMain(config: MixedGrpcGenericBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var parsed: serval_h2.InitialRequest = undefined;
    var request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;

    while (true) {
        const n = try posix.recv(conn, request_buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
        parsed = serval_h2.parseInitialRequest(request_buf[0..total], &request_storage_buf) catch |err| switch (err) {
            error.NeedMoreData => continue,
            else => return err,
        };
        break;
    }

    var settings_buf: [2 * serval_h2.frame_header_size_bytes]u8 = undefined;
    var settings_pos: usize = 0;
    const settings = try appendH2Frame(settings_buf[settings_pos..], .settings, 0, 0, &[_]u8{});
    settings_pos += settings.len;
    const settings_ack = try appendH2Frame(settings_buf[settings_pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    settings_pos += settings_ack.len;
    try sendAllTcp(conn, settings_buf[0..settings_pos]);

    const first_class = serval_grpc.classifyRequest(&parsed.request);
    if (first_class == .grpc) {
        try testing.expectEqualStrings(config.grpc_path, parsed.request.path);
        try sendGrpcUnaryResponse(conn, parsed.stream_id, config.grpc_response);
    } else {
        try testing.expectEqualStrings(config.generic_path, parsed.request.path);
        try sendGenericHeadersOnlyResponse(conn, parsed.stream_id);
    }

    var second_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var second_total: usize = 0;

    const consumed_bytes: usize = @intCast(parsed.consumed_bytes);
    assert(consumed_bytes <= total);
    if (total > consumed_bytes) {
        const carried_len = total - consumed_bytes;
        assert(carried_len <= second_request_buf.len);
        @memcpy(second_request_buf[0..carried_len], request_buf[consumed_bytes..total]);
        second_total = carried_len;
    }

    while (true) {
        if (second_total > 0) {
            const second = parseSingleRequestClass(second_request_buf[0..second_total]) catch |err| switch (err) {
                error.NeedMoreData => null,
                else => return err,
            };
            if (second) |req| {
                if (req.request_class == .grpc) {
                    try testing.expectEqualStrings(config.grpc_path, req.path);
                    try sendGrpcUnaryResponse(conn, req.stream_id, config.grpc_response);
                } else {
                    try testing.expectEqualStrings(config.generic_path, req.path);
                    try sendGenericHeadersOnlyResponse(conn, req.stream_id);
                }
                return;
            }
        }

        const n = try posix.recv(conn, second_request_buf[second_total..], 0);
        if (n == 0) return error.ConnectionClosed;
        second_total += n;
    }
}

fn startMixedGrpcGenericBackend(config: MixedGrpcGenericBackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, mixedGrpcGenericBackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

const GrpcH2ResetThenUnaryBackendConfig = struct {
    port: u16,
    reset_path: []const u8,
    pass_path: []const u8,
    reset_error_code_raw: u32,
    pass_response: []const u8,
};

fn grpcH2ResetThenUnaryBackendMain(config: GrpcH2ResetThenUnaryBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var parsed: serval_h2.InitialRequest = undefined;
    var request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;

    while (true) {
        const n = try posix.recv(conn, request_buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
        parsed = serval_h2.parseInitialRequest(request_buf[0..total], &request_storage_buf) catch |err| switch (err) {
            error.NeedMoreData => continue,
            else => return err,
        };
        break;
    }

    try serval_grpc.validateRequest(&parsed.request);
    try testing.expectEqualStrings(config.reset_path, parsed.request.path);

    var send_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var send_pos: usize = 0;

    const settings = try appendH2Frame(send_buf[send_pos..], .settings, 0, 0, &[_]u8{});
    send_pos += settings.len;

    const settings_ack = try appendH2Frame(send_buf[send_pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    send_pos += settings_ack.len;

    var rst_buf: [serval_h2.frame_header_size_bytes + serval_h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst = try serval_h2.buildRstStreamFrame(&rst_buf, parsed.stream_id, config.reset_error_code_raw);
    @memcpy(send_buf[send_pos..][0..rst.len], rst);
    send_pos += rst.len;

    try sendAllTcp(conn, send_buf[0..send_pos]);

    var second_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var second_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var second_total: usize = 0;

    const consumed_bytes: usize = @intCast(parsed.consumed_bytes);
    assert(consumed_bytes <= total);
    if (total > consumed_bytes) {
        const carried_len = total - consumed_bytes;
        assert(carried_len <= second_request_buf.len);
        @memcpy(second_request_buf[0..carried_len], request_buf[consumed_bytes..total]);
        second_total = carried_len;
    }

    while (true) {
        if (second_total > 0) {
            const parsed_second = parseGrpcStreamRequestFrames(second_request_buf[0..second_total], &second_payload_buf) catch |err| switch (err) {
                error.NeedMoreData => null,
                else => return err,
            };
            if (parsed_second) |second| {
                try testing.expectEqualStrings(config.pass_path, second.path);
                try sendGrpcUnaryResponse(conn, second.stream_id, config.pass_response);
                return;
            }
        }

        const n = try posix.recv(conn, second_request_buf[second_total..], 0);
        if (n == 0) return error.ConnectionClosed;
        second_total += n;
    }
}

fn startGrpcH2ResetThenUnaryBackend(config: GrpcH2ResetThenUnaryBackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, grpcH2ResetThenUnaryBackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

const GrpcH2CancelPropagationBackendConfig = struct {
    port: u16,
    cancel_path: []const u8,
    survivor_path: []const u8,
    first_payload: []const u8,
    survivor_payload: []const u8,
    goaway_last_stream_id: ?u32 = null,
    await_survivor_on_same_session: bool = true,
};

fn waitForProxyRstStream(conn: posix.socket_t, stream_id: u32) !u32 {
    assert(stream_id > 0);

    var recv_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 4) : (iterations += 1) {
        const n = try posix.recv(conn, recv_buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;

        var cursor: usize = 0;
        while (total - cursor >= serval_h2.frame_header_size_bytes) {
            const header = try serval_h2.parseFrameHeader(recv_buf[cursor..total]);
            const payload_start = cursor + serval_h2.frame_header_size_bytes;
            const payload_end = payload_start + header.length;
            if (payload_end > total) break;

            const payload = recv_buf[payload_start..payload_end];
            if (header.frame_type == .rst_stream and header.stream_id == stream_id) {
                const error_code_raw = try serval_h2.parseRstStreamFrame(header, payload);
                return error_code_raw;
            }

            cursor = payload_end;
        }

        if (cursor > 0) {
            const remaining = total - cursor;
            if (remaining > 0) {
                std.mem.copyForwards(u8, recv_buf[0..remaining], recv_buf[cursor..total]);
            }
            total = remaining;
        }
    }

    return error.ReadTimeout;
}

fn grpcH2CancelPropagationBackendMain(config: GrpcH2CancelPropagationBackendConfig) !void {
    const listener = try createTcpListener(config.port);
    defer posix.close(listener);

    const conn = try acceptTcp(listener);
    defer posix.close(conn);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var total: usize = 0;
    var parsed: serval_h2.InitialRequest = undefined;
    var request_storage_buf: [serval_h2.request_stable_storage_size_bytes]u8 = undefined;

    while (true) {
        const n = try posix.recv(conn, request_buf[total..], 0);
        if (n == 0) return error.ConnectionClosed;
        total += n;
        parsed = serval_h2.parseInitialRequest(request_buf[0..total], &request_storage_buf) catch |err| switch (err) {
            error.NeedMoreData => continue,
            else => return err,
        };
        break;
    }

    try serval_grpc.validateRequest(&parsed.request);
    try testing.expectEqualStrings(config.cancel_path, parsed.request.path);

    var send_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var pos: usize = 0;

    const settings = try appendH2Frame(send_buf[pos..], .settings, 0, 0, &[_]u8{});
    pos += settings.len;

    const settings_ack = try appendH2Frame(send_buf[pos..], .settings, serval_h2.flags_ack, 0, &[_]u8{});
    pos += settings_ack.len;

    if (config.goaway_last_stream_id) |last_stream_id| {
        var goaway_buf: [serval_h2.frame_header_size_bytes + 32]u8 = undefined;
        const goaway = try serval_h2.buildGoAwayFrame(
            &goaway_buf,
            last_stream_id,
            @intFromEnum(serval_h2.ErrorCode.no_error),
            "cancel-overlap",
        );
        @memcpy(send_buf[pos..][0..goaway.len], goaway);
        pos += goaway.len;
    }

    var response_headers_buf: [256]u8 = undefined;
    const response_headers = try buildH2HeaderBlock(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
    }, &response_headers_buf);
    const headers_frame = try appendH2Frame(send_buf[pos..], .headers, serval_h2.flags_end_headers, parsed.stream_id, response_headers);
    pos += headers_frame.len;

    var grpc_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const first_message = try serval_grpc.buildMessage(&grpc_payload_buf, false, config.first_payload);
    const first_data = try appendH2Frame(send_buf[pos..], .data, 0, parsed.stream_id, first_message);
    pos += first_data.len;

    try sendAllTcp(conn, send_buf[0..pos]);

    const reset_error_code_raw = try waitForProxyRstStream(conn, parsed.stream_id);
    try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.cancel)), reset_error_code_raw);

    if (!config.await_survivor_on_same_session) return;

    var second_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var second_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var second_total: usize = 0;

    while (true) {
        const n = try posix.recv(conn, second_request_buf[second_total..], 0);
        if (n == 0) return error.ConnectionClosed;
        second_total += n;

        const parsed_second = parseGrpcStreamRequestFrames(second_request_buf[0..second_total], &second_payload_buf) catch |err| switch (err) {
            error.NeedMoreData => null,
            else => return err,
        };
        if (parsed_second) |second| {
            try testing.expectEqualStrings(config.survivor_path, second.path);
            try sendGrpcUnaryResponse(conn, second.stream_id, config.survivor_payload);
            return;
        }
    }
}

fn startGrpcH2CancelPropagationBackend(config: GrpcH2CancelPropagationBackendConfig) !std.Thread {
    const thread = try std.Thread.spawn(.{}, grpcH2CancelPropagationBackendMain, .{config});
    posix.nanosleep(0, H2_SERVER_STARTUP_DELAY_MS * std.time.ns_per_ms);
    return thread;
}

const GrpcH2ProxyHandler = struct {
    upstream: serval.Upstream,

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = ctx;
        _ = request;
        return self.upstream;
    }
};

const GrpcH2ProxyServerShared = struct {
    port: u16,
    shutdown: std.atomic.Value(bool),
    listener_fd: std.atomic.Value(i32),
    insecure_skip_verify: bool,
    frontend_tls: bool,
    tls_h2_frontend_mode: @TypeOf((serval.Config{}).tls_h2_frontend_mode),
    alpn_mixed_offer_policy: @TypeOf((serval.Config{}).alpn_mixed_offer_policy),
};

const GrpcH2ProxyServer = struct {
    shared: *GrpcH2ProxyServerShared,
    thread: ?std.Thread,

    fn wakeListener(port: u16, frontend_tls: bool) void {
        if (frontend_tls) {
            // Shutdown wakeups only need to unblock accept(); forcing ALPN h2
            // drives the generic h2 frontend during teardown and trips an
            // unrelated std.Io.Uring group-cancel race.
            const wake_socket = connectTcpTls(port, "http/1.1") catch null;
            if (wake_socket) |socket| {
                var close_socket = socket;
                close_socket.close();
            }
            return;
        }

        const wake_sock = connectTcp(port) catch null;
        if (wake_sock) |sock| posix.close(sock);
    }

    fn start(port: u16, upstream: serval.Upstream) !GrpcH2ProxyServer {
        return startWithOptions(port, upstream, false);
    }

    fn startWithOptions(
        port: u16,
        upstream: serval.Upstream,
        insecure_skip_verify: bool,
    ) !GrpcH2ProxyServer {
        return startWithTlsOptions(port, upstream, insecure_skip_verify, false);
    }

    fn startWithTlsOptions(
        port: u16,
        upstream: serval.Upstream,
        insecure_skip_verify: bool,
        frontend_tls: bool,
    ) !GrpcH2ProxyServer {
        return startWithFrontendOptions(
            port,
            upstream,
            insecure_skip_verify,
            frontend_tls,
            .terminated_only,
            .prefer_http11,
        );
    }

    fn startWithFrontendOptions(
        port: u16,
        upstream: serval.Upstream,
        insecure_skip_verify: bool,
        frontend_tls: bool,
        tls_h2_frontend_mode: @TypeOf((serval.Config{}).tls_h2_frontend_mode),
        alpn_mixed_offer_policy: @TypeOf((serval.Config{}).alpn_mixed_offer_policy),
    ) !GrpcH2ProxyServer {
        const shared = try std.heap.page_allocator.create(GrpcH2ProxyServerShared);
        errdefer std.heap.page_allocator.destroy(shared);

        shared.* = .{
            .port = port,
            .shutdown = std.atomic.Value(bool).init(false),
            .listener_fd = std.atomic.Value(i32).init(-1),
            .insecure_skip_verify = insecure_skip_verify,
            .frontend_tls = frontend_tls,
            .tls_h2_frontend_mode = tls_h2_frontend_mode,
            .alpn_mixed_offer_policy = alpn_mixed_offer_policy,
        };

        var server = GrpcH2ProxyServer{ .shared = shared, .thread = null };
        server.thread = try std.Thread.spawn(.{}, grpcH2ProxyServerMain, .{ shared, upstream });

        const startup_wait_limit_ms: u16 = 2000;
        var startup_waited_ms: u16 = 0;
        var ready = false;
        while (startup_waited_ms < startup_wait_limit_ms) : (startup_waited_ms += 1) {
            if (shared.listener_fd.load(.acquire) >= 0) {
                ready = true;
                break;
            }
            posix.nanosleep(0, std.time.ns_per_ms);
        }

        if (!ready) {
            shared.shutdown.store(true, .release);
            wakeListener(shared.port, shared.frontend_tls);
            _ = shared.listener_fd.swap(-1, .acq_rel);
            if (server.thread) |thread| {
                thread.join();
                server.thread = null;
            }
            std.heap.page_allocator.destroy(shared);
            return error.ProxyStartupTimeout;
        }

        return server;
    }

    fn stop(self: *GrpcH2ProxyServer) void {
        self.shared.shutdown.store(true, .release);
        wakeListener(self.shared.port, self.shared.frontend_tls);
        _ = self.shared.listener_fd.swap(-1, .acq_rel);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        std.heap.page_allocator.destroy(self.shared);
    }
};

fn grpcH2ProxyServerMain(shared: *GrpcH2ProxyServerShared, upstream: serval.Upstream) void {
    var handler = GrpcH2ProxyHandler{ .upstream = upstream };
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};
    var evented: std.Io.Evented = undefined;
    init_test_io_runtime(&evented, std.heap.page_allocator) catch |err| {
        std.log.err("grpc h2 proxy io init failed: {s}", .{@errorName(err)});
        return;
    };
    defer evented.deinit();

    var client_ctx: ?*ssl.SSL_CTX = null;
    if (upstream.tls) {
        ssl.init();
        const ctx = ssl.createClientCtx() catch |err| {
            std.log.err("grpc h2 proxy test server client ctx init failed: {s}", .{@errorName(err)});
            return;
        };
        if (shared.insecure_skip_verify) {
            ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_NONE, null);
        } else {
            ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_PEER, null);
        }
        client_ctx = ctx;
    }
    defer if (client_ctx) |ctx| ssl.SSL_CTX_free(ctx);

    var server_cfg = serval.Config{ .port = shared.port };
    server_cfg.tls_h2_frontend_mode = shared.tls_h2_frontend_mode;
    server_cfg.alpn_mixed_offer_policy = shared.alpn_mixed_offer_policy;
    if (shared.frontend_tls or upstream.tls) {
        server_cfg.tls = .{
            .cert_path = if (shared.frontend_tls) harness.TEST_CERT_PATH else null,
            .key_path = if (shared.frontend_tls) harness.TEST_KEY_PATH else null,
            .verify_upstream = !shared.insecure_skip_verify,
        };
    }

    const ServerType = serval.Server(
        GrpcH2ProxyHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    var server = ServerType.init(
        &handler,
        &pool,
        &metrics,
        &tracer,
        server_cfg,
        client_ctx,
        serval_net.DnsConfig{},
    );

    server.run(evented.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
        std.log.err("grpc h2 proxy test server failed: {s}", .{@errorName(err)});
    };
}

const NETBIRD_STARTUP_TIMEOUT_MS: u16 = 2000;

const NetbirdGrpcRoute = enum {
    none,
    signal,
    management,
};

const NetbirdGrpcRouteSpec = struct {
    matcher: serval.PathMatch,
    route: NetbirdGrpcRoute,
};

const NetbirdHttpResponseSpec = struct {
    matcher: serval.PathMatch,
    status: u16,
    content_type: []const u8,
    body: []const u8,
};

const netbird_grpc_route_specs = [_]NetbirdGrpcRouteSpec{
    .{ .matcher = .{ .prefix = "/signalexchange.SignalExchange/" }, .route = .signal },
    .{ .matcher = .{ .prefix = "/management.ManagementService/" }, .route = .management },
    .{ .matcher = .{ .prefix = "/management.ProxyService/" }, .route = .management },
};

const netbird_websocket_matchers = [_]serval.PathMatch{
    .{ .prefix = "/relay" },
    .{ .prefix = "/ws-proxy/" },
};

const netbird_http_response_specs = [_]NetbirdHttpResponseSpec{
    .{ .matcher = .{ .prefix = "/api/" }, .status = 401, .content_type = "text/plain", .body = "api-unauthorized" },
    .{ .matcher = .{ .prefix = "/oauth2/" }, .status = 200, .content_type = "text/plain", .body = "oauth2-ok" },
    .{ .matcher = .{ .prefix = "/.well-known/" }, .status = 200, .content_type = "application/json", .body = "{\"issuer\":\"https://netbird.local\"}" },
    .{ .matcher = .{ .prefix = "/ui/" }, .status = 200, .content_type = "text/plain", .body = "zitadel-http-ok" },
    .{ .matcher = .{ .prefix = "/oidc/" }, .status = 200, .content_type = "text/plain", .body = "zitadel-http-ok" },
    .{ .matcher = .{ .prefix = "/oauth/" }, .status = 200, .content_type = "text/plain", .body = "zitadel-http-ok" },
    .{ .matcher = .{ .prefix = "/" }, .status = 200, .content_type = "text/plain", .body = "dashboard-catch-all" },
};

fn netbirdPathMatches(matcher: serval.PathMatch, path: []const u8) bool {
    assert(path.len > 0);
    return matcher.matches(path);
}

fn netbirdIsWebSocketPath(path: []const u8) bool {
    for (netbird_websocket_matchers) |matcher| {
        if (netbirdPathMatches(matcher, path)) return true;
    }
    return false;
}

fn netbirdClassifyGrpcPath(path: []const u8) ?NetbirdGrpcRoute {
    for (netbird_grpc_route_specs) |spec| {
        if (!netbirdPathMatches(spec.matcher, path)) continue;
        return spec.route;
    }
    return null;
}

fn netbirdResolveHttpResponse(path: []const u8) ?NetbirdHttpResponseSpec {
    for (netbird_http_response_specs) |spec| {
        if (!netbirdPathMatches(spec.matcher, path)) continue;
        return spec;
    }
    return null;
}

fn netbirdWriteStaticBody(response_buf: []u8, body: []const u8) []const u8 {
    assert(body.len <= response_buf.len);
    @memcpy(response_buf[0..body.len], body);
    return response_buf[0..body.len];
}

const NetbirdDualBackendHandler = struct {
    const max_tracked_streams: u8 = 8;

    pending_stream_ids: [max_tracked_streams]u32 = [_]u32{0} ** max_tracked_streams,
    pending_stream_routes: [max_tracked_streams]NetbirdGrpcRoute = [_]NetbirdGrpcRoute{.none} ** max_tracked_streams,

    fn trackStreamRoute(self: *@This(), stream_id: u32, route: NetbirdGrpcRoute) !void {
        assert(stream_id > 0);
        assert(route != .none);

        var idx: u8 = 0;
        while (idx < max_tracked_streams) : (idx += 1) {
            if (self.pending_stream_routes[idx] == .none) continue;
            if (self.pending_stream_ids[idx] == stream_id) return error.DuplicateStreamId;
        }

        idx = 0;
        while (idx < max_tracked_streams) : (idx += 1) {
            if (self.pending_stream_routes[idx] != .none) continue;
            self.pending_stream_ids[idx] = stream_id;
            self.pending_stream_routes[idx] = route;
            return;
        }

        return error.StreamTableFull;
    }

    fn takeStreamRoute(self: *@This(), stream_id: u32) !NetbirdGrpcRoute {
        assert(stream_id > 0);

        var idx: u8 = 0;
        while (idx < max_tracked_streams) : (idx += 1) {
            if (self.pending_stream_routes[idx] == .none) continue;
            if (self.pending_stream_ids[idx] != stream_id) continue;

            const route = self.pending_stream_routes[idx];
            self.pending_stream_ids[idx] = 0;
            self.pending_stream_routes[idx] = .none;
            return route;
        }

        return error.UnknownStreamId;
    }

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        @panic("netbird backend should terminate requests directly");
    }

    pub fn onRequest(
        self: *@This(),
        ctx: *serval.Context,
        request: *serval.Request,
        response_buf: []u8,
    ) serval.Action {
        _ = self;
        _ = ctx;

        if (netbirdIsWebSocketPath(request.path)) {
            return .continue_request;
        }

        const response_spec = netbirdResolveHttpResponse(request.path) orelse {
            return .{ .reject = .{
                .status = 500,
                .reason = "netbird test route missing",
            } };
        };

        const body = netbirdWriteStaticBody(response_buf, response_spec.body);
        return .{ .send_response = .{
            .status = response_spec.status,
            .body = body,
            .content_type = response_spec.content_type,
        } };
    }

    pub fn selectWebSocket(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.WebSocketRouteAction {
        _ = self;
        _ = ctx;

        if (netbirdIsWebSocketPath(request.path)) {
            return .{ .accept = .{} };
        }

        return .decline;
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

    pub fn handleH2Headers(
        self: *@This(),
        stream_id: u32,
        request: *const serval.Request,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = writer;

        const route = netbirdClassifyGrpcPath(request.path) orelse return error.InvalidPath;
        try serval_grpc.validateRequest(request);
        try testing.expect(!end_stream);
        try self.trackStreamRoute(stream_id, route);
    }

    pub fn handleH2Data(
        self: *@This(),
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        try testing.expect(end_stream);

        const route = try self.takeStreamRoute(stream_id);
        const grpc_payload = try serval_grpc.parseMessage(payload);

        const response_payload = switch (route) {
            .signal => blk: {
                try testing.expectEqualStrings("signal-ping", grpc_payload);
                break :blk "signal-pong";
            },
            .management => blk: {
                try testing.expectEqualStrings("management-ping", grpc_payload);
                break :blk "management-pong";
            },
            .none => return error.InvalidStreamRoute,
        };

        var grpc_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const response_message = try serval_grpc.buildMessage(&grpc_buf, false, response_payload);
        try writer.sendHeaders(200, &.{.{ .name = "content-type", .value = "application/grpc" }}, false);
        try writer.sendData(response_message, false);
        try writer.sendTrailers(&.{.{ .name = "grpc-status", .value = "0" }});
    }
};

const NetbirdServerShared = struct {
    port: u16,
    shutdown: std.atomic.Value(bool),
    listener_fd: std.atomic.Value(i32),
};

const NetbirdDualBackendServer = struct {
    shared: *NetbirdServerShared,
    thread: ?std.Thread,

    fn start(port: u16) !NetbirdDualBackendServer {
        const shared = try std.heap.page_allocator.create(NetbirdServerShared);
        errdefer std.heap.page_allocator.destroy(shared);

        shared.* = .{
            .port = port,
            .shutdown = std.atomic.Value(bool).init(false),
            .listener_fd = std.atomic.Value(i32).init(-1),
        };

        var server = NetbirdDualBackendServer{ .shared = shared, .thread = null };
        server.thread = try std.Thread.spawn(.{}, netbirdDualBackendServerMain, .{shared});

        var waited_ms: u16 = 0;
        while (waited_ms < NETBIRD_STARTUP_TIMEOUT_MS) : (waited_ms += 1) {
            if (shared.listener_fd.load(.acquire) >= 0) return server;
            posix.nanosleep(0, std.time.ns_per_ms);
        }

        shared.shutdown.store(true, .release);
        const wake_sock = connectTcp(shared.port) catch null;
        if (wake_sock) |sock| posix.close(sock);
        _ = shared.listener_fd.swap(-1, .acq_rel);

        if (server.thread) |thread| {
            thread.join();
            server.thread = null;
        }

        std.heap.page_allocator.destroy(shared);
        return error.BackendStartupTimeout;
    }

    fn stop(self: *NetbirdDualBackendServer) void {
        self.shared.shutdown.store(true, .release);
        const wake_sock = connectTcp(self.shared.port) catch null;
        if (wake_sock) |sock| posix.close(sock);
        _ = self.shared.listener_fd.swap(-1, .acq_rel);

        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }

        std.heap.page_allocator.destroy(self.shared);
    }
};

fn netbirdDualBackendServerMain(shared: *NetbirdServerShared) void {
    var handler = NetbirdDualBackendHandler{};
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};
    var evented: std.Io.Evented = undefined;
    init_test_io_runtime(&evented, std.heap.page_allocator) catch |err| {
        std.log.err("netbird dual backend io init failed: {s}", .{@errorName(err)});
        return;
    };
    defer evented.deinit();

    const ServerType = serval.Server(
        NetbirdDualBackendHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    var server = ServerType.init(
        &handler,
        &pool,
        &metrics,
        &tracer,
        .{ .port = shared.port },
        null,
        serval_net.DnsConfig{},
    );

    server.run(evented.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
        std.log.err("netbird backend test server failed: {s}", .{@errorName(err)});
    };
}

const NetbirdRouteProxyHandler = struct {
    signal_upstream: serval.Upstream,
    management_upstream: serval.Upstream,
    http_upstream: serval.Upstream,

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = ctx;

        const grpc_route = netbirdClassifyGrpcPath(request.path);
        if (grpc_route) |route| {
            return switch (route) {
                .signal => self.signal_upstream,
                .management => self.management_upstream,
                .none => self.http_upstream,
            };
        }

        return self.http_upstream;
    }
};

const NetbirdRouteProxyConfig = struct {
    port: u16,
    signal_upstream: serval.Upstream,
    management_upstream: serval.Upstream,
    http_upstream: serval.Upstream,
};

const NetbirdRouteProxyServer = struct {
    shared: *NetbirdServerShared,
    thread: ?std.Thread,

    fn start(config: NetbirdRouteProxyConfig) !NetbirdRouteProxyServer {
        const shared = try std.heap.page_allocator.create(NetbirdServerShared);
        errdefer std.heap.page_allocator.destroy(shared);

        shared.* = .{
            .port = config.port,
            .shutdown = std.atomic.Value(bool).init(false),
            .listener_fd = std.atomic.Value(i32).init(-1),
        };

        var server = NetbirdRouteProxyServer{ .shared = shared, .thread = null };
        server.thread = try std.Thread.spawn(.{}, netbirdRouteProxyServerMain, .{ shared, config });

        var waited_ms: u16 = 0;
        while (waited_ms < NETBIRD_STARTUP_TIMEOUT_MS) : (waited_ms += 1) {
            if (shared.listener_fd.load(.acquire) >= 0) return server;
            posix.nanosleep(0, std.time.ns_per_ms);
        }

        shared.shutdown.store(true, .release);
        const wake_sock = connectTcp(shared.port) catch null;
        if (wake_sock) |sock| posix.close(sock);
        _ = shared.listener_fd.swap(-1, .acq_rel);

        if (server.thread) |thread| {
            thread.join();
            server.thread = null;
        }

        std.heap.page_allocator.destroy(shared);
        return error.ProxyStartupTimeout;
    }

    fn stop(self: *NetbirdRouteProxyServer) void {
        self.shared.shutdown.store(true, .release);
        const wake_sock = connectTcp(self.shared.port) catch null;
        if (wake_sock) |sock| posix.close(sock);
        _ = self.shared.listener_fd.swap(-1, .acq_rel);

        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }

        std.heap.page_allocator.destroy(self.shared);
    }
};

fn netbirdRouteProxyServerMain(shared: *NetbirdServerShared, config: NetbirdRouteProxyConfig) void {
    var handler = NetbirdRouteProxyHandler{
        .signal_upstream = config.signal_upstream,
        .management_upstream = config.management_upstream,
        .http_upstream = config.http_upstream,
    };
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};
    var evented: std.Io.Evented = undefined;
    init_test_io_runtime(&evented, std.heap.page_allocator) catch |err| {
        std.log.err("netbird route proxy io init failed: {s}", .{@errorName(err)});
        return;
    };
    defer evented.deinit();

    const ServerType = serval.Server(
        NetbirdRouteProxyHandler,
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

    server.run(evented.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
        std.log.err("netbird proxy test server failed: {s}", .{@errorName(err)});
    };
}

fn expectGrpcUnaryThroughNetbirdProxy(
    proxy_port: u16,
    path: []const u8,
    request_payload: []const u8,
    expected_response_payload: []const u8,
) !void {
    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request(path, authority, request_payload, &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings(expected_response_payload, grpc_payload);
                saw_data = true;
            },
            else => {},
        }

        if (saw_headers and saw_data and saw_trailers) break;
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
}

fn expectWebSocketEchoThroughNetbirdProxy(proxy_port: u16, path: []const u8, payload: []const u8) !void {
    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var handshake_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const handshake = try buildClientHandshake(path, proxy_port, &handshake_buf);

    var client_frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const client_frame = try buildMaskedClientTextFrame(payload, &client_frame_buf);

    var request_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf, "{s}{s}", .{ handshake, client_frame });
    try sendAllTcp(sock, request);

    var response_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    const status = harness.TestClient.parseStatusCode(response_buf[0..response_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 101), status);

    const header_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n") orelse return error.InvalidResponse;
    var frame_buf: [WS_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const frame_payload = try readServerTextFrame(sock, response_buf[header_end + 4 .. response_len], &frame_buf);
    try testing.expectEqualStrings(payload, frame_payload);
    try performClientCloseHandshake(sock);
}

test "integration: h1 short-circuit unread body closes connection before pipelined follow-on request" {
    const backend_port = harness.getPort();

    var backend = try NetbirdDualBackendServer.start(backend_port);
    defer backend.stop();

    const sock = try connectTcp(backend_port);
    defer posix.close(sock);

    var request_buf: [1024]u8 = undefined;
    const pipelined_request = try std.fmt.bufPrint(
        &request_buf,
            "POST /api/accounts HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:{d}\r\n" ++
            "Content-Length: 8\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n" ++
            "BODYDATA" ++
            "GET /oauth2/authorize HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:{d}\r\n" ++
            "\r\n",
        .{ backend_port, backend_port },
    );
    try sendAllTcp(sock, pipelined_request);

    var response_buf: [2048]u8 = undefined;
    const first_len = try readUntilHeadersComplete(sock, &response_buf);
    const first_status = harness.TestClient.parseStatusCode(response_buf[0..first_len]) orelse return error.InvalidResponse;
    try testing.expectEqual(@as(u16, 401), first_status);
    try testing.expect(std.mem.indexOf(u8, response_buf[0..first_len], "HTTP/1.1 200") == null);

    var saw_close = false;
    var recv_buf: [1024]u8 = undefined;
    var reads: u8 = 0;
    while (reads < 4) : (reads += 1) {
        const n = posix.recv(sock, &recv_buf, 0) catch |err| switch (err) {
            error.ConnectionResetByPeer => {
                saw_close = true;
                break;
            },
            error.WouldBlock => break,
            else => return err,
        };

        if (n == 0) {
            saw_close = true;
            break;
        }

        try testing.expect(std.mem.indexOf(u8, recv_buf[0..n], "HTTP/1.1 200") == null);
    }

    try testing.expect(saw_close);
}

test "integration: netbird route matrix enforces grpc h2c only for service paths" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var backend = try NetbirdDualBackendServer.start(backend_port);
    defer backend.stop();

    var proxy = try NetbirdRouteProxyServer.start(.{
        .port = proxy_port,
        .signal_upstream = .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 0,
            .http_protocol = .h2c,
        },
        .management_upstream = .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 1,
            .http_protocol = .h2c,
        },
        .http_upstream = .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 2,
            .http_protocol = .h1,
        },
    });
    defer proxy.stop();

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const api_response = try client.get(proxy_port, "/api/accounts");
    defer api_response.deinit();
    try testing.expectEqual(@as(u16, 401), api_response.status);
    try testing.expect(std.mem.indexOf(u8, api_response.body, "api-unauthorized") != null);

    try expectGrpcUnaryThroughNetbirdProxy(
        proxy_port,
        "/signalexchange.SignalExchange/Connect",
        "signal-ping",
        "signal-pong",
    );

    const oauth2_response = try client.get(proxy_port, "/oauth2/authorize");
    defer oauth2_response.deinit();
    try testing.expectEqual(@as(u16, 200), oauth2_response.status);
    try testing.expect(std.mem.indexOf(u8, oauth2_response.body, "oauth2-ok") != null);

    try expectGrpcUnaryThroughNetbirdProxy(
        proxy_port,
        "/management.ManagementService/GetServerKey",
        "management-ping",
        "management-pong",
    );

    const well_known_response = try client.get(proxy_port, "/.well-known/openid-configuration");
    defer well_known_response.deinit();
    try testing.expectEqual(@as(u16, 200), well_known_response.status);
    try testing.expect(std.mem.indexOf(u8, well_known_response.body, "\"issuer\":\"https://netbird.local\"") != null);

    const oidc_response = try client.get(proxy_port, "/oidc/v1/userinfo");
    defer oidc_response.deinit();
    try testing.expectEqual(@as(u16, 200), oidc_response.status);
    try testing.expect(std.mem.indexOf(u8, oidc_response.body, "zitadel-http-ok") != null);

    const oauth_response = try client.get(proxy_port, "/oauth/v2/token");
    defer oauth_response.deinit();
    try testing.expectEqual(@as(u16, 200), oauth_response.status);
    try testing.expect(std.mem.indexOf(u8, oauth_response.body, "zitadel-http-ok") != null);

    const ui_response = try client.get(proxy_port, "/ui/index.html");
    defer ui_response.deinit();
    try testing.expectEqual(@as(u16, 200), ui_response.status);
    try testing.expect(std.mem.indexOf(u8, ui_response.body, "zitadel-http-ok") != null);

    const catch_all_response = try client.get(proxy_port, "/dashboard");
    defer catch_all_response.deinit();
    try testing.expectEqual(@as(u16, 200), catch_all_response.status);
    try testing.expect(std.mem.indexOf(u8, catch_all_response.body, "dashboard-catch-all") != null);

    try expectWebSocketEchoThroughNetbirdProxy(proxy_port, "/ws-proxy/signal", "ws-signal-echo");
    try expectWebSocketEchoThroughNetbirdProxy(proxy_port, "/relay", "ws-relay-echo");
}

fn writeReverseproxyDslFile(
    allocator: std.mem.Allocator,
    proxy_port: u16,
    tag: []const u8,
    dsl_content: []const u8,
) ![]u8 {
    std.debug.assert(tag.len > 0);
    std.debug.assert(dsl_content.len > 0);

    const path = try std.fmt.allocPrint(allocator, "integration/tmp_reverseproxy_{d}_{s}.dsl", .{ proxy_port, tag });
    errdefer allocator.free(path);

    try std.Io.Dir.cwd().writeFile(std.Options.debug_io, .{ .sub_path = path, .data = dsl_content });
    return path;
}

fn cleanupTempDslFile(path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(std.Options.debug_io, path) catch |err| {
        if (err != error.FileNotFound) {
            std.debug.print("warn: failed to delete temp DSL file '{s}': {s}\n", .{ path, @errorName(err) });
        }
    };
}

fn writeReverseproxyDslConfig(
    allocator: std.mem.Allocator,
    proxy_port: u16,
    backend_port: u16,
    route_prefix: []const u8,
) ![]u8 {
    std.debug.assert(route_prefix.len > 0);

    var host_buf: [48]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port});

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-a upstream=http://127.0.0.1:{d}
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=plugin-a
        \\route route-a listener=l1 host={s} path={s} pool=pool-a chain=chain-a
    ,
        .{ proxy_port, backend_port, host, route_prefix },
    );
    defer allocator.free(content);

    return writeReverseproxyDslFile(allocator, proxy_port, "single", content);
}

fn writeReverseproxyNetbirdDslConfig(
    allocator: std.mem.Allocator,
    proxy_port: u16,
    backend_port: u16,
) ![]u8 {
    assert(proxy_port > 0);
    assert(backend_port > 0);

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool signal-grpc upstream=h2c://127.0.0.1:{d}
        \\pool management-grpc upstream=h2c://127.0.0.1:{d}
        \\pool http-matrix upstream=http://127.0.0.1:{d}
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=plugin-a
        \\route signal-grpc listener=l1 host=* path=/signalexchange.SignalExchange/ pool=signal-grpc chain=chain-a
        \\route management-grpc listener=l1 host=* path=/management.ManagementService/ pool=management-grpc chain=chain-a
        \\route management-proxy listener=l1 host=* path=/management.ProxyService/ pool=management-grpc chain=chain-a
        \\route ws-signal listener=l1 host=* path=/ws-proxy/signal pool=http-matrix chain=chain-a
        \\route ws-management listener=l1 host=* path=/ws-proxy/management pool=http-matrix chain=chain-a
        \\route relay listener=l1 host=* path=/relay pool=http-matrix chain=chain-a
        \\route api listener=l1 host=* path=/api/ pool=http-matrix chain=chain-a
        \\route well-known listener=l1 host=* path=/.well-known/ pool=http-matrix chain=chain-a
        \\route dashboard listener=l1 host=* path=/ pool=http-matrix chain=chain-a
    ,
        .{ proxy_port, backend_port, backend_port, backend_port },
    );
    defer allocator.free(content);

    return writeReverseproxyDslFile(allocator, proxy_port, "netbird-replacement", content);
}

test "integration: reverseproxy runtime binary loads dsl config and forwards matched route" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "rp-runtime-backend", .{});

    const dsl_path = try writeReverseproxyDslConfig(allocator, proxy_port, backend_port, "/api");
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntime(proxy_port, .{
        .config_file = dsl_path,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(proxy_port, "/api/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expect(response.backend_id != null);
    try testing.expectEqualStrings("rp-runtime-backend", response.backend_id.?);
}

test "integration: reverseproxy runtime binary returns 404 for unmatched route" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "rp-runtime-backend-404", .{});

    const dsl_path = try writeReverseproxyDslConfig(allocator, proxy_port, backend_port, "/api");
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntime(proxy_port, .{
        .config_file = dsl_path,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(proxy_port, "/nope");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 404), response.status);
    try testing.expect(std.mem.indexOf(u8, response.body, "Not Found") != null);
}

test "integration: reverseproxy runtime binary requires host match" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "rp-runtime-host", .{});

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-a upstream=http://127.0.0.1:{d}
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=plugin-a
        \\route route-a listener=l1 host=example.com path=/api pool=pool-a chain=chain-a
    ,
        .{ proxy_port, backend_port },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "host-mismatch", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntime(proxy_port, .{
        .config_file = dsl_path,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(proxy_port, "/api/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 404), response.status);
    try testing.expect(std.mem.indexOf(u8, response.body, "Not Found") != null);
}

test "integration: reverseproxy runtime binary uses first-match route semantics" {
    const allocator = testing.allocator;
    const backend_api_port = harness.getPort();
    const backend_admin_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_api_port, "rp-runtime-api", .{});
    try pm.startEchoBackend(backend_admin_port, "rp-runtime-admin", .{});

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-api upstream=http://127.0.0.1:{d}
        \\pool pool-admin upstream=http://127.0.0.1:{d}
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-api plugin=plugin-a
        \\chain chain-admin plugin=plugin-a
        \\route route-api listener=l1 host={s} path=/api pool=pool-api chain=chain-api
        \\route route-admin listener=l1 host={s} path=/api/admin pool=pool-admin chain=chain-admin
    ,
        .{ proxy_port, backend_api_port, backend_admin_port, host, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "longest-prefix", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntime(proxy_port, .{
        .config_file = dsl_path,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(proxy_port, "/api/admin/users");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expect(response.backend_id != null);
    try testing.expectEqualStrings("rp-runtime-api", response.backend_id.?);
}

test "integration: reverseproxy runtime binary routes different prefixes to distinct pools" {
    const allocator = testing.allocator;
    const backend_api_port = harness.getPort();
    const backend_static_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_api_port, "rp-runtime-api-split", .{});
    try pm.startEchoBackend(backend_static_port, "rp-runtime-static-split", .{});

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-api upstream=http://127.0.0.1:{d}
        \\pool pool-static upstream=http://127.0.0.1:{d}
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-api plugin=plugin-a
        \\chain chain-static plugin=plugin-a
        \\route route-api listener=l1 host={s} path=/api pool=pool-api chain=chain-api
        \\route route-static listener=l1 host={s} path=/static pool=pool-static chain=chain-static
    ,
        .{ proxy_port, backend_api_port, backend_static_port, host, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "split-prefix", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntime(proxy_port, .{
        .config_file = dsl_path,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const api_response = try client.get(proxy_port, "/api/v1/accounts");
    defer api_response.deinit();
    try testing.expectEqual(@as(u16, 200), api_response.status);
    try testing.expect(api_response.backend_id != null);
    try testing.expectEqualStrings("rp-runtime-api-split", api_response.backend_id.?);

    const static_response = try client.get(proxy_port, "/static/app.js");
    defer static_response.deinit();
    try testing.expectEqual(@as(u16, 200), static_response.status);
    try testing.expect(static_response.backend_id != null);
    try testing.expectEqualStrings("rp-runtime-static-split", static_response.backend_id.?);
}

test "integration: reverseproxy runtime admission rejects missing pool upstream spec" {
    const allocator = testing.allocator;
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-a
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=plugin-a
        \\route route-a listener=l1 host={s} path=/api pool=pool-a chain=chain-a
    ,
        .{ proxy_port, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "missing-pool-upstream", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntimeExpectFailure(proxy_port, .{
        .config_file = dsl_path,
    });
}

test "integration: reverseproxy runtime binary returns 502 when upstream is unavailable" {
    const allocator = testing.allocator;
    const unreachable_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    const dsl_path = try writeReverseproxyDslConfig(allocator, proxy_port, unreachable_port, "/api");
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntime(proxy_port, .{
        .config_file = dsl_path,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.get(proxy_port, "/api/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 502), response.status);
}

test "integration: reverseproxy runtime binary admission rejects duplicate route ids" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "rp-runtime-admission-dup", .{});

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-a upstream=http://127.0.0.1:1
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=plugin-a
        \\route route-a listener=l1 host={s} path=/api pool=pool-a chain=chain-a
        \\route route-a listener=l1 host={s} path=/admin pool=pool-a chain=chain-a
    ,
        .{ proxy_port, host, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "admission-dup", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntimeExpectFailure(proxy_port, .{
        .config_file = dsl_path,
    });
}

test "integration: reverseproxy runtime binary admission rejects unsupported DSL constructs" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "rp-runtime-admission-unsupported", .{});

    const content =
        \\listener l1 0.0.0.0:19000
        \\pool pool-a
        \\plugin plugin-a fail_policy=fail_closed
        \\function dynamic-route-builder
    ;

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "admission-unsupported", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntimeExpectFailure(proxy_port, .{
        .config_file = dsl_path,
    });
}

test "integration: reverseproxy orchestrator rollback to last-known-good on guard breach" {
    const reverseproxy = serval.reverseproxy;

    const budget = reverseproxy.RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };

    const entries = [_]reverseproxy.ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = budget,
        .priority = 1,
        .before = &.{},
        .after = &.{},
    }};

    const candidate = reverseproxy.CanonicalIr{
        .listeners = &[_]reverseproxy.Listener{.{ .id = "l", .bind = "0.0.0.0:443" }},
        .pools = &[_]reverseproxy.Pool{.{ .id = "pool-a" }},
        .routes = &[_]reverseproxy.Route{.{
            .id = "route-a",
            .listener_id = "l",
            .host = "example.com",
            .path_prefix = "/",
            .pool_id = "pool-a",
            .chain_id = "chain-a",
            .disable_plugin_ids = &.{},
            .add_plugin_ids = &.{},
            .waivers = &.{},
        }},
        .plugins = &[_]reverseproxy.PluginCatalogEntry{.{
            .id = "plugin-a",
            .version = "1",
            .enabled = true,
            .mandatory = false,
            .disable_requires_waiver = false,
        }},
        .chains = &[_]reverseproxy.ChainPlan{.{ .id = "chain-a", .entries = entries[0..] }},
        .global_plugin_ids = &.{},
    };

    var orchestrator = reverseproxy.Orchestrator.init(1_000_000);
    var snapshot_v1 = reverseproxy.RuntimeSnapshot.fromCanonicalIr(&candidate, 1, 10);
    try orchestrator.admitAndActivate(&candidate, &snapshot_v1, 20);

    var snapshot_v2 = reverseproxy.RuntimeSnapshot.fromCanonicalIr(&candidate, 2, 30);
    try orchestrator.admitAndActivate(&candidate, &snapshot_v2, 40);

    var monitor = reverseproxy.GuardWindowMonitor.init(
        &orchestrator,
        .{ .guard_window_ns = 1000, .max_error_rate_milli = 10, .max_fail_closed_count = 1 },
        2,
        40,
    );

    const decision = monitor.evaluate(.{ .request_count = 100, .error_count = 60, .fail_closed_count = 0 }, 50);
    try testing.expectEqual(reverseproxy.GuardDecision.auto_rollback, decision);
    try testing.expectEqual(@as(u64, 1), orchestrator.getActiveSnapshot().?.generation_id);
}

test "integration: reverseproxy orchestrator enters safe mode when rollback unavailable" {
    const reverseproxy = serval.reverseproxy;

    var orchestrator = reverseproxy.Orchestrator.init(1_000_000);
    var monitor = reverseproxy.GuardWindowMonitor.init(
        &orchestrator,
        .{ .guard_window_ns = 1000, .max_error_rate_milli = 10, .max_fail_closed_count = 1 },
        1,
        10,
    );

    const decision = monitor.evaluate(.{ .request_count = 10, .error_count = 10, .fail_closed_count = 0 }, 11);
    try testing.expectEqual(reverseproxy.GuardDecision.safe_mode, decision);
    try testing.expectEqual(reverseproxy.ApplyStage.safe_mode, orchestrator.getStage());
}

test "integration: reverseproxy loads custom filter and validates hook lifecycle" {
    const reverseproxy = serval.reverseproxy;
    const sdk = serval.filter_sdk;

    const LoadedFilter = custom_filter.HookLifecycleFilter;
    const Observe = custom_filter.Observer;

    const Sink = struct {
        bytes: u64 = 0,

        fn write(ctx: *anyopaque, out: []const u8) sdk.EmitError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.bytes += out.len;
        }
    };

    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plugin-1 fail_policy=fail_closed
        \\chain c1 plugin=plugin-1
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const parsed = try reverseproxy.parseDsl(source);
    var candidate = parsed.toCanonicalIr();

    var diagnostics: [reverseproxy.ir.MAX_VALIDATION_DIAGNOSTICS]reverseproxy.ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;
    try reverseproxy.validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count);
    try testing.expectEqual(@as(u32, 0), diagnostics_count);

    var registry = reverseproxy.FilterRegistry.init();
    var loaded = LoadedFilter{};
    try registry.registerTyped("plugin-1", &loaded, LoadedFilter);

    var observe = Observe{};
    var filter_ctx = sdk.FilterContext{
        .route_id = "r1",
        .chain_id = "c1",
        .plugin_id = "",
        .request_id = 1,
        .stream_id = 1,
        .set_tag_fn = Observe.setTag,
        .incr_counter_fn = Observe.incrCounter,
        .observe_ctx = &observe,
    };

    var request_header_storage: [serval.config.MAX_HEADERS]serval.Header = undefined;
    var response_header_storage: [serval.config.MAX_HEADERS]serval.Header = undefined;
    var request_header_count: u32 = 0;
    var response_header_count: u32 = 0;
    var request_headers = sdk.HeaderWriteView.init(request_header_storage[0..], &request_header_count);
    var response_headers = sdk.HeaderWriteView.init(response_header_storage[0..], &response_header_count);

    var sink = Sink{};
    var emit = sdk.EmitWriter.init(&sink, Sink.write, 64);
    var hooks = reverseproxy.HookObservation.init();

    const decision = try registry.executeRouteHooks(
        &candidate,
        "r1",
        &filter_ctx,
        &request_headers,
        &response_headers,
        &[_][]const u8{ "ab", "cd" },
        &[_][]const u8{"ef"},
        &emit,
        .{ .ctx = &sink, .wait_writable_fn = custom_filter.AlwaysWritable.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &hooks,
    );

    switch (decision) {
        .continue_filtering => {},
        .reject, .bypass_plugin => return error.TestExpectedEqual,
    }

    try testing.expectEqual(@as(u32, 1), loaded.request_headers);
    try testing.expectEqual(@as(u32, 2), loaded.request_chunks);
    try testing.expectEqual(@as(u32, 1), loaded.request_end);
    try testing.expectEqual(@as(u32, 1), loaded.response_headers);
    try testing.expectEqual(@as(u32, 1), loaded.response_chunks);
    try testing.expectEqual(@as(u32, 1), loaded.response_end);
    try testing.expectEqual(@as(u64, 6), sink.bytes);
    try testing.expectEqual(@as(u32, 1), observe.tags);
    try testing.expectEqual(@as(u32, 1), observe.counters);
    try testing.expectEqual(@as(u32, 1), hooks.request_headers_calls);
    try testing.expectEqual(@as(u32, 2), hooks.request_chunk_calls);
    try testing.expectEqual(@as(u32, 1), hooks.response_chunk_calls);
}

test "integration: reverseproxy custom filter transforms request and response bodies" {
    const reverseproxy = serval.reverseproxy;
    const sdk = serval.filter_sdk;

    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plugin-1 fail_policy=fail_closed
        \\chain c1 plugin=plugin-1
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const parsed = try reverseproxy.parseDsl(source);
    var candidate = parsed.toCanonicalIr();

    var diagnostics: [reverseproxy.ir.MAX_VALIDATION_DIAGNOSTICS]reverseproxy.ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;
    try reverseproxy.validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count);
    try testing.expectEqual(@as(u32, 0), diagnostics_count);

    var registry = reverseproxy.FilterRegistry.init();
    var filter = custom_filter.BodyTransformFilter{};
    try registry.registerTyped("plugin-1", &filter, custom_filter.BodyTransformFilter);

    var filter_ctx = sdk.FilterContext{
        .route_id = "r1",
        .chain_id = "c1",
        .plugin_id = "",
        .request_id = 2,
        .stream_id = 9,
    };

    var request_header_storage: [serval.config.MAX_HEADERS]serval.Header = undefined;
    var response_header_storage: [serval.config.MAX_HEADERS]serval.Header = undefined;
    var request_header_count: u32 = 0;
    var response_header_count: u32 = 0;
    var request_headers = sdk.HeaderWriteView.init(request_header_storage[0..], &request_header_count);
    var response_headers = sdk.HeaderWriteView.init(response_header_storage[0..], &response_header_count);

    var sink = custom_filter.CaptureSink{};
    var emit = sdk.EmitWriter.init(&sink, custom_filter.CaptureSink.write, 128);
    var hooks = reverseproxy.HookObservation.init();

    const decision = try registry.executeRouteHooks(
        &candidate,
        "r1",
        &filter_ctx,
        &request_headers,
        &response_headers,
        &[_][]const u8{"ab"},
        &[_][]const u8{"cd"},
        &emit,
        .{ .ctx = &sink, .wait_writable_fn = custom_filter.AlwaysWritable.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &hooks,
    );

    switch (decision) {
        .continue_filtering => {},
        .reject, .bypass_plugin => return error.TestExpectedEqual,
    }

    try testing.expectEqualStrings("REQ:ab;RES:cd;", sink.bytes());
    try testing.expectEqual(@as(usize, 1), request_headers.len());
    try testing.expectEqual(@as(usize, 1), response_headers.len());
    try testing.expectEqualStrings("x-request-filter", request_headers.get(0).?.name);
    try testing.expectEqualStrings("enabled", request_headers.get(0).?.value);
    try testing.expectEqualStrings("x-response-filter", response_headers.get(0).?.name);
    try testing.expectEqualStrings("enabled", response_headers.get(0).?.value);
}

test "integration: reverseproxy runtime admission rejects unknown pool reference" {
    const allocator = testing.allocator;
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-a upstream=http://127.0.0.1:1
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=plugin-a
        \\route route-a listener=l1 host={s} path=/api pool=missing chain=chain-a
    ,
        .{ proxy_port, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "admission-missing-pool", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntimeExpectFailure(proxy_port, .{
        .config_file = dsl_path,
    });
}

test "integration: reverseproxy runtime admission rejects unknown chain reference" {
    const allocator = testing.allocator;
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-a upstream=http://127.0.0.1:1
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=plugin-a
        \\route route-a listener=l1 host={s} path=/api pool=pool-a chain=missing
    ,
        .{ proxy_port, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "admission-missing-chain", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntimeExpectFailure(proxy_port, .{
        .config_file = dsl_path,
    });
}

test "integration: reverseproxy runtime admission rejects unknown plugin reference" {
    const allocator = testing.allocator;
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-a upstream=http://127.0.0.1:1
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=missing-plugin
        \\route route-a listener=l1 host={s} path=/api pool=pool-a chain=chain-a
    ,
        .{ proxy_port, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "admission-missing-plugin", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntimeExpectFailure(proxy_port, .{
        .config_file = dsl_path,
    });
}

test "integration: reverseproxy runtime admission rejects duplicate chain ids" {
    const allocator = testing.allocator;
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-a upstream=http://127.0.0.1:1
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-a plugin=plugin-a
        \\chain chain-a plugin=plugin-a
        \\route route-a listener=l1 host={s} path=/api pool=pool-a chain=chain-a
    ,
        .{ proxy_port, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "admission-duplicate-chain", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntimeExpectFailure(proxy_port, .{
        .config_file = dsl_path,
    });
}

test "integration: reverseproxy runtime tie-break is deterministic (first route wins)" {
    const allocator = testing.allocator;
    const backend_first_port = harness.getPort();
    const backend_second_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_first_port, "rp-runtime-first", .{});
    try pm.startEchoBackend(backend_second_port, "rp-runtime-second", .{});

    var host_buf: [48]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{proxy_port}) catch unreachable;

    const content = try std.fmt.allocPrint(
        allocator,
        \\listener l1 0.0.0.0:{d}
        \\pool pool-first upstream=http://127.0.0.1:{d}
        \\pool pool-second upstream=http://127.0.0.1:{d}
        \\plugin plugin-a fail_policy=fail_closed
        \\chain chain-first plugin=plugin-a
        \\chain chain-second plugin=plugin-a
        \\route route-first listener=l1 host={s} path=/api pool=pool-first chain=chain-first
        \\route route-second listener=l1 host={s} path=/api pool=pool-second chain=chain-second
    ,
        .{ proxy_port, backend_first_port, backend_second_port, host, host },
    );
    defer allocator.free(content);

    const dsl_path = try writeReverseproxyDslFile(allocator, proxy_port, "tie-break-equal-prefix", content);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntime(proxy_port, .{
        .config_file = dsl_path,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    var request_index: u32 = 0;
    while (request_index < 5) : (request_index += 1) {
        const response = try client.get(proxy_port, "/api/tie-break");
        defer response.deinit();
        try testing.expectEqual(@as(u16, 200), response.status);
        try testing.expect(response.backend_id != null);
        try testing.expectEqualStrings("rp-runtime-first", response.backend_id.?);
    }
}

test "integration: netbird reverseproxy runtime dsl enforces grpc h2c split" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var backend = try NetbirdDualBackendServer.start(backend_port);
    defer backend.stop();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    const dsl_path = try writeReverseproxyNetbirdDslConfig(allocator, proxy_port, backend_port);
    defer allocator.free(dsl_path);
    defer cleanupTempDslFile(dsl_path);

    try pm.startReverseproxyRuntime(proxy_port, .{
        .config_file = dsl_path,
    });

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const api_response = try client.get(proxy_port, "/api/accounts");
    defer api_response.deinit();
    try testing.expectEqual(@as(u16, 401), api_response.status);
    try testing.expect(std.mem.indexOf(u8, api_response.body, "api-unauthorized") != null);

    try expectGrpcUnaryThroughNetbirdProxy(
        proxy_port,
        "/signalexchange.SignalExchange/Connect",
        "signal-ping",
        "signal-pong",
    );

    try expectGrpcUnaryThroughNetbirdProxy(
        proxy_port,
        "/management.ManagementService/GetServerKey",
        "management-ping",
        "management-pong",
    );

    const well_known_response = try client.get(proxy_port, "/.well-known/openid-configuration");
    defer well_known_response.deinit();
    try testing.expectEqual(@as(u16, 200), well_known_response.status);
    try testing.expect(std.mem.indexOf(u8, well_known_response.body, "\"issuer\":\"https://netbird.local\"") != null);

    const catch_all_response = try client.get(proxy_port, "/dashboard");
    defer catch_all_response.deinit();
    try testing.expectEqual(@as(u16, 200), catch_all_response.status);
    try testing.expect(std.mem.indexOf(u8, catch_all_response.body, "dashboard-catch-all") != null);

    try expectWebSocketEchoThroughNetbirdProxy(proxy_port, "/ws-proxy/signal", "ws-signal-echo");
    try expectWebSocketEchoThroughNetbirdProxy(proxy_port, "/relay", "ws-relay-echo");
}

test "integration: netbird subprocess serves local health endpoint" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "rp-health-backend", .{});

    var http_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    var h2c_addr_buf: [ADDR_BUF_LEN + 4]u8 = undefined;
    const http_addr = std.fmt.bufPrint(&http_addr_buf, "http://127.0.0.1:{d}", .{backend_port}) catch unreachable;
    const h2c_addr = std.fmt.bufPrint(&h2c_addr_buf, "h2c://127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startNetbirdProxy(proxy_port, .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
        .management_http = http_addr,
        .dashboard_http = http_addr,
        .relay_http = http_addr,
        .signal_http = http_addr,
        .signal_grpc = h2c_addr,
        .management_grpc = h2c_addr,
        .zitadel_http = h2c_addr,
    });

    const response = try curlHttps(allocator, proxy_port, "/healthz");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqualStrings("ok\n", response.body);
    try testing.expect(response.backend_id == null);
}

test "integration: netbird subprocess routes api to management upstream" {
    const allocator = testing.allocator;
    const management_port = harness.getPort();
    const dashboard_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(management_port, "rp-management", .{});
    try pm.startEchoBackend(dashboard_port, "rp-dashboard", .{});

    var management_http_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    var dashboard_http_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    var management_h2c_addr_buf: [ADDR_BUF_LEN + 4]u8 = undefined;
    var dashboard_h2c_addr_buf: [ADDR_BUF_LEN + 4]u8 = undefined;
    const management_http = std.fmt.bufPrint(&management_http_addr_buf, "http://127.0.0.1:{d}", .{management_port}) catch unreachable;
    const dashboard_http = std.fmt.bufPrint(&dashboard_http_addr_buf, "http://127.0.0.1:{d}", .{dashboard_port}) catch unreachable;
    const management_h2c = std.fmt.bufPrint(&management_h2c_addr_buf, "h2c://127.0.0.1:{d}", .{management_port}) catch unreachable;
    const dashboard_h2c = std.fmt.bufPrint(&dashboard_h2c_addr_buf, "h2c://127.0.0.1:{d}", .{dashboard_port}) catch unreachable;

    try pm.startNetbirdProxy(proxy_port, .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
        .management_http = management_http,
        .dashboard_http = dashboard_http,
        .relay_http = dashboard_http,
        .signal_http = dashboard_http,
        .signal_grpc = management_h2c,
        .management_grpc = management_h2c,
        .zitadel_http = dashboard_h2c,
    });

    const api_response = try curlHttps(allocator, proxy_port, "/api/accounts");
    defer api_response.deinit();
    try testing.expectEqual(@as(u16, 200), api_response.status);
    try testing.expect(api_response.backend_id != null);
    try testing.expectEqualStrings("rp-management", api_response.backend_id.?);

    const catch_all_response = try curlHttps(allocator, proxy_port, "/dashboard");
    defer catch_all_response.deinit();
    try testing.expectEqual(@as(u16, 200), catch_all_response.status);
    try testing.expect(catch_all_response.backend_id != null);
    try testing.expectEqualStrings("rp-dashboard", catch_all_response.backend_id.?);
}

test "integration: terminated h2 server acks settings and ping and serves unary grpc" {
    const server_port = harness.getPort();

    const server_thread = try startTerminatedH2Server(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UnaryDirect",
        .expected_request_payload = "ping",
        .response_payload = "pong-direct",
    });
    defer server_thread.join();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2RequestWithPing("/grpc.test.Echo/UnaryDirect", authority, "ping", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_server_settings = false;
    var saw_settings_ack = false;
    var saw_ping_ack = false;
    var saw_headers = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                } else {
                    saw_settings_ack = true;
                }
            },
            .ping => {
                try testing.expectEqual(serval_h2.flags_ack, frame_view.header.flags);
                saw_ping_ack = true;
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-direct", grpc_payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_settings_ack);
    try testing.expect(saw_ping_ack);
    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: serval-client h2 connection driver interoperates with terminated h2 server" {
    const server_port = harness.getPort();

    const server_thread = try startTerminatedH2Server(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UnaryViaClientConnection",
        .expected_request_payload = "ping-client-conn",
        .response_payload = "pong-client-conn",
    });
    defer server_thread.join();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var socket = serval.Socket.Plain.init_client(sock);
    var h2_conn = try serval_client.H2ClientConnection.init(&socket);
    try h2_conn.completeHandshake();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});

    var request = serval.Request{
        .method = .POST,
        .path = "/grpc.test.Echo/UnaryViaClientConnection",
        .version = .@"HTTP/1.1",
        .headers = serval.HeaderMap.init(),
        .body = null,
    };
    try request.headers.put("host", authority);
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    const stream_id = try h2_conn.sendRequestHeaders(&request, null, false);
    try testing.expectEqual(@as(u32, 1), stream_id);

    var request_payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_payload = try serval_grpc.buildMessage(&request_payload_buf, false, "ping-client-conn");
    try h2_conn.sendRequestData(stream_id, request_payload, true);

    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const action = h2_conn.receiveActionHandlingControl() catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };

        switch (action) {
            .response_headers => |response_headers| {
                try testing.expectEqual(stream_id, response_headers.stream_id);
                try testing.expectEqual(@as(u16, 200), response_headers.response.status);
                saw_headers = true;
            },
            .response_data => |response_data| {
                try testing.expectEqual(stream_id, response_data.stream_id);
                const grpc_payload = try serval_grpc.parseMessage(response_data.payload);
                try testing.expectEqualStrings("pong-client-conn", grpc_payload);
                saw_data = true;
            },
            .response_trailers => |response_trailers| {
                try testing.expectEqual(stream_id, response_trailers.stream_id);
                try testing.expectEqualStrings("0", response_trailers.trailers.get("grpc-status").?);
                saw_trailers = true;
                break;
            },
            .stream_reset => return error.UnexpectedAction,
            .connection_close => return error.UnexpectedAction,
            else => {},
        }
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
}

test "integration: serval-client h2 upstream session pool reuses connected session" {
    const server_port = harness.getPort();

    var server = try TerminatedH2AcceptLoopServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UnaryViaSessionPool",
        .expected_request_payload = "ping-session-pool",
        .response_payload = "pong-session-pool",
    });
    defer server.stop();

    var dns_resolver: serval_net.DnsResolver = undefined;
    serval_net.DnsResolver.init(&dns_resolver, .{});
    var http_client = serval_client.Client.init(testing.allocator, &dns_resolver, null, false);

    var session_pool = serval_client.H2UpstreamSessionPool.init();
    defer session_pool.deinit();

    var evented: std.Io.Evented = undefined;
    try init_test_io_runtime(&evented, testing.allocator);
    defer evented.deinit();

    const upstream = serval.Upstream{
        .host = "127.0.0.1",
        .port = server_port,
        .idx = 1,
        .tls = false,
        .http_protocol = .h2c,
    };

    const acquired_first = try session_pool.acquireOrConnect(&http_client, upstream, evented.io());
    try testing.expect(!acquired_first.connect.reused);
    try testing.expect(acquired_first.connect.tcp_connect_duration_ns > 0);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});

    try sendGrpcUnaryViaUpstreamSession(
        acquired_first.session,
        "/grpc.test.Echo/UnaryViaSessionPool",
        authority,
        "ping-session-pool",
        "pong-session-pool",
    );

    const first_fd = acquired_first.session.connection.socket.get_fd();
    const acquired_second = try session_pool.acquireOrConnect(&http_client, upstream, evented.io());
    try testing.expect(acquired_second.connect.reused);
    try testing.expectEqual(first_fd, acquired_second.session.connection.socket.get_fd());

    try sendGrpcUnaryViaUpstreamSession(
        acquired_second.session,
        "/grpc.test.Echo/UnaryViaSessionPool",
        authority,
        "ping-session-pool",
        "pong-session-pool",
    );

    try testing.expectEqual(@as(u32, 5), acquired_second.session.h2.runtime.state.next_local_stream_id);
}

test "integration: serval-proxy h2 stream bridge binds downstream to upstream streams" {
    const server_port = harness.getPort();

    var server = try TerminatedH2AcceptLoopServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UnaryViaProxyBridge",
        .expected_request_payload = "ping-proxy-bridge",
        .response_payload = "pong-proxy-bridge",
    });
    defer server.stop();

    var dns_resolver: serval_net.DnsResolver = undefined;
    serval_net.DnsResolver.init(&dns_resolver, .{});
    var http_client = serval_client.Client.init(testing.allocator, &dns_resolver, null, false);

    var session_pool = serval_client.H2UpstreamSessionPool.init();
    defer session_pool.deinit();

    var bridge = serval.proxy.H2StreamBridge.init(&http_client, &session_pool);
    defer bridge.deinit();

    var evented: std.Io.Evented = undefined;
    try init_test_io_runtime(&evented, testing.allocator);
    defer evented.deinit();

    const upstream = serval.Upstream{
        .host = "127.0.0.1",
        .port = server_port,
        .idx = 2,
        .tls = false,
        .http_protocol = .h2c,
    };

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});

    try sendGrpcUnaryViaStreamBridge(
        &bridge,
        evented.io(),
        upstream,
        11,
        authority,
        "/grpc.test.Echo/UnaryViaProxyBridge",
        "ping-proxy-bridge",
        "pong-proxy-bridge",
        false,
        1,
    );

    try sendGrpcUnaryViaStreamBridge(
        &bridge,
        evented.io(),
        upstream,
        13,
        authority,
        "/grpc.test.Echo/UnaryViaProxyBridge",
        "ping-proxy-bridge",
        "pong-proxy-bridge",
        true,
        3,
    );
}

test "integration: main server dispatches prior-knowledge h2c to terminated handler" {
    const server_port = harness.getPort();

    var server = try TerminatedH2AcceptLoopServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UnaryViaMainServer",
        .expected_request_payload = "ping-main",
        .response_payload = "pong-main",
    });
    defer server.stop();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/UnaryViaMainServer", authority, "ping-main", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_server_settings = false;
    var saw_settings_ack = false;
    var saw_headers = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                } else {
                    saw_settings_ack = true;
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-main", grpc_payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_settings_ack);
    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: main server terminated h2 prior-knowledge emits per-stream telemetry" {
    const server_port = harness.getPort();

    var telemetry_shared = H2MainServerTelemetryShared{};
    var server = try TerminatedH2TelemetryServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/TelemetryViaMainServer",
        .expected_request_payload = "ping-telemetry",
        .response_payload = "pong-telemetry",
        .telemetry_shared = &telemetry_shared,
    });
    defer server.stop();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/TelemetryViaMainServer", authority, "ping-telemetry", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_server_settings = false;
    var saw_settings_ack = false;
    var saw_headers = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                } else {
                    saw_settings_ack = true;
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-telemetry", grpc_payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_settings_ack);
    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);

    try waitForAtomicU32Equals(&telemetry_shared.request_ends, 1, H2_TELEMETRY_WAIT_TIMEOUT_MS);
    try waitForAtomicU32Equals(&telemetry_shared.spans_ended, 1, H2_TELEMETRY_WAIT_TIMEOUT_MS);
    try waitForAtomicU32Equals(&telemetry_shared.stream_log_count, 1, H2_TELEMETRY_WAIT_TIMEOUT_MS);

    try testing.expectEqual(@as(u32, 1), telemetry_shared.request_starts.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), telemetry_shared.request_ends.load(.monotonic));
    try testing.expectEqual(@as(u16, 200), telemetry_shared.last_status.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), telemetry_shared.spans_started.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), telemetry_shared.spans_ended.load(.monotonic));
    try testing.expect(telemetry_shared.stream_status_attrs.load(.monotonic) >= 1);
    try testing.expectEqual(@as(u32, 0), telemetry_shared.span_error_count.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), telemetry_shared.stream_log_count.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), telemetry_shared.stream_log_2xx_count.load(.monotonic));
    try testing.expectEqual(@as(u16, 200), telemetry_shared.stream_log_last_status.load(.monotonic));
    try testing.expect(telemetry_shared.stream_log_last_request_number.load(.monotonic) >= 1);
}

test "integration: main server terminated h2 prior-knowledge rejects DATA before HEADERS" {
    const server_port = harness.getPort();

    var server = try TerminatedH2AcceptLoopServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UnusedInvalidOrderingViaMainServer",
        .expected_request_payload = "unused",
        .response_payload = "unused",
    });
    defer server.stop();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildH2DataBeforeHeadersRequest("invalid-order-main", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_server_settings = false;
    var saw_goaway = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = readH2Frame(sock, initial, &frame_buf) catch |err| switch (err) {
            error.ConnectionClosed, error.RecvFailed => break,
            else => return err,
        };
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                }
            },
            .goaway => {
                const goaway = try serval_h2.parseGoAwayFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(@as(u32, 1), goaway.last_stream_id);
                try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.protocol_error)), goaway.error_code_raw);
                saw_goaway = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_goaway);
}

test "integration: main server dispatches h2c upgrade to terminated handler" {
    const server_port = harness.getPort();

    var server = try TerminatedH2AcceptLoopServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UpgradeViaMainServer",
        .expected_request_payload = "ping-upgrade",
        .response_payload = "pong-upgrade",
    });
    defer server.stop();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest(
        "/grpc.test.Echo/UpgradeViaMainServer",
        authority,
        "ping-upgrade",
        &request_buf,
    );

    const request_headers_end = std.mem.indexOf(u8, request, "\r\n\r\n").? + 4;
    try sendAllTcp(sock, request[0..request_headers_end]);
    posix.nanosleep(0, 10 * std.time.ns_per_ms);
    try sendAllTcp(sock, request[request_headers_end..]);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
    try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
    try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

    const response_headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[response_headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_server_settings = false;
    var saw_settings_ack = false;
    var saw_headers = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                } else {
                    saw_settings_ack = true;
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-upgrade", grpc_payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_settings_ack);
    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: main server terminated h2c upgrade accepts post-101 client preface" {
    const server_port = harness.getPort();

    var server = try TerminatedH2AcceptLoopServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UpgradeViaMainServerWithPreface",
        .expected_request_payload = "ping-upgrade-preface",
        .response_payload = "pong-upgrade-preface",
    });
    defer server.stop();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest(
        "/grpc.test.Echo/UpgradeViaMainServerWithPreface",
        authority,
        "ping-upgrade-preface",
        &request_buf,
    );

    const request_headers_end = std.mem.indexOf(u8, request, "\r\n\r\n").? + 4;
    try sendAllTcp(sock, request[0..request_headers_end]);
    posix.nanosleep(0, 10 * std.time.ns_per_ms);
    try sendAllTcp(sock, request[request_headers_end..]);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
    try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
    try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

    try sendH2ClientPrefaceAndSettings(sock);

    const response_headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[response_headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_server_settings = false;
    var saw_settings_ack = false;
    var saw_headers = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                } else {
                    saw_settings_ack = true;
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-upgrade-preface", grpc_payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_settings_ack);
    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: main server terminated h2c upgrade rejects malformed post-101 preface" {
    const server_port = harness.getPort();

    var server = try TerminatedH2AcceptLoopServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UpgradeViaMainServerMalformedPreface",
        .expected_request_payload = "ping-upgrade-malformed-preface",
        .response_payload = "pong-upgrade-malformed-preface",
    });
    defer server.stop();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest(
        "/grpc.test.Echo/UpgradeViaMainServerMalformedPreface",
        authority,
        "ping-upgrade-malformed-preface",
        &request_buf,
    );

    const request_headers_end = std.mem.indexOf(u8, request, "\r\n\r\n").? + 4;
    try sendAllTcp(sock, request[0..request_headers_end]);
    posix.nanosleep(0, 10 * std.time.ns_per_ms);
    try sendAllTcp(sock, request[request_headers_end..]);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);

    var malformed_preface: [serval_h2.client_connection_preface.len]u8 = undefined;
    @memcpy(malformed_preface[0..], serval_h2.client_connection_preface);
    malformed_preface[10] = 'X';
    try sendAllTcp(sock, malformed_preface[0..]);

    const response_headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[response_headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_goaway = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = readH2Frame(sock, initial, &frame_buf) catch |err| switch (err) {
            error.ConnectionClosed, error.RecvFailed => break,
            else => return err,
        };
        initial = frame_view.remaining;

        if (frame_view.header.frame_type != .goaway) continue;

        const goaway = try serval_h2.parseGoAwayFrame(frame_view.header, frame_view.payload);
        try testing.expectEqual(@as(u32, 0), goaway.last_stream_id);
        try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.protocol_error)), goaway.error_code_raw);
        saw_goaway = true;
        break;
    }

    try testing.expect(saw_goaway);
}

test "integration: main server terminated h2c upgrade rejects DATA before HEADERS on new stream" {
    const server_port = harness.getPort();

    var server = try TerminatedH2AcceptLoopServer.start(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UpgradeViaMainServerInvalidOrdering",
        .expected_request_payload = "ping-upgrade-invalid-order",
        .response_payload = "pong-upgrade-invalid-order",
    });
    defer server.stop();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest(
        "/grpc.test.Echo/UpgradeViaMainServerInvalidOrdering",
        authority,
        "ping-upgrade-invalid-order",
        &request_buf,
    );

    const request_headers_end = std.mem.indexOf(u8, request, "\r\n\r\n").? + 4;
    try sendAllTcp(sock, request[0..request_headers_end]);
    posix.nanosleep(0, 10 * std.time.ns_per_ms);
    try sendAllTcp(sock, request[request_headers_end..]);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);

    var invalid_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const invalid_frames = try buildH2UpgradeDataBeforeHeadersFrames("invalid-post-101-order", true, &invalid_buf);
    try sendAllTcp(sock, invalid_frames);

    const response_headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[response_headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_goaway = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = readH2Frame(sock, initial, &frame_buf) catch |err| switch (err) {
            error.ConnectionClosed, error.RecvFailed => break,
            else => return err,
        };
        initial = frame_view.remaining;

        if (frame_view.header.frame_type != .goaway) continue;

        const goaway = try serval_h2.parseGoAwayFrame(frame_view.header, frame_view.payload);
        try testing.expectEqual(@as(u32, 3), goaway.last_stream_id);
        try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.protocol_error)), goaway.error_code_raw);
        saw_goaway = true;
        break;
    }

    try testing.expect(saw_goaway);
}

test "integration: terminated h2 server rejects DATA before HEADERS" {
    const server_port = harness.getPort();

    const server_thread = try startTerminatedH2Server(.{
        .port = server_port,
        .expected_path = "/grpc.test.Echo/UnusedInvalidOrdering",
        .expected_request_payload = "unused",
        .response_payload = "unused",
    });
    defer server_thread.join();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildH2DataBeforeHeadersRequest("invalid-order", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_server_settings = false;
    var saw_goaway = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = readH2Frame(sock, initial, &frame_buf) catch |err| switch (err) {
            error.ConnectionClosed, error.RecvFailed => break,
            else => return err,
        };
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    // Do not send ACK in this fail-closed path test. The server may
                    // close immediately after GOAWAY and unread inbound bytes can
                    // trigger RST semantics that race with control-frame delivery.
                    saw_server_settings = true;
                }
            },
            .goaway => {
                const goaway = try serval_h2.parseGoAwayFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(@as(u32, 1), goaway.last_stream_id);
                try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.protocol_error)), goaway.error_code_raw);
                saw_goaway = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_goaway);
}

test "integration: terminated h2 server continues after client rst_stream" {
    const server_port = harness.getPort();

    const server_thread = try startTerminatedH2ResetServer(.{
        .port = server_port,
        .reset_path = "/grpc.test.Echo/Reset",
        .next_path = "/grpc.test.Echo/AfterReset",
        .expected_request_payload = "next",
        .response_payload = "after-reset",
    });
    defer server_thread.join();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2ResetThenUnaryRequest(
        "/grpc.test.Echo/Reset",
        "/grpc.test.Echo/AfterReset",
        authority,
        "next",
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_server_settings = false;
    var saw_settings_ack = false;
    var saw_headers = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                } else {
                    saw_settings_ack = true;
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                try testing.expectEqual(@as(u32, 3), frame_view.header.stream_id);
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("after-reset", grpc_payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_settings_ack);
    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: terminated h2 server handles interleaved unary streams" {
    const server_port = harness.getPort();

    const server_thread = try startTerminatedH2MultiServer(.{
        .port = server_port,
        .first_path = "/grpc.test.Echo/InterleavedOne",
        .second_path = "/grpc.test.Echo/InterleavedTwo",
        .first_request_payload = "one",
        .second_request_payload = "two",
        .first_response_payload = "one-reply",
        .second_response_payload = "two-reply",
    });
    defer server_thread.join();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2InterleavedTwoUnaryRequest(
        "/grpc.test.Echo/InterleavedOne",
        "/grpc.test.Echo/InterleavedTwo",
        authority,
        "one",
        "two",
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_server_settings = false;
    var saw_settings_ack = false;
    var saw_data_one = false;
    var saw_data_two = false;
    var saw_trailers_one = false;
    var saw_trailers_two = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                } else {
                    saw_settings_ack = true;
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len > 0 and std.mem.eql(u8, fields[0].name, ":status")) {
                    continue;
                }

                if (frame_view.header.stream_id == 1) {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers_one = true;
                } else if (frame_view.header.stream_id == 3) {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers_two = true;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                if (frame_view.header.stream_id == 1) {
                    try testing.expectEqualStrings("one-reply", grpc_payload);
                    saw_data_one = true;
                } else if (frame_view.header.stream_id == 3) {
                    try testing.expectEqualStrings("two-reply", grpc_payload);
                    saw_data_two = true;
                }
            },
            else => {},
        }

        if (saw_data_one and saw_data_two and saw_trailers_one and saw_trailers_two) break;
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_settings_ack);
    try testing.expect(saw_data_one);
    try testing.expect(saw_data_two);
    try testing.expect(saw_trailers_one);
    try testing.expect(saw_trailers_two);
}

test "integration: terminated h2 server replenishes flow-control windows for multi-frame request" {
    const server_port = harness.getPort();
    const expected_total_bytes: usize =
        @as(usize, @intCast(H2_FLOW_CONTROL_CHUNK_SIZE_BYTES)) *
        @as(usize, @intCast(H2_FLOW_CONTROL_CHUNK_COUNT));

    const server_thread = try startTerminatedH2FlowControlServer(.{
        .port = server_port,
        .path = "/grpc.test.Echo/FlowControl",
        .expected_total_bytes = expected_total_bytes,
    });
    defer server_thread.join();

    const sock = try connectTcp(server_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{server_port});
    var request_buf: [H2_FLOW_CONTROL_REQUEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildH2FlowControlRequest("/grpc.test.Echo/FlowControl", authority, &request_buf);
    try sendAllTcp(sock, request);

    var expected_body_buf: [64]u8 = undefined;
    const expected_body = try std.fmt.bufPrint(&expected_body_buf, "received={d}", .{expected_total_bytes});

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_server_settings = false;
    var saw_settings_ack = false;
    var saw_window_update = false;
    var saw_response_headers = false;
    var saw_response_data = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 16) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAck(sock);
                } else {
                    saw_settings_ack = true;
                }
            },
            .window_update => {
                saw_window_update = true;
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len == 0) return error.InvalidFrame;
                try testing.expectEqualStrings(":status", fields[0].name);
                try testing.expectEqualStrings("200", fields[0].value);
                saw_response_headers = true;
            },
            .data => {
                try testing.expectEqual(@as(u32, 1), frame_view.header.stream_id);
                try testing.expectEqualStrings(expected_body, frame_view.payload);
                saw_response_data = true;
                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            else => {},
        }

        if (saw_response_headers and saw_response_data and saw_window_update) break;
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_settings_ack);
    try testing.expect(saw_window_update);
    try testing.expect(saw_response_headers);
    try testing.expect(saw_response_data);
}

test "integration: TLS ALPN h2 generic frontend sends SETTINGS first and forwards non-gRPC route" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "h2-generic-backend", .{});

    var proxy = try GrpcH2ProxyServer.startWithFrontendOptions(
        proxy_port,
        .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 0,
            .http_protocol = .h1,
        },
        false,
        true,
        .generic,
        .prefer_h2,
    );
    defer proxy.stop();

    var socket = try connectTcpTls(proxy_port, "h2");
    defer socket.close();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2GetRequest("/h2-generic", authority, "https", &request_buf);
    try sendAllSocket(&socket, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var body_buf: [2048]u8 = undefined;
    var body_len: usize = 0;

    var first_frame_checked = false;
    var saw_server_settings = false;
    var saw_response_headers = false;
    var saw_response_data = false;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2FrameSocket(&socket, initial, &frame_buf);
        initial = frame_view.remaining;

        if (!first_frame_checked) {
            first_frame_checked = true;
            try testing.expectEqual(serval_h2.FrameType.settings, frame_view.header.frame_type);
            try testing.expect((frame_view.header.flags & serval_h2.flags_ack) == 0);
            saw_server_settings = true;
            try sendH2SettingsAckSocket(&socket);
            continue;
        }

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAckSocket(&socket);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len == 0) return error.InvalidFrame;
                try testing.expectEqualStrings(":status", fields[0].name);
                try testing.expectEqualStrings("200", fields[0].value);
                saw_response_headers = true;

                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            .data => {
                saw_response_data = true;
                if (body_len + frame_view.payload.len > body_buf.len) return error.BufferTooSmall;
                @memcpy(body_buf[body_len..][0..frame_view.payload.len], frame_view.payload);
                body_len += frame_view.payload.len;

                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            else => {},
        }

        if (saw_response_headers and saw_response_data) {
            const body = body_buf[0..body_len];
            if (std.mem.indexOf(u8, body, "/h2-generic") != null) break;
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_response_headers);
    try testing.expect(saw_response_data);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "/h2-generic") != null);
}

test "integration: TLS ALPN h2 generic frontend forwards non-gRPC route to h2c upstream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGenericH2Backend(.{
        .port = backend_port,
        .path = "/h2-generic-upstream-h2c",
        .response_payload = "generic-h2-upstream-h2c-response",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.startWithFrontendOptions(
        proxy_port,
        .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 0,
            .http_protocol = .h2c,
        },
        false,
        true,
        .generic,
        .prefer_h2,
    );
    defer proxy.stop();

    var socket = try connectTcpTls(proxy_port, "h2");
    defer socket.close();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2GetRequest("/h2-generic-upstream-h2c", authority, "https", &request_buf);
    try sendAllSocket(&socket, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_response_headers = false;
    var saw_response_data = false;
    var body_buf: [2048]u8 = undefined;
    var body_len: usize = 0;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2FrameSocket(&socket, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAckSocket(&socket);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len == 0) return error.InvalidFrame;
                try testing.expectEqualStrings(":status", fields[0].name);
                try testing.expectEqualStrings("200", fields[0].value);
                saw_response_headers = true;
                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            .data => {
                saw_response_data = true;
                if (body_len + frame_view.payload.len > body_buf.len) return error.BufferTooSmall;
                @memcpy(body_buf[body_len..][0..frame_view.payload.len], frame_view.payload);
                body_len += frame_view.payload.len;
                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            .rst_stream => return error.UnexpectedReset,
            else => {},
        }

        if (saw_response_headers and saw_response_data) {
            if (std.mem.indexOf(u8, body_buf[0..body_len], "generic-h2-upstream-h2c-response") != null) break;
        }
    }

    try testing.expect(saw_response_headers);
    try testing.expect(saw_response_data);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "generic-h2-upstream-h2c-response") != null);
}

test "integration: TLS ALPN h2 generic frontend resets stream on invalid TE value for non-gRPC route" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "h2-generic-invalid-te-backend", .{});

    var proxy = try GrpcH2ProxyServer.startWithFrontendOptions(
        proxy_port,
        .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 0,
            .http_protocol = .h1,
        },
        false,
        true,
        .generic,
        .prefer_h2,
    );
    defer proxy.stop();

    var socket = try connectTcpTls(proxy_port, "h2");
    defer socket.close();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2GetRequestWithInvalidTe("/h2-invalid-te", authority, "https", &request_buf);
    try sendAllSocket(&socket, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_rst_stream = false;
    var rst_error_code_raw: u32 = 0;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2FrameSocket(&socket, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAckSocket(&socket);
                }
            },
            .rst_stream => {
                rst_error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                saw_rst_stream = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_rst_stream);
    try testing.expectEqual(@intFromEnum(serval_h2.ErrorCode.protocol_error), rst_error_code_raw);
}

test "integration: TLS ALPN h2 generic frontend forwards POST body for non-gRPC route" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "h2-generic-post-backend", .{});

    var proxy = try GrpcH2ProxyServer.startWithFrontendOptions(
        proxy_port,
        .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 0,
            .http_protocol = .h1,
        },
        false,
        true,
        .generic,
        .prefer_h2,
    );
    defer proxy.stop();

    var socket = try connectTcpTls(proxy_port, "h2");
    defer socket.close();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    const request_body = "generic-h2-post-body";
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2PostRequest("/h2-generic-post", authority, "https", request_body, &request_buf);
    try sendAllSocket(&socket, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var body_buf: [4096]u8 = undefined;
    var body_len: usize = 0;

    var saw_server_settings = false;
    var saw_response_headers = false;
    var saw_response_data = false;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2FrameSocket(&socket, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAckSocket(&socket);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len == 0) return error.InvalidFrame;
                try testing.expectEqualStrings(":status", fields[0].name);
                try testing.expectEqualStrings("200", fields[0].value);
                saw_response_headers = true;

                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            .data => {
                saw_response_data = true;
                if (body_len + frame_view.payload.len > body_buf.len) return error.BufferTooSmall;
                @memcpy(body_buf[body_len..][0..frame_view.payload.len], frame_view.payload);
                body_len += frame_view.payload.len;

                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            else => {},
        }

        if (saw_response_headers and saw_response_data) {
            const body = body_buf[0..body_len];
            if (std.mem.indexOf(u8, body, "Path: /h2-generic-post") != null) break;
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_response_headers);
    try testing.expect(saw_response_data);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "Method: POST") != null);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "Path: /h2-generic-post") != null);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "Content-Length: 20") != null or std.mem.indexOf(u8, body_buf[0..body_len], "content-length: 20") != null);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "Transfer-Encoding:") == null);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "transfer-encoding:") == null);
}

test "integration: TLS ALPN h2 generic frontend forwards POST body without content-length for non-gRPC route" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "h2-generic-post-no-cl-backend", .{});

    var proxy = try GrpcH2ProxyServer.startWithFrontendOptions(
        proxy_port,
        .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 0,
            .http_protocol = .h1,
        },
        false,
        true,
        .generic,
        .prefer_h2,
    );
    defer proxy.stop();

    var socket = try connectTcpTls(proxy_port, "h2");
    defer socket.close();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    const request_body_part1 = "generic-h2-post-";
    const request_body_part2 = "without-content-length";

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2PostRequestWithoutContentLength(
        "/h2-generic-post-no-cl",
        authority,
        "https",
        request_body_part1,
        request_body_part2,
        &request_buf,
    );
    try sendAllSocket(&socket, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var body_buf: [4096]u8 = undefined;
    var body_len: usize = 0;

    var saw_server_settings = false;
    var saw_response_headers = false;
    var saw_response_data = false;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2FrameSocket(&socket, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    saw_server_settings = true;
                    try sendH2SettingsAckSocket(&socket);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len == 0) return error.InvalidFrame;
                try testing.expectEqualStrings(":status", fields[0].name);
                try testing.expectEqualStrings("200", fields[0].value);
                saw_response_headers = true;

                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            .data => {
                saw_response_data = true;
                if (body_len + frame_view.payload.len > body_buf.len) return error.BufferTooSmall;
                @memcpy(body_buf[body_len..][0..frame_view.payload.len], frame_view.payload);
                body_len += frame_view.payload.len;

                if ((frame_view.header.flags & serval_h2.flags_end_stream) != 0) break;
            },
            else => {},
        }

        if (saw_response_headers and saw_response_data) {
            const body = body_buf[0..body_len];
            if (std.mem.indexOf(u8, body, "Path: /h2-generic-post-no-cl") != null) break;
        }
    }

    try testing.expect(saw_server_settings);
    try testing.expect(saw_response_headers);
    try testing.expect(saw_response_data);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "Method: POST") != null);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "Path: /h2-generic-post-no-cl") != null);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "Transfer-Encoding: chunked") != null or std.mem.indexOf(u8, body_buf[0..body_len], "transfer-encoding: chunked") != null);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "Content-Length:") == null);
    try testing.expect(std.mem.indexOf(u8, body_buf[0..body_len], "content-length:") == null);
}

test "integration: TLS ALPN h2 generic frontend resets stream on request trailers for non-gRPC route" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    try pm.startEchoBackend(backend_port, "h2-generic-post-trailers-backend", .{});

    var proxy = try GrpcH2ProxyServer.startWithFrontendOptions(
        proxy_port,
        .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 0,
            .http_protocol = .h1,
        },
        false,
        true,
        .generic,
        .prefer_h2,
    );
    defer proxy.stop();

    var socket = try connectTcpTls(proxy_port, "h2");
    defer socket.close();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    const request_body = "h2-body-before-trailers";
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2PostRequestWithTrailers(
        "/h2-generic-post-trailers",
        authority,
        "https",
        request_body,
        &request_buf,
    );
    try sendAllSocket(&socket, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_rst_stream = false;
    var rst_error_code_raw: u32 = 0;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2FrameSocket(&socket, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAckSocket(&socket);
                }
            },
            .rst_stream => {
                rst_error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                saw_rst_stream = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_rst_stream);
    try testing.expectEqual(@intFromEnum(serval_h2.ErrorCode.protocol_error), rst_error_code_raw);
}

test "integration: h2c bridge forwards non-gRPC response trailers without grpc-status" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGenericH2Backend(.{
        .port = backend_port,
        .path = "/h2-bridge-generic-trailers",
        .response_payload = "bridge-generic-trailer-body",
        .send_response_trailers = true,
        .response_trailer_name = "x-upstream-trailer",
        .response_trailer_value = "generic-ok",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2GetRequest("/h2-bridge-generic-trailers", authority, "http", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var headers_seen: u8 = 0;
    var saw_data = false;
    var saw_trailers = false;
    var saw_rst_stream = false;
    var response_body_buf: [256]u8 = undefined;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                headers_seen += 1;

                if (headers_seen == 1) {
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                    try testing.expect((frame_view.header.flags & serval_h2.flags_end_stream) == 0);
                    continue;
                }

                const trailer_value = findH2FieldValue(fields, "x-upstream-trailer") orelse return error.MissingExpectedTrailer;
                try testing.expectEqualStrings("generic-ok", trailer_value);
                try testing.expect(findH2FieldValue(fields, "grpc-status") == null);
                try testing.expect((frame_view.header.flags & serval_h2.flags_end_stream) != 0);
                saw_trailers = true;
                break;
            },
            .data => {
                try testing.expect(!saw_data);
                saw_data = true;
                try testing.expectEqualStrings("bridge-generic-trailer-body", frame_view.payload);
                try testing.expect((frame_view.header.flags & serval_h2.flags_end_stream) == 0);
                @memcpy(response_body_buf[0..frame_view.payload.len], frame_view.payload);
            },
            .rst_stream => {
                saw_rst_stream = true;
                break;
            },
            else => {},
        }

        if (saw_trailers) break;
    }

    try testing.expectEqual(@as(u8, 2), headers_seen);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
    try testing.expect(!saw_rst_stream);
}

test "integration: h2c bridge accepts non-gRPC headers-only end-stream response" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGenericH2Backend(.{
        .port = backend_port,
        .path = "/h2-bridge-generic-headers-only",
        .response_status = "204",
        .response_content_type = null,
        .response_payload = null,
        .headers_end_stream = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2GetRequest("/h2-bridge-generic-headers-only", authority, "http", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_response_headers = false;
    var saw_response_data = false;
    var saw_trailers = false;
    var saw_rst_stream = false;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_response_headers) {
                    saw_response_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("204", fields[0].value);
                    try testing.expect((frame_view.header.flags & serval_h2.flags_end_stream) != 0);
                    break;
                }
                saw_trailers = true;
            },
            .data => saw_response_data = true,
            .rst_stream => {
                saw_rst_stream = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_response_headers);
    try testing.expect(!saw_response_data);
    try testing.expect(!saw_trailers);
    try testing.expect(!saw_rst_stream);
}

test "integration: h2c bridge prior-knowledge resets non-gRPC request trailers with protocol error" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startMinimalH2BridgeBackend(.{ .port = backend_port });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildSimpleH2PostRequestWithTrailers(
        "/h2-bridge-prior-nongrpc-trailers",
        authority,
        "http",
        "bridge-trailer-body",
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_rst_stream = false;
    var rst_error_code_raw: u32 = 0;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .rst_stream => {
                if (frame_view.header.stream_id != 1) continue;
                rst_error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                saw_rst_stream = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_rst_stream);
    try testing.expectEqual(@intFromEnum(serval_h2.ErrorCode.protocol_error), rst_error_code_raw);
}

test "integration: h2c bridge upgrade resets non-gRPC request trailers on additional stream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startMinimalH2BridgeBackend(.{ .port = backend_port });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var upgrade_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const upgrade_request = try buildTextH2UpgradeRequest(
        "/h2-bridge-upgrade-nongrpc-trailers",
        authority,
        "",
        &upgrade_request_buf,
    );
    try sendAllTcp(sock, upgrade_request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);

    var stream3_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const stream3_frames = try buildSimpleH2PostStreamWithTrailersFrames(
        "/h2-bridge-upgrade-nongrpc-trailers",
        authority,
        "http",
        "stream-three-body",
        3,
        &stream3_buf,
    );
    try sendAllTcp(sock, stream3_frames);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_rst_stream = false;
    var rst_error_code_raw: u32 = 0;

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .rst_stream => {
                if (frame_view.header.stream_id != 3) continue;
                rst_error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                saw_rst_stream = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_rst_stream);
    try testing.expectEqual(@intFromEnum(serval_h2.ErrorCode.protocol_error), rst_error_code_raw);
}

test "integration: grpc h2 prior-knowledge unary request is proxied to tls h2 upstream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/UnaryTlsUpstream",
        .mode = .unary,
        .first_response = "pong-tls-upstream",
        .tls = true,
        .drain_request_until_end_stream = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.startWithOptions(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .tls = true,
        .http_protocol = .h2,
    }, true);
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/UnaryTlsUpstream", authority, "ping-tls-upstream", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_headers = false;
    var saw_trailers = false;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expect(std.mem.eql(u8, fields[0].name, ":status"));
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-tls-upstream", payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: grpc h2c unary request is proxied end-to-end" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Unary",
        .mode = .unary,
        .first_response = "pong",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/Unary", authority, "ping", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_headers = false;
    var saw_trailers = false;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expect(std.mem.eql(u8, fields[0].name, ":status"));
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong", payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: grpc h2c accepts grpc-go and grpcurl style request metadata" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/GrpcurlHeaders",
        .mode = .unary,
        .first_response = "pong-grpcurl",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2RequestWithExtraHeaders(
        "/grpc.test.Echo/GrpcurlHeaders",
        authority,
        "ping",
        &.{
            .{ .name = "user-agent", .value = "grpc-go/1.64.0" },
            .{ .name = "grpc-timeout", .value = "1S" },
            .{ .name = "grpc-accept-encoding", .value = "identity,deflate,gzip" },
            .{ .name = "grpc-encoding", .value = "identity" },
            .{ .name = "x-grpc-test", .value = "grpcurl" },
        },
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-grpcurl", payload);
                saw_data = true;
            },
            else => {},
        }

        if (saw_headers and saw_data and saw_trailers) break;
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
}

test "integration: grpcurl plaintext unary interop against grpc h2c proxy" {
    const allocator = testing.allocator;

    const grpcurl_help = try runCommandWithOutput(allocator, &.{ "grpcurl", "-help" });
    defer allocator.free(grpcurl_help);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Unary",
        .mode = .unary,
        .first_response = "\x0a\x0cpong-grpcurl",
    });
    var backend_request_completed = false;
    defer {
        if (!backend_request_completed) {
            const wake_sock = connectTcp(backend_port) catch null;
            if (wake_sock) |sock| posix.close(sock);
        }
        backend_thread.join();
    }

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const proto_name = try std.fmt.allocPrint(allocator, "serval_grpcurl_{d}_{d}.proto", .{ proxy_port, backend_port });
    defer allocator.free(proto_name);
    const proto_path = try std.fmt.allocPrint(allocator, "/tmp/{s}", .{proto_name});
    defer allocator.free(proto_path);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = proto_path,
        .data = "syntax = \"proto3\";\n" ++
            "package grpc.test;\n" ++
            "service Echo { rpc Unary (EchoRequest) returns (EchoResponse); }\n" ++
            "message EchoRequest { string message = 1; }\n" ++
            "message EchoResponse { string message = 1; }\n",
    });
    defer {
        std.Io.Dir.deleteFileAbsolute(io, proto_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => @panic("failed to clean up grpcurl proto file"),
        };
    }

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const output = try runCommandWithOutput(
        allocator,
        &.{
            "grpcurl",
            "-plaintext",
            "-max-time",
            "5",
            "-import-path",
            "/tmp",
            "-proto",
            proto_name,
            "-d",
            "{\"message\":\"ping\"}",
            target,
            "grpc.test.Echo/Unary",
        },
    );
    defer allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "pong-grpcurl") != null);
    backend_request_completed = true;
}

test "integration: grpcurl tls unary interop against grpc h2 proxy" {
    const allocator = testing.allocator;

    const grpcurl_help = try runCommandWithOutput(allocator, &.{ "grpcurl", "-help" });
    defer allocator.free(grpcurl_help);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Unary",
        .mode = .unary,
        .first_response = "\x0a\x10pong-grpcurl-tls",
    });
    var backend_request_completed = false;
    defer {
        if (!backend_request_completed) {
            const wake_sock = connectTcp(backend_port) catch null;
            if (wake_sock) |sock| posix.close(sock);
        }
        backend_thread.join();
    }

    var proxy = try GrpcH2ProxyServer.startWithTlsOptions(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    }, false, true);
    defer proxy.stop();

    const proto_name = try std.fmt.allocPrint(allocator, "serval_grpcurl_tls_{d}_{d}.proto", .{ proxy_port, backend_port });
    defer allocator.free(proto_name);
    const proto_path = try std.fmt.allocPrint(allocator, "/tmp/{s}", .{proto_name});
    defer allocator.free(proto_path);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = proto_path,
        .data = "syntax = \"proto3\";\n" ++
            "package grpc.test;\n" ++
            "service Echo { rpc Unary (EchoRequest) returns (EchoResponse); }\n" ++
            "message EchoRequest { string message = 1; }\n" ++
            "message EchoResponse { string message = 1; }\n",
    });
    defer {
        std.Io.Dir.deleteFileAbsolute(io, proto_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => @panic("failed to clean up grpcurl tls proto file"),
        };
    }

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const output = try runCommandWithOutput(
        allocator,
        &.{
            "grpcurl",
            "-insecure",
            "-max-time",
            "5",
            "-import-path",
            "/tmp",
            "-proto",
            proto_name,
            "-d",
            "{\"message\":\"ping\"}",
            target,
            "grpc.test.Echo/Unary",
        },
    );
    defer allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "pong-grpcurl-tls") != null);
    backend_request_completed = true;
}

test "integration: grpcurl plaintext unary interop asserts metadata and trailers against grpc h2c proxy" {
    const allocator = testing.allocator;

    const grpcurl_help = try runCommandWithOutput(allocator, &.{ "grpcurl", "-help" });
    defer allocator.free(grpcurl_help);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Unary",
        .mode = .unary,
        .first_response = "\x0a\x0cpong-grpcurl",
        .expected_request_header_name = "x-serval-request-md",
        .expected_request_header_value = "client-md-value",
        .response_header_name = "x-serval-response-md",
        .response_header_value = "header-md-value",
        .response_trailer_name = "x-serval-response-trailer",
        .response_trailer_value = "trailer-md-value",
    });
    var backend_request_completed = false;
    defer {
        if (!backend_request_completed) {
            const wake_sock = connectTcp(backend_port) catch null;
            if (wake_sock) |sock| posix.close(sock);
        }
        backend_thread.join();
    }

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const proto_name = try std.fmt.allocPrint(allocator, "serval_grpcurl_meta_{d}_{d}.proto", .{ proxy_port, backend_port });
    defer allocator.free(proto_name);
    const proto_path = try std.fmt.allocPrint(allocator, "/tmp/{s}", .{proto_name});
    defer allocator.free(proto_path);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = proto_path,
        .data = "syntax = \"proto3\";\n" ++
            "package grpc.test;\n" ++
            "service Echo { rpc Unary (EchoRequest) returns (EchoResponse); }\n" ++
            "message EchoRequest { string message = 1; }\n" ++
            "message EchoResponse { string message = 1; }\n",
    });
    defer {
        std.Io.Dir.deleteFileAbsolute(io, proto_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => @panic("failed to clean up grpcurl metadata proto file"),
        };
    }

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const output = try runCommandWithOutput(
        allocator,
        &.{
            "grpcurl",
            "-plaintext",
            "-v",
            "-max-time",
            "5",
            "-H",
            "x-serval-request-md: client-md-value",
            "-import-path",
            "/tmp",
            "-proto",
            proto_name,
            "-d",
            "{\"message\":\"ping\"}",
            target,
            "grpc.test.Echo/Unary",
        },
    );
    defer allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "pong-grpcurl") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Request metadata to send:") != null);
    try testing.expect(std.mem.indexOf(u8, output, "x-serval-request-md: client-md-value") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Response headers received:") != null);
    try testing.expect(std.mem.indexOf(u8, output, "x-serval-response-md: header-md-value") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Response trailers received:") != null);
    try testing.expect(std.mem.indexOf(u8, output, "x-serval-response-trailer: trailer-md-value") != null);
    backend_request_completed = true;
}

test "integration: grpcurl plaintext unary metadata/trailer churn loop against grpc h2c proxy" {
    const allocator = testing.allocator;

    const grpcurl_help = try runCommandWithOutput(allocator, &.{ "grpcurl", "-help" });
    defer allocator.free(grpcurl_help);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const proto_name = try std.fmt.allocPrint(allocator, "serval_grpcurl_meta_loop_{d}_{d}.proto", .{ proxy_port, backend_port });
    defer allocator.free(proto_name);
    const proto_path = try std.fmt.allocPrint(allocator, "/tmp/{s}", .{proto_name});
    defer allocator.free(proto_path);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = proto_path,
        .data = "syntax = \"proto3\";\n" ++
            "package grpc.test;\n" ++
            "service Echo { rpc Unary (EchoRequest) returns (EchoResponse); }\n" ++
            "message EchoRequest { string message = 1; }\n" ++
            "message EchoResponse { string message = 1; }\n",
    });
    defer {
        std.Io.Dir.deleteFileAbsolute(io, proto_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => @panic("failed to clean up grpcurl loop proto file"),
        };
    }

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const iteration_limit: u8 = 5;
    var iteration: u8 = 0;
    while (iteration < iteration_limit) : (iteration += 1) {
        var request_md_buf: [32]u8 = undefined;
        const request_md_value = try std.fmt.bufPrint(&request_md_buf, "client-md-{d}", .{iteration});

        var response_header_value_buf: [32]u8 = undefined;
        const response_header_value = try std.fmt.bufPrint(&response_header_value_buf, "header-md-{d}", .{iteration});

        var response_trailer_value_buf: [32]u8 = undefined;
        const response_trailer_value = try std.fmt.bufPrint(&response_trailer_value_buf, "trailer-md-{d}", .{iteration});

        var request_header_arg_buf: [96]u8 = undefined;
        const request_header_arg = try std.fmt.bufPrint(&request_header_arg_buf, "x-serval-request-md: {s}", .{request_md_value});

        const backend_thread = try startGrpcH2Backend(.{
            .port = backend_port,
            .path = "/grpc.test.Echo/Unary",
            .mode = .unary,
            .first_response = "\x0a\x0cpong-grpcurl",
            .expected_request_header_name = "x-serval-request-md",
            .expected_request_header_value = request_md_value,
            .response_header_name = "x-serval-response-md",
            .response_header_value = response_header_value,
            .response_trailer_name = "x-serval-response-trailer",
            .response_trailer_value = response_trailer_value,
        });

        var backend_request_completed = false;
        defer {
            if (!backend_request_completed) {
                const wake_sock = connectTcp(backend_port) catch null;
                if (wake_sock) |sock| posix.close(sock);
            }
            backend_thread.join();
        }

        const output = try runCommandWithOutput(
            allocator,
            &.{
                "grpcurl",
                "-plaintext",
                "-v",
                "-max-time",
                "5",
                "-H",
                request_header_arg,
                "-import-path",
                "/tmp",
                "-proto",
                proto_name,
                "-d",
                "{\"message\":\"ping\"}",
                target,
                "grpc.test.Echo/Unary",
            },
        );
        defer allocator.free(output);

        try testing.expect(std.mem.indexOf(u8, output, "pong-grpcurl") != null);
        try testing.expect(std.mem.indexOf(u8, output, "Request metadata to send:") != null);
        try testing.expect(std.mem.indexOf(u8, output, request_header_arg) != null);
        try testing.expect(std.mem.indexOf(u8, output, "Response headers received:") != null);
        try testing.expect(std.mem.indexOf(u8, output, "x-serval-response-md") != null);
        try testing.expect(std.mem.indexOf(u8, output, response_header_value) != null);
        try testing.expect(std.mem.indexOf(u8, output, "Response trailers received:") != null);
        try testing.expect(std.mem.indexOf(u8, output, "x-serval-response-trailer") != null);
        try testing.expect(std.mem.indexOf(u8, output, response_trailer_value) != null);

        backend_request_completed = true;
    }

    try testing.expectEqual(iteration_limit, iteration);
}

test "integration: grpc-go plaintext unary interop against grpc h2c proxy" {
    const allocator = testing.allocator;

    const go_version = try runCommandWithOutput(allocator, &.{ "go", "version" });
    defer allocator.free(go_version);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Unary",
        .mode = .unary,
        .first_response = "\x0a\x0cpong-grpc-go",
    });
    var backend_request_completed = false;
    defer {
        if (!backend_request_completed) {
            const wake_sock = connectTcp(backend_port) catch null;
            if (wake_sock) |sock| posix.close(sock);
        }
        backend_thread.join();
    }

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const grpc_go_dir = try std.fmt.allocPrint(allocator, "/tmp/serval_grpcgo_{d}_{d}", .{ proxy_port, backend_port });
    defer allocator.free(grpc_go_dir);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    std.Io.Dir.createDirAbsolute(io, grpc_go_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer {
        std.Io.Dir.deleteTree(std.Io.Dir.cwd(), io, grpc_go_dir) catch {
            @panic("failed to clean up grpc-go temp dir");
        };
    }

    const go_mod_path = try std.fmt.allocPrint(allocator, "{s}/go.mod", .{grpc_go_dir});
    defer allocator.free(go_mod_path);
    const go_main_path = try std.fmt.allocPrint(allocator, "{s}/main.go", .{grpc_go_dir});
    defer allocator.free(go_main_path);

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_mod_path,
        .data = "module example.com/serval-grpcgo-interop\n" ++
            "\n" ++
            "go 1.23\n" ++
            "\n" ++
            "require (\n" ++
            "\tgoogle.golang.org/grpc v1.76.0\n" ++
            "\tgoogle.golang.org/protobuf v1.36.10\n" ++
            ")\n",
    });

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_main_path,
        .data = "package main\n" ++
            "\n" ++
            "import (\n" ++
            "\t\"context\"\n" ++
            "\t\"fmt\"\n" ++
            "\t\"os\"\n" ++
            "\t\"time\"\n" ++
            "\n" ++
            "\t\"google.golang.org/grpc\"\n" ++
            "\t\"google.golang.org/grpc/credentials/insecure\"\n" ++
            "\t\"google.golang.org/protobuf/types/known/emptypb\"\n" ++
            ")\n" ++
            "\n" ++
            "func main() {\n" ++
            "\tif len(os.Args) != 2 {\n" ++
            "\t\tfmt.Fprintln(os.Stderr, \"usage: main <target>\")\n" ++
            "\t\tos.Exit(2)\n" ++
            "\t}\n" ++
            "\ttarget := os.Args[1]\n" ++
            "\n" ++
            "\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n" ++
            "\tdefer cancel()\n" ++
            "\n" ++
            "\tconn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"dial failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tdefer conn.Close()\n" ++
            "\n" ++
            "\tif err := conn.Invoke(ctx, \"/grpc.test.Echo/Unary\", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"invoke failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tfmt.Println(\"grpc-go-ok\")\n" ++
            "}\n",
    });

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const output = try runCommandWithOutput(
        allocator,
        &.{
            "go",
            "run",
            "-C",
            grpc_go_dir,
            "-mod=mod",
            ".",
            target,
        },
    );
    defer allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "grpc-go-ok") != null);
    backend_request_completed = true;
}

test "integration: grpc-go tls unary interop against grpc h2 proxy" {
    const allocator = testing.allocator;

    const go_version = try runCommandWithOutput(allocator, &.{ "go", "version" });
    defer allocator.free(go_version);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/UnaryTlsFrontend",
        .mode = .unary,
        .first_response = "\x0a\x10pong-grpc-go-tls",
    });
    var backend_request_completed = false;
    defer {
        if (!backend_request_completed) {
            const wake_sock = connectTcp(backend_port) catch null;
            if (wake_sock) |sock| posix.close(sock);
        }
        backend_thread.join();
    }

    var proxy = try GrpcH2ProxyServer.startWithTlsOptions(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    }, false, true);
    defer proxy.stop();

    const grpc_go_dir = try std.fmt.allocPrint(allocator, "/tmp/serval_grpcgo_tls_{d}_{d}", .{ proxy_port, backend_port });
    defer allocator.free(grpc_go_dir);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    std.Io.Dir.createDirAbsolute(io, grpc_go_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer {
        std.Io.Dir.deleteTree(std.Io.Dir.cwd(), io, grpc_go_dir) catch {
            @panic("failed to clean up grpc-go tls temp dir");
        };
    }

    const go_mod_path = try std.fmt.allocPrint(allocator, "{s}/go.mod", .{grpc_go_dir});
    defer allocator.free(go_mod_path);
    const go_main_path = try std.fmt.allocPrint(allocator, "{s}/main.go", .{grpc_go_dir});
    defer allocator.free(go_main_path);

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_mod_path,
        .data = "module example.com/serval-grpcgo-tls-interop\n" ++
            "\n" ++
            "go 1.23\n" ++
            "\n" ++
            "require (\n" ++
            "\tgoogle.golang.org/grpc v1.76.0\n" ++
            "\tgoogle.golang.org/protobuf v1.36.10\n" ++
            ")\n",
    });

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_main_path,
        .data = "package main\n" ++
            "\n" ++
            "import (\n" ++
            "\t\"context\"\n" ++
            "\t\"crypto/tls\"\n" ++
            "\t\"fmt\"\n" ++
            "\t\"os\"\n" ++
            "\t\"time\"\n" ++
            "\n" ++
            "\t\"google.golang.org/grpc\"\n" ++
            "\t\"google.golang.org/grpc/credentials\"\n" ++
            "\t\"google.golang.org/protobuf/types/known/emptypb\"\n" ++
            ")\n" ++
            "\n" ++
            "func main() {\n" ++
            "\tif len(os.Args) != 2 {\n" ++
            "\t\tfmt.Fprintln(os.Stderr, \"usage: main <target>\")\n" ++
            "\t\tos.Exit(2)\n" ++
            "\t}\n" ++
            "\ttarget := os.Args[1]\n" ++
            "\n" ++
            "\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n" ++
            "\tdefer cancel()\n" ++
            "\n" ++
            "\tcreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})\n" ++
            "\tconn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(creds), grpc.WithBlock())\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"dial failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tdefer conn.Close()\n" ++
            "\n" ++
            "\tif err := conn.Invoke(ctx, \"/grpc.test.Echo/UnaryTlsFrontend\", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"invoke failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tfmt.Println(\"grpc-go-tls-ok\")\n" ++
            "}\n",
    });

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const output = try runCommandWithOutput(
        allocator,
        &.{
            "go",
            "run",
            "-C",
            grpc_go_dir,
            "-mod=mod",
            ".",
            target,
        },
    );
    defer allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "grpc-go-tls-ok") != null);
    backend_request_completed = true;
}

test "integration: grpc-go plaintext server streaming interop against grpc h2c proxy" {
    const allocator = testing.allocator;

    const go_version = try runCommandWithOutput(allocator, &.{ "go", "version" });
    defer allocator.free(go_version);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/ServerStreaming",
        .mode = .server_streaming,
        .first_response = "",
        .second_response = "",
    });
    var backend_request_completed = false;
    defer {
        if (!backend_request_completed) {
            const wake_sock = connectTcp(backend_port) catch null;
            if (wake_sock) |sock| posix.close(sock);
        }
        backend_thread.join();
    }

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const grpc_go_dir = try std.fmt.allocPrint(allocator, "/tmp/serval_grpcgo_stream_{d}_{d}", .{ proxy_port, backend_port });
    defer allocator.free(grpc_go_dir);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    std.Io.Dir.createDirAbsolute(io, grpc_go_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer {
        std.Io.Dir.deleteTree(std.Io.Dir.cwd(), io, grpc_go_dir) catch {
            @panic("failed to clean up grpc-go streaming temp dir");
        };
    }

    const go_mod_path = try std.fmt.allocPrint(allocator, "{s}/go.mod", .{grpc_go_dir});
    defer allocator.free(go_mod_path);
    const go_main_path = try std.fmt.allocPrint(allocator, "{s}/main.go", .{grpc_go_dir});
    defer allocator.free(go_main_path);

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_mod_path,
        .data = "module example.com/serval-grpcgo-stream-interop\n" ++
            "\n" ++
            "go 1.23\n" ++
            "\n" ++
            "require (\n" ++
            "\tgoogle.golang.org/grpc v1.76.0\n" ++
            "\tgoogle.golang.org/protobuf v1.36.10\n" ++
            ")\n",
    });

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_main_path,
        .data = "package main\n" ++
            "\n" ++
            "import (\n" ++
            "\t\"context\"\n" ++
            "\t\"fmt\"\n" ++
            "\t\"io\"\n" ++
            "\t\"os\"\n" ++
            "\t\"time\"\n" ++
            "\n" ++
            "\t\"google.golang.org/grpc\"\n" ++
            "\t\"google.golang.org/grpc/credentials/insecure\"\n" ++
            "\t\"google.golang.org/protobuf/types/known/emptypb\"\n" ++
            ")\n" ++
            "\n" ++
            "func main() {\n" ++
            "\tif len(os.Args) != 2 {\n" ++
            "\t\tfmt.Fprintln(os.Stderr, \"usage: main <target>\")\n" ++
            "\t\tos.Exit(2)\n" ++
            "\t}\n" ++
            "\ttarget := os.Args[1]\n" ++
            "\n" ++
            "\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n" ++
            "\tdefer cancel()\n" ++
            "\n" ++
            "\tconn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"dial failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tdefer conn.Close()\n" ++
            "\n" ++
            "\tdesc := &grpc.StreamDesc{ServerStreams: true}\n" ++
            "\tstream, err := conn.NewStream(ctx, desc, \"/grpc.test.Echo/ServerStreaming\")\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"new stream failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tif err := stream.SendMsg(&emptypb.Empty{}); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"send failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tif err := stream.CloseSend(); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"close send failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tcount := 0\n" ++
            "\tfor {\n" ++
            "\t\tvar msg emptypb.Empty\n" ++
            "\t\terr := stream.RecvMsg(&msg)\n" ++
            "\t\tif err == io.EOF {\n" ++
            "\t\t\tbreak\n" ++
            "\t\t}\n" ++
            "\t\tif err != nil {\n" ++
            "\t\t\tfmt.Fprintf(os.Stderr, \"recv failed: %v\\n\", err)\n" ++
            "\t\t\tos.Exit(1)\n" ++
            "\t\t}\n" ++
            "\t\tcount++\n" ++
            "\t}\n" ++
            "\n" ++
            "\tif count != 2 {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected message count: %d\\n\", count)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tfmt.Println(\"grpc-go-stream-ok\")\n" ++
            "}\n",
    });

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const output = try runCommandWithOutput(
        allocator,
        &.{
            "go",
            "run",
            "-C",
            grpc_go_dir,
            "-mod=mod",
            ".",
            target,
        },
    );
    defer allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "grpc-go-stream-ok") != null);
    backend_request_completed = true;
}

test "integration: grpc-go plaintext unary interop asserts metadata and trailers against grpc h2c proxy" {
    const allocator = testing.allocator;

    const go_version = try runCommandWithOutput(allocator, &.{ "go", "version" });
    defer allocator.free(go_version);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/UnaryMetadata",
        .mode = .unary,
        .first_response = "",
        .expected_request_header_name = "x-serval-request-md",
        .expected_request_header_value = "client-md-value",
        .response_header_name = "x-serval-response-md",
        .response_header_value = "header-md-value",
        .response_trailer_name = "x-serval-response-trailer",
        .response_trailer_value = "trailer-md-value",
    });
    var backend_request_completed = false;
    defer {
        if (!backend_request_completed) {
            const wake_sock = connectTcp(backend_port) catch null;
            if (wake_sock) |sock| posix.close(sock);
        }
        backend_thread.join();
    }

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const grpc_go_dir = try std.fmt.allocPrint(allocator, "/tmp/serval_grpcgo_meta_{d}_{d}", .{ proxy_port, backend_port });
    defer allocator.free(grpc_go_dir);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    std.Io.Dir.createDirAbsolute(io, grpc_go_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer {
        std.Io.Dir.deleteTree(std.Io.Dir.cwd(), io, grpc_go_dir) catch {
            @panic("failed to clean up grpc-go metadata temp dir");
        };
    }

    const go_mod_path = try std.fmt.allocPrint(allocator, "{s}/go.mod", .{grpc_go_dir});
    defer allocator.free(go_mod_path);
    const go_main_path = try std.fmt.allocPrint(allocator, "{s}/main.go", .{grpc_go_dir});
    defer allocator.free(go_main_path);

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_mod_path,
        .data = "module example.com/serval-grpcgo-metadata-interop\n" ++
            "\n" ++
            "go 1.23\n" ++
            "\n" ++
            "require (\n" ++
            "\tgoogle.golang.org/grpc v1.76.0\n" ++
            "\tgoogle.golang.org/protobuf v1.36.10\n" ++
            ")\n",
    });

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_main_path,
        .data = "package main\n" ++
            "\n" ++
            "import (\n" ++
            "\t\"context\"\n" ++
            "\t\"fmt\"\n" ++
            "\t\"os\"\n" ++
            "\t\"time\"\n" ++
            "\n" ++
            "\t\"google.golang.org/grpc\"\n" ++
            "\t\"google.golang.org/grpc/credentials/insecure\"\n" ++
            "\t\"google.golang.org/grpc/metadata\"\n" ++
            "\t\"google.golang.org/protobuf/types/known/emptypb\"\n" ++
            ")\n" ++
            "\n" ++
            "func main() {\n" ++
            "\tif len(os.Args) != 2 {\n" ++
            "\t\tfmt.Fprintln(os.Stderr, \"usage: main <target>\")\n" ++
            "\t\tos.Exit(2)\n" ++
            "\t}\n" ++
            "\ttarget := os.Args[1]\n" ++
            "\n" ++
            "\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n" ++
            "\tdefer cancel()\n" ++
            "\tctx = metadata.AppendToOutgoingContext(ctx, \"x-serval-request-md\", \"client-md-value\")\n" ++
            "\n" ++
            "\tconn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"dial failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tdefer conn.Close()\n" ++
            "\n" ++
            "\tvar headerMD metadata.MD\n" ++
            "\tvar trailerMD metadata.MD\n" ++
            "\tif err := conn.Invoke(ctx, \"/grpc.test.Echo/UnaryMetadata\", &emptypb.Empty{}, &emptypb.Empty{}, grpc.Header(&headerMD), grpc.Trailer(&trailerMD)); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"invoke failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\theaders := headerMD.Get(\"x-serval-response-md\")\n" ++
            "\tif len(headers) != 1 || headers[0] != \"header-md-value\" {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected header metadata: %v\\n\", headers)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\ttrailers := trailerMD.Get(\"x-serval-response-trailer\")\n" ++
            "\tif len(trailers) != 1 || trailers[0] != \"trailer-md-value\" {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected trailer metadata: %v\\n\", trailers)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tfmt.Println(\"grpc-go-metadata-ok\")\n" ++
            "}\n",
    });

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const output = try runCommandWithOutput(
        allocator,
        &.{
            "go",
            "run",
            "-C",
            grpc_go_dir,
            "-mod=mod",
            ".",
            target,
        },
    );
    defer allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "grpc-go-metadata-ok") != null);
    backend_request_completed = true;
}

test "integration: grpc-go plaintext server streaming interop asserts metadata and trailers" {
    const allocator = testing.allocator;

    const go_version = try runCommandWithOutput(allocator, &.{ "go", "version" });
    defer allocator.free(go_version);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/ServerStreamingMetadata",
        .mode = .server_streaming,
        .first_response = "",
        .second_response = "",
        .expected_request_header_name = "x-serval-stream-request-md",
        .expected_request_header_value = "stream-client-md",
        .response_header_name = "x-serval-stream-response-md",
        .response_header_value = "stream-header-md-value",
        .response_trailer_name = "x-serval-stream-response-trailer",
        .response_trailer_value = "stream-trailer-md-value",
    });
    var backend_request_completed = false;
    defer {
        if (!backend_request_completed) {
            const wake_sock = connectTcp(backend_port) catch null;
            if (wake_sock) |sock| posix.close(sock);
        }
        backend_thread.join();
    }

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const grpc_go_dir = try std.fmt.allocPrint(allocator, "/tmp/serval_grpcgo_stream_meta_{d}_{d}", .{ proxy_port, backend_port });
    defer allocator.free(grpc_go_dir);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    std.Io.Dir.createDirAbsolute(io, grpc_go_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer {
        std.Io.Dir.deleteTree(std.Io.Dir.cwd(), io, grpc_go_dir) catch {
            @panic("failed to clean up grpc-go streaming metadata temp dir");
        };
    }

    const go_mod_path = try std.fmt.allocPrint(allocator, "{s}/go.mod", .{grpc_go_dir});
    defer allocator.free(go_mod_path);
    const go_main_path = try std.fmt.allocPrint(allocator, "{s}/main.go", .{grpc_go_dir});
    defer allocator.free(go_main_path);

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_mod_path,
        .data = "module example.com/serval-grpcgo-stream-metadata-interop\n" ++
            "\n" ++
            "go 1.23\n" ++
            "\n" ++
            "require (\n" ++
            "\tgoogle.golang.org/grpc v1.76.0\n" ++
            "\tgoogle.golang.org/protobuf v1.36.10\n" ++
            ")\n",
    });

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_main_path,
        .data = "package main\n" ++
            "\n" ++
            "import (\n" ++
            "\t\"context\"\n" ++
            "\t\"fmt\"\n" ++
            "\t\"io\"\n" ++
            "\t\"os\"\n" ++
            "\t\"time\"\n" ++
            "\n" ++
            "\t\"google.golang.org/grpc\"\n" ++
            "\t\"google.golang.org/grpc/credentials/insecure\"\n" ++
            "\t\"google.golang.org/grpc/metadata\"\n" ++
            "\t\"google.golang.org/protobuf/types/known/emptypb\"\n" ++
            ")\n" ++
            "\n" ++
            "func main() {\n" ++
            "\tif len(os.Args) != 2 {\n" ++
            "\t\tfmt.Fprintln(os.Stderr, \"usage: main <target>\")\n" ++
            "\t\tos.Exit(2)\n" ++
            "\t}\n" ++
            "\ttarget := os.Args[1]\n" ++
            "\n" ++
            "\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n" ++
            "\tdefer cancel()\n" ++
            "\tctx = metadata.AppendToOutgoingContext(ctx, \"x-serval-stream-request-md\", \"stream-client-md\")\n" ++
            "\n" ++
            "\tconn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"dial failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tdefer conn.Close()\n" ++
            "\n" ++
            "\tdesc := &grpc.StreamDesc{ServerStreams: true}\n" ++
            "\tstream, err := conn.NewStream(ctx, desc, \"/grpc.test.Echo/ServerStreamingMetadata\")\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"new stream failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tif err := stream.SendMsg(&emptypb.Empty{}); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"send failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tif err := stream.CloseSend(); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"close send failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\theaders, err := stream.Header()\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"header failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\theaderVals := headers.Get(\"x-serval-stream-response-md\")\n" ++
            "\tif len(headerVals) != 1 || headerVals[0] != \"stream-header-md-value\" {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected stream header metadata: %v\\n\", headerVals)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tcount := 0\n" ++
            "\tfor {\n" ++
            "\t\tvar msg emptypb.Empty\n" ++
            "\t\terr := stream.RecvMsg(&msg)\n" ++
            "\t\tif err == io.EOF {\n" ++
            "\t\t\tbreak\n" ++
            "\t\t}\n" ++
            "\t\tif err != nil {\n" ++
            "\t\t\tfmt.Fprintf(os.Stderr, \"recv failed: %v\\n\", err)\n" ++
            "\t\t\tos.Exit(1)\n" ++
            "\t\t}\n" ++
            "\t\tcount++\n" ++
            "\t}\n" ++
            "\n" ++
            "\tif count != 2 {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected message count: %d\\n\", count)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\ttrailers := stream.Trailer()\n" ++
            "\ttrailerVals := trailers.Get(\"x-serval-stream-response-trailer\")\n" ++
            "\tif len(trailerVals) != 1 || trailerVals[0] != \"stream-trailer-md-value\" {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected stream trailer metadata: %v\\n\", trailerVals)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tfmt.Println(\"grpc-go-stream-metadata-ok\")\n" ++
            "}\n",
    });

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const output = try runCommandWithOutput(
        allocator,
        &.{
            "go",
            "run",
            "-C",
            grpc_go_dir,
            "-mod=mod",
            ".",
            target,
        },
    );
    defer allocator.free(output);

    try testing.expect(std.mem.indexOf(u8, output, "grpc-go-stream-metadata-ok") != null);
    backend_request_completed = true;
}

test "integration: grpc-go plaintext unary metadata/trailer churn loop against grpc h2c proxy" {
    const allocator = testing.allocator;

    const go_version = try runCommandWithOutput(allocator, &.{ "go", "version" });
    defer allocator.free(go_version);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const grpc_go_dir = try std.fmt.allocPrint(allocator, "/tmp/serval_grpcgo_meta_loop_{d}_{d}", .{ proxy_port, backend_port });
    defer allocator.free(grpc_go_dir);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    std.Io.Dir.createDirAbsolute(io, grpc_go_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer {
        std.Io.Dir.deleteTree(std.Io.Dir.cwd(), io, grpc_go_dir) catch {
            @panic("failed to clean up grpc-go unary loop temp dir");
        };
    }

    const go_mod_path = try std.fmt.allocPrint(allocator, "{s}/go.mod", .{grpc_go_dir});
    defer allocator.free(go_mod_path);
    const go_main_path = try std.fmt.allocPrint(allocator, "{s}/main.go", .{grpc_go_dir});
    defer allocator.free(go_main_path);

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_mod_path,
        .data = "module example.com/serval-grpcgo-metadata-loop-interop\n" ++
            "\n" ++
            "go 1.23\n" ++
            "\n" ++
            "require (\n" ++
            "\tgoogle.golang.org/grpc v1.76.0\n" ++
            "\tgoogle.golang.org/protobuf v1.36.10\n" ++
            ")\n",
    });

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_main_path,
        .data = "package main\n" ++
            "\n" ++
            "import (\n" ++
            "\t\"context\"\n" ++
            "\t\"fmt\"\n" ++
            "\t\"os\"\n" ++
            "\t\"time\"\n" ++
            "\n" ++
            "\t\"google.golang.org/grpc\"\n" ++
            "\t\"google.golang.org/grpc/credentials/insecure\"\n" ++
            "\t\"google.golang.org/grpc/metadata\"\n" ++
            "\t\"google.golang.org/protobuf/types/known/emptypb\"\n" ++
            ")\n" ++
            "\n" ++
            "func main() {\n" ++
            "\tif len(os.Args) != 5 {\n" ++
            "\t\tfmt.Fprintln(os.Stderr, \"usage: main <target> <request-md> <expected-header> <expected-trailer>\")\n" ++
            "\t\tos.Exit(2)\n" ++
            "\t}\n" ++
            "\ttarget := os.Args[1]\n" ++
            "\trequestMD := os.Args[2]\n" ++
            "\texpectedHeader := os.Args[3]\n" ++
            "\texpectedTrailer := os.Args[4]\n" ++
            "\n" ++
            "\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n" ++
            "\tdefer cancel()\n" ++
            "\tctx = metadata.AppendToOutgoingContext(ctx, \"x-serval-request-md\", requestMD)\n" ++
            "\n" ++
            "\tconn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"dial failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tdefer conn.Close()\n" ++
            "\n" ++
            "\tvar headerMD metadata.MD\n" ++
            "\tvar trailerMD metadata.MD\n" ++
            "\tif err := conn.Invoke(ctx, \"/grpc.test.Echo/UnaryMetadata\", &emptypb.Empty{}, &emptypb.Empty{}, grpc.Header(&headerMD), grpc.Trailer(&trailerMD)); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"invoke failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\theaderVals := headerMD.Get(\"x-serval-response-md\")\n" ++
            "\tif len(headerVals) != 1 || headerVals[0] != expectedHeader {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected header metadata: %v\\n\", headerVals)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\ttrailerVals := trailerMD.Get(\"x-serval-response-trailer\")\n" ++
            "\tif len(trailerVals) != 1 || trailerVals[0] != expectedTrailer {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected trailer metadata: %v\\n\", trailerVals)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tfmt.Println(\"grpc-go-meta-loop-ok\")\n" ++
            "}\n",
    });

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const iteration_limit: u8 = 4;
    var iteration: u8 = 0;
    while (iteration < iteration_limit) : (iteration += 1) {
        var request_md_buf: [32]u8 = undefined;
        const request_md_value = try std.fmt.bufPrint(&request_md_buf, "loop-client-md-{d}", .{iteration});

        var response_header_buf: [32]u8 = undefined;
        const response_header_value = try std.fmt.bufPrint(&response_header_buf, "loop-header-md-{d}", .{iteration});

        var response_trailer_buf: [32]u8 = undefined;
        const response_trailer_value = try std.fmt.bufPrint(&response_trailer_buf, "loop-trailer-md-{d}", .{iteration});

        const backend_thread = try startGrpcH2Backend(.{
            .port = backend_port,
            .path = "/grpc.test.Echo/UnaryMetadata",
            .mode = .unary,
            .first_response = "",
            .expected_request_header_name = "x-serval-request-md",
            .expected_request_header_value = request_md_value,
            .response_header_name = "x-serval-response-md",
            .response_header_value = response_header_value,
            .response_trailer_name = "x-serval-response-trailer",
            .response_trailer_value = response_trailer_value,
        });
        var backend_request_completed = false;
        errdefer {
            if (!backend_request_completed) {
                const wake_sock = connectTcp(backend_port) catch null;
                if (wake_sock) |sock| posix.close(sock);
            }
            backend_thread.join();
        }

        const output = try runCommandWithOutput(
            allocator,
            &.{
                "go",
                "run",
                "-C",
                grpc_go_dir,
                "-mod=mod",
                ".",
                target,
                request_md_value,
                response_header_value,
                response_trailer_value,
            },
        );
        defer allocator.free(output);

        try testing.expect(std.mem.indexOf(u8, output, "grpc-go-meta-loop-ok") != null);
        backend_request_completed = true;
        backend_thread.join();
    }

    try testing.expectEqual(iteration_limit, iteration);
}

test "integration: grpc-go plaintext server streaming metadata/trailer churn loop against grpc h2c proxy" {
    const allocator = testing.allocator;

    const go_version = try runCommandWithOutput(allocator, &.{ "go", "version" });
    defer allocator.free(go_version);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const grpc_go_dir = try std.fmt.allocPrint(allocator, "/tmp/serval_grpcgo_stream_meta_loop_{d}_{d}", .{ proxy_port, backend_port });
    defer allocator.free(grpc_go_dir);

    var file_io: std.Io.Evented = undefined;
    try init_test_io_runtime(&file_io, allocator);
    defer file_io.deinit();
    const io = file_io.io();

    std.Io.Dir.createDirAbsolute(io, grpc_go_dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer {
        std.Io.Dir.deleteTree(std.Io.Dir.cwd(), io, grpc_go_dir) catch {
            @panic("failed to clean up grpc-go stream loop temp dir");
        };
    }

    const go_mod_path = try std.fmt.allocPrint(allocator, "{s}/go.mod", .{grpc_go_dir});
    defer allocator.free(go_mod_path);
    const go_main_path = try std.fmt.allocPrint(allocator, "{s}/main.go", .{grpc_go_dir});
    defer allocator.free(go_main_path);

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_mod_path,
        .data = "module example.com/serval-grpcgo-stream-metadata-loop-interop\n" ++
            "\n" ++
            "go 1.23\n" ++
            "\n" ++
            "require (\n" ++
            "\tgoogle.golang.org/grpc v1.76.0\n" ++
            "\tgoogle.golang.org/protobuf v1.36.10\n" ++
            ")\n",
    });

    try std.Io.Dir.writeFile(std.Io.Dir.cwd(), io, .{
        .sub_path = go_main_path,
        .data = "package main\n" ++
            "\n" ++
            "import (\n" ++
            "\t\"context\"\n" ++
            "\t\"fmt\"\n" ++
            "\t\"io\"\n" ++
            "\t\"os\"\n" ++
            "\t\"time\"\n" ++
            "\n" ++
            "\t\"google.golang.org/grpc\"\n" ++
            "\t\"google.golang.org/grpc/credentials/insecure\"\n" ++
            "\t\"google.golang.org/grpc/metadata\"\n" ++
            "\t\"google.golang.org/protobuf/types/known/emptypb\"\n" ++
            ")\n" ++
            "\n" ++
            "func main() {\n" ++
            "\tif len(os.Args) != 5 {\n" ++
            "\t\tfmt.Fprintln(os.Stderr, \"usage: main <target> <request-md> <expected-header> <expected-trailer>\")\n" ++
            "\t\tos.Exit(2)\n" ++
            "\t}\n" ++
            "\ttarget := os.Args[1]\n" ++
            "\trequestMD := os.Args[2]\n" ++
            "\texpectedHeader := os.Args[3]\n" ++
            "\texpectedTrailer := os.Args[4]\n" ++
            "\n" ++
            "\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n" ++
            "\tdefer cancel()\n" ++
            "\tctx = metadata.AppendToOutgoingContext(ctx, \"x-serval-stream-request-md\", requestMD)\n" ++
            "\n" ++
            "\tconn, err := grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"dial failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tdefer conn.Close()\n" ++
            "\n" ++
            "\tdesc := &grpc.StreamDesc{ServerStreams: true}\n" ++
            "\tstream, err := conn.NewStream(ctx, desc, \"/grpc.test.Echo/ServerStreamingMetadata\")\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"new stream failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tif err := stream.SendMsg(&emptypb.Empty{}); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"send failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\tif err := stream.CloseSend(); err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"close send failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\theaders, err := stream.Header()\n" ++
            "\tif err != nil {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"header failed: %v\\n\", err)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\theaderVals := headers.Get(\"x-serval-stream-response-md\")\n" ++
            "\tif len(headerVals) != 1 || headerVals[0] != expectedHeader {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected stream header metadata: %v\\n\", headerVals)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tcount := 0\n" ++
            "\tfor {\n" ++
            "\t\tvar msg emptypb.Empty\n" ++
            "\t\terr := stream.RecvMsg(&msg)\n" ++
            "\t\tif err == io.EOF {\n" ++
            "\t\t\tbreak\n" ++
            "\t\t}\n" ++
            "\t\tif err != nil {\n" ++
            "\t\t\tfmt.Fprintf(os.Stderr, \"recv failed: %v\\n\", err)\n" ++
            "\t\t\tos.Exit(1)\n" ++
            "\t\t}\n" ++
            "\t\tcount++\n" ++
            "\t}\n" ++
            "\n" ++
            "\tif count != 2 {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected message count: %d\\n\", count)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\ttrailers := stream.Trailer()\n" ++
            "\ttrailerVals := trailers.Get(\"x-serval-stream-response-trailer\")\n" ++
            "\tif len(trailerVals) != 1 || trailerVals[0] != expectedTrailer {\n" ++
            "\t\tfmt.Fprintf(os.Stderr, \"unexpected stream trailer metadata: %v\\n\", trailerVals)\n" ++
            "\t\tos.Exit(1)\n" ++
            "\t}\n" ++
            "\n" ++
            "\tfmt.Println(\"grpc-go-stream-meta-loop-ok\")\n" ++
            "}\n",
    });

    var target_buf: [32]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "127.0.0.1:{d}", .{proxy_port});

    const iteration_limit: u8 = 3;
    var iteration: u8 = 0;
    while (iteration < iteration_limit) : (iteration += 1) {
        var request_md_buf: [32]u8 = undefined;
        const request_md_value = try std.fmt.bufPrint(&request_md_buf, "loop-stream-client-md-{d}", .{iteration});

        var response_header_buf: [32]u8 = undefined;
        const response_header_value = try std.fmt.bufPrint(&response_header_buf, "loop-stream-header-{d}", .{iteration});

        var response_trailer_buf: [32]u8 = undefined;
        const response_trailer_value = try std.fmt.bufPrint(&response_trailer_buf, "loop-stream-trailer-{d}", .{iteration});

        const backend_thread = try startGrpcH2Backend(.{
            .port = backend_port,
            .path = "/grpc.test.Echo/ServerStreamingMetadata",
            .mode = .server_streaming,
            .first_response = "",
            .second_response = "",
            .expected_request_header_name = "x-serval-stream-request-md",
            .expected_request_header_value = request_md_value,
            .response_header_name = "x-serval-stream-response-md",
            .response_header_value = response_header_value,
            .response_trailer_name = "x-serval-stream-response-trailer",
            .response_trailer_value = response_trailer_value,
        });
        var backend_request_completed = false;
        errdefer {
            if (!backend_request_completed) {
                const wake_sock = connectTcp(backend_port) catch null;
                if (wake_sock) |sock| posix.close(sock);
            }
            backend_thread.join();
        }

        const output = try runCommandWithOutput(
            allocator,
            &.{
                "go",
                "run",
                "-C",
                grpc_go_dir,
                "-mod=mod",
                ".",
                target,
                request_md_value,
                response_header_value,
                response_trailer_value,
            },
        );
        defer allocator.free(output);

        try testing.expect(std.mem.indexOf(u8, output, "grpc-go-stream-meta-loop-ok") != null);
        backend_request_completed = true;
        backend_thread.join();
    }

    try testing.expectEqual(iteration_limit, iteration);
}

test "integration: grpc h2c forwards binary metadata headers to upstream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/BinaryMetadata",
        .mode = .unary,
        .first_response = "pong-bin",
        .expected_request_header_name = "x-trace-bin",
        .expected_request_header_value = "AQIDBA==",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2RequestWithExtraHeaders(
        "/grpc.test.Echo/BinaryMetadata",
        authority,
        "ping-bin",
        &.{
            .{ .name = "x-trace-bin", .value = "AQIDBA==" },
            .{ .name = "grpc-timeout", .value = "1S" },
        },
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-bin", payload);
                saw_data = true;
            },
            else => {},
        }

        if (saw_headers and saw_data and saw_trailers) break;
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
}

test "integration: grpc h2c forwards trailers-only response with grpc-status" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/TrailersOnly",
        .mode = .unary,
        .first_response = "unused",
        .trailers_only_response = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request(
        "/grpc.test.Echo/TrailersOnly",
        authority,
        "ping",
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_headers = false;
    var saw_data = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                try testing.expectEqualStrings(":status", fields[0].name);
                try testing.expectEqualStrings("200", fields[0].value);
                try expectGrpcStatusTrailer(fields, "0");
                try testing.expect((frame_view.header.flags & serval_h2.flags_end_stream) != 0);
                saw_headers = true;
                break;
            },
            .data => {
                saw_data = true;
            },
            else => {},
        }
    }

    try testing.expect(saw_headers);
    try testing.expect(!saw_data);
}

test "integration: grpc h2c relays response HEADERS and trailers split by CONTINUATION" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/ContinuationRelay",
        .mode = .unary,
        .first_response = "pong-cont",
        .split_response_headers_continuation = true,
        .split_response_trailers_continuation = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/ContinuationRelay", authority, "ping", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-cont", payload);
                saw_data = true;
            },
            else => {},
        }

        if (saw_headers and saw_data and saw_trailers) break;
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
}

test "integration: grpc h2c decodes upstream hpack huffman and dynamic indexed trailers" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/HpackInterop",
        .mode = .unary,
        .first_response = "pong-hpack",
        .response_headers_use_incremental_indexing = true,
        .response_headers_add_huffman_header = true,
        .trailers_include_dynamic_indexed_content_type = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/HpackInterop", authority, "ping", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);

                    var saw_huffman_header = false;
                    for (fields) |field| {
                        if (!std.mem.eql(u8, field.name, "x-hpack-huf")) continue;
                        try testing.expectEqualStrings("www.example.com", field.value);
                        saw_huffman_header = true;
                        break;
                    }
                    try testing.expect(saw_huffman_header);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");

                    var saw_dynamic_indexed_content_type = false;
                    for (fields) |field| {
                        if (!std.mem.eql(u8, field.name, "content-type")) continue;
                        try testing.expectEqualStrings("application/grpc", field.value);
                        saw_dynamic_indexed_content_type = true;
                        break;
                    }
                    try testing.expect(saw_dynamic_indexed_content_type);
                    saw_trailers = true;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-hpack", payload);
                saw_data = true;
            },
            else => {},
        }

        if (saw_headers and saw_data and saw_trailers) break;
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
}

test "integration: grpc h2c upgrade request is proxied end-to-end" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Upgrade",
        .mode = .unary,
        .first_response = "upgrade-pong",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest("/grpc.test.Echo/Upgrade", authority, "ping", &request_buf);
    try sendAllTcp(sock, request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
    try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
    try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_headers = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expect(std.mem.eql(u8, fields[0].name, ":status"));
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("upgrade-pong", grpc_payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: h2c upgrade non-gRPC response trailers are proxied without grpc-status enforcement" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGenericH2Backend(.{
        .port = backend_port,
        .path = "/h2-upgrade-generic-trailers",
        .response_payload = "upgrade-generic-body",
        .send_response_trailers = true,
        .response_trailer_name = "x-upgrade-trailer",
        .response_trailer_value = "upgrade-ok",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildTextH2UpgradeRequest(
        "/h2-upgrade-generic-trailers",
        authority,
        "",
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_response_headers = false;
    var saw_response_data = false;
    var saw_response_trailers = false;
    var saw_rst = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);

                if (!saw_response_headers) {
                    saw_response_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                    continue;
                }

                const trailer_value = findH2FieldValue(fields, "x-upgrade-trailer") orelse return error.MissingExpectedTrailer;
                try testing.expectEqualStrings("upgrade-ok", trailer_value);
                try testing.expect(findH2FieldValue(fields, "grpc-status") == null);
                try testing.expect((frame_view.header.flags & serval_h2.flags_end_stream) != 0);
                saw_response_trailers = true;
                break;
            },
            .data => {
                try testing.expectEqualStrings("upgrade-generic-body", frame_view.payload);
                saw_response_data = true;
            },
            .rst_stream => {
                saw_rst = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_response_headers);
    try testing.expect(saw_response_data);
    try testing.expect(saw_response_trailers);
    try testing.expect(!saw_rst);
}

test "integration: h2c upgrade non-gRPC headers-only end-stream response is proxied" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGenericH2Backend(.{
        .port = backend_port,
        .path = "/h2-upgrade-generic-headers-only",
        .response_status = "204",
        .response_content_type = null,
        .response_payload = null,
        .headers_end_stream = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildTextH2UpgradeRequest(
        "/h2-upgrade-generic-headers-only",
        authority,
        "",
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_response_headers = false;
    var saw_response_data = false;
    var saw_response_trailers = false;
    var saw_rst = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_response_headers) {
                    saw_response_headers = true;
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("204", fields[0].value);
                    try testing.expect((frame_view.header.flags & serval_h2.flags_end_stream) != 0);
                    break;
                }
                saw_response_trailers = true;
            },
            .data => saw_response_data = true,
            .rst_stream => {
                saw_rst = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_response_headers);
    try testing.expect(!saw_response_data);
    try testing.expect(!saw_response_trailers);
    try testing.expect(!saw_rst);
}

test "integration: grpc h2c upgrade request is proxied to tls h2 upstream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/UpgradeTlsUpstream",
        .mode = .unary,
        .first_response = "upgrade-tls-pong",
        .tls = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.startWithOptions(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .tls = true,
        .http_protocol = .h2,
    }, true);
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest("/grpc.test.Echo/UpgradeTlsUpstream", authority, "ping", &request_buf);
    try sendAllTcp(sock, request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
    try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
    try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_headers = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expect(std.mem.eql(u8, fields[0].name, ":status"));
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("upgrade-tls-pong", grpc_payload);
            },
            else => {},
        }
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_trailers);
}

test "integration: grpc h2c upgrade server streaming relays multiple DATA frames" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/UpgradeStream",
        .mode = .server_streaming,
        .first_response = "upgrade-one",
        .second_response = "upgrade-two",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest(
        "/grpc.test.Echo/UpgradeStream",
        authority,
        "req",
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
    try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
    try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_headers = false;
    var saw_first = false;
    var saw_second = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    saw_headers = true;
                    try testing.expect(std.mem.eql(u8, fields[0].name, ":status"));
                    try testing.expectEqualStrings("200", fields[0].value);
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                }
            },
            .data => {
                const grpc_payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                if (!saw_first) {
                    try testing.expectEqualStrings("upgrade-one", grpc_payload);
                    saw_first = true;
                } else {
                    try testing.expectEqualStrings("upgrade-two", grpc_payload);
                    saw_second = true;
                }
            },
            else => {},
        }

        if (saw_headers and saw_first and saw_second and saw_trailers) break;
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_first);
    try testing.expect(saw_second);
    try testing.expect(saw_trailers);
}

test "integration: grpc h2c upgrade multiplexes two unary streams on one connection" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2MultiBackend(.{
        .port = backend_port,
        .first_path = "/grpc.test.Echo/UpgradeMultiOne",
        .second_path = "/grpc.test.Echo/UpgradeMultiTwo",
        .first_response = "upgrade-one-reply",
        .second_response = "upgrade-two-reply",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var upgrade_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const upgrade_request = try buildGrpcH2UpgradeRequest(
        "/grpc.test.Echo/UpgradeMultiOne",
        authority,
        "one",
        &upgrade_request_buf,
    );
    try sendAllTcp(sock, upgrade_request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
    try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
    try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var sent_second_request = false;
    var saw_one = false;
    var saw_two = false;
    var saw_trailers_one = false;
    var saw_trailers_two = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                    if (!sent_second_request) {
                        var request_two_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
                        const request_two = try buildGrpcH2StreamFrames(
                            "/grpc.test.Echo/UpgradeMultiTwo",
                            authority,
                            "two",
                            3,
                            &request_two_buf,
                        );
                        try sendAllTcp(sock, request_two);
                        sent_second_request = true;
                    }
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len > 0 and std.mem.eql(u8, fields[0].name, ":status")) {
                    continue;
                }
                if (frame_view.header.stream_id == 1) {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers_one = true;
                } else if (frame_view.header.stream_id == 3) {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers_two = true;
                }
                if (saw_one and saw_two and saw_trailers_one and saw_trailers_two) break;
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                if (frame_view.header.stream_id == 1) {
                    try testing.expectEqualStrings("upgrade-one-reply", payload);
                    saw_one = true;
                } else if (frame_view.header.stream_id == 3) {
                    try testing.expectEqualStrings("upgrade-two-reply", payload);
                    saw_two = true;
                }
                if (saw_one and saw_two and saw_trailers_one and saw_trailers_two) break;
            },
            else => {},
        }
    }

    try testing.expect(sent_second_request);
    try testing.expect(saw_one);
    try testing.expect(saw_two);
    try testing.expect(saw_trailers_one);
    try testing.expect(saw_trailers_two);
}

test "integration: grpc h2c upgrade upstream goaway maps to downstream reset" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2GoAwayBackend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/UpgradeGoAway",
        .last_stream_id = 0,
        .error_code_raw = @intFromEnum(serval_h2.ErrorCode.no_error),
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest("/grpc.test.Echo/UpgradeGoAway", authority, "bye", &request_buf);
    try sendAllTcp(sock, request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
    try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
    try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_reset = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .rst_stream => {
                try testing.expectEqual(@as(u32, 1), frame_view.header.stream_id);
                const error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.cancel)), error_code_raw);
                saw_reset = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_reset);
}

test "integration: grpc h2c upstream goaway with last_stream_id keeps active stream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2GoAwayBackend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/GoAwayGraceful",
        .last_stream_id = 1,
        .error_code_raw = @intFromEnum(serval_h2.ErrorCode.no_error),
        .response_payload = "graceful",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/GoAwayGraceful", authority, "ping", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var saw_reset = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                    saw_headers = true;
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("graceful", payload);
                saw_data = true;
            },
            .rst_stream => {
                saw_reset = true;
                break;
            },
            else => {},
        }

        if (saw_headers and saw_data and saw_trailers) break;
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
    try testing.expect(!saw_reset);
}

test "integration: grpc h2c upgrade upstream goaway with last_stream_id keeps active stream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2GoAwayBackend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/UpgradeGoAwayGraceful",
        .last_stream_id = 1,
        .error_code_raw = @intFromEnum(serval_h2.ErrorCode.no_error),
        .response_payload = "upgrade-graceful",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest("/grpc.test.Echo/UpgradeGoAwayGraceful", authority, "ping", &request_buf);
    try sendAllTcp(sock, request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_headers = false;
    var saw_data = false;
    var saw_trailers = false;
    var saw_reset = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (!saw_headers) {
                    try testing.expectEqualStrings(":status", fields[0].name);
                    try testing.expectEqualStrings("200", fields[0].value);
                    saw_headers = true;
                } else {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("upgrade-graceful", payload);
                saw_data = true;
            },
            .rst_stream => {
                saw_reset = true;
                break;
            },
            else => {},
        }

        if (saw_headers and saw_data and saw_trailers) break;
    }

    try testing.expect(saw_headers);
    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
    try testing.expect(!saw_reset);
}

fn run_goaway_last_stream_resets_higher_scenario() !void {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2GoAwayBackend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/GoAwayAllowed",
        .last_stream_id = 1,
        .error_code_raw = @intFromEnum(serval_h2.ErrorCode.no_error),
        .response_payload = "allowed",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2InterleavedTwoUnaryRequest(
        "/grpc.test.Echo/GoAwayAllowed",
        "/grpc.test.Echo/GoAwayRejected",
        authority,
        "one",
        "two",
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_stream_one_headers = false;
    var saw_stream_one_data = false;
    var saw_stream_one_trailers = false;
    var saw_stream_three_reset = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 4) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);

                if (frame_view.header.stream_id == 1) {
                    if (!saw_stream_one_headers) {
                        try testing.expectEqualStrings(":status", fields[0].name);
                        try testing.expectEqualStrings("200", fields[0].value);
                        saw_stream_one_headers = true;
                    } else {
                        try expectGrpcStatusTrailer(fields, "0");
                        saw_stream_one_trailers = true;
                    }
                }
            },
            .data => {
                if (frame_view.header.stream_id != 1) continue;
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("allowed", payload);
                saw_stream_one_data = true;
            },
            .rst_stream => {
                if (frame_view.header.stream_id != 3) continue;
                const error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.cancel)), error_code_raw);
                saw_stream_three_reset = true;
            },
            else => {},
        }

        if (saw_stream_one_headers and saw_stream_one_data and saw_stream_one_trailers and saw_stream_three_reset) break;
    }

    try testing.expect(saw_stream_one_headers);
    try testing.expect(saw_stream_one_data);
    try testing.expect(saw_stream_one_trailers);
    try testing.expect(saw_stream_three_reset);
}

test "integration: grpc h2c goaway last_stream_id resets higher stream and keeps lower stream" {
    try run_goaway_last_stream_resets_higher_scenario();
}

fn waitForGrpcDataOnStream(
    sock: posix.socket_t,
    initial: *[]const u8,
    frame_buf: []u8,
    payload_buf: []u8,
    stream_id: u32,
    expected_payload: []const u8,
) !void {
    assert(frame_buf.len >= H2_TEST_BUFFER_SIZE_BYTES);
    assert(stream_id > 0);

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS * 3) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial.*, frame_buf);
        initial.* = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .data => {
                if (frame_view.header.stream_id != stream_id) continue;
                const payload = try readGrpcPayloadFromDataFrame(frame_view, payload_buf);
                try testing.expectEqualStrings(expected_payload, payload);
                return;
            },
            .rst_stream => return error.UnexpectedReset,
            else => {},
        }
    }

    return error.ReadTimeout;
}

fn waitForGrpcUnaryResponseOnStream(
    sock: posix.socket_t,
    initial: *[]const u8,
    frame_buf: []u8,
    payload_buf: []u8,
    stream_id: u32,
    expected_payload: []const u8,
) !void {
    assert(frame_buf.len >= H2_TEST_BUFFER_SIZE_BYTES);
    assert(stream_id > 0);

    var saw_data = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 3) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial.*, frame_buf);
        initial.* = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                if (frame_view.header.stream_id != stream_id) continue;
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len > 0 and std.mem.eql(u8, fields[0].name, ":status")) continue;
                try expectGrpcStatusTrailer(fields, "0");
                saw_trailers = true;
            },
            .data => {
                if (frame_view.header.stream_id != stream_id) continue;
                const payload = try readGrpcPayloadFromDataFrame(frame_view, payload_buf);
                try testing.expectEqualStrings(expected_payload, payload);
                saw_data = true;
            },
            .rst_stream => return error.UnexpectedReset,
            else => {},
        }

        if (saw_data and saw_trailers) break;
    }

    try testing.expect(saw_data);
    try testing.expect(saw_trailers);
}

const HeadersOnlyExpectation = struct {
    stream_id: u32,
    expected_status: []const u8,
};

fn waitForHeadersOnlyResponseOnStream(
    sock: posix.socket_t,
    initial: *[]const u8,
    frame_buf: []u8,
    expectation: HeadersOnlyExpectation,
) !void {
    assert(frame_buf.len >= H2_TEST_BUFFER_SIZE_BYTES);
    assert(expectation.stream_id > 0);

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS * 3) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial.*, frame_buf);
        initial.* = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                if (frame_view.header.stream_id != expectation.stream_id) continue;
                try testing.expect((frame_view.header.flags & serval_h2.flags_end_stream) != 0);

                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                const status = findH2FieldValue(fields, ":status") orelse return error.MissingStatus;
                try testing.expectEqualStrings(expectation.expected_status, status);
                try testing.expect(findH2FieldValue(fields, "grpc-status") == null);
                return;
            },
            .rst_stream => {
                if (frame_view.header.stream_id != expectation.stream_id) continue;
                return error.UnexpectedReset;
            },
            else => {},
        }
    }

    return error.ReadTimeout;
}

fn waitForRstOnStream(
    sock: posix.socket_t,
    initial: *[]const u8,
    frame_buf: []u8,
    stream_id: u32,
    expected_error_code_raw: u32,
) !void {
    assert(frame_buf.len >= H2_TEST_BUFFER_SIZE_BYTES);
    assert(stream_id > 0);

    var iterations: u32 = 0;
    while (iterations < H2_MAX_FRAME_READS * 3) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial.*, frame_buf);
        initial.* = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .rst_stream => {
                if (frame_view.header.stream_id != stream_id) continue;
                const error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(expected_error_code_raw, error_code_raw);
                return;
            },
            else => {},
        }
    }

    return error.ReadTimeout;
}

test "integration: grpc h2c opens new upstream session after goaway for next stream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};

    {
        const first_backend_thread = try startGrpcH2GoAwayBackend(.{
            .port = backend_port,
            .path = "/grpc.test.Echo/FirstAfterGoAway",
            .last_stream_id = 1,
            .error_code_raw = @intFromEnum(serval_h2.ErrorCode.no_error),
            .response_payload = "first-reply",
        });
        defer first_backend_thread.join();

        var first_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const first_request = try buildGrpcH2Request(
            "/grpc.test.Echo/FirstAfterGoAway",
            authority,
            "first-ping",
            &first_request_buf,
        );
        try sendAllTcp(sock, first_request);

        var saw_first_data = false;
        var saw_first_trailers = false;
        var first_iterations: u32 = 0;

        while (first_iterations < H2_MAX_FRAME_READS * 2) : (first_iterations += 1) {
            const frame_view = try readH2Frame(sock, initial, &frame_buf);
            initial = frame_view.remaining;

            switch (frame_view.header.frame_type) {
                .settings => {
                    if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                        try sendH2SettingsAck(sock);
                    }
                },
                .headers => {
                    if (frame_view.header.stream_id != 1) continue;
                    var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                    const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                    if (fields.len > 0 and std.mem.eql(u8, fields[0].name, ":status")) continue;
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_first_trailers = true;
                },
                .data => {
                    if (frame_view.header.stream_id != 1) continue;
                    const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                    try testing.expectEqualStrings("first-reply", payload);
                    saw_first_data = true;
                },
                else => {},
            }

            if (saw_first_data and saw_first_trailers) break;
        }

        try testing.expect(saw_first_data);
        try testing.expect(saw_first_trailers);
    }

    const second_backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/SecondAfterGoAway",
        .mode = .unary,
        .first_response = "second-reply",
    });
    defer second_backend_thread.join();

    var second_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const second_request = try buildGrpcH2StreamFrames(
        "/grpc.test.Echo/SecondAfterGoAway",
        authority,
        "second-ping",
        3,
        &second_request_buf,
    );
    try sendAllTcp(sock, second_request);

    var saw_second_data = false;
    var saw_second_trailers = false;
    var second_iterations: u32 = 0;

    while (second_iterations < H2_MAX_FRAME_READS * 2) : (second_iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                if (frame_view.header.stream_id != 3) continue;
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len > 0 and std.mem.eql(u8, fields[0].name, ":status")) continue;
                try expectGrpcStatusTrailer(fields, "0");
                saw_second_trailers = true;
            },
            .data => {
                if (frame_view.header.stream_id != 3) continue;
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("second-reply", payload);
                saw_second_data = true;
            },
            else => {},
        }

        if (saw_second_data and saw_second_trailers) break;
    }

    try testing.expect(saw_second_data);
    try testing.expect(saw_second_trailers);
}

fn run_goaway_rollover_cycles(cycle_count: u8) !void {
    assert(cycle_count > 0);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};

    var stream_id: u32 = 1;
    var cycle: u8 = 0;
    while (cycle < cycle_count) : (cycle += 1) {
        var goaway_path_buf: [96]u8 = undefined;
        const goaway_path = try std.fmt.bufPrint(&goaway_path_buf, "/grpc.test.Echo/GoAwayCycle{d}", .{cycle});
        var goaway_response_buf: [64]u8 = undefined;
        const goaway_response = try std.fmt.bufPrint(&goaway_response_buf, "goaway-reply-{d}", .{cycle});

        const goaway_backend_thread = try startGrpcH2GoAwayBackend(.{
            .port = backend_port,
            .path = goaway_path,
            .last_stream_id = stream_id,
            .error_code_raw = @intFromEnum(serval_h2.ErrorCode.no_error),
            .response_payload = goaway_response,
        });

        var goaway_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        if (stream_id == 1) {
            const goaway_request = try buildGrpcH2Request(
                goaway_path,
                authority,
                "goaway-ping",
                &goaway_request_buf,
            );
            try sendAllTcp(sock, goaway_request);
        } else {
            const goaway_request = try buildGrpcH2StreamFrames(
                goaway_path,
                authority,
                "goaway-ping",
                stream_id,
                &goaway_request_buf,
            );
            try sendAllTcp(sock, goaway_request);
        }

        try waitForGrpcUnaryResponseOnStream(
            sock,
            &initial,
            &frame_buf,
            &payload_buf,
            stream_id,
            goaway_response,
        );
        goaway_backend_thread.join();

        var unary_path_buf: [96]u8 = undefined;
        const unary_path = try std.fmt.bufPrint(&unary_path_buf, "/grpc.test.Echo/AfterGoAwayCycle{d}", .{cycle});
        var unary_response_buf: [64]u8 = undefined;
        const unary_response = try std.fmt.bufPrint(&unary_response_buf, "fresh-reply-{d}", .{cycle});

        const unary_backend_thread = try startGrpcH2Backend(.{
            .port = backend_port,
            .path = unary_path,
            .mode = .unary,
            .first_response = unary_response,
        });

        var unary_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const unary_stream_id = stream_id + 2;
        const unary_request = try buildGrpcH2StreamFrames(
            unary_path,
            authority,
            "fresh-ping",
            unary_stream_id,
            &unary_request_buf,
        );
        try sendAllTcp(sock, unary_request);

        try waitForGrpcUnaryResponseOnStream(
            sock,
            &initial,
            &frame_buf,
            &payload_buf,
            unary_stream_id,
            unary_response,
        );
        unary_backend_thread.join();

        stream_id = unary_stream_id + 2;
    }

    try testing.expectEqual(@as(u32, 1 + @as(u32, cycle_count) * 4), stream_id);
}

test "integration: grpc h2c repeated goaway rollover opens fresh upstream sessions" {
    try run_goaway_rollover_cycles(3);
}

test "integration: grpc h2c repeated goaway rollover soak loop" {
    try run_goaway_rollover_cycles(16);
}

fn run_upgrade_goaway_rollover_cycles(cycle_count: u8) !void {
    assert(cycle_count > 0);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var upgrade_established = false;

    var stream_id: u32 = 1;
    var cycle: u8 = 0;
    while (cycle < cycle_count) : (cycle += 1) {
        var goaway_path_buf: [96]u8 = undefined;
        const goaway_path = try std.fmt.bufPrint(&goaway_path_buf, "/grpc.test.Echo/UpgradeGoAwayCycle{d}", .{cycle});
        var goaway_response_buf: [64]u8 = undefined;
        const goaway_response = try std.fmt.bufPrint(&goaway_response_buf, "upgrade-goaway-reply-{d}", .{cycle});

        const goaway_backend_thread = try startGrpcH2GoAwayBackend(.{
            .port = backend_port,
            .path = goaway_path,
            .last_stream_id = stream_id,
            .error_code_raw = @intFromEnum(serval_h2.ErrorCode.no_error),
            .response_payload = goaway_response,
        });

        var goaway_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        if (!upgrade_established) {
            const goaway_request = try buildGrpcH2UpgradeRequest(
                goaway_path,
                authority,
                "upgrade-goaway-ping",
                &goaway_request_buf,
            );
            try sendAllTcp(sock, goaway_request);

            const response_len = try readUntilHeadersComplete(sock, &response_buf);
            try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
            try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
            try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

            const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
            initial = response_buf[headers_end..response_len];
            upgrade_established = true;
        } else {
            const goaway_request = try buildGrpcH2StreamFrames(
                goaway_path,
                authority,
                "upgrade-goaway-ping",
                stream_id,
                &goaway_request_buf,
            );
            try sendAllTcp(sock, goaway_request);
        }

        try waitForGrpcUnaryResponseOnStream(
            sock,
            &initial,
            &frame_buf,
            &payload_buf,
            stream_id,
            goaway_response,
        );
        goaway_backend_thread.join();

        var unary_path_buf: [96]u8 = undefined;
        const unary_path = try std.fmt.bufPrint(&unary_path_buf, "/grpc.test.Echo/AfterUpgradeGoAwayCycle{d}", .{cycle});
        var unary_response_buf: [64]u8 = undefined;
        const unary_response = try std.fmt.bufPrint(&unary_response_buf, "upgrade-fresh-reply-{d}", .{cycle});

        const unary_backend_thread = try startGrpcH2Backend(.{
            .port = backend_port,
            .path = unary_path,
            .mode = .unary,
            .first_response = unary_response,
        });

        var unary_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const unary_stream_id = stream_id + 2;
        const unary_request = try buildGrpcH2StreamFrames(
            unary_path,
            authority,
            "upgrade-fresh-ping",
            unary_stream_id,
            &unary_request_buf,
        );
        try sendAllTcp(sock, unary_request);

        try waitForGrpcUnaryResponseOnStream(
            sock,
            &initial,
            &frame_buf,
            &payload_buf,
            unary_stream_id,
            unary_response,
        );
        unary_backend_thread.join();

        stream_id = unary_stream_id + 2;
    }

    try testing.expect(upgrade_established);
    try testing.expectEqual(@as(u32, 1 + @as(u32, cycle_count) * 4), stream_id);
}

test "integration: grpc h2c upgrade repeated goaway rollover opens fresh upstream sessions" {
    try run_upgrade_goaway_rollover_cycles(3);
}

test "integration: grpc h2c upgrade repeated goaway rollover soak loop" {
    try run_upgrade_goaway_rollover_cycles(12);
}

fn run_mixed_goaway_and_nongrpc_trailer_cycles(cycle_count: u8) !void {
    assert(cycle_count > 0);

    var cycle: u8 = 0;
    while (cycle < cycle_count) : (cycle += 1) {
        try run_goaway_rollover_cycles(1);

        const backend_port = harness.getPort();
        const proxy_port = harness.getPort();

        const nongrpc_backend_thread = try startMinimalH2BridgeBackend(.{ .port = backend_port });
        defer nongrpc_backend_thread.join();

        var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
            .host = "127.0.0.1",
            .port = backend_port,
            .idx = 0,
            .http_protocol = .h2c,
        });
        defer proxy.stop();

        const sock = try connectTcp(proxy_port);
        defer posix.close(sock);

        var authority_buf: [32]u8 = undefined;
        const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

        var nongrpc_path_buf: [96]u8 = undefined;
        const nongrpc_path = try std.fmt.bufPrint(&nongrpc_path_buf, "/h2-mixed-trailer-cycle-{d}", .{cycle});

        var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const request = try buildSimpleH2PostRequestWithTrailers(
            nongrpc_path,
            authority,
            "http",
            "mixed-nongrpc-body",
            &request_buf,
        );
        try sendAllTcp(sock, request);

        var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        var initial: []const u8 = &[_]u8{};
        try waitForRstOnStream(
            sock,
            &initial,
            &frame_buf,
            1,
            @intFromEnum(serval_h2.ErrorCode.protocol_error),
        );
    }
}

test "integration: grpc h2c mixed goaway and non-grpc trailer reset loop preserves progress" {
    try run_mixed_goaway_and_nongrpc_trailer_cycles(4);
}

test "integration: grpc h2c mixed goaway and non-grpc trailer reset soak loop" {
    try run_mixed_goaway_and_nongrpc_trailer_cycles(20);
}

test "integration: grpc h2c mixed grpc and non-grpc streams share one downstream connection" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startMixedGrpcGenericBackend(.{
        .port = backend_port,
        .grpc_path = "/grpc.test.Echo/MixedGrpcStream",
        .grpc_response = "mixed-grpc-reply",
        .generic_path = "/h2-mixed-nongrpc-stream",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var grpc_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const grpc_request = try buildGrpcH2Request(
        "/grpc.test.Echo/MixedGrpcStream",
        authority,
        "mixed-grpc-ping",
        &grpc_request_buf,
    );
    try sendAllTcp(sock, grpc_request);

    var nongrpc_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const nongrpc_request = try buildSimpleH2PostStreamFrames(
        "/h2-mixed-nongrpc-stream",
        authority,
        "http",
        "mixed-http-body",
        3,
        &nongrpc_request_buf,
    );
    try sendAllTcp(sock, nongrpc_request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};

    try waitForGrpcUnaryResponseOnStream(
        sock,
        &initial,
        &frame_buf,
        &payload_buf,
        1,
        "mixed-grpc-reply",
    );

    try waitForHeadersOnlyResponseOnStream(sock, &initial, &frame_buf, .{
        .stream_id = 3,
        .expected_status = "204",
    });
}

test "integration: grpc h2c missing grpc-status trailer maps to downstream reset" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/MissingStatus",
        .mode = .unary,
        .first_response = "reply",
        .omit_grpc_status = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/MissingStatus", authority, "req", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_reset = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .rst_stream => {
                try testing.expectEqual(@as(u32, 1), frame_view.header.stream_id);
                const error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.protocol_error)), error_code_raw);
                saw_reset = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_reset);
}

test "integration: grpc h2c upgrade missing grpc-status trailer maps to downstream reset" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/UpgradeMissingStatus",
        .mode = .unary,
        .first_response = "reply",
        .omit_grpc_status = true,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2UpgradeRequest("/grpc.test.Echo/UpgradeMissingStatus", authority, "req", &request_buf);
    try sendAllTcp(sock, request);

    var response_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const response_len = try readUntilHeadersComplete(sock, &response_buf);
    try testing.expectEqual(@as(u16, 101), harness.TestClient.parseStatusCode(response_buf[0..response_len]).?);
    try testing.expectEqualStrings("h2c", harness.TestClient.findHeader(response_buf[0..response_len], "Upgrade").?);
    try testing.expectEqualStrings("Upgrade", harness.TestClient.findHeader(response_buf[0..response_len], "Connection").?);

    const headers_end = std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n").? + 4;
    var initial: []const u8 = response_buf[headers_end..response_len];
    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_reset = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .rst_stream => {
                try testing.expectEqual(@as(u32, 1), frame_view.header.stream_id);
                const error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.protocol_error)), error_code_raw);
                saw_reset = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_reset);
}

test "integration: grpc h2c multiplexes two unary streams on one connection" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2MultiBackend(.{
        .port = backend_port,
        .first_path = "/grpc.test.Echo/MultiOne",
        .second_path = "/grpc.test.Echo/MultiTwo",
        .first_response = "one-reply",
        .second_response = "two-reply",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_one_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request_one = try buildGrpcH2Request("/grpc.test.Echo/MultiOne", authority, "one", &request_one_buf);
    try sendAllTcp(sock, request_one);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var sent_second_request = false;
    var saw_one = false;
    var saw_two = false;
    var saw_trailers_one = false;
    var saw_trailers_two = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                    if (!sent_second_request) {
                        var request_two_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
                        const request_two = try buildGrpcH2StreamFrames(
                            "/grpc.test.Echo/MultiTwo",
                            authority,
                            "two",
                            3,
                            &request_two_buf,
                        );
                        try sendAllTcp(sock, request_two);
                        sent_second_request = true;
                    }
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len > 0 and std.mem.eql(u8, fields[0].name, ":status")) {
                    continue;
                }
                if (frame_view.header.stream_id == 1) {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers_one = true;
                } else if (frame_view.header.stream_id == 3) {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers_two = true;
                }
                if (saw_one and saw_two and saw_trailers_one and saw_trailers_two) break;
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                if (frame_view.header.stream_id == 1) {
                    try testing.expectEqualStrings("one-reply", payload);
                    saw_one = true;
                } else if (frame_view.header.stream_id == 3) {
                    try testing.expectEqualStrings("two-reply", payload);
                    saw_two = true;
                }
                if (saw_one and saw_two and saw_trailers_one and saw_trailers_two) break;
            },
            else => {},
        }
    }

    try testing.expect(sent_second_request);
    try testing.expect(saw_one);
    try testing.expect(saw_two);
    try testing.expect(saw_trailers_one);
    try testing.expect(saw_trailers_two);
}

test "integration: grpc h2c stream churn handles many unary streams on one connection" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();
    const stream_count: u8 = 24;

    const backend_thread = try startTerminatedH2ChurnServer(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Churn",
        .expected_request_payload = "ping-churn",
        .response_payload = "pong-churn",
        .expected_stream_count = stream_count,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_FLOW_CONTROL_REQUEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2InterleavedManyUnaryRequest(
        "/grpc.test.Echo/Churn",
        authority,
        "ping-churn",
        stream_count,
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};

    var saw_payload_count: u8 = 0;
    var saw_trailer_count: u8 = 0;
    var completed_streams: [serval.config.H2_MAX_CONCURRENT_STREAMS]bool = [_]bool{false} ** serval.config.H2_MAX_CONCURRENT_STREAMS;

    var iterations: u32 = 0;
    const max_iterations: u32 = 1024;
    while (iterations < max_iterations) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len == 0) continue;

                if (std.mem.eql(u8, fields[0].name, ":status")) {
                    try testing.expectEqualStrings("200", fields[0].value);
                    continue;
                }

                try expectGrpcStatusTrailer(fields, "0");

                const stream_id = frame_view.header.stream_id;
                try testing.expect(stream_id > 0);
                const stream_slot: usize = @intCast((stream_id - 1) / 2);
                try testing.expect(stream_slot < completed_streams.len);
                if (!completed_streams[stream_slot]) {
                    completed_streams[stream_slot] = true;
                    saw_trailer_count += 1;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-churn", payload);
                saw_payload_count += 1;
            },
            else => {},
        }

        if (saw_trailer_count >= stream_count and saw_payload_count >= stream_count) break;
    }

    try testing.expectEqual(stream_count, saw_payload_count);
    try testing.expectEqual(stream_count, saw_trailer_count);
}

test "integration: grpc h2c stream churn near concurrent-stream bound" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();
    const stream_count: u8 = 96;

    const backend_thread = try startTerminatedH2ChurnServer(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/ChurnNearBound",
        .expected_request_payload = "ping-bound",
        .response_payload = "pong-bound",
        .expected_stream_count = stream_count,
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var request_buf: [H2_FLOW_CONTROL_REQUEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2InterleavedManyUnaryRequest(
        "/grpc.test.Echo/ChurnNearBound",
        authority,
        "ping-bound",
        stream_count,
        &request_buf,
    );
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};

    var saw_payload_count: u8 = 0;
    var saw_trailer_count: u8 = 0;
    var completed_streams: [serval.config.H2_MAX_CONCURRENT_STREAMS]bool = [_]bool{false} ** serval.config.H2_MAX_CONCURRENT_STREAMS;

    var iterations: u32 = 0;
    const max_iterations: u32 = 4096;
    while (iterations < max_iterations) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (fields.len == 0) continue;

                if (std.mem.eql(u8, fields[0].name, ":status")) {
                    try testing.expectEqualStrings("200", fields[0].value);
                    continue;
                }

                try expectGrpcStatusTrailer(fields, "0");

                const stream_id = frame_view.header.stream_id;
                try testing.expect(stream_id > 0);
                const stream_slot: usize = @intCast((stream_id - 1) / 2);
                try testing.expect(stream_slot < completed_streams.len);
                if (!completed_streams[stream_slot]) {
                    completed_streams[stream_slot] = true;
                    saw_trailer_count += 1;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("pong-bound", payload);
                saw_payload_count += 1;
            },
            else => {},
        }

        if (saw_trailer_count >= stream_count and saw_payload_count >= stream_count) break;
    }

    try testing.expectEqual(stream_count, saw_payload_count);
    try testing.expectEqual(stream_count, saw_trailer_count);
}

test "integration: grpc h2c server streaming relays multiple DATA frames" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2Backend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Stream",
        .mode = .server_streaming,
        .first_response = "one",
        .second_response = "two",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/Stream", authority, "request", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var saw_one = false;
    var saw_two = false;
    var saw_trailers = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .headers => {
                var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                if (saw_one and saw_two) {
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_trailers = true;
                    break;
                }
            },
            .data => {
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                if (std.mem.eql(u8, payload, "one")) saw_one = true;
                if (std.mem.eql(u8, payload, "two")) saw_two = true;
            },
            else => {},
        }
    }

    try testing.expect(saw_one);
    try testing.expect(saw_two);
    try testing.expect(saw_trailers);
}

test "integration: grpc h2c upstream rst maps to downstream reset" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2ResetBackend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/Reset",
        .error_code_raw = @intFromEnum(serval_h2.ErrorCode.cancel),
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/Reset", authority, "reset-me", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_reset = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .rst_stream => {
                try testing.expectEqual(@as(u32, 1), frame_view.header.stream_id);
                const error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.cancel)), error_code_raw);
                saw_reset = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_reset);
}

fn run_reset_isolation_cycles(cycle_count: u8) !void {
    assert(cycle_count > 0);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var cycle: u8 = 0;
    while (cycle < cycle_count) : (cycle += 1) {
        var reset_path_buf: [96]u8 = undefined;
        const reset_path = try std.fmt.bufPrint(&reset_path_buf, "/grpc.test.Echo/ResetRaceOne{d}", .{cycle});
        var survivor_path_buf: [96]u8 = undefined;
        const survivor_path = try std.fmt.bufPrint(&survivor_path_buf, "/grpc.test.Echo/ResetRaceTwo{d}", .{cycle});
        var survivor_payload_buf: [64]u8 = undefined;
        const survivor_payload = try std.fmt.bufPrint(&survivor_payload_buf, "survivor-{d}", .{cycle});

        const backend_thread = try startGrpcH2ResetThenUnaryBackend(.{
            .port = backend_port,
            .reset_path = reset_path,
            .pass_path = survivor_path,
            .reset_error_code_raw = @intFromEnum(serval_h2.ErrorCode.cancel),
            .pass_response = survivor_payload,
        });

        const sock = try connectTcp(proxy_port);
        defer posix.close(sock);

        var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        var initial: []const u8 = &[_]u8{};

        var stream_one_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const stream_one_request = try buildGrpcH2Request(
            reset_path,
            authority,
            "one",
            &stream_one_buf,
        );
        try sendAllTcp(sock, stream_one_request);

        var saw_stream_one_reset = false;
        var iterations: u32 = 0;
        while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
            const frame_view = try readH2Frame(sock, initial, &frame_buf);
            initial = frame_view.remaining;

            switch (frame_view.header.frame_type) {
                .settings => {
                    if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                        try sendH2SettingsAck(sock);
                    }
                },
                .rst_stream => {
                    if (frame_view.header.stream_id != 1) continue;
                    const error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                    try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.cancel)), error_code_raw);
                    saw_stream_one_reset = true;
                    break;
                },
                else => {},
            }
        }
        try testing.expect(saw_stream_one_reset);

        var stream_three_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const stream_three_request = try buildGrpcH2StreamFrames(
            survivor_path,
            authority,
            "two",
            3,
            &stream_three_buf,
        );
        try sendAllTcp(sock, stream_three_request);

        var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        var saw_stream_three_data = false;
        var saw_stream_three_trailer = false;
        iterations = 0;
        while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
            const frame_view = try readH2Frame(sock, initial, &frame_buf);
            initial = frame_view.remaining;

            switch (frame_view.header.frame_type) {
                .headers => {
                    if (frame_view.header.stream_id != 3) continue;
                    var fields_buf: [H2_MAX_HEADER_FIELDS]serval_h2.HeaderField = undefined;
                    const fields = try decodeH2Fields(frame_view.payload, &fields_buf);
                    if (fields.len > 0 and std.mem.eql(u8, fields[0].name, ":status")) continue;
                    try expectGrpcStatusTrailer(fields, "0");
                    saw_stream_three_trailer = true;
                },
                .data => {
                    if (frame_view.header.stream_id != 3) continue;
                    const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                    try testing.expectEqualStrings(survivor_payload, payload);
                    saw_stream_three_data = true;
                },
                else => {},
            }

            if (saw_stream_three_data and saw_stream_three_trailer) break;
        }

        try testing.expect(saw_stream_three_data);
        try testing.expect(saw_stream_three_trailer);
        backend_thread.join();
    }

    try testing.expectEqual(cycle_count, cycle);
}

test "integration: grpc h2c upstream reset on one stream preserves sibling stream" {
    try run_reset_isolation_cycles(1);
}

test "integration: grpc h2c reset isolation soak loop" {
    try run_reset_isolation_cycles(12);
}

test "integration: grpc h2c downstream cancel propagates upstream and preserves next stream" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2CancelPropagationBackend(.{
        .port = backend_port,
        .cancel_path = "/grpc.test.Echo/CancelMe",
        .survivor_path = "/grpc.test.Echo/AfterCancel",
        .first_payload = "partial",
        .survivor_payload = "after-cancel",
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var first_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const first_request = try buildGrpcH2Request(
        "/grpc.test.Echo/CancelMe",
        authority,
        "cancel-ping",
        &first_request_buf,
    );
    try sendAllTcp(sock, first_request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};

    var saw_first_data = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS * 2) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .data => {
                if (frame_view.header.stream_id != 1) continue;
                const payload = try readGrpcPayloadFromDataFrame(frame_view, &payload_buf);
                try testing.expectEqualStrings("partial", payload);
                saw_first_data = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_first_data);

    var rst_buf: [serval_h2.frame_header_size_bytes + serval_h2.control.rst_stream_payload_size_bytes]u8 = undefined;
    const rst_frame = try serval_h2.buildRstStreamFrame(&rst_buf, 1, @intFromEnum(serval_h2.ErrorCode.cancel));
    try sendAllTcp(sock, rst_frame);

    var second_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const second_request = try buildGrpcH2StreamFrames(
        "/grpc.test.Echo/AfterCancel",
        authority,
        "after-ping",
        3,
        &second_request_buf,
    );
    try sendAllTcp(sock, second_request);

    try waitForGrpcUnaryResponseOnStream(
        sock,
        &initial,
        &frame_buf,
        &payload_buf,
        3,
        "after-cancel",
    );
}

fn run_cancel_goaway_overlap_cycles(cycle_count: u8) !void {
    assert(cycle_count > 0);

    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});

    var cycle: u8 = 0;
    while (cycle < cycle_count) : (cycle += 1) {
        const sock = try connectTcp(proxy_port);
        defer posix.close(sock);

        var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        var payload_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        var initial: []const u8 = &[_]u8{};

        var cancel_path_buf: [96]u8 = undefined;
        const cancel_path = try std.fmt.bufPrint(&cancel_path_buf, "/grpc.test.Echo/CancelOverlapCycle{d}", .{cycle});

        const cancel_backend_thread = try startGrpcH2CancelPropagationBackend(.{
            .port = backend_port,
            .cancel_path = cancel_path,
            .survivor_path = "unused",
            .first_payload = "partial-overlap",
            .survivor_payload = "unused",
            .goaway_last_stream_id = 1,
            .await_survivor_on_same_session = false,
        });

        var cancel_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const cancel_request = try buildGrpcH2Request(
            cancel_path,
            authority,
            "cancel-overlap",
            &cancel_request_buf,
        );
        try sendAllTcp(sock, cancel_request);

        try waitForGrpcDataOnStream(
            sock,
            &initial,
            &frame_buf,
            &payload_buf,
            1,
            "partial-overlap",
        );

        var rst_buf: [serval_h2.frame_header_size_bytes + serval_h2.control.rst_stream_payload_size_bytes]u8 = undefined;
        const rst_frame = try serval_h2.buildRstStreamFrame(&rst_buf, 1, @intFromEnum(serval_h2.ErrorCode.cancel));
        try sendAllTcp(sock, rst_frame);
        cancel_backend_thread.join();

        var survivor_path_buf: [96]u8 = undefined;
        const survivor_path = try std.fmt.bufPrint(&survivor_path_buf, "/grpc.test.Echo/AfterCancelOverlapCycle{d}", .{cycle});
        var survivor_response_buf: [64]u8 = undefined;
        const survivor_response = try std.fmt.bufPrint(&survivor_response_buf, "after-overlap-{d}", .{cycle});

        const survivor_backend_thread = try startGrpcH2Backend(.{
            .port = backend_port,
            .path = survivor_path,
            .mode = .unary,
            .first_response = survivor_response,
        });

        var survivor_request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
        const survivor_request = try buildGrpcH2StreamFrames(
            survivor_path,
            authority,
            "survivor-overlap",
            3,
            &survivor_request_buf,
        );
        try sendAllTcp(sock, survivor_request);

        try waitForGrpcUnaryResponseOnStream(
            sock,
            &initial,
            &frame_buf,
            &payload_buf,
            3,
            survivor_response,
        );
        survivor_backend_thread.join();
    }

    try testing.expectEqual(cycle_count, cycle);
}

test "integration: grpc h2c cancel and goaway overlap loop preserves subsequent streams" {
    try run_cancel_goaway_overlap_cycles(2);
}

test "integration: grpc h2c cancel and goaway overlap soak loop" {
    try run_cancel_goaway_overlap_cycles(12);
}

test "integration: grpc h2c upstream goaway maps to downstream reset" {
    const backend_port = harness.getPort();
    const proxy_port = harness.getPort();

    const backend_thread = try startGrpcH2GoAwayBackend(.{
        .port = backend_port,
        .path = "/grpc.test.Echo/GoAway",
        .last_stream_id = 0,
        .error_code_raw = @intFromEnum(serval_h2.ErrorCode.no_error),
    });
    defer backend_thread.join();

    var proxy = try GrpcH2ProxyServer.start(proxy_port, .{
        .host = "127.0.0.1",
        .port = backend_port,
        .idx = 0,
        .http_protocol = .h2c,
    });
    defer proxy.stop();

    const sock = try connectTcp(proxy_port);
    defer posix.close(sock);

    var authority_buf: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buf, "127.0.0.1:{d}", .{proxy_port});
    var request_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    const request = try buildGrpcH2Request("/grpc.test.Echo/GoAway", authority, "bye", &request_buf);
    try sendAllTcp(sock, request);

    var frame_buf: [H2_TEST_BUFFER_SIZE_BYTES]u8 = undefined;
    var initial: []const u8 = &[_]u8{};
    var saw_reset = false;
    var iterations: u32 = 0;

    while (iterations < H2_MAX_FRAME_READS) : (iterations += 1) {
        const frame_view = try readH2Frame(sock, initial, &frame_buf);
        initial = frame_view.remaining;

        switch (frame_view.header.frame_type) {
            .settings => {
                if ((frame_view.header.flags & serval_h2.flags_ack) == 0) {
                    try sendH2SettingsAck(sock);
                }
            },
            .rst_stream => {
                try testing.expectEqual(@as(u32, 1), frame_view.header.stream_id);
                const error_code_raw = try serval_h2.parseRstStreamFrame(frame_view.header, frame_view.payload);
                try testing.expectEqual(@as(u32, @intFromEnum(serval_h2.ErrorCode.cancel)), error_code_raw);
                saw_reset = true;
                break;
            },
            else => {},
        }
    }

    try testing.expect(saw_reset);
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

        // Redirect stdout/stderr to pipe.
        posix.dup2(write_fd, posix.STDOUT_FILENO) catch std.process.exit(126);
        posix.dup2(write_fd, posix.STDERR_FILENO) catch std.process.exit(126);
        if (write_fd != posix.STDOUT_FILENO and write_fd != posix.STDERR_FILENO) {
            posix.close(write_fd);
        }

        // Run curl with:
        // -k: ignore self-signed cert
        // --http1.1: force h1 for TLS termination/origination tests
        // -s: silent mode
        // -S: show errors
        // -i: include headers in output
        // -m: timeout in seconds
        const argv = [_:null]?[*:0]const u8{
            "curl",
            "-k",
            "--http1.1",
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
        if (total > 0) {
            std.debug.print(
                "debug(curl-https): exit_status={d} exited_normally={} output=\n{s}\n",
                .{ wait_result.status, exited_normally, output_buf[0..total] },
            );
        } else {
            std.debug.print(
                "debug(curl-https): exit_status={d} exited_normally={} with empty output\n",
                .{ wait_result.status, exited_normally },
            );
        }
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

test "performance: lb h1 achieves minimum throughput with hey" {
    const allocator = testing.allocator;
    const perf_cfg = try loadPerfTestConfig(
        allocator,
        PERF_TEST_REQUESTS_H1,
        PERF_TEST_CONCURRENCY_H1,
        PERF_TEST_MIN_RPS_H1,
        PERF_TEST_ENV_REQUESTS_H1,
        PERF_TEST_ENV_CONCURRENCY_H1,
        PERF_TEST_ENV_MIN_RPS_H1,
    );

    if (!perf_cfg.enabled) {
        std.debug.print("SKIP: set {s}=1 to enable throughput perf gate\n", .{PERF_TEST_ENV_ENABLE});
        return error.SkipZigTest;
    }

    try runLbThroughputTest(allocator, perf_cfg, .h1);
}

test "performance: h2 conformance server achieves minimum throughput with h2load" {
    const allocator = testing.allocator;
    const perf_cfg = try loadPerfTestConfig(
        allocator,
        PERF_TEST_REQUESTS_H2,
        PERF_TEST_CONCURRENCY_H2,
        PERF_TEST_MIN_RPS_H2,
        PERF_TEST_ENV_REQUESTS_H2,
        PERF_TEST_ENV_CONCURRENCY_H2,
        PERF_TEST_ENV_MIN_RPS_H2,
    );

    if (!perf_cfg.enabled) {
        std.debug.print("SKIP: set {s}=1 to enable throughput perf gate\n", .{PERF_TEST_ENV_ENABLE});
        return error.SkipZigTest;
    }

    try runLbThroughputTest(allocator, perf_cfg, .h2);
}

const PerfTestProtocol = enum {
    h1,
    h2,
};

const PerfTestConfig = struct {
    enabled: bool,
    requests: u32,
    concurrency: u32,
    min_rps: f64,
    h2load_threads: u32,
    h2load_max_streams: u32,
    h2load_duration_s: u32,
};

fn runLbThroughputTest(
    allocator: std.mem.Allocator,
    perf_cfg: PerfTestConfig,
    protocol: PerfTestProtocol,
) !void {
    const backend_port = harness.getPort();
    const listener_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    var url_buf: [64]u8 = undefined;
    const url = switch (protocol) {
        .h1 => blk: {
            try pm.startEchoBackend(backend_port, "perf-backend", .{});

            var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
            const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;
            try pm.startLoadBalancer(listener_port, &.{backend_addr}, .{});

            break :blk std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/test", .{listener_port}) catch unreachable;
        },
        .h2 => blk: {
            const build_output = runCommandWithOutput(allocator, &.{ "zig", "build", "-Doptimize=ReleaseFast", "build-h2-conformance-server" }) catch |err| {
                std.debug.print("SKIP: failed to build h2 conformance server: {s}\n", .{@errorName(err)});
                return error.SkipZigTest;
            };
            allocator.free(build_output);

            try pm.startH2ConformanceServer(listener_port, harness.TEST_CERT_PATH, harness.TEST_KEY_PATH, false);

            break :blk std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/healthz", .{listener_port}) catch unreachable;
        },
    };

    var n_buf: [16]u8 = undefined;
    const n_arg = std.fmt.bufPrint(&n_buf, "{d}", .{perf_cfg.requests}) catch unreachable;

    var c_buf: [16]u8 = undefined;
    const c_arg = std.fmt.bufPrint(&c_buf, "{d}", .{perf_cfg.concurrency}) catch unreachable;

    var m_buf: [16]u8 = undefined;
    const m_arg = std.fmt.bufPrint(&m_buf, "{d}", .{perf_cfg.h2load_max_streams}) catch unreachable;

    var t_buf: [16]u8 = undefined;
    const t_arg = std.fmt.bufPrint(&t_buf, "{d}", .{perf_cfg.h2load_threads}) catch unreachable;

    var d_buf: [16]u8 = undefined;
    const d_arg = std.fmt.bufPrint(&d_buf, "{d}", .{perf_cfg.h2load_duration_s}) catch unreachable;

    const stdout = switch (protocol) {
        .h1 => runCommandWithOutput(allocator, &.{ "hey", "-n", n_arg, "-c", c_arg, url }) catch |err| {
            if (err == error.CommandNotFound) {
                std.debug.print("SKIP: 'hey' not installed\n", .{});
                return error.SkipZigTest;
            }
            return err;
        },
        .h2 => blk: {
            var args: std.ArrayList([]const u8) = .empty;
            defer args.deinit(allocator);

            try args.append(allocator, "env");
            try args.append(allocator, "SSL_CERT_FILE=" ++ harness.TEST_CERT_PATH);
            try args.append(allocator, "h2load");
            try args.append(allocator, "--alpn-list=h2");
            try args.append(allocator, "-c");
            try args.append(allocator, c_arg);
            try args.append(allocator, "-m");
            try args.append(allocator, m_arg);
            try args.append(allocator, "-t");
            try args.append(allocator, t_arg);

            if (perf_cfg.h2load_duration_s > 0) {
                try args.append(allocator, "-D");
                try args.append(allocator, d_arg);
            } else {
                try args.append(allocator, "-n");
                try args.append(allocator, n_arg);
            }

            try args.append(allocator, url);

            const output = runCommandWithOutput(allocator, args.items) catch |err| {
                if (err == error.CommandNotFound) {
                    std.debug.print("SKIP: 'h2load' not installed\n", .{});
                    return error.SkipZigTest;
                }
                return err;
            };
            break :blk output;
        },
    };
    defer allocator.free(stdout);

    const rps = switch (protocol) {
        .h1 => parseRequestsPerSec(stdout) orelse {
            std.debug.print("Failed to parse hey output:\n{s}\n", .{stdout});
            return error.TestUnexpectedResult;
        },
        .h2 => blk: {
            const summary = parseH2loadSummary(stdout) orelse {
                std.debug.print("Failed to parse h2load output:\n{s}\n", .{stdout});
                return error.TestUnexpectedResult;
            };

            if (summary.succeeded == 0) {
                std.debug.print("SKIP: h2load completed with zero successful requests (failed={d}, errored={d}, timeout={d})\n", .{ summary.failed, summary.errored, summary.timeout });
                return error.SkipZigTest;
            }

            break :blk summary.rps;
        },
    };

    const proto_name = switch (protocol) {
        .h1 => "h1",
        .h2 => "h2",
    };

    if (protocol == .h2) {
        if (perf_cfg.h2load_duration_s > 0) {
            std.debug.print(
                "\nPerformance ({s}): {d:.2} req/s (minimum: {d:.2}, duration_s={d}, concurrency={d}, h2load_threads={d}, h2load_max_streams={d})\n",
                .{ proto_name, rps, perf_cfg.min_rps, perf_cfg.h2load_duration_s, perf_cfg.concurrency, perf_cfg.h2load_threads, perf_cfg.h2load_max_streams },
            );
        } else {
            std.debug.print(
                "\nPerformance ({s}): {d:.2} req/s (minimum: {d:.2}, requests={d}, concurrency={d}, h2load_threads={d}, h2load_max_streams={d})\n",
                .{ proto_name, rps, perf_cfg.min_rps, perf_cfg.requests, perf_cfg.concurrency, perf_cfg.h2load_threads, perf_cfg.h2load_max_streams },
            );
        }
    } else {
        std.debug.print("\nPerformance ({s}): {d:.2} req/s (minimum: {d:.2}, requests={d}, concurrency={d})\n", .{ proto_name, rps, perf_cfg.min_rps, perf_cfg.requests, perf_cfg.concurrency });
    }

    try testing.expect(rps >= perf_cfg.min_rps);
}

fn loadPerfTestConfig(
    allocator: std.mem.Allocator,
    default_requests: u32,
    default_concurrency: u32,
    default_min_rps: f64,
    requests_env_name: []const u8,
    concurrency_env_name: []const u8,
    min_rps_env_name: []const u8,
) !PerfTestConfig {
    const enabled = try parseOptionalEnvBool(allocator, PERF_TEST_ENV_ENABLE) orelse false;
    const requests = try parseOptionalEnvU32(allocator, requests_env_name) orelse default_requests;
    const concurrency = try parseOptionalEnvU32(allocator, concurrency_env_name) orelse default_concurrency;
    const min_rps = try parseOptionalEnvF64(allocator, min_rps_env_name) orelse default_min_rps;
    const h2load_threads = try parseOptionalEnvU32(allocator, PERF_TEST_ENV_H2LOAD_THREADS) orelse PERF_TEST_H2LOAD_THREADS;
    const h2load_max_streams = try parseOptionalEnvU32(allocator, PERF_TEST_ENV_H2LOAD_MAX_STREAMS) orelse PERF_TEST_H2LOAD_MAX_CONCURRENT_STREAMS;
    const h2load_duration_s = try parseOptionalEnvU32(allocator, PERF_TEST_ENV_H2LOAD_DURATION_S) orelse PERF_TEST_H2LOAD_DURATION_S;

    if (enabled) {
        try testing.expect(requests > 0);
        try testing.expect(concurrency > 0);
        try testing.expect(min_rps > 0.0);
        try testing.expect(h2load_threads > 0);
        try testing.expect(h2load_max_streams > 0);
    }

    return .{
        .enabled = enabled,
        .requests = requests,
        .concurrency = concurrency,
        .min_rps = min_rps,
        .h2load_threads = h2load_threads,
        .h2load_max_streams = h2load_max_streams,
        .h2load_duration_s = h2load_duration_s,
    };
}

fn getEnvVarValue(name: []const u8) ?[]const u8 {
    var envp = posix.environPtr();
    while (envp[0]) |entry_z| : (envp += 1) {
        const entry = std.mem.span(entry_z);
        if (entry.len <= name.len) continue;
        if (entry[name.len] != '=') continue;
        if (!std.mem.eql(u8, entry[0..name.len], name)) continue;
        return entry[name.len + 1 ..];
    }
    return null;
}

fn parseOptionalEnvBool(_: std.mem.Allocator, name: []const u8) !?bool {
    const value = getEnvVarValue(name) orelse return null;

    if (std.mem.eql(u8, value, "1")) return true;
    if (std.mem.eql(u8, value, "0")) return false;

    if (std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "yes") or std.ascii.eqlIgnoreCase(value, "on")) {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(value, "false") or std.ascii.eqlIgnoreCase(value, "no") or std.ascii.eqlIgnoreCase(value, "off")) {
        return false;
    }

    std.debug.print("Invalid boolean env {s}={s} (expected 0/1/true/false)\n", .{ name, value });
    return error.InvalidEnvValue;
}

fn parseOptionalEnvU32(_: std.mem.Allocator, name: []const u8) !?u32 {
    const value = getEnvVarValue(name) orelse return null;

    return std.fmt.parseInt(u32, value, 10) catch {
        std.debug.print("Invalid integer env {s}={s}\n", .{ name, value });
        return error.InvalidEnvValue;
    };
}

fn parseOptionalEnvF64(_: std.mem.Allocator, name: []const u8) !?f64 {
    const value = getEnvVarValue(name) orelse return null;

    return std.fmt.parseFloat(f64, value) catch {
        std.debug.print("Invalid float env {s}={s}\n", .{ name, value });
        return error.InvalidEnvValue;
    };
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

        // Redirect stdout/stderr to pipe so failures include diagnostics.
        posix.dup2(write_fd, posix.STDOUT_FILENO) catch std.process.exit(126);
        posix.dup2(write_fd, posix.STDERR_FILENO) catch std.process.exit(126);
        posix.close(write_fd);

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

    // Read all stdout/stderr
    var output: std.ArrayList(u8) = .empty;
    var output_released = false;
    defer {
        if (!output_released and output.capacity > 0) {
            output.deinit(allocator);
        }
    }

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
            return error.CommandNotFound;
        }
        if (exit_code != 0) {
            if (output.items.len > 0) {
                std.debug.print("command failed (exit={d}):\n{s}\n", .{ exit_code, output.items });
            } else {
                std.debug.print("command failed (exit={d}) with no output\n", .{exit_code});
            }
            return error.CommandFailed;
        }
    }

    const owned = try output.toOwnedSlice(allocator);
    output_released = true;
    return owned;
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

const H2loadSummary = struct {
    rps: f64,
    succeeded: u64,
    failed: u64,
    errored: u64,
    timeout: u64,
};

/// Parse h2load summary lines:
/// - "finished in <dur>, <rps> req/s, <throughput>"
/// - "requests: <total> total, ... <succeeded> succeeded, <failed> failed, <errored> errored, <timeout> timeout"
fn parseH2loadSummary(output: []const u8) ?H2loadSummary {
    var maybe_rps: ?f64 = null;
    var maybe_succeeded: ?u64 = null;
    var maybe_failed: ?u64 = null;
    var maybe_errored: ?u64 = null;
    var maybe_timeout: ?u64 = null;

    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "finished in ")) {
            const req_s_idx = std.mem.indexOf(u8, line, " req/s") orelse continue;
            const prefix = line[0..req_s_idx];
            const comma_idx = std.mem.lastIndexOfScalar(u8, prefix, ',') orelse continue;
            const value_region = std.mem.trim(u8, prefix[comma_idx + 1 ..], " \t");
            if (value_region.len == 0) continue;
            maybe_rps = std.fmt.parseFloat(f64, value_region) catch null;
            continue;
        }

        if (std.mem.startsWith(u8, line, "requests:")) {
            maybe_succeeded = parseH2loadRequestCounter(line, " succeeded");
            maybe_failed = parseH2loadRequestCounter(line, " failed");
            maybe_errored = parseH2loadRequestCounter(line, " errored");
            maybe_timeout = parseH2loadRequestCounter(line, " timeout");
            continue;
        }
    }

    return .{
        .rps = maybe_rps orelse return null,
        .succeeded = maybe_succeeded orelse return null,
        .failed = maybe_failed orelse return null,
        .errored = maybe_errored orelse return null,
        .timeout = maybe_timeout orelse return null,
    };
}

fn parseH2loadRequestCounter(line: []const u8, suffix: []const u8) ?u64 {
    const suffix_idx = std.mem.indexOf(u8, line, suffix) orelse return null;
    const before_suffix = line[0..suffix_idx];

    var start = before_suffix.len;
    while (start > 0 and before_suffix[start - 1] >= '0' and before_suffix[start - 1] <= '9') {
        start -= 1;
    }
    if (start == before_suffix.len) return null;

    return std.fmt.parseInt(u64, before_suffix[start..], 10) catch null;
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
    try pm.startEchoBackend(backend_port, "100mb-backend", .{
        .echo_body = true,
        .debug = true,
    });

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

test "integration: lb forwards generated payload stream correctly" {
    const allocator = testing.allocator;
    const backend_port = harness.getPort();
    const lb_port = harness.getPort();

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Echo body mode verifies byte-for-byte forwarding with generated payload stream.
    try pm.startEchoBackend(backend_port, "generated-stream-backend", .{
        .echo_body = true,
        .debug = true,
    });

    var backend_addr_buf: [ADDR_BUF_LEN]u8 = undefined;
    const backend_addr = std.fmt.bufPrint(&backend_addr_buf, "127.0.0.1:{d}", .{backend_port}) catch unreachable;

    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});

    var client = harness.TestClient.init(allocator);
    defer client.deinit();

    const response = try client.postLargeGenerated(
        lb_port,
        "/big-payload",
        BIG_PAYLOAD_SIZE_16MB,
        0xAB,
        "application/octet-stream",
    );
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqual(@as(usize, BIG_PAYLOAD_SIZE_16MB), response.body.len);

    var index: usize = 0;
    while (index < response.body.len) : (index += 1) {
        try testing.expectEqual(@as(u8, 0xAB), response.body[index]);
    }
}

test "integration: lb forwards 5GB payload correctly" {
    // This test validates that files >4GB work correctly.
    // It is opt-in because full 5GB loopback transfer can be very slow/flaky on
    // constrained CI/workstations and may appear hung for long periods.
    // Enable with: SERVAL_RUN_5GB_TEST=1
    const run_5gb_env = std.c.getenv("SERVAL_RUN_5GB_TEST");
    if (run_5gb_env == null or !std.mem.eql(u8, std.mem.span(run_5gb_env.?), "1")) {
        return error.SkipZigTest;
    }

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

    // Send through load balancer using generated streaming payload.
    // Why: avoids 5GB allocation pressure and reduces OOM/flaky behavior.
    std.debug.print("[DEBUG 5GB test] sending generated request\n", .{});
    const response = try client.postLargeGenerated(
        lb_port,
        "/big-payload",
        BIG_PAYLOAD_SIZE_5GB,
        0xAB,
        "application/octet-stream",
    );
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

const UdpRuntimeServerShared = struct {
    runtime: serval.server.frontend.UdpRuntime,
    shutdown: std.atomic.Value(bool),
    listener_fd: std.atomic.Value(i32),
};

const UdpRuntimeServer = struct {
    shared: *UdpRuntimeServerShared,
    thread: ?std.Thread,

    fn start(cfg: serval.config.UdpTransportConfig) !UdpRuntimeServer {
        const shared = try std.heap.page_allocator.create(UdpRuntimeServerShared);
        errdefer std.heap.page_allocator.destroy(shared);

        shared.* = .{
            .runtime = undefined,
            .shutdown = std.atomic.Value(bool).init(false),
            .listener_fd = std.atomic.Value(i32).init(-1),
        };

        try shared.runtime.init(cfg, .{});

        var server = UdpRuntimeServer{ .shared = shared, .thread = null };
        server.thread = try std.Thread.spawn(.{}, udpRuntimeServerMain, .{shared});

        var wait_iters: u32 = 0;
        while (wait_iters < 50) : (wait_iters += 1) {
            if (shared.listener_fd.load(.acquire) >= 0) break;
            posix.nanosleep(0, 10 * std.time.ns_per_ms);
        }
        if (shared.listener_fd.load(.acquire) < 0) return error.ListenerNotReady;

        return server;
    }

    fn stop(self: *UdpRuntimeServer) void {
        self.shared.shutdown.store(true, .release);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        std.heap.page_allocator.destroy(self.shared);
    }
};

fn udpRuntimeServerMain(shared: *UdpRuntimeServerShared) void {
    assert(@intFromPtr(shared) != 0);

    var io_runtime = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_runtime.deinit();

    shared.runtime.run(io_runtime.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
        std.log.err("udp runtime integration server failed: {s}", .{@errorName(err)});
    };
}

const UdpEchoServerConfig = struct {
    port: u16,
    shutdown: *std.atomic.Value(bool),
};

fn udpEchoServerMain(config: UdpEchoServerConfig) void {
    const sock = createUdpSocketBoundLoopback(config.port) catch {
        return;
    };
    defer posix.close(sock);

    var recv_buf: [512]u8 = undefined;
    var from_addr: std.posix.sockaddr.in = undefined;

    while (!config.shutdown.load(.acquire)) {
        var poll_fds = [_]std.posix.pollfd{.{
            .fd = sock,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};

        const ready = std.posix.poll(&poll_fds, 100) catch {
            continue;
        };
        if (ready == 0) continue;

        var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        const n = c.recvfrom(sock, &recv_buf, recv_buf.len, 0, @ptrCast(&from_addr), &from_len);
        switch (c.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => continue,
        }

        const sent = c.sendto(sock, &recv_buf, @intCast(n), 0, @ptrCast(&from_addr), from_len);
        if (c.errno(sent) != .SUCCESS) continue;
    }
}

fn createUdpSocketBoundLoopback(port: u16) !std.posix.socket_t {
    const sock = try posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    errdefer posix.close(sock);

    const addr: std.posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, LOOPBACK_IPV4_BE),
    };

    const bind_rc = c.bind(sock, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.in));
    switch (c.errno(bind_rc)) {
        .SUCCESS => return sock,
        else => return error.BindFailed,
    }
}

fn sendUdpDatagram(sock: std.posix.socket_t, port: u16, payload: []const u8) !void {
    assert(payload.len > 0);

    const dest: std.posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, LOOPBACK_IPV4_BE),
    };

    const sent = c.sendto(sock, payload.ptr, payload.len, 0, @ptrCast(&dest), @sizeOf(std.posix.sockaddr.in));
    switch (c.errno(sent)) {
        .SUCCESS => {
            if (@as(usize, @intCast(sent)) != payload.len) return error.PartialSend;
        },
        else => return error.SendFailed,
    }
}

fn recvUdpDatagramWithTimeout(sock: std.posix.socket_t, buf: []u8, timeout_ms: i32) !?usize {
    assert(buf.len > 0);
    assert(timeout_ms > 0);

    var poll_fds = [_]std.posix.pollfd{.{
        .fd = sock,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&poll_fds, timeout_ms);
    if (ready == 0) return null;

    const n = c.recvfrom(sock, buf.ptr, buf.len, 0, null, null);
    switch (c.errno(n)) {
        .SUCCESS => return @intCast(n),
        else => return error.RecvFailed,
    }
}

test "integration: udp runtime forwards ingress and egress datagrams" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};

    var server = try UdpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_active_sessions = 16,
        .session_idle_timeout_ms = 5000,
    });
    defer server.stop();

    var upstream_shutdown = std.atomic.Value(bool).init(false);
    const upstream_thread = try std.Thread.spawn(.{}, udpEchoServerMain, .{UdpEchoServerConfig{
        .port = upstream_port,
        .shutdown = &upstream_shutdown,
    }});
    defer {
        upstream_shutdown.store(true, .release);
        upstream_thread.join();
    }

    const client_sock = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_sock);

    try sendUdpDatagram(client_sock, listener_port, "ping");

    var recv_buf: [64]u8 = undefined;
    const maybe_n = try recvUdpDatagramWithTimeout(client_sock, &recv_buf, 1000);
    try testing.expect(maybe_n != null);
    const n = maybe_n orelse unreachable;
    try testing.expectEqualStrings("ping", recv_buf[0..n]);

    try testing.expect(server.shared.runtime.packetsForwardedUpstream() >= 1);
    try testing.expect(server.shared.runtime.packetsForwardedDownstream() >= 1);
}

test "integration: udp runtime capacity drop preserves existing session forwarding" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};

    var server = try UdpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_active_sessions = 1,
        .session_idle_timeout_ms = 5000,
    });
    defer server.stop();

    var upstream_shutdown = std.atomic.Value(bool).init(false);
    const upstream_thread = try std.Thread.spawn(.{}, udpEchoServerMain, .{UdpEchoServerConfig{
        .port = upstream_port,
        .shutdown = &upstream_shutdown,
    }});
    defer {
        upstream_shutdown.store(true, .release);
        upstream_thread.join();
    }

    const client_a = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_a);
    const client_b = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_b);

    try sendUdpDatagram(client_a, listener_port, "a1");
    var buf_a: [64]u8 = undefined;
    const maybe_a1 = try recvUdpDatagramWithTimeout(client_a, &buf_a, 1000);
    try testing.expect(maybe_a1 != null);

    try sendUdpDatagram(client_b, listener_port, "b1");
    var buf_b: [64]u8 = undefined;
    const maybe_b1 = try recvUdpDatagramWithTimeout(client_b, &buf_b, 300);
    try testing.expect(maybe_b1 == null);

    try sendUdpDatagram(client_a, listener_port, "a2");
    const maybe_a2 = try recvUdpDatagramWithTimeout(client_a, &buf_a, 1000);
    try testing.expect(maybe_a2 != null);
    const n2 = maybe_a2 orelse unreachable;
    try testing.expectEqualStrings("a2", buf_a[0..n2]);

    try testing.expect(server.shared.runtime.droppedAtSessionCapacity() >= 1);
}

test "integration: udp runtime key mode five_tuple enforces per-endpoint session capacity" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};

    var server = try UdpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_active_sessions = 1,
        .session_idle_timeout_ms = 5000,
        .session_key_mode = .five_tuple,
    });
    defer server.stop();

    var upstream_shutdown = std.atomic.Value(bool).init(false);
    const upstream_thread = try std.Thread.spawn(.{}, udpEchoServerMain, .{UdpEchoServerConfig{
        .port = upstream_port,
        .shutdown = &upstream_shutdown,
    }});
    defer {
        upstream_shutdown.store(true, .release);
        upstream_thread.join();
    }

    const client_a = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_a);
    const client_b = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_b);

    try sendUdpDatagram(client_a, listener_port, "f1");
    var recv_a: [32]u8 = undefined;
    const a1 = try recvUdpDatagramWithTimeout(client_a, &recv_a, 1000);
    try testing.expect(a1 != null);

    try sendUdpDatagram(client_b, listener_port, "f2");
    var recv_b: [32]u8 = undefined;
    const b1 = try recvUdpDatagramWithTimeout(client_b, &recv_b, 300);
    try testing.expect(b1 == null);

    try testing.expect(server.shared.runtime.droppedAtSessionCapacity() >= 1);
}

test "integration: udp runtime key mode source_endpoint reuses session for repeated source endpoint" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};

    var server = try UdpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_active_sessions = 1,
        .session_idle_timeout_ms = 5000,
        .session_key_mode = .source_endpoint,
    });
    defer server.stop();

    var upstream_shutdown = std.atomic.Value(bool).init(false);
    const upstream_thread = try std.Thread.spawn(.{}, udpEchoServerMain, .{UdpEchoServerConfig{
        .port = upstream_port,
        .shutdown = &upstream_shutdown,
    }});
    defer {
        upstream_shutdown.store(true, .release);
        upstream_thread.join();
    }

    const client = try createUdpSocketBoundLoopback(0);
    defer posix.close(client);

    try sendUdpDatagram(client, listener_port, "s1");
    var recv_buf: [32]u8 = undefined;
    const first = try recvUdpDatagramWithTimeout(client, &recv_buf, 1000);
    try testing.expect(first != null);

    try sendUdpDatagram(client, listener_port, "s2");
    const second = try recvUdpDatagramWithTimeout(client, &recv_buf, 1000);
    try testing.expect(second != null);

    try testing.expectEqual(@as(u64, 1), server.shared.runtime.sessionCreationCount());
    try testing.expectEqual(@as(u64, 0), server.shared.runtime.droppedAtSessionCapacity());
}

test "integration: udp runtime key mode source_ip groups distinct source ports" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};

    var server = try UdpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_active_sessions = 1,
        .session_idle_timeout_ms = 5000,
        .session_key_mode = .source_ip,
    });
    defer server.stop();

    var upstream_shutdown = std.atomic.Value(bool).init(false);
    const upstream_thread = try std.Thread.spawn(.{}, udpEchoServerMain, .{UdpEchoServerConfig{
        .port = upstream_port,
        .shutdown = &upstream_shutdown,
    }});
    defer {
        upstream_shutdown.store(true, .release);
        upstream_thread.join();
    }

    const client_a = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_a);
    const client_b = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_b);

    try sendUdpDatagram(client_a, listener_port, "i1");
    var recv_a: [32]u8 = undefined;
    const a1 = try recvUdpDatagramWithTimeout(client_a, &recv_a, 1000);
    try testing.expect(a1 != null);

    try sendUdpDatagram(client_b, listener_port, "i2");
    var recv_b: [32]u8 = undefined;
    const b1 = try recvUdpDatagramWithTimeout(client_b, &recv_b, 300);
    try testing.expect(b1 == null);

    const a2 = try recvUdpDatagramWithTimeout(client_a, &recv_a, 1000);
    try testing.expect(a2 != null);
    const n2 = a2 orelse unreachable;
    try testing.expectEqualStrings("i2", recv_a[0..n2]);

    try testing.expectEqual(@as(u64, 1), server.shared.runtime.sessionCreationCount());
    try testing.expectEqual(@as(u64, 0), server.shared.runtime.droppedAtSessionCapacity());
}

test "integration: udp runtime expires idle session and admits new source" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};

    var server = try UdpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_active_sessions = 1,
        .session_idle_timeout_ms = 100,
        .session_key_mode = .five_tuple,
    });
    defer server.stop();

    var upstream_shutdown = std.atomic.Value(bool).init(false);
    const upstream_thread = try std.Thread.spawn(.{}, udpEchoServerMain, .{UdpEchoServerConfig{
        .port = upstream_port,
        .shutdown = &upstream_shutdown,
    }});
    defer {
        upstream_shutdown.store(true, .release);
        upstream_thread.join();
    }

    const client_a = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_a);
    const client_b = try createUdpSocketBoundLoopback(0);
    defer posix.close(client_b);

    try sendUdpDatagram(client_a, listener_port, "e1");
    var recv_a: [32]u8 = undefined;
    const first = try recvUdpDatagramWithTimeout(client_a, &recv_a, 1000);
    try testing.expect(first != null);

    posix.nanosleep(0, 350 * std.time.ns_per_ms);

    try sendUdpDatagram(client_b, listener_port, "e2");
    var recv_b: [32]u8 = undefined;
    const second = try recvUdpDatagramWithTimeout(client_b, &recv_b, 1000);
    try testing.expect(second != null);

    try testing.expect(server.shared.runtime.sessionExpirationCount() >= 1);
    try testing.expect(server.shared.runtime.sessionCreationCount() >= 2);
}

const TcpRuntimeServerShared = struct {
    runtime: serval.server.frontend.TcpRuntime,
    shutdown: std.atomic.Value(bool),
    listener_fd: std.atomic.Value(i32),
};

const TcpRuntimeServer = struct {
    shared: *TcpRuntimeServerShared,
    thread: ?std.Thread,

    fn start(cfg: serval.config.TcpTransportConfig) !TcpRuntimeServer {
        return startWithTls(cfg, null, true);
    }

    fn startWithTls(cfg: serval.config.TcpTransportConfig, client_ctx: ?*ssl.SSL_CTX, verify_upstream_tls: bool) !TcpRuntimeServer {
        const shared = try std.heap.page_allocator.create(TcpRuntimeServerShared);
        errdefer std.heap.page_allocator.destroy(shared);

        shared.* = .{
            .runtime = undefined,
            .shutdown = std.atomic.Value(bool).init(false),
            .listener_fd = std.atomic.Value(i32).init(-1),
        };

        try shared.runtime.init(cfg, .{}, client_ctx, verify_upstream_tls);

        var server = TcpRuntimeServer{ .shared = shared, .thread = null };
        server.thread = try std.Thread.spawn(.{}, tcpRuntimeServerMain, .{shared});

        var wait_iters: u32 = 0;
        while (wait_iters < 100) : (wait_iters += 1) {
            if (shared.listener_fd.load(.acquire) >= 0) break;
            posix.nanosleep(0, 10 * std.time.ns_per_ms);
        }
        if (shared.listener_fd.load(.acquire) < 0) return error.ListenerNotReady;

        return server;
    }

    fn stop(self: *TcpRuntimeServer, wake_port: u16) void {
        self.shared.shutdown.store(true, .release);
        const wake_sock = connectTcp(wake_port) catch null;
        if (wake_sock) |sock| posix.close(sock);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        std.heap.page_allocator.destroy(self.shared);
    }
};

fn tcpRuntimeServerMain(shared: *TcpRuntimeServerShared) void {
    assert(@intFromPtr(shared) != 0);

    var evented: std.Io.Evented = undefined;
    init_test_io_runtime(&evented, std.heap.page_allocator) catch |err| {
        std.log.err("tcp runtime integration io init failed: {s}", .{@errorName(err)});
        return;
    };
    defer evented.deinit();

    shared.runtime.run(evented.io(), &shared.shutdown, &shared.listener_fd) catch |err| {
        std.log.err("tcp runtime integration server failed: {s}", .{@errorName(err)});
    };
}

const TcpBackendMode = enum { echo, hold, banner_then_hold };

const TcpBackendServerConfig = struct {
    port: u16,
    mode: TcpBackendMode,
    shutdown: *std.atomic.Value(bool),
};

const TlsBackendServerConfig = struct {
    port: u16,
    shutdown: *std.atomic.Value(bool),
    accepts: *std.atomic.Value(u32),
};

fn tcpHoldConnectionWorker(conn: posix.socket_t, shutdown: *std.atomic.Value(bool)) void {
    assert(conn >= 0);
    assert(@intFromPtr(shutdown) != 0);

    defer posix.close(conn);
    while (!shutdown.load(.acquire)) {
        posix.nanosleep(0, 10 * std.time.ns_per_ms);
    }
}

fn waitForTcpServerReady(port: u16, max_attempts: u32) bool {
    assert(port > 0);
    assert(max_attempts > 0);

    var attempts: u32 = 0;
    while (attempts < max_attempts) : (attempts += 1) {
        const sock = connectTcp(port) catch {
            posix.nanosleep(0, 10 * std.time.ns_per_ms);
            continue;
        };
        posix.close(sock);
        return true;
    }

    return false;
}

fn shutdownWriteTcp(sock: posix.socket_t) !void {
    assert(sock >= 0);

    const rc = c.shutdown(sock, @intCast(std.posix.SHUT.WR));
    switch (c.errno(rc)) {
        .SUCCESS => return,
        .INTR => return error.Interrupted,
        else => return error.ShutdownFailed,
    }
}

fn tcpBackendServerMain(config: TcpBackendServerConfig) void {
    const listener = createTcpListener(config.port) catch return;
    defer posix.close(listener);

    while (!config.shutdown.load(.acquire)) {
        var poll_fds = [_]std.posix.pollfd{.{
            .fd = listener,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&poll_fds, 100) catch continue;
        if (ready == 0) continue;

        const conn = acceptTcp(listener) catch continue;

        switch (config.mode) {
            .echo => {
                var buf: [256]u8 = undefined;
                const n = posix.recv(conn, &buf, 0) catch {
                    posix.close(conn);
                    continue;
                };
                if (n > 0) {
                    _ = posix.send(conn, buf[0..n], 0) catch {
                        posix.close(conn);
                        continue;
                    };
                }
                posix.close(conn);
            },
            .hold => {
                const worker = std.Thread.spawn(.{}, tcpHoldConnectionWorker, .{ conn, config.shutdown }) catch {
                    posix.close(conn);
                    continue;
                };
                worker.detach();
            },
            .banner_then_hold => {
                _ = posix.send(conn, "up", 0) catch {
                    posix.close(conn);
                    continue;
                };
                const worker = std.Thread.spawn(.{}, tcpHoldConnectionWorker, .{ conn, config.shutdown }) catch {
                    posix.close(conn);
                    continue;
                };
                worker.detach();
            },
        }
    }
}

fn tlsBackendServerMain(config: TlsBackendServerConfig) void {
    assert(@intFromPtr(config.shutdown) != 0);
    assert(@intFromPtr(config.accepts) != 0);

    const tls_ctx = createTestServerTlsCtx() catch return;
    defer ssl.SSL_CTX_free(tls_ctx);

    const listener = createTcpListener(config.port) catch return;
    defer posix.close(listener);

    while (!config.shutdown.load(.acquire)) {
        var poll_fds = [_]std.posix.pollfd{.{
            .fd = listener,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&poll_fds, 100) catch continue;
        if (ready == 0) continue;

        const conn = acceptTcp(listener) catch continue;
        _ = config.accepts.fetchAdd(1, .seq_cst);
        var tls_stream = serval_tls.TLSStream.initServer(tls_ctx, conn, std.heap.page_allocator) catch {
            posix.close(conn);
            continue;
        };

        tls_stream.close();
        posix.close(conn);
    }
}

test "integration: tcp runtime accepts downstream and records upstream outcome" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    var backend_shutdown = std.atomic.Value(bool).init(false);
    const backend_thread = try std.Thread.spawn(.{}, tcpBackendServerMain, .{TcpBackendServerConfig{
        .port = upstream_port,
        .mode = .hold,
        .shutdown = &backend_shutdown,
    }});
    defer {
        backend_shutdown.store(true, .release);
        _ = connectTcp(upstream_port) catch null;
        backend_thread.join();
    }

    try testing.expect(waitForTcpServerReady(upstream_port, 100));

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};
    var server = try TcpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_concurrent_connections = 8,
        .connect_timeout_ms = 1000,
        .idle_timeout_ms = 1000,
        .tls_mode = .passthrough,
    });
    defer server.stop(listener_port);

    const client = try connectTcp(listener_port);
    defer posix.close(client);

    var wait_iters: u32 = 0;
    while (wait_iters < 200 and server.shared.runtime.acceptedCount() == 0) : (wait_iters += 1) {
        posix.nanosleep(0, 10 * std.time.ns_per_ms);
    }

    try testing.expect(server.shared.runtime.acceptedCount() >= 1);
    posix.nanosleep(1, 200 * std.time.ns_per_ms);
    try testing.expect(server.shared.runtime.connectFailureCount() > 0 or server.shared.runtime.upstreamBytes() > 0);
}

test "integration: tcp runtime enforces bounded behavior under concurrent connects" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    var backend_shutdown = std.atomic.Value(bool).init(false);
    const backend_thread = try std.Thread.spawn(.{}, tcpBackendServerMain, .{TcpBackendServerConfig{
        .port = upstream_port,
        .mode = .hold,
        .shutdown = &backend_shutdown,
    }});
    defer {
        backend_shutdown.store(true, .release);
        _ = connectTcp(upstream_port) catch null;
        backend_thread.join();
    }

    try testing.expect(waitForTcpServerReady(upstream_port, 100));

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};
    var server = try TcpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_concurrent_connections = 1,
        .connect_timeout_ms = 1000,
        .idle_timeout_ms = 10000,
        .tls_mode = .passthrough,
    });
    defer server.stop(listener_port);

    const client_a = try connectTcp(listener_port);
    defer posix.close(client_a);

    posix.nanosleep(0, 50 * std.time.ns_per_ms);

    const client_b = try connectTcp(listener_port);
    defer posix.close(client_b);

    var wait_iters: u32 = 0;
    while (wait_iters < 150 and server.shared.runtime.rejectedCount() == 0 and server.shared.runtime.connectFailureCount() == 0) : (wait_iters += 1) {
        posix.nanosleep(0, 10 * std.time.ns_per_ms);
    }

    const rejected = server.shared.runtime.rejectedCount();
    const connect_failures = server.shared.runtime.connectFailureCount();
    try testing.expect(rejected > 0 or connect_failures > 0);
    try testing.expect(server.shared.runtime.activeCount() <= 1);
}

test "integration: tcp runtime handles downstream half-close without hanging" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    var backend_shutdown = std.atomic.Value(bool).init(false);
    const backend_thread = try std.Thread.spawn(.{}, tcpBackendServerMain, .{TcpBackendServerConfig{
        .port = upstream_port,
        .mode = .hold,
        .shutdown = &backend_shutdown,
    }});
    defer {
        backend_shutdown.store(true, .release);
        _ = connectTcp(upstream_port) catch null;
        backend_thread.join();
    }

    try testing.expect(waitForTcpServerReady(upstream_port, 100));

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};
    var server = try TcpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_concurrent_connections = 4,
        .connect_timeout_ms = 1000,
        .idle_timeout_ms = 250,
        .tls_mode = .passthrough,
    });
    defer server.stop(listener_port);

    const client = try connectTcp(listener_port);
    defer posix.close(client);

    try sendAllTcp(client, "half");

    var shutdown_attempts: u32 = 0;
    var shutdown_done = false;
    while (shutdown_attempts < 5) : (shutdown_attempts += 1) {
        shutdownWriteTcp(client) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };
        shutdown_done = true;
        break;
    }
    try testing.expect(shutdown_done);

    var closed = false;
    var probe_iters: u32 = 0;
    while (probe_iters < 120) : (probe_iters += 1) {
        var poll_fds = [_]std.posix.pollfd{.{
            .fd = client,
            .events = std.posix.POLL.IN | std.posix.POLL.HUP,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&poll_fds, 20);
        if (ready == 0) continue;

        var recv_buf: [8]u8 = undefined;
        const n = posix.recv(client, &recv_buf, 0) catch {
            closed = true;
            break;
        };
        if (n == 0) {
            closed = true;
            break;
        }
    }

    try testing.expect(closed);
    try testing.expect(server.shared.runtime.acceptedCount() >= 1);
}

test "integration: tcp runtime idle timeout closes inactive tunnel" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    var backend_shutdown = std.atomic.Value(bool).init(false);
    const backend_thread = try std.Thread.spawn(.{}, tcpBackendServerMain, .{TcpBackendServerConfig{
        .port = upstream_port,
        .mode = .hold,
        .shutdown = &backend_shutdown,
    }});
    defer {
        backend_shutdown.store(true, .release);
        _ = connectTcp(upstream_port) catch null;
        backend_thread.join();
    }

    try testing.expect(waitForTcpServerReady(upstream_port, 100));

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port }};
    var server = try TcpRuntimeServer.start(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_concurrent_connections = 4,
        .connect_timeout_ms = 1000,
        .idle_timeout_ms = 150,
        .tls_mode = .passthrough,
    });
    defer server.stop(listener_port);

    const client = try connectTcp(listener_port);
    defer posix.close(client);

    var closed = false;
    var probe_iters: u32 = 0;
    while (probe_iters < 80) : (probe_iters += 1) {
        var poll_fds = [_]std.posix.pollfd{.{
            .fd = client,
            .events = std.posix.POLL.IN | std.posix.POLL.HUP,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&poll_fds, 20);
        if (ready > 0) {
            var recv_buf: [8]u8 = undefined;
            const n = posix.recv(client, &recv_buf, 0) catch {
                closed = true;
                break;
            };
            if (n == 0) {
                closed = true;
                break;
            }
        }
    }

    try testing.expect(closed);
}

test "integration: tcp runtime originate_tls establishes TLS upstream" {
    const listener_port = harness.getPort();
    const upstream_port = harness.getPort();

    var tls_backend_shutdown = std.atomic.Value(bool).init(false);
    var tls_accepts = std.atomic.Value(u32).init(0);
    const tls_backend_thread = try std.Thread.spawn(.{}, tlsBackendServerMain, .{TlsBackendServerConfig{
        .port = upstream_port,
        .shutdown = &tls_backend_shutdown,
        .accepts = &tls_accepts,
    }});
    defer {
        tls_backend_shutdown.store(true, .release);
        const wake_tls = connectTcpTls(upstream_port, null) catch null;
        if (wake_tls) |socket| {
            var close_socket = socket;
            close_socket.close();
        }
        tls_backend_thread.join();
    }

    posix.nanosleep(0, 50 * std.time.ns_per_ms);

    var readiness_socket = try connectTcpTls(upstream_port, null);
    readiness_socket.close();

    var ready_iters: u32 = 0;
    while (ready_iters < 100 and tls_accepts.load(.acquire) == 0) : (ready_iters += 1) {
        posix.nanosleep(0, 10 * std.time.ns_per_ms);
    }
    const baseline_accepts = tls_accepts.load(.acquire);
    try testing.expect(baseline_accepts >= 1);

    ssl.init();
    const client_ctx = try ssl.createClientCtx();
    defer ssl.SSL_CTX_free(client_ctx);
    ssl.SSL_CTX_set_verify(client_ctx, ssl.SSL_VERIFY_NONE, null);

    const upstreams = [_]serval.config.L4Target{.{ .host = "127.0.0.1", .port = upstream_port, .tls = false }};
    var server = try TcpRuntimeServer.startWithTls(.{
        .enabled = true,
        .listener_host = "127.0.0.1",
        .listener_port = listener_port,
        .upstreams = &upstreams,
        .max_concurrent_connections = 4,
        .connect_timeout_ms = 1000,
        .idle_timeout_ms = 1000,
        .tls_mode = .originate_tls,
    }, client_ctx, false);
    defer server.stop(listener_port);

    const client = try connectTcp(listener_port);
    defer posix.close(client);

    var wait_iters: u32 = 0;
    while (wait_iters < 200 and server.shared.runtime.acceptedCount() == 0) : (wait_iters += 1) {
        posix.nanosleep(0, 10 * std.time.ns_per_ms);
    }

    try testing.expect(server.shared.runtime.acceptedCount() >= 1);
    try testing.expect(tls_accepts.load(.acquire) >= baseline_accepts);
    try testing.expect(server.shared.runtime.connectFailureCount() <= server.shared.runtime.acceptedCount());
}
