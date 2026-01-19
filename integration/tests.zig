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
const posix = std.posix;
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
        const env: [*:null]const ?[*:0]const u8 = @ptrCast(std.os.environ.ptr);
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

    // Skip if kTLS kernel module is not loaded
    if (!harness.isKtlsAvailable()) {
        std.debug.print("SKIP: kTLS kernel module not loaded\n", .{});
        return error.SkipZigTest;
    }

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

    // Skip if kTLS kernel module is not loaded
    if (!harness.isKtlsAvailable()) {
        std.debug.print("SKIP: kTLS kernel module not loaded\n", .{});
        return error.SkipZigTest;
    }

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

    // Skip if kTLS kernel module is not loaded
    if (!harness.isKtlsAvailable()) {
        std.debug.print("SKIP: kTLS kernel module not loaded\n", .{});
        return error.SkipZigTest;
    }

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

    // Skip if kTLS kernel module is not loaded
    if (!harness.isKtlsAvailable()) {
        std.debug.print("SKIP: kTLS kernel module not loaded\n", .{});
        return error.SkipZigTest;
    }

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

    // Skip if kTLS kernel module is not loaded
    if (!harness.isKtlsAvailable()) {
        std.debug.print("SKIP: kTLS kernel module not loaded\n", .{});
        return error.SkipZigTest;
    }

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
        const env: [*:null]const ?[*:0]const u8 = @ptrCast(std.os.environ.ptr);
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

// Note: 5GB integration test removed - requires streaming body consumption which
// the current server infrastructure doesn't support for handler direct responses.
// The iteration limit fix is verified by unit tests in serval-proxy/h1/body.zig.
// TigerStyle: max_iterations derived from content_length supports arbitrarily large files.

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
        const env: [*:null]const ?[*:0]const u8 = @ptrCast(std.os.environ.ptr);
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
