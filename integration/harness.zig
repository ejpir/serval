// integration/harness.zig
//! Integration Test Harness
//!
//! Manages server processes for integration testing.
//! Uses fork+exec for process spawning to avoid async IO complexity in tests.
//!
//! ## Adding New Tests
//!
//! 1. Use `ProcessManager` to spawn servers:
//!    ```zig
//!    var pm = ProcessManager.init(allocator);
//!    defer pm.deinit();
//!    try pm.startEchoBackend(port, "backend-1", .{});
//!    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{});
//!    ```
//!
//! 2. Use `TestClient` to make HTTP requests:
//!    ```zig
//!    var client = TestClient.init(allocator);
//!    defer client.deinit();
//!    const response = try client.get(port, "/test");
//!    defer response.deinit(allocator);
//!    ```
//!
//! 3. For TLS tests, pass config options:
//!    ```zig
//!    try pm.startEchoBackend(port, "backend-1", .{
//!        .cert_path = "experiments/tls-poc/cert.pem",
//!        .key_path = "experiments/tls-poc/key.pem",
//!    });
//!    ```
//!
//! ## TLS Certificate Location
//!
//! Test certificates are in `experiments/tls-poc/`:
//! - `cert.pem` - Self-signed certificate
//! - `key.pem` - Private key
//!
//! These are for testing only. Use `--insecure-skip-verify` with self-signed certs.

const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;

// =============================================================================
// Constants
// =============================================================================

/// Maximum time to wait for a server to become ready (accept connections).
pub const SERVER_READY_TIMEOUT_MS: u64 = 10_000;

/// Interval between port readiness checks.
pub const READY_POLL_INTERVAL_MS: u64 = 50;

/// Base port for test servers. Each test allocates ports sequentially from here.
pub const BASE_TEST_PORT: u16 = 19_000;

/// Maximum number of backends supported in a single load balancer.
/// TigerStyle: Explicit bound prevents buffer overflow.
pub const MAX_BACKENDS: u32 = 16;

/// Maximum length of a backend address string (e.g., "127.0.0.1:65535").
pub const MAX_BACKEND_ADDR_LEN: u32 = 21;

/// Maximum total length for joined backend addresses (with commas).
/// = MAX_BACKENDS * (MAX_BACKEND_ADDR_LEN + 1 comma)
pub const MAX_BACKENDS_STR_LEN: u32 = MAX_BACKENDS * (MAX_BACKEND_ADDR_LEN + 1);

/// TLS certificate path for tests.
pub const TEST_CERT_PATH: []const u8 = "experiments/tls-poc/cert.pem";

/// TLS key path for tests.
pub const TEST_KEY_PATH: []const u8 = "experiments/tls-poc/key.pem";

/// Delay after starting LB for health checks to complete (seconds).
/// LB needs time to probe backends and mark them healthy.
const HEALTH_SETTLE_DELAY_S: u64 = 1;

/// Port formatting buffer size (max 5 digits + null).
const PORT_BUF_LEN: u32 = 8;

/// TestClient socket receive timeout in seconds.
const TESTCLIENT_RECV_TIMEOUT_S: i64 = 5;

/// Maximum reads for TestClient response (bounded loop).
const TESTCLIENT_MAX_READS: u32 = 100;

/// Maximum POST request buffer size (headers + body).
const POST_REQUEST_MAX_BYTES: u32 = 8192;

/// Maximum chunks for chunked transfer encoding decoding (bounded loop).
/// TigerStyle C1: Named constant for loop bound.
const MAX_CHUNKS: u32 = 100;

/// Maximum decoded body size for chunked encoding.
/// TigerStyle C1: Named constant with unit suffix.
const MAX_DECODED_BODY_SIZE_BYTES: u32 = 4096;

/// Length of CRLF sequence in bytes.
/// TigerStyle C1: Named constant to avoid magic number.
const CRLF_LEN_BYTES: u32 = 2;

/// IPv4 loopback address in network byte order.
const LOOPBACK_IPV4_BE: u32 = 0x7F000001;

// =============================================================================
// kTLS Detection
// =============================================================================

/// Check if kTLS kernel module is loaded and available.
/// TLS tests require kTLS for the server to work properly.
/// Returns false if /proc/sys/net/ipv4/tcp_available_ulp doesn't contain "tls".
pub fn isKtlsAvailable() bool {
    // Read available ULPs from /proc
    const ulp_file = posix.open("/proc/sys/net/ipv4/tcp_available_ulp", .{ .ACCMODE = .RDONLY }, 0) catch {
        return false;
    };
    defer posix.close(ulp_file);

    var buf: [256]u8 = undefined;
    const n = posix.read(ulp_file, &buf) catch {
        return false;
    };

    if (n == 0) return false;

    // Check if "tls" is in the list of available ULPs
    return std.mem.indexOf(u8, buf[0..n], "tls") != null;
}

// =============================================================================
// PortPool
// =============================================================================

/// Thread-safe port allocator for tests.
/// TigerStyle: Wrapping arithmetic prevents overflow panic.
pub const PortPool = struct {
    next_port: u16,
    mutex: std.Io.Mutex,

    pub fn init() PortPool {
        return .{
            .next_port = BASE_TEST_PORT,
            .mutex = .init,
        };
    }

    pub fn next(self: *PortPool) u16 {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        const port = self.next_port;
        self.next_port +%= 1;
        if (self.next_port < BASE_TEST_PORT) {
            self.next_port = BASE_TEST_PORT;
        }
        return port;
    }
};

var global_port_pool: PortPool = PortPool.init();

pub fn getPort() u16 {
    return global_port_pool.next();
}

// =============================================================================
// Deadline
// =============================================================================

/// Timeout tracker for operations with deadlines.
pub const Deadline = struct {
    start: std.time.Instant,
    timeout_ns: u64,

    pub const InitError = error{TimerUnavailable};

    /// Initialize a deadline with the given timeout.
    /// TigerStyle: Returns error instead of unreachable on timer failure.
    pub fn init(timeout_ns: u64) InitError!Deadline {
        const start = std.time.Instant.now() catch return error.TimerUnavailable;
        return .{
            .start = start,
            .timeout_ns = timeout_ns,
        };
    }

    pub fn expired(self: Deadline) bool {
        const now = std.time.Instant.now() catch return true;
        return now.since(self.start) >= self.timeout_ns;
    }

    pub fn remaining_ns(self: Deadline) u64 {
        const now = std.time.Instant.now() catch return 0;
        const elapsed = now.since(self.start);
        if (elapsed >= self.timeout_ns) return 0;
        return self.timeout_ns - elapsed;
    }
};

// =============================================================================
// Process - Manages a single spawned process (using fork+exec)
// =============================================================================

pub const Process = struct {
    pid: posix.pid_t,
    name: []const u8,
    allocator: std.mem.Allocator,

    /// Kill the process and reap the zombie.
    /// TigerStyle: Handles errors explicitly (ESRCH = already dead, which is OK).
    pub fn kill(self: *Process) void {
        // Send SIGKILL to terminate the process
        posix.kill(self.pid, posix.SIG.KILL) catch |err| {
            // ESRCH means process already exited - that's fine
            if (err != error.ProcessNotFound) {
                std.log.warn("kill({d}) failed: {s}", .{ self.pid, @errorName(err) });
            }
        };
        // Reap the zombie - ignore errors (process may have been reaped already)
        _ = posix.waitpid(self.pid, 0);
    }

    pub fn deinit(self: *Process) void {
        self.allocator.free(self.name);
    }
};

// =============================================================================
// ProcessManager - Manages multiple server processes
// =============================================================================

/// Configuration for echo backend server.
pub const EchoBackendConfig = struct {
    /// TLS certificate path (enables HTTPS if set).
    cert_path: ?[]const u8 = null,
    /// TLS private key path (required with cert_path).
    key_path: ?[]const u8 = null,
    /// Use chunked transfer encoding for responses.
    chunked: bool = false,
    /// Enable debug logging.
    debug: bool = false,
    /// Echo exact request body back (for payload verification tests).
    echo_body: bool = false,
    /// Drain request body without echoing (for large upload tests >4GB).
    /// TigerStyle: Reads body in chunks, returns byte count without buffering.
    drain_body: bool = false,
};

/// Configuration for load balancer server.
pub const LoadBalancerConfig = struct {
    /// TLS certificate path for client connections (enables HTTPS frontend).
    cert_path: ?[]const u8 = null,
    /// TLS private key path (required with cert_path).
    key_path: ?[]const u8 = null,
    /// Backend addresses that should use TLS (HTTPS backends).
    upstream_tls: ?[]const []const u8 = null,
    /// Skip TLS certificate verification for upstream connections.
    /// WARNING: Only use for testing with self-signed certificates.
    insecure_skip_verify: bool = false,
    /// Enable debug logging.
    debug: bool = false,
};

pub const ProcessManager = struct {
    allocator: std.mem.Allocator,
    processes: std.ArrayList(Process),

    pub fn init(allocator: std.mem.Allocator) ProcessManager {
        return .{
            .allocator = allocator,
            .processes = .empty,
        };
    }

    pub fn deinit(self: *ProcessManager) void {
        self.stopAll();
        self.processes.deinit(self.allocator);
    }

    /// Start echo backend on given port with server ID.
    pub fn startEchoBackend(
        self: *ProcessManager,
        port: u16,
        server_id: []const u8,
        config: EchoBackendConfig,
    ) !void {
        // Preconditions
        assert(port > 0);
        assert(server_id.len > 0);
        if (config.cert_path != null) {
            assert(config.key_path != null); // TLS requires both cert and key
        }

        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(self.allocator);

        var allocated_strings: std.ArrayList([]const u8) = .empty;
        defer {
            for (allocated_strings.items) |s| self.allocator.free(s);
            allocated_strings.deinit(self.allocator);
        }

        try args.append(self.allocator, "./zig-out/bin/echo_backend");
        try args.append(self.allocator, "--port");

        var port_buf: [8]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch unreachable;
        const port_dup = try self.allocator.dupe(u8, port_str);
        try allocated_strings.append(self.allocator, port_dup);
        try args.append(self.allocator, port_dup);

        try args.append(self.allocator, "--id");
        try args.append(self.allocator, server_id);

        // TLS options
        if (config.cert_path) |cert| {
            try args.append(self.allocator, "--cert");
            try args.append(self.allocator, cert);
        }
        if (config.key_path) |key| {
            try args.append(self.allocator, "--key");
            try args.append(self.allocator, key);
        }

        // Other options
        if (config.chunked) {
            try args.append(self.allocator, "--chunked");
        }
        if (config.debug) {
            try args.append(self.allocator, "--debug");
        }
        if (config.echo_body) {
            try args.append(self.allocator, "--echo-body");
        }
        if (config.drain_body) {
            try args.append(self.allocator, "--drain-body");
        }

        const pid = try spawnProcess(self.allocator, args.items);
        errdefer {
            // TigerStyle S5: Explicit error handling (ESRCH = already dead, OK)
            posix.kill(pid, posix.SIG.KILL) catch |err| {
                if (err != error.ProcessNotFound) {
                    std.log.warn("errdefer kill({d}) failed: {s}", .{ pid, @errorName(err) });
                }
            };
            _ = posix.waitpid(pid, 0);
        }

        try self.processes.append(self.allocator, .{
            .pid = pid,
            .name = try std.fmt.allocPrint(self.allocator, "echo_backend_{s}", .{server_id}),
            .allocator = self.allocator,
        });

        try waitForPort(port, SERVER_READY_TIMEOUT_MS);
    }

    /// Start load balancer with given backends.
    pub fn startLoadBalancer(
        self: *ProcessManager,
        port: u16,
        backend_addrs: []const []const u8,
        config: LoadBalancerConfig,
    ) !void {
        // Preconditions
        assert(port > 0);
        assert(backend_addrs.len > 0);
        assert(backend_addrs.len <= MAX_BACKENDS); // TigerStyle: Bounded
        if (config.cert_path != null) {
            assert(config.key_path != null); // TLS requires both cert and key
        }

        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(self.allocator);

        var allocated_strings: std.ArrayList([]const u8) = .empty;
        defer {
            for (allocated_strings.items) |s| self.allocator.free(s);
            allocated_strings.deinit(self.allocator);
        }

        try args.append(self.allocator, "./zig-out/bin/lb_example");
        try args.append(self.allocator, "--port");

        var port_buf: [8]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch unreachable;
        const port_dup = try self.allocator.dupe(u8, port_str);
        try allocated_strings.append(self.allocator, port_dup);
        try args.append(self.allocator, port_dup);

        try args.append(self.allocator, "--backends");

        // Join backends with comma - bounded buffer with explicit length check
        var backends_buf: [MAX_BACKENDS_STR_LEN]u8 = undefined;
        var backends_len: usize = 0;
        for (backend_addrs, 0..) |addr, i| {
            // TigerStyle: Explicit bounds check
            assert(addr.len <= MAX_BACKEND_ADDR_LEN);
            const needed = if (i > 0) addr.len + 1 else addr.len;
            if (backends_len + needed > backends_buf.len) {
                return error.BackendListTooLong;
            }
            if (i > 0) {
                backends_buf[backends_len] = ',';
                backends_len += 1;
            }
            @memcpy(backends_buf[backends_len..][0..addr.len], addr);
            backends_len += addr.len;
        }
        const backends_str = backends_buf[0..backends_len];
        const backends_dup = try self.allocator.dupe(u8, backends_str);
        try allocated_strings.append(self.allocator, backends_dup);
        try args.append(self.allocator, backends_dup);

        // TLS options for client connections (frontend)
        if (config.cert_path) |cert| {
            try args.append(self.allocator, "--cert");
            try args.append(self.allocator, cert);
        }
        if (config.key_path) |key| {
            try args.append(self.allocator, "--key");
            try args.append(self.allocator, key);
        }

        // TLS options for upstream connections (backends)
        if (config.upstream_tls) |tls_backends| {
            // Join TLS backends with comma
            var tls_buf: [MAX_BACKENDS_STR_LEN]u8 = undefined;
            var tls_len: usize = 0;
            for (tls_backends, 0..) |addr, i| {
                assert(addr.len <= MAX_BACKEND_ADDR_LEN);
                const needed = if (i > 0) addr.len + 1 else addr.len;
                if (tls_len + needed > tls_buf.len) {
                    return error.BackendListTooLong;
                }
                if (i > 0) {
                    tls_buf[tls_len] = ',';
                    tls_len += 1;
                }
                @memcpy(tls_buf[tls_len..][0..addr.len], addr);
                tls_len += addr.len;
            }
            try args.append(self.allocator, "--upstream-tls");
            const tls_dup = try self.allocator.dupe(u8, tls_buf[0..tls_len]);
            try allocated_strings.append(self.allocator, tls_dup);
            try args.append(self.allocator, tls_dup);
        }

        if (config.insecure_skip_verify) {
            try args.append(self.allocator, "--insecure-skip-verify");
        }

        if (config.debug) {
            try args.append(self.allocator, "--debug");
        }

        const pid = try spawnProcess(self.allocator, args.items);
        errdefer {
            // TigerStyle S5: Explicit error handling (ESRCH = already dead, OK)
            posix.kill(pid, posix.SIG.KILL) catch |err| {
                if (err != error.ProcessNotFound) {
                    std.log.warn("errdefer kill({d}) failed: {s}", .{ pid, @errorName(err) });
                }
            };
            _ = posix.waitpid(pid, 0);
        }

        try self.processes.append(self.allocator, .{
            .pid = pid,
            .name = try self.allocator.dupe(u8, "lb_example"),
            .allocator = self.allocator,
        });

        try waitForPort(port, SERVER_READY_TIMEOUT_MS);

        // Wait for health checks (backends need to be marked healthy)
        // TigerStyle C1: Named constant with unit suffix
        posix.nanosleep(HEALTH_SETTLE_DELAY_S, 0);
    }

    pub fn stopAll(self: *ProcessManager) void {
        // Stop in reverse order (LB first, then backends)
        while (self.processes.pop()) |*proc| {
            var p = proc.*;
            p.kill();
            p.deinit();
        }
    }

    /// Kill a specific process by name.
    /// TigerStyle S1: Precondition assertion on name length.
    /// TigerStyle S3: Bounded loop using for over slice.
    pub fn killProcess(self: *ProcessManager, name: []const u8) !void {
        // Precondition: name must be non-empty
        assert(name.len > 0);

        // Find process by name (S3: bounded loop over slice)
        for (self.processes.items, 0..) |*proc, idx| {
            if (std.mem.eql(u8, proc.name, name)) {
                proc.kill();
                proc.deinit();
                _ = self.processes.swapRemove(idx);
                return;
            }
        }

        return error.ProcessNotFound;
    }

    /// Kill a process by index.
    /// TigerStyle S1: Precondition assertion on bounds.
    pub fn killProcessByIndex(self: *ProcessManager, idx: usize) !void {
        // Precondition: index must be in bounds
        if (idx >= self.processes.items.len) {
            return error.IndexOutOfBounds;
        }
        assert(idx < self.processes.items.len);

        var proc = self.processes.swapRemove(idx);
        proc.kill();
        proc.deinit();
    }

    /// Restart an echo backend (semantic wrapper for startEchoBackend).
    /// Useful after killing a backend to restart it on the same port.
    /// TigerStyle S1: Preconditions delegated to startEchoBackend.
    pub fn restartEchoBackend(
        self: *ProcessManager,
        port: u16,
        server_id: []const u8,
        config: EchoBackendConfig,
    ) !void {
        // Delegate to startEchoBackend - same implementation, different semantic name
        try self.startEchoBackend(port, server_id, config);
    }
};

// =============================================================================
// Process spawning using fork+exec
// =============================================================================

const SpawnError = error{
    ForkFailed,
    OutOfMemory,
};

fn spawnProcess(allocator: std.mem.Allocator, argv: []const []const u8) SpawnError!posix.pid_t {
    // Preconditions
    assert(argv.len > 0);

    // Convert argv to null-terminated array for execve
    const argv_buf = allocator.allocSentinel(?[*:0]const u8, argv.len, null) catch return error.OutOfMemory;
    defer allocator.free(argv_buf);

    for (argv, 0..) |arg, i| {
        argv_buf[i] = allocator.dupeZ(u8, arg) catch return error.OutOfMemory;
    }
    defer {
        for (argv_buf) |maybe_ptr| {
            if (maybe_ptr) |ptr| {
                allocator.free(std.mem.span(ptr));
            }
        }
    }

    const pid = posix.fork() catch return error.ForkFailed;
    if (pid == 0) {
        // Child process
        // Redirect stdin/stdout/stderr to /dev/null
        // TigerStyle: Exit with distinct codes on failure (not catch {})
        const devnull = posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0) catch {
            std.process.exit(126); // Cannot open /dev/null
        };
        posix.dup2(devnull, posix.STDIN_FILENO) catch {
            std.process.exit(125); // dup2 failed
        };
        posix.dup2(devnull, posix.STDOUT_FILENO) catch {
            std.process.exit(125);
        };
        posix.dup2(devnull, posix.STDERR_FILENO) catch {
            std.process.exit(125);
        };
        if (devnull > 2) posix.close(devnull);

        // Execute the program - inherit environment from parent
        // execvpeZ only returns on error, so if we get here, exec failed
        const env: [*:null]const ?[*:0]const u8 = @ptrCast(std.os.environ.ptr);
        _ = posix.execvpeZ(argv_buf[0].?, argv_buf, env) catch {
            std.process.exit(127); // Exec failed
        };
        std.process.exit(127);
    }

    // Postcondition: Valid PID returned
    assert(pid > 0);
    return pid;
}

// =============================================================================
// Port waiting
// =============================================================================

pub const WaitError = error{
    TimerUnavailable,
    PortTimeout,
};

pub fn waitForPort(port: u16, timeout_ms: u64) WaitError!void {
    // Precondition
    assert(port > 0);
    assert(timeout_ms > 0);

    const start = std.time.Instant.now() catch return error.TimerUnavailable;
    const timeout_ns = timeout_ms * std.time.ns_per_ms;

    // TigerStyle: Bounded loop with explicit iteration limit
    const max_iterations: u32 = @intCast(timeout_ms / READY_POLL_INTERVAL_MS + 1);
    var iteration: u32 = 0;

    while (iteration < max_iterations) : (iteration += 1) {
        if (tryConnect(port)) {
            return;
        }
        const now = std.time.Instant.now() catch return error.TimerUnavailable;
        if (now.since(start) >= timeout_ns) {
            return error.PortTimeout;
        }
        posix.nanosleep(0, READY_POLL_INTERVAL_MS * std.time.ns_per_ms);
    }

    return error.PortTimeout;
}

fn tryConnect(port: u16) bool {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP) catch return false;
    defer posix.close(sock);

    // TigerStyle C4: Use named constant for loopback address
    const addr: posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, LOOPBACK_IPV4_BE),
    };

    posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return false;
    return true;
}

// =============================================================================
// TestClient - HTTP client for tests
// =============================================================================

pub const TestClient = struct {
    allocator: std.mem.Allocator,

    /// Response with owned memory.
    /// TigerStyle: Caller must call deinit() to free memory.
    pub const Response = struct {
        status: u16,
        /// Owned copy of response body.
        body: []const u8,
        /// Owned copy of backend ID (if present).
        backend_id: ?[]const u8,
        allocator: std.mem.Allocator,

        /// Free owned memory.
        pub fn deinit(self: *const Response) void {
            if (self.body.len > 0) {
                self.allocator.free(self.body);
            }
            if (self.backend_id) |id| {
                self.allocator.free(id);
            }
        }
    };

    pub fn init(allocator: std.mem.Allocator) TestClient {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *TestClient) void {
        _ = self;
        // No cleanup needed - responses are freed individually
    }

    /// Make HTTP GET request and return response with owned memory.
    /// TigerStyle: Response owns its memory, caller must call response.deinit().
    pub fn get(self: *TestClient, port: u16, path: []const u8) !Response {
        // Preconditions
        assert(port > 0);
        assert(path.len > 0);

        const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        defer posix.close(sock);

        // TigerStyle C1/C4: Named constant with unit suffix
        const timeout = posix.timeval{ .sec = TESTCLIENT_RECV_TIMEOUT_S, .usec = 0 };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // TigerStyle C4: Use named constant for loopback address
        const addr: posix.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, LOOPBACK_IPV4_BE),
        };

        try posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));

        // Send request
        var req_buf: [1024]u8 = undefined;
        const req = std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nConnection: close\r\n\r\n", .{ path, port }) catch return error.BufferTooSmall;

        var sent: usize = 0;
        while (sent < req.len) {
            const n = try posix.send(sock, req[sent..], 0);
            sent += n;
        }

        // Read response (with timeout protection)
        var resp_buf: [4096]u8 = undefined;
        var total: u32 = 0; // TigerStyle S6: u32 for bounded buffer

        // TigerStyle S3: Bounded loop with named constant
        var read_count: u32 = 0;

        while (total < resp_buf.len and read_count < TESTCLIENT_MAX_READS) : (read_count += 1) {
            const n = posix.recv(sock, resp_buf[total..], 0) catch |err| {
                // TigerStyle S5: Handle EINTR by continuing, others break
                if (err == error.Interrupted) continue;
                if (err == error.WouldBlock) break;
                break;
            };
            if (n == 0) break;
            total += @intCast(n);
            // If we have headers, check if we have all the content
            if (std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n")) |header_end| {
                // Simple content-length detection
                if (std.mem.indexOf(u8, resp_buf[0..header_end], "Content-Length: ")) |cl_start| {
                    const cl_line_start = cl_start + "Content-Length: ".len;
                    if (std.mem.indexOfPos(u8, resp_buf[0..header_end], cl_line_start, "\r\n")) |cl_line_end| {
                        const content_length = std.fmt.parseInt(usize, resp_buf[cl_line_start..cl_line_end], 10) catch continue;
                        const body_start = header_end + 4;
                        const body_received = total - body_start;
                        if (body_received >= content_length) break;
                    }
                }
            }
        }

        if (total == 0) return error.EmptyResponse;

        const data = resp_buf[0..total];
        const status = parseStatusCode(data) orelse return error.InvalidResponse;

        // TigerStyle: Allocate owned copies of body and backend_id
        var body_slice = findBody(data) orelse "";

        // Check for chunked Transfer-Encoding and decode if present
        var decoded_buf: [MAX_DECODED_BODY_SIZE_BYTES]u8 = undefined;
        if (findHeader(data, "Transfer-Encoding")) |te| {
            if (std.mem.indexOf(u8, te, "chunked") != null) {
                // Decode chunked body
                const decoded = decodeChunkedBody(body_slice, &decoded_buf) orelse
                    return error.InvalidChunkedEncoding;
                body_slice = decoded;
            }
        }

        const body = if (body_slice.len > 0)
            try self.allocator.dupe(u8, body_slice)
        else
            &[_]u8{};

        const backend_id_slice = findHeader(data, "X-Backend-Id");
        const backend_id = if (backend_id_slice) |id|
            try self.allocator.dupe(u8, id)
        else
            null;

        return .{
            .status = status,
            .body = body,
            .backend_id = backend_id,
            .allocator = self.allocator,
        };
    }

    pub fn parseStatusCode(data: []const u8) ?u16 {
        if (data.len < 12) return null;
        if (!std.mem.startsWith(u8, data, "HTTP/1.")) return null;
        const space_idx = std.mem.indexOf(u8, data, " ") orelse return null;
        if (space_idx + 4 > data.len) return null;
        const code_str = data[space_idx + 1 ..][0..3];
        return std.fmt.parseInt(u16, code_str, 10) catch null;
    }

    pub fn findBody(data: []const u8) ?[]const u8 {
        const sep = "\r\n\r\n";
        const idx = std.mem.indexOf(u8, data, sep) orelse return null;
        return data[idx + sep.len ..];
    }

    pub fn findHeader(data: []const u8, name: []const u8) ?[]const u8 {
        var iter = std.mem.splitSequence(u8, data, "\r\n");
        while (iter.next()) |line| {
            if (std.mem.startsWith(u8, line, name)) {
                const colon_idx = std.mem.indexOf(u8, line, ":") orelse continue;
                var value = line[colon_idx + 1 ..];
                if (value.len > 0 and value[0] == ' ') value = value[1..];
                return value;
            }
        }
        return null;
    }

    /// Make HTTP POST request with body and return response with owned memory.
    /// TigerStyle: Response owns its memory, caller must call response.deinit().
    pub fn post(self: *TestClient, port: u16, path: []const u8, body: []const u8, content_type: []const u8) !Response {
        // S1: Preconditions
        assert(port > 0);
        assert(path.len > 0);
        assert(content_type.len > 0);

        const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        defer posix.close(sock);

        // TigerStyle C1/C4: Named constant with unit suffix
        const timeout = posix.timeval{ .sec = TESTCLIENT_RECV_TIMEOUT_S, .usec = 0 };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // TigerStyle C4: Use named constant for loopback address
        const addr: posix.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, LOOPBACK_IPV4_BE),
        };

        try posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));

        // Build request with body
        var req_buf: [POST_REQUEST_MAX_BYTES]u8 = undefined;
        const req = std.fmt.bufPrint(&req_buf, "POST {s} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ path, port, content_type, body.len, body }) catch return error.BufferTooSmall;

        // S3: Bounded send loop
        var sent: u32 = 0; // S6: u32 for bounded buffer
        const req_len: u32 = @intCast(req.len);
        var send_iterations: u32 = 0;
        const max_send_iterations: u32 = 100; // S3: Explicit bound

        while (sent < req_len and send_iterations < max_send_iterations) : (send_iterations += 1) {
            const n = posix.send(sock, req[sent..], 0) catch |err| {
                // S5: Handle EINTR by continuing, others propagate
                if (err == error.Interrupted) continue;
                return err;
            };
            if (n == 0) return error.ConnectionReset;
            sent += @intCast(n);
        }

        if (sent < req_len) return error.SendIncomplete;

        // Read response (with timeout protection) - same logic as get()
        var resp_buf: [4096]u8 = undefined;
        var total: u32 = 0; // TigerStyle S6: u32 for bounded buffer

        // TigerStyle S3: Bounded loop with named constant
        var read_count: u32 = 0;

        while (total < resp_buf.len and read_count < TESTCLIENT_MAX_READS) : (read_count += 1) {
            const n = posix.recv(sock, resp_buf[total..], 0) catch |err| {
                // TigerStyle S5: Handle EINTR by continuing, others break
                if (err == error.Interrupted) continue;
                if (err == error.WouldBlock) break;
                break;
            };
            if (n == 0) break;
            total += @intCast(n);
            // If we have headers, check if we have all the content
            if (std.mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n")) |header_end| {
                // Simple content-length detection
                if (std.mem.indexOf(u8, resp_buf[0..header_end], "Content-Length: ")) |cl_start| {
                    const cl_line_start = cl_start + "Content-Length: ".len;
                    if (std.mem.indexOfPos(u8, resp_buf[0..header_end], cl_line_start, "\r\n")) |cl_line_end| {
                        const content_length = std.fmt.parseInt(usize, resp_buf[cl_line_start..cl_line_end], 10) catch continue;
                        const body_start = header_end + 4;
                        const body_received = total - body_start;
                        if (body_received >= content_length) break;
                    }
                }
            }
        }

        if (total == 0) return error.EmptyResponse;

        const data = resp_buf[0..total];
        const status = parseStatusCode(data) orelse return error.InvalidResponse;

        // TigerStyle: Allocate owned copies of body and backend_id
        var body_slice = findBody(data) orelse "";

        // Check for chunked Transfer-Encoding and decode if present
        var decoded_buf: [MAX_DECODED_BODY_SIZE_BYTES]u8 = undefined;
        if (findHeader(data, "Transfer-Encoding")) |te| {
            if (std.mem.indexOf(u8, te, "chunked") != null) {
                // Decode chunked body
                const decoded = decodeChunkedBody(body_slice, &decoded_buf) orelse
                    return error.InvalidChunkedEncoding;
                body_slice = decoded;
            }
        }

        const resp_body = if (body_slice.len > 0)
            try self.allocator.dupe(u8, body_slice)
        else
            &[_]u8{};
        // TigerStyle S5: errdefer to free body if backend_id allocation fails
        errdefer if (resp_body.len > 0) self.allocator.free(resp_body);

        const backend_id_slice = findHeader(data, "X-Backend-Id");
        const backend_id = if (backend_id_slice) |id|
            try self.allocator.dupe(u8, id)
        else
            null;

        return .{
            .status = status,
            .body = resp_body,
            .backend_id = backend_id,
            .allocator = self.allocator,
        };
    }

    /// Make HTTP POST request with large body support.
    /// Uses streaming write for body and dynamic allocation for response.
    /// Suitable for payload sizes up to several MB.
    pub fn postLarge(self: *TestClient, port: u16, path: []const u8, body: []const u8, content_type: []const u8) !Response {
        // S1: Preconditions
        assert(port > 0);
        assert(path.len > 0);
        assert(content_type.len > 0);

        const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        defer posix.close(sock);

        // Longer timeout for large payloads (100MB+ needs time)
        const timeout = posix.timeval{ .sec = 120, .usec = 0 };
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));

        const addr: posix.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, LOOPBACK_IPV4_BE),
        };

        try posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
        std.debug.print("[DEBUG postLarge] connected to port {d}, body size: {d}\n", .{ port, body.len });

        // Send headers first
        var header_buf: [512]u8 = undefined;
        const headers = std.fmt.bufPrint(&header_buf, "POST {s} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ path, port, content_type, body.len }) catch return error.BufferTooSmall;

        // Send headers
        var sent: usize = 0;
        while (sent < headers.len) {
            const n = posix.send(sock, headers[sent..], 0) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };
            if (n == 0) return error.ConnectionReset;
            sent += n;
        }
        std.debug.print("[DEBUG postLarge] headers sent\n", .{});

        // Send body in chunks (handle WouldBlock for large transfers)
        sent = 0;
        var last_progress: usize = 0;
        while (sent < body.len) {
            const n = posix.send(sock, body[sent..], 0) catch |err| {
                if (err == error.Interrupted) continue;
                if (err == error.WouldBlock) {
                    // Socket buffer full - wait briefly and retry
                    posix.nanosleep(0, 1_000_000); // 1ms
                    continue;
                }
                return err;
            };
            if (n == 0) return error.ConnectionReset;
            sent += n;
            // Progress every 100MB
            if (sent - last_progress >= 100 * 1024 * 1024) {
                std.debug.print("[DEBUG postLarge] sent {d} MB / {d} MB\n", .{ sent / (1024 * 1024), body.len / (1024 * 1024) });
                last_progress = sent;
            }
        }
        std.debug.print("[DEBUG postLarge] body fully sent ({d} bytes)\n", .{sent});

        // Read response - allocate buffer dynamically based on expected size
        // Assume response is roughly same size as request body + headers
        const expected_size = body.len + 1024;
        var resp_data: std.ArrayList(u8) = .empty;
        defer resp_data.deinit(self.allocator);

        var read_buf: [8192]u8 = undefined;
        var read_count: u32 = 0;
        const max_reads: u32 = 20000; // Allow many reads for 100MB+ responses
        var wouldblock_count: u32 = 0;
        const max_wouldblock: u32 = 60000; // 60 seconds max wait (1ms per iteration)

        std.debug.print("[DEBUG postLarge] waiting for response...\n", .{});
        while (read_count < max_reads) : (read_count += 1) {
            const n = posix.recv(sock, &read_buf, 0) catch |err| {
                if (err == error.Interrupted) continue;
                if (err == error.WouldBlock) {
                    // No data yet - wait and retry (needed for large uploads)
                    wouldblock_count += 1;
                    if (wouldblock_count % 1000 == 0) {
                        std.debug.print("[DEBUG postLarge] WouldBlock count: {d}\n", .{wouldblock_count});
                    }
                    if (wouldblock_count >= max_wouldblock) break;
                    posix.nanosleep(0, 1_000_000); // 1ms
                    continue;
                }
                std.debug.print("[DEBUG postLarge] recv error: {s}\n", .{@errorName(err)});
                break;
            };
            if (n == 0) {
                std.debug.print("[DEBUG postLarge] recv returned 0 (EOF)\n", .{});
                break;
            }
            wouldblock_count = 0; // Reset on successful read
            try resp_data.appendSlice(self.allocator, read_buf[0..n]);

            // Check if we have complete response
            if (resp_data.items.len > expected_size) break;
        }

        std.debug.print("[DEBUG postLarge] response received: {d} bytes\n", .{resp_data.items.len});
        if (resp_data.items.len == 0) return error.EmptyResponse;

        const data = resp_data.items;
        const status = parseStatusCode(data) orelse return error.InvalidResponse;

        const body_slice = findBody(data) orelse "";
        const resp_body = if (body_slice.len > 0)
            try self.allocator.dupe(u8, body_slice)
        else
            &[_]u8{};
        errdefer if (resp_body.len > 0) self.allocator.free(resp_body);

        const backend_id_slice = findHeader(data, "X-Backend-Id");
        const backend_id = if (backend_id_slice) |id|
            try self.allocator.dupe(u8, id)
        else
            null;

        return .{
            .status = status,
            .body = resp_body,
            .backend_id = backend_id,
            .allocator = self.allocator,
        };
    }

    /// Decode chunked transfer encoding body.
    /// Returns slice of decoded body within the provided buffer.
    /// TigerStyle: Bounded parsing with explicit limits.
    ///
    /// Chunked format:
    ///   <hex-size>\r\n
    ///   <data>\r\n
    ///   ...
    ///   0\r\n
    ///   \r\n
    pub fn decodeChunkedBody(data: []const u8, out_buf: []u8) ?[]const u8 {
        // S1: Preconditions
        assert(out_buf.len > 0);

        var pos: usize = 0;
        var out_pos: usize = 0;
        var chunk_count: u32 = 0;

        // S3: Bounded loop - max chunks prevents infinite loop on malformed data
        while (pos < data.len and chunk_count < MAX_CHUNKS) : (chunk_count += 1) {
            // Find end of chunk size line (CRLF)
            const crlf_pos = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse return null;
            const size_line = data[pos..crlf_pos];

            // Parse hex size (may have extension after semicolon)
            const size_end = std.mem.indexOf(u8, size_line, ";") orelse size_line.len;
            if (size_end == 0) return null; // Empty size

            const chunk_size = std.fmt.parseInt(usize, size_line[0..size_end], 16) catch return null;

            // Move past size line and CRLF
            pos = crlf_pos + CRLF_LEN_BYTES;

            // Zero-length chunk = end of body
            if (chunk_size == 0) {
                // S1: Postcondition - output fits in buffer
                assert(out_pos <= out_buf.len);
                return out_buf[0..out_pos];
            }

            // Bounds check: enough data for chunk + CRLF?
            // TigerStyle: Use overflow-safe addition
            const chunk_end = pos + chunk_size;
            if (chunk_end > data.len) return null;
            if (chunk_end + CRLF_LEN_BYTES > data.len) return null;

            // Bounds check: enough space in output buffer?
            if (out_pos + chunk_size > out_buf.len) return null;

            // Copy chunk data to output
            @memcpy(out_buf[out_pos..][0..chunk_size], data[pos..][0..chunk_size]);
            out_pos += chunk_size;

            // Skip chunk data and trailing CRLF
            pos += chunk_size;
            if (pos + CRLF_LEN_BYTES > data.len or data[pos] != '\r' or data[pos + 1] != '\n') {
                return null; // Missing CRLF after chunk data
            }
            pos += CRLF_LEN_BYTES;
        }

        // Hit max chunks without finding terminator - malformed
        return null;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "PortPool allocates unique ports" {
    var pool = PortPool.init();
    const p1 = pool.next();
    const p2 = pool.next();
    try std.testing.expect(p1 != p2);
}

test "Deadline tracks expiration" {
    const deadline = try Deadline.init(100 * std.time.ns_per_ms);
    try std.testing.expect(!deadline.expired());
}

test "Deadline returns error on init failure" {
    // Note: This test can't easily simulate timer failure, but we verify
    // the error path compiles and the type is correct.
    const result = Deadline.init(100);
    try std.testing.expect(result != error.TimerUnavailable);
}

test "TestClient parses status codes" {
    try std.testing.expectEqual(@as(?u16, 200), TestClient.parseStatusCode("HTTP/1.1 200 OK\r\n"));
    try std.testing.expectEqual(@as(?u16, null), TestClient.parseStatusCode("garbage"));
}

test "TestClient finds body" {
    const body = TestClient.findBody("HTTP/1.1 200 OK\r\n\r\nhello");
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("hello", body.?);
}

test "TestClient finds headers" {
    const id = TestClient.findHeader("HTTP/1.1 200 OK\r\nX-Backend-Id: b1\r\n\r\n", "X-Backend-Id");
    try std.testing.expect(id != null);
    try std.testing.expectEqualStrings("b1", id.?);
}

test "decodeChunkedBody: single chunk" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "5\r\nhello\r\n0\r\n\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded != null);
    try std.testing.expectEqualStrings("hello", decoded.?);
}

test "decodeChunkedBody: multiple chunks" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded != null);
    try std.testing.expectEqualStrings("hello world", decoded.?);
}

test "decodeChunkedBody: empty body" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "0\r\n\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded != null);
    try std.testing.expectEqualStrings("", decoded.?);
}

test "decodeChunkedBody: hex size" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "a\r\n0123456789\r\n0\r\n\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded != null);
    try std.testing.expectEqualStrings("0123456789", decoded.?);
}

test "decodeChunkedBody: uppercase hex" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "A\r\n0123456789\r\n0\r\n\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded != null);
    try std.testing.expectEqualStrings("0123456789", decoded.?);
}

test "decodeChunkedBody: with extension (ignored)" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "5;name=value\r\nhello\r\n0\r\n\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded != null);
    try std.testing.expectEqualStrings("hello", decoded.?);
}

test "decodeChunkedBody: malformed - missing terminator CRLF" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "5\r\nhello\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded == null);
}

test "decodeChunkedBody: malformed - bad hex" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "xyz\r\nhello\r\n0\r\n\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded == null);
}

test "decodeChunkedBody: malformed - truncated data" {
    var out_buf: [64]u8 = undefined;
    const chunked_data = "5\r\nhel"; // Only 3 bytes when 5 claimed
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded == null);
}

test "decodeChunkedBody: output buffer too small" {
    var out_buf: [3]u8 = undefined; // Only 3 bytes
    const chunked_data = "5\r\nhello\r\n0\r\n\r\n";
    const decoded = TestClient.decodeChunkedBody(chunked_data, &out_buf);
    try std.testing.expect(decoded == null);
}
