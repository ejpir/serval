# Integration Tests

End-to-end integration tests for serval. Tests spawn actual server binaries as subprocesses and make real HTTP/HTTPS requests.

## Running Tests

```bash
# Run all integration tests
zig build test-integration

# Run with summary
zig build test-integration --summary all

# Run specific test (filter by name)
zig build test-integration -- --test-filter "TLS termination"
```

## Prerequisites

### Build Binaries First

Integration tests require the example binaries to be built:

```bash
zig build
```

This creates:
- `zig-out/bin/echo_backend` - Echo HTTP server for testing
- `zig-out/bin/lb_example` - Load balancer with health checking

### TLS Tests: kTLS Kernel Module

TLS tests require the Linux kTLS kernel module to be loaded. If not loaded, TLS tests will be skipped automatically.

```bash
# Check if kTLS is available
cat /proc/sys/net/ipv4/tcp_available_ulp | grep tls

# Load kTLS module (requires root)
sudo modprobe tls
```

### TLS Certificates

Test certificates are located in `experiments/tls-poc/`:
- `cert.pem` - Self-signed certificate
- `key.pem` - Private key

These are for testing only. Use `--insecure-skip-verify` with self-signed certificates.

## Test Categories

### HTTP Tests (Always Run)

| Test | Description |
|------|-------------|
| `echo backend responds with 200` | Basic HTTP echo server |
| `lb forwards to single backend` | Load balancer with one backend |
| `lb round-robins across 2 backends` | Verify round-robin distribution |

### TLS Tests (Require kTLS)

| Test | Description |
|------|-------------|
| `TLS termination` | HTTPS client -> HTTP backend |
| `TLS origination` | HTTP client -> HTTPS backend |
| `TLS full path` | HTTPS client -> HTTPS backend |
| `mixed backends` | Round-robin HTTP + HTTPS backends |
| `health probe over HTTPS` | Health checks via TLS |

## Adding New Tests

### 1. Basic Test Pattern

```zig
test "integration: my new test" {
    const allocator = testing.allocator;
    const port = harness.getPort();  // Get unique port

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();  // Cleanup all processes

    // Start servers
    try pm.startEchoBackend(port, "my-backend", .{});

    // Make request
    var client = harness.TestClient.init(allocator);
    defer client.deinit();
    const response = try client.get(port, "/test");
    defer response.deinit();

    // Assert
    try testing.expectEqual(@as(u16, 200), response.status);
}
```

### 2. TLS Test Pattern

```zig
test "integration: TLS test" {
    // Skip if kTLS not available
    if (!harness.isKtlsAvailable()) {
        std.debug.print("SKIP: kTLS kernel module not loaded\n", .{});
        return error.SkipZigTest;
    }

    const allocator = testing.allocator;

    var pm = harness.ProcessManager.init(allocator);
    defer pm.deinit();

    // Start HTTPS backend
    try pm.startEchoBackend(port, "https-backend", .{
        .cert_path = harness.TEST_CERT_PATH,
        .key_path = harness.TEST_KEY_PATH,
    });

    // Start LB with TLS origination
    try pm.startLoadBalancer(lb_port, &.{backend_addr}, .{
        .upstream_tls = &.{backend_addr},
        .insecure_skip_verify = true,
    });

    // Make HTTP request (LB connects to backend via HTTPS)
    var client = harness.TestClient.init(allocator);
    const response = try client.get(lb_port, "/test");
    defer response.deinit();

    try testing.expectEqual(@as(u16, 200), response.status);
}
```

### 3. HTTPS Client Requests (curl)

For making HTTPS requests to a server with TLS termination:

```zig
const response = try curlHttps(allocator, port, "/test");
defer response.deinit();
```

## Harness API

### ProcessManager

Manages server processes with automatic cleanup.

```zig
var pm = harness.ProcessManager.init(allocator);
defer pm.deinit();

// Start echo backend
try pm.startEchoBackend(port, "backend-id", .{
    .cert_path = "path/to/cert.pem",  // Optional: enables HTTPS
    .key_path = "path/to/key.pem",    // Required if cert_path is set
    .chunked = false,                  // Use chunked encoding
    .debug = false,                    // Enable debug logging
});

// Start load balancer
try pm.startLoadBalancer(port, &.{"127.0.0.1:8001", "127.0.0.1:8002"}, .{
    .cert_path = "path/to/cert.pem",           // Optional: HTTPS frontend
    .key_path = "path/to/key.pem",
    .upstream_tls = &.{"127.0.0.1:8002"},      // Which backends use TLS
    .insecure_skip_verify = true,              // Skip cert verification
    .debug = false,
});
```

### TestClient

HTTP client for making requests.

```zig
var client = harness.TestClient.init(allocator);
defer client.deinit();

const response = try client.get(port, "/path");
defer response.deinit();

// response.status: u16
// response.body: []const u8
// response.backend_id: ?[]const u8 (from X-Backend-Id header)
```

### PortPool

Thread-safe port allocation.

```zig
const port = harness.getPort();  // Returns unique port >= 19000
```

### isKtlsAvailable

Check if kTLS kernel module is loaded.

```zig
if (!harness.isKtlsAvailable()) {
    return error.SkipZigTest;
}
```

## Debugging Failed Tests

### Enable Debug Logging

Pass `.debug = true` to server config:

```zig
try pm.startEchoBackend(port, "test", .{ .debug = true });
try pm.startLoadBalancer(port, backends, .{ .debug = true });
```

### Check Process Status

If tests fail with `PortTimeout`, the server process likely crashed. Run manually:

```bash
# HTTP backend
./zig-out/bin/echo_backend --port 8001 --id test --debug

# HTTPS backend
./zig-out/bin/echo_backend --port 8001 --id test \
  --cert experiments/tls-poc/cert.pem \
  --key experiments/tls-poc/key.pem --debug

# Load balancer
./zig-out/bin/lb_example --port 8080 --backends 127.0.0.1:8001 --debug
```

### Port Conflicts

Tests use ports starting at 19000. If you see conflicts:

```bash
# Kill any lingering test processes
pkill -9 -f "echo_backend|lb_example"
```

## TigerStyle Compliance

The harness follows TigerStyle rules:

- **S1**: Assertions on preconditions (port > 0, path.len > 0)
- **S3**: Bounded loops with explicit iteration limits
- **S4**: Explicit error handling (no `catch {}`)
- **S5**: Zero allocation after init (TestClient uses caller-provided allocator)
- **C1**: Units in names (timeout_ms, timeout_ns)
- **Y1**: snake_case naming

## File Structure

```
integration/
├── README.md        # This file
├── harness.zig      # Test infrastructure
│   ├── ProcessManager   # Server process management
│   ├── TestClient       # HTTP client for tests
│   ├── PortPool         # Port allocation
│   ├── Deadline         # Timeout tracking
│   └── isKtlsAvailable  # kTLS detection
└── tests.zig        # Integration tests
```
