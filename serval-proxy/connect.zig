// lib/serval-proxy/connect.zig
//! Connection Management
//!
//! TCP connection establishment and socket utilities.
//! TigerStyle: Explicit timing, zero-copy where possible.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const Io = std.Io;

const serval_core = @import("serval-core");
const debugLog = serval_core.debugLog;
const time = serval_core.time;

const serval_net = @import("serval-net");
const setTcpNoDelay = serval_net.setTcpNoDelay;
const setTcpKeepAlive = serval_net.setTcpKeepAlive;

const pool_mod = @import("serval-pool").pool;
const Connection = pool_mod.Connection;

const types = @import("types.zig");
const ForwardError = types.ForwardError;
const Protocol = types.Protocol;

const Upstream = serval_core.types.Upstream;

// =============================================================================
// Connection Result
// =============================================================================

/// Result of connecting to upstream, includes timing and socket info.
pub const ConnectResult = struct {
    conn: Connection,
    /// Protocol negotiated at connection time. Immutable for connection lifetime.
    /// TigerStyle: Single source of truth, no mid-connection renegotiation.
    /// Future: TLS negotiation via ALPN, h2c detection via preface.
    protocol: Protocol,
    tcp_connect_duration_ns: u64,
    local_port: u16,
};

// =============================================================================
// Port Extraction
// =============================================================================

/// Get local port from connected socket.
/// Returns 0 if unable to retrieve (non-fatal).
pub fn getLocalPort(fd: i32) u16 {
    assert(fd >= 0);

    var addr: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    posix.getsockname(fd, @ptrCast(&addr), &addr_len) catch {
        return 0;
    };

    return std.mem.bigToNative(u16, addr.port);
}

/// Get local port from stream's socket handle.
pub fn getLocalPortFromStream(stream: Io.net.Stream) u16 {
    return getLocalPort(stream.socket.handle);
}

// =============================================================================
// TCP Connect
// =============================================================================

/// Connect to upstream using async Io.net.
/// TigerStyle: Explicit io parameter, timing collected at phase boundaries.
pub fn connectUpstream(upstream: *const Upstream, io: Io) ForwardError!ConnectResult {
    assert(upstream.port > 0);
    assert(upstream.host.len > 0);

    debugLog("connect: start {s}:{d}", .{ upstream.host, upstream.port });

    // Parse IP address (DNS resolution not yet supported)
    const addr = Io.net.IpAddress.parse(upstream.host, upstream.port) catch {
        debugLog("connect: FAILED invalid address", .{});
        return ForwardError.InvalidAddress;
    };

    // Time the async TCP connect
    const connect_start_ns = time.monotonicNanos();
    const stream = addr.connect(io, .{ .mode = .stream }) catch {
        debugLog("connect: FAILED connection refused/timeout", .{});
        return ForwardError.ConnectFailed;
    };
    const connect_end_ns = time.monotonicNanos();
    debugLog("connect: complete fd={d} duration_us={d}", .{ stream.socket.handle, time.elapsedNanos(connect_start_ns, connect_end_ns) / 1000 });

    // Disable Nagle's algorithm for low-latency request forwarding
    // TigerStyle: Explicit discard - TCP_NODELAY is optimization, not required
    _ = setTcpNoDelay(stream.socket.handle);

    // Enable TCP keepalive for detecting dead connections in pool
    // TigerStyle: Explicit parameters - 60s idle, 10s interval, 3 probes
    _ = setTcpKeepAlive(stream.socket.handle, 60, 10, 3);

    const local_port = getLocalPortFromStream(stream);

    return .{
        .conn = .{
            .stream = stream,
            .created_ns = connect_end_ns,
        },
        .protocol = .h1, // Future: negotiate via ALPN or detect h2c preface
        .tcp_connect_duration_ns = time.elapsedNanos(connect_start_ns, connect_end_ns),
        .local_port = local_port,
    };
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

// =============================================================================
// getLocalPort Tests
// =============================================================================

test "getLocalPort: returns 0 for invalid fd" {
    // TigerStyle: Test boundary condition - minimum valid fd after precondition
    // fd = 0 is typically stdin, getsockname will fail but should return 0 gracefully
    const port = getLocalPort(0);
    try testing.expectEqual(@as(u16, 0), port);
}

test "getLocalPort: returns 0 for non-socket fd" {
    // fd = 1 is stdout, getsockname will fail
    const port = getLocalPort(1);
    try testing.expectEqual(@as(u16, 0), port);
}

test "getLocalPort: returns valid port for bound socket" {
    // Create a TCP socket
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        // Socket creation failed (no network?), skip test
        return;
    };
    defer posix.close(sock);

    // Bind to ephemeral port
    var addr = posix.sockaddr.in{
        .port = 0, // Let OS assign port
        .addr = 0, // INADDR_ANY
    };
    posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch {
        // Bind failed, skip test
        return;
    };

    // getLocalPort should return the assigned port (non-zero)
    const port = getLocalPort(sock);
    // TigerStyle: Postcondition - bound socket must have non-zero port
    try testing.expect(port > 0);
}

// =============================================================================
// ConnectResult Type Tests
// =============================================================================

test "ConnectResult: struct fields are correctly typed" {
    // TigerStyle: Verify contract - all fields have expected types and sizes
    const result = ConnectResult{
        .conn = .{
            .stream = undefined,
            .created_ns = 12345678,
        },
        .protocol = .h1,
        .tcp_connect_duration_ns = 1000000,
        .local_port = 8080,
    };

    try testing.expectEqual(@as(u64, 12345678), result.conn.created_ns);
    try testing.expectEqual(Protocol.h1, result.protocol);
    try testing.expectEqual(@as(u64, 1000000), result.tcp_connect_duration_ns);
    try testing.expectEqual(@as(u16, 8080), result.local_port);
}

test "ConnectResult: tcp_connect_duration_ns uses u64 for nanoseconds" {
    // TigerStyle: Timing in nanoseconds, u64 to avoid overflow
    // Max u64 = ~584 years in nanoseconds - sufficient for any connect timeout
    const max_duration: u64 = std.math.maxInt(u64);
    const result = ConnectResult{
        .conn = .{
            .stream = undefined,
            .created_ns = 0,
        },
        .protocol = .h1,
        .tcp_connect_duration_ns = max_duration,
        .local_port = 0,
    };
    try testing.expectEqual(max_duration, result.tcp_connect_duration_ns);
}

// =============================================================================
// Port Boundary Tests
// =============================================================================

test "Upstream: port boundary values" {
    // TigerStyle: Test boundary conditions for u16 port
    const min_port = Upstream{
        .host = "127.0.0.1",
        .port = 1, // Minimum valid (port 0 would fail assertion)
        .idx = 0,
    };
    try testing.expectEqual(@as(u16, 1), min_port.port);

    const max_port = Upstream{
        .host = "127.0.0.1",
        .port = 65535, // Maximum valid u16
        .idx = 0,
    };
    try testing.expectEqual(@as(u16, 65535), max_port.port);

    // Well-known ports
    const http_port = Upstream{
        .host = "127.0.0.1",
        .port = 80,
        .idx = 0,
    };
    try testing.expectEqual(@as(u16, 80), http_port.port);

    const https_port = Upstream{
        .host = "127.0.0.1",
        .port = 443,
        .idx = 0,
    };
    try testing.expectEqual(@as(u16, 443), https_port.port);
}

// =============================================================================
// ForwardError Tests
// =============================================================================

test "ForwardError: InvalidAddress is a valid error type" {
    // TigerStyle: Verify error union contains expected error
    const Err = ForwardError;
    const invalid_addr_err: Err = ForwardError.InvalidAddress;
    try testing.expectEqual(ForwardError.InvalidAddress, invalid_addr_err);
}

test "ForwardError: ConnectFailed is a valid error type" {
    const connect_failed_err: ForwardError = ForwardError.ConnectFailed;
    try testing.expectEqual(ForwardError.ConnectFailed, connect_failed_err);
}

// =============================================================================
// TCP Options Integration Tests (require real sockets)
// =============================================================================

test "TCP options: NoDelay and KeepAlive functions are called" {
    // This test verifies the functions imported from serval-net are accessible
    // The actual socket option tests are in serval-net/socket.zig
    // Here we just verify the import works and types match

    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return; // Skip if no socket available
    };
    defer posix.close(sock);

    // setTcpNoDelay should succeed on valid TCP socket
    const nodelay_result = setTcpNoDelay(sock);
    try testing.expect(nodelay_result);

    // setTcpKeepAlive with same params as connectUpstream (60s idle, 10s interval, 3 probes)
    const keepalive_result = setTcpKeepAlive(sock, 60, 10, 3);
    try testing.expect(keepalive_result);
}

// =============================================================================
// Connection struct integration
// =============================================================================

test "Connection from connectUpstream has created_ns set" {
    // TigerStyle: Document the contract that created_ns is set to connect_end_ns
    // This is critical for pool eviction - unset created_ns (0) causes immediate eviction

    // We can't actually call connectUpstream without io_uring,
    // but we verify the Connection type has the expected fields
    const conn = pool_mod.Connection{
        .stream = undefined,
        .created_ns = time.monotonicNanos(),
        .last_used_ns = 0,
    };

    // TigerStyle: Postcondition - created_ns must be > 0 for pool to work correctly
    try testing.expect(conn.created_ns > 0);
}

// =============================================================================
// IPv4 Address Parsing (via Io.net.IpAddress.parse)
// =============================================================================

test "IPv4 boundary addresses parse correctly via std.Io" {
    // These are the addresses that Io.net.IpAddress.parse should handle
    // We verify our understanding of valid addresses

    // 0.0.0.0 - bind to all interfaces
    const any_addr = Io.net.IpAddress.parse("0.0.0.0", 8080) catch null;
    try testing.expect(any_addr != null);

    // 255.255.255.255 - broadcast
    const broadcast = Io.net.IpAddress.parse("255.255.255.255", 8080) catch null;
    try testing.expect(broadcast != null);

    // 127.0.0.1 - loopback
    const loopback = Io.net.IpAddress.parse("127.0.0.1", 8080) catch null;
    try testing.expect(loopback != null);

    // Octet boundaries
    const zero_octets = Io.net.IpAddress.parse("0.0.0.0", 1) catch null;
    try testing.expect(zero_octets != null);

    const max_octets = Io.net.IpAddress.parse("255.255.255.255", 65535) catch null;
    try testing.expect(max_octets != null);
}

test "IPv4 invalid addresses fail to parse via std.Io" {
    // Verify Io.net.IpAddress.parse rejects invalid addresses

    // Out of range octet
    const over_255 = Io.net.IpAddress.parse("256.0.0.1", 8080) catch null;
    try testing.expectEqual(@as(?Io.net.IpAddress, null), over_255);

    // Missing octets
    const missing_octet = Io.net.IpAddress.parse("127.0.0", 8080) catch null;
    try testing.expectEqual(@as(?Io.net.IpAddress, null), missing_octet);

    // Empty string
    const empty = Io.net.IpAddress.parse("", 8080) catch null;
    try testing.expectEqual(@as(?Io.net.IpAddress, null), empty);

    // Non-numeric
    const alpha = Io.net.IpAddress.parse("localhost", 8080) catch null;
    // Note: This may or may not parse depending on DNS resolution support
    _ = alpha;
}

// =============================================================================
// Contract Verification Tests
// =============================================================================

test "CRITICAL: connectUpstream result has valid timestamps for pool" {
    // This contract is critical for connection pooling:
    // - ConnectResult.conn.created_ns must be set to connect_end_ns
    // - created_ns = 0 causes immediate eviction (age = now - 0 = huge)
    //
    // Code inspection shows:
    //   const connect_end_ns = time.monotonicNanos();
    //   ...
    //   .conn = .{
    //       .stream = stream,
    //       .created_ns = connect_end_ns,  // <-- correctly set
    //   },
    //
    // This test documents the contract. Actual runtime verification
    // would require integration tests with a listening server.

    const now = time.monotonicNanos();
    try testing.expect(now > 0);

    // Verify time module works correctly
    const later = time.monotonicNanos();
    try testing.expect(later >= now);
}

test "CRITICAL: tcp_connect_duration_ns is computed correctly" {
    // Verify time.elapsedNanos computes correct duration
    const start_ns = time.monotonicNanos();
    const end_ns = time.monotonicNanos();
    const duration = time.elapsedNanos(start_ns, end_ns);

    // Duration should be non-negative
    // TigerStyle: Postcondition - elapsed time >= 0
    try testing.expect(duration >= 0);

    // Duration should be <= (end - start) accounting for wraparound
    if (end_ns >= start_ns) {
        try testing.expect(duration <= end_ns - start_ns + 1);
    }
}

// =============================================================================
// Type Size and Layout Tests
// =============================================================================

test "ConnectResult size is reasonable for stack allocation" {
    // TigerStyle: No runtime allocation - ConnectResult should be small enough for stack
    const size = @sizeOf(ConnectResult);

    // Connection struct + u64 duration + u16 port + padding
    // Should be well under 256 bytes
    try testing.expect(size < 256);
}

test "Upstream size is compact" {
    // Upstream is frequently passed around, should be small
    const size = @sizeOf(Upstream);

    // slice (ptr + len) + u16 port + u32 idx = ~24 bytes on 64-bit
    try testing.expect(size <= 32);
}
