// lib/serval-proxy/connect.zig
//! Connection Management
//!
//! Thin wrapper around serval-client for upstream connections.
//! Provides proxy-specific ConnectResult type for observability.
//!
//! TigerStyle: Delegates to serval-client, adds proxy-specific fields.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const Io = std.Io;

const serval_core = @import("serval-core");
const debugLog = serval_core.debugLog;
const time = serval_core.time;

const serval_net = @import("serval-net");
const DnsResolver = serval_net.DnsResolver;

const serval_socket = @import("serval-socket");
const Socket = serval_socket.Socket;

const serval_client = @import("serval-client");
const Client = serval_client.Client;
const ClientError = serval_client.ClientError;

const types = @import("types.zig");
const ForwardError = types.ForwardError;
const Protocol = types.Protocol;

const Upstream = serval_core.types.Upstream;

const serval_tls = @import("serval-tls");
const ssl = serval_tls.ssl;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for upstream connection.
/// TigerStyle: Explicit config struct, no hidden defaults.
pub const ConnectConfig = struct {
    /// Connection timeout in nanoseconds.
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    timeout_ns: u64,
    /// Whether to verify upstream TLS certificates.
    /// TigerStyle: Explicit, not inferred from environment.
    verify_upstream_tls: bool,
    /// Optional SSL context for TLS connections.
    /// Caller provides this for TLS; null means no TLS capability.
    /// TigerStyle: Caller owns context lifecycle.
    client_ctx: ?*ssl.SSL_CTX = null,
};

// =============================================================================
// Connection Result
// =============================================================================

/// Result of connecting to upstream, includes timing and socket info.
/// TigerStyle: Wraps serval-client result with proxy-specific fields.
pub const ConnectResult = struct {
    /// Unified socket abstraction (plain or TLS).
    /// TigerStyle: Single type for both, caller uses read/write interface.
    socket: Socket,
    /// Timestamp when connection was established (monotonic nanoseconds).
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    created_ns: u64,
    /// Protocol negotiated at connection time. Immutable for connection lifetime.
    /// TigerStyle: Single source of truth, no mid-connection renegotiation.
    /// Future: TLS negotiation via ALPN, h2c detection via preface.
    protocol: Protocol,
    /// Duration of DNS resolution in nanoseconds (0 if IP address was used).
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    dns_duration_ns: u64,
    /// Duration of TCP connect in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// Duration of TLS handshake in nanoseconds (0 if plaintext).
    tls_handshake_duration_ns: u64,
    /// Local port of the connection.
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

/// Get local port from Socket abstraction.
/// TigerStyle: Works with both plain and TLS sockets.
pub fn getLocalPortFromSocket(socket: Socket) u16 {
    return getLocalPort(socket.get_fd());
}

// =============================================================================
// TCP Connect
// =============================================================================

/// Connect to upstream using serval-client.
/// TigerStyle: Delegates to serval-client, maps errors to ForwardError.
pub fn connectUpstream(
    upstream: *const Upstream,
    io: Io,
    cfg: ConnectConfig,
    dns_resolver: *DnsResolver,
) ForwardError!ConnectResult {
    // S1: preconditions
    assert(upstream.port > 0);
    assert(upstream.host.len > 0);
    assert(cfg.timeout_ns > 0);
    assert(@intFromPtr(dns_resolver) != 0);

    debugLog("connect: start {s}:{d} tls={}", .{ upstream.host, upstream.port, upstream.tls });

    // Create a temporary client for this connection.
    // TigerStyle: Client is lightweight, no allocation.
    var client = Client.init(
        std.heap.page_allocator, // Unused by client
        dns_resolver,
        cfg.client_ctx,
        cfg.verify_upstream_tls,
    );

    // Connect using serval-client
    const client_result = client.connect(upstream.*, io) catch |err| {
        debugLog("connect: FAILED err={s}", .{@errorName(err)});
        return mapClientError(err);
    };

    debugLog("connect: complete fd={d} dns_us={d} tcp_us={d} tls_us={d}", .{
        client_result.conn.socket.get_fd(),
        client_result.dns_duration_ns / 1000,
        client_result.tcp_connect_duration_ns / 1000,
        client_result.tls_handshake_duration_ns / 1000,
    });

    // S1: postcondition - socket fd is valid
    assert(client_result.conn.socket.get_fd() >= 0);

    return .{
        .socket = client_result.conn.socket,
        .created_ns = client_result.conn.created_ns,
        .protocol = .h1, // Future: negotiate via ALPN or detect h2c preface
        .dns_duration_ns = client_result.dns_duration_ns,
        .tcp_connect_duration_ns = client_result.tcp_connect_duration_ns,
        .tls_handshake_duration_ns = client_result.tls_handshake_duration_ns,
        .local_port = client_result.local_port,
    };
}

/// Map ClientError to ForwardError.
/// TigerStyle S6: Explicit error handling.
fn mapClientError(err: ClientError) ForwardError {
    return switch (err) {
        ClientError.DnsResolutionFailed => ForwardError.DnsResolutionFailed,
        ClientError.TcpConnectFailed => ForwardError.ConnectFailed,
        ClientError.TcpConnectTimeout => ForwardError.ConnectFailed,
        ClientError.TlsHandshakeFailed => ForwardError.ConnectFailed,
        // Send/Recv errors shouldn't occur during connect, but map them anyway
        ClientError.SendFailed,
        ClientError.SendTimeout,
        ClientError.BufferTooSmall,
        ClientError.RecvFailed,
        ClientError.RecvTimeout,
        ClientError.ResponseHeadersTooLarge,
        ClientError.InvalidResponseStatus,
        ClientError.InvalidResponseHeaders,
        ClientError.ConnectionClosed,
        => ForwardError.ConnectFailed,
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
// ConnectConfig Type Tests
// =============================================================================

test "ConnectConfig: struct fields have correct defaults" {
    // TigerStyle: Verify config defaults and required fields
    const config = ConnectConfig{
        .timeout_ns = 5_000_000_000, // 5 seconds
        .verify_upstream_tls = true,
        // client_ctx defaults to null
    };

    try testing.expectEqual(@as(u64, 5_000_000_000), config.timeout_ns);
    try testing.expect(config.verify_upstream_tls);
    try testing.expectEqual(@as(?*ssl.SSL_CTX, null), config.client_ctx);
}

test "ConnectConfig: timeout_ns uses nanoseconds" {
    // TigerStyle: Verify unit consistency
    // 30 second timeout
    const config = ConnectConfig{
        .timeout_ns = 30_000_000_000,
        .verify_upstream_tls = false,
    };

    try testing.expectEqual(@as(u64, 30_000_000_000), config.timeout_ns);
}

// =============================================================================
// ConnectResult Type Tests
// =============================================================================

test "ConnectResult: struct fields are correctly typed" {
    // TigerStyle: Verify contract - all fields have expected types and sizes
    // Create a real socket to get a valid fd
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return; // Skip if socket creation fails
    };
    defer posix.close(sock);

    const result = ConnectResult{
        .socket = Socket.Plain.init_client(sock),
        .created_ns = 12345678,
        .protocol = .h1,
        .dns_duration_ns = 500000,
        .tcp_connect_duration_ns = 1000000,
        .tls_handshake_duration_ns = 0,
        .local_port = 8080,
    };

    try testing.expectEqual(@as(u64, 12345678), result.created_ns);
    try testing.expectEqual(Protocol.h1, result.protocol);
    try testing.expectEqual(@as(u64, 500000), result.dns_duration_ns);
    try testing.expectEqual(@as(u64, 1000000), result.tcp_connect_duration_ns);
    try testing.expectEqual(@as(u64, 0), result.tls_handshake_duration_ns);
    try testing.expectEqual(@as(u16, 8080), result.local_port);
    try testing.expect(!result.socket.is_tls());
    try testing.expectEqual(sock, result.socket.get_fd());
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
// mapClientError Tests
// =============================================================================

test "mapClientError: maps DNS errors" {
    try testing.expectEqual(ForwardError.DnsResolutionFailed, mapClientError(ClientError.DnsResolutionFailed));
}

test "mapClientError: maps connect errors" {
    try testing.expectEqual(ForwardError.ConnectFailed, mapClientError(ClientError.TcpConnectFailed));
    try testing.expectEqual(ForwardError.ConnectFailed, mapClientError(ClientError.TcpConnectTimeout));
    try testing.expectEqual(ForwardError.ConnectFailed, mapClientError(ClientError.TlsHandshakeFailed));
}

// =============================================================================
// ConnectResult size test
// =============================================================================

test "ConnectResult size is reasonable for stack allocation" {
    // TigerStyle: No runtime allocation - ConnectResult should be small enough for stack
    const size = @sizeOf(ConnectResult);

    // Connection struct + timing fields + port + padding
    // Should be well under 256 bytes
    try testing.expect(size < 256);
}

test "Upstream size is compact" {
    // Upstream is frequently passed around, should be small
    const size = @sizeOf(Upstream);

    // slice (ptr + len) + u16 port + u6 idx + bool tls = ~24 bytes on 64-bit
    try testing.expect(size <= 32);
}
