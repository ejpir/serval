// serval-client/client.zig
//! HTTP/1.1 Client
//!
//! Unified HTTP client for making requests to upstream servers.
//! Handles DNS resolution, TCP connection, optional TLS handshake.
//! TigerStyle: Zero allocation after init, explicit errors, ~2 assertions per function.
//!
//! Layer: 2 (Infrastructure) - alongside serval-pool, serval-prober, serval-health

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const posix = std.posix;

const serval_core = @import("serval-core");
const types = serval_core.types;
const config = serval_core.config;
const time = serval_core.time;
const Upstream = types.Upstream;

const net = @import("serval-net");
const DnsResolver = net.DnsResolver;
const Socket = net.Socket;
const SocketError = net.SocketError;

const pool_mod = @import("serval-pool");
pub const Connection = pool_mod.pool.Connection;

const tls = @import("serval-tls");
const ssl = tls.ssl;

const request_mod = @import("request.zig");
const response_mod = @import("response.zig");
const ResponseHeaders = response_mod.ResponseHeaders;
const ResponseError = response_mod.ResponseError;

// =============================================================================
// Error Types
// =============================================================================

/// Unified client error type combining connection, request, and response errors.
/// TigerStyle: Explicit error set, no catch {}.
pub const ClientError = error{
    // Connection errors
    /// DNS resolution failed (hostname not found, DNS server unreachable).
    DnsResolutionFailed,
    /// TCP connection failed (refused, network unreachable).
    TcpConnectFailed,
    /// TCP connection timed out.
    TcpConnectTimeout,
    /// TLS handshake failed (certificate error, protocol mismatch).
    TlsHandshakeFailed,

    // Send errors (from request module)
    /// Send operation failed (socket error, connection reset).
    SendFailed,
    /// Send operation timed out.
    SendTimeout,
    /// Request headers exceeded buffer size.
    BufferTooSmall,

    // Receive errors (from response module)
    /// Receive operation failed (socket error).
    RecvFailed,
    /// Receive operation timed out.
    RecvTimeout,
    /// Response headers exceeded buffer size.
    ResponseHeadersTooLarge,
    /// Invalid HTTP status line.
    InvalidResponseStatus,
    /// Invalid HTTP response headers.
    InvalidResponseHeaders,
    /// Connection closed by peer before response complete.
    ConnectionClosed,
};

// =============================================================================
// Result Types
// =============================================================================

/// Result of connecting to an upstream server.
/// Includes timing information for observability.
/// TigerStyle: Explicit struct with timing fields.
pub const ConnectResult = struct {
    /// Connection to upstream (caller must release to pool or close).
    conn: Connection,
    /// Duration of DNS resolution in nanoseconds (0 if cached or IP address).
    dns_duration_ns: u64,
    /// Duration of TCP connect in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// Duration of TLS handshake in nanoseconds (0 if plaintext).
    tls_handshake_duration_ns: u64,
    /// Local port of the connection.
    local_port: u16,
};

/// Result of a complete HTTP request (connect + send + read headers).
/// TigerStyle: Explicit struct with owned connection.
pub const RequestResult = struct {
    /// Connection to upstream (caller must release to pool or close).
    conn: Connection,
    /// Parsed response headers.
    response: ResponseHeaders,
};

// =============================================================================
// Client
// =============================================================================

/// HTTP/1.1 client for upstream connections.
/// TigerStyle: Fixed configuration, no runtime allocation.
pub const Client = struct {
    /// Allocator for potential future use (currently unused).
    allocator: std.mem.Allocator,

    /// DNS resolver for hostname lookups.
    dns_resolver: *DnsResolver,

    /// TLS context for client connections (null = plaintext only).
    /// TigerStyle: Optional TLS support, explicit null for plaintext.
    client_ctx: ?*ssl.SSL_CTX,

    /// Whether to verify upstream TLS certificates.
    /// TigerStyle: Explicit boolean, no implicit behavior.
    verify_tls: bool,

    /// Whether to enable kernel TLS offload for connections.
    /// Default true for performance. Set false if kTLS causes EBADMSG errors
    /// with specific servers (e.g., K8s API).
    enable_ktls: bool,

    /// Initialize a new HTTP client with kTLS enabled (default).
    /// TigerStyle S1: Assertions for preconditions.
    pub fn init(
        allocator: std.mem.Allocator,
        dns_resolver: *DnsResolver,
        client_ctx: ?*ssl.SSL_CTX,
        verify_tls: bool,
    ) Client {
        return initWithOptions(allocator, dns_resolver, client_ctx, verify_tls, true);
    }

    /// Initialize a new HTTP client with explicit kTLS control.
    /// TigerStyle S1: Assertions for preconditions.
    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        dns_resolver: *DnsResolver,
        client_ctx: ?*ssl.SSL_CTX,
        verify_tls: bool,
        enable_ktls: bool,
    ) Client {
        // S1: precondition - dns_resolver must be valid
        assert(@intFromPtr(dns_resolver) != 0);
        // S1: precondition - if verify_tls is true, client_ctx should be set (advisory)
        // Note: We don't assert this because plaintext-only clients may have verify_tls=true
        // as a default, and client_ctx=null means TLS upstreams will fail explicitly.

        return .{
            .allocator = allocator,
            .dns_resolver = dns_resolver,
            .client_ctx = client_ctx,
            .verify_tls = verify_tls,
            .enable_ktls = enable_ktls,
        };
    }

    /// Deinitialize the client.
    /// Currently a no-op since we don't own the dns_resolver or client_ctx.
    /// TigerStyle: Explicit cleanup path, even if empty.
    pub fn deinit(self: *Client) void {
        // We don't own dns_resolver or client_ctx, so nothing to clean up
        _ = self;
    }

    /// Connect to an upstream server.
    /// Performs DNS resolution, TCP connection, and optional TLS handshake.
    /// Returns ConnectResult with timing information for observability.
    /// TigerStyle S1: ~2 assertions, S3: bounded operations via Io.
    pub fn connect(
        self: *Client,
        upstream: Upstream,
        io: Io,
    ) ClientError!ConnectResult {
        // S1: preconditions
        assert(upstream.host.len > 0); // S1: non-empty host
        assert(upstream.port > 0); // S1: valid port

        // Step 1: DNS resolution (timed)
        const dns_start_ns = time.monotonicNanos();
        const resolve_result = self.dns_resolver.resolve(
            upstream.host,
            upstream.port,
            io,
        ) catch {
            return ClientError.DnsResolutionFailed;
        };
        const dns_end_ns = time.monotonicNanos();
        const dns_duration_ns = time.elapsedNanos(dns_start_ns, dns_end_ns);

        // S2: postcondition - resolved address has correct port
        assert(resolve_result.address.getPort() == upstream.port);

        // Step 2: TCP connection (timed)
        const tcp_start_ns = time.monotonicNanos();
        const fd = tcpConnect(resolve_result.address, io) catch |err| {
            return mapConnectError(err);
        };
        const tcp_end_ns = time.monotonicNanos();
        const tcp_connect_duration_ns = time.elapsedNanos(tcp_start_ns, tcp_end_ns);

        // S2: postcondition - valid fd
        assert(fd >= 0);

        // Configure socket for low latency
        _ = net.setTcpNoDelay(fd);
        _ = net.setTcpKeepAlive(fd, 60, 10, 3);

        // Get local port for observability
        const local_port = getLocalPort(fd);

        // Step 3: Optional TLS handshake (timed)
        const tls_start_ns = time.monotonicNanos();
        const socket: Socket = if (upstream.tls) blk: {
            // TLS required - client_ctx must be set
            const ctx = self.client_ctx orelse {
                // No TLS context - cannot connect to TLS upstream
                posix.close(fd);
                return ClientError.TlsHandshakeFailed;
            };

            // Perform TLS handshake with SNI
            // Strip trailing dot from hostname for SNI (FQDN dots are not valid in SNI)
            const sni_host = if (std.mem.endsWith(u8, upstream.host, "."))
                upstream.host[0 .. upstream.host.len - 1]
            else
                upstream.host;
            const tls_socket = Socket.TLS.TLSSocket.initClientWithOptions(
                fd,
                ctx,
                sni_host,
                self.enable_ktls,
            ) catch {
                posix.close(fd);
                return ClientError.TlsHandshakeFailed;
            };

            break :blk tls_socket;
        } else blk: {
            // Plaintext connection
            break :blk Socket.Plain.initClient(fd);
        };
        const tls_end_ns = time.monotonicNanos();
        const tls_handshake_duration_ns = if (upstream.tls)
            time.elapsedNanos(tls_start_ns, tls_end_ns)
        else
            0;

        // Build connection with timestamps
        const now_ns = time.monotonicNanos();
        const conn = Connection{
            .socket = socket,
            .created_ns = now_ns,
            .last_used_ns = now_ns,
        };

        return ConnectResult{
            .conn = conn,
            .dns_duration_ns = dns_duration_ns,
            .tcp_connect_duration_ns = tcp_connect_duration_ns,
            .tls_handshake_duration_ns = tls_handshake_duration_ns,
            .local_port = local_port,
        };
    }

    /// Send an HTTP request on an existing connection.
    /// Delegates to request.sendRequest with proper error mapping.
    /// TigerStyle S1: Precondition assertions.
    pub fn sendRequest(
        self: *Client,
        conn: *Connection,
        req: *const types.Request,
        effective_path: ?[]const u8,
    ) ClientError!void {
        _ = self; // Client state not needed for send

        // S1: preconditions
        const path = effective_path orelse req.path;
        assert(path.len > 0); // S1: non-empty path

        request_mod.sendRequest(&conn.socket, req, effective_path) catch |err| {
            return mapRequestError(err);
        };
    }

    /// Read HTTP response headers from an existing connection.
    /// Delegates to response.readResponseHeaders with proper error mapping.
    /// TigerStyle S1: Precondition assertions.
    pub fn readResponseHeaders(
        self: *Client,
        conn: *Connection,
        header_buf: []u8,
    ) ClientError!ResponseHeaders {
        _ = self; // Client state not needed for receive

        // S1: preconditions
        assert(header_buf.len > 0); // S1: non-empty buffer
        assert(header_buf.len <= config.MAX_HEADER_SIZE_BYTES); // S1: bounded buffer

        return response_mod.readResponseHeaders(&conn.socket, header_buf) catch |err| {
            return mapResponseError(err);
        };
    }

    /// Perform a complete HTTP request (connect + send + read headers).
    /// Convenience function for simple request/response flows.
    /// TigerStyle S1: Precondition assertions.
    pub fn request(
        self: *Client,
        upstream: Upstream,
        req: *const types.Request,
        header_buf: []u8,
        io: Io,
    ) ClientError!RequestResult {
        // S1: preconditions
        assert(upstream.host.len > 0); // S1: non-empty host
        assert(header_buf.len > 0); // S1: non-empty buffer

        // Step 1: Connect
        var connect_result = try self.connect(upstream, io);
        errdefer connect_result.conn.close();

        // Step 2: Send request
        try self.sendRequest(&connect_result.conn, req, null);

        // Step 3: Read response headers
        const response = try self.readResponseHeaders(&connect_result.conn, header_buf);

        // S2: postcondition - valid response status
        assert(response.status >= 100 and response.status <= 599);

        return .{
            .conn = connect_result.conn,
            .response = response,
        };
    }
};

// =============================================================================
// Internal Functions
// =============================================================================

/// Get local port from connected socket.
/// Returns 0 if unable to retrieve (non-fatal).
/// TigerStyle: Graceful fallback, no panic on failure.
fn getLocalPort(fd: i32) u16 {
    assert(fd >= 0);

    var addr: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    posix.getsockname(fd, @ptrCast(&addr), &addr_len) catch {
        return 0;
    };

    return std.mem.bigToNative(u16, addr.port);
}

/// Perform TCP connection using Io async API.
/// TigerStyle: Bounded via Io cancellation, explicit error return.
fn tcpConnect(address: Io.net.IpAddress, io: Io) !i32 {
    // Use IpAddress.connect() to perform async TCP connect
    // This creates the socket and connects in one step
    const stream = address.connect(io, .{ .mode = .stream }) catch {
        return error.ConnectionFailed;
    };

    return stream.socket.handle;
}

/// Map DNS errors to ClientError.
/// TigerStyle S6: Explicit error handling.
fn mapDnsError(err: net.DnsError) ClientError {
    return switch (err) {
        net.DnsError.DnsResolutionFailed => ClientError.DnsResolutionFailed,
        net.DnsError.DnsTimeout => ClientError.DnsResolutionFailed,
        net.DnsError.InvalidHostname => ClientError.DnsResolutionFailed,
        net.DnsError.CacheFull => ClientError.DnsResolutionFailed,
    };
}

/// Map TCP connect errors to ClientError.
/// TigerStyle S6: Explicit error handling.
fn mapConnectError(err: anyerror) ClientError {
    return switch (err) {
        error.ConnectionRefused => ClientError.TcpConnectFailed,
        error.NetworkUnreachable => ClientError.TcpConnectFailed,
        error.ConnectionFailed => ClientError.TcpConnectFailed,
        error.ConnectionTimedOut => ClientError.TcpConnectTimeout,
        error.ConnectionResetByPeer => ClientError.TcpConnectFailed,
        else => ClientError.TcpConnectFailed,
    };
}

/// Map request module errors to ClientError.
/// TigerStyle S6: Explicit error handling.
fn mapRequestError(err: request_mod.ClientError) ClientError {
    return switch (err) {
        request_mod.ClientError.SendFailed => ClientError.SendFailed,
        request_mod.ClientError.SendTimeout => ClientError.SendTimeout,
        request_mod.ClientError.BufferTooSmall => ClientError.BufferTooSmall,
    };
}

/// Map response module errors to ClientError.
/// TigerStyle S6: Explicit error handling.
fn mapResponseError(err: ResponseError) ClientError {
    return switch (err) {
        ResponseError.RecvFailed => ClientError.RecvFailed,
        ResponseError.RecvTimeout => ClientError.RecvTimeout,
        ResponseError.ResponseHeadersTooLarge => ClientError.ResponseHeadersTooLarge,
        ResponseError.InvalidResponseStatus => ClientError.InvalidResponseStatus,
        ResponseError.InvalidResponseHeaders => ClientError.InvalidResponseHeaders,
        ResponseError.ConnectionClosed => ClientError.ConnectionClosed,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "Client.init creates client with valid fields" {
    var dns_resolver = DnsResolver.init(.{});
    const client = Client.init(
        std.testing.allocator,
        &dns_resolver,
        null, // No TLS
        false,
    );

    try std.testing.expect(@intFromPtr(client.dns_resolver) != 0);
    try std.testing.expect(client.client_ctx == null);
    try std.testing.expect(client.verify_tls == false);
}

test "Client.init with TLS context" {
    var dns_resolver = DnsResolver.init(.{});

    // We can't actually create a valid SSL_CTX in tests without OpenSSL setup,
    // but we can verify the field is stored correctly with a dummy pointer.
    // In real usage, the caller provides a properly initialized SSL_CTX.
    const client = Client.init(
        std.testing.allocator,
        &dns_resolver,
        null, // No TLS in test
        true, // verify_tls enabled
    );

    try std.testing.expect(client.verify_tls == true);
}

test "Client.deinit is safe to call" {
    var dns_resolver = DnsResolver.init(.{});
    var client = Client.init(
        std.testing.allocator,
        &dns_resolver,
        null,
        false,
    );

    // Should not crash
    client.deinit();
}

test "ClientError error set has all expected variants" {
    // Verify all error variants exist
    const errors = [_]ClientError{
        ClientError.DnsResolutionFailed,
        ClientError.TcpConnectFailed,
        ClientError.TcpConnectTimeout,
        ClientError.TlsHandshakeFailed,
        ClientError.SendFailed,
        ClientError.SendTimeout,
        ClientError.BufferTooSmall,
        ClientError.RecvFailed,
        ClientError.RecvTimeout,
        ClientError.ResponseHeadersTooLarge,
        ClientError.InvalidResponseStatus,
        ClientError.InvalidResponseHeaders,
        ClientError.ConnectionClosed,
    };

    // Each error should be distinct
    for (errors, 0..) |err1, i| {
        for (errors[i + 1 ..]) |err2| {
            try std.testing.expect(err1 != err2);
        }
    }
}

test "RequestResult struct layout" {
    // Verify struct has expected fields
    const info = @typeInfo(RequestResult);
    try std.testing.expect(info == .@"struct");

    const fields = info.@"struct".fields;
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("conn", fields[0].name);
    try std.testing.expectEqualStrings("response", fields[1].name);
}

test "mapRequestError maps all variants" {
    try std.testing.expectEqual(ClientError.SendFailed, mapRequestError(request_mod.ClientError.SendFailed));
    try std.testing.expectEqual(ClientError.SendTimeout, mapRequestError(request_mod.ClientError.SendTimeout));
    try std.testing.expectEqual(ClientError.BufferTooSmall, mapRequestError(request_mod.ClientError.BufferTooSmall));
}

test "mapResponseError maps all variants" {
    try std.testing.expectEqual(ClientError.RecvFailed, mapResponseError(ResponseError.RecvFailed));
    try std.testing.expectEqual(ClientError.RecvTimeout, mapResponseError(ResponseError.RecvTimeout));
    try std.testing.expectEqual(ClientError.ResponseHeadersTooLarge, mapResponseError(ResponseError.ResponseHeadersTooLarge));
    try std.testing.expectEqual(ClientError.InvalidResponseStatus, mapResponseError(ResponseError.InvalidResponseStatus));
    try std.testing.expectEqual(ClientError.InvalidResponseHeaders, mapResponseError(ResponseError.InvalidResponseHeaders));
    try std.testing.expectEqual(ClientError.ConnectionClosed, mapResponseError(ResponseError.ConnectionClosed));
}

test "mapConnectError maps common errors" {
    try std.testing.expectEqual(ClientError.TcpConnectFailed, mapConnectError(error.ConnectionRefused));
    try std.testing.expectEqual(ClientError.TcpConnectFailed, mapConnectError(error.NetworkUnreachable));
    try std.testing.expectEqual(ClientError.TcpConnectFailed, mapConnectError(error.ConnectionFailed));
    try std.testing.expectEqual(ClientError.TcpConnectTimeout, mapConnectError(error.ConnectionTimedOut));
    try std.testing.expectEqual(ClientError.TcpConnectFailed, mapConnectError(error.ConnectionResetByPeer));
    // Unknown errors map to TcpConnectFailed
    try std.testing.expectEqual(ClientError.TcpConnectFailed, mapConnectError(error.OutOfMemory));
}

test "mapDnsError maps all variants" {
    try std.testing.expectEqual(ClientError.DnsResolutionFailed, mapDnsError(net.DnsError.DnsResolutionFailed));
    try std.testing.expectEqual(ClientError.DnsResolutionFailed, mapDnsError(net.DnsError.DnsTimeout));
    try std.testing.expectEqual(ClientError.DnsResolutionFailed, mapDnsError(net.DnsError.InvalidHostname));
    try std.testing.expectEqual(ClientError.DnsResolutionFailed, mapDnsError(net.DnsError.CacheFull));
}
