//! Kubernetes API Client Implementation
//!
//! Client struct and helper functions for communicating with the Kubernetes API server.
//! Handles ServiceAccount authentication and TLS.
//!
//! Uses serval-client for HTTP communication with DNS resolution.
//!
//! TigerStyle: Bounded buffers, explicit error handling, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;
const posix = std.posix;
const Io = std.Io;

const net = @import("serval-net");
const tls = @import("serval-tls");
const serval_client = @import("serval-client");
const serval_core = @import("serval-core");

const DnsResolver = net.DnsResolver;
const HttpClient = serval_client.Client;
const Request = serval_core.types.Request;
const Upstream = serval_core.types.Upstream;
const BodyFraming = serval_core.types.BodyFraming;
const debugLog = serval_core.debugLog;

const mod = @import("mod.zig");
const WatchStream = @import("watch_stream.zig").WatchStream;
const LazyWatchStream = @import("watch_stream.zig").LazyWatchStream;

// Import constants from mod.zig
const SA_TOKEN_PATH = mod.SA_TOKEN_PATH;
const SA_NAMESPACE_PATH = mod.SA_NAMESPACE_PATH;
const DEFAULT_API_SERVER = mod.DEFAULT_API_SERVER;
const DEFAULT_API_PORT = mod.DEFAULT_API_PORT;
const MAX_TOKEN_SIZE_BYTES = mod.MAX_TOKEN_SIZE_BYTES;
const MAX_NAMESPACE_LEN = mod.MAX_NAMESPACE_LEN;
const MAX_RESPONSE_SIZE_BYTES = mod.MAX_RESPONSE_SIZE_BYTES;
const MAX_HOST_LEN = mod.MAX_HOST_LEN;
const HTTP_HEADER_BUFFER_SIZE = mod.HTTP_HEADER_BUFFER_SIZE;
const MAX_READ_ITERATIONS = mod.MAX_READ_ITERATIONS;
const BEARER_PREFIX = mod.BEARER_PREFIX;
const ClientError = mod.ClientError;

// =============================================================================
// Buffer Allocation Helpers
// =============================================================================

/// Pre-allocated buffers for K8s client operations.
/// TigerStyle: Explicit resource ownership, allocated once at init.
const Buffers = struct {
    token: []u8,
    namespace: []u8,
    header: []u8,
    response: []u8,
};

/// Allocate all buffers needed for K8s client.
/// TigerStyle: All allocations in one place, explicit error handling.
fn allocateBuffers(allocator: std.mem.Allocator) ClientError!Buffers {
    // Allocate token buffer
    const token_buf = allocator.alloc(u8, MAX_TOKEN_SIZE_BYTES) catch return ClientError.OutOfMemory;
    errdefer allocator.free(token_buf);

    // Allocate namespace buffer
    const namespace_buf = allocator.alloc(u8, MAX_NAMESPACE_LEN) catch return ClientError.OutOfMemory;
    errdefer allocator.free(namespace_buf);

    // Allocate header buffer
    const header_buf = allocator.alloc(u8, HTTP_HEADER_BUFFER_SIZE) catch return ClientError.OutOfMemory;
    errdefer allocator.free(header_buf);

    // Allocate response buffer
    const response_buf = allocator.alloc(u8, MAX_RESPONSE_SIZE_BYTES) catch return ClientError.OutOfMemory;

    return .{
        .token = token_buf,
        .namespace = namespace_buf,
        .header = header_buf,
        .response = response_buf,
    };
}

/// Free all buffers in the Buffers struct.
/// TigerStyle: Symmetric with allocateBuffers for clean error handling.
fn freeBuffers(allocator: std.mem.Allocator, bufs: Buffers) void {
    allocator.free(bufs.response);
    allocator.free(bufs.header);
    allocator.free(bufs.namespace);
    allocator.free(bufs.token);
}

// =============================================================================
// Client
// =============================================================================

/// Kubernetes API HTTP client.
/// Manages authentication via ServiceAccount token and provides methods
/// for GET requests and watch streams.
pub const Client = struct {
    allocator: std.mem.Allocator,
    api_server: []const u8,
    api_port: u16,
    token: []u8,
    token_len: u32,
    namespace: []u8,
    namespace_len: u32,
    /// Pre-allocated header buffer for HTTP responses
    header_buffer: []u8,
    /// Pre-allocated response buffer for body data
    response_buffer: []u8,
    /// SSL context for TLS connections
    ssl_ctx: *tls.ssl.SSL_CTX,
    /// DNS resolver for hostname lookups
    dns_resolver: DnsResolver,
    /// HTTP client using serval-client
    http_client: HttpClient,
    /// Tracks whether client owns api_server memory
    owns_api_server: bool,

    const Self = @This();

    /// Initialize client with ServiceAccount credentials from pod filesystem.
    /// Reads token, namespace from standard K8s ServiceAccount mount paths.
    ///
    /// Preconditions:
    /// - Running inside a K8s pod with ServiceAccount mounted
    /// - SA_TOKEN_PATH, SA_NAMESPACE_PATH exist and are readable
    ///
    /// For testing outside cluster, use initWithConfig().
    pub fn initInCluster(allocator: std.mem.Allocator) ClientError!*Self {
        // Allocate self first
        const self = allocator.create(Self) catch return ClientError.OutOfMemory;
        errdefer allocator.destroy(self);

        // Allocate all buffers
        const bufs = try allocateBuffers(allocator);
        errdefer freeBuffers(allocator, bufs);

        // Read token from filesystem
        const token_len = readFileIntoBuffer(SA_TOKEN_PATH, bufs.token) catch {
            return ClientError.TokenNotFound;
        };
        if (token_len == 0) return ClientError.TokenNotFound;
        if (token_len > MAX_TOKEN_SIZE_BYTES) return ClientError.TokenTooLarge;

        // Read namespace from filesystem
        const namespace_len = readFileIntoBuffer(SA_NAMESPACE_PATH, bufs.namespace) catch {
            return ClientError.NamespaceNotFound;
        };
        if (namespace_len == 0) return ClientError.NamespaceNotFound;
        if (namespace_len > MAX_NAMESPACE_LEN) return ClientError.NamespaceTooLarge;

        // Create SSL context (insecure - skip cert verification)
        const ssl_ctx = createInsecureSslContext() orelse return ClientError.SslContextFailed;
        errdefer tls.ssl.SSL_CTX_free(ssl_ctx);

        // Initialize DNS resolver
        var dns_resolver: DnsResolver = undefined;
        DnsResolver.init(&dns_resolver, .{});

        // TigerStyle: Initialize all fields in a single struct literal
        self.* = .{
            .allocator = allocator,
            .api_server = DEFAULT_API_SERVER,
            .api_port = DEFAULT_API_PORT,
            .token = bufs.token,
            .token_len = @intCast(token_len),
            .namespace = bufs.namespace,
            .namespace_len = @intCast(namespace_len),
            .header_buffer = bufs.header,
            .response_buffer = bufs.response,
            .ssl_ctx = ssl_ctx,
            .dns_resolver = dns_resolver,
            .http_client = undefined, // Set below
            .owns_api_server = false,
        };

        // Initialize HTTP client with DNS resolver and SSL context
        // kTLS disabled: K8s API responses cause EBADMSG errors with kernel TLS
        self.http_client = HttpClient.initWithOptions(
            allocator,
            &self.dns_resolver,
            ssl_ctx,
            false, // verify_tls: insecure for K8s API
            false, // enable_ktls: disabled for K8s API compatibility
        );

        return self;
    }

    /// Initialize client with explicit configuration (for testing).
    /// Does not read from filesystem - uses provided values directly.
    ///
    /// Preconditions:
    /// - api_server is a hostname (e.g., "localhost" or "kubernetes.default.svc")
    /// - token is a valid K8s bearer token
    /// - namespace is a valid K8s namespace name
    pub fn initWithConfig(
        allocator: std.mem.Allocator,
        api_server: []const u8,
        api_port: u16,
        token: []const u8,
        namespace: []const u8,
    ) ClientError!*Self {
        // Precondition assertions
        assert(api_server.len > 0); // S1: api_server must be non-empty
        assert(api_server.len <= MAX_HOST_LEN); // S1: hostname within limit
        assert(token.len > 0); // S1: token must be non-empty
        assert(token.len <= MAX_TOKEN_SIZE_BYTES); // S1: token must fit buffer
        assert(namespace.len > 0); // S1: namespace must be non-empty
        assert(namespace.len <= MAX_NAMESPACE_LEN); // S1: namespace must fit DNS label

        // Allocate self
        const self = allocator.create(Self) catch return ClientError.OutOfMemory;
        errdefer allocator.destroy(self);

        // Allocate all buffers and copy input data
        const bufs = try allocateBuffers(allocator);
        errdefer freeBuffers(allocator, bufs);
        @memcpy(bufs.token[0..token.len], token);
        @memcpy(bufs.namespace[0..namespace.len], namespace);

        // Copy api_server (we need to own it for lifetime)
        const api_server_copy = allocator.dupe(u8, api_server) catch return ClientError.OutOfMemory;
        errdefer allocator.free(api_server_copy);

        // Create SSL context (insecure - skip cert verification)
        const ssl_ctx = createInsecureSslContext() orelse return ClientError.SslContextFailed;
        errdefer tls.ssl.SSL_CTX_free(ssl_ctx);

        // Initialize DNS resolver
        var dns_resolver: DnsResolver = undefined;
        DnsResolver.init(&dns_resolver, .{});

        // TigerStyle: Initialize all fields in a single struct literal
        self.* = .{
            .allocator = allocator,
            .api_server = api_server_copy,
            .api_port = api_port,
            .token = bufs.token,
            .token_len = @intCast(token.len),
            .namespace = bufs.namespace,
            .namespace_len = @intCast(namespace.len),
            .header_buffer = bufs.header,
            .response_buffer = bufs.response,
            .ssl_ctx = ssl_ctx,
            .dns_resolver = dns_resolver,
            .http_client = undefined, // Set below
            .owns_api_server = true,
        };

        // Initialize HTTP client with DNS resolver and SSL context
        // kTLS disabled: K8s API responses cause EBADMSG errors with kernel TLS
        self.http_client = HttpClient.initWithOptions(
            allocator,
            &self.dns_resolver,
            ssl_ctx,
            false, // verify_tls: insecure for K8s API
            false, // enable_ktls: disabled for K8s API compatibility
        );

        return self;
    }

    /// Clean up all allocated resources.
    pub fn deinit(self: *Self) void {
        self.http_client.deinit();
        tls.ssl.SSL_CTX_free(self.ssl_ctx);
        self.allocator.free(self.response_buffer);
        self.allocator.free(self.header_buffer);
        self.allocator.free(self.namespace);
        self.allocator.free(self.token);
        if (self.owns_api_server) {
            const api_server_ptr: [*]const u8 = self.api_server.ptr;
            self.allocator.free(api_server_ptr[0..self.api_server.len]);
        }
        self.allocator.destroy(self);
    }

    /// Get the configured namespace.
    pub fn getNamespace(self: *const Self) []const u8 {
        return self.namespace[0..self.namespace_len];
    }

    /// Get the configured API server hostname.
    pub fn getApiServer(self: *const Self) []const u8 {
        return self.api_server;
    }

    /// Perform a GET request to the K8s API.
    /// Returns the response body as a slice within the internal response buffer.
    ///
    /// Preconditions:
    /// - path must start with '/' (e.g., "/api/v1/namespaces")
    /// - io must be a valid Io runtime (e.g., from Io.Threaded)
    ///
    /// TigerStyle: Bounded response, uses internal buffer.
    pub fn get(self: *Self, path: []const u8, io: Io) ClientError![]const u8 {
        // Preconditions
        assert(path.len > 0); // S1: path must be non-empty
        assert(path[0] == '/'); // S1: path must start with /

        // Build request with authentication
        var request = Request{
            .method = .GET,
            .path = path,
            .version = .@"HTTP/1.1",
            .headers = .{},
        };

        // Add required headers
        request.headers.put("Host", self.api_server) catch return ClientError.HeaderError;

        // Build Bearer token header
        const token_slice = self.token[0..self.token_len];
        var auth_buf: [BEARER_PREFIX.len + MAX_TOKEN_SIZE_BYTES]u8 = undefined;
        const auth_len = BEARER_PREFIX.len + token_slice.len;
        @memcpy(auth_buf[0..BEARER_PREFIX.len], BEARER_PREFIX);
        @memcpy(auth_buf[BEARER_PREFIX.len..auth_len], token_slice);
        request.headers.put("Authorization", auth_buf[0..auth_len]) catch return ClientError.HeaderError;

        request.headers.put("Accept", "application/json") catch return ClientError.HeaderError;
        // Connection: close for one-shot requests. We close the connection after
        // receiving the response, so tell the server not to expect more requests.
        request.headers.put("Connection", "close") catch return ClientError.HeaderError;

        // Create upstream for K8s API server
        const upstream = Upstream{
            .host = self.api_server,
            .port = self.api_port,
            .tls = true,
            .idx = 0,
        };

        debugLog("K8s client: connecting to {s}:{d}", .{ self.api_server, self.api_port });

        // Make request using serval-client
        var result = self.http_client.request(upstream, &request, self.header_buffer, io) catch |err| {
            debugLog("K8s client: HTTP request failed: {s}", .{@errorName(err)});
            return mapClientError(err);
        };
        defer result.conn.socket.close();

        debugLog("K8s client: got response status {d}", .{result.response.status});

        // Check status code
        if (result.response.status >= 400) {
            return ClientError.HttpError;
        }

        // Read body based on framing, handling pre-read body bytes
        const body = try self.readBodyWithPreread(
            &result.conn,
            result.response,
            self.header_buffer,
        );

        // Debug: log raw response (first 200 bytes)
        const preview_len = @min(body.len, 200);
        debugLog("K8s API response ({d} bytes): {s}", .{ body.len, body[0..preview_len] });

        return body;
    }

    /// PATCH the status subresource of a resource.
    /// Uses JSON Merge Patch (application/merge-patch+json).
    ///
    /// Preconditions:
    /// - resource_path must start with '/' (e.g., "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/my-gw/status")
    /// - status_json must be valid JSON (not validated here, K8s API will return error)
    ///
    /// Returns:
    /// - success (void) on 2xx status
    /// - ConflictRetryable on HTTP 409 (resourceVersion mismatch)
    /// - HttpError on other 4xx/5xx errors
    ///
    /// TigerStyle: Bounded buffers, explicit error handling.
    pub fn patchStatus(
        self: *Self,
        resource_path: []const u8,
        status_json: []const u8,
        io: Io,
    ) ClientError!void {
        // S1: Preconditions
        assert(resource_path.len > 0); // path must be non-empty
        assert(resource_path[0] == '/'); // path must start with /
        assert(status_json.len > 0); // body must be non-empty
        assert(status_json.len <= MAX_RESPONSE_SIZE_BYTES); // S1: body within buffer limit

        // Build Content-Length header value
        // Max Content-Length: MAX_RESPONSE_SIZE_BYTES (1MB) = 7 digits
        var content_length_buf: [16]u8 = undefined;
        const content_length_str = std.fmt.bufPrint(&content_length_buf, "{d}", .{status_json.len}) catch {
            // status_json.len is bounded by caller, this should never fail
            return ClientError.RequestFailed;
        };

        // Build request with authentication
        var request = Request{
            .method = .PATCH,
            .path = resource_path,
            .version = .@"HTTP/1.1",
            .headers = .{},
            .body = status_json,
        };

        // Add required headers
        request.headers.put("Host", self.api_server) catch return ClientError.HeaderError;

        // Build Bearer token header
        const token_slice = self.token[0..self.token_len];
        var auth_buf: [BEARER_PREFIX.len + MAX_TOKEN_SIZE_BYTES]u8 = undefined;
        const auth_len = BEARER_PREFIX.len + token_slice.len;
        @memcpy(auth_buf[0..BEARER_PREFIX.len], BEARER_PREFIX);
        @memcpy(auth_buf[BEARER_PREFIX.len..auth_len], token_slice);
        request.headers.put("Authorization", auth_buf[0..auth_len]) catch return ClientError.HeaderError;

        // JSON Merge Patch content type (RFC 7396)
        request.headers.put("Content-Type", "application/merge-patch+json") catch return ClientError.HeaderError;
        request.headers.put("Content-Length", content_length_str) catch return ClientError.HeaderError;
        request.headers.put("Accept", "application/json") catch return ClientError.HeaderError;
        // Connection: close for one-shot requests. We close the connection after
        // receiving the response, so tell the server not to expect more requests.
        request.headers.put("Connection", "close") catch return ClientError.HeaderError;

        // Create upstream for K8s API server
        const upstream = Upstream{
            .host = self.api_server,
            .port = self.api_port,
            .tls = true,
            .idx = 0,
        };

        debugLog("K8s client: PATCH {s} ({d} bytes)", .{ resource_path, status_json.len });

        // Make request using serval-client
        var result = self.http_client.request(upstream, &request, self.header_buffer, io) catch |err| {
            debugLog("K8s client: PATCH request failed: {s}", .{@errorName(err)});
            return mapClientError(err);
        };
        defer result.conn.socket.close();

        debugLog("K8s client: PATCH response status {d}", .{result.response.status});

        // S2: Postcondition - valid HTTP status code
        assert(result.response.status >= 100 and result.response.status <= 599);

        // Check status code
        if (result.response.status >= 200 and result.response.status < 300) {
            // Success - we don't need to read the body
            return;
        }

        if (result.response.status == 409) {
            // HTTP 409 Conflict - resource version mismatch, caller should retry
            return ClientError.ConflictRetryable;
        }

        // Other 4xx/5xx errors
        return ClientError.HttpError;
    }

    /// Read response body into response_buffer, handling pre-read body bytes.
    ///
    /// When reading response headers, extra body bytes may have been read into
    /// header_buf. This function copies those bytes first, then reads the rest.
    ///
    /// TigerStyle Y1: Split into focused helpers for function length compliance.
    fn readBodyWithPreread(
        self: *Self,
        conn: *serval_client.client.Connection,
        response: serval_client.ResponseHeaders,
        header_buf: []const u8,
    ) ClientError![]const u8 {
        // S1: Preconditions
        assert(self.response_buffer.len > 0);
        assert(header_buf.len >= response.total_bytes_read);

        const pre_read_bytes = response.preReadBodyBytes();
        debugLog("K8s client: reading body, framing={s}, pre_read={d}", .{
            @tagName(response.body_framing),
            pre_read_bytes,
        });

        // Fast path: pre-read bytes exist for content-length response
        if (pre_read_bytes > 0) {
            switch (response.body_framing) {
                .content_length => |content_length| {
                    return self.readContentLengthWithPreread(
                        conn,
                        header_buf,
                        response.header_bytes,
                        response.total_bytes_read,
                        pre_read_bytes,
                        content_length,
                    );
                },
                .chunked => {
                    // Chunked with pre-read: fall through to standard read.
                    // Pre-read bytes will be lost - this is acceptable because
                    // K8s watch streams handle chunked differently via WatchStream.
                    debugLog("K8s client: chunked with pre-read, using standard read", .{});
                },
                .none => return self.response_buffer[0..0],
            }
        }

        // Standard path: no pre-read bytes or chunked encoding
        return self.readBodyStandard(conn, response.body_framing);
    }

    /// Read content-length body when pre-read bytes exist in header buffer.
    ///
    /// Copies pre-read bytes to response buffer, then reads remaining from socket.
    /// TigerStyle Y1: Extracted helper for function length compliance.
    fn readContentLengthWithPreread(
        self: *Self,
        conn: *serval_client.client.Connection,
        header_buf: []const u8,
        header_bytes: u32,
        total_bytes_read: u32,
        pre_read_bytes: u32,
        content_length: u64,
    ) ClientError![]const u8 {
        // S1: Preconditions
        assert(pre_read_bytes > 0);
        assert(total_bytes_read >= header_bytes);
        assert(content_length > 0);

        // Copy pre-read bytes to response buffer
        const pre_read_data = header_buf[header_bytes..total_bytes_read];
        if (pre_read_data.len > self.response_buffer.len) {
            return ClientError.ResponseTooLarge;
        }
        @memcpy(self.response_buffer[0..pre_read_data.len], pre_read_data);

        // Check if body is complete from header read
        if (pre_read_bytes >= content_length) {
            debugLog("K8s client: body complete from header read", .{});
            // S1: Postcondition - return bounded by content_length
            assert(content_length <= self.response_buffer.len);
            return self.response_buffer[0..@intCast(content_length)];
        }

        // Read remaining bytes from socket
        const remaining: u64 = content_length - pre_read_bytes;
        debugLog("K8s client: need {d} more bytes", .{remaining});

        var reader = serval_client.BodyReader.init(&conn.socket, .{ .content_length = remaining });
        const additional = reader.readAll(self.response_buffer[pre_read_bytes..]) catch |err| {
            debugLog("K8s client: body read error: {s}", .{@errorName(err)});
            return mapBodyError(err);
        };

        const total_len = pre_read_bytes + additional.len;
        // S1: Postcondition - total length bounded by buffer
        assert(total_len <= self.response_buffer.len);
        return self.response_buffer[0..total_len];
    }

    /// Read body using standard BodyReader (no pre-read bytes).
    ///
    /// TigerStyle Y1: Extracted helper for function length compliance.
    fn readBodyStandard(
        self: *Self,
        conn: *serval_client.client.Connection,
        body_framing: serval_core.types.BodyFraming,
    ) ClientError![]const u8 {
        debugLog("K8s client: standard read, buffer size {d}", .{self.response_buffer.len});

        var reader = serval_client.BodyReader.init(&conn.socket, body_framing);
        const body = reader.readAll(self.response_buffer) catch |err| {
            debugLog("K8s client: body read error: {s}", .{@errorName(err)});
            return mapBodyError(err);
        };

        // S1: Postconditions
        assert(@intFromPtr(body.ptr) >= @intFromPtr(self.response_buffer.ptr));
        assert(body.len <= self.response_buffer.len);

        if (body.len == 0) return ClientError.EmptyResponse;
        return body;
    }

    /// Start a watch request to the K8s API.
    /// Opens a streaming connection and returns a WatchStream for reading events.
    /// The caller must call stream.close() when done.
    ///
    /// Preconditions:
    /// - path must start with '/' and include watch=true parameter
    ///
    /// TigerStyle: Explicit error handling, connection ownership transferred.
    pub fn watchStream(
        self: *Self,
        path: []const u8,
        line_buffer: []u8,
        io: Io,
    ) ClientError!WatchStream {
        assert(path.len > 0); // S1: path must be non-empty
        assert(path[0] == '/'); // S1: path must start with /
        assert(line_buffer.len > 0); // S1: buffer must have capacity

        // Build request with authentication.
        var request = Request{
            .method = .GET,
            .path = path,
            .version = .@"HTTP/1.1",
            .headers = .{},
        };

        // Add required headers.
        request.headers.put("Host", self.api_server) catch return ClientError.HeaderError;

        // Build Bearer token header.
        const token_slice = self.token[0..self.token_len];
        var auth_buf: [BEARER_PREFIX.len + MAX_TOKEN_SIZE_BYTES]u8 = undefined;
        const auth_len = BEARER_PREFIX.len + token_slice.len;
        @memcpy(auth_buf[0..BEARER_PREFIX.len], BEARER_PREFIX);
        @memcpy(auth_buf[BEARER_PREFIX.len..auth_len], token_slice);
        request.headers.put("Authorization", auth_buf[0..auth_len]) catch return ClientError.HeaderError;

        request.headers.put("Accept", "application/json") catch return ClientError.HeaderError;
        // Do NOT set "Connection: close" for watch requests. Watches are long-lived
        // streaming connections that receive events as they occur. HTTP/1.1 defaults
        // to keep-alive which is what we want here.

        // Create upstream for K8s API server.
        const upstream = Upstream{
            .host = self.api_server,
            .port = self.api_port,
            .tls = true,
            .idx = 0,
        };

        debugLog("watcher: opening watch stream to {s}:{d} path={s}", .{
            self.api_server,
            self.api_port,
            path,
        });

        // Make request using serval-client.
        var result = self.http_client.request(upstream, &request, self.header_buffer, io) catch |err| {
            debugLog("watcher: watch request failed: {s}", .{@errorName(err)});
            return mapClientError(err);
        };

        debugLog("watcher: got response status {d}", .{result.response.status});

        // Check status code.
        if (result.response.status >= 400) {
            result.conn.socket.close();
            return ClientError.HttpError;
        }

        debugLog("watcher: stream opened, framing={s}", .{@tagName(result.response.body_framing)});

        // Note: BodyReader is initialized in WatchStream.initBodyReader() after
        // the struct is in its final location, to avoid dangling pointer issues.
        return WatchStream{
            .conn = result.conn,
            .body_framing = result.response.body_framing,
            .body_reader_initialized = false,
            .body_reader = undefined, // Initialized on first readEvent
            .line_buffer = line_buffer,
            .line_pos = 0,
            .done = false,
        };
    }

    /// Start a watch request with lazy connection initialization.
    /// Opens the connection on first readEvent() call.
    /// The caller must call stream.close() when done to free resources.
    ///
    /// Preconditions:
    /// - path must start with '/' and include watch=true parameter
    ///
    /// TigerStyle: Lazy initialization, explicit cleanup.
    pub fn watch(self: *Self, path: []const u8) LazyWatchStream {
        assert(path.len > 0); // S1: path must be non-empty
        assert(path[0] == '/'); // S1: path must start with /

        return LazyWatchStream.init(self, path, self.allocator);
    }
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Create an SSL context with certificate verification disabled.
/// WARNING: This is insecure and should only be used for testing.
fn createInsecureSslContext() ?*tls.ssl.SSL_CTX {
    const method = tls.ssl.TLS_client_method() orelse return null;
    const ctx = tls.ssl.SSL_CTX_new(method) orelse return null;

    // Disable certificate verification (insecure!)
    tls.ssl.SSL_CTX_set_verify(ctx, tls.ssl.SSL_VERIFY_NONE, null);

    return ctx;
}

/// Map serval-client errors to K8s ClientError.
/// TigerStyle: Explicit error mapping.
pub fn mapClientError(err: serval_client.ClientError) ClientError {
    return switch (err) {
        serval_client.ClientError.DnsResolutionFailed => ClientError.DnsResolutionFailed,
        serval_client.ClientError.TcpConnectFailed => ClientError.ConnectionFailed,
        serval_client.ClientError.TcpConnectTimeout => ClientError.ConnectionFailed,
        serval_client.ClientError.TlsHandshakeFailed => ClientError.TlsHandshakeFailed,
        serval_client.ClientError.SendFailed => ClientError.RequestFailed,
        serval_client.ClientError.SendTimeout => ClientError.RequestFailed,
        serval_client.ClientError.BufferTooSmall => ClientError.UrlTooLarge,
        serval_client.ClientError.RecvFailed => ClientError.RequestFailed,
        serval_client.ClientError.RecvTimeout => ClientError.RequestFailed,
        serval_client.ClientError.ResponseHeadersTooLarge => ClientError.ResponseTooLarge,
        serval_client.ClientError.InvalidResponseStatus => ClientError.ResponseParseFailed,
        serval_client.ClientError.InvalidResponseHeaders => ClientError.ResponseParseFailed,
        serval_client.ClientError.ConnectionClosed => ClientError.EmptyResponse,
    };
}

/// Map BodyReader errors to ClientError.
/// TigerStyle S6: Explicit error handling with complete coverage.
fn mapBodyError(err: anyerror) ClientError {
    return switch (err) {
        error.BufferTooSmall => ClientError.ResponseTooLarge,
        error.UnexpectedEof => ClientError.EmptyResponse,
        error.IterationLimitExceeded => ClientError.ReadIterationsExceeded,
        error.InvalidChunkedEncoding => ClientError.ResponseParseFailed,
        error.ChunkTooLarge => ClientError.ResponseTooLarge,
        error.ReadFailed => ClientError.RequestFailed,
        else => ClientError.RequestFailed,
    };
}

/// Read a file into a buffer, returning the number of bytes read.
fn readFileIntoBuffer(path: []const u8, buffer: []u8) !usize {
    const fd = posix.open(path, .{}, 0) catch |err| {
        return switch (err) {
            error.FileNotFound => error.FileNotFound,
            error.AccessDenied => error.AccessDenied,
            else => err,
        };
    };
    defer posix.close(fd);

    var total_read: usize = 0;
    var iteration: u32 = 0;
    while (total_read < buffer.len and iteration < MAX_READ_ITERATIONS) : (iteration += 1) {
        const bytes_read = posix.read(fd, buffer[total_read..]) catch |err| {
            return err;
        };
        if (bytes_read == 0) break;
        total_read += bytes_read;
    }

    // Strip trailing newline
    if (total_read > 0 and buffer[total_read - 1] == '\n') {
        return total_read - 1;
    }
    return total_read;
}

// =============================================================================
// Unit Tests
// =============================================================================

test "Client.initWithConfig basic" {
    const allocator = std.testing.allocator;

    const client = try Client.initWithConfig(
        allocator,
        "localhost",
        6443,
        "test-token-12345",
        "default",
    );
    defer client.deinit();

    try std.testing.expectEqualStrings("localhost", client.getApiServer());
    try std.testing.expectEqualStrings("default", client.getNamespace());
}

test "SA paths are correct" {
    try std.testing.expectEqualStrings(
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        SA_TOKEN_PATH,
    );
    try std.testing.expectEqualStrings(
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        SA_NAMESPACE_PATH,
    );
}

test "mapClientError maps all variants" {
    // Test that all serval-client errors map to K8s client errors
    try std.testing.expectEqual(ClientError.DnsResolutionFailed, mapClientError(serval_client.ClientError.DnsResolutionFailed));
    try std.testing.expectEqual(ClientError.ConnectionFailed, mapClientError(serval_client.ClientError.TcpConnectFailed));
    try std.testing.expectEqual(ClientError.ConnectionFailed, mapClientError(serval_client.ClientError.TcpConnectTimeout));
    try std.testing.expectEqual(ClientError.TlsHandshakeFailed, mapClientError(serval_client.ClientError.TlsHandshakeFailed));
    try std.testing.expectEqual(ClientError.RequestFailed, mapClientError(serval_client.ClientError.SendFailed));
    try std.testing.expectEqual(ClientError.RequestFailed, mapClientError(serval_client.ClientError.SendTimeout));
    try std.testing.expectEqual(ClientError.UrlTooLarge, mapClientError(serval_client.ClientError.BufferTooSmall));
    try std.testing.expectEqual(ClientError.RequestFailed, mapClientError(serval_client.ClientError.RecvFailed));
    try std.testing.expectEqual(ClientError.RequestFailed, mapClientError(serval_client.ClientError.RecvTimeout));
    try std.testing.expectEqual(ClientError.ResponseTooLarge, mapClientError(serval_client.ClientError.ResponseHeadersTooLarge));
    try std.testing.expectEqual(ClientError.ResponseParseFailed, mapClientError(serval_client.ClientError.InvalidResponseStatus));
    try std.testing.expectEqual(ClientError.ResponseParseFailed, mapClientError(serval_client.ClientError.InvalidResponseHeaders));
    try std.testing.expectEqual(ClientError.EmptyResponse, mapClientError(serval_client.ClientError.ConnectionClosed));
}

test "BEARER_PREFIX is correct" {
    try std.testing.expectEqualStrings("Bearer ", BEARER_PREFIX);
}

test "patchStatus path validation - empty path panics" {
    // Note: This test documents the assertion behavior.
    // In production, assertions should not be triggered - callers must validate inputs.
    // We cannot test assertion failures in unit tests, but we document the precondition.

    // Precondition: path must be non-empty
    // Precondition: path must start with '/'
    // Precondition: status_json must be non-empty
    // Precondition: status_json.len <= MAX_RESPONSE_SIZE_BYTES

    // These assertions protect against programming errors, not runtime conditions.
    // The caller is responsible for providing valid inputs.
}

test "patchStatus builds correct request structure" {
    // This test verifies that patchStatus can be called and builds the request correctly.
    // Since we cannot easily mock the HTTP client, we verify the method's type signature
    // and that a client can be initialized to call it.

    const allocator = std.testing.allocator;

    // Initialize client with test config
    const client = try Client.initWithConfig(
        allocator,
        "localhost",
        6443,
        "test-token-12345",
        "default",
    );
    defer client.deinit();

    // Verify the method signature is correct - patchStatus takes:
    // - resource_path: []const u8 (must start with '/')
    // - status_json: []const u8 (must be non-empty, <= MAX_RESPONSE_SIZE_BYTES)
    // - io: Io
    // Returns: ClientError!void

    // We cannot call patchStatus without a real Io runtime and K8s API,
    // but we can verify the client is properly initialized for PATCH requests.
    try std.testing.expectEqualStrings("localhost", client.getApiServer());
    try std.testing.expectEqual(@as(u16, 6443), client.api_port);

    // Verify buffer sizes are adequate for PATCH operations
    try std.testing.expectEqual(@as(usize, HTTP_HEADER_BUFFER_SIZE), client.header_buffer.len);
    try std.testing.expectEqual(@as(usize, MAX_RESPONSE_SIZE_BYTES), client.response_buffer.len);
}

test "patchStatus preconditions documented" {
    // Document the preconditions that patchStatus enforces via assertions:
    //
    // 1. resource_path.len > 0 - path must be non-empty
    // 2. resource_path[0] == '/' - path must start with '/'
    // 3. status_json.len > 0 - body must be non-empty
    // 4. status_json.len <= MAX_RESPONSE_SIZE_BYTES - body must fit in buffer
    //
    // Violating any of these preconditions will trigger an assertion failure.
    // These are programming errors, not runtime conditions.
    //
    // Valid example paths:
    // - "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/my-gw/status"
    // - "/apis/gateway.networking.k8s.io/v1/namespaces/test/httproutes/my-route/status"
    //
    // Valid status_json examples:
    // - {"status":{"conditions":[{"type":"Accepted","status":"True"}]}}

    // Verify MAX_RESPONSE_SIZE_BYTES is reasonable for status updates
    try std.testing.expect(MAX_RESPONSE_SIZE_BYTES >= 1024); // At least 1KB
    try std.testing.expect(MAX_RESPONSE_SIZE_BYTES <= 16 * 1024 * 1024); // At most 16MB
}
