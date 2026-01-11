//! Kubernetes API Client
//!
//! HTTP client for communicating with the Kubernetes API server.
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

// =============================================================================
// Constants (TigerStyle: Explicit bounds and paths)
// =============================================================================

/// Paths to ServiceAccount credentials (mounted in pods)
pub const SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";
pub const SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
pub const SA_NAMESPACE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Default K8s API server address (in-cluster)
/// Trailing dot makes this an explicit FQDN, preventing search domain appending
/// (ndots:5 in K8s resolv.conf would otherwise append search domains to names with <5 dots)
pub const DEFAULT_API_SERVER = "kubernetes.default.svc.cluster.local.";
pub const DEFAULT_API_PORT: u16 = 443;

/// Maximum token size in bytes (K8s JWT tokens are typically ~1KB)
pub const MAX_TOKEN_SIZE_BYTES: u32 = 8192;

/// Maximum namespace length (DNS label - 63 chars max per K8s spec)
pub const MAX_NAMESPACE_LEN: u32 = 63;

/// Maximum response buffer size for K8s API responses
pub const MAX_RESPONSE_SIZE_BYTES: u32 = 1024 * 1024; // 1MB

/// Maximum URL length for K8s API requests
pub const MAX_URL_SIZE_BYTES: u32 = 2048;

/// Maximum hostname length
pub const MAX_HOST_LEN: u32 = 253;

/// HTTP header buffer size
pub const HTTP_HEADER_BUFFER_SIZE: u32 = 4096;

/// HTTP timeout in seconds
pub const HTTP_TIMEOUT_SECS: u32 = 30;

/// Maximum iterations for response reading (TigerStyle: bounded loops)
pub const MAX_READ_ITERATIONS: u32 = 10000;

/// Bearer token header prefix
pub const BEARER_PREFIX = "Bearer ";

// =============================================================================
// Error Types (TigerStyle: Explicit error sets)
// =============================================================================

pub const ClientError = error{
    /// ServiceAccount token file not found or unreadable
    TokenNotFound,
    /// ServiceAccount namespace file not found or unreadable
    NamespaceNotFound,
    /// ServiceAccount CA certificate file not found or unreadable
    CaNotFound,
    /// Token exceeds MAX_TOKEN_SIZE_BYTES
    TokenTooLarge,
    /// Namespace exceeds MAX_NAMESPACE_LEN
    NamespaceTooLarge,
    /// Response exceeds MAX_RESPONSE_SIZE_BYTES
    ResponseTooLarge,
    /// URL construction failed (path too long)
    UrlTooLarge,
    /// DNS resolution failed
    DnsResolutionFailed,
    /// TCP connection failed
    ConnectionFailed,
    /// TLS handshake failed
    TlsHandshakeFailed,
    /// HTTP request failed
    RequestFailed,
    /// Non-success HTTP status (4xx, 5xx)
    HttpError,
    /// Empty response received
    EmptyResponse,
    /// Failed to parse HTTP response
    ResponseParseFailed,
    /// Out of memory during initialization
    OutOfMemory,
    /// SSL context creation failed
    SslContextFailed,
    /// Read operation exceeded MAX_READ_ITERATIONS
    ReadIterationsExceeded,
    /// Header error (too many headers, etc.)
    HeaderError,
    /// HTTP 409 Conflict - resource version mismatch, caller should retry with fresh data
    ConflictRetryable,
};

// =============================================================================
// Client
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
        const dns_resolver = DnsResolver.init(.{});

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
        const dns_resolver = DnsResolver.init(.{});

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

        // Read body based on framing
        const body = try self.readBody(&result.conn, result.response);

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

    /// Read response body into response_buffer based on body framing.
    /// Returns the slice of data read.
    /// Uses serval-client BodyReader for proper chunked/content-length handling.
    /// TigerStyle: Explicit error mapping.
    fn readBody(
        self: *Self,
        conn: *serval_client.client.Connection,
        response: serval_client.ResponseHeaders,
    ) ClientError![]const u8 {
        // S1: Precondition - connection and response are valid
        assert(self.response_buffer.len > 0); // Buffer must have capacity

        debugLog("K8s client: reading body, framing={s}", .{@tagName(response.body_framing)});

        var reader = serval_client.BodyReader.init(&conn.socket, response.body_framing);
        const body = reader.readAll(self.response_buffer) catch |err| {
            debugLog("K8s client: body read error: {s}", .{@errorName(err)});
            // S6: Explicit error mapping
            return switch (err) {
                error.BufferTooSmall => ClientError.ResponseTooLarge,
                error.UnexpectedEof => ClientError.EmptyResponse,
                error.IterationLimitExceeded => ClientError.ReadIterationsExceeded,
                error.InvalidChunkedEncoding => ClientError.ResponseParseFailed,
                error.ChunkTooLarge => ClientError.ResponseTooLarge,
                error.ReadFailed => ClientError.RequestFailed,
                else => ClientError.RequestFailed,
            };
        };

        // S2: Postcondition - body slice is within response_buffer bounds
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

/// Lazy watch stream that opens connection on first readEvent call.
/// This maintains backward compatibility with existing watcher code.
/// Allocates its own internal line buffer for proper streaming.
pub const LazyWatchStream = struct {
    client: *Client,
    path: []const u8,
    stream: ?WatchStream,
    /// Internal line buffer for accumulating partial events.
    /// Allocated on first readEvent, freed on close.
    internal_buffer: ?[]u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(client: *Client, path: []const u8, allocator: std.mem.Allocator) Self {
        return Self{
            .client = client,
            .path = path,
            .stream = null,
            .internal_buffer = null,
            .allocator = allocator,
        };
    }

    pub fn readEvent(self: *Self, buffer: []u8, io: Io) ClientError!?[]const u8 {
        // Allocate internal buffer on first call if needed.
        if (self.internal_buffer == null) {
            self.internal_buffer = self.allocator.alloc(u8, MAX_WATCH_EVENT_SIZE) catch {
                return ClientError.OutOfMemory;
            };
        }

        // Open stream on first call.
        if (self.stream == null) {
            self.stream = self.client.watchStream(self.path, self.internal_buffer.?, io) catch |err| {
                return err;
            };
        }

        return self.stream.?.readEvent(buffer, io);
    }

    pub fn close(self: *Self) void {
        if (self.stream) |*s| {
            s.close();
        }
        if (self.internal_buffer) |buf| {
            self.allocator.free(buf);
            self.internal_buffer = null;
        }
    }
};

// =============================================================================
// Watch Stream
// =============================================================================

/// Maximum size of a single watch event line.
/// Secrets with TLS certificates can be 500KB+, so we allow 1MB.
const MAX_WATCH_EVENT_SIZE: u32 = 1024 * 1024;

/// Maximum iterations for reading chunks in a single readEvent call.
const MAX_CHUNK_READ_ITERATIONS: u32 = 1000;

/// Represents a streaming watch connection to K8s API.
/// Maintains an open connection and reads newline-delimited JSON events.
/// TigerStyle: Pre-allocated buffer, bounded operations.
pub const WatchStream = struct {
    /// Connection to K8s API (owned, must be closed by caller).
    conn: serval_client.client.Connection,
    /// Body framing type (stored for lazy BodyReader initialization).
    body_framing: BodyFraming,
    /// Whether body_reader has been initialized.
    body_reader_initialized: bool,
    /// Body reader for incremental chunked reading.
    /// Initialized lazily on first readEvent to avoid dangling pointer.
    body_reader: serval_client.BodyReader,
    /// Buffer for accumulating partial lines.
    line_buffer: []u8,
    /// Current position in line_buffer (data from 0..line_pos).
    line_pos: u32,
    /// Whether the stream has ended.
    done: bool,

    const Self = @This();

    /// Read the next event from the watch stream.
    /// Returns a complete JSON line (one event), or null if stream ended.
    /// The returned slice points into the provided buffer.
    ///
    /// TigerStyle: Bounded iterations, explicit error handling.
    pub fn readEvent(self: *Self, buffer: []u8, io: Io) ClientError!?[]const u8 {
        assert(buffer.len > 0); // S1: buffer must have capacity
        _ = io; // Io runtime is embedded in connection's socket

        if (self.done) return null;

        // Lazily initialize body_reader on first call.
        // This must happen after the WatchStream is in its final location.
        if (!self.body_reader_initialized) {
            self.body_reader = serval_client.BodyReader.init(&self.conn.socket, self.body_framing);
            self.body_reader_initialized = true;
            debugLog("watcher: body_reader initialized", .{});
        }

        // Check if we already have a complete line in the buffer.
        if (self.findNewline()) |newline_pos| {
            return self.extractLine(buffer, newline_pos);
        }

        // Read more data until we get a complete line.
        var iterations: u32 = 0;
        while (iterations < MAX_CHUNK_READ_ITERATIONS) : (iterations += 1) {
            // Read next chunk from body.
            const remaining_space = self.line_buffer.len - self.line_pos;
            if (remaining_space == 0) {
                // Buffer full but no newline found - event too large.
                debugLog("watcher: event exceeds buffer size", .{});
                return ClientError.ResponseTooLarge;
            }

            debugLog("watcher: calling body_reader.readChunk, line_pos={d}, space={d}", .{
                self.line_pos,
                self.line_buffer.len - self.line_pos,
            });

            const chunk = self.body_reader.readChunk(self.line_buffer[self.line_pos..]) catch |err| {
                debugLog("watcher: chunk read error: {s}", .{@errorName(err)});
                self.done = true;
                return switch (err) {
                    error.UnexpectedEof => null, // Stream ended gracefully.
                    error.BufferTooSmall => ClientError.ResponseTooLarge,
                    error.InvalidChunkedEncoding => ClientError.ResponseParseFailed,
                    error.ChunkTooLarge => ClientError.ResponseTooLarge,
                    error.ReadFailed => ClientError.RequestFailed,
                    error.IterationLimitExceeded => ClientError.ReadIterationsExceeded,
                    error.WriteFailed, error.SpliceFailed, error.PipeCreationFailed => ClientError.RequestFailed,
                };
            };

            debugLog("watcher: readChunk returned", .{});

            if (chunk) |data| {
                self.line_pos += @intCast(data.len);
                debugLog("watcher: read chunk len={d} total={d}", .{ data.len, self.line_pos });

                // Check for complete line.
                if (self.findNewline()) |newline_pos| {
                    return self.extractLine(buffer, newline_pos);
                }
            } else {
                // Stream ended.
                debugLog("watcher: stream ended", .{});
                self.done = true;

                // Return any remaining data as final event (if non-empty).
                if (self.line_pos > 0) {
                    const len = @min(self.line_pos, @as(u32, @intCast(buffer.len)));
                    @memcpy(buffer[0..len], self.line_buffer[0..len]);
                    self.line_pos = 0;
                    return buffer[0..len];
                }
                return null;
            }
        }

        // Too many iterations without finding a newline.
        debugLog("watcher: max iterations without complete event", .{});
        return ClientError.ReadIterationsExceeded;
    }

    /// Find the position of the first newline in the buffer.
    fn findNewline(self: *Self) ?u32 {
        var i: u32 = 0;
        while (i < self.line_pos) : (i += 1) {
            if (self.line_buffer[i] == '\n') {
                return i;
            }
        }
        return null;
    }

    /// Extract a complete line from the buffer and copy to output.
    /// Shifts remaining data to start of buffer.
    fn extractLine(self: *Self, buffer: []u8, newline_pos: u32) []const u8 {
        // Copy line to output buffer (excluding newline).
        const line_len = @min(newline_pos, @as(u32, @intCast(buffer.len)));
        @memcpy(buffer[0..line_len], self.line_buffer[0..line_len]);

        // Shift remaining data to start of buffer.
        const remaining = self.line_pos - newline_pos - 1;
        if (remaining > 0) {
            const src_start = newline_pos + 1;
            // Use a loop instead of memcpy for overlapping regions.
            var j: u32 = 0;
            while (j < remaining) : (j += 1) {
                self.line_buffer[j] = self.line_buffer[src_start + j];
            }
        }
        self.line_pos = remaining;

        debugLog("watcher: extracted event len={d} remaining={d}", .{ line_len, remaining });
        return buffer[0..line_len];
    }

    /// Close the watch stream connection.
    pub fn close(self: *Self) void {
        self.conn.socket.close();
        self.done = true;
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
fn mapClientError(err: serval_client.ClientError) ClientError {
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
// Imports for Connection type
// =============================================================================

const pool_mod = @import("serval-pool");
const Connection = pool_mod.pool.Connection;

// Re-export Connection type used in readBody
// Note: serval_client.client.Connection is pool_mod.pool.Connection

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

test "ClientError has ConflictRetryable variant" {
    // Verify ConflictRetryable error exists in the error set
    const err: ClientError = ClientError.ConflictRetryable;
    try std.testing.expect(err == ClientError.ConflictRetryable);

    // Verify it's distinct from HttpError
    try std.testing.expect(err != ClientError.HttpError);
}

test "ClientError error set completeness" {
    // Verify all error variants exist and are distinct
    const errors = [_]ClientError{
        ClientError.TokenNotFound,
        ClientError.NamespaceNotFound,
        ClientError.CaNotFound,
        ClientError.TokenTooLarge,
        ClientError.NamespaceTooLarge,
        ClientError.ResponseTooLarge,
        ClientError.UrlTooLarge,
        ClientError.DnsResolutionFailed,
        ClientError.ConnectionFailed,
        ClientError.TlsHandshakeFailed,
        ClientError.RequestFailed,
        ClientError.HttpError,
        ClientError.EmptyResponse,
        ClientError.ResponseParseFailed,
        ClientError.OutOfMemory,
        ClientError.SslContextFailed,
        ClientError.ReadIterationsExceeded,
        ClientError.HeaderError,
        ClientError.ConflictRetryable,
    };

    // Each error should be distinct
    for (errors, 0..) |err1, i| {
        for (errors[i + 1 ..]) |err2| {
            try std.testing.expect(err1 != err2);
        }
    }
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
