//! OTLP Span Exporter
//!
//! Exports spans using OpenTelemetry Protocol (OTLP) over HTTP/JSON.
//! Uses serval-client for proper Kubernetes DNS resolution with FQDN normalization.
//! TigerStyle: fixed-size buffers, explicit error handling, no panic.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const core = @import("serval-core");
const log = core.log.scoped(.otel);
const core_config = core.config;
const core_types = core.types;
const debugLog = core.debugLog;

const net = @import("serval-net");
const DnsResolver = net.DnsResolver;

const client_mod = @import("serval-client");
const Client = client_mod.Client;

const tls = @import("serval-tls");
const ssl = tls.ssl;

const span_mod = @import("span.zig");
const types = @import("types.zig");
const processor = @import("processor.zig");
const json = @import("json.zig");

const Span = span_mod.Span;
const SpanExporter = processor.SpanExporter;

// =============================================================================
// Constants (from serval-core/config.zig - single source of truth)
// =============================================================================

pub const DEFAULT_ENDPOINT = core_config.OTEL_DEFAULT_ENDPOINT;
pub const MAX_EXPORT_BUFFER_SIZE = core_config.OTEL_MAX_EXPORT_BUFFER_SIZE_BYTES;
pub const HTTP_TIMEOUT_MS = core_config.OTEL_HTTP_TIMEOUT_MS;

/// Maximum hostname length for parsed endpoints.
const MAX_HOST_LEN: usize = core_config.DNS_MAX_HOSTNAME_LEN;
/// Maximum path length for parsed endpoints.
const MAX_PATH_LEN: usize = 256;

// =============================================================================
// Fixed Buffer Writer
// =============================================================================

/// Simple fixed buffer writer (no std.io dependency)
pub const FixedBufferWriter = struct {
    buffer: []u8,
    pos: usize,

    const Self = @This();

    pub fn init(buffer: []u8) Self {
        return .{ .buffer = buffer, .pos = 0 };
    }

    pub fn writeAll(self: *Self, data: []const u8) !void {
        if (self.pos + data.len > self.buffer.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
    }

    pub fn writeByte(self: *Self, byte: u8) !void {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn print(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        const remaining = self.buffer[self.pos..];
        const written = std.fmt.bufPrint(remaining, fmt, args) catch return error.NoSpaceLeft;
        self.pos += written.len;
    }

    pub fn getWritten(self: Self) []const u8 {
        return self.buffer[0..self.pos];
    }
};

// =============================================================================
// URL Parsing
// =============================================================================

/// Parsed endpoint URL components.
/// TigerStyle: Fixed-size buffers, no allocation.
const ParsedEndpoint = struct {
    /// Hostname (may include trailing dot for FQDN)
    host: [MAX_HOST_LEN + 1]u8,
    host_len: u16,
    /// Port number
    port: u16,
    /// Path including query string
    path: [MAX_PATH_LEN]u8,
    path_len: u16,
    /// Whether TLS is required (https)
    tls: bool,

    /// Get host as slice.
    pub fn getHost(self: *const ParsedEndpoint) []const u8 {
        return self.host[0..self.host_len];
    }

    /// Get path as slice.
    pub fn getPath(self: *const ParsedEndpoint) []const u8 {
        return self.path[0..self.path_len];
    }
};

/// Parse an endpoint URL into components.
/// Supports http:// and https:// schemes.
/// TigerStyle: Pure function, returns error on invalid input.
fn parseEndpoint(url: []const u8) !ParsedEndpoint {
    // S1: precondition - non-empty URL
    if (url.len == 0) return error.InvalidEndpoint;

    var result: ParsedEndpoint = undefined;
    result.host_len = 0;
    result.path_len = 0;

    // Parse scheme
    var remaining: []const u8 = undefined;
    if (std.mem.startsWith(u8, url, "https://")) {
        result.tls = true;
        result.port = 443; // Default HTTPS port
        remaining = url["https://".len..];
    } else if (std.mem.startsWith(u8, url, "http://")) {
        result.tls = false;
        result.port = 80; // Default HTTP port
        remaining = url["http://".len..];
    } else {
        return error.InvalidEndpoint;
    }

    // Find path separator
    const path_start = std.mem.indexOfScalar(u8, remaining, '/') orelse remaining.len;
    const host_port = remaining[0..path_start];
    const path = if (path_start < remaining.len) remaining[path_start..] else "/";

    // Parse host:port
    if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |colon_idx| {
        // Check if this is IPv6 (contains '[')
        if (std.mem.indexOfScalar(u8, host_port, '[') != null) {
            // IPv6 address - find closing bracket
            if (std.mem.indexOfScalar(u8, host_port, ']')) |bracket_idx| {
                if (bracket_idx + 1 < host_port.len and host_port[bracket_idx + 1] == ':') {
                    // Port after bracket
                    const host = host_port[0 .. bracket_idx + 1];
                    const port_str = host_port[bracket_idx + 2 ..];
                    result.port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidEndpoint;
                    if (host.len > MAX_HOST_LEN) return error.InvalidEndpoint;
                    @memcpy(result.host[0..host.len], host);
                    result.host_len = @intCast(host.len);
                } else {
                    // No port, just IPv6 address
                    if (host_port.len > MAX_HOST_LEN) return error.InvalidEndpoint;
                    @memcpy(result.host[0..host_port.len], host_port);
                    result.host_len = @intCast(host_port.len);
                }
            } else {
                return error.InvalidEndpoint;
            }
        } else {
            // Regular host:port
            const host = host_port[0..colon_idx];
            const port_str = host_port[colon_idx + 1 ..];
            result.port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidEndpoint;
            if (host.len > MAX_HOST_LEN) return error.InvalidEndpoint;
            @memcpy(result.host[0..host.len], host);
            result.host_len = @intCast(host.len);
        }
    } else {
        // No port specified, use default
        if (host_port.len > MAX_HOST_LEN) return error.InvalidEndpoint;
        @memcpy(result.host[0..host_port.len], host_port);
        result.host_len = @intCast(host_port.len);
    }

    // Copy path
    if (path.len > MAX_PATH_LEN) return error.InvalidEndpoint;
    @memcpy(result.path[0..path.len], path);
    result.path_len = @intCast(path.len);

    // S2: postconditions
    assert(result.host_len > 0);
    assert(result.path_len > 0);
    assert(result.port > 0);

    return result;
}

// =============================================================================
// OTLP Exporter Configuration
// =============================================================================

pub const Config = struct {
    /// OTLP collector endpoint (e.g., "http://localhost:4318/v1/traces")
    endpoint: []const u8 = DEFAULT_ENDPOINT,
    /// Service name for resource attributes
    service_name: []const u8 = "unknown-service",
    /// Service version
    service_version: []const u8 = "0.1.0",
    /// HTTP timeout in milliseconds
    timeout_ms: u32 = HTTP_TIMEOUT_MS,
};

// =============================================================================
// OTLP HTTP/JSON Exporter
// =============================================================================

const JsonWriter = json.JsonWriter(FixedBufferWriter);

/// Exports spans to an OTLP collector using HTTP/JSON.
/// Uses serval-client with proper Kubernetes DNS resolution.
pub const OTLPExporter = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Pre-allocated buffer for JSON encoding
    buffer: []u8,
    /// Zig 0.16 requires Io runtime
    io_runtime: Io.Threaded,
    /// DNS resolver with FQDN normalization
    dns_resolver: DnsResolver,
    /// HTTP client using serval-client
    http_client: Client,
    /// TLS context for HTTPS endpoints (null if HTTP only)
    tls_ctx: ?*ssl.SSL_CTX,
    /// Parsed endpoint components
    parsed_endpoint: ParsedEndpoint,
    /// Buffer for response headers
    response_buf: []u8,

    const Self = @This();

    /// Response buffer size (4KB is plenty for OTLP responses)
    const RESPONSE_BUF_SIZE: usize = 4096;

    pub fn init(allocator: std.mem.Allocator, cfg: Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Allocate JSON buffer
        const buffer = try allocator.alloc(u8, MAX_EXPORT_BUFFER_SIZE);
        errdefer allocator.free(buffer);

        // Allocate response buffer
        const response_buf = try allocator.alloc(u8, RESPONSE_BUF_SIZE);
        errdefer allocator.free(response_buf);

        // Parse endpoint URL
        const parsed = parseEndpoint(cfg.endpoint) catch {
            log.err("OTLP: invalid endpoint URL: {s}", .{cfg.endpoint});
            return error.InvalidEndpoint;
        };

        // Create TLS context if needed
        const tls_ctx: ?*ssl.SSL_CTX = if (parsed.tls) blk: {
            break :blk ssl.createClientCtx() catch {
                log.err("OTLP: failed to create TLS context", .{});
                return error.TlsInitFailed;
            };
        } else null;
        errdefer if (tls_ctx) |ctx| ssl.SSL_CTX_free(ctx);

        // Initialize IO runtime
        const io_runtime = Io.Threaded.init(allocator, .{});

        // Initialize DNS resolver
        var dns_resolver = DnsResolver.init(.{});

        // Initialize HTTP client
        const http_client = Client.init(
            allocator,
            &dns_resolver,
            tls_ctx,
            true, // verify_tls
        );

        self.* = .{
            .allocator = allocator,
            .config = cfg,
            .buffer = buffer,
            .io_runtime = io_runtime,
            .dns_resolver = dns_resolver,
            .http_client = http_client,
            .tls_ctx = tls_ctx,
            .parsed_endpoint = parsed,
            .response_buf = response_buf,
        };

        // Log parsed endpoint
        debugLog("OTLP: endpoint parsed - host={s} port={d} path={s} tls={}", .{
            self.parsed_endpoint.getHost(),
            self.parsed_endpoint.port,
            self.parsed_endpoint.getPath(),
            self.parsed_endpoint.tls,
        });

        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.tls_ctx) |ctx| {
            ssl.SSL_CTX_free(ctx);
        }
        self.io_runtime.deinit();
        self.allocator.free(self.response_buf);
        self.allocator.free(self.buffer);
        self.allocator.destroy(self);
    }

    pub fn asSpanExporter(self: *Self) SpanExporter {
        return .{
            .ptr = self,
            .vtable = &.{
                .exportFn = exportSpans,
                .shutdownFn = shutdown,
            },
        };
    }

    fn exportSpans(ptr: *anyopaque, spans: []const Span) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (spans.len == 0) return;

        // Debug: log spans being exported
        debugLog("OTLP: exporting {d} span(s)", .{spans.len});
        for (spans) |*span| {
            self.logSpanDebug(span);
        }

        // Encode spans to OTLP JSON
        var writer = FixedBufferWriter.init(self.buffer);
        try self.writeOTLPJson(&writer, spans);
        const json_data = writer.getWritten();

        // Debug: log JSON payload (truncated for large payloads)
        const max_log_len: usize = 500;
        if (json_data.len <= max_log_len) {
            debugLog("OTLP JSON ({d} bytes): {s}", .{ json_data.len, json_data });
        } else {
            debugLog("OTLP JSON ({d} bytes, truncated): {s}...", .{ json_data.len, json_data[0..max_log_len] });
        }

        // Send HTTP POST
        try self.sendHttp(json_data);
    }

    fn shutdown(_: *anyopaque) void {
        // No cleanup needed
    }

    /// Log a single span for debugging.
    fn logSpanDebug(_: *Self, span: *const Span) void {
        var trace_buf: [32]u8 = undefined;
        var span_buf: [16]u8 = undefined;
        const parent_str: []const u8 = if (span.parent_span_id) |parent_id| blk: {
            var parent_buf: [16]u8 = undefined;
            break :blk parent_id.toHex(&parent_buf);
        } else "ROOT";
        debugLog("  span: {s} trace={s} span={s} parent={s}", .{
            span.getName(),
            span.span_context.trace_id.toHex(&trace_buf),
            span.span_context.span_id.toHex(&span_buf),
            parent_str,
        });
    }

    /// Write spans as OTLP JSON format.
    pub fn writeOTLPJson(self: *Self, writer: *FixedBufferWriter, spans: []const Span) !void {
        var j = JsonWriter.init(writer);

        try j.beginObject();
        try j.field("resourceSpans");
        try j.beginArray();
        try j.beginObject();

        // Resource attributes
        try j.field("resource");
        try j.beginObject();
        try j.field("attributes");
        try j.beginArray();
        try j.otlpStringAttr("service.name", self.config.service_name);
        try j.otlpStringAttr("service.version", self.config.service_version);
        try j.otlpStringAttr("telemetry.sdk.name", "serval-otel");
        try j.endArray();
        try j.endObject();

        // Scope spans
        try j.field("scopeSpans");
        try j.beginArray();
        try j.beginObject();

        try j.field("scope");
        try j.beginObject();
        try j.field("name");
        try j.string("serval");
        try j.field("version");
        try j.string("1.0.0");
        try j.endObject();

        try j.field("spans");
        try j.beginArray();
        for (spans) |*span| {
            try writeSpan(&j, span);
        }
        try j.endArray();

        try j.endObject();
        try j.endArray();

        try j.endObject();
        try j.endArray();
        try j.endObject();
    }

    fn sendHttp(self: *Self, body: []const u8) !void {
        const io = self.io_runtime.io();

        // Normalize hostname for Kubernetes DNS (add trailing dot for FQDNs)
        var fqdn_buf: [core_config.DNS_MAX_HOSTNAME_LEN + 1]u8 = undefined;
        const normalized_host = DnsResolver.normalizeFqdn(self.parsed_endpoint.getHost(), &fqdn_buf);

        debugLog("OTLP: connecting to {s}:{d} (normalized from {s})", .{
            normalized_host,
            self.parsed_endpoint.port,
            self.parsed_endpoint.getHost(),
        });

        // Create upstream for connection
        // Note: We need to copy the normalized host to a fixed buffer since Upstream.host is a slice
        var host_buf: [MAX_HOST_LEN + 1]u8 = undefined;
        @memcpy(host_buf[0..normalized_host.len], normalized_host);
        const upstream = core_types.Upstream{
            .host = host_buf[0..normalized_host.len],
            .port = self.parsed_endpoint.port,
            .tls = self.parsed_endpoint.tls,
            .idx = 0,
        };

        // Connect to upstream
        var connect_result = self.http_client.connect(upstream, io) catch |err| {
            log.err("OTLP: connection failed: {s}", .{@errorName(err)});
            return error.ConnectionFailed;
        };
        defer connect_result.conn.close();

        debugLog("OTLP: connected (dns={d}ns tcp={d}ns tls={d}ns)", .{
            connect_result.dns_duration_ns,
            connect_result.tcp_connect_duration_ns,
            connect_result.tls_handshake_duration_ns,
        });

        // Send request with headers manually (need custom Content-Type for OTLP)
        try self.sendRequestWithHeaders(&connect_result.conn.socket, body);

        // Read response
        const response = client_mod.readResponseHeaders(&connect_result.conn.socket, self.response_buf) catch |err| {
            log.err("OTLP: failed to read response: {s}", .{@errorName(err)});
            return error.ExportFailed;
        };

        debugLog("OTLP: response status={d}", .{response.status});

        if (response.status != 200 and response.status != 202) {
            log.err("OTLP: collector returned status {d}", .{response.status});
            return error.ExportFailed;
        }

        debugLog("OTLP: export successful", .{});
    }

    /// Send HTTP POST request with custom headers.
    /// TigerStyle: Manual header construction for control over Content-Type.
    fn sendRequestWithHeaders(self: *Self, socket: *net.Socket, body: []const u8) !void {
        // Build request line and headers
        var req_buf: [1024]u8 = undefined;
        const req_line = std.fmt.bufPrint(&req_buf, "POST {s} HTTP/1.1\r\nHost: {s}:{d}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
            self.parsed_endpoint.getPath(),
            self.parsed_endpoint.getHost(),
            self.parsed_endpoint.port,
            body.len,
        }) catch return error.BufferTooSmall;

        // Send headers
        _ = socket.write(req_line) catch return error.SendFailed;

        // Send body
        if (body.len > 0) {
            _ = socket.write(body) catch return error.SendFailed;
        }
    }
};

// =============================================================================
// Span Serialization
// =============================================================================

fn writeSpan(j: *JsonWriter, span: *const Span) !void {
    var trace_buf: [32]u8 = undefined;
    var span_buf: [16]u8 = undefined;

    try j.beginObject();

    // Trace ID (hex encoded)
    try j.field("traceId");
    try j.stringHexRaw(span.span_context.trace_id.toHex(&trace_buf));

    // Span ID (hex encoded)
    try j.field("spanId");
    try j.stringHexRaw(span.span_context.span_id.toHex(&span_buf));

    // Parent Span ID (optional)
    if (span.parent_span_id) |parent_id| {
        var parent_buf: [16]u8 = undefined;
        try j.field("parentSpanId");
        try j.stringHexRaw(parent_id.toHex(&parent_buf));
    }

    // Name
    try j.field("name");
    try j.string(span.getName());

    // Kind (OTLP uses 1-indexed)
    try j.field("kind");
    try j.int(@as(u8, @intFromEnum(span.kind)) + 1);

    // Timestamps
    try j.field("startTimeUnixNano");
    try j.intString(span.start_time_ns);
    try j.field("endTimeUnixNano");
    try j.intString(span.end_time_ns);

    // Attributes
    try j.field("attributes");
    try j.beginArray();
    for (0..span.attribute_count) |i| {
        const attr = &span.attributes[i];
        try writeAttribute(j, attr);
    }
    try j.endArray();

    // Events
    try j.field("events");
    try j.beginArray();
    for (0..span.event_count) |i| {
        const event = &span.events[i];
        try j.beginObject();
        try j.field("name");
        try j.string(event.getName());
        try j.field("timeUnixNano");
        try j.intString(event.timestamp_ns);
        try j.endObject();
    }
    try j.endArray();

    // Status
    try j.field("status");
    try j.beginObject();
    try j.field("code");
    try j.int(@intFromEnum(span.status.code));
    if (span.status.code == .Error and span.status.description_len > 0) {
        try j.field("message");
        try j.string(span.status.getDescription());
    }
    try j.endObject();

    try j.endObject();
}

fn writeAttribute(j: *JsonWriter, attr: *const span_mod.Attribute) !void {
    switch (attr.value) {
        .bool_val => |v| try j.otlpBoolAttr(attr.getKey(), v),
        .int_val => |v| try j.otlpIntAttr(attr.getKey(), v),
        .double_val => |v| try j.otlpDoubleAttr(attr.getKey(), v),
        .string_val => |s| try j.otlpStringAttr(attr.getKey(), s.data[0..s.len]),
    }
}

// =============================================================================
// Tests
// =============================================================================

test "parseEndpoint: http URL" {
    const result = try parseEndpoint("http://localhost:4318/v1/traces");
    try std.testing.expectEqualStrings("localhost", result.getHost());
    try std.testing.expectEqual(@as(u16, 4318), result.port);
    try std.testing.expectEqualStrings("/v1/traces", result.getPath());
    try std.testing.expect(!result.tls);
}

test "parseEndpoint: https URL" {
    const result = try parseEndpoint("https://otel.example.com/v1/traces");
    try std.testing.expectEqualStrings("otel.example.com", result.getHost());
    try std.testing.expectEqual(@as(u16, 443), result.port);
    try std.testing.expectEqualStrings("/v1/traces", result.getPath());
    try std.testing.expect(result.tls);
}

test "parseEndpoint: URL with port" {
    const result = try parseEndpoint("https://collector:4317/v1/traces");
    try std.testing.expectEqualStrings("collector", result.getHost());
    try std.testing.expectEqual(@as(u16, 4317), result.port);
    try std.testing.expect(result.tls);
}

test "parseEndpoint: k8s service URL" {
    const result = try parseEndpoint("http://jaeger.default.svc.cluster.local:4318/v1/traces");
    try std.testing.expectEqualStrings("jaeger.default.svc.cluster.local", result.getHost());
    try std.testing.expectEqual(@as(u16, 4318), result.port);
    try std.testing.expectEqualStrings("/v1/traces", result.getPath());
    try std.testing.expect(!result.tls);
}

test "parseEndpoint: invalid scheme" {
    try std.testing.expectError(error.InvalidEndpoint, parseEndpoint("ftp://localhost/path"));
}

test "parseEndpoint: empty URL" {
    try std.testing.expectError(error.InvalidEndpoint, parseEndpoint(""));
}

test "FixedBufferWriter basic operations" {
    var buf: [64]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);

    try writer.writeAll("hello");
    try writer.writeByte(' ');
    try writer.print("{}", .{42});

    try std.testing.expectEqualStrings("hello 42", writer.getWritten());
}
