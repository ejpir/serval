//! OTLP Span Exporter
//!
//! Exports spans using OpenTelemetry Protocol (OTLP) over HTTP/JSON.
//! TigerStyle: fixed-size buffers, explicit error handling, no panic.

const std = @import("std");
const core = @import("serval-core");
const config = core.config;
const debugLog = core.debugLog;
const span_mod = @import("span.zig");
const types = @import("types.zig");
const processor = @import("processor.zig");
const json = @import("json.zig");

const Span = span_mod.Span;
const SpanExporter = processor.SpanExporter;

// =============================================================================
// Constants (from serval-core/config.zig - single source of truth)
// =============================================================================

pub const DEFAULT_ENDPOINT = config.OTEL_DEFAULT_ENDPOINT;
pub const MAX_EXPORT_BUFFER_SIZE = config.OTEL_MAX_EXPORT_BUFFER_SIZE_BYTES;
pub const HTTP_TIMEOUT_MS = config.OTEL_HTTP_TIMEOUT_MS;

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
pub const OTLPExporter = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Pre-allocated buffer for JSON encoding
    buffer: []u8,
    /// Zig 0.16 requires Io runtime for HTTP client
    io_runtime: std.Io.Threaded,
    /// HTTP client
    client: std.http.Client,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, cfg: Config) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Allocate buffer first (can fail)
        const buffer = try allocator.alloc(u8, MAX_EXPORT_BUFFER_SIZE);
        errdefer allocator.free(buffer);

        // TigerStyle: Initialize all fields in a single struct literal to avoid
        // partial initialization and double-assignment bugs.
        self.* = .{
            .allocator = allocator,
            .config = cfg,
            .buffer = buffer,
            .io_runtime = .init(allocator, .{}),
            .client = undefined, // Initialized below after io_runtime
        };

        // Initialize client with io from runtime (must be after io_runtime init)
        self.client = .{ .allocator = allocator, .io = self.io_runtime.io() };

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.client.deinit();
        self.io_runtime.deinit();
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

        // Debug: log spans being exported (only in debug builds)
        debugLog("OTLP: exporting {d} span(s)", .{spans.len});
        for (spans) |*span| {
            self.logSpanDebug(span);
        }

        // Encode spans to OTLP JSON
        var writer = FixedBufferWriter.init(self.buffer);
        try self.writeOTLPJson(&writer, spans);
        const json_data = writer.getWritten();

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
        // Zig 0.16 uses fetch() API instead of open()
        const fetch_options = std.http.Client.FetchOptions{
            .location = .{ .url = self.config.endpoint },
            .method = .POST,
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
            .payload = body,
        };

        const response = self.client.fetch(fetch_options) catch |err| {
            std.log.err("Failed to send OTLP request: {}", .{err});
            return error.ConnectionFailed;
        };

        if (response.status != .ok and response.status != .accepted) {
            std.log.err("OTLP collector returned status: {}", .{response.status});
            return error.ExportFailed;
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

test "OTLPExporter JSON encoding" {
    const allocator = std.testing.allocator;

    var exporter = try OTLPExporter.init(allocator, .{
        .endpoint = "http://localhost:4318/v1/traces",
        .service_name = "test-service",
    });
    defer exporter.deinit();

    // Create a test span
    const trace_id = types.TraceID.init([16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef });
    const span_id = types.SpanID.init([8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef });
    const span_context = types.SpanContext.init(
        trace_id,
        span_id,
        types.TraceFlags.default(),
        types.TraceState.init(),
        false,
    );
    const scope = types.InstrumentationScope.init("test-lib", "1.0.0");

    var span = Span.init(span_context, "test-operation", .Server, scope);
    span.setStringAttribute("http.method", "GET");
    span.setIntAttribute("http.status_code", 200);
    span.end_time_ns = span.start_time_ns + 1000000; // 1ms duration

    // Verify attributes were set
    try std.testing.expectEqual(@as(u8, 2), span.attribute_count);

    // Encode to JSON (use larger buffer)
    var buf: [8192]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);
    const spans = [_]Span{span};
    try exporter.writeOTLPJson(&writer, &spans);

    const json_out = writer.getWritten();

    // Verify basic structure
    try std.testing.expect(std.mem.indexOf(u8, json_out, "\"resourceSpans\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_out, "\"test-service\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_out, "\"test-operation\"") != null);
    // Check for attributes (they should be present since attribute_count > 0)
    try std.testing.expect(std.mem.indexOf(u8, json_out, "\"attributes\"") != null);
}

test "FixedBufferWriter basic operations" {
    var buf: [64]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);

    try writer.writeAll("hello");
    try writer.writeByte(' ');
    try writer.print("{}", .{42});

    try std.testing.expectEqualStrings("hello 42", writer.getWritten());
}
