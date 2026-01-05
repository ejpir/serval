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
            var trace_buf: [32]u8 = undefined;
            var span_buf: [16]u8 = undefined;
            if (span.parent_span_id) |parent_id| {
                var parent_buf: [16]u8 = undefined;
                debugLog("  span: {s} trace={s} span={s} parent={s}", .{
                    span.getName(),
                    span.span_context.trace_id.toHex(&trace_buf),
                    span.span_context.span_id.toHex(&span_buf),
                    parent_id.toHex(&parent_buf),
                });
            } else {
                debugLog("  span: {s} trace={s} span={s} parent=ROOT", .{
                    span.getName(),
                    span.span_context.trace_id.toHex(&trace_buf),
                    span.span_context.span_id.toHex(&span_buf),
                });
            }
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

    /// Write spans as OTLP JSON format
    pub fn writeOTLPJson(self: *Self, writer: *FixedBufferWriter, spans: []const Span) !void {
        try writer.writeAll("{\"resourceSpans\":[{");

        // Resource attributes
        try writer.writeAll("\"resource\":{\"attributes\":[");
        try writer.writeAll("{\"key\":\"service.name\",\"value\":{\"stringValue\":\"");
        try writer.writeAll(self.config.service_name);
        try writer.writeAll("\"}},{\"key\":\"service.version\",\"value\":{\"stringValue\":\"");
        try writer.writeAll(self.config.service_version);
        try writer.writeAll("\"}},{\"key\":\"telemetry.sdk.name\",\"value\":{\"stringValue\":\"serval-otel\"}}");
        try writer.writeAll("]},");

        // Scope spans
        try writer.writeAll("\"scopeSpans\":[{");
        try writer.writeAll("\"scope\":{\"name\":\"serval\",\"version\":\"1.0.0\"},");
        try writer.writeAll("\"spans\":[");

        // Write each span
        for (spans) |*span| {
            if (span != &spans[0]) try writer.writeAll(",");
            try self.writeSpan(writer, span);
        }

        try writer.writeAll("]}]}]}");
    }

    fn writeSpan(self: *Self, writer: *FixedBufferWriter, span: *const Span) !void {
        _ = self;

        try writer.writeAll("{");

        // Trace ID (hex encoded)
        try writer.writeAll("\"traceId\":\"");
        var trace_buf: [32]u8 = undefined;
        try writer.writeAll(span.span_context.trace_id.toHex(&trace_buf));
        try writer.writeAll("\",");

        // Span ID (hex encoded)
        try writer.writeAll("\"spanId\":\"");
        var span_buf: [16]u8 = undefined;
        try writer.writeAll(span.span_context.span_id.toHex(&span_buf));
        try writer.writeAll("\",");

        // Parent Span ID (optional)
        if (span.parent_span_id) |parent_id| {
            try writer.writeAll("\"parentSpanId\":\"");
            var parent_buf: [16]u8 = undefined;
            try writer.writeAll(parent_id.toHex(&parent_buf));
            try writer.writeAll("\",");
        }

        // Name
        try writer.writeAll("\"name\":\"");
        try writeJsonString(writer, span.getName());
        try writer.writeAll("\",");

        // Kind
        try writer.writeAll("\"kind\":");
        try writer.print("{}", .{@as(u8, @intFromEnum(span.kind)) + 1}); // OTLP uses 1-indexed
        try writer.writeAll(",");

        // Timestamps
        try writer.writeAll("\"startTimeUnixNano\":\"");
        try writer.print("{}", .{span.start_time_ns});
        try writer.writeAll("\",\"endTimeUnixNano\":\"");
        try writer.print("{}", .{span.end_time_ns});
        try writer.writeAll("\",");

        // Attributes
        try writer.writeAll("\"attributes\":[");
        for (0..span.attribute_count) |i| {
            if (i > 0) try writer.writeAll(",");
            const attr = &span.attributes[i];
            try writer.writeAll("{\"key\":\"");
            try writeJsonString(writer, attr.getKey());
            try writer.writeAll("\",\"value\":");
            try writeAttributeValue(writer, attr.value);
            try writer.writeAll("}");
        }
        try writer.writeAll("],");

        // Events
        try writer.writeAll("\"events\":[");
        for (0..span.event_count) |i| {
            if (i > 0) try writer.writeAll(",");
            const event = &span.events[i];
            try writer.writeAll("{\"name\":\"");
            try writeJsonString(writer, event.getName());
            try writer.writeAll("\",\"timeUnixNano\":\"");
            try writer.print("{}", .{event.timestamp_ns});
            try writer.writeAll("\"}");
        }
        try writer.writeAll("],");

        // Status
        try writer.writeAll("\"status\":{\"code\":");
        try writer.print("{}", .{@intFromEnum(span.status.code)});
        if (span.status.code == .Error and span.status.description_len > 0) {
            try writer.writeAll(",\"message\":\"");
            try writeJsonString(writer, span.status.getDescription());
            try writer.writeAll("\"");
        }
        try writer.writeAll("}");

        try writer.writeAll("}");
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
// JSON Helpers
// =============================================================================

/// Write a JSON-escaped string
fn writeJsonString(writer: *FixedBufferWriter, str: []const u8) !void {
    for (str) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

fn writeAttributeValue(writer: *FixedBufferWriter, value: span_mod.AttributeValue) !void {
    switch (value) {
        .bool_val => |v| {
            try writer.writeAll("{\"boolValue\":");
            try writer.writeAll(if (v) "true" else "false");
            try writer.writeAll("}");
        },
        .int_val => |v| {
            try writer.writeAll("{\"intValue\":\"");
            try writer.print("{}", .{v});
            try writer.writeAll("\"}");
        },
        .double_val => |v| {
            try writer.writeAll("{\"doubleValue\":");
            try writer.print("{d}", .{v});
            try writer.writeAll("}");
        },
        .string_val => |s| {
            try writer.writeAll("{\"stringValue\":\"");
            try writeJsonString(writer, s.data[0..s.len]);
            try writer.writeAll("\"}");
        },
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

    const json = writer.getWritten();

    // Verify basic structure
    try std.testing.expect(std.mem.indexOf(u8, json, "\"resourceSpans\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"test-service\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"test-operation\"") != null);
    // Check for attributes (they should be present since attribute_count > 0)
    try std.testing.expect(std.mem.indexOf(u8, json, "\"attributes\"") != null);
}

test "writeJsonString escapes special characters" {
    var buf: [256]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);

    try writeJsonString(&writer, "hello\"world\\test\nnewline");

    const result = writer.getWritten();
    try std.testing.expectEqualStrings("hello\\\"world\\\\test\\nnewline", result);
}

test "FixedBufferWriter basic operations" {
    var buf: [64]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);

    try writer.writeAll("hello");
    try writer.writeByte(' ');
    try writer.print("{}", .{42});

    try std.testing.expectEqualStrings("hello 42", writer.getWritten());
}
