//! OpenTelemetry Span - Fixed-Size Implementation
//!
//! Zero-allocation span for maximum performance in hot paths.
//! TigerStyle: fixed-size arrays, explicit bounds, no runtime allocation.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const log = core.log.scoped(.otel);
const config = core.config;
const types = @import("types.zig");

// Re-export types for convenience
/// Re-export of `types.SpanContext`, the immutable trace context carried with a span.
/// It bundles trace and span identifiers, flags, trace state, and remote or local origin.
/// Validate the underlying IDs before treating a context as usable.
pub const SpanContext = types.SpanContext;
/// Re-export of `types.SpanKind`, the span role enum used by OpenTelemetry.
/// Values map directly to OTLP span kinds such as internal, server, client, producer, and consumer.
/// No extra wrapper behavior is added here.
pub const SpanKind = types.SpanKind;
/// Re-export of `types.Status`, the span completion status type.
/// The underlying type stores the code and an optional fixed-size error description buffer.
/// Use the underlying helpers to construct `unset`, `ok`, or error statuses.
pub const Status = types.Status;
/// Re-export of `types.TraceID`, the 128-bit trace identifier type.
/// It is a fixed-size value type with zero, validity, and hex conversion helpers on the underlying type.
/// Use the underlying type's validity rules when accepting external input.
pub const TraceID = types.TraceID;
/// Re-export of `types.SpanID`, the 64-bit span identifier type.
/// It is a fixed-size value type with zero and hex conversion helpers on the underlying type.
/// Use the underlying type's validity rules when accepting external input.
pub const SpanID = types.SpanID;
/// Re-export of `types.TraceFlags`, the OpenTelemetry trace-flags bitset.
/// Use it to read or update sampling state via the underlying type's methods.
/// This alias adds no wrapper behavior or ownership rules.
pub const TraceFlags = types.TraceFlags;
/// Re-export of `types.InstrumentationScope` for span-related APIs.
/// The underlying type stores the instrumentation library name and version in fixed-size buffers.
/// Follow the underlying type's length and truncation behavior when constructing values.
pub const InstrumentationScope = types.InstrumentationScope;

// =============================================================================
// Constants (from serval-core/config.zig)
// =============================================================================

/// Maximum number of attributes a span can store.
/// This value is sourced from `config.OTEL_MAX_ATTRIBUTES` and is a fixed compile-time limit.
/// Use it when sizing or validating span attribute storage.
pub const MAX_ATTRIBUTES = config.OTEL_MAX_ATTRIBUTES;
/// Maximum number of events a span can store.
/// This value is sourced from `config.OTEL_MAX_EVENTS` and is a fixed compile-time limit.
/// Use it when sizing or validating span event storage.
pub const MAX_EVENTS = config.OTEL_MAX_EVENTS;
/// Maximum number of span links stored inline on a span.
/// The span's fixed-size link buffer is sized to this limit.
pub const MAX_LINKS = config.OTEL_MAX_LINKS;
/// Maximum number of bytes stored inline for attribute and event keys.
/// Callers should keep keys within this bound before copying them in.
pub const MAX_KEY_LEN = config.OTEL_MAX_KEY_LEN;
/// Maximum number of bytes stored inline for span names.
/// `Span.init` asserts that the provided name does not exceed this limit.
pub const MAX_NAME_LEN = config.OTEL_MAX_NAME_LEN;
/// Maximum number of bytes stored inline for attribute string values.
/// Longer inputs passed to `fromString` are truncated to this size.
pub const MAX_STRING_VALUE_LEN = config.OTEL_MAX_STRING_VALUE_LEN;

// =============================================================================
// Attribute Value - discriminated union for attribute types
// =============================================================================

/// Fixed-size OpenTelemetry attribute value stored inline.
/// String values are copied into the internal buffer; longer inputs are
/// truncated to `MAX_STRING_VALUE_LEN` bytes.
/// The helper constructors return tagged union values without allocation.
pub const AttributeValue = union(enum) {
    bool_val: bool,
    int_val: i64,
    double_val: f64,
    string_val: struct {
        data: [MAX_STRING_VALUE_LEN]u8,
        len: u16,
    },

    const Self = @This();

    /// Constructs an `AttributeValue` containing a boolean value.
/// The value is stored directly in the union.
/// No allocation or validation is performed.
    pub fn fromBool(val: bool) Self {
        return .{ .bool_val = val };
    }

    /// Constructs an `AttributeValue` containing an integer value.
/// The value is stored directly in the union.
/// No allocation or validation is performed.
    pub fn fromInt(val: i64) Self {
        return .{ .int_val = val };
    }

    /// Constructs an `AttributeValue` containing a floating-point value.
/// The value is stored directly in the union.
/// No allocation or validation is performed.
    pub fn fromDouble(val: f64) Self {
        return .{ .double_val = val };
    }

    /// Copies `val` into the inline string buffer and returns a string variant.
/// Inputs longer than `MAX_STRING_VALUE_LEN` bytes are truncated.
/// No allocation or error is performed.
    pub fn fromString(val: []const u8) Self {
        var result = Self{ .string_val = .{ .data = undefined, .len = 0 } };
        const copy_len = @min(val.len, MAX_STRING_VALUE_LEN);
        @memcpy(result.string_val.data[0..copy_len], val[0..copy_len]);
        result.string_val.len = @intCast(copy_len);
        return result;
    }

    /// Returns the stored string value when this union holds `.string_val`.
/// Non-string variants return `null`.
/// The returned slice aliases the union's inline string buffer, so the union
/// value must stay alive for as long as the slice is used.
    pub fn getString(self: Self) ?[]const u8 {
        return switch (self) {
            .string_val => |s| s.data[0..s.len],
            else => null,
        };
    }
};

// =============================================================================
// Fixed-Size Attribute
// =============================================================================

/// A key/value attribute stored inline with no heap allocation.
/// The key is copied into the fixed-size buffer and read back with `getKey()`.
/// `value` may hold a bool, integer, floating-point number, or string.
pub const Attribute = struct {
    key: [MAX_KEY_LEN]u8,
    key_len: u8,
    value: AttributeValue,

    const Self = @This();

    // TigerStyle: use pointer to avoid copying and dangling slice
    /// Returns the stored key as a slice of the inline buffer.
/// The returned slice aliases storage owned by `self` and remains valid while
/// that object is alive and the key length is unchanged.
/// No allocation or copying is performed.
    pub fn getKey(self: *const Self) []const u8 {
        return self.key[0..self.key_len];
    }
};

// =============================================================================
// Fixed-Size Event
// =============================================================================

/// A span event stored entirely in fixed-size inline storage.
/// The event name is copied into `name` and exposed through `getName()`.
/// `timestamp_ns` records the event time in nanoseconds.
pub const Event = struct {
    name: [MAX_KEY_LEN]u8,
    name_len: u8,
    timestamp_ns: u64,

    const Self = @This();

    // TigerStyle: use pointer to avoid copying and dangling slice
    /// Returns the stored name as a slice of the inline buffer.
/// The returned slice aliases storage owned by `self` and remains valid while
/// that object is alive and the name length is unchanged.
/// No allocation or copying is performed.
    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }
};

// =============================================================================
// Fixed-Size Link (reference to another span)
// =============================================================================

/// A link to another span context.
/// The context is stored by value and copied into the parent span's fixed
/// link storage.
/// No ownership or lifetime management is involved beyond the embedded data.
pub const Link = struct {
    span_context: SpanContext,
};

// =============================================================================
// Span - The main tracing unit
// =============================================================================

/// In-memory OpenTelemetry span with fixed-size storage for metadata,
/// attributes, events, and links.
/// Use `init` to create a recording span or `disabled` for a no-op span.
/// Inline name storage is bounded by `MAX_NAME_LEN`, and collection fields
/// are capped by the corresponding `MAX_*` constants.
pub const Span = struct {
    // Identity
    span_context: SpanContext,
    parent_span_id: ?SpanID,

    // Metadata
    name_buf: [MAX_NAME_LEN]u8,
    name_len: u8,
    kind: SpanKind,
    scope: InstrumentationScope,

    // Timing (TigerStyle: _ns suffix for nanoseconds)
    start_time_ns: u64,
    end_time_ns: u64,

    // Fixed-size storage
    attributes: [MAX_ATTRIBUTES]Attribute,
    attribute_count: u8,
    events: [MAX_EVENTS]Event,
    event_count: u8,
    links: [MAX_LINKS]Link,
    link_count: u8,

    // Status
    status: Status,
    is_recording: bool,

    const Self = @This();

    /// Create a new recording span
    pub fn init(
        span_context: SpanContext,
        name: []const u8,
        kind: SpanKind,
        scope: InstrumentationScope,
    ) Self {
        // TigerStyle: assertion on name length
        assert(name.len <= MAX_NAME_LEN);

        var span = Self{
            .span_context = span_context,
            .parent_span_id = null,
            .name_buf = [_]u8{0} ** MAX_NAME_LEN, // Zero for defense-in-depth
            .name_len = 0,
            .kind = kind,
            .scope = scope,
            .start_time_ns = @intCast(@max(0, core.realtimeNanos())),
            .end_time_ns = 0,
            .attributes = undefined,
            .attribute_count = 0,
            .events = undefined,
            .event_count = 0,
            .links = undefined,
            .link_count = 0,
            .status = Status.unset(),
            .is_recording = true,
        };

        const copy_len: usize = @min(name.len, MAX_NAME_LEN);
        @memcpy(span.name_buf[0..copy_len], name[0..copy_len]);
        span.name_len = @intCast(copy_len);
        return span;
    }

    /// Create a non-recording (disabled) span
    pub fn disabled() Self {
        return Self{
            .span_context = SpanContext.init(
                TraceID.zero(),
                SpanID.zero(),
                TraceFlags.init(0),
                types.TraceState.init(),
                false,
            ),
            .parent_span_id = null,
            .name_buf = undefined,
            .name_len = 0,
            .kind = .Internal,
            .scope = InstrumentationScope.init("", ""),
            .start_time_ns = 0,
            .end_time_ns = 0,
            .attributes = undefined,
            .attribute_count = 0,
            .events = undefined,
            .event_count = 0,
            .links = undefined,
            .link_count = 0,
            .status = Status.unset(),
            .is_recording = false,
        };
    }

    /// Get span name
    /// TigerStyle: use pointer to avoid copying and dangling slice
    pub fn getName(self: *const Self) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    /// Update span name
    pub fn updateName(self: *Self, name: []const u8) void {
        if (!self.is_recording) return;
        const copy_len = @min(name.len, MAX_NAME_LEN);
        @memcpy(self.name_buf[0..copy_len], name[0..copy_len]);
        self.name_len = @intCast(copy_len);
    }

    /// Set a string attribute.
    /// TigerStyle: logs on failure rather than swallowing errors.
    pub fn setStringAttribute(self: *Self, key: []const u8, value: []const u8) void {
        self.setAttribute(key, AttributeValue.fromString(value)) catch |err| {
            log.debug("setStringAttribute failed for key '{s}': {}", .{ key, err });
        };
    }

    /// Set an integer attribute.
    /// TigerStyle: logs on failure rather than swallowing errors.
    pub fn setIntAttribute(self: *Self, key: []const u8, value: i64) void {
        self.setAttribute(key, AttributeValue.fromInt(value)) catch |err| {
            log.debug("setIntAttribute failed for key '{s}': {}", .{ key, err });
        };
    }

    /// Set a boolean attribute.
    /// TigerStyle: logs on failure rather than swallowing errors.
    pub fn setBoolAttribute(self: *Self, key: []const u8, value: bool) void {
        self.setAttribute(key, AttributeValue.fromBool(value)) catch |err| {
            log.debug("setBoolAttribute failed for key '{s}': {}", .{ key, err });
        };
    }

    /// Set a double attribute.
    /// TigerStyle: logs on failure rather than swallowing errors.
    pub fn setDoubleAttribute(self: *Self, key: []const u8, value: f64) void {
        self.setAttribute(key, AttributeValue.fromDouble(value)) catch |err| {
            log.debug("setDoubleAttribute failed for key '{s}': {}", .{ key, err });
        };
    }

    /// Set an attribute (generic)
    pub fn setAttribute(self: *Self, key: []const u8, value: AttributeValue) !void {
        if (!self.is_recording) return;
        if (key.len > MAX_KEY_LEN) return error.KeyTooLong;

        // Check if key exists - update in place
        for (self.attributes[0..self.attribute_count]) |*attr| {
            if (std.mem.eql(u8, attr.key[0..attr.key_len], key)) {
                attr.value = value;
                return;
            }
        }

        // Add new attribute
        if (self.attribute_count >= MAX_ATTRIBUTES) return error.TooManyAttributes;

        var attr = &self.attributes[self.attribute_count];
        // TigerStyle: zero the buffer first for defense-in-depth
        @memset(&attr.key, 0);
        const copy_len: usize = @min(key.len, MAX_KEY_LEN);
        @memcpy(attr.key[0..copy_len], key[0..copy_len]);
        attr.key_len = @intCast(copy_len);
        attr.value = value;
        self.attribute_count += 1;
    }

    /// Add an event (simplified - no event attributes)
    pub fn addEvent(self: *Self, name: []const u8) !void {
        if (!self.is_recording) return;
        if (self.event_count >= MAX_EVENTS) return error.TooManyEvents;
        if (name.len > MAX_KEY_LEN) return error.NameTooLong;

        var event = &self.events[self.event_count];
        // TigerStyle: zero the buffer first for defense-in-depth (prevents info leak)
        @memset(&event.name, 0);
        @memcpy(event.name[0..name.len], name);
        event.name_len = @intCast(name.len);
        event.timestamp_ns = @intCast(@max(0, core.realtimeNanos()));
        self.event_count += 1;
    }

    /// Add a link to another span
    pub fn addLink(self: *Self, span_context: SpanContext) !void {
        if (!self.is_recording) return;
        if (self.link_count >= MAX_LINKS) return error.TooManyLinks;

        self.links[self.link_count] = Link{ .span_context = span_context };
        self.link_count += 1;
    }

    /// Set status to OK
    pub fn setOk(self: *Self) void {
        if (!self.is_recording) return;
        self.status = Status.ok();
    }

    /// Set status to Error with description
    pub fn setError(self: *Self, description: []const u8) void {
        if (!self.is_recording) return;
        self.status = Status.err(description);
    }

    /// Set status (generic)
    pub fn setStatus(self: *Self, status: Status) void {
        if (!self.is_recording) return;
        self.status = status;
    }

    /// End the span (records end time)
    pub fn end(self: *Self) void {
        if (!self.is_recording) return;
        if (self.end_time_ns != 0) return; // Already ended
        self.end_time_ns = @intCast(@max(0, core.realtimeNanos()));
    }

    /// End the span with explicit timestamp
    pub fn endWithTimestamp(self: *Self, end_time_ns: u64) void {
        if (!self.is_recording) return;
        if (self.end_time_ns != 0) return;
        self.end_time_ns = end_time_ns;
    }

    /// Get duration in nanoseconds (0 if not ended)
    pub fn getDurationNs(self: Self) u64 {
        if (self.end_time_ns == 0) return 0;
        return self.end_time_ns -| self.start_time_ns; // Saturating sub
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Span basic lifecycle" {
    const trace_id = TraceID.init([16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
    const span_id = SpanID.init([8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const span_context = SpanContext.init(trace_id, span_id, TraceFlags.default(), types.TraceState.init(), false);
    const scope = InstrumentationScope.init("test-lib", "1.0.0");

    var span = Span.init(span_context, "test-span", .Server, scope);

    try std.testing.expectEqualStrings("test-span", span.getName());
    try std.testing.expect(span.is_recording);
    try std.testing.expect(span.start_time_ns > 0);
    try std.testing.expectEqual(@as(u64, 0), span.end_time_ns);

    span.setStringAttribute("http.method", "GET");
    span.setIntAttribute("http.status_code", 200);
    span.setBoolAttribute("http.retry", false);

    try std.testing.expectEqual(@as(u8, 3), span.attribute_count);

    try span.addEvent("request_started");
    try std.testing.expectEqual(@as(u8, 1), span.event_count);

    span.setOk();
    try std.testing.expectEqual(Status.Code.Ok, span.status.code);

    span.end();
    try std.testing.expect(span.end_time_ns > 0);
    try std.testing.expect(span.getDurationNs() > 0);
}

test "Span disabled is no-op" {
    var span = Span.disabled();
    try std.testing.expect(!span.is_recording);

    // These should all be no-ops
    span.setStringAttribute("key", "value");
    span.setIntAttribute("key", 42);
    try std.testing.expectEqual(@as(u8, 0), span.attribute_count);

    span.addEvent("event") catch |err| {
        std.log.warn("span disabled addEvent failed unexpectedly: {s}", .{@errorName(err)});
    };
    try std.testing.expectEqual(@as(u8, 0), span.event_count);

    span.setOk();
    try std.testing.expectEqual(Status.Code.Unset, span.status.code);
}

test "Span attribute update" {
    const trace_id = TraceID.init([16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
    const span_id = SpanID.init([8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const span_context = SpanContext.init(trace_id, span_id, TraceFlags.default(), types.TraceState.init(), false);
    const scope = InstrumentationScope.init("test-lib", "1.0.0");

    var span = Span.init(span_context, "test", .Internal, scope);

    span.setIntAttribute("retries", 1);
    span.setIntAttribute("retries", 2);
    span.setIntAttribute("retries", 3);

    // Should still only have 1 attribute (updated in place)
    try std.testing.expectEqual(@as(u8, 1), span.attribute_count);
    try std.testing.expectEqual(@as(i64, 3), span.attributes[0].value.int_val);
}

test "Span error status" {
    const trace_id = TraceID.init([16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
    const span_id = SpanID.init([8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const span_context = SpanContext.init(trace_id, span_id, TraceFlags.default(), types.TraceState.init(), false);
    const scope = InstrumentationScope.init("test-lib", "1.0.0");

    var span = Span.init(span_context, "test", .Internal, scope);

    span.setError("connection refused");
    try std.testing.expectEqual(Status.Code.Error, span.status.code);
    try std.testing.expectEqualStrings("connection refused", span.status.getDescription());
}
