//! OpenTelemetry Core Types
//!
//! Fixed-size types for distributed tracing. TigerStyle: no allocation,
//! explicit sizes (u8, u16, u32, u64 - not usize except for slice indexing).

const std = @import("std");
const core = @import("serval-core");
const config = core.config;

// =============================================================================
// Constants (from serval-core/config.zig - single source of truth)
// =============================================================================

pub const MAX_TRACE_STATE_ENTRIES = config.OTEL_MAX_TRACE_STATE_ENTRIES;
pub const MAX_TRACE_STATE_KEY_LEN = config.OTEL_MAX_TRACE_STATE_KEY_LEN;
pub const MAX_TRACE_STATE_VALUE_LEN = config.OTEL_MAX_TRACE_STATE_VALUE_LEN;

// =============================================================================
// TraceID - 128-bit trace identifier
// =============================================================================

pub const TraceID = struct {
    bytes: [16]u8,

    const Self = @This();

    pub fn init(value: [16]u8) Self {
        return .{ .bytes = value };
    }

    pub fn zero() Self {
        return .{ .bytes = [_]u8{0} ** 16 };
    }

    /// A TraceID is valid if it contains at least one non-zero byte
    pub fn isValid(self: Self) bool {
        for (self.bytes) |byte| {
            if (byte != 0) return true;
        }
        return false;
    }

    /// Returns the binary representation (16-byte array)
    pub fn toBinary(self: Self) [16]u8 {
        return self.bytes;
    }

    /// Returns lowercase hex-encoded string (32 characters)
    pub fn toHex(self: Self, buf: *[32]u8) []const u8 {
        _ = std.fmt.bufPrint(buf, "{x:0>32}", .{std.mem.readInt(u128, &self.bytes, .big)}) catch unreachable;
        return buf;
    }

    /// Parse TraceID from hex string
    pub fn fromHex(hex_string: []const u8) !Self {
        if (hex_string.len != 32) return error.InvalidHexLength;

        var value: [16]u8 = undefined;
        for (0..16) |i| {
            value[i] = try std.fmt.parseInt(u8, hex_string[i * 2 .. i * 2 + 2], 16);
        }
        return Self.init(value);
    }
};

// =============================================================================
// SpanID - 64-bit span identifier
// =============================================================================

pub const SpanID = struct {
    bytes: [8]u8,

    const Self = @This();

    pub fn init(value: [8]u8) Self {
        return .{ .bytes = value };
    }

    pub fn zero() Self {
        return .{ .bytes = [_]u8{0} ** 8 };
    }

    /// A SpanID is valid if it contains at least one non-zero byte
    pub fn isValid(self: Self) bool {
        for (self.bytes) |byte| {
            if (byte != 0) return true;
        }
        return false;
    }

    /// Returns the binary representation (8-byte array)
    pub fn toBinary(self: Self) [8]u8 {
        return self.bytes;
    }

    /// Returns lowercase hex-encoded string (16 characters)
    pub fn toHex(self: Self, buf: *[16]u8) []const u8 {
        _ = std.fmt.bufPrint(buf, "{x:0>16}", .{std.mem.readInt(u64, &self.bytes, .big)}) catch unreachable;
        return buf;
    }

    /// Parse SpanID from hex string
    pub fn fromHex(hex_string: []const u8) !Self {
        if (hex_string.len != 16) return error.InvalidHexLength;

        var value: [8]u8 = undefined;
        for (0..8) |i| {
            value[i] = try std.fmt.parseInt(u8, hex_string[i * 2 .. i * 2 + 2], 16);
        }
        return Self.init(value);
    }
};

// =============================================================================
// TraceFlags - W3C Trace Context flags (8-bit)
// =============================================================================

pub const TraceFlags = struct {
    value: u8,

    const Self = @This();

    /// Sampled flag bit position
    pub const SAMPLED: u8 = 0x01;

    pub fn init(value: u8) Self {
        return .{ .value = value };
    }

    /// Default: sampled = true
    pub fn default() Self {
        return .{ .value = SAMPLED };
    }

    pub fn isSampled(self: Self) bool {
        return (self.value & SAMPLED) != 0;
    }

    pub fn setSampled(self: *Self, sampled: bool) void {
        if (sampled) {
            self.value |= SAMPLED;
        } else {
            self.value &= ~SAMPLED;
        }
    }
};

// =============================================================================
// TraceState - W3C Trace Context vendor-specific state (fixed-size)
// =============================================================================

pub const TraceState = struct {
    const Entry = struct {
        key: [MAX_TRACE_STATE_KEY_LEN]u8,
        key_len: u8,
        value: [MAX_TRACE_STATE_VALUE_LEN]u8,
        value_len: u16,
    };

    entries: [MAX_TRACE_STATE_ENTRIES]Entry,
    count: u8,

    const Self = @This();

    pub fn init() Self {
        return .{
            .entries = undefined,
            .count = 0,
        };
    }

    /// Get value for key (returns null if not found)
    /// TigerStyle: takes *const Self to avoid returning slice to temporary copy
    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        // TigerStyle: bounded loop (max MAX_TRACE_STATE_ENTRIES iterations)
        for (self.entries[0..self.count]) |*entry| {
            if (std.mem.eql(u8, entry.key[0..entry.key_len], key)) {
                return entry.value[0..entry.value_len];
            }
        }
        return null;
    }

    /// Insert or update a key-value pair. Returns error if full or key/value too long.
    pub fn put(self: *Self, key: []const u8, value: []const u8) !void {
        // TigerStyle: explicit bounds checks as assertions
        if (key.len > MAX_TRACE_STATE_KEY_LEN) return error.KeyTooLong;
        if (value.len > MAX_TRACE_STATE_VALUE_LEN) return error.ValueTooLong;

        // Check if key exists - update in place
        for (self.entries[0..self.count]) |*entry| {
            if (std.mem.eql(u8, entry.key[0..entry.key_len], key)) {
                @memcpy(entry.value[0..value.len], value);
                entry.value_len = @intCast(value.len);
                return;
            }
        }

        // Add new entry
        if (self.count >= MAX_TRACE_STATE_ENTRIES) return error.TraceStateFull;

        var entry = &self.entries[self.count];
        @memcpy(entry.key[0..key.len], key);
        entry.key_len = @intCast(key.len);
        @memcpy(entry.value[0..value.len], value);
        entry.value_len = @intCast(value.len);
        self.count += 1;
    }

    /// Remove a key. No-op if key not found.
    pub fn remove(self: *Self, key: []const u8) void {
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.entries[i].key[0..self.entries[i].key_len], key)) {
                // Shift remaining entries down
                if (i + 1 < self.count) {
                    std.mem.copyForwards(Entry, self.entries[i .. self.count - 1], self.entries[i + 1 .. self.count]);
                }
                self.count -= 1;
                return;
            }
        }
    }
};

// =============================================================================
// SpanContext - immutable trace context propagated across process boundaries
// =============================================================================

pub const SpanContext = struct {
    trace_id: TraceID,
    span_id: SpanID,
    trace_flags: TraceFlags,
    trace_state: TraceState,
    is_remote: bool,

    const Self = @This();

    pub fn init(
        trace_id: TraceID,
        span_id: SpanID,
        trace_flags: TraceFlags,
        trace_state: TraceState,
        is_remote: bool,
    ) Self {
        return .{
            .trace_id = trace_id,
            .span_id = span_id,
            .trace_flags = trace_flags,
            .trace_state = trace_state,
            .is_remote = is_remote,
        };
    }

    /// A SpanContext is valid if both trace_id and span_id are valid
    pub fn isValid(self: Self) bool {
        return self.trace_id.isValid() and self.span_id.isValid();
    }

    pub fn isSampled(self: Self) bool {
        return self.trace_flags.isSampled();
    }
};

// =============================================================================
// SpanKind - type of span (maps to OTLP SpanKind)
// =============================================================================

pub const SpanKind = enum(u8) {
    /// Default. Indicates that the span represents an internal operation.
    Internal = 0,
    /// Indicates that the span covers server-side handling of an RPC or HTTP request.
    Server = 1,
    /// Indicates that the span describes a request to some remote service.
    Client = 2,
    /// Indicates that the span describes a producer sending a message to a broker.
    Producer = 3,
    /// Indicates that the span describes a consumer receiving a message from a broker.
    Consumer = 4,
};

// =============================================================================
// Status - span completion status
// =============================================================================

pub const Status = struct {
    code: Code,
    /// Error description (only used when code == .Error). Points to fixed-size buffer.
    description_buf: [256]u8,
    description_len: u16,

    pub const Code = enum(u8) {
        /// The default status.
        Unset = 0,
        /// The Span has been validated by an application developer or operator.
        Ok = 1,
        /// The Span contains an error.
        Error = 2,
    };

    const Self = @This();

    pub fn unset() Self {
        return .{
            .code = .Unset,
            .description_buf = undefined,
            .description_len = 0,
        };
    }

    pub fn ok() Self {
        return .{
            .code = .Ok,
            .description_buf = undefined,
            .description_len = 0,
        };
    }

    pub fn err(description: []const u8) Self {
        var status = Self{
            .code = .Error,
            .description_buf = undefined,
            .description_len = 0,
        };
        const copy_len = @min(description.len, status.description_buf.len);
        @memcpy(status.description_buf[0..copy_len], description[0..copy_len]);
        status.description_len = @intCast(copy_len);
        return status;
    }

    /// TigerStyle: takes *const Self to avoid returning slice to temporary copy
    pub fn getDescription(self: *const Self) []const u8 {
        return self.description_buf[0..self.description_len];
    }
};

// =============================================================================
// InstrumentationScope - identifies the instrumentation library
// =============================================================================

pub const InstrumentationScope = struct {
    /// Library name (e.g., "serval-proxy")
    name_buf: [64]u8,
    name_len: u8,
    /// Library version (e.g., "1.0.0")
    version_buf: [32]u8,
    version_len: u8,

    const Self = @This();

    pub fn init(name: []const u8, version: []const u8) Self {
        var scope = Self{
            .name_buf = undefined,
            .name_len = 0,
            .version_buf = undefined,
            .version_len = 0,
        };
        const name_copy_len = @min(name.len, scope.name_buf.len);
        @memcpy(scope.name_buf[0..name_copy_len], name[0..name_copy_len]);
        scope.name_len = @intCast(name_copy_len);

        const version_copy_len = @min(version.len, scope.version_buf.len);
        @memcpy(scope.version_buf[0..version_copy_len], version[0..version_copy_len]);
        scope.version_len = @intCast(version_copy_len);
        return scope;
    }

    /// TigerStyle: takes *const Self to avoid returning slice to temporary copy
    pub fn getName(self: *const Self) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    /// TigerStyle: takes *const Self to avoid returning slice to temporary copy
    pub fn getVersion(self: *const Self) []const u8 {
        return self.version_buf[0..self.version_len];
    }
};

// =============================================================================
// Tests
// =============================================================================

test "TraceID validity" {
    const valid = TraceID.init([16]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    try std.testing.expect(valid.isValid());

    const invalid = TraceID.zero();
    try std.testing.expect(!invalid.isValid());
}

test "TraceID hex roundtrip" {
    const trace_id = TraceID.init([16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef });
    var buf: [32]u8 = undefined;
    const hex = trace_id.toHex(&buf);
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", hex);

    const parsed = try TraceID.fromHex(hex);
    try std.testing.expectEqual(trace_id.bytes, parsed.bytes);
}

test "SpanID validity" {
    const valid = SpanID.init([8]u8{ 1, 0, 0, 0, 0, 0, 0, 0 });
    try std.testing.expect(valid.isValid());

    const invalid = SpanID.zero();
    try std.testing.expect(!invalid.isValid());
}

test "SpanID hex roundtrip" {
    const span_id = SpanID.init([8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef });
    var buf: [16]u8 = undefined;
    const hex = span_id.toHex(&buf);
    try std.testing.expectEqualStrings("0123456789abcdef", hex);

    const parsed = try SpanID.fromHex(hex);
    try std.testing.expectEqual(span_id.bytes, parsed.bytes);
}

test "TraceFlags sampled" {
    var flags = TraceFlags.default();
    try std.testing.expect(flags.isSampled());

    flags.setSampled(false);
    try std.testing.expect(!flags.isSampled());

    flags.setSampled(true);
    try std.testing.expect(flags.isSampled());
}

test "TraceState put and get" {
    var state = TraceState.init();
    try state.put("vendor1", "value1");
    try state.put("vendor2", "value2");

    try std.testing.expectEqualStrings("value1", state.get("vendor1").?);
    try std.testing.expectEqualStrings("value2", state.get("vendor2").?);
    try std.testing.expect(state.get("vendor3") == null);
}

test "TraceState update existing key" {
    var state = TraceState.init();
    try state.put("key", "value1");
    try state.put("key", "value2");

    try std.testing.expectEqualStrings("value2", state.get("key").?);
    try std.testing.expectEqual(@as(u8, 1), state.count);
}

test "TraceState remove" {
    var state = TraceState.init();
    try state.put("key1", "value1");
    try state.put("key2", "value2");

    state.remove("key1");
    try std.testing.expect(state.get("key1") == null);
    try std.testing.expectEqualStrings("value2", state.get("key2").?);
    try std.testing.expectEqual(@as(u8, 1), state.count);
}

test "SpanContext validity" {
    const valid_ctx = SpanContext.init(
        TraceID.init([16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }),
        SpanID.init([8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }),
        TraceFlags.default(),
        TraceState.init(),
        false,
    );
    try std.testing.expect(valid_ctx.isValid());
    try std.testing.expect(valid_ctx.isSampled());

    const invalid_ctx = SpanContext.init(
        TraceID.zero(),
        SpanID.zero(),
        TraceFlags.init(0),
        TraceState.init(),
        false,
    );
    try std.testing.expect(!invalid_ctx.isValid());
}

test "Status error with description" {
    const status = Status.err("connection timeout");
    try std.testing.expectEqual(Status.Code.Error, status.code);
    try std.testing.expectEqualStrings("connection timeout", status.getDescription());
}

test "InstrumentationScope" {
    const scope = InstrumentationScope.init("serval-proxy", "1.0.0");
    try std.testing.expectEqualStrings("serval-proxy", scope.getName());
    try std.testing.expectEqualStrings("1.0.0", scope.getVersion());
}

test "TraceState get with pointer" {
    var state = TraceState.init();
    try state.put("vendor", "value");
    // Test that get works correctly with pointer semantics
    try std.testing.expectEqualStrings("value", state.get("vendor").?);
}

test "Status getDescription with pointer" {
    const status = Status.err("timeout");
    try std.testing.expectEqualStrings("timeout", status.getDescription());
}
