//! Comptime JSON Writer
//!
//! Type-safe JSON builder with automatic comma handling.
//! TigerStyle: Fixed-size state stack, no allocation, explicit errors.

const std = @import("std");
const assert = std.debug.assert;

// =============================================================================
// Constants
// =============================================================================

/// Maximum nesting depth for JSON structures.
/// TigerStyle: Fixed bound, sufficient for OTLP (depth ~6).
const MAX_DEPTH: u4 = 12;

// =============================================================================
// JsonWriter
// =============================================================================

/// Streaming JSON writer with automatic comma and structure handling.
/// Tracks object/array state to ensure valid JSON output.
pub fn JsonWriter(comptime BufferWriter: type) type {
    return struct {
        writer: *BufferWriter,
        state: [MAX_DEPTH]State,
        depth: u4,

        const Self = @This();

        const State = enum(u2) {
            object_empty, // Just opened {, no fields yet
            object, // In object, has fields
            array_empty, // Just opened [, no items yet
            array, // In array, has items
        };

        /// Initialize writer in root state.
        pub fn init(writer: *BufferWriter) Self {
            return .{
                .writer = writer,
                .state = undefined,
                .depth = 0,
            };
        }

        // =====================================================================
        // Object Operations
        // =====================================================================

        /// Begin a JSON object: `{`
        pub fn beginObject(self: *Self) !void {
            try self.maybeComma();
            try self.writer.writeByte('{');
            self.push(.object_empty);
        }

        /// End current JSON object: `}`
        pub fn endObject(self: *Self) !void {
            assert(self.depth > 0);
            assert(self.state[self.depth - 1] == .object_empty or
                self.state[self.depth - 1] == .object);
            try self.writer.writeByte('}');
            self.pop();
        }

        /// Write object field name: `"name":`
        /// Must be inside an object.
        pub fn field(self: *Self, comptime name: []const u8) !void {
            assert(self.depth > 0);
            const s = &self.state[self.depth - 1];
            assert(s.* == .object_empty or s.* == .object);

            if (s.* == .object) {
                try self.writer.writeByte(',');
            }
            try self.writer.writeAll("\"" ++ name ++ "\":");
            s.* = .object_empty; // Next value doesn't need comma
        }

        /// Write field with runtime name (for dynamic keys).
        pub fn fieldRuntime(self: *Self, name: []const u8) !void {
            assert(self.depth > 0);
            const s = &self.state[self.depth - 1];
            assert(s.* == .object_empty or s.* == .object);

            if (s.* == .object) {
                try self.writer.writeByte(',');
            }
            try self.writer.writeByte('"');
            try self.writer.writeAll(name);
            try self.writer.writeAll("\":");
            s.* = .object_empty;
        }

        // =====================================================================
        // Array Operations
        // =====================================================================

        /// Begin a JSON array: `[`
        pub fn beginArray(self: *Self) !void {
            try self.maybeComma();
            try self.writer.writeByte('[');
            self.push(.array_empty);
        }

        /// End current JSON array: `]`
        pub fn endArray(self: *Self) !void {
            assert(self.depth > 0);
            assert(self.state[self.depth - 1] == .array_empty or
                self.state[self.depth - 1] == .array);
            try self.writer.writeByte(']');
            self.pop();
        }

        // =====================================================================
        // Value Operations
        // =====================================================================

        /// Write a JSON string value with escaping.
        pub fn string(self: *Self, value: []const u8) !void {
            try self.maybeComma();
            try self.writer.writeByte('"');
            try self.writeEscaped(value);
            try self.writer.writeByte('"');
            self.markValue();
        }

        /// Write a JSON string from a hex-encoded buffer.
        pub fn stringHex(self: *Self, bytes: []const u8, hex_buf: []u8) !void {
            assert(hex_buf.len >= bytes.len * 2);
            const hex = std.fmt.bytesToHex(bytes, .lower);
            try self.maybeComma();
            try self.writer.writeByte('"');
            try self.writer.writeAll(&hex);
            try self.writer.writeByte('"');
            self.markValue();
        }

        /// Write a raw hex string (for trace/span IDs).
        pub fn stringHexRaw(self: *Self, hex: []const u8) !void {
            try self.maybeComma();
            try self.writer.writeByte('"');
            try self.writer.writeAll(hex);
            try self.writer.writeByte('"');
            self.markValue();
        }

        /// Write a JSON integer value.
        pub fn int(self: *Self, value: anytype) !void {
            try self.maybeComma();
            try self.writer.print("{d}", .{value});
            self.markValue();
        }

        /// Write a JSON integer as a quoted string (OTLP style for i64).
        pub fn intString(self: *Self, value: anytype) !void {
            try self.maybeComma();
            try self.writer.writeByte('"');
            try self.writer.print("{d}", .{value});
            try self.writer.writeByte('"');
            self.markValue();
        }

        /// Write a JSON float value.
        pub fn float(self: *Self, value: anytype) !void {
            try self.maybeComma();
            try self.writer.print("{d}", .{value});
            self.markValue();
        }

        /// Write a JSON boolean value.
        pub fn boolean(self: *Self, value: bool) !void {
            try self.maybeComma();
            try self.writer.writeAll(if (value) "true" else "false");
            self.markValue();
        }

        /// Write a JSON null value.
        pub fn writeNull(self: *Self) !void {
            try self.maybeComma();
            try self.writer.writeAll("null");
            self.markValue();
        }

        // =====================================================================
        // OTLP Helpers
        // =====================================================================

        /// Write OTLP string attribute: `{"key":"name","value":{"stringValue":"val"}}`
        pub fn otlpStringAttr(self: *Self, key: []const u8, value: []const u8) !void {
            try self.beginObject();
            try self.field("key");
            try self.string(key);
            try self.field("value");
            try self.beginObject();
            try self.field("stringValue");
            try self.string(value);
            try self.endObject();
            try self.endObject();
        }

        /// Write OTLP int attribute: `{"key":"name","value":{"intValue":"123"}}`
        pub fn otlpIntAttr(self: *Self, key: []const u8, value: i64) !void {
            try self.beginObject();
            try self.field("key");
            try self.string(key);
            try self.field("value");
            try self.beginObject();
            try self.field("intValue");
            try self.intString(value);
            try self.endObject();
            try self.endObject();
        }

        /// Write OTLP bool attribute.
        pub fn otlpBoolAttr(self: *Self, key: []const u8, value: bool) !void {
            try self.beginObject();
            try self.field("key");
            try self.string(key);
            try self.field("value");
            try self.beginObject();
            try self.field("boolValue");
            try self.boolean(value);
            try self.endObject();
            try self.endObject();
        }

        /// Write OTLP double attribute.
        pub fn otlpDoubleAttr(self: *Self, key: []const u8, value: f64) !void {
            try self.beginObject();
            try self.field("key");
            try self.string(key);
            try self.field("value");
            try self.beginObject();
            try self.field("doubleValue");
            try self.float(value);
            try self.endObject();
            try self.endObject();
        }

        // =====================================================================
        // Internal Helpers
        // =====================================================================

        /// Write comma if needed (inside non-empty object/array).
        fn maybeComma(self: *Self) !void {
            if (self.depth == 0) return;
            const s = self.state[self.depth - 1];
            if (s == .array) {
                try self.writer.writeByte(',');
            }
            // object comma is handled in field()
        }

        /// Mark that a value was written (for array comma tracking).
        fn markValue(self: *Self) void {
            if (self.depth == 0) return;
            const s = &self.state[self.depth - 1];
            if (s.* == .array_empty) s.* = .array;
            if (s.* == .object_empty) s.* = .object;
        }

        fn push(self: *Self, state: State) void {
            assert(self.depth < MAX_DEPTH);
            self.state[self.depth] = state;
            self.depth += 1;
        }

        fn pop(self: *Self) void {
            assert(self.depth > 0);
            self.depth -= 1;
            self.markValue(); // The object/array we just closed counts as a value
        }

        /// Write JSON-escaped string content.
        fn writeEscaped(self: *Self, str: []const u8) !void {
            for (str) |c| {
                switch (c) {
                    '"' => try self.writer.writeAll("\\\""),
                    '\\' => try self.writer.writeAll("\\\\"),
                    '\n' => try self.writer.writeAll("\\n"),
                    '\r' => try self.writer.writeAll("\\r"),
                    '\t' => try self.writer.writeAll("\\t"),
                    else => {
                        if (c < 0x20) {
                            try self.writer.print("\\u{x:0>4}", .{c});
                        } else {
                            try self.writer.writeByte(c);
                        }
                    },
                }
            }
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

const FixedBufferWriter = @import("exporter.zig").FixedBufferWriter;

test "JsonWriter simple object" {
    var buf: [256]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);
    var json = JsonWriter(FixedBufferWriter).init(&writer);

    try json.beginObject();
    try json.field("name");
    try json.string("test");
    try json.field("count");
    try json.int(42);
    try json.endObject();

    try std.testing.expectEqualStrings(
        \\{"name":"test","count":42}
    , writer.getWritten());
}

test "JsonWriter nested structures" {
    var buf: [512]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);
    var json = JsonWriter(FixedBufferWriter).init(&writer);

    try json.beginObject();
    try json.field("items");
    try json.beginArray();
    try json.int(1);
    try json.int(2);
    try json.int(3);
    try json.endArray();
    try json.field("nested");
    try json.beginObject();
    try json.field("a");
    try json.boolean(true);
    try json.endObject();
    try json.endObject();

    try std.testing.expectEqualStrings(
        \\{"items":[1,2,3],"nested":{"a":true}}
    , writer.getWritten());
}

test "JsonWriter OTLP attributes" {
    var buf: [512]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);
    var json = JsonWriter(FixedBufferWriter).init(&writer);

    try json.beginArray();
    try json.otlpStringAttr("service.name", "my-service");
    try json.otlpIntAttr("http.status", 200);
    try json.endArray();

    try std.testing.expectEqualStrings(
        \\[{"key":"service.name","value":{"stringValue":"my-service"}},{"key":"http.status","value":{"intValue":"200"}}]
    , writer.getWritten());
}

test "JsonWriter escapes strings" {
    var buf: [256]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);
    var json = JsonWriter(FixedBufferWriter).init(&writer);

    try json.string("hello\"world\ntest");

    try std.testing.expectEqualStrings(
        \\"hello\"world\ntest"
    , writer.getWritten());
}

test "JsonWriter array of objects" {
    var buf: [512]u8 = undefined;
    var writer = FixedBufferWriter.init(&buf);
    var json = JsonWriter(FixedBufferWriter).init(&writer);

    try json.beginArray();
    try json.beginObject();
    try json.field("id");
    try json.int(1);
    try json.endObject();
    try json.beginObject();
    try json.field("id");
    try json.int(2);
    try json.endObject();
    try json.endArray();

    try std.testing.expectEqualStrings(
        \\[{"id":1},{"id":2}]
    , writer.getWritten());
}
