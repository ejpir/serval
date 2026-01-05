// lib/serval-tracing/tracing.zig
//! Tracing Interface
//!
//! Comptime interface for distributed tracing.
//! Includes NoopTracer (zero overhead).
//! TigerStyle: Fixed-size buffers, no allocation.

const std = @import("std");
const core = @import("serval-core");

// =============================================================================
// Tracer Interface Verification
// =============================================================================

/// Verify that a type implements the Tracer interface.
/// Required methods: startSpan, endSpan
/// Optional methods: setStringAttribute, setIntAttribute (verified if present)
pub fn verifyTracer(comptime T: type) void {
    // Required methods
    if (!@hasDecl(T, "startSpan")) {
        @compileError("Tracer must implement: pub fn startSpan(self, name: []const u8, parent: ?SpanHandle) SpanHandle");
    }
    if (!@hasDecl(T, "endSpan")) {
        @compileError("Tracer must implement: pub fn endSpan(self, handle: SpanHandle, err: ?[]const u8) void");
    }

    // Optional methods - verify signature if declared
    // This catches mismatched signatures at compile time rather than call site
    if (@hasDecl(T, "setStringAttribute")) {
        const SetStringAttrFn = @TypeOf(@field(T, "setStringAttribute"));
        const expected_args = .{ *T, SpanHandle, []const u8, []const u8 };
        const actual_info = @typeInfo(SetStringAttrFn);
        if (actual_info != .@"fn") {
            @compileError("setStringAttribute must be a function");
        }
        if (actual_info.@"fn".params.len != expected_args.len) {
            @compileError("setStringAttribute signature: fn(self, handle: SpanHandle, key: []const u8, value: []const u8) void");
        }
    }
    if (@hasDecl(T, "setIntAttribute")) {
        const SetIntAttrFn = @TypeOf(@field(T, "setIntAttribute"));
        const actual_info = @typeInfo(SetIntAttrFn);
        if (actual_info != .@"fn") {
            @compileError("setIntAttribute must be a function");
        }
        if (actual_info.@"fn".params.len != 4) {
            @compileError("setIntAttribute signature: fn(self, handle: SpanHandle, key: []const u8, value: i64) void");
        }
    }
}

// =============================================================================
// Span Handle (re-exported from serval-core)
// =============================================================================

/// Lightweight reference to a span.
/// Defined in serval-core for use by Context.
/// Re-exported here for convenience.
pub const SpanHandle = core.SpanHandle;

// =============================================================================
// NoopTracer (zero overhead)
// =============================================================================

pub const NoopTracer = struct {
    pub fn startSpan(_: *@This(), _: []const u8, _: ?SpanHandle) SpanHandle {
        return .{};
    }

    pub fn endSpan(_: *@This(), _: SpanHandle, _: ?[]const u8) void {}

    pub fn setStringAttribute(_: *@This(), _: SpanHandle, _: []const u8, _: []const u8) void {}

    pub fn setIntAttribute(_: *@This(), _: SpanHandle, _: []const u8, _: i64) void {}
};

// =============================================================================
// Tests
// =============================================================================

test "NoopTracer compiles and runs" {
    var t = NoopTracer{};
    const span = t.startSpan("test", null);
    t.setStringAttribute(span, "key", "value");
    t.setIntAttribute(span, "count", 42);
    t.endSpan(span, null);
}

// SpanHandle tests are in serval-core/span_handle.zig

test "verifyTracer accepts valid tracers" {
    comptime verifyTracer(NoopTracer);
}
