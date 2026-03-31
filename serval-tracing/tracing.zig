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
/// Kept private here; the public alias lives at the module root.
const SpanHandle = core.SpanHandle;

// =============================================================================
// NoopTracer (zero overhead)
// =============================================================================

/// No-op tracer implementation that satisfies the tracing API without recording spans or events.
/// `startSpan` ignores `name` and `parent` and always returns a zero-initialized `SpanHandle`.
/// `endSpan`, `setStringAttribute`, `setIntAttribute`, and `addEvent` ignore all inputs and perform no action.
/// No data is retained from passed slices, and all methods are infallible.
pub const NoopTracer = struct {
    /// Starts a tracing span and returns a `SpanHandle` for subsequent tracing calls.
    /// Current implementation is a no-op: `name` and `parent` are ignored, and the returned handle is always `.{}`.
    /// This function does not allocate and cannot fail.
    pub fn startSpan(_: *@This(), _: []const u8, _: ?SpanHandle) SpanHandle {
        return .{};
    }

    /// Ends a tracing span.
    /// This implementation is a no-op: it ignores the provided `SpanHandle` and optional `[]const u8`.
    /// It always returns normally and reports no errors.
    pub fn endSpan(_: *@This(), _: SpanHandle, _: ?[]const u8) void {}

    /// Sets a string attribute on a span.
    /// Current implementation is a no-op: all arguments are ignored and no attribute is recorded.
    /// Accepts a span handle plus UTF-8 byte slices for key and value; slices are not retained.
    /// Never fails and has no side effects.
    pub fn setStringAttribute(_: *@This(), _: SpanHandle, _: []const u8, _: []const u8) void {}

    /// Sets an integer attribute on the given span using the provided key.
    /// This implementation is currently a no-op; `span`, `key`, and `value` are ignored.
    /// The key slice is borrowed only for the call and is not retained.
    /// Does not return errors or modify tracer state.
    pub fn setIntAttribute(_: *@This(), _: SpanHandle, _: []const u8, _: i64) void {}

    /// Records an event for `span` with the provided `message`.
    /// This implementation is currently a no-op: all parameters are ignored.
    /// No validation is performed on `span` or `message`, and no state is mutated.
    /// The function does not allocate, does not retain `message`, and cannot fail.
    pub fn addEvent(_: *@This(), _: SpanHandle, _: []const u8) void {}
};

// =============================================================================
// Tests
// =============================================================================

test "NoopTracer compiles and runs" {
    var t = NoopTracer{};
    const span = t.startSpan("test", null);
    t.setStringAttribute(span, "key", "value");
    t.setIntAttribute(span, "count", 42);
    t.addEvent(span, "request_started");
    t.endSpan(span, null);
}

// SpanHandle tests are in serval-core/span_handle.zig

test "verifyTracer accepts valid tracers" {
    comptime verifyTracer(NoopTracer);
}
