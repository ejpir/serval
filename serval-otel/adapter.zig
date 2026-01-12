//! OtelTracer Adapter
//!
//! Implements the serval-tracing interface using serval-otel spans.
//! Bridges the lightweight SpanHandle with full OTLP Span objects.
//!
//! TigerStyle: Fixed-size span pool, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const log = core.log.scoped(.otel);
const config = core.config;
const tracing = @import("serval-tracing");
const SpanHandle = tracing.SpanHandle;

const span_mod = @import("span.zig");
const types = @import("types.zig");
const tracer_mod = @import("tracer.zig");
const id_gen_mod = @import("id_generator.zig");

const Span = span_mod.Span;
const SpanContext = types.SpanContext;
const SpanKind = types.SpanKind;
const TraceID = types.TraceID;
const SpanID = types.SpanID;
const TraceFlags = types.TraceFlags;
const TraceState = types.TraceState;
const InstrumentationScope = types.InstrumentationScope;
const SpanProcessor = tracer_mod.SpanProcessor;
const RandomIDGenerator = id_gen_mod.RandomIDGenerator;

// =============================================================================
// Constants (from serval-core/config.zig - single source of truth)
// =============================================================================

/// Maximum number of concurrent active spans.
/// TigerStyle: fixed at compile time, no runtime allocation.
pub const MAX_ACTIVE_SPANS = config.OTEL_MAX_ACTIVE_SPANS;

// =============================================================================
// OtelTracer
// =============================================================================

/// Tracer that implements serval-tracing interface using serval-otel spans.
/// Maintains a fixed-size pool of active spans, mapping SpanHandle → Span.
///
/// Usage:
/// ```zig
/// var otel_tracer = OtelTracer.init(processor.asSpanProcessor(), "my-service", "1.0.0");
/// // Use with serval-server:
/// const MyServer = Server(MyHandler, SimplePool, NoopMetrics, OtelTracer);
/// ```
pub const OtelTracer = struct {
    /// Pool of active spans (fixed-size, slots reused)
    spans: [MAX_ACTIVE_SPANS]SpanSlot,
    /// Number of active spans (for diagnostics)
    active_count: u32,
    /// ID generator for new traces/spans
    id_generator: RandomIDGenerator,
    /// Processor to export ended spans
    processor: SpanProcessor,
    /// Instrumentation scope for all spans
    scope: InstrumentationScope,
    /// Mutex for thread-safe access
    mutex: std.Thread.Mutex,

    const Self = @This();

    /// Slot in the span pool
    const SpanSlot = struct {
        span: Span,
        in_use: bool,
    };

    /// Create a heap-allocated OtelTracer.
    /// TigerStyle: ~240KB struct requires heap allocation to avoid stack overflow.
    /// Pairs with destroy() for cleanup.
    pub fn create(
        allocator: std.mem.Allocator,
        processor: SpanProcessor,
        scope_name: []const u8,
        scope_version: []const u8,
    ) !*Self {
        // TigerStyle: assertions on inputs
        assert(scope_name.len <= 64);
        assert(scope_version.len <= 32);

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.active_count = 0;
        self.id_generator = RandomIDGenerator.initRandom();
        self.processor = processor;
        self.scope = InstrumentationScope.init(scope_name, scope_version);
        self.mutex = .{};

        // Initialize all slots as not in use
        for (&self.spans) |*slot| {
            slot.in_use = false;
        }

        return self;
    }

    /// Destroy a heap-allocated OtelTracer.
    /// TigerStyle: Pairs with create().
    pub fn destroy(self: *Self, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    // =========================================================================
    // serval-tracing interface implementation
    // =========================================================================

    /// Start a new span, optionally as a child of parent.
    /// Returns a SpanHandle that can be used to reference the span.
    pub fn startSpan(self: *Self, name: []const u8, parent: ?SpanHandle) SpanHandle {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Find a free slot
        const slot_index = self.findFreeSlot() orelse {
            // Pool exhausted - return invalid handle (span will be dropped)
            log.warn("OtelTracer: span pool exhausted, dropping span '{s}'", .{name});
            return .{};
        };

        // Generate IDs
        const trace_id: TraceID = if (parent) |p|
            TraceID.init(p.trace_id)
        else
            self.id_generator.newTraceId();

        const span_id = self.id_generator.newSpanId();

        // Create span context
        const span_context = SpanContext.init(
            trace_id,
            span_id,
            TraceFlags.default(),
            TraceState.init(),
            false, // not remote
        );

        // Create the span
        var span = Span.init(span_context, name, .Server, self.scope);

        // Set parent if provided
        if (parent) |p| {
            span.parent_span_id = SpanID.init(p.span_id);
        }

        // Store in slot
        self.spans[slot_index] = .{
            .span = span,
            .in_use = true,
        };
        self.active_count += 1;

        // Return handle
        return .{
            .trace_id = trace_id.bytes,
            .span_id = span_id.bytes,
            .parent_span_id = if (parent) |p| p.span_id else [_]u8{0} ** 8,
        };
    }

    /// End a span and submit for export.
    /// If err is non-null, sets the span status to Error with the description.
    pub fn endSpan(self: *Self, handle: SpanHandle, err: ?[]const u8) void {
        self.mutex.lock();

        // Find the span by span_id
        const slot_index = self.findSpanBySpanId(handle.span_id) orelse {
            self.mutex.unlock();
            return; // Span not found (already ended or invalid)
        };

        // Get the span and mark slot as free
        var span = self.spans[slot_index].span;
        self.spans[slot_index].in_use = false;

        // TigerStyle: assertion guards against underflow from double-end bugs
        assert(self.active_count > 0);
        self.active_count -= 1;

        // Set error status if provided
        if (err) |description| {
            span.setError(description);
        } else {
            span.setOk();
        }

        // End the span (records end time)
        span.end();

        // Release mutex before I/O (TigerStyle: I/O outside critical section)
        self.mutex.unlock();

        // Export via processor
        self.processor.onEnd(span);
    }

    /// Set a string attribute on an active span.
    pub fn setStringAttribute(self: *Self, handle: SpanHandle, key: []const u8, value: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findSpanBySpanId(handle.span_id)) |slot_index| {
            self.spans[slot_index].span.setStringAttribute(key, value);
        }
    }

    /// Set an integer attribute on an active span.
    pub fn setIntAttribute(self: *Self, handle: SpanHandle, key: []const u8, value: i64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findSpanBySpanId(handle.span_id)) |slot_index| {
            self.spans[slot_index].span.setIntAttribute(key, value);
        }
    }

    /// Add an event (log) to an active span.
    pub fn addEvent(self: *Self, handle: SpanHandle, name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findSpanBySpanId(handle.span_id)) |slot_index| {
            self.spans[slot_index].span.addEvent(name) catch |err| {
                log.debug("addEvent failed for span: {}", .{err});
            };
        }
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Find a free slot in the span pool.
    /// Returns null if pool is exhausted.
    fn findFreeSlot(self: *Self) ?usize {
        // TigerStyle: bounded loop
        for (&self.spans, 0..) |*slot, i| {
            if (!slot.in_use) {
                return i;
            }
        }
        return null;
    }

    /// Find a span by its span_id.
    /// Returns the slot index or null if not found.
    fn findSpanBySpanId(self: *Self, span_id: [8]u8) ?usize {
        // TigerStyle: bounded loop
        for (&self.spans, 0..) |*slot, i| {
            if (slot.in_use and std.mem.eql(u8, &slot.span.span_context.span_id.bytes, &span_id)) {
                return i;
            }
        }
        return null;
    }

    /// Get the number of active spans (for diagnostics).
    pub fn getActiveCount(self: *Self) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.active_count;
    }
};

// Compile-time verification that OtelTracer implements the interface
comptime {
    tracing.verifyTracer(OtelTracer);
}

// =============================================================================
// Tests
// =============================================================================

test "OtelTracer implements serval-tracing interface" {
    // This test verifies at compile time via comptime block above
    // Runtime test just ensures basic functionality works

    const TestProcessor = struct {
        ended_count: u32 = 0,

        pub fn asSpanProcessor(self: *@This()) SpanProcessor {
            return .{
                .ptr = self,
                .vtable = &.{
                    .onEndFn = onEnd,
                },
            };
        }

        fn onEnd(ptr: *anyopaque, _: Span) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.ended_count += 1;
        }
    };

    var proc = TestProcessor{};
    const tracer = try OtelTracer.create(std.testing.allocator, proc.asSpanProcessor(), "test-service", "1.0.0");
    defer tracer.destroy(std.testing.allocator);

    // Start a root span
    const root = tracer.startSpan("root-operation", null);
    try std.testing.expect(root.isValid());
    try std.testing.expectEqual(@as(u32, 1), tracer.getActiveCount());

    // Start a child span
    const child = tracer.startSpan("child-operation", root);
    try std.testing.expect(child.isValid());
    try std.testing.expectEqual(root.trace_id, child.trace_id); // Same trace
    try std.testing.expect(!std.mem.eql(u8, &root.span_id, &child.span_id)); // Different span
    try std.testing.expectEqual(@as(u32, 2), tracer.getActiveCount());

    // Set attributes
    tracer.setStringAttribute(root, "http.method", "GET");
    tracer.setIntAttribute(root, "http.status_code", 200);

    // Add events
    tracer.addEvent(root, "request_started");
    tracer.addEvent(child, "processing_request");

    // End spans
    tracer.endSpan(child, null);
    try std.testing.expectEqual(@as(u32, 1), tracer.getActiveCount());
    try std.testing.expectEqual(@as(u32, 1), proc.ended_count);

    tracer.endSpan(root, null);
    try std.testing.expectEqual(@as(u32, 0), tracer.getActiveCount());
    try std.testing.expectEqual(@as(u32, 2), proc.ended_count);
}

test "OtelTracer handles error spans" {
    const TestProcessor = struct {
        last_status_code: ?span_mod.Status.Code = null,

        pub fn asSpanProcessor(self: *@This()) SpanProcessor {
            return .{
                .ptr = self,
                .vtable = &.{
                    .onEndFn = onEnd,
                },
            };
        }

        fn onEnd(ptr: *anyopaque, span: Span) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.last_status_code = span.status.code;
        }
    };

    var proc = TestProcessor{};
    const tracer = try OtelTracer.create(std.testing.allocator, proc.asSpanProcessor(), "test", "1.0");
    defer tracer.destroy(std.testing.allocator);

    const handle = tracer.startSpan("failing-operation", null);
    tracer.endSpan(handle, "connection timeout");

    try std.testing.expectEqual(span_mod.Status.Code.Error, proc.last_status_code.?);
}

test "OtelTracer pool exhaustion returns invalid handle" {
    const NoopProcessor = struct {
        pub fn asSpanProcessor(_: *@This()) SpanProcessor {
            return .{
                .ptr = undefined,
                .vtable = &.{
                    .onEndFn = onEnd,
                },
            };
        }

        fn onEnd(_: *anyopaque, _: Span) void {}
    };

    var proc = NoopProcessor{};
    const tracer = try OtelTracer.create(std.testing.allocator, proc.asSpanProcessor(), "test", "1.0");
    defer tracer.destroy(std.testing.allocator);

    // Exhaust the pool
    var handles: [MAX_ACTIVE_SPANS]SpanHandle = undefined;
    for (&handles) |*h| {
        h.* = tracer.startSpan("span", null);
        try std.testing.expect(h.isValid());
    }

    // Next span should return invalid handle
    const overflow = tracer.startSpan("overflow", null);
    try std.testing.expect(!overflow.isValid());

    // Clean up
    for (&handles) |*h| {
        tracer.endSpan(h.*, null);
    }
}
