//! OpenTelemetry Tracer and TracerProvider
//!
//! Creates and manages spans. TracerProvider is the factory for Tracers.
//! TigerStyle: no allocation after init, explicit thread safety.

const std = @import("std");
const types = @import("types.zig");
const span_mod = @import("span.zig");
const id_gen = @import("id_generator.zig");

const Span = span_mod.Span;
const SpanKind = types.SpanKind;
const SpanContext = types.SpanContext;
const TraceID = types.TraceID;
const SpanID = types.SpanID;
const TraceFlags = types.TraceFlags;
const TraceState = types.TraceState;
const InstrumentationScope = types.InstrumentationScope;
const RandomIDGenerator = id_gen.RandomIDGenerator;

// =============================================================================
// SpanProcessor Interface (forward declaration for dependency injection)
// =============================================================================

/// Interface for processing spans when they end.
/// Implementations: SimpleProcessor, BatchingProcessor
pub const SpanProcessor = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    const VTable = struct {
        onEndFn: *const fn (ptr: *anyopaque, span: Span) void,
    };

    pub fn onEnd(self: SpanProcessor, span: Span) void {
        self.vtable.onEndFn(self.ptr, span);
    }
};

/// No-op processor for when tracing is disabled
pub const NoopProcessor = struct {
    pub fn asSpanProcessor(self: *NoopProcessor) SpanProcessor {
        return .{
            .ptr = self,
            .vtable = &.{
                .onEndFn = onEnd,
            },
        };
    }

    fn onEnd(_: *anyopaque, _: Span) void {
        // No-op
    }
};

// =============================================================================
// Tracer
// =============================================================================

/// Creates spans for a specific instrumentation scope.
/// Obtained from TracerProvider.getTracer().
pub const Tracer = struct {
    provider: *TracerProvider,
    scope: InstrumentationScope,

    const Self = @This();

    /// Start a new root span (no parent)
    pub fn startSpan(self: *Self, name: []const u8, kind: SpanKind) Span {
        return self.startSpanWithParent(name, kind, null);
    }

    /// Start a new span with optional parent
    pub fn startSpanWithParent(self: *Self, name: []const u8, kind: SpanKind, parent: ?*const Span) Span {
        self.provider.mutex.lock();
        defer self.provider.mutex.unlock();

        const span_id = self.provider.id_gen.newSpanId();

        // Inherit context from parent or create new root context
        const span_context = if (parent) |p|
            SpanContext.init(p.span_context.trace_id, span_id, p.span_context.trace_flags, p.span_context.trace_state, false)
        else
            SpanContext.init(self.provider.id_gen.newTraceId(), span_id, TraceFlags.default(), TraceState.init(), false);

        var span = Span.init(span_context, name, kind, self.scope);
        if (parent) |p| {
            span.parent_span_id = p.span_context.span_id;
        }
        return span;
    }

    /// Start a server span (convenience for handling incoming requests)
    pub fn startServerSpan(self: *Self, name: []const u8) Span {
        return self.startSpan(name, .Server);
    }

    /// Start a client span (convenience for outgoing requests)
    pub fn startClientSpan(self: *Self, name: []const u8) Span {
        return self.startSpan(name, .Client);
    }

    /// Start a child span from parent context
    pub fn startChildSpan(self: *Self, parent: *const Span, name: []const u8, kind: SpanKind) Span {
        return self.startSpanWithParent(name, kind, parent);
    }

    /// End a span and submit to processor
    pub fn endSpan(self: *Self, span: *Span) void {
        span.end();

        // Submit to processor (outside mutex - processor has its own locking)
        if (self.provider.processor) |processor| {
            processor.onEnd(span.*);
        }
    }
};

// =============================================================================
// TracerProvider
// =============================================================================

/// Factory for creating Tracers. Owns the ID generator and processor.
pub const TracerProvider = struct {
    id_gen: RandomIDGenerator,
    processor: ?SpanProcessor,
    mutex: std.Thread.Mutex,

    const Self = @This();

    /// Initialize with optional processor
    pub fn init(processor: ?SpanProcessor) Self {
        return .{
            .id_gen = RandomIDGenerator.initRandom(),
            .processor = processor,
            .mutex = .{},
        };
    }

    /// Initialize with deterministic seed (for testing)
    pub fn initWithSeed(seed: u64, processor: ?SpanProcessor) Self {
        return .{
            .id_gen = RandomIDGenerator.init(seed),
            .processor = processor,
            .mutex = .{},
        };
    }

    /// Get a tracer for the given scope
    pub fn getTracer(self: *Self, name: []const u8, version: []const u8) Tracer {
        return .{
            .provider = self,
            .scope = InstrumentationScope.init(name, version),
        };
    }

    /// Shutdown the provider (flushes processor if applicable)
    pub fn shutdown(self: *Self) void {
        _ = self;
        // Processor shutdown is handled externally
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Tracer creates valid spans" {
    var provider = TracerProvider.initWithSeed(12345, null);
    var tracer = provider.getTracer("test-lib", "1.0.0");

    var span = tracer.startSpan("test-operation", .Internal);
    try std.testing.expect(span.span_context.isValid());
    try std.testing.expect(span.is_recording);
    try std.testing.expectEqualStrings("test-operation", span.getName());
    try std.testing.expectEqualStrings("test-lib", span.scope.getName());

    span.setStringAttribute("key", "value");
    tracer.endSpan(&span);

    try std.testing.expect(span.end_time_ns > 0);
}

test "Tracer creates child spans" {
    var provider = TracerProvider.initWithSeed(12345, null);
    var tracer = provider.getTracer("test-lib", "1.0.0");

    var parent = tracer.startServerSpan("handle-request");
    var child = tracer.startChildSpan(&parent, "database-query", .Client);

    // Child should share trace_id with parent
    try std.testing.expectEqual(parent.span_context.trace_id.bytes, child.span_context.trace_id.bytes);

    // Child should have different span_id
    try std.testing.expect(!std.mem.eql(u8, &parent.span_context.span_id.bytes, &child.span_context.span_id.bytes));

    // Child should reference parent
    try std.testing.expect(child.parent_span_id != null);
    try std.testing.expectEqual(parent.span_context.span_id.bytes, child.parent_span_id.?.bytes);

    tracer.endSpan(&child);
    tracer.endSpan(&parent);
}

test "TracerProvider with processor" {
    const TestProcessor = struct {
        spans_received: u32 = 0,

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
            self.spans_received += 1;
        }
    };

    var processor = TestProcessor{};
    var provider = TracerProvider.initWithSeed(12345, processor.asSpanProcessor());
    var tracer = provider.getTracer("test", "1.0");

    var span = tracer.startSpan("op", .Internal);
    tracer.endSpan(&span);

    try std.testing.expectEqual(@as(u32, 1), processor.spans_received);
}

test "NoopProcessor is no-op" {
    var noop = NoopProcessor{};
    const processor = noop.asSpanProcessor();

    const span = Span.disabled();
    processor.onEnd(span); // Should not crash
}
