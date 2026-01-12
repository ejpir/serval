//! Span Processors
//!
//! SimpleProcessor: exports spans immediately (low latency, high overhead)
//! BatchingProcessor: batches spans for efficient export (recommended)
//!
//! TigerStyle: fixed-size queue, bounded loops, explicit thread safety.

const std = @import("std");
const core = @import("serval-core");
const config = core.config;
const time = core.time;
const span_mod = @import("span.zig");
const tracer_mod = @import("tracer.zig");

const Span = span_mod.Span;
const SpanProcessor = tracer_mod.SpanProcessor;

// Constants from serval-core/config.zig (single source of truth)
pub const MAX_QUEUE_SIZE = config.OTEL_MAX_QUEUE_SIZE;
pub const MAX_EXPORT_BATCH_SIZE = config.OTEL_MAX_EXPORT_BATCH_SIZE;
pub const DEFAULT_BATCH_DELAY_MS = config.OTEL_BATCH_DELAY_MS;

// =============================================================================
// Exporter Interface
// =============================================================================

/// Interface for exporting spans to a backend (OTLP, console, etc.)
pub const SpanExporter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    const VTable = struct {
        exportFn: *const fn (ptr: *anyopaque, spans: []const Span) anyerror!void,
        shutdownFn: *const fn (ptr: *anyopaque) void,
    };

    pub fn exportSpans(self: SpanExporter, spans: []const Span) !void {
        return self.vtable.exportFn(self.ptr, spans);
    }

    pub fn shutdown(self: SpanExporter) void {
        self.vtable.shutdownFn(self.ptr);
    }
};

// =============================================================================
// SimpleProcessor
// =============================================================================

/// Exports each span immediately when it ends.
/// Low latency but higher overhead - use for debugging or low-volume tracing.
pub const SimpleProcessor = struct {
    exporter: SpanExporter,
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(exporter: SpanExporter) Self {
        return .{
            .exporter = exporter,
            .mutex = .{},
        };
    }

    pub fn asSpanProcessor(self: *Self) SpanProcessor {
        return .{
            .ptr = self,
            .vtable = &.{
                .onEndFn = onEnd,
            },
        };
    }

    fn onEnd(ptr: *anyopaque, span: Span) void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (!span.is_recording) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        var spans = [_]Span{span};
        self.exporter.exportSpans(&spans) catch |err| {
            std.log.err("SimpleProcessor export failed: {}", .{err});
        };
    }

    pub fn shutdown(self: *Self) void {
        self.exporter.shutdown();
    }
};

// =============================================================================
// BatchingProcessor
// =============================================================================

/// Batches spans and exports them periodically or when batch size is reached.
/// Recommended for production - lower overhead, higher throughput.
/// TigerStyle: mutex released during export to avoid blocking producers.
pub const BatchingProcessor = struct {
    // Configuration (TigerStyle: explicit u32, _ms suffix)
    // Uses module-level constants from config.zig as defaults
    pub const Config = struct {
        scheduled_delay_ms: u32 = DEFAULT_BATCH_DELAY_MS,
        max_export_batch_size: u32 = MAX_EXPORT_BATCH_SIZE,
    };

    allocator: std.mem.Allocator,
    exporter: SpanExporter,
    config: Config,

    // Fixed-size queue (TigerStyle: no dynamic allocation after init)
    // Uses MAX_QUEUE_SIZE from config.zig
    queue: [MAX_QUEUE_SIZE]Span,
    queue_len: u32,

    // Export buffer - copy spans here before releasing mutex
    // TigerStyle: I/O happens outside critical sections
    export_buffer: [MAX_EXPORT_BATCH_SIZE]Span,

    // Thread synchronization
    mutex: std.Thread.Mutex,
    condition: std.Thread.Condition,
    export_thread: ?std.Thread,
    should_shutdown: std.atomic.Value(bool),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, exporter: SpanExporter, cfg: Config) !*Self {
        // TigerStyle: assertions on config values
        std.debug.assert(cfg.max_export_batch_size > 0);
        std.debug.assert(cfg.max_export_batch_size <= MAX_EXPORT_BATCH_SIZE);
        std.debug.assert(cfg.scheduled_delay_ms > 0);

        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .exporter = exporter,
            .config = cfg,
            .queue = undefined,
            .queue_len = 0,
            .export_buffer = undefined,
            .mutex = .{},
            .condition = .{},
            .export_thread = null,
            .should_shutdown = std.atomic.Value(bool).init(false),
        };

        // Start background export thread
        self.export_thread = try std.Thread.spawn(.{}, exportLoop, .{self});

        return self;
    }

    pub fn deinit(self: *Self) void {
        // Shutdown should have been called first
        std.debug.assert(self.export_thread == null);
        self.allocator.destroy(self);
    }

    pub fn asSpanProcessor(self: *Self) SpanProcessor {
        return .{
            .ptr = self,
            .vtable = &.{
                .onEndFn = onEnd,
            },
        };
    }

    fn onEnd(ptr: *anyopaque, span: Span) void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        if (!span.is_recording) return;

        self.mutex.lock();

        // Drop span if queue is full (TigerStyle: bounded, no panic)
        if (self.queue_len >= MAX_QUEUE_SIZE) {
            self.mutex.unlock();
            std.log.warn("BatchingProcessor queue full, dropping span", .{});
            return;
        }

        // Add span to queue (fixed-size copy, no allocation)
        self.queue[self.queue_len] = span;
        self.queue_len += 1;

        // Signal if batch size reached
        const should_signal = self.queue_len >= self.config.max_export_batch_size;
        self.mutex.unlock();

        if (should_signal) {
            self.condition.signal();
        }
    }

    /// Force export of all queued spans (for graceful shutdown)
    pub fn forceFlush(self: *Self) !void {
        self.mutex.lock();

        if (self.queue_len > 0) {
            // exportBatchUnlocked releases the mutex
            self.exportBatchUnlocked();
        } else {
            self.mutex.unlock();
        }
    }

    /// Shutdown the processor (stops background thread, exports remaining spans)
    pub fn shutdown(self: *Self) void {
        // Signal shutdown
        self.should_shutdown.store(true, .release);

        // Wake up export thread
        self.mutex.lock();
        self.condition.signal();
        self.mutex.unlock();

        // Wait for thread to finish
        if (self.export_thread) |thread| {
            thread.join();
            self.export_thread = null;
        }

        self.exporter.shutdown();
    }

    fn exportLoop(self: *Self) void {
        while (!self.should_shutdown.load(.acquire)) {
            self.mutex.lock();

            // Wait for batch size or timeout
            if (self.queue_len < self.config.max_export_batch_size) {
                self.condition.timedWait(
                    &self.mutex,
                    @as(u64, self.config.scheduled_delay_ms) * time.ns_per_ms,
                ) catch {};
            }

            // Export if we have spans (releases mutex during I/O)
            if (self.queue_len > 0) {
                self.exportBatchUnlocked();
            } else {
                self.mutex.unlock();
            }
        }

        // Final export on shutdown
        self.mutex.lock();
        if (self.queue_len > 0) {
            self.exportBatchUnlocked();
        } else {
            self.mutex.unlock();
        }
    }

    /// Copy spans to export buffer, release mutex, then export.
    /// TigerStyle: I/O happens outside critical section to avoid blocking producers.
    /// IMPORTANT: Caller must hold mutex. This function releases it.
    fn exportBatchUnlocked(self: *Self) void {
        std.debug.assert(self.queue_len > 0); // Precondition

        const batch_size = @min(self.queue_len, self.config.max_export_batch_size);

        // Copy spans to export buffer (while holding mutex)
        @memcpy(self.export_buffer[0..batch_size], self.queue[0..batch_size]);

        // Remove exported spans from queue
        if (batch_size < self.queue_len) {
            std.mem.copyForwards(
                Span,
                self.queue[0 .. self.queue_len - batch_size],
                self.queue[batch_size..self.queue_len],
            );
        }
        self.queue_len -= batch_size;

        // Release mutex BEFORE I/O
        self.mutex.unlock();

        // Export spans (outside critical section)
        self.exporter.exportSpans(self.export_buffer[0..batch_size]) catch |err| {
            std.log.err("BatchingProcessor export failed: {}", .{err});
        };
    }
};

// =============================================================================
// Console Exporter (for debugging)
// =============================================================================

/// Simple exporter that prints spans to stderr (for debugging)
pub const ConsoleExporter = struct {
    const Self = @This();

    pub fn asSpanExporter(self: *Self) SpanExporter {
        return .{
            .ptr = self,
            .vtable = &.{
                .exportFn = exportSpans,
                .shutdownFn = shutdown,
            },
        };
    }

    fn exportSpans(_: *anyopaque, spans: []const Span) anyerror!void {
        // TigerStyle: use pointer iteration to avoid copies and ensure getName() works
        for (spans) |*span| {
            var trace_buf: [32]u8 = undefined;
            var span_buf: [16]u8 = undefined;
            std.debug.print(
                "[SPAN] {s} trace={s} span={s} duration_us={}\n",
                .{
                    span.getName(),
                    span.span_context.trace_id.toHex(&trace_buf),
                    span.span_context.span_id.toHex(&span_buf),
                    span.getDurationNs() / 1000,
                },
            );
        }
    }

    fn shutdown(_: *anyopaque) void {}
};

// =============================================================================
// Tests
// =============================================================================

test "SimpleProcessor exports immediately" {
    const TestExporter = struct {
        exported_count: u32 = 0,

        pub fn asSpanExporter(self: *@This()) SpanExporter {
            return .{
                .ptr = self,
                .vtable = &.{
                    .exportFn = exportSpans,
                    .shutdownFn = shutdown,
                },
            };
        }

        fn exportSpans(ptr: *anyopaque, spans: []const Span) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.exported_count += @intCast(spans.len);
        }

        fn shutdown(_: *anyopaque) void {}
    };

    var exporter = TestExporter{};
    var processor = SimpleProcessor.init(exporter.asSpanExporter());
    const span_processor = processor.asSpanProcessor();

    // Create and end a span
    const span = Span.init(
        span_mod.SpanContext.init(
            span_mod.TraceID.init([16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }),
            span_mod.SpanID.init([8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }),
            span_mod.TraceFlags.default(),
            @import("types.zig").TraceState.init(),
            false,
        ),
        "test-span",
        .Internal,
        @import("types.zig").InstrumentationScope.init("test", "1.0"),
    );

    span_processor.onEnd(span);

    try std.testing.expectEqual(@as(u32, 1), exporter.exported_count);
}

test "BatchingProcessor batches spans" {
    const TestExporter = struct {
        export_calls: u32 = 0,
        total_spans: u32 = 0,

        pub fn asSpanExporter(self: *@This()) SpanExporter {
            return .{
                .ptr = self,
                .vtable = &.{
                    .exportFn = exportSpans,
                    .shutdownFn = shutdown,
                },
            };
        }

        fn exportSpans(ptr: *anyopaque, spans: []const Span) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.export_calls += 1;
            self.total_spans += @intCast(spans.len);
        }

        fn shutdown(_: *anyopaque) void {}
    };

    var exporter = TestExporter{};
    var processor = try BatchingProcessor.init(
        std.testing.allocator,
        exporter.asSpanExporter(),
        .{ .max_export_batch_size = 5, .scheduled_delay_ms = 100 },
    );
    defer processor.deinit();

    const span_processor = processor.asSpanProcessor();

    // Add 3 spans (below batch threshold)
    for (0..3) |i| {
        const span = Span.init(
            span_mod.SpanContext.init(
                span_mod.TraceID.init([16]u8{ @intCast(i), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }),
                span_mod.SpanID.init([8]u8{ @intCast(i), 2, 3, 4, 5, 6, 7, 8 }),
                span_mod.TraceFlags.default(),
                @import("types.zig").TraceState.init(),
                false,
            ),
            "test-span",
            .Internal,
            @import("types.zig").InstrumentationScope.init("test", "1.0"),
        );
        span_processor.onEnd(span);
    }

    // Wait for timer to trigger export
    time.sleep(time.millisToNanos(150));

    // Force flush and shutdown
    try processor.forceFlush();
    processor.shutdown();

    try std.testing.expectEqual(@as(u32, 3), exporter.total_spans);
}
