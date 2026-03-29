//! Span Processors
//!
//! SimpleProcessor: exports spans immediately (low latency, high overhead)
//! BatchingProcessor: batches spans for efficient export (recommended)
//!
//! TigerStyle: fixed-size queue, bounded loops, explicit thread safety.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const log = core.log.scoped(.otel);
const config = core.config;
const time = core.time;
const span_mod = @import("span.zig");
const tracer_mod = @import("tracer.zig");

const Span = span_mod.Span;
const SpanProcessor = tracer_mod.SpanProcessor;

// Constants from serval-core/config.zig (single source of truth)
/// Maximum queue capacity used by the OTEL processor.
/// This constant aliases `config.OTEL_MAX_QUEUE_SIZE`, so its value is defined centrally in `serval-core` config.
/// It is a compile-time constant and does not allocate, own resources, or return errors.
pub const MAX_QUEUE_SIZE = config.OTEL_MAX_QUEUE_SIZE;
/// Maximum number of spans a `BatchingProcessor` export operation may include.
/// Mirrors `serval-core.config.OTEL_MAX_EXPORT_BATCH_SIZE` as this module's public limit.
/// Used as a fixed compile-time array bound (`export_buffer`) and as the upper bound for `Config.max_export_batch_size`.
/// This declaration has no runtime behavior or errors; enforcement occurs in `BatchingProcessor.init` assertions.
pub const MAX_EXPORT_BATCH_SIZE = config.OTEL_MAX_EXPORT_BATCH_SIZE;
/// Default OpenTelemetry batch delay, in milliseconds, used by the processor.
/// This constant is an alias of `config.OTEL_BATCH_DELAY_MS`, so its value is defined centrally in config.
/// Affects timing defaults only; reading this constant has no ownership, lifetime, or error behavior.
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

    /// Exports a batch of spans using this exporter’s vtable implementation.
    /// `self` must reference a valid `SpanExporter` instance with an initialized `vtable` and `ptr`.
    /// `spans` is passed through as-is; the caller retains ownership of the slice.
    /// Returns any error produced by the underlying `exportFn` implementation.
    pub fn exportSpans(self: SpanExporter, spans: []const Span) !void {
        return self.vtable.exportFn(self.ptr, spans);
    }

    /// Shuts down this exporter by dispatching to the implementation-specific `shutdownFn`.
    /// Preconditions: `self` must reference a valid exporter instance with an initialized vtable.
    /// This call does not return errors; any shutdown failures must be handled internally by the implementation.
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
    mutex: std.Io.Mutex,

    const Self = @This();

    /// Initializes a processor instance with the provided `SpanExporter`.
    /// The `exporter` value is stored directly in the returned `Self`.
    /// Initializes `mutex` to its default `.init` state for synchronization.
    /// This function performs no allocation and cannot fail.
    pub fn init(exporter: SpanExporter) Self {
        return .{
            .exporter = exporter,
            .mutex = .init,
        };
    }

    /// Returns a `SpanProcessor` adapter that forwards callbacks to this `Self` via a vtable.
    /// The returned value stores `self` as an opaque pointer and sets only `.onEndFn = onEnd`.
    /// `self` must remain valid for the entire lifetime of any use of the returned processor.
    /// This function does not allocate and cannot fail.
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

        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        var spans = [_]Span{span};
        self.exporter.exportSpans(&spans) catch |err| {
            log.err("SimpleProcessor export failed: {}", .{err});
        };
    }

    /// Forwards shutdown to the wrapped exporter.
    /// This does not deallocate the processor or join the background thread; it only propagates shutdown to the exporter interface.
    /// Call this during teardown before destroying the processor instance.
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
    /// Runtime configuration for the batch processor.
    /// `scheduled_delay_ms` controls the export wake-up delay in milliseconds, and `max_export_batch_size` limits the number of spans per batch.
    /// `init` validates both fields before use; the defaults are chosen from the module's batch timing and size constants.
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
    mutex: std.Io.Mutex,
    wake_event: std.Io.Event,
    export_thread: ?std.Thread,
    should_shutdown: std.atomic.Value(bool),

    const Self = @This();

    /// Allocates and initializes a new processor instance.
    /// `cfg.max_export_batch_size` must be in `1..=MAX_EXPORT_BATCH_SIZE`, and `cfg.scheduled_delay_ms` must be non-zero.
    /// On success, the processor starts its background export thread and returns an owning pointer that must later be shut down and destroyed.
    /// Fails if allocation or thread creation fails.
    pub fn init(allocator: std.mem.Allocator, exporter: SpanExporter, cfg: Config) !*Self {
        // TigerStyle: assertions on config values
        assert(cfg.max_export_batch_size > 0);
        assert(cfg.max_export_batch_size <= MAX_EXPORT_BATCH_SIZE);
        assert(cfg.scheduled_delay_ms > 0);

        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .exporter = exporter,
            .config = cfg,
            .queue = undefined,
            .queue_len = 0,
            .export_buffer = undefined,
            .mutex = .init,
            .wake_event = .unset,
            .export_thread = null,
            .should_shutdown = std.atomic.Value(bool).init(false),
        };

        // Start background export thread
        self.export_thread = try std.Thread.spawn(.{}, exportLoop, .{self});

        return self;
    }

    /// Destroys `self` after shutdown has completed.
    /// This asserts that the background export thread has already been cleared; call shutdown and wait for teardown before deinitializing.
    /// After this returns, the pointer must not be used again.
    pub fn deinit(self: *Self) void {
        // Shutdown should have been called first
        assert(self.export_thread == null);
        self.allocator.destroy(self);
    }

    /// Returns a `SpanProcessor` adapter backed by `self`.
    /// The returned processor does not own `self`; it is only valid while `self` remains alive.
    /// Use this view when a caller needs the processor interface for the processor's `onEnd` callback.
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

        self.mutex.lockUncancelable(std.Options.debug_io);

        // Drop span if queue is full (TigerStyle: bounded, no panic)
        if (self.queue_len >= MAX_QUEUE_SIZE) {
            self.mutex.unlock(std.Options.debug_io);
            log.warn("BatchingProcessor queue full, dropping span", .{});
            return;
        }

        // Add span to queue (fixed-size copy, no allocation)
        self.queue[self.queue_len] = span;
        self.queue_len += 1;

        // Signal if batch size reached
        const should_signal = self.queue_len >= self.config.max_export_batch_size;
        self.mutex.unlock(std.Options.debug_io);

        if (should_signal) {
            self.wake_event.set(std.Options.debug_io);
        }
    }

    /// Force export of all queued spans (for graceful shutdown)
    pub fn forceFlush(self: *Self) !void {
        self.mutex.lockUncancelable(std.Options.debug_io);

        if (self.queue_len > 0) {
            // exportBatchUnlocked releases the mutex
            self.exportBatchUnlocked(std.Options.debug_io);
        } else {
            self.mutex.unlock(std.Options.debug_io);
        }
    }

    /// Shutdown the processor (stops background thread, exports remaining spans)
    pub fn shutdown(self: *Self) void {
        // Signal shutdown
        self.should_shutdown.store(true, .release);

        // Wake up export thread
        self.wake_event.set(std.Options.debug_io);

        // Wait for thread to finish
        if (self.export_thread) |thread| {
            thread.join();
            self.export_thread = null;
        }

        self.exporter.shutdown();
    }

    fn exportLoop(self: *Self) void {
        const io = std.Options.debug_io;
        const timeout: std.Io.Timeout = .{ .duration = .{
            .clock = .awake,
            .raw = .fromMilliseconds(@intCast(self.config.scheduled_delay_ms)),
        } };
        while (!self.should_shutdown.load(.acquire)) {
            _ = self.wake_event.waitTimeout(io, timeout) catch |err| switch (err) {
                error.Timeout => {},
                error.Canceled => {},
            };
            self.wake_event.reset();
            self.mutex.lockUncancelable(io);
            if (self.queue_len > 0) {
                self.exportBatchUnlocked(io);
            } else {
                self.mutex.unlock(io);
            }
        }
        // Final export on shutdown
        self.mutex.lockUncancelable(io);
        if (self.queue_len > 0) {
            self.exportBatchUnlocked(io);
        } else {
            self.mutex.unlock(io);
        }
    }

    /// Copy spans to export buffer, release mutex, then export.
    /// TigerStyle: I/O happens outside critical section to avoid blocking producers.
    /// IMPORTANT: Caller must hold mutex. This function releases it.
    fn exportBatchUnlocked(self: *Self, io: std.Io) void {
        assert(self.queue_len > 0); // Precondition

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
        self.mutex.unlock(io);

        // Export spans (outside critical section)
        self.exporter.exportSpans(self.export_buffer[0..batch_size]) catch |err| {
            log.err("BatchingProcessor export failed: {}", .{err});
        };
    }
};

// =============================================================================
// Console Exporter (for debugging)
// =============================================================================

/// Simple exporter that prints spans to stderr (for debugging)
pub const ConsoleExporter = struct {
    const Self = @This();

    /// Returns a `SpanExporter` adapter backed by `self`.
    /// The returned exporter does not own `self`; it is only valid while `self` remains alive.
    /// Use this view when a caller needs the exporter interface instead of `Self` directly.
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
            std.log.info(
                "[SPAN] {s} trace={s} span={s} duration_us={}",
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

        /// Returns a `SpanExporter` adapter backed by `self`.
        /// The returned exporter does not own `self`; it is only valid while `self` remains alive.
        /// Use this view when a caller needs the exporter interface instead of `Self` directly.
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

        /// Returns a `SpanExporter` adapter backed by `self`.
        /// The returned exporter does not own `self`; it is only valid while `self` remains alive.
        /// Use this view when a caller needs the exporter interface instead of `Self` directly.
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
