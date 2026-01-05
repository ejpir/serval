//! serval-otel - OpenTelemetry Tracing for Serval
//!
//! Minimal OTLP tracing implementation extracted from zig-o11y.
//! Provides fixed-size spans with zero-allocation hot path.
//!
//! ## Quick Start
//!
//! ```zig
//! const otel = @import("serval-otel");
//!
//! // Initialize with OTLP exporter
//! try otel.init(allocator, .{
//!     .endpoint = "http://localhost:4318/v1/traces",
//!     .service_name = "my-service",
//! });
//! defer otel.deinit();
//!
//! // Create spans
//! var span = otel.startServerSpan("handle-request");
//! defer otel.endSpan(&span);
//!
//! span.setStringAttribute("http.method", "GET");
//! span.setIntAttribute("http.status_code", 200);
//! ```
//!
//! ## TigerStyle Compliance
//!
//! - Fixed-size Span struct (no allocation after init)
//! - Bounded arrays for attributes (32), events (8), links (4)
//! - Explicit u32/u64 types, _ns suffix for nanoseconds
//! - ~2 assertions per function for preconditions
//! - Single GlobalState struct for synchronized state

const std = @import("std");

// =============================================================================
// Public Exports
// =============================================================================

// Core types
pub const types = @import("types.zig");
pub const TraceID = types.TraceID;
pub const SpanID = types.SpanID;
pub const SpanContext = types.SpanContext;
pub const SpanKind = types.SpanKind;
pub const Status = types.Status;
pub const TraceFlags = types.TraceFlags;
pub const TraceState = types.TraceState;
pub const InstrumentationScope = types.InstrumentationScope;

// Span
pub const span = @import("span.zig");
pub const Span = span.Span;
pub const AttributeValue = span.AttributeValue;
pub const Attribute = span.Attribute;
pub const Event = span.Event;
pub const Link = span.Link;

// Tracer
pub const tracer = @import("tracer.zig");
pub const Tracer = tracer.Tracer;
pub const TracerProvider = tracer.TracerProvider;
pub const SpanProcessor = tracer.SpanProcessor;
pub const NoopProcessor = tracer.NoopProcessor;

// Processor
pub const processor = @import("processor.zig");
pub const SimpleProcessor = processor.SimpleProcessor;
pub const BatchingProcessor = processor.BatchingProcessor;
pub const SpanExporter = processor.SpanExporter;
pub const ConsoleExporter = processor.ConsoleExporter;

// Exporter
pub const exporter = @import("exporter.zig");
pub const OTLPExporter = exporter.OTLPExporter;
pub const OTLPConfig = exporter.Config;

// ID Generator
pub const id_generator = @import("id_generator.zig");
pub const RandomIDGenerator = id_generator.RandomIDGenerator;

// Adapter (implements serval-tracing interface)
pub const adapter = @import("adapter.zig");
pub const OtelTracer = adapter.OtelTracer;

// =============================================================================
// Global Tracing State
// =============================================================================

/// TigerStyle: Single struct for all global state to keep in sync.
/// All fields are set atomically during init/deinit.
const GlobalState = struct {
    allocator: std.mem.Allocator,
    provider: *TracerProvider,
    tracer_instance: *Tracer,
    processor_instance: *BatchingProcessor,
    exporter_instance: *OTLPExporter,
};

var global_state: ?GlobalState = null;
var global_mutex: std.Thread.Mutex = .{};

/// Configuration for global tracing initialization
pub const Config = struct {
    /// OTLP collector endpoint
    endpoint: []const u8 = exporter.DEFAULT_ENDPOINT,
    /// Service name for resource attributes
    service_name: []const u8 = "unknown-service",
    /// Service version
    service_version: []const u8 = "0.1.0",
    /// Instrumentation scope name
    scope_name: []const u8 = "serval",
    /// Instrumentation scope version
    scope_version: []const u8 = "1.0.0",
    /// Batching processor config
    batch_config: BatchingProcessor.Config = .{},
};

// =============================================================================
// Global API
// =============================================================================

/// Initialize global tracing with OTLP exporter.
/// Must be called before using any tracing functions.
/// TigerStyle: All-or-nothing initialization, no partial state.
pub fn init(allocator: std.mem.Allocator, cfg: Config) !void {
    global_mutex.lock();
    defer global_mutex.unlock();

    // TigerStyle: assertion on precondition
    if (global_state != null) {
        return error.AlreadyInitialized;
    }

    // Create exporter
    const exp = try OTLPExporter.init(allocator, .{
        .endpoint = cfg.endpoint,
        .service_name = cfg.service_name,
        .service_version = cfg.service_version,
    });
    errdefer exp.deinit();

    // Create processor
    const proc = try BatchingProcessor.init(allocator, exp.asSpanExporter(), cfg.batch_config);
    errdefer {
        proc.shutdown();
        proc.deinit();
    }

    // Create provider
    const provider = try allocator.create(TracerProvider);
    errdefer allocator.destroy(provider);
    provider.* = TracerProvider.init(proc.asSpanProcessor());

    // Create tracer
    const t = try allocator.create(Tracer);
    errdefer allocator.destroy(t);
    t.* = provider.getTracer(cfg.scope_name, cfg.scope_version);

    // TigerStyle: atomic assignment of entire state
    global_state = .{
        .allocator = allocator,
        .provider = provider,
        .tracer_instance = t,
        .processor_instance = proc,
        .exporter_instance = exp,
    };
}

/// Shutdown global tracing (flushes and closes connections)
/// TigerStyle: All-or-nothing cleanup, no partial state.
pub fn deinit() void {
    global_mutex.lock();
    defer global_mutex.unlock();

    const state = global_state orelse return;

    // Shutdown in reverse order of creation
    state.processor_instance.shutdown();
    state.processor_instance.deinit();
    state.exporter_instance.deinit();
    state.allocator.destroy(state.tracer_instance);
    state.allocator.destroy(state.provider);

    global_state = null;
}

/// Check if tracing is enabled
pub fn isEnabled() bool {
    return global_state != null;
}

/// Start a server span (for handling incoming requests)
pub fn startServerSpan(name: []const u8) Span {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_state) |state| {
        return state.tracer_instance.startServerSpan(name);
    }
    return Span.disabled();
}

/// Start a client span (for outgoing requests)
pub fn startClientSpan(name: []const u8) Span {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_state) |state| {
        return state.tracer_instance.startClientSpan(name);
    }
    return Span.disabled();
}

/// Start an internal span
pub fn startSpan(name: []const u8) Span {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_state) |state| {
        return state.tracer_instance.startSpan(name, .Internal);
    }
    return Span.disabled();
}

/// Start a child span from parent
pub fn startChildSpan(parent: *const Span, name: []const u8, kind: SpanKind) Span {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_state) |state| {
        return state.tracer_instance.startChildSpan(parent, name, kind);
    }
    return Span.disabled();
}

/// End a span and submit for export
pub fn endSpan(s: *Span) void {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_state) |state| {
        state.tracer_instance.endSpan(s);
    } else {
        s.end();
    }
}

/// Force flush pending spans
pub fn flush() !void {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_state) |state| {
        try state.processor_instance.forceFlush();
    }
}

// =============================================================================
// Tests
// =============================================================================

test "module exports" {
    // Verify all public types are accessible
    _ = Span;
    _ = Tracer;
    _ = TracerProvider;
    _ = OTLPExporter;
    _ = BatchingProcessor;
    _ = SpanContext;
    _ = SpanKind;
}

test "disabled span is no-op" {
    var s = Span.disabled();
    try std.testing.expect(!s.is_recording);

    s.setStringAttribute("key", "value");
    s.setIntAttribute("count", 42);
    try std.testing.expectEqual(@as(u8, 0), s.attribute_count);
}

test "global API without init returns disabled spans" {
    // Don't call init - should return disabled spans
    var s = startServerSpan("test");
    try std.testing.expect(!s.is_recording);
    endSpan(&s);
}

// Run all submodule tests
test {
    _ = @import("types.zig");
    _ = @import("span.zig");
    _ = @import("id_generator.zig");
    _ = @import("tracer.zig");
    _ = @import("processor.zig");
    _ = @import("exporter.zig");
    _ = @import("adapter.zig");
}
