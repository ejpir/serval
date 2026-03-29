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
/// Public import of `types.zig`.
/// Use this namespace for trace identifiers, flags, state, and context types.
/// This is a re-export only and does not carry runtime behavior.
pub const types = @import("types.zig");
/// Alias of [`types.TraceID`](./types.zig).
/// Represents the 128-bit trace identifier used across span contexts.
/// See `types.zig` for validation and conversion helpers.
pub const TraceID = types.TraceID;
/// Alias of [`types.SpanID`](./types.zig).
/// Represents the 64-bit span identifier used within a trace.
/// See `types.zig` for binary and hex conversion helpers.
pub const SpanID = types.SpanID;
/// Alias of [`types.SpanContext`](./types.zig).
/// Carries trace identity, flags, trace state, and remote-local state.
/// See `types.zig` for initialization and validation behavior.
pub const SpanContext = types.SpanContext;
/// Alias of [`types.SpanKind`](./types.zig).
/// Describes how a span is used, such as server or client work.
/// See `types.zig` for the complete set of kinds.
pub const SpanKind = types.SpanKind;
/// Alias of [`types.Status`](./types.zig).
/// Represents the current span status exposed through the public API.
/// See `types.zig` for the status fields and constructors.
pub const Status = types.Status;
/// Alias of [`types.TraceFlags`](./types.zig).
/// Holds the W3C trace-context flag bits for a span context.
/// See `types.zig` for flag helpers and default behavior.
pub const TraceFlags = types.TraceFlags;
/// Alias of [`types.TraceState`](./types.zig).
/// Stores vendor-specific trace context entries in a fixed-size container.
/// See `types.zig` for entry limits and mutation rules.
pub const TraceState = types.TraceState;
/// Alias of [`types.InstrumentationScope`](./types.zig).
/// Identifies the instrumentation library that produced a span.
/// See `types.zig` for construction and accessor behavior.
pub const InstrumentationScope = types.InstrumentationScope;

// Span
/// Public import of `span.zig`.
/// Use this namespace for span types, constants, and helper methods.
/// This is a re-export only and carries no runtime behavior by itself.
pub const span = @import("span.zig");
/// Alias of [`span.Span`](./span.zig).
/// Use this type for the in-memory span object returned by tracer APIs.
/// See `span.zig` for lifecycle, recording state, and mutation methods.
pub const Span = span.Span;
/// Alias of [`span.AttributeValue`](./span.zig).
/// Encodes supported attribute value kinds in a fixed-size union.
/// See `span.zig` for constructors and string truncation behavior.
pub const AttributeValue = span.AttributeValue;
/// Alias of [`span.Attribute`](./span.zig).
/// Use this type for fixed-size span attributes stored on the span itself.
/// See `span.zig` for the key and value storage rules.
pub const Attribute = span.Attribute;
/// Alias of [`span.Event`](./span.zig).
/// Represents a span event with a fixed-size name buffer and timestamp.
/// See `span.zig` for field details and related helper methods.
pub const Event = span.Event;
/// Alias of [`span.Link`](./span.zig).
/// Use this type when you need to represent a link to another span context.
/// See `span.zig` for the underlying field layout and semantics.
pub const Link = span.Link;

// Tracer
/// Public import of `tracer.zig`.
/// Use this namespace to access tracer creation and span-processing APIs.
/// This is a re-export only; it does not allocate or initialize any state.
pub const tracer = @import("tracer.zig");
/// Alias for `tracer.Tracer`.
/// Creates spans for a specific instrumentation scope and supports root, server, client, and child span creation.
/// Child spans inherit trace context from the parent, and ending a span submits it to the provider's processor when one is configured.
pub const Tracer = tracer.Tracer;
/// Alias for `tracer.TracerProvider`.
/// Factory for `Tracer` instances that owns the ID generator and mutex, and may hold an optional processor view.
/// Use `init()` or `initWithSeed()` to configure randomness; processor teardown is managed externally.
pub const TracerProvider = tracer.TracerProvider;
/// Alias for `tracer.SpanProcessor`.
/// Interface invoked when a span ends and needs to be handed to a processor implementation.
/// `onEnd()` is infallible and passes the span by value; ownership and synchronization stay with the implementation.
pub const SpanProcessor = tracer.SpanProcessor;
/// Alias for `tracer.NoopProcessor`.
/// Processor implementation that drops ended spans and is useful when tracing is disabled.
/// `asSpanProcessor()` returns a borrowed adapter with no allocation and no error path.
pub const NoopProcessor = tracer.NoopProcessor;

// Processor
/// Public namespace import for `serval-otel/processor.zig`.
/// This module contains the processor interfaces and the simple, batching, and console-exporter adapters.
/// It is exposed for callers that need direct access to processor-specific APIs.
pub const processor = @import("processor.zig");
/// Alias for `processor.SimpleProcessor`.
/// Exports each ended span immediately under a mutex, which keeps latency low but increases export overhead.
/// It does not allocate after construction; `shutdown()` only forwards to the wrapped exporter.
pub const SimpleProcessor = processor.SimpleProcessor;
/// Alias for `processor.BatchingProcessor`.
/// Buffers ended spans in a fixed-size queue and exports them periodically or when the batch limit is reached.
/// `init()` allocates and starts a background thread, `shutdown()` flushes and joins before `deinit()`, and spans may be dropped if the queue fills.
pub const BatchingProcessor = processor.BatchingProcessor;
/// Alias for `processor.SpanExporter`.
/// Interface used by exporter backends that receive ended spans from processors.
/// `exportSpans()` may fail; `shutdown()` is infallible and must clean up implementation-specific resources internally.
pub const SpanExporter = processor.SpanExporter;
/// Alias for `processor.ConsoleExporter`.
/// Debug exporter that prints a human-readable span summary through the logging system.
/// Its exporter view borrows `self`, and `shutdown()` is a no-op.
pub const ConsoleExporter = processor.ConsoleExporter;

// Exporter
/// Public namespace import for `serval-otel/exporter.zig`.
/// This module contains the OTLP exporter implementation and its configuration type.
/// It is exposed so callers can use the exporter directly when they do not want the higher-level tracing wrappers.
pub const exporter = @import("exporter.zig");
/// Alias for `exporter.OTLPExporter`.
/// Exports spans to an OTLP collector over HTTP/JSON.
/// Use `init()`/`deinit()` to manage the owned buffers, I/O runtime, DNS resolver, HTTP client, and optional TLS context; initialization can fail for invalid endpoints, TLS setup, or allocation errors.
pub const OTLPExporter = exporter.OTLPExporter;
/// Alias for `exporter.Config`.
/// Configures the OTLP HTTP/JSON exporter, including endpoint, service metadata, and timeout.
/// Field defaults come from `serval-core.config`; the type itself owns no resources.
pub const OTLPConfig = exporter.Config;

// ID Generator
/// Public namespace import for `serval-otel/id_generator.zig`.
/// This module contains the ID generator used to create trace and span identifiers.
/// It is exposed for callers that need direct access to the generator API.
pub const id_generator = @import("id_generator.zig");
/// Alias for `id_generator.RandomIDGenerator`.
/// Generates non-zero TraceID and SpanID values for tracers and adapters.
/// Use `init(seed)` for deterministic tests or `initRandom()` for runtime seeding; callers must synchronize access externally.
pub const RandomIDGenerator = id_generator.RandomIDGenerator;

// Adapter (implements serval-tracing interface)
/// Public namespace import for `serval-otel/adapter.zig`.
/// This module contains the `OtelTracer` bridge that maps `SpanHandle`-based tracing onto OTLP spans.
/// It is a borrowed namespace only; it does not own runtime state.
pub const adapter = @import("adapter.zig");
/// Alias for `adapter.OtelTracer`.
/// Use this to adapt Serval tracing calls onto OTLP spans through the `serval-tracing` interface.
/// Create it with `create()` and release it with `destroy()`; new spans are dropped when the fixed-size pool is exhausted.
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
var global_mutex: std.Io.Mutex = .init;

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
    global_mutex.lockUncancelable(std.Options.debug_io);
    defer global_mutex.unlock(std.Options.debug_io);

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
    global_mutex.lockUncancelable(std.Options.debug_io);
    defer global_mutex.unlock(std.Options.debug_io);

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
    global_mutex.lockUncancelable(std.Options.debug_io);
    defer global_mutex.unlock(std.Options.debug_io);

    if (global_state) |state| {
        return state.tracer_instance.startServerSpan(name);
    }
    return Span.disabled();
}

/// Start a client span (for outgoing requests)
pub fn startClientSpan(name: []const u8) Span {
    global_mutex.lockUncancelable(std.Options.debug_io);
    defer global_mutex.unlock(std.Options.debug_io);

    if (global_state) |state| {
        return state.tracer_instance.startClientSpan(name);
    }
    return Span.disabled();
}

/// Start an internal span
pub fn startSpan(name: []const u8) Span {
    global_mutex.lockUncancelable(std.Options.debug_io);
    defer global_mutex.unlock(std.Options.debug_io);

    if (global_state) |state| {
        return state.tracer_instance.startSpan(name, .Internal);
    }
    return Span.disabled();
}

/// Start a child span from parent
pub fn startChildSpan(parent: *const Span, name: []const u8, kind: SpanKind) Span {
    global_mutex.lockUncancelable(std.Options.debug_io);
    defer global_mutex.unlock(std.Options.debug_io);

    if (global_state) |state| {
        return state.tracer_instance.startChildSpan(parent, name, kind);
    }
    return Span.disabled();
}

/// End a span and submit for export
pub fn endSpan(s: *Span) void {
    global_mutex.lockUncancelable(std.Options.debug_io);
    defer global_mutex.unlock(std.Options.debug_io);

    if (global_state) |state| {
        state.tracer_instance.endSpan(s);
    } else {
        s.end();
    }
}

/// Force flush pending spans
pub fn flush() !void {
    global_mutex.lockUncancelable(std.Options.debug_io);
    defer global_mutex.unlock(std.Options.debug_io);

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
