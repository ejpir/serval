# serval-otel

Minimal OpenTelemetry tracing implementation for Serval. Extracted from zig-o11y SDK (~1,500 lines → ~800 lines).

## Purpose

Provides distributed tracing with OTLP export, optimized for high-performance proxying:
- Fixed-size spans (no allocation in hot path)
- OTLP/JSON export over HTTP
- Background batching for efficient export

## Exports

```zig
const otel = @import("serval-otel");

// Core types
otel.TraceID          // 128-bit trace identifier
otel.SpanID           // 64-bit span identifier
otel.SpanContext      // Immutable context propagated across boundaries
otel.SpanKind         // Internal, Server, Client, Producer, Consumer
otel.Status           // Unset, Ok, Error with description
otel.TraceFlags       // W3C Trace Context flags
otel.InstrumentationScope  // Library name and version

// Span (fixed-size, zero-allocation)
otel.Span             // Main tracing unit with attributes, events, links
otel.AttributeValue   // bool, int, double, string (fixed-size buffer)

// Tracer
otel.Tracer           // Creates spans for a scope
otel.TracerProvider   // Factory for tracers

// Processors
otel.SimpleProcessor     // Export immediately (debugging)
otel.BatchingProcessor   // Batch export (production)

// Exporters
otel.OTLPExporter     // OTLP/JSON over HTTP
otel.ConsoleExporter  // Print to stderr (debugging)

// Global API (convenience)
otel.init(allocator, config)  // Initialize global tracing
otel.deinit()                  // Shutdown
otel.startServerSpan(name)     // Start server span
otel.startClientSpan(name)     // Start client span
otel.startChildSpan(parent, name, kind)  // Start child span
otel.endSpan(span)             // End and export span
```

## Usage

### Basic Usage (Global API)

```zig
const otel = @import("serval-otel");

pub fn main() !void {
    // Initialize with OTLP exporter
    try otel.init(allocator, .{
        .endpoint = "http://localhost:4318/v1/traces",
        .service_name = "my-proxy",
    });
    defer otel.deinit();

    // Create spans
    var span = otel.startServerSpan("handle-request");
    defer otel.endSpan(&span);

    span.setStringAttribute("http.method", "GET");
    span.setIntAttribute("http.status_code", 200);

    // Child span for downstream call
    var child = otel.startChildSpan(&span, "upstream-request", .Client);
    defer otel.endSpan(&child);
}
```

### Manual Setup (Custom Processor)

```zig
const otel = @import("serval-otel");

// Create exporter
var exporter = try otel.OTLPExporter.init(allocator, .{
    .endpoint = "http://collector:4318/v1/traces",
    .service_name = "my-service",
});

// Create batching processor
var processor = try otel.BatchingProcessor.init(
    allocator,
    exporter.asSpanExporter(),
    .{ .max_export_batch_size = 512, .scheduled_delay_ms = 5000 },
);

// Create provider and tracer
var provider = otel.TracerProvider.init(processor.asSpanProcessor());
var tracer = provider.getTracer("my-lib", "1.0.0");

// Create spans
var span = tracer.startServerSpan("operation");
span.setStringAttribute("key", "value");
tracer.endSpan(&span);

// Shutdown
processor.shutdown();
processor.deinit();
exporter.deinit();
```

## Fixed-Size Limits

| Limit | Value | Description |
|-------|-------|-------------|
| `MAX_ATTRIBUTES` | 32 | Max attributes per span |
| `MAX_EVENTS` | 8 | Max events per span |
| `MAX_LINKS` | 4 | Max links per span |
| `MAX_KEY_LEN` | 64 | Max attribute key length |
| `MAX_NAME_LEN` | 128 | Max span name length |
| `MAX_STRING_VALUE_LEN` | 256 | Max string attribute value |
| `MAX_QUEUE_SIZE` | 2048 | Max spans in batch queue |

## TigerStyle Compliance

| Requirement | Implementation |
|-------------|----------------|
| No runtime alloc after init | Fixed-size Span struct, pre-allocated queue |
| ~2 assertions per function | Bounds checks on name/key lengths |
| Bounded loops | MAX_ATTRIBUTES, MAX_QUEUE_SIZE limits |
| Explicit types | u32 for counts, u64 for timestamps |
| Units in names | `_ns` suffix for nanoseconds, `_ms` for milliseconds |

## Architecture

```
lib/serval-otel/
├── mod.zig           # Public API, global state
├── types.zig         # TraceID, SpanID, SpanContext, etc.
├── span.zig          # Fixed-size Span struct
├── tracer.zig        # Tracer, TracerProvider
├── processor.zig     # Simple/Batching processors
├── exporter.zig      # OTLP HTTP/JSON export
├── id_generator.zig  # Random TraceID/SpanID generation
├── time.zig          # Nanosecond timestamps
└── README.md
```

## Implementation Status

- [x] Core types (TraceID, SpanID, SpanContext)
- [x] Fixed-size Span with attributes, events
- [x] RandomIDGenerator
- [x] Tracer and TracerProvider
- [x] SimpleProcessor (immediate export)
- [x] BatchingProcessor (background batching)
- [x] OTLP/JSON exporter
- [x] Global convenience API
- [ ] W3C TraceContext propagation (traceparent header)
- [ ] OTLP/Protobuf exporter (smaller payloads)
- [ ] Sampling strategies

## Testing

```bash
zig build test-otel
```
