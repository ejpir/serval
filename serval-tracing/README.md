# serval-tracing

Distributed tracing interface with zero-overhead noop implementation.

## Purpose

Provides compile-time pluggable distributed tracing. Supports OpenTelemetry-style spans with trace propagation context.

## Exports

- `SpanHandle` - Trace context (trace_id, span_id, parent)
- `NoopTracer` - Zero-overhead, compiles away
- `verifyTracer` - Compile-time interface verification

## Usage

```zig
const tracing_mod = @import("serval-tracing");

// Zero overhead
var tracer = tracing_mod.NoopTracer{};

const span = tracer.startSpan("handle_request", null);
defer tracer.endSpan(span, null);

// Nested span
const child = tracer.startSpan("forward_upstream", span);
defer tracer.endSpan(child, null);
```

## Tracer Interface

Any tracer implementation must provide:

```zig
pub fn startSpan(self, name: []const u8, parent: ?SpanHandle) SpanHandle
pub fn endSpan(self, handle: SpanHandle, err: ?[]const u8) void
```

Optional attributes:
- `setStringAttribute(handle, key, value)`
- `setIntAttribute(handle, key, value)`

## SpanHandle

```zig
pub const SpanHandle = struct {
    trace_id: u128 = 0,
    span_id: u64 = 0,
    parent_span_id: u64 = 0,

    pub fn isValid(self: SpanHandle) bool {
        return self.trace_id != 0;
    }
};
```

## Implementation Status

| Feature | Status |
|---------|--------|
| NoopTracer | Complete |
| SpanHandle | Complete |
| Interface verification | Complete |
| OTLP Tracer | Not implemented |
| W3C Trace Context propagation | Not implemented |
| Sampling | Not implemented |

## TigerStyle Compliance

- Fixed-size SpanHandle (u128 + u64 + u64)
- Zero allocation in NoopTracer
- Compile-time interface verification
