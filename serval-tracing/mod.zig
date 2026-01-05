// lib/serval-tracing/mod.zig
//! Serval Tracing - Distributed Tracing Interface
//!
//! Comptime interface for distributed tracing.
//! TigerStyle: Fixed buffers, no allocation.

pub const tracing = @import("tracing.zig");
pub const SpanHandle = tracing.SpanHandle;
pub const NoopTracer = tracing.NoopTracer;
pub const verifyTracer = tracing.verifyTracer;

test {
    _ = @import("tracing.zig");
}
