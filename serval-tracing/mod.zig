// lib/serval-tracing/mod.zig
//! Serval Tracing - Distributed Tracing Interface
//!
//! Comptime interface for distributed tracing.
//! TigerStyle: Fixed buffers, no allocation.

/// Re-exports the `tracing.zig` module as `tracing` from this package.
/// Consumers can access tracing APIs through this namespace instead of importing `tracing.zig` directly.
/// This is a compile-time module binding only; it has no runtime ownership/lifetime effects and no runtime error behavior.
pub const tracing = @import("tracing.zig");
/// Alias of [`tracing.SpanHandle`] re-exported by `serval-tracing`.
/// This introduces no new behavior; semantics, ownership/lifetime rules,
/// and any validity requirements are exactly those of `tracing.SpanHandle`.
/// Constructing/using values follows the underlying type's API; this alias
/// itself performs no allocation and cannot fail.
pub const SpanHandle = tracing.SpanHandle;
/// Alias to `tracing.NoopTracer`, the no-op tracer implementation used by Serval.
/// Use this when an API requires a tracer but tracing should be effectively disabled.
/// Semantics, ownership/lifetime expectations, and error behavior are exactly those of `tracing.NoopTracer`.
pub const NoopTracer = tracing.NoopTracer;
/// Compile-time tracer interface validator re-exported from `tracing.verifyTracer`.
/// Call as `comptime verifyTracer(T)` to assert that `T` declares `startSpan` and `endSpan`.
/// If `setStringAttribute` or `setIntAttribute` are declared, this also validates they are functions with the expected arity.
/// On mismatch it emits `@compileError`; it has no runtime behavior, allocation, or ownership effects.
pub const verifyTracer = tracing.verifyTracer;

test {
    _ = @import("tracing.zig");
}
