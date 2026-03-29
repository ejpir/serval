//! serval-filter-sdk - restricted public filter API.

/// Re-exports the public filter SDK type module.
/// It defines the header views, decision types, writer, and context passed to hooks.
/// Prefer this module when importing the SDK's concrete public types.
pub const types = @import("types.zig");
/// Re-exports the compile-time verification module for filter contracts.
/// It contains `verifyFilter`, which checks hook presence and signatures.
/// Import this module when you need direct access to the verifier helpers.
pub const verify = @import("verify.zig");

/// Re-exports the per-request context passed to filter hooks.
/// It carries route, chain, plugin, request, and stream identifiers, plus optional observation callbacks.
/// `setTag` and `incrementCounter` no-op when the runtime does not provide those callbacks.
pub const FilterContext = types.FilterContext;
/// Re-exports a single header name/value pair.
/// Both fields are borrowed slices; the view does not own header storage.
/// Use this for read-only inspection only.
pub const HeaderView = types.HeaderView;
/// Re-exports the read-only header collection view used by header hooks.
/// It provides indexed access into an existing header slice without copying.
/// Use `len()` and `get()` to inspect entries safely.
pub const HeaderSliceView = types.HeaderSliceView;
/// Re-exports the mutable header collection view used by write-capable hooks.
/// The view wraps caller-provided storage and a shared count pointer.
/// Mutations update the backing array in place and reflect through read-only views.
pub const HeaderWriteView = types.HeaderWriteView;
/// Error set returned when mutating a `HeaderWriteView`.
/// `TooManyHeaders` indicates the backing storage is full and a new header could not be appended.
/// Existing headers may still be updated in place without raising this error.
pub const HeaderWriteError = types.HeaderWriteError;
/// Re-exports the read-only chunk view passed to request and response chunk hooks.
/// `bytes` references the current body chunk and `is_last` marks the final chunk.
/// The view borrows runtime-owned data and should only be used during the hook call.
pub const ChunkView = types.ChunkView;
/// Re-exports the response-body emission writer used by filter hooks.
/// Initialize it with a non-null sink context, a write callback, and a positive budget.
/// Each successful `emit` call advances the emitted-byte count and enforces `max_bytes`.
pub const EmitWriter = types.EmitWriter;
/// Error set returned by `EmitWriter.emit`.
/// `OutputLimitExceeded` means the write would exceed the configured budget.
/// `WriteFailed` means the sink's write callback returned an error.
pub const EmitError = types.EmitError;
/// Re-exports the hook return type used to control filter flow.
/// `continue_filtering` keeps processing, `reject` stops with a response,
/// and `bypass_plugin` skips the plugin for the current event.
pub const Decision = types.Decision;
/// Re-exports `core.RejectResponse` for filter rejection responses.
/// Use this type when returning `.reject` from `Decision`.
/// Refer to `serval-core` for the exact fields and lifetime rules.
pub const RejectResponse = types.RejectResponse;

/// Re-exports the compile-time filter contract verifier from `verify.zig`.
/// Use it to validate that a filter type exposes supported hook signatures.
/// The verifier rejects types that implement no hooks or that mismatch parameters or return types.
pub const verifyFilter = verify.verifyFilter;

test {
    _ = types;
    _ = verify;
}

test "author example filter compiles against sdk boundary" {
    const ExampleFilter = struct {
        /// Tags the request with `plugin=example` and continues filtering.
        /// The `headers` view is accepted to satisfy the hook contract, but this
        /// implementation does not inspect or mutate it.
        pub fn onRequestHeaders(self: *@This(), ctx: *FilterContext, headers: HeaderSliceView) Decision {
            _ = self;
            _ = headers;
            ctx.setTag("plugin", "example");
            return .continue_filtering;
        }

        /// Handles one response body chunk by incrementing the `response_chunk` counter.
        /// Forwards `chunk.bytes` to `emit`; if emission fails, returns a 500 reject.
        /// The `self` receiver is unused by this implementation.
        pub fn onResponseChunk(self: *@This(), ctx: *FilterContext, chunk: ChunkView, emit: *EmitWriter) Decision {
            _ = self;
            ctx.incrementCounter("response_chunk", 1);
            emit.emit(chunk.bytes) catch {
                return .{ .reject = .{ .status = 500, .reason = "emit failed" } };
            };
            return .continue_filtering;
        }
    };

    comptime verifyFilter(ExampleFilter);
    try @import("std").testing.expect(true);
}
