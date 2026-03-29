//! Response streaming transform execution and framing planning.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const config = core.config;
const sdk = @import("serval-filter-sdk");
const request_stream = @import("stream_request.zig");

/// Describes how response bytes should be framed on the wire.
/// `h1_content_length` and `h1_chunked` are HTTP/1.1 plans; `h2_data_stream` is used for HTTP/2.
/// Use this to decide whether the response needs a content-length header or chunked transfer encoding.
pub const ResponseFramingPlan = enum(u8) {
    h1_content_length,
    h1_chunked,
    h2_data_stream,
};

/// Chooses the response framing plan for the negotiated HTTP protocol.
/// For HTTP/1.1, transformed responses without a known length use chunked framing; otherwise content length framing is used.
/// For HTTP/2 and HTTP/2 cleartext, the response is always treated as a data stream.
pub fn planResponseFraming(protocol: core.HttpProtocol, transformed: bool, content_length_known: bool) ResponseFramingPlan {
    assert(@intFromEnum(protocol) <= @intFromEnum(core.HttpProtocol.h2));

    return switch (protocol) {
        .h1 => if (transformed and !content_length_known) .h1_chunked else .h1_content_length,
        .h2c, .h2 => .h2_data_stream,
    };
}

/// Returns whether the response should carry an explicit `Content-Length` header.
/// Only the `h1_content_length` framing plan emits a content length.
/// Other framing plans stream without a content-length declaration.
pub fn shouldEmitContentLength(plan: ResponseFramingPlan) bool {
    assert(@intFromEnum(plan) <= @intFromEnum(ResponseFramingPlan.h2_data_stream));
    return plan == .h1_content_length;
}

/// Captures how a response stream was processed during execution.
/// Tracks header, chunk, and end callback counts, plus the total bytes emitted.
/// Call `init()` to obtain a zeroed observation before passing it to stream execution.
pub const ResponseObservation = struct {
    response_headers_calls: u32,
    response_chunk_calls: u32,
    response_end_calls: u32,
    emitted_bytes: u64,

    /// Creates a zero-initialized `ResponseObservation`.
    /// All callback counters and the emitted-byte total start at zero.
    /// Use this before executing a response stream if you need to collect metrics.
    pub fn init() ResponseObservation {
        return .{
            .response_headers_calls = 0,
            .response_chunk_calls = 0,
            .response_end_calls = 0,
            .emitted_bytes = 0,
        };
    }
};

/// Drives a filter through the full response stream lifecycle.
/// Calls `onResponseHeaders`, then each chunk after `waitWritable()`, and finally `onResponseEnd`.
/// Propagates backpressure errors with `try` and returns the first filter rejection unchanged.
/// Updates `observation` with callback counts and the emit writer's final emitted byte total.
pub fn executeResponseStream(
    comptime Filter: type,
    filter: *Filter,
    filter_ctx: *sdk.FilterContext,
    headers: sdk.HeaderSliceView,
    chunks: []const []const u8,
    emit_writer: *sdk.EmitWriter,
    backpressure: request_stream.BackpressureController,
    observation: *ResponseObservation,
) request_stream.StreamError!sdk.Decision {
    assert(@intFromPtr(filter) != 0);
    assert(@intFromPtr(filter_ctx) != 0);
    assert(@intFromPtr(emit_writer) != 0);
    assert(@intFromPtr(observation) != 0);
    assert(chunks.len <= config.MAX_STREAM_CHUNK_COUNT);

    const headers_decision = filter.onResponseHeaders(filter_ctx, headers);
    observation.response_headers_calls += 1;
    switch (headers_decision) {
        .continue_filtering, .bypass_plugin => {},
        .reject => |rej| return .{ .reject = rej },
    }

    var chunk_index: usize = 0;
    while (chunk_index < chunks.len) : (chunk_index += 1) {
        try backpressure.waitWritable();
        const is_last = chunk_index + 1 == chunks.len;
        const chunk_view = sdk.ChunkView{ .bytes = chunks[chunk_index], .is_last = is_last };
        const decision = filter.onResponseChunk(filter_ctx, chunk_view, emit_writer);
        observation.response_chunk_calls += 1;

        switch (decision) {
            .continue_filtering, .bypass_plugin => {},
            .reject => |rej| return .{ .reject = rej },
        }
    }

    try backpressure.waitWritable();
    const end_decision = filter.onResponseEnd(filter_ctx, emit_writer);
    observation.response_end_calls += 1;
    switch (end_decision) {
        .continue_filtering, .bypass_plugin => {},
        .reject => |rej| return .{ .reject = rej },
    }

    observation.emitted_bytes = emit_writer.emitted_bytes;
    return .continue_filtering;
}

test "framing planner uses chunked for transformed h1 unknown length" {
    const plan = planResponseFraming(.h1, true, false);
    try std.testing.expectEqual(ResponseFramingPlan.h1_chunked, plan);
    try std.testing.expect(!shouldEmitContentLength(plan));
}

test "framing planner keeps content-length for h1 known length" {
    const plan = planResponseFraming(.h1, true, true);
    try std.testing.expectEqual(ResponseFramingPlan.h1_content_length, plan);
    try std.testing.expect(shouldEmitContentLength(plan));
}

test "framing planner always uses h2 data stream for h2 protocols" {
    try std.testing.expectEqual(ResponseFramingPlan.h2_data_stream, planResponseFraming(.h2, true, false));
    try std.testing.expectEqual(ResponseFramingPlan.h2_data_stream, planResponseFraming(.h2c, false, true));
}

test "response stream lifecycle executes headers/chunks/end" {
    const Filter = struct {
        header_calls: u32 = 0,
        chunk_calls: u32 = 0,
        end_calls: u32 = 0,

        /// Records that response headers were delivered to this test filter.
        /// The `ctx` and `headers` parameters are accepted for API compatibility and are not used.
        /// Increments the header-call counter and always continues filtering.
        pub fn onResponseHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = ctx;
            _ = headers;
            self.header_calls += 1;
            return .continue_filtering;
        }

        /// Records a response chunk callback and forwards the chunk bytes to the emit writer.
        /// The `ctx` parameter is accepted for API compatibility and is not used.
        /// Returns a 500 rejection with reason `"emit"` if writing the chunk bytes fails.
        pub fn onResponseChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            self.chunk_calls += 1;
            emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "emit" } };
            return .continue_filtering;
        }

        /// Records that the response stream has ended for this test filter.
        /// The `ctx` and `emit` parameters are accepted for API compatibility and are not used.
        /// Increments the end-call counter and always continues filtering.
        pub fn onResponseEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            _ = emit;
            self.end_calls += 1;
            return .continue_filtering;
        }
    };

    const Sink = struct {
        total: u64 = 0,
        fn write(ctx: *anyopaque, bytes: []const u8) sdk.EmitError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.total += bytes.len;
        }
    };

    const Wait = struct {
        fn wait(ctx: *anyopaque, timeout_ns: u64) bool {
            _ = ctx;
            _ = timeout_ns;
            return true;
        }
    };

    var sink = Sink{};
    var emit = sdk.EmitWriter.init(&sink, Sink.write, 6);
    var filter_ctx = sdk.FilterContext{ .route_id = "r", .chain_id = "c", .plugin_id = "p", .request_id = 1, .stream_id = 1 };
    var observation = ResponseObservation.init();
    var filter = Filter{};

    const decision = try executeResponseStream(
        Filter,
        &filter,
        &filter_ctx,
        .{ .headers = &[_]core.Header{} },
        &[_][]const u8{ "ab", "cd", "ef" },
        &emit,
        .{ .ctx = &sink, .wait_writable_fn = Wait.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &observation,
    );

    switch (decision) {
        .continue_filtering => {},
        .reject, .bypass_plugin => return error.TestExpectedEqual,
    }

    try std.testing.expectEqual(@as(u32, 1), filter.header_calls);
    try std.testing.expectEqual(@as(u32, 3), filter.chunk_calls);
    try std.testing.expectEqual(@as(u32, 1), filter.end_calls);
    try std.testing.expectEqual(@as(u64, 6), sink.total);
}
