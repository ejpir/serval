//! Request streaming transform execution (headers/chunk/end) with backpressure bounds.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const sdk = @import("serval-filter-sdk");

pub const StreamError = error{
    BackpressureTimeout,
    EmitFailed,
};

pub const BackpressureController = struct {
    ctx: *anyopaque,
    wait_writable_fn: *const fn (ctx: *anyopaque, timeout_ns: u64) bool,
    max_wait_attempts: u32,
    wait_timeout_ns: u64,

    pub fn waitWritable(self: BackpressureController) StreamError!void {
        assert(@intFromPtr(self.ctx) != 0);
        assert(self.max_wait_attempts > 0);
        assert(self.wait_timeout_ns > 0);

        var attempt: u32 = 0;
        while (attempt < self.max_wait_attempts) : (attempt += 1) {
            if (self.wait_writable_fn(self.ctx, self.wait_timeout_ns)) return;
        }

        return error.BackpressureTimeout;
    }
};

pub const StreamObservation = struct {
    request_headers_calls: u32,
    request_chunk_calls: u32,
    request_end_calls: u32,
    emitted_bytes: u64,

    pub fn init() StreamObservation {
        return .{
            .request_headers_calls = 0,
            .request_chunk_calls = 0,
            .request_end_calls = 0,
            .emitted_bytes = 0,
        };
    }
};

pub fn executeRequestStream(
    comptime Filter: type,
    filter: *Filter,
    filter_ctx: *sdk.FilterContext,
    headers: sdk.HeaderSliceView,
    chunks: []const []const u8,
    emit_writer: *sdk.EmitWriter,
    backpressure: BackpressureController,
    observation: *StreamObservation,
) StreamError!sdk.Decision {
    assert(@intFromPtr(filter) != 0);
    assert(@intFromPtr(filter_ctx) != 0);
    assert(@intFromPtr(emit_writer) != 0);
    assert(@intFromPtr(observation) != 0);
    assert(chunks.len <= config.MAX_STREAM_CHUNK_COUNT);

    const headers_decision = filter.onRequestHeaders(filter_ctx, headers);
    observation.request_headers_calls += 1;
    switch (headers_decision) {
        .continue_filtering, .bypass_plugin => {},
        .reject => |rej| return .{ .reject = rej },
    }

    var chunk_index: usize = 0;
    while (chunk_index < chunks.len) : (chunk_index += 1) {
        try backpressure.waitWritable();

        const is_last = chunk_index + 1 == chunks.len;
        const chunk_view = sdk.ChunkView{ .bytes = chunks[chunk_index], .is_last = is_last };
        const decision = filter.onRequestChunk(filter_ctx, chunk_view, emit_writer);
        observation.request_chunk_calls += 1;

        switch (decision) {
            .continue_filtering, .bypass_plugin => {},
            .reject => |rej| return .{ .reject = rej },
        }
    }

    try backpressure.waitWritable();
    const end_decision = filter.onRequestEnd(filter_ctx, emit_writer);
    observation.request_end_calls += 1;
    switch (end_decision) {
        .continue_filtering, .bypass_plugin => {},
        .reject => |rej| return .{ .reject = rej },
    }

    observation.emitted_bytes = emit_writer.emitted_bytes;
    return .continue_filtering;
}

test "request stream enforces backpressure timeout" {
    const Filter = struct {
        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = self;
            _ = ctx;
            _ = headers;
            return .continue_filtering;
        }

        pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
            _ = self;
            _ = ctx;
            emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "emit" } };
            return .continue_filtering;
        }

        pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
            _ = self;
            _ = ctx;
            _ = emit;
            return .continue_filtering;
        }
    };

    const Sink = struct {
        fn write(ctx: *anyopaque, bytes: []const u8) sdk.EmitError!void {
            _ = ctx;
            _ = bytes;
        }
    };

    const Wait = struct {
        fn wait(ctx: *anyopaque, timeout_ns: u64) bool {
            _ = ctx;
            _ = timeout_ns;
            return false;
        }
    };

    var sink_ctx: u8 = 0;
    var emit = sdk.EmitWriter.init(&sink_ctx, Sink.write, 1024);
    var ctx = sdk.FilterContext{ .route_id = "r", .chain_id = "c", .plugin_id = "p", .request_id = 1, .stream_id = 1 };
    var obs = StreamObservation.init();
    var filter = Filter{};

    try std.testing.expectError(
        error.BackpressureTimeout,
        executeRequestStream(
            Filter,
            &filter,
            &ctx,
            .{ .headers = &[_]@import("serval-core").Header{} },
            &[_][]const u8{"abc"},
            &emit,
            .{ .ctx = &sink_ctx, .wait_writable_fn = Wait.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
            &obs,
        ),
    );
}

test "request stream stress enforces output cap under many chunks" {
    const Filter = struct {
        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = self;
            _ = ctx;
            _ = headers;
            return .continue_filtering;
        }

        pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
            _ = self;
            _ = ctx;
            emit.emit(chunk.bytes) catch {
                return .{ .reject = .{ .status = 413, .reason = "expansion cap" } };
            };
            return .continue_filtering;
        }

        pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
            _ = self;
            _ = ctx;
            _ = emit;
            return .continue_filtering;
        }
    };

    const Sink = struct {
        fn write(ctx: *anyopaque, bytes: []const u8) sdk.EmitError!void {
            _ = ctx;
            _ = bytes;
        }
    };

    const Wait = struct {
        fn wait(ctx: *anyopaque, timeout_ns: u64) bool {
            _ = ctx;
            _ = timeout_ns;
            return true;
        }
    };

    var sink_ctx: u8 = 0;
    var emit = sdk.EmitWriter.init(&sink_ctx, Sink.write, 8);
    var ctx = sdk.FilterContext{ .route_id = "r", .chain_id = "c", .plugin_id = "p", .request_id = 1, .stream_id = 1 };
    var obs = StreamObservation.init();
    var filter = Filter{};

    const chunks = [_][]const u8{ "aa", "bb", "cc", "dd", "ee" };
    const decision = try executeRequestStream(
        Filter,
        &filter,
        &ctx,
        .{ .headers = &[_]@import("serval-core").Header{} },
        chunks[0..],
        &emit,
        .{ .ctx = &sink_ctx, .wait_writable_fn = Wait.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &obs,
    );

    switch (decision) {
        .continue_filtering => return error.TestExpectedEqual,
        .reject => |rej| try std.testing.expectEqual(@as(u16, 413), rej.status),
        .bypass_plugin => return error.TestExpectedEqual,
    }
}

test "request stream lifecycle calls headers/chunk/end and keeps bounded emit" {
    const Filter = struct {
        header_calls: u32 = 0,
        chunk_calls: u32 = 0,
        end_calls: u32 = 0,

        pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
            _ = ctx;
            _ = headers;
            self.header_calls += 1;
            return .continue_filtering;
        }

        pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
            _ = ctx;
            self.chunk_calls += 1;
            emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "emit" } };
            return .continue_filtering;
        }

        pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
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
    var ctx = sdk.FilterContext{ .route_id = "r", .chain_id = "c", .plugin_id = "p", .request_id = 1, .stream_id = 1 };
    var obs = StreamObservation.init();
    var filter = Filter{};

    const result = try executeRequestStream(
        Filter,
        &filter,
        &ctx,
        .{ .headers = &[_]@import("serval-core").Header{} },
        &[_][]const u8{ "ab", "cd", "ef" },
        &emit,
        .{ .ctx = &sink, .wait_writable_fn = Wait.wait, .max_wait_attempts = 2, .wait_timeout_ns = 1 },
        &obs,
    );

    switch (result) {
        .continue_filtering => {},
        .reject => return error.TestExpectedEqual,
        .bypass_plugin => return error.TestExpectedEqual,
    }

    try std.testing.expectEqual(@as(u32, 1), filter.header_calls);
    try std.testing.expectEqual(@as(u32, 3), filter.chunk_calls);
    try std.testing.expectEqual(@as(u32, 1), filter.end_calls);
    try std.testing.expectEqual(@as(u64, 6), sink.total);
    try std.testing.expectEqual(@as(u64, 6), obs.emitted_bytes);
}
