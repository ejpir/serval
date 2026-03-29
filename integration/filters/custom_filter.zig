//! Reusable integration-test filter implementations.

const std = @import("std");
const assert = std.debug.assert;
const serval = @import("serval");
const sdk = serval.filter_sdk;

/// Stateful filter implementation that tracks how many times each lifecycle hook runs.
/// Request and response callbacks update the counters stored on the struct and may also
/// mutate the provided filter context. Chunk handlers forward bytes through the emit
/// writer and reject with HTTP 500 if emission fails.
pub const HookLifecycleFilter = struct {
    request_headers: u32 = 0,
    request_chunks: u32 = 0,
    request_end: u32 = 0,
    response_headers: u32 = 0,
    response_chunks: u32 = 0,
    response_end: u32 = 0,

    /// Records a request header callback and increments the request header counter.
    /// Updates the filter context counter `req_headers` by 1, then continues filtering.
    /// The `headers` view is observed for API compatibility only and is not retained after
    /// the call.
    pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(ctx) != 0);
        _ = headers;
        self.request_headers += 1;
        ctx.incrementCounter("req_headers", 1);
        return .continue_filtering;
    }

    /// Records a request body chunk and forwards the chunk bytes to the emit writer.
    /// Increments `request_chunks` before emitting. If emission fails, the hook rejects the
    /// request with HTTP 500 and reason `"request emit failed"`. `ctx` is accepted for API
    /// compatibility and is not otherwise used.
    pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(emit) != 0);
        _ = ctx;
        self.request_chunks += 1;
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "request emit failed" } };
        return .continue_filtering;
    }

    /// Records that request processing has reached the end of the request body.
    /// Increments `request_end` and then continues filtering. `ctx` and `emit` are accepted
    /// for API compatibility, but this implementation does not read from them.
    /// This hook does not emit data or reject on its own.
    pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(emit) != 0);
        _ = ctx;
        self.request_end += 1;
        return .continue_filtering;
    }

    /// Records a response header callback and marks the current phase in the filter context.
    /// Increments `response_headers` and sets the context tag `phase=response`. The `headers`
    /// view is observed for API compatibility only and is not retained after the call.
    /// Returns `.continue_filtering` after updating local state and context.
    pub fn onResponseHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(ctx) != 0);
        _ = headers;
        self.response_headers += 1;
        ctx.setTag("phase", "response");
        return .continue_filtering;
    }

    /// Records a response body chunk and forwards the chunk bytes to the emit writer.
    /// Increments `response_chunks` before emitting. If emission fails, the hook rejects the
    /// request with HTTP 500 and reason `"response emit failed"`. `ctx` is accepted for API
    /// compatibility and is not otherwise used.
    pub fn onResponseChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(emit) != 0);
        _ = ctx;
        self.response_chunks += 1;
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "response emit failed" } };
        return .continue_filtering;
    }

    /// Records a response-end event by incrementing `response_end`.
    /// The context is ignored, and `emit` is only validated for a non-null pointer.
    /// Returns `.continue_filtering` without emitting additional output or reporting an error.
    pub fn onResponseEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(emit) != 0);
        _ = ctx;
        self.response_end += 1;
        return .continue_filtering;
    }
};

/// In-memory observer that tracks tag and counter events.
/// `setTag` and `incrCounter` accept opaque callback contexts and update the stored tallies directly.
/// The callbacks ignore the supplied key/value data, and `incrCounter` requires `delta > 0`.
pub const Observer = struct {
    tags: u32 = 0,
    counters: u32 = 0,

    /// Records one tag event against the opaque context pointer.
    /// The context must identify a valid receiver.
    /// The key and value are ignored and the tag tally is incremented on the receiver.
    pub fn setTag(ctx: *anyopaque, key: []const u8, value: []const u8) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        assert(@intFromPtr(self) != 0);
        _ = key;
        _ = value;
        self.tags += 1;
    }

    /// Records one counter event against the opaque context pointer.
    /// The context must identify a valid receiver, and `delta` must be greater than zero.
    /// The key is ignored and the counter tally is incremented on the receiver.
    pub fn incrCounter(ctx: *anyopaque, key: []const u8, delta: u64) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        assert(@intFromPtr(self) != 0);
        assert(delta > 0);
        _ = key;
        self.counters += 1;
    }
};

/// Filter that applies simple request and response body/header transforms.
/// Request chunks are prefixed with `REQ:`, response chunks with `RES:`, and both streams are terminated with `;`.
/// Header writes add `x-request-filter: enabled` or `x-response-filter: enabled`; any emit or header update failure rejects with status `500`.
pub const BodyTransformFilter = struct {
    /// Writes the `x-request-filter: enabled` header to the request headers view.
    /// The header view must support mutation through `upsert`.
    /// If the write fails, the filter rejects with status `500` and reason `request header write failed`.
    pub fn onRequestHeadersWrite(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
        _ = self;
        _ = ctx;
        var writable = headers;
        writable.upsert("x-request-filter", "enabled") catch return .{ .reject = .{ .status = 500, .reason = "request header write failed" } };
        return .continue_filtering;
    }

    /// Prefixes each request chunk with `REQ:` and forwards the chunk bytes.
    /// Any emit failure rejects the request with status `500` and the matching error reason.
    /// On success, filtering continues without altering the chunk contents.
    pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit("REQ:") catch return .{ .reject = .{ .status = 500, .reason = "request prefix emit failed" } };
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "request body emit failed" } };
        return .continue_filtering;
    }

    /// Emits the request terminator marker `;`.
    /// If emission fails, the filter rejects the request with status `500` and reason `request end emit failed`.
    /// On success, filtering continues.
    pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit(";") catch return .{ .reject = .{ .status = 500, .reason = "request end emit failed" } };
        return .continue_filtering;
    }

    /// Writes the `x-response-filter: enabled` header to the response headers view.
    /// The header view must support mutation through `upsert`.
    /// If the write fails, the filter rejects with status `500` and reason `response header write failed`.
    pub fn onResponseHeadersWrite(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
        _ = self;
        _ = ctx;
        var writable = headers;
        writable.upsert("x-response-filter", "enabled") catch return .{ .reject = .{ .status = 500, .reason = "response header write failed" } };
        return .continue_filtering;
    }

    /// Prefixes each response chunk with `RES:` and forwards the chunk bytes.
    /// Any emit failure rejects the response with status `500` and the matching error reason.
    /// On success, filtering continues without altering the chunk contents.
    pub fn onResponseChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit("RES:") catch return .{ .reject = .{ .status = 500, .reason = "response prefix emit failed" } };
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "response body emit failed" } };
        return .continue_filtering;
    }

    /// Emits the response terminator marker `;`.
    /// If emission fails, the filter rejects the response with status `500` and reason `response end emit failed`.
    /// On success, filtering continues.
    pub fn onResponseEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit(";") catch return .{ .reject = .{ .status = 500, .reason = "response end emit failed" } };
        return .continue_filtering;
    }
};

/// Fixed-size byte sink used to capture emitted output in memory.
/// `write` appends bytes until the buffer fills, and `bytes` exposes the initialized prefix.
/// The stored slice aliases the struct and must not outlive it.
pub const CaptureSink = struct {
    storage: [128]u8 = undefined,
    len: u32 = 0,

    /// Appends `out` to the sink buffer through the opaque context pointer.
    /// The context must identify a valid `CaptureSink` instance.
    /// Returns `error.WriteFailed` if the fixed buffer does not have enough remaining space; otherwise it updates `len` atomically for the successful write.
    pub fn write(ctx: *anyopaque, out: []const u8) sdk.EmitError!void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        assert(@intFromPtr(self) != 0);

        const start: usize = @intCast(self.len);
        const end = start + out.len;
        if (end > self.storage.len) return error.WriteFailed;
        @memcpy(self.storage[start..end], out);
        self.len = @intCast(end);
    }

    /// Returns the initialized bytes currently stored in the receiver.
    /// The returned slice aliases `self.storage` and is valid only while the receiver lives.
    /// No allocation or copying occurs.
    pub fn bytes(self: *const @This()) []const u8 {
        assert(@intFromPtr(self) != 0);
        return self.storage[0..self.len];
    }
};

/// Helper type whose wait callback always succeeds immediately.
/// This is useful for tests that need a writable or ready signal without delay.
/// The public `wait` entry point ignores its inputs and returns `true`.
pub const AlwaysWritable = struct {
    /// Reports the sink as immediately ready.
    /// The context pointer and timeout value are ignored.
    /// Always returns `true` and never signals failure.
    pub fn wait(ctx: *anyopaque, timeout_ns: u64) bool {
        _ = ctx;
        _ = timeout_ns;
        return true;
    }
};
