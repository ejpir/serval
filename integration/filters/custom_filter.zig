//! Reusable integration-test filter implementations.

const std = @import("std");
const assert = std.debug.assert;
const serval = @import("serval");
const sdk = serval.filter_sdk;

pub const HookLifecycleFilter = struct {
    request_headers: u32 = 0,
    request_chunks: u32 = 0,
    request_end: u32 = 0,
    response_headers: u32 = 0,
    response_chunks: u32 = 0,
    response_end: u32 = 0,

    pub fn onRequestHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(ctx) != 0);
        _ = headers;
        self.request_headers += 1;
        ctx.incrementCounter("req_headers", 1);
        return .continue_filtering;
    }

    pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(emit) != 0);
        _ = ctx;
        self.request_chunks += 1;
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "request emit failed" } };
        return .continue_filtering;
    }

    pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(emit) != 0);
        _ = ctx;
        self.request_end += 1;
        return .continue_filtering;
    }

    pub fn onResponseHeaders(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderSliceView) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(ctx) != 0);
        _ = headers;
        self.response_headers += 1;
        ctx.setTag("phase", "response");
        return .continue_filtering;
    }

    pub fn onResponseChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(emit) != 0);
        _ = ctx;
        self.response_chunks += 1;
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "response emit failed" } };
        return .continue_filtering;
    }

    pub fn onResponseEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(emit) != 0);
        _ = ctx;
        self.response_end += 1;
        return .continue_filtering;
    }
};

pub const Observer = struct {
    tags: u32 = 0,
    counters: u32 = 0,

    pub fn setTag(ctx: *anyopaque, key: []const u8, value: []const u8) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        assert(@intFromPtr(self) != 0);
        _ = key;
        _ = value;
        self.tags += 1;
    }

    pub fn incrCounter(ctx: *anyopaque, key: []const u8, delta: u64) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        assert(@intFromPtr(self) != 0);
        assert(delta > 0);
        _ = key;
        self.counters += 1;
    }
};

pub const BodyTransformFilter = struct {
    pub fn onRequestHeadersWrite(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
        _ = self;
        _ = ctx;
        var writable = headers;
        writable.upsert("x-request-filter", "enabled") catch return .{ .reject = .{ .status = 500, .reason = "request header write failed" } };
        return .continue_filtering;
    }

    pub fn onRequestChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit("REQ:") catch return .{ .reject = .{ .status = 500, .reason = "request prefix emit failed" } };
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "request body emit failed" } };
        return .continue_filtering;
    }

    pub fn onRequestEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit(";") catch return .{ .reject = .{ .status = 500, .reason = "request end emit failed" } };
        return .continue_filtering;
    }

    pub fn onResponseHeadersWrite(self: *@This(), ctx: *sdk.FilterContext, headers: sdk.HeaderWriteView) sdk.Decision {
        _ = self;
        _ = ctx;
        var writable = headers;
        writable.upsert("x-response-filter", "enabled") catch return .{ .reject = .{ .status = 500, .reason = "response header write failed" } };
        return .continue_filtering;
    }

    pub fn onResponseChunk(self: *@This(), ctx: *sdk.FilterContext, chunk: sdk.ChunkView, emit: *sdk.EmitWriter) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit("RES:") catch return .{ .reject = .{ .status = 500, .reason = "response prefix emit failed" } };
        emit.emit(chunk.bytes) catch return .{ .reject = .{ .status = 500, .reason = "response body emit failed" } };
        return .continue_filtering;
    }

    pub fn onResponseEnd(self: *@This(), ctx: *sdk.FilterContext, emit: *sdk.EmitWriter) sdk.Decision {
        _ = self;
        _ = ctx;
        emit.emit(";") catch return .{ .reject = .{ .status = 500, .reason = "response end emit failed" } };
        return .continue_filtering;
    }
};

pub const CaptureSink = struct {
    storage: [128]u8 = undefined,
    len: u32 = 0,

    pub fn write(ctx: *anyopaque, out: []const u8) sdk.EmitError!void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        assert(@intFromPtr(self) != 0);

        const start: usize = @intCast(self.len);
        const end = start + out.len;
        if (end > self.storage.len) return error.WriteFailed;
        @memcpy(self.storage[start..end], out);
        self.len = @intCast(end);
    }

    pub fn bytes(self: *const @This()) []const u8 {
        assert(@intFromPtr(self) != 0);
        return self.storage[0..self.len];
    }
};

pub const AlwaysWritable = struct {
    pub fn wait(ctx: *anyopaque, timeout_ns: u64) bool {
        _ = ctx;
        _ = timeout_ns;
        return true;
    }
};
