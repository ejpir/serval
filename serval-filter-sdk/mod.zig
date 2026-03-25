//! serval-filter-sdk - restricted public filter API.

pub const types = @import("types.zig");
pub const verify = @import("verify.zig");

pub const FilterContext = types.FilterContext;
pub const HeaderView = types.HeaderView;
pub const HeaderSliceView = types.HeaderSliceView;
pub const ChunkView = types.ChunkView;
pub const EmitWriter = types.EmitWriter;
pub const EmitError = types.EmitError;
pub const Decision = types.Decision;
pub const RejectResponse = types.RejectResponse;

pub const verifyFilter = verify.verifyFilter;

test {
    _ = types;
    _ = verify;
}

test "author example filter compiles against sdk boundary" {
    const ExampleFilter = struct {
        pub fn onRequestHeaders(self: *@This(), ctx: *FilterContext, headers: HeaderSliceView) Decision {
            _ = self;
            _ = headers;
            ctx.setTag("plugin", "example");
            return .continue_filtering;
        }

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
