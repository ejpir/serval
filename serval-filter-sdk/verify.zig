//! Compile-time filter contract verification.

const std = @import("std");
const types = @import("types.zig");

const FilterContext = types.FilterContext;
const HeaderSliceView = types.HeaderSliceView;
const HeaderWriteView = types.HeaderWriteView;
const ChunkView = types.ChunkView;
const EmitWriter = types.EmitWriter;
const Decision = types.Decision;

pub fn verifyFilter(comptime Filter: type) void {
    var implemented_hooks: u8 = 0;

    verifyOptional(Filter, "onRequestHeaders", &[_]type{ *Filter, *FilterContext, HeaderSliceView }, Decision, &implemented_hooks);
    verifyOptional(Filter, "onRequestHeadersWrite", &[_]type{ *Filter, *FilterContext, HeaderWriteView }, Decision, &implemented_hooks);
    verifyOptional(Filter, "onRequestChunk", &[_]type{ *Filter, *FilterContext, ChunkView, *EmitWriter }, Decision, &implemented_hooks);
    verifyOptional(Filter, "onRequestEnd", &[_]type{ *Filter, *FilterContext, *EmitWriter }, Decision, &implemented_hooks);
    verifyOptional(Filter, "onResponseHeaders", &[_]type{ *Filter, *FilterContext, HeaderSliceView }, Decision, &implemented_hooks);
    verifyOptional(Filter, "onResponseHeadersWrite", &[_]type{ *Filter, *FilterContext, HeaderWriteView }, Decision, &implemented_hooks);
    verifyOptional(Filter, "onResponseChunk", &[_]type{ *Filter, *FilterContext, ChunkView, *EmitWriter }, Decision, &implemented_hooks);
    verifyOptional(Filter, "onResponseEnd", &[_]type{ *Filter, *FilterContext, *EmitWriter }, Decision, &implemented_hooks);

    if (implemented_hooks == 0) {
        @compileError("Filter must implement at least one hook (request/response headers/chunk/end)");
    }
}

fn verifyOptional(
    comptime Filter: type,
    comptime hook_name: []const u8,
    comptime expected_params: []const type,
    comptime expected_return: type,
    implemented_hooks: *u8,
) void {
    if (!@hasDecl(Filter, hook_name)) return;

    implemented_hooks.* += 1;

    const Hook = @TypeOf(@field(Filter, hook_name));
    const info = @typeInfo(Hook);
    if (info != .@"fn") {
        @compileError(hook_name ++ " must be a function");
    }

    const fn_info = info.@"fn";
    if (fn_info.return_type != expected_return) {
        @compileError(hook_name ++ " must return " ++ @typeName(expected_return));
    }
    if (fn_info.params.len != expected_params.len) {
        @compileError(hook_name ++ " has incorrect parameter count");
    }

    inline for (expected_params, 0..) |expected, idx| {
        if (fn_info.params[idx].type != expected) {
            @compileError(hook_name ++ " parameter " ++ std.fmt.comptimePrint("{d}", .{idx}) ++ " must be " ++ @typeName(expected));
        }
    }
}

test "verifyFilter accepts well-typed filter" {
    const GoodFilter = struct {
        pub fn onRequestHeaders(self: *@This(), ctx: *FilterContext, headers: HeaderSliceView) Decision {
            _ = self;
            _ = ctx;
            _ = headers;
            return .continue_filtering;
        }
    };

    comptime verifyFilter(GoodFilter);
    try std.testing.expect(true);
}
