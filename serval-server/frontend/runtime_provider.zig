//! Optional runtime-provider interface for server orchestration integration.
//!
//! Keeps `serval-server` reusable as a standalone module while allowing
//! external orchestrators to provide generation-aware route snapshots.

const std = @import("std");
const assert = std.debug.assert;
const Request = @import("serval-core").Request;

pub const RouteSnapshot = struct {
    generation_id: u64,
    route_id: []const u8,
    pool_id: []const u8,
    chain_id: []const u8,
};

pub const RuntimeProvider = struct {
    ptr: *const anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        activeGenerationFn: *const fn (ptr: *const anyopaque) ?u64,
        lookupRouteFn: *const fn (ptr: *const anyopaque, request: *const Request) ?RouteSnapshot,
    };

    pub fn activeGeneration(self: RuntimeProvider) ?u64 {
        assert(@intFromPtr(self.ptr) != 0);
        const generation = self.vtable.activeGenerationFn(self.ptr);
        if (generation) |value| {
            assert(value > 0);
        }
        return generation;
    }

    pub fn lookupRoute(self: RuntimeProvider, request: *const Request) ?RouteSnapshot {
        assert(@intFromPtr(self.ptr) != 0);
        assert(@intFromPtr(request) != 0);

        const snapshot = self.vtable.lookupRouteFn(self.ptr, request);
        if (snapshot) |value| {
            assert(value.generation_id > 0);
            assert(value.route_id.len > 0);
            assert(value.pool_id.len > 0);
            assert(value.chain_id.len > 0);
        }
        return snapshot;
    }
};

pub fn verifyRuntimeProvider(comptime Provider: type) void {
    verifyActiveGeneration(Provider);
    verifyLookupRoute(Provider);
}

pub fn fromProvider(provider: anytype) RuntimeProvider {
    const Provider = @TypeOf(provider.*);
    verifyRuntimeProvider(Provider);

    const Adapter = struct {
        fn activeGeneration(ptr: *const anyopaque) ?u64 {
            const typed: *const Provider = @ptrCast(@alignCast(ptr));
            return typed.activeGeneration();
        }

        fn lookupRoute(ptr: *const anyopaque, request: *const Request) ?RouteSnapshot {
            const typed: *const Provider = @ptrCast(@alignCast(ptr));
            return typed.lookupRoute(request);
        }

        const vtable = RuntimeProvider.VTable{
            .activeGenerationFn = activeGeneration,
            .lookupRouteFn = lookupRoute,
        };
    };

    return .{
        .ptr = provider,
        .vtable = &Adapter.vtable,
    };
}

fn verifyActiveGeneration(comptime Provider: type) void {
    if (!@hasDecl(Provider, "activeGeneration")) {
        @compileError("Runtime provider must implement: pub fn activeGeneration(self: *const Provider) ?u64");
    }

    const FnType = @TypeOf(@field(Provider, "activeGeneration"));
    const fn_info = switch (@typeInfo(FnType)) {
        .@"fn" => |info| info,
        else => @compileError("activeGeneration must be a function"),
    };

    if (fn_info.params.len != 1 or fn_info.params[0].type != *const Provider) {
        @compileError("activeGeneration signature must be: pub fn activeGeneration(self: *const Provider) ?u64");
    }
    if (fn_info.return_type != ?u64) {
        @compileError("activeGeneration must return ?u64");
    }
}

fn verifyLookupRoute(comptime Provider: type) void {
    if (!@hasDecl(Provider, "lookupRoute")) {
        @compileError("Runtime provider must implement: pub fn lookupRoute(self: *const Provider, request: *const Request) ?RouteSnapshot");
    }

    const FnType = @TypeOf(@field(Provider, "lookupRoute"));
    const fn_info = switch (@typeInfo(FnType)) {
        .@"fn" => |info| info,
        else => @compileError("lookupRoute must be a function"),
    };

    if (fn_info.params.len != 2 or fn_info.params[0].type != *const Provider or fn_info.params[1].type != *const Request) {
        @compileError("lookupRoute signature must be: pub fn lookupRoute(self: *const Provider, request: *const Request) ?RouteSnapshot");
    }
    if (fn_info.return_type != ?RouteSnapshot) {
        @compileError("lookupRoute must return ?RouteSnapshot");
    }
}

test "runtime provider adapter forwards generation and route lookup" {
    const Provider = struct {
        generation_id: u64,

        pub fn activeGeneration(self: *const @This()) ?u64 {
            assert(self.generation_id > 0);
            return self.generation_id;
        }

        pub fn lookupRoute(self: *const @This(), request: *const Request) ?RouteSnapshot {
            _ = request;
            assert(self.generation_id > 0);
            return .{
                .generation_id = self.generation_id,
                .route_id = "route-a",
                .pool_id = "pool-a",
                .chain_id = "chain-a",
            };
        }
    };

    const req = Request{ .method = .GET, .path = "/", .version = .http1_1, .headers = .{}, .body = "" };
    const provider = Provider{ .generation_id = 42 };
    const runtime_provider = fromProvider(&provider);

    try std.testing.expectEqual(@as(?u64, 42), runtime_provider.activeGeneration());
    const route = runtime_provider.lookupRoute(&req) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(u64, 42), route.generation_id);
    try std.testing.expectEqualStrings("route-a", route.route_id);
}
