//! Reverseproxy-owned adapter that can be consumed by server runtime-provider APIs.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const Request = core.Request;
const orchestrator_mod = @import("orchestrator.zig");
const ir = @import("ir.zig");

pub fn RuntimeProviderAdapter(comptime RouteSnapshot: type) type {
    comptime verifyRouteSnapshotType(RouteSnapshot);

    return struct {
        orchestrator: *orchestrator_mod.Orchestrator,

        const Self = @This();

        pub fn init(orchestrator: *orchestrator_mod.Orchestrator) Self {
            assert(@intFromPtr(orchestrator) != 0);
            return .{ .orchestrator = orchestrator };
        }

        pub fn activeGeneration(self: *const Self) ?u64 {
            assert(@intFromPtr(self) != 0);

            const active_snapshot = self.orchestrator.getActiveSnapshot() orelse return null;
            assert(active_snapshot.generation_id > 0);
            return active_snapshot.generation_id;
        }

        pub fn lookupRoute(self: *const Self, request: *const Request) ?RouteSnapshot {
            assert(@intFromPtr(self) != 0);
            assert(@intFromPtr(request) != 0);

            const active_snapshot = self.orchestrator.getActiveSnapshot() orelse return null;
            const host = request.headers.get("Host") orelse return null;

            var best: ?*const ir.Route = null;
            var best_prefix_len: usize = 0;
            var route_index: usize = 0;
            while (route_index < active_snapshot.routes.len) : (route_index += 1) {
                const route = &active_snapshot.routes[route_index];
                if (!std.mem.eql(u8, route.host, host)) continue;
                if (!std.mem.startsWith(u8, request.path, route.path_prefix)) continue;

                if (route.path_prefix.len >= best_prefix_len) {
                    best = route;
                    best_prefix_len = route.path_prefix.len;
                }
            }

            const route = best orelse return null;
            return .{
                .generation_id = active_snapshot.generation_id,
                .route_id = route.id,
                .pool_id = route.pool_id,
                .chain_id = route.chain_id,
            };
        }

        pub fn applyCandidate(
            self: *Self,
            candidate_ir: *const ir.CanonicalIr,
            candidate_snapshot: *const orchestrator_mod.RuntimeSnapshot,
            now_ns: u64,
        ) orchestrator_mod.OrchestratorError!void {
            assert(@intFromPtr(self) != 0);
            assert(@intFromPtr(candidate_ir) != 0);
            assert(@intFromPtr(candidate_snapshot) != 0);
            assert(now_ns > 0);

            try self.orchestrator.admitAndActivate(candidate_ir, candidate_snapshot, now_ns);
            assert(self.orchestrator.getActiveSnapshot() != null);
        }
    };
}

fn verifyRouteSnapshotType(comptime RouteSnapshot: type) void {
    const info = @typeInfo(RouteSnapshot);
    if (info != .@"struct") {
        @compileError("RouteSnapshot must be a struct with generation_id/route_id/pool_id/chain_id fields");
    }

    if (!@hasField(RouteSnapshot, "generation_id") or
        !@hasField(RouteSnapshot, "route_id") or
        !@hasField(RouteSnapshot, "pool_id") or
        !@hasField(RouteSnapshot, "chain_id"))
    {
        @compileError("RouteSnapshot must define fields: generation_id, route_id, pool_id, chain_id");
    }
}

test "adapter routes apply through orchestrator and preserves active generation on admission failure" {
    const Snapshot = struct {
        generation_id: u64,
        route_id: []const u8,
        pool_id: []const u8,
        chain_id: []const u8,
    };

    var orchestrator = orchestrator_mod.Orchestrator.init(1_000_000);
    var adapter = RuntimeProviderAdapter(Snapshot).init(&orchestrator);

    const budget = ir.RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };

    const entries = [_]ir.ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = budget,
        .priority = 10,
        .before = &.{},
        .after = &.{},
    }};
    const chains = [_]ir.ChainPlan{.{ .id = "chain-a", .entries = entries[0..] }};
    const listeners = [_]ir.Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }};
    const pools = [_]ir.Pool{.{ .id = "pool-a" }};
    const plugins = [_]ir.PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }};
    const routes_ok = [_]ir.Route{.{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    }};

    const candidate_ok = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes_ok[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };
    var snapshot_ok = orchestrator_mod.RuntimeSnapshot.fromCanonicalIr(&candidate_ok, 1, 100);
    try adapter.applyCandidate(&candidate_ok, &snapshot_ok, 110);
    try std.testing.expectEqual(@as(?u64, 1), adapter.activeGeneration());

    const routes_bad = [_]ir.Route{.{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "missing-chain",
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    }};
    const candidate_bad = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes_bad[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };
    var snapshot_bad = orchestrator_mod.RuntimeSnapshot.fromCanonicalIr(&candidate_bad, 2, 200);
    try std.testing.expectError(error.MissingChainReference, adapter.applyCandidate(&candidate_bad, &snapshot_bad, 210));
    try std.testing.expectEqual(@as(?u64, 1), adapter.activeGeneration());
}
