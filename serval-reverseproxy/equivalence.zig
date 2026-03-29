//! DSL/schema canonical IR equivalence harness.

const std = @import("std");
const assert = std.debug.assert;
const dsl = @import("dsl.zig");
const ir = @import("ir.zig");

/// Enumerates the mismatch categories reported by equivalence comparison.
/// The `*_count` variants indicate that the two IRs have different list lengths.
/// The `*_id` variants indicate that the lists have the same length but a different item ID at the reported index.
pub const MismatchReason = enum(u8) {
    listener_count,
    pool_count,
    plugin_count,
    chain_count,
    route_count,
    listener_id,
    pool_id,
    plugin_id,
    chain_id,
    route_id,
};

/// Describes a specific mismatch found during equivalence comparison.
/// `reason` identifies the kind of count or ID difference that was observed.
/// `index` points to the matching element position when the mismatch is element-specific; it is `0` for count mismatches.
pub const Mismatch = struct {
    reason: MismatchReason,
    index: u32,
};

/// Result of an equivalence comparison between two canonical IR values.
/// `equivalent` is `true` when the compared structures match under this module's rules.
/// When `equivalent` is `false`, `mismatch` describes the first observed difference; otherwise it is `null`.
pub const EquivalenceReport = struct {
    equivalent: bool,
    mismatch: ?Mismatch,
};

/// Parses `dsl_source` and compares the resulting canonical IR against `expected`.
/// Returns a DSL parse error if parsing fails, otherwise returns the same equivalence report as `compareCanonical`.
/// `dsl_source` must be non-empty and `expected` must point to a valid canonical IR.
/// The parsed value is used only for the duration of the call; this function does not transfer ownership.
pub fn compareDslToCanonical(dsl_source: []const u8, expected: *const ir.CanonicalIr) dsl.ParseError!EquivalenceReport {
    assert(dsl_source.len > 0);
    assert(@intFromPtr(expected) != 0);

    const parsed = try dsl.parse(dsl_source);
    const actual = parsed.toCanonicalIr();
    return compareCanonical(&actual, expected);
}

/// Compares two canonical IR values for structural equivalence.
/// Returns `.equivalent = false` with a populated `mismatch` on the first count or ID difference.
/// Both pointers must be valid non-null references for the duration of the call.
/// This comparison checks listener, pool, plugin, chain, and route ordering and IDs only.
pub fn compareCanonical(actual: *const ir.CanonicalIr, expected: *const ir.CanonicalIr) EquivalenceReport {
    assert(@intFromPtr(actual) != 0);
    assert(@intFromPtr(expected) != 0);

    if (actual.listeners.len != expected.listeners.len) return .{ .equivalent = false, .mismatch = .{ .reason = .listener_count, .index = 0 } };
    if (actual.pools.len != expected.pools.len) return .{ .equivalent = false, .mismatch = .{ .reason = .pool_count, .index = 0 } };
    if (actual.plugins.len != expected.plugins.len) return .{ .equivalent = false, .mismatch = .{ .reason = .plugin_count, .index = 0 } };
    if (actual.chains.len != expected.chains.len) return .{ .equivalent = false, .mismatch = .{ .reason = .chain_count, .index = 0 } };
    if (actual.routes.len != expected.routes.len) return .{ .equivalent = false, .mismatch = .{ .reason = .route_count, .index = 0 } };

    var index: usize = 0;
    while (index < actual.listeners.len) : (index += 1) {
        if (!std.mem.eql(u8, actual.listeners[index].id, expected.listeners[index].id)) {
            return .{ .equivalent = false, .mismatch = .{ .reason = .listener_id, .index = @intCast(index) } };
        }
    }

    index = 0;
    while (index < actual.pools.len) : (index += 1) {
        if (!std.mem.eql(u8, actual.pools[index].id, expected.pools[index].id)) {
            return .{ .equivalent = false, .mismatch = .{ .reason = .pool_id, .index = @intCast(index) } };
        }
    }

    index = 0;
    while (index < actual.plugins.len) : (index += 1) {
        if (!std.mem.eql(u8, actual.plugins[index].id, expected.plugins[index].id)) {
            return .{ .equivalent = false, .mismatch = .{ .reason = .plugin_id, .index = @intCast(index) } };
        }
    }

    index = 0;
    while (index < actual.chains.len) : (index += 1) {
        if (!std.mem.eql(u8, actual.chains[index].id, expected.chains[index].id)) {
            return .{ .equivalent = false, .mismatch = .{ .reason = .chain_id, .index = @intCast(index) } };
        }
    }

    index = 0;
    while (index < actual.routes.len) : (index += 1) {
        if (!std.mem.eql(u8, actual.routes[index].id, expected.routes[index].id)) {
            return .{ .equivalent = false, .mismatch = .{ .reason = .route_id, .index = @intCast(index) } };
        }
    }

    return .{ .equivalent = true, .mismatch = null };
}

test "equivalence harness reports equivalent dsl and canonical inputs" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const budget = ir.RuntimeBudget{ .max_state_bytes = 1024, .max_output_bytes = 1024 * 1024, .max_expansion_ratio_milli = 2000, .max_cpu_micros_per_chunk = 1000 };
    const entries = [_]ir.ChainEntry{.{ .plugin_id = "plug", .failure_policy = .fail_closed, .budget = budget, .priority = 1, .before = &.{}, .after = &.{} }};
    const expected = ir.CanonicalIr{
        .listeners = &[_]ir.Listener{.{ .id = "l1", .bind = "0.0.0.0:443" }},
        .pools = &[_]ir.Pool{.{ .id = "p1" }},
        .routes = &[_]ir.Route{.{ .id = "r1", .host = "example.com", .path_prefix = "/", .pool_id = "p1", .chain_id = "c1", .disable_plugin_ids = &.{}, .add_plugin_ids = &.{}, .waivers = &.{} }},
        .plugins = &[_]ir.PluginCatalogEntry{.{ .id = "plug", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }},
        .chains = &[_]ir.ChainPlan{.{ .id = "c1", .entries = entries[0..] }},
        .global_plugin_ids = &.{},
    };

    const report = try compareDslToCanonical(source, &expected);
    try std.testing.expect(report.equivalent);
    try std.testing.expect(report.mismatch == null);
}

test "equivalence harness reports mismatch diagnostics" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const expected = ir.CanonicalIr{
        .listeners = &[_]ir.Listener{.{ .id = "different", .bind = "0.0.0.0:443" }},
        .pools = &[_]ir.Pool{.{ .id = "p1" }},
        .routes = &[_]ir.Route{.{ .id = "r1", .host = "example.com", .path_prefix = "/", .pool_id = "p1", .chain_id = "c1", .disable_plugin_ids = &.{}, .add_plugin_ids = &.{}, .waivers = &.{} }},
        .plugins = &[_]ir.PluginCatalogEntry{.{ .id = "plug", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }},
        .chains = &[_]ir.ChainPlan{.{ .id = "c1", .entries = &[_]ir.ChainEntry{.{ .plugin_id = "plug", .failure_policy = .fail_closed, .budget = .{ .max_state_bytes = 1024, .max_output_bytes = 1024 * 1024, .max_expansion_ratio_milli = 2000, .max_cpu_micros_per_chunk = 1000 }, .priority = 1, .before = &.{}, .after = &.{} }} }},
        .global_plugin_ids = &.{},
    };

    const report = try compareDslToCanonical(source, &expected);
    try std.testing.expect(!report.equivalent);
    try std.testing.expect(report.mismatch != null);
    try std.testing.expectEqual(MismatchReason.listener_id, report.mismatch.?.reason);
}
