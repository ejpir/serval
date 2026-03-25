//! Global + route plugin composition with mandatory/waiver enforcement.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const ir = @import("ir.zig");

pub const MAX_EFFECTIVE_PLUGINS: usize = config.MAX_ROUTES;

pub const CompositionError = error{
    TooManyEffectivePlugins,
    MissingGlobalPlugin,
    MissingRouteAddPlugin,
    MissingRouteDisablePlugin,
    MandatoryPluginDisableRejected,
    MissingRequiredWaiver,
};

pub const EffectiveChain = struct {
    plugin_ids: [MAX_EFFECTIVE_PLUGINS][]const u8,
    count: u32,

    pub fn init() EffectiveChain {
        return .{ .plugin_ids = undefined, .count = 0 };
    }

    pub fn slice(self: *const EffectiveChain) []const []const u8 {
        assert(self.count <= MAX_EFFECTIVE_PLUGINS);
        return self.plugin_ids[0..self.count];
    }
};

pub fn composeEffectiveChain(
    plugins: []const ir.PluginCatalogEntry,
    global_plugin_ids: []const []const u8,
    route: *const ir.Route,
) CompositionError!EffectiveChain {
    assert(@intFromPtr(route) != 0);

    var result = EffectiveChain.init();

    var global_index: usize = 0;
    while (global_index < global_plugin_ids.len) : (global_index += 1) {
        const plugin_id = global_plugin_ids[global_index];
        const plugin = findPlugin(plugins, plugin_id) orelse return error.MissingGlobalPlugin;

        if (isDisabled(route, plugin_id)) {
            if (plugin.mandatory) return error.MandatoryPluginDisableRejected;
            if (plugin.disable_requires_waiver and !hasWaiver(route, plugin_id)) {
                return error.MissingRequiredWaiver;
            }
            continue;
        }

        try appendUnique(&result, plugin_id);
    }

    var add_index: usize = 0;
    while (add_index < route.add_plugin_ids.len) : (add_index += 1) {
        const plugin_id = route.add_plugin_ids[add_index];
        _ = findPlugin(plugins, plugin_id) orelse return error.MissingRouteAddPlugin;
        try appendUnique(&result, plugin_id);
    }

    var disable_index: usize = 0;
    while (disable_index < route.disable_plugin_ids.len) : (disable_index += 1) {
        const plugin_id = route.disable_plugin_ids[disable_index];
        const plugin = findPlugin(plugins, plugin_id) orelse return error.MissingRouteDisablePlugin;

        if (plugin.mandatory and !hasWaiver(route, plugin_id)) {
            return error.MandatoryPluginDisableRejected;
        }
        if (plugin.disable_requires_waiver and !hasWaiver(route, plugin_id)) {
            return error.MissingRequiredWaiver;
        }
    }

    return result;
}

fn appendUnique(chain: *EffectiveChain, plugin_id: []const u8) CompositionError!void {
    assert(@intFromPtr(chain) != 0);
    assert(plugin_id.len > 0);

    if (contains(chain.slice(), plugin_id)) return;
    if (chain.count >= MAX_EFFECTIVE_PLUGINS) return error.TooManyEffectivePlugins;

    chain.plugin_ids[chain.count] = plugin_id;
    chain.count += 1;
}

fn contains(ids: []const []const u8, target: []const u8) bool {
    assert(target.len > 0);

    var index: usize = 0;
    while (index < ids.len) : (index += 1) {
        if (std.mem.eql(u8, ids[index], target)) return true;
    }
    return false;
}

fn findPlugin(plugins: []const ir.PluginCatalogEntry, plugin_id: []const u8) ?ir.PluginCatalogEntry {
    assert(plugin_id.len > 0);

    var index: usize = 0;
    while (index < plugins.len) : (index += 1) {
        if (std.mem.eql(u8, plugins[index].id, plugin_id)) return plugins[index];
    }
    return null;
}

fn hasWaiver(route: *const ir.Route, plugin_id: []const u8) bool {
    assert(@intFromPtr(route) != 0);
    assert(plugin_id.len > 0);

    var index: usize = 0;
    while (index < route.waivers.len) : (index += 1) {
        const waiver = route.waivers[index];
        if (std.mem.eql(u8, waiver.plugin_id, plugin_id) and waiver.waiver_id.len > 0) return true;
    }
    return false;
}

fn isDisabled(route: *const ir.Route, plugin_id: []const u8) bool {
    assert(@intFromPtr(route) != 0);
    return contains(route.disable_plugin_ids, plugin_id);
}

test "composition applies global minus disables plus additions deterministically" {
    const plugins = [_]ir.PluginCatalogEntry{
        .{ .id = "p1", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false },
        .{ .id = "p2", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false },
        .{ .id = "p3", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false },
    };
    const route = ir.Route{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{"p2"},
        .add_plugin_ids = &.{"p3"},
        .waivers = &.{},
    };

    const effective = try composeEffectiveChain(plugins[0..], &.{ "p1", "p2" }, &route);
    const ids = effective.slice();
    try std.testing.expectEqual(@as(usize, 2), ids.len);
    try std.testing.expectEqualStrings("p1", ids[0]);
    try std.testing.expectEqualStrings("p3", ids[1]);
}

test "composition rejects disabling mandatory plugin without waiver" {
    const plugins = [_]ir.PluginCatalogEntry{
        .{ .id = "p1", .version = "1", .enabled = true, .mandatory = true, .disable_requires_waiver = false },
    };
    const route = ir.Route{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{"p1"},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    };

    try std.testing.expectError(
        error.MandatoryPluginDisableRejected,
        composeEffectiveChain(plugins[0..], &.{"p1"}, &route),
    );
}

test "composition allows waiver-required disable when waiver exists" {
    const plugins = [_]ir.PluginCatalogEntry{
        .{ .id = "p1", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = true },
    };
    const route = ir.Route{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{"p1"},
        .add_plugin_ids = &.{},
        .waivers = &.{.{ .plugin_id = "p1", .waiver_id = "ticket-1" }},
    };

    const effective = try composeEffectiveChain(plugins[0..], &.{"p1"}, &route);
    try std.testing.expectEqual(@as(usize, 0), effective.slice().len);
}
