//! Deterministic plugin ordering resolver (DAG + tie-break).

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

/// Maximum number of plugins that can participate in one resolved chain.
/// This is the fixed capacity used by `resolve()` and `OrderedChain`.
/// The value is sourced from `config.MAX_ROUTES`.
pub const MAX_CHAIN_PLUGINS: usize = config.MAX_ROUTES;

/// Describes one plugin and its relative ordering constraints.
/// `plugin_id` names the plugin being placed; `before` and `after` list peer plugin IDs that must come later or earlier.
/// The struct does not own any strings; all slices borrow caller-provided data.
pub const ConstraintEntry = struct {
    plugin_id: []const u8,
    priority: i32,
    before: []const []const u8,
    after: []const []const u8,
};

/// Errors returned while resolving plugin ordering constraints.
/// `TooManyPlugins` means the input exceeds the fixed chain capacity.
/// `DuplicatePluginId`, `MissingDependency`, and `CycleDetected` report invalid or unsatisfiable ordering constraints.
pub const OrderingError = error{
    TooManyPlugins,
    DuplicatePluginId,
    MissingDependency,
    CycleDetected,
};

/// Stores a resolved plugin ordering and the number of valid entries.
/// The chain owns no allocations; it only holds borrowed plugin ID slices copied into fixed storage.
/// Use `init()` to create an empty value and `slice()` to read the populated prefix.
pub const OrderedChain = struct {
    plugin_ids: [MAX_CHAIN_PLUGINS][]const u8,
    count: u32,

    /// Initialize an empty ordered chain.
    /// The chain starts with `count == 0` and an uninitialized backing array.
    /// Populate the `plugin_ids` entries before exposing the chain through `slice()` or other readers.
    pub fn init() OrderedChain {
        return .{
            .plugin_ids = undefined,
            .count = 0,
        };
    }

    /// Return the ordered plugin IDs as a slice view into this chain.
    /// The returned slice is valid for as long as `self` remains alive and is not modified.
    /// `count` must not exceed `MAX_CHAIN_PLUGINS`; this is asserted before the slice is formed.
    pub fn slice(self: *const OrderedChain) []const []const u8 {
        assert(self.count <= MAX_CHAIN_PLUGINS);
        return self.plugin_ids[0..self.count];
    }
};

/// Resolve a constraint graph into a deterministic plugin order.
/// The input slice is not owned; the returned chain stores copied plugin IDs from `entries`.
/// Returns `error.TooManyPlugins`, `error.DuplicatePluginId`, `error.MissingDependency`, or `error.CycleDetected` when the constraints cannot be satisfied.
/// `entries.len` must fit in `u32` and must not exceed `MAX_CHAIN_PLUGINS`; both are enforced at runtime.
pub fn resolve(entries: []const ConstraintEntry) OrderingError!OrderedChain {
    assert(entries.len <= std.math.maxInt(u32));

    if (entries.len > MAX_CHAIN_PLUGINS) return error.TooManyPlugins;

    var indegree: [MAX_CHAIN_PLUGINS]u16 = std.mem.zeroes([MAX_CHAIN_PLUGINS]u16);
    var edges: [MAX_CHAIN_PLUGINS][MAX_CHAIN_PLUGINS]bool = std.mem.zeroes([MAX_CHAIN_PLUGINS][MAX_CHAIN_PLUGINS]bool);
    var processed: [MAX_CHAIN_PLUGINS]bool = std.mem.zeroes([MAX_CHAIN_PLUGINS]bool);

    try validateUniqueIds(entries);
    try buildEdges(entries, &edges, &indegree);

    var ordered = OrderedChain.init();

    var produced: usize = 0;
    while (produced < entries.len) : (produced += 1) {
        const selected = selectNext(entries, &indegree, &processed) orelse return error.CycleDetected;
        processed[selected] = true;
        ordered.plugin_ids[ordered.count] = entries[selected].plugin_id;
        ordered.count += 1;

        var target_index: usize = 0;
        while (target_index < entries.len) : (target_index += 1) {
            if (!edges[selected][target_index]) continue;
            assert(indegree[target_index] > 0);
            indegree[target_index] -= 1;
        }
    }

    assert(ordered.count == entries.len);
    return ordered;
}

fn validateUniqueIds(entries: []const ConstraintEntry) OrderingError!void {
    var i: usize = 0;
    while (i < entries.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < entries.len) : (j += 1) {
            if (std.mem.eql(u8, entries[i].plugin_id, entries[j].plugin_id)) return error.DuplicatePluginId;
        }
    }
}

fn buildEdges(
    entries: []const ConstraintEntry,
    edges: *[MAX_CHAIN_PLUGINS][MAX_CHAIN_PLUGINS]bool,
    indegree: *[MAX_CHAIN_PLUGINS]u16,
) OrderingError!void {
    var from_index: usize = 0;
    while (from_index < entries.len) : (from_index += 1) {
        const entry = entries[from_index];

        var before_index: usize = 0;
        while (before_index < entry.before.len) : (before_index += 1) {
            const target = findEntryIndex(entries, entry.before[before_index]) orelse return error.MissingDependency;
            try addEdge(edges, indegree, from_index, target);
        }

        var after_index: usize = 0;
        while (after_index < entry.after.len) : (after_index += 1) {
            const dependency = findEntryIndex(entries, entry.after[after_index]) orelse return error.MissingDependency;
            try addEdge(edges, indegree, dependency, from_index);
        }
    }
}

fn addEdge(
    edges: *[MAX_CHAIN_PLUGINS][MAX_CHAIN_PLUGINS]bool,
    indegree: *[MAX_CHAIN_PLUGINS]u16,
    from_index: usize,
    to_index: usize,
) OrderingError!void {
    assert(from_index < MAX_CHAIN_PLUGINS);
    assert(to_index < MAX_CHAIN_PLUGINS);

    if (from_index == to_index) return error.CycleDetected;
    if (edges[from_index][to_index]) return;

    edges[from_index][to_index] = true;
    if (indegree[to_index] == std.math.maxInt(u16)) return error.TooManyPlugins;
    indegree[to_index] += 1;
}

fn findEntryIndex(entries: []const ConstraintEntry, plugin_id: []const u8) ?usize {
    assert(plugin_id.len > 0);

    var index: usize = 0;
    while (index < entries.len) : (index += 1) {
        if (std.mem.eql(u8, entries[index].plugin_id, plugin_id)) return index;
    }
    return null;
}

fn selectNext(
    entries: []const ConstraintEntry,
    indegree: *const [MAX_CHAIN_PLUGINS]u16,
    processed: *const [MAX_CHAIN_PLUGINS]bool,
) ?usize {
    var selected: ?usize = null;

    var index: usize = 0;
    while (index < entries.len) : (index += 1) {
        if (processed[index]) continue;
        if (indegree[index] != 0) continue;

        if (selected == null) {
            selected = index;
            continue;
        }

        const current = entries[index];
        const previous = entries[selected.?];
        if (current.priority > previous.priority) {
            selected = index;
            continue;
        }
        if (current.priority == previous.priority and std.mem.order(u8, current.plugin_id, previous.plugin_id) == .lt) {
            selected = index;
        }
    }

    return selected;
}

test "resolve applies deterministic tie-break by priority then id" {
    const entries = [_]ConstraintEntry{
        .{ .plugin_id = "beta", .priority = 5, .before = &.{}, .after = &.{} },
        .{ .plugin_id = "alpha", .priority = 5, .before = &.{}, .after = &.{} },
        .{ .plugin_id = "gamma", .priority = 10, .before = &.{}, .after = &.{} },
    };

    const ordered = try resolve(entries[0..]);
    const ids = ordered.slice();
    try std.testing.expectEqual(@as(usize, 3), ids.len);
    try std.testing.expectEqualStrings("gamma", ids[0]);
    try std.testing.expectEqualStrings("alpha", ids[1]);
    try std.testing.expectEqualStrings("beta", ids[2]);
}

test "resolve rejects cycles" {
    const entries = [_]ConstraintEntry{
        .{ .plugin_id = "a", .priority = 1, .before = &.{}, .after = &.{"b"} },
        .{ .plugin_id = "b", .priority = 1, .before = &.{}, .after = &.{"a"} },
    };

    try std.testing.expectError(error.CycleDetected, resolve(entries[0..]));
}
