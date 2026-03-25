//! Minimal declarative DSL frontend compiling into canonical IR.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const ir = @import("ir.zig");

pub const ParseError = error{
    TooManyLines,
    InvalidStatement,
    MissingRequiredField,
    UnsupportedConstruct,
    TooManyListeners,
    TooManyPools,
    TooManyPlugins,
    TooManyChains,
    TooManyRoutes,
    UnknownListenerReference,
    UnknownPoolReference,
    UnknownChainReference,
    UnknownPluginReference,
};

pub const ParsedDsl = struct {
    listeners: [config.MAX_ALLOWED_HOSTS]ir.Listener,
    listener_count: u32,
    pools: [config.MAX_POOLS]ir.Pool,
    pool_count: u32,
    plugins: [config.MAX_ROUTES]ir.PluginCatalogEntry,
    plugin_count: u32,
    chains: [config.MAX_ROUTES]ir.ChainPlan,
    chain_entries: [config.MAX_ROUTES]ir.ChainEntry,
    chain_count: u32,
    routes: [config.MAX_ROUTES]ir.Route,
    route_count: u32,

    pub fn init() ParsedDsl {
        return .{
            .listeners = undefined,
            .listener_count = 0,
            .pools = undefined,
            .pool_count = 0,
            .plugins = undefined,
            .plugin_count = 0,
            .chains = undefined,
            .chain_entries = undefined,
            .chain_count = 0,
            .routes = undefined,
            .route_count = 0,
        };
    }

    pub fn toCanonicalIr(self: *const ParsedDsl) ir.CanonicalIr {
        assert(self.listener_count <= self.listeners.len);
        assert(self.pool_count <= self.pools.len);
        assert(self.plugin_count <= self.plugins.len);
        assert(self.chain_count <= self.chains.len);
        assert(self.route_count <= self.routes.len);

        return .{
            .listeners = self.listeners[0..self.listener_count],
            .pools = self.pools[0..self.pool_count],
            .routes = self.routes[0..self.route_count],
            .plugins = self.plugins[0..self.plugin_count],
            .chains = self.chains[0..self.chain_count],
            .global_plugin_ids = &.{},
        };
    }
};

pub fn parse(source: []const u8) ParseError!ParsedDsl {
    assert(source.len > 0);

    var parsed = ParsedDsl.init();
    var line_index: u32 = 0;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line_raw| : (line_index += 1) {
        if (line_index >= 4096) return error.TooManyLines;

        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (isUnsupportedConstruct(line)) return error.UnsupportedConstruct;

        try parseLine(line, &parsed);
    }

    try validateReferences(&parsed);
    return parsed;
}

fn parseLine(line: []const u8, parsed: *ParsedDsl) ParseError!void {
    assert(line.len > 0);
    assert(@intFromPtr(parsed) != 0);

    var tokens = std.mem.tokenizeScalar(u8, line, ' ');
    const keyword = tokens.next() orelse return error.InvalidStatement;

    if (std.mem.eql(u8, keyword, "listener")) return parseListener(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "pool")) return parsePool(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "plugin")) return parsePlugin(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "chain")) return parseChain(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "route")) return parseRoute(tokens.rest(), parsed);

    return error.InvalidStatement;
}

fn parseListener(rest: []const u8, parsed: *ParsedDsl) ParseError!void {
    if (parsed.listener_count >= parsed.listeners.len) return error.TooManyListeners;

    var tokens = std.mem.tokenizeScalar(u8, rest, ' ');
    const id = tokens.next() orelse return error.InvalidStatement;
    const bind = tokens.next() orelse return error.InvalidStatement;

    parsed.listeners[parsed.listener_count] = .{ .id = id, .bind = bind };
    parsed.listener_count += 1;
}

fn parsePool(rest: []const u8, parsed: *ParsedDsl) ParseError!void {
    if (parsed.pool_count >= parsed.pools.len) return error.TooManyPools;

    var tokens = std.mem.tokenizeScalar(u8, rest, ' ');
    const id = tokens.next() orelse return error.InvalidStatement;
    var upstream_spec: ?[]const u8 = null;

    while (tokens.next()) |token| {
        if (!std.mem.startsWith(u8, token, "upstream=")) continue;
        const value = token["upstream=".len..];
        if (value.len == 0) return error.MissingRequiredField;
        upstream_spec = value;
    }

    parsed.pools[parsed.pool_count] = .{ .id = id, .upstream_spec = upstream_spec };
    parsed.pool_count += 1;
}

fn parsePlugin(rest: []const u8, parsed: *ParsedDsl) ParseError!void {
    if (parsed.plugin_count >= parsed.plugins.len) return error.TooManyPlugins;

    var tokens = std.mem.tokenizeScalar(u8, rest, ' ');
    const id = tokens.next() orelse return error.InvalidStatement;

    var mandatory = false;
    var waiver_required = false;
    var has_fail_policy = false;

    while (tokens.next()) |token| {
        if (std.mem.eql(u8, token, "mandatory=true")) mandatory = true;
        if (std.mem.eql(u8, token, "waiver_required=true")) waiver_required = true;
        if (std.mem.eql(u8, token, "fail_policy=fail_open") or std.mem.eql(u8, token, "fail_policy=fail_closed")) {
            has_fail_policy = true;
        }
    }

    if (!has_fail_policy) return error.MissingRequiredField;

    parsed.plugins[parsed.plugin_count] = .{
        .id = id,
        .version = "1",
        .enabled = true,
        .mandatory = mandatory,
        .disable_requires_waiver = waiver_required,
    };
    parsed.plugin_count += 1;
}

fn parseChain(rest: []const u8, parsed: *ParsedDsl) ParseError!void {
    if (parsed.chain_count >= parsed.chains.len) return error.TooManyChains;

    var tokens = std.mem.tokenizeScalar(u8, rest, ' ');
    const id = tokens.next() orelse return error.InvalidStatement;
    const plugin_token = tokens.next() orelse return error.MissingRequiredField;
    if (!std.mem.startsWith(u8, plugin_token, "plugin=")) return error.MissingRequiredField;
    const plugin_id = plugin_token["plugin=".len..];

    parsed.chain_entries[parsed.chain_count] = .{
        .plugin_id = plugin_id,
        .failure_policy = .fail_closed,
        .budget = .{
            .max_state_bytes = 1024,
            .max_output_bytes = 1024 * 1024,
            .max_expansion_ratio_milli = 2000,
            .max_cpu_micros_per_chunk = 1000,
        },
        .priority = 1,
        .before = &.{},
        .after = &.{},
    };
    parsed.chains[parsed.chain_count] = .{ .id = id, .entries = parsed.chain_entries[parsed.chain_count .. parsed.chain_count + 1] };
    parsed.chain_count += 1;
}

fn parseRoute(rest: []const u8, parsed: *ParsedDsl) ParseError!void {
    if (parsed.route_count >= parsed.routes.len) return error.TooManyRoutes;

    var tokens = std.mem.tokenizeScalar(u8, rest, ' ');
    const id = tokens.next() orelse return error.InvalidStatement;

    var listener_id: ?[]const u8 = null;
    var host: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var pool_id: ?[]const u8 = null;
    var chain_id: ?[]const u8 = null;

    while (tokens.next()) |token| {
        if (std.mem.startsWith(u8, token, "listener=")) listener_id = token[9..];
        if (std.mem.startsWith(u8, token, "host=")) host = token[5..];
        if (std.mem.startsWith(u8, token, "path=")) path = token[5..];
        if (std.mem.startsWith(u8, token, "pool=")) pool_id = token[5..];
        if (std.mem.startsWith(u8, token, "chain=")) chain_id = token[6..];
    }

    parsed.routes[parsed.route_count] = .{
        .id = id,
        .listener_id = listener_id orelse return error.MissingRequiredField,
        .host = host orelse return error.MissingRequiredField,
        .path_prefix = path orelse return error.MissingRequiredField,
        .pool_id = pool_id orelse return error.MissingRequiredField,
        .chain_id = chain_id orelse return error.MissingRequiredField,
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    };
    parsed.route_count += 1;
}

fn validateReferences(parsed: *const ParsedDsl) ParseError!void {
    assert(@intFromPtr(parsed) != 0);

    var route_index: usize = 0;
    while (route_index < parsed.route_count) : (route_index += 1) {
        const route = parsed.routes[route_index];
        if (!containsListener(parsed.listeners[0..parsed.listener_count], route.listener_id)) return error.UnknownListenerReference;
        if (!containsPool(parsed.pools[0..parsed.pool_count], route.pool_id)) return error.UnknownPoolReference;
        if (!containsChain(parsed.chains[0..parsed.chain_count], route.chain_id)) return error.UnknownChainReference;
    }

    var chain_index: usize = 0;
    while (chain_index < parsed.chain_count) : (chain_index += 1) {
        const chain = parsed.chains[chain_index];
        var entry_index: usize = 0;
        while (entry_index < chain.entries.len) : (entry_index += 1) {
            if (!containsPlugin(parsed.plugins[0..parsed.plugin_count], chain.entries[entry_index].plugin_id)) {
                return error.UnknownPluginReference;
            }
        }
    }
}

fn isUnsupportedConstruct(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "macro ") or
        std.mem.startsWith(u8, line, "function ") or
        std.mem.startsWith(u8, line, "if ");
}

fn containsListener(listeners: []const ir.Listener, id: []const u8) bool {
    var index: usize = 0;
    while (index < listeners.len) : (index += 1) {
        if (std.mem.eql(u8, listeners[index].id, id)) return true;
    }
    return false;
}

fn containsPool(pools: []const ir.Pool, id: []const u8) bool {
    var index: usize = 0;
    while (index < pools.len) : (index += 1) {
        if (std.mem.eql(u8, pools[index].id, id)) return true;
    }
    return false;
}

fn containsChain(chains: []const ir.ChainPlan, id: []const u8) bool {
    var index: usize = 0;
    while (index < chains.len) : (index += 1) {
        if (std.mem.eql(u8, chains[index].id, id)) return true;
    }
    return false;
}

fn containsPlugin(plugins: []const ir.PluginCatalogEntry, id: []const u8) bool {
    var index: usize = 0;
    while (index < plugins.len) : (index += 1) {
        if (std.mem.eql(u8, plugins[index].id, id)) return true;
    }
    return false;
}

test "dsl parse builds canonical ir for minimal configuration" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plug fail_policy=fail_closed mandatory=true
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const parsed = try parse(source);
    var candidate = parsed.toCanonicalIr();
    var diagnostics: [ir.MAX_VALIDATION_DIAGNOSTICS]ir.ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;
    try ir.validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count);
    try std.testing.expectEqual(@as(u32, 0), diagnostics_count);
}

test "dsl parse rejects missing plugin fail_policy" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plug mandatory=true
    ;
    try std.testing.expectError(error.MissingRequiredField, parse(source));
}

test "dsl parse rejects unsupported constructs" {
    try std.testing.expectError(error.UnsupportedConstruct, parse("macro x"));
    try std.testing.expectError(error.UnsupportedConstruct, parse("function x"));
    try std.testing.expectError(error.UnsupportedConstruct, parse("if x"));
}

test "dsl semantic validation rejects unknown route references" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=missing chain=c1
    ;

    try std.testing.expectError(error.UnknownPoolReference, parse(source));
}

test "dsl semantic validation rejects unknown listener reference" {
    const source =
        \\listener l1 0.0.0.0:443
        \\pool p1
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=missing host=example.com path=/ pool=p1 chain=c1
    ;

    try std.testing.expectError(error.UnknownListenerReference, parse(source));
}
