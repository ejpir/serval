//! Minimal declarative DSL frontend compiling into canonical IR.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const ir = @import("ir.zig");
const components = @import("components.zig");

/// Errors returned while parsing or validating reverse proxy DSL input.
/// These cover structural issues, capacity limits, unsupported syntax, and unresolved references.
/// Callers should treat the set as non-exhaustive for higher-level validation failures surfaced by the parser.
pub const ParseError = error{
    TooManyLines,
    InvalidStatement,
    MissingRequiredField,
    MissingOtelEndpoint,
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

/// In-memory representation of the reverse proxy DSL after parsing and validation.
/// Stores listeners, pools, plugins, chains, and routes in fixed-capacity arrays with explicit counts for the used prefix.
/// Also carries component selection and OpenTelemetry defaults used when building canonical IR.
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

    component_pool_kind: components.PoolKind,
    component_metrics_kind: components.MetricsKind,
    component_tracer_kind: components.TracerKind,
    component_tracing_otel_endpoint: ?[]const u8,
    component_tracing_otel_service_name: []const u8,
    component_tracing_otel_service_version: []const u8,
    component_tracing_otel_scope_name: []const u8,
    component_tracing_otel_scope_version: []const u8,

    /// Initializes a `ParsedDsl` with zero counts and default component settings.
    /// The fixed-capacity arrays are left undefined until entries are parsed and counted into them.
    /// No allocation is performed; the default tracing service and scope values are prefilled.
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
            .component_pool_kind = .simple,
            .component_metrics_kind = .noop,
            .component_tracer_kind = .noop,
            .component_tracing_otel_endpoint = null,
            .component_tracing_otel_service_name = "serval-reverseproxy",
            .component_tracing_otel_service_version = "1.0.0",
            .component_tracing_otel_scope_name = "serval.reverseproxy",
            .component_tracing_otel_scope_version = "1.0.0",
        };
    }

    /// Converts the parsed DSL into canonical IR using the populated prefixes of each fixed-capacity array.
    /// The returned slices borrow storage from `self` and remain valid only while `self` is unchanged and alive.
    /// Asserts that every count is within the corresponding array capacity before slicing.
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

/// Parses reverse proxy DSL text into a validated `ParsedDsl` value.
/// Blank lines and lines starting with `#` are ignored after trimming ASCII space, tab, and carriage return.
/// Requires non-empty input and returns `error.TooManyLines`, `error.UnsupportedConstruct`, or a validation error from the parsed content.
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

    try validateComponentConfig(&parsed);
    try validateReferences(&parsed);
    return parsed;
}

fn parseLine(line: []const u8, parsed: *ParsedDsl) ParseError!void {
    assert(line.len > 0);
    assert(@intFromPtr(parsed) != 0);

    if (std.mem.startsWith(u8, line, "config.component.")) return parseComponentConfigLine(line, parsed);

    var tokens = std.mem.tokenizeScalar(u8, line, ' ');
    const keyword = tokens.next() orelse return error.InvalidStatement;

    if (std.mem.eql(u8, keyword, "listener")) return parseListener(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "pool")) return parsePool(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "plugin")) return parsePlugin(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "chain")) return parseChain(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "route")) return parseRoute(tokens.rest(), parsed);
    if (std.mem.eql(u8, keyword, "component")) return parseComponent(tokens.rest(), parsed);

    return error.InvalidStatement;
}

fn parseComponentConfigLine(line: []const u8, parsed: *ParsedDsl) ParseError!void {
    assert(line.len > 0);
    assert(@intFromPtr(parsed) != 0);

    if (std.mem.startsWith(u8, line, "config.component.pool=")) {
        parsed.component_pool_kind = try parsePoolKind(line["config.component.pool=".len..]);
        return;
    }
    if (std.mem.startsWith(u8, line, "config.component.metrics=")) {
        parsed.component_metrics_kind = try parseMetricsKind(line["config.component.metrics=".len..]);
        return;
    }
    if (std.mem.startsWith(u8, line, "config.component.tracing=")) {
        parsed.component_tracer_kind = try parseTracerKind(line["config.component.tracing=".len..]);
        return;
    }
    if (std.mem.startsWith(u8, line, "config.component.tracing.otel.endpoint=")) {
        parsed.component_tracing_otel_endpoint = line["config.component.tracing.otel.endpoint=".len..];
        return;
    }
    if (std.mem.startsWith(u8, line, "config.component.tracing.otel.service_name=")) {
        parsed.component_tracing_otel_service_name = line["config.component.tracing.otel.service_name=".len..];
        return;
    }
    if (std.mem.startsWith(u8, line, "config.component.tracing.otel.service_version=")) {
        parsed.component_tracing_otel_service_version = line["config.component.tracing.otel.service_version=".len..];
        return;
    }
    if (std.mem.startsWith(u8, line, "config.component.tracing.otel.scope_name=")) {
        parsed.component_tracing_otel_scope_name = line["config.component.tracing.otel.scope_name=".len..];
        return;
    }
    if (std.mem.startsWith(u8, line, "config.component.tracing.otel.scope_version=")) {
        parsed.component_tracing_otel_scope_version = line["config.component.tracing.otel.scope_version=".len..];
        return;
    }

    return error.InvalidStatement;
}

fn parseComponent(rest: []const u8, parsed: *ParsedDsl) ParseError!void {
    assert(rest.len > 0);
    assert(@intFromPtr(parsed) != 0);

    var tokens = std.mem.tokenizeScalar(u8, rest, ' ');
    const kind = tokens.next() orelse return error.InvalidStatement;
    const value = tokens.next() orelse return error.InvalidStatement;

    if (std.mem.eql(u8, kind, "pool")) {
        parsed.component_pool_kind = try parsePoolKind(value);
        return;
    }
    if (std.mem.eql(u8, kind, "metrics")) {
        parsed.component_metrics_kind = try parseMetricsKind(value);
        return;
    }
    if (std.mem.eql(u8, kind, "tracing")) {
        parsed.component_tracer_kind = try parseTracerKind(value);
        return;
    }

    return error.InvalidStatement;
}

fn parsePoolKind(raw: []const u8) ParseError!components.PoolKind {
    if (std.mem.eql(u8, raw, "simple")) return .simple;
    if (std.mem.eql(u8, raw, "none")) return .none;
    return error.InvalidStatement;
}

fn parseMetricsKind(raw: []const u8) ParseError!components.MetricsKind {
    if (std.mem.eql(u8, raw, "noop")) return .noop;
    if (std.mem.eql(u8, raw, "prometheus")) return .prometheus;
    return error.InvalidStatement;
}

fn parseTracerKind(raw: []const u8) ParseError!components.TracerKind {
    if (std.mem.eql(u8, raw, "noop")) return .noop;
    if (std.mem.eql(u8, raw, "otel")) return .otel;
    return error.InvalidStatement;
}

fn parseListener(rest: []const u8, parsed: *ParsedDsl) ParseError!void {
    if (parsed.listener_count >= parsed.listeners.len) return error.TooManyListeners;

    var tokens = std.mem.tokenizeScalar(u8, rest, ' ');
    const id = tokens.next() orelse return error.InvalidStatement;
    const bind = tokens.next() orelse return error.InvalidStatement;

    var tls_provider: ?ir.TlsProvider = null;
    var static_cert_path: ?[]const u8 = null;
    var static_key_path: ?[]const u8 = null;
    var selfsigned_state_dir: ?[]const u8 = null;
    var selfsigned_domain: ?[]const u8 = null;
    var selfsigned_rotate_on_boot = false;

    var acme_directory_url: ?[]const u8 = null;
    var acme_contact_email: ?[]const u8 = null;
    var acme_state_dir: ?[]const u8 = null;
    var acme_domain: ?[]const u8 = null;
    var acme_renew_before_ns = config.ACME_DEFAULT_RENEW_BEFORE_NS;
    var acme_poll_interval_ms = config.ACME_DEFAULT_POLL_INTERVAL_MS;
    var acme_fail_backoff_min_ms = config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS;
    var acme_fail_backoff_max_ms = config.ACME_DEFAULT_FAIL_BACKOFF_MAX_MS;

    while (tokens.next()) |token| {
        if (std.mem.startsWith(u8, token, "tls.provider=")) {
            const raw = token["tls.provider=".len..];
            if (std.mem.eql(u8, raw, "static")) tls_provider = .static else if (std.mem.eql(u8, raw, "selfsigned")) tls_provider = .selfsigned else if (std.mem.eql(u8, raw, "acme")) tls_provider = .acme else return error.InvalidStatement;
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.static.cert_path=")) {
            static_cert_path = token["tls.static.cert_path=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.static.key_path=")) {
            static_key_path = token["tls.static.key_path=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.selfsigned.state_dir=")) {
            selfsigned_state_dir = token["tls.selfsigned.state_dir=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.selfsigned.domain=")) {
            selfsigned_domain = token["tls.selfsigned.domain=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.selfsigned.rotate_on_boot=")) {
            selfsigned_rotate_on_boot = try parseBool(token["tls.selfsigned.rotate_on_boot=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.acme.directory_url=")) {
            acme_directory_url = token["tls.acme.directory_url=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.acme.contact_email=")) {
            acme_contact_email = token["tls.acme.contact_email=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.acme.state_dir=")) {
            acme_state_dir = token["tls.acme.state_dir=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.acme.domain=")) {
            acme_domain = token["tls.acme.domain=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.acme.renew_before_ns=")) {
            acme_renew_before_ns = try parseU64(token["tls.acme.renew_before_ns=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.acme.poll_interval_ms=")) {
            acme_poll_interval_ms = try parseU32(token["tls.acme.poll_interval_ms=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.acme.fail_backoff_min_ms=")) {
            acme_fail_backoff_min_ms = try parseU32(token["tls.acme.fail_backoff_min_ms=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, token, "tls.acme.fail_backoff_max_ms=")) {
            acme_fail_backoff_max_ms = try parseU32(token["tls.acme.fail_backoff_max_ms=".len..]);
            continue;
        }
    }

    const tls_cfg: ?ir.ListenerTls = if (tls_provider) |provider| switch (provider) {
        .static => .{
            .provider = .static,
            .static = .{
                .cert_path = static_cert_path orelse return error.MissingRequiredField,
                .key_path = static_key_path orelse return error.MissingRequiredField,
            },
        },
        .selfsigned => .{
            .provider = .selfsigned,
            .selfsigned = .{
                .state_dir_path = selfsigned_state_dir orelse return error.MissingRequiredField,
                .domain = selfsigned_domain orelse return error.MissingRequiredField,
                .rotate_on_boot = selfsigned_rotate_on_boot,
            },
        },
        .acme => .{
            .provider = .acme,
            .acme = .{
                .directory_url = acme_directory_url orelse return error.MissingRequiredField,
                .contact_email = acme_contact_email orelse return error.MissingRequiredField,
                .state_dir_path = acme_state_dir orelse return error.MissingRequiredField,
                .domain = acme_domain orelse return error.MissingRequiredField,
                .renew_before_ns = acme_renew_before_ns,
                .poll_interval_ms = acme_poll_interval_ms,
                .fail_backoff_min_ms = acme_fail_backoff_min_ms,
                .fail_backoff_max_ms = acme_fail_backoff_max_ms,
            },
        },
    } else null;

    parsed.listeners[parsed.listener_count] = .{ .id = id, .bind = bind, .tls = tls_cfg };
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

fn validateComponentConfig(parsed: *const ParsedDsl) ParseError!void {
    assert(@intFromPtr(parsed) != 0);
    if (parsed.component_tracer_kind == .otel) {
        const endpoint = parsed.component_tracing_otel_endpoint orelse return error.MissingOtelEndpoint;
        if (endpoint.len == 0) return error.MissingOtelEndpoint;
    }
}

fn parseBool(raw: []const u8) ParseError!bool {
    if (std.mem.eql(u8, raw, "true")) return true;
    if (std.mem.eql(u8, raw, "false")) return false;
    return error.InvalidStatement;
}

fn parseU32(raw: []const u8) ParseError!u32 {
    return std.fmt.parseInt(u32, raw, 10) catch return error.InvalidStatement;
}

fn parseU64(raw: []const u8) ParseError!u64 {
    return std.fmt.parseInt(u64, raw, 10) catch return error.InvalidStatement;
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

test "dsl listener supports selfsigned tls provider" {
    const source =
        \\listener l1 0.0.0.0:443 tls.provider=selfsigned tls.selfsigned.state_dir=/tmp/rp tls.selfsigned.domain=example.com tls.selfsigned.rotate_on_boot=true
        \\pool p1 upstream=http://127.0.0.1:8081
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const parsed = try parse(source);
    try std.testing.expect(parsed.listeners[0].tls != null);
    const tls_cfg = parsed.listeners[0].tls.?;
    try std.testing.expectEqual(ir.TlsProvider.selfsigned, tls_cfg.provider);
    try std.testing.expect(tls_cfg.selfsigned != null);
    try std.testing.expect(tls_cfg.selfsigned.?.rotate_on_boot);
}

test "dsl listener requires acme fields when provider is acme" {
    const source =
        \\listener l1 0.0.0.0:443 tls.provider=acme tls.acme.state_dir=/tmp/rp tls.acme.domain=example.com
        \\pool p1 upstream=http://127.0.0.1:8081
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    try std.testing.expectError(error.MissingRequiredField, parse(source));
}

test "dsl supports config.component keys" {
    const source =
        \\config.component.pool=none
        \\config.component.metrics=prometheus
        \\config.component.tracing=noop
        \\listener l1 0.0.0.0:443
        \\pool p1 upstream=http://127.0.0.1:8081
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const parsed = try parse(source);
    try std.testing.expectEqual(components.PoolKind.none, parsed.component_pool_kind);
    try std.testing.expectEqual(components.MetricsKind.prometheus, parsed.component_metrics_kind);
    try std.testing.expectEqual(components.TracerKind.noop, parsed.component_tracer_kind);
}

test "dsl supports component statements" {
    const source =
        \\component pool none
        \\component metrics noop
        \\component tracing noop
        \\listener l1 0.0.0.0:443
        \\pool p1 upstream=http://127.0.0.1:8081
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const parsed = try parse(source);
    try std.testing.expectEqual(components.PoolKind.none, parsed.component_pool_kind);
    try std.testing.expectEqual(components.MetricsKind.noop, parsed.component_metrics_kind);
    try std.testing.expectEqual(components.TracerKind.noop, parsed.component_tracer_kind);
}

test "dsl tracing otel requires endpoint" {
    const source =
        \\config.component.tracing=otel
        \\listener l1 0.0.0.0:443
        \\pool p1 upstream=http://127.0.0.1:8081
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    try std.testing.expectError(error.MissingOtelEndpoint, parse(source));
}

test "dsl tracing otel accepts endpoint and metadata" {
    const source =
        \\config.component.tracing=otel
        \\config.component.tracing.otel.endpoint=http://127.0.0.1:4318/v1/traces
        \\config.component.tracing.otel.service_name=rp
        \\config.component.tracing.otel.service_version=2.1.0
        \\config.component.tracing.otel.scope_name=rp.scope
        \\config.component.tracing.otel.scope_version=2.1.0
        \\listener l1 0.0.0.0:443
        \\pool p1 upstream=http://127.0.0.1:8081
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=example.com path=/ pool=p1 chain=c1
    ;

    const parsed = try parse(source);
    try std.testing.expectEqual(components.TracerKind.otel, parsed.component_tracer_kind);
    try std.testing.expectEqualStrings("http://127.0.0.1:4318/v1/traces", parsed.component_tracing_otel_endpoint.?);
    try std.testing.expectEqualStrings("rp", parsed.component_tracing_otel_service_name);
}
