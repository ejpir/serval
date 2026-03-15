// examples/netbird_proxy.zig
//! NetBird Reverse Proxy Example (Production-oriented)
//!
//! Serves NetBird path matrix with explicit per-route protocol policy:
//! - NetBird gRPC service paths -> h2c/h2 upstreams
//! - Zitadel paths (Caddy parity) -> h2c/h2 upstreams
//! - WebSocket/API/relay/dashboard paths -> HTTP/1.1 upstreams
//!
//! This binary is intended as a deployable starting point for self-hosted NetBird
//! fronting with Serval. TLS frontend is required (self-signed certs supported).

const std = @import("std");
const assert = std.debug.assert;
const serval = @import("serval");
const cli = @import("serval-cli");
const tls = @import("serval-tls");

const ssl = tls.ssl;

const VERSION: []const u8 = "0.1.0";
const MAX_CONFIG_SIZE_BYTES: u32 = 64 * 1024;

const UpstreamIndex = serval.config.UpstreamIndex;

const DEFAULT_SIGNAL_GRPC_SPEC: []const u8 = "h2c://signal:10000";
const DEFAULT_MANAGEMENT_GRPC_SPEC: []const u8 = "h2c://management:80";
const DEFAULT_SIGNAL_HTTP_SPEC: []const u8 = "http://signal:80";
const DEFAULT_MANAGEMENT_HTTP_SPEC: []const u8 = "http://management:80";
const DEFAULT_RELAY_HTTP_SPEC: []const u8 = "http://relay:80";
const DEFAULT_DASHBOARD_HTTP_SPEC: []const u8 = "http://dashboard:80";
const DEFAULT_ZITADEL_HTTP_SPEC: []const u8 = "h2c://zitadel:8080";

const NETBIRD_HEALTH_BODY: []const u8 = "ok\n";

const NetbirdExtra = struct {
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
    @"signal-grpc": ?[]const u8 = null,
    @"management-grpc": ?[]const u8 = null,
    @"signal-http": ?[]const u8 = null,
    @"management-http": ?[]const u8 = null,
    @"relay-http": ?[]const u8 = null,
    @"dashboard-http": ?[]const u8 = null,
    @"zitadel-http": ?[]const u8 = null,
    @"insecure-skip-verify": bool = false,
};

const NetbirdProxyConfig = struct {
    listen_host: []const u8 = "0.0.0.0",
    listen_port: u16 = 8080,
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    verify_upstream: bool = true,
    tls_h2_frontend_mode: serval.config.TlsH2FrontendMode = .terminated_only,
    alpn_mixed_offer_policy: serval.config.AlpnMixedOfferPolicy = .prefer_http11,

    signal_grpc_spec: []const u8 = DEFAULT_SIGNAL_GRPC_SPEC,
    management_grpc_spec: []const u8 = DEFAULT_MANAGEMENT_GRPC_SPEC,
    signal_http_spec: []const u8 = DEFAULT_SIGNAL_HTTP_SPEC,
    management_http_spec: []const u8 = DEFAULT_MANAGEMENT_HTTP_SPEC,
    relay_http_spec: []const u8 = DEFAULT_RELAY_HTTP_SPEC,
    dashboard_http_spec: []const u8 = DEFAULT_DASHBOARD_HTTP_SPEC,
    zitadel_http_spec: []const u8 = DEFAULT_ZITADEL_HTTP_SPEC,
};

const ParsedUpstreamSpec = struct {
    host: []const u8,
    port: u16,
    tls_enabled: bool,
    http_protocol: serval.HttpProtocol,
};

const UpstreamRole = enum {
    signal_grpc,
    management_grpc,
    signal_http,
    management_http,
    relay_http,
    zitadel_http,
    dashboard_http,
};

const NetbirdRouteSpec = struct {
    matcher: serval.PathMatch,
    role: UpstreamRole,
};

const netbird_route_specs = [_]NetbirdRouteSpec{
    .{ .matcher = .{ .prefix = "/signalexchange.SignalExchange/" }, .role = .signal_grpc },
    .{ .matcher = .{ .prefix = "/management.ManagementService/" }, .role = .management_grpc },
    .{ .matcher = .{ .prefix = "/ws-proxy/signal" }, .role = .signal_http },
    .{ .matcher = .{ .prefix = "/ws-proxy/management" }, .role = .management_http },
    .{ .matcher = .{ .prefix = "/relay" }, .role = .relay_http },
    .{ .matcher = .{ .prefix = "/api/" }, .role = .management_http },

    // Caddy-compat Zitadel route matrix (legacy deployment parity)
    .{ .matcher = .{ .prefix = "/zitadel.admin.v1.AdminService/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/admin/v1/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/zitadel.auth.v1.AuthService/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/auth/v1/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/zitadel.management.v1.ManagementService/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/management/v1/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/zitadel.system.v1.SystemService/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/system/v1/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/assets/v1/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/saml/v2/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/openapi/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/debug/" }, .role = .zitadel_http },
    .{ .matcher = .{ .exact = "/device" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/device/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/zitadel.user.v2.UserService/" }, .role = .zitadel_http },

    .{ .matcher = .{ .exact = "/.well-known/openid-configuration" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/ui/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/oidc/v1/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/oauth/v2/" }, .role = .zitadel_http },
    .{ .matcher = .{ .prefix = "/" }, .role = .dashboard_http },
};

const NetbirdUpstreams = struct {
    signal_grpc: serval.Upstream,
    management_grpc: serval.Upstream,
    signal_http: serval.Upstream,
    management_http: serval.Upstream,
    relay_http: serval.Upstream,
    zitadel_http: serval.Upstream,
    dashboard_http: serval.Upstream,

    fn get(self: *const @This(), role: UpstreamRole) serval.Upstream {
        return switch (role) {
            .signal_grpc => self.signal_grpc,
            .management_grpc => self.management_grpc,
            .signal_http => self.signal_http,
            .management_http => self.management_http,
            .relay_http => self.relay_http,
            .zitadel_http => self.zitadel_http,
            .dashboard_http => self.dashboard_http,
        };
    }

    fn anyTlsEnabled(self: *const @This()) bool {
        if (self.signal_grpc.tls) return true;
        if (self.management_grpc.tls) return true;
        if (self.signal_http.tls) return true;
        if (self.management_http.tls) return true;
        if (self.relay_http.tls) return true;
        if (self.zitadel_http.tls) return true;
        return self.dashboard_http.tls;
    }
};

const NetbirdProxyHandler = struct {
    upstreams: NetbirdUpstreams,

    pub fn onRequest(
        self: *@This(),
        ctx: *serval.Context,
        request: *serval.Request,
        response_buf: []u8,
    ) serval.Action {
        _ = self;
        _ = ctx;
        assert(response_buf.len >= NETBIRD_HEALTH_BODY.len);

        std.debug.print("[DEBUG] onRequest: method={s} path={s}\n", .{ @tagName(request.method), request.path });

        if (std.mem.eql(u8, request.path, "/healthz") or std.mem.eql(u8, request.path, "/readyz")) {
            std.debug.print("[DEBUG] -> health check, returning 200\n", .{});
            const body = netbirdWriteStaticBody(response_buf, NETBIRD_HEALTH_BODY);
            return .{ .send_response = .{
                .status = 200,
                .body = body,
                .content_type = "text/plain",
            } };
        }

        std.debug.print("[DEBUG] -> continue to upstream\n", .{});
        return .continue_request;
    }

    pub fn selectUpstream(
        self: *@This(),
        ctx: *serval.Context,
        request: *const serval.Request,
    ) serval.Upstream {
        _ = ctx;

        const role = resolveRouteRole(request.path);
        const upstream = self.upstreams.get(role);
        
        const protocol = switch (upstream.http_protocol) {
            .h1 => if (upstream.tls) "https" else "http",
            .h2c => "h2c",
            .h2 => "h2",
        };

        std.debug.print("[DEBUG] selectUpstream: path={s} -> role={s} upstream={s}://{s}:{d}\n", .{
            request.path,
            @tagName(role),
            protocol,
            upstream.host,
            upstream.port,
        });

        return upstream;
    }
};

fn resolveRouteRole(path: []const u8) UpstreamRole {
    assert(path.len > 0);

    for (netbird_route_specs) |route| {
        if (!route.matcher.matches(path)) continue;
        return route.role;
    }

    // Route table has explicit catch-all prefix '/'.
    unreachable;
}

fn netbirdWriteStaticBody(response_buf: []u8, body: []const u8) []const u8 {
    assert(body.len <= response_buf.len);
    @memcpy(response_buf[0..body.len], body);
    return response_buf[0..body.len];
}

fn parseBoolean(value: []const u8) !bool {
    const trimmed = std.mem.trim(u8, value, " \t\r");
    if (std.ascii.eqlIgnoreCase(trimmed, "true")) return true;
    if (std.ascii.eqlIgnoreCase(trimmed, "false")) return false;
    if (std.mem.eql(u8, trimmed, "1")) return true;
    if (std.mem.eql(u8, trimmed, "0")) return false;
    return error.InvalidBoolean;
}

fn parseTlsH2FrontendMode(value: []const u8) !serval.config.TlsH2FrontendMode {
    const trimmed = std.mem.trim(u8, value, " \t\r");
    if (std.ascii.eqlIgnoreCase(trimmed, "disabled")) return .disabled;
    if (std.ascii.eqlIgnoreCase(trimmed, "terminated_only")) return .terminated_only;
    if (std.ascii.eqlIgnoreCase(trimmed, "generic")) return .generic;
    return error.InvalidTlsH2FrontendMode;
}

fn parseAlpnMixedOfferPolicy(value: []const u8) !serval.config.AlpnMixedOfferPolicy {
    const trimmed = std.mem.trim(u8, value, " \t\r");
    if (std.ascii.eqlIgnoreCase(trimmed, "prefer_http11")) return .prefer_http11;
    if (std.ascii.eqlIgnoreCase(trimmed, "prefer_h2")) return .prefer_h2;
    if (std.ascii.eqlIgnoreCase(trimmed, "http11_only")) return .http11_only;
    return error.InvalidAlpnMixedOfferPolicy;
}

fn parsePort(value: []const u8) !u16 {
    const trimmed = std.mem.trim(u8, value, " \t\r");
    const parsed = try std.fmt.parseInt(u16, trimmed, 10);
    if (parsed == 0) return error.InvalidPort;
    return parsed;
}

fn parseListenHost(value: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r");
    if (trimmed.len == 0) return error.InvalidListenHost;
    return trimmed;
}

fn splitHostPort(endpoint: []const u8) !struct { host: []const u8, port: u16 } {
    const trimmed = std.mem.trim(u8, endpoint, " \t\r");
    if (trimmed.len == 0) return error.EmptyEndpoint;

    if (trimmed[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, trimmed, ']') orelse return error.InvalidEndpoint;
        if (close_idx <= 1) return error.InvalidEndpoint;
        if (close_idx + 1 >= trimmed.len) return error.InvalidEndpoint;
        if (trimmed[close_idx + 1] != ':') return error.InvalidEndpoint;

        const host = trimmed[1..close_idx];
        const port_value = trimmed[close_idx + 2 ..];
        const port = try parsePort(port_value);
        return .{ .host = host, .port = port };
    }

    const colon_idx = std.mem.lastIndexOfScalar(u8, trimmed, ':') orelse return error.InvalidEndpoint;
    if (colon_idx == 0) return error.InvalidEndpoint;
    if (colon_idx + 1 >= trimmed.len) return error.InvalidEndpoint;

    const host = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
    if (host.len == 0) return error.InvalidEndpoint;

    const port = try parsePort(trimmed[colon_idx + 1 ..]);
    return .{ .host = host, .port = port };
}

fn parseUpstreamSpec(
    spec: []const u8,
    default_protocol: serval.HttpProtocol,
    default_tls: bool,
) !ParsedUpstreamSpec {
    assert(spec.len > 0);

    var protocol = default_protocol;
    var tls_enabled = default_tls;
    var endpoint = std.mem.trim(u8, spec, " \t\r");

    if (std.mem.indexOf(u8, endpoint, "://")) |scheme_end| {
        const scheme = endpoint[0..scheme_end];
        endpoint = endpoint[scheme_end + 3 ..];

        if (std.ascii.eqlIgnoreCase(scheme, "http")) {
            protocol = .h1;
            tls_enabled = false;
        } else if (std.ascii.eqlIgnoreCase(scheme, "https")) {
            protocol = .h1;
            tls_enabled = true;
        } else if (std.ascii.eqlIgnoreCase(scheme, "h2c")) {
            protocol = .h2c;
            tls_enabled = false;
        } else if (std.ascii.eqlIgnoreCase(scheme, "h2")) {
            protocol = .h2;
            tls_enabled = true;
        } else {
            return error.InvalidEndpointScheme;
        }
    }

    const host_port = try splitHostPort(endpoint);
    return .{
        .host = host_port.host,
        .port = host_port.port,
        .tls_enabled = tls_enabled,
        .http_protocol = protocol,
    };
}

fn buildUpstream(
    spec: []const u8,
    idx: UpstreamIndex,
    default_protocol: serval.HttpProtocol,
    default_tls: bool,
) !serval.Upstream {
    const parsed = try parseUpstreamSpec(spec, default_protocol, default_tls);
    return .{
        .host = parsed.host,
        .port = parsed.port,
        .idx = idx,
        .tls = parsed.tls_enabled,
        .http_protocol = parsed.http_protocol,
    };
}

fn validateGrpcUpstream(name: []const u8, upstream: serval.Upstream) !void {
    _ = name;
    const protocol = upstream.http_protocol;
    if (protocol == .h2c) {
        if (upstream.tls) return error.InvalidGrpcUpstream;
        return;
    }
    if (protocol == .h2) {
        if (!upstream.tls) return error.InvalidGrpcUpstream;
        return;
    }
    return error.InvalidGrpcUpstream;
}

fn validateHttpUpstream(name: []const u8, upstream: serval.Upstream) !void {
    _ = name;
    if (upstream.http_protocol != .h1) return error.InvalidHttpUpstream;
}

fn parseConfigLine(
    cfg: *NetbirdProxyConfig,
    line: []const u8,
    saw_listen_port: *bool,
) !void {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0) return;
    if (trimmed[0] == '#') return;

    const eq_idx = std.mem.indexOfScalar(u8, trimmed, '=') orelse return error.InvalidConfigLine;
    if (eq_idx == 0) return error.InvalidConfigLine;
    if (eq_idx + 1 >= trimmed.len) return error.InvalidConfigLine;

    const key = std.mem.trim(u8, trimmed[0..eq_idx], " \t");
    const value = std.mem.trim(u8, trimmed[eq_idx + 1 ..], " \t");
    if (value.len == 0) return error.InvalidConfigLine;

    if (std.mem.eql(u8, key, "listen_host")) {
        cfg.listen_host = try parseListenHost(value);
        return;
    }
    if (std.mem.eql(u8, key, "listen_port")) {
        cfg.listen_port = try parsePort(value);
        saw_listen_port.* = true;
        return;
    }
    if (std.mem.eql(u8, key, "cert_path")) {
        cfg.cert_path = value;
        return;
    }
    if (std.mem.eql(u8, key, "key_path")) {
        cfg.key_path = value;
        return;
    }
    if (std.mem.eql(u8, key, "verify_upstream")) {
        cfg.verify_upstream = try parseBoolean(value);
        return;
    }
    if (std.mem.eql(u8, key, "tls_h2_frontend_mode")) {
        cfg.tls_h2_frontend_mode = try parseTlsH2FrontendMode(value);
        return;
    }
    if (std.mem.eql(u8, key, "alpn_mixed_offer_policy")) {
        cfg.alpn_mixed_offer_policy = try parseAlpnMixedOfferPolicy(value);
        return;
    }
    if (std.mem.eql(u8, key, "signal_grpc")) {
        cfg.signal_grpc_spec = value;
        return;
    }
    if (std.mem.eql(u8, key, "management_grpc")) {
        cfg.management_grpc_spec = value;
        return;
    }
    if (std.mem.eql(u8, key, "signal_http")) {
        cfg.signal_http_spec = value;
        return;
    }
    if (std.mem.eql(u8, key, "management_http")) {
        cfg.management_http_spec = value;
        return;
    }
    if (std.mem.eql(u8, key, "relay_http")) {
        cfg.relay_http_spec = value;
        return;
    }
    if (std.mem.eql(u8, key, "dashboard_http")) {
        cfg.dashboard_http_spec = value;
        return;
    }
    if (std.mem.eql(u8, key, "zitadel_http")) {
        cfg.zitadel_http_spec = value;
        return;
    }

    return error.UnknownConfigKey;
}

fn parseConfigFile(
    cfg: *NetbirdProxyConfig,
    data: []const u8,
    saw_listen_port: *bool,
) !void {
    var line_iter = std.mem.splitScalar(u8, data, '\n');

    var line_count: u32 = 0;
    const max_lines: u32 = 1024;

    while (line_count < max_lines) : (line_count += 1) {
        const line = line_iter.next() orelse return;
        parseConfigLine(cfg, line, saw_listen_port) catch |err| {
            std.debug.print("config parse error line={d} err={s}\n", .{ line_count + 1, @errorName(err) });
            return err;
        };
    }

    return error.ConfigTooManyLines;
}

fn printUpstream(name: []const u8, upstream: serval.Upstream) void {
    const protocol = switch (upstream.http_protocol) {
        .h1 => if (upstream.tls) "https" else "http",
        .h2c => "h2c",
        .h2 => "h2",
    };

    std.debug.print("  {s: <18} {s}://{s}:{d} (idx={d})\n", .{
        name,
        protocol,
        upstream.host,
        upstream.port,
        upstream.idx,
    });
}

fn printRouteMatrix() void {
    std.debug.print("Route matrix (Caddy parity):\n", .{});
    std.debug.print("  /signalexchange.SignalExchange/*  -> signal_grpc (h2c/h2)\n", .{});
    std.debug.print("  /management.ManagementService/*   -> management_grpc (h2c/h2)\n", .{});
    std.debug.print("  /ws-proxy/signal*                 -> signal_http (websocket/http1)\n", .{});
    std.debug.print("  /ws-proxy/management*             -> management_http (websocket/http1)\n", .{});
    std.debug.print("  /relay*                           -> relay_http (websocket/http1)\n", .{});
    std.debug.print("  /api/*                            -> management_http\n", .{});
    std.debug.print("  Zitadel paths (/admin/v1,/auth/v1,/management/v1,/system/v1,/assets/v1,/ui,/oidc/v1,/saml/v2,/oauth/v2,/openapi,/debug,/device,/.well-known/openid-configuration,...) -> zitadel_http (h2c/h2)\n", .{});
    std.debug.print("  /*                                -> dashboard_http\n", .{});
}

pub fn main(process_init: std.process.Init) !void {
    var args = cli.Args(NetbirdExtra).init("netbird_proxy", VERSION, process_init.minimal.args);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    var cfg = NetbirdProxyConfig{};
    var saw_listen_port_in_file = false;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var config_file_data: ?[]u8 = null;
    defer if (config_file_data) |buf| allocator.free(buf);

    if (args.config_file) |path| {
        var file_io: std.Io.Threaded = .init(allocator, .{});
        defer file_io.deinit();

        const io = file_io.io();
        const data = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(MAX_CONFIG_SIZE_BYTES));
        config_file_data = data;
        try parseConfigFile(&cfg, data, &saw_listen_port_in_file);
    }

    if (args.extra.cert) |cert| cfg.cert_path = cert;
    if (args.extra.key) |key| cfg.key_path = key;

    if (args.extra.@"signal-grpc") |value| cfg.signal_grpc_spec = value;
    if (args.extra.@"management-grpc") |value| cfg.management_grpc_spec = value;
    if (args.extra.@"signal-http") |value| cfg.signal_http_spec = value;
    if (args.extra.@"management-http") |value| cfg.management_http_spec = value;
    if (args.extra.@"relay-http") |value| cfg.relay_http_spec = value;
    if (args.extra.@"dashboard-http") |value| cfg.dashboard_http_spec = value;
    if (args.extra.@"zitadel-http") |value| cfg.zitadel_http_spec = value;

    if (args.extra.@"insecure-skip-verify") {
        cfg.verify_upstream = false;
    }

    if (args.port != 8080 or !saw_listen_port_in_file) {
        cfg.listen_port = args.port;
    }

    if (cfg.cert_path == null or cfg.key_path == null) {
        std.debug.print("error: TLS frontend requires both --cert and --key (or cert_path/key_path in --config file)\n", .{});
        return error.MissingTlsCredentials;
    }

    const signal_grpc_idx: UpstreamIndex = 0;
    const management_grpc_idx: UpstreamIndex = 1;
    const signal_http_idx: UpstreamIndex = 2;
    const management_http_idx: UpstreamIndex = 3;
    const relay_http_idx: UpstreamIndex = 4;
    const zitadel_http_idx: UpstreamIndex = 5;
    const dashboard_http_idx: UpstreamIndex = 6;

    const upstreams = NetbirdUpstreams{
        .signal_grpc = try buildUpstream(cfg.signal_grpc_spec, signal_grpc_idx, .h2c, false),
        .management_grpc = try buildUpstream(cfg.management_grpc_spec, management_grpc_idx, .h2c, false),
        .signal_http = try buildUpstream(cfg.signal_http_spec, signal_http_idx, .h1, false),
        .management_http = try buildUpstream(cfg.management_http_spec, management_http_idx, .h1, false),
        .relay_http = try buildUpstream(cfg.relay_http_spec, relay_http_idx, .h1, false),
        .zitadel_http = try buildUpstream(cfg.zitadel_http_spec, zitadel_http_idx, .h2c, false),
        .dashboard_http = try buildUpstream(cfg.dashboard_http_spec, dashboard_http_idx, .h1, false),
    };

    try validateGrpcUpstream("signal_grpc", upstreams.signal_grpc);
    try validateGrpcUpstream("management_grpc", upstreams.management_grpc);
    try validateHttpUpstream("signal_http", upstreams.signal_http);
    try validateHttpUpstream("management_http", upstreams.management_http);
    try validateHttpUpstream("relay_http", upstreams.relay_http);
    try validateGrpcUpstream("zitadel_http", upstreams.zitadel_http);
    try validateHttpUpstream("dashboard_http", upstreams.dashboard_http);

    var upstream_client_ctx: ?*ssl.SSL_CTX = null;
    if (upstreams.anyTlsEnabled()) {
        ssl.init();
        const ctx = try ssl.createClientCtx();
        if (cfg.verify_upstream) {
            ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_PEER, null);
        } else {
            ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_NONE, null);
        }
        upstream_client_ctx = ctx;
    }
    defer if (upstream_client_ctx) |ctx| ssl.SSL_CTX_free(ctx);

    var handler = NetbirdProxyHandler{ .upstreams = upstreams };
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};

    var io_threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_threaded.deinit();

    var shutdown = std.atomic.Value(bool).init(false);

    const tls_config = serval.config.TlsConfig{
        .cert_path = cfg.cert_path.?,
        .key_path = cfg.key_path.?,
        .verify_upstream = cfg.verify_upstream,
    };

    std.debug.print("NetBird proxy listening on {s}:{d} (HTTPS)\n", .{ cfg.listen_host, cfg.listen_port });
    std.debug.print("TLS cert: {s}\n", .{cfg.cert_path.?});
    std.debug.print("TLS key:  {s}\n", .{cfg.key_path.?});
    std.debug.print("Upstream verify: {}\n", .{cfg.verify_upstream});
    std.debug.print("TLS h2 frontend mode: {s}\n", .{@tagName(cfg.tls_h2_frontend_mode)});
    std.debug.print("ALPN mixed-offer policy: {s}\n", .{@tagName(cfg.alpn_mixed_offer_policy)});
    std.debug.print("Upstreams:\n", .{});
    printUpstream("signal_grpc", upstreams.signal_grpc);
    printUpstream("management_grpc", upstreams.management_grpc);
    printUpstream("signal_http", upstreams.signal_http);
    printUpstream("management_http", upstreams.management_http);
    printUpstream("relay_http", upstreams.relay_http);
    printUpstream("zitadel_http", upstreams.zitadel_http);
    printUpstream("dashboard_http", upstreams.dashboard_http);
    printRouteMatrix();

    const ServerType = serval.Server(
        NetbirdProxyHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    var server = ServerType.init(
        &handler,
        &pool,
        &metrics,
        &tracer,
        .{
            .listen_host = cfg.listen_host,
            .port = cfg.listen_port,
            .tls = tls_config,
            .tls_h2_frontend_mode = cfg.tls_h2_frontend_mode,
            .alpn_mixed_offer_policy = cfg.alpn_mixed_offer_policy,
        },
        upstream_client_ctx,
        serval.net.DnsConfig{},
    );

    try server.run(io_threaded.io(), &shutdown, null);
}

test "parseTlsH2FrontendMode supports all valid values" {
    try std.testing.expectEqual(serval.config.TlsH2FrontendMode.disabled, try parseTlsH2FrontendMode("disabled"));
    try std.testing.expectEqual(serval.config.TlsH2FrontendMode.terminated_only, try parseTlsH2FrontendMode("terminated_only"));
    try std.testing.expectEqual(serval.config.TlsH2FrontendMode.generic, try parseTlsH2FrontendMode("generic"));
    try std.testing.expectError(error.InvalidTlsH2FrontendMode, parseTlsH2FrontendMode("unknown"));
}

test "parseAlpnMixedOfferPolicy supports all valid values" {
    try std.testing.expectEqual(serval.config.AlpnMixedOfferPolicy.prefer_http11, try parseAlpnMixedOfferPolicy("prefer_http11"));
    try std.testing.expectEqual(serval.config.AlpnMixedOfferPolicy.prefer_h2, try parseAlpnMixedOfferPolicy("prefer_h2"));
    try std.testing.expectEqual(serval.config.AlpnMixedOfferPolicy.http11_only, try parseAlpnMixedOfferPolicy("http11_only"));
    try std.testing.expectError(error.InvalidAlpnMixedOfferPolicy, parseAlpnMixedOfferPolicy("invalid"));
}

test "parseConfigLine parses ALPN and frontend h2 policy keys" {
    var cfg = NetbirdProxyConfig{};
    var saw_listen_port = false;

    try parseConfigLine(&cfg, "tls_h2_frontend_mode=generic", &saw_listen_port);
    try std.testing.expectEqual(serval.config.TlsH2FrontendMode.generic, cfg.tls_h2_frontend_mode);

    try parseConfigLine(&cfg, "alpn_mixed_offer_policy=prefer_h2", &saw_listen_port);
    try std.testing.expectEqual(serval.config.AlpnMixedOfferPolicy.prefer_h2, cfg.alpn_mixed_offer_policy);
}

test "parseListenHost validates non-empty value" {
    try std.testing.expectEqualStrings("::", try parseListenHost("::"));
    try std.testing.expectEqualStrings("0.0.0.0", try parseListenHost(" 0.0.0.0 "));
    try std.testing.expectError(error.InvalidListenHost, parseListenHost("   "));
}

test "parseConfigLine parses listen_host" {
    var cfg = NetbirdProxyConfig{};
    var saw_listen_port = false;

    try parseConfigLine(&cfg, "listen_host=::", &saw_listen_port);
    try std.testing.expectEqualStrings("::", cfg.listen_host);
    try std.testing.expect(!saw_listen_port);
}

test "resolveRouteRole keeps caddy-compatible zitadel paths on zitadel_http" {
    const cases = [_]struct {
        path: []const u8,
        expected: UpstreamRole,
    }{
        .{ .path = "/admin/v1/projects", .expected = .zitadel_http },
        .{ .path = "/auth/v1/login", .expected = .zitadel_http },
        .{ .path = "/management/v1/users", .expected = .zitadel_http },
        .{ .path = "/system/v1/healthz", .expected = .zitadel_http },
        .{ .path = "/assets/v1/static/logo.svg", .expected = .zitadel_http },
        .{ .path = "/saml/v2/metadata", .expected = .zitadel_http },
        .{ .path = "/oidc/v1/authorize", .expected = .zitadel_http },
        .{ .path = "/oauth/v2/token", .expected = .zitadel_http },
        .{ .path = "/.well-known/openid-configuration", .expected = .zitadel_http },
        .{ .path = "/openapi/spec", .expected = .zitadel_http },
        .{ .path = "/debug/events", .expected = .zitadel_http },
        .{ .path = "/device", .expected = .zitadel_http },
        .{ .path = "/device/authorize", .expected = .zitadel_http },
        .{ .path = "/zitadel.user.v2.UserService/GetUserByID", .expected = .zitadel_http },
        .{ .path = "/.well-known/other", .expected = .dashboard_http },
        .{ .path = "/oauth2/token", .expected = .dashboard_http },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expected, resolveRouteRole(case.path));
    }
}
