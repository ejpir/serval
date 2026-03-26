//! Reverseproxy product runtime API.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const server_mod = @import("serval-server");
const net = @import("serval-net");
const router_mod = @import("serval-router");
const dsl = @import("dsl.zig");
const ir = @import("ir.zig");
const orchestrator = @import("orchestrator.zig");
const certs = @import("certs/mod.zig");
const components = @import("components.zig");

const DnsConfig = net.DnsConfig;

pub const LoadOptions = struct {
    config_file: []const u8,
};

pub const RunOptions = struct {
    port: ?u16 = null,
};

pub const Runtime = struct {
    io_threaded: std.Io.Threaded,
    dsl_source: []u8,
    parsed_dsl: dsl.ParsedDsl,
    orchestrator_state: orchestrator.Orchestrator,
    route_storage: [core.config.MAX_ROUTES]router_mod.Route,
    route_count: u32,
    pool_upstream_storage: [core.config.MAX_POOLS]core.Upstream,
    pool_count: u32,

    pub fn deinit(self: *Runtime) void {
        assert(@intFromPtr(self) != 0);
        std.heap.page_allocator.free(self.dsl_source);
        self.io_threaded.deinit();
    }

    pub fn run(self: *Runtime, options: RunOptions) !void {
        assert(@intFromPtr(self) != 0);

        var candidate = self.parsed_dsl.toCanonicalIr();
        var snapshot = orchestrator.RuntimeSnapshot.fromCanonicalIr(&candidate, 1, 100);
        try self.orchestrator_state.admitAndActivate(&candidate, &snapshot, 200);

        const active_listener_id = try defaultListenerId(&candidate);
        try buildRouterArtifacts(
            &candidate,
            active_listener_id,
            &self.route_storage,
            &self.route_count,
            &self.pool_upstream_storage,
            &self.pool_count,
        );
        assert(self.pool_count > 0);
        assert(self.route_count > 0);

        const listen_port = options.port orelse try listenerPortFromCandidate(&candidate);
        if (listen_port == 0) return error.InvalidListenerPort;

        var pool_configs: [core.config.MAX_POOLS]router_mod.PoolConfig = undefined;
        var pool_index: u32 = 0;
        while (pool_index < self.pool_count) : (pool_index += 1) {
            const idx: usize = @intCast(pool_index);
            pool_configs[idx] = .{
                .name = self.parsed_dsl.pools[idx].id,
                .upstreams = self.pool_upstream_storage[idx .. idx + 1],
                .lb_config = .{ .enable_probing = false },
            };
        }

        var router: router_mod.Router = undefined;
        try router.init(
            self.route_storage[0..self.route_count],
            pool_configs[0..self.pool_count],
            &.{},
            null,
            null,
        );
        defer router.deinit();

        var handler = ProxyHandler{ .router = &router, .default_upstream = self.pool_upstream_storage[0] };

        const active_listener = try findListenerById(&candidate, active_listener_id);

        var maybe_static_provider: ?certs.StaticProvider = null;
        var maybe_selfsigned_provider: ?certs.SelfSignedProvider = null;
        var maybe_acme_provider: ?certs.AcmeProvider = null;

        var server_tls_config: ?core.config.TlsConfig = null;
        if (active_listener.tls) |tls_cfg| {
            switch (tls_cfg.provider) {
                .static => {
                    maybe_static_provider = try certs.StaticProvider.init(tls_cfg.static orelse return error.InvalidListenerTls);
                    const initial = maybe_static_provider.?.loadInitial();
                    server_tls_config = .{ .cert_path = initial.cert_path, .key_path = initial.key_path };
                },
                .selfsigned => {
                    maybe_selfsigned_provider = try certs.SelfSignedProvider.init(tls_cfg.selfsigned orelse return error.InvalidListenerTls, active_listener.id);
                    const initial = try maybe_selfsigned_provider.?.loadInitial(self.io_threaded.io());
                    server_tls_config = .{ .cert_path = initial.cert_path, .key_path = initial.key_path };
                },
                .acme => {
                    maybe_acme_provider = try certs.AcmeProvider.init(tls_cfg.acme orelse return error.InvalidListenerTls, active_listener.id);
                    const initial = try maybe_acme_provider.?.loadInitial(self.io_threaded.io());
                    server_tls_config = .{ .cert_path = initial.cert_path, .key_path = initial.key_path };
                },
            }
        }

        defer if (maybe_static_provider) |*static_provider| static_provider.deinit();
        defer if (maybe_selfsigned_provider) |*selfsigned_provider| selfsigned_provider.deinit();
        defer if (maybe_acme_provider) |*acme_provider| acme_provider.deinit();

        var runtime_pool = components.RuntimePool.init(self.parsed_dsl.component_pool_kind);
        var runtime_metrics = components.RuntimeMetrics.init(self.parsed_dsl.component_metrics_kind);
        var runtime_tracer = try components.RuntimeTracer.init(self.parsed_dsl.component_tracer_kind, .{
            .endpoint = self.parsed_dsl.component_tracing_otel_endpoint,
            .service_name = self.parsed_dsl.component_tracing_otel_service_name,
            .service_version = self.parsed_dsl.component_tracing_otel_service_version,
            .scope_name = self.parsed_dsl.component_tracing_otel_scope_name,
            .scope_version = self.parsed_dsl.component_tracing_otel_scope_version,
        });
        defer runtime_tracer.deinit();
        var shutdown = std.atomic.Value(bool).init(false);

        const ServerType = server_mod.Server(ProxyHandler, components.RuntimePool, components.RuntimeMetrics, components.RuntimeTracer);
        var server = ServerType.init(&handler, &runtime_pool, &runtime_metrics, &runtime_tracer, .{
            .port = listen_port,
            .tls = server_tls_config,
        }, null, DnsConfig{});

        const ReloadCtx = struct {
            server: *ServerType,

            fn activate(ctx_raw: *anyopaque, cert_path: []const u8, key_path: []const u8) certs.ActivationResult {
                const ctx: *@This() = @ptrCast(@alignCast(ctx_raw));
                _ = ctx.server.reloadServerTlsFromPemFiles(cert_path, key_path) catch |err| {
                    std.log.err("reverseproxy-acme: tls reload failed err={s}", .{@errorName(err)});
                    return .transient_failure;
                };
                return .success;
            }
        };

        const AcmeRunCtx = struct {
            provider: *certs.AcmeProvider,
            shutdown: *std.atomic.Value(bool),
            activate_ctx: *anyopaque,
            activate_fn: certs.ActivateFn,

            fn run(ctx: *@This()) void {
                ctx.provider.run(ctx.shutdown, ctx.activate_ctx, ctx.activate_fn) catch |err| {
                    if (ctx.shutdown.load(.acquire)) return;
                    std.log.err("reverseproxy-acme: provider exited err={s}", .{@errorName(err)});
                };
            }
        };

        var maybe_reload_ctx: ?ReloadCtx = null;
        var maybe_acme_run_ctx: ?AcmeRunCtx = null;
        var maybe_acme_thread: ?std.Thread = null;
        defer if (maybe_acme_thread) |thread| thread.join();

        if (maybe_acme_provider) |*acme_provider| {
            maybe_reload_ctx = .{ .server = &server };
            maybe_acme_run_ctx = .{
                .provider = acme_provider,
                .shutdown = &shutdown,
                .activate_ctx = @ptrCast(&maybe_reload_ctx.?),
                .activate_fn = ReloadCtx.activate,
            };
            maybe_acme_thread = try std.Thread.spawn(.{}, AcmeRunCtx.run, .{&maybe_acme_run_ctx.?});
        }

        std.debug.print("reverseproxy runtime listening on :{d}\n", .{listen_port});
        try server.run(self.io_threaded.io(), &shutdown, null);
    }
};

const ProxyHandler = struct {
    router: *router_mod.Router,
    default_upstream: core.Upstream,

    pub fn onRequest(self: *@This(), ctx: *core.Context, request: *core.Request, response_buf: []u8) core.Action {
        assert(response_buf.len >= 16);

        const router_action = self.router.selectUpstream(ctx, request);
        switch (router_action) {
            .forward => |upstream| {
                ctx.upstream = upstream;
                return .continue_request;
            },
            .reject => |rej| {
                const body = writeStaticBody(response_buf, rej.body);
                return .{ .send_response = .{ .status = rej.status, .body = body, .content_type = "text/plain" } };
            },
        }
    }

    pub fn selectUpstream(self: *@This(), ctx: *core.Context, request: *const core.Request) core.Upstream {
        _ = request;
        return ctx.upstream orelse self.default_upstream;
    }
};

pub fn load(options: LoadOptions) !Runtime {
    assert(options.config_file.len > 0);

    var io_threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    errdefer io_threaded.deinit();
    const io = io_threaded.io();

    const dsl_source = try std.Io.Dir.cwd().readFileAlloc(io, options.config_file, std.heap.page_allocator, .limited(64 * 1024));
    errdefer std.heap.page_allocator.free(dsl_source);

    const parsed = try dsl.parse(dsl_source);
    var candidate = parsed.toCanonicalIr();

    var diagnostics: [ir.MAX_VALIDATION_DIAGNOSTICS]ir.ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;
    try ir.validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count);
    if (diagnostics_count > 0) return error.InvalidCanonicalIr;

    var runtime = Runtime{
        .io_threaded = io_threaded,
        .dsl_source = dsl_source,
        .parsed_dsl = parsed,
        .orchestrator_state = orchestrator.Orchestrator.init(5 * std.time.ns_per_s),
        .route_storage = undefined,
        .route_count = 0,
        .pool_upstream_storage = undefined,
        .pool_count = 0,
    };

    const active_listener_id = try defaultListenerId(&candidate);
    try buildRouterArtifacts(
        &candidate,
        active_listener_id,
        &runtime.route_storage,
        &runtime.route_count,
        &runtime.pool_upstream_storage,
        &runtime.pool_count,
    );

    return runtime;
}

fn buildRouterArtifacts(
    candidate: *const ir.CanonicalIr,
    active_listener_id: []const u8,
    route_storage: *[core.config.MAX_ROUTES]router_mod.Route,
    route_count: *u32,
    pool_upstream_storage: *[core.config.MAX_POOLS]core.Upstream,
    pool_count: *u32,
) !void {
    assert(@intFromPtr(candidate) != 0);
    assert(active_listener_id.len > 0);
    assert(@intFromPtr(route_storage) != 0);
    assert(@intFromPtr(route_count) != 0);
    assert(@intFromPtr(pool_upstream_storage) != 0);
    assert(@intFromPtr(pool_count) != 0);

    if (candidate.pools.len == 0) return error.MissingPoolUpstreamSpec;
    if (candidate.routes.len == 0) return error.MissingRoutes;

    var pool_index: usize = 0;
    while (pool_index < candidate.pools.len) : (pool_index += 1) {
        if (pool_index >= pool_upstream_storage.len) return error.TooManyPoolMappings;

        const pool = candidate.pools[pool_index];
        const upstream_spec = pool.upstream_spec orelse return error.MissingPoolUpstreamSpec;

        pool_upstream_storage[pool_index] = try parseUpstreamSpec(upstream_spec, @intCast(pool_index));
    }

    var route_index: usize = 0;
    var selected_route_count: u32 = 0;
    while (route_index < candidate.routes.len) : (route_index += 1) {
        const route = candidate.routes[route_index];
        if (!std.mem.eql(u8, route.listener_id, active_listener_id)) continue;

        const write_index: usize = @intCast(selected_route_count);
        if (write_index >= route_storage.len) return error.TooManyRoutes;

        const pool_idx = try findPoolIndex(candidate.pools, route.pool_id);

        route_storage[write_index] = .{
            .name = route.id,
            .matcher = .{
                .host = normalizeHostForRouter(route.host),
                .path = .{ .prefix = route.path_prefix },
            },
            .pool_idx = pool_idx,
            .strip_prefix = false,
        };
        selected_route_count += 1;
    }

    if (selected_route_count == 0) return error.MissingRoutes;

    route_count.* = selected_route_count;
    pool_count.* = @intCast(candidate.pools.len);
}

fn findListenerById(candidate: *const ir.CanonicalIr, listener_id: []const u8) !*const ir.Listener {
    assert(@intFromPtr(candidate) != 0);
    assert(listener_id.len > 0);

    var listener_index: usize = 0;
    while (listener_index < candidate.listeners.len) : (listener_index += 1) {
        if (std.mem.eql(u8, candidate.listeners[listener_index].id, listener_id)) return &candidate.listeners[listener_index];
    }

    return error.MissingListener;
}

fn findPoolIndex(pools: []const ir.Pool, pool_id: []const u8) !u8 {
    var pool_index: usize = 0;
    while (pool_index < pools.len) : (pool_index += 1) {
        if (std.mem.eql(u8, pools[pool_index].id, pool_id)) return @intCast(pool_index);
    }
    return error.MissingPoolReference;
}

fn normalizeHostForRouter(host: []const u8) []const u8 {
    assert(host.len > 0);
    const colon_index = std.mem.indexOfScalar(u8, host, ':') orelse return host;
    if (colon_index == 0) return host;
    return host[0..colon_index];
}

fn parseUpstreamSpec(spec: []const u8, idx: core.config.UpstreamIndex) !core.Upstream {
    assert(spec.len > 0);

    const Parsed = struct {
        host_port: []const u8,
        tls_enabled: bool,
        protocol: core.HttpProtocol,
    };

    const parsed: Parsed = if (std.mem.startsWith(u8, spec, "http://"))
        .{ .host_port = spec["http://".len..], .tls_enabled = false, .protocol = .h1 }
    else if (std.mem.startsWith(u8, spec, "https://"))
        .{ .host_port = spec["https://".len..], .tls_enabled = true, .protocol = .h1 }
    else if (std.mem.startsWith(u8, spec, "h2c://"))
        .{ .host_port = spec["h2c://".len..], .tls_enabled = false, .protocol = .h2c }
    else if (std.mem.startsWith(u8, spec, "h2://"))
        .{ .host_port = spec["h2://".len..], .tls_enabled = true, .protocol = .h2 }
    else
        return error.InvalidUpstreamScheme;

    const colon_index = std.mem.lastIndexOfScalar(u8, parsed.host_port, ':') orelse return error.InvalidUpstreamAddress;
    if (colon_index == 0 or colon_index + 1 >= parsed.host_port.len) return error.InvalidUpstreamAddress;

    const host = parsed.host_port[0..colon_index];
    const port_raw = parsed.host_port[colon_index + 1 ..];
    const port = std.fmt.parseInt(u16, port_raw, 10) catch return error.InvalidUpstreamAddress;
    if (host.len == 0 or port == 0) return error.InvalidUpstreamAddress;

    return .{ .host = host, .port = port, .idx = idx, .tls = parsed.tls_enabled, .http_protocol = parsed.protocol };
}

fn defaultListenerId(candidate: *const ir.CanonicalIr) ![]const u8 {
    assert(@intFromPtr(candidate) != 0);
    if (candidate.listeners.len == 0) return error.MissingListener;
    if (candidate.listeners[0].id.len == 0) return error.InvalidListenerId;
    return candidate.listeners[0].id;
}

fn listenerPortFromCandidate(candidate: *const ir.CanonicalIr) !u16 {
    assert(@intFromPtr(candidate) != 0);
    if (candidate.listeners.len == 0) return error.MissingListener;

    const bind = candidate.listeners[0].bind;
    const colon_index = std.mem.lastIndexOfScalar(u8, bind, ':') orelse return error.InvalidListenerBind;
    if (colon_index + 1 >= bind.len) return error.InvalidListenerBind;

    const port_raw = bind[colon_index + 1 ..];
    const port = std.fmt.parseInt(u16, port_raw, 10) catch return error.InvalidListenerBind;
    if (port == 0) return error.InvalidListenerBind;
    return port;
}

fn writeStaticBody(response_buf: []u8, body: []const u8) []const u8 {
    assert(body.len <= response_buf.len);
    @memcpy(response_buf[0..body.len], body);
    return response_buf[0..body.len];
}

test "load parses config and derives listener/pool upstreams" {
    const path = "serval-reverseproxy/runtime_test.dsl";
    const source =
        \\listener l1 0.0.0.0:19090
        \\pool p1 upstream=http://127.0.0.1:18001
        \\plugin plug fail_policy=fail_closed
        \\chain c1 plugin=plug
        \\route r1 listener=l1 host=127.0.0.1:19090 path=/ pool=p1 chain=c1
    ;
    try std.Io.Dir.cwd().writeFile(std.Options.debug_io, .{ .sub_path = path, .data = source });
    defer {
        std.Io.Dir.cwd().deleteFile(std.Options.debug_io, path) catch |err| {
            if (err != error.FileNotFound) {
                std.debug.print("warn: cleanup failed for {s}: {s}\n", .{ path, @errorName(err) });
            }
        };
    }

    var runtime = try load(.{ .config_file = path });
    defer runtime.deinit();

    try std.testing.expectEqual(@as(u32, 1), runtime.pool_count);
    try std.testing.expectEqual(@as(u16, 18001), runtime.pool_upstream_storage[0].port);
}
