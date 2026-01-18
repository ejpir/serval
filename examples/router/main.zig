// examples/router/main.zig
//! Content-Based Router with Atomic Config Swap
//!
//! Production-ready HTTP router with hot config reload via admin API.
//! Routes requests to different backend pools based on path prefix matching.
//!
//! ## Features
//!
//! - Double-buffered router storage for atomic configuration updates
//! - Admin API for health checks and runtime config updates
//! - Per-pool load balancing with health tracking
//! - Path prefix stripping for API gateway patterns
//!
//! ## Usage
//!
//!   router [OPTIONS]
//!
//! ## Options
//!
//!   --port <PORT>                Listening port (default: 8080)
//!   --admin-port <PORT>          Admin API port (default: 9901)
//!   --api-backends <HOSTS>       Comma-separated API backend addresses (default: 127.0.0.1:8001)
//!   --static-backends <HOSTS>    Comma-separated static backend addresses (default: 127.0.0.1:8002)
//!   --controller-mode            Start without config, wait for controller push via /routes/update
//!   --trace                      Enable OpenTelemetry tracing
//!   --otel-endpoint <URL>        OTLP collector endpoint (default: http://localhost:4318/v1/traces)
//!   --debug                      Enable debug logging
//!   --help                       Show help message
//!   --version                    Show version

const std = @import("std");
const log = serval.core.log.scoped(.router_example);
const serval = @import("serval");
const serval_router = @import("serval-router");
const serval_net = @import("serval-net");
const cli = @import("serval-cli");
const otel = @import("serval-otel");

// Local modules
const config_storage = @import("config_storage.zig");
const handler = @import("handler.zig");
const backends = @import("backends.zig");
const admin = @import("admin/mod.zig");

const Route = serval_router.Route;
const PoolConfig = serval_router.PoolConfig;
const Upstream = serval_router.Upstream;
const DnsConfig = serval_net.DnsConfig;
const RouterHandler = handler.RouterHandler;

/// Version of this binary.
const VERSION = "0.1.0";

/// Router-specific CLI options.
const RouterExtra = struct {
    /// Comma-separated list of API backend addresses (host:port,host:port,...)
    @"api-backends": []const u8 = "127.0.0.1:8001",
    /// Comma-separated list of static backend addresses (host:port,host:port,...)
    @"static-backends": []const u8 = "127.0.0.1:8002",
    /// Admin API port for health checks and configuration.
    @"admin-port": u16 = 9901,
    /// Start without config, wait for controller to push via /routes/update.
    /// Router will return 503 on /readyz until first config is received.
    @"controller-mode": bool = false,
    /// Enable OpenTelemetry tracing (requires collector at otel-endpoint)
    trace: bool = false,
    /// OTLP collector endpoint for trace export
    @"otel-endpoint": []const u8 = "http://localhost:4318/v1/traces",
};

/// Admin server thread entry point.
fn runAdminServer(
    admin_server: anytype,
    io: std.Io,
    shutdown: *std.atomic.Value(bool),
) void {
    admin_server.run(io, shutdown, null) catch |err| {
        log.err("Admin server error: {}", .{err});
    };
}

/// Run both admin and main servers with the given tracer.
/// TigerStyle: Generic function to avoid code duplication between tracer modes.
/// Admin server always uses NoopTracer to avoid tracing internal health checks.
fn runServers(
    comptime Tracer: type,
    tracer: *Tracer,
    router_handler: *RouterHandler,
    main_port: u16,
    admin_port: u16,
    io: std.Io,
    shutdown: *std.atomic.Value(bool),
) !void {
    // Admin server always uses NoopTracer - no need to trace health checks and config updates
    const AdminHandlerType = admin.AdminHandler(serval.NoopTracer);
    const AdminServerType = serval.Server(
        AdminHandlerType,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    const RouterServerType = serval.Server(
        RouterHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        Tracer,
    );

    // Initialize admin handler and server with NoopTracer
    var admin_noop_tracer = serval.NoopTracer{};
    var admin_handler = AdminHandlerType.init(&admin_noop_tracer);
    var admin_pool = serval.SimplePool.init();
    var admin_metrics = serval.NoopMetrics{};
    var admin_server = AdminServerType.init(&admin_handler, &admin_pool, &admin_metrics, &admin_noop_tracer, .{
        .port = admin_port,
        .tls = null,
    }, null, DnsConfig{});

    // Start admin server in separate thread
    const admin_thread = std.Thread.spawn(.{}, runAdminServer, .{
        &admin_server,
        io,
        shutdown,
    }) catch |err| {
        std.debug.print("Failed to start admin server: {s}\n", .{@errorName(err)});
        return error.AdminServerFailed;
    };
    defer {
        shutdown.store(true, .release);
        admin_thread.join();
    }

    // Initialize main server resources
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var server = RouterServerType.init(router_handler, &pool, &metrics, tracer, .{
        .port = main_port,
        .tls = null,
    }, null, DnsConfig{});

    server.run(io, shutdown, null) catch |err| {
        std.debug.print("Server error: {}\n", .{err});
        return;
    };
}

pub fn main() !void {
    // Parse command-line arguments
    var args = cli.Args(RouterExtra).init("router", VERSION);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Parse API backends
    var api_upstreams_buf: [backends.MAX_UPSTREAMS_PER_POOL]Upstream = std.mem.zeroes([backends.MAX_UPSTREAMS_PER_POOL]Upstream);
    const api_count = backends.parseBackends(args.extra.@"api-backends", &api_upstreams_buf, 0);

    if (api_count == 0) {
        std.debug.print("Error: no valid API backends specified\n", .{});
        return error.NoBackends;
    }

    const api_upstreams = api_upstreams_buf[0..api_count];

    // Parse static backends with idx continuing from api_count
    var static_upstreams_buf: [backends.MAX_UPSTREAMS_PER_POOL]Upstream = std.mem.zeroes([backends.MAX_UPSTREAMS_PER_POOL]Upstream);
    const static_count = backends.parseBackends(args.extra.@"static-backends", &static_upstreams_buf, api_count);

    if (static_count == 0) {
        std.debug.print("Error: no valid static backends specified\n", .{});
        return error.NoBackends;
    }

    const static_upstreams = static_upstreams_buf[0..static_count];

    // Pool indices
    const API_POOL: u8 = 0;
    const STATIC_POOL: u8 = 1;

    // Define routes
    // TigerStyle: Routes are evaluated in order, first match wins.
    // Unmatched requests return 404 Not Found.
    const routes = [_]Route{
        // /api/* -> api-pool (strip prefix so /api/users becomes /users)
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = API_POOL,
            .strip_prefix = true,
        },
        // /static/* -> static-pool (strip prefix so /static/image.png becomes /image.png)
        .{
            .name = "static",
            .matcher = .{ .path = .{ .prefix = "/static/" } },
            .pool_idx = STATIC_POOL,
            .strip_prefix = true,
        },
    };

    // Pool configurations
    // TigerStyle: Disable probing for simplicity in this example
    const pool_configs = [_]PoolConfig{
        .{
            .name = "api-pool",
            .upstreams = api_upstreams,
            .lb_config = .{ .enable_probing = false },
        },
        .{
            .name = "static-pool",
            .upstreams = static_upstreams,
            .lb_config = .{ .enable_probing = false },
        },
    };

    // Initialize router in slot 0 of double-buffered storage.
    // TigerStyle: dns_resolver is null since probing is disabled for all pools.
    // Empty allowed_hosts means accept any host.
    // In controller-mode, skip init - wait for controller to push config via /routes/update.
    if (!args.extra.@"controller-mode") {
        try config_storage.initRouter(&routes, &pool_configs, &.{}, null);

        // S2: Postcondition - router must be available after init (only in normal mode)
        if (config_storage.getActiveRouter() == null) {
            std.debug.print("Error: router initialization failed\n", .{});
            return error.RouterInitFailed;
        }
    }
    defer config_storage.deinitAllRouters();

    // Initialize async IO runtime
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    // Initialize router handler
    var router_handler = RouterHandler{};

    // Print startup info (before creating servers so it's visible regardless of tracing mode)
    std.debug.print("Router listening on :{d}\n", .{args.port});
    std.debug.print("Admin API listening on :{d}\n", .{args.extra.@"admin-port"});
    std.debug.print("  GET /healthz          - liveness probe\n", .{});
    std.debug.print("  GET /readyz           - readiness probe\n", .{});
    std.debug.print("  GET /routes           - current routes as JSON\n", .{});
    std.debug.print("  POST /routes/update   - full config replacement\n", .{});
    std.debug.print("  POST /routes/add      - add a single route\n", .{});
    std.debug.print("  POST /routes/remove   - remove route by name\n", .{});
    std.debug.print("  POST /pools/add       - add a new pool\n", .{});
    std.debug.print("  POST /pools/remove    - remove pool by name\n", .{});
    std.debug.print("  POST /upstreams/add   - add upstream to pool\n", .{});
    std.debug.print("  POST /upstreams/remove - remove upstream from pool\n", .{});

    if (args.extra.@"controller-mode") {
        std.debug.print("Controller mode: ENABLED\n", .{});
        std.debug.print("  Waiting for controller to push config via POST /routes/update\n", .{});
        std.debug.print("  /readyz will return 503 until config is received\n", .{});
    } else {
        std.debug.print("Routes:\n", .{});
        std.debug.print("  /api/* -> api-pool (strip prefix) ", .{});
        backends.formatUpstreams(api_upstreams);
        std.debug.print("\n", .{});
        std.debug.print("  /static/* -> static-pool (strip prefix) ", .{});
        backends.formatUpstreams(static_upstreams);
        std.debug.print("\n", .{});
        std.debug.print("  (other paths) -> 404 Not Found\n", .{});
        std.debug.print("Config generation: {d}\n", .{config_storage.getRouterGeneration()});
    }
    std.debug.print("Tracing: {s}\n", .{if (args.extra.trace) args.extra.@"otel-endpoint" else "disabled"});
    std.debug.print("Debug logging: {}\n", .{args.debug});

    // Run servers with appropriate tracer type.
    if (args.extra.trace) {
        // OpenTelemetry tracing enabled
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var otel_exporter = try otel.OTLPExporter.init(allocator, .{
            .endpoint = args.extra.@"otel-endpoint",
            .service_name = "serval-router",
            .service_version = VERSION,
        });
        defer otel_exporter.deinit();

        var otel_processor = try otel.BatchingProcessor.init(allocator, otel_exporter.asSpanExporter(), .{
            .scheduled_delay_ms = 5000,
            .max_export_batch_size = 512,
        });
        defer otel_processor.deinit();
        defer otel_processor.shutdown();

        // TigerStyle: OtelTracer is ~240KB, requires heap allocation.
        const otel_tracer = try otel.OtelTracer.create(
            allocator,
            otel_processor.asSpanProcessor(),
            "serval-router",
            VERSION,
        );
        defer otel_tracer.destroy(allocator);

        try runServers(otel.OtelTracer, otel_tracer, &router_handler, args.port, args.extra.@"admin-port", io, &shutdown);
    } else {
        // No tracing (default)
        var noop_tracer = serval.NoopTracer{};
        try runServers(serval.NoopTracer, &noop_tracer, &router_handler, args.port, args.extra.@"admin-port", io, &shutdown);
    }
}
