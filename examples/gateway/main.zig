//! Kubernetes Gateway API Controller
//!
//! Complete controller implementation that:
//! - Watches K8s Gateway API resources (Gateway, HTTPRoute)
//! - Translates to serval-router configuration
//! - Pushes config to data plane via admin API
//! - Runs admin HTTP server for K8s health probes (/healthz, /readyz)
//!
//! Usage:
//!   gateway [OPTIONS]
//!
//! Options:
//!   --admin-port <PORT>       Admin API port for health probes (default: 8080)
//!   --data-plane-host <HOST>  Data plane hostname (default: "serval-router")
//!   --data-plane-port <PORT>  Data plane admin port for config updates (default: 9901)
//!   --api-server <URL>        K8s API server (for out-of-cluster)
//!   --api-port <PORT>         K8s API port (default: 443)
//!   --token <TOKEN>           Bearer token for K8s API
//!   --namespace <NS>          Namespace to watch (default: "default")
//!   --controller-name <NAME>  Controller name for GatewayClass filtering
//!                             (default: "serval.dev/gateway-controller")
//!
//! TigerStyle Y1: Functions under 70 lines, extracted helpers.

const std = @import("std");
const Io = std.Io;
const time = @import("serval-core").time;
const gateway = @import("serval-k8s-gateway");
const gw_config = gateway.config;
const serval_server = @import("serval-server");
const serval_net = @import("serval-net");
const serval_pool = @import("serval-pool");
const serval_metrics = @import("serval-metrics");
const serval_tracing = @import("serval-tracing");

const controller_mod = @import("controller/mod.zig");
const Controller = controller_mod.Controller;
const AdminHandler = controller_mod.admin.AdminHandler;
const k8s_client_mod = @import("k8s_client/mod.zig");
const K8sClient = k8s_client_mod.Client;
const Watcher = @import("watcher/mod.zig").Watcher;

/// Version
const VERSION = "0.1.0";

/// CLI configuration parsed from command line arguments.
/// TigerStyle: Explicit struct with named fields.
const CliConfig = struct {
    /// Gateway controller's admin port for health probes (/healthz, /readyz).
    /// Different from data_plane_port to avoid conflict.
    admin_port: u16 = 8080,
    /// Trailing dot makes this an explicit FQDN, preventing search domain appending
    data_plane_host: []const u8 = "serval-router.default.svc.cluster.local.",
    /// Data plane admin port where router_example listens for config updates.
    data_plane_port: u16 = 9901,
    api_server: ?[]const u8 = null,
    api_port: u16 = 443,
    token: ?[]const u8 = null,
    namespace: []const u8 = "default",
    /// Controller name for GatewayClass filtering.
    /// Only Gateways referencing GatewayClasses with this controllerName are managed.
    controller_name: []const u8 = "serval.dev/gateway-controller",
    /// Router service name for multi-endpoint discovery (enables HA mode).
    /// When set, discovers all router pod IPs via EndpointSlice and pushes to all.
    router_service: ?[]const u8 = null,
    /// Router service namespace for multi-endpoint discovery.
    router_namespace: []const u8 = "default",
};

/// Maximum number of CLI arguments to process.
/// TigerStyle: Bounded iteration.
const MAX_CLI_ARGS: u32 = 32;

/// Parse command line arguments into CliConfig.
/// TigerStyle: Bounded iteration, explicit defaults.
fn parseArgs() CliConfig {
    var config = CliConfig{};
    var args = std.process.args();
    std.debug.assert(config.admin_port > 0); // S1: postcondition - valid default port
    std.debug.assert(config.data_plane_port > 0); // S1: postcondition - valid default port

    // Skip program name
    _ = args.skip();

    var iteration: u32 = 0;
    while (iteration < MAX_CLI_ARGS) : (iteration += 1) {
        const arg = args.next() orelse break;

        if (std.mem.eql(u8, arg, "--admin-port")) {
            if (args.next()) |val| {
                config.admin_port = std.fmt.parseInt(u16, val, 10) catch 8080;
            }
        } else if (std.mem.eql(u8, arg, "--data-plane-host")) {
            if (args.next()) |val| {
                config.data_plane_host = val;
            }
        } else if (std.mem.eql(u8, arg, "--data-plane-port")) {
            if (args.next()) |val| {
                config.data_plane_port = std.fmt.parseInt(u16, val, 10) catch 9901;
            }
        } else if (std.mem.eql(u8, arg, "--api-server")) {
            config.api_server = args.next();
        } else if (std.mem.eql(u8, arg, "--api-port")) {
            if (args.next()) |val| {
                config.api_port = std.fmt.parseInt(u16, val, 10) catch 443;
            }
        } else if (std.mem.eql(u8, arg, "--token")) {
            config.token = args.next();
        } else if (std.mem.eql(u8, arg, "--namespace")) {
            if (args.next()) |val| {
                config.namespace = val;
            }
        } else if (std.mem.eql(u8, arg, "--controller-name")) {
            if (args.next()) |val| {
                config.controller_name = val;
            }
        } else if (std.mem.eql(u8, arg, "--router-service")) {
            config.router_service = args.next();
        } else if (std.mem.eql(u8, arg, "--router-namespace")) {
            if (args.next()) |val| {
                config.router_namespace = val;
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            std.process.exit(0);
        }
    }

    std.debug.assert(config.admin_port > 0); // S1: postcondition - valid port after parsing
    std.debug.assert(config.namespace.len > 0); // S1: postcondition - namespace always set
    return config;
}

/// Print usage information.
/// TigerStyle: Extracted helper for readability.
fn printUsage() void {
    const usage =
        \\Usage: gateway [OPTIONS]
        \\
        \\Kubernetes Gateway API controller for serval.
        \\
        \\Options:
        \\  --admin-port <PORT>       Admin API port for health probes (default: 8080)
        \\  --data-plane-host <HOST>  Data plane hostname (default: "serval-router.default.svc.cluster.local.")
        \\  --data-plane-port <PORT>  Data plane admin port for config updates (default: 9901)
        \\  --api-server <URL>        K8s API server hostname (for out-of-cluster)
        \\  --api-port <PORT>         K8s API port (default: 443)
        \\  --token <TOKEN>           Bearer token for K8s API authentication
        \\  --namespace <NS>          Namespace to watch (default: "default")
        \\  --controller-name <NAME>  Controller name for GatewayClass filtering
        \\                            (default: "serval.dev/gateway-controller")
        \\  --router-service <NAME>   Router service name for multi-endpoint discovery (HA mode)
        \\                            When set, discovers all router pods via EndpointSlice
        \\  --router-namespace <NS>   Router service namespace (default: "default")
        \\  --help, -h                Show this help message
        \\
        \\When running inside a Kubernetes pod, credentials are read from
        \\/var/run/secrets/kubernetes.io/serviceaccount/.
        \\
        \\When running outside a cluster, provide --api-server and --token.
        \\
        \\Multi-endpoint mode (HA):
        \\  Use --router-service to enable pushing config to ALL router pods.
        \\  Example: --router-service serval-router-admin --router-namespace serval-system
        \\
    ;
    std.debug.print("{s}", .{usage});
}

/// Main entry point.
/// TigerStyle Y1: Under 70 lines with extracted helpers.
pub fn main() !void {
    std.log.info("=== MAIN STARTING ===", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args
    const cli_config = parseArgs();

    // Initialize and run
    try run(allocator, cli_config);
}

/// Shutdown context for coordinating graceful shutdown across threads.
/// TigerStyle: Explicit struct to avoid passing multiple related params.
const ShutdownContext = struct {
    ctrl: *Controller,
    admin_shutdown: *std.atomic.Value(bool),
    admin_thread: std.Thread,

    /// Wait for shutdown and stop admin server.
    fn shutdownAdmin(self: *const ShutdownContext) void {
        std.debug.assert(@intFromPtr(self.ctrl) != 0); // S1: precondition
        waitForShutdown(self.ctrl);
        std.log.info("shutdown requested, stopping admin server...", .{});
        self.admin_shutdown.store(true, .release);
        self.admin_thread.join();
    }
};

/// Watcher pointer for cleanup.
/// Note: Threads are managed internally by the Watcher; stop() joins all threads.
const WatcherResult = struct {
    watcher: *Watcher,
};

/// Run the gateway controller.
/// TigerStyle Y1: Under 70 lines with extracted helpers.
fn run(allocator: std.mem.Allocator, config: CliConfig) !void {
    std.debug.assert(config.admin_port > 0); // S1: precondition - valid port
    std.debug.assert(config.data_plane_port > 0); // S1: precondition - valid port

    logStartupBanner(config);

    // Initialize K8s client first (needed for Controller's StatusManager)
    const k8s_client = initK8sClient(allocator, config) catch |err| {
        std.log.err("failed to initialize K8s client: {s}", .{@errorName(err)});
        std.log.info("hint: run inside a K8s pod or provide --api-server and --token", .{});
        return;
    };
    defer k8s_client.deinit();
    std.log.info("K8s client initialized: {s}:{d}", .{ k8s_client.getApiServer(), k8s_client.api_port });

    // Initialize controller (heap-allocated due to ~2.5MB size)
    // Controller now takes K8s client for status updates
    const ctrl = try Controller.create(
        allocator,
        config.admin_port,
        config.data_plane_host,
        config.data_plane_port,
        k8s_client,
        config.controller_name,
    );
    defer ctrl.destroy();

    // Enable multi-endpoint mode if router-service is specified
    // This discovers all router pod IPs via EndpointSlice and pushes to all
    if (config.router_service) |service| {
        ctrl.enableMultiEndpoint(config.router_namespace, service);
        std.log.info("multi-endpoint mode enabled: {s}/{s}", .{ config.router_namespace, service });
    }

    // Start admin server thread for K8s health probes
    var admin_shutdown = std.atomic.Value(bool).init(false);
    const admin_thread = startAdminServer(ctrl.getAdminHandler(), config.admin_port, &admin_shutdown) catch |err| {
        std.log.err("failed to start admin server: {s}", .{@errorName(err)});
        return err;
    };
    std.log.info("admin server started on port {d}", .{config.admin_port});

    const shutdown_ctx = ShutdownContext{
        .ctrl = ctrl,
        .admin_shutdown = &admin_shutdown,
        .admin_thread = admin_thread,
    };

    // Initialize watcher and start watching
    const watcher_result = initAndStartWatcher(allocator, k8s_client, ctrl, &shutdown_ctx, config.controller_name) orelse return;
    defer watcher_result.watcher.deinit();

    // Start endpoint sync thread if multi-endpoint mode is enabled
    // This ensures new router pods receive the current config
    var sync_thread: ?std.Thread = null;
    if (ctrl.isMultiEndpointEnabled()) {
        if (std.Thread.spawn(.{}, runEndpointSyncLoop, .{ allocator, ctrl })) |t| {
            sync_thread = t;
            std.log.info("endpoint sync thread started (interval: 5s)", .{});
        } else |err| {
            std.log.warn("failed to start endpoint sync thread: {s}", .{@errorName(err)});
        }
    }

    // Mark ready and run until shutdown
    ctrl.setReady(true);
    std.log.info("controller ready, watching for Gateway API resources...", .{});
    waitForShutdown(ctrl);

    // Graceful shutdown: stop all threads
    std.log.info("shutdown requested, stopping services...", .{});
    watcher_result.watcher.stop(); // stop() internally joins all watch threads
    if (sync_thread) |t| t.join();
    admin_shutdown.store(true, .release);
    admin_thread.join();
    std.log.info("gateway controller stopped", .{});
}

/// Log startup banner with config info.
/// TigerStyle Y1: Extracted helper for function length compliance.
fn logStartupBanner(config: CliConfig) void {
    std.debug.assert(config.admin_port > 0); // S1: precondition
    std.debug.assert(config.namespace.len > 0); // S1: precondition
    std.log.info("=== serval-k8s-gateway v{s} ===", .{VERSION});
    std.log.info("Admin API: http://localhost:{d}", .{config.admin_port});
    std.log.info("Data plane: {s}:{d}", .{ config.data_plane_host, config.data_plane_port });
    if (config.router_service) |service| {
        std.log.info("Multi-endpoint mode: {s}/{s} (HA)", .{ config.router_namespace, service });
    } else {
        std.log.info("Single-endpoint mode (use --router-service for HA)", .{});
    }
}

/// Initialize watcher and start thread. Returns watcher and thread, or null on failure.
/// TigerStyle Y1: Extracted helper for function length compliance.
fn initAndStartWatcher(
    allocator: std.mem.Allocator,
    k8s_client: *K8sClient,
    ctrl: *Controller,
    shutdown_ctx: *const ShutdownContext,
    controller_name: []const u8,
) ?WatcherResult {
    std.debug.assert(@intFromPtr(k8s_client) != 0); // S1: precondition
    std.debug.assert(@intFromPtr(ctrl) != 0); // S1: precondition
    std.debug.assert(controller_name.len > 0); // S1: precondition

    std.log.info("watching namespace: {s}", .{k8s_client.getNamespace()});
    std.log.info("controller name: {s}", .{controller_name});

    // Get resolver from controller for endpoint data updates.
    // Watcher updates resolver when it receives Endpoints events.
    const resolver = ctrl.getResolver();

    const watcher = Watcher.init(allocator, k8s_client, onConfigChange, ctrl, resolver, controller_name) catch |err| {
        std.log.err("failed to initialize watcher: {s}", .{@errorName(err)});
        shutdown_ctx.shutdownAdmin();
        return null;
    };

    // Start spawns parallel watch threads for each resource type.
    // Threads are managed internally; stop() will join all of them.
    watcher.start() catch |err| {
        std.log.err("failed to start watcher threads: {s}", .{@errorName(err)});
        watcher.deinit();
        shutdown_ctx.shutdownAdmin();
        return null;
    };

    return WatcherResult{ .watcher = watcher };
}

/// Callback invoked when K8s watcher detects config changes.
/// TigerStyle: Explicit error handling, logs failures.
/// Receives Io from watcher thread for async operations (status updates).
fn onConfigChange(ctx: ?*anyopaque, config_ptr: *gw_config.GatewayConfig, io: Io) void {
    std.debug.assert(ctx != null); // S1: precondition - context required
    std.debug.assert(@intFromPtr(config_ptr) != 0); // S1: precondition - valid config pointer

    const ctrl: *Controller = @ptrCast(@alignCast(ctx.?));
    ctrl.updateConfig(config_ptr, io) catch |err| {
        std.log.err("config update failed: {s}", .{@errorName(err)});
    };
}

/// Initialize K8s client based on CLI config or in-cluster defaults.
/// TigerStyle Y1: Extracted helper for function length compliance.
fn initK8sClient(allocator: std.mem.Allocator, config: CliConfig) k8s_client_mod.ClientError!*K8sClient {
    std.debug.assert(config.namespace.len > 0); // S1: precondition - namespace required
    std.debug.assert(config.api_port > 0); // S1: precondition - valid API port

    if (config.api_server) |server| {
        // Out-of-cluster: use provided config
        const token = config.token orelse {
            std.log.err("--token required when using --api-server", .{});
            return k8s_client_mod.ClientError.TokenNotFound;
        };
        return K8sClient.initWithConfig(
            allocator,
            server,
            config.api_port,
            token,
            config.namespace,
        );
    } else {
        // In-cluster: use ServiceAccount credentials
        return K8sClient.initInCluster(allocator);
    }
}

/// Wait for shutdown signal (Ctrl+C or controller shutdown).
/// TigerStyle: Bounded sleep loop with explicit exit condition.
fn waitForShutdown(ctrl: *Controller) void {
    std.debug.assert(@intFromPtr(ctrl) != 0); // S1: precondition - valid controller pointer

    const sleep_interval_ns: u64 = 100_000_000; // 100ms
    const max_iterations: u32 = 1_000_000_000; // ~27 hours max (effectively unbounded for practical use)
    var iteration: u32 = 0;

    while (iteration < max_iterations) : (iteration += 1) {
        if (ctrl.isShutdown()) break;
        std.posix.nanosleep(0, sleep_interval_ns);
    }
}

/// Start the admin HTTP server in a separate thread.
/// Serves K8s health probes at /healthz and /readyz.
///
/// TigerStyle S1: ~2 assertions, explicit error handling.
fn startAdminServer(
    handler: *AdminHandler,
    port: u16,
    shutdown: *std.atomic.Value(bool),
) !std.Thread {
    std.debug.assert(port > 0); // S1: precondition - valid port

    return std.Thread.spawn(.{}, adminServerLoop, .{ handler, port, shutdown });
}

/// Admin server loop running in dedicated thread.
/// Uses MinimalServer from serval-server for health probe responses.
///
/// TigerStyle: Initializes Io runtime in thread context.
fn adminServerLoop(
    handler: *AdminHandler,
    port: u16,
    shutdown: *std.atomic.Value(bool),
) void {
    std.debug.assert(port > 0); // S1: precondition - valid port
    std.debug.assert(@intFromPtr(handler) != 0); // S1: precondition - valid handler pointer
    std.debug.assert(@intFromPtr(shutdown) != 0); // S1: precondition - valid shutdown flag pointer

    // Initialize async I/O runtime for this thread
    var threaded: Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Initialize minimal server components
    var pool = serval_pool.SimplePool.init();
    var metrics = serval_metrics.NoopMetrics{};
    var tracer = serval_tracing.NoopTracer{};

    // Create minimal server - no TLS, no upstream forwarding needed
    // TigerStyle: Use MinimalServer for handlers that only return direct responses
    var server = serval_server.MinimalServer(AdminHandler).init(
        handler,
        &pool,
        &metrics,
        &tracer,
        .{ .port = port },
        null, // No TLS client context
        serval_net.DnsConfig{}, // Default DNS config
    );

    // Run server until shutdown
    server.run(io, shutdown) catch |err| {
        std.log.err("admin server error: {s}", .{@errorName(err)});
    };
}

/// Endpoint sync loop running in dedicated thread.
/// Periodically checks for new router endpoints and pushes config to them.
///
/// TigerStyle S3: Bounded loop with explicit iteration limit.
fn runEndpointSyncLoop(allocator: std.mem.Allocator, ctrl: *Controller) void {
    std.debug.assert(@intFromPtr(ctrl) != 0); // S1: precondition - valid controller pointer

    // Initialize async I/O runtime for this thread
    var threaded: Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Sync interval: 5 seconds
    const sync_interval_ns: u64 = 5_000_000_000;
    const max_iterations: u32 = 1_000_000_000; // Effectively unbounded
    var iteration: u32 = 0;

    std.log.debug("endpoint sync loop started", .{});

    while (iteration < max_iterations) : (iteration += 1) {
        if (ctrl.isShutdown()) break;

        // Sleep first to allow initial config to be pushed
        std.posix.nanosleep(sync_interval_ns / time.ns_per_s, sync_interval_ns % time.ns_per_s);

        if (ctrl.isShutdown()) break;

        // Sync config to any new router endpoints
        const synced = ctrl.syncRouterEndpoints(io);
        if (synced > 0) {
            std.log.info("endpoint sync: pushed config to {d} new router(s)", .{synced});
        }
    }

    std.log.debug("endpoint sync loop stopped", .{});
}

test "main module compiles" {
    // Basic compile test
    _ = Controller;
    _ = K8sClient;
    _ = Watcher;
    _ = AdminHandler;
}
