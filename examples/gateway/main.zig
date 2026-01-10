//! Kubernetes Gateway API Controller
//!
//! Complete controller implementation that:
//! - Watches K8s Gateway API resources (Gateway, HTTPRoute)
//! - Translates to serval-router configuration
//! - Pushes config to data plane via admin API
//!
//! Usage:
//!   gateway [OPTIONS]
//!
//! Options:
//!   --admin-port <PORT>      Admin API port (default: 9901)
//!   --data-plane-port <PORT> Data plane port (default: 9901)
//!   --api-server <URL>       K8s API server (for out-of-cluster)
//!   --api-port <PORT>        K8s API port (default: 443)
//!   --token <TOKEN>          Bearer token for K8s API
//!   --namespace <NS>         Namespace to watch (default: "default")
//!
//! TigerStyle Y1: Functions under 70 lines, extracted helpers.

const std = @import("std");
const gateway = @import("serval-gateway");
const gw_config = gateway.config;

const Controller = @import("controller.zig").Controller;
const k8s_client_mod = @import("k8s_client.zig");
const K8sClient = k8s_client_mod.Client;
const Watcher = @import("watcher.zig").Watcher;

/// Version
const VERSION = "0.1.0";

/// CLI configuration parsed from command line arguments.
/// TigerStyle: Explicit struct with named fields.
const CliConfig = struct {
    admin_port: u16 = 9901,
    data_plane_port: u16 = 9901,
    api_server: ?[]const u8 = null,
    api_port: u16 = 443,
    token: ?[]const u8 = null,
    namespace: []const u8 = "default",
};

/// Maximum number of CLI arguments to process.
/// TigerStyle: Bounded iteration.
const MAX_CLI_ARGS: u32 = 32;

/// Parse command line arguments into CliConfig.
/// TigerStyle: Bounded iteration, explicit defaults.
fn parseArgs() CliConfig {
    var config = CliConfig{};
    var args = std.process.args();

    // Skip program name
    _ = args.skip();

    var iteration: u32 = 0;
    while (iteration < MAX_CLI_ARGS) : (iteration += 1) {
        const arg = args.next() orelse break;

        if (std.mem.eql(u8, arg, "--admin-port")) {
            if (args.next()) |val| {
                config.admin_port = std.fmt.parseInt(u16, val, 10) catch 9901;
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
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            std.process.exit(0);
        }
    }

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
        \\  --admin-port <PORT>      Admin API port (default: 9901)
        \\  --data-plane-port <PORT> Data plane port (default: 9901)
        \\  --api-server <URL>       K8s API server hostname (for out-of-cluster)
        \\  --api-port <PORT>        K8s API port (default: 443)
        \\  --token <TOKEN>          Bearer token for K8s API authentication
        \\  --namespace <NS>         Namespace to watch (default: "default")
        \\  --help, -h               Show this help message
        \\
        \\When running inside a Kubernetes pod, credentials are read from
        \\/var/run/secrets/kubernetes.io/serviceaccount/.
        \\
        \\When running outside a cluster, provide --api-server and --token.
        \\
    ;
    std.debug.print("{s}", .{usage});
}

/// Main entry point.
/// TigerStyle Y1: Under 70 lines with extracted helpers.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args
    const cli_config = parseArgs();

    // Initialize and run
    try run(allocator, cli_config);
}

/// Run the gateway controller.
/// TigerStyle Y1: Extracted from main for function length compliance.
fn run(allocator: std.mem.Allocator, config: CliConfig) !void {
    std.log.info("=== serval-gateway v{s} ===", .{VERSION});
    std.log.info("Admin API: http://localhost:{d}", .{config.admin_port});
    std.log.info("Data plane: localhost:{d}", .{config.data_plane_port});

    // Initialize controller (heap-allocated due to ~2.5MB size)
    const ctrl = try Controller.create(allocator, config.admin_port, config.data_plane_port);
    defer ctrl.destroy();

    // Initialize K8s client
    const k8s_client = initK8sClient(allocator, config) catch |err| {
        std.log.err("failed to initialize K8s client: {s}", .{@errorName(err)});
        std.log.info("hint: run inside a K8s pod or provide --api-server and --token", .{});
        return err;
    };
    defer k8s_client.deinit();

    std.log.info("K8s client initialized: {s}:{d}", .{ k8s_client.getApiServer(), k8s_client.api_port });
    std.log.info("watching namespace: {s}", .{k8s_client.getNamespace()});

    // Initialize watcher with callback
    const watcher = Watcher.init(allocator, k8s_client, onConfigChange, ctrl) catch |err| {
        std.log.err("failed to initialize watcher: {s}", .{@errorName(err)});
        return error.WatcherInitFailed;
    };
    defer watcher.deinit();

    // Start watcher thread
    const watcher_thread = watcher.start() catch |err| {
        std.log.err("failed to start watcher thread: {s}", .{@errorName(err)});
        return err;
    };

    // Mark ready after watcher started
    ctrl.setReady(true);
    std.log.info("controller ready, watching for Gateway API resources...", .{});

    // Wait for shutdown signal
    waitForShutdown(ctrl);

    // Graceful shutdown
    std.log.info("shutdown requested, stopping watcher...", .{});
    watcher.stop();
    watcher_thread.join();

    std.log.info("gateway controller stopped", .{});
}

/// Callback invoked when K8s watcher detects config changes.
/// TigerStyle: Explicit error handling, logs failures.
fn onConfigChange(ctx: ?*anyopaque, config_ptr: *gw_config.GatewayConfig) void {
    const ctrl: *Controller = @ptrCast(@alignCast(ctx.?));
    ctrl.updateConfig(config_ptr) catch |err| {
        std.log.err("config update failed: {s}", .{@errorName(err)});
    };
}

/// Initialize K8s client based on CLI config or in-cluster defaults.
/// TigerStyle Y1: Extracted helper for function length compliance.
fn initK8sClient(allocator: std.mem.Allocator, config: CliConfig) k8s_client_mod.ClientError!*K8sClient {
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
    const sleep_interval_ns: u64 = 100_000_000; // 100ms
    const max_iterations: u32 = 1_000_000_000; // ~27 hours max (effectively unbounded for practical use)
    var iteration: u32 = 0;

    while (iteration < max_iterations) : (iteration += 1) {
        if (ctrl.isShutdown()) break;
        std.posix.nanosleep(0, sleep_interval_ns);
    }
}

test "main module compiles" {
    // Basic compile test
    _ = Controller;
    _ = K8sClient;
    _ = Watcher;
}
