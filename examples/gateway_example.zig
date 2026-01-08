// examples/gateway_example.zig
//! Gateway Controller Example
//!
//! Kubernetes Gateway API controller for serval.
//! Watches Gateway API resources and configures the data plane.
//!
//! Usage:
//!   gateway_example [OPTIONS]
//!
//! Options:
//!   --port <PORT>          Data plane port (default: 8080)
//!   --admin-port <PORT>    Admin API port (default: 9901)
//!   --kubeconfig <PATH>    Path to kubeconfig file (for out-of-cluster testing)
//!   --api-server <URL>     K8s API server URL (overrides kubeconfig)
//!   --token <TOKEN>        Bearer token for K8s API (overrides kubeconfig)
//!   --namespace <NS>       Namespace to watch (default: from kubeconfig or "default")
//!   --debug                Enable debug logging
//!   --help                 Show help message
//!   --version              Show version
//!
//! In-cluster mode (default):
//!   Reads ServiceAccount credentials from pod filesystem.
//!   Requires appropriate RBAC permissions for Gateway API resources.
//!
//! Out-of-cluster mode:
//!   Use --api-server and --token, or --kubeconfig for local testing.
//!
//! TigerStyle: Explicit configuration, bounded operations, graceful shutdown.

const std = @import("std");
const gateway = @import("serval-gateway");
const cli = @import("serval-cli");

/// Version of this binary.
const VERSION = "0.1.0";

/// Gateway-specific CLI options.
const GatewayExtra = struct {
    /// Admin API port (default: 9901, matches gateway.ADMIN_PORT)
    @"admin-port": u16 = 9901,
    /// K8s API server hostname (for out-of-cluster testing)
    @"api-server": ?[]const u8 = null,
    /// K8s API server port (default: 443)
    @"api-port": u16 = 443,
    /// Bearer token for K8s API auth (for out-of-cluster testing)
    token: ?[]const u8 = null,
    /// Namespace to watch (default: from ServiceAccount or "default")
    namespace: ?[]const u8 = null,
};

/// Global config change counter for logging.
var config_changes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Callback invoked when K8s resources change.
/// TigerStyle: Pure logging function, no side effects.
fn onConfigChange(config: *gateway.GatewayConfig) void {
    const count = config_changes.fetchAdd(1, .monotonic) + 1;

    // Count resources in config
    var gateway_count: usize = 0;
    var route_count: usize = 0;

    // Count gateways
    gateway_count = config.gateways.len;
    route_count = config.http_routes.len;

    std.log.info("config update #{d}: {d} gateways, {d} routes", .{
        count,
        gateway_count,
        route_count,
    });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command-line arguments
    var args = cli.Args(GatewayExtra).init("gateway_example", VERSION);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Determine mode (in-cluster vs out-of-cluster)
    const is_out_of_cluster = args.extra.@"api-server" != null;

    // Initialize K8s client
    const client: *gateway.k8s.Client = if (is_out_of_cluster) blk: {
        // Out-of-cluster: use explicit config
        const api_server = args.extra.@"api-server" orelse {
            std.debug.print("Error: --api-server is required for out-of-cluster mode\n", .{});
            return error.MissingApiServer;
        };

        const token = args.extra.token orelse {
            std.debug.print("Error: --token is required for out-of-cluster mode\n", .{});
            return error.MissingToken;
        };

        const namespace = args.extra.namespace orelse "default";

        std.log.info("initializing K8s client (out-of-cluster)", .{});
        std.log.info("  api-server: {s}", .{api_server});
        std.log.info("  namespace: {s}", .{namespace});

        break :blk gateway.k8s.Client.initWithConfig(
            allocator,
            api_server,
            args.extra.@"api-port",
            token,
            namespace,
        ) catch |err| {
            std.debug.print("Error: failed to initialize K8s client: {s}\n", .{@errorName(err)});
            return error.K8sClientInitFailed;
        };
    } else blk: {
        // In-cluster: read ServiceAccount credentials
        std.log.info("initializing K8s client (in-cluster)", .{});

        break :blk gateway.k8s.Client.initInCluster(allocator) catch |err| {
            std.debug.print("Error: failed to initialize K8s client: {s}\n", .{@errorName(err)});
            std.debug.print("Hint: for out-of-cluster testing, use --api-server and --token\n", .{});
            return error.K8sClientInitFailed;
        };
    };
    defer client.deinit();

    // Initialize gateway controller
    std.log.info("initializing gateway controller", .{});
    var gw = gateway.Gateway.init(allocator);
    defer gw.deinit();

    // Mark ready for K8s probes (watcher will update config separately)
    gw.ready.store(true, .release);

    // Start admin API server
    std.log.info("starting admin server on :{d}", .{args.extra.@"admin-port"});
    gw.startAdminServer() catch |err| {
        std.debug.print("Error: failed to start admin server: {s}\n", .{@errorName(err)});
        return error.AdminServerFailed;
    };

    // Initialize watcher with config change callback
    std.log.info("initializing K8s resource watcher", .{});
    const watcher = gateway.k8s.Watcher.init(
        allocator,
        client,
        &onConfigChange,
    ) catch |err| {
        std.debug.print("Error: failed to initialize watcher: {s}\n", .{@errorName(err)});
        return error.WatcherInitFailed;
    };
    defer watcher.deinit();

    // Print startup info
    std.debug.print("\n", .{});
    std.debug.print("=== serval-gateway ===\n", .{});
    std.debug.print("Data plane port: {d}\n", .{args.port});
    std.debug.print("Admin API: http://localhost:{d}\n", .{args.extra.@"admin-port"});
    std.debug.print("  /healthz  - liveness probe\n", .{});
    std.debug.print("  /readyz   - readiness probe\n", .{});
    std.debug.print("  /config   - current config\n", .{});
    std.debug.print("  /metrics  - Prometheus metrics\n", .{});
    std.debug.print("  /reload   - trigger config sync\n", .{});
    std.debug.print("K8s namespace: {s}\n", .{client.getNamespace()});
    std.debug.print("Debug logging: {}\n", .{args.debug});
    std.debug.print("\n", .{});
    std.debug.print("Watching Gateway API resources...\n", .{});
    std.debug.print("Press Ctrl+C to stop\n", .{});
    std.debug.print("\n", .{});

    // Start watching K8s resources (blocking)
    const watch_thread = watcher.start() catch |err| {
        std.debug.print("Error: failed to start watcher: {}\n", .{err});
        return error.WatcherStartFailed;
    };

    // Wait for watcher to complete (runs until stopped or error)
    watch_thread.join();

    std.log.info("gateway controller stopped", .{});
}
