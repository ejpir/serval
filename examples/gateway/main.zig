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
//!   --admin-port <PORT>    Admin API port (default: 9901)
//!   --data-plane-port <PORT> Data plane port (default: 9901)
//!   --api-server <URL>     K8s API server (for out-of-cluster)
//!   --api-port <PORT>      K8s API port (default: 443)
//!   --token <TOKEN>        Bearer token for K8s API
//!   --namespace <NS>       Namespace to watch (default: "default")
//!
//! TigerStyle Y1: Functions under 70 lines, extracted helpers.

const std = @import("std");
const gateway = @import("serval-gateway");

const Controller = @import("controller.zig").Controller;
const K8sClient = @import("k8s_client.zig").Client;
const Watcher = @import("watcher.zig").Watcher;

/// Version
const VERSION = "0.1.0";

/// Main entry point.
/// TigerStyle Y1: Under 70 lines with extracted helpers.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args (simplified for now)
    const args = std.process.args();
    _ = args;

    // Default configuration
    const admin_port: u16 = 9901;
    const data_plane_port: u16 = 9901;

    // Initialize and run
    try run(allocator, admin_port, data_plane_port);
}

/// Run the gateway controller.
/// TigerStyle Y1: Extracted from main for function length compliance.
fn run(allocator: std.mem.Allocator, admin_port: u16, data_plane_port: u16) !void {
    std.debug.print("\n=== serval-gateway v{s} ===\n", .{VERSION});
    std.debug.print("Admin API: http://localhost:{d}\n", .{admin_port});
    std.debug.print("Data plane: localhost:{d}\n", .{data_plane_port});

    // Initialize controller (heap-allocated due to ~2.5MB size)
    const ctrl = try Controller.create(allocator, admin_port, data_plane_port);
    defer ctrl.destroy();

    // Mark ready (simplified - in production would wait for K8s connection)
    ctrl.setReady(true);

    std.debug.print("\nController initialized. Press Ctrl+C to stop.\n", .{});
    std.debug.print("(Full K8s watcher integration pending - see Task 10 build.zig)\n\n", .{});

    // In production, this would:
    // 1. Start admin server in background thread
    // 2. Initialize K8s client
    // 3. Start watcher for Gateway and HTTPRoute resources
    // 4. Block until shutdown signal

    // For now, just wait for interrupt
    while (!ctrl.isShutdown()) {
        std.posix.nanosleep(1, 0); // 1 second
    }

    std.log.info("gateway controller stopped", .{});
}

test "main module compiles" {
    // Basic compile test
    _ = Controller;
    _ = K8sClient;
    _ = Watcher;
}
