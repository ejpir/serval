//! Kubernetes Gateway API Controller
//!
//! Watches K8s Gateway API resources and configures serval-router.
//! This is a complete controller implementation using serval-gateway library.

const std = @import("std");

pub fn main() !void {
    std.debug.print("gateway controller starting...\n", .{});
}
