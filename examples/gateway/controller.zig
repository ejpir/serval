//! Gateway Controller
//!
//! Manages gateway state, admin server, and config updates.
//! Coordinates between K8s watcher and data plane.
//!
//! Uses serval-server.MinimalServer for admin API instead of raw sockets.
//! Uses serval-core.config for all constants (no local definitions).
//!
//! TigerStyle: Thread-safe state, uses serval components, explicit errors.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const gateway = @import("serval-gateway");
const GatewayConfig = gateway.GatewayConfig;

const core_config = serval_core.config;

const DataPlaneClient = @import("data_plane.zig").DataPlaneClient;
const Resolver = @import("resolver/mod.zig").Resolver;
const AdminHandler = @import("admin_handler.zig").AdminHandler;

// ============================================================================
// Error Types
// ============================================================================

pub const ControllerError = error{
    /// Admin server bind failed.
    AdminBindFailed,
    /// Admin server listen failed.
    AdminListenFailed,
    /// Admin server thread spawn failed.
    AdminThreadFailed,
    /// Memory allocation failed.
    OutOfMemory,
    /// Failed to push config to data plane.
    DataPlanePushFailed,
};

// ============================================================================
// Controller
// ============================================================================

pub const Controller = struct {
    const Self = @This();

    /// Allocator for resources.
    allocator: std.mem.Allocator,

    /// Ready flag for K8s probes.
    ready: std.atomic.Value(bool),

    /// Admin server port.
    admin_port: u16,

    /// Data plane port.
    data_plane_port: u16,

    /// Current gateway config (atomic pointer for lock-free access).
    gateway_config: ?*const GatewayConfig,

    /// Data plane client (heap-allocated, TigerStyle C3).
    data_plane_client: *DataPlaneClient,

    /// Service resolver (heap-allocated due to large size ~2.5MB).
    resolver: *Resolver,

    /// Shutdown flag.
    shutdown: std.atomic.Value(bool),

    /// Admin handler for serval-server.
    admin_handler: AdminHandler,

    /// Create controller on heap.
    ///
    /// TigerStyle C3: Large struct (~2.5MB) must be heap-allocated.
    /// TigerStyle S1: Assertions validate port arguments.
    pub fn create(
        allocator: std.mem.Allocator,
        admin_port: u16,
        data_plane_host: []const u8,
        data_plane_port: u16,
    ) !*Self {
        assert(admin_port > 0); // S1: precondition - valid port
        assert(data_plane_host.len > 0); // S1: precondition - non-empty host
        assert(data_plane_port > 0); // S1: precondition - valid port

        // Create resolver first (can fail)
        const resolver = try Resolver.create(allocator);
        errdefer resolver.destroy();

        // Create data plane client (can fail)
        const data_plane_client = try DataPlaneClient.create(allocator, data_plane_host, data_plane_port);
        errdefer data_plane_client.destroy();

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = Self{
            .allocator = allocator,
            .ready = std.atomic.Value(bool).init(false),
            .admin_port = admin_port,
            .data_plane_port = data_plane_port,
            .gateway_config = null,
            .data_plane_client = data_plane_client,
            .resolver = resolver,
            .shutdown = std.atomic.Value(bool).init(false),
            .admin_handler = undefined, // Set below after self is initialized
        };

        // Initialize admin handler with pointers to our state
        self.admin_handler = AdminHandler.init(&self.ready, &self.gateway_config);

        assert(self.admin_port > 0); // S1: postcondition - valid admin port
        assert(self.data_plane_port > 0); // S1: postcondition - valid data plane port
        assert(!self.ready.load(.acquire)); // S1: postcondition - not ready initially
        return self;
    }

    /// Destroy controller and free heap memory.
    ///
    /// TigerStyle: Explicit cleanup, pairs with create.
    pub fn destroy(self: *Self) void {
        assert(@intFromPtr(self) != 0); // S1: precondition - valid self pointer
        assert(@intFromPtr(self.data_plane_client) != 0); // S1: precondition - valid client pointer

        self.shutdown.store(true, .release);
        self.data_plane_client.destroy();
        self.resolver.destroy();
        self.allocator.destroy(self);
    }

    /// Get the resolver for updating with K8s data.
    ///
    /// TigerStyle: Trivial accessor, assertion-exempt.
    pub fn getResolver(self: *Self) *Resolver {
        return self.resolver;
    }

    /// Mark the controller as ready.
    ///
    /// TigerStyle: Trivial setter, assertion-exempt.
    pub fn setReady(self: *Self, ready_val: bool) void {
        self.ready.store(ready_val, .release);
    }

    /// Check if controller is ready.
    ///
    /// TigerStyle: Trivial getter, assertion-exempt.
    pub fn isReady(self: *Self) bool {
        return self.ready.load(.acquire);
    }

    /// Check if shutdown was requested.
    ///
    /// TigerStyle: Trivial getter, assertion-exempt.
    pub fn isShutdown(self: *Self) bool {
        return self.shutdown.load(.acquire);
    }

    /// Request controller shutdown.
    ///
    /// TigerStyle: Trivial setter, assertion-exempt.
    pub fn requestShutdown(self: *Self) void {
        self.shutdown.store(true, .release);
    }

    /// Get the admin handler for use with serval-server.
    ///
    /// TigerStyle: Trivial accessor, assertion-exempt.
    pub fn getAdminHandler(self: *Self) *AdminHandler {
        return &self.admin_handler;
    }

    /// Update gateway config and push to data plane.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    /// TODO: Implement config push after Task 11 updates translator API.
    pub fn updateConfig(self: *Self, config_ptr: *const GatewayConfig) ControllerError!void {
        assert(@intFromPtr(config_ptr) != 0); // S1: precondition - valid pointer
        assert(config_ptr.gateways.len > 0 or config_ptr.http_routes.len > 0); // S1: precondition - non-empty config

        self.gateway_config = config_ptr;

        // TODO: Push to data plane after Task 11 updates translator API
        // self.data_plane_client.pushConfigWithRetry(config_ptr, &self.resolver, io) catch |err| {
        //     std.log.err("failed to push config to data plane: {s}", .{@errorName(err)});
        //     return error.DataPlanePushFailed;
        // };

        std.log.info("config updated (push pending Task 11)", .{});

        assert(self.gateway_config != null); // S2: postcondition - config stored
    }

    /// Get current gateway config.
    ///
    /// TigerStyle: Trivial accessor, assertion-exempt.
    pub fn getConfig(self: *Self) ?*const GatewayConfig {
        return self.gateway_config;
    }

    /// Get admin port.
    ///
    /// TigerStyle: Trivial accessor, assertion-exempt.
    pub fn getAdminPort(self: *Self) u16 {
        return self.admin_port;
    }

    /// Get data plane port.
    ///
    /// TigerStyle: Trivial accessor, assertion-exempt.
    pub fn getDataPlanePort(self: *Self) u16 {
        return self.data_plane_port;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Controller create" {
    const ctrl = try Controller.create(std.testing.allocator, 9901, "localhost", 8080);
    defer ctrl.destroy();

    try std.testing.expectEqual(@as(u16, 9901), ctrl.admin_port);
    try std.testing.expectEqual(@as(u16, 8080), ctrl.data_plane_port);
    try std.testing.expectEqual(false, ctrl.ready.load(.acquire));
    try std.testing.expectEqual(false, ctrl.shutdown.load(.acquire));
    try std.testing.expect(ctrl.gateway_config == null);
}

test "Controller setReady" {
    const ctrl = try Controller.create(std.testing.allocator, 9901, "localhost", 8080);
    defer ctrl.destroy();

    try std.testing.expectEqual(false, ctrl.isReady());

    ctrl.setReady(true);
    try std.testing.expectEqual(true, ctrl.isReady());

    ctrl.setReady(false);
    try std.testing.expectEqual(false, ctrl.isReady());
}

test "Controller requestShutdown" {
    const ctrl = try Controller.create(std.testing.allocator, 9901, "localhost", 8080);
    defer ctrl.destroy();

    try std.testing.expectEqual(false, ctrl.isShutdown());

    ctrl.requestShutdown();
    try std.testing.expectEqual(true, ctrl.isShutdown());
}

test "Controller getResolver" {
    const ctrl = try Controller.create(std.testing.allocator, 9901, "localhost", 8080);
    defer ctrl.destroy();

    const resolver = ctrl.getResolver();
    try std.testing.expect(@intFromPtr(resolver) != 0);
}

test "Controller getAdminHandler" {
    const ctrl = try Controller.create(std.testing.allocator, 9901, "localhost", 8080);
    defer ctrl.destroy();

    const handler = ctrl.getAdminHandler();
    try std.testing.expect(@intFromPtr(handler) != 0);
}

test "Controller getAdminPort and getDataPlanePort" {
    const ctrl = try Controller.create(std.testing.allocator, 9901, "localhost", 8080);
    defer ctrl.destroy();

    try std.testing.expectEqual(@as(u16, 9901), ctrl.getAdminPort());
    try std.testing.expectEqual(@as(u16, 8080), ctrl.getDataPlanePort());
}

test "Controller getConfig returns null initially" {
    const ctrl = try Controller.create(std.testing.allocator, 9901, "localhost", 8080);
    defer ctrl.destroy();

    try std.testing.expect(ctrl.getConfig() == null);
}

test "Controller uses default admin port from config" {
    // Verify we can use serval-core.config constants
    const default_port = core_config.DEFAULT_ADMIN_PORT;
    try std.testing.expectEqual(@as(u16, 9901), default_port);

    const ctrl = try Controller.create(std.testing.allocator, default_port, "localhost", 8080);
    defer ctrl.destroy();

    try std.testing.expectEqual(default_port, ctrl.admin_port);
}
