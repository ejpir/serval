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
const Io = std.Io;

const serval_core = @import("serval-core");
const gateway = @import("serval-k8s-gateway");
const GatewayConfig = gateway.GatewayConfig;
const Gateway = gateway.Gateway;

const core_config = serval_core.config;

const data_plane = @import("data_plane.zig");
const DataPlaneClient = data_plane.DataPlaneClient;
const DataPlaneError = data_plane.DataPlaneError;
const PushResult = data_plane.PushResult;
const Resolver = @import("resolver/mod.zig").Resolver;
const AdminHandler = @import("admin_handler.zig").AdminHandler;
const status_mod = @import("status.zig");
const StatusManager = status_mod.StatusManager;
const GatewayReconcileResult = status_mod.GatewayReconcileResult;
const k8s_client_mod = @import("k8s_client/mod.zig");
const K8sClient = k8s_client_mod.Client;

// ============================================================================
// Constants (TigerStyle Y3: Units in names)
// ============================================================================

/// Maximum length for router service namespace.
pub const MAX_ROUTER_NAMESPACE_LEN: u8 = 63;

/// Maximum length for router service name.
pub const MAX_ROUTER_SERVICE_NAME_LEN: u8 = 63;

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

    /// Status manager for K8s resource status updates (heap-allocated ~70KB).
    status_manager: *StatusManager,

    /// K8s API client for endpoint discovery (borrowed reference).
    /// TigerStyle: Controller does not own this client's lifecycle.
    k8s_client: *K8sClient,

    /// Router service namespace for multi-endpoint discovery.
    /// TigerStyle S7: Fixed-size storage, no allocation.
    router_namespace: [MAX_ROUTER_NAMESPACE_LEN]u8,
    router_namespace_len: u8,

    /// Router admin service name for multi-endpoint discovery.
    /// TigerStyle S7: Fixed-size storage, no allocation.
    router_service_name: [MAX_ROUTER_SERVICE_NAME_LEN]u8,
    router_service_name_len: u8,

    /// Whether multi-endpoint mode is enabled.
    /// When true, discovers router endpoints before each config push.
    multi_endpoint_enabled: bool,

    /// Create controller on heap.
    ///
    /// TigerStyle C3: Large struct (~2.5MB) must be heap-allocated.
    /// TigerStyle S1: Assertions validate port arguments.
    ///
    /// Parameters:
    /// - allocator: Memory allocator for all resources
    /// - admin_port: Port for admin HTTP server (health probes)
    /// - data_plane_host: Hostname of data plane for config push
    /// - data_plane_port: Port of data plane admin API
    /// - k8s_client: K8s API client for status updates (borrowed reference)
    /// - controller_name: Controller name for GatewayClass status updates
    pub fn create(
        allocator: std.mem.Allocator,
        admin_port: u16,
        data_plane_host: []const u8,
        data_plane_port: u16,
        k8s_client: *K8sClient,
        controller_name: []const u8,
    ) !*Self {
        assert(admin_port > 0); // S1: precondition - valid port
        assert(data_plane_host.len > 0); // S1: precondition - non-empty host
        assert(data_plane_port > 0); // S1: precondition - valid port
        assert(@intFromPtr(k8s_client) != 0); // S1: precondition - valid k8s client
        assert(controller_name.len > 0); // S1: precondition - non-empty controller name

        // Create resolver first (can fail)
        const resolver = try Resolver.create(allocator);
        errdefer resolver.destroy();

        // Create data plane client (can fail)
        const data_plane_client = try DataPlaneClient.create(allocator, data_plane_host, data_plane_port);
        errdefer data_plane_client.destroy();

        // Create status manager (can fail)
        const status_manager = try StatusManager.init(allocator, k8s_client, controller_name);
        errdefer status_manager.deinit();

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
            .status_manager = status_manager,
            .k8s_client = k8s_client,
            .router_namespace = undefined,
            .router_namespace_len = 0,
            .router_service_name = undefined,
            .router_service_name_len = 0,
            .multi_endpoint_enabled = false, // Single-instance mode by default
        };

        // Initialize admin handler with pointers to our state
        self.admin_handler = AdminHandler.init(&self.ready, &self.gateway_config);

        assert(self.admin_port > 0); // S1: postcondition - valid admin port
        assert(self.data_plane_port > 0); // S1: postcondition - valid data plane port
        assert(!self.ready.load(.acquire)); // S1: postcondition - not ready initially
        assert(@intFromPtr(self.status_manager) != 0); // S1: postcondition - status manager initialized
        return self;
    }

    /// Enable multi-endpoint mode for pushing config to all router replicas.
    ///
    /// Call this after create() to enable EndpointSlice-based discovery.
    /// When enabled, updateConfig will discover router pod IPs and push to all.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    ///
    /// Parameters:
    /// - namespace: Namespace where router service lives (e.g., "serval-system")
    /// - service_name: Router admin service name (e.g., "serval-router-admin")
    pub fn enableMultiEndpoint(
        self: *Self,
        namespace: []const u8,
        service_name: []const u8,
    ) void {
        // S1: Preconditions
        assert(namespace.len > 0 and namespace.len <= MAX_ROUTER_NAMESPACE_LEN);
        assert(service_name.len > 0 and service_name.len <= MAX_ROUTER_SERVICE_NAME_LEN);

        @memcpy(self.router_namespace[0..namespace.len], namespace);
        self.router_namespace_len = @intCast(namespace.len);

        @memcpy(self.router_service_name[0..service_name.len], service_name);
        self.router_service_name_len = @intCast(service_name.len);

        self.multi_endpoint_enabled = true;

        std.log.info("controller: multi-endpoint mode enabled for {s}/{s}", .{
            namespace,
            service_name,
        });

        // S2: Postcondition
        assert(self.multi_endpoint_enabled);
    }

    /// Get router namespace as slice.
    ///
    /// TigerStyle: Trivial accessor.
    pub fn getRouterNamespace(self: *const Self) []const u8 {
        return self.router_namespace[0..self.router_namespace_len];
    }

    /// Get router service name as slice.
    ///
    /// TigerStyle: Trivial accessor.
    pub fn getRouterServiceName(self: *const Self) []const u8 {
        return self.router_service_name[0..self.router_service_name_len];
    }

    /// Check if multi-endpoint mode is enabled.
    ///
    /// TigerStyle: Trivial accessor.
    pub fn isMultiEndpointEnabled(self: *const Self) bool {
        return self.multi_endpoint_enabled;
    }

    /// Destroy controller and free heap memory.
    ///
    /// TigerStyle: Explicit cleanup, pairs with create.
    pub fn destroy(self: *Self) void {
        assert(@intFromPtr(self) != 0); // S1: precondition - valid self pointer
        assert(@intFromPtr(self.data_plane_client) != 0); // S1: precondition - valid client pointer
        assert(@intFromPtr(self.status_manager) != 0); // S1: precondition - valid status manager

        self.shutdown.store(true, .release);
        self.status_manager.deinit();
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

    /// Update gateway config, push to data plane, and update K8s status.
    ///
    /// In multi-endpoint mode, discovers router endpoints from EndpointSlice
    /// and pushes config to all router pods.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    /// Status updates are best-effort (StatusManager logs errors internally).
    ///
    /// Parameters:
    /// - config_ptr: New gateway configuration to apply
    /// - io: Io runtime for async status update operations
    pub fn updateConfig(self: *Self, config_ptr: *const GatewayConfig, io: Io) ControllerError!void {
        assert(@intFromPtr(config_ptr) != 0); // S1: precondition - valid pointer
        // Note: Empty config is valid (e.g., during startup before Gateways match,
        // or when all Gateways are deleted). We still update and send status.

        self.gateway_config = config_ptr;

        // Push to data plane only if config has content
        // Empty configs (no routes/gateways) are valid during startup or when
        // all resources are deleted - skip push but still update status
        const has_content = config_ptr.http_routes.len > 0 or config_ptr.gateways.len > 0;
        if (has_content) {
            // In multi-endpoint mode, discover endpoints and push to all
            if (self.multi_endpoint_enabled) {
                try self.pushConfigMultiEndpoint(config_ptr, io);
            } else {
                // Single-endpoint mode: use existing pushConfigWithRetry
                self.data_plane_client.pushConfigWithRetry(
                    config_ptr,
                    self.resolver,
                    io,
                ) catch |err| {
                    // BackendsNotReady is not a failure - endpoints haven't arrived yet.
                    // The next reconciliation (when endpoints arrive) will push the config.
                    if (err == DataPlaneError.BackendsNotReady) {
                        std.log.info("config push deferred: waiting for endpoint data", .{});
                        // Continue to update status - don't return error
                    } else {
                        std.log.err("failed to push config to data plane: {s}", .{@errorName(err)});
                        return error.DataPlanePushFailed;
                    }
                };
            }
        }

        // TODO: GatewayClass status updates are not yet implemented.
        //
        // Per Gateway API spec, GatewayClasses matching our controllerName should have
        // their status.conditions updated with "Accepted=True" when we recognize them.
        // However, GatewayConfig currently only contains Gateways and HTTPRoutes - the
        // GatewayClass filtering happens in the watcher before calling onConfigChange.
        //
        // Options to implement:
        // 1. Add gateway_class_names: [][]const u8 to GatewayConfig
        // 2. Have watcher call StatusManager.updateGatewayClassStatus() directly
        // 3. Pass GatewayClasses alongside GatewayConfig in onConfigChange
        //
        // For now, only Gateway status is updated. GatewayClass status will be added
        // when we refactor the watcher/controller interface.

        // Update Gateway status for each gateway (best-effort)
        // TigerStyle S3: Bounded loop with explicit limit
        const max_gateways: u32 = 256;
        var gateway_idx: u32 = 0;
        for (config_ptr.gateways) |gw| {
            if (gateway_idx >= max_gateways) break;
            gateway_idx += 1;

            const result = self.evaluateGateway(&gw);
            self.status_manager.updateGatewayStatus(
                gw.name,
                gw.namespace,
                result,
                io,
            );
        }

        std.log.info("config updated ({d} gateways, {d} routes)", .{
            config_ptr.gateways.len,
            config_ptr.http_routes.len,
        });

        assert(self.gateway_config != null); // S2: postcondition - config stored
    }

    /// Evaluate a Gateway and produce a reconcile result for status updates.
    ///
    /// Currently returns success status (Accepted=true, Programmed=true).
    /// Future: validate gateway config, check data plane status, track generation.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    fn evaluateGateway(self: *Self, gw: *const Gateway) GatewayReconcileResult {
        // S1: Preconditions
        assert(gw.name.len > 0); // gateway must have a name
        assert(gw.namespace.len > 0); // gateway must have a namespace
        _ = self; // Will be used when we add config validation

        // For now, accept all gateways as valid and programmed
        // TODO: Validate listener config (port conflicts, TLS refs, etc.)
        // TODO: Check if data plane actually programmed the config
        // TODO: Track actual generation from K8s resource metadata
        const result = GatewayReconcileResult{
            .accepted = true,
            .accepted_reason = "Accepted",
            .accepted_message = "Gateway configuration is valid",
            .programmed = true,
            .programmed_reason = "Programmed",
            .programmed_message = "Configuration applied to data plane",
            .observed_generation = 1, // TODO: track actual generation from Gateway metadata
            .listener_results = &.{}, // Empty for now - listener status tracking is future work
        };

        // S2: Postcondition - result has valid strings
        assert(result.accepted_reason.len > 0);
        assert(result.programmed_reason.len > 0);

        return result;
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

    /// Push config to multiple router endpoints via EndpointSlice discovery.
    ///
    /// Discovers router pod IPs from K8s EndpointSlice API, then pushes
    /// config to all discovered endpoints.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    fn pushConfigMultiEndpoint(
        self: *Self,
        config_ptr: *const GatewayConfig,
        io: Io,
    ) ControllerError!void {
        // S1: Preconditions
        assert(self.multi_endpoint_enabled);
        assert(self.router_namespace_len > 0);
        assert(self.router_service_name_len > 0);

        const namespace = self.getRouterNamespace();
        const service_name = self.getRouterServiceName();

        // Discover router endpoints from EndpointSlice
        const endpoint_count = self.data_plane_client.refreshEndpoints(
            self.k8s_client,
            namespace,
            service_name,
            io,
        ) catch |err| {
            // Endpoint discovery failed - fall back to single endpoint
            std.log.warn("controller: endpoint discovery failed ({s}), using single endpoint", .{
                @errorName(err),
            });
            // Try single-endpoint push as fallback
            self.data_plane_client.pushConfigWithRetry(
                config_ptr,
                self.resolver,
                io,
            ) catch |push_err| {
                if (push_err == DataPlaneError.BackendsNotReady) {
                    std.log.info("config push deferred: waiting for endpoint data", .{});
                    return;
                }
                std.log.err("failed to push config (fallback): {s}", .{@errorName(push_err)});
                return error.DataPlanePushFailed;
            };
            return;
        };

        std.log.info("controller: discovered {d} router endpoints", .{endpoint_count});

        // Push config to all discovered endpoints
        const result = self.data_plane_client.pushConfigToAll(
            config_ptr,
            self.resolver,
            io,
        ) catch |err| {
            if (err == DataPlaneError.BackendsNotReady) {
                std.log.info("config push deferred: waiting for backend endpoint data", .{});
                return;
            }
            if (err == DataPlaneError.AllPushesFailed) {
                std.log.err("config push failed: all {d} router endpoints failed", .{endpoint_count});
                return error.DataPlanePushFailed;
            }
            std.log.err("failed to push config to routers: {s}", .{@errorName(err)});
            return error.DataPlanePushFailed;
        };

        // Log push results
        if (result.total == 0) {
            std.log.debug("controller: config unchanged, no push needed", .{});
        } else if (result.isFullSuccess()) {
            std.log.info("controller: config pushed to all {d} routers", .{result.success_count});
        } else if (result.hasAnySuccess()) {
            std.log.warn("controller: config push partial: {d}/{d} succeeded", .{
                result.success_count,
                result.total,
            });
        }

        // S2: Postcondition
        assert(result.success_count <= result.total);
    }

    /// Sync config to any new router endpoints.
    ///
    /// Call this when router EndpointSlice changes to ensure new pods
    /// receive the current config. Only pushes to endpoints that haven't
    /// received the current config version.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    ///
    /// Parameters:
    /// - io: Io runtime for async operations
    ///
    /// Returns number of new endpoints that received config.
    pub fn syncRouterEndpoints(self: *Self, io: Io) u8 {
        // S1: Preconditions
        assert(self.multi_endpoint_enabled);

        // Skip if no config has been set yet
        const config_ptr = self.gateway_config orelse {
            std.log.debug("controller: syncRouterEndpoints skipped - no config yet", .{});
            return 0;
        };

        const namespace = self.getRouterNamespace();
        const service_name = self.getRouterServiceName();

        const synced = self.data_plane_client.syncNewEndpoints(
            self.k8s_client,
            namespace,
            service_name,
            config_ptr,
            self.resolver,
            io,
        ) catch |err| {
            std.log.warn("controller: syncRouterEndpoints failed: {s}", .{@errorName(err)});
            return 0;
        };

        if (synced > 0) {
            std.log.info("controller: synced config to {d} new router endpoints", .{synced});
        }

        return synced;
    }
};

// ============================================================================
// Tests
// ============================================================================

/// Test helper: Create a mock K8s client for Controller tests.
/// TigerStyle: Test helper reduces duplication.
fn createTestK8sClient(allocator: std.mem.Allocator) !*K8sClient {
    return try K8sClient.initWithConfig(
        allocator,
        "localhost",
        6443,
        "test-token-12345",
        "default",
    );
}

/// Test controller name for all tests.
const TEST_CONTROLLER_NAME = "serval.dev/test-controller";

test "Controller create" {
    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        9901,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    try std.testing.expectEqual(@as(u16, 9901), ctrl.admin_port);
    try std.testing.expectEqual(@as(u16, 8080), ctrl.data_plane_port);
    try std.testing.expectEqual(false, ctrl.ready.load(.acquire));
    try std.testing.expectEqual(false, ctrl.shutdown.load(.acquire));
    try std.testing.expect(ctrl.gateway_config == null);
    try std.testing.expect(@intFromPtr(ctrl.status_manager) != 0);
}

test "Controller setReady" {
    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        9901,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    try std.testing.expectEqual(false, ctrl.isReady());

    ctrl.setReady(true);
    try std.testing.expectEqual(true, ctrl.isReady());

    ctrl.setReady(false);
    try std.testing.expectEqual(false, ctrl.isReady());
}

test "Controller requestShutdown" {
    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        9901,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    try std.testing.expectEqual(false, ctrl.isShutdown());

    ctrl.requestShutdown();
    try std.testing.expectEqual(true, ctrl.isShutdown());
}

test "Controller getResolver" {
    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        9901,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    const resolver = ctrl.getResolver();
    try std.testing.expect(@intFromPtr(resolver) != 0);
}

test "Controller getAdminHandler" {
    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        9901,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    const handler = ctrl.getAdminHandler();
    try std.testing.expect(@intFromPtr(handler) != 0);
}

test "Controller getAdminPort and getDataPlanePort" {
    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        9901,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    try std.testing.expectEqual(@as(u16, 9901), ctrl.getAdminPort());
    try std.testing.expectEqual(@as(u16, 8080), ctrl.getDataPlanePort());
}

test "Controller getConfig returns null initially" {
    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        9901,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    try std.testing.expect(ctrl.getConfig() == null);
}

test "Controller uses default admin port from config" {
    // Verify we can use serval-core.config constants
    const default_port = core_config.DEFAULT_ADMIN_PORT;
    try std.testing.expectEqual(@as(u16, 9901), default_port);

    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        default_port,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    try std.testing.expectEqual(default_port, ctrl.admin_port);
}

test "Controller evaluateGateway returns accepted" {
    const k8s_client = try createTestK8sClient(std.testing.allocator);
    defer k8s_client.deinit();

    const ctrl = try Controller.create(
        std.testing.allocator,
        9901,
        "localhost",
        8080,
        k8s_client,
        TEST_CONTROLLER_NAME,
    );
    defer ctrl.destroy();

    // Create a test gateway
    const gw = Gateway{
        .name = "test-gateway",
        .namespace = "default",
        .listeners = &.{},
    };

    const result = ctrl.evaluateGateway(&gw);

    // Verify the result indicates success
    try std.testing.expect(result.accepted);
    try std.testing.expect(result.programmed);
    try std.testing.expectEqualStrings("Accepted", result.accepted_reason);
    try std.testing.expectEqualStrings("Programmed", result.programmed_reason);
    try std.testing.expectEqual(@as(i64, 1), result.observed_generation);
}
