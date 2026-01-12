//! Data Plane Client
//!
//! Pushes configuration to serval-router admin API using serval-client.
//! Resolves backends before translation to decouple from K8s-specific Resolver.
//! Supports multi-instance config push via EndpointSlice discovery.
//!
//! TigerStyle: Uses serval-client, bounded buffers, explicit errors, ~2 assertions per function.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const serval_client = @import("serval-client");
const serval_core = @import("serval-core");
const serval_net = @import("serval-net");
const gateway = @import("serval-k8s-gateway");
const resolver_mod = @import("resolver/mod.zig");
const k8s_client_mod = @import("k8s_client/mod.zig");

const Client = serval_client.Client;
const Upstream = serval_core.types.Upstream;
const core_config = serval_core.config;
const GatewayConfig = gateway.GatewayConfig;
const ResolvedBackend = gateway.config.ResolvedBackend;
const FixedResolvedEndpoint = gateway.config.FixedResolvedEndpoint;
const Resolver = resolver_mod.Resolver;
const K8sClient = k8s_client_mod.Client;
const RouterEndpoint = k8s_client_mod.RouterEndpoint;
const RouterEndpoints = k8s_client_mod.RouterEndpoints;
const MAX_ROUTER_ENDPOINTS = k8s_client_mod.MAX_ROUTER_ENDPOINTS;

// ============================================================================
// Constants (TigerStyle Y3: Units in names)
// ============================================================================

/// Default admin port for data plane.
pub const DEFAULT_ADMIN_PORT: u16 = core_config.DEFAULT_ADMIN_PORT;

/// Maximum JSON payload size in bytes.
pub const MAX_JSON_SIZE_BYTES: u32 = gateway.translator.MAX_JSON_SIZE_BYTES;

/// Maximum response header size in bytes.
const MAX_RESPONSE_HEADER_SIZE_BYTES: u32 = core_config.MAX_HEADER_SIZE_BYTES;

/// Maximum retries for config push (TigerStyle S4: bounded).
pub const MAX_RETRIES: u8 = core_config.MAX_CONFIG_PUSH_RETRIES;

/// Base backoff delay in milliseconds.
const BACKOFF_BASE_MS: u64 = core_config.CONFIG_PUSH_BACKOFF_BASE_MS;

/// Maximum backoff delay in milliseconds.
const MAX_BACKOFF_MS: u64 = core_config.MAX_CONFIG_PUSH_BACKOFF_MS;

/// Admin endpoint path for route updates.
const ADMIN_ROUTES_PATH: []const u8 = "/routes/update";

// ============================================================================
// Error Types (TigerStyle S6: Explicit error set)
// ============================================================================

pub const DataPlaneError = error{
    /// No config to push.
    NoConfig,
    /// Backend resolution failed.
    ResolutionFailed,
    /// Translation to JSON failed.
    TranslationFailed,
    /// Connection to data plane failed.
    ConnectionFailed,
    /// Request send failed.
    SendFailed,
    /// Response receive failed.
    ReceiveFailed,
    /// Empty response from data plane.
    EmptyResponse,
    /// Data plane rejected config (non-2xx response).
    Rejected,
    /// All retries exhausted.
    RetriesExhausted,
    /// Backends not yet resolved (endpoints not available).
    BackendsNotReady,
    /// No router endpoints discovered.
    NoRouterEndpoints,
    /// All router pushes failed.
    AllPushesFailed,
    /// Endpoint discovery failed.
    EndpointDiscoveryFailed,
};

// ============================================================================
// Push Result (TigerStyle: Explicit result type)
// ============================================================================

/// Result of pushing config to multiple router endpoints.
/// TigerStyle: Explicit success/failure counts for partial failures.
pub const PushResult = struct {
    /// Number of successful pushes.
    success_count: u8,
    /// Number of failed pushes.
    failure_count: u8,
    /// Total endpoints attempted.
    total: u8,

    /// Check if push was fully successful.
    pub fn isFullSuccess(self: PushResult) bool {
        return self.failure_count == 0 and self.success_count > 0;
    }

    /// Check if any pushes succeeded (partial success).
    pub fn hasAnySuccess(self: PushResult) bool {
        return self.success_count > 0;
    }
};

// ============================================================================
// Data Plane Client (TigerStyle: No allocation after init)
// ============================================================================

pub const DataPlaneClient = struct {
    const Self = @This();

    /// Allocator for client resources.
    allocator: std.mem.Allocator,

    /// Data plane admin port (default port for single-instance mode).
    admin_port: u16,

    /// Data plane host (typically localhost for sidecar pattern, or service name).
    admin_host: []const u8,

    /// JSON buffer for config serialization (TigerStyle S7: bounded).
    json_buffer: [MAX_JSON_SIZE_BYTES]u8,

    /// Response header buffer (TigerStyle S7: bounded).
    response_header_buffer: [MAX_RESPONSE_HEADER_SIZE_BYTES]u8,

    /// Resolved backends buffer (TigerStyle S7: bounded).
    resolved_backends: [gateway.config.MAX_RESOLVED_BACKENDS]ResolvedBackend,

    /// Hash of last successfully pushed config (0 = no config pushed yet).
    /// Used to skip redundant pushes when config hasn't changed.
    last_config_hash: u64,

    /// Router endpoints for multi-instance mode (TigerStyle S7: bounded).
    /// When populated, config is pushed to all discovered endpoints instead of admin_host.
    router_endpoints: RouterEndpoints,

    /// Whether multi-endpoint mode is enabled.
    /// When true, uses router_endpoints; when false, uses admin_host/admin_port.
    multi_endpoint_mode: bool,

    /// Pod names of endpoints that have received the current config.
    /// Used to detect new endpoints that need config push.
    /// TigerStyle S7: Fixed-size storage, no allocation.
    synced_pod_names: [MAX_ROUTER_ENDPOINTS][k8s_client_mod.MAX_POD_NAME_LEN]u8,
    synced_pod_name_lens: [MAX_ROUTER_ENDPOINTS]u8,
    synced_endpoint_count: u8,

    /// Flag indicating endpoints were refreshed since last push.
    /// When true, we should push even if config hash matches.
    endpoints_refreshed: bool,

    /// Create data plane client on heap.
    ///
    /// TigerStyle C3: Large struct (~1MB) must be heap-allocated.
    /// TigerStyle S1: Assertions for preconditions.
    pub fn create(allocator: std.mem.Allocator, admin_host: []const u8, admin_port: u16) !*Self {
        assert(admin_port > 0); // S1: precondition - valid port
        assert(admin_host.len > 0); // S1: precondition - non-empty host

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = Self{
            .allocator = allocator,
            .admin_port = admin_port,
            .admin_host = admin_host,
            .json_buffer = undefined,
            .response_header_buffer = undefined,
            .resolved_backends = undefined,
            .last_config_hash = 0, // No config pushed yet
            .router_endpoints = RouterEndpoints.init(),
            .multi_endpoint_mode = false, // Single-instance mode by default
            .synced_pod_names = undefined,
            .synced_pod_name_lens = std.mem.zeroes([MAX_ROUTER_ENDPOINTS]u8),
            .synced_endpoint_count = 0,
            .endpoints_refreshed = false,
        };

        return self;
    }

    /// Create data plane client with default localhost host.
    ///
    /// TigerStyle C3: Large struct (~1MB) must be heap-allocated.
    /// TigerStyle S1: Assertions for preconditions.
    pub fn createLocalhost(allocator: std.mem.Allocator, admin_port: u16) !*Self {
        return create(allocator, "127.0.0.1", admin_port);
    }

    /// Destroy client and free heap memory.
    ///
    /// TigerStyle: Explicit cleanup, pairs with create.
    pub fn destroy(self: *Self) void {
        self.allocator.destroy(self);
    }

    /// Refresh router endpoints by discovering from K8s EndpointSlice.
    ///
    /// After this call, pushConfigWithRetry will push to all discovered endpoints.
    /// Call this before each config push to ensure endpoint list is current.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    ///
    /// Parameters:
    /// - k8s: K8s API client for EndpointSlice discovery
    /// - namespace: Namespace where router service lives
    /// - service_name: Router admin service name
    /// - io: Io runtime for async operations
    ///
    /// Returns number of discovered endpoints.
    pub fn refreshEndpoints(
        self: *Self,
        k8s: *K8sClient,
        namespace: []const u8,
        service_name: []const u8,
        io: Io,
    ) DataPlaneError!u8 {
        // S1: Preconditions
        assert(@intFromPtr(k8s) != 0);
        assert(namespace.len > 0);
        assert(service_name.len > 0);

        std.log.debug("data_plane: refreshEndpoints for {s}/{s}", .{ namespace, service_name });

        const endpoints = k8s_client_mod.discoverRouterEndpoints(
            k8s,
            namespace,
            service_name,
            self.admin_port,
            io,
        ) catch |err| {
            std.log.warn("data_plane: endpoint discovery failed: {s}", .{@errorName(err)});
            // Fall back to single-instance mode
            self.multi_endpoint_mode = false;
            return DataPlaneError.EndpointDiscoveryFailed;
        };

        // Check if pod names changed (not just IPs - IPs can be reused)
        const pods_changed = self.havePodNamesChanged(&endpoints);
        self.router_endpoints = endpoints;
        self.multi_endpoint_mode = true;
        if (pods_changed) {
            self.endpoints_refreshed = true;
            std.log.info("data_plane: router pods changed, will push config", .{});
        }

        // S1: Postcondition
        assert(self.router_endpoints.count <= MAX_ROUTER_ENDPOINTS);

        return self.router_endpoints.count;
    }

    /// Get the number of currently known router endpoints.
    ///
    /// TigerStyle: Trivial accessor, assertion-exempt.
    pub fn endpointCount(self: *const Self) u8 {
        if (self.multi_endpoint_mode) {
            return self.router_endpoints.count;
        }
        return 1; // Single-instance mode counts as 1 endpoint
    }

    /// Check if multi-endpoint mode is enabled.
    ///
    /// TigerStyle: Trivial accessor, assertion-exempt.
    pub fn isMultiEndpointMode(self: *const Self) bool {
        return self.multi_endpoint_mode;
    }

    /// Push configuration to data plane.
    ///
    /// Resolves backends using the provided resolver, translates to JSON,
    /// and POSTs to the data plane admin API.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    /// TigerStyle S3: Bounded operations via serval-client.
    pub fn pushConfig(
        self: *Self,
        config_ptr: *const GatewayConfig,
        resolver: *const Resolver,
        io: Io,
    ) DataPlaneError!void {
        // S1: precondition - config has content
        assert(config_ptr.http_routes.len > 0 or config_ptr.gateways.len > 0);

        std.log.debug("data_plane: pushConfig routes={d} gateways={d}", .{
            config_ptr.http_routes.len,
            config_ptr.gateways.len,
        });

        // Count expected backends from config
        const expected_backends = countExpectedBackends(config_ptr);
        std.log.debug("data_plane: expecting {d} backends", .{expected_backends});

        // Step 1: Resolve backends to IPs
        const resolved_count = self.resolveBackends(config_ptr, resolver) catch |err| {
            std.log.err("data_plane: resolveBackends failed: {s}", .{@errorName(err)});
            return err;
        };
        std.log.debug("data_plane: resolved {d} backends", .{resolved_count});

        // Check if all expected backends were resolved
        // Don't push config with unresolved backends - wait for endpoints to arrive
        if (expected_backends > 0 and resolved_count < expected_backends) {
            std.log.info("data_plane: waiting for backends ({d}/{d} resolved)", .{
                resolved_count,
                expected_backends,
            });
            return DataPlaneError.BackendsNotReady;
        }

        // Step 2: Translate to JSON using resolved backends
        const json_len = gateway.translator.translateToJson(
            config_ptr,
            self.resolved_backends[0..resolved_count],
            &self.json_buffer,
        ) catch |err| {
            std.log.err("data_plane: translateToJson failed: {s}", .{@errorName(err)});
            return DataPlaneError.TranslationFailed;
        };

        // S2: postcondition - non-empty JSON
        assert(json_len > 0);

        // Step 3: Check if config changed (skip redundant pushes)
        const config_hash = std.hash.Wyhash.hash(0, self.json_buffer[0..json_len]);
        if (config_hash == self.last_config_hash) {
            std.log.debug("data_plane: config unchanged (hash={x}), skipping push", .{config_hash});
            return;
        }

        std.log.debug("data_plane: generated JSON len={d}", .{json_len});
        std.log.debug("data_plane: JSON preview: {s}", .{self.json_buffer[0..@min(500, json_len)]});

        // Step 4: Push to data plane using serval-client
        try self.sendConfigRequest(self.json_buffer[0..json_len], io);

        // Step 5: Update hash after successful push
        self.last_config_hash = config_hash;
        std.log.info("data_plane: config pushed successfully (hash={x})", .{config_hash});
    }

    /// Push configuration with retry logic.
    ///
    /// Uses exponential backoff with bounded retries.
    /// TigerStyle S3: Bounded loop with MAX_RETRIES.
    pub fn pushConfigWithRetry(
        self: *Self,
        config_ptr: *const GatewayConfig,
        resolver: *const Resolver,
        io: Io,
    ) DataPlaneError!void {
        // S1: precondition - valid config
        assert(config_ptr.http_routes.len > 0 or config_ptr.gateways.len > 0);

        var attempt: u8 = 0;
        var backoff_ms: u64 = BACKOFF_BASE_MS;

        // S3: bounded loop - MAX_RETRIES iterations maximum
        while (attempt < MAX_RETRIES) : (attempt += 1) {
            self.pushConfig(config_ptr, resolver, io) catch |err| {
                // BackendsNotReady is not a failure - endpoints haven't arrived yet.
                // Return immediately without retries; next reconciliation will try again.
                if (err == DataPlaneError.BackendsNotReady) {
                    return err;
                }

                // If last attempt, return the appropriate error
                if (attempt + 1 >= MAX_RETRIES) {
                    // S6: explicit error - distinguish exhausted retries vs other failures
                    return switch (err) {
                        DataPlaneError.ConnectionFailed,
                        DataPlaneError.SendFailed,
                        DataPlaneError.ReceiveFailed,
                        DataPlaneError.Rejected,
                        => DataPlaneError.RetriesExhausted,
                        else => err,
                    };
                }

                // Sleep with exponential backoff
                // TigerStyle: Use posix nanosleep for sleeping
                const backoff_ns = backoff_ms * std.time.ns_per_ms;
                const backoff_secs: u64 = backoff_ns / std.time.ns_per_s;
                const backoff_remaining_ns: u64 = backoff_ns % std.time.ns_per_s;
                std.posix.nanosleep(backoff_secs, backoff_remaining_ns);

                // Increase backoff (capped at MAX_BACKOFF_MS)
                backoff_ms = @min(backoff_ms * 2, MAX_BACKOFF_MS);
                continue;
            };

            // S2: postcondition - success on this attempt
            return;
        }

        // S1: postcondition - should never reach here due to loop logic
        return DataPlaneError.RetriesExhausted;
    }

    /// Resolve all backends in config to IP addresses.
    ///
    /// Populates resolved_backends buffer from resolver.
    /// TigerStyle S3: Bounded loop over config.http_routes.
    fn resolveBackends(
        self: *Self,
        config_ptr: *const GatewayConfig,
        resolver: *const Resolver,
    ) DataPlaneError!u16 {
        // S1: precondition - config is valid
        assert(config_ptr.http_routes.len <= gateway.config.MAX_HTTP_ROUTES);

        std.log.debug("resolveBackends: resolver has {d} services", .{resolver.serviceCount()});

        var count: u16 = 0;

        // S3: bounded loop - limited by MAX_HTTP_ROUTES
        for (config_ptr.http_routes, 0..) |http_route, route_i| {
            if (route_i >= gateway.config.MAX_HTTP_ROUTES) break;

            std.log.debug("resolveBackends: route[{d}] has {d} rules", .{ route_i, http_route.rules.len });

            // S3: bounded loop - limited by MAX_RULES
            for (http_route.rules, 0..) |rule, rule_i| {
                if (rule_i >= gateway.config.MAX_RULES) break;

                std.log.debug("resolveBackends: rule[{d}] has {d} backend_refs", .{ rule_i, rule.backend_refs.len });

                // S3: bounded loop - limited by MAX_BACKEND_REFS
                for (rule.backend_refs, 0..) |backend_ref, ref_i| {
                    if (ref_i >= gateway.config.MAX_BACKEND_REFS) break;

                    std.log.debug("resolveBackends: trying to resolve backend_ref[{d}]: {s}/{s}:{d}", .{
                        ref_i,
                        backend_ref.namespace,
                        backend_ref.name,
                        backend_ref.port,
                    });

                    if (count >= gateway.config.MAX_RESOLVED_BACKENDS) {
                        return DataPlaneError.ResolutionFailed;
                    }

                    // Resolve backend to endpoints using resolver
                    resolver.resolveBackend(
                        backend_ref.name,
                        backend_ref.namespace,
                        &self.resolved_backends[count],
                    ) catch |err| {
                        // Skip backends that can't be resolved (service not found)
                        std.log.debug("resolveBackends: failed to resolve {s}/{s}: {s}", .{
                            backend_ref.namespace,
                            backend_ref.name,
                            @errorName(err),
                        });
                        continue;
                    };

                    std.log.debug("resolveBackends: resolved {s}/{s} with {d} endpoints", .{
                        backend_ref.namespace,
                        backend_ref.name,
                        self.resolved_backends[count].endpoint_count,
                    });

                    count += 1;
                }
            }
        }

        // S2: postcondition - count is bounded
        assert(count <= gateway.config.MAX_RESOLVED_BACKENDS);

        return count;
    }

    /// Send config JSON to data plane admin API.
    ///
    /// TigerStyle: Uses serval-client for HTTP, explicit error handling.
    /// TigerStyle Y1: Refactored to stay under 70 lines by extracting buildConfigRequest.
    fn sendConfigRequest(
        self: *Self,
        json_body: []const u8,
        io: Io,
    ) DataPlaneError!void {
        // S1: preconditions
        assert(json_body.len > 0);
        assert(json_body.len <= MAX_JSON_SIZE_BYTES);

        // Create DNS resolver for client (admin is typically localhost)
        // TigerStyle: DnsResolver has no heap allocations, no deinit needed
        var dns_resolver = serval_net.DnsResolver.init(.{});

        // Create HTTP client (no TLS for admin API)
        var client = Client.init(
            self.allocator,
            &dns_resolver,
            null, // No TLS for admin API
            false,
        );
        defer client.deinit();

        // Connect to data plane admin port
        const upstream = Upstream{
            .host = self.admin_host,
            .port = self.admin_port,
            .tls = false,
        };

        var connect_result = client.connect(upstream, io) catch {
            return DataPlaneError.ConnectionFailed;
        };
        defer connect_result.conn.close();

        // Build and send request
        var content_len_buf: [16]u8 = undefined;
        const request = buildConfigRequest(
            self.admin_host,
            json_body,
            &content_len_buf,
        ) orelse return DataPlaneError.SendFailed;

        client.sendRequest(&connect_result.conn, &request, null) catch {
            return DataPlaneError.SendFailed;
        };

        // Read and validate response
        const response = client.readResponseHeaders(
            &connect_result.conn,
            &self.response_header_buffer,
        ) catch |err| {
            std.log.err("data_plane: failed to read response: {s}", .{@errorName(err)});
            return DataPlaneError.ReceiveFailed;
        };

        std.log.debug("data_plane: response status={d}", .{response.status});

        if (response.status < 200 or response.status >= 300) {
            std.log.err("data_plane: rejected with status {d}", .{response.status});
            return DataPlaneError.Rejected;
        }

        // S2: postcondition - successful response
        assert(response.status >= 200 and response.status < 300);
    }

    /// Send config JSON to a specific endpoint (host:port).
    ///
    /// TigerStyle: Uses serval-client for HTTP, explicit error handling.
    fn sendConfigToEndpoint(
        self: *Self,
        host: []const u8,
        port: u16,
        json_body: []const u8,
        io: Io,
    ) DataPlaneError!void {
        // S1: preconditions
        assert(host.len > 0);
        assert(port > 0);
        assert(json_body.len > 0);
        assert(json_body.len <= MAX_JSON_SIZE_BYTES);

        // Create DNS resolver for client
        // TigerStyle: DnsResolver has no heap allocations, no deinit needed
        var dns_resolver = serval_net.DnsResolver.init(.{});

        // Create HTTP client (no TLS for admin API)
        var client = Client.init(
            self.allocator,
            &dns_resolver,
            null, // No TLS for admin API
            false,
        );
        defer client.deinit();

        // Connect to specific endpoint
        const upstream = Upstream{
            .host = host,
            .port = port,
            .tls = false,
        };

        var connect_result = client.connect(upstream, io) catch {
            return DataPlaneError.ConnectionFailed;
        };
        defer connect_result.conn.close();

        // Build and send request
        var content_len_buf: [16]u8 = undefined;
        const request = buildConfigRequest(
            host,
            json_body,
            &content_len_buf,
        ) orelse return DataPlaneError.SendFailed;

        client.sendRequest(&connect_result.conn, &request, null) catch {
            return DataPlaneError.SendFailed;
        };

        // Read and validate response
        const response = client.readResponseHeaders(
            &connect_result.conn,
            &self.response_header_buffer,
        ) catch |err| {
            std.log.err("data_plane: failed to read response from {s}:{d}: {s}", .{
                host,
                port,
                @errorName(err),
            });
            return DataPlaneError.ReceiveFailed;
        };

        if (response.status < 200 or response.status >= 300) {
            std.log.err("data_plane: {s}:{d} rejected with status {d}", .{
                host,
                port,
                response.status,
            });
            return DataPlaneError.Rejected;
        }

        // S2: postcondition - successful response
        assert(response.status >= 200 and response.status < 300);
    }

    /// Push config JSON to all discovered router endpoints.
    ///
    /// Iterates over router_endpoints and pushes to each one.
    /// Returns PushResult with success/failure counts.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    /// TigerStyle S3: Bounded loop over MAX_ROUTER_ENDPOINTS.
    pub fn pushToAll(
        self: *Self,
        json_body: []const u8,
        io: Io,
    ) DataPlaneError!PushResult {
        // S1: preconditions
        assert(json_body.len > 0);
        assert(json_body.len <= MAX_JSON_SIZE_BYTES);

        var result = PushResult{
            .success_count = 0,
            .failure_count = 0,
            .total = 0,
        };

        // If not in multi-endpoint mode, use single endpoint (admin_host:admin_port)
        if (!self.multi_endpoint_mode or self.router_endpoints.count == 0) {
            result.total = 1;
            self.sendConfigRequest(json_body, io) catch |err| {
                std.log.err("data_plane: push to {s}:{d} failed: {s}", .{
                    self.admin_host,
                    self.admin_port,
                    @errorName(err),
                });
                result.failure_count = 1;
                return result;
            };
            result.success_count = 1;
            std.log.info("data_plane: pushed to {s}:{d}", .{ self.admin_host, self.admin_port });
            return result;
        }

        // Multi-endpoint mode: push to all discovered endpoints
        result.total = self.router_endpoints.count;
        std.log.info("data_plane: pushing to {d} router endpoints", .{result.total});

        // Clear synced list and refresh flag - we're pushing new config
        self.clearSyncedEndpoints();
        self.endpoints_refreshed = false;

        // S3: bounded loop - limited by MAX_ROUTER_ENDPOINTS
        var idx: u8 = 0;
        while (idx < self.router_endpoints.count) : (idx += 1) {
            const endpoint = &self.router_endpoints.endpoints[idx];

            // Skip non-ready endpoints
            if (!endpoint.ready) {
                std.log.debug("data_plane: skipping non-ready endpoint {s}:{d}", .{
                    endpoint.getIp(),
                    endpoint.port,
                });
                continue;
            }

            const ip = endpoint.getIp();
            self.sendConfigToEndpoint(ip, endpoint.port, json_body, io) catch |err| {
                std.log.warn("data_plane: push to {s}:{d} failed: {s}", .{
                    ip,
                    endpoint.port,
                    @errorName(err),
                });
                result.failure_count += 1;
                continue;
            };

            // Record this endpoint as synced (by pod name)
            self.addSyncedEndpoint(endpoint.getPodName());
            result.success_count += 1;
            std.log.info("data_plane: pushed to {s}:{d} (pod={s})", .{ ip, endpoint.port, endpoint.getPodName() });
        }

        // Log summary
        if (result.failure_count > 0) {
            std.log.warn("data_plane: config push: {d}/{d} succeeded", .{
                result.success_count,
                result.total,
            });
        } else if (result.success_count > 0) {
            std.log.info("data_plane: config pushed to all {d} routers", .{result.success_count});
        }

        // S2: postcondition - counts are consistent
        assert(result.success_count + result.failure_count <= result.total);

        return result;
    }

    /// Push config with multi-endpoint support and retry logic.
    ///
    /// Combines resolving backends, JSON translation, and multi-endpoint push.
    /// Used as the main entry point for config updates.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    pub fn pushConfigToAll(
        self: *Self,
        config_ptr: *const GatewayConfig,
        resolver: *const Resolver,
        io: Io,
    ) DataPlaneError!PushResult {
        // S1: precondition - config has content
        assert(config_ptr.http_routes.len > 0 or config_ptr.gateways.len > 0);

        std.log.debug("data_plane: pushConfigToAll routes={d} gateways={d}", .{
            config_ptr.http_routes.len,
            config_ptr.gateways.len,
        });

        // Count expected backends from config
        const expected_backends = countExpectedBackends(config_ptr);
        std.log.debug("data_plane: expecting {d} backends", .{expected_backends});

        // Step 1: Resolve backends to IPs
        const resolved_count = self.resolveBackends(config_ptr, resolver) catch |err| {
            std.log.err("data_plane: resolveBackends failed: {s}", .{@errorName(err)});
            return err;
        };
        std.log.debug("data_plane: resolved {d} backends", .{resolved_count});

        // Check if all expected backends were resolved
        if (expected_backends > 0 and resolved_count < expected_backends) {
            std.log.info("data_plane: waiting for backends ({d}/{d} resolved)", .{
                resolved_count,
                expected_backends,
            });
            return DataPlaneError.BackendsNotReady;
        }

        // Step 2: Translate to JSON using resolved backends
        const json_len = gateway.translator.translateToJson(
            config_ptr,
            self.resolved_backends[0..resolved_count],
            &self.json_buffer,
        ) catch |err| {
            std.log.err("data_plane: translateToJson failed: {s}", .{@errorName(err)});
            return DataPlaneError.TranslationFailed;
        };

        // S2: postcondition - non-empty JSON
        assert(json_len > 0);

        // Step 3: Check if config changed OR router endpoints were refreshed
        const config_hash = std.hash.Wyhash.hash(0, self.json_buffer[0..json_len]);

        if (config_hash == self.last_config_hash and !self.endpoints_refreshed) {
            std.log.debug("data_plane: config unchanged (hash={x}), skipping push", .{config_hash});
            // Return success with 0 endpoints pushed (config unchanged)
            return PushResult{
                .success_count = 0,
                .failure_count = 0,
                .total = 0,
            };
        }

        if (self.endpoints_refreshed) {
            std.log.info("data_plane: endpoints refreshed, pushing config to all", .{});
        }

        std.log.debug("data_plane: generated JSON len={d}", .{json_len});

        // Step 4: Push to all discovered router endpoints
        const result = try self.pushToAll(self.json_buffer[0..json_len], io);

        // Step 5: Update hash only if at least one push succeeded
        if (result.success_count > 0) {
            self.last_config_hash = config_hash;
            std.log.info("data_plane: config updated (hash={x})", .{config_hash});
        }

        // Check for total failure
        if (result.success_count == 0 and result.total > 0) {
            return DataPlaneError.AllPushesFailed;
        }

        return result;
    }

    /// Sync router endpoints and push config to any new endpoints.
    ///
    /// Call this when router EndpointSlice changes to ensure new pods
    /// receive the current config. Only pushes to endpoints that haven't
    /// received the current config version.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    /// TigerStyle S3: Bounded loops.
    ///
    /// Parameters:
    /// - k8s: K8s API client for EndpointSlice discovery
    /// - namespace: Namespace where router service lives
    /// - service_name: Router admin service name
    /// - config_ptr: Current gateway config to push
    /// - resolver: Backend resolver
    /// - io: Io runtime for async operations
    ///
    /// Returns number of new endpoints that received config.
    pub fn syncNewEndpoints(
        self: *Self,
        k8s: *K8sClient,
        namespace: []const u8,
        service_name: []const u8,
        config_ptr: *const GatewayConfig,
        resolver: *const Resolver,
        io: Io,
    ) DataPlaneError!u8 {
        // S1: Preconditions
        assert(namespace.len > 0);
        assert(service_name.len > 0);

        // Skip if no config has been pushed yet
        if (self.last_config_hash == 0) {
            std.log.info("data_plane: syncNewEndpoints skipped - no config pushed yet", .{});
            return 0;
        }

        // Refresh endpoints from K8s
        _ = self.refreshEndpoints(k8s, namespace, service_name, io) catch |err| {
            std.log.warn("data_plane: syncNewEndpoints discovery failed: {s}", .{@errorName(err)});
            return err;
        };

        // Find new endpoints not in synced list
        var new_endpoints: [MAX_ROUTER_ENDPOINTS]RouterEndpoint = undefined;
        var new_count: u8 = 0;

        // S3: Bounded loop
        var ep_idx: u8 = 0;
        while (ep_idx < self.router_endpoints.count) : (ep_idx += 1) {
            const ep = &self.router_endpoints.endpoints[ep_idx];
            if (!ep.ready) continue;

            const pod_name = ep.getPodName();
            if (!self.isEndpointSynced(pod_name)) {
                if (new_count < MAX_ROUTER_ENDPOINTS) {
                    new_endpoints[new_count] = ep.*;
                    new_count += 1;
                    std.log.info("data_plane: found new endpoint {s}:{d} (pod={s})", .{ ep.getIp(), ep.port, pod_name });
                }
            }
        }

        if (new_count == 0) {
            std.log.info("data_plane: no new endpoints to sync (synced={d}, current={d})", .{
                self.synced_endpoint_count,
                self.router_endpoints.count,
            });
            return 0;
        }

        std.log.info("data_plane: syncing config to {d} new endpoints", .{new_count});

        // Resolve backends (reuse existing resolution if valid)
        const expected_backends = countExpectedBackends(config_ptr);
        const resolved_count = self.resolveBackends(config_ptr, resolver) catch |err| {
            std.log.err("data_plane: syncNewEndpoints resolveBackends failed: {s}", .{@errorName(err)});
            return err;
        };

        if (expected_backends > 0 and resolved_count < expected_backends) {
            return DataPlaneError.BackendsNotReady;
        }

        // Translate to JSON
        const json_len = gateway.translator.translateToJson(
            config_ptr,
            self.resolved_backends[0..resolved_count],
            &self.json_buffer,
        ) catch |err| {
            std.log.err("data_plane: syncNewEndpoints translateToJson failed: {s}", .{@errorName(err)});
            return DataPlaneError.TranslationFailed;
        };

        // Push to each new endpoint
        var success_count: u8 = 0;
        var push_idx: u8 = 0;
        while (push_idx < new_count) : (push_idx += 1) {
            const ep = &new_endpoints[push_idx];
            const ip = ep.getIp();

            self.sendConfigToEndpoint(ip, ep.port, self.json_buffer[0..json_len], io) catch |err| {
                std.log.warn("data_plane: push to {s}:{d} failed: {s}", .{ ip, ep.port, @errorName(err) });
                continue;
            };

            // Record successful sync (by pod name)
            self.addSyncedEndpoint(ep.getPodName());
            success_count += 1;
            std.log.info("data_plane: synced config to {s}:{d} (pod={s})", .{ ip, ep.port, ep.getPodName() });
        }

        // S1: Postcondition
        assert(success_count <= new_count);

        return success_count;
    }

    /// Check if pod names in new endpoints differ from current endpoints.
    ///
    /// Returns true if any pod name changed, even if IPs are the same.
    /// TigerStyle S3: Bounded loops.
    fn havePodNamesChanged(self: *const Self, new_endpoints: *const RouterEndpoints) bool {
        // Different count means changed
        if (new_endpoints.count != self.router_endpoints.count) {
            return true;
        }

        // Check each new endpoint's pod name exists in current list
        var new_idx: u8 = 0;
        while (new_idx < new_endpoints.count) : (new_idx += 1) {
            const new_ep = &new_endpoints.endpoints[new_idx];
            const new_pod = new_ep.getPodName();
            if (new_pod.len == 0) continue; // Skip if pod name unknown

            var found = false;
            var cur_idx: u8 = 0;
            while (cur_idx < self.router_endpoints.count) : (cur_idx += 1) {
                const cur_ep = &self.router_endpoints.endpoints[cur_idx];
                if (std.mem.eql(u8, new_pod, cur_ep.getPodName())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return true;
            }
        }

        return false;
    }

    /// Check if an endpoint pod name is in the synced list.
    ///
    /// TigerStyle S3: Bounded loop.
    fn isEndpointSynced(self: *const Self, pod_name: []const u8) bool {
        if (pod_name.len == 0) return false; // Unknown pod name, treat as not synced

        var idx: u8 = 0;
        while (idx < self.synced_endpoint_count) : (idx += 1) {
            const synced_len = self.synced_pod_name_lens[idx];
            if (synced_len == pod_name.len) {
                if (std.mem.eql(u8, self.synced_pod_names[idx][0..synced_len], pod_name)) {
                    return true;
                }
            }
        }
        return false;
    }

    /// Add an endpoint pod name to the synced list.
    ///
    /// TigerStyle S1: Precondition - pod name fits in buffer.
    fn addSyncedEndpoint(self: *Self, pod_name: []const u8) void {
        if (pod_name.len == 0) return; // Skip unknown pod names

        assert(pod_name.len <= k8s_client_mod.MAX_POD_NAME_LEN); // S1: precondition

        if (self.synced_endpoint_count >= MAX_ROUTER_ENDPOINTS) {
            std.log.warn("data_plane: synced endpoint list full, cannot add {s}", .{pod_name});
            return;
        }

        const idx = self.synced_endpoint_count;
        @memcpy(self.synced_pod_names[idx][0..pod_name.len], pod_name);
        self.synced_pod_name_lens[idx] = @intCast(pod_name.len);
        self.synced_endpoint_count += 1;
    }

    /// Clear the synced endpoint list.
    ///
    /// Call this when config changes to ensure all endpoints get the new config.
    pub fn clearSyncedEndpoints(self: *Self) void {
        self.synced_endpoint_count = 0;
        self.synced_pod_name_lens = std.mem.zeroes([MAX_ROUTER_ENDPOINTS]u8);
    }
};

/// Build HTTP request for config push.
///
/// TigerStyle Y1: Extracted from sendConfigRequest to meet 70-line limit.
/// TigerStyle S1: Assertions for preconditions.
fn buildConfigRequest(
    host: []const u8,
    json_body: []const u8,
    content_len_buf: *[16]u8,
) ?serval_core.types.Request {
    // S1: preconditions
    assert(host.len > 0);
    assert(json_body.len > 0);

    // Format Content-Length value
    const content_len_str = std.fmt.bufPrint(content_len_buf, "{d}", .{json_body.len}) catch {
        return null;
    };

    // Build headers.
    // Connection: close is required because we close the connection after receiving
    // the response (defer conn.close()). Without it, HTTP/1.1 defaults to keep-alive
    // and the server waits for more requests, causing ConnectionResetByPeer when we close.
    var header_map = serval_core.types.HeaderMap.init();
    header_map.put("Host", host) catch return null;
    header_map.put("Content-Type", "application/json") catch return null;
    header_map.put("Content-Length", content_len_str) catch return null;
    header_map.put("Connection", "close") catch return null;

    // S2: postcondition - headers populated
    assert(header_map.count > 0);

    return serval_core.types.Request{
        .method = .POST,
        .path = ADMIN_ROUTES_PATH,
        .version = .@"HTTP/1.1",
        .headers = header_map,
        .body = json_body,
    };
}

/// Count expected backends from config.
///
/// Counts unique backend_refs across all HTTPRoutes.
/// TigerStyle S3: Bounded loops over config arrays.
fn countExpectedBackends(config_ptr: *const GatewayConfig) u16 {
    var count: u16 = 0;

    // S3: bounded loop - limited by MAX_HTTP_ROUTES
    for (config_ptr.http_routes) |http_route| {
        // S3: bounded loop - limited by MAX_RULES
        for (http_route.rules) |rule| {
            // S3: bounded loop - limited by MAX_BACKEND_REFS
            count += @intCast(rule.backend_refs.len);
        }
    }

    return count;
}

// ============================================================================
// Tests
// ============================================================================

test "DataPlaneClient create with custom host and port" {
    const client = try DataPlaneClient.create(std.testing.allocator, "10.0.0.1", 9901);
    defer client.destroy();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
    try std.testing.expectEqualStrings("10.0.0.1", client.admin_host);
}

test "DataPlaneClient createLocalhost uses 127.0.0.1" {
    const client = try DataPlaneClient.createLocalhost(std.testing.allocator, DEFAULT_ADMIN_PORT);
    defer client.destroy();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
    try std.testing.expectEqualStrings("127.0.0.1", client.admin_host);
}

test "DataPlaneClient create with default port" {
    const client = try DataPlaneClient.create(std.testing.allocator, "localhost", DEFAULT_ADMIN_PORT);
    defer client.destroy();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
}

test "Constants match serval-core config" {
    try std.testing.expectEqual(core_config.DEFAULT_ADMIN_PORT, DEFAULT_ADMIN_PORT);
    try std.testing.expectEqual(core_config.MAX_CONFIG_PUSH_RETRIES, MAX_RETRIES);
    try std.testing.expectEqual(core_config.CONFIG_PUSH_BACKOFF_BASE_MS, BACKOFF_BASE_MS);
    try std.testing.expectEqual(core_config.MAX_CONFIG_PUSH_BACKOFF_MS, MAX_BACKOFF_MS);
}

test "DataPlaneError has all expected variants" {
    // Verify all error variants exist
    const errors = [_]DataPlaneError{
        DataPlaneError.NoConfig,
        DataPlaneError.ResolutionFailed,
        DataPlaneError.TranslationFailed,
        DataPlaneError.ConnectionFailed,
        DataPlaneError.SendFailed,
        DataPlaneError.ReceiveFailed,
        DataPlaneError.EmptyResponse,
        DataPlaneError.Rejected,
        DataPlaneError.RetriesExhausted,
        DataPlaneError.BackendsNotReady,
        DataPlaneError.NoRouterEndpoints,
        DataPlaneError.AllPushesFailed,
        DataPlaneError.EndpointDiscoveryFailed,
    };

    // Each error should be distinct
    for (errors, 0..) |err1, i| {
        for (errors[i + 1 ..]) |err2| {
            try std.testing.expect(err1 != err2);
        }
    }
}

test "Buffer sizes are bounded" {
    // TigerStyle: Verify buffers have explicit bounds
    try std.testing.expect(MAX_JSON_SIZE_BYTES > 0);
    try std.testing.expect(MAX_JSON_SIZE_BYTES <= 1024 * 1024); // 1MB max
    try std.testing.expect(MAX_RESPONSE_HEADER_SIZE_BYTES > 0);
    try std.testing.expect(MAX_RESPONSE_HEADER_SIZE_BYTES <= 16384); // 16KB max headers
}

test "Retry constants are reasonable" {
    // TigerStyle: Verify retry config is bounded
    try std.testing.expect(MAX_RETRIES > 0);
    try std.testing.expect(MAX_RETRIES <= 10); // Reasonable retry limit
    try std.testing.expect(BACKOFF_BASE_MS > 0);
    try std.testing.expect(MAX_BACKOFF_MS >= BACKOFF_BASE_MS);
    try std.testing.expect(MAX_BACKOFF_MS <= 30000); // 30s max backoff
}

test "DataPlaneClient multi-endpoint mode defaults to false" {
    const client = try DataPlaneClient.create(std.testing.allocator, "localhost", 9901);
    defer client.destroy();

    try std.testing.expect(!client.isMultiEndpointMode());
    try std.testing.expectEqual(@as(u8, 1), client.endpointCount());
}

test "DataPlaneClient router_endpoints initialized empty" {
    const client = try DataPlaneClient.create(std.testing.allocator, "localhost", 9901);
    defer client.destroy();

    try std.testing.expectEqual(@as(u8, 0), client.router_endpoints.count);
}

test "PushResult isFullSuccess" {
    // Full success
    const success = PushResult{ .success_count = 3, .failure_count = 0, .total = 3 };
    try std.testing.expect(success.isFullSuccess());
    try std.testing.expect(success.hasAnySuccess());

    // Partial success
    const partial = PushResult{ .success_count = 2, .failure_count = 1, .total = 3 };
    try std.testing.expect(!partial.isFullSuccess());
    try std.testing.expect(partial.hasAnySuccess());

    // Total failure
    const failure = PushResult{ .success_count = 0, .failure_count = 3, .total = 3 };
    try std.testing.expect(!failure.isFullSuccess());
    try std.testing.expect(!failure.hasAnySuccess());

    // Empty (config unchanged)
    const empty = PushResult{ .success_count = 0, .failure_count = 0, .total = 0 };
    try std.testing.expect(!empty.isFullSuccess()); // No success with 0 total
    try std.testing.expect(!empty.hasAnySuccess());
}

test "MAX_ROUTER_ENDPOINTS constant" {
    try std.testing.expectEqual(@as(u8, 32), MAX_ROUTER_ENDPOINTS);
}
