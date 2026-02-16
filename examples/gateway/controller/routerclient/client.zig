//! Router Client
//!
//! Main client struct for pushing configuration to serval-router admin API.
//! Uses serval-client for HTTP requests, supports multi-instance config push.
//!
//! TigerStyle: No allocation after init, bounded buffers, ~2 assertions per function.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const serval_client = @import("serval-client");
const serval_core = @import("serval-core");
const log = serval_core.log.scoped(.gateway_controller);
const time = serval_core.time;
const serval_net = @import("serval-net");
const gateway = @import("serval-k8s-gateway");
const resolver_mod = @import("../../resolver/mod.zig");
const k8s_client_mod = @import("../../k8s_client/mod.zig");
const push = @import("push.zig");

const Client = serval_client.Client;
const Upstream = serval_core.types.Upstream;
const GatewayConfig = gateway.GatewayConfig;
const ResolvedBackend = gateway.config.ResolvedBackend;
const Resolver = resolver_mod.Resolver;
const K8sClient = k8s_client_mod.Client;
const RouterEndpoint = k8s_client_mod.RouterEndpoint;
const RouterEndpoints = k8s_client_mod.RouterEndpoints;
const MAX_ROUTER_ENDPOINTS = k8s_client_mod.MAX_ROUTER_ENDPOINTS;
const MAX_POD_NAME_LEN = k8s_client_mod.MAX_POD_NAME_LEN;

const mod = @import("mod.zig");
const RouterClientError = mod.RouterClientError;
const MAX_JSON_SIZE_BYTES = mod.MAX_JSON_SIZE_BYTES;
const MAX_RESPONSE_HEADER_SIZE_BYTES = mod.MAX_RESPONSE_HEADER_SIZE_BYTES;
const MAX_RETRIES = mod.MAX_RETRIES;
const BACKOFF_BASE_MS = mod.BACKOFF_BASE_MS;
const MAX_BACKOFF_MS = mod.MAX_BACKOFF_MS;
const ADMIN_ROUTES_PATH = mod.ADMIN_ROUTES_PATH;
const PushResult = @import("types.zig").PushResult;

// ============================================================================
// Router Client (TigerStyle: No allocation after init)
// ============================================================================

pub const RouterClient = struct {
    const Self = @This();

    /// Allocator for client resources.
    allocator: std.mem.Allocator,

    /// Router admin port (default port for single-instance mode).
    admin_port: u16,

    /// Router admin host (typically localhost for sidecar pattern, or service name).
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
    synced_pod_names: [MAX_ROUTER_ENDPOINTS][MAX_POD_NAME_LEN]u8,
    synced_pod_name_lens: [MAX_ROUTER_ENDPOINTS]u8,
    synced_endpoint_count: u8,

    /// Flag indicating endpoints were refreshed since last push.
    /// When true, we should push even if config hash matches.
    endpoints_refreshed: bool,

    /// Create router client on heap.
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

    /// Create router client with default localhost host.
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
    ) RouterClientError!u8 {
        // S1: Preconditions
        assert(@intFromPtr(k8s) != 0);
        assert(namespace.len > 0);
        assert(service_name.len > 0);

        log.debug("router_client: refreshEndpoints for {s}/{s}", .{ namespace, service_name });

        const endpoints = k8s_client_mod.discoverRouterEndpoints(
            k8s,
            namespace,
            service_name,
            self.admin_port,
            io,
        ) catch |err| {
            log.warn("router_client: endpoint discovery failed: {s}", .{@errorName(err)});
            // Fall back to single-instance mode
            self.multi_endpoint_mode = false;
            return RouterClientError.EndpointDiscoveryFailed;
        };

        // Check if pod names changed (not just IPs - IPs can be reused)
        const pods_changed = push.havePodNamesChanged(&self.router_endpoints, &endpoints);
        self.router_endpoints = endpoints;
        self.multi_endpoint_mode = true;
        if (pods_changed) {
            self.endpoints_refreshed = true;
            log.info("router_client: router pods changed, will push config", .{});
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

    /// Push configuration to router.
    ///
    /// Resolves backends using the provided resolver, translates to JSON,
    /// and POSTs to the router admin API.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    /// TigerStyle S3: Bounded operations via serval-client.
    pub fn pushConfig(
        self: *Self,
        config_ptr: *const GatewayConfig,
        resolver: *const Resolver,
        io: Io,
    ) RouterClientError!void {
        // S1: precondition - config has content
        assert(config_ptr.http_routes.len > 0 or config_ptr.gateways.len > 0);

        log.debug("router_client: pushConfig routes={d} gateways={d}", .{
            config_ptr.http_routes.len,
            config_ptr.gateways.len,
        });

        // Count expected backends from config
        const expected_backends = countExpectedBackends(config_ptr);
        log.debug("router_client: expecting {d} backends", .{expected_backends});

        // Step 1: Resolve backends to IPs
        const resolved_count = self.resolveBackends(config_ptr, resolver) catch |err| {
            log.err("router_client: resolveBackends failed: {s}", .{@errorName(err)});
            return err;
        };
        log.debug("router_client: resolved {d} backends", .{resolved_count});

        // Check if all expected backends were resolved
        // Don't push config with unresolved backends - wait for endpoints to arrive
        if (expected_backends > 0 and resolved_count < expected_backends) {
            log.info("router_client: waiting for backends ({d}/{d} resolved)", .{
                resolved_count,
                expected_backends,
            });
            return RouterClientError.BackendsNotReady;
        }

        // Step 2: Translate to JSON using resolved backends
        const json_len = gateway.translator.translateToJson(
            config_ptr,
            self.resolved_backends[0..resolved_count],
            &self.json_buffer,
        ) catch |err| {
            log.err("router_client: translateToJson failed: {s}", .{@errorName(err)});
            return RouterClientError.TranslationFailed;
        };

        // S2: postcondition - non-empty JSON
        assert(json_len > 0);

        // Step 3: Check if config changed (skip redundant pushes)
        const config_hash = std.hash.Wyhash.hash(0, self.json_buffer[0..json_len]);
        if (config_hash == self.last_config_hash) {
            log.debug("router_client: config unchanged (hash={x}), skipping push", .{config_hash});
            return;
        }

        log.debug("router_client: generated JSON len={d}", .{json_len});
        log.debug("router_client: JSON preview: {s}", .{self.json_buffer[0..@min(500, json_len)]});

        // Step 4: Push to router using serval-client
        try self.sendConfigRequest(self.json_buffer[0..json_len], io);

        // Step 5: Update hash after successful push
        self.last_config_hash = config_hash;
        log.info("router_client: config pushed successfully (hash={x})", .{config_hash});
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
    ) RouterClientError!void {
        // S1: precondition - valid config
        assert(config_ptr.http_routes.len > 0 or config_ptr.gateways.len > 0);

        var attempt: u8 = 0;
        var backoff_ms: u64 = BACKOFF_BASE_MS;

        // S3: bounded loop - MAX_RETRIES iterations maximum
        while (attempt < MAX_RETRIES) : (attempt += 1) {
            self.pushConfig(config_ptr, resolver, io) catch |err| {
                // BackendsNotReady is not a failure - endpoints haven't arrived yet.
                // Return immediately without retries; next reconciliation will try again.
                if (err == RouterClientError.BackendsNotReady) {
                    return err;
                }

                // If last attempt, return the appropriate error
                if (attempt + 1 >= MAX_RETRIES) {
                    // S6: explicit error - distinguish exhausted retries vs other failures
                    return switch (err) {
                        RouterClientError.ConnectionFailed,
                        RouterClientError.SendFailed,
                        RouterClientError.ReceiveFailed,
                        RouterClientError.Rejected,
                        => RouterClientError.RetriesExhausted,
                        else => err,
                    };
                }

                // Sleep with exponential backoff
                const backoff_ns = backoff_ms * time.ns_per_ms;
                std.Io.sleep(std.Options.debug_io, .fromNanoseconds(@intCast(backoff_ns)), .awake) catch {};

                // Increase backoff (capped at MAX_BACKOFF_MS)
                backoff_ms = @min(backoff_ms * 2, MAX_BACKOFF_MS);
                continue;
            };

            // S2: postcondition - success on this attempt
            return;
        }

        // S1: postcondition - should never reach here due to loop logic
        return RouterClientError.RetriesExhausted;
    }

    /// Resolve all backends in config to IP addresses.
    ///
    /// Populates resolved_backends buffer from resolver.
    /// TigerStyle S3: Bounded loop over config.http_routes.
    fn resolveBackends(
        self: *Self,
        config_ptr: *const GatewayConfig,
        resolver: *const Resolver,
    ) RouterClientError!u16 {
        // S1: precondition - config is valid
        assert(config_ptr.http_routes.len <= gateway.config.MAX_HTTP_ROUTES);

        log.debug("resolveBackends: resolver has {d} services", .{resolver.serviceCount()});

        var count: u16 = 0;

        // S3: bounded loop - limited by MAX_HTTP_ROUTES
        for (config_ptr.http_routes, 0..) |http_route, route_i| {
            if (route_i >= gateway.config.MAX_HTTP_ROUTES) break;

            log.debug("resolveBackends: route[{d}] has {d} rules", .{ route_i, http_route.rules.len });

            // S3: bounded loop - limited by MAX_RULES
            for (http_route.rules, 0..) |rule, rule_i| {
                if (rule_i >= gateway.config.MAX_RULES) break;

                log.debug("resolveBackends: rule[{d}] has {d} backend_refs", .{ rule_i, rule.backend_refs.len });

                // S3: bounded loop - limited by MAX_BACKEND_REFS
                for (rule.backend_refs, 0..) |backend_ref, ref_i| {
                    if (ref_i >= gateway.config.MAX_BACKEND_REFS) break;

                    log.debug("resolveBackends: trying to resolve backend_ref[{d}]: {s}/{s}:{d}", .{
                        ref_i,
                        backend_ref.namespace,
                        backend_ref.name,
                        backend_ref.port,
                    });

                    if (count >= gateway.config.MAX_RESOLVED_BACKENDS) {
                        return RouterClientError.ResolutionFailed;
                    }

                    // Resolve backend to endpoints using resolver
                    resolver.resolveBackend(
                        backend_ref.name,
                        backend_ref.namespace,
                        &self.resolved_backends[count],
                    ) catch |err| {
                        // Skip backends that can't be resolved (service not found)
                        log.debug("resolveBackends: failed to resolve {s}/{s}: {s}", .{
                            backend_ref.namespace,
                            backend_ref.name,
                            @errorName(err),
                        });
                        continue;
                    };

                    log.debug("resolveBackends: resolved {s}/{s} with {d} endpoints", .{
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

    /// Send config JSON to router admin API using default admin_host:admin_port.
    ///
    /// TigerStyle: Delegates to sendConfigToEndpoint for code reuse.
    fn sendConfigRequest(
        self: *Self,
        json_body: []const u8,
        io: Io,
    ) RouterClientError!void {
        return self.sendConfigToEndpoint(self.admin_host, self.admin_port, json_body, io);
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
    ) RouterClientError!void {
        // S1: preconditions
        assert(host.len > 0);
        assert(port > 0);
        assert(json_body.len > 0);
        assert(json_body.len <= MAX_JSON_SIZE_BYTES);

        // Create DNS resolver for client
        // TigerStyle: DnsResolver has no heap allocations, no deinit needed
        var dns_resolver: serval_net.DnsResolver = undefined;
        serval_net.DnsResolver.init(&dns_resolver, .{});

        // Create HTTP client (no TLS for admin API)
        var client = Client.init(
            self.allocator,
            &dns_resolver,
            null, // No TLS for admin API
            false,
        );
        defer client.deinit();

        // Connect to endpoint
        const upstream = Upstream{
            .host = host,
            .port = port,
            .tls = false,
        };

        var connect_result = client.connect(upstream, io) catch {
            return RouterClientError.ConnectionFailed;
        };
        defer connect_result.conn.close();

        // Build and send request
        var content_len_buf: [16]u8 = undefined;
        const request = buildConfigRequest(
            host,
            json_body,
            &content_len_buf,
        ) orelse return RouterClientError.SendFailed;

        client.sendRequest(&connect_result.conn, &request, null) catch {
            return RouterClientError.SendFailed;
        };

        // Read and validate response
        const response = client.readResponseHeaders(
            &connect_result.conn,
            &self.response_header_buffer,
        ) catch |err| {
            log.err("router_client: failed to read response from {s}:{d}: {s}", .{
                host,
                port,
                @errorName(err),
            });
            return RouterClientError.ReceiveFailed;
        };

        log.debug("router_client: response status={d}", .{response.status});

        if (response.status < 200 or response.status >= 300) {
            log.err("router_client: {s}:{d} rejected with status {d}", .{
                host,
                port,
                response.status,
            });
            return RouterClientError.Rejected;
        }

        // S2: postcondition - successful response
        assert(response.status >= 200 and response.status < 300);
    }

    /// Push config JSON to router endpoints.
    ///
    /// When clear_synced is true: clears synced list and pushes to ALL endpoints (full update).
    /// When clear_synced is false: pushes only to endpoints NOT in synced list (incremental).
    /// Returns PushResult with success/failure counts.
    ///
    /// TigerStyle S1: ~2 assertions per function.
    /// TigerStyle S3: Bounded loop over MAX_ROUTER_ENDPOINTS.
    pub fn pushToAll(
        self: *Self,
        json_body: []const u8,
        io: Io,
        clear_synced: bool,
    ) RouterClientError!PushResult {
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
                log.err("router_client: push to {s}:{d} failed: {s}", .{
                    self.admin_host,
                    self.admin_port,
                    @errorName(err),
                });
                result.failure_count = 1;
                return result;
            };
            result.success_count = 1;
            log.info("router_client: pushed to {s}:{d}", .{ self.admin_host, self.admin_port });
            return result;
        }

        // Clear synced list if this is a full update (config changed)
        if (clear_synced) {
            self.clearSyncedEndpoints();
        }
        self.endpoints_refreshed = false;

        // Count endpoints to push (all if clear_synced, only unsynced otherwise)
        var endpoints_to_push: u8 = 0;

        // S3: bounded loop - limited by MAX_ROUTER_ENDPOINTS
        var idx: u8 = 0;
        while (idx < self.router_endpoints.count) : (idx += 1) {
            const endpoint = &self.router_endpoints.endpoints[idx];
            if (!endpoint.ready) continue;

            // Skip already-synced endpoints in incremental mode
            if (!clear_synced and self.isEndpointSynced(endpoint.getPodName())) {
                continue;
            }

            endpoints_to_push += 1;
            const ip = endpoint.getIp();
            self.sendConfigToEndpoint(ip, endpoint.port, json_body, io) catch |err| {
                log.warn("router_client: push to {s}:{d} failed: {s}", .{
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
            log.info("router_client: pushed to {s}:{d} (pod={s})", .{ ip, endpoint.port, endpoint.getPodName() });
        }

        result.total = endpoints_to_push;

        // Log summary
        if (result.total == 0) {
            log.debug("router_client: no endpoints to push (all already synced)", .{});
        } else if (result.failure_count > 0) {
            log.warn("router_client: config push: {d}/{d} succeeded", .{
                result.success_count,
                result.total,
            });
        } else if (result.success_count > 0) {
            log.info("router_client: config pushed to {d} routers", .{result.success_count});
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
    ) RouterClientError!PushResult {
        // S1: precondition - config has content
        assert(config_ptr.http_routes.len > 0 or config_ptr.gateways.len > 0);

        log.debug("router_client: pushConfigToAll routes={d} gateways={d}", .{
            config_ptr.http_routes.len,
            config_ptr.gateways.len,
        });

        // Count expected backends from config
        const expected_backends = countExpectedBackends(config_ptr);
        log.debug("router_client: expecting {d} backends", .{expected_backends});

        // Step 1: Resolve backends to IPs
        const resolved_count = self.resolveBackends(config_ptr, resolver) catch |err| {
            log.err("router_client: resolveBackends failed: {s}", .{@errorName(err)});
            return err;
        };
        log.debug("router_client: resolved {d} backends", .{resolved_count});

        // Check if all expected backends were resolved
        if (expected_backends > 0 and resolved_count < expected_backends) {
            log.info("router_client: waiting for backends ({d}/{d} resolved)", .{
                resolved_count,
                expected_backends,
            });
            return RouterClientError.BackendsNotReady;
        }

        // Step 2: Translate to JSON using resolved backends
        const json_len = gateway.translator.translateToJson(
            config_ptr,
            self.resolved_backends[0..resolved_count],
            &self.json_buffer,
        ) catch |err| {
            log.err("router_client: translateToJson failed: {s}", .{@errorName(err)});
            return RouterClientError.TranslationFailed;
        };

        // S2: postcondition - non-empty JSON
        assert(json_len > 0);

        // Step 3: Check if config changed OR router endpoints were refreshed
        const config_hash = std.hash.Wyhash.hash(0, self.json_buffer[0..json_len]);
        const config_changed = config_hash != self.last_config_hash;

        if (!config_changed and !self.endpoints_refreshed) {
            log.debug("router_client: config unchanged (hash={x}), skipping push", .{config_hash});
            // Return success with 0 endpoints pushed (config unchanged)
            return PushResult{
                .success_count = 0,
                .failure_count = 0,
                .total = 0,
            };
        }

        log.debug("router_client: generated JSON len={d}", .{json_len});

        // Step 4: Push config
        // - If config changed: clear synced list and push to ALL endpoints (full update)
        // - If only endpoints refreshed: push only to NEW endpoints (incremental)
        var result: PushResult = undefined;

        if (config_changed) {
            log.info("router_client: config changed, pushing to all endpoints", .{});
            result = try self.pushToAll(self.json_buffer[0..json_len], io, true);
        } else {
            // Only endpoints refreshed - push incrementally to new endpoints only
            log.info("router_client: endpoints refreshed, pushing to new endpoints only", .{});
            self.pruneStaleSyncedEndpoints();
            result = try self.pushToAll(self.json_buffer[0..json_len], io, false);
        }

        // Step 5: Update hash only if at least one push succeeded
        if (result.success_count > 0) {
            self.last_config_hash = config_hash;
            if (config_changed) {
                log.info("router_client: config updated (hash={x})", .{config_hash});
            }
        }

        // Check for total failure
        if (result.success_count == 0 and result.total > 0) {
            return RouterClientError.AllPushesFailed;
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
    ) RouterClientError!u8 {
        // S1: Preconditions
        assert(namespace.len > 0);
        assert(service_name.len > 0);

        // Skip if no config has been pushed yet
        if (self.last_config_hash == 0) {
            log.info("router_client: syncNewEndpoints skipped - no config pushed yet", .{});
            return 0;
        }

        // Refresh endpoints from K8s
        _ = self.refreshEndpoints(k8s, namespace, service_name, io) catch |err| {
            log.warn("router_client: syncNewEndpoints discovery failed: {s}", .{@errorName(err)});
            return err;
        };

        // Prune stale entries from synced list (pods that no longer exist)
        self.pruneStaleSyncedEndpoints();

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
                    log.info("router_client: found new endpoint {s}:{d} (pod={s})", .{ ep.getIp(), ep.port, pod_name });
                }
            }
        }

        if (new_count == 0) {
            log.info("router_client: no new endpoints to sync (synced={d}, current={d})", .{
                self.synced_endpoint_count,
                self.router_endpoints.count,
            });
            return 0;
        }

        log.info("router_client: syncing config to {d} new endpoints", .{new_count});

        // Resolve backends (reuse existing resolution if valid)
        const expected_backends = countExpectedBackends(config_ptr);
        const resolved_count = self.resolveBackends(config_ptr, resolver) catch |err| {
            log.err("router_client: syncNewEndpoints resolveBackends failed: {s}", .{@errorName(err)});
            return err;
        };

        if (expected_backends > 0 and resolved_count < expected_backends) {
            return RouterClientError.BackendsNotReady;
        }

        // Translate to JSON
        const json_len = gateway.translator.translateToJson(
            config_ptr,
            self.resolved_backends[0..resolved_count],
            &self.json_buffer,
        ) catch |err| {
            log.err("router_client: syncNewEndpoints translateToJson failed: {s}", .{@errorName(err)});
            return RouterClientError.TranslationFailed;
        };

        // Push to each new endpoint
        var success_count: u8 = 0;
        var push_idx: u8 = 0;
        while (push_idx < new_count) : (push_idx += 1) {
            const ep = &new_endpoints[push_idx];
            const ip = ep.getIp();

            self.sendConfigToEndpoint(ip, ep.port, self.json_buffer[0..json_len], io) catch |err| {
                log.warn("router_client: push to {s}:{d} failed: {s}", .{ ip, ep.port, @errorName(err) });
                continue;
            };

            // Record successful sync (by pod name)
            self.addSyncedEndpoint(ep.getPodName());
            success_count += 1;
            log.info("router_client: synced config to {s}:{d} (pod={s})", .{ ip, ep.port, ep.getPodName() });
        }

        // S1: Postcondition
        assert(success_count <= new_count);

        return success_count;
    }

    /// Check if an endpoint pod name is in the synced list.
    fn isEndpointSynced(self: *const Self, pod_name: []const u8) bool {
        return push.isEndpointSynced(
            &self.synced_pod_names,
            &self.synced_pod_name_lens,
            self.synced_endpoint_count,
            pod_name,
        );
    }

    /// Add an endpoint pod name to the synced list.
    fn addSyncedEndpoint(self: *Self, pod_name: []const u8) void {
        push.addSyncedEndpoint(
            &self.synced_pod_names,
            &self.synced_pod_name_lens,
            &self.synced_endpoint_count,
            pod_name,
        );
    }

    /// Clear the synced endpoint list.
    pub fn clearSyncedEndpoints(self: *Self) void {
        push.clearSyncedEndpoints(
            &self.synced_pod_name_lens,
            &self.synced_endpoint_count,
        );
    }

    /// Prune stale entries from synced list.
    fn pruneStaleSyncedEndpoints(self: *Self) void {
        push.pruneStaleSyncedEndpoints(
            &self.synced_pod_names,
            &self.synced_pod_name_lens,
            &self.synced_endpoint_count,
            &self.router_endpoints,
        );
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

test "RouterClient create with custom host and port" {
    const client = try RouterClient.create(std.testing.allocator, "10.0.0.1", 9901);
    defer client.destroy();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
    try std.testing.expectEqualStrings("10.0.0.1", client.admin_host);
}

test "RouterClient createLocalhost uses 127.0.0.1" {
    const client = try RouterClient.createLocalhost(std.testing.allocator, mod.DEFAULT_ADMIN_PORT);
    defer client.destroy();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
    try std.testing.expectEqualStrings("127.0.0.1", client.admin_host);
}

test "RouterClient create with default port" {
    const client = try RouterClient.create(std.testing.allocator, "localhost", mod.DEFAULT_ADMIN_PORT);
    defer client.destroy();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
}

test "RouterClient multi-endpoint mode defaults to false" {
    const client = try RouterClient.create(std.testing.allocator, "localhost", 9901);
    defer client.destroy();

    try std.testing.expect(!client.isMultiEndpointMode());
    try std.testing.expectEqual(@as(u8, 1), client.endpointCount());
}

test "RouterClient router_endpoints initialized empty" {
    const client = try RouterClient.create(std.testing.allocator, "localhost", 9901);
    defer client.destroy();

    try std.testing.expectEqual(@as(u8, 0), client.router_endpoints.count);
}

test "MAX_ROUTER_ENDPOINTS constant" {
    try std.testing.expectEqual(@as(u8, 32), MAX_ROUTER_ENDPOINTS);
}
