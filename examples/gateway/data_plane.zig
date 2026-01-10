//! Data Plane Client
//!
//! Pushes configuration to serval-router admin API using serval-client.
//! Resolves backends before translation to decouple from K8s-specific Resolver.
//!
//! TigerStyle: Uses serval-client, bounded buffers, explicit errors, ~2 assertions per function.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const serval_client = @import("serval-client");
const serval_core = @import("serval-core");
const serval_net = @import("serval-net");
const gateway = @import("serval-gateway");
const resolver_mod = @import("resolver.zig");

const Client = serval_client.Client;
const Upstream = serval_core.types.Upstream;
const core_config = serval_core.config;
const GatewayConfig = gateway.GatewayConfig;
const ResolvedBackend = gateway.config.ResolvedBackend;
const FixedResolvedEndpoint = gateway.config.FixedResolvedEndpoint;
const Resolver = resolver_mod.Resolver;

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
};

// ============================================================================
// Data Plane Client (TigerStyle: No allocation after init)
// ============================================================================

pub const DataPlaneClient = struct {
    const Self = @This();

    /// Allocator for client resources.
    allocator: std.mem.Allocator,

    /// Data plane admin port.
    admin_port: u16,

    /// Data plane host (typically localhost for sidecar pattern).
    admin_host: []const u8,

    /// JSON buffer for config serialization (TigerStyle S7: bounded).
    json_buffer: [MAX_JSON_SIZE_BYTES]u8,

    /// Response header buffer (TigerStyle S7: bounded).
    response_header_buffer: [MAX_RESPONSE_HEADER_SIZE_BYTES]u8,

    /// Resolved backends buffer (TigerStyle S7: bounded).
    resolved_backends: [gateway.config.MAX_RESOLVED_BACKENDS]ResolvedBackend,

    /// Initialize data plane client.
    ///
    /// TigerStyle S1: Assertions for preconditions.
    /// TigerStyle S5: Fixed buffers, no runtime allocation.
    pub fn init(allocator: std.mem.Allocator, admin_host: []const u8, admin_port: u16) Self {
        assert(admin_port > 0); // S1: precondition - valid port
        assert(admin_host.len > 0); // S1: precondition - non-empty host

        return Self{
            .allocator = allocator,
            .admin_port = admin_port,
            .admin_host = admin_host,
            .json_buffer = undefined,
            .response_header_buffer = undefined,
            .resolved_backends = undefined,
        };
    }

    /// Initialize data plane client with default localhost host.
    ///
    /// TigerStyle S1: Assertions for preconditions.
    pub fn initLocalhost(allocator: std.mem.Allocator, admin_port: u16) Self {
        return init(allocator, "127.0.0.1", admin_port);
    }

    /// Deinitialize client resources.
    /// TigerStyle: Explicit cleanup, pairs with init.
    pub fn deinit(self: *Self) void {
        _ = self;
        // No resources to free - fixed buffers only
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

        // Step 1: Resolve backends to IPs
        const resolved_count = try self.resolveBackends(config_ptr, resolver);

        // Step 2: Translate to JSON using resolved backends
        const json_len = gateway.translator.translateToJson(
            config_ptr,
            self.resolved_backends[0..resolved_count],
            &self.json_buffer,
        ) catch {
            return DataPlaneError.TranslationFailed;
        };

        // S2: postcondition - non-empty JSON
        assert(json_len > 0);

        // Step 3: Push to data plane using serval-client
        try self.sendConfigRequest(self.json_buffer[0..json_len], io);
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
                std.time.sleep(backoff_ms * std.time.ns_per_ms);

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

        var count: u16 = 0;

        // S3: bounded loop - limited by MAX_HTTP_ROUTES
        for (config_ptr.http_routes, 0..) |http_route, route_i| {
            if (route_i >= gateway.config.MAX_HTTP_ROUTES) break;

            // S3: bounded loop - limited by MAX_RULES
            for (http_route.rules, 0..) |rule, rule_i| {
                if (rule_i >= gateway.config.MAX_RULES) break;

                // S3: bounded loop - limited by MAX_BACKEND_REFS
                for (rule.backend_refs, 0..) |backend_ref, ref_i| {
                    if (ref_i >= gateway.config.MAX_BACKEND_REFS) break;

                    if (count >= gateway.config.MAX_RESOLVED_BACKENDS) {
                        return DataPlaneError.ResolutionFailed;
                    }

                    // Resolve backend to endpoints using resolver
                    resolver.resolveBackend(
                        backend_ref.name,
                        backend_ref.namespace,
                        &self.resolved_backends[count],
                    ) catch {
                        // Skip backends that can't be resolved (service not found)
                        continue;
                    };

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
    fn sendConfigRequest(
        self: *Self,
        json_body: []const u8,
        io: Io,
    ) DataPlaneError!void {
        // S1: preconditions
        assert(json_body.len > 0);
        assert(json_body.len <= MAX_JSON_SIZE_BYTES);

        // Create DNS resolver for client (admin is typically localhost)
        var dns_resolver = serval_net.DnsResolver.init(.{});
        defer dns_resolver.deinit();

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

        // Format Content-Length value into stable buffer
        var content_len_buf: [16]u8 = undefined;
        const content_len_str = std.fmt.bufPrint(&content_len_buf, "{d}", .{json_body.len}) catch {
            return DataPlaneError.SendFailed;
        };

        // Build request with Content-Type and Content-Length headers
        var header_map = serval_core.types.HeaderMap.init();
        header_map.put("Host", self.admin_host) catch {
            return DataPlaneError.SendFailed;
        };
        header_map.put("Content-Type", "application/json") catch {
            return DataPlaneError.SendFailed;
        };
        header_map.put("Content-Length", content_len_str) catch {
            return DataPlaneError.SendFailed;
        };

        const request = serval_core.types.Request{
            .method = .POST,
            .path = ADMIN_ROUTES_PATH,
            .version = .@"HTTP/1.1",
            .headers = header_map,
            .body = json_body,
        };

        // Send request
        client.sendRequest(&connect_result.conn, &request, null) catch {
            return DataPlaneError.SendFailed;
        };

        // Read response headers
        const response = client.readResponseHeaders(
            &connect_result.conn,
            &self.response_header_buffer,
        ) catch {
            return DataPlaneError.ReceiveFailed;
        };

        // Check response status (expect 2xx)
        if (response.status < 200 or response.status >= 300) {
            return DataPlaneError.Rejected;
        }

        // S2: postcondition - successful response
        assert(response.status >= 200 and response.status < 300);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DataPlaneClient init with custom host and port" {
    var client = DataPlaneClient.init(std.testing.allocator, "10.0.0.1", 9901);
    defer client.deinit();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
    try std.testing.expectEqualStrings("10.0.0.1", client.admin_host);
}

test "DataPlaneClient initLocalhost uses 127.0.0.1" {
    var client = DataPlaneClient.initLocalhost(std.testing.allocator, DEFAULT_ADMIN_PORT);
    defer client.deinit();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
    try std.testing.expectEqualStrings("127.0.0.1", client.admin_host);
}

test "DataPlaneClient init with default port" {
    var client = DataPlaneClient.init(std.testing.allocator, "localhost", DEFAULT_ADMIN_PORT);
    defer client.deinit();
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
