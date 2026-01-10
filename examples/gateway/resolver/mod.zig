//! Resource Resolver
//!
//! Resolves Kubernetes resource references to concrete values:
//! - Service -> Endpoints (pod IPs)
//! - Secret -> TLS certificate/key data
//!
//! TigerStyle: Bounded storage, explicit errors, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;
const gateway = @import("serval-gateway");
const gw_config = gateway.config;

// Import and re-export types from types.zig
const resolver_types = @import("types.zig");

pub const MAX_ENDPOINTS_PER_SERVICE = resolver_types.MAX_ENDPOINTS_PER_SERVICE;
pub const MAX_SERVICES = resolver_types.MAX_SERVICES;
pub const MAX_SECRETS = resolver_types.MAX_SECRETS;
pub const MAX_NAME_LEN = resolver_types.MAX_NAME_LEN;
pub const MAX_IP_LEN = resolver_types.MAX_IP_LEN;
pub const MAX_CERT_SIZE = resolver_types.MAX_CERT_SIZE;
pub const MAX_BASE64_INPUT_SIZE = resolver_types.MAX_BASE64_INPUT_SIZE;

pub const ResolverError = resolver_types.ResolverError;

// Internal type aliases
const IpStorage = resolver_types.IpStorage;
const NameStorage = resolver_types.NameStorage;
const CertStorage = resolver_types.CertStorage;
const StoredEndpoint = resolver_types.StoredEndpoint;
const StoredService = resolver_types.StoredService;
const StoredSecret = resolver_types.StoredSecret;

// Import JSON parsing functions from parsing.zig
const resolver_parsing = @import("parsing.zig");
const parseEndpointsJson = resolver_parsing.parseEndpointsJson;
const parseSecretJson = resolver_parsing.parseSecretJson;

// ============================================================================
// Resolved Types (returned to callers)
// ============================================================================

/// Resolved service with endpoints (view into stored data).
pub const ResolvedService = struct {
    name: []const u8,
    namespace: []const u8,
    endpoints_count: u8,

    // Internal reference for endpoint access
    _stored: *const StoredService,

    /// Get endpoint at index.
    pub fn getEndpoint(self: *const ResolvedService, idx: u8) ?gw_config.ResolvedEndpoint {
        assert(idx < MAX_ENDPOINTS_PER_SERVICE);
        if (idx >= self.endpoints_count) return null;
        const stored_ep = &self._stored.endpoints[idx];
        return gw_config.ResolvedEndpoint{
            .address = stored_ep.ip(),
            .port = stored_ep.port,
        };
    }
};

/// Resolved secret with cert data (view into stored data).
pub const ResolvedSecret = struct {
    name: []const u8,
    namespace: []const u8,
    cert_pem: []const u8,
    key_pem: []const u8,
};

// ============================================================================
// Resolver
// ============================================================================

/// Resource resolver for K8s Services and Secrets.
/// All storage is pre-allocated; no allocation after init.
///
/// TigerStyle C3: Large struct (~2.5MB) must use create/destroy pattern.
/// Contains [128]StoredService and [32]StoredSecret arrays.
pub const Resolver = struct {
    /// Allocator for heap allocation.
    allocator: std.mem.Allocator,

    /// Storage for resolved services.
    services: [MAX_SERVICES]StoredService,

    /// Storage for resolved secrets.
    secrets: [MAX_SECRETS]StoredSecret,

    const Self = @This();

    /// Create resolver on heap with zeroed storage.
    ///
    /// TigerStyle C3: Large struct (~2.5MB) returned via pointer, not value.
    /// TigerStyle S1: Allocator must be valid (non-null implied by type).
    pub fn create(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = Self{
            .allocator = allocator,
            .services = std.mem.zeroes([MAX_SERVICES]StoredService),
            .secrets = std.mem.zeroes([MAX_SECRETS]StoredSecret),
        };

        // S2: postcondition - all storage zeroed means no active entries
        assert(self.serviceCount() == 0);
        assert(self.secretCount() == 0);

        return self;
    }

    /// Destroy resolver and free heap memory.
    ///
    /// TigerStyle: Explicit cleanup, pairs with create.
    pub fn destroy(self: *Self) void {
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// Update service endpoints from K8s Endpoints JSON.
    ///
    /// Expected JSON format:
    /// ```json
    /// {
    ///   "metadata": { "name": "my-service", "namespace": "default" },
    ///   "subsets": [
    ///     {
    ///       "addresses": [{ "ip": "10.0.1.1" }, { "ip": "10.0.1.2" }],
    ///       "ports": [{ "port": 8080 }]
    ///     }
    ///   ]
    /// }
    /// ```
    pub fn updateService(
        self: *Self,
        svc_name: []const u8,
        svc_namespace: []const u8,
        endpoints_json: []const u8,
    ) ResolverError!void {
        // Preconditions
        assert(svc_name.len > 0);
        assert(svc_namespace.len > 0);
        assert(endpoints_json.len > 0);

        if (svc_name.len > MAX_NAME_LEN) return error.NameTooLong;
        if (svc_namespace.len > MAX_NAME_LEN) return error.NameTooLong;

        // Find existing slot or allocate new one
        var slot: ?*StoredService = null;
        var first_empty: ?*StoredService = null;

        for (&self.services) |*svc| {
            if (svc.matches(svc_name, svc_namespace)) {
                slot = svc;
                break;
            }
            if (!svc.active and first_empty == null) {
                first_empty = svc;
            }
        }

        if (slot == null) {
            if (first_empty == null) {
                return error.ServiceLimitExceeded;
            }
            slot = first_empty;
        }

        const target = slot.?;

        // Parse endpoints from JSON
        var endpoints_count: u8 = 0;
        var endpoints_buf: [MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint = undefined;

        try parseEndpointsJson(endpoints_json, &endpoints_buf, &endpoints_count);

        // Update slot atomically (copy all fields)
        @memcpy(target.name_storage[0..svc_name.len], svc_name);
        target.name_len = @intCast(svc_name.len);
        @memcpy(target.namespace_storage[0..svc_namespace.len], svc_namespace);
        target.namespace_len = @intCast(svc_namespace.len);
        @memcpy(target.endpoints[0..endpoints_count], endpoints_buf[0..endpoints_count]);
        target.endpoints_count = endpoints_count;
        target.active = true;

        // Postcondition
        assert(target.active);
        assert(target.endpoints_count <= MAX_ENDPOINTS_PER_SERVICE);
    }

    /// Update secret from K8s Secret JSON.
    ///
    /// Expected JSON format:
    /// ```json
    /// {
    ///   "metadata": { "name": "my-cert", "namespace": "default" },
    ///   "type": "kubernetes.io/tls",
    ///   "data": {
    ///     "tls.crt": "base64-encoded-cert",
    ///     "tls.key": "base64-encoded-key"
    ///   }
    /// }
    /// ```
    pub fn updateSecret(
        self: *Self,
        secret_name: []const u8,
        secret_namespace: []const u8,
        secret_json: []const u8,
    ) ResolverError!void {
        // Preconditions
        assert(secret_name.len > 0);
        assert(secret_namespace.len > 0);
        assert(secret_json.len > 0);

        if (secret_name.len > MAX_NAME_LEN) return error.NameTooLong;
        if (secret_namespace.len > MAX_NAME_LEN) return error.NameTooLong;

        // Find existing slot or allocate new one
        var slot: ?*StoredSecret = null;
        var first_empty: ?*StoredSecret = null;

        for (&self.secrets) |*sec| {
            if (sec.matches(secret_name, secret_namespace)) {
                slot = sec;
                break;
            }
            if (!sec.active and first_empty == null) {
                first_empty = sec;
            }
        }

        if (slot == null) {
            if (first_empty == null) {
                return error.SecretLimitExceeded;
            }
            slot = first_empty;
        }

        const target = slot.?;

        // Parse secret from JSON
        var cert_buf: CertStorage = undefined;
        var cert_len: u16 = 0;
        var key_buf: CertStorage = undefined;
        var key_len: u16 = 0;

        try parseSecretJson(secret_json, &cert_buf, &cert_len, &key_buf, &key_len);

        // Update slot atomically
        @memcpy(target.name_storage[0..secret_name.len], secret_name);
        target.name_len = @intCast(secret_name.len);
        @memcpy(target.namespace_storage[0..secret_namespace.len], secret_namespace);
        target.namespace_len = @intCast(secret_namespace.len);
        @memcpy(target.cert_storage[0..cert_len], cert_buf[0..cert_len]);
        target.cert_len = cert_len;
        @memcpy(target.key_storage[0..key_len], key_buf[0..key_len]);
        target.key_len = key_len;
        target.active = true;

        // Postcondition
        assert(target.active);
        assert(target.cert_len <= MAX_CERT_SIZE);
        assert(target.key_len <= MAX_CERT_SIZE);
    }

    /// Remove a service by name/namespace.
    pub fn removeService(self: *Self, svc_name: []const u8, svc_namespace: []const u8) void {
        assert(svc_name.len > 0);
        assert(svc_namespace.len > 0);

        for (&self.services) |*svc| {
            if (svc.matches(svc_name, svc_namespace)) {
                svc.active = false;
                svc.endpoints_count = 0;
                return;
            }
        }
    }

    /// Remove a secret by name/namespace.
    pub fn removeSecret(self: *Self, secret_name: []const u8, secret_namespace: []const u8) void {
        assert(secret_name.len > 0);
        assert(secret_namespace.len > 0);

        for (&self.secrets) |*sec| {
            if (sec.matches(secret_name, secret_namespace)) {
                sec.active = false;
                sec.cert_len = 0;
                sec.key_len = 0;
                return;
            }
        }
    }

    /// Lookup service by name/namespace.
    /// Returns null if service not found.
    pub fn getService(self: *const Self, svc_name: []const u8, svc_namespace: []const u8) ?ResolvedService {
        assert(svc_name.len > 0);
        assert(svc_namespace.len > 0);

        for (&self.services) |*svc| {
            if (svc.matches(svc_name, svc_namespace)) {
                return ResolvedService{
                    .name = svc.name(),
                    .namespace = svc.namespace(),
                    .endpoints_count = svc.endpoints_count,
                    ._stored = svc,
                };
            }
        }
        return null;
    }

    /// Lookup service endpoints by name/namespace.
    /// Copies endpoints to output buffer, returns count.
    pub fn getServiceEndpoints(
        self: *const Self,
        svc_name: []const u8,
        svc_namespace: []const u8,
        out_endpoints: []gw_config.ResolvedEndpoint,
    ) u8 {
        assert(svc_name.len > 0);
        assert(svc_namespace.len > 0);

        for (&self.services) |*svc| {
            if (svc.matches(svc_name, svc_namespace)) {
                const count = @min(svc.endpoints_count, @as(u8, @intCast(out_endpoints.len)));
                for (0..count) |i| {
                    const stored_ep = &svc.endpoints[i];
                    out_endpoints[i] = gw_config.ResolvedEndpoint{
                        .address = stored_ep.ip(),
                        .port = stored_ep.port,
                    };
                }
                return count;
            }
        }
        return 0;
    }

    /// Lookup secret by name/namespace.
    /// Returns null if secret not found.
    pub fn getSecret(self: *const Self, secret_name: []const u8, secret_namespace: []const u8) ?ResolvedSecret {
        assert(secret_name.len > 0);
        assert(secret_namespace.len > 0);

        for (&self.secrets) |*sec| {
            if (sec.matches(secret_name, secret_namespace)) {
                return ResolvedSecret{
                    .name = sec.name(),
                    .namespace = sec.namespace(),
                    .cert_pem = sec.certPem(),
                    .key_pem = sec.keyPem(),
                };
            }
        }
        return null;
    }

    /// Resolve BackendRef to endpoints using stored service data.
    /// Copies resolved endpoints to output buffer, returns count.
    pub fn resolveBackendRef(
        self: *const Self,
        backend_ref: *const gw_config.BackendRef,
        out_upstreams: []gw_config.ResolvedEndpoint,
    ) u8 {
        assert(backend_ref.name.len > 0);
        assert(backend_ref.namespace.len > 0);

        for (&self.services) |*svc| {
            if (svc.matches(backend_ref.name, backend_ref.namespace)) {
                const count = @min(svc.endpoints_count, @as(u8, @intCast(out_upstreams.len)));
                for (0..count) |i| {
                    const stored_ep = &svc.endpoints[i];
                    // Use backend_ref.port as the target port (service port mapping)
                    out_upstreams[i] = gw_config.ResolvedEndpoint{
                        .address = stored_ep.ip(),
                        .port = backend_ref.port,
                    };
                }
                return count;
            }
        }
        return 0;
    }

    /// Get count of active services.
    pub fn serviceCount(self: *const Self) u8 {
        var count: u8 = 0;
        for (&self.services) |*svc| {
            if (svc.active) count += 1;
        }
        return count;
    }

    /// Get count of active secrets.
    pub fn secretCount(self: *const Self) u8 {
        var count: u8 = 0;
        for (&self.secrets) |*sec| {
            if (sec.active) count += 1;
        }
        return count;
    }

    /// Find a service by name/namespace.
    /// Returns the service index or null if not found.
    fn findService(self: *const Self, svc_name: []const u8, svc_namespace: []const u8) ?usize {
        assert(svc_name.len > 0); // S1: precondition
        assert(svc_namespace.len > 0); // S1: precondition

        for (&self.services, 0..) |*svc, idx| {
            if (svc.matches(svc_name, svc_namespace)) {
                return idx;
            }
        }
        return null;
    }

    /// Resolve a backend reference to ResolvedBackend.
    /// Used by data_plane.zig before calling translator.
    ///
    /// TigerStyle C3: Uses out pointer for large struct (~5KB), avoids stack copy.
    /// TigerStyle S1: Assertions for pre/postconditions.
    pub fn resolveBackend(
        self: *const Self,
        name: []const u8,
        namespace: []const u8,
        out: *gw_config.ResolvedBackend,
    ) ResolverError!void {
        assert(name.len > 0); // S1: precondition
        assert(name.len <= gw_config.MAX_NAME_LEN);
        assert(namespace.len <= gw_config.MAX_NAME_LEN);

        // Find service in our registry
        const service_idx = self.findService(name, namespace) orelse {
            return error.ServiceNotFound;
        };

        const service = &self.services[service_idx];

        // Copy name
        @memcpy(out.name[0..name.len], name);
        out.name_len = @intCast(name.len);

        // Copy namespace
        @memcpy(out.namespace[0..namespace.len], namespace);
        out.namespace_len = @intCast(namespace.len);

        // Copy endpoints
        var ep_count: u8 = 0;
        const max_eps = gw_config.MAX_RESOLVED_ENDPOINTS;
        for (service.endpoints[0..service.endpoints_count]) |ep| {
            if (ep_count >= max_eps) break;

            const ip = ep.ip();
            @memcpy(out.endpoints[ep_count].ip[0..ip.len], ip);
            out.endpoints[ep_count].ip_len = @intCast(ip.len);
            out.endpoints[ep_count].port = ep.port;
            ep_count += 1;
        }
        out.endpoint_count = ep_count;

        assert(out.endpoint_count > 0); // S1: postcondition - found at least one endpoint
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "Resolver create and destroy" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    try std.testing.expectEqual(@as(u8, 0), resolver.serviceCount());
    try std.testing.expectEqual(@as(u8, 0), resolver.secretCount());
}

test "Resolver updateService and getService" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const endpoints_json =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [
        \\        { "ip": "10.0.1.1" },
        \\        { "ip": "10.0.1.2" }
        \\      ],
        \\      "ports": [
        \\        { "port": 8080 }
        \\      ]
        \\    }
        \\  ]
        \\}
    ;

    try resolver.updateService("my-service", "default", endpoints_json);

    try std.testing.expectEqual(@as(u8, 1), resolver.serviceCount());

    const svc = resolver.getService("my-service", "default");
    try std.testing.expect(svc != null);
    try std.testing.expectEqualStrings("my-service", svc.?.name);
    try std.testing.expectEqualStrings("default", svc.?.namespace);
    try std.testing.expectEqual(@as(u8, 2), svc.?.endpoints_count);

    // Check endpoints
    const ep0 = svc.?.getEndpoint(0);
    try std.testing.expect(ep0 != null);
    try std.testing.expectEqualStrings("10.0.1.1", ep0.?.address);
    try std.testing.expectEqual(@as(u16, 8080), ep0.?.port);

    const ep1 = svc.?.getEndpoint(1);
    try std.testing.expect(ep1 != null);
    try std.testing.expectEqualStrings("10.0.1.2", ep1.?.address);
    try std.testing.expectEqual(@as(u16, 8080), ep1.?.port);

    // Out of bounds
    try std.testing.expect(svc.?.getEndpoint(2) == null);
}

test "Resolver getServiceEndpoints" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const endpoints_json =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [
        \\        { "ip": "10.0.1.1" },
        \\        { "ip": "10.0.1.2" },
        \\        { "ip": "10.0.1.3" }
        \\      ],
        \\      "ports": [
        \\        { "port": 9090 }
        \\      ]
        \\    }
        \\  ]
        \\}
    ;

    try resolver.updateService("api-service", "prod", endpoints_json);

    var endpoints: [10]gw_config.ResolvedEndpoint = undefined;
    const count = resolver.getServiceEndpoints("api-service", "prod", &endpoints);

    try std.testing.expectEqual(@as(u8, 3), count);
    try std.testing.expectEqualStrings("10.0.1.1", endpoints[0].address);
    try std.testing.expectEqual(@as(u16, 9090), endpoints[0].port);
    try std.testing.expectEqualStrings("10.0.1.3", endpoints[2].address);
}

test "Resolver updateService overwrites existing" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const json1 =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [{ "ip": "10.0.1.1" }],
        \\      "ports": [{ "port": 8080 }]
        \\    }
        \\  ]
        \\}
    ;

    const json2 =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [
        \\        { "ip": "10.0.2.1" },
        \\        { "ip": "10.0.2.2" }
        \\      ],
        \\      "ports": [{ "port": 9090 }]
        \\    }
        \\  ]
        \\}
    ;

    try resolver.updateService("svc", "ns", json1);
    try std.testing.expectEqual(@as(u8, 1), resolver.serviceCount());

    const svc1 = resolver.getService("svc", "ns").?;
    try std.testing.expectEqual(@as(u8, 1), svc1.endpoints_count);

    // Update same service
    try resolver.updateService("svc", "ns", json2);
    try std.testing.expectEqual(@as(u8, 1), resolver.serviceCount());

    const svc2 = resolver.getService("svc", "ns").?;
    try std.testing.expectEqual(@as(u8, 2), svc2.endpoints_count);

    const ep = svc2.getEndpoint(0).?;
    try std.testing.expectEqualStrings("10.0.2.1", ep.address);
    try std.testing.expectEqual(@as(u16, 9090), ep.port);
}

test "Resolver removeService" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const endpoints_json =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [{ "ip": "10.0.1.1" }],
        \\      "ports": [{ "port": 8080 }]
        \\    }
        \\  ]
        \\}
    ;

    try resolver.updateService("svc", "ns", endpoints_json);
    try std.testing.expectEqual(@as(u8, 1), resolver.serviceCount());
    try std.testing.expect(resolver.getService("svc", "ns") != null);

    resolver.removeService("svc", "ns");
    try std.testing.expectEqual(@as(u8, 0), resolver.serviceCount());
    try std.testing.expect(resolver.getService("svc", "ns") == null);
}

test "Resolver getService not found" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    try std.testing.expect(resolver.getService("nonexistent", "ns") == null);
}

test "Resolver updateSecret and getSecret" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    // Base64 encode test cert/key
    const cert_plain = "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----";
    const key_plain = "-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----";

    var cert_b64: [256]u8 = undefined;
    const cert_b64_slice = std.base64.standard.Encoder.encode(&cert_b64, cert_plain);

    var key_b64: [256]u8 = undefined;
    const key_b64_slice = std.base64.standard.Encoder.encode(&key_b64, key_plain);

    var json_buf: [1024]u8 = undefined;
    const secret_json = std.fmt.bufPrint(&json_buf,
        \\{{
        \\  "type": "kubernetes.io/tls",
        \\  "data": {{
        \\    "tls.crt": "{s}",
        \\    "tls.key": "{s}"
        \\  }}
        \\}}
    , .{ cert_b64_slice, key_b64_slice }) catch unreachable;

    try resolver.updateSecret("my-cert", "default", secret_json);

    try std.testing.expectEqual(@as(u8, 1), resolver.secretCount());

    const sec = resolver.getSecret("my-cert", "default");
    try std.testing.expect(sec != null);
    try std.testing.expectEqualStrings("my-cert", sec.?.name);
    try std.testing.expectEqualStrings("default", sec.?.namespace);
    try std.testing.expectEqualStrings(cert_plain, sec.?.cert_pem);
    try std.testing.expectEqualStrings(key_plain, sec.?.key_pem);
}

test "Resolver removeSecret" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const cert_plain = "cert-data";
    const key_plain = "key-data";

    var cert_b64: [64]u8 = undefined;
    const cert_b64_slice = std.base64.standard.Encoder.encode(&cert_b64, cert_plain);

    var key_b64: [64]u8 = undefined;
    const key_b64_slice = std.base64.standard.Encoder.encode(&key_b64, key_plain);

    var json_buf: [512]u8 = undefined;
    const secret_json = std.fmt.bufPrint(&json_buf,
        \\{{
        \\  "type": "kubernetes.io/tls",
        \\  "data": {{
        \\    "tls.crt": "{s}",
        \\    "tls.key": "{s}"
        \\  }}
        \\}}
    , .{ cert_b64_slice, key_b64_slice }) catch unreachable;

    try resolver.updateSecret("sec", "ns", secret_json);
    try std.testing.expectEqual(@as(u8, 1), resolver.secretCount());

    resolver.removeSecret("sec", "ns");
    try std.testing.expectEqual(@as(u8, 0), resolver.secretCount());
    try std.testing.expect(resolver.getSecret("sec", "ns") == null);
}

test "Resolver getSecret not found" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    try std.testing.expect(resolver.getSecret("nonexistent", "ns") == null);
}

test "Resolver resolveBackendRef" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const endpoints_json =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [
        \\        { "ip": "10.0.1.1" },
        \\        { "ip": "10.0.1.2" }
        \\      ],
        \\      "ports": [{ "port": 8080 }]
        \\    }
        \\  ]
        \\}
    ;

    try resolver.updateService("backend-svc", "prod", endpoints_json);

    const backend_ref = gw_config.BackendRef{
        .name = "backend-svc",
        .namespace = "prod",
        .port = 9000, // Different from pod port - service port
    };

    var upstreams: [10]gw_config.ResolvedEndpoint = undefined;
    const count = resolver.resolveBackendRef(&backend_ref, &upstreams);

    try std.testing.expectEqual(@as(u8, 2), count);
    // Should use backend_ref.port, not the pod port
    try std.testing.expectEqual(@as(u16, 9000), upstreams[0].port);
    try std.testing.expectEqual(@as(u16, 9000), upstreams[1].port);
    try std.testing.expectEqualStrings("10.0.1.1", upstreams[0].address);
    try std.testing.expectEqualStrings("10.0.1.2", upstreams[1].address);
}

test "Resolver resolveBackendRef not found" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const backend_ref = gw_config.BackendRef{
        .name = "nonexistent",
        .namespace = "ns",
        .port = 8080,
    };

    var upstreams: [10]gw_config.ResolvedEndpoint = undefined;
    const count = resolver.resolveBackendRef(&backend_ref, &upstreams);

    try std.testing.expectEqual(@as(u8, 0), count);
}

test "MAX constants are within bounds" {
    comptime {
        assert(MAX_ENDPOINTS_PER_SERVICE <= 255);
        assert(MAX_SERVICES <= 255);
        assert(MAX_SECRETS <= 255);
        assert(MAX_NAME_LEN <= 65535);
        assert(MAX_IP_LEN <= 255);
        assert(MAX_CERT_SIZE <= 65535);
    }
}

test "Resolver multiple services" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const json1 =
        \\{
        \\  "subsets": [{
        \\    "addresses": [{ "ip": "10.0.1.1" }],
        \\    "ports": [{ "port": 8080 }]
        \\  }]
        \\}
    ;

    const json2 =
        \\{
        \\  "subsets": [{
        \\    "addresses": [{ "ip": "10.0.2.1" }],
        \\    "ports": [{ "port": 9090 }]
        \\  }]
        \\}
    ;

    try resolver.updateService("svc1", "ns1", json1);
    try resolver.updateService("svc2", "ns2", json2);

    try std.testing.expectEqual(@as(u8, 2), resolver.serviceCount());

    const svc1 = resolver.getService("svc1", "ns1").?;
    try std.testing.expectEqualStrings("10.0.1.1", svc1.getEndpoint(0).?.address);

    const svc2 = resolver.getService("svc2", "ns2").?;
    try std.testing.expectEqualStrings("10.0.2.1", svc2.getEndpoint(0).?.address);
}

test "Resolver slot reuse after remove" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const json =
        \\{
        \\  "subsets": [{
        \\    "addresses": [{ "ip": "10.0.1.1" }],
        \\    "ports": [{ "port": 8080 }]
        \\  }]
        \\}
    ;

    try resolver.updateService("svc1", "ns", json);
    try std.testing.expectEqual(@as(u8, 1), resolver.serviceCount());

    resolver.removeService("svc1", "ns");
    try std.testing.expectEqual(@as(u8, 0), resolver.serviceCount());

    // Should reuse the slot
    try resolver.updateService("svc2", "ns", json);
    try std.testing.expectEqual(@as(u8, 1), resolver.serviceCount());
    try std.testing.expect(resolver.getService("svc2", "ns") != null);
}

test "Resolver resolveBackend" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    const endpoints_json =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [
        \\        { "ip": "10.0.1.1" },
        \\        { "ip": "10.0.1.2" }
        \\      ],
        \\      "ports": [{ "port": 8080 }]
        \\    }
        \\  ]
        \\}
    ;

    try resolver.updateService("backend-svc", "prod", endpoints_json);

    var resolved: gw_config.ResolvedBackend = undefined;
    try resolver.resolveBackend("backend-svc", "prod", &resolved);

    try std.testing.expectEqualStrings("backend-svc", resolved.getName());
    try std.testing.expectEqualStrings("prod", resolved.getNamespace());
    try std.testing.expectEqual(@as(u8, 2), resolved.endpoint_count);

    const endpoints = resolved.getEndpoints();
    try std.testing.expectEqualStrings("10.0.1.1", endpoints[0].getIp());
    try std.testing.expectEqual(@as(u16, 8080), endpoints[0].port);
    try std.testing.expectEqualStrings("10.0.1.2", endpoints[1].getIp());
    try std.testing.expectEqual(@as(u16, 8080), endpoints[1].port);
}

test "Resolver resolveBackend not found" {
    const resolver = try Resolver.create(std.testing.allocator);
    defer resolver.destroy();

    var resolved: gw_config.ResolvedBackend = undefined;
    try std.testing.expectError(error.ServiceNotFound, resolver.resolveBackend("nonexistent", "ns", &resolved));
}
