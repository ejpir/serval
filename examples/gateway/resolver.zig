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

// ============================================================================
// Bounded Array Limits (TigerStyle: explicit bounds, no unbounded growth)
// ============================================================================

/// Maximum endpoints per service (pod instances).
pub const MAX_ENDPOINTS_PER_SERVICE: u8 = 64;

/// Maximum services that can be resolved concurrently.
pub const MAX_SERVICES: u8 = 128;

/// Maximum secrets that can be resolved concurrently.
pub const MAX_SECRETS: u8 = 32;

/// Maximum length of name/namespace strings.
pub const MAX_NAME_LEN: u16 = 253; // K8s DNS-1123 subdomain max

/// Maximum length of IP address string (IPv6: 39 chars, IPv4: 15 chars).
pub const MAX_IP_LEN: u8 = 45; // IPv6 mapped IPv4: "::ffff:xxx.xxx.xxx.xxx"

/// Maximum size of base64-decoded cert/key data.
pub const MAX_CERT_SIZE: u32 = 16384; // 16KB should cover most certificates

/// Maximum size of base64-encoded input (cert data before decoding).
pub const MAX_BASE64_INPUT_SIZE: u32 = 22000; // ~16KB * 4/3 for base64 overhead

/// Maximum number of subsets in Endpoints JSON.
const MAX_SUBSETS: u8 = 8;

/// Maximum number of addresses per subset.
const MAX_ADDRESSES_PER_SUBSET: u8 = 32;

/// Maximum number of ports per subset.
const MAX_PORTS_PER_SUBSET: u8 = 8;

// ============================================================================
// Error Types
// ============================================================================

pub const ResolverError = error{
    /// Too many services registered (exceeds MAX_SERVICES).
    ServiceLimitExceeded,
    /// Too many secrets registered (exceeds MAX_SECRETS).
    SecretLimitExceeded,
    /// Too many endpoints for service (exceeds MAX_ENDPOINTS_PER_SERVICE).
    EndpointLimitExceeded,
    /// Name or namespace string too long.
    NameTooLong,
    /// Invalid JSON format in Endpoints data.
    InvalidEndpointsJson,
    /// Invalid JSON format in Secret data.
    InvalidSecretJson,
    /// Secret is not of type kubernetes.io/tls.
    InvalidSecretType,
    /// Missing tls.crt in Secret data.
    MissingTlsCert,
    /// Missing tls.key in Secret data.
    MissingTlsKey,
    /// Base64 decoding failed for cert/key.
    Base64DecodeFailed,
    /// Certificate data too large.
    CertTooLarge,
    /// IP address string too long.
    IpTooLong,
    /// Output buffer too small.
    BufferTooSmall,
    /// Service not found in resolver registry.
    ServiceNotFound,
};

// ============================================================================
// Storage Types
// ============================================================================

/// Fixed-size storage for endpoint IP addresses.
const IpStorage = [MAX_IP_LEN]u8;

/// Fixed-size storage for name strings.
const NameStorage = [MAX_NAME_LEN]u8;

/// Fixed-size storage for certificate/key PEM data.
const CertStorage = [MAX_CERT_SIZE]u8;

/// Stored endpoint with inline IP string.
const StoredEndpoint = struct {
    ip_storage: IpStorage,
    ip_len: u8,
    port: u16,

    /// Get IP as slice.
    pub fn ip(self: *const StoredEndpoint) []const u8 {
        assert(self.ip_len <= MAX_IP_LEN);
        return self.ip_storage[0..self.ip_len];
    }
};

/// Stored service with inline storage.
const StoredService = struct {
    name_storage: NameStorage,
    name_len: u8,
    namespace_storage: NameStorage,
    namespace_len: u8,
    endpoints: [MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint,
    endpoints_count: u8,
    active: bool,

    /// Get name as slice.
    pub fn name(self: *const StoredService) []const u8 {
        assert(self.name_len <= MAX_NAME_LEN);
        return self.name_storage[0..self.name_len];
    }

    /// Get namespace as slice.
    pub fn namespace(self: *const StoredService) []const u8 {
        assert(self.namespace_len <= MAX_NAME_LEN);
        return self.namespace_storage[0..self.namespace_len];
    }

    /// Check if this service matches name/namespace.
    pub fn matches(self: *const StoredService, svc_name: []const u8, svc_namespace: []const u8) bool {
        if (!self.active) return false;
        return std.mem.eql(u8, self.name(), svc_name) and
            std.mem.eql(u8, self.namespace(), svc_namespace);
    }
};

/// Stored secret with inline storage.
const StoredSecret = struct {
    name_storage: NameStorage,
    name_len: u8,
    namespace_storage: NameStorage,
    namespace_len: u8,
    cert_storage: CertStorage,
    cert_len: u16,
    key_storage: CertStorage,
    key_len: u16,
    active: bool,

    /// Get name as slice.
    pub fn name(self: *const StoredSecret) []const u8 {
        assert(self.name_len <= MAX_NAME_LEN);
        return self.name_storage[0..self.name_len];
    }

    /// Get namespace as slice.
    pub fn namespace(self: *const StoredSecret) []const u8 {
        assert(self.namespace_len <= MAX_NAME_LEN);
        return self.namespace_storage[0..self.namespace_len];
    }

    /// Get certificate PEM as slice.
    pub fn certPem(self: *const StoredSecret) []const u8 {
        assert(self.cert_len <= MAX_CERT_SIZE);
        return self.cert_storage[0..self.cert_len];
    }

    /// Get key PEM as slice.
    pub fn keyPem(self: *const StoredSecret) []const u8 {
        assert(self.key_len <= MAX_CERT_SIZE);
        return self.key_storage[0..self.key_len];
    }

    /// Check if this secret matches name/namespace.
    pub fn matches(self: *const StoredSecret, secret_name: []const u8, secret_namespace: []const u8) bool {
        if (!self.active) return false;
        return std.mem.eql(u8, self.name(), secret_name) and
            std.mem.eql(u8, self.namespace(), secret_namespace);
    }
};

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
pub const Resolver = struct {
    /// Storage for resolved services.
    services: [MAX_SERVICES]StoredService,

    /// Storage for resolved secrets.
    secrets: [MAX_SECRETS]StoredSecret,

    const Self = @This();

    /// Initialize resolver with zeroed storage.
    pub fn init() Self {
        return Self{
            .services = std.mem.zeroes([MAX_SERVICES]StoredService),
            .secrets = std.mem.zeroes([MAX_SECRETS]StoredSecret),
        };
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
// JSON Parsing Helpers
// ============================================================================

/// JSON types for K8s Endpoints parsing.
const EndpointsJson = struct {
    subsets: ?[]const SubsetJson = null,
};

const SubsetJson = struct {
    addresses: ?[]const AddressJson = null,
    ports: ?[]const PortJson = null,
};

const AddressJson = struct {
    ip: []const u8,
};

const PortJson = struct {
    port: u16,
};

/// JSON types for K8s Secret parsing.
const SecretJson = struct {
    type: ?[]const u8 = null,
    data: ?DataJson = null,
};

const DataJson = struct {
    @"tls.crt": ?[]const u8 = null,
    @"tls.key": ?[]const u8 = null,
};

/// Parse K8s Endpoints JSON into StoredEndpoint array.
fn parseEndpointsJson(
    json_data: []const u8,
    out_endpoints: *[MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint,
    out_count: *u8,
) ResolverError!void {
    assert(json_data.len > 0);

    const parsed = std.json.parseFromSlice(
        EndpointsJson,
        std.heap.page_allocator, // Temporary allocator for parsing only
        json_data,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return error.InvalidEndpointsJson;
    };
    defer parsed.deinit();

    const endpoints = parsed.value;
    var count: u8 = 0;

    const subsets = endpoints.subsets orelse {
        out_count.* = 0;
        return;
    };

    // Bound loop iterations (TigerStyle: no unbounded loops)
    const max_subsets = @min(subsets.len, MAX_SUBSETS);

    for (subsets[0..max_subsets]) |subset| {
        const addresses = subset.addresses orelse continue;
        const ports = subset.ports orelse continue;

        if (ports.len == 0) continue;

        // Use first port (simplification - full impl would handle named ports)
        const port = ports[0].port;

        const max_addresses = @min(addresses.len, MAX_ADDRESSES_PER_SUBSET);

        for (addresses[0..max_addresses]) |addr| {
            if (count >= MAX_ENDPOINTS_PER_SERVICE) {
                return error.EndpointLimitExceeded;
            }

            if (addr.ip.len > MAX_IP_LEN) {
                return error.IpTooLong;
            }

            var stored = &out_endpoints[count];
            @memcpy(stored.ip_storage[0..addr.ip.len], addr.ip);
            stored.ip_len = @intCast(addr.ip.len);
            stored.port = port;
            count += 1;
        }
    }

    out_count.* = count;

    // Postcondition
    assert(out_count.* <= MAX_ENDPOINTS_PER_SERVICE);
}

/// Parse K8s Secret JSON and decode base64 cert/key.
fn parseSecretJson(
    json_data: []const u8,
    out_cert: *CertStorage,
    out_cert_len: *u16,
    out_key: *CertStorage,
    out_key_len: *u16,
) ResolverError!void {
    assert(json_data.len > 0);

    const parsed = std.json.parseFromSlice(
        SecretJson,
        std.heap.page_allocator, // Temporary allocator for parsing only
        json_data,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return error.InvalidSecretJson;
    };
    defer parsed.deinit();

    const secret = parsed.value;

    // Verify secret type
    if (secret.type) |secret_type| {
        if (!std.mem.eql(u8, secret_type, "kubernetes.io/tls")) {
            return error.InvalidSecretType;
        }
    }

    const data = secret.data orelse return error.InvalidSecretJson;

    // Decode certificate
    const cert_b64 = data.@"tls.crt" orelse return error.MissingTlsCert;
    if (cert_b64.len > MAX_BASE64_INPUT_SIZE) {
        return error.CertTooLarge;
    }
    const cert_len = decodeBase64(cert_b64, out_cert) catch {
        return error.Base64DecodeFailed;
    };
    if (cert_len > MAX_CERT_SIZE) {
        return error.CertTooLarge;
    }
    out_cert_len.* = @intCast(cert_len);

    // Decode key
    const key_b64 = data.@"tls.key" orelse return error.MissingTlsKey;
    if (key_b64.len > MAX_BASE64_INPUT_SIZE) {
        return error.CertTooLarge;
    }
    const key_len = decodeBase64(key_b64, out_key) catch {
        return error.Base64DecodeFailed;
    };
    if (key_len > MAX_CERT_SIZE) {
        return error.CertTooLarge;
    }
    out_key_len.* = @intCast(key_len);

    // Postconditions
    assert(out_cert_len.* <= MAX_CERT_SIZE);
    assert(out_key_len.* <= MAX_CERT_SIZE);
}

/// Decode base64 data into output buffer.
/// Returns decoded length.
fn decodeBase64(input: []const u8, output: *CertStorage) !usize {
    if (input.len == 0) return 0;

    // Calculate expected decoded size
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(input) catch {
        return error.InvalidCharacter;
    };

    if (decoded_len > MAX_CERT_SIZE) {
        return error.NoSpaceLeft;
    }

    // Decode
    std.base64.standard.Decoder.decode(output[0..decoded_len], input) catch {
        return error.InvalidCharacter;
    };

    return decoded_len;
}

// ============================================================================
// Unit Tests
// ============================================================================

test "Resolver init" {
    const resolver = Resolver.init();
    try std.testing.expectEqual(@as(u8, 0), resolver.serviceCount());
    try std.testing.expectEqual(@as(u8, 0), resolver.secretCount());
}

test "Resolver updateService and getService" {
    var resolver = Resolver.init();

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
    var resolver = Resolver.init();

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
    var resolver = Resolver.init();

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
    var resolver = Resolver.init();

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
    const resolver = Resolver.init();
    try std.testing.expect(resolver.getService("nonexistent", "ns") == null);
}

test "Resolver updateSecret and getSecret" {
    var resolver = Resolver.init();

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
    var resolver = Resolver.init();

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
    const resolver = Resolver.init();
    try std.testing.expect(resolver.getSecret("nonexistent", "ns") == null);
}

test "Resolver resolveBackendRef" {
    var resolver = Resolver.init();

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
    const resolver = Resolver.init();

    const backend_ref = gw_config.BackendRef{
        .name = "nonexistent",
        .namespace = "ns",
        .port = 8080,
    };

    var upstreams: [10]gw_config.ResolvedEndpoint = undefined;
    const count = resolver.resolveBackendRef(&backend_ref, &upstreams);

    try std.testing.expectEqual(@as(u8, 0), count);
}

test "parseEndpointsJson empty subsets" {
    var endpoints: [MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint = undefined;
    var count: u8 = 0;

    const json = "{}";
    try parseEndpointsJson(json, &endpoints, &count);
    try std.testing.expectEqual(@as(u8, 0), count);
}

test "parseEndpointsJson multiple subsets" {
    var endpoints: [MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint = undefined;
    var count: u8 = 0;

    const json =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [{ "ip": "10.0.1.1" }],
        \\      "ports": [{ "port": 8080 }]
        \\    },
        \\    {
        \\      "addresses": [{ "ip": "10.0.2.1" }],
        \\      "ports": [{ "port": 9090 }]
        \\    }
        \\  ]
        \\}
    ;

    try parseEndpointsJson(json, &endpoints, &count);
    try std.testing.expectEqual(@as(u8, 2), count);
    try std.testing.expectEqualStrings("10.0.1.1", endpoints[0].ip());
    try std.testing.expectEqual(@as(u16, 8080), endpoints[0].port);
    try std.testing.expectEqualStrings("10.0.2.1", endpoints[1].ip());
    try std.testing.expectEqual(@as(u16, 9090), endpoints[1].port);
}

test "parseEndpointsJson invalid JSON" {
    var endpoints: [MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint = undefined;
    var count: u8 = 0;

    const json = "not valid json";
    try std.testing.expectError(error.InvalidEndpointsJson, parseEndpointsJson(json, &endpoints, &count));
}

test "parseSecretJson missing tls.crt" {
    var cert: CertStorage = undefined;
    var cert_len: u16 = 0;
    var key: CertStorage = undefined;
    var key_len: u16 = 0;

    const json =
        \\{
        \\  "type": "kubernetes.io/tls",
        \\  "data": {
        \\    "tls.key": "a2V5"
        \\  }
        \\}
    ;

    try std.testing.expectError(error.MissingTlsCert, parseSecretJson(json, &cert, &cert_len, &key, &key_len));
}

test "parseSecretJson missing tls.key" {
    var cert: CertStorage = undefined;
    var cert_len: u16 = 0;
    var key: CertStorage = undefined;
    var key_len: u16 = 0;

    const json =
        \\{
        \\  "type": "kubernetes.io/tls",
        \\  "data": {
        \\    "tls.crt": "Y2VydA=="
        \\  }
        \\}
    ;

    try std.testing.expectError(error.MissingTlsKey, parseSecretJson(json, &cert, &cert_len, &key, &key_len));
}

test "parseSecretJson invalid type" {
    var cert: CertStorage = undefined;
    var cert_len: u16 = 0;
    var key: CertStorage = undefined;
    var key_len: u16 = 0;

    const json =
        \\{
        \\  "type": "Opaque",
        \\  "data": {
        \\    "tls.crt": "Y2VydA==",
        \\    "tls.key": "a2V5"
        \\  }
        \\}
    ;

    try std.testing.expectError(error.InvalidSecretType, parseSecretJson(json, &cert, &cert_len, &key, &key_len));
}

test "parseSecretJson invalid base64" {
    var cert: CertStorage = undefined;
    var cert_len: u16 = 0;
    var key: CertStorage = undefined;
    var key_len: u16 = 0;

    const json =
        \\{
        \\  "type": "kubernetes.io/tls",
        \\  "data": {
        \\    "tls.crt": "not-valid-base64!!!",
        \\    "tls.key": "a2V5"
        \\  }
        \\}
    ;

    try std.testing.expectError(error.Base64DecodeFailed, parseSecretJson(json, &cert, &cert_len, &key, &key_len));
}

test "decodeBase64 empty input" {
    var output: CertStorage = undefined;
    const len = try decodeBase64("", &output);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "decodeBase64 valid input" {
    var output: CertStorage = undefined;
    const len = try decodeBase64("SGVsbG8gV29ybGQ=", &output);
    try std.testing.expectEqual(@as(usize, 11), len);
    try std.testing.expectEqualStrings("Hello World", output[0..len]);
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
    var resolver = Resolver.init();

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
    var resolver = Resolver.init();

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
    var resolver = Resolver.init();

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
    const resolver = Resolver.init();

    var resolved: gw_config.ResolvedBackend = undefined;
    try std.testing.expectError(error.ServiceNotFound, resolver.resolveBackend("nonexistent", "ns", &resolved));
}
