//! Resolver Types
//!
//! Types and constants for the resource resolver.
//! Separated from resolver.zig for modularity.
//!
//! TigerStyle: Bounded storage, explicit errors, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;

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
pub const MAX_SUBSETS: u8 = 8;

/// Maximum number of addresses per subset.
pub const MAX_ADDRESSES_PER_SUBSET: u8 = 32;

/// Maximum number of ports per subset.
pub const MAX_PORTS_PER_SUBSET: u8 = 8;

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
pub const IpStorage = [MAX_IP_LEN]u8;

/// Fixed-size storage for name strings.
pub const NameStorage = [MAX_NAME_LEN]u8;

/// Fixed-size storage for certificate/key PEM data.
pub const CertStorage = [MAX_CERT_SIZE]u8;

/// Stored endpoint with inline IP string.
pub const StoredEndpoint = struct {
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
pub const StoredService = struct {
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
pub const StoredSecret = struct {
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
