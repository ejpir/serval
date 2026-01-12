//! Resolved Types
//!
//! Types returned to callers from the resolver.
//! These are views into stored data, not owned copies.
//!
//! TigerStyle: Bounded storage, explicit errors, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;
const gateway = @import("serval-k8s-gateway");
const gw_config = gateway.config;

const resolver_types = @import("types.zig");
const MAX_ENDPOINTS_PER_SERVICE = resolver_types.MAX_ENDPOINTS_PER_SERVICE;
const StoredService = resolver_types.StoredService;

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
