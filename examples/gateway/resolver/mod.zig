//! Resource Resolver
//!
//! Resolves Kubernetes resource references to concrete values:
//! - Service -> Endpoints (pod IPs)
//! - Secret -> TLS certificate/key data
//!
//! TigerStyle: Bounded storage, explicit errors, no allocation after init.

// ============================================================================
// Public API
// ============================================================================

// Resolver struct and methods
pub const Resolver = @import("resolver.zig").Resolver;

// Resolved types (returned to callers)
pub const ResolvedService = @import("resolved_types.zig").ResolvedService;
pub const ResolvedSecret = @import("resolved_types.zig").ResolvedSecret;

// ============================================================================
// Types and Constants
// ============================================================================

const resolver_types = @import("types.zig");

// Constants
pub const MAX_ENDPOINTS_PER_SERVICE = resolver_types.MAX_ENDPOINTS_PER_SERVICE;
pub const MAX_SERVICES = resolver_types.MAX_SERVICES;
pub const MAX_SECRETS = resolver_types.MAX_SECRETS;
pub const MAX_NAME_LEN = resolver_types.MAX_NAME_LEN;
pub const MAX_IP_LEN = resolver_types.MAX_IP_LEN;
pub const MAX_CERT_SIZE = resolver_types.MAX_CERT_SIZE;
pub const MAX_BASE64_INPUT_SIZE = resolver_types.MAX_BASE64_INPUT_SIZE;

// Error types
pub const ResolverError = resolver_types.ResolverError;

// ============================================================================
// Tests
// ============================================================================

test {
    // Run tests from submodules
    _ = @import("resolver.zig");
    _ = @import("resolved_types.zig");
    _ = @import("types.zig");
    _ = @import("parsing.zig");
}
