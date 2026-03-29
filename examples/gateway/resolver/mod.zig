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
/// Re-export of the bounded resolver that stores services and secrets in preallocated memory.
/// Use `create` and `destroy` to manage its heap allocation and keep the instance alive for borrowed views.
pub const Resolver = @import("resolver.zig").Resolver;

// Resolved types (returned to callers)
/// Re-export of the resolved service view type returned by the resolver.
/// The endpoint list is a borrowed view into resolver storage, so the resolver must stay alive.
pub const ResolvedService = @import("resolved_types.zig").ResolvedService;
/// Re-export of the resolved secret view type returned by the resolver.
/// The PEM slices are borrowed from resolver-owned storage and do not allocate or copy data.
pub const ResolvedSecret = @import("resolved_types.zig").ResolvedSecret;

// ============================================================================
// Types and Constants
// ============================================================================

const resolver_types = @import("types.zig");

// Constants
/// Maximum number of endpoints stored for a single service.
/// Endpoint parsing fails with `EndpointLimitExceeded` if this bound is exceeded.
pub const MAX_ENDPOINTS_PER_SERVICE = resolver_types.MAX_ENDPOINTS_PER_SERVICE;
/// Maximum number of services the resolver can store concurrently.
/// When the limit is reached, registering another service returns `ServiceLimitExceeded`.
pub const MAX_SERVICES = resolver_types.MAX_SERVICES;
/// Maximum number of secrets the resolver can store concurrently.
/// When the limit is reached, registering another secret returns `SecretLimitExceeded`.
pub const MAX_SECRETS = resolver_types.MAX_SECRETS;
/// Maximum length of a service or namespace name accepted by the resolver.
/// Values longer than this limit are rejected before they are copied into storage.
pub const MAX_NAME_LEN = resolver_types.MAX_NAME_LEN;
/// Maximum length of an IP address string stored for a resolved endpoint.
/// The limit accommodates both IPv4 and IPv6 textual representations.
pub const MAX_IP_LEN = resolver_types.MAX_IP_LEN;
/// Maximum decoded certificate or key size stored by the resolver.
/// This bounds inline PEM storage for TLS secrets managed by the gateway resolver.
pub const MAX_CERT_SIZE = resolver_types.MAX_CERT_SIZE;
/// Maximum base64-encoded input size accepted for certificate and key fields.
/// Inputs larger than this limit are rejected before decoding to bound memory use.
pub const MAX_BASE64_INPUT_SIZE = resolver_types.MAX_BASE64_INPUT_SIZE;

// Error types
/// Re-export of the resolver error set used by the gateway resolver module.
/// This includes registration, parsing, validation, lookup, and capacity failures.
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
