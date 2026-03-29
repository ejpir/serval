/// Imports the shared certificate provider definitions for this package.
/// Re-exported types in this module alias declarations from `provider`.
pub const provider = @import("provider.zig");
/// Imports the static certificate provider module for this package.
/// This module provides certificate material from fixed, preconfigured inputs.
pub const static_provider = @import("static_provider.zig");
/// Imports the self-signed certificate provider module for this package.
/// Use this module when certificate material is generated locally instead of fetched from an external authority.
pub const selfsigned_provider = @import("selfsigned_provider.zig");
/// Imports the ACME certificate provider module for this package.
/// This module exposes ACME-backed certificate provisioning and related provider APIs.
pub const acme_provider = @import("acme_provider.zig");

/// Alias for the activation result type defined by `provider`.
/// Use this re-export for values returned after a certificate provider has been activated.
pub const ActivationResult = provider.ActivationResult;
/// Alias for the certificate material type defined by `provider`.
/// Use this re-export when working with certificate generation and activation data in this package.
pub const CertMaterial = provider.CertMaterial;
/// Function signature used to activate a certificate provider.
/// Re-exported from `provider.ActivateFn`; the concrete calling convention
/// and error behavior are defined by the provider abstraction.
pub const ActivateFn = provider.ActivateFn;

/// Static certificate provider implementation.
/// Re-exported from `static_provider.Provider` for consumers that need the
/// concrete provider type via the certs module.
pub const StaticProvider = static_provider.Provider;
/// Self-signed certificate provider implementation.
/// Re-exported from `selfsigned_provider.Provider` so callers can construct
/// or use it through the certs module.
pub const SelfSignedProvider = selfsigned_provider.Provider;
/// ACME certificate provider implementation.
/// Re-exported from `acme_provider.Provider` for use through the certs
/// module without depending on the concrete submodule path.
pub const AcmeProvider = acme_provider.Provider;

/// Error set returned by the static certificate provider.
/// Re-exported from `static_provider.Error` to preserve the provider's
/// original error behavior at the module boundary.
pub const StaticError = static_provider.Error;
/// Error set returned by the self-signed certificate provider.
/// Re-exported from `selfsigned_provider.Error` for consumers that work
/// with the certificate provider abstraction in this package.
pub const SelfSignedError = selfsigned_provider.Error;
/// Error set returned by the ACME certificate provider.
/// Re-exported from `acme_provider.Error` so callers can depend on the
/// provider-specific failure contract through this module.
pub const AcmeError = acme_provider.Error;

test {
    _ = provider;
    _ = static_provider;
    _ = selfsigned_provider;
    _ = acme_provider;
}
