pub const provider = @import("provider.zig");
pub const static_provider = @import("static_provider.zig");
pub const selfsigned_provider = @import("selfsigned_provider.zig");
pub const acme_provider = @import("acme_provider.zig");

pub const ActivationResult = provider.ActivationResult;
pub const CertMaterial = provider.CertMaterial;
pub const ActivateFn = provider.ActivateFn;

pub const StaticProvider = static_provider.Provider;
pub const SelfSignedProvider = selfsigned_provider.Provider;
pub const AcmeProvider = acme_provider.Provider;

pub const StaticError = static_provider.Error;
pub const SelfSignedError = selfsigned_provider.Error;
pub const AcmeError = acme_provider.Error;

test {
    _ = provider;
    _ = static_provider;
    _ = selfsigned_provider;
    _ = acme_provider;
}
