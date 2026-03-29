const std = @import("std");
const assert = std.debug.assert;
const ir = @import("../ir.zig");
const provider = @import("provider.zig");

/// Errors returned by `Provider.init`.
/// `InvalidStaticConfig` indicates that either `cert_path` or `key_path` was empty.
/// No other validation failures are reported by this provider.
pub const Error = error{
    InvalidStaticConfig,
};

/// Static certificate provider backed by preconfigured certificate and key paths.
/// The provider stores borrowed path slices from `ir.StaticTlsConfig` and does not copy or own them.
/// Use `init` to validate the config, `loadInitial` to fetch the material, and `run` is a no-op.
pub const Provider = struct {
    cfg: ir.StaticTlsConfig,

    /// Validates that both certificate paths are non-empty and constructs a `Provider`.
    /// Returns `error.InvalidStaticConfig` when either path is empty.
    /// The returned provider stores the borrowed slices from `cfg` without copying them.
    pub fn init(cfg: ir.StaticTlsConfig) Error!Provider {
        if (cfg.cert_path.len == 0 or cfg.key_path.len == 0) return error.InvalidStaticConfig;
        return .{ .cfg = cfg };
    }

    /// Releases provider state.
    /// This implementation owns no heap resources and has no cleanup work beyond validation of the receiver.
    /// Call with a valid provider pointer.
    pub fn deinit(self: *Provider) void {
        assert(@intFromPtr(self) != 0);
    }

    /// Returns the certificate and key paths configured for this provider.
    /// The returned `provider.CertMaterial` borrows slices from the stored config and does not allocate.
    /// The paths remain valid as long as the original config data referenced by the provider remains valid.
    pub fn loadInitial(self: *Provider) provider.CertMaterial {
        assert(@intFromPtr(self) != 0);
        return .{ .cert_path = self.cfg.cert_path, .key_path = self.cfg.key_path };
    }

    /// Enters the provider runtime loop for static TLS material.
    /// This implementation performs no activation work and returns immediately.
    /// `shutdown`, `activate_ctx`, and `activate_fn` are accepted for interface compatibility and are not used.
    pub fn run(
        self: *Provider,
        shutdown: *std.atomic.Value(bool),
        activate_ctx: *anyopaque,
        activate_fn: provider.ActivateFn,
    ) void {
        _ = self;
        _ = shutdown;
        _ = activate_ctx;
        _ = activate_fn;
    }
};
