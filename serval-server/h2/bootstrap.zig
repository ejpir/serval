//! HTTP/2 bootstrap helpers.
//!
//! Mirrors frontend bootstrap entrypoints so h2-specific listeners can share
//! the same preflight/transport-readiness contract as h1.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const core_config = @import("serval-core").config;
const frontend_bootstrap = @import("../frontend/bootstrap.zig");

/// Error set returned by the HTTP/2 bootstrap helpers.
/// This is an alias of `frontend_bootstrap.FrontendBootstrapError`, so callers
/// should handle the same bootstrap validation failures in either module.
pub const H2BootstrapError = frontend_bootstrap.FrontendBootstrapError;

/// Validates that the configured transports are ready for HTTP/2 startup.
/// Delegates to the shared frontend bootstrap implementation and returns
/// `error.InvalidTransportConfig` when transport validation fails.
pub fn validateTransportReadiness(cfg: *const core_config.Config) H2BootstrapError!void {
    assert(@intFromPtr(cfg) != 0);
    return frontend_bootstrap.validateTransportReadiness(cfg);
}

/// Runs HTTP/2 bootstrap preflight and resolves the listen `IpAddress` from `cfg`.
/// Preconditions: `cfg` must be a valid non-null borrowed pointer.
/// Delegates to shared frontend bootstrap logic, so transport-readiness validation and address parsing
/// semantics are identical to HTTP/1 bootstrap.
/// Returns `H2BootstrapError` when transport config is invalid or address resolution/parsing fails.
pub fn preflightAndResolveListenAddress(cfg: *const core_config.Config) H2BootstrapError!Io.net.IpAddress {
    assert(@intFromPtr(cfg) != 0);
    return frontend_bootstrap.preflightAndResolveListenAddress(cfg);
}

test "h2 bootstrap delegates to shared frontend preflight" {
    const cfg = core_config.Config{};
    const addr = try preflightAndResolveListenAddress(&cfg);
    try std.testing.expectEqual(@as(u16, cfg.port), addr.getPort());
}
