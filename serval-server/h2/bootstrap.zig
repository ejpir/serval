//! HTTP/2 bootstrap helpers.
//!
//! Mirrors frontend bootstrap entrypoints so h2-specific listeners can share
//! the same preflight/transport-readiness contract as h1.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const core_config = @import("serval-core").config;
const frontend_bootstrap = @import("../frontend/bootstrap.zig");

pub const H2BootstrapError = frontend_bootstrap.FrontendBootstrapError;

pub fn validateTransportReadiness(cfg: *const core_config.Config) H2BootstrapError!void {
    assert(@intFromPtr(cfg) != 0);
    return frontend_bootstrap.validateTransportReadiness(cfg);
}

pub fn preflightAndResolveListenAddress(cfg: *const core_config.Config) H2BootstrapError!Io.net.IpAddress {
    assert(@intFromPtr(cfg) != 0);
    return frontend_bootstrap.preflightAndResolveListenAddress(cfg);
}

test "h2 bootstrap delegates to shared frontend preflight" {
    const cfg = core_config.Config{};
    const addr = try preflightAndResolveListenAddress(&cfg);
    try std.testing.expectEqual(@as(u16, cfg.port), addr.getPort());
}
