//! Frontend bootstrap validation helpers.
//!
//! Keeps protocol-neutral startup validation out of protocol-specific drivers.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const core_config = @import("serval-core").config;

/// Errors returned while validating and resolving frontend bootstrap listen configuration.
/// `InvalidTransportConfig` indicates the transport settings failed validation.
/// `InvalidAddress` indicates the configured host and port could not be parsed into an IP address.
pub const FrontendBootstrapError = error{
    InvalidTransportConfig,
    InvalidAddress,
};

/// Checks whether the transport-related fields in `cfg` are valid for frontend bootstrap.
/// Requires `cfg` to be a non-null `Config` pointer.
/// Maps any validation failure from `core_config.validateTransportConfig` to `error.InvalidTransportConfig`.
/// Does not allocate or take ownership of `cfg`; it only inspects the referenced configuration.
pub fn validateTransportReadiness(cfg: *const core_config.Config) FrontendBootstrapError!void {
    assert(@intFromPtr(cfg) != 0);

    core_config.validateTransportConfig(cfg) catch {
        return error.InvalidTransportConfig;
    };

}

/// Validates transport readiness for `cfg` and resolves the configured listen address.
/// Requires `cfg` to point to a non-null `Config` with `port > 0` and a non-empty `listen_host`.
/// Returns `error.InvalidTransportConfig` if transport validation fails, or `error.InvalidAddress` if `listen_host:port` cannot be parsed.
/// On success, returns the parsed IP address to bind the frontend listener.
pub fn preflightAndResolveListenAddress(cfg: *const core_config.Config) FrontendBootstrapError!Io.net.IpAddress {
    assert(@intFromPtr(cfg) != 0);
    assert(cfg.port > 0);
    assert(cfg.listen_host.len > 0);

    try validateTransportReadiness(cfg);

    return Io.net.IpAddress.parse(cfg.listen_host, cfg.port) catch {
        return error.InvalidAddress;
    };
}

test "validateTransportReadiness accepts http-only config" {
    const cfg = core_config.Config{};
    try validateTransportReadiness(&cfg);
}

test "validateTransportReadiness rejects invalid transport config" {
    var cfg = core_config.Config{
        .tcp_transport = .{
            .enabled = true,
            .listener_host = "",
            .listener_port = 0,
            .upstreams = &.{},
        },
    };

    try std.testing.expectError(error.InvalidTransportConfig, validateTransportReadiness(&cfg));
}

test "validateTransportReadiness accepts valid enabled tcp/udp transport configs" {
    const tcp_targets = [_]core_config.L4Target{
        .{ .host = "127.0.0.1", .port = 9001 },
    };
    const udp_targets = [_]core_config.L4Target{
        .{ .host = "127.0.0.1", .port = 9002 },
    };

    var cfg = core_config.Config{
        .tcp_transport = .{
            .enabled = true,
            .listener_host = "0.0.0.0",
            .listener_port = 7000,
            .upstreams = &tcp_targets,
        },
        .udp_transport = .{
            .enabled = true,
            .listener_host = "0.0.0.0",
            .listener_port = 7001,
            .upstreams = &udp_targets,
        },
    };

    try validateTransportReadiness(&cfg);
}

test "preflightAndResolveListenAddress accepts http-only config" {
    const cfg = core_config.Config{};

    const addr = try preflightAndResolveListenAddress(&cfg);
    try std.testing.expectEqual(@as(u16, cfg.port), addr.getPort());
}

test "preflightAndResolveListenAddress rejects invalid listen host" {
    const cfg = core_config.Config{ .listen_host = "not a host", .port = 8080 };

    try std.testing.expectError(error.InvalidAddress, preflightAndResolveListenAddress(&cfg));
}
