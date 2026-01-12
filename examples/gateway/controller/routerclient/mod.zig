//! Router Client Module
//!
//! Pushes configuration to serval-router admin API using serval-client.
//! Resolves backends before translation to decouple from K8s-specific Resolver.
//! Supports multi-instance config push via EndpointSlice discovery.
//!
//! TigerStyle: Uses serval-client, bounded buffers, explicit errors, ~2 assertions per function.

const std = @import("std");

const serval_core = @import("serval-core");
const gateway = @import("serval-k8s-gateway");
const core_config = serval_core.config;

// ============================================================================
// Re-exports
// ============================================================================

pub const RouterClient = @import("client.zig").RouterClient;
pub const PushResult = @import("types.zig").PushResult;

// ============================================================================
// Constants (TigerStyle Y3: Units in names)
// ============================================================================

/// Default admin port for router.
pub const DEFAULT_ADMIN_PORT: u16 = core_config.DEFAULT_ADMIN_PORT;

/// Maximum JSON payload size in bytes.
pub const MAX_JSON_SIZE_BYTES: u32 = gateway.translator.MAX_JSON_SIZE_BYTES;

/// Maximum response header size in bytes.
pub const MAX_RESPONSE_HEADER_SIZE_BYTES: u32 = core_config.MAX_HEADER_SIZE_BYTES;

/// Maximum retries for config push (TigerStyle S4: bounded).
pub const MAX_RETRIES: u8 = core_config.MAX_CONFIG_PUSH_RETRIES;

/// Base backoff delay in milliseconds.
pub const BACKOFF_BASE_MS: u64 = core_config.CONFIG_PUSH_BACKOFF_BASE_MS;

/// Maximum backoff delay in milliseconds.
pub const MAX_BACKOFF_MS: u64 = core_config.MAX_CONFIG_PUSH_BACKOFF_MS;

/// Admin endpoint path for route updates.
pub const ADMIN_ROUTES_PATH: []const u8 = "/routes/update";

// ============================================================================
// Error Types (TigerStyle S6: Explicit error set)
// ============================================================================

pub const RouterClientError = error{
    /// No config to push.
    NoConfig,
    /// Backend resolution failed.
    ResolutionFailed,
    /// Translation to JSON failed.
    TranslationFailed,
    /// Connection to router failed.
    ConnectionFailed,
    /// Request send failed.
    SendFailed,
    /// Response receive failed.
    ReceiveFailed,
    /// Empty response from router.
    EmptyResponse,
    /// Router rejected config (non-2xx response).
    Rejected,
    /// All retries exhausted.
    RetriesExhausted,
    /// Backends not yet resolved (endpoints not available).
    BackendsNotReady,
    /// No router endpoints discovered.
    NoRouterEndpoints,
    /// All router pushes failed.
    AllPushesFailed,
    /// Endpoint discovery failed.
    EndpointDiscoveryFailed,
};

// ============================================================================
// Tests
// ============================================================================

test "Constants match serval-core config" {
    try std.testing.expectEqual(core_config.DEFAULT_ADMIN_PORT, DEFAULT_ADMIN_PORT);
    try std.testing.expectEqual(core_config.MAX_CONFIG_PUSH_RETRIES, MAX_RETRIES);
    try std.testing.expectEqual(core_config.CONFIG_PUSH_BACKOFF_BASE_MS, BACKOFF_BASE_MS);
    try std.testing.expectEqual(core_config.MAX_CONFIG_PUSH_BACKOFF_MS, MAX_BACKOFF_MS);
}

test "RouterClientError has all expected variants" {
    // Verify all error variants exist
    const errors = [_]RouterClientError{
        RouterClientError.NoConfig,
        RouterClientError.ResolutionFailed,
        RouterClientError.TranslationFailed,
        RouterClientError.ConnectionFailed,
        RouterClientError.SendFailed,
        RouterClientError.ReceiveFailed,
        RouterClientError.EmptyResponse,
        RouterClientError.Rejected,
        RouterClientError.RetriesExhausted,
        RouterClientError.BackendsNotReady,
        RouterClientError.NoRouterEndpoints,
        RouterClientError.AllPushesFailed,
        RouterClientError.EndpointDiscoveryFailed,
    };

    // Each error should be distinct
    for (errors, 0..) |err1, i| {
        for (errors[i + 1 ..]) |err2| {
            try std.testing.expect(err1 != err2);
        }
    }
}

test "Buffer sizes are bounded" {
    // TigerStyle: Verify buffers have explicit bounds
    try std.testing.expect(MAX_JSON_SIZE_BYTES > 0);
    try std.testing.expect(MAX_JSON_SIZE_BYTES <= 1024 * 1024); // 1MB max
    try std.testing.expect(MAX_RESPONSE_HEADER_SIZE_BYTES > 0);
    try std.testing.expect(MAX_RESPONSE_HEADER_SIZE_BYTES <= 16384); // 16KB max headers
}

test "Retry constants are reasonable" {
    // TigerStyle: Verify retry config is bounded
    try std.testing.expect(MAX_RETRIES > 0);
    try std.testing.expect(MAX_RETRIES <= 10); // Reasonable retry limit
    try std.testing.expect(BACKOFF_BASE_MS > 0);
    try std.testing.expect(MAX_BACKOFF_MS >= BACKOFF_BASE_MS);
    try std.testing.expect(MAX_BACKOFF_MS <= 30000); // 30s max backoff
}
