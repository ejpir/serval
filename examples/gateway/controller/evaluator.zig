//! Gateway Evaluator
//!
//! Evaluates Gateway resources and produces reconcile results for status updates.
//!
//! TigerStyle: Explicit validation results, clear error reasons.

const std = @import("std");
const assert = std.debug.assert;

const gateway = @import("serval-k8s-gateway");
const Gateway = gateway.Gateway;

const status_mod = @import("status/mod.zig");
const GatewayReconcileResult = status_mod.GatewayReconcileResult;

/// Evaluate a Gateway and produce a reconcile result for status updates.
///
/// Currently returns success status (Accepted=true, Programmed=true).
/// Future: validate gateway config, check data plane status, track generation.
///
/// TigerStyle S1: ~2 assertions per function.
///
/// Parameters:
/// - gw: Gateway resource to evaluate
///
/// Returns: GatewayReconcileResult with status information for K8s status update.
pub fn evaluateGateway(gw: *const Gateway) GatewayReconcileResult {
    // S1: Preconditions
    assert(gw.name.len > 0); // gateway must have a name
    assert(gw.namespace.len > 0); // gateway must have a namespace

    // For now, accept all gateways as valid and programmed
    // TODO: Validate listener config (port conflicts, TLS refs, etc.)
    // TODO: Check if data plane actually programmed the config
    // TODO: Track actual generation from K8s resource metadata
    const result = GatewayReconcileResult{
        .accepted = true,
        .accepted_reason = "Accepted",
        .accepted_message = "Gateway configuration is valid",
        .programmed = true,
        .programmed_reason = "Programmed",
        .programmed_message = "Configuration applied to data plane",
        .observed_generation = 1, // TODO: track actual generation from Gateway metadata
        .listener_results = &.{}, // Empty for now - listener status tracking is future work
    };

    // S2: Postcondition - result has valid strings
    assert(result.accepted_reason.len > 0);
    assert(result.programmed_reason.len > 0);

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "evaluateGateway returns accepted for valid gateway" {
    const gw = Gateway{
        .name = "test-gateway",
        .namespace = "default",
        .listeners = &.{},
    };

    const result = evaluateGateway(&gw);

    try std.testing.expect(result.accepted);
    try std.testing.expect(result.programmed);
    try std.testing.expectEqualStrings("Accepted", result.accepted_reason);
    try std.testing.expectEqualStrings("Programmed", result.programmed_reason);
    try std.testing.expectEqual(@as(i64, 1), result.observed_generation);
}

test "evaluateGateway result has valid messages" {
    const gw = Gateway{
        .name = "my-gateway",
        .namespace = "production",
        .listeners = &.{},
    };

    const result = evaluateGateway(&gw);

    try std.testing.expect(result.accepted_message.len > 0);
    try std.testing.expect(result.programmed_message.len > 0);
    try std.testing.expectEqualStrings("Gateway configuration is valid", result.accepted_message);
    try std.testing.expectEqualStrings("Configuration applied to data plane", result.programmed_message);
}
