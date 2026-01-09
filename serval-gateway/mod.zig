//! serval-gateway
//!
//! Kubernetes Gateway API data plane for serval.
//! Watches Gateway API resources and configures serval-router.
//!
//! Layer 5 (Orchestration) - composes all serval modules

// Core gateway
const gateway_mod = @import("gateway.zig");
pub const Gateway = gateway_mod.Gateway;
pub const GatewayError = gateway_mod.GatewayError;
pub const DataPlanePushError = gateway_mod.DataPlanePushError;
pub const ADMIN_PORT = gateway_mod.ADMIN_PORT;

// Configuration types
pub const config = @import("config.zig");
pub const GatewayConfig = config.GatewayConfig;
pub const HTTPRoute = config.HTTPRoute;
pub const Listener = config.Listener;

// K8s integration
pub const k8s = @import("k8s/mod.zig");

// Resolution
const resolver_mod = @import("resolver.zig");
pub const Resolver = resolver_mod.Resolver;

// Translator (Gateway API -> Router JSON)
pub const translator = @import("translator.zig");
pub const translateToJson = translator.translateToJson;

test {
    // Run tests from all submodules
    @import("std").testing.refAllDecls(@This());
    _ = gateway_mod;
    _ = config;
    _ = k8s;
    _ = resolver_mod;
    _ = translator;
}
