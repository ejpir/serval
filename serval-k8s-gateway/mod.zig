//! serval-k8s-gateway
//!
//! Kubernetes Gateway API library for serval.
//! Provides Gateway API types and translation to serval-router config.
//!
//! Use this library to build your own Kubernetes gateway controller:
//! - Define GatewayConfig with routes
//! - Use translator to convert to JSON
//! - POST to serval-router admin API
//!
//! See examples/gateway/ for a complete K8s controller implementation.
//!
//! Layer 4 (Strategy) - routing configuration

const std = @import("std");

// Configuration types (Gateway API)
pub const config = @import("config.zig");
pub const GatewayConfig = config.GatewayConfig;
pub const Gateway = config.Gateway;
pub const GatewayClass = config.GatewayClass;
pub const HTTPRoute = config.HTTPRoute;
pub const HTTPRouteRule = config.HTTPRouteRule;
pub const HTTPRouteMatch = config.HTTPRouteMatch;
pub const HTTPRouteFilter = config.HTTPRouteFilter;
pub const BackendRef = config.BackendRef;
pub const Listener = config.Listener;

// Status types (for K8s status updates)
pub const GatewayClassStatus = config.GatewayClassStatus;
pub const GatewayStatus = config.GatewayStatus;
pub const ListenerStatus = config.ListenerStatus;
pub const Condition = config.Condition;
pub const ConditionType = config.ConditionType;
pub const ConditionStatus = config.ConditionStatus;

// Status constants
pub const MAX_GATEWAY_CLASSES = config.MAX_GATEWAY_CLASSES;
pub const MAX_STATUS_JSON_SIZE = config.MAX_STATUS_JSON_SIZE;
pub const MAX_CONDITIONS = config.MAX_CONDITIONS;
pub const MAX_REASON_LEN = config.MAX_REASON_LEN;
pub const MAX_MESSAGE_LEN = config.MAX_MESSAGE_LEN;

// Resolved types (for translator API)
pub const ResolvedBackend = config.ResolvedBackend;
pub const FixedResolvedEndpoint = config.FixedResolvedEndpoint;

// Translator (GatewayConfig -> Router JSON)
pub const translator = @import("translator.zig");
pub const translateToJson = translator.translateToJson;
pub const TranslatorError = translator.TranslatorError;

test {
    std.testing.refAllDecls(@This());
    _ = config;
    _ = translator;
}
