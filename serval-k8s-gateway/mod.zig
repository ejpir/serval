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
/// Gateway API configuration types, limits, and status structs.
/// Re-exports the bounded data model used by `serval-k8s-gateway` to parse and
/// represent Kubernetes watch state.
/// See `config.zig` for the full set of resource definitions and `MAX_*` bounds.
pub const config = @import("config.zig");
/// Re-export of `config.GatewayConfig`.
/// Captures a complete Gateway API configuration snapshot with Gateways and HTTPRoutes.
/// Both slices borrow their backing storage, so the source data must outlive the snapshot.
pub const GatewayConfig = config.GatewayConfig;
/// Re-export of `config.Gateway`.
/// Represents a namespaced Gateway with one or more listeners.
/// Name, namespace, and listener data are all borrowed from caller-owned storage.
pub const Gateway = config.Gateway;
/// Re-export of `config.GatewayClass`.
/// Describes a cluster-scoped GatewayClass and the controller that manages it.
/// The underlying string fields are borrowed slices and do not transfer ownership.
pub const GatewayClass = config.GatewayClass;
/// Re-export of `config.HTTPRoute`.
/// Represents a namespaced HTTPRoute with optional hostnames and an ordered rule list.
/// An empty `hostnames` list matches all hosts; slice-backed fields borrow their storage.
pub const HTTPRoute = config.HTTPRoute;
/// Re-export of `config.HTTPRouteRule`.
/// Groups match conditions, filters, and backend references for one routing rule.
/// The contained slices borrow their storage and must remain valid while the rule is used.
pub const HTTPRouteRule = config.HTTPRouteRule;
/// Re-export of `config.HTTPRouteMatch`.
/// Models the match criteria for a route rule, with path matching as the currently supported field.
/// This type does not add storage ownership beyond the underlying optional fields.
pub const HTTPRouteMatch = config.HTTPRouteMatch;
/// Re-export of `config.HTTPRouteFilter`.
/// Currently models URL rewrite filtering only; set `url_rewrite` when `type` is `URLRewrite`.
/// Additional Gateway API filter kinds are not represented by this type.
pub const HTTPRouteFilter = config.HTTPRouteFilter;
/// Re-export of `config.BackendRef`.
/// References a backend service by name, namespace, and port, with an optional weight for load balancing.
/// `weight` defaults to `1` when not specified.
pub const BackendRef = config.BackendRef;
/// Re-export of `config.Listener`.
/// Defines one Gateway listener with a port, protocol, and optional hostname or TLS settings.
/// Listener names, hostnames, and certificate references are borrowed slices; keep their backing storage alive.
pub const Listener = config.Listener;

// Status types (for K8s status updates)
/// Re-export of `config.GatewayClassStatus`.
/// Carries the status conditions reported for a GatewayClass resource.
/// The conditions slice borrows its storage from the caller.
pub const GatewayClassStatus = config.GatewayClassStatus;
/// Re-export of `config.GatewayStatus`.
/// Aggregates gateway-wide conditions and per-listener status snapshots.
/// Callers keep ownership of the backing storage used by the contained slices.
pub const GatewayStatus = config.GatewayStatus;
/// Re-export of `config.ListenerStatus`.
/// Describes the state of one listener, including its name, attached route count, and conditions.
/// Any slices contained in the status borrow their backing storage.
pub const ListenerStatus = config.ListenerStatus;
/// Re-export of `config.Condition`.
/// Represents one Gateway API status condition with type, status, reason, message, and timestamps.
/// String fields borrow their backing storage and must stay valid for the lifetime of the value.
pub const Condition = config.Condition;
/// Re-export of `config.ConditionType`.
/// Identifies which Gateway API condition is being reported, such as `Accepted` or `Programmed`.
/// This alias adds no behavior beyond the underlying enum.
pub const ConditionType = config.ConditionType;
/// Re-export of `config.ConditionStatus`.
/// Uses the standard Gateway API condition values: `True`, `False`, and `Unknown`.
/// The status token itself carries no message or reason fields.
pub const ConditionStatus = config.ConditionStatus;

// Status constants
/// Upper bound for GatewayClass resources tracked by bounded storage.
/// Use this limit when sizing fixed arrays or validating class-count assumptions.
/// Re-exported unchanged from `config`.
pub const MAX_GATEWAY_CLASSES = config.MAX_GATEWAY_CLASSES;
/// Upper bound on the JSON payload size for gateway status translation.
/// Callers should provision buffers at or above this limit before encoding status JSON.
pub const MAX_STATUS_JSON_SIZE = config.MAX_STATUS_JSON_SIZE;
/// Maximum number of conditions represented in gateway status data.
/// Iteration and serialization code should respect this bound to avoid overflow.
pub const MAX_CONDITIONS = config.MAX_CONDITIONS;
/// Maximum reason length accepted or emitted by the gateway status configuration.
/// Use this constant when allocating or validating reason text fields.
pub const MAX_REASON_LEN = config.MAX_REASON_LEN;
/// Maximum message length accepted or emitted by the gateway status configuration.
/// Use this constant to size buffers and reject oversized messages consistently.
pub const MAX_MESSAGE_LEN = config.MAX_MESSAGE_LEN;

// Resolved types (for translator API)
/// Re-export of the resolved backend type used by gateway configuration.
/// This alias points at the canonical definition in `config`.
pub const ResolvedBackend = config.ResolvedBackend;
/// Re-export of the fixed resolved endpoint type used by gateway configuration.
/// This type is shared with `config` and carries no ownership by this module.
pub const FixedResolvedEndpoint = config.FixedResolvedEndpoint;

// Translator (GatewayConfig -> Router JSON)
/// Re-export of the gateway status translator module.
/// Import this namespace to access translator-specific helpers and error types.
pub const translator = @import("translator.zig");
/// Re-export of the gateway status translator entry point.
/// Converts gateway state into JSON using the translator module's rules and limits.
/// Propagates `TranslatorError` on translation or encoding failures.
pub const translateToJson = translator.translateToJson;
/// Re-export of the translator error set used by the gateway status translator.
/// Use this alias when handling failures returned from `translateToJson`.
pub const TranslatorError = translator.TranslatorError;

test {
    std.testing.refAllDecls(@This());
    _ = config;
    _ = translator;
}
