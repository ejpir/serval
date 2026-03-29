//! Kubernetes Resource Watcher Module
//!
//! Watches Gateway API resources and related K8s resources for changes.
//! Re-exports all public types and functions from submodules.
//!
//! TigerStyle: Clean module boundary with explicit re-exports.

const std = @import("std");

// =============================================================================
// Submodule Imports
// =============================================================================

const watcher_mod = @import("watcher.zig");
const types_mod = @import("types.zig");
const parsing_mod = @import("parsing.zig");
const resource_type_mod = @import("resource_type.zig");

// =============================================================================
// Public Re-exports: Core Types
// =============================================================================

/// Main watcher struct - watches K8s resources and triggers reconciliation.
pub const Watcher = watcher_mod.Watcher;

/// Resource type enum for dispatch (GatewayClass, Gateway, HTTPRoute, etc.).
pub const ResourceType = resource_type_mod.ResourceType;

/// Number of resource types watched in parallel.
pub const RESOURCE_TYPE_COUNT = watcher_mod.RESOURCE_TYPE_COUNT;

// =============================================================================
// Public Re-exports: Types Module
// =============================================================================

/// All types from types.zig for storage and configuration.
pub const watcher_types = types_mod;

/// Error types for watcher operations.
pub const WatcherError = types_mod.WatcherError;

/// Watch event types from K8s API.
pub const EventType = types_mod.EventType;

/// Generic watch event from K8s API.
pub const WatchEvent = types_mod.WatchEvent;

/// Resource metadata extracted from K8s objects.
pub const ResourceMeta = types_mod.ResourceMeta;

/// Tracked resource with metadata and raw JSON.
pub const TrackedResource = types_mod.TrackedResource;

/// Storage for tracked resources of a single type.
pub const ResourceStore = types_mod.ResourceStore;

/// Stored gateway with inline storage.
pub const StoredGateway = types_mod.StoredGateway;

/// Stored GatewayClass with inline storage.
pub const StoredGatewayClass = types_mod.StoredGatewayClass;

/// Stored HTTP route with inline storage.
pub const StoredHTTPRoute = types_mod.StoredHTTPRoute;

/// Fixed-size storage for controller name strings.
pub const ControllerNameStorage = types_mod.ControllerNameStorage;

/// Stored listener with inline storage.
pub const StoredListener = types_mod.StoredListener;

/// Stored HTTP route rule with inline storage.
pub const StoredHTTPRouteRule = types_mod.StoredHTTPRouteRule;

/// Stored HTTP route match with inline storage.
pub const StoredHTTPRouteMatch = types_mod.StoredHTTPRouteMatch;

/// Stored HTTP route filter with inline storage.
pub const StoredHTTPRouteFilter = types_mod.StoredHTTPRouteFilter;

/// Stored backend reference with inline storage.
pub const StoredBackendRef = types_mod.StoredBackendRef;

/// Fixed-size storage for a name string.
pub const NameStorage = types_mod.NameStorage;

/// Fixed-size storage for a hostname string.
pub const HostnameStorage = types_mod.HostnameStorage;

/// Fixed-size storage for a path value string.
pub const PathStorage = types_mod.PathStorage;

/// Stored path match with inline storage.
pub const StoredPathMatch = types_mod.StoredPathMatch;

/// Stored path rewrite with inline storage.
pub const StoredPathRewrite = types_mod.StoredPathRewrite;

// =============================================================================
// Public Re-exports: Constants
// =============================================================================

/// Kubernetes API path for the GatewayClass collection.
/// This is a re-export of `types_mod.GATEWAY_CLASS_PATH` and
/// identifies the Gateway API endpoint watched for GatewayClass updates.
pub const GATEWAY_CLASS_PATH = types_mod.GATEWAY_CLASS_PATH;
/// Kubernetes API path for the Gateway collection.
/// This is a re-export of `types_mod.GATEWAY_PATH` and identifies
/// the Gateway API endpoint watched for Gateway updates.
pub const GATEWAY_PATH = types_mod.GATEWAY_PATH;
/// Kubernetes API path for the HTTPRoute collection.
/// This is a re-export of `types_mod.HTTP_ROUTE_PATH` and identifies
/// the Gateway API endpoint watched for HTTPRoute updates.
pub const HTTP_ROUTE_PATH = types_mod.HTTP_ROUTE_PATH;
/// Kubernetes API path for the Services collection.
/// This is a re-export of `types_mod.SERVICES_PATH` and identifies
/// the resource endpoint watched for service updates.
pub const SERVICES_PATH = types_mod.SERVICES_PATH;
/// Kubernetes API path for the Endpoints collection.
/// This is a re-export of `types_mod.ENDPOINTS_PATH` and identifies
/// the resource endpoint watched for endpoint updates.
pub const ENDPOINTS_PATH = types_mod.ENDPOINTS_PATH;
/// Kubernetes API path for the Secrets collection.
/// This is a re-export of `types_mod.SECRETS_PATH` and identifies the
/// resource endpoint watched for secret updates.
pub const SECRETS_PATH = types_mod.SECRETS_PATH;
/// Maximum line buffer size, in bytes, for parsing watch event input.
/// This is a re-export of `types_mod.MAX_LINE_SIZE_BYTES` and should
/// be treated as the parser's explicit upper bound for one line.
pub const MAX_LINE_SIZE_BYTES = types_mod.MAX_LINE_SIZE_BYTES;
/// Maximum number of watch events processed in one iteration.
/// This is a re-export of `types_mod.MAX_EVENTS_PER_ITERATION` and
/// prevents a single loop pass from running without a bound.
pub const MAX_EVENTS_PER_ITERATION = types_mod.MAX_EVENTS_PER_ITERATION;
/// Maximum number of reconnect attempts before the watcher gives up.
/// This is a re-export of `types_mod.MAX_RECONNECT_ATTEMPTS` and is
/// used to bound retry behavior in the watch loop.
pub const MAX_RECONNECT_ATTEMPTS = types_mod.MAX_RECONNECT_ATTEMPTS;
/// Maximum number of Gateway resources tracked by the watcher.
/// This is a re-export of `types_mod.MAX_GATEWAYS` and keeps gateway
/// storage bounded during watch and reconciliation processing.
pub const MAX_GATEWAYS = types_mod.MAX_GATEWAYS;
/// Maximum number of GatewayClass resources tracked by the watcher.
/// This is a re-export of `types_mod.MAX_GATEWAY_CLASSES` and caps
/// the watcher-side storage for GatewayClass state.
pub const MAX_GATEWAY_CLASSES = types_mod.MAX_GATEWAY_CLASSES;
/// Maximum number of HTTPRoute resources tracked by the watcher.
/// This is a re-export of `types_mod.MAX_HTTP_ROUTES` and is used as a
/// bounded storage limit rather than a dynamic allocation target.
pub const MAX_HTTP_ROUTES = types_mod.MAX_HTTP_ROUTES;
/// Maximum number of service resources tracked by the watcher.
/// Re-exported from `types.zig` as a bounded capacity limit for in-memory resource storage.
/// This limit is part of the watcher's fixed-size resource accounting.
pub const MAX_SERVICES = types_mod.MAX_SERVICES;
/// Maximum number of endpoint resources tracked by the watcher.
/// Re-exported from `types.zig` as a bounded capacity limit for in-memory resource storage.
/// This limit is part of the watcher's fixed-size resource accounting.
pub const MAX_ENDPOINTS = types_mod.MAX_ENDPOINTS;
/// Maximum number of secret resources tracked by the watcher.
/// Re-exported from `types.zig` as a bounded capacity limit for in-memory resource storage.
/// This limit is part of the watcher's fixed-size resource accounting.
pub const MAX_SECRETS = types_mod.MAX_SECRETS;
/// Maximum accepted length for Gateway API controller names.
/// Re-exported from `types.zig` so GatewayClass parsing and controller matching share the same bound.
/// Oversized controller names are rejected by the parser.
pub const MAX_CONTROLLER_NAME_LEN = types_mod.MAX_CONTROLLER_NAME_LEN;
/// Maximum accepted length for names and namespaces parsed from Kubernetes objects.
/// Re-exported from `types.zig` to keep metadata validation aligned with the storage layer.
/// Parsers reject or ignore values that exceed this bound depending on the field.
pub const MAX_NAME_LEN = types_mod.MAX_NAME_LEN;
/// Maximum accepted hostname length for Gateway and HTTPRoute parsing.
/// Re-exported from `types.zig` so hostname validation is consistent across watcher parsers.
/// Hostnames longer than this limit are skipped or rejected by the parser.
pub const MAX_HOSTNAME_LEN = types_mod.MAX_HOSTNAME_LEN;
/// Maximum accepted length for parsed path values and path rewrite targets.
/// Re-exported from `types.zig` so route parsing and validation share the same bound.
/// Values longer than this limit are not stored by the route parser.
pub const MAX_PATH_VALUE_LEN = types_mod.MAX_PATH_VALUE_LEN;
/// Initial reconnect delay in milliseconds for watcher retry backoff.
/// Re-exported from `types.zig` to keep retry timing consistent across the watcher module.
/// Used as the starting point before backoff growth is applied.
pub const INITIAL_BACKOFF_MS = types_mod.INITIAL_BACKOFF_MS;
/// Maximum reconnect delay in milliseconds for watcher retry backoff.
/// Re-exported from `types.zig` to keep retry timing consistent across the watcher module.
/// Used as the upper bound when exponential backoff is applied.
pub const MAX_BACKOFF_MS = types_mod.MAX_BACKOFF_MS;
/// Backoff growth factor applied when reconnecting a watch stream.
/// Re-exported from `types.zig` so reconnect logic uses the same bounded retry policy everywhere.
/// This is a compile-time constant used with the initial and maximum backoff values.
pub const BACKOFF_MULTIPLIER = types_mod.BACKOFF_MULTIPLIER;

// =============================================================================
// Public Re-exports: Parsing Functions
// =============================================================================

/// Parse a newline-delimited Kubernetes watch event.
/// Returns `WatcherError.ParseError` for malformed JSON, `WatcherError.UnknownEventType` for an unrecognized `type`, and `WatcherError.MissingField` when the `object` payload cannot be found.
/// The returned event stores the parsed event type and a slice of the raw `object` JSON from the input line.
/// `line` must be non-empty and the `raw_object` slice remains valid only as long as `line` remains alive.
pub const parseEvent = parsing_mod.parseEvent;
/// Extract `metadata.name`, `metadata.namespace`, and `metadata.resourceVersion` from a Kubernetes object.
/// `metadata.name` is required; missing metadata or name returns `WatcherError.MissingField`, and malformed JSON returns `WatcherError.ParseError`.
/// Namespace defaults to `"default"` and resource version defaults to an empty slice when not present.
/// The returned slices are sourced from the parsed JSON data and should be treated as tied to the parse result's lifetime.
pub const extractResourceMeta = parsing_mod.extractResourceMeta;
/// Parse a `Gateway` resource into `StoredGateway` storage.
/// Required metadata and spec fields return `WatcherError.MissingField` when absent, and oversized required strings return `WatcherError.InvalidJson`.
/// The gateway class name is optional and only stored when it fits the configured name limit; listeners are truncated to the configured maximum.
/// `out` is reset before parsing and must point to writable storage.
pub const parseGatewayJson = parsing_mod.parseGatewayJson;
/// Parse a `GatewayClass` resource into `StoredGatewayClass` storage.
/// `metadata.name` and `spec.controllerName` are required, and values longer than the configured bounds return `WatcherError.InvalidJson`.
/// The output is reset before parsing and marked active only after all required fields are accepted.
/// `out` must point to writable storage for the parsed result.
pub const parseGatewayClassJson = parsing_mod.parseGatewayClassJson;
/// Parse an `HTTPRoute` resource into `StoredHTTPRoute` storage.
/// Required metadata and spec fields are validated; missing fields return `WatcherError.MissingField` and malformed JSON returns `WatcherError.ParseError`.
/// Hostnames, rules, and nested match/filter/backend data are bounded by the watcher limits and excess entries are skipped.
/// `out` is reset before parsing and must point to initialized storage.
pub const parseHTTPRouteJson = parsing_mod.parseHTTPRouteJson;
/// Parse a Gateway API `HTTPRouteFilter` from decoded JSON.
/// Unsupported or malformed filter data leaves the output in its initialized state.
/// URL rewrite filters are populated when present; missing or unknown filter types are ignored.
/// The output pointer must be valid and writable for the duration of the call.
pub const parseFilterFromJson = parsing_mod.parseFilterFromJson;

// =============================================================================
// Tests
// =============================================================================

test {
    // Run tests from all submodules.
    std.testing.refAllDecls(@This());
    _ = types_mod;
    _ = parsing_mod;
    _ = watcher_mod;
    _ = resource_type_mod;
}
