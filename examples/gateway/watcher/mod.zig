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

pub const GATEWAY_CLASS_PATH = types_mod.GATEWAY_CLASS_PATH;
pub const GATEWAY_PATH = types_mod.GATEWAY_PATH;
pub const HTTP_ROUTE_PATH = types_mod.HTTP_ROUTE_PATH;
pub const SERVICES_PATH = types_mod.SERVICES_PATH;
pub const ENDPOINTS_PATH = types_mod.ENDPOINTS_PATH;
pub const SECRETS_PATH = types_mod.SECRETS_PATH;
pub const MAX_LINE_SIZE_BYTES = types_mod.MAX_LINE_SIZE_BYTES;
pub const MAX_EVENTS_PER_ITERATION = types_mod.MAX_EVENTS_PER_ITERATION;
pub const MAX_RECONNECT_ATTEMPTS = types_mod.MAX_RECONNECT_ATTEMPTS;
pub const MAX_GATEWAYS = types_mod.MAX_GATEWAYS;
pub const MAX_GATEWAY_CLASSES = types_mod.MAX_GATEWAY_CLASSES;
pub const MAX_HTTP_ROUTES = types_mod.MAX_HTTP_ROUTES;
pub const MAX_SERVICES = types_mod.MAX_SERVICES;
pub const MAX_ENDPOINTS = types_mod.MAX_ENDPOINTS;
pub const MAX_SECRETS = types_mod.MAX_SECRETS;
pub const MAX_CONTROLLER_NAME_LEN = types_mod.MAX_CONTROLLER_NAME_LEN;
pub const MAX_NAME_LEN = types_mod.MAX_NAME_LEN;
pub const MAX_HOSTNAME_LEN = types_mod.MAX_HOSTNAME_LEN;
pub const MAX_PATH_VALUE_LEN = types_mod.MAX_PATH_VALUE_LEN;
pub const INITIAL_BACKOFF_MS = types_mod.INITIAL_BACKOFF_MS;
pub const MAX_BACKOFF_MS = types_mod.MAX_BACKOFF_MS;
pub const BACKOFF_MULTIPLIER = types_mod.BACKOFF_MULTIPLIER;

// =============================================================================
// Public Re-exports: Parsing Functions
// =============================================================================

pub const parseEvent = parsing_mod.parseEvent;
pub const extractResourceMeta = parsing_mod.extractResourceMeta;
pub const parseGatewayJson = parsing_mod.parseGatewayJson;
pub const parseGatewayClassJson = parsing_mod.parseGatewayClassJson;
pub const parseHTTPRouteJson = parsing_mod.parseHTTPRouteJson;
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
