//! Kubernetes JSON Type Definitions
//!
//! JSON struct definitions for parsing Kubernetes Gateway API resources
//! using std.json. These types mirror the K8s API schema structure
//! for Gateway, HTTPRoute, and related resources.
//!
//! TigerStyle: All fields are optional with defaults to handle partial
//! K8s responses gracefully.

const std = @import("std");

/// K8s watch event JSON structure.
pub const WatchEventJson = struct {
    type: []const u8,
    object: std.json.Value,
};

/// K8s metadata JSON structure.
pub const MetadataJson = struct {
    name: ?[]const u8 = null,
    namespace: ?[]const u8 = null,
    resourceVersion: ?[]const u8 = null,
};

/// K8s Gateway listener JSON structure.
pub const ListenerJson = struct {
    name: ?[]const u8 = null,
    port: ?i64 = null,
    protocol: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
};

/// K8s Gateway spec JSON structure.
pub const GatewaySpecJson = struct {
    listeners: ?[]const ListenerJson = null,
};

/// K8s Gateway JSON structure.
pub const GatewayJson = struct {
    metadata: ?MetadataJson = null,
    spec: ?GatewaySpecJson = null,
};

/// K8s HTTPRoute path match JSON structure.
pub const PathMatchJson = struct {
    type: ?[]const u8 = null,
    value: ?[]const u8 = null,
};

/// K8s HTTPRoute match JSON structure.
pub const HTTPRouteMatchJson = struct {
    path: ?PathMatchJson = null,
};

/// K8s HTTPRoute path rewrite JSON structure.
pub const PathRewriteJson = struct {
    type: ?[]const u8 = null,
    replacePrefixMatch: ?[]const u8 = null,
    replaceFullPath: ?[]const u8 = null,
};

/// K8s HTTPRoute URL rewrite JSON structure.
pub const URLRewriteJson = struct {
    path: ?PathRewriteJson = null,
};

/// K8s HTTPRoute filter JSON structure.
pub const HTTPRouteFilterJson = struct {
    type: ?[]const u8 = null,
    urlRewrite: ?URLRewriteJson = null,
};

/// K8s HTTPRoute backend ref JSON structure.
pub const BackendRefJson = struct {
    name: ?[]const u8 = null,
    namespace: ?[]const u8 = null,
    port: ?i64 = null,
    weight: ?i64 = null,
};

/// K8s HTTPRoute rule JSON structure.
pub const HTTPRouteRuleJson = struct {
    matches: ?[]const HTTPRouteMatchJson = null,
    filters: ?[]const HTTPRouteFilterJson = null,
    backendRefs: ?[]const BackendRefJson = null,
};

/// K8s HTTPRoute spec JSON structure.
pub const HTTPRouteSpecJson = struct {
    hostnames: ?[]const []const u8 = null,
    rules: ?[]const HTTPRouteRuleJson = null,
};

/// K8s HTTPRoute JSON structure.
pub const HTTPRouteJson = struct {
    metadata: ?MetadataJson = null,
    spec: ?HTTPRouteSpecJson = null,
};
