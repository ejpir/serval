//! Kubernetes Resource Type Enum
//!
//! Defines the ResourceType enum for dispatch in watch threads.
//! Each resource type maps to a K8s API path and display name.
//!
//! TigerStyle: Explicit enum values, bounded resource types.

const types = @import("types.zig");

// Import API paths from types.zig
const GATEWAY_CLASS_PATH = types.GATEWAY_CLASS_PATH;
const GATEWAY_PATH = types.GATEWAY_PATH;
const HTTP_ROUTE_PATH = types.HTTP_ROUTE_PATH;
const SERVICES_PATH = types.SERVICES_PATH;
const ENDPOINTS_PATH = types.ENDPOINTS_PATH;
const SECRETS_PATH = types.SECRETS_PATH;

/// Resource type enum for dispatch.
/// Each variant corresponds to a K8s resource type watched by the gateway controller.
pub const ResourceType = enum(u8) {
    gateway_class = 0,
    gateway = 1,
    http_route = 2,
    service = 3,
    endpoints = 4,
    secret = 5,

    /// Get the K8s API path for this resource type.
    pub fn getPath(self: ResourceType) []const u8 {
        return switch (self) {
            .gateway_class => GATEWAY_CLASS_PATH,
            .gateway => GATEWAY_PATH,
            .http_route => HTTP_ROUTE_PATH,
            .service => SERVICES_PATH,
            .endpoints => ENDPOINTS_PATH,
            .secret => SECRETS_PATH,
        };
    }

    /// Get the resource type name for logging.
    pub fn getName(self: ResourceType) []const u8 {
        return switch (self) {
            .gateway_class => "GatewayClass",
            .gateway => "Gateway",
            .http_route => "HTTPRoute",
            .service => "Service",
            .endpoints => "Endpoints",
            .secret => "Secret",
        };
    }
};
