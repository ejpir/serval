// examples/router/json/mod.zig
//! JSON Module
//!
//! JSON types and serialization for router admin API.

/// Re-export of `types.zig`.
/// Defines the JSON request payload structs and shared request-size limit for the router admin API.
/// Import this namespace when decoding or constructing router JSON values.
pub const types = @import("types.zig");
/// Re-export of `writer.zig`.
/// Provides JSON serialization helpers for streaming router state into a fixed buffer.
/// The writer module performs bounded, zero-allocation output.
pub const writer = @import("writer.zig");
/// Re-export of `response.zig`.
/// Provides JSON error bodies, response helpers, and body-validation utilities for router handlers.
/// Import this namespace when formatting admin API responses.
pub const response = @import("response.zig");

// Re-export commonly used types
/// Re-export of `types.ConfigJson`.
/// JSON representation of a full router configuration body.
/// `allowed_hosts` and `routes` default to empty slices; `pools` is required.
pub const ConfigJson = types.ConfigJson;
/// Re-export of `types.RouteJson`.
/// JSON representation of a route used by full-config parsing.
/// Exactly one of `path_prefix` or `path_exact` must be set; `host` and `strip_prefix` are optional.
pub const RouteJson = types.RouteJson;
/// Re-export of `types.PoolJson`.
/// JSON representation of a pool and its upstream list.
/// `name` and `upstreams` are required; `lb_config` defaults to `.{};`.
pub const PoolJson = types.PoolJson;
/// Re-export of `types.UpstreamJson`.
/// JSON representation of a single upstream entry.
/// `host`, `port`, and `idx` are required; `tls` defaults to `false`.
pub const UpstreamJson = types.UpstreamJson;
/// Re-export of `types.LbConfigJson`.
/// JSON representation of load-balancer health-check settings.
/// Defaults are sourced from `serval.config`, and `health_path` is borrowed from the input JSON.
pub const LbConfigJson = types.LbConfigJson;
/// Re-export of `types.AddRouteJson`.
/// Request payload for adding a single route to the router.
/// Exactly one of `path_prefix` or `path_exact` must be set; `strip_prefix` defaults to `false`.
pub const AddRouteJson = types.AddRouteJson;
/// Re-export of `types.RemoveRouteJson`.
/// Request payload for removing a route by name.
/// The route identifier is borrowed from the decoded JSON input.
pub const RemoveRouteJson = types.RemoveRouteJson;
/// Re-export of `types.AddPoolJson`.
/// Request payload for creating a pool with one or more upstreams.
/// `lb_config` defaults to `.{};` `name` and `upstreams` are required.
pub const AddPoolJson = types.AddPoolJson;
/// Re-export of `types.RemovePoolJson`.
/// Request payload for removing a pool by name.
/// The string slice is borrowed from the decoded JSON input.
pub const RemovePoolJson = types.RemovePoolJson;
/// Re-export of `types.AddUpstreamJson`.
/// Request payload for adding an upstream to an existing pool.
/// `tls` defaults to `false`; `host`, `port`, `idx`, and `pool_name` are required.
pub const AddUpstreamJson = types.AddUpstreamJson;
/// Re-export of `types.RemoveUpstreamJson`.
/// Request payload for removing an upstream from an existing pool.
/// The payload identifies the pool by name and the upstream by index.
pub const RemoveUpstreamJson = types.RemoveUpstreamJson;
/// Maximum request-body size accepted by the router JSON handlers.
/// Defined as 64 KiB and reused by body-validation paths for admin endpoints.
/// Use this limit when rejecting oversized JSON payloads before parsing.
pub const MAX_JSON_BODY_SIZE = types.MAX_JSON_BODY_SIZE;

/// Re-export of `writer.streamRouterConfig`.
/// Streams the current router configuration as JSON into a caller-provided buffer.
/// The returned slice aliases `buf`; the operation is bounded and does not allocate.
pub const streamRouterConfig = writer.streamRouterConfig;
