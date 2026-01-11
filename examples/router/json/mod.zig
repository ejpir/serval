// examples/router/json/mod.zig
//! JSON Module
//!
//! JSON types and serialization for router admin API.

pub const types = @import("types.zig");
pub const writer = @import("writer.zig");
pub const response = @import("response.zig");

// Re-export commonly used types
pub const ConfigJson = types.ConfigJson;
pub const RouteJson = types.RouteJson;
pub const PoolJson = types.PoolJson;
pub const UpstreamJson = types.UpstreamJson;
pub const LbConfigJson = types.LbConfigJson;
pub const AddRouteJson = types.AddRouteJson;
pub const RemoveRouteJson = types.RemoveRouteJson;
pub const AddPoolJson = types.AddPoolJson;
pub const RemovePoolJson = types.RemovePoolJson;
pub const AddUpstreamJson = types.AddUpstreamJson;
pub const RemoveUpstreamJson = types.RemoveUpstreamJson;
pub const MAX_JSON_BODY_SIZE = types.MAX_JSON_BODY_SIZE;

pub const streamRouterConfig = writer.streamRouterConfig;
