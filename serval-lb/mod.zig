// serval-lb/mod.zig
//! Serval Load Balancer Library
//!
//! Health-aware load balancing with automatic background probing.
//! Backends marked unhealthy after consecutive failures recover
//! automatically when background probes succeed.
//!
//! Example:
//!   const serval_lb = @import("serval-lb");
//!   var handler = try serval_lb.LbHandler.init(&upstreams, .{});
//!   defer handler.deinit();

pub const handler = @import("handler.zig");
pub const strategy_core = @import("strategy_core.zig");

pub const LbHandler = handler.LbHandler;
pub const LbConfig = handler.LbConfig;
pub const RoundRobinStrategy = strategy_core.RoundRobinStrategy;
pub const StrategyConfig = strategy_core.StrategyConfig;

test {
    _ = @import("handler.zig");
    _ = @import("strategy_core.zig");
}
