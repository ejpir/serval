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
pub const LbHandler = handler.LbHandler;
pub const LbConfig = handler.LbConfig;

test {
    _ = @import("handler.zig");
}
