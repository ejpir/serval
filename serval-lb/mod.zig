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
pub const prober = @import("prober.zig");
pub const LbHandler = handler.LbHandler;
pub const LbConfig = handler.LbConfig;
pub const ProberContext = prober.ProberContext;

test {
    _ = @import("handler.zig");
    _ = @import("prober.zig");
}
