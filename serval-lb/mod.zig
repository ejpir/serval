// lib/serval-lb/mod.zig
//! Serval Load Balancer Library
//!
//! Standalone load balancing handlers compatible with serval HTTP/1.1 server.
//! Like Pingora's separate crates, this library can be used independently.
//!
//! Example:
//!   const serval_lb = @import("serval-lb");
//!   var handler = serval_lb.LbHandler.init(&upstreams);
//!   var server = serval.Server(serval_lb.LbHandler, ...).init(&handler, ...);

pub const handler = @import("handler.zig");
pub const LbHandler = handler.LbHandler;

test {
    _ = @import("handler.zig");
}
