//! serval-health - Backend Health Tracking
//!
//! Lock-free health state with threshold-based transitions.
//! Designed for embedding in handlers without pointers.
//!
//! TigerStyle: Cache-line aligned, no allocation after init, bounded loops.

pub const health_state = @import("health_state.zig");

pub const HealthState = health_state.HealthState;
pub const UpstreamIndex = health_state.UpstreamIndex;
pub const MAX_UPSTREAMS = health_state.MAX_UPSTREAMS;

test {
    _ = health_state;
    _ = @import("tests.zig");
    _ = @import("integration_tests.zig");
}
