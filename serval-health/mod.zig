//! serval-health - Backend Health Tracking
//!
//! Lock-free health state with threshold-based transitions.
//! Designed for embedding in handlers without pointers.
//!
//! TigerStyle: Cache-line aligned, no allocation after init, bounded loops.

pub const health_state = @import("health_state.zig");

pub const HealthState = health_state.HealthState;
pub const BackendIndex = health_state.BackendIndex;
pub const MAX_UPSTREAMS = health_state.MAX_UPSTREAMS;

// Keep old types for backwards compatibility during transition
pub const state = @import("state.zig");
pub const tracker = @import("tracker.zig");
pub const SharedHealthState = state.SharedHealthState;
pub const HealthTracker = tracker.HealthTracker;

test {
    _ = health_state;
    _ = state;
    _ = tracker;
    _ = @import("tests.zig");
    _ = @import("integration_tests.zig");
}
