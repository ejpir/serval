//! serval-health - Backend Health Tracking
//!
//! Lock-free shared state for tracking backend health status.
//! Threshold-based transitions prevent flapping on transient failures.
//!
//! Features:
//! - Atomic u64 bitmap for health status (64 backends max)
//! - Per-backend failure/success counters with thresholds
//! - Cache-line aligned to prevent false sharing
//! - O(1) health checks, O(popcount) selection
//!
//! TigerStyle: All operations bounded, no allocations after init.

pub const state = @import("state.zig");
pub const tracker = @import("tracker.zig");

pub const SharedHealthState = state.SharedHealthState;
pub const BackendIndex = state.BackendIndex;
pub const HealthTracker = tracker.HealthTracker;

test {
    _ = state;
    _ = tracker;
    _ = @import("tests.zig");
}
