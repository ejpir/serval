//! serval-health - Backend Health Tracking
//!
//! Lock-free health state with threshold-based transitions.
//! Designed for embedding in handlers without pointers.
//!
//! TigerStyle: Cache-line aligned, no allocation after init, bounded loops.

/// Namespace import for the health-state implementation module.
/// This exposes the underlying declarations defined in `health_state.zig` under the `serval-health` package root.
/// Importing this module does not allocate or initialize runtime state by itself.
pub const health_state = @import("health_state.zig");

/// Re-export of the unified health-state implementation from `health_state.zig`.
/// `HealthState` stores the health bitmap, per-backend counters, and threshold logic used by the module.
/// Create and manage instances through the imported API; this alias adds no additional behavior or ownership.
pub const HealthState = health_state.HealthState;
/// Re-export of `serval-core.config.UpstreamIndex` for indexing health-tracked backends.
/// Use this type for backend slots within the configured upstream bound.
/// This is a type alias only; it does not allocate, own, or validate values on its own.
pub const UpstreamIndex = @import("serval-core").config.UpstreamIndex;
/// Re-export of `serval-core.config.MAX_UPSTREAMS` for health state sizing.
/// This is the fixed upper bound for tracked upstream backends and the bitmap width used by this module.
/// No runtime behavior or ownership is associated with this alias.
pub const MAX_UPSTREAMS = @import("serval-core").config.MAX_UPSTREAMS;

test {
    _ = health_state;
    _ = @import("tests.zig");
    _ = @import("integration_tests.zig");
}
