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

/// Re-export of the `handler.zig` module under `serval_lb.handler`.
/// Provides the load-balancer handler API surface, including `LbHandler` and `LbConfig`.
/// This is a compile-time module import (no runtime state, ownership, or error path).
pub const handler = @import("handler.zig");
/// Re-exports the load-balancing strategy core module from `strategy_core.zig`.
/// This is a compile-time namespace alias used to access shared strategy types and logic.
/// It has no runtime allocation, ownership, or error behavior by itself.
pub const strategy_core = @import("strategy_core.zig");

/// Public re-export of [`handler.LbHandler`] for the `serval-lb` module API surface.
/// This is a type alias, so construction, behavior, ownership/lifetime, and error semantics
/// are exactly those defined on `handler.LbHandler` with no additional wrapping logic.
pub const LbHandler = handler.LbHandler;
/// Re-export of [`handler.LbConfig`] for users of `serval-lb`.
/// This is a type alias, not a distinct type; all fields, validation rules,
/// and error behavior are defined by `handler.LbConfig`.
pub const LbConfig = handler.LbConfig;
/// Public re-export of `strategy_core.RoundRobinStrategy` for consumers of `serval-lb`.
/// Implements health-aware round-robin selection with fallback round-robin when no upstream is healthy.
/// Must be initialized before use; `init` requires a non-empty upstream slice and valid thresholds (asserted).
/// Holds a borrowed `[]const Upstream` reference and uses assertions for contract violations (no error return path).
pub const RoundRobinStrategy = strategy_core.RoundRobinStrategy;
/// Re-export of [`strategy_core.StrategyConfig`], the health-threshold config for strategy initialization.
/// Fields are `unhealthy_threshold` and `healthy_threshold`, each defaulting to `serval-core.config` constants.
/// Passed by value into `RoundRobinStrategy.init`; it has no owned resources or lifetime coupling.
/// This alias has no error path; zero thresholds are rejected by `RoundRobinStrategy.init` assertions.
pub const StrategyConfig = strategy_core.StrategyConfig;

test {
    _ = @import("handler.zig");
    _ = @import("strategy_core.zig");
}
