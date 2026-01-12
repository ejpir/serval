//! Admin module for gateway controller.
//!
//! Provides health probes and config status endpoints for K8s.

pub const AdminHandler = @import("handler.zig").AdminHandler;
