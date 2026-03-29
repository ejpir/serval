//! Admin module for gateway controller.
//!
//! Provides health probes and config status endpoints for K8s.

/// Re-exports the gateway controller's admin request handler type.
/// This handler serves `/healthz`, `/readyz`, and `/config` locally without forwarding traffic.
/// It borrows the controller-owned readiness flag and gateway config pointer; both must outlive the handler.
pub const AdminHandler = @import("handler.zig").AdminHandler;
