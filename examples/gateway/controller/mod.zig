//! Controller Module
//!
//! Manages gateway state, admin server, and config updates.
//! Coordinates between K8s watcher and data plane.
//!
//! TigerStyle: Thread-safe state, uses serval components, explicit errors.

const controller = @import("controller.zig");
pub const Controller = controller.Controller;

pub const evaluator = @import("evaluator.zig");
pub const status = @import("status/mod.zig");

pub const routerclient = @import("routerclient/mod.zig");

pub const admin = @import("admin/mod.zig");

// ============================================================================
// Constants (TigerStyle Y3: Units in names)
// ============================================================================

/// Maximum length for router service namespace.
pub const MAX_ROUTER_NAMESPACE_LEN: u8 = 63;

/// Maximum length for router service name.
pub const MAX_ROUTER_SERVICE_NAME_LEN: u8 = 63;

// ============================================================================
// Error Types
// ============================================================================

pub const ControllerError = error{
    /// Admin server bind failed.
    AdminBindFailed,
    /// Admin server listen failed.
    AdminListenFailed,
    /// Admin server thread spawn failed.
    AdminThreadFailed,
    /// Memory allocation failed.
    OutOfMemory,
    /// Failed to push config to data plane.
    DataPlanePushFailed,
};
