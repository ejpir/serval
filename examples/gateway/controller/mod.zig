//! Controller Module
//!
//! Manages gateway state, admin server, and config updates.
//! Coordinates between K8s watcher and data plane.
//!
//! TigerStyle: Thread-safe state, uses serval components, explicit errors.

const controller = @import("controller.zig");
/// Re-exports the main gateway controller type.
/// This is an alias of `controller.Controller` for callers importing `examples/gateway/controller/mod.zig`.
pub const Controller = controller.Controller;

/// Imports the gateway controller evaluator implementation.
/// Use this namespace for evaluator logic defined in `evaluator.zig`.
pub const evaluator = @import("evaluator.zig");
/// Imports the gateway controller status submodule.
/// Use this namespace for status types and helpers defined under `status/mod.zig`.
pub const status = @import("status/mod.zig");

/// Imports the gateway controller router client submodule.
/// Use this namespace for router-client types and helpers defined under `routerclient/mod.zig`.
pub const routerclient = @import("routerclient/mod.zig");

/// Imports the gateway controller admin submodule.
/// Use this namespace for admin-server types and helpers defined under `admin/mod.zig`.
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

/// Errors returned by gateway controller operations.
/// AdminBindFailed, AdminListenFailed, and AdminThreadFailed report admin server startup failures.
/// OutOfMemory reports allocation failure, and DataPlanePushFailed reports a failed config push.
/// Callers should handle these errors when creating, starting, or synchronizing the controller.
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
