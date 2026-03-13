//! Frontend orchestration helpers.

pub const dispatch = @import("dispatch.zig");
pub const generic_h2 = @import("generic_h2.zig");
pub const TlsDispatchAction = dispatch.TlsDispatchAction;
pub const selectTlsAlpnDispatchAction = dispatch.selectTlsAlpnDispatchAction;
pub const tryServeTlsAlpnConnection = generic_h2.tryServeTlsAlpnConnection;
