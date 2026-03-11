//! HTTP/2 Proxy Primitives
//!
//! Early fixed-capacity stream binding utilities for future stream-aware HTTP/2
//! proxying.
//! TigerStyle: Explicit state, no socket ownership.

pub const bindings = @import("bindings.zig");
pub const Binding = bindings.Binding;
pub const BindingTable = bindings.BindingTable;
pub const BindingError = bindings.Error;

pub const bridge = @import("bridge.zig");
pub const StreamBridge = bridge.StreamBridge;
pub const StreamBridgeError = bridge.Error;
pub const StreamBridgeOpenResult = bridge.OpenResult;
pub const StreamBridgeReceiveAction = bridge.ReceiveAction;

test {
    _ = @import("bindings.zig");
    _ = @import("bridge.zig");
}
