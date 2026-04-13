//! HTTP/2 Proxy Primitives
//!
//! Early fixed-capacity stream binding utilities for future stream-aware HTTP/2
//! proxying.
//! TigerStyle: Explicit state, no socket ownership.

/// Re-export of the `bindings.zig` module for HTTP/2 binding management.
/// Import this namespace to access binding types, errors, and table helpers.
/// The module definition and behavior live in `bindings.zig`.
pub const bindings = @import("bindings.zig");
/// Alias for `bindings.Binding`, the HTTP/2 binding record type.
/// A binding represents one table entry used by the proxy layer.
/// See `bindings` for the underlying fields and lifecycle expectations.
pub const Binding = bindings.Binding;
/// Alias for `bindings.BindingTable`, the HTTP/2 binding table type.
/// The table stores and manages bindings used by the proxy layer.
/// Initialize caller-owned storage with `BindingTable.initInto()` before use.
/// Refer to `bindings` for construction, ownership, and error behavior.
pub const BindingTable = bindings.BindingTable;
/// Alias for `bindings.Error` in the HTTP/2 binding API.
/// Use this error set for binding-related failures reported by the table and binding types.
/// See `bindings` for the exact error members.
pub const BindingError = bindings.Error;

/// Re-export of the `bridge.zig` module for HTTP/2 stream bridging.
/// Import this namespace to access bridge types and helpers from one place.
/// The module definition and behavior live in `bridge.zig`.
pub const bridge = @import("bridge.zig");
/// Alias for `bridge.StreamBridge`, the HTTP/2 stream bridging implementation.
/// This type owns the bridge behavior used to connect HTTP/2 streams to proxy logic.
/// Initialize caller-owned storage with `StreamBridge.initInto(client, sessions)`.
/// Refer to `bridge` for construction, lifecycle, and error semantics.
pub const StreamBridge = bridge.StreamBridge;
/// Alias for `bridge.Error` in the HTTP/2 stream bridge API.
/// Use this error set for bridge-specific failure conditions.
/// See `bridge` for the exact error members and their meaning.
pub const StreamBridgeError = bridge.Error;
/// Alias for `bridge.OpenResult` in the HTTP/2 stream bridge API.
/// This type reports the result of opening a bridged stream.
/// See `bridge` for the underlying definition and any associated fields or errors.
pub const StreamBridgeOpenResult = bridge.OpenResult;
/// Alias for `bridge.ReceiveAction` in the HTTP/2 stream bridge API.
/// Use this type to describe how received data should be handled by bridge code.
/// See `bridge` for the underlying definition and behavior.
pub const StreamBridgeReceiveAction = bridge.ReceiveAction;

test {
    _ = @import("bindings.zig");
    _ = @import("bridge.zig");
}
