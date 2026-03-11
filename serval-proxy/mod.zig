// lib/serval-proxy/mod.zig
//! Serval Proxy - Upstream Forwarding
//!
//! Zero-copy upstream forwarding with connection pooling.
//! TigerStyle: Splice for zero-copy, bounded loops.

pub const types = @import("types.zig");
pub const ForwardError = types.ForwardError;
pub const ForwardResult = types.ForwardResult;
pub const BodyInfo = types.BodyInfo;
pub const Protocol = types.Protocol;

pub const tunnel = @import("tunnel.zig");
pub const TunnelStats = tunnel.TunnelStats;
pub const TunnelTermination = tunnel.Termination;

pub const h2 = @import("h2/mod.zig");
pub const H2Binding = h2.Binding;
pub const H2BindingTable = h2.BindingTable;
pub const H2BindingError = h2.BindingError;
pub const H2StreamBridge = h2.StreamBridge;
pub const H2StreamBridgeError = h2.StreamBridgeError;
pub const H2StreamBridgeOpenResult = h2.StreamBridgeOpenResult;
pub const H2StreamBridgeReceiveAction = h2.StreamBridgeReceiveAction;

pub const forwarder = @import("forwarder.zig");
pub const Forwarder = forwarder.Forwarder;

test {
    _ = @import("types.zig");
    _ = @import("connect.zig");
    _ = @import("h1/mod.zig");
    _ = @import("h2/mod.zig");
    _ = @import("tunnel.zig");
    _ = @import("forwarder.zig");
}
