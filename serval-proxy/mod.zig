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

pub const forwarder = @import("forwarder.zig");
pub const Forwarder = forwarder.Forwarder;

test {
    _ = @import("types.zig");
    _ = @import("connect.zig");
    _ = @import("h1/mod.zig");
    _ = @import("forwarder.zig");
}
