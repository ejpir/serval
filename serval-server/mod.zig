// lib/serval-server/mod.zig
//! Serval HTTP Server
//!
//! Provides HTTP/1.1 server (h1/) with future HTTP/2 support (h2/).
//! TigerStyle: Modular protocol implementations.

pub const h1 = @import("h1/mod.zig");

// Primary exports (HTTP/1.1 for now)
pub const Server = h1.Server;
pub const MinimalServer = h1.MinimalServer;

test {
    _ = h1;
}
