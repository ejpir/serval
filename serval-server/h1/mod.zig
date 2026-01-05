// lib/serval-server/h1/mod.zig
//! HTTP/1.1 Server Implementation
//!
//! Provides the generic Server type parameterized by Handler, Pool, Metrics, Tracer.
//! TigerStyle: Modular design preparing for HTTP/2 in h2/.

pub const server = @import("server.zig");
pub const connection = @import("connection.zig");
pub const response = @import("response.zig");
pub const reader = @import("reader.zig");

// Primary exports
pub const Server = server.Server;
pub const MinimalServer = server.MinimalServer;

test {
    _ = server;
    _ = connection;
    _ = response;
    _ = reader;
}
