// lib/serval-server/h1/mod.zig
//! HTTP/1.1 Server Implementation
//!
//! Provides the generic Server type parameterized by Handler, Pool, Metrics, Tracer.
//! TigerStyle: Modular design preparing for HTTP/2 in h2/.

/// Imported `server.zig` namespace for the HTTP/1.1 server implementation.
/// Contains the generic `Server` factory, the minimal specialization, and the internal wiring used by both.
/// This namespace is the source of the public server aliases exported by `h1.mod`.
pub const server = @import("server.zig");
/// Imported `connection.zig` namespace for HTTP/1.1 connection helpers.
/// Provides connection IDs, close-detection, and request-processing state types.
/// Call these helpers through `h1.connection` when managing per-connection behavior.
pub const connection = @import("connection.zig");
/// Imported `response.zig` namespace for HTTP/1.1 response-writing helpers.
/// Exposes status text lookup, standard error responses, and direct or streaming response emitters.
/// Call these helpers through `h1.response` when writing responses to a client stream.
pub const response = @import("response.zig");
/// Imported `reader.zig` namespace for HTTP/1.1 request-reading helpers.
/// Exposes buffered request reads and Content-Length extraction utilities.
/// Call these helpers through `h1.reader` when working with incoming request bytes.
pub const reader = @import("reader.zig");

// Primary exports
/// Re-export of `server.Server`.
/// This is the generic HTTP/1.1 server factory parameterized by handler, pool, metrics, and tracer types.
/// The returned type is verified at compile time against the Serval interfaces it requires.
pub const Server = server.Server;
/// Re-export of `server.MinimalServer`.
/// Use this alias when you want the minimal HTTP/1.1 server specialization from `server.zig`.
/// The exact handler interface and stored dependencies are defined by the returned type.
pub const MinimalServer = server.MinimalServer;

test {
    _ = server;
    _ = connection;
    _ = response;
    _ = reader;
}
