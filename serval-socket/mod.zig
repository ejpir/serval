// serval-socket/mod.zig
//! Serval Socket Abstraction
//!
//! Unified socket interface for both plain TCP and TLS connections.
//! Layer 2 (Infrastructure) module that composes serval-tls primitives
//! into a single Socket tagged union for use by higher-level modules.
//!
//! TigerStyle: Tagged union, explicit dispatch, no generics.

const socket = @import("socket.zig");

/// Unified socket type for both plain TCP and TLS connections.
/// TigerStyle: Tagged union, explicit dispatch.
pub const Socket = socket.Socket;

/// Error type for socket operations.
/// TigerStyle: Explicit error set.
pub const SocketError = socket.SocketError;

/// Plain TCP socket (no encryption).
/// TigerStyle: Thin wrapper over fd with explicit lifecycle.
pub const PlainSocket = socket.PlainSocket;

// =============================================================================
// Tests
// =============================================================================

test {
    _ = @import("socket.zig");
    _ = @import("tls_socket.zig");
}
