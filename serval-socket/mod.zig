// serval-socket/mod.zig
//! Serval Socket Abstraction
//!
//! Unified socket interface for both plain TCP and TLS connections.
//! Layer 2 (Infrastructure) module that composes serval-tls primitives
//! into a single Socket tagged union for use by higher-level modules.
//!
//! TigerStyle: Tagged union, explicit dispatch, no generics.

const socket = @import("socket.zig");
const terminated_driver = @import("terminated_driver.zig");

/// Unified socket type for both plain TCP and TLS connections.
/// TigerStyle: Tagged union, explicit dispatch.
pub const Socket = socket.Socket;

/// Error type for socket operations.
/// TigerStyle: Explicit error set.
pub const SocketError = socket.SocketError;

/// Plain TCP socket (no encryption).
/// TigerStyle: Thin wrapper over fd with explicit lifecycle.
pub const PlainSocket = socket.PlainSocket;

/// Terminated transport driver namespace.
/// Provides deadline-based plain+TLS read/write outcomes for terminated
/// protocol loops that must not interpret low-level TLS WANT states.
pub const terminated = terminated_driver;

/// Re-export of terminated driver read outcomes.
/// Use this for progress/close/timeout handling at protocol-driver call sites.
pub const ReadOutcome = terminated_driver.ReadOutcome;

/// Re-export of terminated driver write outcomes.
/// Use this for progress/close/timeout handling at protocol-driver call sites.
pub const WriteOutcome = terminated_driver.WriteOutcome;

/// Re-export of terminated driver fatal transport errors.
/// Reserved for unrecoverable readiness/syscall/TLS failures.
pub const DriverError = terminated_driver.DriverError;

// =============================================================================
// Tests
// =============================================================================

test {
    _ = @import("socket.zig");
    _ = @import("tls_socket.zig");
    _ = @import("terminated_driver.zig");
}
