// lib/serval-core/log.zig
//! Logging Utilities
//!
//! Comptime-conditional debug logging and LogEntry for request lifecycle.
//! TigerStyle: Zero overhead in release builds.

const std = @import("std");
const config = @import("config.zig");
const types = @import("types.zig");
const errors = @import("errors.zig");

const Method = types.Method;
const Upstream = types.Upstream;

/// Comptime-conditional debug logging.
/// TigerStyle: Zero overhead in release builds via dead code elimination.
pub fn debugLog(comptime fmt: []const u8, args: anytype) void {
    comptime std.debug.assert(fmt.len > 0); // Precondition: non-empty format
    if (comptime config.DEBUG_LOGGING) {
        std.log.debug(fmt, args);
    }
}

// =============================================================================
// Log Entry (passed to onLog hook)
// =============================================================================

/// Complete request lifecycle information for structured logging.
/// Passed to the handler's onLog hook after each request completes.
pub const LogEntry = struct {
    // Timing
    timestamp_s: u64, // Unix epoch seconds (for log output)
    start_time_ns: i128, // Full precision nanoseconds since epoch
    duration_ns: u64,

    // Request
    method: Method,
    /// Request path.
    /// Lifetime: Valid only during onLog callback; points into the request buffer
    /// which is owned by the connection handler and may be reused for the next request.
    path: []const u8,
    request_bytes: u64,

    // Response
    status: u16,
    response_bytes: u64,

    // Upstream
    upstream: ?Upstream,
    upstream_duration_ns: u64,

    // Errors
    error_phase: ?errors.ErrorContext.Phase,
    /// Error name if an error occurred.
    /// Lifetime: Valid only during onLog callback; points into the error name constant
    /// pool or temporary buffer owned by the connection handler.
    error_name: ?[]const u8,

    // Connection
    connection_reused: bool,
    keepalive: bool,

    // Phase timing breakdown
    parse_duration_ns: u64 = 0,
    connect_duration_ns: u64 = 0,
    send_duration_ns: u64 = 0,
    recv_duration_ns: u64 = 0,

    // Network-level timing
    dns_duration_ns: u64 = 0,
    tcp_connect_duration_ns: u64 = 0,
    pool_wait_ns: u64 = 0,

    // Connection context
    connection_id: u64 = 0,
    request_number: u32 = 0,
    client_addr: [46]u8 = std.mem.zeroes([46]u8),
    upstream_local_port: u16 = 0,
};

test "debugLog compiles in both modes" {
    debugLog("test message {d}", .{42});
}
