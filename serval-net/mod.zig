// lib/serval-net/mod.zig
//! Serval Network Utilities
//!
//! Socket abstraction (plain + TLS) and TCP configuration utilities.
//! Like Pingora's connectors module.
//! TigerStyle: Focused utilities, explicit error handling.

const socket = @import("socket.zig");

/// Unified socket type for both plain TCP and TLS connections.
/// TigerStyle: Tagged union, explicit dispatch.
pub const Socket = socket.Socket;

/// Error type for socket operations.
/// TigerStyle: Explicit error set.
pub const SocketError = socket.SocketError;

/// TCP socket configuration utilities.
pub const tcp = @import("tcp.zig");

// Re-export common TCP utilities for convenience.
// TigerStyle: Explicit exports, no wildcard imports.
pub const setTcpNoDelay = tcp.setTcpNoDelay;
pub const setTcpKeepAlive = tcp.setTcpKeepAlive;
pub const setTcpQuickAck = tcp.setTcpQuickAck;
pub const setSoLinger = tcp.setSoLinger;

// =============================================================================
// IPv4 Parsing
// =============================================================================

const std = @import("std");
const assert = std.debug.assert;

/// Parse IPv4 address string to network-order u32.
/// Returns null for invalid addresses.
pub fn parseIPv4(host: []const u8) ?u32 {
    if (host.len == 0) return null;
    if (host.len > 15) return null; // "255.255.255.255" = 15 chars max

    var octets: [4]u8 = std.mem.zeroes([4]u8);
    var octet_idx: usize = 0;
    var current_value: u16 = 0;
    var digit_count: usize = 0;

    const max_iterations: usize = 16;
    var iterations: usize = 0;

    for (host) |ch| {
        if (iterations >= max_iterations) return null;
        iterations += 1;

        if (ch == '.') {
            if (digit_count == 0) return null;
            if (current_value > 255) return null;
            if (octet_idx >= 3) return null;

            octets[octet_idx] = @intCast(current_value);
            octet_idx += 1;
            current_value = 0;
            digit_count = 0;
        } else if (ch >= '0' and ch <= '9') {
            current_value = current_value * 10 + (ch - '0');
            digit_count += 1;
            if (digit_count > 3) return null;
        } else {
            return null;
        }
    }

    // Final octet
    if (digit_count == 0) return null;
    if (current_value > 255) return null;
    if (octet_idx != 3) return null;

    octets[3] = @intCast(current_value);

    assert(octet_idx == 3);
    return @as(u32, octets[0]) |
        (@as(u32, octets[1]) << 8) |
        (@as(u32, octets[2]) << 16) |
        (@as(u32, octets[3]) << 24);
}

// =============================================================================
// Tests
// =============================================================================

test {
    _ = @import("socket.zig");
    _ = @import("tcp.zig");
    _ = @import("tls_socket.zig");
}

test "parseIPv4 valid addresses" {
    // Network byte order: first octet in least significant byte
    try std.testing.expectEqual(@as(?u32, 0x0100007F), parseIPv4("127.0.0.1"));
    try std.testing.expectEqual(@as(?u32, 0x00000000), parseIPv4("0.0.0.0"));
    try std.testing.expectEqual(@as(?u32, 0xFFFFFFFF), parseIPv4("255.255.255.255"));
    try std.testing.expectEqual(@as(?u32, 0x0101A8C0), parseIPv4("192.168.1.1"));
}

test "parseIPv4 invalid addresses" {
    try std.testing.expectEqual(@as(?u32, null), parseIPv4(""));
    try std.testing.expectEqual(@as(?u32, null), parseIPv4("256.0.0.1"));
    try std.testing.expectEqual(@as(?u32, null), parseIPv4("127.0.0"));
    try std.testing.expectEqual(@as(?u32, null), parseIPv4("127.0.0.1.2"));
    try std.testing.expectEqual(@as(?u32, null), parseIPv4("abc.def.ghi.jkl"));
    try std.testing.expectEqual(@as(?u32, null), parseIPv4("127.0.0."));
    try std.testing.expectEqual(@as(?u32, null), parseIPv4(".0.0.1"));
}
