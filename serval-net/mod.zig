// lib/serval-net/mod.zig
//! Serval Network Utilities
//!
//! DNS resolution and TCP configuration utilities.
//! Like Pingora's connectors module (DNS portion).
//! TigerStyle: Focused utilities, explicit error handling.
//!
//! Note: Socket abstraction moved to serval-socket (Layer 2).
//! This module is Layer 1 (protocol) - only DNS and TCP helpers.

/// TCP socket configuration utilities.
pub const tcp = @import("tcp.zig");

/// DNS resolution with TTL caching.
/// TigerStyle: Fixed-size cache, thread-safe, no runtime allocation.
pub const dns = @import("dns.zig");

// Re-export DNS types for convenience.
/// Re-export of `dns.DnsResolver`.
/// Thread-safe DNS resolver with a fixed-size TTL cache and no runtime allocation after initialization.
/// Call `init(&resolver, config)` before use; the instance owns its internal cache storage and must remain alive for the duration of lookups.
/// Resolution methods return `DnsError` on lookup, timeout, invalid-hostname, or overflow failures.
pub const DnsResolver = dns.DnsResolver;
/// Re-export of `dns.DnsConfig`.
/// Configuration for `DnsResolver`.
/// `ttl_ns` controls how long cached answers remain valid and defaults to `config.DNS_DEFAULT_TTL_NS`.
/// This is a small value type and does not own any resources.
pub const DnsConfig = dns.DnsConfig;
/// Re-export of `dns.DnsError`.
/// Error set returned by DNS resolution APIs in `serval-net`.
/// Includes lookup failure, timeout, invalid hostname, cache exhaustion, and address-buffer overflow.
/// Callers should handle `InvalidHostname` and `AddressOverflow` explicitly when validating inputs or limiting result counts.
pub const DnsError = dns.DnsError;
/// Re-export of `dns.ResolveResult`.
/// Result of resolving a single hostname to one `Io.net.IpAddress`.
/// `address` includes the requested port, `from_cache` reports whether the answer was cached, and `resolution_ns` is `0` for cache hits.
/// This is a plain value type with no ownership or cleanup requirements.
pub const ResolveResult = dns.ResolveResult;

// Re-export common TCP utilities for convenience.
// TigerStyle: Explicit exports, no wildcard imports.
/// Re-export of `tcp.set_tcp_no_delay`.
/// Disables Nagle's algorithm on a TCP socket to reduce latency for small packets.
/// The `-1` file-descriptor sentinel is accepted as a no-op success.
/// Returns `false` if enabling `TCP_NODELAY` fails on a real socket.
pub const set_tcp_no_delay = tcp.set_tcp_no_delay;
/// Re-export of `tcp.set_tcp_keep_alive`.
/// Enables TCP keepalive and configures the idle, interval, and probe-count timers.
/// Requires a valid file descriptor and positive timing values.
/// Returns `false` if any keepalive-related `setsockopt` call fails.
pub const set_tcp_keep_alive = tcp.set_tcp_keep_alive;
/// Re-export of `tcp.set_tcp_quick_ack`.
/// Disables delayed ACK behavior on Linux TCP sockets to reduce latency for small writes.
/// On non-Linux platforms this is treated as a no-op success.
/// Returns `false` only if the underlying socket option call fails.
pub const set_tcp_quick_ack = tcp.set_tcp_quick_ack;
/// Re-export of `tcp.set_so_linger`.
/// Configures `SO_LINGER` on a TCP socket.
/// A timeout of `0` makes `close()` return immediately with an RST; a positive timeout lets `close()` block while queued data drains.
/// Returns `false` if the underlying `setsockopt` call fails.
pub const set_so_linger = tcp.set_so_linger;

// =============================================================================
// IPv4 Parsing
// =============================================================================

const std = @import("std");
const assert = std.debug.assert;

/// Parse IPv4 address string to network-order u32.
/// Returns null for invalid addresses.
pub fn parse_ipv4(host: []const u8) ?u32 {
    if (host.len == 0) return null;
    if (host.len > 15) return null; // "255.255.255.255" = 15 chars max

    assert(host.len <= 15);
    const host_len: u8 = @intCast(host.len);

    var octets: [4]u8 = std.mem.zeroes([4]u8);
    var octet_idx: u8 = 0;
    var current_value: u16 = 0;
    var digit_count: u8 = 0;

    const max_iterations: u8 = 16;
    var iterations: u8 = 0;

    var index: u8 = 0;
    while (index < host_len) : (index += 1) {
        if (iterations >= max_iterations) return null;
        iterations += 1;

        const ch = host[index];
        if (ch == '.') {
            if (digit_count == 0) return null;
            if (current_value > 255) return null;
            if (octet_idx >= 3) return null;

            octets[@intCast(octet_idx)] = @intCast(current_value);
            octet_idx += 1;
            current_value = 0;
            digit_count = 0;
        } else if (ch >= '0' and ch <= '9') {
            current_value = current_value * 10 + @as(u16, ch - '0');
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
    assert(iterations <= max_iterations);
    return @as(u32, octets[0]) |
        (@as(u32, octets[1]) << 8) |
        (@as(u32, octets[2]) << 16) |
        (@as(u32, octets[3]) << 24);
}

// =============================================================================
// Tests
// =============================================================================

test {
    _ = @import("tcp.zig");
    _ = @import("dns.zig");
}

test "parse_ipv4 valid addresses" {
    // Network byte order: first octet in least significant byte
    try std.testing.expectEqual(@as(?u32, 0x0100007F), parse_ipv4("127.0.0.1"));
    try std.testing.expectEqual(@as(?u32, 0x00000000), parse_ipv4("0.0.0.0"));
    try std.testing.expectEqual(@as(?u32, 0xFFFFFFFF), parse_ipv4("255.255.255.255"));
    try std.testing.expectEqual(@as(?u32, 0x0101A8C0), parse_ipv4("192.168.1.1"));
}

test "parse_ipv4 invalid addresses" {
    try std.testing.expectEqual(@as(?u32, null), parse_ipv4(""));
    try std.testing.expectEqual(@as(?u32, null), parse_ipv4("256.0.0.1"));
    try std.testing.expectEqual(@as(?u32, null), parse_ipv4("127.0.0"));
    try std.testing.expectEqual(@as(?u32, null), parse_ipv4("127.0.0.1.2"));
    try std.testing.expectEqual(@as(?u32, null), parse_ipv4("abc.def.ghi.jkl"));
    try std.testing.expectEqual(@as(?u32, null), parse_ipv4("127.0.0."));
    try std.testing.expectEqual(@as(?u32, null), parse_ipv4(".0.0.1"));
}
