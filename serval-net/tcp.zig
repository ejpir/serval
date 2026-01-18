// serval-net/tcp.zig
//! TCP Socket Utilities
//!
//! TCP socket configuration helpers (Nagle, keepalive, linger).
//! TigerStyle: Small focused functions, explicit error handling.

const std = @import("std");
const log = @import("serval-core").log.scoped(.net);
const assert = std.debug.assert;
const posix = std.posix;

// Verify TCP protocol number at comptime (defense in depth)
comptime {
    assert(posix.IPPROTO.TCP == 6);
}

/// Disable Nagle's algorithm on a TCP socket.
/// Prevents 40ms delay when sending small packets (Nagle + delayed ACKs).
/// Returns true if successful, false if setsockopt failed.
/// TigerStyle: Explicit return value instead of swallowing errors.
pub fn set_tcp_no_delay(fd: i32) bool {
    // Precondition: fd must be >= -1 (-1 is valid "skip" sentinel, < -1 is programming error)
    assert(fd >= -1);

    // No-op for invalid fd sentinel, not an error
    if (fd < 0) return true;

    // Use native endianness - setsockopt expects host byte order for integer options
    const enabled: u32 = 1;
    const value_bytes = std.mem.asBytes(&enabled);

    posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, value_bytes) catch |err| {
        // Log at debug level - this is an optimization, not critical
        // TigerStyle: Explicit error handling instead of catch {}
        log.debug("set_tcp_no_delay failed on fd {d}: {s}", .{ fd, @errorName(err) });
        return false;
    };

    return true;
}

/// Configure TCP keepalive on a socket.
/// Sends probes after idle_secs of inactivity, then every interval_secs,
/// closing after count failed probes.
/// Returns true if all options set successfully.
/// TigerStyle: Explicit parameters, no magic defaults.
pub fn set_tcp_keep_alive(
    fd: i32,
    idle_secs: u32,
    interval_secs: u32,
    count: u32,
) bool {
    // Preconditions: valid fd and positive timing values
    assert(fd >= 0);
    assert(idle_secs > 0);
    assert(interval_secs > 0);
    assert(count > 0);

    // Enable keepalive
    const enabled: u32 = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&enabled)) catch |err| {
        log.debug("set_tcp_keep_alive SO_KEEPALIVE failed on fd {d}: {s}", .{ fd, @errorName(err) });
        return false;
    };

    // Set timing parameters (Linux only - other platforms use system defaults)
    if (@import("builtin").os.tag == .linux) {
        // TCP_KEEPIDLE: idle time before first probe
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, std.mem.asBytes(&idle_secs)) catch |err| {
            log.debug("set_tcp_keep_alive KEEPIDLE failed on fd {d}: {s}", .{ fd, @errorName(err) });
            return false;
        };

        // TCP_KEEPINTVL: interval between probes
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, std.mem.asBytes(&interval_secs)) catch |err| {
            log.debug("set_tcp_keep_alive KEEPINTVL failed on fd {d}: {s}", .{ fd, @errorName(err) });
            return false;
        };

        // TCP_KEEPCNT: probe count before declaring dead
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, std.mem.asBytes(&count)) catch |err| {
            log.debug("set_tcp_keep_alive KEEPCNT failed on fd {d}: {s}", .{ fd, @errorName(err) });
            return false;
        };
    }
    // On non-Linux, only SO_KEEPALIVE is set (uses system defaults for timing)

    return true;
}

/// Disable delayed ACKs on a TCP socket (Linux only).
/// Reduces latency at cost of more ACK packets.
/// Returns true if successful (or not Linux).
/// TigerStyle: Explicit opt-in for latency optimization.
pub fn set_tcp_quick_ack(fd: i32) bool {
    // Precondition: valid fd
    assert(fd >= 0);

    if (@import("builtin").os.tag != .linux) return true;

    const enabled: u32 = 1;
    posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.QUICKACK, std.mem.asBytes(&enabled)) catch |err| {
        log.debug("set_tcp_quick_ack failed on fd {d}: {s}", .{ fd, @errorName(err) });
        return false;
    };
    return true;
}

/// Configure SO_LINGER on a socket.
/// If timeout_secs > 0, close() blocks up to timeout_secs waiting for data to send.
/// If timeout_secs = 0, close() returns immediately with RST, unsent data lost.
/// Returns true if successful.
/// TigerStyle: Explicit close behavior, no implicit blocking.
pub fn set_so_linger(fd: i32, timeout_secs: u16) bool {
    // Precondition: valid fd
    assert(fd >= 0);

    const linger_val = posix.linger{
        .onoff = if (timeout_secs > 0) 1 else 0,
        .linger = @intCast(timeout_secs),
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.LINGER, std.mem.asBytes(&linger_val)) catch |err| {
        log.debug("set_so_linger failed on fd {d}: {s}", .{ fd, @errorName(err) });
        return false;
    };
    return true;
}

test "set_tcp_no_delay sentinel fd returns true" {
    // -1 sentinel should return true (no-op success)
    try std.testing.expect(set_tcp_no_delay(-1) == true);
}

test "set_tcp_no_delay on valid socket" {
    // Use a real socket to test - fd 0 (stdin) causes panic in setsockopt
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(sock);

    // Valid socket should succeed
    const result = set_tcp_no_delay(sock);
    try std.testing.expect(result == true);
}

test "set_tcp_keep_alive on valid socket" {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(sock);

    // Valid call should succeed
    const result = set_tcp_keep_alive(sock, 60, 10, 3);
    try std.testing.expect(result);
}

test "set_tcp_quick_ack on valid socket" {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(sock);

    const result = set_tcp_quick_ack(sock);
    // On Linux should succeed, on other platforms returns true (no-op)
    try std.testing.expect(result);
}

test "set_so_linger sets linger options" {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(sock);

    // Test immediate close (RST)
    try std.testing.expect(set_so_linger(sock, 0));

    // Test linger with timeout
    try std.testing.expect(set_so_linger(sock, 5));
}
