// serval-net/tcp.zig
//! TCP Socket Utilities
//!
//! TCP socket configuration helpers (Nagle, keepalive, linger).
//! TigerStyle: Small focused functions, explicit error handling.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const posix = std.posix;

// Verify TCP protocol number at comptime (defense in depth)
comptime {
    assert(posix.IPPROTO.TCP == 6);
}

// kTLS constants (Linux kernel TLS offload)
// See: https://www.kernel.org/doc/html/latest/networking/tls-offload.html
const SOL_TLS: i32 = 282;
const TLS_TX: u32 = 1;
const TLS_RX: u32 = 2;

/// Disable Nagle's algorithm on a TCP socket.
/// Prevents 40ms delay when sending small packets (Nagle + delayed ACKs).
/// Returns true if successful, false if setsockopt failed.
/// TigerStyle: Explicit return value instead of swallowing errors.
pub fn setTcpNoDelay(fd: i32) bool {
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
        std.log.debug("setTcpNoDelay failed on fd {d}: {s}", .{ fd, @errorName(err) });
        return false;
    };

    return true;
}

/// Configure TCP keepalive on a socket.
/// Sends probes after idle_secs of inactivity, then every interval_secs,
/// closing after count failed probes.
/// Returns true if all options set successfully.
/// TigerStyle: Explicit parameters, no magic defaults.
pub fn setTcpKeepAlive(
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
        std.log.debug("setTcpKeepAlive SO_KEEPALIVE failed on fd {d}: {s}", .{ fd, @errorName(err) });
        return false;
    };

    // Set timing parameters (Linux only - other platforms use system defaults)
    if (@import("builtin").os.tag == .linux) {
        // TCP_KEEPIDLE: idle time before first probe
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, std.mem.asBytes(&idle_secs)) catch |err| {
            std.log.debug("setTcpKeepAlive KEEPIDLE failed on fd {d}: {s}", .{ fd, @errorName(err) });
            return false;
        };

        // TCP_KEEPINTVL: interval between probes
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, std.mem.asBytes(&interval_secs)) catch |err| {
            std.log.debug("setTcpKeepAlive KEEPINTVL failed on fd {d}: {s}", .{ fd, @errorName(err) });
            return false;
        };

        // TCP_KEEPCNT: probe count before declaring dead
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, std.mem.asBytes(&count)) catch |err| {
            std.log.debug("setTcpKeepAlive KEEPCNT failed on fd {d}: {s}", .{ fd, @errorName(err) });
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
pub fn setTcpQuickAck(fd: i32) bool {
    // Precondition: valid fd
    assert(fd >= 0);

    if (@import("builtin").os.tag != .linux) return true;

    const enabled: u32 = 1;
    posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.QUICKACK, std.mem.asBytes(&enabled)) catch |err| {
        std.log.debug("setTcpQuickAck failed on fd {d}: {s}", .{ fd, @errorName(err) });
        return false;
    };
    return true;
}

/// Configure SO_LINGER on a socket.
/// If timeout_secs > 0, close() blocks up to timeout_secs waiting for data to send.
/// If timeout_secs = 0, close() returns immediately with RST, unsent data lost.
/// Returns true if successful.
/// TigerStyle: Explicit close behavior, no implicit blocking.
pub fn setSoLinger(fd: i32, timeout_secs: u16) bool {
    // Precondition: valid fd
    assert(fd >= 0);

    const linger_val = posix.linger{
        .onoff = if (timeout_secs > 0) 1 else 0,
        .linger = @intCast(timeout_secs),
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.LINGER, std.mem.asBytes(&linger_val)) catch |err| {
        std.log.debug("setSoLinger failed on fd {d}: {s}", .{ fd, @errorName(err) });
        return false;
    };
    return true;
}

/// Attach TLS Upper Layer Protocol to a TCP socket (Linux only).
/// This is the first step to enable kernel TLS offload.
/// After attachment, use setKtlsTx/setKtlsRx to configure crypto params.
/// Returns true if successful, false if failed or not Linux.
/// TigerStyle: Linux-only feature with explicit platform check.
pub fn attachTlsULP(fd: i32) bool {
    // Precondition: valid fd
    assert(fd >= 0);

    // kTLS is Linux-only
    if (builtin.os.tag != .linux) {
        std.log.debug("attachTlsULP: kTLS not available (non-Linux platform)", .{});
        return false;
    }

    // TCP_ULP expects a null-terminated string "tls"
    const ulp_name: *const [4]u8 = "tls\x00";

    // Use raw Linux syscall to handle all possible errors gracefully
    // (posix.setsockopt panics on some unexpected errno values)
    const rc = std.os.linux.setsockopt(
        fd,
        posix.IPPROTO.TCP,
        posix.TCP.ULP,
        ulp_name,
        4,
    );

    const err = posix.errno(rc);
    if (err != .SUCCESS) {
        if (err == .NOPROTOOPT or err == .NOENT) {
            // kTLS module not loaded or TLS ULP not available
            std.log.debug("attachTlsULP: kTLS not available ({s})", .{@tagName(err)});
        } else {
            std.log.debug("attachTlsULP failed on fd {d}: {s}", .{ fd, @tagName(err) });
        }
        return false;
    }

    return true;
}

/// Configure kTLS TX (encrypt) offload on a socket (Linux only).
/// Must call attachTlsULP first. crypto_info contains cipher-specific params
/// (e.g., tls12_crypto_info_aes_gcm_128 struct from linux/tls.h).
/// Returns true if successful.
/// TigerStyle: Explicit crypto_info parameter, caller provides cipher config.
pub fn setKtlsTx(fd: i32, crypto_info: []const u8) bool {
    return setKtlsDirection(fd, crypto_info, TLS_TX, "TX");
}

/// Configure kTLS RX (decrypt) offload on a socket (Linux only).
/// Must call attachTlsULP first. crypto_info contains cipher-specific params.
/// Returns true if successful.
/// TigerStyle: Same pattern as setKtlsTx for consistency.
pub fn setKtlsRx(fd: i32, crypto_info: []const u8) bool {
    return setKtlsDirection(fd, crypto_info, TLS_RX, "RX");
}

/// Shared implementation for kTLS TX/RX configuration.
/// TigerStyle: Single implementation avoids duplication.
fn setKtlsDirection(fd: i32, crypto_info: []const u8, direction: u32, direction_name: []const u8) bool {
    // Preconditions: valid fd and non-empty crypto info
    assert(fd >= 0);
    assert(crypto_info.len > 0);
    assert(direction == TLS_TX or direction == TLS_RX);

    // kTLS is Linux-only
    if (builtin.os.tag != .linux) {
        std.log.debug("setKtls{s}: kTLS not available (non-Linux platform)", .{direction_name});
        return false;
    }

    // Use raw Linux syscall since SOL_TLS is not in std.posix
    const rc = std.os.linux.setsockopt(
        fd,
        SOL_TLS,
        direction,
        crypto_info.ptr,
        @intCast(crypto_info.len),
    );

    const err = posix.errno(rc);
    if (err != .SUCCESS) {
        if (err == .NOPROTOOPT) {
            std.log.debug("setKtls{s}: kTLS not available (ENOPROTOOPT)", .{direction_name});
        } else {
            std.log.debug("setKtls{s} failed on fd {d}: {s}", .{ direction_name, fd, @tagName(err) });
        }
        return false;
    }

    return true;
}

test "setTcpNoDelay does not crash on invalid fd" {
    // -1 sentinel should return true (no-op success)
    try std.testing.expect(setTcpNoDelay(-1) == true);
    // fd 0 is typically stdin, setsockopt will fail but should return false (not crash)
    _ = setTcpNoDelay(0);
}

test "setTcpKeepAlive on valid socket" {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        // Socket creation failed (no network?), skip test
        return;
    };
    defer posix.close(sock);

    // Valid call should succeed
    const result = setTcpKeepAlive(sock, 60, 10, 3);
    try std.testing.expect(result);
}

test "setTcpQuickAck on valid socket" {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return;
    };
    defer posix.close(sock);

    const result = setTcpQuickAck(sock);
    // On Linux should succeed, on other platforms returns true (no-op)
    try std.testing.expect(result);
}

test "setSoLinger sets linger options" {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch {
        return;
    };
    defer posix.close(sock);

    // Test immediate close (RST)
    try std.testing.expect(setSoLinger(sock, 0));

    // Test linger with timeout
    try std.testing.expect(setSoLinger(sock, 5));
}

test "attachTlsULP on unconnected socket" {
    // kTLS requires a connected socket to actually succeed
    // but we can test that the function doesn't crash on a valid fd
    if (builtin.os.tag != .linux) {
        // Non-Linux: should return false gracefully
        const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
        defer posix.close(sock);
        try std.testing.expect(attachTlsULP(sock) == false);
        return;
    }

    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(sock);

    // Will likely fail (ENOTCONN or ENOPROTOOPT) but should not crash
    _ = attachTlsULP(sock);
}

test "setKtlsTx returns false without TLS ULP attached" {
    if (builtin.os.tag != .linux) return;

    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(sock);

    // Dummy crypto_info - actual kTLS requires proper tls12_crypto_info struct
    const dummy_crypto: [40]u8 = .{0} ** 40;

    // Should fail since TLS ULP not attached
    const result = setKtlsTx(sock, &dummy_crypto);
    try std.testing.expect(result == false);
}

test "setKtlsRx returns false without TLS ULP attached" {
    if (builtin.os.tag != .linux) return;

    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(sock);

    // Dummy crypto_info
    const dummy_crypto: [40]u8 = .{0} ** 40;

    // Should fail since TLS ULP not attached
    const result = setKtlsRx(sock, &dummy_crypto);
    try std.testing.expect(result == false);
}
