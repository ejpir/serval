//! Test-only POSIX I/O helpers for socket-backed ACME unit tests.

const std = @import("std");
const assert = std.debug.assert;
const c = std.c;
const posix = std.posix;

/// Creates a connected UNIX stream socket pair.
/// Returns both file descriptors on success, or `null` if `socketpair` fails.
/// The caller owns both descriptors and must close them when finished.
/// The function asserts the UNIX and stream socket constants are valid before calling into C.
pub fn create_socket_pair() ?[2]i32 {
    assert(posix.AF.UNIX > 0);
    assert(posix.SOCK.STREAM > 0);

    var fds: [2]i32 = undefined;
    const rc = c.socketpair(
        @intCast(posix.AF.UNIX),
        @intCast(posix.SOCK.STREAM),
        0,
        &fds,
    );
    if (rc != 0) return null;
    return fds;
}

/// Closes `fd` with `c.close` and ignores the return value.
/// This helper does not report close failures to the caller.
/// `fd` must be a non-negative descriptor that fits in `c_int`.
pub fn close_fd(fd: i32) void {
    assert(fd >= 0);
    assert(fd <= std.math.maxInt(c_int));
    _ = c.close(fd);
}

/// Writes the entire `bytes` slice to `fd` using `c.write`.
/// Returns `true` only when the call succeeds and the kernel reports that all bytes were written.
/// Returns `false` on any write error or short write.
/// `fd` must be a non-negative file descriptor, and `bytes.len` must fit in `isize`.
pub fn write_bytes(fd: i32, bytes: []const u8) bool {
    assert(fd >= 0);
    assert(bytes.len <= std.math.maxInt(isize));

    const written = c.write(fd, bytes.ptr, bytes.len);
    if (written < 0) return false;
    return written == @as(isize, @intCast(bytes.len));
}
