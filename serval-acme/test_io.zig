//! Test-only POSIX I/O helpers for socket-backed ACME unit tests.

const std = @import("std");
const assert = std.debug.assert;
const c = std.c;
const posix = std.posix;

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

pub fn close_fd(fd: i32) void {
    assert(fd >= 0);
    assert(fd <= std.math.maxInt(c_int));
    _ = c.close(fd);
}

pub fn write_bytes(fd: i32, bytes: []const u8) bool {
    assert(fd >= 0);
    assert(bytes.len <= std.math.maxInt(isize));

    const written = c.write(fd, bytes.ptr, bytes.len);
    if (written < 0) return false;
    return written == @as(isize, @intCast(bytes.len));
}
