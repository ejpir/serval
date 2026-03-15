// serval-core/posix_compat.zig
//! POSIX Compatibility Layer
//!
//! Provides wrappers for POSIX functions that were removed from std.posix
//! in Zig 0.16.0-dev.2821+. These functions are thin wrappers around the
//! Linux syscall layer (std.os.linux) with Zig-idiomatic error handling.
//!
//! TigerStyle: Explicit wrappers, no hidden behavior, assertion on invalid fd.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");

const linux = std.os.linux;

/// Close a file descriptor.
///
/// This is a direct replacement for the removed std.posix.close().
/// Asserts the fd is valid (not negative). Ignores EINTR per POSIX semantics
/// (the fd is closed regardless of EINTR on Linux).
///
/// TigerStyle: Assertion on precondition, explicit behavior.
pub fn closeFd(fd: std.posix.fd_t) void {
    assert(fd >= 0); // S1: precondition - fd must be valid
    _ = linux.close(fd);
}

test "closeFd: closes a valid pipe fd" {
    var pipe_fds: [2]i32 = undefined;
    const rc = linux.pipe(&pipe_fds);
    if (linux.E.init(rc) != .SUCCESS) return error.PipeFailed;
    closeFd(pipe_fds[0]);
    closeFd(pipe_fds[1]);
}
