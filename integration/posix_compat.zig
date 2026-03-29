const std = @import("std");
const c = std.c;

/// Re-exports the standard library POSIX address family namespace.
/// Use this alias for socket address family constants such as IPv4 and IPv6.
/// Behavior and availability follow `std.posix.AF` on the target platform.
pub const AF = std.posix.AF;
/// Re-exports the standard library POSIX IP protocol namespace.
/// Use this alias for protocol constants passed to socket and networking APIs.
/// Behavior and availability follow `std.posix.IPPROTO` on the target platform.
pub const IPPROTO = std.posix.IPPROTO;
/// Re-exports the standard library POSIX signal namespace.
/// Use this alias for signal numbers, signal sets, and related platform-specific values.
/// Behavior and availability follow `std.posix.SIG` on the target platform.
pub const SIG = std.posix.SIG;
/// Alias for `std.posix.SO`, the socket option namespace.
/// Use these constants with socket option setters and getters.
/// They map to the standard POSIX socket-option names for the target platform.
pub const SO = std.posix.SO;
/// Alias for `std.posix.SOCK`, the socket type and flag namespace.
/// Use these constants when creating sockets or configuring socket behavior.
/// The available values depend on the target platform.
pub const SOCK = std.posix.SOCK;
/// Alias for `std.posix.SOL`, the socket option level namespace.
/// Use these constants when selecting the protocol level for socket options.
/// The exact values are supplied by the standard library platform bindings.
pub const SOL = std.posix.SOL;
/// Alias for `std.posix.STDERR_FILENO`.
/// Identifies the standard error file descriptor.
/// Use it when writing diagnostic or error output.
pub const STDERR_FILENO = std.posix.STDERR_FILENO;
/// Alias for `std.posix.STDIN_FILENO`.
/// Identifies the standard input file descriptor.
/// Use it when reading from the process's conventional input stream.
pub const STDIN_FILENO = std.posix.STDIN_FILENO;
/// Alias for `std.posix.STDOUT_FILENO`.
/// Identifies the standard output file descriptor.
/// Use it when writing to the process's conventional output stream.
pub const STDOUT_FILENO = std.posix.STDOUT_FILENO;
/// Alias for `std.posix.W`, the POSIX wait-status helpers namespace.
/// Use these helpers to inspect process status values returned by wait-related calls.
/// The available predicates and accessors are defined by the standard library.
pub const W = std.posix.W;
/// Alias for `std.posix.sockaddr`.
/// Use this storage type when working with generic socket addresses.
/// Concrete address families still need to be interpreted according to the active protocol.
pub const sockaddr = std.posix.sockaddr;
/// Alias for `std.posix.timeval`.
/// Use this structure for second-and-microsecond timeout or timestamp values in POSIX APIs.
/// Field layout and precision follow the standard library definition.
pub const timeval = std.posix.timeval;
/// Alias for `std.posix.pid_t`.
/// Use this type for process identifiers returned by or passed to POSIX process APIs.
/// The underlying representation is platform-defined.
pub const pid_t = std.posix.pid_t;
/// Alias for `std.posix.mode_t`.
/// This type represents permission and mode bits for POSIX filesystem operations.
/// Its width and signedness are platform-specific.
pub const mode_t = std.posix.mode_t;
/// Alias for `std.posix.O`, the POSIX open flags namespace.
/// Use these flags when constructing file open options for compatible system calls.
/// The exact flag set is platform-defined by the standard library.
pub const O = std.posix.O;
/// Alias for `std.posix.fd_t`.
/// This is the file-descriptor type used by the POSIX compatibility layer.
/// Prefer this alias when a function or field stores a raw descriptor.
pub const fd_t = std.posix.fd_t;
/// Alias for `std.posix.socket_t`.
/// Use this type for socket handles on platforms where `std.posix` defines one.
/// It exists here to keep integration code aligned with the standard POSIX API surface.
pub const socket_t = std.posix.socket_t;
/// Alias for `std.posix.socklen_t`.
/// Use this type when passing socket-length values to POSIX APIs.
/// It preserves the platform-specific width used by the standard library.
pub const socklen_t = std.posix.socklen_t;

/// Closes a Linux file descriptor.
///
/// The descriptor must be non-negative; this function asserts that precondition.
/// The underlying syscall result is ignored, so no error is reported to the caller.
pub fn close(fd: fd_t) void {
    std.debug.assert(fd >= 0);
    _ = std.os.linux.close(fd);
}

/// Sends `sig` to the process or process group identified by `pid`.
/// This is a direct alias of `std.posix.kill`.
/// Errors follow the standard library implementation for the current target.
pub const kill = std.posix.kill;
/// Reads bytes from `fd` into `buf`.
/// Returns the number of bytes copied, which may be smaller than `buf.len`.
/// This is a direct alias of `std.posix.read` and uses its error set and blocking behavior.
pub const read = std.posix.read;
/// Sets an option on the socket `sockfd`.
/// This is a direct alias of `std.posix.setsockopt`.
/// Errors and option encoding rules are the same as the standard library API.
pub const setsockopt = std.posix.setsockopt;

/// Result returned by `waitpid`.
/// Uses `std.posix.WaitPidResult` when available.
/// The fallback definition stores the child `pid` and raw wait `status` as `u32`.
pub const WaitPidResult = if (@hasDecl(std.posix, "WaitPidResult"))
    std.posix.WaitPidResult
else
    struct {
        pid: pid_t,
        status: u32,
    };

/// Opens `file_path` with the supplied flags and mode.
/// Returns a file descriptor owned by the caller; the compatibility path forwards to `openat(FDCWD, ...)`.
/// Errors are reported by the underlying `std.posix.open` or `openat` implementation.
pub const open = if (@hasDecl(std.posix, "open")) std.posix.open else open_compat;

fn open_compat(file_path: []const u8, flags: O, mode: mode_t) anyerror!fd_t {
    return std.posix.openat(std.posix.AT.FDCWD, file_path, flags, mode);
}

/// Creates a new process by forking the current one.
/// Returns `0` in the child and the child's pid in the parent.
/// The fallback retries `INTR` and returns `ForkFailed` for other errors.
pub const fork = if (@hasDecl(std.posix, "fork")) std.posix.fork else fork_compat;

fn fork_compat() anyerror!pid_t {
    while (true) {
        const rc = c.fork();
        switch (c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return error.ForkFailed,
        }
    }
}

/// Waits for state changes in the child process identified by `pid`.
/// Returns a `WaitPidResult` whose fields mirror the platform's wait-status encoding.
/// The fallback retries `INTR` and, if the OS call fails unexpectedly, returns the requested `pid` with `status = 0`.
pub const waitpid = if (@hasDecl(std.posix, "waitpid")) std.posix.waitpid else waitpid_compat;

fn waitpid_compat(pid: pid_t, flags: u32) WaitPidResult {
    var status: c_int = 0;

    while (true) {
        const rc = c.waitpid(pid, &status, @intCast(flags));
        switch (c.errno(rc)) {
            .SUCCESS => return .{
                .pid = @intCast(rc),
                .status = @bitCast(status),
            },
            .INTR => continue,
            else => return .{
                .pid = pid,
                .status = 0,
            },
        }
    }
}

/// Creates a unidirectional pipe and returns the read and write descriptors.
/// The returned descriptors are owned by the caller and must be closed when no longer needed.
/// The fallback retries `INTR` and returns `PipeFailed` for other errors.
pub const pipe = if (@hasDecl(std.posix, "pipe")) std.posix.pipe else pipe_compat;

fn pipe_compat() anyerror![2]fd_t {
    var fds: [2]fd_t = undefined;

    while (true) {
        const rc = c.pipe(&fds);
        switch (c.errno(rc)) {
            .SUCCESS => return fds,
            .INTR => continue,
            else => return error.PipeFailed,
        }
    }
}

/// Duplicates `old_fd` onto `new_fd`.
/// On success the resulting descriptor refers to the same open file description as `old_fd`.
/// The fallback retries `INTR` and returns `Dup2Failed` for other errors.
pub const dup2 = if (@hasDecl(std.posix, "dup2")) std.posix.dup2 else dup2_compat;

fn dup2_compat(old_fd: fd_t, new_fd: fd_t) anyerror!void {
    while (true) {
        const rc = c.dup2(old_fd, new_fd);
        switch (c.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => return error.Dup2Failed,
        }
    }
}

/// Creates a socket for the requested domain, type, and protocol.
/// On success this returns a new socket descriptor owned by the caller.
/// The fallback retries `INTR`, logs unexpected failures, and returns `SocketFailed` on error.
pub const socket = if (@hasDecl(std.posix, "socket")) std.posix.socket else socket_compat;

fn socket_compat(domain: u32, sock_type: u32, protocol: u32) anyerror!socket_t {
    while (true) {
        const rc = c.socket(@intCast(domain), @intCast(sock_type), @intCast(protocol));
        switch (c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => |errno_value| {
                std.log.err(
                    "posix_compat.socket_compat failed: domain={d} type={d} proto={d} errno={s}",
                    .{ domain, sock_type, protocol, @tagName(errno_value) },
                );
                return error.SocketFailed;
            },
        }
    }
}

/// Initiates a connection on `sockfd` to `sock_addr`.
/// `sock_addr` must point to a valid socket address with length `addrlen` for the duration of the call.
/// The fallback retries interruptions, returns `WouldBlock` for `AGAIN`, and `ConnectFailed` otherwise.
pub const connect = if (@hasDecl(std.posix, "connect")) std.posix.connect else connect_compat;

fn connect_compat(sockfd: socket_t, sock_addr: *const sockaddr, addrlen: socklen_t) anyerror!void {
    while (true) {
        const rc = c.connect(sockfd, @ptrCast(sock_addr), addrlen);
        switch (c.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.ConnectFailed,
        }
    }
}

/// Sends the contents of `buf` on `sockfd`.
/// The call may accept fewer bytes than requested, so callers must handle partial sends.
/// The fallback retries interrupted syscalls and returns `WouldBlock` or `SendFailed` on error.
pub const send = if (@hasDecl(std.posix, "send")) std.posix.send else send_compat;

fn send_compat(sockfd: socket_t, buf: []const u8, flags: u32) anyerror!usize {
    while (true) {
        const rc = c.send(sockfd, buf.ptr, buf.len, flags);
        switch (c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.SendFailed,
        }
    }
}

/// Receives data from `sockfd` into `buf`.
/// The call may return fewer bytes than requested, and the fallback retries interrupted syscalls.
/// The fallback returns `WouldBlock` for `AGAIN` and `RecvFailed` for other OS errors.
pub const recv = if (@hasDecl(std.posix, "recv")) std.posix.recv else recv_compat;

fn recv_compat(sockfd: socket_t, buf: []u8, flags: u32) anyerror!usize {
    while (true) {
        const rc = c.recv(sockfd, buf.ptr, buf.len, @intCast(flags));
        switch (c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.RecvFailed,
        }
    }
}

/// Replaces the current process image with `file` using the provided argv/envp vectors.
/// On success this function does not return; the caller's address space is replaced by the new program.
/// The fallback maps common errno values to `AccessDenied`, `FileNotFound`, `SystemResources`, or `ExecFailed`.
/// `file`, `argv`, and `envp` must remain valid and zero-terminated for the duration of the call.
pub const execvpeZ = if (@hasDecl(std.posix, "execvpeZ")) std.posix.execvpeZ else execvpe_z_compat;

extern "c" fn execvpe(
    file: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) c_int;

fn execvpe_z_compat(
    file: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) anyerror!noreturn {
    while (true) {
        const rc = execvpe(file, argv, envp);
        switch (c.errno(rc)) {
            .SUCCESS => unreachable,
            .INTR => continue,
            .ACCES => return error.AccessDenied,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            else => return error.ExecFailed,
        }
    }
}

/// Sleeps the current thread for the requested interval.
/// Uses `std.posix.nanosleep` when available and a compatibility shim otherwise.
/// The fallback asserts that `nanoseconds` is less than one second.
pub const nanosleep = if (@hasDecl(std.posix, "nanosleep")) std.posix.nanosleep else nanosleep_compat;

fn nanosleep_compat(seconds: u64, nanoseconds: u64) void {
    std.debug.assert(nanoseconds < std.time.ns_per_s);

    var req = c.timespec{
        .sec = @intCast(seconds),
        .nsec = @intCast(nanoseconds),
    };
    var rem: c.timespec = undefined;

    while (true) {
        const rc = c.nanosleep(&req, &rem);
        switch (c.errno(rc)) {
            .SUCCESS => return,
            .INTR => {
                req = rem;
                continue;
            },
            else => return,
        }
    }
}

/// Returns the active process environment vector as a null-terminated array.
/// Prefers `std.os.environ` when available and falls back to `std.c.environ`.
/// The returned storage is owned by the runtime/C library; do not free it.
pub fn environPtr() [*:null]const ?[*:0]const u8 {
    if (@hasDecl(std.os, "environ")) {
        return @ptrCast(std.os.environ.ptr);
    }
    return @ptrCast(std.c.environ);
}
