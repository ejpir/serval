const std = @import("std");
const c = std.c;

pub const AF = std.posix.AF;
pub const IPPROTO = std.posix.IPPROTO;
pub const SIG = std.posix.SIG;
pub const SO = std.posix.SO;
pub const SOCK = std.posix.SOCK;
pub const SOL = std.posix.SOL;
pub const STDERR_FILENO = std.posix.STDERR_FILENO;
pub const STDIN_FILENO = std.posix.STDIN_FILENO;
pub const STDOUT_FILENO = std.posix.STDOUT_FILENO;
pub const W = std.posix.W;
pub const sockaddr = std.posix.sockaddr;
pub const timeval = std.posix.timeval;
pub const pid_t = std.posix.pid_t;
pub const mode_t = std.posix.mode_t;
pub const O = std.posix.O;
pub const fd_t = std.posix.fd_t;
pub const socket_t = std.posix.socket_t;
pub const socklen_t = std.posix.socklen_t;

pub const close = std.posix.close;
pub const kill = std.posix.kill;
pub const read = std.posix.read;
pub const setsockopt = std.posix.setsockopt;

pub const WaitPidResult = if (@hasDecl(std.posix, "WaitPidResult"))
    std.posix.WaitPidResult
else
    struct {
        pid: pid_t,
        status: u32,
    };

pub const open = if (@hasDecl(std.posix, "open")) std.posix.open else open_compat;

fn open_compat(file_path: []const u8, flags: O, mode: mode_t) anyerror!fd_t {
    return std.posix.openat(std.posix.AT.FDCWD, file_path, flags, mode);
}

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

pub const socket = if (@hasDecl(std.posix, "socket")) std.posix.socket else socket_compat;

fn socket_compat(domain: u32, sock_type: u32, protocol: u32) anyerror!socket_t {
    while (true) {
        const rc = c.socket(@intCast(domain), @intCast(sock_type), @intCast(protocol));
        switch (c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return error.SocketFailed,
        }
    }
}

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

pub fn environPtr() [*:null]const ?[*:0]const u8 {
    if (@hasDecl(std.os, "environ")) {
        return @ptrCast(std.os.environ.ptr);
    }
    return @ptrCast(std.c.environ);
}
