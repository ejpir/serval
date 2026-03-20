//! ACME certificate/key atomic persistence.
//!
//! Writes fullchain/key PEM files with tmp+fsync+rename protocol.

const std = @import("std");
const assert = std.debug.assert;
const c = std.c;
const Io = std.Io;

pub const Error = error{
    InvalidStateDir,
    InvalidCert,
    InvalidKey,
    PathTooLong,
    CreateDirFailed,
    WriteFailed,
    SyncFailed,
    RenameFailed,
};

pub const PersistedPaths = struct {
    cert_path: []const u8,
    key_path: []const u8,
};

pub fn persistCertificateAndKey(
    state_dir: []const u8,
    cert_pem: []const u8,
    key_pem: []const u8,
    cert_path_out: []u8,
    key_path_out: []u8,
) Error!PersistedPaths {
    assert(state_dir.len > 0);
    assert(cert_pem.len > 0);
    assert(key_pem.len > 0);

    if (state_dir.len == 0) return error.InvalidStateDir;
    if (cert_pem.len == 0) return error.InvalidCert;
    if (key_pem.len == 0) return error.InvalidKey;

    const io = std.Options.debug_io;

    var cert_dir_buf: [1024]u8 = undefined;
    const cert_dir = std.fmt.bufPrint(&cert_dir_buf, "{s}/cert/current", .{state_dir}) catch return error.PathTooLong;
    Io.Dir.cwd().createDirPath(io, cert_dir) catch return error.CreateDirFailed;

    const cert_path = std.fmt.bufPrint(cert_path_out, "{s}/fullchain.pem", .{cert_dir}) catch return error.PathTooLong;
    const key_path = std.fmt.bufPrint(key_path_out, "{s}/privkey.pem", .{cert_dir}) catch return error.PathTooLong;

    try writeAtomic(cert_path, cert_pem);
    try writeAtomic(key_path, key_pem);

    return .{ .cert_path = cert_path, .key_path = key_path };
}

fn writeAtomic(path: []const u8, data: []const u8) Error!void {
    assert(path.len > 0);
    assert(data.len > 0);

    var tmp_buf: [1200]u8 = undefined;
    const tmp_path = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path}) catch return error.PathTooLong;

    const io = std.Options.debug_io;
    var file = Io.Dir.cwd().createFile(io, tmp_path, .{ .truncate = true }) catch return error.WriteFailed;
    defer file.close(io);

    var write_buf: [4096]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    writer.interface.writeAll(data) catch return error.WriteFailed;
    writer.interface.flush() catch return error.WriteFailed;
    file.sync(io) catch return error.SyncFailed;

    Io.Dir.cwd().rename(tmp_path, Io.Dir.cwd(), path, io) catch return error.RenameFailed;
    fsyncParent(path);
}

fn fsyncParent(path: []const u8) void {
    assert(path.len > 0);
    assert(path.len <= 1200);
    const parent_path = std.fs.path.dirname(path) orelse return;
    const io = std.Options.debug_io;
    var dir = Io.Dir.cwd().openDir(io, parent_path, .{}) catch |err| {
        std.log.warn("acme-storage: open parent for fsync failed path={s} err={s}", .{ parent_path, @errorName(err) });
        return;
    };
    defer dir.close(io);

    if (c.fsync(dir.handle) != 0) {
        std.log.warn("acme-storage: fsync parent failed path={s}", .{parent_path});
    }
}

test "persistCertificateAndKey writes files under cert/current" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var state_buf: [1200]u8 = undefined;
    const state_path = try std.fmt.bufPrint(&state_buf, "{s}/state", .{tmp.sub_path[0..]});

    var cert_path_buf: [1024]u8 = undefined;
    var key_path_buf: [1024]u8 = undefined;

    const persisted = try persistCertificateAndKey(
        state_path,
        "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
        "-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----\n",
        &cert_path_buf,
        &key_path_buf,
    );

    var cert_read_buf: [256]u8 = undefined;
    const cert_read = try Io.Dir.cwd().readFile(std.Options.debug_io, persisted.cert_path, &cert_read_buf);
    try std.testing.expect(std.mem.indexOf(u8, cert_read, "BEGIN CERTIFICATE") != null);
}
