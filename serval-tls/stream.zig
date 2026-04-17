// lib/serval-tls/stream.zig
//! TLS stream abstraction
//!
//! Provides unified interface for TLS I/O operations with two modes:
//! - Userspace mode: TLS via BoringSSL SSL object (default after handshake)
//! - kTLS mode: Kernel TLS offload for symmetric crypto (upgrade from userspace)
//!
//! This module keeps TLS sockets non-blocking and layers explicit readiness
//! waits plus bounded handshake/I/O timeouts on top of OpenSSL/BoringSSL.
//! - initServer/initClient: timed TLS handshakes for server/client use
//! - read/write: low-level non-blocking TLS primitives
//! - readBounded/writeBounded: timeout-enforcing TLS I/O helpers
//! - close: Graceful TLS shutdown

const std = @import("std");
const serval_core = @import("serval-core");
const log = serval_core.log.scoped(.tls);
const closeFd = serval_core.closeFd;
const config = serval_core.config;
const time = serval_core.time;
const assert = std.debug.assert;
const posix = std.posix;
const ssl = @import("ssl.zig");
const ktls = @import("ktls.zig");
const handshake_info = @import("handshake_info.zig");
const Allocator = std.mem.Allocator;

/// Alias of `handshake_info.HandshakeInfo`, used by `TLSStream` to carry completed-handshake metadata.
/// Pure type alias: fields, methods, and invariants are exactly those defined in `handshake_info.zig`.
/// Values are plain struct data with fixed-size internal buffers and no heap ownership transfer.
/// Declaring or referencing this alias has no runtime side effects and no error behavior.
pub const HandshakeInfo = handshake_info.HandshakeInfo;

/// TLS operation mode.
/// TigerStyle: Tagged union for explicit mode handling (no default cases).
pub const Mode = union(enum) {
    /// Kernel TLS offload - read/write go directly to kernel.
    /// After kTLS setup, symmetric crypto is handled by the kernel.
    ktls: void,
    /// Userspace TLS via BoringSSL SSL object.
    /// All TLS operations go through the SSL library.
    userspace: *ssl.SSL,
};

/// Get monotonic timestamp in nanoseconds for timing measurements.
/// TigerStyle: Centralize clock access through serval-core.time.
const default_tls_cfg = config.TlsConfig{};
const default_tls_handshake_timeout_ns: u64 = default_tls_cfg.handshake_timeout_ns;
const default_tls_io_timeout_ns: u64 = default_tls_cfg.io_timeout_ns;
const tls_handshake_max_iterations: u32 = 4096;
const tls_io_max_iterations: u32 = 131_072;

const ReadinessDirection = enum {
    read,
    write,
};

/// Result of one non-blocking TLS read attempt.
/// `.need_read`/`.need_write` signal readiness direction without throwing.
pub const ReadStep = union(enum) {
    bytes: u32,
    closed,
    need_read,
    need_write,
};

/// Result of one non-blocking TLS write attempt.
/// `.need_read`/`.need_write` signal readiness direction without throwing.
pub const WriteStep = union(enum) {
    bytes: u32,
    closed,
    need_read,
    need_write,
};

/// Terminal errors for `readStep` (excludes retry/backpressure states).
pub const ReadStepError = error{
    ConnectionReset,
    KtlsRead,
    SslRead,
};

/// Terminal errors for `writeStep` (excludes retry/backpressure states).
pub const WriteStepError = error{
    ConnectionReset,
    KtlsWrite,
    SslWrite,
};

const WaitForReadyError = error{
    Timeout,
    ConnectionReset,
    ReadinessWaitFailed,
};

fn monotonicNanos() u64 {
    const now_ns = time.monotonicNanos();
    assert(now_ns > 0);
    return now_ns;
}

/// Represents an established TLS stream on `fd`, with runtime state for either userspace TLS or manual kTLS I/O.
/// `mode` selects backend behavior: `.userspace` carries an OpenSSL connection, while `.ktls` uses direct fd-based kernel offload semantics.
/// `info` holds handshake-derived metadata (including cached kTLS enablement) used for fast status checks without extra work.
/// Introspection methods on this type are non-throwing and return conservative fallbacks (`false`/`null`) when backend state is not available.
pub const TLSStream = struct {
    fd: c_int,
    mode: Mode,
    allocator: Allocator,
    io_timeout_ns: u64,
    info: HandshakeInfo,

    /// Check if stream is using kTLS (kernel TLS offload).
    /// Uses cached value from handshake - zero overhead.
    pub fn isKtls(self: *const TLSStream) bool {
        return self.info.ktls_enabled;
    }

    /// Check if stream is using manual kTLS mode (direct fd I/O).
    /// This mode is only used with BoringSSL where we extract keys manually.
    pub fn isManualKtls(self: *const TLSStream) bool {
        return self.mode == .ktls;
    }

    /// Query current kTLS status from OpenSSL BIO layer (for diagnostics).
    /// Slightly more overhead than isKtls() - use sparingly in hot paths.
    pub fn queryKtlsStatus(self: *const TLSStream) struct { tx: bool, rx: bool, manual: bool } {
        return switch (self.mode) {
            .ktls => .{ .tx = true, .rx = true, .manual = true },
            .userspace => |ssl_conn| .{
                .tx = if (ssl.SSL_get_wbio(ssl_conn)) |wbio| ssl.BIO_get_ktls_send(wbio) else false,
                .rx = if (ssl.SSL_get_rbio(ssl_conn)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false,
                .manual = false,
            },
        };
    }

    /// Returns true if the TLS library has decrypted plaintext buffered.
    /// When true, a subsequent `read()` will return data immediately even if
    /// the underlying fd would not be poll-readable.
    /// TigerStyle: Required for correct poll-based multiplexing on TLS sockets.
    pub fn hasPendingRead(self: *const TLSStream) bool {
        return switch (self.mode) {
            .ktls => false,
            .userspace => |ssl_conn| blk: {
                const pending = ssl.SSL_pending(ssl_conn);
                break :blk pending > 0;
            },
        };
    }

    /// Get underlying SSL object for userspace mode, null for kTLS.
    /// Useful for advanced operations (session tickets, renegotiation).
    pub fn getSSL(self: *TLSStream) ?*ssl.SSL {
        return switch (self.mode) {
            .ktls => null,
            .userspace => |ssl_conn| ssl_conn,
        };
    }

    /// Check native kTLS status after successful handshake.
    /// OpenSSL handles kernel TLS setup internally when SSL_OP_ENABLE_KTLS is set.
    /// Returns userspace mode always; OpenSSL BIO transparently uses kTLS when active.
    fn setupKtlsAfterHandshake(ssl_conn: *ssl.SSL, info: *HandshakeInfo, enable_ktls: bool) Mode {
        if (!enable_ktls) {
            info.ktls_enabled = false;
            return .{ .userspace = ssl_conn };
        }

        const tx_ktls = if (ssl.SSL_get_wbio(ssl_conn)) |wbio| ssl.BIO_get_ktls_send(wbio) else false;
        const rx_ktls = if (ssl.SSL_get_rbio(ssl_conn)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false;
        info.ktls_enabled = tx_ktls or rx_ktls;
        return .{ .userspace = ssl_conn };
    }

    /// Log kTLS status after handshake.
    fn logKtlsStatus(info: *const HandshakeInfo, is_server: bool) void {
        const role = if (is_server) "server" else "client";
        const ktls_status = if (info.ktls_enabled) "enabled" else "disabled";
        log.info("TLS handshake ({s}): ktls={s}, cipher={s}", .{ role, ktls_status, info.cipher() });
    }

    /// Initializes a server-side `TLSStream` and performs the handshake using default timeouts.
    /// Preconditions: `ctx` and `fd` must be valid borrowed handles; caller retains fd ownership.
    /// On success returns an initialized stream with handshake metadata populated and optional kTLS
    /// state detected; caller must eventually call `close()` to free SSL resources.
    /// Returns handshake/setup errors (for example `SslNew`, `SslSetFd`, timeout/readiness failures)
    /// from the underlying initialization path.
    pub fn initServer(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        allocator: Allocator,
    ) !TLSStream {
        return initServerWithTimeouts(
            ctx,
            fd,
            default_tls_handshake_timeout_ns,
            default_tls_io_timeout_ns,
            allocator,
        );
    }

    /// Initializes a server-side `TLSStream` with explicit handshake and I/O timeout bounds.
    /// Preconditions: valid non-null `ctx`, `fd > 0`, and both timeout values > 0.
    /// `ctx` is borrowed (not owned), and caller keeps fd ownership/responsibility for fd close.
    /// Returns setup/handshake errors when TLS state cannot be created, configured, or completed
    /// within the provided timeout bounds.
    pub fn initServerWithTimeouts(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        handshake_timeout_ns: u64,
        io_timeout_ns: u64,
        allocator: Allocator,
    ) !TLSStream {
        assert(@intFromPtr(ctx) != 0);
        assert(fd > 0);
        assert(handshake_timeout_ns > 0);
        assert(io_timeout_ns > 0);

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        try setNonblocking(fd);
        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        const enable_ktls: bool = ktls.isKtlsRuntimeAvailable();
        if (enable_ktls) {
            _ = ssl.SSL_set_options(ssl_conn, ssl.SSL_OP_ENABLE_KTLS);
        }
        ssl.SSL_set_accept_state(ssl_conn);

        const start_ns: u64 = monotonicNanos();
        try doHandshake(ssl_conn, fd, handshake_timeout_ns);
        const end_ns: u64 = monotonicNanos();
        assert(end_ns >= start_ns);
        assert(ssl.SSL_is_init_finished(ssl_conn) == 1);

        var info = HandshakeInfo{};
        info.client_mode = false;
        info.handshake_duration_ns = @intCast(end_ns - start_ns);
        populateHandshakeInfo(ssl_conn, &info);

        const mode = setupKtlsAfterHandshake(ssl_conn, &info, enable_ktls);
        logKtlsStatus(&info, true);

        return .{
            .fd = fd,
            .mode = mode,
            .allocator = allocator,
            .io_timeout_ns = io_timeout_ns,
            .info = info,
        };
    }

    /// Initializes a client-side `TLSStream` (upstream origination) using default timeout bounds.
    /// Preconditions: valid `ctx`, `fd`, and null-terminated borrowed `sni_z`.
    /// `ctx`/`sni_z` are borrowed inputs and are not owned by the returned stream; caller still owns fd.
    /// Returns setup/handshake errors (including SNI/ALPN configuration and timeout/readiness failures).
    pub fn initClient(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        sni_z: [*:0]const u8,
        allocator: Allocator,
        enable_ktls: bool,
        desired_alpn: ?[]const u8,
        verify_peer: bool,
    ) !TLSStream {
        return initClientWithTimeouts(
            ctx,
            fd,
            sni_z,
            default_tls_handshake_timeout_ns,
            default_tls_io_timeout_ns,
            allocator,
            enable_ktls,
            desired_alpn,
            verify_peer,
        );
    }

    /// Initializes a client-side `TLSStream` with explicit handshake and I/O timeout bounds.
    /// Preconditions: valid non-null `ctx`, `fd > 0`, null-terminated borrowed `sni_z`, and timeout
    /// values > 0.
    /// Uses borrowed context/SNI inputs and does not assume ownership of fd; caller manages fd lifetime.
    /// Returns setup/handshake errors for SSL creation, fd binding, SNI/ALPN setup, verification, and
    /// timeout/readiness failures.
    pub fn initClientWithTimeouts(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        sni_z: [*:0]const u8,
        handshake_timeout_ns: u64,
        io_timeout_ns: u64,
        allocator: Allocator,
        enable_ktls: bool,
        desired_alpn: ?[]const u8,
        verify_peer: bool,
    ) !TLSStream {
        assert(@intFromPtr(ctx) != 0);
        assert(fd > 0);
        assert(handshake_timeout_ns > 0);
        assert(io_timeout_ns > 0);

        const ssl_conn = ssl.SSL_new(ctx) orelse return error.SslNew;
        errdefer ssl.SSL_free(ssl_conn);

        try setNonblocking(fd);
        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        const should_enable_ktls: bool = enable_ktls and ktls.isKtlsRuntimeAvailable();
        if (should_enable_ktls) {
            _ = ssl.SSL_set_options(ssl_conn, ssl.SSL_OP_ENABLE_KTLS);
        }
        if (ssl.SSL_set_tlsext_host_name(ssl_conn, sni_z) != 1) return error.SslSetSni;

        if (desired_alpn) |protocol| {
            try ssl.setClientAlpnProtocol(ssl_conn, protocol);
        }

        if (verify_peer) {
            ssl.SSL_set_verify(ssl_conn, ssl.SSL_VERIFY_PEER, null);
        } else {
            ssl.SSL_set_verify(ssl_conn, ssl.SSL_VERIFY_NONE, null);
        }
        ssl.SSL_set_connect_state(ssl_conn);

        const start_ns: u64 = monotonicNanos();
        try doHandshake(ssl_conn, fd, handshake_timeout_ns);
        const end_ns: u64 = monotonicNanos();
        assert(end_ns >= start_ns);
        assert(ssl.SSL_is_init_finished(ssl_conn) == 1);

        var info = HandshakeInfo{};
        info.client_mode = true;
        info.handshake_duration_ns = @intCast(end_ns - start_ns);
        populateHandshakeInfo(ssl_conn, &info);

        const mode: Mode = if (should_enable_ktls) blk: {
            const m = setupKtlsAfterHandshake(ssl_conn, &info, true);
            logKtlsStatus(&info, false);
            break :blk m;
        } else .{ .userspace = ssl_conn };

        if (!should_enable_ktls) {
            info.ktls_enabled = false;
            logKtlsStatus(&info, false);
        }

        return .{
            .fd = fd,
            .mode = mode,
            .allocator = allocator,
            .io_timeout_ns = io_timeout_ns,
            .info = info,
        };
    }

    /// Execute exactly one non-blocking TLS read step without readiness waits.
    ///
    /// Contract: `buf` must be non-empty and `self.fd` must reference an open,
    /// non-blocking stream.
    /// Ownership/lifetime: caller retains ownership of `self` and `buf`; both
    /// must remain valid for the full duration of the call.
    /// Failure semantics: returns `ReadStepError` on terminal TLS/fd failures;
    /// backpressure is represented as `.need_read` / `.need_write` instead of
    /// error unions.
    pub fn readStep(self: *TLSStream, buf: []u8) ReadStepError!ReadStep {
        assert(buf.len > 0);
        assert(self.fd > 0);

        return switch (self.mode) {
            .ktls => blk: {
                const n = posix.read(self.fd, buf) catch |err| switch (err) {
                    error.WouldBlock => break :blk .need_read,
                    error.ConnectionResetByPeer => return error.ConnectionReset,
                    else => return error.KtlsRead,
                };
                if (n == 0) break :blk .closed;
                const bytes_read: u32 = @intCast(n);
                assert(bytes_read <= buf.len);
                break :blk .{ .bytes = bytes_read };
            },
            .userspace => |ssl_conn| blk: {
                const n = ssl.SSL_read(ssl_conn, buf.ptr, @intCast(buf.len));
                if (n <= 0) {
                    const err = ssl.SSL_get_error(ssl_conn, n);
                    switch (err) {
                        ssl.SSL_ERROR_ZERO_RETURN => {
                            log.info(
                                "TLS read closed: reason=close_notify fd={d} cipher={s}",
                                .{ self.fd, self.info.cipher() },
                            );
                            break :blk .closed;
                        },
                        ssl.SSL_ERROR_WANT_READ => break :blk .need_read,
                        ssl.SSL_ERROR_WANT_WRITE => break :blk .need_write,
                        ssl.SSL_ERROR_SYSCALL => {
                            log.warn(
                                "TLS read failed: reason=peer_reset fd={d} cipher={s} ssl_error={s} ret={d}",
                                .{ self.fd, self.info.cipher(), ssl.sslErrorName(err), n },
                            );
                            ssl.printErrors();
                            return error.ConnectionReset;
                        },
                        ssl.SSL_ERROR_SSL => {
                            log.warn(
                                "TLS read failed: reason=tls_protocol fd={d} cipher={s} ssl_error={s} ret={d}",
                                .{ self.fd, self.info.cipher(), ssl.sslErrorName(err), n },
                            );
                            ssl.printErrors();
                            return error.SslRead;
                        },
                        else => {
                            log.warn(
                                "TLS read failed: reason=ssl_unexpected fd={d} cipher={s} ssl_error={s} ret={d}",
                                .{ self.fd, self.info.cipher(), ssl.sslErrorName(err), n },
                            );
                            ssl.printErrors();
                            return error.SslRead;
                        },
                    }
                }

                const bytes_read: u32 = @intCast(n);
                assert(bytes_read <= buf.len);
                break :blk .{ .bytes = bytes_read };
            },
        };
    }

    /// Non-blocking TLS read primitive.
    ///
    /// Contract: `buf` must be non-empty and `self.fd` must reference a live
    /// TLS stream.
    /// Ownership/lifetime: caller retains ownership of `self` and `buf`.
    /// Failure semantics: returns `error.WantRead`/`error.WantWrite` for
    /// backpressure and terminal TLS/fd read failures for unrecoverable states.
    /// Returns number of bytes read, or 0 on clean shutdown.
    pub fn read(self: *TLSStream, buf: []u8) !u32 {
        assert(buf.len > 0);
        assert(self.fd > 0);

        const step = self.readStep(buf) catch |err| return err;
        return switch (step) {
            .bytes => |n| n,
            .closed => 0,
            .need_read => error.WantRead,
            .need_write => error.WantWrite,
        };
    }

    /// Reads TLS application bytes using the stream's configured I/O timeout.
    /// Preconditions: `self.io_timeout_ns > 0`; `buf` is caller-owned output storage.
    /// `self` is borrowed and remains owned by the caller.
    /// Returns read-related TLS/socket errors (including timeout/reset/want-read-want-write mapping)
    /// from `readWithTimeout`.
    pub fn readBounded(self: *TLSStream, buf: []u8) !u32 {
        assert(self.io_timeout_ns > 0);
        return self.readWithTimeout(buf, self.io_timeout_ns);
    }

    /// Reads TLS application bytes with an explicit timeout budget in nanoseconds.
    ///
    /// Contract: `buf.len > 0`, `fd > 0`, and `timeout_ns > 0`.
    /// Ownership/lifetime: `buf` and `self` stay caller-owned; no ownership
    /// transfer occurs.
    /// Failure semantics: returns `error.Timeout` when deadline budget expires,
    /// `error.ConnectionReset` for reset paths, and mode-specific read failures
    /// (`error.SslRead`/`error.KtlsRead`) for terminal TLS/fd errors.
    pub fn readWithTimeout(self: *TLSStream, buf: []u8, timeout_ns: u64) !u32 {
        assert(buf.len > 0);
        assert(self.fd > 0);
        assert(timeout_ns > 0);

        const readiness_wait_failed = switch (self.mode) {
            .ktls => error.KtlsRead,
            .userspace => error.SslRead,
        };
        const deadline_ns = deadlineFromTimeout(timeout_ns);
        var iterations: u32 = 0;
        while (iterations < tls_io_max_iterations) : (iterations += 1) {
            const step = self.readStep(buf) catch |err| return err;
            switch (step) {
                .bytes => |n| {
                    assert(n <= buf.len);
                    return n;
                },
                .closed => return 0,
                .need_read => {
                    waitForReady(self.fd, .read, deadline_ns) catch |wait_err| switch (wait_err) {
                        error.Timeout => return error.Timeout,
                        error.ConnectionReset => return error.ConnectionReset,
                        error.ReadinessWaitFailed => return readiness_wait_failed,
                    };
                },
                .need_write => {
                    waitForReady(self.fd, .write, deadline_ns) catch |wait_err| switch (wait_err) {
                        error.Timeout => return error.Timeout,
                        error.ConnectionReset => return error.ConnectionReset,
                        error.ReadinessWaitFailed => return readiness_wait_failed,
                    };
                },
            }
        }

        return error.Timeout;
    }

    /// Execute exactly one non-blocking TLS write step without readiness waits.
    ///
    /// Contract: `data` must be non-empty and `self.fd` must reference a live
    /// non-blocking TLS stream.
    /// Ownership/lifetime: caller retains ownership of `self` and `data`; both
    /// must remain valid for the full call duration.
    /// Failure semantics: returns `WriteStepError` for terminal TLS/fd failures;
    /// caller-facing backpressure is represented by `.need_read`/`.need_write`.
    pub fn writeStep(self: *TLSStream, data: []const u8) WriteStepError!WriteStep {
        assert(data.len > 0);
        assert(self.fd > 0);

        return switch (self.mode) {
            .ktls => blk: {
                const file: std.Io.File = .{
                    .handle = self.fd,
                    .flags = .{ .nonblocking = true },
                };
                const n = file.writeStreaming(std.Options.debug_io, &.{}, &.{data}, 1) catch |err| switch (err) {
                    error.BrokenPipe => return error.ConnectionReset,
                    error.WouldBlock => break :blk .need_write,
                    else => return error.KtlsWrite,
                };
                if (n == 0) break :blk .closed;
                const bytes_written: u32 = @intCast(n);
                assert(bytes_written <= data.len);
                break :blk .{ .bytes = bytes_written };
            },
            .userspace => |ssl_conn| blk: {
                const n = ssl.SSL_write(ssl_conn, data.ptr, @intCast(data.len));
                if (n <= 0) {
                    const ssl_err = ssl.SSL_get_error(ssl_conn, n);
                    switch (ssl_err) {
                        ssl.SSL_ERROR_WANT_READ => break :blk .need_read,
                        ssl.SSL_ERROR_WANT_WRITE => break :blk .need_write,
                        ssl.SSL_ERROR_ZERO_RETURN => break :blk .closed,
                        ssl.SSL_ERROR_SYSCALL => return error.ConnectionReset,
                        else => return error.SslWrite,
                    }
                }

                const bytes_written: u32 = @intCast(n);
                assert(bytes_written <= data.len);
                break :blk .{ .bytes = bytes_written };
            },
        };
    }

    /// TLS write with nonblocking-aware error mapping.
    ///
    /// Contract: `data` must be non-empty and the stream must stay open.
    /// Ownership/lifetime: caller retains ownership of `self` and `data`.
    /// Failure semantics: returns `error.WantRead`/`error.WantWrite` for
    /// backpressure and terminal TLS/fd write failures for fatal states.
    /// Returns number of bytes written.
    pub fn write(self: *TLSStream, data: []const u8) !u32 {
        assert(data.len > 0);
        assert(self.fd > 0);

        const step = self.writeStep(data) catch |err| return err;
        return switch (step) {
            .bytes => |n| n,
            .closed => error.ConnectionReset,
            .need_read => error.WantRead,
            .need_write => error.WantWrite,
        };
    }

    /// Writes TLS application bytes using the stream's configured I/O timeout.
    /// Preconditions: `self.io_timeout_ns > 0`; `data` is borrowed caller-owned input.
    /// `self` remains caller-owned and valid for the duration of the write.
    /// Returns write-related TLS/socket errors from `writeWithTimeout`.
    pub fn writeBounded(self: *TLSStream, data: []const u8) !u32 {
        assert(self.io_timeout_ns > 0);
        return self.writeWithTimeout(data, self.io_timeout_ns);
    }

    /// Writes TLS application bytes with an explicit timeout budget in nanoseconds.
    ///
    /// Contract: `data.len > 0`, `fd > 0`, and `timeout_ns > 0`.
    /// Ownership/lifetime: `data` and `self` remain caller-owned and must stay
    /// valid for the call duration.
    /// Failure semantics: returns `error.Timeout` when readiness deadline
    /// expires, `error.ConnectionReset` for reset/closed paths, and
    /// mode-specific write failures (`error.SslWrite`/`error.KtlsWrite`).
    pub fn writeWithTimeout(self: *TLSStream, data: []const u8, timeout_ns: u64) !u32 {
        assert(data.len > 0);
        assert(self.fd > 0);
        assert(timeout_ns > 0);

        const readiness_wait_failed = switch (self.mode) {
            .ktls => error.KtlsWrite,
            .userspace => error.SslWrite,
        };
        const deadline_ns = deadlineFromTimeout(timeout_ns);
        var iterations: u32 = 0;
        while (iterations < tls_io_max_iterations) : (iterations += 1) {
            const step = self.writeStep(data) catch |err| return err;
            switch (step) {
                .bytes => |n| {
                    assert(n <= data.len);
                    return n;
                },
                .closed => return error.ConnectionReset,
                .need_read => {
                    waitForReady(self.fd, .read, deadline_ns) catch |wait_err| switch (wait_err) {
                        error.Timeout => return error.Timeout,
                        error.ConnectionReset => return error.ConnectionReset,
                        error.ReadinessWaitFailed => return readiness_wait_failed,
                    };
                },
                .need_write => {
                    waitForReady(self.fd, .write, deadline_ns) catch |wait_err| switch (wait_err) {
                        error.Timeout => return error.Timeout,
                        error.ConnectionReset => return error.ConnectionReset,
                        error.ReadinessWaitFailed => return readiness_wait_failed,
                    };
                },
            }
        }

        return error.Timeout;
    }

    /// Graceful TLS shutdown.
    /// Caller owns fd and is responsible for closing it.
    /// TigerStyle: Explicit switch on mode (no default case).
    pub fn close(self: *TLSStream) void {
        switch (self.mode) {
            .ktls => {
                // kTLS: kernel handles TLS shutdown when fd is closed
                // No SSL resources to free, caller closes fd
            },
            .userspace => |ssl_conn| {
                // Userspace: quiet shutdown avoids writing close_notify into a
                // peer that already closed, which can otherwise raise SIGPIPE
                // during tunnel cleanup on OpenSSL's socket BIO path.
                ssl.SSL_set_quiet_shutdown(ssl_conn, 1);
                _ = ssl.SSL_shutdown(ssl_conn);
                ssl.SSL_free(ssl_conn);
            },
        }
        // Caller owns fd, don't close it here
    }
};

fn setNonblocking(fd: c_int) !void {
    assert(fd > 0);

    const flags_value = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (flags_value < 0) return error.Unexpected;
    const flags: usize = @intCast(flags_value);
    const nonblocking_flags = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    if ((flags & nonblocking_flags) != 0) return;

    const set_result = posix.system.fcntl(fd, posix.F.SETFL, flags | nonblocking_flags);
    if (set_result < 0) return error.Unexpected;

    const verify_flags_value = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (verify_flags_value < 0) return error.Unexpected;
    const verify_flags: usize = @intCast(verify_flags_value);
    assert((verify_flags & nonblocking_flags) != 0);
}

fn deadlineFromTimeout(timeout_ns: u64) u64 {
    assert(timeout_ns > 0);

    const start_ns = monotonicNanos();
    const deadline_ns, const overflow = @addWithOverflow(start_ns, timeout_ns);
    const result = if (overflow == 0) deadline_ns else std.math.maxInt(u64);
    assert(result >= start_ns);
    return result;
}

fn remainingTimeoutMs(deadline_ns: u64) ?i32 {
    const now_ns = monotonicNanos();
    if (now_ns >= deadline_ns) return null;

    const remaining_ns = deadline_ns - now_ns;
    const remaining_ms_u64 = std.math.divCeil(u64, remaining_ns, time.ns_per_ms) catch unreachable;
    const max_timeout_ms_u64: u64 = @intCast(std.math.maxInt(i32));
    const clamped_ms_u64 = @min(remaining_ms_u64, max_timeout_ms_u64);
    const timeout_ms: i32 = @intCast(@max(@as(u64, 1), clamped_ms_u64));
    assert(timeout_ms > 0);
    return timeout_ms;
}

fn waitForReady(fd: c_int, direction: ReadinessDirection, deadline_ns: u64) WaitForReadyError!void {
    assert(fd > 0);

    const timeout_ms = remainingTimeoutMs(deadline_ns) orelse return error.Timeout;
    const events: i16 = switch (direction) {
        .read => posix.POLL.IN,
        .write => posix.POLL.OUT,
    };

    var poll_fds = [_]posix.pollfd{.{
        .fd = fd,
        .events = events,
        .revents = 0,
    }};
    const polled = posix.poll(&poll_fds, timeout_ms) catch return error.ReadinessWaitFailed;
    if (polled == 0) return error.Timeout;

    const revents = poll_fds[0].revents;
    if ((revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) return error.ReadinessWaitFailed;
    if ((revents & posix.POLL.HUP) != 0) return error.ConnectionReset;
    if ((revents & events) == 0) return error.ReadinessWaitFailed;
}

fn doHandshake(ssl_conn: *ssl.SSL, fd: c_int, timeout_ns: u64) !void {
    assert(@intFromPtr(ssl_conn) != 0);
    assert(fd > 0);
    assert(timeout_ns > 0);

    const deadline_ns = deadlineFromTimeout(timeout_ns);
    var iterations: u32 = 0;
    while (iterations < tls_handshake_max_iterations) : (iterations += 1) {
        const ret = ssl.SSL_do_handshake(ssl_conn);
        if (ret == 1) {
            assert(ssl.SSL_is_init_finished(ssl_conn) == 1);
            return;
        }

        const handshake_err = ssl.SSL_get_error(ssl_conn, ret);
        switch (handshake_err) {
            ssl.SSL_ERROR_WANT_READ => {
                waitForReady(fd, .read, deadline_ns) catch |wait_err| switch (wait_err) {
                    error.Timeout => return error.HandshakeTimeout,
                    error.ConnectionReset,
                    error.ReadinessWaitFailed,
                    => return error.HandshakeFailed,
                };
            },
            ssl.SSL_ERROR_WANT_WRITE => {
                waitForReady(fd, .write, deadline_ns) catch |wait_err| switch (wait_err) {
                    error.Timeout => return error.HandshakeTimeout,
                    error.ConnectionReset,
                    error.ReadinessWaitFailed,
                    => return error.HandshakeFailed,
                };
            },
            else => {
                ssl.printErrors();
                return error.HandshakeFailed;
            },
        }
    }

    return error.HandshakeFailed;
}

/// Extract TLS session info from completed handshake.
/// Populates version, cipher, resumed, ALPN, and peer certificate info.
fn populateHandshakeInfo(ssl_conn: *ssl.SSL, info: *HandshakeInfo) void {
    // S1: preconditions
    assert(@intFromPtr(ssl_conn) != 0);
    assert(ssl.SSL_is_init_finished(ssl_conn) == 1);

    // TLS version (e.g., "TLSv1.3")
    if (ssl.SSL_get_version(ssl_conn)) |version_ptr| {
        const version_str = std.mem.sliceTo(version_ptr, 0);
        const len: u8 = @intCast(@min(version_str.len, HandshakeInfo.VERSION_BUF_SIZE));
        @memcpy(info.version_buf[0..len], version_str[0..len]);
        info.version_len = len;
    }

    // Cipher suite (e.g., "TLS_AES_256_GCM_SHA384")
    if (ssl.SSL_get_current_cipher(ssl_conn)) |cipher| {
        if (ssl.SSL_CIPHER_get_name(cipher)) |name_ptr| {
            const cipher_str = std.mem.sliceTo(name_ptr, 0);
            const len: u8 = @intCast(@min(cipher_str.len, HandshakeInfo.CIPHER_BUF_SIZE));
            @memcpy(info.cipher_buf[0..len], cipher_str[0..len]);
            info.cipher_len = len;
        }
    }

    // Session resumption
    info.resumed = ssl.SSL_session_reused(ssl_conn) != 0;

    // ALPN protocol (e.g., "h2", "http/1.1")
    // Note: SSL_get0_alpn_selected sets data to NULL if no ALPN negotiated
    var alpn_data: ?[*]const u8 = null;
    var alpn_len: c_uint = 0;
    ssl.SSL_get0_alpn_selected(ssl_conn, &alpn_data, &alpn_len);
    if (alpn_len > 0) {
        if (alpn_data) |data| {
            const len: u8 = @intCast(@min(alpn_len, HandshakeInfo.ALPN_BUF_SIZE));
            @memcpy(info.alpn_buf[0..len], data[0..len]);
            info.alpn_len = len;
        }
    }

    // Peer certificate subject and issuer
    if (ssl.SSL_get1_peer_certificate(ssl_conn)) |cert| {
        defer ssl.X509_free(cert);

        // Subject
        if (ssl.X509_get_subject_name(cert)) |subject| {
            if (ssl.X509_NAME_oneline(subject, &info.cert_subject_buf, HandshakeInfo.CERT_NAME_BUF_SIZE)) |result| {
                const subject_str = std.mem.sliceTo(result, 0);
                info.cert_subject_len = @intCast(subject_str.len);
            }
        }

        // Issuer
        if (ssl.X509_get_issuer_name(cert)) |issuer| {
            if (ssl.X509_NAME_oneline(issuer, &info.cert_issuer_buf, HandshakeInfo.CERT_NAME_BUF_SIZE)) |result| {
                const issuer_str = std.mem.sliceTo(result, 0);
                info.cert_issuer_len = @intCast(issuer_str.len);
            }
        }
    }
}

// Tests
fn makeKtlsTestStream(fd: c_int) TLSStream {
    assert(fd > 0);
    return .{
        .fd = fd,
        .mode = .{ .ktls = {} },
        .allocator = std.testing.allocator,
        .io_timeout_ns = default_tls_io_timeout_ns,
        .info = HandshakeInfo{},
    };
}

test "readStep returns need_read then bytes for kTLS mode" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try setNonblocking(fds[0]);
    try setNonblocking(fds[1]);

    var stream = makeKtlsTestStream(fds[0]);
    var buf: [4]u8 = undefined;

    const step_idle = try stream.readStep(buf[0..1]);
    try std.testing.expectEqual(ReadStep.need_read, step_idle);

    const payload = [_]u8{0x5a};
    try std.testing.expectEqual(@as(usize, 1), try posix.write(fds[1], &payload));

    const step_data = try stream.readStep(buf[0..1]);
    switch (step_data) {
        .bytes => |n| try std.testing.expectEqual(@as(u32, 1), n),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(payload[0], buf[0]);
}

test "writeStep writes bytes for kTLS mode" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try setNonblocking(fds[0]);
    try setNonblocking(fds[1]);

    var stream = makeKtlsTestStream(fds[0]);
    const payload = [_]u8{ 0x42, 0x43 };
    const step = try stream.writeStep(&payload);
    switch (step) {
        .bytes => |n| try std.testing.expectEqual(@as(u32, payload.len), n),
        else => return error.TestUnexpectedResult,
    }

    var out: [2]u8 = undefined;
    const read_count = try posix.read(fds[1], &out);
    try std.testing.expectEqual(@as(usize, payload.len), read_count);
    try std.testing.expectEqualSlices(u8, &payload, &out);
}

test "waitForReady times out on idle readable fd" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const deadline_ns = deadlineFromTimeout(time.millisToNanos(20));
    try std.testing.expectError(error.Timeout, waitForReady(fds[0], .read, deadline_ns));
}

test "waitForReady detects writable fd" {
    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const deadline_ns = deadlineFromTimeout(time.millisToNanos(20));
    try waitForReady(fds[0], .write, deadline_ns);
}

test "initServerWithTimeouts times out on idle peer" {
    ssl.init();

    const cert_path = "experiments/tls-poc/cert.pem";
    const key_path = "experiments/tls-poc/key.pem";
    const cert_fd = posix.openat(posix.AT.FDCWD, cert_path, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    closeFd(cert_fd);
    const key_fd = posix.openat(posix.AT.FDCWD, key_path, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    closeFd(key_fd);

    const server_ctx = try ssl.createServerCtxFromPemFiles(cert_path, key_path);
    defer ssl.SSL_CTX_free(server_ctx);

    const fds = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try std.testing.expectError(
        error.HandshakeTimeout,
        TLSStream.initServerWithTimeouts(
            server_ctx,
            fds[0],
            time.millisToNanos(20),
            default_tls_io_timeout_ns,
            std.testing.allocator,
        ),
    );
}

test "native kTLS BIO status after loopback handshake" {
    const builtin = @import("builtin");

    if (builtin.os.tag != .linux) return error.SkipZigTest;

    ssl.init();

    // Skip when TLS test fixtures are unavailable in this checkout.
    const cert_path = "experiments/tls-poc/cert.pem";
    const key_path = "experiments/tls-poc/key.pem";
    const cert_fd = posix.openat(posix.AT.FDCWD, cert_path, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    closeFd(cert_fd);
    const key_fd = posix.openat(posix.AT.FDCWD, key_path, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    closeFd(key_fd);

    const server_ctx = try ssl.createServerCtxFromPemFiles(cert_path, key_path);
    defer ssl.SSL_CTX_free(server_ctx);

    const client_ctx = try ssl.createClientCtx();
    defer ssl.SSL_CTX_free(client_ctx);

    // Nonblocking socketpair prevents single-threaded handshake deadlocks.
    const linux = std.os.linux;
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK, 0, &fds);
    if (posix.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const server_ssl = ssl.SSL_new(server_ctx) orelse return error.SslNew;
    defer ssl.SSL_free(server_ssl);
    _ = ssl.SSL_set_options(server_ssl, ssl.SSL_OP_ENABLE_KTLS);
    if (ssl.SSL_set_fd(server_ssl, fds[0]) != 1) return error.SslSetFd;
    ssl.SSL_set_accept_state(server_ssl);

    const client_ssl = ssl.SSL_new(client_ctx) orelse return error.SslNew;
    defer ssl.SSL_free(client_ssl);
    ssl.SSL_set_verify(client_ssl, ssl.SSL_VERIFY_NONE, null);
    _ = ssl.SSL_set_options(client_ssl, ssl.SSL_OP_ENABLE_KTLS);
    if (ssl.SSL_set_fd(client_ssl, fds[1]) != 1) return error.SslSetFd;
    ssl.SSL_set_connect_state(client_ssl);

    const max_handshake_rounds: u32 = 200;
    var rounds: u32 = 0;
    var client_done = false;
    var server_done = false;
    while (rounds < max_handshake_rounds and (!client_done or !server_done)) : (rounds += 1) {
        if (!client_done) {
            const client_rc = ssl.SSL_do_handshake(client_ssl);
            if (client_rc == 1) {
                client_done = true;
            } else {
                const client_err = ssl.SSL_get_error(client_ssl, client_rc);
                if (client_err != ssl.SSL_ERROR_WANT_READ and client_err != ssl.SSL_ERROR_WANT_WRITE) {
                    return error.HandshakeFailed;
                }
            }
        }

        if (!server_done) {
            const server_rc = ssl.SSL_do_handshake(server_ssl);
            if (server_rc == 1) {
                server_done = true;
            } else {
                const server_err = ssl.SSL_get_error(server_ssl, server_rc);
                if (server_err != ssl.SSL_ERROR_WANT_READ and server_err != ssl.SSL_ERROR_WANT_WRITE) {
                    return error.HandshakeFailed;
                }
            }
        }
    }
    if (!client_done or !server_done) return error.HandshakeFailed;

    const ktls_available = ktls.isKtlsRuntimeAvailable();
    const server_tx = if (ssl.SSL_get_wbio(server_ssl)) |wbio| ssl.BIO_get_ktls_send(wbio) else false;
    const server_rx = if (ssl.SSL_get_rbio(server_ssl)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false;

    if (server_rx) {
        try std.testing.expect(server_tx);
    }

    if (!ktls_available) {
        try std.testing.expect(!server_tx);
        try std.testing.expect(!server_rx);
    }

    if (server_tx or server_rx) {
        try std.testing.expect(ktls_available);
    }
}

test "TLSStream compiles" {
    // Basic compilation test
    _ = TLSStream;
}
