//! ACME continuous renewer.
//!
//! Composes scheduler + issuance runtime + certificate-expiry check into one
//! reusable layer-2 component. Callers provide only TLS activation callback.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const core = @import("serval-core");
const config = core.config;
const time = core.time;

const types = @import("types.zig");
const signer_mod = @import("signer.zig");
const runtime = @import("runtime.zig");
const scheduler_mod = @import("scheduler.zig");
const backoff_mod = @import("backoff.zig");
const hook_mod = @import("tls_alpn_hook.zig");

const serval_client = @import("serval-client");
const Client = serval_client.Client;

const serval_net = @import("serval-net");
const DnsResolver = serval_net.DnsResolver;

const serval_tls = @import("serval-tls");
const ssl = serval_tls.ssl;

pub const ActivationResult = enum {
    success,
    transient_failure,
    fatal_failure,
};

pub const ActivateFn = *const fn (ctx: *anyopaque, cert_path: []const u8, key_path: []const u8) ActivationResult;

pub const ParseBuffers = struct {
    cert_pem_read_buf: []u8,
    cert_pem_b64_buf: []u8,
    cert_der_buf: []u8,
};

pub const Params = struct {
    runtime_config: *const types.RuntimeConfig,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    work: runtime.WorkBuffers,
    cert_current_path: []const u8,
    parse_buffers: ParseBuffers,
    check_interval_ms: u32,
    backoff: backoff_mod.BoundedBackoff,
    hook_provider: *hook_mod.TlsAlpnHookProvider,
    activate_ctx: *anyopaque,
    activate_fn: ActivateFn,
};

const cert_path_buf_size_bytes: usize = 1024;
const key_path_buf_size_bytes: usize = 1024;
const csr_buf_size_bytes: usize = 32 * 1024;
const key_pem_buf_size_bytes: usize = 32 * 1024;
const cert_pem_read_buf_size_bytes: usize = 24 * 1024;
const cert_pem_base64_buf_size_bytes: usize = 24 * 1024;
const cert_der_buf_size_bytes: usize = 16 * 1024;

pub const ManagedParams = struct {
    allocator: std.mem.Allocator,
    runtime_config: *const types.RuntimeConfig,
    check_interval_ms: u32,
    hook_provider: *hook_mod.TlsAlpnHookProvider,
    activate_ctx: *anyopaque,
    activate_fn: ActivateFn,
    verify_tls: bool = true,
};

pub const ManagedFromAcmeConfigParams = struct {
    allocator: std.mem.Allocator,
    acme_config: config.AcmeConfig,
    hook_provider: *hook_mod.TlsAlpnHookProvider,
    activate_ctx: *anyopaque,
    activate_fn: ActivateFn,
    verify_tls: bool = true,
};

pub const Error = error{
    InvalidCheckInterval,
    InvalidCertPath,
    CertPathTooLong,
    TlsClientCtxInitFailed,
    FatalFailure,
} || types.Error || backoff_mod.Error || scheduler_mod.Error || runtime.Error || Io.Cancelable;

pub const Renewer = struct {
    runtime_config: *const types.RuntimeConfig,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    work: runtime.WorkBuffers,
    cert_current_path: []const u8,
    parse_buffers: ParseBuffers,
    check_interval_ms: u32,
    backoff: backoff_mod.BoundedBackoff,
    hook_provider: *hook_mod.TlsAlpnHookProvider,
    activate_ctx: *anyopaque,
    activate_fn: ActivateFn,

    pub fn init(params: Params) Error!Renewer {
        if (params.check_interval_ms == 0) return error.InvalidCheckInterval;
        if (params.cert_current_path.len == 0) return error.InvalidCertPath;
        assert(@intFromPtr(params.runtime_config) != 0);
        assert(@intFromPtr(params.acme_client) != 0);
        assert(@intFromPtr(params.signer) != 0);
        assert(@intFromPtr(params.activate_ctx) != 0);

        return .{
            .runtime_config = params.runtime_config,
            .acme_client = params.acme_client,
            .signer = params.signer,
            .work = params.work,
            .cert_current_path = params.cert_current_path,
            .parse_buffers = params.parse_buffers,
            .check_interval_ms = params.check_interval_ms,
            .backoff = params.backoff,
            .hook_provider = params.hook_provider,
            .activate_ctx = params.activate_ctx,
            .activate_fn = params.activate_fn,
        };
    }

    pub fn run(self: *Renewer, io: Io, shutdown: *std.atomic.Value(bool)) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(shutdown) != 0);

        const scheduler_config = try scheduler_mod.Config.init(self.check_interval_ms);
        var scheduler = scheduler_mod.Scheduler.init(
            scheduler_config,
            self.backoff,
            @ptrCast(self),
            should_renew_callback,
            issue_callback,
        );

        scheduler.run(io, shutdown) catch |err| switch (err) {
            error.FatalFailure => return error.FatalFailure,
            else => return err,
        };
    }

    fn should_renew_callback(ctx_raw: *anyopaque, now_ns: u64) scheduler_mod.ShouldRenewResult {
        _ = now_ns;
        const self: *Renewer = @ptrCast(@alignCast(ctx_raw));

        const renew = should_renew_from_certificate(
            self.cert_current_path,
            self.runtime_config.renew_before_ns,
            self.parse_buffers,
        );
        return if (renew) .renew_now else .skip;
    }

    fn issue_callback(ctx_raw: *anyopaque, io: Io) scheduler_mod.IssueResult {
        const self: *Renewer = @ptrCast(@alignCast(ctx_raw));

        const persisted = runtime.runIssuanceOnce(
            self.runtime_config,
            self.acme_client,
            self.signer,
            io,
            self.work,
            null,
            self.hook_provider,
        ) catch |err| {
            std.debug.print("error: ACME issuance failed: {s}\n", .{@errorName(err)});
            return switch (err) {
                error.InvalidRuntimeConfig => .fatal_failure,
                else => .transient_failure,
            };
        };

        return switch (self.activate_fn(self.activate_ctx, persisted.cert_path, persisted.key_path)) {
            .success => blk: {
                std.debug.print("ACME issuance succeeded; activated cert={s} key={s}\n", .{ persisted.cert_path, persisted.key_path });
                break :blk .success;
            },
            .transient_failure => .transient_failure,
            .fatal_failure => .fatal_failure,
        };
    }
};

pub const ManagedRenewer = struct {
    runtime_config: types.RuntimeConfig,
    check_interval_ms: u32,
    hook_provider: *hook_mod.TlsAlpnHookProvider,
    activate_ctx: *anyopaque,
    activate_fn: ActivateFn,

    dns_resolver: DnsResolver,
    client_ctx: ?*ssl.SSL_CTX,
    acme_client: Client,
    signer: signer_mod.AccountSigner,
    backoff: backoff_mod.BoundedBackoff,

    cert_current_path_len: u16,
    cert_current_path_bytes: [cert_path_buf_size_bytes]u8,

    header_buf: [config.MAX_HEADER_SIZE_BYTES]u8,
    body_buf: [config.ACME_MAX_ORDER_RESPONSE_BYTES]u8,
    jws_buf: [config.ACME_MAX_JWS_BODY_BYTES]u8,
    payload_buf: [config.ACME_MAX_JWS_BODY_BYTES]u8,
    csr_der_buf: [csr_buf_size_bytes]u8,
    key_pem_buf: [key_pem_buf_size_bytes]u8,
    cert_path_buf: [cert_path_buf_size_bytes]u8,
    key_path_buf: [key_path_buf_size_bytes]u8,
    cert_pem_read_buf: [cert_pem_read_buf_size_bytes]u8,
    cert_pem_b64_buf: [cert_pem_base64_buf_size_bytes]u8,
    cert_der_buf: [cert_der_buf_size_bytes]u8,

    pub fn init(params: ManagedParams, io: Io) Error!ManagedRenewer {
        assert(@intFromPtr(params.runtime_config) != 0);
        assert(@intFromPtr(params.activate_ctx) != 0);
        if (params.check_interval_ms == 0) return error.InvalidCheckInterval;

        var service: ManagedRenewer = undefined;
        service.runtime_config = params.runtime_config.*;
        service.check_interval_ms = params.check_interval_ms;
        service.hook_provider = params.hook_provider;
        service.activate_ctx = params.activate_ctx;
        service.activate_fn = params.activate_fn;

        DnsResolver.init(&service.dns_resolver, serval_net.DnsConfig{});

        ssl.init();
        const client_ctx = ssl.createClientCtx() catch return error.TlsClientCtxInitFailed;
        errdefer ssl.SSL_CTX_free(client_ctx);
        if (params.verify_tls) {
            ssl.SSL_CTX_set_verify(client_ctx, ssl.SSL_VERIFY_PEER, null);
        } else {
            ssl.SSL_CTX_set_verify(client_ctx, ssl.SSL_VERIFY_NONE, null);
        }

        service.client_ctx = client_ctx;
        service.acme_client = Client.init(params.allocator, &service.dns_resolver, client_ctx, params.verify_tls);
        service.signer = signer_mod.AccountSigner.generate(io);
        service.backoff = try backoff_mod.BoundedBackoff.init(
            service.runtime_config.fail_backoff_min_ms,
            service.runtime_config.fail_backoff_max_ms,
        );

        const cert_current_path = try build_current_cert_path(
            service.runtime_config.stateDirPath(),
            &service.cert_current_path_bytes,
        );
        service.cert_current_path_len = @intCast(cert_current_path.len);

        service.header_buf = undefined;
        service.body_buf = undefined;
        service.jws_buf = undefined;
        service.payload_buf = undefined;
        service.csr_der_buf = undefined;
        service.key_pem_buf = undefined;
        service.cert_path_buf = undefined;
        service.key_path_buf = undefined;
        service.cert_pem_read_buf = undefined;
        service.cert_pem_b64_buf = undefined;
        service.cert_der_buf = undefined;

        return service;
    }

    pub fn initFromAcmeConfig(params: ManagedFromAcmeConfigParams, io: Io) Error!ManagedRenewer {
        assert(@intFromPtr(params.activate_ctx) != 0);

        var runtime_config = try types.RuntimeConfig.initFromConfig(params.acme_config);
        return init(.{
            .allocator = params.allocator,
            .runtime_config = &runtime_config,
            .check_interval_ms = params.acme_config.poll_interval_ms,
            .hook_provider = params.hook_provider,
            .activate_ctx = params.activate_ctx,
            .activate_fn = params.activate_fn,
            .verify_tls = params.verify_tls,
        }, io);
    }

    pub fn deinit(self: *ManagedRenewer) void {
        assert(@intFromPtr(self) != 0);

        self.acme_client.deinit();
        if (self.client_ctx) |ctx| {
            ssl.SSL_CTX_free(ctx);
            self.client_ctx = null;
        }
    }

    pub fn run(self: *ManagedRenewer, io: Io, shutdown: *std.atomic.Value(bool)) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(shutdown) != 0);

        var renewer = try Renewer.init(.{
            .runtime_config = &self.runtime_config,
            .acme_client = &self.acme_client,
            .signer = &self.signer,
            .work = .{
                .header_buf = &self.header_buf,
                .body_buf = &self.body_buf,
                .jws_buf = &self.jws_buf,
                .payload_buf = &self.payload_buf,
                .csr_der_buf = &self.csr_der_buf,
                .key_pem_buf = &self.key_pem_buf,
                .cert_path_buf = &self.cert_path_buf,
                .key_path_buf = &self.key_path_buf,
            },
            .cert_current_path = self.certCurrentPath(),
            .parse_buffers = .{
                .cert_pem_read_buf = &self.cert_pem_read_buf,
                .cert_pem_b64_buf = &self.cert_pem_b64_buf,
                .cert_der_buf = &self.cert_der_buf,
            },
            .check_interval_ms = self.check_interval_ms,
            .backoff = self.backoff,
            .hook_provider = self.hook_provider,
            .activate_ctx = self.activate_ctx,
            .activate_fn = self.activate_fn,
        });

        try renewer.run(io, shutdown);
    }

    fn certCurrentPath(self: *const ManagedRenewer) []const u8 {
        assert(self.cert_current_path_len <= cert_path_buf_size_bytes);
        return self.cert_current_path_bytes[0..self.cert_current_path_len];
    }
};

fn build_current_cert_path(state_dir_path: []const u8, out: []u8) Error![]const u8 {
    if (state_dir_path.len == 0) return error.InvalidCertPath;
    const path = std.fmt.bufPrint(out, "{s}/cert/current/fullchain.pem", .{state_dir_path}) catch {
        return error.CertPathTooLong;
    };
    return path;
}

fn should_renew_from_certificate(cert_path: []const u8, renew_before_ns: u64, parse_buffers: ParseBuffers) bool {
    const not_after_sec = parse_first_pem_certificate_not_after_sec(cert_path, parse_buffers) orelse return true;

    const now_ns_i128 = time.realtimeNanos();
    if (now_ns_i128 <= 0) return true;

    const now_sec: u64 = time.nanosToSecondsI128(now_ns_i128);
    const renew_before_sec: u64 = time.nanosToSeconds(renew_before_ns);
    const renew_at_sec: u64 = now_sec +| renew_before_sec;
    return renew_at_sec >= not_after_sec;
}

fn parse_first_pem_certificate_not_after_sec(cert_path: []const u8, parse_buffers: ParseBuffers) ?u64 {
    const pem = Io.Dir.cwd().readFile(std.Options.debug_io, cert_path, parse_buffers.cert_pem_read_buf) catch return null;

    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const begin_idx = std.mem.indexOf(u8, pem, begin_marker) orelse return null;
    const after_begin = begin_idx + begin_marker.len;
    const end_idx_rel = std.mem.indexOf(u8, pem[after_begin..], end_marker) orelse return null;
    const end_idx = after_begin + end_idx_rel;
    const block = pem[after_begin..end_idx];

    var b64_len: usize = 0;
    var i: usize = 0;
    while (i < block.len) : (i += 1) {
        const c = block[i];
        if (c == '\n' or c == '\r' or c == ' ' or c == '\t') continue;
        if (b64_len >= parse_buffers.cert_pem_b64_buf.len) return null;
        parse_buffers.cert_pem_b64_buf[b64_len] = c;
        b64_len += 1;
    }

    const b64 = parse_buffers.cert_pem_b64_buf[0..b64_len];
    const der_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return null;
    if (der_len > parse_buffers.cert_der_buf.len) return null;
    std.base64.standard.Decoder.decode(parse_buffers.cert_der_buf[0..der_len], b64) catch return null;

    const cert = std.crypto.Certificate{
        .buffer = parse_buffers.cert_der_buf[0..der_len],
        .index = 0,
    };
    const parsed = std.crypto.Certificate.parse(cert) catch return null;
    return parsed.validity.not_after;
}

test "build_current_cert_path builds expected current fullchain path" {
    var out: [cert_path_buf_size_bytes]u8 = undefined;
    const path = try build_current_cert_path("/tmp/acme", &out);
    try std.testing.expectEqualStrings("/tmp/acme/cert/current/fullchain.pem", path);
}

test "build_current_cert_path rejects empty state dir" {
    var out: [cert_path_buf_size_bytes]u8 = undefined;
    try std.testing.expectError(error.InvalidCertPath, build_current_cert_path("", &out));
}

test "ManagedRenewer initFromAcmeConfig validates ACME config" {
    var io_threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer io_threaded.deinit();

    var activation_flag: u8 = 0;
    var hook_provider = hook_mod.TlsAlpnHookProvider.init();
    const Callbacks = struct {
        fn activate(_: *anyopaque, _: []const u8, _: []const u8) ActivationResult {
            return .success;
        }
    };

    const bad_cfg = config.AcmeConfig{
        .enabled = true,
        .directory_url = "https://acme-v02.api.letsencrypt.org/directory",
        .contact_email = "ops@example.com",
        .state_dir_path = "/tmp/acme-state",
        .domains = &.{},
    };

    try std.testing.expectError(error.InvalidDomainCount, ManagedRenewer.initFromAcmeConfig(.{
        .allocator = std.testing.allocator,
        .acme_config = bad_cfg,
        .hook_provider = &hook_provider,
        .activate_ctx = @ptrCast(&activation_flag),
        .activate_fn = Callbacks.activate,
        .verify_tls = true,
    }, io_threaded.io()));
}

test "should_renew_from_certificate true when cert missing" {
    var pem_read: [1024]u8 = undefined;
    var pem_b64: [1024]u8 = undefined;
    var der_buf: [1024]u8 = undefined;

    const renew = should_renew_from_certificate(
        "/tmp/does-not-exist-cert.pem",
        time.secondsToNanos(3600),
        .{
            .cert_pem_read_buf = &pem_read,
            .cert_pem_b64_buf = &pem_b64,
            .cert_der_buf = &der_buf,
        },
    );
    try std.testing.expect(renew);
}

test "should_renew_from_certificate false for far-future bootstrap cert" {
    var io_threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer io_threaded.deinit();

    var cert_buf: [8192]u8 = undefined;
    var key_buf: [4096]u8 = undefined;
    const materials = try @import("tls_alpn_cert.zig").generateMaterials(
        io_threaded.io(),
        "example.com",
        "abc.def",
        &cert_buf,
        &key_buf,
    );

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var cert_path_buf: [1024]u8 = undefined;
    const cert_path = try std.fmt.bufPrint(&cert_path_buf, "{s}/bootstrap.pem", .{tmp.sub_path[0..]});
    const cert_parent = std.fs.path.dirname(cert_path) orelse unreachable;
    try Io.Dir.cwd().createDirPath(std.Options.debug_io, cert_parent);
    try Io.Dir.cwd().writeFile(std.Options.debug_io, .{ .sub_path = cert_path, .data = materials.cert_pem });

    var pem_read: [8192]u8 = undefined;
    var pem_b64: [8192]u8 = undefined;
    var der_buf: [4096]u8 = undefined;

    const renew = should_renew_from_certificate(
        cert_path,
        time.secondsToNanos(30 * 24 * 60 * 60),
        .{
            .cert_pem_read_buf = &pem_read,
            .cert_pem_b64_buf = &pem_b64,
            .cert_der_buf = &der_buf,
        },
    );
    try std.testing.expect(!renew);
}
