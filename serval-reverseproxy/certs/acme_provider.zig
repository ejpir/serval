const std = @import("std");
const assert = std.debug.assert;
const core_config = @import("serval-core").config;
const acme = @import("serval-acme");
const ir = @import("../ir.zig");
const provider = @import("provider.zig");
const selfsigned_provider = @import("selfsigned_provider.zig");

const cert_path_buf_size_bytes: u16 = 1024;
const key_path_buf_size_bytes: u16 = 1024;

/// Errors returned by the ACME TLS provider lifecycle.
/// `InvalidConfig` covers missing required configuration, `InitFailed` covers setup and bootstrap failures, and `RunFailed` covers renew-loop execution failures.
/// `HookInstallFailed` and `HookUninstallFailed` describe TLS-ALPN hook management errors.
pub const Error = error{
    InvalidConfig,
    InitFailed,
    HookInstallFailed,
    HookUninstallFailed,
    RunFailed,
};

/// Provider state for ACME certificate loading and renewal.
/// The struct stores configured ACME parameters plus fixed-size buffers for the current certificate path and any bootstrap certificate material.
/// Its public API is `init`, `loadInitial`, `run`, and `deinit`; borrowed slices in `cfg` and `listener_id` must outlive the provider.
pub const Provider = struct {
    cfg: ir.AcmeTlsConfig,
    listener_id: []const u8,

    cert_current_path_len: u16,
    cert_current_path_bytes: [cert_path_buf_size_bytes]u8,

    key_current_path_len: u16,
    key_current_path_bytes: [key_path_buf_size_bytes]u8,

    bootstrap_cert_path_len: u16,
    bootstrap_cert_path_bytes: [cert_path_buf_size_bytes]u8,

    bootstrap_key_path_len: u16,
    bootstrap_key_path_bytes: [key_path_buf_size_bytes]u8,

    /// Construct a provider for the configured ACME state directory and listener.
    /// `cfg` and `listener_id` are borrowed by value or slice reference, so their backing storage must remain valid for the returned provider.
    /// Returns `error.InvalidConfig` when required ACME fields are empty, or `error.InitFailed` if the current certificate or key path cannot be formatted into the internal buffers.
    pub fn init(cfg: ir.AcmeTlsConfig, listener_id: []const u8) Error!Provider {
        assert(listener_id.len > 0);
        if (cfg.directory_url.len == 0 or cfg.contact_email.len == 0 or cfg.state_dir_path.len == 0 or cfg.domain.len == 0) {
            return error.InvalidConfig;
        }

        var service = Provider{
            .cfg = cfg,
            .listener_id = listener_id,
            .cert_current_path_len = 0,
            .cert_current_path_bytes = undefined,
            .key_current_path_len = 0,
            .key_current_path_bytes = undefined,
            .bootstrap_cert_path_len = 0,
            .bootstrap_cert_path_bytes = undefined,
            .bootstrap_key_path_len = 0,
            .bootstrap_key_path_bytes = undefined,
        };

        const cert_path = std.fmt.bufPrint(&service.cert_current_path_bytes, "{s}/cert/current/fullchain.pem", .{cfg.state_dir_path}) catch {
            return error.InitFailed;
        };
        const key_path = std.fmt.bufPrint(&service.key_current_path_bytes, "{s}/cert/current/privkey.pem", .{cfg.state_dir_path}) catch {
            return error.InitFailed;
        };

        service.cert_current_path_len = @intCast(cert_path.len);
        service.key_current_path_len = @intCast(key_path.len);
        return service;
    }

    /// Release provider state.
    /// This implementation does not free heap memory; it only checks internal length invariants in debug builds.
    /// Callers should still treat this as the teardown point for the provider lifecycle.
    pub fn deinit(self: *Provider) void {
        assert(@intFromPtr(self) != 0);
        assert(self.cert_current_path_len <= cert_path_buf_size_bytes);
        assert(self.bootstrap_cert_path_len <= cert_path_buf_size_bytes);
        assert(self.bootstrap_key_path_len <= key_path_buf_size_bytes);
    }

    /// Load the initial certificate material for this provider.
    /// If the current certificate and key already exist, returns those paths directly; otherwise it bootstraps a listener-scoped self-signed certificate and stores the generated paths in `self`.
    /// The returned paths borrow storage owned by `self` and remain valid until the provider is mutated or deinitialized; bootstrap failures and path-copy bounds checks return `error.InitFailed`.
    pub fn loadInitial(self: *Provider, io: std.Io) Error!provider.CertMaterial {
        assert(@intFromPtr(self) != 0);
        assert(self.key_current_path_len <= key_path_buf_size_bytes);

        const cert_current_path = self.certCurrentPath();
        const key_current_path = self.keyCurrentPath();
        if (fileExists(cert_current_path) and fileExists(key_current_path)) {
            return .{ .cert_path = cert_current_path, .key_path = key_current_path };
        }

        // ACME bootstrap path: generate self-signed listener-scoped cert first.
        var bootstrap = try selfSignedBootstrapConfig(self.cfg, self.listener_id);
        const bootstrap_material = bootstrap.loadInitial(io) catch return error.InitFailed;

        if (bootstrap_material.cert_path.len == 0 or bootstrap_material.cert_path.len > self.bootstrap_cert_path_bytes.len) {
            return error.InitFailed;
        }
        if (bootstrap_material.key_path.len == 0 or bootstrap_material.key_path.len > self.bootstrap_key_path_bytes.len) {
            return error.InitFailed;
        }

        @memcpy(self.bootstrap_cert_path_bytes[0..bootstrap_material.cert_path.len], bootstrap_material.cert_path);
        @memcpy(self.bootstrap_key_path_bytes[0..bootstrap_material.key_path.len], bootstrap_material.key_path);
        self.bootstrap_cert_path_len = @intCast(bootstrap_material.cert_path.len);
        self.bootstrap_key_path_len = @intCast(bootstrap_material.key_path.len);

        return .{ .cert_path = self.bootstrapCertPath(), .key_path = self.bootstrapKeyPath() };
    }

    /// Run the ACME renewer loop until `shutdown` is signaled or an error occurs.
    /// Installs the TLS-ALPN hook before starting and always attempts to uninstall it on exit; uninstall failures are logged.
    /// Returns `error.HookInstallFailed`, `error.InitFailed`, or `error.RunFailed` when hook setup, renewer creation, or the renew loop fails.
    pub fn run(
        self: *Provider,
        shutdown: *std.atomic.Value(bool),
        activate_ctx: *anyopaque,
        activate_fn: provider.ActivateFn,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(shutdown) != 0);
        assert(@intFromPtr(activate_ctx) != 0);

        var io_threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
        defer io_threaded.deinit();

        var hook_provider = acme.AcmeTlsAlpnHookProvider.init();
        hook_provider.install() catch return error.HookInstallFailed;
        defer hook_provider.uninstall() catch {
            std.log.err("reverseproxy-acme: hook uninstall failed", .{});
        };

        const acme_cfg = core_config.AcmeConfig{
            .enabled = true,
            .directory_url = self.cfg.directory_url,
            .contact_email = self.cfg.contact_email,
            .state_dir_path = self.cfg.state_dir_path,
            .renew_before_ns = self.cfg.renew_before_ns,
            .poll_interval_ms = self.cfg.poll_interval_ms,
            .fail_backoff_min_ms = self.cfg.fail_backoff_min_ms,
            .fail_backoff_max_ms = self.cfg.fail_backoff_max_ms,
            .domains = &.{self.cfg.domain},
        };

        const ActivationBridge = struct {
            ctx: *anyopaque,
            cb: provider.ActivateFn,

            fn activate(ctx_raw: *anyopaque, cert_path: []const u8, key_path: []const u8) acme.AcmeActivationResult {
                const bridge: *@This() = @ptrCast(@alignCast(ctx_raw));
                return switch (bridge.cb(bridge.ctx, cert_path, key_path)) {
                    .success => .success,
                    .transient_failure => .transient_failure,
                    .fatal_failure => .fatal_failure,
                };
            }
        };

        var bridge = ActivationBridge{ .ctx = activate_ctx, .cb = activate_fn };
        var renewer = acme.AcmeManagedRenewer.initFromAcmeConfig(.{
            .allocator = std.heap.page_allocator,
            .acme_config = acme_cfg,
            .hook_provider = &hook_provider,
            .activate_ctx = @ptrCast(&bridge),
            .activate_fn = ActivationBridge.activate,
            .verify_tls = true,
        }, io_threaded.io()) catch return error.InitFailed;
        defer renewer.deinit();

        renewer.run(io_threaded.io(), shutdown) catch return error.RunFailed;
    }

    fn certCurrentPath(self: *const Provider) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.cert_current_path_len <= cert_path_buf_size_bytes);
        return self.cert_current_path_bytes[0..self.cert_current_path_len];
    }

    fn keyCurrentPath(self: *const Provider) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.key_current_path_len <= key_path_buf_size_bytes);
        return self.key_current_path_bytes[0..self.key_current_path_len];
    }

    fn bootstrapCertPath(self: *const Provider) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.bootstrap_cert_path_len <= cert_path_buf_size_bytes);
        return self.bootstrap_cert_path_bytes[0..self.bootstrap_cert_path_len];
    }

    fn bootstrapKeyPath(self: *const Provider) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.bootstrap_key_path_len <= key_path_buf_size_bytes);
        return self.bootstrap_key_path_bytes[0..self.bootstrap_key_path_len];
    }
};

fn fileExists(path: []const u8) bool {
    assert(path.len > 0);
    var read_buf: [16384]u8 = undefined;
    _ = std.Io.Dir.cwd().readFile(std.Options.debug_io, path, &read_buf) catch return false;
    return true;
}

fn selfSignedBootstrapConfig(cfg: ir.AcmeTlsConfig, listener_id: []const u8) Error!selfsigned_provider.Provider {
    assert(listener_id.len > 0);
    const selfsigned_cfg = ir.SelfSignedTlsConfig{
        .state_dir_path = cfg.state_dir_path,
        .domain = cfg.domain,
        .rotate_on_boot = false,
    };
    return selfsigned_provider.Provider.init(selfsigned_cfg, listener_id) catch return error.InitFailed;
}

test "acme provider loadInitial prefers existing current cert paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var state_dir_buf: [1024]u8 = undefined;
    var current_dir_buf: [1024]u8 = undefined;
    const state_dir = try std.fmt.bufPrint(&state_dir_buf, "{s}/acme-state", .{tmp.sub_path[0..]});
    const current_dir = try std.fmt.bufPrint(&current_dir_buf, "{s}/cert/current", .{state_dir});
    try std.Io.Dir.cwd().createDirPath(std.Options.debug_io, current_dir);

    var cert_path_buf: [1024]u8 = undefined;
    var key_path_buf: [1024]u8 = undefined;
    const cert_path = try std.fmt.bufPrint(&cert_path_buf, "{s}/fullchain.pem", .{current_dir});
    const key_path = try std.fmt.bufPrint(&key_path_buf, "{s}/privkey.pem", .{current_dir});

    try std.Io.Dir.cwd().writeFile(std.Options.debug_io, .{ .sub_path = cert_path, .data = "CERT\n" });
    try std.Io.Dir.cwd().writeFile(std.Options.debug_io, .{ .sub_path = key_path, .data = "KEY\n" });

    const cfg = ir.AcmeTlsConfig{
        .directory_url = "https://acme-v02.api.letsencrypt.org/directory",
        .contact_email = "ops@example.com",
        .state_dir_path = state_dir,
        .domain = "example.com",
    };
    var service = try Provider.init(cfg, "l1");
    defer service.deinit();

    var io_threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_threaded.deinit();

    const initial = try service.loadInitial(io_threaded.io());
    try std.testing.expectEqualStrings(cert_path, initial.cert_path);
    try std.testing.expectEqualStrings(key_path, initial.key_path);
}

test "acme provider loadInitial bootstraps selfsigned when current cert missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var state_dir_buf: [1024]u8 = undefined;
    const state_dir = try std.fmt.bufPrint(&state_dir_buf, "{s}/acme-state", .{tmp.sub_path[0..]});

    const cfg = ir.AcmeTlsConfig{
        .directory_url = "https://acme-v02.api.letsencrypt.org/directory",
        .contact_email = "ops@example.com",
        .state_dir_path = state_dir,
        .domain = "example.com",
    };
    var service = try Provider.init(cfg, "listener-a");
    defer service.deinit();

    var io_threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_threaded.deinit();

    const initial = try service.loadInitial(io_threaded.io());
    try std.testing.expect(std.mem.indexOf(u8, initial.cert_path, "/listeners/listener-a/selfsigned/") != null);
    try std.testing.expect(std.mem.indexOf(u8, initial.key_path, "/listeners/listener-a/selfsigned/") != null);

    var cert_read_buf: [16384]u8 = undefined;
    const cert_read = try std.Io.Dir.cwd().readFile(std.Options.debug_io, initial.cert_path, &cert_read_buf);
    try std.testing.expect(std.mem.indexOf(u8, cert_read, "BEGIN CERTIFICATE") != null);

    var key_read_buf: [16384]u8 = undefined;
    const key_read = try std.Io.Dir.cwd().readFile(std.Options.debug_io, initial.key_path, &key_read_buf);
    try std.testing.expect(std.mem.indexOf(u8, key_read, "BEGIN EC PRIVATE KEY") != null);
}
