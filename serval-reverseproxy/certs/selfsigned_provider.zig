const std = @import("std");
const assert = std.debug.assert;
const acme = @import("serval-acme");
const ir = @import("../ir.zig");
const provider = @import("provider.zig");

const cert_path_buf_size_bytes: u16 = 1024;
const key_path_buf_size_bytes: u16 = 1024;
const cert_pem_buf_size_bytes: u16 = 8192;
const key_pem_buf_size_bytes: u16 = 4096;

/// Errors returned by the self-signed certificate provider.
/// `InvalidConfig` indicates required configuration values were empty.
/// `PathTooLong`, `CreateDirFailed`, `GenerateFailed`, and `WriteFailed` report path construction, directory creation, certificate generation, and file-write failures.
pub const Error = error{
    InvalidConfig,
    PathTooLong,
    CreateDirFailed,
    GenerateFailed,
    WriteFailed,
};

/// Provider state for self-signed TLS certificate management.
/// Stores the configuration, listener identifier, and precomputed certificate/key paths in fixed-size buffers.
/// Use `init` to construct a value, `loadInitial` to obtain or create certificate material, and `deinit` to finish the lifecycle.
pub const Provider = struct {
    cfg: ir.SelfSignedTlsConfig,
    listener_id: []const u8,

    cert_path_len: u16,
    cert_path_bytes: [cert_path_buf_size_bytes]u8,

    key_path_len: u16,
    key_path_bytes: [key_path_buf_size_bytes]u8,

    /// Initialize a self-signed TLS provider for one listener.
    /// `cfg.state_dir_path` and `cfg.domain` must be non-empty, and `listener_id` must not be empty.
    /// Builds the certificate and key paths under `<state_dir>/listeners/<listener_id>/selfsigned/`.
    /// Returns `error.InvalidConfig` if required config fields are missing, or `error.PathTooLong` if either path does not fit.
    pub fn init(cfg: ir.SelfSignedTlsConfig, listener_id: []const u8) Error!Provider {
        assert(listener_id.len > 0);
        if (cfg.state_dir_path.len == 0 or cfg.domain.len == 0) return error.InvalidConfig;

        var service = Provider{
            .cfg = cfg,
            .listener_id = listener_id,
            .cert_path_len = 0,
            .cert_path_bytes = undefined,
            .key_path_len = 0,
            .key_path_bytes = undefined,
        };

        const cert_path = std.fmt.bufPrint(
            &service.cert_path_bytes,
            "{s}/listeners/{s}/selfsigned/fullchain.pem",
            .{ cfg.state_dir_path, listener_id },
        ) catch return error.PathTooLong;
        service.cert_path_len = @intCast(cert_path.len);

        const key_path = std.fmt.bufPrint(
            &service.key_path_bytes,
            "{s}/listeners/{s}/selfsigned/privkey.pem",
            .{ cfg.state_dir_path, listener_id },
        ) catch return error.PathTooLong;
        service.key_path_len = @intCast(key_path.len);

        return service;
    }

    /// Release any resources associated with the provider.
    /// The provider stores fixed-size path buffers and does not allocate heap memory here.
    /// Call this when the provider is no longer needed.
    pub fn deinit(self: *Provider) void {
        assert(@intFromPtr(self) != 0);
        assert(self.cert_path_len <= cert_path_buf_size_bytes);
    }

    /// Load the initial certificate material for this provider.
    /// Reuses existing certificate and key files when `rotate_on_boot` is disabled and both paths already exist.
    /// Otherwise generates new PEM material, creates the parent directory, and writes both files before returning their paths.
    /// Returns `error.PathTooLong`, `error.CreateDirFailed`, `error.GenerateFailed`, or `error.WriteFailed` on failure.
    pub fn loadInitial(self: *Provider, io: std.Io) Error!provider.CertMaterial {
        assert(@intFromPtr(self) != 0);
        assert(self.key_path_len <= key_path_buf_size_bytes);

        const cert_path = self.certPath();
        const key_path = self.keyPath();

        if (!self.cfg.rotate_on_boot and fileExists(cert_path) and fileExists(key_path)) {
            return .{ .cert_path = cert_path, .key_path = key_path };
        }

        const cert_parent = std.fs.path.dirname(cert_path) orelse return error.PathTooLong;
        std.Io.Dir.cwd().createDirPath(std.Options.debug_io, cert_parent) catch return error.CreateDirFailed;

        var cert_pem_buf: [cert_pem_buf_size_bytes]u8 = undefined;
        var key_pem_buf: [key_pem_buf_size_bytes]u8 = undefined;
        const materials = acme.bootstrap_cert.generateMaterials(io, self.cfg.domain, &cert_pem_buf, &key_pem_buf) catch {
            return error.GenerateFailed;
        };

        std.Io.Dir.cwd().writeFile(std.Options.debug_io, .{ .sub_path = cert_path, .data = materials.cert_pem }) catch {
            return error.WriteFailed;
        };
        std.Io.Dir.cwd().writeFile(std.Options.debug_io, .{ .sub_path = key_path, .data = materials.key_pem }) catch {
            return error.WriteFailed;
        };

        return .{ .cert_path = cert_path, .key_path = key_path };
    }

    /// Run the self-signed certificate provider lifecycle hook.
    /// This implementation does not perform any background work and ignores all inputs.
    /// The provider is activated through `loadInitial`; `run` returns immediately.
    pub fn run(
        self: *Provider,
        shutdown: *std.atomic.Value(bool),
        activate_ctx: *anyopaque,
        activate_fn: provider.ActivateFn,
    ) void {
        _ = self;
        _ = shutdown;
        _ = activate_ctx;
        _ = activate_fn;
    }

    fn certPath(self: *const Provider) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.cert_path_len <= cert_path_buf_size_bytes);
        return self.cert_path_bytes[0..self.cert_path_len];
    }

    fn keyPath(self: *const Provider) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.key_path_len <= key_path_buf_size_bytes);
        return self.key_path_bytes[0..self.key_path_len];
    }
};

fn fileExists(path: []const u8) bool {
    assert(path.len > 0);
    var read_buf: [16384]u8 = undefined;
    _ = std.Io.Dir.cwd().readFile(std.Options.debug_io, path, &read_buf) catch return false;
    return true;
}
