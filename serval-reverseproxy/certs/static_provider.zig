const std = @import("std");
const assert = std.debug.assert;
const ir = @import("../ir.zig");
const provider = @import("provider.zig");

pub const Error = error{
    InvalidStaticConfig,
};

pub const Provider = struct {
    cfg: ir.StaticTlsConfig,

    pub fn init(cfg: ir.StaticTlsConfig) Error!Provider {
        if (cfg.cert_path.len == 0 or cfg.key_path.len == 0) return error.InvalidStaticConfig;
        return .{ .cfg = cfg };
    }

    pub fn deinit(self: *Provider) void {
        assert(@intFromPtr(self) != 0);
    }

    pub fn loadInitial(self: *Provider) provider.CertMaterial {
        assert(@intFromPtr(self) != 0);
        return .{ .cert_path = self.cfg.cert_path, .key_path = self.cfg.key_path };
    }

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
};
