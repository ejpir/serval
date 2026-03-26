const std = @import("std");

pub const ActivationResult = enum(u8) {
    success,
    transient_failure,
    fatal_failure,
};

pub const CertMaterial = struct {
    cert_path: []const u8,
    key_path: []const u8,
};

pub const ActivateFn = *const fn (
    ctx: *anyopaque,
    cert_path: []const u8,
    key_path: []const u8,
) ActivationResult;
