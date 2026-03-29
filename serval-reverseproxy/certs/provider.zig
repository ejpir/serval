const std = @import("std");

/// Result of attempting to activate certificate material.
/// `success` indicates the activation completed, `transient_failure` indicates the operation may succeed if retried, and `fatal_failure` indicates a non-recoverable failure for the current input or state.
/// This enum is used by activation callbacks to communicate retryability without raising an error.
pub const ActivationResult = enum(u8) {
    success,
    transient_failure,
    fatal_failure,
};

/// Paths identifying the certificate material and matching private key to activate.
/// Both fields are borrowed slices; this type does not own or copy the referenced data.
/// Callers must keep the paths valid for as long as they are needed by the consumer.
pub const CertMaterial = struct {
    cert_path: []const u8,
    key_path: []const u8,
};

/// Callback used to activate a certificate/key pair at `cert_path` and `key_path`.
/// `ctx` must point to the provider-specific state expected by the implementation, and both paths are borrowed for the duration of the call.
/// The callback does not take ownership of either path and reports the outcome via `ActivationResult`.
pub const ActivateFn = *const fn (
    ctx: *anyopaque,
    cert_path: []const u8,
    key_path: []const u8,
) ActivationResult;
