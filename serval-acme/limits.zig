//! Internal ACME implementation limits owned by `serval-acme`.
//!
//! These bounds size parser scratch, serializer output, bounded polling, and
//! other ACME-specific runtime machinery. Deployment-facing schema defaults stay
//! in `serval-core.config`; owner-internal capacities live here.

const std = @import("std");

pub const max_active_challenges: u8 = 64;
pub const max_poll_attempts: u16 = 120;
pub const max_transitions_per_tick: u8 = 32;

pub const max_http01_token_bytes: u16 = 128;
pub const max_http01_key_authorization_bytes: u16 = 512;
pub const max_nonce_bytes: u16 = 512;

pub const max_directory_response_bytes: u32 = 64 * 1024;
pub const max_account_response_bytes: u32 = 64 * 1024;
pub const max_order_response_bytes: u32 = 128 * 1024;

pub const max_jws_body_bytes: u32 = 64 * 1024;
pub const max_jws_signature_bytes: u16 = 512;

pub const max_authorization_urls_per_order: u8 = 16;

comptime {
    if (max_active_challenges == 0) {
        @compileError("serval-acme.limits.max_active_challenges must be > 0");
    }
    if (max_poll_attempts == 0) {
        @compileError("serval-acme.limits.max_poll_attempts must be > 0");
    }
    if (max_transitions_per_tick == 0) {
        @compileError("serval-acme.limits.max_transitions_per_tick must be > 0");
    }
    if (max_http01_token_bytes == 0) {
        @compileError("serval-acme.limits.max_http01_token_bytes must be > 0");
    }
    if (max_http01_key_authorization_bytes == 0) {
        @compileError("serval-acme.limits.max_http01_key_authorization_bytes must be > 0");
    }
    if (max_nonce_bytes == 0) {
        @compileError("serval-acme.limits.max_nonce_bytes must be > 0");
    }
    if (max_directory_response_bytes == 0) {
        @compileError("serval-acme.limits.max_directory_response_bytes must be > 0");
    }
    if (max_account_response_bytes == 0) {
        @compileError("serval-acme.limits.max_account_response_bytes must be > 0");
    }
    if (max_order_response_bytes == 0) {
        @compileError("serval-acme.limits.max_order_response_bytes must be > 0");
    }
    if (max_jws_body_bytes == 0) {
        @compileError("serval-acme.limits.max_jws_body_bytes must be > 0");
    }
    if (max_jws_signature_bytes == 0) {
        @compileError("serval-acme.limits.max_jws_signature_bytes must be > 0");
    }
    if (max_authorization_urls_per_order == 0) {
        @compileError("serval-acme.limits.max_authorization_urls_per_order must be > 0");
    }
    if (max_authorization_urls_per_order > std.math.maxInt(u8)) {
        @compileError("serval-acme.limits.max_authorization_urls_per_order must fit in u8");
    }
}
