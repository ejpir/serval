// lib/serval-tls/stream.zig
//! TLS stream abstraction
//!
//! Provides unified interface for TLS I/O operations.
//! Phase 1: Userspace-only implementation (kTLS deferred).
//! Will be implemented in Task 3.

const std = @import("std");
const ssl = @import("ssl.zig");

pub const TlsStream = struct {
    // Placeholder - will be implemented in Task 3
    // This file exists to satisfy module structure
    // and allow compilation of mod.zig

    dummy: u8 = 0,
};
