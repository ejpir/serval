//! Frontend protocol dispatch helpers.
//!
//! Centralizes ALPN/preface routing decisions so protocol selection does not
//! live in protocol-specific drivers.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const TLSStream = @import("serval-tls").TLSStream;

pub const TlsDispatchAction = enum {
    continue_h1,
    generic_h2,
    terminated_h2,
};

pub fn selectTlsAlpnDispatchAction(
    maybe_tls: ?*TLSStream,
    frontend_mode: config.TlsH2FrontendMode,
    has_terminated_h2_handler: bool,
) TlsDispatchAction {
    const alpn = if (maybe_tls) |tls_stream| tls_stream.info.alpn() else null;
    return selectTlsAlpnDispatchActionFromAlpn(alpn, frontend_mode, has_terminated_h2_handler);
}

pub fn selectTlsAlpnDispatchActionFromAlpn(
    alpn: ?[]const u8,
    frontend_mode: config.TlsH2FrontendMode,
    has_terminated_h2_handler: bool,
) TlsDispatchAction {
    if (frontend_mode == .disabled) return .continue_h1;

    const negotiated = alpn orelse return .continue_h1;
    if (!std.mem.eql(u8, negotiated, "h2")) return .continue_h1;

    if (frontend_mode == .generic and !has_terminated_h2_handler) {
        return .generic_h2;
    }

    if (has_terminated_h2_handler and frontend_mode != .disabled) {
        return .terminated_h2;
    }

    return .continue_h1;
}

test "selectTlsAlpnDispatchAction keeps h1 when tls absent" {
    const action = selectTlsAlpnDispatchActionFromAlpn(null, .generic, true);
    try std.testing.expectEqual(TlsDispatchAction.continue_h1, action);
}

test "selectTlsAlpnDispatchAction keeps h1 when mode disabled" {
    const action = selectTlsAlpnDispatchActionFromAlpn("h2", .disabled, true);
    try std.testing.expectEqual(TlsDispatchAction.continue_h1, action);
}

test "selectTlsAlpnDispatchAction routes generic h2 without terminated hooks" {
    const action = selectTlsAlpnDispatchActionFromAlpn("h2", .generic, false);
    try std.testing.expectEqual(TlsDispatchAction.generic_h2, action);
}

test "selectTlsAlpnDispatchAction routes terminated h2 when hooks exist" {
    const action = selectTlsAlpnDispatchActionFromAlpn("h2", .terminated_only, true);
    try std.testing.expectEqual(TlsDispatchAction.terminated_h2, action);
}
