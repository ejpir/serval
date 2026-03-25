//! Failure classification and protocol-correct terminal actions.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const ir = @import("ir.zig");

pub const FailurePhase = enum(u8) {
    request_headers,
    request_body,
    response_headers,
    response_body,
};

pub const FailureSource = enum(u8) {
    plugin_error,
    upstream_read_error,
    downstream_write_error,
    backpressure_timeout,
};

pub const TerminalAction = enum(u8) {
    send_error_response,
    close_h1_connection,
    reset_h2_stream,
    sticky_bypass_plugin,
};

pub const FailureDecision = struct {
    action: TerminalAction,
    sticky_bypass_active: bool,
};

pub fn classifyFailure(
    protocol: core.HttpProtocol,
    phase: FailurePhase,
    source: FailureSource,
    policy: ir.FailurePolicy,
    headers_sent: bool,
) FailureDecision {
    assert(@intFromEnum(protocol) <= @intFromEnum(core.HttpProtocol.h2));
    assert(@intFromEnum(phase) <= @intFromEnum(FailurePhase.response_body));
    assert(@intFromEnum(source) <= @intFromEnum(FailureSource.backpressure_timeout));

    if (source == .plugin_error and policy == .fail_open and isStickyBypassSafe(phase, headers_sent)) {
        return .{ .action = .sticky_bypass_plugin, .sticky_bypass_active = true };
    }

    if (!headers_sent and (source == .plugin_error or source == .upstream_read_error)) {
        return .{ .action = .send_error_response, .sticky_bypass_active = false };
    }

    return .{
        .action = protocolTerminalAction(protocol),
        .sticky_bypass_active = false,
    };
}

pub fn isStickyBypassSafe(phase: FailurePhase, headers_sent: bool) bool {
    assert(@intFromEnum(phase) <= @intFromEnum(FailurePhase.response_body));

    if (!headers_sent) return true;
    return switch (phase) {
        .request_headers => true,
        .request_body, .response_headers, .response_body => false,
    };
}

fn protocolTerminalAction(protocol: core.HttpProtocol) TerminalAction {
    return switch (protocol) {
        .h1 => .close_h1_connection,
        .h2, .h2c => .reset_h2_stream,
    };
}

test "plugin fail-open enables sticky bypass only when safe" {
    const safe = classifyFailure(.h1, .request_headers, .plugin_error, .fail_open, false);
    try std.testing.expectEqual(TerminalAction.sticky_bypass_plugin, safe.action);
    try std.testing.expect(safe.sticky_bypass_active);

    const unsafe = classifyFailure(.h1, .response_body, .plugin_error, .fail_open, true);
    try std.testing.expectEqual(TerminalAction.close_h1_connection, unsafe.action);
    try std.testing.expect(!unsafe.sticky_bypass_active);
}

test "mid-stream failure uses protocol-correct terminal actions" {
    const h1_decision = classifyFailure(.h1, .response_body, .plugin_error, .fail_closed, true);
    try std.testing.expectEqual(TerminalAction.close_h1_connection, h1_decision.action);

    const h2_decision = classifyFailure(.h2, .response_body, .plugin_error, .fail_closed, true);
    try std.testing.expectEqual(TerminalAction.reset_h2_stream, h2_decision.action);
}

test "pre-header upstream error returns explicit error response action" {
    const decision = classifyFailure(.h1, .request_headers, .upstream_read_error, .fail_closed, false);
    try std.testing.expectEqual(TerminalAction.send_error_response, decision.action);
    try std.testing.expect(!decision.sticky_bypass_active);
}
