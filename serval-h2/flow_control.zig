//! HTTP/2 Flow-Control Helpers
//!
//! Explicit bounded window accounting for connection-level and stream-level
//! HTTP/2 flow control.
//! TigerStyle: Fixed-size state, explicit overflow/underflow checks, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

pub const Error = error{
    InvalidInitialWindowSize,
    InvalidIncrement,
    WindowUnderflow,
    WindowOverflow,
};

pub const Window = struct {
    available_bytes: u32,

    pub fn init(initial_bytes: u32) Error!Window {
        assert(config.H2_MAX_WINDOW_SIZE_BYTES > 0);
        assert(config.H2_INITIAL_WINDOW_SIZE_BYTES <= config.H2_MAX_WINDOW_SIZE_BYTES);
        if (initial_bytes > config.H2_MAX_WINDOW_SIZE_BYTES) {
            return error.InvalidInitialWindowSize;
        }
        return .{ .available_bytes = initial_bytes };
    }

    pub fn consume(self: *Window, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);

        if (bytes > self.available_bytes) return error.WindowUnderflow;
        self.available_bytes -= bytes;
    }

    pub fn increment(self: *Window, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);

        if (delta_bytes == 0) return error.InvalidIncrement;
        const next: u64 = @as(u64, self.available_bytes) + delta_bytes;
        if (next > config.H2_MAX_WINDOW_SIZE_BYTES) return error.WindowOverflow;
        self.available_bytes = @intCast(next);
    }

    pub fn set(self: *Window, new_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        if (new_bytes > config.H2_MAX_WINDOW_SIZE_BYTES) {
            return error.InvalidInitialWindowSize;
        }
        self.available_bytes = new_bytes;
    }
};

pub const ConnectionFlowControl = struct {
    recv_window: Window,
    send_window: Window,

    pub fn init(initial_bytes: u32) Error!ConnectionFlowControl {
        assert(initial_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        assert(config.H2_CONNECTION_WINDOW_SIZE_BYTES <= config.H2_MAX_WINDOW_SIZE_BYTES);
        const recv_window = try Window.init(initial_bytes);
        const send_window = try Window.init(initial_bytes);
        return .{
            .recv_window = recv_window,
            .send_window = send_window,
        };
    }
};

test "Window init accepts RFC default" {
    const window = try Window.init(config.H2_INITIAL_WINDOW_SIZE_BYTES);
    try std.testing.expectEqual(config.H2_INITIAL_WINDOW_SIZE_BYTES, window.available_bytes);
}

test "Window consume decrements available bytes" {
    var window = try Window.init(1024);
    try window.consume(512);
    try std.testing.expectEqual(@as(u32, 512), window.available_bytes);
}

test "Window consume rejects underflow" {
    var window = try Window.init(64);
    try std.testing.expectError(error.WindowUnderflow, window.consume(65));
}

test "Window increment rejects zero delta" {
    var window = try Window.init(64);
    try std.testing.expectError(error.InvalidIncrement, window.increment(0));
}

test "Window increment rejects overflow" {
    var window = try Window.init(config.H2_MAX_WINDOW_SIZE_BYTES);
    try std.testing.expectError(error.WindowOverflow, window.increment(1));
}

test "Window set enforces max size" {
    var window = try Window.init(1);
    try std.testing.expectError(error.InvalidInitialWindowSize, window.set(config.H2_MAX_WINDOW_SIZE_BYTES + 1));
}

test "ConnectionFlowControl initializes send and recv windows" {
    const flow = try ConnectionFlowControl.init(config.H2_CONNECTION_WINDOW_SIZE_BYTES);
    try std.testing.expectEqual(config.H2_CONNECTION_WINDOW_SIZE_BYTES, flow.recv_window.available_bytes);
    try std.testing.expectEqual(config.H2_CONNECTION_WINDOW_SIZE_BYTES, flow.send_window.available_bytes);
}
