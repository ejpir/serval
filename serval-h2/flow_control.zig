//! HTTP/2 Flow-Control Helpers
//!
//! Explicit bounded window accounting for connection-level and stream-level
//! HTTP/2 flow control.
//! TigerStyle: Fixed-size state, explicit overflow/underflow checks, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;

/// Errors returned by HTTP/2 flow-control window operations.
/// `InvalidInitialWindowSize` and `InvalidIncrement` report rejected inputs when
/// initializing or updating a window.
/// `WindowUnderflow` is returned when consuming more bytes than available, and
/// `WindowOverflow` when an update would exceed the configured maximum window size.
pub const Error = error{
    InvalidInitialWindowSize,
    InvalidIncrement,
    WindowUnderflow,
    WindowOverflow,
};

/// Represents the available byte count for an HTTP/2 flow-control window.
/// The value is always kept within `0..=config.H2_MAX_WINDOW_SIZE_BYTES` by the public methods.
/// Use `init`, `consume`, `increment`, and `set` to manage the window; each method reports invalid sizes and overflow or underflow conditions.
pub const Window = struct {
    available_bytes: u32,

    /// Creates a flow-control window with `initial_bytes` available.
    /// `initial_bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`; larger values are rejected.
    /// Returns `error.InvalidInitialWindowSize` when the requested size is above the configured maximum.
    pub fn init(initial_bytes: u32) Error!Window {
        assert(config.H2_MAX_WINDOW_SIZE_BYTES > 0);
        assert(config.H2_INITIAL_WINDOW_SIZE_BYTES <= config.H2_MAX_WINDOW_SIZE_BYTES);
        if (initial_bytes > config.H2_MAX_WINDOW_SIZE_BYTES) {
            return error.InvalidInitialWindowSize;
        }
        return .{ .available_bytes = initial_bytes };
    }

    /// Decreases the available bytes in a flow-control window by `bytes`.
    /// `bytes` must be less than or equal to the current `available_bytes` in `self`.
    /// Returns `error.WindowUnderflow` if the subtraction would make the window negative.
    pub fn consume(self: *Window, bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);

        if (bytes > self.available_bytes) return error.WindowUnderflow;
        self.available_bytes -= bytes;
    }

    /// Increases the available bytes in a flow-control window by `delta_bytes`.
    /// `delta_bytes` must be non-zero, and the addition must stay within `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// Returns `error.InvalidIncrement` for zero deltas and `error.WindowOverflow` if the window would exceed the configured maximum.
    pub fn increment(self: *Window, delta_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);

        if (delta_bytes == 0) return error.InvalidIncrement;
        const next: u64 = @as(u64, self.available_bytes) + delta_bytes;
        if (next > config.H2_MAX_WINDOW_SIZE_BYTES) return error.WindowOverflow;
        self.available_bytes = @intCast(next);
    }

    /// Sets the available bytes in a flow-control window to `new_bytes`.
    /// `self` must point to a valid `Window`, and `new_bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`.
    /// Returns `error.InvalidInitialWindowSize` when the requested size is above the configured maximum.
    pub fn set(self: *Window, new_bytes: u32) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.available_bytes <= config.H2_MAX_WINDOW_SIZE_BYTES);
        if (new_bytes > config.H2_MAX_WINDOW_SIZE_BYTES) {
            return error.InvalidInitialWindowSize;
        }
        self.available_bytes = new_bytes;
    }
};

/// Tracks HTTP/2 connection flow control for both directions.
/// `recv_window` limits bytes the peer may send; `send_window` limits bytes this endpoint may send.
/// Use `ConnectionFlowControl.init` to construct a value with both windows initialized to the same size.
pub const ConnectionFlowControl = struct {
    recv_window: Window,
    send_window: Window,

    /// Creates a connection-level flow-control state with matching receive and send windows.
    /// `initial_bytes` must not exceed `config.H2_MAX_WINDOW_SIZE_BYTES`; the function asserts that bound.
    /// Returns a fully initialized `ConnectionFlowControl` or propagates `error.InvalidInitialWindowSize` / window initialization errors from `Window.init`.
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
