// lib/serval-core/context.zig
//! Per-Request Context
//!
//! Passed to all handler hooks. Allows sharing state within request lifecycle.
//! TigerStyle: Fixed-size, no allocation.

const std = @import("std");
const types = @import("types.zig");
const time = @import("time.zig");
const span_handle_mod = @import("span_handle.zig");
const Upstream = types.Upstream;
const SpanHandle = span_handle_mod.SpanHandle;

pub const Context = struct {
    // Timing - i128 matches std.time.Instant.timestamp/realtimeNanos() return type,
    // which can represent nanoseconds since epoch including pre-1970 dates.
    start_time_ns: i128 = 0,

    // Request metadata
    request_id: u64 = 0,

    // User-defined storage - caller owns lifetime; must remain valid for request duration.
    // Server does not free or manage this pointer.
    user_data: ?*anyopaque = null,

    // Set after selectUpstream
    upstream: ?Upstream = null,

    // Metrics (updated by server)
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,

    // Response status (set after response)
    response_status: u16 = 0,
    duration_ns: u64 = 0,

    // Error tracking - points to comptime string literal from @errorName().
    // Valid for program lifetime (static string table).
    error_name: ?[]const u8 = null,

    // Connection-scoped fields (set once per connection, preserved across requests)
    connection_id: u64 = 0,
    connection_start_ns: i128 = 0,
    request_number: u32 = 0,
    client_addr: [46]u8 = std.mem.zeroes([46]u8),
    client_port: u16 = 0,

    // Request timing
    parse_duration_ns: u64 = 0,

    // Tracing - span handle for the current request
    // Set by server, can be used by handlers to create child spans.
    // TigerStyle: Fixed-size (32 bytes), no allocation.
    span_handle: SpanHandle = .{},

    pub fn init() Context {
        const ctx = Context{
            .start_time_ns = time.realtimeNanos(),
        };

        // Postcondition: time must be valid (realtimeNanos always returns positive nanoseconds)
        std.debug.assert(ctx.start_time_ns > 0);

        return ctx;
    }

    /// Reset context for a new request while preserving connection-scoped fields.
    /// Connection-scoped fields (connection_id, connection_start_ns, client_addr,
    /// client_port) are preserved. Per-request fields are reset, and request_number
    /// is incremented.
    pub fn reset(self: *Context) void {
        // Preserve connection-scoped fields
        const connection_id = self.connection_id;
        const connection_start_ns = self.connection_start_ns;
        const client_addr = self.client_addr;
        const client_port = self.client_port;
        const request_number = self.request_number;

        // Reset all fields to defaults
        self.* = .{
            .start_time_ns = time.realtimeNanos(),
        };

        // Restore connection-scoped fields
        self.connection_id = connection_id;
        self.connection_start_ns = connection_start_ns;
        self.client_addr = client_addr;
        self.client_port = client_port;
        self.request_number = request_number + 1;

        // Postcondition: connection-scoped fields preserved, per-request fields reset
        std.debug.assert(self.connection_id == connection_id);
        std.debug.assert(self.bytes_received == 0 and self.response_status == 0);
    }
};

test "Context init" {
    const ctx = Context.init();
    try std.testing.expect(ctx.start_time_ns > 0);
    try std.testing.expectEqual(@as(?Upstream, null), ctx.upstream);
}

test "Context reset preserves connection-scoped fields" {
    var ctx = Context.init();

    // Set connection-scoped fields
    ctx.connection_id = 12345;
    ctx.connection_start_ns = 9999;
    ctx.client_addr[0] = '1';
    ctx.client_addr[1] = '2';
    ctx.client_addr[2] = '7';
    ctx.client_port = 8080;
    ctx.request_number = 5;

    // Set per-request fields that should be reset
    ctx.bytes_received = 1000;
    ctx.parse_duration_ns = 500;
    ctx.response_status = 200;

    // Reset for new request
    ctx.reset();

    // Connection-scoped fields should be preserved
    try std.testing.expectEqual(@as(u64, 12345), ctx.connection_id);
    try std.testing.expectEqual(@as(i128, 9999), ctx.connection_start_ns);
    try std.testing.expectEqual(@as(u8, '1'), ctx.client_addr[0]);
    try std.testing.expectEqual(@as(u8, '2'), ctx.client_addr[1]);
    try std.testing.expectEqual(@as(u8, '7'), ctx.client_addr[2]);
    try std.testing.expectEqual(@as(u16, 8080), ctx.client_port);

    // Request number should be incremented
    try std.testing.expectEqual(@as(u32, 6), ctx.request_number);

    // Per-request fields should be reset
    try std.testing.expectEqual(@as(u64, 0), ctx.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), ctx.parse_duration_ns);
    try std.testing.expectEqual(@as(u16, 0), ctx.response_status);

    // Start time should be refreshed
    try std.testing.expect(ctx.start_time_ns > 0);
}
