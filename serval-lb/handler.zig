// lib/serval-lb/handler.zig
//! Load Balancer Handler
//!
//! Round-robin upstream selection for serval server.
//! TigerStyle: No allocation, simple selection logic.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");

const Context = core.Context;
const Request = core.Request;
const Upstream = core.Upstream;

pub const LbHandler = struct {
    upstreams: []const Upstream,
    /// Atomic counter for thread-safe round-robin selection.
    /// TigerStyle: Atomic over mutex for simple counter operations.
    next_idx: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Initialize the load balancer with a list of upstreams.
    /// Upstreams slice must have at least one element.
    pub fn init(upstreams: []const Upstream) LbHandler {
        assert(upstreams.len > 0);
        return .{ .upstreams = upstreams };
    }

    /// Select next upstream using round-robin.
    /// Cycles through upstreams in order, wrapping at the end.
    /// TigerStyle: Thread-safe via atomic fetchAdd, no mutex overhead.
    pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) Upstream {
        _ = ctx;
        _ = request;
        assert(self.upstreams.len > 0);

        // Atomically get and increment counter
        // TigerStyle: .monotonic ordering sufficient for counter, no ordering constraints.
        const current = self.next_idx.fetchAdd(1, .monotonic);
        const idx = current % @as(u32, @intCast(self.upstreams.len));

        return self.upstreams[idx];
    }
};

// =============================================================================
// Tests
// =============================================================================

test "LbHandler round-robin cycles through upstreams" {
    const upstreams = [_]Upstream{
        .{ .host = "backend1", .port = 8001, .idx = 0 },
        .{ .host = "backend2", .port = 8002, .idx = 1 },
        .{ .host = "backend3", .port = 8003, .idx = 2 },
    };

    var handler = LbHandler.init(&upstreams);
    var ctx = Context.init();
    const request = Request{};

    // First cycle
    const first = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqualStrings("backend1", first.host);
    try std.testing.expectEqual(@as(u16, 8001), first.port);

    const second = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqualStrings("backend2", second.host);
    try std.testing.expectEqual(@as(u16, 8002), second.port);

    const third = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqualStrings("backend3", third.host);
    try std.testing.expectEqual(@as(u16, 8003), third.port);

    // Wraps around
    const fourth = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqualStrings("backend1", fourth.host);
    try std.testing.expectEqual(@as(u16, 8001), fourth.port);
}

test "LbHandler single upstream always returns same" {
    const upstreams = [_]Upstream{
        .{ .host = "single-backend", .port = 9000, .idx = 0 },
    };

    var handler = LbHandler.init(&upstreams);
    var ctx = Context.init();
    const request = Request{};

    // Call multiple times, should always return the same upstream
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const upstream = handler.selectUpstream(&ctx, &request);
        try std.testing.expectEqualStrings("single-backend", upstream.host);
        try std.testing.expectEqual(@as(u16, 9000), upstream.port);
    }
}

test "LbHandler wrapping counter handles overflow" {
    const upstreams = [_]Upstream{
        .{ .host = "backend1", .port = 8001, .idx = 0 },
        .{ .host = "backend2", .port = 8002, .idx = 1 },
    };

    var handler = LbHandler.init(&upstreams);
    var ctx = Context.init();
    const request = Request{};

    // Set counter near max to test wraparound
    // TigerStyle: Use .store for atomic field initialization in tests.
    handler.next_idx.store(std.math.maxInt(u32), .monotonic);

    const first = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqualStrings("backend2", first.host);

    // Counter wrapped to 0
    const second = handler.selectUpstream(&ctx, &request);
    try std.testing.expectEqualStrings("backend1", second.host);
}
