// examples/router/backends.zig
//! Backend Parsing Utilities
//!
//! Parse CLI backend strings into Upstream arrays.
//! TigerStyle: Bounded loop, no allocation after init.

const std = @import("std");
const serval = @import("serval");
const serval_router = @import("serval-router");

const Upstream = serval_router.Upstream;
const UpstreamIndex = serval.config.UpstreamIndex;

/// Maximum number of upstreams per pool from CLI.
pub const MAX_UPSTREAMS_PER_POOL: u8 = 100;

/// Parse backends string into Upstream array with sequential idx starting at base_idx.
/// Format: "host:port,host:port,..."
/// TigerStyle: Bounded loop, count only increments on successful parse.
pub fn parseBackends(
    backends_str: []const u8,
    upstreams: *[MAX_UPSTREAMS_PER_POOL]Upstream,
    base_idx: UpstreamIndex,
) UpstreamIndex {
    var count: UpstreamIndex = 0;
    var iter = std.mem.splitScalar(u8, backends_str, ',');

    // Bounded iteration - use count directly, MAX_UPSTREAMS_PER_POOL-1 is max valid index
    while (count < MAX_UPSTREAMS_PER_POOL) {
        const backend = iter.next() orelse break;

        // Find the colon separator
        const colon_pos = std.mem.lastIndexOfScalar(u8, backend, ':') orelse {
            std.debug.print("Invalid backend format (missing port): {s}\n", .{backend});
            continue;
        };

        const host = backend[0..colon_pos];
        const port_str = backend[colon_pos + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch {
            std.debug.print("Invalid port number: {s}\n", .{port_str});
            continue;
        };

        upstreams[count] = .{
            .host = host,
            .port = port,
            .idx = base_idx + count,
            .tls = false,
        };
        count += 1;
    }

    return count;
}

/// Format upstream list for display.
/// TigerStyle: Bounded loop.
pub fn formatUpstreams(upstreams: []const Upstream) void {
    std.debug.print("[", .{});
    for (upstreams, 0..) |upstream, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s}:{d}", .{ upstream.host, upstream.port });
    }
    std.debug.print("]", .{});
}
