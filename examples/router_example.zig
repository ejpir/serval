// examples/router_example.zig
//! Content-Based Router Example
//!
//! Demonstrates serval with Router for content-based routing with multiple backend pools.
//! Routes requests to different pools based on path prefix matching.
//!
//! Usage:
//!   router_example [OPTIONS]
//!
//! Options:
//!   --port <PORT>                Listening port (default: 8080)
//!   --api-backends <HOSTS>       Comma-separated API backend addresses (default: 127.0.0.1:8001)
//!   --static-backends <HOSTS>    Comma-separated static backend addresses (default: 127.0.0.1:8002)
//!   --debug                      Enable debug logging
//!   --help                       Show help message
//!   --version                    Show version

const std = @import("std");
const serval = @import("serval");
const serval_router = @import("serval-router");
const serval_net = @import("serval-net");
const cli = @import("serval-cli");

const DnsConfig = serval_net.DnsConfig;
const Router = serval_router.Router;
const Route = serval_router.Route;
const PoolConfig = serval_router.PoolConfig;
const Upstream = serval_router.Upstream;

/// Version of this binary.
const VERSION = "0.1.0";

/// Router-specific CLI options.
const RouterExtra = struct {
    /// Comma-separated list of API backend addresses (host:port,host:port,...)
    @"api-backends": []const u8 = "127.0.0.1:8001",
    /// Comma-separated list of static backend addresses (host:port,host:port,...)
    @"static-backends": []const u8 = "127.0.0.1:8002",
};

/// Maximum number of upstreams per pool.
const MAX_UPSTREAMS_PER_POOL: u8 = 16;

const UpstreamIndex = serval.config.UpstreamIndex;

/// Parse backends string into Upstream array with sequential idx starting at base_idx.
/// Format: "host:port,host:port,..."
/// TigerStyle: Bounded loop, count only increments on successful parse.
fn parseBackends(
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
fn formatUpstreams(upstreams: []const Upstream) void {
    std.debug.print("[", .{});
    for (upstreams, 0..) |upstream, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s}:{d}", .{ upstream.host, upstream.port });
    }
    std.debug.print("]", .{});
}

pub fn main() !void {
    // Parse command-line arguments
    var args = cli.Args(RouterExtra).init("router_example", VERSION);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Parse API backends
    var api_upstreams_buf: [MAX_UPSTREAMS_PER_POOL]Upstream = std.mem.zeroes([MAX_UPSTREAMS_PER_POOL]Upstream);
    const api_count = parseBackends(args.extra.@"api-backends", &api_upstreams_buf, 0);

    if (api_count == 0) {
        std.debug.print("Error: no valid API backends specified\n", .{});
        return error.NoBackends;
    }

    const api_upstreams = api_upstreams_buf[0..api_count];

    // Parse static backends with idx continuing from api_count
    var static_upstreams_buf: [MAX_UPSTREAMS_PER_POOL]Upstream = std.mem.zeroes([MAX_UPSTREAMS_PER_POOL]Upstream);
    const static_count = parseBackends(args.extra.@"static-backends", &static_upstreams_buf, api_count);

    if (static_count == 0) {
        std.debug.print("Error: no valid static backends specified\n", .{});
        return error.NoBackends;
    }

    const static_upstreams = static_upstreams_buf[0..static_count];

    // Pool indices
    const API_POOL: u8 = 0;
    const STATIC_POOL: u8 = 1;

    // Define routes
    // TigerStyle: Routes are evaluated in order, first match wins
    const routes = [_]Route{
        // /api/* -> api-pool (strip prefix so /api/users becomes /users)
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = API_POOL,
            .strip_prefix = true,
        },
        // /static/* -> static-pool (strip prefix so /static/image.png becomes /image.png)
        .{
            .name = "static",
            .matcher = .{ .path = .{ .prefix = "/static/" } },
            .pool_idx = STATIC_POOL,
            .strip_prefix = true,
        },
    };

    // Default route: /* -> api-pool (no strip_prefix)
    const default_route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = API_POOL,
        .strip_prefix = false,
    };

    // Pool configurations
    // TigerStyle: Disable probing for simplicity in this example
    const pool_configs = [_]PoolConfig{
        .{
            .name = "api-pool",
            .upstreams = api_upstreams,
            .lb_config = .{ .enable_probing = false },
        },
        .{
            .name = "static-pool",
            .upstreams = static_upstreams,
            .lb_config = .{ .enable_probing = false },
        },
    };

    // Initialize router
    var router: Router = undefined;
    try router.init(&routes, default_route, &pool_configs, null);
    defer router.deinit();

    // Initialize connection pool
    var pool = serval.SimplePool.init();

    // Initialize metrics (noop for simplicity)
    var metrics = serval.NoopMetrics{};

    // Initialize tracer (noop for simplicity)
    var tracer = serval.NoopTracer{};

    // Initialize async IO runtime
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    // Print startup info
    std.debug.print("Router listening on :{d}\n", .{args.port});
    std.debug.print("Routes:\n", .{});
    std.debug.print("  /api/* -> api-pool (strip prefix) ", .{});
    formatUpstreams(api_upstreams);
    std.debug.print("\n", .{});
    std.debug.print("  /static/* -> static-pool (strip prefix) ", .{});
    formatUpstreams(static_upstreams);
    std.debug.print("\n", .{});
    std.debug.print("  /* (default) -> api-pool ", .{});
    formatUpstreams(api_upstreams);
    std.debug.print("\n", .{});
    std.debug.print("Debug logging: {}\n", .{args.debug});

    // Run server
    const ServerType = serval.Server(
        Router,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );

    // DnsConfig{} uses default TTL (60s) and timeout (5s) values
    var server = ServerType.init(&router, &pool, &metrics, &tracer, .{
        .port = args.port,
        .tls = null, // No TLS for simplicity
    }, null, DnsConfig{});

    server.run(io, &shutdown) catch |err| {
        std.debug.print("Server error: {}\n", .{err});
        return;
    };
}
