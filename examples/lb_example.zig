// examples/lb_example.zig
//! Load Balancer Example
//!
//! Demonstrates serval with LbHandler for round-robin load balancing.
//! This example shows how to configure upstreams and create a server
//! that distributes requests across multiple backends.
//!
//! Usage:
//!   lb_example [OPTIONS]
//!
//! Options:
//!   --port <PORT>       Listening port (default: 8080)
//!   --backends <HOSTS>  Comma-separated backend addresses (default: 127.0.0.1:8001,127.0.0.1:8002)
//!   --stats             Enable real-time terminal stats display
//!   --debug             Enable debug logging
//!   --help              Show help message
//!   --version           Show version

const std = @import("std");
const serval = @import("serval");
const cli = @import("serval-cli");
const otel = @import("serval-otel");
const serval_metrics = @import("serval-metrics");
const stats_display = @import("stats_display");

const RealTimeMetrics = serval_metrics.RealTimeMetrics;
const StatsDisplay = stats_display.StatsDisplay;

/// Version of this binary.
const VERSION = "0.1.0";

/// LB-specific CLI options.
const LbExtra = struct {
    /// Comma-separated list of backend addresses (host:port,host:port,...)
    backends: []const u8 = "127.0.0.1:8001,127.0.0.1:8002",
    /// Enable real-time terminal stats display (header pinned at top, logs scroll below)
    stats: bool = false,
    /// Enable OpenTelemetry tracing (requires collector at localhost:4318)
    trace: bool = false,
};

/// Logging handler that wraps round-robin selection with timing output.
const LoggingLbHandler = struct {
    upstreams: []const serval.Upstream,
    metrics: *RealTimeMetrics,
    debug: bool,
    next_idx: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn init(upstreams: []const serval.Upstream, metrics: *RealTimeMetrics, debug: bool) LoggingLbHandler {
        return .{ .upstreams = upstreams, .metrics = metrics, .debug = debug };
    }

    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, request: *const serval.Request) serval.Upstream {
        _ = ctx;
        _ = request;
        const current = self.next_idx.fetchAdd(1, .monotonic);
        const idx = current % @as(u32, @intCast(self.upstreams.len));
        return self.upstreams[idx];
    }

    pub fn onConnectionOpen(self: *@This(), info: *const serval.ConnectionInfo) void {
        if (self.debug) {
            std.debug.print("[CONN-{d}] opened port={d}\n", .{ info.connection_id, info.local_port });
        }
    }

    pub fn onConnectionClose(self: *@This(), connection_id: u64, request_count: u32, duration_ns: u64) void {
        if (self.debug) {
            std.debug.print("[CONN-{d}] closed requests={d} duration={d}ms\n", .{
                connection_id,
                request_count,
                duration_ns / 1_000_000,
            });
        }
    }

    pub fn onLog(self: *@This(), ctx: *serval.Context, entry: serval.LogEntry) void {
        _ = ctx;

        // Always record per-upstream stats (server already recorded totals via requestEnd)
        if (entry.upstream) |upstream| {
            // TigerStyle: Safe cast - MAX_UPSTREAMS is 64, idx fits in u8
            const idx: u8 = @intCast(upstream.idx);
            self.metrics.recordUpstreamStats(entry.status, entry.duration_ns, idx);
        }

        // Only print detailed timing when --debug is enabled
        if (self.debug) {
            std.debug.print(
                "[{d}] conn={d} req={d} {s} {s} -> {d} total={d}us parse={d}us connect={d}us send={d}us recv={d}us pool={d}us reused={}\n",
                .{
                    entry.timestamp_s,
                    entry.connection_id,
                    entry.request_number,
                    @tagName(entry.method),
                    entry.path,
                    entry.status,
                    entry.duration_ns / 1_000,
                    entry.parse_duration_ns / 1_000,
                    entry.tcp_connect_duration_ns / 1_000,
                    entry.send_duration_ns / 1_000,
                    entry.recv_duration_ns / 1_000,
                    entry.pool_wait_ns / 1_000,
                    entry.connection_reused,
                },
            );
        }
    }
};

/// Maximum number of upstreams supported.
const MAX_UPSTREAMS: u8 = 16;

/// Parse backends string into Upstream array.
/// Format: "host:port,host:port,..."
/// TigerStyle: Bounded loop, count only increments on successful parse.
fn parseBackends(backends_str: []const u8, upstreams: *[MAX_UPSTREAMS]serval.Upstream) u8 {
    var count: u8 = 0;
    var iter = std.mem.splitScalar(u8, backends_str, ',');

    // Bounded iteration
    var iterations: u8 = 0;
    while (iterations < MAX_UPSTREAMS) : (iterations += 1) {
        const backend = iter.next() orelse break;
        if (count >= MAX_UPSTREAMS) break;

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
            .idx = count,
        };
        count += 1; // Only increment on successful parse
    }

    return count;
}

pub fn main() !void {
    // Parse command-line arguments
    var args = cli.Args(LbExtra).init("lb_example", VERSION);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Parse backends string into upstream array
    // TigerStyle: Zero buffer for defense-in-depth.
    var upstreams_buf: [MAX_UPSTREAMS]serval.Upstream = std.mem.zeroes([MAX_UPSTREAMS]serval.Upstream);
    const upstream_count = parseBackends(args.extra.backends, &upstreams_buf);

    if (upstream_count == 0) {
        std.debug.print("Error: no valid backends specified\n", .{});
        return error.NoBackends;
    }

    const upstreams = upstreams_buf[0..upstream_count];

    // Initialize connection pool for upstream keepalive.
    // SimplePool maintains per-upstream connection caches.
    var pool = serval.SimplePool.init();

    // Initialize metrics (RealTimeMetrics for stats display support).
    // Minimal overhead even when display is not enabled.
    var metrics = RealTimeMetrics.init();

    // Initialize logging load balancer handler with upstream list and metrics.
    var handler = LoggingLbHandler.init(upstreams, &metrics, args.debug);

    // Initialize stats display if --stats flag is enabled.
    // TigerStyle: Explicit optional, defer cleanup.
    var stats_display_instance: ?StatsDisplay = null;
    if (args.extra.stats) {
        stats_display_instance = StatsDisplay.init(&metrics, &pool, upstreams);
        try stats_display_instance.?.start();
        // TigerStyle: Postcondition - verify display thread started
        std.debug.assert(stats_display_instance.?.running.load(.acquire));
    }
    defer if (stats_display_instance) |*sd| sd.stop();

    // Initialize async IO runtime (uses io_uring on Linux)
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    // Print startup info
    std.debug.print("Load balancer listening on :{d}\n", .{args.port});
    std.debug.print("Tracing: {s}\n", .{if (args.extra.trace) "OpenTelemetry (localhost:4318)" else "disabled"});
    std.debug.print("Stats display: {}\n", .{args.extra.stats});
    std.debug.print("Debug logging: {}\n", .{args.debug});
    std.debug.print("Forwarding to: ", .{});
    for (upstreams, 0..) |upstream, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s}:{d}", .{ upstream.host, upstream.port });
    }
    std.debug.print("\n", .{});

    // Run server with appropriate tracer based on --trace flag
    if (args.extra.trace) {
        // OpenTelemetry tracing enabled
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var otel_exporter = try otel.OTLPExporter.init(allocator, .{
            .endpoint = "http://localhost:4318/v1/traces",
            .service_name = "serval-lb-example",
            .service_version = VERSION,
        });
        defer otel_exporter.deinit();

        var otel_processor = try otel.BatchingProcessor.init(allocator, otel_exporter.asSpanExporter(), .{
            .scheduled_delay_ms = 5000,
            .max_export_batch_size = 512,
        });
        defer otel_processor.shutdown();
        defer otel_processor.deinit();

        var tracer = otel.OtelTracer.init(
            otel_processor.asSpanProcessor(),
            "serval-lb",
            VERSION,
        );

        const OtelServerType = serval.Server(
            LoggingLbHandler,
            serval.SimplePool,
            RealTimeMetrics,
            otel.OtelTracer,
        );
        var server = OtelServerType.init(&handler, &pool, &metrics, &tracer, .{
            .port = args.port,
        });

        server.run(io, &shutdown) catch |err| {
            std.debug.print("Server error: {}\n", .{err});
            return;
        };
    } else {
        // No tracing (default) - zero overhead
        var tracer = serval.NoopTracer{};

        const NoopServerType = serval.Server(
            LoggingLbHandler,
            serval.SimplePool,
            RealTimeMetrics,
            serval.NoopTracer,
        );
        var server = NoopServerType.init(&handler, &pool, &metrics, &tracer, .{
            .port = args.port,
        });

        server.run(io, &shutdown) catch |err| {
            std.debug.print("Server error: {}\n", .{err});
            return;
        };
    }
}
