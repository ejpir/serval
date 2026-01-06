// examples/lb_example.zig
//! Load Balancer Example
//!
//! Demonstrates serval with LbHandler for health-aware load balancing.
//! Backends automatically recover via background probing.
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
const serval_lb = @import("serval-lb");
const cli = @import("serval-cli");
const otel = @import("serval-otel");
const serval_metrics = @import("serval-metrics");
const stats_display = @import("stats_display");

const RealTimeMetrics = serval_metrics.RealTimeMetrics;
const StatsDisplay = stats_display.StatsDisplay;
const LbHandler = serval_lb.LbHandler;

/// Version of this binary.
const VERSION = "0.1.0";

/// LB-specific CLI options.
const LbExtra = struct {
    /// Comma-separated list of backend addresses (host:port,host:port,...)
    backends: []const u8 = "127.0.0.1:8001,127.0.0.1:8002",
    /// Enable real-time terminal stats display
    stats: bool = false,
    /// Enable OpenTelemetry tracing (requires collector at localhost:4318)
    trace: bool = false,
};

/// Maximum number of upstreams supported.
const MAX_UPSTREAMS: u8 = 16;

const UpstreamIndex = serval.config.UpstreamIndex;

/// Parse backends string into Upstream array.
/// Format: "host:port,host:port,..."
/// TigerStyle: Bounded loop, count only increments on successful parse.
fn parseBackends(backends_str: []const u8, upstreams: *[MAX_UPSTREAMS]serval.Upstream) UpstreamIndex {
    var count: UpstreamIndex = 0;
    var iter = std.mem.splitScalar(u8, backends_str, ',');

    // Bounded iteration - use count directly, MAX_UPSTREAMS-1 is max valid index
    while (count < MAX_UPSTREAMS) {
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
            .idx = count,
        };
        count += 1;
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
    var upstreams_buf: [MAX_UPSTREAMS]serval.Upstream = std.mem.zeroes([MAX_UPSTREAMS]serval.Upstream);
    const upstream_count = parseBackends(args.extra.backends, &upstreams_buf);

    if (upstream_count == 0) {
        std.debug.print("Error: no valid backends specified\n", .{});
        return error.NoBackends;
    }

    const upstreams = upstreams_buf[0..upstream_count];

    // Initialize connection pool
    var pool = serval.SimplePool.init();

    // Initialize metrics
    var metrics = RealTimeMetrics.init();

    // Initialize load balancer with automatic health tracking and probing
    var handler: LbHandler = undefined;
    try handler.init(upstreams, .{
        .probe_interval_ms = 5000, // Probe every 5 seconds
    });
    defer handler.deinit();

    // Initialize stats display if enabled
    var stats_display_instance: ?StatsDisplay = null;
    if (args.extra.stats) {
        stats_display_instance = StatsDisplay.init(&metrics, &pool, upstreams);
        try stats_display_instance.?.start();
        std.debug.assert(stats_display_instance.?.running.load(.acquire));
    }
    defer if (stats_display_instance) |*sd| sd.stop();

    // Initialize async IO runtime
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    // Print startup info
    std.debug.print("Load balancer listening on :{d}\n", .{args.port});
    std.debug.print("Health tracking: enabled (unhealthy after {d} failures, healthy after {d} successes)\n", .{
        serval.config.DEFAULT_UNHEALTHY_THRESHOLD,
        serval.config.DEFAULT_HEALTHY_THRESHOLD,
    });
    std.debug.print("Background probing: every 5000ms\n", .{});
    std.debug.print("Tracing: {s}\n", .{if (args.extra.trace) "OpenTelemetry (localhost:4318)" else "disabled"});
    std.debug.print("Stats display: {}\n", .{args.extra.stats});
    std.debug.print("Debug logging: {}\n", .{args.debug});
    std.debug.print("Forwarding to: ", .{});
    for (upstreams, 0..) |upstream, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s}:{d}", .{ upstream.host, upstream.port });
    }
    std.debug.print("\n", .{});

    // Run server
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
            LbHandler,
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
        // No tracing (default)
        var tracer = serval.NoopTracer{};

        const NoopServerType = serval.Server(
            LbHandler,
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
