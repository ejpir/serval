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
//!   --port <PORT>                Listening port (default: 8080)
//!   --backends <HOSTS>           Comma-separated backend addresses (default: 127.0.0.1:8001,127.0.0.1:8002)
//!   --cert <PATH>                Server certificate file (PEM format, enables TLS)
//!   --key <PATH>                 Server private key file (PEM format, required with --cert)
//!   --upstream-tls <HOSTS>       Comma-separated TLS backend addresses (enables HTTPS to those backends)
//!   --insecure-skip-verify       Skip TLS certificate verification for upstream probes (insecure, for testing only)
//!   --stats                      Enable real-time terminal stats display
//!   --trace                      Enable OpenTelemetry tracing
//!   --debug                      Enable debug logging
//!   --help                       Show help message
//!   --version                    Show version

const std = @import("std");
const serval = @import("serval");
const serval_lb = @import("serval-lb");
const serval_net = @import("serval-net");
const cli = @import("serval-cli");
const otel = @import("serval-otel");
const serval_metrics = @import("serval-metrics");
const stats_display = @import("stats_display");
const tls = @import("serval-tls");
const DnsConfig = serval_net.DnsConfig;

const RealTimeMetrics = serval_metrics.RealTimeMetrics;
const StatsDisplay = stats_display.StatsDisplay;
const LbHandler = serval_lb.LbHandler;
const ssl = tls.ssl;

/// Version of this binary.
const VERSION = "0.1.0";

/// LB-specific CLI options.
const LbExtra = struct {
    /// Comma-separated list of backend addresses (host:port,host:port,...)
    backends: []const u8 = "127.0.0.1:8001,127.0.0.1:8002",
    /// Server certificate file path (PEM format) for TLS termination
    cert: ?[]const u8 = null,
    /// Server private key file path (PEM format) for TLS termination
    key: ?[]const u8 = null,
    /// Enable real-time terminal stats display
    stats: bool = false,
    /// Enable OpenTelemetry tracing (requires collector at localhost:4318)
    trace: bool = false,
    /// Comma-separated list of TLS-enabled backend addresses (host:port,host:port,...)
    /// Backends in this list will use HTTPS instead of HTTP
    @"upstream-tls": ?[]const u8 = null,
    /// Skip TLS certificate verification for upstream HTTPS probes (insecure, for testing only)
    @"insecure-skip-verify": bool = false,
};

/// Maximum number of upstreams supported.
const MAX_UPSTREAMS: u8 = 16;

const UpstreamIndex = serval.config.UpstreamIndex;

/// Parse backends string into Upstream array.
/// Format: "host:port,host:port,..."
/// If tls_backends_str is provided, mark those backends as TLS-enabled.
/// TigerStyle: Bounded loop, count only increments on successful parse.
fn parseBackends(
    backends_str: []const u8,
    upstreams: *[MAX_UPSTREAMS]serval.Upstream,
    tls_backends_str: ?[]const u8,
) UpstreamIndex {
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

        // Check if this backend is in the TLS list
        const is_tls = if (tls_backends_str) |tls_str| blk: {
            var tls_iter = std.mem.splitScalar(u8, tls_str, ',');
            while (tls_iter.next()) |tls_backend| {
                if (std.mem.eql(u8, backend, tls_backend)) {
                    break :blk true;
                }
            }
            break :blk false;
        } else false;

        upstreams[count] = .{
            .host = host,
            .port = port,
            .idx = count,
            .tls = is_tls,
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
    const upstream_count = parseBackends(args.extra.backends, &upstreams_buf, args.extra.@"upstream-tls");

    if (upstream_count == 0) {
        std.debug.print("Error: no valid backends specified\n", .{});
        return error.NoBackends;
    }

    const upstreams = upstreams_buf[0..upstream_count];

    // Validate TLS configuration
    const tls_config: ?serval.config.TlsConfig = if (args.extra.cert) |cert_path| blk: {
        if (args.extra.key == null) {
            std.debug.print("Error: --key is required when --cert is specified\n", .{});
            return error.MissingTlsKey;
        }
        break :blk .{
            .cert_path = cert_path,
            .key_path = args.extra.key,
            .verify_upstream = !args.extra.@"insecure-skip-verify",
        };
    } else if (args.extra.key) |_| {
        std.debug.print("Error: --cert is required when --key is specified\n", .{});
        return error.MissingTlsCert;
    } else if (args.extra.@"insecure-skip-verify") blk: {
        // If only --insecure-skip-verify is specified (no server TLS), still configure upstream verification
        break :blk .{
            .verify_upstream = false,
        };
    } else null;

    // Initialize connection pool
    var pool = serval.SimplePool.init();

    // Initialize metrics
    var metrics = RealTimeMetrics.init();

    // Check if any upstreams need TLS for health probes
    const has_tls_upstreams = blk: {
        for (upstreams) |upstream| {
            if (upstream.tls) break :blk true;
        }
        break :blk false;
    };

    // Create SSL context for health probes if needed
    // TigerStyle: Caller owns SSL_CTX lifetime
    const probe_ctx: ?*ssl.SSL_CTX = if (has_tls_upstreams) ctx_blk: {
        ssl.init();
        const ctx = ssl.createClientCtx() catch {
            std.debug.print("Error: failed to create SSL context for health probes\n", .{});
            return error.TlsInitFailed;
        };

        // Configure certificate verification
        const verify_upstream = if (tls_config) |cfg| cfg.verify_upstream else true;
        if (verify_upstream) {
            ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_PEER, null);
        } else {
            ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_NONE, null);
        }

        break :ctx_blk ctx;
    } else null;
    defer if (probe_ctx) |ctx| ssl.SSL_CTX_free(ctx);

    // Initialize load balancer with automatic health tracking and probing
    var handler: LbHandler = undefined;
    try handler.init(upstreams, .{
        .probe_interval_ms = 5000, // Probe every 5 seconds
    }, probe_ctx);
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
    std.debug.print("Load balancer listening on :{d} ({s})\n", .{ args.port, if (tls_config != null) "HTTPS" else "HTTP" });
    if (tls_config) |tls_cfg| {
        std.debug.print("TLS: enabled (cert={s}, key={s})\n", .{ tls_cfg.cert_path.?, tls_cfg.key_path.? });
    }
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
        const protocol = if (upstream.tls) "https" else "http";
        std.debug.print("{s}://{s}:{d}", .{ protocol, upstream.host, upstream.port });
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
        // Pass probe_ctx as client_ctx for upstream TLS connections.
        // Same SSL context is used for probing and forwarding.
        // DnsConfig{} uses default TTL (60s) and timeout (5s) values
        var server = OtelServerType.init(&handler, &pool, &metrics, &tracer, .{
            .port = args.port,
            .tls = tls_config,
        }, probe_ctx, DnsConfig{});

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
        // Pass probe_ctx as client_ctx for upstream TLS connections.
        // Same SSL context is used for probing and forwarding.
        // DnsConfig{} uses default TTL (60s) and timeout (5s) values
        var server = NoopServerType.init(&handler, &pool, &metrics, &tracer, .{
            .port = args.port,
            .tls = tls_config,
        }, probe_ctx, DnsConfig{});

        server.run(io, &shutdown) catch |err| {
            std.debug.print("Server error: {}\n", .{err});
            return;
        };
    }
}
