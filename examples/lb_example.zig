// examples/lb_example.zig
//! Load Balancer Example
//!
//! Demonstrates serval with LbHandler for health-aware load balancing.
//! Backends automatically recover via background probing.
//!
//! ## Component Flow Diagram
//!
//! ```
//!                                    REQUEST FLOW
//!  ┌─────────┐
//!  │ Client  │
//!  └────┬────┘
//!       │ TCP/TLS connection
//!       ▼
//!  ┌─────────────────────────────────────────────────────────────────────────┐
//!  │                         serval-server                                   │
//!  │  (accept loop, HTTP/1.1 parsing, connection management, hooks)          │
//!  │                                                                         │
//!  │  Server struct contains:                                                │
//!  │  - handler: *Handler (LbHandler in this example)                        │
//!  │  - forwarder: Forwarder(Pool, Tracer)  ← BUILT-IN, not a hook!          │
//!  │  - pool: *Pool                                                          │
//!  │  - metrics: *Metrics                                                    │
//!  │  - tracer: *Tracer                                                      │
//!  │                                                                         │
//!  │  Request processing (server.zig:715-745):                               │
//!  │  ┌─────────────────────────────────────────────────────────────────┐    │
//!  │  │ 1. handler.onRequest(ctx, request) → Action     [OPTIONAL HOOK] │    │
//!  │  │    - .continue_request → proceed to step 2                      │    │
//!  │  │    - .send_response    → send direct response, skip forwarding  │    │
//!  │  │    - .reject           → send error, skip forwarding            │    │
//!  │  │                                                                 │    │
//!  │  │ 2. handler.selectUpstream(ctx, request) → Upstream [REQUIRED]   │    │
//!  │  │    - Handler decides which backend to use                       │    │
//!  │  │    - Returns Upstream{host, port, tls, idx}                     │    │
//!  │  │                                                                 │    │
//!  │  │ 3. forwarder.forward(io, stream, tls, request, upstream, ...)   │    │
//!  │  │    - Server calls its built-in forwarder automatically          │    │
//!  │  │    - Handler is NOT involved in forwarding!                     │    │
//!  │  └─────────────────────────────────────────────────────────────────┘    │
//!  │                                                                         │
//!  │  Components used:                                                       │
//!  │  - serval-socket: TCP/TLS unified socket abstraction                     │
//!  │  - serval-http: HTTP/1.1 request parser                                 │
//!  │  - serval-tls: TLS termination (if --cert/--key provided)               │
//!  │  - serval-pool: Connection pooling (SimplePool)                         │
//!  │  - serval-metrics: Request metrics (RealTimeMetrics)                    │
//!  │  - serval-tracing: Distributed tracing (OtelTracer or NoopTracer)       │
//!  │  - serval-proxy: Forwarder (BUILT INTO Server struct)                   │
//!  └────┬────────────────────────────────────────────────────────────────────┘
//!       │
//!       │ Step 2: handler.selectUpstream(ctx, request)
//!       ▼
//!  ┌─────────────────────────────────────────────────────────────────────────┐
//!  │                         serval-lb (LbHandler)                           │
//!  │  (health-aware round-robin, passive health tracking, background probes) │
//!  │                                                                         │
//!  │  selectUpstream() implementation:                                       │
//!  │  1. Get next index (atomic round-robin counter)                         │
//!  │  2. health.findNthHealthy(n) → skip unhealthy backends                  │
//!  │  3. Return upstreams[healthy_idx]                                       │
//!  │                                                                         │
//!  │  Components used:                                                       │
//!  │  - serval-health: HealthState (atomic bitmap + threshold counters)      │
//!  │  - serval-prober: Background HTTP/HTTPS probes to unhealthy backends    │
//!  │  - serval-net.DnsResolver: DNS resolution for probe hostnames           │
//!  │  - serval-tls: TLS for HTTPS probes (if upstream.tls=true)              │
//!  └────┬────────────────────────────────────────────────────────────────────┘
//!       │ returns Upstream{host, port, tls, idx}
//!       │
//!       │ Step 3: Server automatically calls forwarder.forward()
//!       ▼
//!  ┌─────────────────────────────────────────────────────────────────────────┐
//!  │                    serval-proxy (Forwarder.forward)                     │
//!  │                                                                         │
//!  │  Step 1: Pool Acquire                                                   │
//!  │  ┌─────────────────────────────────────────────────────────────────┐    │
//!  │  │ pool.acquire(upstream.idx) → Connection?                        │    │
//!  │  │ - If HIT: reuse existing TCP/TLS connection (skip DNS+connect)  │    │
//!  │  │ - If MISS or STALE: create fresh connection (see Step 2)        │    │
//!  │  │ - Bounded retry on stale (MAX_STALE_RETRIES=2)                  │    │
//!  │  └─────────────────────────────────────────────────────────────────┘    │
//!  │                              │                                          │
//!  │                              ▼                                          │
//!  │  Step 2: Connect (if pool miss)                                         │
//!  │  ┌─────────────────────────────────────────────────────────────────┐    │
//!  │  │ connectUpstream(upstream, io, config, dns_resolver)             │    │
//!  │  │ 1. dns_resolver.resolve(host) → IP address (cached 60s)         │    │
//!  │  │ 2. posix.socket() + posix.connect() → TCP connection            │    │
//!  │  │ 3. If upstream.tls: TLS handshake via serval-tls                │    │
//!  │  │ Returns: ConnectResult{socket, dns_ns, tcp_ns, local_port}      │    │
//!  │  └─────────────────────────────────────────────────────────────────┘    │
//!  │                              │                                          │
//!  │                              ▼                                          │
//!  │  Step 3: Send Request                                                   │
//!  │  ┌─────────────────────────────────────────────────────────────────┐    │
//!  │  │ sendRequest(conn, io, request, effective_path)                  │    │
//!  │  │ 1. buildRequestBuffer() - serialize headers (filter hop-by-hop) │    │
//!  │  │ 2. conn.socket.write() - send headers to upstream               │    │
//!  │  │ 3. streamRequestBody() - forward body from client→upstream      │    │
//!  │  │    (uses Socket abstraction for TLS/plaintext transparency)     │    │
//!  │  └─────────────────────────────────────────────────────────────────┘    │
//!  │                              │                                          │
//!  │                              ▼                                          │
//!  │  Step 4: Receive Response                                               │
//!  │  ┌─────────────────────────────────────────────────────────────────┐    │
//!  │  │ forwardResponse(io, conn, client_stream, upstream_sock, ...)    │    │
//!  │  │ 1. Read response headers from upstream                          │    │
//!  │  │ 2. Parse status code and headers                                │    │
//!  │  │ 3. Forward response body upstream→client (streaming/chunked)    │    │
//!  │  │ Returns: ForwardResult{status, response_bytes, timings...}      │    │
//!  │  └─────────────────────────────────────────────────────────────────┘    │
//!  │                              │                                          │
//!  │                              ▼                                          │
//!  │  Step 5: Pool Release                                                   │
//!  │  ┌─────────────────────────────────────────────────────────────────┐    │
//!  │  │ pool.release(upstream.idx, conn, healthy=true)                  │    │
//!  │  │ - Returns connection to pool for reuse (keep-alive)             │    │
//!  │  │ - Or closes if unhealthy/error                                  │    │
//!  │  └─────────────────────────────────────────────────────────────────┘    │
//!  │                                                                         │
//!  │  Components used:                                                       │
//!  │  - serval-pool: Connection pooling (acquire/release by upstream.idx)   │
//!  │  - serval-net.DnsResolver: DNS resolution with TTL caching             │
//!  │  - serval-socket: Unified TCP/TLS read/write                           │
//!  │  - serval-tls: TLS origination for HTTPS upstreams                     │
//!  │  - serval-client.request: buildRequestBuffer, sendBufferToSocket       │
//!  │  - serval-core.config: CONNECT_TIMEOUT_NS, MAX_BODY_SIZE_BYTES, etc.   │
//!  └────┬────────────────────────────────────────────────────────────────────┘
//!       │ TCP/TLS connection (pooled or fresh)
//!       ▼
//!  ┌─────────┐
//!  │ Backend │  (e.g., 127.0.0.1:8001, 127.0.0.1:8002)
//!  └─────────┘
//!
//!
//!                              BACKGROUND HEALTH PROBING
//!
//!  ┌─────────────────────────────────────────────────────────────────────────┐
//!  │                         serval-prober                                   │
//!  │  (separate thread, probes unhealthy backends at probe_interval_ms)      │
//!  │                                                                         │
//!  │  Uses serval-client to:                                                 │
//!  │  1. DNS resolve backend hostname                                        │
//!  │  2. TCP connect (+ TLS handshake if upstream.tls=true)                  │
//!  │  3. Send GET /health_path HTTP/1.1                                      │
//!  │  4. Check for 2xx response                                              │
//!  │                                                                         │
//!  │  Updates serval-health.HealthState:                                     │
//!  │  - Success: recordSuccess(idx) → may transition to healthy              │
//!  │  - Failure: recordFailure(idx) → stays unhealthy                        │
//!  └─────────────────────────────────────────────────────────────────────────┘
//!
//!
//!                              COMPONENT SUMMARY
//!
//!  Layer 0 (Foundation):    serval-core    - types, config, errors, context, time
//!  Layer 1 (Protocol):      serval-http    - HTTP/1.1 request/response parsing
//!                           serval-net     - Socket (TCP/TLS), DnsResolver
//!                           serval-tls     - TLS handshake, kTLS offload
//!  Layer 2 (Infrastructure): serval-pool   - Connection pooling (per-upstream)
//!                           serval-metrics - Request metrics (RealTimeMetrics)
//!                           serval-tracing - Distributed tracing (OtelTracer)
//!                           serval-health  - Health state (atomic bitmap)
//!                           serval-prober  - Background HTTP/HTTPS probes
//!                           serval-client  - HTTP client (used by prober)
//!  Layer 3 (Mechanics):     serval-proxy   - Forwarder (pool+connect+send+recv)
//!  Layer 4 (Strategy):      serval-lb      - LbHandler (round-robin + health)
//!  Layer 5 (Orchestration): serval-server  - Server (accept loop, hooks)
//!                           serval-cli     - CLI argument parsing
//!
//!                              KEY DATA STRUCTURES
//!
//!  Upstream         = {host, port, tls, idx}     - backend server address
//!  Connection       = {socket, created_ns}       - pooled TCP/TLS connection
//!  Socket           = Plain{fd} | TLS{fd,stream} - unified read/write interface
//!  HealthState      = {bitmap, counters[16]}     - per-upstream health tracking
//!  ForwardResult    = {status, bytes, timings}   - result of upstream forward
//! ```
//!
//! ## Usage
//!
//!   lb_example [OPTIONS]
//!
//! ## Options
//!
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
const assert = std.debug.assert;
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

    // Create DNS resolver for health probes
    // TigerStyle: Resolver uses default TTL (60s) and timeout (5s)
    var dns_resolver: serval_net.DnsResolver = undefined;
    serval_net.DnsResolver.init(&dns_resolver, .{});

    // Initialize load balancer with automatic health tracking and probing
    var handler: LbHandler = undefined;
    try handler.init(upstreams, .{
        .probe_interval_ms = 5000, // Probe every 5 seconds
    }, probe_ctx, &dns_resolver);
    defer handler.deinit();

    // Initialize stats display if enabled
    var stats_display_instance: ?StatsDisplay = null;
    if (args.extra.stats) {
        stats_display_instance = StatsDisplay.init(&metrics, &pool, upstreams);
        try stats_display_instance.?.start();
        assert(stats_display_instance.?.running.load(.acquire));
    }
    defer if (stats_display_instance) |*sd| sd.stop();

    // Initialize async IO runtime
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    // Print startup info
    // Server-side TLS (HTTPS) requires cert and key; upstream-only TLS config doesn't
    const has_server_tls = if (tls_config) |cfg| cfg.cert_path != null else false;
    std.debug.print("Load balancer listening on :{d} ({s})\n", .{ args.port, if (has_server_tls) "HTTPS" else "HTTP" });
    if (tls_config) |tls_cfg| {
        if (tls_cfg.cert_path) |cert| {
            std.debug.print("TLS: enabled (cert={s}, key={s})\n", .{ cert, tls_cfg.key_path.? });
        }
        if (!tls_cfg.verify_upstream) {
            std.debug.print("TLS verification: DISABLED (insecure, for testing only)\n", .{});
        }
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
        defer otel_processor.deinit();
        defer otel_processor.shutdown();

        // TigerStyle: OtelTracer is ~240KB, requires heap allocation.
        const tracer = try otel.OtelTracer.create(
            allocator,
            otel_processor.asSpanProcessor(),
            "serval-lb",
            VERSION,
        );
        defer tracer.destroy(allocator);

        const OtelServerType = serval.Server(
            LbHandler,
            serval.SimplePool,
            RealTimeMetrics,
            otel.OtelTracer,
        );
        // Pass probe_ctx as client_ctx for upstream TLS connections.
        // Same SSL context is used for probing and forwarding.
        // DnsConfig{} uses default TTL (60s) and timeout (5s) values
        var server = OtelServerType.init(&handler, &pool, &metrics, tracer, .{
            .port = args.port,
            .tls = tls_config,
        }, probe_ctx, DnsConfig{});

        server.run(io, &shutdown, null) catch |err| {
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

        server.run(io, &shutdown, null) catch |err| {
            std.debug.print("Server error: {}\n", .{err});
            return;
        };
    }
}
