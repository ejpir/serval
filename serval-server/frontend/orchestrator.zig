//! Frontend runtime orchestration.
//!
//! Starts/stops pluggable transport runtimes (TCP/UDP) around the HTTP frontend.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const serval_core = @import("serval-core");
const core_config = serval_core.config;
const log = serval_core.log.scoped(.frontend_orchestrator);
const serval_net = @import("serval-net");
const serval_tls = @import("serval-tls");
const tcp_runtime = @import("tcp_runtime.zig");
const udp_runtime = @import("udp_runtime.zig");

const Config = core_config.Config;
const DnsConfig = serval_net.DnsConfig;
const ssl = serval_tls.ssl;

/// Errors returned by `RuntimeOrchestrator.start` when a transport cannot be brought up.
/// The variants distinguish TCP versus UDP and runtime initialization versus worker-thread spawn failure.
/// Callers can use the specific error to report which transport and which phase failed.
pub const OrchestratorError = error{
    TcpRuntimeInitFailed,
    TcpRuntimeThreadSpawnFailed,
    UdpRuntimeInitFailed,
    UdpRuntimeThreadSpawnFailed,
};

/// Coordinates the frontend TCP and UDP runtime lifecycles for a single server instance.
/// Holds the shared shutdown flag, runtime configuration, optional TLS client context, and thread/context handles for each transport.
/// Use `init` to seed the state, `start` to launch enabled transports, and `stop` to request shutdown and join workers.
pub const RuntimeOrchestrator = struct {
    shutdown: *std.atomic.Value(bool),
    dns_config: DnsConfig,
    client_ctx: ?*ssl.SSL_CTX,
    verify_upstream_tls: bool,
    tcp_thread: ?std.Thread,
    tcp_context: ?TcpRuntimeThreadContext,
    udp_thread: ?std.Thread,
    udp_context: ?UdpRuntimeThreadContext,

    const Self = @This();

    /// Initializes the orchestrator with shared shutdown state and runtime configuration.
    /// Stores the DNS, client TLS, and upstream TLS verification settings, and clears all thread and context slots.
    /// This function does not allocate and cannot fail; `shutdown` must point to a valid atomic boolean for the lifetime of the orchestrator.
    pub fn init(
        self: *Self,
        shutdown: *std.atomic.Value(bool),
        dns_config: DnsConfig,
        client_ctx: ?*ssl.SSL_CTX,
        verify_upstream_tls: bool,
    ) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(shutdown) != 0);

        self.* = .{
            .shutdown = shutdown,
            .dns_config = dns_config,
            .client_ctx = client_ctx,
            .verify_upstream_tls = verify_upstream_tls,
            .tcp_thread = null,
            .tcp_context = null,
            .udp_thread = null,
            .udp_context = null,
        };
    }

    /// Starts the enabled transport runtimes described by `cfg`.
    /// UDP is started first when present and enabled; TCP is started only when present and enabled.
    /// If initialization or thread creation fails for either transport, any started UDP state is torn down and the corresponding `OrchestratorError` is returned.
    pub fn start(self: *Self, cfg: *const Config) OrchestratorError!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(cfg) != 0);

        if (cfg.udp_transport) |udp_cfg| {
            if (udp_cfg.enabled) {
                self.udp_context = .{
                    .runtime = undefined,
                    .shutdown = self.shutdown,
                };

                self.udp_context.?.runtime.init(udp_cfg, self.dns_config) catch {
                    self.udp_context = null;
                    return error.UdpRuntimeInitFailed;
                };

                self.udp_thread = std.Thread.spawn(.{}, udpRuntimeThreadMain, .{&self.udp_context.?}) catch {
                    self.udp_context = null;
                    return error.UdpRuntimeThreadSpawnFailed;
                };
            }
        }

        if (cfg.tcp_transport) |tcp_cfg| {
            if (!tcp_cfg.enabled) return;

            self.tcp_context = .{
                .runtime = undefined,
                .shutdown = self.shutdown,
            };

            self.tcp_context.?.runtime.init(
                tcp_cfg,
                self.dns_config,
                self.client_ctx,
                self.verify_upstream_tls,
            ) catch {
                self.tcp_context = null;
                self.stopUdpThread();
                return error.TcpRuntimeInitFailed;
            };

            self.tcp_thread = std.Thread.spawn(.{}, tcpRuntimeThreadMain, .{&self.tcp_context.?}) catch {
                self.tcp_context = null;
                self.stopUdpThread();
                return error.TcpRuntimeThreadSpawnFailed;
            };
        }
    }

    /// Requests orchestrator shutdown and stops any running transport workers.
    /// Sets the shared shutdown flag first, then stops the TCP thread and the UDP thread.
    /// This function does not report errors; cleanup is performed through the transport stop helpers.
    pub fn stop(self: *Self) void {
        assert(@intFromPtr(self) != 0);

        self.shutdown.store(true, .release);
        self.stopTcpThread();
        self.stopUdpThread();
    }

    fn stopTcpThread(self: *Self) void {
        assert(@intFromPtr(self) != 0);

        if (self.tcp_thread) |thread| {
            thread.join();
            self.tcp_thread = null;
            self.tcp_context = null;
        }
    }

    fn stopUdpThread(self: *Self) void {
        assert(@intFromPtr(self) != 0);

        if (self.udp_thread) |thread| {
            thread.join();
            self.udp_thread = null;
            self.udp_context = null;
        }
    }
};

const TcpRuntimeThreadContext = struct {
    runtime: tcp_runtime.Runtime,
    shutdown: *std.atomic.Value(bool),
};

const UdpRuntimeThreadContext = struct {
    runtime: udp_runtime.Runtime,
    shutdown: *std.atomic.Value(bool),
};

fn tcpRuntimeThreadMain(ctx: *TcpRuntimeThreadContext) void {
    assert(@intFromPtr(ctx) != 0);
    assert(@intFromPtr(ctx.shutdown) != 0);

    var io_runtime = Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_runtime.deinit();

    ctx.runtime.run(io_runtime.io(), ctx.shutdown, null) catch |err| {
        log.err("frontend orchestrator: tcp runtime exited with error: {s}", .{@errorName(err)});
    };
}

fn udpRuntimeThreadMain(ctx: *UdpRuntimeThreadContext) void {
    assert(@intFromPtr(ctx) != 0);
    assert(@intFromPtr(ctx.shutdown) != 0);

    var io_runtime = Io.Threaded.init(std.heap.page_allocator, .{});
    defer io_runtime.deinit();

    ctx.runtime.run(io_runtime.io(), ctx.shutdown, null) catch |err| {
        log.err("frontend orchestrator: udp runtime exited with error: {s}", .{@errorName(err)});
    };
}

test "RuntimeOrchestrator accepts config without tcp/udp runtimes" {
    var shutdown = std.atomic.Value(bool).init(false);
    var orchestrator: RuntimeOrchestrator = undefined;
    orchestrator.init(&shutdown, .{}, null, true);

    const cfg = Config{};
    try orchestrator.start(&cfg);
    orchestrator.stop();
}

test "RuntimeOrchestrator returns udp init failure for invalid udp runtime config" {
    const udp_targets = [_]core_config.L4Target{.{ .host = "127.0.0.1", .port = 9001 }};
    var cfg = Config{
        .udp_transport = .{
            .enabled = true,
            .listener_host = "",
            .listener_port = 7001,
            .upstreams = &udp_targets,
        },
    };

    var shutdown = std.atomic.Value(bool).init(false);
    var orchestrator: RuntimeOrchestrator = undefined;
    orchestrator.init(&shutdown, .{}, null, true);

    try std.testing.expectError(error.UdpRuntimeInitFailed, orchestrator.start(&cfg));
}
