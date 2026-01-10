const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // =========================================================================
    // Serval Library Modules
    // =========================================================================

    // Foundation module - no dependencies
    const serval_core_module = b.addModule("serval-core", .{
        .root_source_file = b.path("serval-core/mod.zig"),
    });

    // TLS module - no dependencies (Layer 1 - Protocol)
    // Note: Linking happens per compilation unit (tests, executables)
    // Modules cannot link libraries directly in Zig build system
    const serval_tls_module = b.addModule("serval-tls", .{
        .root_source_file = b.path("serval-tls/mod.zig"),
        .link_libc = true,
    });

    // Network utilities - depends on core (for config, time) and tls for TLSSocket
    const serval_net_module = b.addModule("serval-net", .{
        .root_source_file = b.path("serval-net/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
        },
    });

    // CLI module - no dependencies
    const serval_cli_module = b.addModule("serval-cli", .{
        .root_source_file = b.path("serval-cli/mod.zig"),
    });

    // Pool module - depends on core and net
    const serval_pool_module = b.addModule("serval-pool", .{
        .root_source_file = b.path("serval-pool/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
        },
    });

    // HTTP parser module - depends on core
    const serval_http_module = b.addModule("serval-http", .{
        .root_source_file = b.path("serval-http/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // Metrics module - depends on core
    const serval_metrics_module = b.addModule("serval-metrics", .{
        .root_source_file = b.path("serval-metrics/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // Tracing module - depends on core
    const serval_tracing_module = b.addModule("serval-tracing", .{
        .root_source_file = b.path("serval-tracing/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // OpenTelemetry module - depends on core + tracing
    const serval_otel_module = b.addModule("serval-otel", .{
        .root_source_file = b.path("serval-otel/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
        },
    });

    // Health module - depends on core
    const serval_health_module = b.addModule("serval-health", .{
        .root_source_file = b.path("serval-health/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // Client module - depends on core, http, net, pool, tls (Layer 3 - Mechanics)
    // HTTP/1.1 client for making requests to upstream servers
    const serval_client_module = b.addModule("serval-client", .{
        .root_source_file = b.path("serval-client/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
        },
    });

    // Proxy module - depends on core, net, pool, tracing, http, tls, client
    const serval_proxy_module = b.addModule("serval-proxy", .{
        .root_source_file = b.path("serval-proxy/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
            .{ .name = "serval-client", .module = serval_client_module },
        },
    });

    // Server module - composes core, net, http, pool, proxy, metrics, tracing, tls
    const serval_server_module = b.addModule("serval-server", .{
        .root_source_file = b.path("serval-server/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
            .{ .name = "serval-proxy", .module = serval_proxy_module },
            .{ .name = "serval-metrics", .module = serval_metrics_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
        },
    });

    // Prober module - depends on core, net, health, tls, client
    const serval_prober_module = b.addModule("serval-prober", .{
        .root_source_file = b.path("serval-prober/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-health", .module = serval_health_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
            .{ .name = "serval-client", .module = serval_client_module },
        },
    });

    // Load balancer handler module - depends on core, health, prober, tls, net
    const serval_lb_module = b.addModule("serval-lb", .{
        .root_source_file = b.path("serval-lb/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-health", .module = serval_health_module },
            .{ .name = "serval-prober", .module = serval_prober_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
        },
    });

    // Router module - depends on core, lb, health, prober, tls, net (Layer 4 - Strategy)
    // Note: Not yet added to umbrella module - will be integrated when feature is complete
    const serval_router_module = b.addModule("serval-router", .{
        .root_source_file = b.path("serval-router/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-lb", .module = serval_lb_module },
            .{ .name = "serval-health", .module = serval_health_module },
            .{ .name = "serval-prober", .module = serval_prober_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
        },
    });

    // Gateway module - depends on router, core, server, net, tls, client, pool (Layer 5 - Orchestration)
    const serval_gateway_module = b.addModule("serval-k8s-gateway", .{
        .root_source_file = b.path("serval-k8s-gateway/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-router", .module = serval_router_module },
            .{ .name = "serval-server", .module = serval_server_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
            .{ .name = "serval-client", .module = serval_client_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
        },
    });

    // Main serval module - composes all (umbrella)
    const serval_module = b.addModule("serval", .{
        .root_source_file = b.path("serval/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
            .{ .name = "serval-proxy", .module = serval_proxy_module },
            .{ .name = "serval-metrics", .module = serval_metrics_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
            .{ .name = "serval-otel", .module = serval_otel_module },
            .{ .name = "serval-server", .module = serval_server_module },
        },
    });

    // =========================================================================
    // Tests
    // =========================================================================

    // Serval library tests (full integration)
    // Note: Links SSL libraries since serval-server now depends on serval-tls
    const serval_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    serval_tests_mod.linkSystemLibrary("ssl", .{});
    serval_tests_mod.linkSystemLibrary("crypto", .{});
    serval_tests_mod.addImport("serval-core", serval_core_module);
    serval_tests_mod.addImport("serval-net", serval_net_module);
    serval_tests_mod.addImport("serval-http", serval_http_module);
    serval_tests_mod.addImport("serval-pool", serval_pool_module);
    serval_tests_mod.addImport("serval-proxy", serval_proxy_module);
    serval_tests_mod.addImport("serval-metrics", serval_metrics_module);
    serval_tests_mod.addImport("serval-tracing", serval_tracing_module);
    serval_tests_mod.addImport("serval-otel", serval_otel_module);
    serval_tests_mod.addImport("serval-server", serval_server_module);
    serval_tests_mod.addImport("serval-client", serval_client_module);
    const serval_tests = b.addTest(.{
        .name = "serval_tests",
        .root_module = serval_tests_mod,
    });
    const run_serval_tests = b.addRunArtifact(serval_tests);

    const test_step = b.step("test", "Run all serval library tests");
    test_step.dependOn(&run_serval_tests.step);

    // Load balancer handler tests
    // Note: Links SSL libraries since serval-prober and serval-lb now depend on serval-tls
    // serval-prober depends on serval-client which depends on http, pool
    const lb_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-lb/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lb_tests_mod.linkSystemLibrary("ssl", .{});
    lb_tests_mod.linkSystemLibrary("crypto", .{});
    lb_tests_mod.addImport("serval-core", serval_core_module);
    lb_tests_mod.addImport("serval-health", serval_health_module);
    lb_tests_mod.addImport("serval-prober", serval_prober_module);
    lb_tests_mod.addImport("serval-tls", serval_tls_module);
    lb_tests_mod.addImport("serval-http", serval_http_module);
    lb_tests_mod.addImport("serval-pool", serval_pool_module);
    lb_tests_mod.addImport("serval-net", serval_net_module);
    lb_tests_mod.addImport("serval-client", serval_client_module);
    const lb_tests = b.addTest(.{
        .name = "lb_tests",
        .root_module = lb_tests_mod,
    });
    const run_lb_tests = b.addRunArtifact(lb_tests);

    const lb_test_step = b.step("test-lb", "Run serval-lb library tests");
    lb_test_step.dependOn(&run_lb_tests.step);

    // Router module tests
    // Note: Links SSL libraries since serval-router depends on serval-lb/prober which depend on serval-tls
    // serval-prober depends on serval-client which depends on http, pool
    const router_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-router/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    router_tests_mod.linkSystemLibrary("ssl", .{});
    router_tests_mod.linkSystemLibrary("crypto", .{});
    router_tests_mod.addImport("serval-core", serval_core_module);
    router_tests_mod.addImport("serval-lb", serval_lb_module);
    router_tests_mod.addImport("serval-health", serval_health_module);
    router_tests_mod.addImport("serval-prober", serval_prober_module);
    router_tests_mod.addImport("serval-tls", serval_tls_module);
    router_tests_mod.addImport("serval-http", serval_http_module);
    router_tests_mod.addImport("serval-pool", serval_pool_module);
    router_tests_mod.addImport("serval-net", serval_net_module);
    router_tests_mod.addImport("serval-client", serval_client_module);
    const router_tests = b.addTest(.{
        .name = "router_tests",
        .root_module = router_tests_mod,
    });
    const run_router_tests = b.addRunArtifact(router_tests);

    const router_test_step = b.step("test-router", "Run serval-router library tests");
    router_test_step.dependOn(&run_router_tests.step);

    // Gateway module tests
    // Note: Links SSL libraries since serval-k8s-gateway depends on serval-server/router which depend on serval-tls
    // serval-router -> serval-prober -> serval-client dependencies
    const gateway_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-k8s-gateway/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gateway_tests_mod.linkSystemLibrary("ssl", .{});
    gateway_tests_mod.linkSystemLibrary("crypto", .{});
    gateway_tests_mod.addImport("serval-core", serval_core_module);
    gateway_tests_mod.addImport("serval-router", serval_router_module);
    gateway_tests_mod.addImport("serval-server", serval_server_module);
    gateway_tests_mod.addImport("serval-tls", serval_tls_module);
    gateway_tests_mod.addImport("serval-http", serval_http_module);
    gateway_tests_mod.addImport("serval-pool", serval_pool_module);
    gateway_tests_mod.addImport("serval-net", serval_net_module);
    gateway_tests_mod.addImport("serval-client", serval_client_module);
    gateway_tests_mod.addImport("serval-lb", serval_lb_module);
    gateway_tests_mod.addImport("serval-health", serval_health_module);
    gateway_tests_mod.addImport("serval-prober", serval_prober_module);
    const gateway_tests = b.addTest(.{
        .name = "gateway_tests",
        .root_module = gateway_tests_mod,
    });
    const run_gateway_tests = b.addRunArtifact(gateway_tests);

    const gateway_test_step = b.step("test-k8s-gateway", "Run serval-k8s-gateway library tests");
    gateway_test_step.dependOn(&run_gateway_tests.step);

    // Health module tests
    const health_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-health/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    health_tests_mod.addImport("serval-core", serval_core_module);
    const health_tests = b.addTest(.{
        .name = "health_tests",
        .root_module = health_tests_mod,
    });
    const run_health_tests = b.addRunArtifact(health_tests);

    const health_test_step = b.step("test-health", "Run serval-health library tests");
    health_test_step.dependOn(&run_health_tests.step);

    // TLS module tests
    // Note: Uses system-installed OpenSSL/BoringSSL (libssl + libcrypto)
    const tls_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-tls/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    tls_tests_mod.linkSystemLibrary("ssl", .{});
    tls_tests_mod.linkSystemLibrary("crypto", .{});
    const tls_tests = b.addTest(.{
        .name = "tls_tests",
        .root_module = tls_tests_mod,
    });
    const run_tls_tests = b.addRunArtifact(tls_tests);

    const tls_test_step = b.step("test-tls", "Run serval-tls library tests");
    tls_test_step.dependOn(&run_tls_tests.step);

    // Network module tests
    // Note: Links SSL libraries since serval-net now depends on serval-tls
    const net_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-net/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    net_tests_mod.linkSystemLibrary("ssl", .{});
    net_tests_mod.linkSystemLibrary("crypto", .{});
    net_tests_mod.addImport("serval-core", serval_core_module);
    net_tests_mod.addImport("serval-tls", serval_tls_module);
    const net_tests = b.addTest(.{
        .name = "net_tests",
        .root_module = net_tests_mod,
    });
    const run_net_tests = b.addRunArtifact(net_tests);

    const net_test_step = b.step("test-net", "Run serval-net library tests");
    net_test_step.dependOn(&run_net_tests.step);

    // OpenTelemetry module tests
    const otel_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-otel/mod.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
        },
    });
    const otel_tests = b.addTest(.{
        .name = "otel_tests",
        .root_module = otel_tests_mod,
    });
    const run_otel_tests = b.addRunArtifact(otel_tests);

    const otel_test_step = b.step("test-otel", "Run serval-otel library tests");
    otel_test_step.dependOn(&run_otel_tests.step);

    // Client module tests
    // Note: Links SSL libraries since serval-client depends on serval-tls
    const client_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-client/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    client_tests_mod.linkSystemLibrary("ssl", .{});
    client_tests_mod.linkSystemLibrary("crypto", .{});
    client_tests_mod.addImport("serval-core", serval_core_module);
    client_tests_mod.addImport("serval-http", serval_http_module);
    client_tests_mod.addImport("serval-net", serval_net_module);
    client_tests_mod.addImport("serval-pool", serval_pool_module);
    client_tests_mod.addImport("serval-tls", serval_tls_module);
    const client_tests = b.addTest(.{
        .name = "client_tests",
        .root_module = client_tests_mod,
    });
    const run_client_tests = b.addRunArtifact(client_tests);

    const client_test_step = b.step("test-client", "Run serval-client library tests");
    client_test_step.dependOn(&run_client_tests.step);

    // =========================================================================
    // Examples
    // =========================================================================

    // Stats display module (for use by examples)
    const stats_display_module = b.addModule("stats_display", .{
        .root_source_file = b.path("examples/stats_display.zig"),
        .imports = &.{
            .{ .name = "serval", .module = serval_module },
            .{ .name = "serval-metrics", .module = serval_metrics_module },
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // Load balancer example
    // Note: Links SSL libraries since serval depends on serval-server which depends on serval-tls
    const lb_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/lb_example.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lb_example_mod.linkSystemLibrary("ssl", .{});
    lb_example_mod.linkSystemLibrary("crypto", .{});
    lb_example_mod.addImport("serval", serval_module);
    lb_example_mod.addImport("serval-lb", serval_lb_module);
    lb_example_mod.addImport("serval-net", serval_net_module);
    lb_example_mod.addImport("serval-cli", serval_cli_module);
    lb_example_mod.addImport("serval-otel", serval_otel_module);
    lb_example_mod.addImport("serval-metrics", serval_metrics_module);
    lb_example_mod.addImport("serval-health", serval_health_module);
    lb_example_mod.addImport("serval-tls", serval_tls_module);
    lb_example_mod.addImport("stats_display", stats_display_module);
    const lb_example = b.addExecutable(.{
        .name = "lb_example",
        .root_module = lb_example_mod,
    });
    const build_lb_example = b.addInstallArtifact(lb_example, .{});
    const run_lb_example = b.addRunArtifact(lb_example);

    if (b.args) |args| {
        run_lb_example.addArgs(args);
    }

    const run_lb_example_step = b.step("run-lb-example", "Run load balancer example");
    run_lb_example_step.dependOn(&run_lb_example.step);

    // Router example
    // Note: Links SSL libraries since serval depends on serval-server which depends on serval-tls
    const router_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/router_example.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    router_example_mod.linkSystemLibrary("ssl", .{});
    router_example_mod.linkSystemLibrary("crypto", .{});
    router_example_mod.addImport("serval", serval_module);
    router_example_mod.addImport("serval-router", serval_router_module);
    router_example_mod.addImport("serval-net", serval_net_module);
    router_example_mod.addImport("serval-cli", serval_cli_module);
    const router_example = b.addExecutable(.{
        .name = "router_example",
        .root_module = router_example_mod,
    });
    const build_router_example = b.addInstallArtifact(router_example, .{});
    const run_router_example = b.addRunArtifact(router_example);

    if (b.args) |args| {
        run_router_example.addArgs(args);
    }

    const build_router_example_step = b.step("build-router-example", "Build router example");
    build_router_example_step.dependOn(&build_router_example.step);

    const run_router_example_step = b.step("run-router-example", "Run router example");
    run_router_example_step.dependOn(&run_router_example.step);

    // Gateway example (Kubernetes Gateway API controller)
    // Note: Links SSL libraries since serval-k8s-gateway depends on serval-server which depends on serval-tls
    const gateway_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/gateway/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gateway_example_mod.linkSystemLibrary("ssl", .{});
    gateway_example_mod.linkSystemLibrary("crypto", .{});
    gateway_example_mod.addImport("serval-k8s-gateway", serval_gateway_module);
    gateway_example_mod.addImport("serval-cli", serval_cli_module);
    gateway_example_mod.addImport("serval-core", serval_core_module);
    gateway_example_mod.addImport("serval-net", serval_net_module);
    gateway_example_mod.addImport("serval-pool", serval_pool_module);
    gateway_example_mod.addImport("serval-client", serval_client_module);
    gateway_example_mod.addImport("serval-tls", serval_tls_module);
    gateway_example_mod.addImport("serval-server", serval_server_module);
    gateway_example_mod.addImport("serval-metrics", serval_metrics_module);
    gateway_example_mod.addImport("serval-tracing", serval_tracing_module);
    const gateway_example = b.addExecutable(.{
        .name = "gateway_example",
        .root_module = gateway_example_mod,
    });
    const build_gateway_example = b.addInstallArtifact(gateway_example, .{});
    const run_gateway_example = b.addRunArtifact(gateway_example);

    if (b.args) |args| {
        run_gateway_example.addArgs(args);
    }

    const build_gateway_example_step = b.step("build-gateway-example", "Build gateway example");
    build_gateway_example_step.dependOn(&build_gateway_example.step);

    const run_gateway_example_step = b.step("run-gateway-example", "Run gateway example");
    run_gateway_example_step.dependOn(&run_gateway_example.step);

    // Echo backend example (for testing load balancer)
    // Note: Links SSL libraries since serval depends on serval-server which depends on serval-tls
    const echo_backend_mod = b.createModule(.{
        .root_source_file = b.path("examples/echo_backend.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    echo_backend_mod.linkSystemLibrary("ssl", .{});
    echo_backend_mod.linkSystemLibrary("crypto", .{});
    echo_backend_mod.addImport("serval", serval_module);
    echo_backend_mod.addImport("serval-net", serval_net_module);
    echo_backend_mod.addImport("serval-cli", serval_cli_module);
    const echo_backend = b.addExecutable(.{
        .name = "echo_backend",
        .root_module = echo_backend_mod,
    });
    const build_echo_backend = b.addInstallArtifact(echo_backend, .{});
    const run_echo_backend = b.addRunArtifact(echo_backend);

    const build_echo_backend_step = b.step("build-echo-backend", "Build echo backend");
    build_echo_backend_step.dependOn(&build_echo_backend.step);

    if (b.args) |args| {
        run_echo_backend.addArgs(args);
    }

    const run_echo_backend_step = b.step("run-echo-backend", "Run echo backend example");
    run_echo_backend_step.dependOn(&run_echo_backend.step);

    // OTLP test example
    const otel_test_mod = b.createModule(.{
        .root_source_file = b.path("examples/otel_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    otel_test_mod.addImport("serval-otel", serval_otel_module);
    const otel_test = b.addExecutable(.{
        .name = "otel_test",
        .root_module = otel_test_mod,
    });
    const build_otel_test = b.addInstallArtifact(otel_test, .{});

    const run_otel_test = b.addRunArtifact(otel_test);
    const run_otel_test_step = b.step("run-otel-test", "Run OTLP export test");
    run_otel_test_step.dependOn(&run_otel_test.step);

    // LLM streaming example (demonstrates Action.stream and nextChunk)
    // Note: Links SSL libraries since serval depends on serval-server which depends on serval-tls
    const llm_streaming_mod = b.createModule(.{
        .root_source_file = b.path("examples/llm_streaming.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    llm_streaming_mod.linkSystemLibrary("ssl", .{});
    llm_streaming_mod.linkSystemLibrary("crypto", .{});
    llm_streaming_mod.addImport("serval", serval_module);
    llm_streaming_mod.addImport("serval-net", serval_net_module);
    llm_streaming_mod.addImport("serval-cli", serval_cli_module);
    const llm_streaming = b.addExecutable(.{
        .name = "llm_streaming",
        .root_module = llm_streaming_mod,
    });
    const build_llm_streaming = b.addInstallArtifact(llm_streaming, .{});
    const run_llm_streaming = b.addRunArtifact(llm_streaming);

    if (b.args) |args| {
        run_llm_streaming.addArgs(args);
    }

    const build_llm_streaming_step = b.step("build-llm-example", "Build LLM streaming example");
    build_llm_streaming_step.dependOn(&build_llm_streaming.step);

    const run_llm_streaming_step = b.step("run-llm-example", "Run LLM streaming example");
    run_llm_streaming_step.dependOn(&run_llm_streaming.step);

    // Default step - build all examples
    b.default_step.dependOn(&build_lb_example.step);
    b.default_step.dependOn(&build_router_example.step);
    b.default_step.dependOn(&build_gateway_example.step);
    b.default_step.dependOn(&build_echo_backend.step);
    b.default_step.dependOn(&build_otel_test.step);
    b.default_step.dependOn(&build_llm_streaming.step);
}
