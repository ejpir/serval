const std = @import("std");
const builtin = @import("builtin");

const max_toolchain_file_bytes: u32 = 2 * 1024 * 1024;
const required_zig_version = "0.16.0-dev.3153+d6f43caad";
const required_zig_path = "/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig";
const required_patch_file = "integration/toolchains/zig-0.16.0-dev.3153+d6f43caad-uring.patch";
const required_threaded_patch_marker = "fn posixConnectWithTimeout(";
const required_uring_network_patch_marker = ".netConnectIp = netConnectIp,";
const required_uring_null_guard_patch_marker = "if (batch_userdata[0] == 0) break :ready_fiber null;";

fn toolchainFileContains(
    io: anytype,
    allocator: std.mem.Allocator,
    path: []const u8,
    marker: []const u8,
) !bool {
    std.debug.assert(path.len > 0);
    std.debug.assert(marker.len > 0);

    const contents = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(max_toolchain_file_bytes),
    );
    defer allocator.free(contents);

    return std.mem.indexOf(u8, contents, marker) != null;
}

fn enforce_required_zig_toolchain(b: *std.Build) void {
    const zig_exe_path = b.graph.zig_exe;
    std.debug.assert(zig_exe_path.len > 0);
    std.debug.assert(required_patch_file.len > 0);

    if (!std.mem.eql(u8, builtin.zig_version_string, required_zig_version)) {
        std.log.err(
            \\Serval requires Zig {s}.
            \\Current compiler: {s} ({s})
            \\Re-run with:
            \\  {s} build ...
            \\Reason: Serval's Threaded/io_uring runtime paths depend on the locally patched stdlib shipped by `{s}`.
        , .{
            required_zig_version,
            zig_exe_path,
            builtin.zig_version_string,
            required_zig_path,
            required_patch_file,
        });
        std.process.exit(1);
    }

    const io = b.graph.io;

    const toolchain_dir = std.fs.path.dirname(zig_exe_path) orelse {
        std.log.err("failed to derive Zig toolchain directory from compiler path: {s}", .{zig_exe_path});
        std.process.exit(1);
    };

    var threaded_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const threaded_path = std.fmt.bufPrint(
        &threaded_path_buffer,
        "{s}/lib/std/Io/Threaded.zig",
        .{toolchain_dir},
    ) catch |err| {
        std.log.err("failed to construct Threaded stdlib path: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    var uring_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const uring_path = std.fmt.bufPrint(
        &uring_path_buffer,
        "{s}/lib/std/Io/Uring.zig",
        .{toolchain_dir},
    ) catch |err| {
        std.log.err("failed to construct Uring stdlib path: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    const has_threaded_patch = toolchainFileContains(
        io,
        b.allocator,
        threaded_path,
        required_threaded_patch_marker,
    ) catch |err| {
        std.log.err("failed to verify Threaded stdlib patch marker: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    const has_uring_network_patch = toolchainFileContains(
        io,
        b.allocator,
        uring_path,
        required_uring_network_patch_marker,
    ) catch |err| {
        std.log.err("failed to verify Uring networking patch marker: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    const has_uring_null_guard_patch = toolchainFileContains(
        io,
        b.allocator,
        uring_path,
        required_uring_null_guard_patch_marker,
    ) catch |err| {
        std.log.err("failed to verify Uring null-guard patch marker: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    if (has_threaded_patch and has_uring_network_patch and has_uring_null_guard_patch) return;

    std.log.err(
        \\Serval requires the patched Zig {s} stdlib.
        \\Current compiler: {s} ({s})
        \\Missing patch markers:
        \\  Threaded connect timeout helper: {s}
        \\  Uring networking hooks: {s}
        \\  Uring batch null guard: {s}
        \\Apply: patch -p0 -d /usr/local < {s}
    , .{
        required_zig_version,
        zig_exe_path,
        builtin.zig_version_string,
        if (has_threaded_patch) "present" else "missing",
        if (has_uring_network_patch) "present" else "missing",
        if (has_uring_null_guard_patch) "present" else "missing",
        required_patch_file,
    });
    std.process.exit(1);
}

fn force_llvm_lld(compile_step: *std.Build.Step.Compile) void {
    compile_step.use_llvm = true;
    compile_step.use_lld = true;
}

fn apply_optional_openssl_paths(
    module: *std.Build.Module,
    openssl_include_dir: ?[]const u8,
    openssl_lib_dir: ?[]const u8,
) void {
    if (openssl_include_dir) |include_dir| {
        module.addSystemIncludePath(.{ .cwd_relative = include_dir });
    }
    if (openssl_lib_dir) |lib_dir| {
        module.addLibraryPath(.{ .cwd_relative = lib_dir });
    }
}

/// Configures the Serval build graph using the standard target and optimize options.
/// Registers the Serval modules and any downstream executables/tests, wiring module imports as needed.
/// Optional `openssl-include-dir` and `openssl-lib-dir` values are forwarded to TLS-related compilation units.
/// `b` must be a valid build context supplied by Zig's build system; this function mutates the graph and does not return an error.
pub fn build(b: *std.Build) void {
    enforce_required_zig_toolchain(b);

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const openssl_include_dir = b.option(
        []const u8,
        "openssl-include-dir",
        "Optional OpenSSL include directory (for cross builds)",
    );
    const openssl_lib_dir = b.option(
        []const u8,
        "openssl-lib-dir",
        "Optional OpenSSL library directory (for cross builds)",
    );

    // =========================================================================
    // Serval Library Modules
    // =========================================================================

    // Foundation module - no dependencies
    const serval_core_module = b.addModule("serval-core", .{
        .root_source_file = b.path("serval-core/mod.zig"),
    });

    // TLS module - depends on core for logging (Layer 1 - Protocol)
    // Note: Linking happens per compilation unit (tests, executables)
    // Modules cannot link libraries directly in Zig build system
    const serval_tls_module = b.addModule("serval-tls", .{
        .root_source_file = b.path("serval-tls/mod.zig"),
        .link_libc = true,
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });
    apply_optional_openssl_paths(serval_tls_module, openssl_include_dir, openssl_lib_dir);

    // Network utilities - DNS + TCP helpers (Layer 1 - Protocol)
    // Note: Socket abstraction moved to serval-socket (Layer 2)
    const serval_net_module = b.addModule("serval-net", .{
        .root_source_file = b.path("serval-net/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // Socket abstraction - unified TCP/TLS socket (Layer 2 - Infrastructure)
    // Composes serval-tls primitives into a tagged union Socket type
    const serval_socket_module = b.addModule("serval-socket", .{
        .root_source_file = b.path("serval-socket/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
        },
    });

    // CLI module - no dependencies
    const serval_cli_module = b.addModule("serval-cli", .{
        .root_source_file = b.path("serval-cli/mod.zig"),
    });

    // Pool module - depends on core and socket
    const serval_pool_module = b.addModule("serval-pool", .{
        .root_source_file = b.path("serval-pool/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-socket", .module = serval_socket_module },
        },
    });

    // HTTP parser module - depends on core
    const serval_http_module = b.addModule("serval-http", .{
        .root_source_file = b.path("serval-http/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // WebSocket protocol helpers - depends on core (Layer 1 - Protocol)
    const serval_websocket_module = b.addModule("serval-websocket", .{
        .root_source_file = b.path("serval-websocket/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // HTTP/2 / h2c protocol helpers - depends on core (Layer 1 - Protocol)
    const serval_h2_module = b.addModule("serval-h2", .{
        .root_source_file = b.path("serval-h2/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // gRPC protocol helpers - depends on core (Layer 2 - Infrastructure)
    const serval_grpc_module = b.addModule("serval-grpc", .{
        .root_source_file = b.path("serval-grpc/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // ACME certificate automation primitives - depends on core (Layer 2 - Infrastructure)
    const serval_acme_module = b.addModule("serval-acme", .{
        .root_source_file = b.path("serval-acme/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-socket", .module = serval_socket_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
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

    // Health module - depends on core
    const serval_health_module = b.addModule("serval-health", .{
        .root_source_file = b.path("serval-health/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // WAF module - depends on core (Layer 2 - Infrastructure)
    const serval_waf_module = b.addModule("serval-waf", .{
        .root_source_file = b.path("serval-waf/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // Client module - depends on core, http, net, socket, pool, tls, h2 (Layer 3 - Mechanics)
    // HTTP/1.1 client plus bounded HTTP/2 client primitives for upstream sessions
    const serval_client_module = b.addModule("serval-client", .{
        .root_source_file = b.path("serval-client/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-socket", .module = serval_socket_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
            .{ .name = "serval-h2", .module = serval_h2_module },
        },
    });

    // ACME transport adapter depends on serval-client for wire execution.
    serval_acme_module.addImport("serval-client", serval_client_module);

    // OpenTelemetry module - depends on core, tracing, client, net, socket, tls, pool
    // Uses serval-client for HTTP export with proper K8s DNS resolution
    const serval_otel_module = b.addModule("serval-otel", .{
        .root_source_file = b.path("serval-otel/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
            .{ .name = "serval-client", .module = serval_client_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-socket", .module = serval_socket_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
        },
    });

    // Proxy module - depends on core, net, socket, pool, tracing, http, websocket, h2, grpc, tls, client
    const serval_proxy_module = b.addModule("serval-proxy", .{
        .root_source_file = b.path("serval-proxy/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-socket", .module = serval_socket_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-websocket", .module = serval_websocket_module },
            .{ .name = "serval-h2", .module = serval_h2_module },
            .{ .name = "serval-grpc", .module = serval_grpc_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
            .{ .name = "serval-client", .module = serval_client_module },
        },
    });

    // Reverse-proxy orchestrator runtime module - canonical IR + generation lifecycle
    const serval_reverseproxy_module = b.addModule("serval-reverseproxy", .{
        .root_source_file = b.path("serval-reverseproxy/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // Filter SDK module - restricted surface for user-authored filters.
    const serval_filter_sdk_module = b.addModule("serval-filter-sdk", .{
        .root_source_file = b.path("serval-filter-sdk/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
        },
    });

    // Server module - composes core, net, socket, http, websocket, h2, grpc, pool, proxy, client, metrics, tracing, tls
    const serval_server_module = b.addModule("serval-server", .{
        .root_source_file = b.path("serval-server/mod.zig"),
        .imports = &.{
            .{ .name = "serval-core", .module = serval_core_module },
            .{ .name = "serval-net", .module = serval_net_module },
            .{ .name = "serval-socket", .module = serval_socket_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-websocket", .module = serval_websocket_module },
            .{ .name = "serval-h2", .module = serval_h2_module },
            .{ .name = "serval-grpc", .module = serval_grpc_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
            .{ .name = "serval-proxy", .module = serval_proxy_module },
            .{ .name = "serval-client", .module = serval_client_module },
            .{ .name = "serval-metrics", .module = serval_metrics_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
            .{ .name = "serval-tls", .module = serval_tls_module },
            .{ .name = "serval-acme", .module = serval_acme_module },
        },
    });

    // Reverseproxy runtime depends on server runtime composition modules.
    serval_reverseproxy_module.addImport("serval-filter-sdk", serval_filter_sdk_module);
    serval_reverseproxy_module.addImport("serval-net", serval_net_module);
    serval_reverseproxy_module.addImport("serval-pool", serval_pool_module);
    serval_reverseproxy_module.addImport("serval-metrics", serval_metrics_module);
    serval_reverseproxy_module.addImport("serval-tracing", serval_tracing_module);
    serval_reverseproxy_module.addImport("serval-server", serval_server_module);
    serval_reverseproxy_module.addImport("serval-acme", serval_acme_module);
    serval_reverseproxy_module.addImport("serval-otel", serval_otel_module);

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

    // Server frontend TCP runtime reuses shared LB strategy core.
    serval_server_module.addImport("serval-lb", serval_lb_module);

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

    // Reverseproxy runtime uses router strategy as the routing engine.
    serval_reverseproxy_module.addImport("serval-router", serval_router_module);

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
            .{ .name = "serval-socket", .module = serval_socket_module },
            .{ .name = "serval-http", .module = serval_http_module },
            .{ .name = "serval-websocket", .module = serval_websocket_module },
            .{ .name = "serval-h2", .module = serval_h2_module },
            .{ .name = "serval-grpc", .module = serval_grpc_module },
            .{ .name = "serval-acme", .module = serval_acme_module },
            .{ .name = "serval-pool", .module = serval_pool_module },
            .{ .name = "serval-proxy", .module = serval_proxy_module },
            .{ .name = "serval-reverseproxy", .module = serval_reverseproxy_module },
            .{ .name = "serval-filter-sdk", .module = serval_filter_sdk_module },
            .{ .name = "serval-metrics", .module = serval_metrics_module },
            .{ .name = "serval-tracing", .module = serval_tracing_module },
            .{ .name = "serval-otel", .module = serval_otel_module },
            .{ .name = "serval-waf", .module = serval_waf_module },
            .{ .name = "serval-server", .module = serval_server_module },
            .{ .name = "serval-router", .module = serval_router_module },
        },
    });

    // Build-time pub const ownership audit tool.
    const pub_const_audit_options = b.addOptions();
    pub_const_audit_options.addOption([]const u8, "repo_root", b.pathFromRoot("."));

    const pub_const_audit_mod = b.createModule(.{
        .root_source_file = b.path("tools/pub_const_audit.zig"),
        .target = target,
        .optimize = optimize,
    });
    pub_const_audit_mod.addOptions("pub_const_audit_options", pub_const_audit_options);

    const pub_const_audit = b.addExecutable(.{
        .name = "pub-const-audit",
        .root_module = pub_const_audit_mod,
    });
    force_llvm_lld(pub_const_audit);

    const run_pub_const_audit = b.addRunArtifact(pub_const_audit);
    run_pub_const_audit.addArgs(&.{
        "--repo-root",
        b.pathFromRoot("."),
    });
    const audit_pub_consts_step = b.step(
        "audit-pub-consts",
        "Audit top-level non-core pub const ownership and semantic duplicates",
    );
    audit_pub_consts_step.dependOn(&run_pub_const_audit.step);

    const run_pub_const_audit_report = b.addRunArtifact(pub_const_audit);
    run_pub_const_audit_report.addArgs(&.{
        "--repo-root",
        b.pathFromRoot("."),
        "--report-only",
    });
    const audit_pub_consts_report_step = b.step(
        "audit-pub-consts-report",
        "Report top-level non-core pub const ownership and semantic duplicates without failing",
    );
    audit_pub_consts_report_step.dependOn(&run_pub_const_audit_report.step);

    const pub_const_audit_tests_mod = b.createModule(.{
        .root_source_file = b.path("tools/pub_const_audit.zig"),
        .target = target,
        .optimize = optimize,
    });
    pub_const_audit_tests_mod.addOptions("pub_const_audit_options", pub_const_audit_options);
    const pub_const_audit_tests = b.addTest(.{
        .name = "pub_const_audit_tests",
        .root_module = pub_const_audit_tests_mod,
    });
    force_llvm_lld(pub_const_audit_tests);
    const run_pub_const_audit_tests = b.addRunArtifact(pub_const_audit_tests);

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
    serval_tests_mod.addImport("serval-socket", serval_socket_module);
    serval_tests_mod.addImport("serval-http", serval_http_module);
    serval_tests_mod.addImport("serval-websocket", serval_websocket_module);
    serval_tests_mod.addImport("serval-h2", serval_h2_module);
    serval_tests_mod.addImport("serval-grpc", serval_grpc_module);
    serval_tests_mod.addImport("serval-acme", serval_acme_module);
    serval_tests_mod.addImport("serval-pool", serval_pool_module);
    serval_tests_mod.addImport("serval-proxy", serval_proxy_module);
    serval_tests_mod.addImport("serval-reverseproxy", serval_reverseproxy_module);
    serval_tests_mod.addImport("serval-filter-sdk", serval_filter_sdk_module);
    serval_tests_mod.addImport("serval-metrics", serval_metrics_module);
    serval_tests_mod.addImport("serval-tracing", serval_tracing_module);
    serval_tests_mod.addImport("serval-otel", serval_otel_module);
    serval_tests_mod.addImport("serval-waf", serval_waf_module);
    serval_tests_mod.addImport("serval-server", serval_server_module);
    serval_tests_mod.addImport("serval-client", serval_client_module);
    const serval_tests = b.addTest(.{
        .name = "serval_tests",
        .root_module = serval_tests_mod,
    });
    force_llvm_lld(serval_tests);
    const run_serval_tests = b.addRunArtifact(serval_tests);

    const test_step = b.step("test", "Run all serval library tests");
    test_step.dependOn(&run_serval_tests.step);
    test_step.dependOn(&run_pub_const_audit_tests.step);

    const test_pub_const_audit_step = b.step(
        "test-pub-const-audit",
        "Run unit tests for the pub const ownership audit tool",
    );
    test_pub_const_audit_step.dependOn(&run_pub_const_audit_tests.step);

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
    lb_tests_mod.addImport("serval-socket", serval_socket_module);
    lb_tests_mod.addImport("serval-client", serval_client_module);
    const lb_tests = b.addTest(.{
        .name = "lb_tests",
        .root_module = lb_tests_mod,
    });
    force_llvm_lld(lb_tests);
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
    router_tests_mod.addImport("serval-socket", serval_socket_module);
    router_tests_mod.addImport("serval-client", serval_client_module);
    const router_tests = b.addTest(.{
        .name = "router_tests",
        .root_module = router_tests_mod,
    });
    force_llvm_lld(router_tests);
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
    gateway_tests_mod.addImport("serval-socket", serval_socket_module);
    gateway_tests_mod.addImport("serval-client", serval_client_module);
    gateway_tests_mod.addImport("serval-lb", serval_lb_module);
    gateway_tests_mod.addImport("serval-health", serval_health_module);
    gateway_tests_mod.addImport("serval-prober", serval_prober_module);
    const gateway_tests = b.addTest(.{
        .name = "gateway_tests",
        .root_module = gateway_tests_mod,
    });
    force_llvm_lld(gateway_tests);
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
    force_llvm_lld(health_tests);
    const run_health_tests = b.addRunArtifact(health_tests);

    const health_test_step = b.step("test-health", "Run serval-health library tests");
    health_test_step.dependOn(&run_health_tests.step);

    // WAF module tests
    const waf_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-waf/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    waf_tests_mod.addImport("serval-core", serval_core_module);
    const waf_tests = b.addTest(.{
        .name = "waf_tests",
        .root_module = waf_tests_mod,
    });
    force_llvm_lld(waf_tests);
    const run_waf_tests = b.addRunArtifact(waf_tests);

    const waf_test_step = b.step("test-waf", "Run serval-waf library tests");
    waf_test_step.dependOn(&run_waf_tests.step);

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
    tls_tests_mod.addImport("serval-core", serval_core_module);
    const tls_tests = b.addTest(.{
        .name = "tls_tests",
        .root_module = tls_tests_mod,
    });
    force_llvm_lld(tls_tests);
    const run_tls_tests = b.addRunArtifact(tls_tests);

    const tls_test_step = b.step("test-tls", "Run serval-tls library tests");
    tls_test_step.dependOn(&run_tls_tests.step);

    // Network module tests (DNS + TCP helpers)
    const net_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-net/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    net_tests_mod.addImport("serval-core", serval_core_module);
    const net_tests = b.addTest(.{
        .name = "net_tests",
        .root_module = net_tests_mod,
    });
    force_llvm_lld(net_tests);
    const run_net_tests = b.addRunArtifact(net_tests);

    const net_test_step = b.step("test-net", "Run serval-net library tests");
    net_test_step.dependOn(&run_net_tests.step);

    // WebSocket protocol module tests
    const websocket_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-websocket/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    websocket_tests_mod.addImport("serval-core", serval_core_module);
    const websocket_tests = b.addTest(.{
        .name = "websocket_tests",
        .root_module = websocket_tests_mod,
    });
    force_llvm_lld(websocket_tests);
    const run_websocket_tests = b.addRunArtifact(websocket_tests);

    const websocket_test_step = b.step("test-websocket", "Run serval-websocket library tests");
    websocket_test_step.dependOn(&run_websocket_tests.step);

    // HTTP/2 / h2c protocol module tests
    const h2_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-h2/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    h2_tests_mod.addImport("serval-core", serval_core_module);
    const h2_tests = b.addTest(.{
        .name = "h2_tests",
        .root_module = h2_tests_mod,
    });
    force_llvm_lld(h2_tests);
    const run_h2_tests = b.addRunArtifact(h2_tests);

    const h2_test_step = b.step("test-h2", "Run serval-h2 library tests");
    h2_test_step.dependOn(&run_h2_tests.step);

    // gRPC protocol module tests
    const grpc_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-grpc/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    grpc_tests_mod.addImport("serval-core", serval_core_module);
    const grpc_tests = b.addTest(.{
        .name = "grpc_tests",
        .root_module = grpc_tests_mod,
    });
    force_llvm_lld(grpc_tests);
    const run_grpc_tests = b.addRunArtifact(grpc_tests);

    const grpc_test_step = b.step("test-grpc", "Run serval-grpc library tests");
    grpc_test_step.dependOn(&run_grpc_tests.step);

    // ACME module tests
    const acme_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-acme/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    acme_tests_mod.linkSystemLibrary("ssl", .{});
    acme_tests_mod.linkSystemLibrary("crypto", .{});
    acme_tests_mod.addImport("serval-core", serval_core_module);
    acme_tests_mod.addImport("serval-http", serval_http_module);
    acme_tests_mod.addImport("serval-net", serval_net_module);
    acme_tests_mod.addImport("serval-socket", serval_socket_module);
    acme_tests_mod.addImport("serval-client", serval_client_module);
    acme_tests_mod.addImport("serval-tls", serval_tls_module);
    const acme_tests = b.addTest(.{
        .name = "acme_tests",
        .root_module = acme_tests_mod,
    });
    force_llvm_lld(acme_tests);
    const run_acme_tests = b.addRunArtifact(acme_tests);

    const acme_test_step = b.step("test-acme", "Run serval-acme library tests");
    acme_test_step.dependOn(&run_acme_tests.step);

    // Client h2 primitive tests
    const client_h2_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-client/h2/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    client_h2_tests_mod.linkSystemLibrary("ssl", .{});
    client_h2_tests_mod.linkSystemLibrary("crypto", .{});
    client_h2_tests_mod.addImport("serval-core", serval_core_module);
    client_h2_tests_mod.addImport("serval-h2", serval_h2_module);
    client_h2_tests_mod.addImport("serval-socket", serval_socket_module);
    const client_h2_tests = b.addTest(.{
        .name = "client_h2_tests",
        .root_module = client_h2_tests_mod,
    });
    force_llvm_lld(client_h2_tests);
    const run_client_h2_tests = b.addRunArtifact(client_h2_tests);

    const client_test_step = b.step("test-client", "Run serval-client h2 primitive tests");
    client_test_step.dependOn(&run_client_h2_tests.step);

    // Proxy h2 primitive tests
    const proxy_h2_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-proxy/h2/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    proxy_h2_tests_mod.linkSystemLibrary("ssl", .{});
    proxy_h2_tests_mod.linkSystemLibrary("crypto", .{});
    proxy_h2_tests_mod.addImport("serval-core", serval_core_module);
    proxy_h2_tests_mod.addImport("serval-client", serval_client_module);
    proxy_h2_tests_mod.addImport("serval-h2", serval_h2_module);
    proxy_h2_tests_mod.addImport("serval-net", serval_net_module);
    const proxy_h2_tests = b.addTest(.{
        .name = "proxy_h2_tests",
        .root_module = proxy_h2_tests_mod,
    });
    force_llvm_lld(proxy_h2_tests);
    const run_proxy_h2_tests = b.addRunArtifact(proxy_h2_tests);

    const proxy_test_step = b.step("test-proxy", "Run serval-proxy h2 primitive tests");
    proxy_test_step.dependOn(&run_proxy_h2_tests.step);

    // Reverseproxy module tests (IR/admission/orchestration + DSL equivalence)
    const reverseproxy_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-reverseproxy/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    reverseproxy_tests_mod.addImport("serval-core", serval_core_module);
    reverseproxy_tests_mod.addImport("serval-filter-sdk", serval_filter_sdk_module);
    reverseproxy_tests_mod.addImport("serval-net", serval_net_module);
    reverseproxy_tests_mod.addImport("serval-pool", serval_pool_module);
    reverseproxy_tests_mod.addImport("serval-metrics", serval_metrics_module);
    reverseproxy_tests_mod.addImport("serval-tracing", serval_tracing_module);
    reverseproxy_tests_mod.addImport("serval-server", serval_server_module);
    reverseproxy_tests_mod.addImport("serval-router", serval_router_module);
    reverseproxy_tests_mod.addImport("serval-acme", serval_acme_module);
    reverseproxy_tests_mod.addImport("serval-otel", serval_otel_module);
    reverseproxy_tests_mod.linkSystemLibrary("ssl", .{});
    reverseproxy_tests_mod.linkSystemLibrary("crypto", .{});
    const reverseproxy_tests = b.addTest(.{
        .name = "reverseproxy_tests",
        .root_module = reverseproxy_tests_mod,
    });
    force_llvm_lld(reverseproxy_tests);
    const run_reverseproxy_tests = b.addRunArtifact(reverseproxy_tests);

    const reverseproxy_test_step = b.step("test-reverseproxy", "Run serval-reverseproxy library tests");
    reverseproxy_test_step.dependOn(&run_reverseproxy_tests.step);

    const reverseproxy_integration_tests = b.addTest(.{
        .name = "reverseproxy_integration_tests",
        .root_module = reverseproxy_tests_mod,
        .filters = &.{"integration: reverseproxy"},
    });
    force_llvm_lld(reverseproxy_integration_tests);
    const run_reverseproxy_integration_tests = b.addRunArtifact(reverseproxy_integration_tests);

    const reverseproxy_integration_test_step = b.step(
        "test-reverseproxy-integration",
        "Run serval-reverseproxy cross-component integration tests",
    );
    reverseproxy_integration_test_step.dependOn(&run_reverseproxy_integration_tests.step);

    // Server module tests
    const server_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-server/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    server_tests_mod.linkSystemLibrary("ssl", .{});
    server_tests_mod.linkSystemLibrary("crypto", .{});
    server_tests_mod.addImport("serval-core", serval_core_module);
    server_tests_mod.addImport("serval-net", serval_net_module);
    server_tests_mod.addImport("serval-socket", serval_socket_module);
    server_tests_mod.addImport("serval-http", serval_http_module);
    server_tests_mod.addImport("serval-websocket", serval_websocket_module);
    server_tests_mod.addImport("serval-h2", serval_h2_module);
    server_tests_mod.addImport("serval-grpc", serval_grpc_module);
    server_tests_mod.addImport("serval-pool", serval_pool_module);
    server_tests_mod.addImport("serval-proxy", serval_proxy_module);
    server_tests_mod.addImport("serval-client", serval_client_module);
    server_tests_mod.addImport("serval-metrics", serval_metrics_module);
    server_tests_mod.addImport("serval-tracing", serval_tracing_module);
    server_tests_mod.addImport("serval-tls", serval_tls_module);
    server_tests_mod.addImport("serval-acme", serval_acme_module);
    const server_tests = b.addTest(.{
        .name = "server_tests",
        .root_module = server_tests_mod,
    });
    force_llvm_lld(server_tests);
    const run_server_tests = b.addRunArtifact(server_tests);

    const server_test_step = b.step("test-server", "Run serval-server library tests");
    server_test_step.dependOn(&run_server_tests.step);

    // Socket module tests (unified TCP/TLS socket abstraction)
    // Note: Links SSL libraries since serval-socket depends on serval-tls
    const socket_tests_mod = b.createModule(.{
        .root_source_file = b.path("serval-socket/mod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    socket_tests_mod.linkSystemLibrary("ssl", .{});
    socket_tests_mod.linkSystemLibrary("crypto", .{});
    socket_tests_mod.addImport("serval-tls", serval_tls_module);
    const socket_tests = b.addTest(.{
        .name = "socket_tests",
        .root_module = socket_tests_mod,
    });
    force_llvm_lld(socket_tests);
    const run_socket_tests = b.addRunArtifact(socket_tests);

    const socket_test_step = b.step("test-socket", "Run serval-socket library tests");
    socket_test_step.dependOn(&run_socket_tests.step);

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
    force_llvm_lld(otel_tests);
    const run_otel_tests = b.addRunArtifact(otel_tests);

    const otel_test_step = b.step("test-otel", "Run serval-otel library tests");
    otel_test_step.dependOn(&run_otel_tests.step);

    // Integration tests (end-to-end tests using subprocesses and in-process native WS servers)
    // Links serval modules for native WebSocket endpoint coverage.
    const integration_tests_mod = b.createModule(.{
        .root_source_file = b.path("integration/tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    integration_tests_mod.linkSystemLibrary("ssl", .{});
    integration_tests_mod.linkSystemLibrary("crypto", .{});
    integration_tests_mod.addImport("serval", serval_module);
    integration_tests_mod.addImport("serval-net", serval_net_module);
    integration_tests_mod.addImport("serval-h2", serval_h2_module);
    integration_tests_mod.addImport("serval-grpc", serval_grpc_module);
    integration_tests_mod.addImport("serval-client", serval_client_module);
    integration_tests_mod.addImport("serval-tls", serval_tls_module);
    const integration_tests = b.addTest(.{
        .name = "integration_tests",
        .root_module = integration_tests_mod,
        // Custom test runner that prints each test name
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_tests);
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const integration_test_step = b.step("test-integration", "Run integration tests");
    integration_test_step.dependOn(&run_integration_tests.step);

    const integration_test_udp_runtime = b.addTest(.{
        .name = "integration_test_udp_runtime",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: udp runtime"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_udp_runtime);
    const run_integration_test_udp_runtime = b.addRunArtifact(integration_test_udp_runtime);

    const integration_test_udp_runtime_step = b.step(
        "test-integration-udp-runtime",
        "Run integration UDP runtime tests",
    );
    integration_test_udp_runtime_step.dependOn(&run_integration_test_udp_runtime.step);

    const integration_test_tcp_runtime = b.addTest(.{
        .name = "integration_test_tcp_runtime",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: tcp runtime"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_tcp_runtime);
    const run_integration_test_tcp_runtime = b.addRunArtifact(integration_test_tcp_runtime);

    const integration_test_tcp_runtime_step = b.step(
        "test-integration-tcp-runtime",
        "Run integration TCP runtime tests",
    );
    integration_test_tcp_runtime_step.dependOn(&run_integration_test_tcp_runtime.step);

    const integration_test_reverseproxy = b.addTest(.{
        .name = "integration_test_reverseproxy",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: reverseproxy"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_reverseproxy);
    const run_integration_test_reverseproxy = b.addRunArtifact(integration_test_reverseproxy);

    const integration_test_reverseproxy_step = b.step(
        "test-integration-reverseproxy",
        "Run integration reverseproxy tests",
    );
    integration_test_reverseproxy_step.dependOn(&run_integration_test_reverseproxy.step);

    const integration_test_netbird = b.addTest(.{
        .name = "integration_test_netbird",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: netbird"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_netbird);
    const run_integration_test_netbird = b.addRunArtifact(integration_test_netbird);

    const integration_test_netbird_step = b.step(
        "test-integration-netbird",
        "Run integration netbird tests",
    );
    integration_test_netbird_step.dependOn(&run_integration_test_netbird.step);

    const acme_pebble_smoke = b.addSystemCommand(&.{
        "bash",
        "integration/acme_pebble_smoke.sh",
    });
    const test_acme_pebble_step = b.step("test-acme-pebble", "Run Docker Pebble ACME smoke test");
    test_acme_pebble_step.dependOn(&acme_pebble_smoke.step);

    const integration_test_64 = b.addTest(.{
        .name = "integration_test_64",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c stream churn near concurrent-stream bound"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_64);
    const run_integration_test_64 = b.addRunArtifact(integration_test_64);

    const integration_test_64_step = b.step(
        "test-integration-64",
        "Run integration test 64 (grpc h2c stream churn near concurrent-stream bound)",
    );
    integration_test_64_step.dependOn(&run_integration_test_64.step);

    const integration_test_perf_throughput_h1 = b.addTest(.{
        .name = "integration_test_perf_throughput_h1",
        .root_module = integration_tests_mod,
        .filters = &.{"performance: lb h1 achieves minimum throughput with hey"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_perf_throughput_h1);
    const run_integration_test_perf_throughput_h1 = b.addRunArtifact(integration_test_perf_throughput_h1);

    const integration_test_perf_throughput_h2 = b.addTest(.{
        .name = "integration_test_perf_throughput_h2",
        .root_module = integration_tests_mod,
        .filters = &.{"performance: h2 conformance server achieves minimum throughput with h2load"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_perf_throughput_h2);
    const run_integration_test_perf_throughput_h2 = b.addRunArtifact(integration_test_perf_throughput_h2);
    const run_integration_test_perf_throughput_h2_max = b.addRunArtifact(integration_test_perf_throughput_h2);

    // Perf throughput gates are opt-in in integration/tests.zig; force-enable for dedicated steps.
    run_integration_test_perf_throughput_h1.setEnvironmentVariable("SERVAL_ENABLE_PERF_TEST", "1");
    run_integration_test_perf_throughput_h2.setEnvironmentVariable("SERVAL_ENABLE_PERF_TEST", "1");
    run_integration_test_perf_throughput_h2_max.setEnvironmentVariable("SERVAL_ENABLE_PERF_TEST", "1");
    run_integration_test_perf_throughput_h2_max.setEnvironmentVariable("SERVAL_PERF_TEST_REQUESTS_H2", "500000");
    run_integration_test_perf_throughput_h2_max.setEnvironmentVariable("SERVAL_PERF_TEST_CONCURRENCY_H2", "100");
    run_integration_test_perf_throughput_h2_max.setEnvironmentVariable("SERVAL_PERF_TEST_H2LOAD_THREADS", "8");
    run_integration_test_perf_throughput_h2_max.setEnvironmentVariable("SERVAL_PERF_TEST_H2LOAD_MAX_STREAMS", "64");
    run_integration_test_perf_throughput_h2_max.setEnvironmentVariable("SERVAL_PERF_TEST_H2LOAD_DURATION_S", "15");
    run_integration_test_perf_throughput_h2_max.setEnvironmentVariable("SERVAL_PERF_TEST_MIN_RPS_H2", "1");

    const integration_test_perf_throughput_h1_step = b.step(
        "test-integration-perf-throughput-h1",
        "Run integration perf test (lb HTTP/1.1 minimum throughput with hey)",
    );
    integration_test_perf_throughput_h1_step.dependOn(&run_integration_test_perf_throughput_h1.step);

    const integration_test_perf_throughput_h2_step = b.step(
        "test-integration-perf-throughput-h2",
        "Run integration perf test (terminated HTTP/2 server minimum throughput with h2load)",
    );
    integration_test_perf_throughput_h2_step.dependOn(&run_integration_test_perf_throughput_h2.step);

    const integration_test_perf_throughput_h2_max_step = b.step(
        "test-integration-perf-throughput-h2-max",
        "Run integration perf test (terminated HTTP/2 server, max-profile h2load: -D15 -t8 -c100 -m64)",
    );
    integration_test_perf_throughput_h2_max_step.dependOn(&run_integration_test_perf_throughput_h2_max.step);

    const integration_test_perf_throughput_step = b.step(
        "test-integration-perf-throughput",
        "Run integration perf tests (lb HTTP/1.1 with hey + terminated HTTP/2 with h2load)",
    );
    integration_test_perf_throughput_step.dependOn(&run_integration_test_perf_throughput_h1.step);
    integration_test_perf_throughput_step.dependOn(&run_integration_test_perf_throughput_h2.step);

    const integration_test_h2c_reset_isolation = b.addTest(.{
        .name = "integration_test_h2c_reset_isolation",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c upstream reset on one stream preserves sibling stream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_reset_isolation);
    const run_integration_test_h2c_reset_isolation = b.addRunArtifact(integration_test_h2c_reset_isolation);

    const integration_test_h2c_reset_isolation_step = b.step(
        "test-integration-h2c-reset-isolation",
        "Run integration test (grpc h2c reset on one stream preserves sibling stream)",
    );
    integration_test_h2c_reset_isolation_step.dependOn(&run_integration_test_h2c_reset_isolation.step);

    const integration_test_h2c_reset_isolation_soak = b.addTest(.{
        .name = "integration_test_h2c_reset_isolation_soak",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c reset isolation soak loop"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_reset_isolation_soak);
    const run_integration_test_h2c_reset_isolation_soak = b.addRunArtifact(integration_test_h2c_reset_isolation_soak);

    const integration_test_h2c_reset_isolation_soak_step = b.step(
        "test-integration-h2c-reset-isolation-soak",
        "Run integration test (grpc h2c reset-isolation soak loop)",
    );
    integration_test_h2c_reset_isolation_soak_step.dependOn(&run_integration_test_h2c_reset_isolation_soak.step);

    const integration_test_h2c_goaway_last_stream = b.addTest(.{
        .name = "integration_test_h2c_goaway_last_stream",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c goaway last_stream_id resets higher stream and keeps lower stream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_goaway_last_stream);
    const run_integration_test_h2c_goaway_last_stream = b.addRunArtifact(integration_test_h2c_goaway_last_stream);

    const integration_test_h2c_goaway_last_stream_step = b.step(
        "test-integration-h2c-goaway-last-stream",
        "Run integration test (grpc h2c GOAWAY last_stream_id resets higher stream)",
    );
    integration_test_h2c_goaway_last_stream_step.dependOn(&run_integration_test_h2c_goaway_last_stream.step);

    const integration_test_h2c_goaway_rollover_loop = b.addTest(.{
        .name = "integration_test_h2c_goaway_rollover_loop",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c repeated goaway rollover opens fresh upstream sessions"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_goaway_rollover_loop);
    const run_integration_test_h2c_goaway_rollover_loop = b.addRunArtifact(integration_test_h2c_goaway_rollover_loop);

    const integration_test_h2c_goaway_rollover_loop_step = b.step(
        "test-integration-h2c-goaway-rollover-loop",
        "Run integration test (grpc h2c repeated GOAWAY rollover opens fresh upstream sessions)",
    );
    integration_test_h2c_goaway_rollover_loop_step.dependOn(&run_integration_test_h2c_goaway_rollover_loop.step);

    const integration_test_h2c_goaway_rollover_soak = b.addTest(.{
        .name = "integration_test_h2c_goaway_rollover_soak",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c repeated goaway rollover soak loop"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_goaway_rollover_soak);
    const run_integration_test_h2c_goaway_rollover_soak = b.addRunArtifact(integration_test_h2c_goaway_rollover_soak);

    const integration_test_h2c_goaway_rollover_soak_step = b.step(
        "test-integration-h2c-goaway-rollover-soak",
        "Run integration test (grpc h2c repeated GOAWAY rollover soak loop)",
    );
    integration_test_h2c_goaway_rollover_soak_step.dependOn(&run_integration_test_h2c_goaway_rollover_soak.step);

    const integration_test_h2c_upgrade_goaway_rollover_loop = b.addTest(.{
        .name = "integration_test_h2c_upgrade_goaway_rollover_loop",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c upgrade repeated goaway rollover opens fresh upstream sessions"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_upgrade_goaway_rollover_loop);
    const run_integration_test_h2c_upgrade_goaway_rollover_loop = b.addRunArtifact(integration_test_h2c_upgrade_goaway_rollover_loop);

    const integration_test_h2c_upgrade_goaway_rollover_loop_step = b.step(
        "test-integration-h2c-upgrade-goaway-rollover-loop",
        "Run integration test (grpc h2c upgrade repeated GOAWAY rollover opens fresh upstream sessions)",
    );
    integration_test_h2c_upgrade_goaway_rollover_loop_step.dependOn(&run_integration_test_h2c_upgrade_goaway_rollover_loop.step);

    const integration_test_h2c_upgrade_goaway_rollover_soak = b.addTest(.{
        .name = "integration_test_h2c_upgrade_goaway_rollover_soak",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c upgrade repeated goaway rollover soak loop"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_upgrade_goaway_rollover_soak);
    const run_integration_test_h2c_upgrade_goaway_rollover_soak = b.addRunArtifact(integration_test_h2c_upgrade_goaway_rollover_soak);

    const integration_test_h2c_upgrade_goaway_rollover_soak_step = b.step(
        "test-integration-h2c-upgrade-goaway-rollover-soak",
        "Run integration test (grpc h2c upgrade repeated GOAWAY rollover soak loop)",
    );
    integration_test_h2c_upgrade_goaway_rollover_soak_step.dependOn(&run_integration_test_h2c_upgrade_goaway_rollover_soak.step);

    const integration_test_h2c_cancel_propagation = b.addTest(.{
        .name = "integration_test_h2c_cancel_propagation",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c downstream cancel propagates upstream and preserves next stream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_cancel_propagation);
    const run_integration_test_h2c_cancel_propagation = b.addRunArtifact(integration_test_h2c_cancel_propagation);

    const integration_test_h2c_cancel_propagation_step = b.step(
        "test-integration-h2c-cancel-propagation",
        "Run integration test (grpc h2c downstream cancel propagates upstream)",
    );
    integration_test_h2c_cancel_propagation_step.dependOn(&run_integration_test_h2c_cancel_propagation.step);

    const integration_test_h2c_cancel_goaway_overlap = b.addTest(.{
        .name = "integration_test_h2c_cancel_goaway_overlap",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c cancel and goaway overlap loop preserves subsequent streams"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_cancel_goaway_overlap);
    const run_integration_test_h2c_cancel_goaway_overlap = b.addRunArtifact(integration_test_h2c_cancel_goaway_overlap);

    const integration_test_h2c_cancel_goaway_overlap_step = b.step(
        "test-integration-h2c-cancel-goaway-overlap",
        "Run integration test (grpc h2c cancel + GOAWAY overlap loop)",
    );
    integration_test_h2c_cancel_goaway_overlap_step.dependOn(&run_integration_test_h2c_cancel_goaway_overlap.step);

    const integration_test_h2c_cancel_goaway_overlap_soak = b.addTest(.{
        .name = "integration_test_h2c_cancel_goaway_overlap_soak",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c cancel and goaway overlap soak loop"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_cancel_goaway_overlap_soak);
    const run_integration_test_h2c_cancel_goaway_overlap_soak = b.addRunArtifact(integration_test_h2c_cancel_goaway_overlap_soak);

    const integration_test_h2c_cancel_goaway_overlap_soak_step = b.step(
        "test-integration-h2c-cancel-goaway-overlap-soak",
        "Run integration test (grpc h2c cancel + GOAWAY overlap soak loop)",
    );
    integration_test_h2c_cancel_goaway_overlap_soak_step.dependOn(&run_integration_test_h2c_cancel_goaway_overlap_soak.step);

    const integration_test_32 = b.addTest(.{
        .name = "integration_test_32",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: terminated h2 server replenishes flow-control windows for multi-frame request"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_32);
    const run_integration_test_32 = b.addRunArtifact(integration_test_32);

    const integration_test_32_step = b.step(
        "test-integration-32",
        "Run integration test 32 (terminated h2 server replenishes flow-control windows for multi-frame request)",
    );
    integration_test_32_step.dependOn(&run_integration_test_32.step);

    const integration_test_34 = b.addTest(.{
        .name = "integration_test_34",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2 prior-knowledge unary request is proxied to tls h2 upstream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_34);
    const run_integration_test_34 = b.addRunArtifact(integration_test_34);

    const integration_test_34_step = b.step(
        "test-integration-34",
        "Run integration test 34 (grpc h2 prior-knowledge unary request is proxied to tls h2 upstream)",
    );
    integration_test_34_step.dependOn(&run_integration_test_34.step);

    const integration_test_22 = b.addTest(.{
        .name = "integration_test_22",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: reverseproxy runtime binary uses first-match route semantics"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_22);
    const run_integration_test_22 = b.addRunArtifact(integration_test_22);

    const integration_test_22_step = b.step(
        "test-integration-22",
        "Run integration test 22 (reverseproxy runtime binary uses first-match route semantics)",
    );
    integration_test_22_step.dependOn(&run_integration_test_22.step);

    const integration_test_5 = b.addTest(.{
        .name = "integration_test_5",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: echo backend responds with chunked encoding"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_5);
    const run_integration_test_5 = b.addRunArtifact(integration_test_5);

    const integration_test_5_step = b.step(
        "test-integration-5",
        "Run integration test 5 (echo backend responds with chunked encoding)",
    );
    integration_test_5_step.dependOn(&run_integration_test_5.step);

    const integration_test_echo_backend_200 = b.addTest(.{
        .name = "integration_test_echo_backend_200",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: echo backend responds with 200"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_echo_backend_200);
    const run_integration_test_echo_backend_200 = b.addRunArtifact(integration_test_echo_backend_200);

    const integration_test_echo_backend_200_step = b.step(
        "test-integration-echo-backend-200",
        "Run integration test (echo backend responds with 200)",
    );
    integration_test_echo_backend_200_step.dependOn(&run_integration_test_echo_backend_200.step);

    const integration_test_2 = b.addTest(.{
        .name = "integration_test_2",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: lb forwards to single backend"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_2);
    const run_integration_test_2 = b.addRunArtifact(integration_test_2);

    const integration_test_2_step = b.step(
        "test-integration-2",
        "Run integration test 2 (lb forwards to single backend)",
    );
    integration_test_2_step.dependOn(&run_integration_test_2.step);

    const integration_test_16 = b.addTest(.{
        .name = "integration_test_16",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: native websocket endpoint and proxy websocket fallback coexist"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_16);
    const run_integration_test_16 = b.addRunArtifact(integration_test_16);

    const integration_test_16_step = b.step(
        "test-integration-16",
        "Run integration test 16 (native websocket endpoint and proxy websocket fallback coexist)",
    );
    integration_test_16_step.dependOn(&run_integration_test_16.step);

    const integration_test_18 = b.addTest(.{
        .name = "integration_test_18",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: netbird route matrix enforces grpc h2c only for service paths"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_18);
    const run_integration_test_18 = b.addRunArtifact(integration_test_18);

    const integration_test_18_step = b.step(
        "test-integration-18",
        "Run integration test 18 (netbird route matrix enforces grpc h2c only for service paths)",
    );
    integration_test_18_step.dependOn(&run_integration_test_18.step);

    const integration_ws_netbird_debug_step = b.step(
        "test-integration-ws-netbird-debug",
        "Run failing integration tests 16 + 18 for focused debugging",
    );
    integration_ws_netbird_debug_step.dependOn(&run_integration_test_16.step);
    integration_ws_netbird_debug_step.dependOn(&run_integration_test_18.step);

    const integration_test_136 = b.addTest(.{
        .name = "integration_test_136",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: tcp runtime accepts downstream and records upstream outcome"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_136);
    const run_integration_test_136 = b.addRunArtifact(integration_test_136);

    const integration_test_136_step = b.step(
        "test-integration-136",
        "Run integration test 136 (tcp runtime accepts downstream and records upstream outcome)",
    );
    integration_test_136_step.dependOn(&run_integration_test_136.step);

    const integration_test_139 = b.addTest(.{
        .name = "integration_test_139",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: tcp runtime idle timeout closes inactive tunnel"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_139);
    const run_integration_test_139 = b.addRunArtifact(integration_test_139);

    const integration_test_139_step = b.step(
        "test-integration-139",
        "Run integration test 139 (tcp runtime idle timeout closes inactive tunnel)",
    );
    integration_test_139_step.dependOn(&run_integration_test_139.step);

    const integration_debug_port_step = b.step(
        "test-integration-debug-port",
        "Run the two port-sensitive integration tests (echo backend 200 + lb forwards single backend)",
    );
    integration_debug_port_step.dependOn(&run_integration_test_echo_backend_200.step);
    integration_debug_port_step.dependOn(&run_integration_test_2.step);

    const integration_test_38 = b.addTest(.{
        .name = "integration_test_38",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpcurl tls unary interop against grpc h2 proxy"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_38);
    const run_integration_test_38 = b.addRunArtifact(integration_test_38);

    const integration_test_38_step = b.step(
        "test-integration-38",
        "Run integration test 38 (grpcurl tls unary interop against grpc h2 proxy)",
    );
    integration_test_38_step.dependOn(&run_integration_test_38.step);

    const integration_test_70 = b.addTest(.{
        .name = "integration_test_70",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpcurl plaintext unary interop asserts metadata and trailers against grpc h2c proxy"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_70);
    const run_integration_test_70 = b.addRunArtifact(integration_test_70);

    const integration_test_70_step = b.step(
        "test-integration-70",
        "Run integration test 70 (grpcurl plaintext unary interop asserts metadata and trailers against grpc h2c proxy)",
    );
    integration_test_70_step.dependOn(&run_integration_test_70.step);

    const integration_test_92 = b.addTest(.{
        .name = "integration_test_92",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c goaway last_stream_id resets higher stream and keeps lower stream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_92);
    const run_integration_test_92 = b.addRunArtifact(integration_test_92);

    const integration_test_92_step = b.step(
        "test-integration-92",
        "Run integration test 92 (grpc h2c goaway last_stream_id resets higher stream and keeps lower stream)",
    );
    integration_test_92_step.dependOn(&run_integration_test_92.step);

    const integration_test_93 = b.addTest(.{
        .name = "integration_test_93",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c opens new upstream session after goaway for next stream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_93);
    const run_integration_test_93 = b.addRunArtifact(integration_test_93);

    const integration_test_93_step = b.step(
        "test-integration-93",
        "Run integration test 93 (grpc h2c opens new upstream session after goaway for next stream)",
    );
    integration_test_93_step.dependOn(&run_integration_test_93.step);

    const integration_test_99 = b.addTest(.{
        .name = "integration_test_99",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c mixed goaway and non-grpc trailer reset soak loop"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_99);
    const run_integration_test_99 = b.addRunArtifact(integration_test_99);

    const integration_test_99_step = b.step(
        "test-integration-99",
        "Run integration test 99 (grpc h2c mixed goaway and non-grpc trailer reset soak loop)",
    );
    integration_test_99_step.dependOn(&run_integration_test_99.step);

    const integration_test_101 = b.addTest(.{
        .name = "integration_test_101",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c missing grpc-status trailer maps to downstream reset"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_101);
    const run_integration_test_101 = b.addRunArtifact(integration_test_101);

    const integration_test_101_step = b.step(
        "test-integration-101",
        "Run integration test 101 (grpc h2c missing grpc-status trailer maps to downstream reset)",
    );
    integration_test_101_step.dependOn(&run_integration_test_101.step);

    const integration_test_105 = b.addTest(.{
        .name = "integration_test_105",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c stream churn near concurrent-stream bound"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_105);
    const run_integration_test_105 = b.addRunArtifact(integration_test_105);

    const integration_test_105_step = b.step(
        "test-integration-105",
        "Run integration test 105 (grpc h2c stream churn near concurrent-stream bound)",
    );
    integration_test_105_step.dependOn(&run_integration_test_105.step);

    const integration_test_37 = b.addTest(.{
        .name = "integration_test_37",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: netbird reverseproxy runtime dsl enforces grpc h2c split"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_37);
    const run_integration_test_37 = b.addRunArtifact(integration_test_37);

    const integration_test_37_step = b.step(
        "test-integration-37",
        "Run integration test 37 (netbird reverseproxy runtime dsl enforces grpc h2c split)",
    );
    integration_test_37_step.dependOn(&run_integration_test_37.step);

    const integration_test_42 = b.addTest(.{
        .name = "integration_test_42",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: serval-client h2 upstream session pool reuses connected session"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_42);
    const run_integration_test_42 = b.addRunArtifact(integration_test_42);

    const integration_test_42_step = b.step(
        "test-integration-42",
        "Run integration test 42 (serval-client h2 upstream session pool reuses connected session)",
    );
    integration_test_42_step.dependOn(&run_integration_test_42.step);

    const integration_test_78 = b.addTest(.{
        .name = "integration_test_78",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: lb forwards 1MB payload correctly"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_78);
    const run_integration_test_78 = b.addRunArtifact(integration_test_78);

    const integration_test_78_step = b.step(
        "test-integration-78",
        "Run integration test 78 (lb forwards 1MB payload correctly)",
    );
    integration_test_78_step.dependOn(&run_integration_test_78.step);

    const integration_test_77 = b.addTest(.{
        .name = "integration_test_77",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: lb forwards 100KB payload correctly"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_77);
    const run_integration_test_77 = b.addRunArtifact(integration_test_77);

    const integration_test_77_step = b.step(
        "test-integration-77",
        "Run integration test 77 (lb forwards 100KB payload correctly)",
    );
    integration_test_77_step.dependOn(&run_integration_test_77.step);

    const integration_test_h2_generic_post_no_cl = b.addTest(.{
        .name = "integration_test_h2_generic_post_no_cl",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: TLS ALPN h2 generic frontend forwards POST body without content-length for non-gRPC route"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2_generic_post_no_cl);
    const run_integration_test_h2_generic_post_no_cl = b.addRunArtifact(integration_test_h2_generic_post_no_cl);

    const integration_test_h2_generic_post_no_cl_step = b.step(
        "test-integration-h2-generic-post-no-cl",
        "Run integration test (TLS ALPN h2 generic frontend POST without content-length)",
    );
    integration_test_h2_generic_post_no_cl_step.dependOn(&run_integration_test_h2_generic_post_no_cl.step);

    const integration_test_56 = b.addTest(.{
        .name = "integration_test_56",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: TLS ALPN h2 generic frontend forwards non-gRPC route to h2c upstream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_56);
    const run_integration_test_56 = b.addRunArtifact(integration_test_56);

    const integration_test_56_step = b.step(
        "test-integration-56",
        "Run integration test 56 (TLS ALPN h2 generic frontend forwards non-gRPC route to h2c upstream)",
    );
    integration_test_56_step.dependOn(&run_integration_test_56.step);

    const integration_test_h2_generic_post = b.addTest(.{
        .name = "integration_test_h2_generic_post",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: TLS ALPN h2 generic frontend forwards POST body for non-gRPC route"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2_generic_post);
    const run_integration_test_h2_generic_post = b.addRunArtifact(integration_test_h2_generic_post);

    const integration_test_h2_generic_post_step = b.step(
        "test-integration-h2-generic-post",
        "Run integration test (TLS ALPN h2 generic frontend POST with content-length)",
    );
    integration_test_h2_generic_post_step.dependOn(&run_integration_test_h2_generic_post.step);

    const integration_test_h2_generic_invalid_te = b.addTest(.{
        .name = "integration_test_h2_generic_invalid_te",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: TLS ALPN h2 generic frontend resets stream on invalid TE value for non-gRPC route"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2_generic_invalid_te);
    const run_integration_test_h2_generic_invalid_te = b.addRunArtifact(integration_test_h2_generic_invalid_te);

    const integration_test_h2_generic_invalid_te_step = b.step(
        "test-integration-h2-generic-invalid-te",
        "Run integration test (TLS ALPN h2 generic frontend resets stream on invalid TE)",
    );
    integration_test_h2_generic_invalid_te_step.dependOn(&run_integration_test_h2_generic_invalid_te.step);

    const integration_test_h2_generic_trailers_reset = b.addTest(.{
        .name = "integration_test_h2_generic_trailers_reset",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: TLS ALPN h2 generic frontend resets stream on request trailers for non-gRPC route"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2_generic_trailers_reset);
    const run_integration_test_h2_generic_trailers_reset = b.addRunArtifact(integration_test_h2_generic_trailers_reset);

    const integration_test_h2_generic_trailers_reset_step = b.step(
        "test-integration-h2-generic-trailers-reset",
        "Run integration test (TLS ALPN h2 generic frontend resets stream on request trailers)",
    );
    integration_test_h2_generic_trailers_reset_step.dependOn(&run_integration_test_h2_generic_trailers_reset.step);

    const integration_test_h2c_bridge_generic_trailers = b.addTest(.{
        .name = "integration_test_h2c_bridge_generic_trailers",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: h2c bridge forwards non-gRPC response trailers without grpc-status"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_bridge_generic_trailers);
    const run_integration_test_h2c_bridge_generic_trailers = b.addRunArtifact(integration_test_h2c_bridge_generic_trailers);

    const integration_test_h2c_bridge_generic_trailers_step = b.step(
        "test-integration-h2c-bridge-generic-trailers",
        "Run integration test (h2c bridge non-gRPC response trailers without grpc-status)",
    );
    integration_test_h2c_bridge_generic_trailers_step.dependOn(&run_integration_test_h2c_bridge_generic_trailers.step);

    const integration_test_h2c_bridge_generic_headers_only = b.addTest(.{
        .name = "integration_test_h2c_bridge_generic_headers_only",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: h2c bridge accepts non-gRPC headers-only end-stream response"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_bridge_generic_headers_only);
    const run_integration_test_h2c_bridge_generic_headers_only = b.addRunArtifact(integration_test_h2c_bridge_generic_headers_only);

    const integration_test_h2c_bridge_generic_headers_only_step = b.step(
        "test-integration-h2c-bridge-generic-headers-only",
        "Run integration test (h2c bridge non-gRPC headers-only end-stream response)",
    );
    integration_test_h2c_bridge_generic_headers_only_step.dependOn(&run_integration_test_h2c_bridge_generic_headers_only.step);

    const integration_test_h2c_bridge_prior_nongrpc_request_trailers = b.addTest(.{
        .name = "integration_test_h2c_bridge_prior_nongrpc_request_trailers",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: h2c bridge prior-knowledge resets non-gRPC request trailers with protocol error"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_bridge_prior_nongrpc_request_trailers);
    const run_integration_test_h2c_bridge_prior_nongrpc_request_trailers = b.addRunArtifact(integration_test_h2c_bridge_prior_nongrpc_request_trailers);

    const integration_test_h2c_bridge_prior_nongrpc_request_trailers_step = b.step(
        "test-integration-h2c-bridge-prior-nongrpc-request-trailers",
        "Run integration test (h2c bridge prior-knowledge non-gRPC request trailers -> PROTOCOL_ERROR)",
    );
    integration_test_h2c_bridge_prior_nongrpc_request_trailers_step.dependOn(&run_integration_test_h2c_bridge_prior_nongrpc_request_trailers.step);

    const integration_test_h2c_bridge_upgrade_nongrpc_request_trailers = b.addTest(.{
        .name = "integration_test_h2c_bridge_upgrade_nongrpc_request_trailers",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: h2c bridge upgrade resets non-gRPC request trailers on additional stream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_bridge_upgrade_nongrpc_request_trailers);
    const run_integration_test_h2c_bridge_upgrade_nongrpc_request_trailers = b.addRunArtifact(integration_test_h2c_bridge_upgrade_nongrpc_request_trailers);

    const integration_test_h2c_bridge_upgrade_nongrpc_request_trailers_step = b.step(
        "test-integration-h2c-bridge-upgrade-nongrpc-request-trailers",
        "Run integration test (h2c bridge upgrade non-gRPC request trailers -> PROTOCOL_ERROR)",
    );
    integration_test_h2c_bridge_upgrade_nongrpc_request_trailers_step.dependOn(&run_integration_test_h2c_bridge_upgrade_nongrpc_request_trailers.step);

    const integration_test_h2c_bridge_missing_grpc_status = b.addTest(.{
        .name = "integration_test_h2c_bridge_missing_grpc_status",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c missing grpc-status trailer maps to downstream reset"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_bridge_missing_grpc_status);
    const run_integration_test_h2c_bridge_missing_grpc_status = b.addRunArtifact(integration_test_h2c_bridge_missing_grpc_status);

    const integration_test_h2c_bridge_missing_grpc_status_step = b.step(
        "test-integration-h2c-bridge-missing-grpc-status",
        "Run integration test (h2c prior-knowledge missing grpc-status -> downstream reset)",
    );
    integration_test_h2c_bridge_missing_grpc_status_step.dependOn(&run_integration_test_h2c_bridge_missing_grpc_status.step);

    const integration_test_h2c_bridge_grpc_trailers_only = b.addTest(.{
        .name = "integration_test_h2c_bridge_grpc_trailers_only",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c forwards trailers-only response with grpc-status"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_bridge_grpc_trailers_only);
    const run_integration_test_h2c_bridge_grpc_trailers_only = b.addRunArtifact(integration_test_h2c_bridge_grpc_trailers_only);

    const integration_test_h2c_bridge_grpc_trailers_only_step = b.step(
        "test-integration-h2c-bridge-grpc-trailers-only",
        "Run integration test (h2c prior-knowledge gRPC trailers-only response includes grpc-status)",
    );
    integration_test_h2c_bridge_grpc_trailers_only_step.dependOn(&run_integration_test_h2c_bridge_grpc_trailers_only.step);

    const integration_test_h2c_upgrade_missing_grpc_status = b.addTest(.{
        .name = "integration_test_h2c_upgrade_missing_grpc_status",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c upgrade missing grpc-status trailer maps to downstream reset"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_upgrade_missing_grpc_status);
    const run_integration_test_h2c_upgrade_missing_grpc_status = b.addRunArtifact(integration_test_h2c_upgrade_missing_grpc_status);

    const integration_test_h2c_upgrade_missing_grpc_status_step = b.step(
        "test-integration-h2c-upgrade-missing-grpc-status",
        "Run integration test (h2c upgrade missing grpc-status -> downstream reset)",
    );
    integration_test_h2c_upgrade_missing_grpc_status_step.dependOn(&run_integration_test_h2c_upgrade_missing_grpc_status.step);

    const integration_test_h2c_upgrade_grpc_success = b.addTest(.{
        .name = "integration_test_h2c_upgrade_grpc_success",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c upgrade request is proxied end-to-end"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_upgrade_grpc_success);
    const run_integration_test_h2c_upgrade_grpc_success = b.addRunArtifact(integration_test_h2c_upgrade_grpc_success);

    const integration_test_h2c_upgrade_grpc_success_step = b.step(
        "test-integration-h2c-upgrade-grpc-success",
        "Run integration test (h2c upgrade gRPC success path with grpc-status trailers)",
    );
    integration_test_h2c_upgrade_grpc_success_step.dependOn(&run_integration_test_h2c_upgrade_grpc_success.step);

    const integration_test_h2c_upgrade_tls_upstream = b.addTest(.{
        .name = "integration_test_h2c_upgrade_tls_upstream",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c upgrade request is proxied to tls h2 upstream"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_upgrade_tls_upstream);
    const run_integration_test_h2c_upgrade_tls_upstream = b.addRunArtifact(integration_test_h2c_upgrade_tls_upstream);

    const integration_test_h2c_upgrade_tls_upstream_step = b.step(
        "test-integration-h2c-upgrade-tls-upstream",
        "Run integration test (h2c upgrade gRPC request proxied to TLS h2 upstream)",
    );
    integration_test_h2c_upgrade_tls_upstream_step.dependOn(&run_integration_test_h2c_upgrade_tls_upstream.step);

    const integration_test_h2c_grpc_completion_fast_step = b.step(
        "test-integration-h2c-grpc-completion-fast",
        "Run focused gRPC completion checks (bridge+upgrade, fail-closed+success)",
    );
    integration_test_h2c_grpc_completion_fast_step.dependOn(&run_integration_test_h2c_bridge_missing_grpc_status.step);
    integration_test_h2c_grpc_completion_fast_step.dependOn(&run_integration_test_h2c_upgrade_missing_grpc_status.step);
    integration_test_h2c_grpc_completion_fast_step.dependOn(&run_integration_test_h2c_bridge_grpc_trailers_only.step);
    integration_test_h2c_grpc_completion_fast_step.dependOn(&run_integration_test_h2c_upgrade_grpc_success.step);

    const integration_test_h2c_upgrade_generic_trailers = b.addTest(.{
        .name = "integration_test_h2c_upgrade_generic_trailers",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: h2c upgrade non-gRPC response trailers are proxied without grpc-status enforcement"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_upgrade_generic_trailers);
    const run_integration_test_h2c_upgrade_generic_trailers = b.addRunArtifact(integration_test_h2c_upgrade_generic_trailers);

    const integration_test_h2c_upgrade_generic_trailers_step = b.step(
        "test-integration-h2c-upgrade-generic-trailers",
        "Run integration test (h2c upgrade non-gRPC response trailers)",
    );
    integration_test_h2c_upgrade_generic_trailers_step.dependOn(&run_integration_test_h2c_upgrade_generic_trailers.step);

    const integration_test_h2c_upgrade_generic_headers_only = b.addTest(.{
        .name = "integration_test_h2c_upgrade_generic_headers_only",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: h2c upgrade non-gRPC headers-only end-stream response is proxied"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_upgrade_generic_headers_only);
    const run_integration_test_h2c_upgrade_generic_headers_only = b.addRunArtifact(integration_test_h2c_upgrade_generic_headers_only);

    const integration_test_h2c_upgrade_generic_headers_only_step = b.step(
        "test-integration-h2c-upgrade-generic-headers-only",
        "Run integration test (h2c upgrade non-gRPC headers-only end-stream response)",
    );
    integration_test_h2c_upgrade_generic_headers_only_step.dependOn(&run_integration_test_h2c_upgrade_generic_headers_only.step);

    const integration_test_h2c_mixed_goaway_nongrpc = b.addTest(.{
        .name = "integration_test_h2c_mixed_goaway_nongrpc",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c mixed goaway and non-grpc trailer reset loop preserves progress"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_mixed_goaway_nongrpc);
    const run_integration_test_h2c_mixed_goaway_nongrpc = b.addRunArtifact(integration_test_h2c_mixed_goaway_nongrpc);

    const integration_test_h2c_mixed_goaway_nongrpc_step = b.step(
        "test-integration-h2c-mixed-goaway-nongrpc",
        "Run integration test (h2c mixed GOAWAY + non-gRPC trailer reset loop)",
    );
    integration_test_h2c_mixed_goaway_nongrpc_step.dependOn(&run_integration_test_h2c_mixed_goaway_nongrpc.step);

    const integration_test_h2c_mixed_goaway_nongrpc_soak = b.addTest(.{
        .name = "integration_test_h2c_mixed_goaway_nongrpc_soak",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c mixed goaway and non-grpc trailer reset soak loop"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_mixed_goaway_nongrpc_soak);
    const run_integration_test_h2c_mixed_goaway_nongrpc_soak = b.addRunArtifact(integration_test_h2c_mixed_goaway_nongrpc_soak);

    const integration_test_h2c_mixed_goaway_nongrpc_soak_step = b.step(
        "test-integration-h2c-mixed-goaway-nongrpc-soak",
        "Run integration test (h2c mixed GOAWAY + non-gRPC trailer reset soak loop)",
    );
    integration_test_h2c_mixed_goaway_nongrpc_soak_step.dependOn(&run_integration_test_h2c_mixed_goaway_nongrpc_soak.step);

    const integration_test_h2c_mixed_grpc_nongrpc_same_conn = b.addTest(.{
        .name = "integration_test_h2c_mixed_grpc_nongrpc_same_conn",
        .root_module = integration_tests_mod,
        .filters = &.{"integration: grpc h2c mixed grpc and non-grpc streams share one downstream connection"},
        .test_runner = .{ .path = b.path("integration/test_runner.zig"), .mode = .simple },
    });
    force_llvm_lld(integration_test_h2c_mixed_grpc_nongrpc_same_conn);
    const run_integration_test_h2c_mixed_grpc_nongrpc_same_conn = b.addRunArtifact(integration_test_h2c_mixed_grpc_nongrpc_same_conn);

    const integration_test_h2c_mixed_grpc_nongrpc_same_conn_step = b.step(
        "test-integration-h2c-mixed-grpc-nongrpc-same-conn",
        "Run integration test (h2c mixed gRPC + non-gRPC streams on one downstream connection)",
    );
    integration_test_h2c_mixed_grpc_nongrpc_same_conn_step.dependOn(&run_integration_test_h2c_mixed_grpc_nongrpc_same_conn.step);

    const integration_test_h2_generic_completeness_fast_step = b.step(
        "test-integration-h2-generic-completeness-fast",
        "Run focused HTTP/2 generic parity checks (non-gRPC semantics across ALPN + h2c prior-knowledge + h2c upgrade)",
    );
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2_generic_post.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2_generic_post_no_cl.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2_generic_invalid_te.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2_generic_trailers_reset.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2c_bridge_generic_trailers.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2c_bridge_generic_headers_only.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2c_bridge_prior_nongrpc_request_trailers.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2c_bridge_upgrade_nongrpc_request_trailers.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2c_upgrade_generic_trailers.step);
    integration_test_h2_generic_completeness_fast_step.dependOn(&run_integration_test_h2c_upgrade_generic_headers_only.step);

    const integration_test_h2_mixed_hardening_fast_step = b.step(
        "test-integration-h2-mixed-hardening-fast",
        "Run focused HTTP/2 mixed-workload hardening checks (GOAWAY/reset/cancel overlap + non-gRPC interactions)",
    );
    integration_test_h2_mixed_hardening_fast_step.dependOn(&run_integration_test_h2c_mixed_goaway_nongrpc.step);
    integration_test_h2_mixed_hardening_fast_step.dependOn(&run_integration_test_h2c_mixed_goaway_nongrpc_soak.step);
    integration_test_h2_mixed_hardening_fast_step.dependOn(&run_integration_test_h2c_mixed_grpc_nongrpc_same_conn.step);
    integration_test_h2_mixed_hardening_fast_step.dependOn(&run_integration_test_h2c_cancel_goaway_overlap.step);
    integration_test_h2_mixed_hardening_fast_step.dependOn(&run_integration_test_h2c_cancel_goaway_overlap_soak.step);
    integration_test_h2_mixed_hardening_fast_step.dependOn(&run_integration_test_h2c_reset_isolation.step);
    integration_test_h2_mixed_hardening_fast_step.dependOn(&run_integration_test_h2c_reset_isolation_soak.step);

    const integration_test_h2_mixed_hardening_soak_step = b.step(
        "test-integration-h2-mixed-hardening-soak",
        "Run extended HTTP/2 mixed-workload soak set (GOAWAY/reset/cancel overlaps + upgrade rollover)",
    );
    integration_test_h2_mixed_hardening_soak_step.dependOn(&run_integration_test_h2c_mixed_goaway_nongrpc_soak.step);
    integration_test_h2_mixed_hardening_soak_step.dependOn(&run_integration_test_h2c_cancel_goaway_overlap_soak.step);
    integration_test_h2_mixed_hardening_soak_step.dependOn(&run_integration_test_h2c_reset_isolation_soak.step);
    integration_test_h2_mixed_hardening_soak_step.dependOn(&run_integration_test_h2c_goaway_rollover_soak.step);
    integration_test_h2_mixed_hardening_soak_step.dependOn(&run_integration_test_h2c_upgrade_goaway_rollover_soak.step);

    const acme_issue_once_mod = b.createModule(.{
        .root_source_file = b.path("integration/acme_issue_once.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    acme_issue_once_mod.linkSystemLibrary("ssl", .{});
    acme_issue_once_mod.linkSystemLibrary("crypto", .{});
    acme_issue_once_mod.addImport("serval-core", serval_core_module);
    acme_issue_once_mod.addImport("serval-net", serval_net_module);
    acme_issue_once_mod.addImport("serval-client", serval_client_module);
    acme_issue_once_mod.addImport("serval-tls", serval_tls_module);
    acme_issue_once_mod.addImport("serval-acme", serval_acme_module);

    const acme_issue_once = b.addExecutable(.{
        .name = "acme_issue_once",
        .root_module = acme_issue_once_mod,
    });
    force_llvm_lld(acme_issue_once);
    const run_acme_issue_once = b.addRunArtifact(acme_issue_once);
    const run_acme_issue_once_step = b.step("run-acme-issue-once", "Run one ACME issuance cycle against configured ACME directory");
    run_acme_issue_once_step.dependOn(&run_acme_issue_once.step);

    const gdb_integration_test_32 = b.addSystemCommand(&.{
        "sudo",
        "gdb",
        "-batch",
        "-ex",
        "set pagination off",
        "-ex",
        "run",
        "--args",
    });
    gdb_integration_test_32.addFileArg(integration_test_32.getEmittedBin());

    const integration_test_32_gdb_step = b.step(
        "test-integration-32-gdb",
        "Run integration test 32 under sudo gdb and print a backtrace on failure",
    );
    integration_test_32_gdb_step.dependOn(&gdb_integration_test_32.step);

    const gdb_integration_test_37 = b.addSystemCommand(&.{
        "sudo",
        "gdb",
        "-batch",
        "-ex",
        "set pagination off",
        "-ex",
        "run",
        "--args",
    });
    gdb_integration_test_37.addFileArg(integration_test_37.getEmittedBin());

    const integration_test_37_gdb_step = b.step(
        "test-integration-37-gdb",
        "Run integration test 37 under sudo gdb and print a backtrace on failure",
    );
    integration_test_37_gdb_step.dependOn(&gdb_integration_test_37.step);

    const gdb_integration_test_42 = b.addSystemCommand(&.{
        "sudo",
        "gdb",
        "-batch",
        "-ex",
        "set pagination off",
        "-ex",
        "run",
        "--args",
    });
    gdb_integration_test_42.addFileArg(integration_test_42.getEmittedBin());

    const integration_test_42_gdb_step = b.step(
        "test-integration-42-gdb",
        "Run integration test 42 under sudo gdb and print a backtrace on failure",
    );
    integration_test_42_gdb_step.dependOn(&gdb_integration_test_42.step);

    const gdb_integration_test_105 = b.addSystemCommand(&.{
        "sudo",
        "gdb",
        "-batch",
        "-ex",
        "set pagination off",
        "-ex",
        "run",
        "--args",
    });
    gdb_integration_test_105.addFileArg(integration_test_105.getEmittedBin());

    const integration_test_105_gdb_step = b.step(
        "test-integration-105-gdb",
        "Run integration test 105 under sudo gdb and print a backtrace on failure",
    );
    integration_test_105_gdb_step.dependOn(&gdb_integration_test_105.step);

    const integration_test_105_loop = b.addSystemCommand(&.{
        "bash",
        "integration/run_loop_until_failure.sh",
        "test-integration-105",
    });
    const integration_test_105_loop_step = b.step(
        "test-integration-105-loop",
        "Run integration test 105 repeatedly until the first failure or loop limit",
    );
    integration_test_105_loop_step.dependOn(&integration_test_105_loop.step);

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
    force_llvm_lld(lb_example);
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
        .root_source_file = b.path("examples/router/main.zig"),
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
    router_example_mod.addImport("serval-otel", serval_otel_module);
    const router_example = b.addExecutable(.{
        .name = "router_example",
        .root_module = router_example_mod,
    });
    force_llvm_lld(router_example);
    const build_router_example = b.addInstallArtifact(router_example, .{});
    const run_router_example = b.addRunArtifact(router_example);

    if (b.args) |args| {
        run_router_example.addArgs(args);
    }

    const build_router_example_step = b.step("build-router-example", "Build router example");
    build_router_example_step.dependOn(&build_router_example.step);

    const run_router_example_step = b.step("run-router-example", "Run router example");
    run_router_example_step.dependOn(&run_router_example.step);

    // Reverseproxy runtime example (DSL + orchestrator runtime provider)
    const reverseproxy_runtime_mod = b.createModule(.{
        .root_source_file = b.path("examples/reverseproxy_runtime.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    reverseproxy_runtime_mod.linkSystemLibrary("ssl", .{});
    reverseproxy_runtime_mod.linkSystemLibrary("crypto", .{});
    reverseproxy_runtime_mod.addImport("serval", serval_module);
    reverseproxy_runtime_mod.addImport("serval-cli", serval_cli_module);
    reverseproxy_runtime_mod.addImport("serval-net", serval_net_module);
    const reverseproxy_runtime = b.addExecutable(.{
        .name = "reverseproxy_runtime",
        .root_module = reverseproxy_runtime_mod,
    });
    force_llvm_lld(reverseproxy_runtime);
    const build_reverseproxy_runtime = b.addInstallArtifact(reverseproxy_runtime, .{});
    const run_reverseproxy_runtime = b.addRunArtifact(reverseproxy_runtime);

    if (b.args) |args| {
        run_reverseproxy_runtime.addArgs(args);
    }

    const build_reverseproxy_runtime_step = b.step("build-reverseproxy-runtime", "Build reverseproxy runtime example");
    build_reverseproxy_runtime_step.dependOn(&build_reverseproxy_runtime.step);

    const reverseproxy_runtime_tests_mod = b.createModule(.{
        .root_source_file = b.path("examples/reverseproxy_runtime.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    reverseproxy_runtime_tests_mod.linkSystemLibrary("ssl", .{});
    reverseproxy_runtime_tests_mod.linkSystemLibrary("crypto", .{});
    reverseproxy_runtime_tests_mod.addImport("serval", serval_module);
    reverseproxy_runtime_tests_mod.addImport("serval-cli", serval_cli_module);
    reverseproxy_runtime_tests_mod.addImport("serval-net", serval_net_module);
    const reverseproxy_runtime_tests = b.addTest(.{
        .name = "reverseproxy_runtime_tests",
        .root_module = reverseproxy_runtime_tests_mod,
    });
    force_llvm_lld(reverseproxy_runtime_tests);
    const run_reverseproxy_runtime_tests = b.addRunArtifact(reverseproxy_runtime_tests);

    const reverseproxy_runtime_test_step = b.step("test-reverseproxy-runtime", "Run reverseproxy runtime example tests");
    reverseproxy_runtime_test_step.dependOn(&run_reverseproxy_runtime_tests.step);
    test_step.dependOn(&run_reverseproxy_runtime_tests.step);

    const run_reverseproxy_runtime_step = b.step("run-reverseproxy-runtime", "Run reverseproxy runtime example");
    run_reverseproxy_runtime_step.dependOn(&run_reverseproxy_runtime.step);

    // NetBird reverse-proxy example
    // Note: Links SSL libraries since serval depends on serval-server which depends on serval-tls
    const netbird_proxy_mod = b.createModule(.{
        .root_source_file = b.path("examples/netbird_proxy.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    netbird_proxy_mod.linkSystemLibrary("ssl", .{ .needed = true });
    netbird_proxy_mod.linkSystemLibrary("crypto", .{ .needed = true });
    apply_optional_openssl_paths(netbird_proxy_mod, openssl_include_dir, openssl_lib_dir);
    netbird_proxy_mod.addImport("serval", serval_module);
    netbird_proxy_mod.addImport("serval-cli", serval_cli_module);
    netbird_proxy_mod.addImport("serval-tls", serval_tls_module);
    netbird_proxy_mod.addImport("serval-client", serval_client_module);
    const netbird_proxy = b.addExecutable(.{
        .name = "netbird_proxy",
        .root_module = netbird_proxy_mod,
        .linkage = .dynamic,
    });
    force_llvm_lld(netbird_proxy);
    const build_netbird_proxy = b.addInstallArtifact(netbird_proxy, .{});
    const run_netbird_proxy = b.addRunArtifact(netbird_proxy);

    if (b.args) |args| {
        run_netbird_proxy.addArgs(args);
    }

    const build_netbird_proxy_step = b.step("build-netbird-proxy", "Build NetBird reverse-proxy example");
    build_netbird_proxy_step.dependOn(&build_netbird_proxy.step);

    const netbird_proxy_tests_mod = b.createModule(.{
        .root_source_file = b.path("examples/netbird_proxy.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    netbird_proxy_tests_mod.linkSystemLibrary("ssl", .{});
    netbird_proxy_tests_mod.linkSystemLibrary("crypto", .{});
    apply_optional_openssl_paths(netbird_proxy_tests_mod, openssl_include_dir, openssl_lib_dir);
    netbird_proxy_tests_mod.addImport("serval", serval_module);
    netbird_proxy_tests_mod.addImport("serval-cli", serval_cli_module);
    netbird_proxy_tests_mod.addImport("serval-tls", serval_tls_module);
    netbird_proxy_tests_mod.addImport("serval-client", serval_client_module);
    const netbird_proxy_tests = b.addTest(.{
        .name = "netbird_proxy_tests",
        .root_module = netbird_proxy_tests_mod,
    });
    force_llvm_lld(netbird_proxy_tests);
    const run_netbird_proxy_tests = b.addRunArtifact(netbird_proxy_tests);

    const netbird_proxy_test_step = b.step("test-netbird-proxy", "Run NetBird reverse-proxy example tests");
    netbird_proxy_test_step.dependOn(&run_netbird_proxy_tests.step);
    test_step.dependOn(&run_netbird_proxy_tests.step);

    const run_netbird_proxy_step = b.step("run-netbird-proxy", "Run NetBird reverse-proxy example");
    run_netbird_proxy_step.dependOn(&run_netbird_proxy.step);

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
    gateway_example_mod.addImport("serval-router", serval_router_module);
    const gateway_example = b.addExecutable(.{
        .name = "gateway_example",
        .root_module = gateway_example_mod,
    });
    force_llvm_lld(gateway_example);
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
    force_llvm_lld(echo_backend);
    const build_echo_backend = b.addInstallArtifact(echo_backend, .{});
    const run_echo_backend = b.addRunArtifact(echo_backend);

    // Ensure subprocess binaries are rebuilt before integration tests run.
    // The harness spawns ./zig-out/bin/echo_backend and ./zig-out/bin/netbird_proxy directly.
    run_integration_tests.step.dependOn(&build_echo_backend.step);
    run_integration_tests.step.dependOn(&build_netbird_proxy.step);
    run_integration_tests.step.dependOn(&build_reverseproxy_runtime.step);
    run_integration_test_echo_backend_200.step.dependOn(&build_echo_backend.step);
    run_integration_test_2.step.dependOn(&build_echo_backend.step);
    run_integration_test_32.step.dependOn(&build_echo_backend.step);
    run_integration_test_34.step.dependOn(&build_echo_backend.step);
    run_integration_test_22.step.dependOn(&build_echo_backend.step);
    run_integration_test_5.step.dependOn(&build_echo_backend.step);
    run_integration_test_64.step.dependOn(&build_echo_backend.step);
    run_integration_test_perf_throughput_h1.step.dependOn(&build_echo_backend.step);
    run_integration_test_perf_throughput_h2.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_reset_isolation.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_reset_isolation_soak.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_goaway_last_stream.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_goaway_rollover_loop.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_goaway_rollover_soak.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_upgrade_goaway_rollover_loop.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_upgrade_goaway_rollover_soak.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_cancel_propagation.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_cancel_goaway_overlap.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_cancel_goaway_overlap_soak.step.dependOn(&build_echo_backend.step);
    run_integration_test_77.step.dependOn(&build_echo_backend.step);
    run_integration_test_78.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2_generic_post_no_cl.step.dependOn(&build_echo_backend.step);
    run_integration_test_56.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2_generic_post.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2_generic_invalid_te.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2_generic_trailers_reset.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_bridge_generic_trailers.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_bridge_generic_headers_only.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_bridge_prior_nongrpc_request_trailers.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_bridge_upgrade_nongrpc_request_trailers.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_bridge_missing_grpc_status.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_bridge_grpc_trailers_only.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_upgrade_missing_grpc_status.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_upgrade_grpc_success.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_upgrade_generic_trailers.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_upgrade_generic_headers_only.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_mixed_goaway_nongrpc.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_mixed_goaway_nongrpc_soak.step.dependOn(&build_echo_backend.step);
    run_integration_test_h2c_mixed_grpc_nongrpc_same_conn.step.dependOn(&build_echo_backend.step);
    run_integration_test_reverseproxy.step.dependOn(&build_echo_backend.step);
    run_integration_test_reverseproxy.step.dependOn(&build_reverseproxy_runtime.step);
    run_integration_test_22.step.dependOn(&build_reverseproxy_runtime.step);
    run_integration_test_netbird.step.dependOn(&build_echo_backend.step);
    run_integration_test_netbird.step.dependOn(&build_netbird_proxy.step);
    run_integration_test_netbird.step.dependOn(&build_reverseproxy_runtime.step);
    run_integration_test_2.step.dependOn(&build_lb_example.step);
    run_integration_test_77.step.dependOn(&build_lb_example.step);
    run_integration_test_78.step.dependOn(&build_lb_example.step);

    const build_echo_backend_step = b.step("build-echo-backend", "Build echo backend");
    build_echo_backend_step.dependOn(&build_echo_backend.step);

    if (b.args) |args| {
        run_echo_backend.addArgs(args);
    }

    const run_echo_backend_step = b.step("run-echo-backend", "Run echo backend example");
    run_echo_backend_step.dependOn(&run_echo_backend.step);

    // HTTP/2 conformance target server (terminated h2 callbacks + optional TLS)
    const h2_conformance_server_mod = b.createModule(.{
        .root_source_file = b.path("examples/h2_conformance_server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    h2_conformance_server_mod.linkSystemLibrary("ssl", .{});
    h2_conformance_server_mod.linkSystemLibrary("crypto", .{});
    h2_conformance_server_mod.addImport("serval", serval_module);
    h2_conformance_server_mod.addImport("serval-net", serval_net_module);
    h2_conformance_server_mod.addImport("serval-cli", serval_cli_module);
    const h2_conformance_server = b.addExecutable(.{
        .name = "h2_conformance_server",
        .root_module = h2_conformance_server_mod,
    });
    force_llvm_lld(h2_conformance_server);
    const build_h2_conformance_server = b.addInstallArtifact(h2_conformance_server, .{});
    const run_h2_conformance_server = b.addRunArtifact(h2_conformance_server);

    const build_h2_conformance_server_step = b.step("build-h2-conformance-server", "Build HTTP/2 conformance target server");
    build_h2_conformance_server_step.dependOn(&build_h2_conformance_server.step);

    if (b.args) |args| {
        run_h2_conformance_server.addArgs(args);
    }

    const run_h2_conformance_server_step = b.step("run-h2-conformance-server", "Run HTTP/2 conformance target server");
    run_h2_conformance_server_step.dependOn(&run_h2_conformance_server.step);

    const test_h2_conformance_ci = b.addSystemCommand(&.{
        "bash",
        "integration/h2_conformance_ci.sh",
        "--h2c-port",
        "28080",
        "--tls-port",
        "28443",
    });
    const test_h2_conformance_ci_step = b.step("test-h2-conformance-ci", "Run h2spec conformance sweep against plain+TLS h2 conformance server");
    test_h2_conformance_ci_step.dependOn(&test_h2_conformance_ci.step);

    // OTLP test example
    // Note: Links SSL libraries since serval-otel uses serval-client which uses serval-tls
    const otel_test_mod = b.createModule(.{
        .root_source_file = b.path("examples/otel_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    otel_test_mod.linkSystemLibrary("ssl", .{});
    otel_test_mod.linkSystemLibrary("crypto", .{});
    otel_test_mod.addImport("serval-otel", serval_otel_module);
    const otel_test = b.addExecutable(.{
        .name = "otel_test",
        .root_module = otel_test_mod,
    });
    force_llvm_lld(otel_test);
    const build_otel_test = b.addInstallArtifact(otel_test, .{});

    const run_otel_test = b.addRunArtifact(otel_test);
    const run_otel_test_step = b.step("run-otel-test", "Run OTLP export test");
    run_otel_test_step.dependOn(&run_otel_test.step);

    // DNS test example (for debugging DNS resolution issues)
    const dns_test_mod = b.createModule(.{
        .root_source_file = b.path("examples/dns_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    dns_test_mod.addImport("serval-net", serval_net_module);
    dns_test_mod.addImport("serval-core", serval_core_module);
    const dns_test = b.addExecutable(.{
        .name = "dns_test",
        .root_module = dns_test_mod,
    });
    force_llvm_lld(dns_test);
    const build_dns_test = b.addInstallArtifact(dns_test, .{});
    _ = build_dns_test;

    const run_dns_test = b.addRunArtifact(dns_test);
    if (b.args) |args| {
        run_dns_test.addArgs(args);
    }
    const run_dns_test_step = b.step("run-dns-test", "Run DNS resolution test");
    run_dns_test_step.dependOn(&run_dns_test.step);

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
    force_llvm_lld(llm_streaming);
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
    b.default_step.dependOn(&build_reverseproxy_runtime.step);
    b.default_step.dependOn(&build_netbird_proxy.step);
    b.default_step.dependOn(&build_gateway_example.step);
    b.default_step.dependOn(&build_echo_backend.step);
    b.default_step.dependOn(&build_h2_conformance_server.step);
    b.default_step.dependOn(&build_otel_test.step);
    b.default_step.dependOn(&build_llm_streaming.step);
}
