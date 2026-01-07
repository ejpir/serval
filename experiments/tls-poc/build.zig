const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Client executable
    const client = b.addExecutable(.{
        .name = "tls_client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });

    client.root_module.addObjectFile(b.path("boringssl/build/libssl.a"));
    client.root_module.addObjectFile(b.path("boringssl/build/libcrypto.a"));
    b.installArtifact(client);

    const run_client = b.addRunArtifact(client);
    run_client.step.dependOn(b.getInstallStep());
    const run_client_step = b.step("run-client", "Run the TLS client");
    run_client_step.dependOn(&run_client.step);

    // Server executable
    const server = b.addExecutable(.{
        .name = "tls_server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/server.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });

    server.root_module.addObjectFile(b.path("boringssl/build/libssl.a"));
    server.root_module.addObjectFile(b.path("boringssl/build/libcrypto.a"));
    b.installArtifact(server);

    const run_server = b.addRunArtifact(server);
    run_server.step.dependOn(b.getInstallStep());
    const run_server_step = b.step("run-server", "Run the TLS server");
    run_server_step.dependOn(&run_server.step);

    // Test client executable
    const test_client = b.addExecutable(.{
        .name = "test_client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test_client.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });

    test_client.root_module.addObjectFile(b.path("boringssl/build/libssl.a"));
    test_client.root_module.addObjectFile(b.path("boringssl/build/libcrypto.a"));
    b.installArtifact(test_client);

    const run_test_client = b.addRunArtifact(test_client);
    run_test_client.step.dependOn(b.getInstallStep());
    const run_test_client_step = b.step("run-test", "Run the test client");
    run_test_client_step.dependOn(&run_test_client.step);
}
