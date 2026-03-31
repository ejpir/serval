const std = @import("std");

const core = @import("serval-core");
const config = core.config;

const acme = @import("serval-acme");
const acme_limits = acme.limits;
const net = @import("serval-net");
const client_mod = @import("serval-client");
const tls = @import("serval-tls");

/// Runs a one-shot ACME issuance against the local test directory and prints the persisted cert and key paths.
/// Initializes the ACME runtime, DNS resolver, TLS client context, and account signer, then invokes issuance once.
/// The stack buffers passed to `runAcmeIssuanceOnce` must remain valid for the duration of the call.
/// The temporary ALPN hook provider is installed before issuance and uninstalled on return.
/// Returns any error from runtime setup, hook installation, TLS/client initialization, or the issuance flow.
pub fn main() !void {
    const io = std.Options.debug_io;

    const directory_url = "https://127.0.0.1:14000/dir";
    const state_dir = ".tmp/acme-state";

    const cfg = config.AcmeConfig{
        .enabled = true,
        .directory_url = directory_url,
        .contact_email = "ops@example.com",
        .state_dir_path = state_dir,
        .poll_interval_ms = 200,
        .domains = &.{"example.com"},
    };

    const runtime = try acme.RuntimeConfig.initFromConfig(cfg);

    var hook_provider = acme.AcmeTlsAlpnHookProvider.init();
    try hook_provider.install();
    defer hook_provider.uninstall() catch |err| {
        std.debug.print("warn: acme_issue_once failed to uninstall ALPN hook provider: {s}\n", .{@errorName(err)});
    };

    var resolver: net.DnsResolver = undefined;
    net.DnsResolver.init(&resolver, net.DnsConfig{});

    tls.ssl.init();
    const client_ctx = try tls.ssl.createClientCtx();
    defer tls.ssl.SSL_CTX_free(client_ctx);

    var acme_client = client_mod.Client.init(std.heap.page_allocator, &resolver, client_ctx, false);
    defer acme_client.deinit();

    const signer = acme.AcmeAccountSigner.generate(io);

    var header_buf: [config.MAX_HEADER_SIZE_BYTES]u8 = undefined;
    var body_buf: [acme_limits.max_order_response_bytes]u8 = undefined;
    var jws_buf: [acme_limits.max_jws_body_bytes]u8 = undefined;
    var payload_buf: [acme_limits.max_jws_body_bytes]u8 = undefined;
    var csr_der_buf: [32 * 1024]u8 = undefined;
    var key_pem_buf: [32 * 1024]u8 = undefined;
    var cert_path_buf: [1024]u8 = undefined;
    var key_path_buf: [1024]u8 = undefined;

    const persisted = try acme.runAcmeIssuanceOnce(
        &runtime,
        &acme_client,
        &signer,
        io,
        .{
            .header_buf = &header_buf,
            .body_buf = &body_buf,
            .jws_buf = &jws_buf,
            .payload_buf = &payload_buf,
            .csr_der_buf = &csr_der_buf,
            .key_pem_buf = &key_pem_buf,
            .cert_path_buf = &cert_path_buf,
            .key_path_buf = &key_path_buf,
        },
        null,
        &hook_provider,
    );

    std.debug.print("acme_issue_once: cert={s} key={s}\n", .{ persisted.cert_path, persisted.key_path });
}
