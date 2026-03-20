//! ACME automated issuance runtime.
//!
//! Drives account/order/authz/finalize/download flow with bounded polling,
//! TLS-ALPN-01 challenge activation, atomic persistence, and optional TLS reload.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const core = @import("serval-core");
const config = core.config;
const HeaderMap = core.HeaderMap;
const Method = core.Method;

const client = @import("client.zig");
const wire = @import("wire.zig");
const transport = @import("transport.zig");
const orchestration = @import("orchestration.zig");
const acme_types = @import("types.zig");
const signer_mod = @import("signer.zig");
const csr_mod = @import("csr.zig");
const storage = @import("storage.zig");
const tls_alpn_hook_mod = @import("tls_alpn_hook.zig");
const tls_alpn_cert_mod = @import("tls_alpn_cert.zig");

const serval_client = @import("serval-client");
const Client = serval_client.Client;

const serval_tls = @import("serval-tls");
const ReloadableServerCtx = serval_tls.ReloadableServerCtx;
const ssl = serval_tls.ssl;

pub const Error = error{
    InvalidRuntimeConfig,
    MissingTlsAlpnHookProvider,
    MissingTlsAlpn01Challenge,
    AuthorizationInvalid,
    AuthorizationPollExceeded,
    OrderPollExceeded,
    MissingCertificateUrl,
    CertResponseEmpty,
} || client.Error || wire.Error || transport.Error || transport.ExecuteOperationError || signer_mod.Error || csr_mod.Error || storage.Error || tls_alpn_hook_mod.Error || tls_alpn_cert_mod.Error || serval_tls.ReloadableServerCtxError || serval_tls.ssl.CreateServerCtxFromPemFilesError || Io.Cancelable;

pub const WorkBuffers = struct {
    header_buf: []u8,
    body_buf: []u8,
    jws_buf: []u8,
    payload_buf: []u8,
    csr_der_buf: []u8,
    key_pem_buf: []u8,
    cert_path_buf: []u8,
    key_path_buf: []u8,
};

pub fn runIssuanceOnce(
    runtime_config: *const acme_types.RuntimeConfig,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    io: Io,
    work: WorkBuffers,
    tls_manager: ?*ReloadableServerCtx,
    tls_alpn_hook_provider: ?*tls_alpn_hook_mod.TlsAlpnHookProvider,
) Error!storage.PersistedPaths {
    assert(@intFromPtr(runtime_config) != 0);
    assert(@intFromPtr(acme_client) != 0);
    assert(@intFromPtr(signer) != 0);

    if (!runtime_config.enabled) return error.InvalidRuntimeConfig;
    if (runtime_config.domain_count == 0) return error.InvalidRuntimeConfig;
    if (tls_alpn_hook_provider == null) return error.MissingTlsAlpnHookProvider;

    const directory = try fetchDirectory(runtime_config, acme_client, io, work.header_buf, work.body_buf);
    var flow_ctx = orchestration.FlowContext.init(&directory);

    // 1) nonce
    _ = try transport.executeOperation(&flow_ctx, acme_client, .{
        .operation = .fetch_nonce,
        .signed_body = &.{},
        .io = io,
        .header_buf = work.header_buf,
        .body_buf = work.body_buf,
    });

    // 2) ensure account (new)
    const new_account_payload = try client.serializeNewAccountPayload(work.payload_buf, .{
        .contact_email = runtime_config.contactEmail(),
    });
    const new_account_body = try signer.signWithJwk(
        work.jws_buf,
        &flow_ctx.nonce,
        &directory.new_account_url,
        new_account_payload,
    );
    _ = try transport.executeOperation(&flow_ctx, acme_client, .{
        .operation = .new_account,
        .signed_body = new_account_body,
        .io = io,
        .header_buf = work.header_buf,
        .body_buf = work.body_buf,
    });

    // 3) create order
    const new_order_req = try client.NewOrderRequest.initFromRuntimeConfig(runtime_config);
    const new_order_payload = try client.serializeNewOrderPayload(work.payload_buf, &new_order_req);
    const new_order_body = try signer.signWithKid(
        work.jws_buf,
        &flow_ctx.nonce,
        &directory.new_order_url,
        &flow_ctx.account_url,
        new_order_payload,
    );
    const new_order_handled = try transport.executeOperation(&flow_ctx, acme_client, .{
        .operation = .new_order,
        .signed_body = new_order_body,
        .io = io,
        .header_buf = work.header_buf,
        .body_buf = work.body_buf,
    });
    const initial_order = switch (new_order_handled.parsed) {
        .order => |order| order,
        else => return error.InvalidOrderStatus,
    };

    // 4) authorize each authz URL using TLS-ALPN-01
    const hook_provider = tls_alpn_hook_provider orelse return error.MissingTlsAlpnHookProvider;
    var auth_idx: u8 = 0;
    while (auth_idx < initial_order.authorization_count) : (auth_idx += 1) {
        const auth_url = initial_order.authorization_urls[auth_idx];
        try authorizeChallenge(
            &flow_ctx,
            runtime_config,
            acme_client,
            signer,
            io,
            work,
            &auth_url,
            hook_provider,
        );
    }

    // 5) finalize with CSR
    var domains: [config.ACME_MAX_DOMAINS_PER_CERT][]const u8 = undefined;
    var domain_count: usize = 0;
    var domain_idx: u8 = 0;
    while (domain_idx < runtime_config.domain_count) : (domain_idx += 1) {
        const domain = runtime_config.domainAt(domain_idx) orelse break;
        domains[domain_count] = domain;
        domain_count += 1;
    }

    const csr_result = try csr_mod.generate(
        std.heap.page_allocator,
        runtime_config.stateDirPath(),
        domains[0..domain_count],
        work.csr_der_buf,
        work.key_pem_buf,
    );

    const finalize_payload = try client.serializeFinalizePayload(work.payload_buf, csr_result.csr_der);
    const finalize_body = try signer.signWithKid(
        work.jws_buf,
        &flow_ctx.nonce,
        &flow_ctx.finalize_url,
        &flow_ctx.account_url,
        finalize_payload,
    );
    _ = try transport.executeOperation(&flow_ctx, acme_client, .{
        .operation = .finalize_order,
        .signed_body = finalize_body,
        .io = io,
        .header_buf = work.header_buf,
        .body_buf = work.body_buf,
    });

    // 6) poll order until cert URL available
    const final_order = try pollOrderValid(
        &flow_ctx,
        runtime_config,
        acme_client,
        signer,
        io,
        work,
    );
    if (!final_order.has_certificate_url) return error.MissingCertificateUrl;

    // 7) download certificate via POST-as-GET (empty payload)
    const cert_pem = try downloadCertificate(
        &flow_ctx,
        acme_client,
        signer,
        io,
        work,
        &final_order.certificate_url,
    );
    if (cert_pem.len == 0) return error.CertResponseEmpty;

    // 8) persist and activate
    const persisted = try storage.persistCertificateAndKey(
        runtime_config.stateDirPath(),
        cert_pem,
        csr_result.key_pem,
        work.cert_path_buf,
        work.key_path_buf,
    );

    if (tls_manager) |manager| {
        _ = try manager.activateFromPemFiles(persisted.cert_path, persisted.key_path);
    }

    return persisted;
}

fn fetchDirectory(
    runtime_config: *const acme_types.RuntimeConfig,
    acme_client: *Client,
    io: Io,
    header_buf: []u8,
    body_buf: []u8,
) Error!client.Directory {
    var dir_url = client.Url{};
    try dir_url.set(runtime_config.directoryUrl());
    const parsed = try wire.parseAbsoluteUrl(&dir_url);

    const req = wire.WireRequest{
        .method = Method.GET,
        .target = parsed,
        .body = &.{},
        .content_type = null,
    };

    const response = try transport.execute(acme_client, .{
        .wire_request = &req,
        .io = io,
        .header_buf = header_buf,
        .body_buf = body_buf,
    });

    return try client.parseDirectoryResponseJson(response.body);
}

fn authorizeChallenge(
    flow_ctx: *orchestration.FlowContext,
    runtime_config: *const acme_types.RuntimeConfig,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    io: Io,
    work: WorkBuffers,
    auth_url: *const client.Url,
    hook_provider: *tls_alpn_hook_mod.TlsAlpnHookProvider,
) Error!void {
    const auth = try fetchAuthorization(flow_ctx, acme_client, signer, io, work, auth_url);
    if (auth.status == .valid) return;

    const host = auth.identifier_dns.slice();

    const challenge = auth.firstTlsAlpn01Challenge() orelse return error.MissingTlsAlpn01Challenge;
    return try authorizeTlsAlpn01(
        flow_ctx,
        runtime_config,
        acme_client,
        signer,
        io,
        work,
        auth_url,
        host,
        challenge,
        hook_provider,
    );
}

fn authorizeTlsAlpn01(
    flow_ctx: *orchestration.FlowContext,
    runtime_config: *const acme_types.RuntimeConfig,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    io: Io,
    work: WorkBuffers,
    auth_url: *const client.Url,
    host: []const u8,
    challenge: *const client.AuthorizationChallenge,
    hook_provider: *tls_alpn_hook_mod.TlsAlpnHookProvider,
) Error!void {
    var key_auth_buf: [config.ACME_MAX_HTTP01_KEY_AUTHORIZATION_BYTES]u8 = undefined;
    const key_auth = try signer.computeKeyAuthorization(challenge.token(), &key_auth_buf);

    var cert_pem_buf: [8192]u8 = undefined;
    var key_pem_buf: [4096]u8 = undefined;
    const materials = try tls_alpn_cert_mod.generateMaterials(io, host, key_auth, &cert_pem_buf, &key_pem_buf);

    const state_dir = runtime_config.stateDirPath();

    var cert_path_buf: [1024]u8 = undefined;
    var key_path_buf: [1024]u8 = undefined;
    const cert_path = std.fmt.bufPrint(&cert_path_buf, "{s}/tls-alpn-challenge-cert.pem", .{state_dir}) catch return error.InvalidRuntimeConfig;
    const key_path = std.fmt.bufPrint(&key_path_buf, "{s}/tls-alpn-challenge-key.pem", .{state_dir}) catch return error.InvalidRuntimeConfig;

    const cwd = Io.Dir.cwd();
    cwd.createDirPath(std.Options.debug_io, state_dir) catch return error.InvalidRuntimeConfig;
    cwd.writeFile(std.Options.debug_io, .{ .sub_path = cert_path, .data = materials.cert_pem }) catch return error.InvalidRuntimeConfig;
    cwd.writeFile(std.Options.debug_io, .{ .sub_path = key_path, .data = materials.key_pem }) catch return error.InvalidRuntimeConfig;
    defer {
        cwd.deleteFile(std.Options.debug_io, cert_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => std.log.warn("acme-runtime: challenge cert cleanup failed path={s} err={s}", .{
                cert_path,
                @errorName(err),
            }),
        };
        cwd.deleteFile(std.Options.debug_io, key_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => std.log.warn("acme-runtime: challenge key cleanup failed path={s} err={s}", .{
                key_path,
                @errorName(err),
            }),
        };
    }

    const challenge_ctx = try ssl.createServerCtxFromPemFiles(cert_path, key_path);
    defer ssl.SSL_CTX_free(challenge_ctx);

    try hook_provider.activateChallenge(host, challenge_ctx);
    defer hook_provider.clearChallenge() catch |err| switch (err) {
        error.NotInstalled => {},
        else => std.log.warn("acme-runtime: tls-alpn challenge clear failed err={s}", .{@errorName(err)}),
    };

    try notifyChallengeReady(flow_ctx, acme_client, signer, io, work, &challenge.url);
    try pollAuthorizationValid(flow_ctx, runtime_config, acme_client, signer, io, work, auth_url);
}

fn notifyChallengeReady(
    flow_ctx: *orchestration.FlowContext,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    io: Io,
    work: WorkBuffers,
    challenge_url: *const client.Url,
) Error!void {
    const notify_body = try signer.signWithKid(
        work.jws_buf,
        &flow_ctx.nonce,
        challenge_url,
        &flow_ctx.account_url,
        "{}",
    );
    var notify_req = try wire.buildSignedPostRequest(challenge_url, notify_body);
    const notify_resp = try transport.execute(acme_client, .{
        .wire_request = &notify_req,
        .io = io,
        .header_buf = work.header_buf,
        .body_buf = work.body_buf,
    });
    const notify_nonce = try wire.parseReplayNonceFromHeaders(&notify_resp.headers);
    flow_ctx.setNonce(&notify_nonce);
}

fn pollAuthorizationValid(
    flow_ctx: *orchestration.FlowContext,
    runtime_config: *const acme_types.RuntimeConfig,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    io: Io,
    work: WorkBuffers,
    auth_url: *const client.Url,
) Error!void {
    var attempt: u16 = 0;
    while (attempt < config.ACME_MAX_POLL_ATTEMPTS) : (attempt += 1) {
        const polled = try fetchAuthorization(flow_ctx, acme_client, signer, io, work, auth_url);
        switch (polled.status) {
            .valid => return,
            .invalid, .deactivated, .expired, .revoked => return error.AuthorizationInvalid,
            .pending => try std.Io.sleep(io, Io.Duration.fromMilliseconds(runtime_config.poll_interval_ms), .awake),
        }
    }

    return error.AuthorizationPollExceeded;
}

fn fetchAuthorization(
    flow_ctx: *orchestration.FlowContext,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    io: Io,
    work: WorkBuffers,
    auth_url: *const client.Url,
) Error!client.AuthorizationResponse {
    const body = try signer.signWithKid(
        work.jws_buf,
        &flow_ctx.nonce,
        auth_url,
        &flow_ctx.account_url,
        "",
    );
    var req = try wire.buildSignedPostRequest(auth_url, body);

    const resp = try transport.execute(acme_client, .{
        .wire_request = &req,
        .io = io,
        .header_buf = work.header_buf,
        .body_buf = work.body_buf,
    });
    const nonce = try wire.parseReplayNonceFromHeaders(&resp.headers);
    flow_ctx.setNonce(&nonce);

    return try client.parseAuthorizationResponseJson(resp.body);
}

fn pollOrderValid(
    flow_ctx: *orchestration.FlowContext,
    runtime_config: *const acme_types.RuntimeConfig,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    io: Io,
    work: WorkBuffers,
) Error!client.OrderResponse {
    var attempt: u16 = 0;
    while (attempt < config.ACME_MAX_POLL_ATTEMPTS) : (attempt += 1) {
        const fetch_order_body = try signer.signWithKid(
            work.jws_buf,
            &flow_ctx.nonce,
            &flow_ctx.order_url,
            &flow_ctx.account_url,
            "",
        );

        const handled = try transport.executeOperation(flow_ctx, acme_client, .{
            .operation = .fetch_order,
            .signed_body = fetch_order_body,
            .io = io,
            .header_buf = work.header_buf,
            .body_buf = work.body_buf,
        });
        const order = switch (handled.parsed) {
            .order => |order| order,
            else => return error.InvalidOrderStatus,
        };

        switch (order.status) {
            .valid => return order,
            .invalid => return error.InvalidOrderStatus,
            .pending, .processing, .ready => try std.Io.sleep(
                io,
                Io.Duration.fromMilliseconds(runtime_config.poll_interval_ms),
                .awake,
            ),
        }
    }

    return error.OrderPollExceeded;
}

fn downloadCertificate(
    flow_ctx: *orchestration.FlowContext,
    acme_client: *Client,
    signer: *const signer_mod.AccountSigner,
    io: Io,
    work: WorkBuffers,
    cert_url: *const client.Url,
) Error![]const u8 {
    const body = try signer.signWithKid(
        work.jws_buf,
        &flow_ctx.nonce,
        cert_url,
        &flow_ctx.account_url,
        "",
    );
    var req = try wire.buildSignedPostRequest(cert_url, body);

    const resp = try transport.execute(acme_client, .{
        .wire_request = &req,
        .io = io,
        .header_buf = work.header_buf,
        .body_buf = work.body_buf,
    });
    const nonce = try wire.parseReplayNonceFromHeaders(&resp.headers);
    flow_ctx.setNonce(&nonce);
    return resp.body;
}
