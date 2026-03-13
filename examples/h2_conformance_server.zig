//! HTTP/2 Conformance Target Server
//!
//! Minimal server for running h2spec/nghttp against Serval.
//! - Plain listener supports terminated prior-knowledge h2 handling.
//! - TLS listener supports ALPN h2 dispatch into the terminated h2 runtime.

const std = @import("std");
const assert = std.debug.assert;

const serval = @import("serval");
const serval_net = @import("serval-net");
const cli = @import("serval-cli");

const DnsConfig = serval_net.DnsConfig;

const VERSION = "0.1.0";

const Extra = struct {
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
};

const h1_fallback_message: []const u8 = "h2 conformance target (h1 fallback)\n";

const Handler = struct {
    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, request: *const serval.Request) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        @panic("conformance handler should not forward upstream");
    }

    pub fn onRequest(
        self: *@This(),
        ctx: *serval.Context,
        request: *serval.Request,
        response_buf: []u8,
    ) serval.Action {
        _ = self;
        _ = ctx;
        _ = request;

        assert(response_buf.len >= h1_fallback_message.len);
        @memcpy(response_buf[0..h1_fallback_message.len], h1_fallback_message);
        return .{ .send_response = .{
            .status = 200,
            .body = response_buf[0..h1_fallback_message.len],
            .content_type = "text/plain",
            .extra_headers = "",
            .response_mode = .content_length,
        } };
    }

    pub fn handleH2Headers(
        self: *@This(),
        stream_id: u32,
        request: *const serval.Request,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = self;
        _ = request;
        assert(stream_id > 0);

        if (!end_stream) return;

        send_h2_ok(writer) catch |err| switch (err) {
            error.HeadersAlreadySent, error.ResponseClosed => return,
            else => return err,
        };
    }

    pub fn handleH2Data(
        self: *@This(),
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = self;
        _ = payload;
        assert(stream_id > 0);

        if (!end_stream) return;

        send_h2_ok(writer) catch |err| switch (err) {
            error.HeadersAlreadySent, error.ResponseClosed => return,
            else => return err,
        };
    }
};

fn send_h2_ok(writer: *serval.server.H2ResponseWriter) !void {
    assert(@intFromPtr(writer) != 0);

    try writer.sendHeaders(200, &.{.{ .name = "content-type", .value = "text/plain" }}, false);
    try writer.sendData("hello", true);
}

pub fn main(process_init: std.process.Init) !void {
    var args = cli.Args(Extra).init("h2_conformance_server", VERSION, process_init.minimal.args);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    var tls_config: ?serval.config.TlsConfig = null;
    if (args.extra.cert) |cert_path| {
        if (args.extra.key == null) return error.MissingTlsKey;
        tls_config = .{
            .cert_path = cert_path,
            .key_path = args.extra.key,
        };
    } else if (args.extra.key != null) {
        return error.MissingTlsCert;
    }

    var handler = Handler{};
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};

    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    const ServerType = serval.Server(
        Handler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );

    var server = ServerType.init(
        &handler,
        &pool,
        &metrics,
        &tracer,
        .{
            .port = args.port,
            .tls = tls_config,
            .h2c_prior_knowledge_only = tls_config == null,
        },
        null,
        DnsConfig{},
    );

    std.debug.print(
        "h2 conformance server listening on :{d} ({s})\n",
        .{ args.port, if (tls_config != null) "HTTPS" else "HTTP" },
    );

    try server.run(io, &shutdown, null);
}
