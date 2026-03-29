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
    /// Selects an upstream for forwarding, but this conformance handler never forwards requests.
    /// Panics unconditionally with `"conformance handler should not forward upstream"` and does not return.
    /// `self`, `ctx`, and `request` are currently unused; callers must not invoke this in forwarding paths.
    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, request: *const serval.Request) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        @panic("conformance handler should not forward upstream");
    }

    /// Handles any request by returning a fixed plain-text fallback body with HTTP `200`.
    /// Preconditions: `response_buf.len >= h1_fallback_message.len` (enforced via `assert`).
    /// Copies `h1_fallback_message` into `response_buf` and returns a body slice over that copied region.
    /// `self`, `ctx`, and `request` are currently ignored; this function does not return an error union.
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

    /// Handles incoming HTTP/2 request headers for a single stream and immediately attempts a conformance `OK` response via `send_h2_ok`.
    /// Preconditions: `stream_id` must be non-zero (asserted); `writer` must reference an open response context for that stream.
    /// `request` and `end_stream` are currently ignored, so behavior is the same for header-only and continued (DATA/trailers) requests.
    /// Treats `error.HeadersAlreadySent` and `error.ResponseClosed` from `send_h2_ok` as non-fatal and returns success.
    /// Propagates any other writer/response error to the caller.
    pub fn handleH2Headers(
        self: *@This(),
        stream_id: u32,
        request: *const serval.Request,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = self;
        _ = request;
        _ = end_stream;
        assert(stream_id > 0);

        // Respond immediately for conformance probes, including requests that
        // continue with DATA + trailer frames.
        send_h2_ok(writer) catch |err| switch (err) {
            error.HeadersAlreadySent, error.ResponseClosed => return,
            else => return err,
        };
    }

    /// Handles incoming HTTP/2 DATA for the conformance response path.
    /// `stream_id` must be non-zero; this is enforced with an assertion before any response is sent.
    /// The request payload and `end_stream` flag are ignored here because this target always sends the same final response.
    /// If the response is already finalized or the stream is closed, those conditions are treated as success; other send errors are returned.
    pub fn handleH2Data(
        self: *@This(),
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
        writer: *serval.server.H2ResponseWriter,
    ) !void {
        _ = self;
        _ = payload;
        _ = end_stream;
        assert(stream_id > 0);

        // Conformance target should respond even when request trailers follow DATA.
        // RFC 9113 permits the server to send a final response before consuming all
        // request-body/trailer octets, as long as stream state is coherent.
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

/// Parses command-line arguments and starts the HTTP/2 conformance server.
/// Requires `--cert` and `--key` to be provided together; returns `error.MissingTlsKey` or `error.MissingTlsCert` for mismatched TLS inputs.
/// On invalid CLI input, prints the parse error and returns `error.InvalidArgs`; `help` and `version` exit successfully.
/// Initializes the handler, pool, metrics, tracer, and threaded I/O runtime, then runs the server until it stops or returns an error.
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
