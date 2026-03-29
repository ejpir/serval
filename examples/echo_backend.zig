// examples/echo_backend.zig
//! Echo Backend Server
//!
//! Simple HTTP backend for testing load balancers. Returns request details
//! in plain text, including a configurable instance ID to verify load balancing.
//!
//! Usage:
//!   echo_backend [OPTIONS]
//!
//! Options:
//!   --port <PORT>    Listening port (default: 8001)
//!   --id <ID>        Instance identifier (default: "echo-1")
//!   --cert <PATH>    Server certificate file (PEM format, enables TLS)
//!   --key <PATH>     Server private key file (PEM format, required with --cert)
//!   --chunked        Use Transfer-Encoding: chunked for responses
//!   --debug          Enable debug logging
//!   --help           Show help message
//!   --version        Show version
//!
//! TigerStyle: Demonstrates direct response capability without forwarding.

const std = @import("std");
const assert = std.debug.assert;
const serval = @import("serval");
const serval_net = @import("serval-net");
const cli = @import("serval-cli");
const DnsConfig = serval_net.DnsConfig;

/// Version of this binary.
const VERSION = "0.1.0";

/// Echo-specific CLI options.
const EchoExtra = struct {
    /// Instance identifier for load balancer testing.
    id: []const u8 = "echo-1",
    /// Server certificate file path (PEM format) for TLS termination
    cert: ?[]const u8 = null,
    /// Server private key file path (PEM format) for TLS termination
    key: ?[]const u8 = null,
    /// Use Transfer-Encoding: chunked for responses.
    /// Why configurable: Allows testing how clients and proxies handle
    /// chunked vs content-length responses from backends.
    chunked: bool = false,
    /// Echo the exact request body back (for payload verification tests).
    /// When enabled, response body is exactly the request body.
    @"echo-body": bool = false,
    /// Drain the request body without echoing (for large upload tests).
    /// Reads and discards body, returns small response with byte count.
    /// TigerStyle: Enables testing >4GB uploads without buffering entire body.
    @"drain-body": bool = false,
};

/// Handler that echoes request details without forwarding.
/// TigerStyle: All state explicit, no hidden dependencies.
const EchoHandler = struct {
    id: []const u8,
    port: u16,
    debug: bool,
    chunked: bool,
    echo_body: bool,
    drain_body: bool,
    /// Pre-formatted extra headers buffer. Formatted once at init.
    extra_headers_buf: [128]u8 = std.mem.zeroes([128]u8),
    extra_headers_len: u8 = 0,

    /// Initializes an `EchoHandler` with the provided backend identity, port, and behavior flags.
    /// Requires `id.len > 0` and `port > 0`; these are enforced with `assert`.
    /// Stores `id` by reference (no copy), so the backing bytes must remain valid for the handler lifetime.
    /// Pre-formats `X-Backend-Id` into the internal extra-header buffer for reuse across requests.
    /// Header formatting errors are swallowed (`catch ""`), leaving `extra_headers_len` as `0` instead of failing initialization.
    pub fn init(id: []const u8, port: u16, debug: bool, chunked: bool, echo_body: bool, drain_body: bool) EchoHandler {
        // Preconditions
        assert(id.len > 0);
        assert(port > 0);

        var self = EchoHandler{
            .id = id,
            .port = port,
            .debug = debug,
            .chunked = chunked,
            .echo_body = echo_body,
            .drain_body = drain_body,
        };

        // Pre-format extra headers (persists for handler lifetime)
        const formatted = std.fmt.bufPrint(
            &self.extra_headers_buf,
            "X-Backend-Id: {s}\r\n",
            .{id},
        ) catch "";
        self.extra_headers_len = @intCast(formatted.len);

        // Postcondition: handler state is consistent
        assert(self.id.len > 0);
        assert(self.port > 0);

        return self;
    }

    /// Required by handler interface, but never called (onRequest handles everything).
    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, request: *const serval.Request) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        // TigerStyle: Explicit sentinel - this should never be reached.
        assert(false);
        return .{ .host = "0.0.0.0", .port = 0, .idx = 0 };
    }

    /// Intercept all requests and return echo response directly.
    /// TigerStyle: Uses server-provided buffer, no allocation.
    pub fn onRequest(
        self: *@This(),
        ctx: *serval.Context,
        request: *serval.Request,
        response_buf: []u8,
    ) serval.Action {
        // Precondition: response buffer must be provided
        assert(response_buf.len > 0);

        // In drain-body mode, read and discard body in chunks, return byte count.
        // This actually transfers all bytes through the proxy without buffering entire body.
        // TigerStyle: Tests large upload path (>4GB) with bounded memory usage.
        if (self.drain_body) {
            var total_bytes: u64 = 0;
            var last_progress: u64 = 0;
            var chunk_buf: [65536]u8 = undefined; // 64KB chunks

            std.debug.print("[DEBUG drain-body] starting to drain body\n", .{});

            // Read body in chunks until fully consumed (null = end of body)
            while (ctx.readBodyChunk(&chunk_buf) catch |err| {
                std.debug.print("[DEBUG drain-body] error after {d} bytes: {s}\n", .{ total_bytes, @errorName(err) });
                if (self.debug) {
                    std.debug.print("[{s}] {s} {s} -> 500 (drain error: {s})\n", .{
                        self.id,
                        @tagName(request.method),
                        request.path,
                        @errorName(err),
                    });
                }
                return .{ .send_response = .{
                    .status = 500,
                    .body = "Failed to drain request body",
                    .content_type = "text/plain",
                    .extra_headers = "",
                    .response_mode = .content_length,
                } };
            }) |chunk| {
                total_bytes += chunk.len;
                // Progress every 100MB
                if (total_bytes - last_progress >= 100 * 1024 * 1024) {
                    std.debug.print("[DEBUG drain-body] drained {d} MB\n", .{total_bytes / (1024 * 1024)});
                    last_progress = total_bytes;
                }
            }
            std.debug.print("[DEBUG drain-body] done, total {d} bytes\n", .{total_bytes});

            // Format response with actual byte count
            const body_len = std.fmt.bufPrint(response_buf, "drained {d} bytes\n", .{total_bytes}) catch {
                return .{ .send_response = .{
                    .status = 500,
                    .body = "Response format error",
                    .content_type = "text/plain",
                    .extra_headers = "",
                    .response_mode = .content_length,
                } };
            };

            if (self.debug) {
                std.debug.print("[{s}] {s} {s} -> 200 (drained {d} bytes)\n", .{
                    self.id,
                    @tagName(request.method),
                    request.path,
                    total_bytes,
                });
            }

            return .{ .send_response = .{
                .status = 200,
                .body = body_len,
                .content_type = "text/plain",
                .extra_headers = self.extra_headers_buf[0..self.extra_headers_len],
                .response_mode = .content_length,
            } };
        }

        // In echo-body mode, read request body and return it exactly
        if (self.echo_body) {
            if (self.debug) {
                std.debug.print("[{s}] {s} {s} -> 200 (echo-body stream)\n", .{
                    self.id,
                    @tagName(request.method),
                    request.path,
                });
            }

            return .{ .stream = .{
                .status = 200,
                .content_type = "application/octet-stream",
                .extra_headers = self.extra_headers_buf[0..self.extra_headers_len],
            } };
        }

        // Format echo response into server-provided buffer
        // Note: ctx not used in non-echo-body path
        const body_len = formatEchoBody(response_buf, request, self.id, self.port);

        if (self.debug) {
            std.debug.print("[{s}] {s} {s} -> 200 ({d} bytes)\n", .{
                self.id,
                @tagName(request.method),
                request.path,
                body_len,
            });
        }

        return .{ .send_response = .{
            .status = 200,
            .body = response_buf[0..body_len],
            .content_type = "text/plain",
            .extra_headers = self.extra_headers_buf[0..self.extra_headers_len],
            .response_mode = if (self.chunked) .chunked else .content_length,
        } };
    }

    /// Reads the next request-body chunk into `response_buf` when `echo_body` is enabled.
    /// Returns `null` if body echoing is disabled or when `ctx.readBodyChunk` reports no more data.
    /// On success, returns the number of bytes written, guaranteed to be `<= response_buf.len`.
    /// Preconditions: `self` must be valid and `response_buf.len > 0`.
    /// Propagates any `ctx.readBodyChunk` error unchanged (with optional debug logging when `debug` is true).
    pub fn nextChunk(self: *@This(), ctx: *serval.Context, response_buf: []u8) !?usize {
        assert(@intFromPtr(self) != 0);
        assert(response_buf.len > 0);

        if (!self.echo_body) return null;

        const maybe_chunk = ctx.readBodyChunk(response_buf) catch |err| {
            if (self.debug) {
                std.debug.print("[{s}] nextChunk readBodyChunk failed: {s}\n", .{
                    self.id,
                    @errorName(err),
                });
            }
            return err;
        };
        const chunk = maybe_chunk orelse return null;

        if (self.debug and chunk.len > 0) {
            std.debug.print("[{s}] nextChunk produced {d} bytes\n", .{
                self.id,
                chunk.len,
            });
        }

        assert(chunk.len <= response_buf.len);
        return chunk.len;
    }
};

/// Format echo body into buffer. Returns length written.
/// TigerStyle: Bounded buffer, explicit length tracking, no allocation.
fn formatEchoBody(
    buf: []u8,
    request: *const serval.Request,
    id: []const u8,
    port: u16,
) usize {
    // Preconditions
    assert(buf.len > 0);
    assert(id.len > 0);

    var position: usize = 0;

    // Helper to append formatted text
    const appendFmt = struct {
        fn call(b: []u8, p: *usize, comptime fmt: []const u8, args: anytype) void {
            const remaining = b[p.*..];
            const result = std.fmt.bufPrint(remaining, fmt, args) catch return;
            p.* += result.len;
        }
    }.call;

    // Helper to append raw bytes
    const appendRaw = struct {
        fn call(b: []u8, p: *usize, data: []const u8) void {
            const remaining = b[p.*..];
            if (data.len <= remaining.len) {
                @memcpy(remaining[0..data.len], data);
                p.* += data.len;
            }
        }
    }.call;

    // Header
    appendFmt(buf, &position, "=== Echo Backend: {s} (port {d}) ===\n\n", .{ id, port });

    // Request line
    appendFmt(buf, &position, "Method: {s}\n", .{@tagName(request.method)});
    appendFmt(buf, &position, "Path: {s}\n", .{request.path});
    appendFmt(buf, &position, "Version: {s}\n\n", .{@tagName(request.version)});

    // Headers
    appendFmt(buf, &position, "Headers:\n", .{});
    const headers = &request.headers;
    // TigerStyle: Bounded iteration over headers.
    var header_idx: u8 = 0;
    while (header_idx < headers.count) : (header_idx += 1) {
        const header = headers.headers[header_idx];
        appendFmt(buf, &position, "  {s}: {s}\n", .{ header.name, header.value });
    }

    // Body (if present)
    if (request.body) |body| {
        appendFmt(buf, &position, "\nBody ({d} bytes):\n", .{body.len});
        // TigerStyle: Truncate large bodies to avoid buffer overflow.
        const max_body_preview: u32 = 1024;
        const preview_len = @min(body.len, max_body_preview);
        appendRaw(buf, &position, body[0..preview_len]);
        if (body.len > max_body_preview) {
            appendFmt(buf, &position, "\n... ({d} more bytes)\n", .{body.len - max_body_preview});
        }
    } else {
        appendFmt(buf, &position, "\nBody: (empty)\n", .{});
    }

    // Postcondition: returned length is within buffer bounds.
    assert(position <= buf.len);

    return position;
}

/// Entry point for the echo backend example: parses CLI args, validates TLS flags, and initializes the echo handler/runtime.
/// `process_init.minimal.args` must contain valid arguments for `cli.Args(EchoExtra)`; `.help`/`.version` return without error.
/// If argument parsing fails, prints the parse error and returns `error.InvalidArgs`.
/// TLS options must be provided as a pair: `--cert` without `--key` returns `error.MissingTlsKey`, and `--key` without `--cert` returns `error.MissingTlsCert`.
/// Constructs server dependencies on the stack (`handler`, pool, metrics, tracer, threaded I/O) and deinitializes the threaded runtime via `defer`.
pub fn main(process_init: std.process.Init) !void {
    // Parse command-line arguments
    var args = cli.Args(EchoExtra).init("echo_backend", VERSION, process_init.minimal.args);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Validate TLS configuration
    const tls_config: ?serval.config.TlsConfig = if (args.extra.cert) |cert_path| blk: {
        if (args.extra.key == null) {
            std.debug.print("Error: --key is required when --cert is specified\n", .{});
            return error.MissingTlsKey;
        }
        break :blk .{
            .cert_path = cert_path,
            .key_path = args.extra.key,
        };
    } else if (args.extra.key) |_| {
        std.debug.print("Error: --cert is required when --key is specified\n", .{});
        return error.MissingTlsCert;
    } else null;

    // Initialize handler with config
    var handler = EchoHandler.init(args.extra.id, args.port, args.debug, args.extra.chunked, args.extra.@"echo-body", args.extra.@"drain-body");

    // Initialize components (minimal - no pooling/tracing needed for echo)
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};

    // Initialize async IO runtime
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    // Print startup info
    std.debug.print("Echo backend '{s}' listening on :{d} ({s})\n", .{ args.extra.id, args.port, if (tls_config != null) "HTTPS" else "HTTP" });
    if (tls_config) |tls_cfg| {
        std.debug.print("TLS: enabled (cert={s}, key={s})\n", .{ tls_cfg.cert_path.?, tls_cfg.key_path.? });
    }
    std.debug.print("Response mode: {s}\n", .{if (args.extra.chunked) "chunked" else "content-length"});
    std.debug.print("Debug logging: {}\n", .{args.debug});

    // Create and run server
    const ServerType = serval.Server(
        EchoHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    // Echo backend doesn't forward to upstreams, so no client_ctx needed.
    // DnsConfig{} uses default TTL (60s) and timeout (5s) values
    var server = ServerType.init(&handler, &pool, &metrics, &tracer, .{
        .port = args.port,
        .tls = tls_config,
    }, null, DnsConfig{});

    server.run(io, &shutdown, null) catch |err| {
        std.debug.print("Server error: {}\n", .{err});
        return;
    };
}
