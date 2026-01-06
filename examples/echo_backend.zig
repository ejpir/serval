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
//!   --debug          Enable debug logging
//!   --help           Show help message
//!   --version        Show version
//!
//! TigerStyle: Demonstrates direct response capability without forwarding.

const std = @import("std");
const serval = @import("serval");
const cli = @import("serval-cli");

/// Version of this binary.
const VERSION = "0.1.0";

/// Echo-specific CLI options.
const EchoExtra = struct {
    /// Instance identifier for load balancer testing.
    id: []const u8 = "echo-1",
};

/// Handler that echoes request details without forwarding.
/// TigerStyle: All state explicit, no hidden dependencies.
const EchoHandler = struct {
    id: []const u8,
    port: u16,
    debug: bool,

    pub fn init(id: []const u8, port: u16, debug: bool) EchoHandler {
        // Preconditions
        std.debug.assert(id.len > 0);
        std.debug.assert(port > 0);

        return .{ .id = id, .port = port, .debug = debug };
    }

    /// Required by handler interface, but never called (onRequest handles everything).
    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, request: *const serval.Request) serval.Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        // TigerStyle: Explicit sentinel - this should never be reached.
        std.debug.assert(false);
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
        _ = ctx;

        // Format echo response into server-provided buffer
        const body_len = formatEchoBody(response_buf, request, self.id, self.port);

        // Format extra headers (X-Backend-Id for programmatic detection)
        var header_buf: [128]u8 = std.mem.zeroes([128]u8);
        const extra_headers = std.fmt.bufPrint(
            &header_buf,
            "X-Backend-Id: {s}\r\n",
            .{self.id},
        ) catch "";

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
            .extra_headers = extra_headers,
        } };
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
    std.debug.assert(buf.len > 0);
    std.debug.assert(id.len > 0);

    var pos: usize = 0;

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
    appendFmt(buf, &pos, "=== Echo Backend: {s} (port {d}) ===\n\n", .{ id, port });

    // Request line
    appendFmt(buf, &pos, "Method: {s}\n", .{@tagName(request.method)});
    appendFmt(buf, &pos, "Path: {s}\n", .{request.path});
    appendFmt(buf, &pos, "Version: {s}\n\n", .{@tagName(request.version)});

    // Headers
    appendFmt(buf, &pos, "Headers:\n", .{});
    const headers = &request.headers;
    // TigerStyle: Bounded iteration over headers.
    var header_idx: u8 = 0;
    while (header_idx < headers.count) : (header_idx += 1) {
        const header = headers.headers[header_idx];
        appendFmt(buf, &pos, "  {s}: {s}\n", .{ header.name, header.value });
    }

    // Body (if present)
    if (request.body) |body| {
        appendFmt(buf, &pos, "\nBody ({d} bytes):\n", .{body.len});
        // TigerStyle: Truncate large bodies to avoid buffer overflow.
        const max_body_preview: usize = 1024;
        const preview_len = @min(body.len, max_body_preview);
        appendRaw(buf, &pos, body[0..preview_len]);
        if (body.len > max_body_preview) {
            appendFmt(buf, &pos, "\n... ({d} more bytes)\n", .{body.len - max_body_preview});
        }
    } else {
        appendFmt(buf, &pos, "\nBody: (empty)\n", .{});
    }

    // Postcondition: returned length is within buffer bounds.
    std.debug.assert(pos <= buf.len);

    return pos;
}

pub fn main() !void {
    // Parse command-line arguments
    var args = cli.Args(EchoExtra).init("echo_backend", VERSION);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Initialize handler with config
    var handler = EchoHandler.init(args.extra.id, args.port, args.debug);

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
    std.debug.print("Echo backend '{s}' listening on :{d}\n", .{ args.extra.id, args.port });
    std.debug.print("Debug logging: {}\n", .{args.debug});

    // Create and run server
    const ServerType = serval.Server(
        EchoHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    var server = ServerType.init(&handler, &pool, &metrics, &tracer, .{
        .port = args.port,
    });

    server.run(io, &shutdown) catch |err| {
        std.debug.print("Server error: {}\n", .{err});
        return;
    };
}
