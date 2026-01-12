// examples/llm_streaming.zig
//! LLM Streaming Response Example
//!
//! Demonstrates streaming responses by simulating an LLM API endpoint.
//! Uses Server-Sent Events (SSE) format to stream tokens incrementally.
//!
//! Usage:
//!   llm_streaming [OPTIONS]
//!
//! Options:
//!   --port <PORT>    Listening port (default: 8080)
//!   --debug          Enable debug logging
//!   --help           Show help message
//!   --version        Show version
//!
//! Endpoints:
//!   POST /v1/chat/completions - Streaming LLM response (SSE format)
//!   GET  /health              - Health check endpoint
//!
//! Test with:
//!   curl -X POST http://localhost:8080/v1/chat/completions -d '{}'
//!
//! TigerStyle: Demonstrates Action.stream and nextChunk() interface.

const std = @import("std");
const serval = @import("serval");
const time = serval.time;
const serval_net = @import("serval-net");
const cli = @import("serval-cli");
const DnsConfig = serval_net.DnsConfig;

/// Version of this binary.
const VERSION = "0.1.0";

/// Simulated LLM response tokens.
/// TigerStyle: Compile-time constant, bounded array.
const RESPONSE_TOKENS: []const []const u8 = &.{
    "Hello",
    "!",
    " I",
    " am",
    " a",
    " helpful",
    " AI",
    " assistant",
    ".",
    " How",
    " can",
    " I",
    " help",
    " you",
    " today",
    "?",
};

/// Delay between tokens in nanoseconds (50ms = simulated thinking time).
/// TigerStyle: Explicit unit in name.
const TOKEN_DELAY_NS: u64 = 50 * time.ns_per_ms;

/// Maximum tokens per response.
/// TigerStyle: S3 bounded loop limit.
const MAX_TOKENS: u32 = 256;

/// Handler that serves LLM-style streaming responses.
/// TigerStyle: All state explicit, no hidden dependencies.
const LlmHandler = struct {
    port: u16,
    debug: bool,
    /// Current token index for streaming. Reset per request in onRequest.
    /// Note: This is per-handler state, meaning only one streaming request
    /// can be active at a time. For production, use per-context state.
    token_idx: u32 = 0,

    /// Convert nanoseconds to (seconds, remaining_ns) for nanosleep.
    /// TigerStyle: Trivial pure function, inline calculation.
    fn nsToSecAndNs(total_ns: u64) struct { s: u64, ns: u64 } {
        const ns_per_s: u64 = 1_000_000_000;
        return .{
            .s = total_ns / ns_per_s,
            .ns = total_ns % ns_per_s,
        };
    }

    pub fn init(port: u16, debug: bool) LlmHandler {
        // S1: Preconditions
        std.debug.assert(port > 0);

        const self = LlmHandler{
            .port = port,
            .debug = debug,
            .token_idx = 0,
        };

        // S2: Postcondition - handler initialized
        std.debug.assert(self.port > 0);

        return self;
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

    /// Handle all requests and route to appropriate response.
    /// TigerStyle: Uses server-provided buffer, no allocation.
    pub fn onRequest(
        self: *@This(),
        ctx: *serval.Context,
        request: *serval.Request,
        response_buf: []u8,
    ) serval.Action {
        _ = ctx;
        // S1: Precondition - response buffer must be provided
        std.debug.assert(response_buf.len > 0);

        if (self.debug) {
            std.debug.print("[llm] {s} {s}\n", .{
                @tagName(request.method),
                request.path,
            });
        }

        // Route based on path
        if (std.mem.eql(u8, request.path, "/health")) {
            return self.handleHealth(response_buf);
        } else if (std.mem.eql(u8, request.path, "/v1/chat/completions")) {
            return self.handleChatCompletions(request);
        } else {
            return self.handleNotFound(response_buf);
        }
    }

    /// Health check endpoint - simple 200 OK.
    /// TigerStyle: Direct response, no streaming.
    fn handleHealth(self: *@This(), response_buf: []u8) serval.Action {
        _ = self;
        // S1: Precondition
        std.debug.assert(response_buf.len > 0);

        const body = "OK";
        @memcpy(response_buf[0..body.len], body);

        return .{ .send_response = .{
            .status = 200,
            .body = response_buf[0..body.len],
            .content_type = "text/plain",
        } };
    }

    /// Chat completions endpoint - returns streaming response.
    /// TigerStyle: Returns Action.stream to initiate streaming.
    fn handleChatCompletions(self: *@This(), request: *const serval.Request) serval.Action {
        // S1: Precondition - must be POST
        if (request.method != .POST) {
            // Method not allowed - but we can't easily return error from here
            // since we return stream. For simplicity, just stream anyway.
            // Production code would validate and return DirectResponse with 405.
        }

        // Reset token index for new request
        self.token_idx = 0;

        return .{ .stream = .{
            .status = 200,
            .content_type = "text/event-stream",
            // SSE headers: disable caching and buffering
            .extra_headers = "Cache-Control: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n",
        } };
    }

    /// 404 Not Found response.
    /// TigerStyle: Direct response for unknown paths.
    fn handleNotFound(self: *@This(), response_buf: []u8) serval.Action {
        _ = self;
        // S1: Precondition
        std.debug.assert(response_buf.len > 0);

        const body = "Not Found";
        @memcpy(response_buf[0..body.len], body);

        return .{ .send_response = .{
            .status = 404,
            .body = response_buf[0..body.len],
            .content_type = "text/plain",
        } };
    }

    /// Generate next chunk for streaming response.
    /// Returns the length of data written to buffer, or null when done.
    /// Called repeatedly by server until null is returned.
    /// TigerStyle: Bounded iteration, explicit return values.
    pub fn nextChunk(
        self: *@This(),
        ctx: *serval.Context,
        response_buf: []u8,
    ) !?usize {
        _ = ctx;
        // S1: Preconditions
        std.debug.assert(response_buf.len > 0);

        // S3: Bounded check - have we exceeded max tokens?
        if (self.token_idx > RESPONSE_TOKENS.len + 1) {
            // Safety: already sent [DONE], signal completion
            return null;
        }

        // Check if we've sent all tokens - time to send [DONE]
        if (self.token_idx == RESPONSE_TOKENS.len) {
            // Send final [DONE] message
            const done_msg = "data: [DONE]\n\n";
            if (done_msg.len > response_buf.len) {
                return error.BufferTooSmall;
            }
            @memcpy(response_buf[0..done_msg.len], done_msg);

            // Mark [DONE] as sent
            self.token_idx += 1;
            return done_msg.len;
        }

        // Already sent [DONE], now signal completion
        if (self.token_idx > RESPONSE_TOKENS.len) {
            return null;
        }

        // Simulate thinking delay between tokens
        if (self.token_idx > 0) {
            const delay = nsToSecAndNs(TOKEN_DELAY_NS);
            std.posix.nanosleep(delay.s, delay.ns);
        }

        // Get current token
        const token = RESPONSE_TOKENS[self.token_idx];

        // Format SSE message: "data: {token}\n\n"
        // S1: Precondition - buffer must fit SSE envelope + token
        const prefix = "data: ";
        const suffix = "\n\n";
        const total_len = prefix.len + token.len + suffix.len;

        if (total_len > response_buf.len) {
            return error.BufferTooSmall;
        }

        // Write SSE message to buffer
        @memcpy(response_buf[0..prefix.len], prefix);
        @memcpy(response_buf[prefix.len..][0..token.len], token);
        @memcpy(response_buf[prefix.len + token.len ..][0..suffix.len], suffix);

        // Advance to next token
        self.token_idx += 1;

        // S2: Postcondition - returned length matches written data
        std.debug.assert(total_len <= response_buf.len);

        if (self.debug) {
            std.debug.print("[llm] streaming token {d}/{d}: {s}\n", .{
                self.token_idx,
                RESPONSE_TOKENS.len,
                token,
            });
        }

        return total_len;
    }
};

pub fn main() !void {
    // Parse command-line arguments
    // Note: cli.Args expects a struct for extra options, use NoExtra for none
    var args = cli.Args(cli.NoExtra).init("llm_streaming", VERSION);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Initialize handler with config
    var handler = LlmHandler.init(args.port, args.debug);

    // Initialize components (minimal - no pooling/tracing needed for demo)
    var pool = serval.SimplePool.init();
    var metrics = serval.NoopMetrics{};
    var tracer = serval.NoopTracer{};

    // Initialize async IO runtime
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var shutdown = std.atomic.Value(bool).init(false);

    // Print startup info
    std.debug.print("LLM Streaming Example listening on :{d}\n", .{args.port});
    std.debug.print("Endpoints:\n", .{});
    std.debug.print("  POST /v1/chat/completions - Streaming LLM response\n", .{});
    std.debug.print("  GET  /health              - Health check\n", .{});
    std.debug.print("\nTest with:\n", .{});
    std.debug.print("  curl -X POST http://localhost:{d}/v1/chat/completions\n", .{args.port});

    // Create and run server
    const ServerType = serval.Server(
        LlmHandler,
        serval.SimplePool,
        serval.NoopMetrics,
        serval.NoopTracer,
    );
    // LLM example doesn't forward to upstreams, so no client_ctx needed.
    // DnsConfig{} uses default TTL (60s) and timeout (5s) values.
    var server = ServerType.init(&handler, &pool, &metrics, &tracer, .{
        .port = args.port,
    }, null, DnsConfig{});

    server.run(io, &shutdown) catch |err| {
        std.debug.print("Server error: {}\n", .{err});
        return;
    };
}
