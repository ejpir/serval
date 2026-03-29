//! serval-waf/handler.zig
//! Generic handler wrapper applying scanner-focused WAF decisions.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const types = @import("types.zig");
const scanner = @import("scanner.zig");

const Request = core.Request;
const Response = core.Response;
const Context = core.Context;
const Action = core.Action;
const BodyAction = core.BodyAction;
const ErrorAction = core.ErrorAction;
const LogEntry = core.LogEntry;

/// Signature for an optional miss-classification hook used by `ShieldedHandler`.
/// Invoked by `onLog` with read-only `ctx` and the current `LogEntry`; return `true` to classify the entry as a miss.
/// `ctx` and `entry` are borrowed for the duration of the call only; do not retain either pointer.
/// This function is non-fallible (`bool` return only); implementers must handle any internal failure paths themselves.
pub const IsMissFn = *const fn (ctx: *const Context, entry: *const LogEntry) bool;

fn defaultIsMiss(ctx: *const Context, entry: *const LogEntry) bool {
    _ = ctx;
    return entry.status == 404;
}

/// Returns a handler type that wraps `Inner` with request inspection, decision observation, and tracker updates.
/// Instances keep a non-owning `*Inner`; the pointee must outlive the `ShieldedHandler` instance.
/// `init` validates `types.Config`, initializes internal tracking from that config, and fails if validation fails.
/// `onRequest` may return a WAF reject action (using configured block status/reason) or delegate to `Inner.onRequest` when present.
/// `onRequestBody` forwards to `Inner.onRequestBody` when present; otherwise it continues body processing unchanged.
pub fn ShieldedHandler(comptime Inner: type) type {
    return struct {
        inner: *Inner,
        config: types.Config,
        observer: ?types.ObserveFn,
        is_miss: ?IsMissFn,
        tracker: scanner.Tracker,

        const Self = @This();

        /// Initializes a handler by validating `config`, storing `inner`, callbacks, and a copy of `config` in the returned `Self`.
        /// `inner` is borrowed (not owned) and must remain valid for at least as long as the handler is used.
        /// `observer` and `is_miss` are optional function pointers and may be `null`.
        /// Returns any error produced by `config.validate()`; otherwise initializes `tracker` and returns the fully initialized handler.
        pub fn init(inner: *Inner, config: types.Config, observer: ?types.ObserveFn, is_miss: ?IsMissFn) !Self {
            try config.validate();
            var result = Self{
                .inner = inner,
                .config = config,
                .observer = observer,
                .is_miss = is_miss,
                .tracker = undefined,
            };
            result.tracker.init(&config);
            return result;
        }

        /// Evaluates the incoming request with temporary inspection scratch state and derives a local decision.
        /// If evaluation produced tracker input, records request activity; on rejection, also records a blocked outcome for the client address.
        /// Always emits decision observation before returning, including reject and pass-through paths.
        /// Returns `.reject` with configured block status/reason when `shouldReject` is true; otherwise delegates to `Inner.onRequest` when available, or `.continue_request`.
        /// Does not take ownership of `ctx`, `request`, or `response_buf`; all must remain valid for the duration of the call.
        pub fn onRequest(self: *Self, ctx: *Context, request: *Request, response_buf: []u8) Action {
            var scratch = types.InspectionScratch{};
            const eval = self.evaluateRequest(ctx, request, &scratch);
            var decision = eval.decision;

            if (eval.input) |input| {
                const request_update = self.tracker.commitRequest(&input);
                if (request_update.tracker_degraded) decision.tracker_degraded = true;
            }

            if (self.shouldReject(&decision)) {
                if (eval.input) |input| {
                    const update = self.tracker.commitOutcome(input.client_addr, false, true);
                    if (update.tracker_degraded) decision.tracker_degraded = true;
                }
                self.observeDecision(ctx, request, &decision);
                return .{ .reject = .{ .status = self.config.block_status, .reason = self.config.block_reason } };
            }

            self.observeDecision(ctx, request, &decision);

            if (comptime @hasDecl(Inner, "onRequest")) {
                return self.inner.onRequest(ctx, request, response_buf);
            }
            return .continue_request;
        }

        /// Handles an inbound request-body chunk and returns the next `BodyAction`.
        /// If `Inner` declares `onRequestBody`, this forwards directly to `self.inner.onRequestBody(ctx, chunk, is_last)`.
        /// `chunk` is passed as a read-only borrowed slice; this function does not take ownership of its storage.
        /// If `Inner` does not implement `onRequestBody`, the default behavior is `.continue_body`.
        pub fn onRequestBody(self: *Self, ctx: *Context, chunk: []const u8, is_last: bool) BodyAction {
            if (comptime @hasDecl(Inner, "onRequestBody")) {
                return self.inner.onRequestBody(ctx, chunk, is_last);
            }
            return .continue_body;
        }

        /// Selects an upstream by delegating directly to `self.inner.selectUpstream(ctx, request)`.
        /// `self`, `ctx`, and `request` must be valid for the duration of this call.
        /// This wrapper adds no routing logic and does not take ownership of `ctx` or `request`.
        /// Returns exactly the inner result; if the inner call fails, its error is propagated unchanged.
        pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) @typeInfo(@TypeOf(Inner.selectUpstream)).@"fn".return_type.? {
            return self.inner.selectUpstream(ctx, request);
        }

        /// Invokes the optional upstream-request hook on the wrapped `Inner` handler.
        /// Requires `self`, `ctx`, and `request` to be valid pointers for the duration of the call.
        /// If `Inner` declares `onUpstreamRequest`, this forwards to `self.inner.onUpstreamRequest(ctx, request)`;
        /// otherwise this function is a no-op. It returns no error (`void`).
        pub fn onUpstreamRequest(self: *Self, ctx: *Context, request: *Request) void {
            if (comptime @hasDecl(Inner, "onUpstreamRequest")) {
                self.inner.onUpstreamRequest(ctx, request);
            }
        }

        /// Invoked when an upstream connection is established for the current request context.
        /// If `Inner` defines `onUpstreamConnect`, this method forwards `ctx` and `info` to `self.inner`; otherwise it is a no-op.
        /// Preconditions: `self`, `ctx`, and `info` must be valid, non-dangling pointers for the duration of the call.
        /// This function does not allocate, does not transfer ownership, and cannot return errors.
        pub fn onUpstreamConnect(self: *Self, ctx: *Context, info: *const core.UpstreamConnectInfo) void {
            if (comptime @hasDecl(Inner, "onUpstreamConnect")) {
                self.inner.onUpstreamConnect(ctx, info);
            }
        }

        /// Handles a response event for this handler and returns the next `Action`.
        /// Requires `self`, `ctx`, and `response` to be valid pointers for the duration of the call.
        /// If `Inner` defines `onResponse`, this forwards directly to `self.inner.onResponse(ctx, response)`.
        /// Otherwise, it performs no response-specific handling and returns `.continue_request`.
        pub fn onResponse(self: *Self, ctx: *Context, response: *Response) Action {
            if (comptime @hasDecl(Inner, "onResponse")) {
                return self.inner.onResponse(ctx, response);
            }
            return .continue_request;
        }

        /// Handles a response body chunk in the middleware wrapper.
        /// If `Inner` defines `onResponseBody`, this forwards `ctx`, `chunk`, and `is_last` and returns its `BodyAction`.
        /// Otherwise, it defaults to `.continue_body` and performs no additional processing.
        /// `chunk` is read-only input for this call; ownership remains with the caller.
        pub fn onResponseBody(self: *Self, ctx: *Context, chunk: []const u8, is_last: bool) BodyAction {
            if (comptime @hasDecl(Inner, "onResponseBody")) {
                return self.inner.onResponseBody(ctx, chunk, is_last);
            }
            return .continue_body;
        }

        /// Handles an error produced while processing a request and returns the desired recovery action.
        /// If `Inner` defines `onError`, this delegates to `self.inner.onError(ctx, err_ctx)` and returns its result.
        /// Otherwise, it returns `.default` without additional handling.
        /// `self`, `ctx`, and `err_ctx` must be valid pointers for the duration of the call.
        pub fn onError(self: *Self, ctx: *Context, err_ctx: *const core.ErrorContext) ErrorAction {
            if (comptime @hasDecl(Inner, "onError")) {
                return self.inner.onError(ctx, err_ctx);
            }
            return .default;
        }

        /// Processes a completed request log entry for WAF outcome tracking.
        /// Uses `self.is_miss` when configured, otherwise `defaultIsMiss`, to classify the entry as a cache miss.
        /// Marks the entry as rejected when `entry.status == self.config.block_status`, then commits `(client_addr, miss, reject)` to `tracker` (result ignored).
        /// If `Inner` defines `onLog`, this forwards the same `ctx` and `entry`; this function is `void` and does not propagate errors.
        pub fn onLog(self: *Self, ctx: *Context, entry: LogEntry) void {
            const classifier = self.is_miss orelse defaultIsMiss;
            const client_addr = std.mem.sliceTo(&entry.client_addr, 0);
            const miss = classifier(ctx, &entry);
            const reject = entry.status == self.config.block_status;
            _ = self.tracker.commitOutcome(client_addr, miss, reject);
            if (comptime @hasDecl(Inner, "onLog")) {
                self.inner.onLog(ctx, entry);
            }
        }

        /// Notifies the wrapped handler that a connection has opened.
        /// If `Inner` declares `onConnectionOpen`, this forwards `info` to `self.inner.onConnectionOpen(info)`; otherwise it is a no-op.
        /// Preconditions: `self` must reference an initialized handler and `info` must point to a valid `core.ConnectionInfo` for the duration of this call.
        /// Ownership/lifetime: this function does not take ownership of `info` and performs no allocation; it cannot fail.
        pub fn onConnectionOpen(self: *Self, info: *const core.ConnectionInfo) void {
            if (comptime @hasDecl(Inner, "onConnectionOpen")) {
                self.inner.onConnectionOpen(info);
            }
        }

        /// Notifies the wrapped `Inner` that a connection has closed, including its `connection_id`,
        /// total `request_count`, and observed `duration_ns` lifetime.
        /// `self` must reference a valid handler instance; this function does not take ownership of any data.
        /// If `Inner` does not declare `onConnectionClose`, this call is a no-op.
        /// This function cannot fail and returns `void`.
        pub fn onConnectionClose(self: *Self, connection_id: u64, request_count: u32, duration_ns: u64) void {
            if (comptime @hasDecl(Inner, "onConnectionClose")) {
                self.inner.onConnectionClose(connection_id, request_count, duration_ns);
            }
        }

        const EvaluateResult = struct {
            decision: types.Decision,
            input: ?types.InspectionInput = null,
        };

        fn evaluateRequest(self: *Self, ctx: *Context, request: *const Request, scratch: *types.InspectionScratch) EvaluateResult {
            const input = types.InspectionInput.fromRequest(request, ctx, scratch) catch |err| {
                return .{
                    .decision = scanner.buildFailureDecision(self.config.enforcement_mode, mapFailureReason(err), self.config.failure_mode),
                };
            };

            const snapshot = self.tracker.snapshot(&input);
            const decision = scanner.evaluateWithBehavior(&self.config, &input, snapshot);
            return .{
                .decision = decision,
                .input = input,
            };
        }

        fn shouldReject(self: *const Self, decision: *const types.Decision) bool {
            if (decision.action != .block) return false;
            if (decision.failure_reason != null) {
                return self.config.failure_mode == .fail_closed;
            }
            return self.config.enforcement_mode == .enforce;
        }

        fn observeDecision(self: *const Self, ctx: *const Context, request: *const Request, decision: *const types.Decision) void {
            const observer = self.observer orelse return;
            observer(ctx, request, decision);
        }
    };
}

fn mapFailureReason(err: anyerror) types.FailureReason {
    return switch (err) {
        error.InvalidPercentEncoding => .invalid_percent_encoding,
        error.NormalizedFieldTooLong => .normalized_field_too_long,
        else => unreachable,
    };
}

test "ShieldedHandler blocks before upstream selection in enforce mode" {
    const TestInner = struct {
        select_calls: u8 = 0,

        /// Selects the upstream target for a request and records that a selection occurred.
        /// This implementation ignores both `ctx` and `request` and always returns the same upstream:
        /// host `127.0.0.1`, port `8080`, index `0`.
        /// Requires a mutable, valid `self`; it mutates `self.select_calls` and does not retain pointer inputs.
        pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) core.Upstream {
            _ = ctx;
            _ = request;
            self.select_calls += 1;
            return .{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
        }
    };

    var inner = TestInner{};
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("ua-sqlmap", .user_agent, .contains_ascii_ci, "sqlmap", 120, .block),
    };
    var handler = try ShieldedHandler(TestInner).init(&inner, .{
        .rules = rules[0..],
        .enforcement_mode = .enforce,
        .failure_mode = .fail_open,
    }, null, null);

    var headers = core.HeaderMap.init();
    try headers.put("User-Agent", "sqlmap/1.8");
    const request = Request{ .method = .GET, .path = "/", .headers = headers };
    var request_mut = request;
    var ctx = Context.init();
    ctx.client_addr[0] = '1';
    ctx.client_addr[1] = 0;
    var response_buf: [64]u8 = undefined;

    const action = handler.onRequest(&ctx, &request_mut, response_buf[0..]);

    try std.testing.expect(action == .reject);
    try std.testing.expectEqual(@as(u8, 0), inner.select_calls);
}

test "ShieldedHandler detect-only continues and delegated selectUpstream still runs" {
    const TestInner = struct {
        select_calls: u8 = 0,

        /// Selects an upstream for the current request and returns it by value.
        /// This implementation ignores both `ctx` and `request`.
        /// Requires a valid mutable `self`; increments `self.select_calls` on every invocation.
        /// Always returns the fixed endpoint `{ host = "127.0.0.1", port = 8080, idx = 0 }` and cannot fail.
        pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) core.Upstream {
            _ = ctx;
            _ = request;
            self.select_calls += 1;
            return .{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
        }
    };

    var inner = TestInner{};
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("ua-sqlmap", .user_agent, .contains_ascii_ci, "sqlmap", 120, .block),
    };
    var handler = try ShieldedHandler(TestInner).init(&inner, .{
        .rules = rules[0..],
        .enforcement_mode = .detect_only,
        .failure_mode = .fail_open,
    }, null, null);

    var headers = core.HeaderMap.init();
    try headers.put("User-Agent", "sqlmap/1.8");
    const request = Request{ .method = .GET, .path = "/", .headers = headers };
    var request_mut = request;
    var ctx = Context.init();
    ctx.client_addr[0] = '1';
    ctx.client_addr[1] = 0;
    var response_buf: [64]u8 = undefined;

    const action = handler.onRequest(&ctx, &request_mut, response_buf[0..]);
    _ = handler.selectUpstream(&ctx, &request);

    try std.testing.expect(action == .continue_request);
    try std.testing.expectEqual(@as(u8, 1), inner.select_calls);
}

test "ShieldedHandler emits failure metadata and honors fail-closed" {
    const TestInner = struct {
        /// Selects the upstream target for a request and returns it by value.
        /// Current behavior is static: it always returns `127.0.0.1:8080` with upstream index `0`.
        /// `self`, `ctx`, and `request` are currently ignored and impose no additional preconditions.
        /// This function is infallible and performs no allocation or ownership transfer.
        pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) core.Upstream {
            _ = self;
            _ = ctx;
            _ = request;
            return .{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
        }
    };
    const ObserverState = struct {
        saw_failure: bool = false,
        action: types.DecisionAction = .allow,
    };
    const Observer = struct {
        fn observe(ctx: *const Context, request: *const Request, decision: *const types.Decision) void {
            _ = request;
            const state: *ObserverState = @ptrCast(@alignCast(ctx.user_data.?));
            state.saw_failure = decision.failure_reason != null;
            state.action = decision.action;
        }
    };

    var inner = TestInner{};
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/admin", 10, .score),
    };
    var handler = try ShieldedHandler(TestInner).init(&inner, .{
        .rules = rules[0..],
        .enforcement_mode = .enforce,
        .failure_mode = .fail_closed,
    }, Observer.observe, null);

    var state = ObserverState{};
    const request = Request{ .method = .GET, .path = "/bad%2", .headers = .{} };
    var request_mut = request;
    var ctx = Context.init();
    ctx.client_addr[0] = '1';
    ctx.client_addr[1] = 0;
    ctx.user_data = &state;
    var response_buf: [64]u8 = undefined;

    const action = handler.onRequest(&ctx, &request_mut, response_buf[0..]);

    try std.testing.expect(action == .reject);
    try std.testing.expect(state.saw_failure);
    try std.testing.expectEqual(types.DecisionAction.block, state.action);
}

test "ShieldedHandler applies miss feedback to subsequent requests only" {
    const TestInner = struct {
        /// Selects the upstream target for a request and returns a `core.Upstream` by value.
        /// This implementation is deterministic: it ignores `self`, `ctx`, and `request`.
        /// It always returns host `127.0.0.1`, port `8080`, with upstream index `0`.
        /// The function does not allocate, does not retain any input references, and cannot fail.
        pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) core.Upstream {
            _ = self;
            _ = ctx;
            _ = request;
            return .{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
        }
    };

    var inner = TestInner{};
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/never", 10, .score),
    };
    var handler = try ShieldedHandler(TestInner).init(&inner, .{
        .rules = rules[0..],
        .block_threshold = 80,
        .enforcement_mode = .enforce,
        .failure_mode = .fail_open,
        .burst_enabled = true,
        .burst_request_threshold = 200,
        .burst_miss_reject_threshold = 1,
        .burst_miss_reject_score = 90,
    }, null, null);

    var ctx = Context.init();
    ctx.client_addr[0] = '1';
    ctx.client_addr[1] = 0;
    var response_buf: [64]u8 = undefined;

    var req1 = Request{ .method = .GET, .path = "/any-1", .headers = .{} };
    const action1 = handler.onRequest(&ctx, &req1, response_buf[0..]);
    try std.testing.expect(action1 == .continue_request);

    var entry = LogEntry{
        .timestamp_s = 0,
        .start_time_ns = 0,
        .duration_ns = 0,
        .method = .GET,
        .path = req1.path,
        .request_bytes = 0,
        .status = 404,
        .response_bytes = 0,
        .upstream = null,
        .upstream_duration_ns = 0,
        .error_phase = null,
        .error_name = null,
        .connection_reused = false,
        .keepalive = false,
    };
    entry.client_addr[0] = '1';
    entry.client_addr[1] = 0;
    handler.onLog(&ctx, entry);

    var req2 = Request{ .method = .GET, .path = "/any-2", .headers = .{} };
    const action2 = handler.onRequest(&ctx, &req2, response_buf[0..]);
    try std.testing.expect(action2 == .reject);
}

test "ShieldedHandler supports custom isMiss classifier hook" {
    const TestInner = struct {
        /// Selects the upstream target for a request.
        /// Currently returns a fixed upstream at `127.0.0.1:8080` with index `0`.
        /// `self`, `ctx`, and `request` are accepted but not consulted by this implementation.
        /// Returns `core.Upstream` by value and does not allocate or return errors.
        pub fn selectUpstream(self: *@This(), ctx: *Context, request: *const Request) core.Upstream {
            _ = self;
            _ = ctx;
            _ = request;
            return .{ .host = "127.0.0.1", .port = 8080, .idx = 0 };
        }
    };
    const Hooks = struct {
        fn isMiss(ctx: *const Context, entry: *const LogEntry) bool {
            _ = ctx;
            return entry.status == 418;
        }
    };

    var inner = TestInner{};
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/never", 10, .score),
    };
    var handler = try ShieldedHandler(TestInner).init(&inner, .{
        .rules = rules[0..],
        .block_threshold = 80,
        .enforcement_mode = .enforce,
        .failure_mode = .fail_open,
        .burst_enabled = true,
        .burst_request_threshold = 200,
        .burst_miss_reject_threshold = 1,
        .burst_miss_reject_score = 90,
    }, null, Hooks.isMiss);

    var ctx = Context.init();
    ctx.client_addr[0] = '1';
    ctx.client_addr[1] = 0;
    var response_buf: [64]u8 = undefined;

    var req1 = Request{ .method = .GET, .path = "/any-1", .headers = .{} };
    const action1 = handler.onRequest(&ctx, &req1, response_buf[0..]);
    try std.testing.expect(action1 == .continue_request);

    var entry = LogEntry{
        .timestamp_s = 0,
        .start_time_ns = 0,
        .duration_ns = 0,
        .method = .GET,
        .path = req1.path,
        .request_bytes = 0,
        .status = 404,
        .response_bytes = 0,
        .upstream = null,
        .upstream_duration_ns = 0,
        .error_phase = null,
        .error_name = null,
        .connection_reused = false,
        .keepalive = false,
    };
    entry.client_addr[0] = '1';
    entry.client_addr[1] = 0;
    handler.onLog(&ctx, entry);

    var req2 = Request{ .method = .GET, .path = "/any-2", .headers = .{} };
    const action2 = handler.onRequest(&ctx, &req2, response_buf[0..]);
    try std.testing.expect(action2 == .continue_request);
}
