//! ACME manager transition runner (PR4 scaffolding).
//!
//! Executes bounded nonce/account/order/finalize state transitions using the
//! ACME orchestration and transport adapters.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const core = @import("serval-core");
const config = core.config;

const acme_types = @import("types.zig");
const client = @import("client.zig");
const orchestration = @import("orchestration.zig");
const transport = @import("transport.zig");

const serval_client = @import("serval-client");
const Client = serval_client.Client;

pub const Error = error{
    InvalidTransitionLimit,
    InvalidHeaderBuffer,
    InvalidBodyBuffer,
    MissingSignedBody,
};

const max_error_count: u16 = std.math.maxInt(u16);

pub const SignedBodies = struct {
    new_account_body: []const u8 = &.{},
    fetch_account_body: []const u8 = &.{},
    new_order_body: []const u8 = &.{},
    fetch_order_body: []const u8 = &.{},
    finalize_order_body: []const u8 = &.{},

    pub fn bodyForOperation(self: *const SignedBodies, operation: orchestration.Operation) Error![]const u8 {
        assert(@intFromPtr(self) != 0);

        return switch (operation) {
            .fetch_nonce => &.{},
            .new_account => requireSignedBody(self.new_account_body),
            .fetch_account => requireSignedBody(self.fetch_account_body),
            .new_order => requireSignedBody(self.new_order_body),
            .fetch_order => requireSignedBody(self.fetch_order_body),
            .finalize_order => requireSignedBody(self.finalize_order_body),
        };
    }

    fn requireSignedBody(value: []const u8) Error![]const u8 {
        if (value.len == 0) return error.MissingSignedBody;
        return value;
    }
};

pub const TickResult = struct {
    transitions_executed: u8 = 0,
    did_work: bool = false,
    state: acme_types.CertState = .idle,
};

pub const Executor = struct {
    context: ?*anyopaque,
    execute_fn: *const fn (
        context: ?*anyopaque,
        flow_ctx: *orchestration.FlowContext,
        params: transport.ExecuteOperationParams,
    ) transport.ExecuteOperationError!orchestration.HandledResponse,

    pub fn init(
        context: ?*anyopaque,
        execute_fn: *const fn (
            context: ?*anyopaque,
            flow_ctx: *orchestration.FlowContext,
            params: transport.ExecuteOperationParams,
        ) transport.ExecuteOperationError!orchestration.HandledResponse,
    ) Executor {
        assert(@intFromPtr(execute_fn) != 0);
        return .{
            .context = context,
            .execute_fn = execute_fn,
        };
    }

    pub fn fromClient(client_ptr: *Client) Executor {
        assert(@intFromPtr(client_ptr) != 0);
        return .{
            .context = client_ptr,
            .execute_fn = executeWithClient,
        };
    }

    pub fn execute(
        self: Executor,
        flow_ctx: *orchestration.FlowContext,
        params: transport.ExecuteOperationParams,
    ) transport.ExecuteOperationError!orchestration.HandledResponse {
        assert(@intFromPtr(flow_ctx) != 0);
        return self.execute_fn(self.context, flow_ctx, params);
    }

    fn executeWithClient(
        context: ?*anyopaque,
        flow_ctx: *orchestration.FlowContext,
        params: transport.ExecuteOperationParams,
    ) transport.ExecuteOperationError!orchestration.HandledResponse {
        assert(context != null);

        const client_ptr: *Client = @ptrCast(@alignCast(context.?));
        return transport.executeOperation(flow_ctx, client_ptr, params);
    }
};

const StepOutcome = enum(u8) {
    skipped,
    executed_state_changed,
    executed_state_unchanged,
};

const ExecutionDisposition = enum(u8) {
    refresh_nonce,
    backoff,
    fatal,
};

pub const Manager = struct {
    state: acme_types.CertState = .idle,
    flow_ctx: orchestration.FlowContext,
    max_transitions_per_tick: u8 = config.ACME_MAX_TRANSITIONS_PER_TICK,
    upstream_idx: config.UpstreamIndex = 0,
    consecutive_failures: u16 = 0,
    last_response_assessment: ?orchestration.ResponseAssessment = null,
    last_error_assessment: ?orchestration.ErrorAssessment = null,

    pub fn init(directory: *const client.Directory, upstream_idx: config.UpstreamIndex) Manager {
        assert(@intFromPtr(directory) != 0);

        return .{
            .state = .idle,
            .flow_ctx = orchestration.FlowContext.init(directory),
            .upstream_idx = upstream_idx,
        };
    }

    pub fn startRenewal(self: *Manager) void {
        assert(@intFromPtr(self) != 0);

        self.state = .fetch_nonce;
        self.consecutive_failures = 0;
        self.last_error_assessment = null;
        self.last_response_assessment = null;
    }

    pub fn runTick(
        self: *Manager,
        client_ptr: *Client,
        signed_bodies: *const SignedBodies,
        io: Io,
        header_buf: []u8,
        body_buf: []u8,
    ) Error!TickResult {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(client_ptr) != 0);
        assert(@intFromPtr(signed_bodies) != 0);

        const executor = Executor.fromClient(client_ptr);
        return try self.runTickWithExecutor(executor, signed_bodies, io, header_buf, body_buf);
    }

    pub fn runTickWithExecutor(
        self: *Manager,
        executor: Executor,
        signed_bodies: *const SignedBodies,
        io: Io,
        header_buf: []u8,
        body_buf: []u8,
    ) Error!TickResult {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(signed_bodies) != 0);

        if (self.max_transitions_per_tick == 0) return error.InvalidTransitionLimit;
        if (header_buf.len == 0) return error.InvalidHeaderBuffer;
        if (body_buf.len == 0) return error.InvalidBodyBuffer;

        var result = TickResult{ .state = self.state };
        var transition_count: u8 = 0;

        while (transition_count < self.max_transitions_per_tick) : (transition_count += 1) {
            const outcome = try self.runStep(executor, signed_bodies, io, header_buf, body_buf);
            switch (outcome) {
                .skipped => break,
                .executed_state_changed => {
                    result.transitions_executed += 1;
                    result.did_work = true;
                },
                .executed_state_unchanged => {
                    result.transitions_executed += 1;
                    result.did_work = true;
                    break;
                },
            }

            if (isTerminal(self.state)) break;
        }

        result.state = self.state;
        return result;
    }

    fn runStep(
        self: *Manager,
        executor: Executor,
        signed_bodies: *const SignedBodies,
        io: Io,
        header_buf: []u8,
        body_buf: []u8,
    ) Error!StepOutcome {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(signed_bodies) != 0);

        const operation = self.operationForState() orelse return .skipped;
        const signed_body = try signed_bodies.bodyForOperation(operation);

        const state_before = self.state;
        const handled = executor.execute(&self.flow_ctx, .{
            .operation = operation,
            .signed_body = signed_body,
            .io = io,
            .header_buf = header_buf,
            .body_buf = body_buf,
            .upstream_idx = self.upstream_idx,
        }) catch |err| {
            self.handleExecutionError(err);
            // Stop the current tick after transport/protocol execution failures.
            return .executed_state_unchanged;
        };

        self.applyHandledResult(operation, &handled);
        if (handled.assessment.outcome != .success) {
            // Stop the current tick after non-success ACME outcomes.
            return .executed_state_unchanged;
        }

        return if (self.state != state_before) .executed_state_changed else .executed_state_unchanged;
    }

    fn operationForState(self: *const Manager) ?orchestration.Operation {
        assert(@intFromPtr(self) != 0);

        return switch (self.state) {
            .fetch_nonce => .fetch_nonce,
            .ensure_account => if (self.flow_ctx.has_account_url) .fetch_account else .new_account,
            .create_order => .new_order,
            .finalize_order => .finalize_order,
            .poll_order_ready => .fetch_order,
            else => null,
        };
    }

    fn applyHandledResult(
        self: *Manager,
        operation: orchestration.Operation,
        handled: *const orchestration.HandledResponse,
    ) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(handled) != 0);

        self.last_response_assessment = handled.assessment;
        self.last_error_assessment = null;

        switch (handled.assessment.outcome) {
            .success => {
                self.consecutive_failures = 0;
                self.applySuccess(operation, handled);
            },
            .retry_with_new_nonce => {
                self.consecutive_failures = incrementErrorCount(self.consecutive_failures);
                self.applyFailureState(.refresh_nonce);
            },
            .retry_with_backoff => {
                self.consecutive_failures = incrementErrorCount(self.consecutive_failures);
                self.applyFailureState(.backoff);
            },
            .fatal => {
                self.consecutive_failures = incrementErrorCount(self.consecutive_failures);
                self.applyFailureState(.fatal);
            },
        }
    }

    fn applySuccess(
        self: *Manager,
        operation: orchestration.Operation,
        handled: *const orchestration.HandledResponse,
    ) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(handled) != 0);

        switch (operation) {
            .fetch_nonce => {
                self.state = .ensure_account;
            },
            .new_account, .fetch_account => {
                const account = switch (handled.parsed) {
                    .account => |account| account,
                    else => {
                        self.state = .fatal;
                        return;
                    },
                };

                switch (account.status) {
                    .valid => self.state = .create_order,
                    .deactivated, .revoked => self.state = .fatal,
                }
            },
            .new_order => {
                const order = switch (handled.parsed) {
                    .order => |order| order,
                    else => {
                        self.state = .fatal;
                        return;
                    },
                };

                switch (order.status) {
                    .ready => self.state = .finalize_order,
                    .pending, .processing => self.state = .poll_order_ready,
                    .valid => {
                        if (order.has_certificate_url) {
                            self.state = .download_certificate;
                        } else {
                            self.state = .poll_order_ready;
                        }
                    },
                    .invalid => self.state = .backoff_wait,
                }
            },
            .finalize_order => {
                const order = switch (handled.parsed) {
                    .order => |order| order,
                    else => {
                        self.state = .fatal;
                        return;
                    },
                };

                switch (order.status) {
                    .valid => {
                        if (order.has_certificate_url) {
                            self.state = .download_certificate;
                        } else {
                            self.state = .poll_order_ready;
                        }
                    },
                    .invalid => self.state = .backoff_wait,
                    .pending, .ready, .processing => self.state = .poll_order_ready,
                }
            },
            .fetch_order => {
                const order = switch (handled.parsed) {
                    .order => |order| order,
                    else => {
                        self.state = .fatal;
                        return;
                    },
                };

                switch (order.status) {
                    .ready => self.state = .finalize_order,
                    .pending, .processing => self.state = .poll_order_ready,
                    .valid => {
                        if (order.has_certificate_url) {
                            self.state = .download_certificate;
                        } else {
                            self.state = .poll_order_ready;
                        }
                    },
                    .invalid => self.state = .backoff_wait,
                }
            },
        }
    }

    fn handleExecutionError(self: *Manager, err: transport.ExecuteOperationError) void {
        assert(@intFromPtr(self) != 0);

        const disposition = classifyExecutionError(err);
        self.consecutive_failures = incrementErrorCount(self.consecutive_failures);

        self.last_response_assessment = null;
        self.last_error_assessment = classifyExecutionErrorAssessment(err);

        self.applyFailureState(disposition);
    }

    fn applyFailureState(self: *Manager, disposition: ExecutionDisposition) void {
        assert(@intFromPtr(self) != 0);

        switch (disposition) {
            .refresh_nonce => self.state = .fetch_nonce,
            .backoff => self.state = .backoff_wait,
            .fatal => self.state = .fatal,
        }
    }
};

fn incrementErrorCount(value: u16) u16 {
    const next = std.math.add(u16, value, 1) catch max_error_count;
    assert(next >= value);
    return next;
}

fn isTerminal(state: acme_types.CertState) bool {
    return switch (state) {
        .fatal,
        .download_certificate,
        .persist_and_activate,
        .cleanup_challenges,
        .backoff_wait,
        => true,
        else => false,
    };
}

fn classifyExecutionError(err: transport.ExecuteOperationError) ExecutionDisposition {
    return switch (err) {
        error.MissingReplayNonceHeader,
        error.NonceUnavailable,
        error.InvalidNonce,
        => .refresh_nonce,

        error.DnsResolutionFailed,
        error.TcpConnectFailed,
        error.TcpConnectTimeout,
        error.TlsHandshakeFailed,
        error.SendFailed,
        error.SendTimeout,
        error.RecvFailed,
        error.RecvTimeout,
        error.ConnectionClosed,
        error.BodyReadFailed,
        error.BodyReadTimeout,
        error.BodyConnectionClosed,
        error.BodyIterationLimitExceeded,
        => .backoff,

        else => .fatal,
    };
}

fn classifyExecutionErrorAssessment(err: transport.ExecuteOperationError) orchestration.ErrorAssessment {
    return switch (err) {
        error.MissingReplayNonceHeader,
        error.NonceUnavailable,
        error.InvalidNonce,
        => .{ .class = .retry_with_new_nonce, .reason = .missing_replay_nonce },

        error.DnsResolutionFailed,
        error.TcpConnectFailed,
        error.TcpConnectTimeout,
        error.TlsHandshakeFailed,
        error.SendFailed,
        error.SendTimeout,
        error.RecvFailed,
        error.RecvTimeout,
        error.ConnectionClosed,
        error.BodyReadFailed,
        error.BodyReadTimeout,
        error.BodyConnectionClosed,
        error.BodyIterationLimitExceeded,
        => .{ .class = .retry_with_backoff, .reason = .other },

        error.MissingLocationHeader => .{ .class = .protocol, .reason = .missing_location },
        error.SignedBodyRequired => .{ .class = .input, .reason = .signed_body_required },

        error.AccountUrlUnavailable,
        error.OrderUrlUnavailable,
        error.FinalizeUrlUnavailable,
        => .{ .class = .input, .reason = .unavailable_endpoint },

        else => .{ .class = .protocol, .reason = .other },
    };
}

fn make_url(value: []const u8) client.Url {
    var url = client.Url{};
    url.set(value) catch unreachable;
    return url;
}

fn make_order(status: client.OrderStatus, has_certificate_url: bool) client.OrderResponse {
    var order = client.OrderResponse{
        .status = status,
        .finalize_url = make_url("https://acme.example/order/1/finalize"),
    };

    if (has_certificate_url) {
        order.has_certificate_url = true;
        order.certificate_url = make_url("https://acme.example/cert/1");
    }

    return order;
}

const ScriptStep = struct {
    operation: orchestration.Operation,
    result: union(enum) {
        handled: orchestration.HandledResponse,
        err: transport.ExecuteOperationError,
    },
};

const ScriptExecutor = struct {
    steps: []const ScriptStep,
    cursor: u8 = 0,

    fn asExecutor(self: *ScriptExecutor) Executor {
        return Executor.init(self, run);
    }

    fn run(
        context: ?*anyopaque,
        flow_ctx: *orchestration.FlowContext,
        params: transport.ExecuteOperationParams,
    ) transport.ExecuteOperationError!orchestration.HandledResponse {
        _ = flow_ctx;
        assert(context != null);

        const self: *ScriptExecutor = @ptrCast(@alignCast(context.?));
        assert(self.cursor < self.steps.len);

        const index: usize = self.cursor;
        const step = self.steps[index];
        self.cursor += 1;

        if (params.operation != step.operation) return error.InvalidResponseBody;

        return switch (step.result) {
            .handled => |handled| handled,
            .err => |err| err,
        };
    }
};

test "Manager runTick transitions nonce->account->order->finalize->download" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    var manager = Manager.init(&directory, 0);
    manager.startRenewal();

    const order_url = make_url("https://acme.example/order/1");
    manager.flow_ctx.setOrderUrl(&order_url);

    const finalize_url = make_url("https://acme.example/order/1/finalize");
    manager.flow_ctx.setFinalizeUrl(&finalize_url);

    const steps = [_]ScriptStep{
        .{
            .operation = .fetch_nonce,
            .result = .{ .handled = .{
                .assessment = .{ .outcome = .success, .reason = .none, .http_status = 204 },
                .parsed = .none,
            } },
        },
        .{
            .operation = .new_account,
            .result = .{ .handled = .{
                .assessment = .{ .outcome = .success, .reason = .none, .http_status = 201 },
                .parsed = .{ .account = .{ .status = .valid } },
            } },
        },
        .{
            .operation = .new_order,
            .result = .{ .handled = .{
                .assessment = .{ .outcome = .success, .reason = .none, .http_status = 201 },
                .parsed = .{ .order = make_order(.ready, false) },
            } },
        },
        .{
            .operation = .finalize_order,
            .result = .{ .handled = .{
                .assessment = .{ .outcome = .success, .reason = .none, .http_status = 200 },
                .parsed = .{ .order = make_order(.processing, false) },
            } },
        },
        .{
            .operation = .fetch_order,
            .result = .{ .handled = .{
                .assessment = .{ .outcome = .success, .reason = .none, .http_status = 200 },
                .parsed = .{ .order = make_order(.valid, true) },
            } },
        },
    };

    var script_executor = ScriptExecutor{ .steps = &steps };
    const signed_bodies = SignedBodies{
        .new_account_body = "{\"account\":1}",
        .new_order_body = "{\"order\":1}",
        .fetch_order_body = "{}",
        .finalize_order_body = "{\"csr\":\"x\"}",
    };

    var header_buf: [1024]u8 = undefined;
    var body_buf: [2048]u8 = undefined;
    const result = try manager.runTickWithExecutor(
        script_executor.asExecutor(),
        &signed_bodies,
        undefined,
        &header_buf,
        &body_buf,
    );

    try std.testing.expect(result.did_work);
    try std.testing.expectEqual(@as(u8, 5), result.transitions_executed);
    try std.testing.expectEqual(acme_types.CertState.download_certificate, result.state);
    try std.testing.expectEqual(@as(u16, 0), manager.consecutive_failures);
}

test "Manager applies retry_with_new_nonce assessment" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    var manager = Manager.init(&directory, 0);
    manager.state = .create_order;

    const steps = [_]ScriptStep{
        .{
            .operation = .new_order,
            .result = .{ .handled = .{
                .assessment = .{
                    .outcome = .retry_with_new_nonce,
                    .reason = .bad_nonce,
                    .http_status = 400,
                },
                .parsed = .none,
            } },
        },
    };

    var script_executor = ScriptExecutor{ .steps = &steps };
    const signed_bodies = SignedBodies{ .new_order_body = "{}" };
    var header_buf: [256]u8 = undefined;
    var body_buf: [256]u8 = undefined;

    const result = try manager.runTickWithExecutor(
        script_executor.asExecutor(),
        &signed_bodies,
        undefined,
        &header_buf,
        &body_buf,
    );

    try std.testing.expect(result.did_work);
    try std.testing.expectEqual(acme_types.CertState.fetch_nonce, result.state);
    try std.testing.expectEqual(@as(u16, 1), manager.consecutive_failures);
}

test "Manager maps transport DNS failure to backoff_wait" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    var manager = Manager.init(&directory, 0);
    manager.state = .create_order;

    const steps = [_]ScriptStep{
        .{
            .operation = .new_order,
            .result = .{ .err = error.DnsResolutionFailed },
        },
    };

    var script_executor = ScriptExecutor{ .steps = &steps };
    const signed_bodies = SignedBodies{ .new_order_body = "{}" };

    var header_buf: [256]u8 = undefined;
    var body_buf: [256]u8 = undefined;
    const result = try manager.runTickWithExecutor(
        script_executor.asExecutor(),
        &signed_bodies,
        undefined,
        &header_buf,
        &body_buf,
    );

    try std.testing.expect(result.did_work);
    try std.testing.expectEqual(acme_types.CertState.backoff_wait, result.state);
    try std.testing.expect(manager.last_error_assessment != null);
    try std.testing.expectEqual(orchestration.ErrorClass.retry_with_backoff, manager.last_error_assessment.?.class);
}

test "Manager returns MissingSignedBody for required operation" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    var manager = Manager.init(&directory, 0);
    manager.state = .create_order;

    const steps = [_]ScriptStep{};
    var script_executor = ScriptExecutor{ .steps = &steps };
    const signed_bodies = SignedBodies{};

    var header_buf: [256]u8 = undefined;
    var body_buf: [256]u8 = undefined;

    try std.testing.expectError(
        error.MissingSignedBody,
        manager.runTickWithExecutor(
            script_executor.asExecutor(),
            &signed_bodies,
            undefined,
            &header_buf,
            &body_buf,
        ),
    );
}

test "Manager idle state does not execute steps" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    var manager = Manager.init(&directory, 0);

    const steps = [_]ScriptStep{};
    var script_executor = ScriptExecutor{ .steps = &steps };

    const signed_bodies = SignedBodies{};
    var header_buf: [256]u8 = undefined;
    var body_buf: [256]u8 = undefined;
    const result = try manager.runTickWithExecutor(
        script_executor.asExecutor(),
        &signed_bodies,
        undefined,
        &header_buf,
        &body_buf,
    );

    try std.testing.expect(!result.did_work);
    try std.testing.expectEqual(@as(u8, 0), result.transitions_executed);
    try std.testing.expectEqual(acme_types.CertState.idle, result.state);
}
