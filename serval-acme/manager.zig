//! ACME manager transition runner (PR4 scaffolding).
//!
//! Executes bounded nonce/account/order/finalize state transitions using the
//! ACME orchestration and transport adapters.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const core = @import("serval-core");
const config = core.config;
const time = core.time;

const acme_types = @import("types.zig");
const backoff = @import("backoff.zig");
const client = @import("client.zig");
const orchestration = @import("orchestration.zig");
const transport = @import("transport.zig");
const signer_mod = @import("signer.zig");
const runtime = @import("runtime.zig");
const storage = @import("storage.zig");

const serval_client = @import("serval-client");
const Client = serval_client.Client;

const serval_tls = @import("serval-tls");
const ReloadableServerCtx = serval_tls.ReloadableServerCtx;

/// Errors returned by ACME manager helpers when local validation fails before a transport call.
/// `InvalidTransitionLimit` means the manager was configured with zero allowed transitions per tick.
/// `InvalidHeaderBuffer` and `InvalidBodyBuffer` mean the caller passed an empty scratch buffer.
/// `MissingSignedBody` means a required signed request body was not configured.
pub const Error = error{
    InvalidTransitionLimit,
    InvalidHeaderBuffer,
    InvalidBodyBuffer,
    MissingSignedBody,
};

const max_error_count: u16 = std.math.maxInt(u16);

/// Collection of prebuilt signed request bodies used by ACME operations.
/// Each field stores the payload for one operation and defaults to an empty slice when no body is configured.
/// `bodyForOperation` returns the matching body or `error.MissingSignedBody` when the operation requires a non-empty payload that is absent.
/// The struct does not copy body bytes; callers remain responsible for the lifetime of the referenced buffers.
pub const SignedBodies = struct {
    new_account_body: []const u8 = &.{},
    fetch_account_body: []const u8 = &.{},
    new_order_body: []const u8 = &.{},
    fetch_order_body: []const u8 = &.{},
    finalize_order_body: []const u8 = &.{},

    /// Returns the signed JWS body required for a given ACME operation.
    /// Operations that do not need a body, such as `fetch_nonce`, return an empty slice.
    /// Operations that require a signed body return `error.MissingSignedBody` if the configured body is empty.
    /// `self` must remain valid while the returned slice is in use; the slice aliases storage owned by `self`.
    pub fn bodyForOperation(self: *const SignedBodies, operation: orchestration.Operation) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.new_account_body.len <= config.ACME_MAX_JWS_BODY_BYTES);

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
        assert(config.ACME_MAX_JWS_BODY_BYTES > 0);
        assert(value.len <= config.ACME_MAX_JWS_BODY_BYTES);
        if (value.len == 0) return error.MissingSignedBody;
        return value;
    }
};

/// Summary of work performed during a manager tick.
/// `transitions_executed` counts successful state transitions, `did_work` records whether any transition ran, and `state` captures the manager state after the tick.
/// The struct is returned by tick helpers so callers can observe progress without reading manager internals.
/// All fields default to the idle/no-work state.
pub const TickResult = struct {
    transitions_executed: u8 = 0,
    did_work: bool = false,
    state: acme_types.CertState = .idle,
};

/// Opaque executor wrapper used to dispatch transport operations through a stored callback.
/// The wrapper carries an optional context pointer plus the function to invoke for each operation.
/// `init` constructs a generic executor, `fromClient` binds one to a concrete `Client`, and `execute` performs the dispatch.
/// The executor does not manage the lifetime of the context it points at.
pub const Executor = struct {
    context: ?*anyopaque,
    execute_fn: *const fn (
        context: ?*anyopaque,
        flow_ctx: *orchestration.FlowContext,
        params: transport.ExecuteOperationParams,
    ) transport.ExecuteOperationError!orchestration.HandledResponse,

    /// Creates an executor from an arbitrary opaque context and operation callback.
    /// The callback must accept the same context pointer that is supplied here and must be safe to call for every execution.
    /// `execute_fn` must be non-null and compatible with the `transport.ExecuteOperationError!orchestration.HandledResponse` contract.
    /// The executor does not own `context`; lifetime management remains the caller's responsibility.
    pub fn init(
        context: ?*anyopaque,
        execute_fn: *const fn (
            context: ?*anyopaque,
            flow_ctx: *orchestration.FlowContext,
            params: transport.ExecuteOperationParams,
        ) transport.ExecuteOperationError!orchestration.HandledResponse,
    ) Executor {
        assert(@intFromPtr(execute_fn) != 0);
        assert(@sizeOf(Executor) > 0);
        return .{
            .context = context,
            .execute_fn = execute_fn,
        };
    }

    /// Builds an executor that dispatches transport operations through the ACME client helper.
    /// The returned executor stores `client_ptr` as opaque context and uses `executeWithClient` as its callback.
    /// `client_ptr` must remain valid for as long as the executor may be used.
    /// This is a convenience constructor for code that already has a concrete `Client` pointer.
    pub fn fromClient(client_ptr: *Client) Executor {
        assert(@intFromPtr(client_ptr) != 0);
        assert(@intFromPtr(executeWithClient) != 0);
        return .{
            .context = client_ptr,
            .execute_fn = executeWithClient,
        };
    }

    /// Executes a single transport operation through the stored callback.
    /// `flow_ctx` must be non-null and valid, and `self.execute_fn` must point to a compatible implementation.
    /// Forwards `self.context` unchanged to the callback and returns whatever response or transport error it produces.
    /// This wrapper does not take ownership of the context pointer or the flow context.
    pub fn execute(
        self: Executor,
        flow_ctx: *orchestration.FlowContext,
        params: transport.ExecuteOperationParams,
    ) transport.ExecuteOperationError!orchestration.HandledResponse {
        assert(@intFromPtr(flow_ctx) != 0);
        assert(@intFromPtr(self.execute_fn) != 0);
        return self.execute_fn(self.context, flow_ctx, params);
    }

    fn executeWithClient(
        context: ?*anyopaque,
        flow_ctx: *orchestration.FlowContext,
        params: transport.ExecuteOperationParams,
    ) transport.ExecuteOperationError!orchestration.HandledResponse {
        assert(context != null);
        assert(@intFromPtr(flow_ctx) != 0);

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

/// ACME issuance and renewal state machine plus retry bookkeeping.
/// The manager tracks the current certificate state, orchestration flow context, transition cap, upstream selection, and backoff state.
/// `init` creates a new idle manager; `startRenewal` resets the machine to begin at `fetch_nonce`; `runAutomatedIssuanceOnce` performs one full issuance attempt.
/// Callers must preserve any referenced context objects used by the embedded flow context and runtime helpers.
pub const Manager = struct {
    state: acme_types.CertState = .idle,
    flow_ctx: orchestration.FlowContext,
    max_transitions_per_tick: u8 = config.ACME_MAX_TRANSITIONS_PER_TICK,
    upstream_idx: config.UpstreamIndex = 0,
    retry_backoff: backoff.BoundedBackoff,
    backoff_wait_until_ns: u64 = 0,
    consecutive_failures: u16 = 0,
    last_response_assessment: ?orchestration.ResponseAssessment = null,
    last_error_assessment: ?orchestration.ErrorAssessment = null,

    /// Constructs a manager with the default retry backoff configuration and an idle state.
    /// The returned manager owns its `FlowContext` value but borrows `directory` only for initialization.
    /// `directory` must be non-null, and the configured backoff bounds must be valid (`min_ms > 0` and `min_ms <= max_ms`).
    /// `upstream_idx` is stored unchanged and used to select the upstream route later.
    pub fn init(directory: *const client.Directory, upstream_idx: config.UpstreamIndex) Manager {
        assert(@intFromPtr(directory) != 0);
        assert(config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS > 0);
        assert(config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS <= config.ACME_DEFAULT_FAIL_BACKOFF_MAX_MS);

        const retry_backoff = backoff.BoundedBackoff{
            .min_ms = config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS,
            .max_ms = config.ACME_DEFAULT_FAIL_BACKOFF_MAX_MS,
        };

        return .{
            .state = .idle,
            .flow_ctx = orchestration.FlowContext.init(directory),
            .upstream_idx = upstream_idx,
            .retry_backoff = retry_backoff,
        };
    }

    /// Starts a renewal cycle from the beginning of the ACME flow.
    /// Resets backoff timing and failure counters, then moves the manager state to `fetch_nonce`.
    /// `max_transitions_per_tick` must be greater than zero before calling this function.
    /// Clears any cached response or error assessment so the next tick starts from a clean slate.
    pub fn startRenewal(self: *Manager) void {
        assert(@intFromPtr(self) != 0);
        assert(self.max_transitions_per_tick > 0);

        self.state = .fetch_nonce;
        self.backoff_wait_until_ns = 0;
        self.consecutive_failures = 0;
        self.last_error_assessment = null;
        self.last_response_assessment = null;
    }

    /// Runs one automated ACME issuance attempt and updates manager bookkeeping around the call.
    /// Sets the manager state to `fetch_nonce` before invoking the runtime helper, then restores `idle` and clears failure tracking on success.
    /// `runtime_config`, `signer`, and `client_ptr` must remain valid for the duration of the call; `work` is passed through to the runtime helper.
    /// Propagates errors from either this manager's `Error` set or `runtime.runIssuanceOnce`'s `runtime.Error` set.
    pub fn runAutomatedIssuanceOnce(
        self: *Manager,
        runtime_config: *const acme_types.RuntimeConfig,
        signer: *const signer_mod.AccountSigner,
        client_ptr: *Client,
        io: Io,
        work: runtime.WorkBuffers,
        tls_manager: ?*ReloadableServerCtx,
        tls_alpn_hook_provider: ?*@import("tls_alpn_hook.zig").TlsAlpnHookProvider,
    ) (Error || runtime.Error)!storage.PersistedPaths {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(runtime_config) != 0);
        assert(@intFromPtr(signer) != 0);
        assert(@intFromPtr(client_ptr) != 0);

        self.state = .fetch_nonce;
        const persisted = try runtime.runIssuanceOnce(
            runtime_config,
            client_ptr,
            signer,
            io,
            work,
            tls_manager,
            tls_alpn_hook_provider,
        );
        self.state = .idle;
        self.consecutive_failures = 0;
        self.last_error_assessment = null;
        return persisted;
    }

    /// Convenience wrapper around `runTickWithExecutor` for a concrete `Client` implementation.
    /// Builds an `Executor` from `client_ptr` and forwards the same buffers, I/O handle, and signed bodies to the tick runner.
    /// `client_ptr` and `signed_bodies` must be non-null and valid for the duration of the call.
    /// Propagates any error returned by the underlying tick execution.
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

    /// Runs ACME manager steps through an injected executor until no more work is available.
    /// Stops early when the manager reaches a terminal state, when a step is skipped, or when the transition limit is hit.
    /// `header_buf` and `body_buf` must be non-empty scratch buffers; otherwise this returns `error.InvalidHeaderBuffer` or `error.InvalidBodyBuffer`.
    /// Propagates step execution errors from `runStep` and reports the final manager state in the returned `TickResult`.
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

        if (self.state == .backoff_wait) {
            const now_ns = time.monotonicNanos();
            if (self.backoff_wait_until_ns == 0 or now_ns >= self.backoff_wait_until_ns) {
                self.state = .fetch_nonce;
                self.backoff_wait_until_ns = 0;
                return .executed_state_changed;
            }
            return .skipped;
        }

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
        assert(self.max_transitions_per_tick > 0);

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
            .fetch_nonce => self.state = .ensure_account,
            .new_account, .fetch_account => self.applyAccountSuccess(handled),
            .new_order, .finalize_order, .fetch_order => self.applyOrderSuccess(handled),
        }
    }

    fn applyAccountSuccess(self: *Manager, handled: *const orchestration.HandledResponse) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(handled) != 0);

        const account = switch (handled.parsed) {
            .account => |account| account,
            else => {
                self.state = .fatal;
                return;
            },
        };
        self.state = switch (account.status) {
            .valid => .create_order,
            .deactivated, .revoked => .fatal,
        };
    }

    fn applyOrderSuccess(self: *Manager, handled: *const orchestration.HandledResponse) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(handled) != 0);

        const order = switch (handled.parsed) {
            .order => |order| order,
            else => {
                self.state = .fatal;
                return;
            },
        };
        self.state = nextStateFromOrder(&order);
    }

    fn handleExecutionError(self: *Manager, err: transport.ExecuteOperationError) void {
        assert(@intFromPtr(self) != 0);
        assert(self.consecutive_failures <= max_error_count);

        const disposition = classifyExecutionError(err);
        self.consecutive_failures = incrementErrorCount(self.consecutive_failures);

        self.last_response_assessment = null;
        self.last_error_assessment = classifyExecutionErrorAssessment(err);

        self.applyFailureState(disposition);
    }

    fn applyFailureState(self: *Manager, disposition: ExecutionDisposition) void {
        assert(@intFromPtr(self) != 0);
        assert(self.retry_backoff.min_ms <= self.retry_backoff.max_ms);

        switch (disposition) {
            .refresh_nonce => {
                self.backoff_wait_until_ns = 0;
                self.state = .fetch_nonce;
            },
            .backoff => {
                const now_ns = time.monotonicNanos();
                const seed = (@as(u64, self.consecutive_failures) << 32) ^ now_ns;
                self.backoff_wait_until_ns = self.retry_backoff.nextRetryDeadlineNs(
                    now_ns,
                    self.consecutive_failures,
                    seed,
                );
                self.state = .backoff_wait;
            },
            .fatal => {
                self.backoff_wait_until_ns = 0;
                self.state = .fatal;
            },
        }
    }
};

fn nextStateFromOrder(order: *const client.OrderResponse) acme_types.CertState {
    assert(@intFromPtr(order) != 0);
    assert(order.authorization_count <= config.ACME_MAX_AUTHORIZATION_URLS_PER_ORDER);

    return switch (order.status) {
        .ready => .finalize_order,
        .pending, .processing => .poll_order_ready,
        .valid => if (order.has_certificate_url) .download_certificate else .poll_order_ready,
        .invalid => .backoff_wait,
    };
}

fn incrementErrorCount(value: u16) u16 {
    assert(value <= max_error_count);
    const next = std.math.add(u16, value, 1) catch max_error_count;
    assert(next >= value);
    return next;
}

fn isTerminal(state: acme_types.CertState) bool {
    assert(@sizeOf(acme_types.CertState) == 1);
    assert(@intFromEnum(state) <= @intFromEnum(acme_types.CertState.fatal));
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
    assert(@sizeOf(ExecutionDisposition) == 1);
    assert(@sizeOf(@TypeOf(err)) > 0);
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
    assert(@sizeOf(orchestration.ErrorAssessment) > 0);
    assert(@sizeOf(@TypeOf(err)) > 0);
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
    assert(value.len > 0);
    assert(value.len <= config.ACME_MAX_DIRECTORY_URL_BYTES);
    var url = client.Url{};
    url.set(value) catch |err| {
        std.debug.panic("manager test helper invalid url err={s}", .{@errorName(err)});
    };
    return url;
}

fn make_order(status: client.OrderStatus, has_certificate_url: bool) client.OrderResponse {
    assert(@sizeOf(client.OrderStatus) == 1);
    assert(@sizeOf(client.OrderResponse) > 0);
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
        assert(@intFromPtr(self) != 0);
        assert(self.cursor <= self.steps.len);
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

        const index: u8 = self.cursor;
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

test "Manager backoff_wait transitions to fetch_nonce when deadline passes" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    var manager = Manager.init(&directory, 0);
    manager.max_transitions_per_tick = 1;
    manager.state = .backoff_wait;
    manager.backoff_wait_until_ns = 1;

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

    try std.testing.expect(result.did_work);
    try std.testing.expectEqual(@as(u8, 1), result.transitions_executed);
    try std.testing.expectEqual(acme_types.CertState.fetch_nonce, result.state);
}
