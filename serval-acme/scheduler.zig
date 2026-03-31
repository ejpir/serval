//! ACME renewal scheduler.
//!
//! Generic bounded control loop that decides when to attempt issuance and applies
//! exponential backoff on transient failures.
//! TigerStyle: explicit state machine, bounded loop, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const core = @import("serval-core");
const config = core.config;
const time = core.time;
const backoff_mod = @import("backoff.zig");
const limits = @import("limits.zig");

/// Errors returned by scheduler configuration and execution.
/// `InvalidCheckInterval` is raised when the polling interval is zero, `FatalFailure` signals an unrecoverable callback result, and `MaxIterationsExceeded` caps the run loop.
/// These errors describe scheduler-level failures only; I/O cancellation is reported separately through `Io.Cancelable`.
pub const Error = error{
    InvalidCheckInterval,
    FatalFailure,
    MaxIterationsExceeded,
};

/// Outcome of the renewal decision callback.
/// `skip` means nothing should be issued now and the scheduler should wait for the next normal check interval.
/// `renew_now` requests immediate issuance, while `fatal_failure` aborts the scheduler with `error.FatalFailure`.
pub const ShouldRenewResult = enum {
    skip,
    renew_now,
    fatal_failure,
};

/// Outcome of the renewal issuance callback.
/// `success` means the renewal step completed and the scheduler may resume the normal check interval.
/// `transient_failure` keeps retrying with backoff, while `fatal_failure` aborts the scheduler with `error.FatalFailure`.
pub const IssueResult = enum {
    success,
    transient_failure,
    fatal_failure,
};

/// Callback used to decide whether the scheduler should renew at a given monotonic timestamp.
/// The function receives the opaque scheduler context and the current time in nanoseconds.
/// It returns a `ShouldRenewResult` and must not retain the passed context pointer unless the caller's lifetime guarantees permit it.
pub const ShouldRenewFn = *const fn (ctx: *anyopaque, now_ns: u64) ShouldRenewResult;
/// Callback used to issue or trigger the ACME renewal action.
/// The function receives the opaque scheduler context plus the I/O handle to use for side effects.
/// It returns an `IssueResult` and does not transfer ownership of either argument.
pub const IssueFn = *const fn (ctx: *anyopaque, io: Io) IssueResult;

/// Scheduler configuration used to control polling cadence and loop bounds.
/// `check_interval_ms` sets the nominal delay between successful checks, and `max_iterations` limits the run loop.
/// Use `init` to validate the interval before constructing a config for production use.
pub const Config = struct {
    check_interval_ms: u32,
    max_iterations: u32 = 1_000_000_000,

    /// Validate and construct a polling configuration.
    /// `check_interval_ms` must be non-zero or `error.InvalidCheckInterval` is returned.
    /// The function leaves all other policy fields at their default values.
    pub fn init(check_interval_ms: u32) Error!Config {
        assert(limits.max_poll_attempts > 0);
        assert(check_interval_ms <= std.math.maxInt(u32));
        if (check_interval_ms == 0) return error.InvalidCheckInterval;
        return .{ .check_interval_ms = check_interval_ms };
    }
};

/// Result of one scheduler step.
/// `sleep_until_ns` is an absolute monotonic deadline; the caller should sleep until that time when it is in the future.
/// A deadline less than or equal to the current time means the scheduler wants to continue immediately.
pub const StepAction = struct {
    sleep_until_ns: u64,
};

/// Stateful ACME renewal scheduler that tracks callback wiring and retry state.
/// Use `init` to construct a valid instance, then call `step` for single-shot decisions or `run` for the polling loop.
/// The scheduler keeps transient failure count and the next scheduled check timestamp in its own state.
pub const Scheduler = struct {
    config: Config,
    backoff: backoff_mod.BoundedBackoff,
    ctx: *anyopaque,
    should_renew_fn: ShouldRenewFn,
    issue_fn: IssueFn,

    consecutive_failures: u16 = 0,
    next_check_ns: u64 = 0,

    /// Create a scheduler with the supplied configuration, backoff policy, context, and callback functions.
    /// The context pointer must be non-null and the check interval must be greater than zero.
    /// The returned scheduler owns no heap memory; it stores the provided pointers and function references for later calls.
    pub fn init(
        scheduler_config: Config,
        backoff: backoff_mod.BoundedBackoff,
        ctx: *anyopaque,
        should_renew_fn: ShouldRenewFn,
        issue_fn: IssueFn,
    ) Scheduler {
        assert(@intFromPtr(ctx) != 0);
        assert(scheduler_config.check_interval_ms > 0);

        return .{
            .config = scheduler_config,
            .backoff = backoff,
            .ctx = ctx,
            .should_renew_fn = should_renew_fn,
            .issue_fn = issue_fn,
        };
    }

    /// Run the scheduler loop until shutdown, sleep interruption, or the configured iteration limit.
    /// Each iteration reads the current monotonic time, calls `step`, and sleeps until the returned deadline when one is in the future.
    /// Returns `error.MaxIterationsExceeded` if the loop reaches `config.max_iterations`, and otherwise propagates errors from `step` or sleeping.
    pub fn run(
        self: *Scheduler,
        io: Io,
        shutdown: *std.atomic.Value(bool),
    ) (Error || Io.Cancelable)!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(shutdown) != 0);

        var iteration: u32 = 0;
        while (iteration < self.config.max_iterations) : (iteration += 1) {
            if (shutdown.load(.acquire)) return;

            const now_ns: u64 = time.monotonicNanos();
            const action = try self.step(now_ns, io);

            if (shutdown.load(.acquire)) return;
            if (action.sleep_until_ns <= now_ns) continue;

            const sleep_ns: u64 = action.sleep_until_ns - now_ns;
            assert(action.sleep_until_ns >= now_ns);
            if (sleep_ns == 0) continue;

            try std.Io.sleep(io, Io.Duration.fromNanoseconds(sleep_ns), .awake);
        }

        return error.MaxIterationsExceeded;
    }

    /// Advance the scheduler once at the given monotonic timestamp.
    /// If the next check is still in the future, returns that deadline without invoking callbacks.
    /// Otherwise it consults `should_renew_fn`, then `issue_fn` when renewal is required, and propagates `error.FatalFailure` on unrecoverable callback failure.
    pub fn step(self: *Scheduler, now_ns: u64, io: Io) Error!StepAction {
        assert(@intFromPtr(self) != 0);
        assert(now_ns > 0);

        if (self.next_check_ns == 0) {
            self.next_check_ns = now_ns;
        }
        if (now_ns < self.next_check_ns) {
            return .{ .sleep_until_ns = self.next_check_ns };
        }

        switch (self.should_renew_fn(self.ctx, now_ns)) {
            .skip => {
                self.consecutive_failures = 0;
                self.next_check_ns = now_ns +| time.millisToNanos(self.config.check_interval_ms);
                return .{ .sleep_until_ns = self.next_check_ns };
            },
            .fatal_failure => return error.FatalFailure,
            .renew_now => {},
        }

        switch (self.issue_fn(self.ctx, io)) {
            .success => {
                self.consecutive_failures = 0;
                self.next_check_ns = now_ns +| time.millisToNanos(self.config.check_interval_ms);
                return .{ .sleep_until_ns = self.next_check_ns };
            },
            .fatal_failure => return error.FatalFailure,
            .transient_failure => {
                if (self.consecutive_failures < std.math.maxInt(u16)) {
                    self.consecutive_failures += 1;
                }
                const jitter_seed: u64 = now_ns ^ @as(u64, self.consecutive_failures);
                self.next_check_ns = self.backoff.nextRetryDeadlineNs(now_ns, self.consecutive_failures, jitter_seed);
                return .{ .sleep_until_ns = self.next_check_ns };
            },
        }
    }
};

const TestCtx = struct {
    should_result: ShouldRenewResult = .skip,
    issue_result: IssueResult = .success,
    should_calls: u32 = 0,
    issue_calls: u32 = 0,
};

fn testShouldRenew(ctx_raw: *anyopaque, now_ns: u64) ShouldRenewResult {
    assert(@intFromPtr(ctx_raw) != 0);
    assert(now_ns <= std.math.maxInt(u64));
    const ctx: *TestCtx = @ptrCast(@alignCast(ctx_raw));
    ctx.should_calls += 1;
    return ctx.should_result;
}

fn testIssue(ctx_raw: *anyopaque, io: Io) IssueResult {
    assert(@intFromPtr(ctx_raw) != 0);
    assert(@sizeOf(Io) > 0);
    _ = io;
    const ctx: *TestCtx = @ptrCast(@alignCast(ctx_raw));
    ctx.issue_calls += 1;
    return ctx.issue_result;
}

test "scheduler skip path advances next check and does not issue" {
    var ctx = TestCtx{ .should_result = .skip };
    const scheduler_config = try Config.init(10_000);
    const backoff = try backoff_mod.BoundedBackoff.init(
        config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS,
        config.ACME_DEFAULT_FAIL_BACKOFF_MAX_MS,
    );
    var scheduler = Scheduler.init(scheduler_config, backoff, @ptrCast(&ctx), testShouldRenew, testIssue);

    const now_ns: u64 = time.monotonicNanos();
    const action = try scheduler.step(now_ns, std.Options.debug_io);

    try std.testing.expect(ctx.should_calls == 1);
    try std.testing.expect(ctx.issue_calls == 0);
    try std.testing.expect(action.sleep_until_ns > now_ns);
    try std.testing.expect(scheduler.consecutive_failures == 0);
}

test "scheduler transient failure applies backoff" {
    var ctx = TestCtx{
        .should_result = .renew_now,
        .issue_result = .transient_failure,
    };
    const scheduler_config = try Config.init(5_000);
    const backoff = try backoff_mod.BoundedBackoff.init(1000, 10_000);
    var scheduler = Scheduler.init(scheduler_config, backoff, @ptrCast(&ctx), testShouldRenew, testIssue);

    const now_ns: u64 = time.monotonicNanos();
    const action = try scheduler.step(now_ns, std.Options.debug_io);

    try std.testing.expect(ctx.should_calls == 1);
    try std.testing.expect(ctx.issue_calls == 1);
    try std.testing.expect(scheduler.consecutive_failures == 1);
    try std.testing.expect(action.sleep_until_ns >= now_ns);
}

test "scheduler success resets failures and uses check interval" {
    var ctx = TestCtx{
        .should_result = .renew_now,
        .issue_result = .success,
    };
    const scheduler_config = try Config.init(7_000);
    const backoff = try backoff_mod.BoundedBackoff.init(1000, 10_000);
    var scheduler = Scheduler.init(scheduler_config, backoff, @ptrCast(&ctx), testShouldRenew, testIssue);
    scheduler.consecutive_failures = 4;

    const now_ns: u64 = time.monotonicNanos();
    const action = try scheduler.step(now_ns, std.Options.debug_io);

    try std.testing.expect(ctx.issue_calls == 1);
    try std.testing.expect(scheduler.consecutive_failures == 0);
    try std.testing.expect(action.sleep_until_ns > now_ns);
}
