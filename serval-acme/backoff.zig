//! Bounded exponential backoff utilities for ACME retry scheduling.
//!
//! TigerStyle: explicit bounds, deterministic jitter, no allocation.

const std = @import("std");
const assert = std.debug.assert;

const core = @import("serval-core");
const config = core.config;
const time = core.time;

/// Errors returned when a backoff range is invalid.
/// `InvalidRange` indicates that `min_ms` was zero or greater than `max_ms`.
/// This error set is used by the public constructor and has no other variants.
pub const Error = error{
    InvalidRange,
};

/// Bounded exponential backoff configuration expressed in milliseconds.
/// Use `init` to validate the range before constructing a value.
/// `delayMs` computes the delay for a failure count, and `nextRetryDeadlineNs`
/// converts that delay into an absolute retry deadline.
/// The type owns no resources and carries no lifetime-managed state.
pub const BoundedBackoff = struct {
    min_ms: u32,
    max_ms: u32,

    /// Construct a bounded backoff policy with the given minimum and maximum delays.
    /// Returns `error.InvalidRange` when `min_ms` is zero or when `min_ms > max_ms`.
    /// The resulting value is a plain configuration object and does not allocate.
    /// Callers are responsible for choosing bounds that fit their retry policy.
    pub fn init(min_ms: u32, max_ms: u32) Error!BoundedBackoff {
        assert(config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS > 0);
        assert(config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS <= config.ACME_DEFAULT_FAIL_BACKOFF_MAX_MS);
        if (min_ms == 0) return error.InvalidRange;
        if (min_ms > max_ms) return error.InvalidRange;

        return .{
            .min_ms = min_ms,
            .max_ms = max_ms,
        };
    }

    /// Compute bounded delay in milliseconds for `consecutive_failures`.
    ///
    /// Rules:
    /// - 0 failures => 0ms
    /// - 1 failure  => min_ms (+ deterministic jitter)
    /// - n failures => min_ms * 2^(n-1), capped to max_ms (+ deterministic jitter, re-capped)
    pub fn delayMs(self: *const BoundedBackoff, consecutive_failures: u16, jitter_seed: u64) u32 {
        assert(@intFromPtr(self) != 0);
        assert(self.min_ms > 0);
        assert(self.min_ms <= self.max_ms);

        if (consecutive_failures == 0) return 0;

        const shift: u6 = @intCast(@min(consecutive_failures - 1, @as(u16, 31)));
        const scaled: u64 = (@as(u64, self.min_ms) << shift);
        const capped: u64 = @min(scaled, @as(u64, self.max_ms));
        const jittered: u64 = addDeterministicJitter(capped, jitter_seed);
        const final_capped: u64 = @min(jittered, @as(u64, self.max_ms));

        return @intCast(final_capped);
    }

    /// Compute the next retry deadline in nanoseconds from `now_ns`.
    /// Returns `now_ns` when the backoff delay is zero; otherwise adds the bounded delay
    /// returned by `delayMs` after converting milliseconds to nanoseconds.
    /// `self` must point to a valid `BoundedBackoff`, and `now_ns` must be nonzero.
    /// This function does not allocate and cannot fail.
    pub fn nextRetryDeadlineNs(
        self: *const BoundedBackoff,
        now_ns: u64,
        consecutive_failures: u16,
        jitter_seed: u64,
    ) u64 {
        assert(@intFromPtr(self) != 0);
        assert(now_ns > 0);

        const delay_ms: u32 = self.delayMs(consecutive_failures, jitter_seed);
        if (delay_ms == 0) return now_ns;

        const delay_ns: u64 = time.millisToNanos(delay_ms);
        const deadline_ns: u64 = now_ns +| delay_ns;
        assert(deadline_ns >= now_ns);
        return deadline_ns;
    }
};

fn addDeterministicJitter(base_ms: u64, seed: u64) u64 {
    assert(base_ms > 0);
    assert(seed <= std.math.maxInt(u64));

    // Bounded 0..12.5% jitter to avoid synchronization while preserving cap.
    const max_jitter_ms: u64 = @max(1, base_ms >> 3);
    const mixed: u64 = mix64(seed ^ base_ms);
    const jitter_ms: u64 = mixed % (max_jitter_ms + 1);
    return base_ms +| jitter_ms;
}

fn mix64(value: u64) u64 {
    assert(@sizeOf(u64) == 8);
    assert(value <= std.math.maxInt(u64));
    var x = value;
    x ^= x >> 33;
    x *%= 0xff51afd7ed558ccd;
    x ^= x >> 33;
    x *%= 0xc4ceb9fe1a85ec53;
    x ^= x >> 33;
    return x;
}

test "BoundedBackoff validates range" {
    try std.testing.expectError(error.InvalidRange, BoundedBackoff.init(0, 1000));
    try std.testing.expectError(error.InvalidRange, BoundedBackoff.init(2000, 1000));
}

test "BoundedBackoff delay is zero for no failures" {
    const backoff = try BoundedBackoff.init(1000, 30_000);
    try std.testing.expectEqual(@as(u32, 0), backoff.delayMs(0, 42));
}

test "BoundedBackoff delay grows and caps" {
    const backoff = try BoundedBackoff.init(1000, 30_000);

    const first = backoff.delayMs(1, 1);
    const second = backoff.delayMs(2, 2);
    const third = backoff.delayMs(3, 3);
    const tenth = backoff.delayMs(10, 10);

    try std.testing.expect(first >= 1000 and first <= 30_000);
    try std.testing.expect(second >= 2000 and second <= 30_000);
    try std.testing.expect(third >= 4000 and third <= 30_000);
    try std.testing.expect(tenth <= 30_000);
}

test "BoundedBackoff nextRetryDeadlineNs is monotonic" {
    const backoff = try BoundedBackoff.init(
        config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS,
        config.ACME_DEFAULT_FAIL_BACKOFF_MAX_MS,
    );
    const now_ns: u64 = time.monotonicNanos();
    const deadline_ns = backoff.nextRetryDeadlineNs(now_ns, 3, 7);

    try std.testing.expect(deadline_ns >= now_ns);
}
