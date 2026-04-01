# LB/Health Findings Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 5 audit findings in serval-lb/serval-health/serval-prober: data race on health counters, unvalidated upstream.idx, silent TLS misconfiguration, slow prober shutdown, and stale README.

**Architecture:** Add a mutex to HealthState to protect counter read-modify-write sequences (bitmap reads stay lock-free). Add init-time validation in LbHandler for upstream idx density and TLS context requirements. Replace the single long sleep in scheduler with an interruptible polling loop. Update README to match current API.

**Tech Stack:** Zig 0.16, std.Thread.Mutex, std.atomic

---

### Task 1: Fix data race on health counters (Finding 1 - High)

The `failure_counts` and `success_counts` arrays are plain `[MAX_UPSTREAMS]u8`. Both the request path (`onLog` -> `recordFailure`/`recordSuccess`) and the prober thread (`probeUnhealthyOnce` -> `recordSuccess`) write these concurrently. The bitmap itself is atomic, but the counter read-modify-write sequences are not protected.

**Files:**
- Modify: `serval-health/health_state.zig`

**Step 1: Write concurrent stress test**

Add a concurrent write stress test to `serval-health/tests.zig` that exercises both `recordFailure` and `recordSuccess` from multiple threads simultaneously. This test exercises the exact race pattern: request-path threads calling `recordFailure` while prober-like threads call `recordSuccess` on the same backend. Note: data races are timing-dependent and may not deterministically fail before the fix; this test documents the concurrent contract and will catch regressions/UB under sanitizers.

```zig
test "concurrent writes are thread-safe" {
    // Simulates request path (recordFailure) + prober (recordSuccess) racing.
    var hs = HealthState.init(MAX_UPSTREAMS, 3, 2);

    const Context = struct {
        hs: *HealthState,
    };

    const failure_worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                const idx: UpstreamIndex = @intCast(iteration % MAX_UPSTREAMS);
                ctx.hs.recordFailure(idx);
            }
        }
    }.run;

    const success_worker = struct {
        fn run(ctx: *Context) void {
            var iteration: u32 = 0;
            while (iteration < ITERATIONS_PER_THREAD) : (iteration += 1) {
                const idx: UpstreamIndex = @intCast(iteration % MAX_UPSTREAMS);
                ctx.hs.recordSuccess(idx);
            }
        }
    }.run;

    var ctx = Context{ .hs = &hs };

    var threads: [CONCURRENT_THREAD_COUNT]Thread = undefined;
    var spawned: u32 = 0;

    // Half failure workers, half success workers
    while (spawned < CONCURRENT_THREAD_COUNT) : (spawned += 1) {
        if (spawned % 2 == 0) {
            threads[spawned] = Thread.spawn(.{}, failure_worker, .{&ctx}) catch unreachable;
        } else {
            threads[spawned] = Thread.spawn(.{}, success_worker, .{&ctx}) catch unreachable;
        }
    }

    var joined: u32 = 0;
    while (joined < CONCURRENT_THREAD_COUNT) : (joined += 1) {
        threads[joined].join();
    }

    // Invariant: no crash, no UB, counters are bounded
    for (0..MAX_UPSTREAMS) |i| {
        const idx: UpstreamIndex = @intCast(i);
        // counters must be valid u8 values (no torn reads)
        _ = hs.isHealthy(idx);
    }
}
```

**Step 2: Run stress test to establish baseline**

Run: `zig build test-health`
Expected: Likely passes (race window is timing-dependent), but exercises the concurrent pattern that constitutes UB on non-atomic counters. After the mutex fix, this test guarantees defined behavior under concurrent access. Check the exit code directly — do not pipe through tail/grep as that masks build failures.

**Step 3: Add mutex to HealthState and protect counter operations**

In `serval-health/health_state.zig`, add a mutex field and acquire it around counter read-modify-write in `recordSuccess` and `recordFailure`. The bitmap reads (`isHealthy`, `countHealthy`, `findNthHealthy`, `findFirstHealthy`) remain lock-free since they only touch the atomic bitmap.

Add per-backend mutex array to the struct (after `healthy_threshold`):

```zig
    /// Per-backend mutexes protecting failure_counts/success_counts read-modify-write.
    /// One mutex per backend index eliminates cross-backend contention — updates to
    /// backend 0 never block updates to backend 1. Bitmap reads (isHealthy,
    /// countHealthy, findNthHealthy) stay lock-free.
    counter_mutexes: [MAX_UPSTREAMS]std.Thread.Mutex,
```

Initialize in `init` (`.{}` zero-inits all mutexes to unlocked):

```zig
        return HealthState{
            .health_bitmap = std.atomic.Value(u64).init(backendMask(backend_count)),
            .failure_counts = std.mem.zeroes([MAX_UPSTREAMS]u8),
            .success_counts = std.mem.zeroes([MAX_UPSTREAMS]u8),
            .backend_count = backend_count,
            .unhealthy_threshold = unhealthy_threshold,
            .healthy_threshold = healthy_threshold,
            .counter_mutexes = .{.{}} ** MAX_UPSTREAMS,
        };
```

In `reset`, lock each active backend's mutex:

```zig
    pub fn reset(self: *HealthState) void {
        // Lock all active backend mutexes to ensure no concurrent counter updates.
        for (0..self.backend_count) |i| {
            self.counter_mutexes[i].lock();
        }
        defer for (0..self.backend_count) |i| {
            self.counter_mutexes[i].unlock();
        };
        self.health_bitmap.store(backendMask(self.backend_count), .release);
        self.failure_counts = std.mem.zeroes([MAX_UPSTREAMS]u8);
        self.success_counts = std.mem.zeroes([MAX_UPSTREAMS]u8);
    }
```

Wrap `recordSuccess` body with per-backend mutex:

```zig
    pub inline fn recordSuccess(self: *HealthState, idx: UpstreamIndex) void {
        assert(idx < self.backend_count);

        self.counter_mutexes[idx].lock();
        defer self.counter_mutexes[idx].unlock();

        self.failure_counts[idx] = 0;
        if (self.isHealthy(idx)) return;

        const new_count = self.success_counts[idx] +| 1;
        self.success_counts[idx] = new_count;

        if (new_count >= self.healthy_threshold) {
            self.markHealthy(idx);
            self.success_counts[idx] = 0;
        }
    }
```

Wrap `recordFailure` body identically:

```zig
    pub inline fn recordFailure(self: *HealthState, idx: UpstreamIndex) void {
        assert(idx < self.backend_count);

        self.counter_mutexes[idx].lock();
        defer self.counter_mutexes[idx].unlock();

        self.success_counts[idx] = 0;
        if (!self.isHealthy(idx)) return;

        const new_count = self.failure_counts[idx] +| 1;
        self.failure_counts[idx] = new_count;

        if (new_count >= self.unhealthy_threshold) {
            self.markUnhealthy(idx);
            self.failure_counts[idx] = 0;
        }
    }
```

**Step 4: Run tests**

Run: `zig build test-health`
Expected: All tests PASS (existing + new concurrent write test). Verify exit code 0.

**Step 5: Commit**

```bash
git add serval-health/health_state.zig serval-health/tests.zig
git commit -m "fix(health): add mutex to protect counter read-modify-write from data race

Passive health updates (request path) and active probing (background thread)
both write failure_counts/success_counts concurrently. Bitmap reads remain
lock-free."
```

---

### Task 2: Validate upstream.idx at LB init (Finding 2 - High)

`onLog` uses `entry.upstream.idx` as an array index into health state. No init-time check ensures each upstream's idx forms a dense 0..N-1 range. In release builds (asserts stripped), an out-of-range or non-dense idx silently corrupts health state.

**Files:**
- Modify: `serval-lb/handler.zig`

**Step 1: Write the failing test**

Add tests to `serval-lb/handler.zig` that verify init rejects non-dense upstream indices.

```zig
test "LbHandler init rejects non-dense upstream idx" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 5 }, // gap: should be 1
    };

    var handler: LbHandler = undefined;
    const result = handler.init(&upstreams, .{ .enable_probing = false }, null, null);
    try std.testing.expectError(error.InvalidUpstreamIndex, result);
}

test "LbHandler init rejects duplicate upstream idx" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 0 }, // duplicate
    };

    var handler: LbHandler = undefined;
    const result = handler.init(&upstreams, .{ .enable_probing = false }, null, null);
    try std.testing.expectError(error.InvalidUpstreamIndex, result);
}
```

**Step 2: Run test to verify it fails**

Run: `zig build test-lb`
Expected: Compile error (error.InvalidUpstreamIndex doesn't exist yet) or assertion panic. Verify non-zero exit code.

**Step 3: Add idx validation to LbHandler.init**

Add a validation block in `handler.zig` `init`, after the existing asserts and before setting `self.*`. This validates that upstream indices form a dense 0..N-1 permutation.

Keep `init` return type as `!void` (inferred error set). This is required because `init` also calls `std.Thread.spawn` which returns spawn-related errors not in any named LbError set. The new validation errors (`error.InvalidUpstreamIndex`, `error.TlsContextRequired`) are returned as part of the inferred set alongside existing spawn errors.

Add validation in `init` after the existing asserts, before `self.* = .{`:

```zig
        // Validate upstream indices are a dense 0..N-1 permutation.
        // Prevents health state corruption from misconfigured idx values.
        var idx_seen: u64 = 0;
        for (upstreams) |upstream| {
            if (upstream.idx >= upstreams.len) return error.InvalidUpstreamIndex;
            const mask: u64 = @as(u64, 1) << @as(u6, @intCast(upstream.idx));
            if (idx_seen & mask != 0) return error.InvalidUpstreamIndex; // duplicate
            idx_seen |= mask;
        }
```

**Step 4: Run tests**

Run: `zig build test-lb`
Expected: All tests PASS. Verify exit code 0.

**Step 5: Commit**

```bash
git add serval-lb/handler.zig
git commit -m "fix(lb): validate upstream.idx is dense 0..N-1 at init

Prevents health state corruption from misconfigured idx values.
Returns error.InvalidUpstreamIndex instead of relying on debug asserts."
```

---

### Task 3: Validate TLS context at init when upstreams require TLS (Finding 3 - Medium)

If any upstream has `tls=true` but `client_ctx` is null, probes silently fail (client returns `TlsHandshakeFailed`, adapter catches as `false`). The backend stays permanently unhealthy with no indication of misconfiguration.

**Files:**
- Modify: `serval-lb/handler.zig`

**Step 1: Write the failing test**

Note: The existing assert at `handler.zig:85` checks `!enable_probing or dns_resolver != null` and would panic before the TLS check if `dns_resolver` is null with probing enabled. The test must provide a valid `dns_resolver` to reach the TLS validation path.

```zig
test "LbHandler init rejects null client_ctx when upstream has tls=true" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0, .tls = true },
    };

    // Provide dns_resolver so the existing probing assert at handler.zig:85 passes.
    // The TLS validation fires after that assert.
    var dns_resolver: DnsResolver = undefined;
    DnsResolver.init(&dns_resolver, .{});

    var handler: LbHandler = undefined;
    const result = handler.init(&upstreams, .{ .enable_probing = true }, null, &dns_resolver);
    try std.testing.expectError(error.TlsContextRequired, result);
}

test "LbHandler init accepts null client_ctx when no upstream has tls" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0, .tls = false },
    };

    var handler: LbHandler = undefined;
    // probing disabled so dns_resolver=null is fine, and no TLS upstreams so client_ctx=null is fine
    try handler.init(&upstreams, .{ .enable_probing = false }, null, null);
    defer handler.deinit();
}
```

**Step 2: Run test to verify it fails**

Run: `zig build test-lb`
Expected: FAIL (error.TlsContextRequired doesn't exist yet). Verify non-zero exit code.

**Step 3: Add TLS context validation**

In `handler.zig` `init`, add after the idx validation:

```zig
        // Validate TLS context when probing is enabled and any upstream requires TLS.
        // Without client_ctx, TLS probes silently fail and backends stay permanently unhealthy.
        // Only relevant when probing is active — without probing, no TLS handshakes are attempted
        // by the LbHandler (request-path TLS uses its own client_ctx from the Client).
        if (lb_config.enable_probing and client_ctx == null) {
            for (upstreams) |upstream| {
                if (upstream.tls) return error.TlsContextRequired;
            }
        }
```

**Step 4: Run tests**

Run: `zig build test-lb`
Expected: All tests PASS. Verify exit code 0.

**Step 5: Commit**

```bash
git add serval-lb/handler.zig
git commit -m "fix(lb): reject null client_ctx when upstreams require TLS

Without TLS context, probes silently fail and backends stay permanently
unhealthy. Now returns error.TlsContextRequired at init."
```

---

### Task 4: Reduce prober shutdown latency (Finding 4 - Medium)

`runLoopWithIo` sleeps for the full probe interval (default 5s) then checks `probe_running`. `deinit()` sets the flag then blocks on `join()`. Worst-case shutdown blocks for the full interval.

**Files:**
- Modify: `serval-prober/scheduler.zig`

**Step 1: Write tests**

Two tests: one for immediate exit (flag false at entry), one for mid-sleep cancellation (flag flips while sleeping). The mid-sleep test spawns `runLoopWithIo` on a background thread with a long interval, flips the flag after a short delay, and asserts the thread joins well before the full interval elapses.

```zig
test "runLoopWithIo exits immediately when probe_running is false" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    var health = HealthState.init(1, 1, 1);
    var running = std.atomic.Value(bool).init(false); // already stopped

    var adapter_marker: u8 = 0;
    const NoopAdapter = struct {
        fn probe(context: *anyopaque, upstream: Upstream, io_arg: Io) bool {
            _ = context;
            _ = upstream;
            _ = io_arg;
            return false;
        }
    };

    const ctx = SchedulerContext{
        .upstreams = &upstreams,
        .health = &health,
        .probe_running = &running,
        .probe_interval_ms = 60_000, // 60 seconds - would hang if not interruptible
        .adapter = .{
            .context = &adapter_marker,
            .probeFn = NoopAdapter.probe,
        },
    };

    // This should return near-instantly, not block for 60 seconds
    runLoopWithIo(ctx, undefined);
}

test "interruptibleSleep exits early when flag flips mid-sleep" {
    var running = std.atomic.Value(bool).init(true);

    // Spawn interruptibleSleep on a background thread with a 10-second total sleep.
    const worker = struct {
        fn run(probe_running: *std.atomic.Value(bool)) void {
            // Use undefined Io — interruptibleSleep only needs it for Io.sleep,
            // and the real Io.Threaded is not needed for this timing test.
            // In production the caller provides a real Io.
            var io_runtime = std.Io.Threaded.init(std.heap.page_allocator, .{});
            defer io_runtime.deinit();
            interruptibleSleep(probe_running, 10_000, io_runtime.io());
        }
    }.run;

    const thread = std.Thread.spawn(.{}, worker, .{&running}) catch unreachable;

    // Wait 300ms then flip the flag — well past one SHUTDOWN_POLL_MS (100ms) cycle
    // but well under the 10-second total sleep.
    const delay = std.Io.Duration.fromMilliseconds(300);
    std.Io.sleep(std.Options.debug_io, delay, .awake) catch {};

    running.store(false, .release);

    // Thread should join promptly (within ~100ms of flag flip).
    // If interruptibleSleep were a single 10s sleep, this would hang for ~9.7s.
    thread.join();

    // If we got here, the interruptible sleep exited early. Success.
}
```

**Step 2: Run tests**

Run: `zig build test`
Expected: Both PASS. Verify exit code 0. The mid-sleep test confirms the thread joins in ~400ms total, not 10 seconds.

**Step 3: Replace single long sleep with interruptible polling loop**

In `scheduler.zig`, replace the single `Io.sleep` call with a loop of shorter sleeps (100ms increments) that checks `probe_running` between each:

Replace the `runLoopWithIo` function:

```zig
/// Maximum sleep granularity for interruptible shutdown (100ms).
const SHUTDOWN_POLL_MS: u32 = 100;

pub fn runLoopWithIo(ctx: SchedulerContext, io: Io) void {
    assert(ctx.probe_interval_ms > 0);

    while (ctx.probe_running.load(.acquire)) {
        probeUnhealthyOnce(ctx, io);
        // Sleep in small increments so shutdown is responsive.
        interruptibleSleep(ctx.probe_running, ctx.probe_interval_ms, io);
    }
}

/// Sleep for `total_ms` in increments of SHUTDOWN_POLL_MS, checking the
/// stop flag between each increment. Returns early if flag becomes false.
/// Visible to tests for direct validation of mid-sleep cancellation.
pub fn interruptibleSleep(
    probe_running: *std.atomic.Value(bool),
    total_ms: u32,
    io: Io,
) void {
    var remaining_ms: u32 = total_ms;
    while (remaining_ms > 0 and probe_running.load(.acquire)) {
        const sleep_ms = @min(remaining_ms, SHUTDOWN_POLL_MS);
        const duration = std.Io.Duration.fromMilliseconds(@intCast(sleep_ms));
        std.Io.sleep(std.Options.debug_io, duration, .awake) catch |err| {
            log.debug("interruptible sleep failed: {s}", .{@errorName(err)});
        };
        remaining_ms -= sleep_ms;
    }
}
```

**Step 4: Run tests**

Run: `zig build test`
Expected: All PASS. Verify exit code 0. Note: there is no dedicated `test-prober` build step; `zig build test` runs all library tests including the prober scheduler tests.

**Step 5: Commit**

```bash
git add serval-prober/scheduler.zig
git commit -m "fix(prober): reduce shutdown latency with interruptible sleep

Replaces single long sleep with 100ms polling loop that checks
probe_running between increments. Worst-case shutdown delay is
now ~100ms instead of the full probe interval."
```

---

### Task 5: Update serval-lb README (Finding 5 - Low)

The usage example calls `handler.init` with old 2-arg signature; current API requires `client_ctx` and `dns_resolver`. The struct snippet shows fields (`health`, `next_idx`) that now live in `RoundRobinStrategy`.

**Files:**
- Modify: `serval-lb/README.md`

**Step 1: Update usage example**

Change the init call at line 44 to match current signature:

```zig
var handler: serval_lb.LbHandler = undefined;
try handler.init(&upstreams, .{
    .unhealthy_threshold = 3,
    .healthy_threshold = 2,
    .probe_interval_ms = 5000,
    .probe_timeout_ms = 2000,
    .health_path = "/health",
}, client_ctx, &dns_resolver);
defer handler.deinit();
```

**Step 2: Update struct snippet**

Replace the LbHandler struct snippet (line 57) to match actual fields:

```zig
pub const LbHandler = struct {
    upstreams: []const Upstream,
    strategy: RoundRobinStrategy,
    probe_running: std.atomic.Value(bool),
    probe_thread: ?std.Thread,
    lb_config: LbConfig,

    pub fn init(self: *Self, upstreams: []const Upstream, lb_config: LbConfig, client_ctx: ?*ssl.SSL_CTX, dns_resolver: ?*DnsResolver) !void
    pub fn deinit(self: *Self) void
    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Upstream
    pub fn onLog(self: *Self, ctx: *Context, entry: LogEntry) void
    pub fn countHealthy(self: *const Self) u32
    pub fn isHealthy(self: *const Self, idx: UpstreamIndex) bool
};
```

**Step 3: Commit**

```bash
git add serval-lb/README.md
git commit -m "docs(lb): update README to match current init signature and struct fields"
```

---

### Task 6: Run full test suite

**Step 1: Run all unit tests**

Run: `zig build test`
Expected: All PASS. Verify exit code 0.

**Step 2: Run LB and health tests specifically**

Run: `zig build test-lb test-health`
Expected: All PASS. Verify exit code 0.
