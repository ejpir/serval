# Router Findings Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 5 findings in serval-router ordered by severity — wrong-pool health updates, broken IPv6 host parsing, missing prefix boundary guard, onLog hot-path cost, and README inconsistencies.

**Architecture:** Each fix is isolated to serval-router (types.zig, router.zig, README.md) except Task 1 which adds one field to `Context` in serval-core. Task 1 threads `pool_idx` through Context so `onLog()` can jump directly to the correct pool — fixing correctness (#1) and reducing the hot-path from O(pools × upstreams) to O(upstreams_per_pool) (#4). Findings 2 and 3 are independent leaf changes in matching logic. Finding 5 is docs-only.

**Tech Stack:** Zig, `zig build test-router`

---

### Task 1: Fix onLog wrong-pool matching (Finding #1) and reduce hot-path cost (Finding #4)

**Problem:** `onLog()` iterates all pools × all upstreams matching by `u.idx == upstream.idx`. Two bugs:
1. **Correctness:** When pools have upstreams with overlapping `idx` values (0,1,2... — the common case for independently configured pools), the first matching pool wins, corrupting health state for subsequent pools. This also breaks when the same backend endpoint appears in multiple pools (shared infra, blue/green, gradual migration).
2. **Performance:** The O(pools × upstreams) scan runs on every log entry, which is the hot path at high RPS.

**Fix approach:** `Context` already flows through both `selectUpstream()` and `onLog()`, and already carries router-set state (`rewritten_path`). Add `pool_idx: ?u8 = null` to Context. In `selectUpstream()`, **clear it to null at entry** (guards against stale values from Context reuse without reset), then store `route.pool_idx` on the forward path. Reject paths (421, 404) return before setting it, leaving it null. In `onLog()`, read it to jump directly to the correct pool, then scan only that pool's upstreams (matching by `(host, port)` for the local index within the pool). If `pool_idx` is null (no pool was selected — e.g., the request was rejected), log a warning so dropped health updates are observable rather than silently swallowed.

This fixes correctness (explicit pool identity — no ambiguity even with shared backends or overlapping idx) and reduces onLog cost to O(upstreams_per_pool), which is typically 2-10 backends. The inner scan remains because `strategy.select()` returns the upstream as-is from the pool's array (the configured `idx` may differ from the array position), so we need to find the array position. True O(1) would require also threading the local index, but the remaining cost is negligible.

**Files:**
- Modify: `serval-core/context.zig:231-270` (add pool_idx field to Context)
- Modify: `serval-router/router.zig:203-240` (selectUpstream — store pool_idx)
- Modify: `serval-router/router.zig:248-272` (onLog — use pool_idx for direct lookup)
- Test: `serval-router/router.zig` (new tests)

**Step 1: Write the failing tests**

Add two tests after the existing `"Router onLog still updates pool health after LB strategy extraction"` test (~line 762).

First test — overlapping idx values:

```zig
test "Router onLog does not corrupt health across pools with overlapping idx" {
    // Two pools whose upstreams have overlapping idx values (both start at 0).
    // This is the common case when each pool's upstreams are configured independently.
    const pool0_upstreams = [_]Upstream{
        .{ .host = "pool0-a", .port = 8001, .idx = 0 },
        .{ .host = "pool0-b", .port = 8002, .idx = 1 },
    };

    const pool1_upstreams = [_]Upstream{
        .{ .host = "pool1-a", .port = 9001, .idx = 0 }, // Same idx as pool0-a!
        .{ .host = "pool1-b", .port = 9002, .idx = 1 }, // Same idx as pool0-b!
    };

    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
        },
        .{
            .name = "static",
            .matcher = .{ .path = .{ .prefix = "/static/" } },
            .pool_idx = 1,
        },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &pool0_upstreams, .lb_config = .{
            .enable_probing = false,
            .unhealthy_threshold = 2,
            .healthy_threshold = 1,
        } },
        .{ .name = "pool-1", .upstreams = &pool1_upstreams, .lb_config = .{
            .enable_probing = false,
            .unhealthy_threshold = 2,
            .healthy_threshold = 1,
        } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    var ctx = Context.init();

    // Route to pool 1 first so ctx.pool_idx is set correctly
    const req = Request{ .path = "/static/img.png" };
    const action = router.selectUpstream(&ctx, &req);
    try std.testing.expect(action == .forward);

    // Send 5xx errors for pool1's upstream
    router.onLog(&ctx, makeRouterLogEntry(500, pool1_upstreams[0]));
    router.onLog(&ctx, makeRouterLogEntry(500, pool1_upstreams[0]));

    // Pool 0 must be completely unaffected
    const p0 = router.getPool(0).?;
    try std.testing.expect(p0.lb_handler.isHealthy(0)); // pool0-a still healthy
    try std.testing.expect(p0.lb_handler.isHealthy(1)); // pool0-b still healthy

    // Pool 1's first upstream should be unhealthy, second still healthy
    const p1 = router.getPool(1).?;
    try std.testing.expect(!p1.lb_handler.isHealthy(0)); // pool1-a unhealthy
    try std.testing.expect(p1.lb_handler.isHealthy(1));  // pool1-b still healthy
}
```

Second test — shared backend across pools (same host:port in two pools):

```zig
test "Router onLog targets correct pool when backend is shared across pools" {
    // Same backend endpoint in both pools (e.g., shared infra, blue/green overlap).
    // onLog must update the pool that actually served the request, not the first match.
    const shared_upstream = Upstream{ .host = "shared-backend", .port = 8001, .idx = 0 };

    const pool0_upstreams = [_]Upstream{shared_upstream};
    const pool1_upstreams = [_]Upstream{shared_upstream};

    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/api/" } },
            .pool_idx = 0,
        },
        .{
            .name = "admin",
            .matcher = .{ .path = .{ .prefix = "/admin/" } },
            .pool_idx = 1,
        },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &pool0_upstreams, .lb_config = .{
            .enable_probing = false,
            .unhealthy_threshold = 2,
            .healthy_threshold = 1,
        } },
        .{ .name = "pool-1", .upstreams = &pool1_upstreams, .lb_config = .{
            .enable_probing = false,
            .unhealthy_threshold = 2,
            .healthy_threshold = 1,
        } },
    };

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &.{}, null, null);
    defer router.deinit();

    // Route to pool 1 (admin)
    var ctx = Context.init();
    const req = Request{ .path = "/admin/dashboard" };
    const action = router.selectUpstream(&ctx, &req);
    try std.testing.expect(action == .forward);

    // Send 5xx — should only affect pool 1, not pool 0
    router.onLog(&ctx, makeRouterLogEntry(500, shared_upstream));
    router.onLog(&ctx, makeRouterLogEntry(500, shared_upstream));

    // Pool 0 must be unaffected (same backend but different pool context)
    const p0 = router.getPool(0).?;
    try std.testing.expect(p0.lb_handler.isHealthy(0));

    // Pool 1 should be unhealthy
    const p1 = router.getPool(1).?;
    try std.testing.expect(!p1.lb_handler.isHealthy(0));
}
```

Third test — stale pool_idx after reject (Context reuse without reset):

```zig
test "Router onLog ignores stale pool_idx after rejected request" {
    // Scenario: Context is reused across requests without full reset.
    // 1. First request forwards to pool 0 (sets ctx.pool_idx = 0).
    // 2. Second request on same Context is rejected (421).
    //    selectUpstream must clear pool_idx so onLog doesn't use the stale value.
    // 3. onLog after the rejected request must not mutate any pool.
    const upstreams = [_]Upstream{
        .{ .host = "backend-a", .port = 8001, .idx = 0 },
    };

    const routes = [_]Route{
        .{
            .name = "api",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{
            .enable_probing = false,
            .unhealthy_threshold = 2,
            .healthy_threshold = 1,
        } },
    };

    const allowed_hosts = [_][]const u8{"allowed.example.com"};

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &allowed_hosts, null, null);
    defer router.deinit();

    var ctx = Context.init();

    // Step 1: Forward request — sets ctx.pool_idx = 0
    var req1 = Request{ .path = "/test" };
    try req1.headers.put("Host", "allowed.example.com");
    const action1 = router.selectUpstream(&ctx, &req1);
    try std.testing.expect(action1 == .forward);
    try std.testing.expectEqual(@as(?u8, 0), ctx.pool_idx);

    // Step 2: Rejected request on SAME context (host not allowed → 421)
    // selectUpstream must clear pool_idx before the reject return.
    var req2 = Request{ .path = "/test" };
    try req2.headers.put("Host", "disallowed.example.com");
    const action2 = router.selectUpstream(&ctx, &req2);
    try std.testing.expect(action2 == .reject);
    try std.testing.expectEqual(@as(?u8, null), ctx.pool_idx);

    // Step 3: onLog after rejection must not touch pool 0
    router.onLog(&ctx, makeRouterLogEntry(500, upstreams[0]));
    router.onLog(&ctx, makeRouterLogEntry(500, upstreams[0]));

    const p0 = router.getPool(0).?;
    try std.testing.expect(p0.lb_handler.isHealthy(0)); // Must still be healthy
}
```

**Step 2: Run test to verify it fails**

Run: `zig build test-router 2>&1 | tail -20`
Expected: FAIL — pool0's health is corrupted in first test; wrong pool updated in second test; stale pool_idx causes mutation in third test.

**Step 3: Add pool_idx to Context**

In `serval-core/context.zig`, add after the `rewritten_path` field (line 249):

```zig
    // Set by router to identify which pool handled this request.
    // Used by onLog to route health updates to the correct pool.
    // TigerStyle: Optional u8 (null = no pool selected yet).
    pool_idx: ?u8 = null,
```

Verify `Context.reset()` already handles this: it does `self.* = .{ .start_time_ns = ... }` which resets all fields to defaults, so `pool_idx` will reset to `null`. No change needed in `reset()`.

**Step 4: Store pool_idx in selectUpstream**

In `serval-router/router.zig`, in `selectUpstream()`:

First, **clear pool_idx at entry** (after the assertions at lines 204-205, before the host validation). This prevents stale values if Context is reused without a full reset:

```zig
        assert(self.pools.len > 0); // S1: Router initialized
        assert(self.allowed_hosts.len <= MAX_ALLOWED_HOSTS); // S1: Bounds check

        // Clear pool_idx to prevent stale values from prior requests on reused Context.
        ctx.pool_idx = null;
```

Then, on the forward path (after the assertion at line 236), set it:

```zig
        assert(route.pool_idx < self.pools.len); // S1: Valid pool index
        ctx.pool_idx = route.pool_idx;
        const upstream = self.pools[route.pool_idx].lb_handler.selectUpstream(ctx, request);
```

Reject paths (421 and 404) return before reaching this line, so `pool_idx` stays null — which is correct: no pool was selected, so `onLog()` should not target any pool.

**Step 5: Rewrite onLog to use pool_idx**

Replace the `onLog` method (lines 248-272):

```zig
    /// Handler interface: forward health tracking to correct pool.
    ///
    /// Uses pool_idx from Context (set by selectUpstream) to go directly
    /// to the correct pool, then finds the upstream's local array index
    /// by matching (host, port).
    ///
    /// Complexity: O(upstreams_per_pool) — the outer pool scan is eliminated.
    /// TigerStyle: Bounded inner loop (MAX_UPSTREAMS per pool).
    pub fn onLog(self: *Self, ctx: *Context, entry: LogEntry) void {
        const upstream = entry.upstream orelse return;
        const pool_idx = ctx.pool_idx orelse {
            log.warn("onLog: pool_idx not set on context, dropping health update for {s}:{d}", .{
                upstream.host, upstream.port,
            });
            return;
        };

        assert(pool_idx < self.pools.len);
        var pool = &self.pools[pool_idx];

        // Find local array index within the pool by (host, port).
        // Within a single pool, (host, port) is unique.
        // TigerStyle S3: Bounded loop (MAX_UPSTREAMS per pool)
        for (pool.lb_handler.upstreams, 0..) |u, local_idx| {
            if (u.port == upstream.port and std.mem.eql(u8, u.host, upstream.host)) {
                var local_upstream = u;
                local_upstream.idx = @intCast(local_idx);

                var local_entry = entry;
                local_entry.upstream = local_upstream;

                pool.lb_handler.onLog(ctx, local_entry);
                return;
            }
        }
        // Upstream not found in pool — ignore (may be from different handler)
    }
```

**Step 6: Run test to verify it passes**

Run: `zig build test-router 2>&1 | tail -20`
Expected: ALL PASS

**Step 6b: Run full test suite (cross-module verification)**

Context is shared infrastructure used by every module. Adding a field must not break any consumer.

Run: `zig build test 2>&1 | tail -30`
Expected: ALL PASS across all modules. If any module fails, fix before committing.

**Step 7: Commit**

```bash
git add serval-core/context.zig serval-router/router.zig
git commit -m "fix(serval-router): thread pool_idx through Context for correct onLog routing

onLog matched upstreams by idx alone, which overlaps across pools
(each pool uses local indices 0,1,2...). This corrupted health state
for the wrong pool, and also failed when the same backend appeared in
multiple pools (shared infra, blue/green).

Store pool_idx on Context during selectUpstream so onLog can jump
directly to the correct pool. Also reduces hot-path cost from
O(pools * upstreams) to O(upstreams_per_pool)."
```

---

### Task 2: Fix IPv6 host parsing (Finding #2)

**Problem:** Both `RouteMatcher.matches()` (types.zig:101) and `Router.isHostAllowed()` (router.zig:330) use `indexOfScalar(u8, host, ':')` to strip port. This breaks IPv6 literals like `[2001:db8::1]:443` (splits at first colon inside brackets) and bare `2001:db8::1` (splits at first colon in the address).

**Fix approach:** Extract a shared `stripPort()` helper that handles:
- IPv6 bracket form: `[2001:db8::1]:443` → `2001:db8::1` (strip brackets and port)
- IPv6 bracket no port: `[2001:db8::1]` → `2001:db8::1` (strip brackets)
- IPv4/hostname with port: `example.com:8080` → `example.com`
- IPv4/hostname no port: `example.com` → `example.com`
- Bare IPv6 (no brackets): `2001:db8::1` → `2001:db8::1` (return as-is; no port to strip)

**Files:**
- Modify: `serval-router/types.zig:96-110` (RouteMatcher.matches, add stripPort helper)
- Modify: `serval-router/router.zig:329-330` (isHostAllowed)
- Test: `serval-router/types.zig` (new RouteMatcher-level tests)
- Test: `serval-router/router.zig` (new Router-level isHostAllowed test)

**Step 1: Write the failing tests**

Add RouteMatcher-level tests in `types.zig` after the existing `"RouteMatcher strips port from host"` test (~line 373):

```zig
test "RouteMatcher handles IPv6 host with port" {
    const matcher = RouteMatcher{
        .host = "2001:db8::1",
        .path = .{ .prefix = "/" },
    };

    // Bracketed IPv6 with port (standard HTTP Host header form)
    try std.testing.expect(matcher.matches("[2001:db8::1]:443", "/"));
    try std.testing.expect(matcher.matches("[2001:db8::1]:8080", "/"));

    // Bracketed IPv6 without port
    try std.testing.expect(matcher.matches("[2001:db8::1]", "/"));

    // Bare IPv6 (no brackets, no port)
    try std.testing.expect(matcher.matches("2001:db8::1", "/"));

    // Wrong IPv6 address should not match
    try std.testing.expect(!matcher.matches("[2001:db8::2]:443", "/"));

    // Malformed bracket tail should not match (returns as-is, fails host compare)
    try std.testing.expect(!matcher.matches("[2001:db8::1]junk", "/"));
}

test "RouteMatcher handles IPv4 host unchanged" {
    const matcher = RouteMatcher{
        .host = "192.168.1.1",
        .path = .{ .prefix = "/" },
    };

    try std.testing.expect(matcher.matches("192.168.1.1:8080", "/"));
    try std.testing.expect(matcher.matches("192.168.1.1", "/"));
    try std.testing.expect(!matcher.matches("192.168.1.2:8080", "/"));
}
```

Add Router-level test in `router.zig` after the existing `"Router isHostAllowed strips port from host"` test (~line 977):

```zig
test "Router isHostAllowed handles IPv6 bracket notation" {
    const routes = [_]Route{
        .{
            .name = "default",
            .matcher = .{ .path = .{ .prefix = "/" } },
            .pool_idx = 0,
        },
    };

    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool_configs = [_]PoolConfig{
        .{ .name = "pool-0", .upstreams = &upstreams, .lb_config = .{ .enable_probing = false } },
    };

    const allowed_hosts = [_][]const u8{"2001:db8::1"};

    var router: Router = undefined;
    try router.init(&routes, &pool_configs, &allowed_hosts, null, null);
    defer router.deinit();

    // Bracketed IPv6 with port
    try std.testing.expect(router.isHostAllowed("[2001:db8::1]:443"));
    try std.testing.expect(router.isHostAllowed("[2001:db8::1]:8080"));

    // Bracketed IPv6 without port
    try std.testing.expect(router.isHostAllowed("[2001:db8::1]"));

    // Bare IPv6
    try std.testing.expect(router.isHostAllowed("2001:db8::1"));

    // Wrong address
    try std.testing.expect(!router.isHostAllowed("[2001:db8::2]:443"));
}
```

**Step 2: Run test to verify it fails**

Run: `zig build test-router 2>&1 | tail -20`
Expected: FAIL — IPv6 bracketed forms are incorrectly split at both RouteMatcher and Router level.

**Step 3: Implement the fix**

Add a `stripPort` function in `types.zig` (after imports, before `PathMatch`):

```zig
/// Strip port from hostname, handling IPv6 bracket notation.
///
/// RFC 9110 §7.2: Host header may include port.
/// RFC 3986 §3.2.2: IPv6 addresses in URIs use bracket notation.
///
/// Examples:
///   "[2001:db8::1]:443" -> "2001:db8::1"
///   "[2001:db8::1]"     -> "2001:db8::1"
///   "example.com:8080"  -> "example.com"
///   "example.com"       -> "example.com"
///   "2001:db8::1"       -> "2001:db8::1" (bare IPv6, no port to strip)
///
/// TigerStyle: Pure function, no allocation, returns slice into input.
pub fn stripPort(host: []const u8) []const u8 {
    // IPv6 bracket notation: [addr] or [addr]:port
    if (host.len > 0 and host[0] == '[') {
        if (std.mem.indexOfScalar(u8, host, ']')) |close| {
            // Validate: ']' must be at end or followed by ':'
            // Rejects malformed inputs like "[2001:db8::1]junk"
            if (close + 1 == host.len or host[close + 1] == ':') {
                return host[1..close];
            }
            // Malformed tail after bracket — return as-is
            return host;
        }
        // No closing bracket — return as-is
        return host;
    }

    // Non-bracketed: use first colon to find port (IPv4/hostname only).
    // If there are multiple colons, it's a bare IPv6 address — return as-is.
    if (std.mem.indexOfScalar(u8, host, ':')) |first_colon| {
        // Check if there's another colon after the first — bare IPv6
        if (std.mem.indexOfScalar(u8, host[first_colon + 1 ..], ':') != null) {
            return host; // Bare IPv6, no port to strip
        }
        // Single colon — hostname:port
        return host[0..first_colon];
    }

    return host;
}
```

Update `RouteMatcher.matches()` in `types.zig` (replace the `indexOfScalar` line at ~line 101):

```zig
            const hostname = stripPort(actual_host);
```

Update `Router.isHostAllowed()` in `router.zig` (replace the `indexOfScalar` line at ~line 330):

```zig
        const hostname = types.stripPort(h);
```

**Step 4: Run test to verify it passes**

Run: `zig build test-router 2>&1 | tail -20`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add serval-router/types.zig serval-router/router.zig
git commit -m "fix(serval-router): handle IPv6 bracket notation in host parsing

indexOfScalar(':') breaks IPv6 literals like [2001:db8::1]:443 by
splitting at the first colon inside brackets. Add stripPort() that
handles bracket notation (RFC 3986 §3.2.2) and bare IPv6 addresses.
Both RouteMatcher.matches and Router.isHostAllowed now use it."
```

---

### Task 3: Add path-segment boundary guard to prefix matching (Finding #3)

**Problem:** `PathMatch.prefix` uses `startsWith()` alone, so prefix `/api` also matches `/apiary`. Traffic can be misrouted when config lacks trailing slash discipline.

**Fix approach:** After the `startsWith` check, verify the next character (if any) is `/` or `?` — i.e., the match is at a path-segment boundary. Exact-length match (path == prefix) is also valid.

**Files:**
- Modify: `serval-router/types.zig:46` (PathMatch.matches, prefix branch)
- Test: `serval-router/types.zig` (new test)

**Step 1: Write the failing test**

The existing test at line 254 already tests `!pattern.matches("/apifoo")` for prefix `/api/`. But that passes because `/api/` doesn't start `/apifoo`. We need a test with prefix `/api` (no trailing slash).

Add a new test block after the existing `"PathMatch prefix matches"` test:

```zig
test "PathMatch prefix respects segment boundary" {
    // Prefix without trailing slash — must still respect path boundaries
    const pattern = PathMatch{ .prefix = "/api" };

    // Exact match
    try std.testing.expect(pattern.matches("/api"));

    // Segment boundary (next char is /)
    try std.testing.expect(pattern.matches("/api/"));
    try std.testing.expect(pattern.matches("/api/users"));

    // Query string boundary (next char is ?)
    try std.testing.expect(pattern.matches("/api?key=val"));

    // NOT a segment boundary — different path that happens to share prefix
    try std.testing.expect(!pattern.matches("/apiary"));
    try std.testing.expect(!pattern.matches("/api-v2"));
    try std.testing.expect(!pattern.matches("/apis"));
}
```

**Step 2: Run test to verify it fails**

Run: `zig build test-router 2>&1 | tail -20`
Expected: FAIL — `/apiary` matches because `startsWith("/api")` is true.

**Step 3: Implement the fix**

Replace the prefix branch in `PathMatch.matches()` (types.zig line 46):

```zig
            .prefix => |pattern| {
                if (!std.mem.startsWith(u8, request_path, pattern)) return false;
                // Exact-length match or next char is a segment boundary (/ or ?)
                return request_path.len == pattern.len or
                    request_path[pattern.len] == '/' or
                    request_path[pattern.len] == '?';
            },
```

**Step 4: Run test to verify it passes**

Run: `zig build test-router 2>&1 | tail -20`
Expected: ALL PASS (existing prefix tests with trailing-slash prefixes like `/api/` still pass because the char after the prefix is always `/` or beyond).

**Step 5: Commit**

```bash
git add serval-router/types.zig
git commit -m "fix(serval-router): enforce path-segment boundary on prefix match

startsWith alone means prefix '/api' also matches '/apiary'. Now
require the character after the prefix to be '/', '?', or end-of-path,
preventing misrouting from missing trailing-slash conventions."
```

---

### Task 4: Fix README inconsistencies (Finding #5)

**Problem:**
1. README says "Wildcard host matching | Not implemented" but it IS implemented and tested.
2. PathMatch API snippet in README omits `exactPath` variant.

**Files:**
- Modify: `serval-router/README.md:293` (status table)
- Modify: `serval-router/README.md:214-220` (PathMatch API snippet)

**Step 1: Fix the status table**

In the Implementation Status table, change:

```
| Wildcard host matching | Not implemented |
```

to:

```
| Wildcard host matching | Complete |
```

**Step 2: Fix the PathMatch API snippet**

In the API Reference section, the PathMatch snippet (around line 214) currently shows:

```zig
pub const PathMatch = union(enum) {
    exact: []const u8,   // Exact path match
    prefix: []const u8,  // Prefix match

    pub fn matches(self: PathMatch, request_path: []const u8) bool
    pub fn getPattern(self: PathMatch) []const u8
};
```

Update to include `exactPath`:

```zig
pub const PathMatch = union(enum) {
    exact: []const u8,      // Exact path match
    exactPath: []const u8,  // Exact path match ignoring query string
    prefix: []const u8,     // Prefix match (segment-boundary aware)

    pub fn matches(self: PathMatch, request_path: []const u8) bool
    pub fn getPattern(self: PathMatch) []const u8
};
```

**Step 3: Commit**

```bash
git add serval-router/README.md
git commit -m "docs(serval-router): fix README inconsistencies with implementation

Update status table to reflect wildcard host matching is complete.
Add missing exactPath variant to PathMatch API snippet."
```

---

## Task Summary

| Task | Finding | Severity | Change | Residual |
|------|---------|----------|--------|----------|
| 1 | #1 | High | Thread `pool_idx` via Context for correct pool targeting in `onLog()` | None |
| 1 | #4 | Medium(Perf) | Same change eliminates outer pool scan | Inner scan remains: O(upstreams_per_pool), typically 2-10. True O(1) deferred — would require threading local_idx or changing LbHandler.select() return type. |
| 2 | #2 | Medium | IPv6-aware `stripPort()` helper, tested at both RouteMatcher and Router level | None |
| 3 | #3 | Medium | Segment-boundary guard on prefix match | None |
| 4 | #5 | Low | README status table + API snippet | None |

All changes are in `serval-router/` except one field added to `serval-core/context.zig`. Run `zig build test-router` after each task. Task 1 additionally requires `zig build test` (full suite) since Context is shared infrastructure.
