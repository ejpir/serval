# Verification Findings Fixes

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 7 verified findings from the verification pass, ordered by severity.

**Architecture:** Each finding gets a focused fix with minimal blast radius. Finding 1 (desync) checks body-reader consumption state to decide keep-alive vs close — preserving keep-alive for handlers that consume the body, closing only when body bytes remain on the wire. Finding 2 (h2 timeout) wires the existing config constant through. Finding 3 (buffer size) requires caller inventory before changing the constant. Findings 4-6 are contained single-file changes. Finding 7 (loop decomposition) uses `LoopAction` enum for all three outcomes.

**Tech Stack:** Zig 0.16, serval-server h1/h2 modules, `zig build test`, `zig build test-h2`

---

### Task 1: Fix h1 short-circuit body desync (Finding 1 — ship blocker)

**Problem:** When `onRequest` returns `.send_response` or `.reject`, the code advances `buffer_offset` by `getBodyLength()` which returns 0 for chunked bodies and doesn't account for body bytes still on the socket. The connection is then reused, causing request desynchronization.

**Fix:** After a short-circuit response, check whether the body was actually consumed by the handler via the BodyReader's tracking state. Three cases:
- `body_framing == .none`: no body, keep-alive safe, advance by `headers_end`
- `body_framing == .content_length` and handler fully read it (`body_reader.total_bytes_read >= content_length`): body drained, keep-alive safe, advance by `headers_end + content_length`
- Otherwise (chunked, or Content-Length not fully read): close connection — unconsumed bytes on wire

The BodyReader already tracks `total_bytes_read` (`serval-core/context.zig:60`) and `initial_consumed` (`serval-core/context.zig:63`). Handlers use `ctx.readBody()` (`context.zig:351`) or `ctx.readBodyChunk()` (`context.zig:371`) which update these fields. We inspect them; no new tracking needed.

**Files:**
- Modify: `serval-server/h1/server.zig` — onRequest `.send_response` branch (~line 2746), `.reject` branch (~line 2759), `selectUpstream` action-reject branch (~line 3081), CONNECT rejection (~line 2674)

**Step 1: Add a helper to determine if body was consumed**

Add near the existing `getBodyLength` usage in `serval-server/h1/server.zig`:

```zig
/// Check if a short-circuit response can safely reuse the connection.
/// Returns true only when no body exists or the handler fully consumed it.
/// TigerStyle: Fail closed — unknown/partial consumption closes the connection.
fn isBodyConsumed(body_reader: *const BodyReader, framing: types.BodyFraming) bool {
    return switch (framing) {
        .none => true,
        .chunked => false, // BodyReader doesn't support chunked; can't verify consumption
        .content_length => |cl| body_reader.total_bytes_read >= cl,
    };
}
```

**Step 2: Fix the `.send_response` branch**

In `serval-server/h1/server.zig`, in the `.send_response` branch (around line 2746):

```zig
                        .send_response => |resp| {
                            // Handler wants to send direct response without forwarding
                            sendDirectResponseTls(maybe_tls_ptr, &io_mut, stream, resp);
                            const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                            metrics.requestEnd(resp.status, duration_ns);
                            tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(resp.status));
                            tracer.endSpan(span_handle, null);
                            // If body was not fully consumed, close connection to prevent
                            // desync — unconsumed bytes would be parsed as next request.
                            // TigerStyle: Fail closed on protocol ambiguity.
                            if (!isBodyConsumed(&body_reader, parser.body_framing)) return;
                            buffer_offset += parser.headers_end + body_length_for_offset;
                            const should_close = clientWantsClose(&parser.request.headers) or
                                request_count >= cfg.max_requests_per_connection;
                            if (should_close) return;
                            continue;
                        },
```

Key: `isBodyConsumed` checks whether the handler fully read the body. If yes, the existing `body_length_for_offset` advancement is correct (Content-Length is known and body is drained). If no, `return` closes the connection.

**Step 3: Fix the `.reject` branch**

Same pattern in the `.reject` branch (around line 2759):

```zig
                        .reject => |reject| {
                            // Handler wants to reject request (WAF, rate limiting, auth)
                            sendErrorResponseTls(maybe_tls_ptr, &io_mut, stream, reject.status, reject.reason);
                            const duration_ns: u64 = @intCast(realtimeNanos() - ctx.start_time_ns);
                            metrics.requestEnd(reject.status, duration_ns);
                            tracer.setIntAttribute(span_handle, "http.response.status_code", @intCast(reject.status));
                            tracer.endSpan(span_handle, reject.reason);
                            // Body not consumed — close connection to prevent desync.
                            // sendErrorResponseTls already sends Connection: close header.
                            if (!isBodyConsumed(&body_reader, parser.body_framing)) return;
                            buffer_offset += parser.headers_end + body_length_for_offset;
                            const should_close = clientWantsClose(&parser.request.headers) or
                                request_count >= cfg.max_requests_per_connection;
                            if (should_close) return;
                            continue;
                        },
```

**Step 4: Fix the `selectUpstream` action-reject branch**

In the `selectUpstream` action-reject path (around line 3081). This path runs after the `has_on_request` block, so `body_reader` may not be in scope. The body was not consumed here (selectUpstream doesn't read bodies), so close unconditionally when framing is non-none:

```zig
                            .reject => |rej| {
                                // ... (existing response sending, metrics, logging, tracing unchanged) ...

                                // Body not consumed by routing — close connection to prevent desync.
                                if (parser.body_framing != .none) return;
                                buffer_offset += parser.headers_end;
                                continue;
                            },
```

Note: `selectUpstream` never consumes the body, so `body_framing != .none` is the correct check here — no need for the BodyReader state check.

**Step 5: Fix the CONNECT rejection path**

The CONNECT rejection (around line 2674) has the same bug:

```zig
                if (parser.request.method == .CONNECT) {
                    send501NotImplementedTls(maybe_tls_ptr, &io_mut, stream, "CONNECT method not supported");
                    metrics.requestEnd(501, @intCast(realtimeNanos() - ctx.start_time_ns));
                    // send501NotImplementedTls sends Connection: close.
                    // Body not consumed — close to prevent desync.
                    if (parser.body_framing != .none) return;
                    buffer_offset += parser.headers_end;
                    continue;
                }
```

**Step 6: Write unit tests for body-consumption logic**

Test the `isBodyConsumed` helper that drives the keep-alive/close decision. These verify the decision logic directly — a full keep-alive desync regression test requires the integration test harness (multi-request connection with interleaved body data) and belongs in `integration/tests.zig`, not here. Add in `serval-server/h1/server.zig` tests:

```zig
test "isBodyConsumed returns false for chunked framing" {
    var reader = BodyReader{
        .framing = .chunked,
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };
    try std.testing.expect(!isBodyConsumed(&reader, .chunked));
}

test "isBodyConsumed returns true for fully-read content-length body" {
    var reader = BodyReader{
        .framing = .{ .content_length = 100 },
        .bytes_already_read = 100,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
        .total_bytes_read = 100,
    };
    try std.testing.expect(isBodyConsumed(&reader, .{ .content_length = 100 }));
}

test "isBodyConsumed returns false for partially-read content-length body" {
    var reader = BodyReader{
        .framing = .{ .content_length = 100 },
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
        .total_bytes_read = 50,
    };
    try std.testing.expect(!isBodyConsumed(&reader, .{ .content_length = 100 }));
}

test "isBodyConsumed returns true for no-body request" {
    var reader = BodyReader{
        .framing = .none,
        .bytes_already_read = 0,
        .initial_body = &[_]u8{},
        .read_ctx = null,
        .read_fn = null,
    };
    try std.testing.expect(isBodyConsumed(&reader, .none));
}
```

**Step 7: Add an integration regression for the original desync**

Add a real wire-level regression in `integration/tests.zig`. This test should:
- start a server path that short-circuits in `onRequest` without forwarding upstream
- open one raw TCP connection to the server (do not use `TestClient.get/post`, which force `Connection: close`)
- send request 1 with `Connection: keep-alive` and a body that will remain unread on the old buggy path
- assert the server responds and then closes the connection instead of accepting request 2 on the same socket

Recommended shape:

```zig
test "integration: short-circuit request with unread body closes connection to prevent desync" {
    // 1. Start a server/handler that rejects or send_response's in onRequest.
    // 2. Connect with posix.socket/connect to a single TCP socket.
    // 3. Write request 1:
    //    POST /short-circuit HTTP/1.1
    //    Host: 127.0.0.1:PORT
    //    Connection: keep-alive
    //    Transfer-Encoding: chunked
    //
    //    5\r\nhello\r\n0\r\n\r\n
    //
    // 4. Read the first response and assert status is the short-circuit status.
    // 5. Write request 2 on the same socket:
    //    GET /second HTTP/1.1
    //    Host: 127.0.0.1:PORT
    //    Connection: close
    //
    // 6. Assert the write fails or the subsequent read returns EOF / connection reset.
    //    The key invariant: the server must not parse request 2 after a short-circuit
    //    response with unread body bytes still on the wire.
}
```

Why `Transfer-Encoding: chunked`:
- this is the original high-risk case because the old `getBodyLength()`-based offset logic treated it as zero
- it verifies the fail-closed behavior on the exact framing mode that caused the desync

If starting a dedicated in-process server for the test is cheaper than extending `ProcessManager`, do that. The important part is the single persistent socket and second request on the same connection.

**Step 8: Run tests**

Run: `zig build test 2>&1 | tail -20`
Expected: All pass.

Run: `zig build test-integration 2>&1 | tail -20`
Expected: the new keep-alive/desync regression passes.

**Step 9: Commit**

```bash
git add serval-server/h1/server.zig
git commit -m "fix(h1): close connection on short-circuit with unconsumed body

Prevents request desynchronization when onRequest/selectUpstream rejects
a request with an unconsumed body. Checks BodyReader.total_bytes_read
to preserve keep-alive when handlers fully consumed the body (e.g. echo).
Chunked bodies always close since BodyReader can't drain chunked framing.

Adds isBodyConsumed() helper and unit tests for all framing cases."
```

---

### Task 2: Fix h2 TLS read timeout (Finding 2)

**Problem:** `waitUntilReadable()` in `h2/server.zig` passes `.none` as timeout to `receiveManyTimeout`, allowing indefinite blocking. The README claims `H2_SERVER_IDLE_TIMEOUT_NS` is used — it isn't.

**Fix:** Pass the idle timeout to `waitUntilReadable`. The `WantWrite` case (TLS renegotiation needing write) remains as a retry — adding a `waitUntilWritable` helper is deferred since TLS renegotiation during reads is rare and the timeout now bounds the overall wait regardless.

**Files:**
- Modify: `serval-server/h2/server.zig` — `waitUntilReadable()` (~line 2361) and TLS read branch (~line 2336)
- Modify: `serval-server/README.md` — correct the WantRead/WantWrite claim

**Step 1: Add timeout parameter to `waitUntilReadable`**

Change the function signature and body (around line 2361):

```zig
fn waitUntilReadable(fd: i32, io: Io, timeout: Io.Timeout) anyerror!void {
    assert(fd >= 0);
    assert(read_max_retry_count > 0);

    var messages: [1]Io.net.IncomingMessage = .{Io.net.IncomingMessage.init};
    var peek_buf: [1]u8 = undefined;
    const maybe_err, _ = rawStreamForFd(fd).socket.receiveManyTimeout(
        io,
        &messages,
        &peek_buf,
        .{ .peek = true },
        timeout,
    );
    if (maybe_err) |err| return err;
}
```

**Step 2: Wire the timeout at the call site**

In `readSome` TLS branch (around line 2336), compute the timeout and pass it:

```zig
        .tls_stream => |tls_stream| blk: {
            const timeout: Io.Timeout = .{ .duration = .{
                .raw = Io.Duration.fromNanoseconds(config.H2_SERVER_IDLE_TIMEOUT_NS),
                .clock = .awake,
            } };
            var retry_count: u32 = 0;
            while (retry_count < read_max_retry_count) : (retry_count += 1) {
                if (!tls_stream.hasPendingRead()) {
                    waitUntilReadable(tls_stream.fd, io, timeout) catch |err| switch (err) {
                        error.ConnectionResetByPeer,
                        error.SocketUnconnected,
                        => return error.ConnectionClosed,
                        error.Timeout => return error.ConnectionClosed,
                        else => return error.ReadFailed,
                    };
                }

                const n: u32 = tls_stream.read(out) catch |err| switch (err) {
                    error.WantRead, error.WantWrite => continue,
                    error.ConnectionReset => return error.ConnectionClosed,
                    else => return error.ReadFailed,
                };
                break :blk @intCast(n);
            }

            return error.ReadFailed;
        },
```

**Step 3: Check if `Io.Duration.fromNanoseconds` exists**

Search for the available Duration constructors. The h1 server uses `fromMilliseconds` at line 1678. If `fromNanoseconds` doesn't exist, convert:
```zig
.raw = Io.Duration.fromMilliseconds(config.H2_SERVER_IDLE_TIMEOUT_NS / time.ns_per_ms),
```

**Step 4: Update the README to match reality**

In `serval-server/README.md` line 7, replace the WantRead/WantWrite split claim. The current text says:

> TLS read backpressure is split into `WantRead` vs `WantWrite` so h2 and upgraded-tunnel call sites can wait on the correct fd readiness instead of flattening both cases into a generic idle retry.

Replace with:

> TLS h2 reads use `H2_SERVER_IDLE_TIMEOUT_NS` as the readiness timeout bound. `WantRead` and `WantWrite` from TLS are both retried within the bounded loop; a dedicated writable-wait for `WantWrite` (TLS renegotiation) is deferred until needed.

**Step 5: Run tests**

Run: `zig build test-h2 2>&1 | tail -20`
Expected: All pass.

**Step 6: Commit**

```bash
git add serval-server/h2/server.zig serval-server/README.md
git commit -m "fix(h2): add idle timeout to TLS read path

waitUntilReadable() was passing .none timeout, allowing indefinite
blocking on quiet TLS h2 connections. Now uses H2_SERVER_IDLE_TIMEOUT_NS.
Updates README to match actual WantRead/WantWrite handling."
```

---

### Task 3: Fix 128 MiB per-connection allocation (Finding 3)

**Problem:** Every connection to a handler with `onRequest` allocates 128 MiB via `page_allocator` at connection setup (`h1/server.zig:2593`). Under concurrency, 100 connections = 12.8 GiB.

**Fix:** This constant has dependents that must be inventoried before changing the value. `DIRECT_REQUEST_BODY_SIZE_BYTES` (`config.zig:91`) is documented as matching it ("Matches DIRECT_RESPONSE_BUFFER_SIZE_BYTES for echo handlers"). The gateway admin handler stores it as a struct field (`examples/gateway/controller/admin/handler.zig:39`). A blind reduction risks silent truncation.

**Files:**
- Modify: `serval-core/config.zig` — `DIRECT_RESPONSE_BUFFER_SIZE_BYTES` (line 81), `DIRECT_REQUEST_BODY_SIZE_BYTES` (line 91)
- Audit: `examples/gateway/controller/admin/handler.zig:39`, all `onRequest` implementations

**Step 1: Inventory all callers of `DIRECT_RESPONSE_BUFFER_SIZE_BYTES`**

```bash
rg "DIRECT_RESPONSE_BUFFER_SIZE_BYTES\|DIRECT_REQUEST_BODY_SIZE_BYTES" --type zig
```

For each caller, determine:
- What is the maximum response/body size this handler actually produces?
- Does it use `.stream` for large payloads, or write directly into the buffer?

Document findings before proceeding.

**Step 2: Determine the safe reduction target**

Based on the caller inventory:
- If all production handlers produce responses < N bytes, set the constant to N (rounded up to a power of 2).
- If echo/test handlers need the large buffer, split into two constants: `DIRECT_RESPONSE_BUFFER_SIZE_BYTES` for production (smaller) and a test-specific constant for echo backends.
- If the gateway admin handler stores it as a struct field, it must be updated to use the new constant or a handler-specific size.

**Step 3: Also reduce `DIRECT_REQUEST_BODY_SIZE_BYTES` to match**

These two constants are coupled (`config.zig:90` documents the coupling). Both must change together.

**Step 4: Update callers**

- `examples/gateway/controller/admin/handler.zig:39`: Update the response_buffer field size to match the new constant, or switch to a handler-appropriate size.
- Any echo/test handlers: switch to `.stream` if they need to handle payloads larger than the new constant.

**Step 5: Run all tests including integration**

Run: `zig build test 2>&1 | tail -20` and `zig build test-integration 2>&1 | tail -20`
Expected: All pass. If integration tests fail, the reduction target is too aggressive — increase until tests pass, then document the minimum safe value.

**Step 6: Commit**

```bash
git add serval-core/config.zig examples/
git commit -m "fix(config): reduce direct response/request buffer sizes

Reduces DIRECT_RESPONSE_BUFFER_SIZE_BYTES and DIRECT_REQUEST_BODY_SIZE_BYTES
from 128 MiB to [N] based on caller inventory. Eliminates memory DoS vector
where 100 concurrent onRequest connections consumed 12.8 GiB."
```

---

### Task 4: Fix TLS reload mutex panic (Finding 5)

**Problem:** `lockTlsReloadControlMutex()` panics the process after 1M spin iterations. Control-plane operations should return errors, not crash.

**Fix:** Return an error instead of panicking.

**Files:**
- Modify: `serval-server/h1/server.zig` — `lockTlsReloadControlMutex()` (lines 96-106) and its callers (lines 236, 249, 262, 272)

**Step 1: Change the function to return an error**

```zig
const TlsReloadLockError = error{TlsReloadLockContention};

fn lockTlsReloadControlMutex(mutex: *std.atomic.Mutex) TlsReloadLockError!void {
    assert(@intFromPtr(mutex) != 0);

    var attempts: u32 = 0;
    while (attempts < TLS_RELOAD_CONTROL_LOCK_MAX_ATTEMPTS) : (attempts += 1) {
        if (mutex.tryLock()) return;
        std.atomic.spinLoopHint();
    }

    return error.TlsReloadLockContention;
}
```

**Step 2: Update fallible callers to propagate the error**

`reloadServerTlsFromPemFiles` (line 236) and `activeServerTlsGeneration` (line 249) already return error unions. Change:
```zig
lockTlsReloadControlMutex(&self.tls_reload_control_mutex) catch return error.TlsReloadLockContention;
```
Add `TlsReloadLockContention` to `ReloadServerTlsError` and the generation query error set.

**Step 3: Handle void-returning callers**

`publishTlsCtxManager` (line 258) and `unpublishTlsCtxManager` (line 269) currently return `void`. These are internal setup/teardown functions called during server init/deinit — contention during startup is a configuration/ordering bug, not a runtime condition. Keep `@panic` for these two callers since they run exactly once at startup/shutdown and contention there indicates a logic error:

```zig
fn publishTlsCtxManager(self: *Self, manager: *ReloadableServerCtx) void {
    assert(@intFromPtr(self) != 0);
    assert(@intFromPtr(manager) != 0);

    lockTlsReloadControlMutex(&self.tls_reload_control_mutex) catch
        @panic("TLS context manager publish failed: lock contention during startup");
    defer self.tls_reload_control_mutex.unlock();

    assert(self.tls_ctx_manager_ptr == null);
    self.tls_ctx_manager_ptr = manager;
}

fn unpublishTlsCtxManager(self: *Self) void {
    assert(@intFromPtr(self) != 0);

    lockTlsReloadControlMutex(&self.tls_reload_control_mutex) catch
        @panic("TLS context manager unpublish failed: lock contention during shutdown");
    defer self.tls_reload_control_mutex.unlock();

    self.tls_ctx_manager_ptr = null;
}
```

This preserves the original severity for startup paths (contention there is a programming error) while fixing the runtime paths (reload/query) that must not crash.

**Step 3: Run tests**

Run: `zig build test 2>&1 | tail -20`
Expected: Existing reload tests should still pass — they test the happy path. The spin loop is unlikely to time out in tests.

**Step 4: Commit**

```bash
git add serval-server/h1/server.zig
git commit -m "fix(h1): return error on TLS reload lock contention instead of panicking

Control-plane operations (cert reload, generation query) were panicking
the entire process on mutex contention. Now returns TlsReloadLockContention
error so callers can handle gracefully."
```

---

### Task 5: Fix h2 body tracker silent overwrite (Finding 6)

**Problem:** `getOrInsertRequestBodyTracker()` overwrites an existing slot by modulo when the table is full, silently corrupting another stream's body accounting.

**Fix:** Return an error when the table is full. The caller (`startRequestBodyTracking` and `noteRequestData`) already return `Error`, so this propagates to the h2 connection error handling which sends GOAWAY.

**Files:**
- Modify: `serval-server/h2/runtime.zig` — `getOrInsertRequestBodyTracker()` (lines 519-534)

**Step 1: Write a test for the overflow case**

Check the existing tests in `runtime.zig` (lines 712+). Add a test that fills the tracker table and verifies the next insert fails:

```zig
test "getOrInsertRequestBodyTracker returns error when table is full" {
    var runtime = try Runtime.init();
    // Fill all tracker slots
    for (0..request_body_tracker_capacity) |i| {
        const stream_id: u32 = @intCast((i * 2) + 1); // odd stream IDs
        const tracker = try runtime.getOrInsertRequestBodyTracker(stream_id);
        try std.testing.expect(tracker.used);
        try std.testing.expectEqual(stream_id, tracker.stream_id);
    }
    // Next insert should fail
    const result = runtime.getOrInsertRequestBodyTracker(999);
    try std.testing.expectError(error.StreamProtocolError, result);
}
```

Note: `Runtime` requires `try Runtime.init()` because the `state` field (`ConnectionState`) has no default. Check whether `getOrInsertRequestBodyTracker` is private — if so, test through `startRequestBodyTracking`/`noteRequestData` which are the public callers.

**Step 2: Run test to verify it fails (currently overwrites instead of erroring)**

Run: `zig build test-h2 2>&1 | tail -20`
Expected: FAIL — the test expects an error but currently gets a silent overwrite.

**Step 3: Change `getOrInsertRequestBodyTracker` to return an error**

```zig
fn getOrInsertRequestBodyTracker(self: *Runtime, stream_id: u32) Error!*RequestBodyTracker {
    assert(@intFromPtr(self) != 0);
    assert(stream_id > 0);

    if (getRequestBodyTracker(self, stream_id)) |tracker| return tracker;

    for (self.request_body_trackers[0..]) |*tracker| {
        if (tracker.used) continue;
        tracker.* = .{ .used = true, .stream_id = stream_id };
        return tracker;
    }

    // Table full — fail closed. Caller sends RST_STREAM or GOAWAY.
    return error.StreamProtocolError;
}
```

**Step 4: Update callers**

`startRequestBodyTracking` (line 468) and `noteRequestData` (line 484) both call this function. They already return `Error!void`, so change:

```zig
// was: var tracker = getOrInsertRequestBodyTracker(self, stream_id);
// now:
var tracker = try getOrInsertRequestBodyTracker(self, stream_id);
```

**Step 5: Run tests**

Run: `zig build test-h2 2>&1 | tail -20`
Expected: All pass including new test.

**Step 6: Commit**

```bash
git add serval-server/h2/runtime.zig
git commit -m "fix(h2): fail closed when body tracker table is full

getOrInsertRequestBodyTracker was silently overwriting an existing
stream's tracker when the table was full (modulo collision). Now returns
StreamProtocolError, which propagates to RST_STREAM or GOAWAY."
```

---

### Task 6: Reduce hot-path page_allocator usage (Finding 4)

**Problem:** Multiple hot paths allocate per-request/per-connection on `page_allocator`: h2 bridge session pools (lines 1900, 1997), generic h2 client init (lines 394, 486, 1093), TCP runtime client init (line 236).

**Fix:** This is the lowest-priority item and the largest refactor. The `Client.init` takes an allocator parameter — the fix is to pass a connection-scoped or arena allocator instead of `page_allocator`. However, `Client` internals need auditing to ensure they don't hold allocator references beyond the call scope.

**Approach:** For now, fix the most impactful case — the bridge session pool allocations at lines 1900 and 1997, which allocate a full `H2UpstreamSessionPool` struct per bridge request. These can use a stack-local since the session pool is scoped to the bridge call.

**Files:**
- Modify: `serval-server/h1/server.zig` — bridge functions (~lines 1894, 1991)

**Step 1: Check `H2UpstreamSessionPool` size**

Before changing allocators, check the size of the struct to ensure it fits on the stack:

```zig
@compileLog(@sizeOf(serval_client.H2UpstreamSessionPool));
```

If it's small enough (< 64 KiB), use stack allocation. If large, use `FixedBufferAllocator` with a stack buffer.

**Step 2: Replace page_allocator.create with stack allocation for bridge sessions**

In `forwardH2cWithBridge` (line 1900):

```zig
// was:
// const bridge_sessions = std.heap.page_allocator.create(serval_client.H2UpstreamSessionPool) catch { ... };
// bridge_sessions.* = serval_client.H2UpstreamSessionPool.init();

// now:
var bridge_sessions_storage = serval_client.H2UpstreamSessionPool.init();
const bridge_sessions = &bridge_sessions_storage;
```

Remove the corresponding `defer std.heap.page_allocator.destroy(bridge_sessions)` — stack cleanup is automatic.

Same change in `forwardH2cUpgradeWithBridge` (line 1997).

**Step 3: Run tests**

Run: `zig build test 2>&1 | tail -20`
Expected: All pass.

**Step 4: Commit**

```bash
git add serval-server/h1/server.zig
git commit -m "perf(h1): stack-allocate h2 bridge session pools instead of page_allocator

Bridge session pools are scoped to a single bridge request — no need for
heap allocation. Eliminates two page_allocator round-trips per h2c bridge
request in the hot path."
```

---

### Task 7: Decompose monolithic request loop (Finding 7)

**Problem:** The request loop in `handleConnection` (lines 2605-3255, ~650 lines) mixes TLS/ALPN dispatch, h1 parsing, onRequest hook dispatch, streaming responses, h2c upgrade validation, WebSocket session management, selectUpstream action handling, and HTTP forwarding in one surface. Tests only cover reload plumbing and helpers, not the request-loop branches.

**Fix:** Extract the three largest self-contained blocks into named functions. Each extraction is a pure refactor — no behavior change. The control flow uses `continue` (next request), `return` (close connection), and fall-through, so extracted functions return a `LoopAction` enum.

**This task runs AFTER Tasks 1-6 so the desync fix is already in place.**

**Files:**
- Modify: `serval-server/h1/server.zig`

**Step 1: Define `LoopAction` return type**

Add above the `handleConnection` function:

```zig
/// Control flow signal from extracted request-handling sub-functions.
/// TigerStyle: Explicit enum replaces implicit continue/return/fall-through.
const LoopAction = enum {
    continue_loop,    // Advance to next request (was: continue)
    close_connection, // End the connection (was: return)
    fall_through,     // Continue to next phase in current request
};
```

**Step 2: Extract `handleOnRequestHook`**

Extract lines 2704-2865 (the `if (comptime has_on_request) { ... }` block) into:

```zig
/// Dispatch onRequest hook and handle send_response/reject/stream results.
/// Returns .fall_through if handler returns .continue_request (proceed to selectUpstream).
/// Returns .continue_loop or .close_connection for short-circuit responses.
fn handleOnRequestHook(
    handler: *Handler,
    ctx: *Context,
    parser: *const Parser,
    recv_buf: []const u8,
    buffer_offset: *usize,
    buffer_len: usize,
    response_buf: []u8,
    maybe_tls_ptr: ?*const TLSStream,
    io: *Io,
    stream: Io.net.Stream,
    metrics: *Metrics,
    tracer: *Tracer,
    span_handle: SpanHandle,
    request_count: u32,
    cfg: Config,
    connection_id: u64,
) LoopAction {
    // ... body extracted from the has_on_request block ...
    // Replace `continue` with `return .continue_loop`
    // Replace `return` (close) with `return .close_connection`
    // End of block (fall-through to selectUpstream) returns `.fall_through`
}
```

At the call site in the loop, replace the block with:

```zig
if (comptime has_on_request) {
    switch (handleOnRequestHook(
        handler, &ctx, &parser, recv_buf[0..], &buffer_offset,
        buffer_len, response_buf, maybe_tls_ptr, &io_mut, stream,
        metrics, tracer, span_handle, request_count, cfg, connection_id,
    )) {
        .close_connection => return,
        .continue_loop => continue,
        .fall_through => {},
    }
}
```

**Step 3: Run tests to verify no behavior change**

Run: `zig build test 2>&1 | tail -20`
Expected: All pass — pure refactor.

**Step 4: Extract `handleNativeWebSocket`**

Extract lines 2921-3070 (the `if (websocket_candidate) { ... if (comptime has_select_websocket) { ... } }` block before selectUpstream) into:

```zig
/// Handle native WebSocket upgrade if handler implements selectWebSocket.
/// Returns .close_connection if WebSocket session completes or is rejected.
/// Returns .fall_through if handler declines or no selectWebSocket hook.
fn handleNativeWebSocket(
    handler: *Handler,
    ctx: *Context,
    parser: *const Parser,
    recv_buf: []const u8,
    buffer_offset: usize,
    buffer_len: usize,
    maybe_tls_ptr: ?*const TLSStream,
    io: *Io,
    stream: Io.net.Stream,
    metrics: *Metrics,
    tracer: *Tracer,
    span_handle: SpanHandle,
    connection_id: u64,
) LoopAction {
    // ... body extracted from websocket_candidate block ...
    // .accept path ends with `return` → return .close_connection
    // .reject path ends with `return` → return .close_connection
    // .decline falls through → return .fall_through
}
```

Call site:

```zig
if (websocket_candidate) {
    serval_websocket.validateClientRequest(...) catch |err| { ... return; };
    if (comptime has_select_websocket) {
        switch (handleNativeWebSocket(
            handler, &ctx, &parser, recv_buf[0..], buffer_offset,
            buffer_len, maybe_tls_ptr, &io_mut, stream,
            metrics, tracer, span_handle, connection_id,
        )) {
            .close_connection => return,
            .fall_through => {},
            .continue_loop => continue,
        }
    }
}
```

**Step 5: Run tests**

Run: `zig build test 2>&1 | tail -20`
Expected: All pass.

**Step 6: Extract `resolveUpstreamAction`**

Extract lines 3076-3136 (the action union switch with `.forward`/`.reject`). This function must return `LoopAction` (not `?Upstream`) to preserve the three-way control flow from Task 1's desync fix — rejects with unconsumed bodies need `.close_connection`, not just "no upstream":

```zig
/// Resolve selectUpstream action, handling reject responses.
/// Returns .fall_through with upstream set on ctx when forwarding.
/// Returns .continue_loop for bodyless rejects (safe to reuse connection).
/// Returns .close_connection for rejects with unconsumed body (desync prevention).
fn resolveUpstreamAction(
    handler: *Handler,
    action_result: anytype,
    ctx: *Context,
    parser: *const Parser,
    maybe_tls_ptr: ?*const TLSStream,
    io: *Io,
    stream: Io.net.Stream,
    metrics: *Metrics,
    tracer: *Tracer,
    span_handle: SpanHandle,
    buffer_offset: *usize,
) LoopAction {
    if (comptime hooks.hasUpstreamAction(Handler)) {
        switch (action_result) {
            .forward => |up| {
                ctx.upstream = up;
                return .fall_through;
            },
            .reject => |rej| {
                // ... existing reject handling (response, metrics, logging, tracing) ...

                // Body not consumed by routing — close if body present (desync prevention).
                if (parser.body_framing != .none) return .close_connection;
                buffer_offset.* += parser.headers_end;
                return .continue_loop;
            },
        }
    } else {
        ctx.upstream = action_result;
        return .fall_through;
    }
}
```

Call site:

```zig
switch (resolveUpstreamAction(
    handler, action_result, &ctx, &parser,
    maybe_tls_ptr, &io_mut, stream, metrics, tracer,
    span_handle, &buffer_offset,
)) {
    .close_connection => return,
    .continue_loop => continue,
    .fall_through => {},
}
const upstream = ctx.upstream.?;
```

**Step 7: Run tests**

Run: `zig build test 2>&1 | tail -20`
Expected: All pass.

**Step 8: Add targeted tests for extracted functions**

Add tests that exercise the extracted functions directly. These test the branches that were previously untestable because they were buried in the monolithic loop:

```zig
test "handleOnRequestHook returns close_connection for reject with unconsumed body" {
    // Tests that the Task 1 desync fix works through the extracted function.
    // Setup: mock handler returning .reject, parser with body_framing = .chunked,
    //        body_reader with total_bytes_read = 0.
    // Assert: returns .close_connection (not .continue_loop).
}

test "handleOnRequestHook returns continue_loop for reject with no body" {
    // Setup: mock handler returning .reject, parser with body_framing = .none.
    // Assert: returns .continue_loop.
}

test "resolveUpstreamAction returns close_connection for reject with body" {
    // Tests that the three-way LoopAction correctly prevents desync.
    // Setup: action_result = .{ .reject = ... }, parser.body_framing = .chunked.
    // Assert: returns .close_connection.
}

test "resolveUpstreamAction returns continue_loop for reject without body" {
    // Setup: action_result = .{ .reject = ... }, parser.body_framing = .none.
    // Assert: returns .continue_loop.
}
```

Note: The exact test setup depends on what `Handler`, `Parser`, `Metrics`, and `Tracer` types need for construction. Follow the existing `TestHandler` pattern at line 3516. If the extracted functions require too much setup infrastructure, add a comment documenting the coverage gap instead of writing brittle tests.

**Step 9: Run full test suite**

Run: `zig build test 2>&1 | tail -20`
Expected: All pass.

**Step 10: Commit**

```bash
git add serval-server/h1/server.zig
git commit -m "refactor(h1): extract request loop concerns into named functions

Decompose the 650-line handleConnection request loop into:
- handleOnRequestHook: onRequest dispatch + send_response/reject/stream
- handleNativeWebSocket: WebSocket upgrade negotiation + session lifecycle
- resolveUpstreamAction: action-style routing with reject handling

All three return LoopAction enum for explicit three-way control flow
(continue_loop / close_connection / fall_through), preserving the
desync-prevention semantics from Task 1."
```
