# Proxy Verification Findings Fixes

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 4 verified findings from proxy code review plus fiber-safety gap: poisoned pool connections on body stream failure, silent truncation of close-delimited responses, blocking header I/O in fiber context, dead timeout config, and TigerStyle drift.

**Architecture:** Each fix is scoped to 1-3 files with minimal blast radius. Finding 1 tracks body stream success and passes it to `pool.release()`. Task 2 makes the h1 response header I/O fiber-safe by using `io.vtable.netRead`/`netWrite` for plain sockets (same pattern as tunnel.zig `ioReadSome`/`ioWriteAll`), while TLS falls back to blocking (TLS can't yield mid-handshake). Task 3 threads `is_head_request: bool` into `forwardResponse()` and rejects close-delimited responses fail-closed. Finding 3 wires `ConnectConfig.timeout_ns` through to `client.connectWithTimeout()`. Finding 5 fixes `catch {}` → `catch |err|` with debug logging and `std.time` → `time` (from core). Each task includes targeted regression tests.

**Task ordering:** Task 2 (fiber-safe I/O) must land before Task 3 (close-delimited) since Task 3's tests use `std.Io.Evented` with socketpairs, which requires fiber-safe header reads.

**Tech Stack:** Zig 0.16, serval-proxy modules, `zig build test` (covers all inline tests via `serval-proxy/mod.zig` test block)

**Validation command:** `zig build test` (NOT `test-proxy` — that only covers h2 primitives from `build.zig:672`, not forwarder/connect/h1/tunnel)

---

### Task 1: Fix pool release on body stream failure (Finding 1 — High)

**Problem:** `serval-proxy/forwarder.zig:1073-1086` — when `body_group.await()` or `body_ctx.result` fails, the error is only debug-logged. Line 1086 unconditionally calls `self.pool.release(upstream.idx, mutable_conn, true)`, marking the connection healthy. A failed body stream (client disconnect, partial upload, upstream write error) leaves a poisoned connection in the pool for the next request.

**Fix:** Track body stream success in a `body_stream_ok` flag and pass it to `pool.release()`.

**Files:**
- Modify: `serval-proxy/forwarder.zig:1070-1086`

**Step 1: Replace the body-await + release block**

Find this block at `forwarder.zig:1070-1086`:

```zig
            // Wait for body streaming to finish before releasing the connection.
            // Must happen before pool.release so the background task no longer
            // holds references to mutable_conn.
            body_group.await(io) catch |err| {
                debugLog("send: body group await failed err={s}", .{@errorName(err)});
            };
            if (has_body) {
                _ = body_ctx.result catch |err| {
                    debugLog("send: body stream error={s}", .{@errorName(err)});
                };
            }

            // RFC 9112 recommends checking upstream's Connection: close header and not
            // pooling if present. Current implementation relies on StaleConnection retry
            // (Pingora-style). Consider adding explicit header check if retry overhead
            // becomes measurable.
            self.pool.release(upstream.idx, mutable_conn, true);
```

Replace with:

```zig
            // Wait for body streaming to finish before releasing the connection.
            // Must happen before pool.release so the background task no longer
            // holds references to mutable_conn.
            var body_stream_ok = true;
            body_group.await(io) catch |err| {
                debugLog("send: body group await failed err={s}", .{@errorName(err)});
                body_stream_ok = false;
            };
            if (has_body) {
                _ = body_ctx.result catch |err| {
                    debugLog("send: body stream error={s}", .{@errorName(err)});
                    body_stream_ok = false;
                };
            }

            // Release connection to pool. Mark unhealthy if body streaming failed
            // (client disconnect, partial upload, upstream write error) to prevent
            // poisoned connections from being reused. S2/S4: fail-safe pool hygiene.
            // RFC 9112 recommends checking upstream's Connection: close header and not
            // pooling if present. Current implementation relies on StaleConnection retry
            // (Pingora-style). Consider adding explicit header check if retry overhead
            // becomes measurable.
            self.pool.release(upstream.idx, mutable_conn, body_stream_ok);
```

**Step 2: Verify existing test coverage for unhealthy release**

The `SimplePool.release(healthy=false)` path is already tested at `serval-pool/pool.zig:1185-1187`:

```zig
// Release as unhealthy (still requires correct sentinel)
pool.release(0, conn3.?, false);
try std.testing.expectEqual(@as(u8, 0), pool.counts[0]); // Not pooled (unhealthy)
```

That test uses a real connection from `pool.acquire()`, which survives the `close()` call on the unhealthy path (`pool.zig:335`). No new pool-level test is needed — the pool already handles `healthy=false` correctly. The bug was in the forwarder unconditionally passing `true`, which is a caller-level issue fixed by the code change above.

**Step 3: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass

**Step 4: Commit**

```bash
git add serval-proxy/forwarder.zig
git commit -m "fix(proxy): mark connection unhealthy on body stream failure

pool.release() was unconditionally called with healthy=true after body
streaming. When body streaming fails (client disconnect, partial upload,
upstream write error), the connection is now marked unhealthy to prevent
poisoned connections from being reused by subsequent requests."
```

---

### Task 2: Make h1 header I/O fiber-safe (New finding — High)

**Problem:** `readHeaderBytesWithPreread` (response.zig:349) uses blocking `socket.read()` and `sendBuffer` (request.zig:70) uses blocking `socket.write()` via `sendBufferToSocket`. Both discard the `io` parameter. In a fiber system, blocking reads/writes stall the scheduler — no other fibers make progress while waiting on a slow upstream's headers. The body forwarding path was already migrated to fiber-safe I/O (body.zig:431 `forwardBodyCopyFiber`), but the header paths were not.

**Fix:** Follow the established pattern from `tunnel.zig:388` (`ioReadSome`) and `tunnel.zig:411` (`ioWriteAll`):
- Plain sockets: use `io.vtable.netRead`/`io.vtable.netWrite` (fiber-safe, scheduler can multiplex)
- TLS sockets: blocking `socket.read()`/`socket.write()` (TLS can't yield mid-handshake)

**Scope:** `readHeaderBytesWithPreread` and `receiveHeaders` (response.zig), `sendBuffer` (request.zig). For `receiveHeaders`, instead of making serval-client's `readHeaderBytes` fiber-safe (wider blast radius), we redirect it to the local `readHeaderBytesWithPreread` with `pre_read_bytes=0` — identical behavior, already fiber-safe.

**Files:**
- Modify: `serval-proxy/h1/response.zig:246-271,284,314-366` — fiber-safe reads, redirect receiveHeaders
- Modify: `serval-proxy/h1/request.zig:69-81` — fiber-safe writes

**Step 1: Add fiber-safe read helper to response.zig**

Add after the existing `mapSocketErrorLocal` function (after line ~383):

```zig
/// Fiber-safe socket read. Plain sockets use io.vtable.netRead so the fiber
/// scheduler can multiplex; TLS falls back to blocking (can't yield mid-handshake).
/// Follows tunnel.zig ioReadSome pattern.
fn readFiberSafe(socket: *Socket, buf: []u8, io: Io) ResponseError!u32 {
    assert(buf.len > 0);
    return switch (socket.*) {
        .plain => |plain| {
            var read_bufs: [1][]u8 = .{buf};
            const n = io.vtable.netRead(io.userdata, plain.fd, &read_bufs) catch {
                return error.RecvFailed;
            };
            return @intCast(n);
        },
        .tls => socket.read(buf) catch |err| {
            return mapSocketErrorLocal(err);
        },
    };
}
```

**Step 2: Thread `io` through `readHeaderBytesWithPreread` and use fiber-safe reads**

Change the function signature at response.zig:314:

```zig
fn readHeaderBytesWithPreread(
    socket: *Socket,
    header_buf: *[config.MAX_HEADER_SIZE_BYTES]u8,
    pre_read_bytes: usize,
    io: Io,
) ResponseError!HeaderBytesResult {
```

Replace the read at line 348-351:

```zig
        // Read more data
        const remaining_buf = header_buf[total_read..];
        const bytes_read = socket.read(remaining_buf) catch |err| {
            return mapSocketErrorLocal(err);
        };
```

With:

```zig
        // Read more data (fiber-safe for plain sockets).
        const remaining_buf = header_buf[total_read..];
        const bytes_read = readFiberSafe(socket, remaining_buf, io) catch |err| {
            return err;
        };
```

**Step 3: Update `receiveHeadersWithPreread` to pass `io` through**

At response.zig:284, replace:

```zig
    _ = io; // Unused - Socket handles I/O internally
```

With nothing (remove the line). Then update the call at line 293:

```zig
    const result = readHeaderBytesWithPreread(&conn.socket, buffer, pre_read_bytes) catch |err| {
```

To:

```zig
    const result = readHeaderBytesWithPreread(&conn.socket, buffer, pre_read_bytes, io) catch |err| {
```

**Step 4: Redirect `receiveHeaders` to fiber-safe path**

`receiveHeaders` (response.zig:246-271) currently calls serval-client's `readHeaderBytes` (blocking). Instead of making that fiber-safe (wider blast radius), redirect to the now-fiber-safe `readHeaderBytesWithPreread` with `pre_read_bytes=0`.

Replace the body of `receiveHeaders` at response.zig:246-271:

```zig
pub fn receiveHeaders(
    conn: *Connection,
    io: Io,
    buffer: *[config.MAX_HEADER_SIZE_BYTES]u8,
    is_pooled: bool,
) ForwardError!HeadersResult {
    _ = io; // Unused - Socket handles I/O internally
    // Precondition: socket fd must be valid.
    assert(conn.get_fd() >= 0);
    // Precondition: buffer is provided (not null via pointer).
    assert(buffer.len == config.MAX_HEADER_SIZE_BYTES);

    // Delegate to serval-client for header reading.
    // TigerStyle: Reuse code from serval-client, handle error mapping locally.
    const result = readHeaderBytes(&conn.socket, buffer) catch |err| {
        return mapResponseErrorToForwardError(err, is_pooled);
    };

    // S2: Postcondition - header_end is within total_bytes
    assert(result.header_end <= result.total_bytes);

    return .{
        .header_len = @intCast(result.total_bytes),
        .header_end = @intCast(result.header_end),
    };
}
```

With:

```zig
pub fn receiveHeaders(
    conn: *Connection,
    io: Io,
    buffer: *[config.MAX_HEADER_SIZE_BYTES]u8,
    is_pooled: bool,
) ForwardError!HeadersResult {
    // Delegate to fiber-safe readHeaderBytesWithPreread with pre_read_bytes=0.
    // This avoids the serval-client readHeaderBytes path (blocking socket.read).
    return receiveHeadersWithPreread(conn, io, buffer, is_pooled, 0);
}
```

**Step 5: Make `sendBuffer` fiber-safe in request.zig**

Replace the entire `sendBuffer` function at request.zig:69-81:

```zig
pub fn sendBuffer(conn: *Connection, io: Io, data: []const u8) ForwardError!void {
    _ = io; // Unused - Socket handles I/O internally
    assert(data.len > 0); // S1: precondition - data must not be empty

    // Delegate to serval-client's sendBuffer, mapping errors
    client_request.sendBufferToSocket(&conn.socket, data) catch |err| {
        return switch (err) {
            client_request.ClientError.SendFailed => ForwardError.SendFailed,
            client_request.ClientError.SendTimeout => ForwardError.SendFailed,
            client_request.ClientError.BufferTooSmall => ForwardError.SendFailed,
        };
    };
}
```

With:

```zig
/// Send buffer to connection using fiber-safe I/O.
/// Plain sockets use io.vtable.netWrite so the fiber scheduler can multiplex;
/// TLS falls back to blocking via serval-client's sendBufferToSocket.
/// Follows tunnel.zig ioWriteAll pattern.
/// TigerStyle S3: Bounded write loop with MAX_WRITE_ITERATIONS.
pub fn sendBuffer(conn: *Connection, io: Io, data: []const u8) ForwardError!void {
    assert(data.len > 0); // S1: precondition - data must not be empty

    switch (conn.socket) {
        .plain => |plain| {
            var sent: usize = 0;
            var iterations: u32 = 0;
            // S3: Bounded loop — same guard as serval-client sendBufferToSocket.
            while (sent < data.len and iterations < client_request.MAX_WRITE_ITERATIONS) : (iterations += 1) {
                const pending = data[sent..];
                const write_slices = [_][]const u8{pending};
                const n = io.vtable.netWrite(io.userdata, plain.fd, &.{}, &write_slices, 1) catch {
                    return ForwardError.SendFailed;
                };
                if (n == 0) return ForwardError.SendFailed;
                sent += n;
            }
            if (sent < data.len) return ForwardError.SendFailed;
        },
        .tls => {
            // TLS can't yield mid-handshake; use blocking path.
            client_request.sendBufferToSocket(&conn.socket, data) catch |err| {
                return switch (err) {
                    client_request.ClientError.SendFailed => ForwardError.SendFailed,
                    client_request.ClientError.SendTimeout => ForwardError.SendFailed,
                    client_request.ClientError.BufferTooSmall => ForwardError.SendFailed,
                };
            };
        },
    }
}
```

**Step 6: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass. Existing tunnel.zig tests use `std.Io.Evented` with socketpairs and validate the `io.vtable.netRead`/`netWrite` pattern.

**Step 7: Commit**

```bash
git add serval-proxy/h1/response.zig serval-proxy/h1/request.zig
git commit -m "fix(proxy/h1): make header I/O fiber-safe for plain sockets

readHeaderBytesWithPreread, receiveHeaders, and sendBuffer previously
used blocking socket.read()/socket.write() and discarded the io
parameter. In a fiber system this stalls the scheduler while waiting on
slow upstreams.

Now uses io.vtable.netRead/netWrite for plain sockets (fiber-safe),
with TLS falling back to blocking (can't yield mid-handshake). Follows
the established pattern from tunnel.zig ioReadSome/ioWriteAll.
receiveHeaders redirected to fiber-safe readHeaderBytesWithPreread."
```

---

### Task 3: Reject close-delimited responses fail-closed (Finding 2 — High)

**Problem:** `serval-proxy/h1/response.zig:204-227` — the body forwarding only handles chunked and Content-Length. The else branch silently falls through for ALL other cases, including close-delimited responses where body bytes may not yet have arrived (pre_read_body.len == 0 is not proof of no body). Without request-method context, `forwardResponse()` cannot distinguish HEAD (no body) from close-delimited (body exists, never read).

**Fix:** Two changes:
1. Thread `is_head_request: bool` into `forwardResponse()` from the caller (which has `request.method`).
2. In the else branch: if HEAD, no body expected — pass through. If not HEAD and status expects a body (not 204/304), return `InvalidResponse` fail-closed. This rejects all close-delimited responses rather than silently truncating them.

**Files:**
- Modify: `serval-proxy/h1/response.zig:118-127,224-227` — add parameter, add rejection logic
- Modify: `serval-proxy/forwarder.zig:1054` — pass `request.method == .HEAD` at call site
- Modify: `serval-proxy/forwarder.zig:41` — import is already `const forwardResponse = h1.forwardResponse;`, no change needed

**Step 1: Add `is_head_request` parameter to `forwardResponse`**

Find the function signature at `h1/response.zig:118-125`:

```zig
pub fn forwardResponse(
    io: Io,
    upstream_conn: *Connection,
    client_stream: Io.net.Stream,
    upstream_socket: *Socket,
    client_socket: *Socket,
    is_pooled: bool,
) ForwardError!ForwardResult {
```

Replace with:

```zig
pub fn forwardResponse(
    io: Io,
    upstream_conn: *Connection,
    client_stream: Io.net.Stream,
    upstream_socket: *Socket,
    client_socket: *Socket,
    is_pooled: bool,
    is_head_request: bool,
) ForwardError!ForwardResult {
```

**Step 2: Replace the else branch with fail-closed detection**

Find this block at `h1/response.zig:224-227`:

```zig
    }
    // else: No body (e.g., 204, 304) or connection-close semantics.
    // Connection-close without Content-Length or chunked is unsupported
    // for now (would require read-until-EOF which complicates pooling).
```

Replace with:

```zig
    } else if (is_head_request or status == 204 or status == 304) {
        // No body expected: HEAD responses have no body regardless of headers;
        // 204/304 have no body by spec (RFC 9110 §6.4.1, §15.4.5).
        debugLog("recv: no body expected (head={} status={d})", .{ is_head_request, status });
    } else {
        // Close-delimited response: no Content-Length, not chunked, not HEAD,
        // status expects a body. RFC 9112 §6.3 says the body is terminated by
        // connection close — but we cannot forward this without read-until-EOF
        // (which prevents connection reuse and has no bounded size). Reject
        // fail-closed to prevent silent truncation. C1/C4/C5.
        debugLog("recv: close-delimited response rejected status={d} pre_read={d}", .{ status, pre_read_body.len });
        return ForwardError.InvalidResponse;
    }
```

**Step 3: Update the call site in forwarder.zig**

Find the call at `forwarder.zig:1054`:

```zig
            var result = forwardResponse(io, &mutable_conn, client_stream, &mutable_conn.socket, &client_socket, is_pooled) catch |err| {
```

Replace with:

```zig
            const is_head = request.method == .HEAD;
            var result = forwardResponse(io, &mutable_conn, client_stream, &mutable_conn.socket, &client_socket, is_pooled, is_head) catch |err| {
```

**Step 4: Add socket-backed regression tests that call forwardResponse directly**

These tests use UNIX socketpairs with `std.Io.Evented` to exercise `forwardResponse()`
end-to-end with fiber-safe I/O (Task 2 prerequisite). This follows the established
test pattern from `tunnel.zig:559`.

Add these tests at end of `serval-proxy/h1/response.zig` test section:

```zig
// -----------------------------------------------------------------------------
// Socket-backed forwardResponse tests
// Regression: forwardResponse previously silently dropped body bytes for
// responses without Content-Length or chunked encoding.
// Uses std.Io.Evented with socketpairs for fiber-safe I/O (tunnel.zig pattern).
// -----------------------------------------------------------------------------

const posix = std.posix;

fn writeAllToFd(fd: i32, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        written += try posix.write(fd, data[written..]);
    }
}

test "forwardResponse: non-HEAD unframed 200 returns InvalidResponse" {
    // Upstream sends 200 OK with no Content-Length and no chunked encoding.
    // For a non-HEAD request, this is a close-delimited response that the
    // proxy cannot safely forward. Must return InvalidResponse.
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();
    const io = evented.io();

    const upstream_pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(upstream_pair[0]);
    defer posix.close(upstream_pair[1]);

    const client_pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(client_pair[0]);
    defer posix.close(client_pair[1]);

    // Write an unframed 200 response to the "upstream" end.
    const response_data = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    try writeAllToFd(upstream_pair[1], response_data);

    // Set up Connection + Socket wrapping the read end of upstream pair.
    var upstream_socket: Socket = .{ .plain = .{ .fd = upstream_pair[0] } };
    var upstream_conn = Connection{ .socket = upstream_socket };

    // Client socket (receives forwarded headers).
    var client_socket: Socket = .{ .plain = .{ .fd = client_pair[1] } };

    // client_stream is unused by forwardResponse (line 126: _ = client_stream).
    const client_stream: Io.net.Stream = undefined;

    const result = forwardResponse(io, &upstream_conn, client_stream, &upstream_socket, &client_socket, false, false);
    try testing.expectError(ForwardError.InvalidResponse, result);
}

test "forwardResponse: HEAD unframed 200 succeeds with zero body" {
    // HEAD response to a 200: no body expected even without Content-Length.
    // forwardResponse must return success with 0 body bytes.
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();
    const io = evented.io();

    const upstream_pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(upstream_pair[0]);
    defer posix.close(upstream_pair[1]);

    const client_pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(client_pair[0]);
    defer posix.close(client_pair[1]);

    const response_data = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    try writeAllToFd(upstream_pair[1], response_data);

    var upstream_socket: Socket = .{ .plain = .{ .fd = upstream_pair[0] } };
    var upstream_conn = Connection{ .socket = upstream_socket };
    var client_socket: Socket = .{ .plain = .{ .fd = client_pair[1] } };
    const client_stream: Io.net.Stream = undefined;

    // is_head_request=true: should succeed
    const result = try forwardResponse(io, &upstream_conn, client_stream, &upstream_socket, &client_socket, false, true);
    try testing.expectEqual(@as(u16, 200), result.status);
    // Headers forwarded but no body bytes
    const header_len = std.mem.indexOf(u8, response_data, "\r\n\r\n").? + 4;
    try testing.expectEqual(@as(u64, header_len), result.response_bytes);
}

test "forwardResponse: 204 without framing succeeds (no body by spec)" {
    // 204 No Content never has a body, regardless of HEAD or framing.
    var evented: std.Io.Evented = undefined;
    try evented.init(std.testing.allocator, .{ .thread_limit = 0 });
    defer evented.deinit();
    const io = evented.io();

    const upstream_pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(upstream_pair[0]);
    defer posix.close(upstream_pair[1]);

    const client_pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(client_pair[0]);
    defer posix.close(client_pair[1]);

    const response_data = "HTTP/1.1 204 No Content\r\n\r\n";
    try writeAllToFd(upstream_pair[1], response_data);

    var upstream_socket: Socket = .{ .plain = .{ .fd = upstream_pair[0] } };
    var upstream_conn = Connection{ .socket = upstream_socket };
    var client_socket: Socket = .{ .plain = .{ .fd = client_pair[1] } };
    const client_stream: Io.net.Stream = undefined;

    // is_head_request=false: 204 should still succeed (no body by spec)
    const result = try forwardResponse(io, &upstream_conn, client_stream, &upstream_socket, &client_socket, false, false);
    try testing.expectEqual(@as(u16, 204), result.status);
}
```

**Step 5: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass. The three new tests exercise forwardResponse directly:
- non-HEAD + unframed 200 → `ForwardError.InvalidResponse`
- HEAD + unframed 200 → success, 0 body bytes
- 204 without framing → success (no body by spec)

**Step 6: Commit**

```bash
git add serval-proxy/h1/response.zig serval-proxy/forwarder.zig
git commit -m "fix(proxy/h1): reject close-delimited responses fail-closed

Thread is_head_request through forwardResponse() so it can distinguish
HEAD (no body) from close-delimited (body exists but unframed). Any
body-bearing response (not HEAD, not 204/304) without Content-Length or
chunked encoding is now rejected with InvalidResponse instead of
silently dropping the body. Previously, even when pre_read_body was
empty, later body bytes would never be read.

Socket-backed regression tests call forwardResponse() directly and
assert the three key behaviors: non-HEAD unframed rejection, HEAD
pass-through, and 204 pass-through."
```

---

### Task 4: Wire ConnectConfig.timeout_ns to connectWithTimeout (Finding 3 — Medium)

**Problem:** `serval-proxy/connect.zig:124` asserts `cfg.timeout_ns > 0`, but line 139 calls `client.connect()` which hardcodes `.none` timeout (`serval-client/client.zig:187`). The timeout-aware `connectWithTimeout()` exists at `client.zig:192` but is never called from the proxy.

**Fix:** Convert `cfg.timeout_ns` to `Io.Timeout` and call `connectWithTimeout` instead of `connect`. Use the same `Io.Duration.fromNanoseconds` pattern as `serval-server/h2/server.zig:2358-2364`.

**Files:**
- Modify: `serval-proxy/connect.zig:138-142`

**Step 1: Replace the client.connect call**

Find this block at `connect.zig:138-142`:

```zig
    // Connect using serval-client
    const client_result = client.connect(upstream.*, io) catch |err| {
        debugLog("connect: FAILED err={s}", .{@errorName(err)});
        return mapClientError(err);
    };
```

Replace with:

```zig
    // Connect using serval-client with configured timeout.
    // S7/C3: Honor the timeout_ns that callers configured and we asserted non-zero.
    const connect_timeout: Io.Timeout = .{ .duration = .{
        .raw = Io.Duration.fromNanoseconds(@intCast(cfg.timeout_ns)),
        .clock = .awake,
    } };
    const client_result = client.connectWithTimeout(upstream.*, io, connect_timeout) catch |err| {
        debugLog("connect: FAILED err={s}", .{@errorName(err)});
        return mapClientError(err);
    };
```

**Step 2: Add compile-time guard test for timeout conversion**

This test verifies the Io.Timeout construction compiles and produces a non-none
value. It is a compile-time guard, NOT a proof that `connectWithTimeout` is called
at runtime — that assurance comes from the code change itself and code review.
An integration test exercising the actual timeout behavior against a slow upstream
is deferred to the integration test suite.

Add at end of `serval-proxy/connect.zig` test section (find or create the test block):

```zig
test "ConnectConfig: timeout_ns converts to non-none Io.Timeout (compile-time guard)" {
    // Guard: if the Io.Timeout construction pattern changes or breaks,
    // this test will fail at compile time or assertion. It does NOT prove
    // that connectUpstream calls connectWithTimeout — that is verified by
    // code review of the connect.zig change.
    const cfg = ConnectConfig{
        .timeout_ns = 5_000_000_000, // 5 seconds
        .verify_upstream_tls = false,
    };
    assert(cfg.timeout_ns > 0);

    const timeout: Io.Timeout = .{ .duration = .{
        .raw = Io.Duration.fromNanoseconds(@intCast(cfg.timeout_ns)),
        .clock = .awake,
    } };
    try std.testing.expect(timeout != .none);
}
```

**Step 3: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass

**Step 4: Commit**

```bash
git add serval-proxy/connect.zig
git commit -m "fix(proxy): wire ConnectConfig.timeout_ns to connectWithTimeout

connect.zig asserted timeout_ns > 0 but called client.connect() which
hardcoded .none timeout. Now converts timeout_ns to Io.Timeout and
calls connectWithTimeout, honoring the operator-configured bound.

Includes compile-time guard test for the timeout conversion pattern."
```

---

### Task 5: Fix TigerStyle drift — catch {} and std.time (Finding 5 — Low)

**Problem A:** `serval-proxy/tunnel.zig:220` and `:229` use `catch {` which discards the error value. TigerStyle requires capturing errors for debuggability. The scheduler/spawn failure is collapsed into a generic `.upstream_error` with no visibility into the actual error.

**Problem B:** `serval-proxy/h2/bridge.zig:80-83` uses `std.time.ns_per_ms` and `std.time.ns_per_s` directly despite importing `time = core.time` at line 17. TigerStyle: use the project's time module consistently.

**Files:**
- Modify: `serval-proxy/tunnel.zig:220,229`
- Modify: `serval-proxy/h2/bridge.zig:80-83`

**Step 1: Fix tunnel.zig first catch block**

Find the first catch block at `tunnel.zig:220`:

```zig
    }) catch {
        shared.finishTermination(.upstream_error, io);
        return shared.snapshot(io);
    };
```

Replace with:

```zig
    }) catch |err| {
        debugLog("tunnel: relay fiber spawn failed err={s}", .{@errorName(err)});
        shared.finishTermination(.upstream_error, io);
        return shared.snapshot(io);
    };
```

**Step 2: Fix tunnel.zig second catch block**

Find the second catch block at `tunnel.zig:229`:

```zig
        group.concurrent(io, idleWatchdog, .{ &shared, &group, io, idle_timeout_ns, check_interval_ms }) catch {
            shared.finishTermination(.upstream_error, io);
            return shared.snapshot(io);
        };
```

Replace with:

```zig
        group.concurrent(io, idleWatchdog, .{ &shared, &group, io, idle_timeout_ns, check_interval_ms }) catch |err| {
            debugLog("tunnel: idle watchdog spawn failed err={s}", .{@errorName(err)});
            shared.finishTermination(.upstream_error, io);
            return shared.snapshot(io);
        };
```

**Step 3: Fix bridge.zig std.time references**

Find at `bridge.zig:77-83`:

```zig
fn shouldLogIdleWait(since_last_action_ns: u64) bool {
    // Reduce WouldBlock log flood while preserving periodic visibility.
    // Log aggressively during first 250ms, then roughly once per second.
    if (since_last_action_ns <= 250 * std.time.ns_per_ms) return true;
    const second_ns: u64 = std.time.ns_per_s;
    const phase_ns = since_last_action_ns % second_ns;
    return phase_ns <= 50 * std.time.ns_per_ms;
}
```

Replace with:

```zig
fn shouldLogIdleWait(since_last_action_ns: u64) bool {
    // Reduce WouldBlock log flood while preserving periodic visibility.
    // Log aggressively during first 250ms, then roughly once per second.
    if (since_last_action_ns <= 250 * time.ns_per_ms) return true;
    const second_ns: u64 = time.ns_per_s;
    const phase_ns = since_last_action_ns % second_ns;
    return phase_ns <= 50 * time.ns_per_ms;
}
```

**Step 4: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass

**Step 5: Commit**

```bash
git add serval-proxy/tunnel.zig serval-proxy/h2/bridge.zig
git commit -m "style(proxy): fix TigerStyle drift in tunnel and bridge

tunnel.zig: capture scheduler errors in catch blocks and log them
instead of silently discarding with catch {}.
bridge.zig: use serval-core time constants instead of std.time."
```
