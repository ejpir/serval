# Client & H2 Bridge Findings Fixes

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 4 findings from client/proxy code review: silent connect timeout fallback, fiber-unsafe H2 bridge receive path, unenforced `verify_tls` in client connect, and README overstating async behavior.

**Architecture:** Finding 1 makes the connect timeout fallback a behavioral signal, not just a log: `ConnectResult` gains a `connect_timeout_honored: bool` field so callers can enforce fail-fast policy at the right level (io_uring currently doesn't support connect-time timeouts — `Uring.zig:5172` — and `address.connect` creates the socket internally, so we cannot set socket-level timeouts before connect). Finding 2 threads `Io` through the H2 bridge `receiveForUpstream` path so reads use the fiber-safe `io.vtable.netRead` instead of blocking `plain.read`. Finding 4 enforces `verify_tls` per-connection via `SSL_set_verify` on the SSL object (NOT the shared `SSL_CTX`), set between `SSL_new` and `SSL_connect` in `TLSStream.initClient`. Finding 5 corrects the README to clarify which paths are async vs blocking.

**Note:** Finding 3 (HTTP/1 timeout semantics are weak) is already addressed by the existing plan `2026-03-26-proxy-findings-fixes.md` Task 2 (fiber-safe H1 I/O), which replaces blocking `socket.read()`/`socket.write()` with `io.vtable.netRead`/`netWrite` for plain sockets.

**Task ordering:** Tasks 1, 3, and 4 are independent and can land in any order. Task 2 is an atomic unit — the signature change in `bridge.zig` and all caller updates must land in the same commit for build correctness.

**Tech Stack:** Zig 0.16, serval-client, serval-proxy, serval-tls, serval-socket, `zig build test`

**Validation command:** `zig build test`

---

### Task 1: Surface connect timeout degradation as behavioral signal (Finding 1 — High)

**Problem:** `serval-client/client.zig:413` catches `OptionUnsupported` when the caller requested a connect timeout and silently retries with `.timeout = .none`. This degrades a bounded connect into an unbounded one with zero visibility. Under failure conditions (firewalled ports), connections can hang for the kernel's full TCP SYN retry window (~2 minutes on Linux default `tcp_syn_retries=6`).

**Constraint:** `address.connect(io, ...)` from `std.Io` creates the socket internally — we cannot set `TCP_SYNCNT` or other socket options before `connect()`. The io_uring backend explicitly rejects connect-time timeouts at `std/Io/Uring.zig:5172`. The proper kernel-level fix (io_uring `IORING_OP_LINK_TIMEOUT`) is tracked in `docs/plans/2026-03-16-uring-networking-pr-quality.md:401`.

**Fix:** Two changes:
1. Add `connect_timeout_honored: bool` to `ConnectResult` so callers get a behavioral signal — they can enforce fail-fast or SLO policy at the right level.
2. Log a warning in the fallback path for operator visibility.

This makes the degradation observable AND actionable. Callers that need bounded connect semantics can check the flag and reject the connection. Callers that tolerate degradation (development, non-SLO paths) continue working.

**Files:**
- Modify: `serval-client/client.zig:87-98` — add field to `ConnectResult`
- Modify: `serval-client/client.zig:192-230` — set field in `connectWithTimeout`
- Modify: `serval-client/client.zig:404-429` — refactor `tcpConnect` to return degradation info
- Modify: `serval-proxy/connect.zig:138-146` — propagate to proxy ConnectResult

**Step 1: Add `connect_timeout_honored` field to `ConnectResult`**

Find the struct at `client.zig:87-98`:

```zig
pub const ConnectResult = struct {
    /// Connection to upstream (caller must release to pool or close).
    conn: Connection,
    /// Duration of DNS resolution in nanoseconds (0 if cached or IP address).
    dns_duration_ns: u64,
    /// Duration of TCP connect in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// Duration of TLS handshake in nanoseconds (0 if plaintext).
    tls_handshake_duration_ns: u64,
    /// Local port of the connection.
    local_port: u16,
};
```

Replace with:

```zig
pub const ConnectResult = struct {
    /// Connection to upstream (caller must release to pool or close).
    conn: Connection,
    /// Duration of DNS resolution in nanoseconds (0 if cached or IP address).
    dns_duration_ns: u64,
    /// Duration of TCP connect in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// Duration of TLS handshake in nanoseconds (0 if plaintext).
    tls_handshake_duration_ns: u64,
    /// Local port of the connection.
    local_port: u16,
    /// Whether the caller's connect timeout was honored by the IO backend.
    /// False when the backend (e.g., io_uring) does not support connect-time
    /// timeouts and the connect fell back to kernel-default SYN retry bounds
    /// (~2min on Linux). Callers needing bounded connect semantics should
    /// check this flag and reject the connection if false.
    connect_timeout_honored: bool,
};
```

**Step 2: Refactor `tcpConnect` to return degradation info**

Replace the `tcpConnect` function at `client.zig:404-429`:

```zig
fn tcpConnect(address: Io.net.IpAddress, io: Io, connect_timeout: Io.Timeout) !i32 {
    const stream = address.connect(io, .{
        .mode = .stream,
        .timeout = connect_timeout,
    }) catch |err| {
        if (err == error.OptionUnsupported and connect_timeout != .none) {
            // Some IO backends (notably uring today) do not yet support
            // connect-time timeout options. Fall back to backend-default connect
            // semantics so callers can still establish connections.
            const fallback = address.connect(io, .{
                .mode = .stream,
                .timeout = .none,
            }) catch |fallback_err| {
                return fallback_err;
            };
            return fallback.socket.handle;
        }
        return err;
    };

    return stream.socket.handle;
}
```

With:

```zig
const TcpConnectResult = struct {
    fd: i32,
    timeout_honored: bool,
};

fn tcpConnect(address: Io.net.IpAddress, io: Io, connect_timeout: Io.Timeout) !TcpConnectResult {
    const stream = address.connect(io, .{
        .mode = .stream,
        .timeout = connect_timeout,
    }) catch |err| {
        if (err == error.OptionUnsupported and connect_timeout != .none) {
            // IO backend does not support connect-time timeouts.
            // io_uring rejects with OptionUnsupported (Uring.zig:5172);
            // proper fix is IORING_OP_LINK_TIMEOUT (tracked in
            // docs/plans/2026-03-16-uring-networking-pr-quality.md:401).
            // Fallback is bounded by kernel tcp_syn_retries (~2min default).
            log.warn("tcpConnect: IO backend does not support connect timeout, falling back to unbounded connect (kernel SYN retry bound only)", .{});
            const fallback = address.connect(io, .{
                .mode = .stream,
                .timeout = .none,
            }) catch |fallback_err| {
                return fallback_err;
            };
            return .{ .fd = fallback.socket.handle, .timeout_honored = false };
        }
        return err;
    };

    return .{ .fd = stream.socket.handle, .timeout_honored = true };
}
```

**Step 3: Update `connectWithTimeout` to propagate the flag**

Find the TCP connect call at `client.zig:219-221`:

```zig
        const fd = tcpConnect(resolve_result.address, io, connect_timeout) catch |err| {
            return mapConnectError(err);
        };
```

Replace with:

```zig
        const tcp_result = tcpConnect(resolve_result.address, io, connect_timeout) catch |err| {
            return mapConnectError(err);
        };
        const fd = tcp_result.fd;
```

Then find the return statement at the end of `connectWithTimeout` (around line 300) and add the new field. The return should include:

```zig
            .connect_timeout_honored = tcp_result.timeout_honored,
```

**Step 4: Update `connect()` (no-timeout variant)**

`connect()` at `client.zig:182-188` calls `connectWithTimeout` with `.none` — no timeout requested, so `connect_timeout_honored` will be `true` (the `tcpConnect` success path always returns `true`). No changes needed.

**Step 5: Fix all ConnectResult construction sites in serval-client**

Search for `ConnectResult{` across serval-client to find any other construction sites that need the new field:

Run: `grep -rn 'ConnectResult{' serval-client/`

Add `.connect_timeout_honored = true` to each.

**Step 6: Update serval-proxy/connect.zig to propagate the flag**

The proxy has its own `ConnectResult` struct that wraps the client result. Add the field and propagate.

Find the proxy `ConnectResult` struct at `serval-proxy/connect.zig:62-82`:

```zig
pub const ConnectResult = struct {
    /// Unified socket abstraction (plain or TLS).
    /// TigerStyle: Single type for both, caller uses read/write interface.
    socket: Socket,
    /// Timestamp when connection was established (monotonic nanoseconds).
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    created_ns: u64,
    /// Protocol negotiated at connection time. Immutable for connection lifetime.
    /// TigerStyle: Single source of truth, no mid-connection renegotiation.
    /// Future: TLS negotiation via ALPN, h2c detection via preface.
    protocol: Protocol,
    /// Duration of DNS resolution in nanoseconds (0 if IP address was used).
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    dns_duration_ns: u64,
    /// Duration of TCP connect in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// Duration of TLS handshake in nanoseconds (0 if plaintext).
    tls_handshake_duration_ns: u64,
    /// Local port of the connection.
    local_port: u16,
};
```

Replace with:

```zig
pub const ConnectResult = struct {
    /// Unified socket abstraction (plain or TLS).
    /// TigerStyle: Single type for both, caller uses read/write interface.
    socket: Socket,
    /// Timestamp when connection was established (monotonic nanoseconds).
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    created_ns: u64,
    /// Protocol negotiated at connection time. Immutable for connection lifetime.
    /// TigerStyle: Single source of truth, no mid-connection renegotiation.
    /// Future: TLS negotiation via ALPN, h2c detection via preface.
    protocol: Protocol,
    /// Duration of DNS resolution in nanoseconds (0 if IP address was used).
    /// TigerStyle: u64 for nanoseconds, explicit unit in name.
    dns_duration_ns: u64,
    /// Duration of TCP connect in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// Duration of TLS handshake in nanoseconds (0 if plaintext).
    tls_handshake_duration_ns: u64,
    /// Local port of the connection.
    local_port: u16,
    /// Whether the caller's connect timeout was honored by the IO backend.
    /// False when io_uring fell back to kernel SYN retry bounds (~2min).
    /// Callers needing bounded connect semantics should check this flag.
    connect_timeout_honored: bool,
};
```

Then find the return at `connect.zig:158-166`:

```zig
    return .{
        .socket = client_result.conn.socket,
        .created_ns = client_result.conn.created_ns,
        .protocol = .h1, // Future: negotiate via ALPN or detect h2c preface
        .dns_duration_ns = client_result.dns_duration_ns,
        .tcp_connect_duration_ns = client_result.tcp_connect_duration_ns,
        .tls_handshake_duration_ns = client_result.tls_handshake_duration_ns,
        .local_port = client_result.local_port,
    };
```

Replace with:

```zig
    return .{
        .socket = client_result.conn.socket,
        .created_ns = client_result.conn.created_ns,
        .protocol = .h1, // Future: negotiate via ALPN or detect h2c preface
        .dns_duration_ns = client_result.dns_duration_ns,
        .tcp_connect_duration_ns = client_result.tcp_connect_duration_ns,
        .tls_handshake_duration_ns = client_result.tls_handshake_duration_ns,
        .local_port = client_result.local_port,
        .connect_timeout_honored = client_result.connect_timeout_honored,
    };
```

**Step 7: Fix proxy ConnectResult test construction**

Find the test at `connect.zig:292-300`:

```zig
    const result = ConnectResult{
        .socket = Socket.Plain.init_client(sock),
        .created_ns = 12345678,
        .protocol = .h1,
        .dns_duration_ns = 500000,
        .tcp_connect_duration_ns = 1000000,
        .tls_handshake_duration_ns = 0,
        .local_port = 8080,
    };
```

Replace with:

```zig
    const result = ConnectResult{
        .socket = Socket.Plain.init_client(sock),
        .created_ns = 12345678,
        .protocol = .h1,
        .dns_duration_ns = 500000,
        .tcp_connect_duration_ns = 1000000,
        .tls_handshake_duration_ns = 0,
        .local_port = 8080,
        .connect_timeout_honored = true,
    };
```

**Step 8: Add explicit proxy enforcement policy for degraded connect timeout**

After propagating `connect_timeout_honored`, enforce behavior in `serval-proxy/connect.zig` where `client_result` is available.

Immediately after:

```zig
    const client_result = try client.connectWithTimeout(upstream, io, connect_timeout);
```

add:

```zig
    // Enforce bounded-connect policy for proxy paths:
    // if caller requested a timeout but backend could not honor it, fail fast.
    if (connect_timeout != .none and !client_result.connect_timeout_honored) {
        client_result.conn.close();
        return error.ConnectTimeoutUnsupported;
    }
```

Also add `ConnectTimeoutUnsupported` to `ForwardError` in `serval-proxy/connect.zig`.

This prevents the proxy from silently accepting a connection that violated bounded-time semantics.

**Step 9: Verify `log` import exists in client.zig**

Check that `client.zig` imports the scoped logger. The file should have:

```zig
const log = @import("serval-core").log.scoped(.client);
```

If not present, add it after the existing imports.

**Step 10: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass

**Step 11: Commit**

```bash
git add serval-client/client.zig serval-proxy/connect.zig
git commit -m "fix(client): surface connect timeout degradation as behavioral signal

tcpConnect silently retried with .timeout = .none when the IO backend
returned OptionUnsupported. ConnectResult now includes
connect_timeout_honored: bool so callers can enforce fail-fast policy
when bounded connect semantics are required. Also logs a warning in
the fallback path. Proxy ConnectResult propagates the flag from the
client result and enforces fail-fast when timeout was requested but not
honored. io_uring LINK_TIMEOUT is the proper fix — tracked
in docs/plans/2026-03-16-uring-networking-pr-quality.md:401."
```

---

### Task 2: Make H2 bridge receiveForUpstream fiber-safe (Finding 2 — High)

**Problem:** `serval-proxy/h2/bridge.zig:294` calls `session.receiveActionHandlingControl()` which passes `null, .none` to `receiveActionHandlingControlTimeout`. With `maybe_io=null`, `readSome` at `serval-client/h2/connection.zig:503` falls to the blocking `plain.read(out)` path. In a fiber context, this blocks the scheduler — no other fibers can run while waiting for H2 upstream frames.

The non-io API variants (`receiveAction`, `receiveActionHandlingControl`) exist for non-fiber callers, but the bridge is a fiber-context caller and must use the io-aware variants.

**Fix:** Thread `Io` into `receiveForUpstream` and call `receiveActionHandlingControlTimeout(io, .none)`. Note: `UpstreamSession` (upstream_pool.zig:130) does NOT have a `receiveActionHandlingControlIo` method — only `receiveActionHandlingControlTimeout(io, timeout)`. Use `.none` timeout for non-blocking fiber-safe behavior.

**Atomicity:** This task changes a public function signature. The signature change and ALL caller updates must land in the same commit — partial application will break the build.

**Files:**
- Modify: `serval-proxy/h2/bridge.zig:287-296` — add `io: Io` parameter, call timeout variant
- Modify: all callers of `receiveForUpstream` — pass `io` at call sites

**Step 1: Find all callers of receiveForUpstream**

Run: `grep -rn 'receiveForUpstream' serval-proxy/ integration/`

Note the call sites and their signatures.

**Step 2: Update `receiveForUpstream` to accept `Io`**

Find this function at `bridge.zig:287-296`:

```zig
    pub fn receiveForUpstream(
        self: *StreamBridge,
        upstream_index: config.UpstreamIndex,
    ) Error!ReceiveAction {
        assert(@intFromPtr(self) != 0);

        const session = self.sessions.get(upstream_index) orelse return error.SessionNotFound;
        const action = try session.receiveActionHandlingControl();
        return self.mapReceiveAction(upstream_index, session.generation, action);
    }
```

Replace with:

```zig
    pub fn receiveForUpstream(
        self: *StreamBridge,
        upstream_index: config.UpstreamIndex,
        io: Io,
    ) Error!ReceiveAction {
        assert(@intFromPtr(self) != 0);

        const session = self.sessions.get(upstream_index) orelse return error.SessionNotFound;
        const action = try session.receiveActionHandlingControlTimeout(io, .none);
        return self.mapReceiveAction(upstream_index, session.generation, action);
    }
```

**Step 3: Update ALL callers found in Step 1**

For each call site, add the `io` argument. Example pattern:

Before:
```zig
const action = bridge.receiveForUpstream(upstream.idx) catch |err| switch (err) {
```

After:
```zig
const action = bridge.receiveForUpstream(upstream.idx, io) catch |err| switch (err) {
```

Every caller must be updated in this step — verify no callers are missed by grepping after edits.

**Step 4: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass. The existing tests already have `io` in scope from `std.Io.Evented`.

**Step 5: Commit**

```bash
git add serval-proxy/h2/bridge.zig integration/tests.zig
git commit -m "fix(proxy/h2): make receiveForUpstream fiber-safe

receiveForUpstream called receiveActionHandlingControl() which passed
null Io, causing readSome to use blocking plain.read() instead of
fiber-safe io.vtable.netRead. Now accepts Io parameter and calls
receiveActionHandlingControlTimeout(io, .none) so the fiber scheduler
can multiplex while waiting for upstream H2 frames."
```

---

### Task 3: Enforce verify_tls per-connection via SSL_set_verify (Finding 4 — Medium)

**Problem:** `serval-client/client.zig:128` stores `verify_tls: bool` and callers pass their verification preference (e.g., `serval-proxy/connect.zig:135` passes `cfg.verify_upstream_tls`). But the TLS connect path at `client.zig:258` calls `TLSSocket.init_client` without applying the verify mode. The `SSL_CTX` may or may not have verification set depending on the caller — some callers (lb_example, acme/renewer) set it themselves, but the client's own `verify_tls` field is dead code.

**Why NOT mutate SSL_CTX:** `SSL_CTX` is shared process-wide (e.g., `netbird_proxy.zig:942-951` creates one ctx for all connections). Calling `SSL_CTX_set_verify` in `connectWithTimeout` would create cross-request policy bleed and concurrency races between clients with different `verify_tls` values.

**Fix:** Use per-connection `SSL_set_verify` on the SSL object. BoringSSL's `SSL_set_verify` (ssl.h:2798) sets verification mode per-connection, not on the shared context. `TLSStream.initClient` (stream.zig:194) creates the SSL object via `SSL_new` at line 194, then handshakes at line 213 (`SSL_connect`). We add a `verify_peer: bool` parameter and call `SSL_set_verify` between these two operations.

**Files:**
- Modify: `serval-tls/ssl.zig` — add `SSL_set_verify` extern binding
- Modify: `serval-tls/stream.zig:182-222` — add `verify_peer` parameter to `initClient`
- Modify: `serval-socket/tls_socket.zig:44-88` — add `verify_peer` parameter to `init_client`
- Modify: `serval-client/client.zig:258` — pass `self.verify_tls` to `init_client`

**Step 1: Add `SSL_set_verify` and `SSL_get_verify_mode` extern to ssl.zig**

Find this line at `ssl.zig:71`:

```zig
pub extern fn SSL_CTX_set_verify(ctx: *SSL_CTX, mode: c_int, callback: ?*anyopaque) void;
```

Add after it:

```zig
pub extern fn SSL_set_verify(ssl_obj: *SSL, mode: c_int, callback: ?*anyopaque) void;
pub extern fn SSL_get_verify_mode(ssl_obj: *const SSL) c_int;
```

**Step 2: Add `verify_peer` parameter to `TLSStream.initClient`**

Find the function signature at `stream.zig:182-189`:

```zig
    pub fn initClient(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        sni_z: [*:0]const u8,
        allocator: Allocator,
        enable_ktls: bool,
        desired_alpn: ?[]const u8,
    ) !TLSStream {
```

Replace with:

```zig
    pub fn initClient(
        ctx: *ssl.SSL_CTX,
        fd: c_int,
        sni_z: [*:0]const u8,
        allocator: Allocator,
        enable_ktls: bool,
        desired_alpn: ?[]const u8,
        verify_peer: bool,
    ) !TLSStream {
```

Then find the block at `stream.zig:207` (after ALPN setup, before `SSL_set_connect_state`):

```zig
        ssl.SSL_set_connect_state(ssl_conn);
```

Add before it:

```zig
        // Set per-connection verify mode. Uses SSL_set_verify (per-SSL object),
        // NOT SSL_CTX_set_verify (shared context), to avoid concurrency races.
        if (verify_peer) {
            ssl.SSL_set_verify(ssl_conn, ssl.SSL_VERIFY_PEER, null);
        } else {
            ssl.SSL_set_verify(ssl_conn, ssl.SSL_VERIFY_NONE, null);
        }

```

**Step 3: Add `verify_peer` parameter to `TLSSocket.init_client`**

Find the function signature at `tls_socket.zig:44-50`:

```zig
    pub fn init_client(
        fd: i32,
        ctx: *ssl.SSL_CTX,
        host: []const u8,
        enable_ktls: bool,
        desired_alpn: ?[]const u8,
    ) SocketError!Socket {
```

Replace with:

```zig
    pub fn init_client(
        fd: i32,
        ctx: *ssl.SSL_CTX,
        host: []const u8,
        enable_ktls: bool,
        desired_alpn: ?[]const u8,
        verify_peer: bool,
    ) SocketError!Socket {
```

Then find the `TLSStream.initClient` call at `tls_socket.zig:68-75`:

```zig
        const stream = TLSStream.initClient(
            ctx,
            fd,
            sni_z,
            std.heap.page_allocator,
            enable_ktls,
            desired_alpn,
        ) catch |err| {
```

Replace with:

```zig
        const stream = TLSStream.initClient(
            ctx,
            fd,
            sni_z,
            std.heap.page_allocator,
            enable_ktls,
            desired_alpn,
            verify_peer,
        ) catch |err| {
```

**Step 4: Pass `self.verify_tls` from client.zig**

Find the `init_client` call at `client.zig:258-264`:

```zig
            var tls_socket = Socket.TLS.TLSSocket.init_client(
                fd,
                ctx,
                sni_host,
                self.enable_ktls,
                desired_alpn,
            ) catch {
```

Replace with:

```zig
            var tls_socket = Socket.TLS.TLSSocket.init_client(
                fd,
                ctx,
                sni_host,
                self.enable_ktls,
                desired_alpn,
                self.verify_tls,
            ) catch {
```

**Step 5: Update all other callers of `init_client`**

Search for all callers of `TLSSocket.init_client` and add the `verify_peer` parameter:

Run: `grep -rn 'TLSSocket.init_client(' serval-socket/ serval-client/ serval-proxy/ integration/ examples/`

For each call site, add the appropriate `verify_peer` argument (typically `false` for tests with self-signed certs, `true` for production callers). Example:

```zig
// integration/tests.zig — self-signed cert, no verification
Socket.TLS.TLSSocket.init_client(sock, ctx, "localhost", true, null, false)
```

**Step 6: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass

**Step 7: Commit**

```bash
git add serval-tls/ssl.zig serval-tls/stream.zig serval-socket/tls_socket.zig serval-client/client.zig integration/tests.zig
git commit -m "fix(tls): enforce verify_tls per-connection via SSL_set_verify

verify_tls was stored in Client but never applied during the connect
path. Added SSL_set_verify/SSL_get_verify_mode bindings to ssl.zig,
threaded verify_peer through TLSStream.initClient and
TLSSocket.init_client, and pass self.verify_tls from Client.

Uses per-connection SSL_set_verify (not SSL_CTX_set_verify) to avoid
concurrency races on the shared SSL_CTX. Verify mode is set between
SSL_new and SSL_connect, before the handshake begins."
```

---

### Task 4: Fix README async/non-blocking claims (Finding 5 — Low)

**Problem:** `serval-client/README.md:33` claims "Async I/O - Uses `std.Io` (io_uring integration) for non-blocking operations" as a design principle, but HTTP/1 request serialization (`request.zig:170` `sendBufferToSocket`) and response header reading (`response.zig:132-154` `readHeaderBytes`) use blocking socket paths. Only the H2 connection driver uses `std.Io` for fiber-safe I/O when an `Io` context is provided.

**Fix:** Clarify the README to accurately describe which paths are async and which are blocking.

**Files:**
- Modify: `serval-client/README.md:33`

**Step 1: Update the design principles section**

Find this line at `README.md:33`:

```markdown
- **Async I/O** - Uses `std.Io` (io_uring integration) for non-blocking operations
```

Replace with:

```markdown
- **Async I/O** - H2 connection driver uses `std.Io` (io_uring integration) for fiber-safe operations when an `Io` context is provided; HTTP/1 request/response paths use blocking socket I/O (fiber-safe variants live in `serval-proxy/h1/`)
```

**Step 2: Run tests**

Run: `zig build test 2>&1 | tail -5`
Expected: all tests pass (README change, no code affected)

**Step 3: Commit**

```bash
git add serval-client/README.md
git commit -m "docs(client): clarify async I/O scope in README

README claimed async/non-blocking for all operations, but HTTP/1
request serialization and response header reading use blocking socket
paths. H2 paths are fiber-safe when Io is provided. Clarified which
paths are async vs blocking."
```
