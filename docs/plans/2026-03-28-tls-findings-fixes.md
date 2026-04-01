# serval-tls Findings Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 8 code-review findings in serval-tls (2 critical, 2 high, 3 medium, 1 low).

**Architecture:** Replace broken manual kTLS key extraction with OpenSSL 3.x native kTLS (handles key derivation internally). Fix error mapping, mutex behavior, global synchronization, and docs independently.

**Tech Stack:** Zig, OpenSSL 3.x / BoringSSL, Linux kTLS

---

### Task 1: Enforce TLS 1.2 minimum version floor

**Finding:** #3 (High) — `createClientCtx`/`createServerCtx` do not set min protocol version; TODOs remain.

**Files:**
- Modify: `serval-tls/ssl.zig:253-259` (createClientCtx)
- Modify: `serval-tls/ssl.zig:262-271` (createServerCtx)

The extern `SSL_CTX_set_min_proto_version` is already declared at ssl.zig:66 and works in both OpenSSL 3.x and BoringSSL. The TODO comment claiming it's "BoringSSL-specific" is wrong.

**Step 1: Fix createClientCtx — check return value**

Replace:
```zig
pub fn createClientCtx() !*SSL_CTX {
    const method = TLS_client_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    // NOTE: SSL_CTX_set_min_proto_version is BoringSSL-specific, not in OpenSSL
    // TODO: Use OpenSSL-compatible SSL_CTX_set_options with SSL_OP_NO_TLSv1 etc
    // _ = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}
```

With:
```zig
pub fn createClientCtx() !*SSL_CTX {
    const method = TLS_client_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        SSL_CTX_free(ctx);
        return error.SslCtxNew;
    }
    return ctx;
}
```

Note: Return value is checked and ctx freed on failure. Uses `error.SslCtxNew` since the error set is already established; adding a new error would ripple through callers for no benefit.

**Step 2: Fix createServerCtx — check return value**

Replace:
```zig
pub fn createServerCtx() !*SSL_CTX {
    const method = TLS_server_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    // NOTE: SSL_CTX_set_min_proto_version is BoringSSL-specific, not in OpenSSL
    // TODO: Use OpenSSL-compatible SSL_CTX_set_options with SSL_OP_NO_TLSv1 etc
    // _ = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    configureServerAlpn(ctx);
    configureServerCertHook(ctx);
    return ctx;
}
```

With:
```zig
pub fn createServerCtx() !*SSL_CTX {
    const method = TLS_server_method() orelse return error.NoTlsMethod;
    const ctx = SSL_CTX_new(method) orelse return error.SslCtxNew;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        SSL_CTX_free(ctx);
        return error.SslCtxNew;
    }
    configureServerAlpn(ctx);
    configureServerCertHook(ctx);
    return ctx;
}
```

**Step 3: Run tests**

Run: `zig build test-tls`
Expected: PASS — all TLS unit tests pass with min version enforced

**Step 4: Commit**

```
fix(tls): enforce TLS 1.2 minimum version in client and server contexts
```

---

### Task 2: Replace broken manual kTLS with OpenSSL native kTLS

**Findings:** #1 (Critical) — `extractKeyMaterial` uses RFC 5705 exporter to derive new keys instead of actual traffic secrets. #2 (Critical) — partial TX/RX kTLS enable can leave socket in inconsistent state.

**Root cause:** The manual kTLS path in `ktls.zig` uses `SSL_export_keying_material` which derives *new* key material from the session, not the actual record-layer traffic keys. These keys won't match what the peer uses, breaking the protocol.

**Fix approach:** OpenSSL 3.x has built-in kTLS support via `SSL_OP_ENABLE_KTLS`. When set before handshake, OpenSSL automatically configures kernel TLS with the correct traffic keys. After handshake, check `BIO_get_ktls_send`/`BIO_get_ktls_recv` for status. This eliminates manual key extraction entirely and handles TX/RX atomically.

**Portability note:** `SSL_OP_ENABLE_KTLS` is defined as `1 << 3` in OpenSSL 3.x. BoringSSL does not define this constant. `isKtlsRuntimeAvailable()` only checks OS/kernel/env — it has no TLS-library awareness and *can* return true on Linux+BoringSSL when the kernel `tls` ULP is loaded. In that case we set bit 3 on a BoringSSL SSL object. This is safe: BoringSSL's `SSL_set_options` stores unknown bits but does not act on them, so the flag is a no-op and kTLS is never activated. The BIO check after handshake (`BIO_get_ktls_send`/`BIO_get_ktls_recv`) is the sole source of truth for whether kTLS is actually active — it will correctly return false under BoringSSL.

**Files:**
- Modify: `serval-tls/stream.zig:99-118` (setupKtlsAfterHandshake)
- Modify: `serval-tls/stream.zig:138-143` (initServer — set option before handshake)
- Modify: `serval-tls/stream.zig:195-200` (initClient — set option before handshake)
- Modify: `serval-tls/ktls.zig:347-415` (remove broken extractKeyMaterial)
- Modify: `serval-tls/ktls.zig:518-555` (remove configureKtlsForDirection)
- Modify: `serval-tls/ktls.zig:581-640` (rename tryEnableKtls → isKtlsCompatible, narrow scope)

**Step 1: Set SSL_OP_ENABLE_KTLS before handshake in initServer**

In `stream.zig` initServer, after `SSL_set_fd` and before `SSL_set_accept_state`, add the kTLS option:

Replace:
```zig
        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        const enable_ktls: bool = ktls.isKtlsRuntimeAvailable();
        ssl.SSL_set_accept_state(ssl_conn);
```

With:
```zig
        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        const enable_ktls: bool = ktls.isKtlsRuntimeAvailable();
        if (enable_ktls) {
            _ = ssl.SSL_set_options(ssl_conn, ssl.SSL_OP_ENABLE_KTLS);
        }
        ssl.SSL_set_accept_state(ssl_conn);
```

**Step 2: Set SSL_OP_ENABLE_KTLS before handshake in initClient**

In `stream.zig` initClient, after `SSL_set_fd` and before `SSL_set_tlsext_host_name`, add:

Replace:
```zig
        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        const should_enable_ktls: bool = enable_ktls and ktls.isKtlsRuntimeAvailable();
        // Set SNI (caller provides null-terminated string - no allocation)
```

With:
```zig
        if (ssl.SSL_set_fd(ssl_conn, fd) != 1) return error.SslSetFd;

        const should_enable_ktls: bool = enable_ktls and ktls.isKtlsRuntimeAvailable();
        if (should_enable_ktls) {
            _ = ssl.SSL_set_options(ssl_conn, ssl.SSL_OP_ENABLE_KTLS);
        }
        // Set SNI (caller provides null-terminated string - no allocation)
```

**Step 3: Rewrite setupKtlsAfterHandshake to check native kTLS status**

Replace the entire `setupKtlsAfterHandshake` function:

Replace:
```zig
    /// Setup kTLS after successful handshake.
    /// Uses manual kTLS setup for deterministic fallback behavior across runtimes.
    /// Returns the appropriate mode and updates info.ktls_enabled.
    fn setupKtlsAfterHandshake(ssl_conn: *ssl.SSL, fd: c_int, info: *HandshakeInfo, enable_ktls: bool) Mode {
        if (!enable_ktls) {
            info.ktls_enabled = false;
            return .{ .userspace = ssl_conn };
        }

        const ktls_result = ktls.tryEnableKtls(ssl_conn, fd);
        const manual_ktls = ktls_result.isKtls();
        info.ktls_enabled = manual_ktls;

        if (manual_ktls) {
            ssl.SSL_free(ssl_conn);
            return .ktls;
        }

        return .{ .userspace = ssl_conn };
    }
```

With:
```zig
    /// Check native kTLS status after handshake.
    /// OpenSSL 3.x handles kTLS setup internally when SSL_OP_ENABLE_KTLS is set.
    /// SSL object is always retained — OpenSSL transparently uses kernel TLS for I/O.
    fn setupKtlsAfterHandshake(ssl_conn: *ssl.SSL, info: *HandshakeInfo, enable_ktls: bool) Mode {
        if (!enable_ktls) {
            info.ktls_enabled = false;
            return .{ .userspace = ssl_conn };
        }

        // Check if OpenSSL enabled native kTLS via BIO layer
        const tx_ktls = if (ssl.SSL_get_wbio(ssl_conn)) |wbio| ssl.BIO_get_ktls_send(wbio) else false;
        const rx_ktls = if (ssl.SSL_get_rbio(ssl_conn)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false;
        info.ktls_enabled = tx_ktls and rx_ktls;

        return .{ .userspace = ssl_conn };
    }
```

**Step 4: Update call sites to remove fd parameter**

In initServer, replace:
```zig
        const mode = setupKtlsAfterHandshake(ssl_conn, fd, &info, enable_ktls);
```
With:
```zig
        const mode = setupKtlsAfterHandshake(ssl_conn, &info, enable_ktls);
```

In initClient, replace:
```zig
            const m = setupKtlsAfterHandshake(ssl_conn, fd, &info, true);
```
With:
```zig
            const m = setupKtlsAfterHandshake(ssl_conn, &info, true);
```

**Step 5: Rename tryEnableKtls → isKtlsCompatible and narrow to pure check**

The old `tryEnableKtls` both checked compatibility AND performed setup. Now that setup is handled by OpenSSL natively, the function should only check whether the negotiated cipher/version *could* use kTLS. Rename to `isKtlsCompatible` and change return type to `bool` so callers cannot confuse "compatible" with "enabled."

Replace the entire `tryEnableKtls` function (from doc comment through closing `}`):

```zig
/// Checks whether the negotiated TLS cipher/version is kTLS-compatible.
///
/// This is a pure compatibility check — it does NOT enable kTLS. Actual kernel
/// TLS setup is handled natively by OpenSSL 3.x via SSL_OP_ENABLE_KTLS.
/// Use BIO_get_ktls_send/recv after handshake to check actual kTLS status.
///
/// Returns true if the negotiated parameters are kTLS-compatible.
pub fn isKtlsCompatible(ssl_ptr: *ssl.SSL) bool {
    assert(@intFromPtr(ssl_ptr) != 0);

    if (!isKtlsRuntimeAvailable()) return false;

    const tls_version_int: c_int = ssl.SSL_version(ssl_ptr);
    if (tls_version_int != ssl.TLS1_2_VERSION and tls_version_int != ssl.TLS1_3_VERSION) return false;

    const cipher = ssl.SSL_get_current_cipher(ssl_ptr) orelse return false;
    const cipher_id: u16 = ssl.SSL_CIPHER_get_protocol_id(cipher);
    return mapCipherToKtls(cipher_id) != .unsupported;
}
```

Remove the `fd` parameter entirely — the function no longer touches the socket.

**Step 6: Remove broken extractKeyMaterial function**

Delete the `extractKeyMaterial` function (lines ~347-415) and `configureKtlsForDirection` function (lines ~518-555) since they are no longer called. Keep `setKtlsCrypto`, `buildCryptoInfo*`, `attachTlsULP`, and `setKtlsDirection` — they are tested and may be used for future BoringSSL manual path.

**Step 7: Run tests**

Run: `zig build test-tls`
Expected: PASS — cipher mapping tests unaffected, no compile errors from removed functions

Then run full build to catch cross-module breakage:
Run: `zig build test`
Expected: PASS — no module references broken `tryEnableKtls` signature

**Step 8: Commit**

```
fix(tls): replace broken manual kTLS with OpenSSL native kTLS

The manual key extraction path used SSL_export_keying_material to derive
new keys instead of actual traffic secrets, breaking kTLS data path.
OpenSSL 3.x handles kTLS setup internally with correct keys when
SSL_OP_ENABLE_KTLS is set before handshake.

Also fixes partial TX/RX kTLS state — OpenSSL manages both directions
atomically via its BIO layer.
```

---

### Task 3: Fix nonblocking error mapping in stream I/O

**Findings:** #4 (High) — kTLS write maps WouldBlock→WantRead (wrong). Userspace write collapses WANT_READ/WANT_WRITE to WouldBlock (inconsistent with read path). #5 (Medium) — kTLS read treats WouldBlock as hard KtlsRead error.

**Files:**
- Modify: `serval-tls/stream.zig:266-272` (kTLS read — add WouldBlock handling)
- Modify: `serval-tls/stream.zig:345-348` (kTLS write — fix WouldBlock direction)
- Modify: `serval-tls/stream.zig:360-366` (userspace write — keep direction-specific errors)

**Step 1: Fix kTLS read to handle WouldBlock as nonblocking signal**

Replace:
```zig
                const n = result catch |err| {
                    // Map posix errors to TLS errors for consistent API
                    return switch (err) {
                        error.ConnectionResetByPeer => error.ConnectionReset,
                        else => error.KtlsRead,
                    };
                };
```

With:
```zig
                const n = result catch |err| {
                    // Map posix errors to TLS errors for consistent API
                    return switch (err) {
                        error.ConnectionResetByPeer => error.ConnectionReset,
                        error.WouldBlock => error.WantRead,
                        else => error.KtlsRead,
                    };
                };
```

**Step 2: Fix kTLS write WouldBlock direction**

Replace:
```zig
                    return switch (err) {
                        error.BrokenPipe => error.ConnectionReset,
                        error.WouldBlock => error.WantRead,
                        else => error.KtlsWrite,
                    };
```

With:
```zig
                    return switch (err) {
                        error.BrokenPipe => error.ConnectionReset,
                        error.WouldBlock => error.WantWrite,
                        else => error.KtlsWrite,
                    };
```

**Step 3: Fix userspace write to preserve direction-specific errors**

Replace:
```zig
                    switch (ssl_err) {
                        ssl.SSL_ERROR_WANT_READ, ssl.SSL_ERROR_WANT_WRITE => return error.WouldBlock,
                        ssl.SSL_ERROR_ZERO_RETURN => return error.ConnectionReset,
                        ssl.SSL_ERROR_SYSCALL => return error.ConnectionReset,
                        else => return error.SslWrite,
                    }
```

With:
```zig
                    switch (ssl_err) {
                        ssl.SSL_ERROR_WANT_READ => return error.WantRead,
                        ssl.SSL_ERROR_WANT_WRITE => return error.WantWrite,
                        ssl.SSL_ERROR_ZERO_RETURN => return error.ConnectionReset,
                        ssl.SSL_ERROR_SYSCALL => return error.ConnectionReset,
                        else => return error.SslWrite,
                    }
```

**Step 4: Update write callers that handle error.WouldBlock**

Changing write to return `WantRead`/`WantWrite` instead of `WouldBlock` is a breaking change. Four direct callers need updating (4a–4d). Each should handle `WantRead`/`WantWrite` the same way it handled `WouldBlock` (retry/continue).

First, run a repo-wide search to find ALL direct TLSStream.write callers with explicit error handling:

Run: `grep -rn 'WouldBlock' serval-server/ serval-socket/ serval-client/ serval-proxy/ serval-otel/ --include='*.zig' | grep -i 'write\|tls'`

Known direct callers that explicitly catch `error.WouldBlock` from TLSStream.write:

**4a: `serval-server/websocket/io.zig:110-111`** — retry loop

Replace:
```zig
            error.WouldBlock => continue,
```
With:
```zig
            error.WouldBlock, error.WantRead, error.WantWrite => continue,
```

**4b: `serval-server/h2/server.zig:2422`** — propagate as WouldBlock

Replace:
```zig
                error.WouldBlock => return error.WouldBlock,
```
With:
```zig
                error.WouldBlock, error.WantRead, error.WantWrite => return error.WouldBlock,
```

**4c: `serval-server/frontend/generic_h2.zig:1203`** — sleep + retry

Replace:
```zig
    error.WouldBlock => {
```
With:
```zig
    error.WouldBlock, error.WantRead, error.WantWrite => {
```

**4d: `serval-socket/tls_socket.zig:216`** — error mapping

Replace:
```zig
        error.WouldBlock => SocketError.TLSError,
```
With:
```zig
        error.WouldBlock, error.WantRead, error.WantWrite => SocketError.TLSError,
```

**4e: Verify no callers missed** — after making the changes, `zig build test` will fail to compile if any switch on TLSStream.write errors doesn't handle the new error variants. This is the definitive check — Zig's exhaustive error sets enforce it at compile time.

Note: `serval-server/h1/server.zig:553` uses `try` (error set widens automatically). Indirect callers through `Socket.write()` are covered by the tls_socket.zig mapping.

**Step 5: Run full test suite**

Run: `zig build test`
Expected: PASS — callers compile with new error set

**Step 6: Commit**

```
fix(tls): correct nonblocking error mapping in stream read/write

- kTLS read: WouldBlock now returns WantRead (was hard KtlsRead error)
- kTLS write: WouldBlock now returns WantWrite (was incorrectly WantRead)
- Userspace write: preserves WantRead/WantWrite direction (was collapsed)
- Updated 4 callers to handle WantRead/WantWrite alongside WouldBlock
```

---

### Task 4: Replace mutex contention panic with error return

**Finding:** #6 (Medium) — `lockMutex` panics after spin attempts. Enterprise infra should return error, not abort.

**Files:**
- Modify: `serval-tls/reloadable_ctx.zig:15-18` (Error enum — add MutexTimeout)
- Modify: `serval-tls/reloadable_ctx.zig:217-227` (lockMutex — return error)
- Modify: `serval-tls/reloadable_ctx.zig:66-81` (deinit — handle lock failure)
- Modify: `serval-tls/reloadable_ctx.zig:83-106` (acquire — propagate)
- Modify: `serval-tls/reloadable_ctx.zig:108-126` (release — handle lock failure)
- Modify: `serval-tls/reloadable_ctx.zig:128-161` (activate — propagate)
- Modify: `serval-tls/reloadable_ctx.zig:185-194` (activeGeneration — propagate)

**Step 1: Add MutexTimeout to Error enum**

Replace:
```zig
pub const Error = error{
    NoActiveContext,
    RefCountOverflow,
    NoFreeSlot,
};
```

With:
```zig
pub const Error = error{
    NoActiveContext,
    RefCountOverflow,
    NoFreeSlot,
    MutexTimeout,
};
```

**Step 2: Make lockMutex return error instead of panic**

Replace:
```zig
fn lockMutex(mutex: *std.atomic.Mutex) void {
    assert(@intFromPtr(mutex) != 0);

    var attempts: u32 = 0;
    while (attempts < mutex_lock_max_attempts) : (attempts += 1) {
        if (mutex.tryLock()) return;
        std.atomic.spinLoopHint();
    }

    @panic("ReloadableServerCtx mutex lock timeout");
}
```

With (note: now takes `*ReloadableServerCtx` for per-instance timeout tracking):
```zig
fn lockMutex(self: *ReloadableServerCtx) error{MutexTimeout}!void {
    assert(@intFromPtr(self) != 0);

    var attempts: u32 = 0;
    while (attempts < mutex_lock_max_attempts) : (attempts += 1) {
        if (self.mutex.tryLock()) {
            self.consecutive_mutex_timeouts.store(0, .release);
            return;
        }
        std.atomic.spinLoopHint();
    }

    const prev = self.consecutive_mutex_timeouts.fetchAdd(1, .acq_rel);
    if (prev + 1 >= max_consecutive_mutex_timeouts) {
        log.err("ReloadableServerCtx: {d} consecutive mutex timeouts — context manager degraded", .{prev + 1});
    }
    return error.MutexTimeout;
}
```

**Step 3: Propagate in acquire**

Replace:
```zig
    pub fn acquire(self: *ReloadableServerCtx) Error!Lease {
        assert(@intFromPtr(self) != 0);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();
```

With:
```zig
    pub fn acquire(self: *ReloadableServerCtx) Error!Lease {
        assert(@intFromPtr(self) != 0);

        try lockMutex(self);
        defer self.mutex.unlock();
```

**Step 4: Propagate in activate**

Replace:
```zig
    pub fn activate(self: *ReloadableServerCtx, new_ctx: *ssl.SSL_CTX) Error!u32 {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(new_ctx) != 0);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();
```

With:
```zig
    pub fn activate(self: *ReloadableServerCtx, new_ctx: *ssl.SSL_CTX) Error!u32 {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(new_ctx) != 0);

        try lockMutex(self);
        defer self.mutex.unlock();
```

**Step 5: Propagate in activeGeneration**

Replace:
```zig
    pub fn activeGeneration(self: *ReloadableServerCtx) u32 {
        assert(@intFromPtr(self) != 0);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();
```

With:
```zig
    pub fn activeGeneration(self: *ReloadableServerCtx) Error!u32 {
        assert(@intFromPtr(self) != 0);

        try lockMutex(self);
        defer self.mutex.unlock();
```

**Step 6: Handle gracefully in deinit (log and return, don't crash)**

Replace:
```zig
    pub fn deinit(self: *ReloadableServerCtx) void {
        assert(@intFromPtr(self) != 0);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();
```

With:
```zig
    pub fn deinit(self: *ReloadableServerCtx) void {
        assert(@intFromPtr(self) != 0);

        lockMutex(self) catch {
            log.err("ReloadableServerCtx.deinit: mutex timeout, leaking SSL contexts", .{});
            return;
        };
        defer self.mutex.unlock();
```

Note: Add `const log = @import("serval-core").log.scoped(.tls);` to imports if not already present.

**Step 7: Handle gracefully in release (log and return, leak ref)**

Replace:
```zig
    pub fn release(self: *ReloadableServerCtx, lease: Lease) void {
        assert(@intFromPtr(self) != 0);
        assert(lease.slot_index < slot_capacity);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();
```

With:
```zig
    pub fn release(self: *ReloadableServerCtx, lease: Lease) void {
        assert(@intFromPtr(self) != 0);
        assert(lease.slot_index < slot_capacity);

        lockMutex(self) catch {
            log.err("ReloadableServerCtx.release: mutex timeout, leaking ref on generation {d}", .{lease.generation});
            return;
        };
        defer self.mutex.unlock();
```

**Escalation policy for mutex timeout leaks:**

Track consecutive timeouts as a per-instance field on `ReloadableServerCtx` (not a module-global) to avoid cross-instance interference and data races. The field is only accessed inside `lockMutex` calls, which are per-instance. After 3 consecutive timeouts, log at `.err` as the alerting signal.

Add field to `ReloadableServerCtx` struct (atomic because it's accessed before the mutex is held):
```zig
consecutive_mutex_timeouts: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
```

Add constant at module scope:
```zig
const max_consecutive_mutex_timeouts: u32 = 3;
```

`lockMutex` gains a `self` parameter (see Step 2 below). On success, reset via `.store(0, .release)`. On timeout, increment via `.fetchAdd(1, .acq_rel)` and log at threshold. Callers of `acquire()` propagate `MutexTimeout` to the handshake path — new connections fail rather than silently accumulate leaked state. The `.err` log line at threshold 3 is the alerting signal for operators to investigate (stuck holder or contention spike requiring restart).

**Step 8: Fix tests that call activeGeneration (now returns error union)**

Any test that calls `manager.activeGeneration()` needs to become `try manager.activeGeneration()`.

**Step 9: Run tests**

Run: `zig build test-tls`
Expected: PASS — all reloadable ctx tests pass with new error union

Then run full build to catch callers of `activeGeneration()` that don't handle the error:
Run: `zig build test`
Expected: PASS

**Step 10: Commit**

```
fix(tls): replace mutex contention panic with error return in ReloadableServerCtx

lockMutex now returns error.MutexTimeout instead of panicking.
Failable callers propagate; deinit/release log and return gracefully
to preserve process availability.
```

---

### Task 5: Synchronize global ALPN/cert hooks with atomics

**Finding:** #7 (Medium) — Process-wide mutable vars read/written without atomic/lock coordination.

**Files:**
- Modify: `serval-tls/ssl.zig:359-391` (global vars and getters/setters)
- Modify: `serval-tls/ssl.zig:393-398` (resolveServerAlpnMixedOfferPolicy)

**Step 1: Make setters use @atomicStore**

Replace:
```zig
pub fn setServerAlpnMixedOfferPolicy(policy: AlpnMixedOfferPolicy) void {
    server_alpn_mixed_offer_policy = policy;
}
```
With:
```zig
pub fn setServerAlpnMixedOfferPolicy(policy: AlpnMixedOfferPolicy) void {
    @atomicStore(&server_alpn_mixed_offer_policy, policy, .release);
}
```

Replace:
```zig
pub fn setServerAlpnHook(hook: ?ServerAlpnHook) void {
    server_alpn_hook = hook;
}
```
With:
```zig
pub fn setServerAlpnHook(hook: ?ServerAlpnHook) void {
    @atomicStore(&server_alpn_hook, hook, .release);
}
```

Replace:
```zig
pub fn setServerCertHook(hook: ?ServerCertHook) void {
    server_cert_hook = hook;
}
```
With:
```zig
pub fn setServerCertHook(hook: ?ServerCertHook) void {
    @atomicStore(&server_cert_hook, hook, .release);
}
```

**Step 2: Make getters use @atomicLoad**

Replace:
```zig
pub fn getServerAlpnMixedOfferPolicy() AlpnMixedOfferPolicy {
    return server_alpn_mixed_offer_policy;
}
```
With:
```zig
pub fn getServerAlpnMixedOfferPolicy() AlpnMixedOfferPolicy {
    return @atomicLoad(&server_alpn_mixed_offer_policy, .acquire);
}
```

Replace:
```zig
pub fn getServerAlpnHook() ?ServerAlpnHook {
    return server_alpn_hook;
}
```
With:
```zig
pub fn getServerAlpnHook() ?ServerAlpnHook {
    return @atomicLoad(&server_alpn_hook, .acquire);
}
```

Replace:
```zig
pub fn getServerCertHook() ?ServerCertHook {
    return server_cert_hook;
}
```
With:
```zig
pub fn getServerCertHook() ?ServerCertHook {
    return @atomicLoad(&server_cert_hook, .acquire);
}
```

**Step 3: Fix resolveServerAlpnMixedOfferPolicy to use atomic read**

Replace:
```zig
fn resolveServerAlpnMixedOfferPolicy(arg: ?*anyopaque) AlpnMixedOfferPolicy {
    if (arg) |raw| {
        const policy_ptr: *const AlpnMixedOfferPolicy = @ptrCast(@alignCast(raw));
        return policy_ptr.*;
    }
    return server_alpn_mixed_offer_policy;
}
```

With:
```zig
fn resolveServerAlpnMixedOfferPolicy(arg: ?*anyopaque) AlpnMixedOfferPolicy {
    if (arg) |raw| {
        const policy_ptr: *const AlpnMixedOfferPolicy = @ptrCast(@alignCast(raw));
        return @atomicLoad(policy_ptr, .acquire);
    }
    return @atomicLoad(&server_alpn_mixed_offer_policy, .acquire);
}
```

**Step 4: Fix callback reads of hook globals to use atomic**

Check `applyServerAlpnHook` and `serverNameSelectCb` (or wherever `server_alpn_hook` and `server_cert_hook` are read) and ensure they use `@atomicLoad`. Find all direct reads with: `grep -n 'server_alpn_hook\|server_cert_hook' ssl.zig` and fix any bare reads that aren't going through the getters.

**Step 5: Run tests**

Run: `zig build test-tls`
Expected: PASS — ALPN tests pass with atomic accessors

Run: `zig build test`
Expected: PASS — no cross-module breakage from atomic changes

**Step 6: Commit**

```
fix(tls): synchronize global ALPN/cert hooks with atomic load/store

Process-wide hook variables now use acquire/release atomics to prevent
data races from concurrent read/write across threads.
```

---

### Task 6: Fix README inconsistencies

**Finding:** #8 (Low) — README claims kTLS deferred to Phase 2, then marks Phase 2 complete. Claims "None" internal dependencies while importing serval-core.

**Files:**
- Modify: `serval-tls/README.md`

**Step 1: Fix Phase 1 description**

Replace line 7:
```
Provides TLS support for both incoming client connections (termination) and outgoing upstream connections (origination). Handles handshakes, encryption/decryption, and certificate validation. Phase 1 uses userspace crypto; kTLS kernel offload deferred to Phase 2.
```

With:
```
Provides TLS support for both incoming client connections (termination) and outgoing upstream connections (origination). Handles handshakes, encryption/decryption, and certificate validation with optional kTLS kernel offload.
```

**Step 2: Fix internal dependencies**

Replace line 67:
```
- None (Layer 1 module - no serval dependencies)
```

With:
```
- `serval-core` (logging, config constants, fd utilities)
```

**Step 3: Update kTLS description in Phase 2 to reflect native OpenSSL approach**

Replace:
```
**Phase 2 - Complete**
- kTLS kernel offload (manual key extraction path with deterministic fallback)
- Automatic runtime detection and fallback to userspace (module missing/non-Linux/disabled)
- Zero-copy sendfile() support when kTLS active
```

With:
```
**Phase 2 - Complete**
- kTLS kernel offload via OpenSSL native `SSL_OP_ENABLE_KTLS`
- Automatic runtime detection and fallback to userspace (module missing/non-Linux/disabled)
- Zero-copy sendfile() support when kTLS active
```

**Step 4: Update Architecture Decisions kTLS section**

Replace lines 151-171 (the kTLS architecture decision section):
```
### kTLS with Deterministic Manual Path

**Decision:** Use manual kTLS setup path consistently after handshake, with explicit runtime checks and userspace fallback.

**Rationale:**
- Manual key extraction via `SSL_export_keying_material` enables one consistent path across OpenSSL/BoringSSL
- Runtime checks gate kTLS setup (platform, module presence, optional env disable)
- Deterministic fallback: any setup failure stays on userspace TLS without failing handshakes
- Transparent to users - TLSStream API unchanged, `isKtls()` for status
```

With:
```
### kTLS via OpenSSL Native Support

**Decision:** Use OpenSSL 3.x native kTLS via `SSL_OP_ENABLE_KTLS`, with runtime checks and userspace fallback.

**Rationale:**
- OpenSSL handles traffic key extraction and kernel setup internally with correct keys
- Runtime checks gate kTLS enablement (platform, module presence, optional env disable)
- Deterministic fallback: any setup failure stays on userspace TLS without failing handshakes
- Transparent to users — TLSStream API unchanged, `isKtls()` for status
```

**Step 5: Update requirements section**

Replace:
```
- OpenSSL/BoringSSL with `SSL_export_keying_material` support for key extraction
```

With:
```
- OpenSSL 3.x with `SSL_OP_ENABLE_KTLS` support
```

**Step 6: Commit**

```
docs(tls): fix README inconsistencies and update kTLS architecture
```

---

### Final Verification

After all 6 tasks are complete, run the full verification suite. Every command must exit 0; any non-zero exit fails the verification.

**Step 1: Full unit tests**
Run: `zig build test`

**Step 2: TLS-specific tests**
Run: `zig build test-tls`

**Step 3: Build check (no test, just compile)**
Run: `zig build`

**Step 4: Grep for stale references**
Run: `! grep -rn 'tryEnableKtls\|extractKeyMaterial\|configureKtlsForDirection' serval-tls/ serval-server/ serval-client/ serval-socket/ --include='*.zig'`
The `!` inverts grep's exit code: exits 0 when no matches found, exits 1 if any match exists. `SSL_export_keying_material` is excluded — the extern binding in ssl.zig is retained (valid OpenSSL API, just no longer used for kTLS).

**Step 5: kTLS runtime integration test**

Add a loopback handshake test to `serval-tls/stream.zig` (test section) that exercises the real handshake path and asserts BIO status:

```zig
test "native kTLS BIO status after loopback handshake" {
    const builtin = @import("builtin");

    if (builtin.os.tag != .linux) return error.SkipZigTest;

    ssl.init();

    // Test fixtures: skip (not fail) if certs are unavailable in this checkout.
    const cert_path = "experiments/tls-poc/cert.pem";
    const key_path = "experiments/tls-poc/key.pem";
    std.fs.cwd().access(cert_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    std.fs.cwd().access(key_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };

    // Create server and client contexts with test certs.
    const server_ctx = try ssl.createServerCtxFromPemFiles(
        cert_path,
        key_path,
    );
    defer ssl.SSL_CTX_free(server_ctx);

    const client_ctx = try ssl.createClientCtx();
    defer ssl.SSL_CTX_free(client_ctx);

    // Create nonblocking socketpair to prevent deadlock.
    // Blocking sockets would deadlock: the first SSL_do_handshake call blocks
    // waiting for peer data that can never arrive because both sides share a thread.
    const linux = std.os.linux;
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK, 0, &fds);
    if (posix.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    // Server side
    const server_ssl = ssl.SSL_new(server_ctx) orelse return error.SslNew;
    defer ssl.SSL_free(server_ssl);
    _ = ssl.SSL_set_options(server_ssl, ssl.SSL_OP_ENABLE_KTLS);
    if (ssl.SSL_set_fd(server_ssl, fds[0]) != 1) return error.SslSetFd;
    ssl.SSL_set_accept_state(server_ssl);

    // Client side
    const client_ssl = ssl.SSL_new(client_ctx) orelse return error.SslNew;
    defer ssl.SSL_free(client_ssl);
    ssl.SSL_set_verify(client_ssl, ssl.SSL_VERIFY_NONE, null);
    _ = ssl.SSL_set_options(client_ssl, ssl.SSL_OP_ENABLE_KTLS);
    if (ssl.SSL_set_fd(client_ssl, fds[1]) != 1) return error.SslSetFd;
    ssl.SSL_set_connect_state(client_ssl);

    // Drive handshake to completion with bounded alternating calls.
    // Nonblocking sockets ensure SSL_do_handshake returns WANT_READ/WANT_WRITE
    // instead of blocking, allowing the single-threaded alternation to make progress.
    const max_handshake_rounds: u32 = 200;
    var rounds: u32 = 0;
    var client_done = false;
    var server_done = false;
    while (rounds < max_handshake_rounds and (!client_done or !server_done)) : (rounds += 1) {
        if (!client_done) {
            const rc = ssl.SSL_do_handshake(client_ssl);
            if (rc == 1) client_done = true
            else {
                const err = ssl.SSL_get_error(client_ssl, rc);
                if (err != ssl.SSL_ERROR_WANT_READ and err != ssl.SSL_ERROR_WANT_WRITE)
                    return error.HandshakeFailed;
            }
        }
        if (!server_done) {
            const rc = ssl.SSL_do_handshake(server_ssl);
            if (rc == 1) server_done = true
            else {
                const err = ssl.SSL_get_error(server_ssl, rc);
                if (err != ssl.SSL_ERROR_WANT_READ and err != ssl.SSL_ERROR_WANT_WRITE)
                    return error.HandshakeFailed;
            }
        }
    }
    if (!client_done or !server_done) return error.HandshakeFailed;

    // Check kTLS BIO status after handshake.
    const ktls_available = ktls.isKtlsRuntimeAvailable();
    const server_tx = if (ssl.SSL_get_wbio(server_ssl)) |wbio| ssl.BIO_get_ktls_send(wbio) else false;
    const server_rx = if (ssl.SSL_get_rbio(server_ssl)) |rbio| ssl.BIO_get_ktls_recv(rbio) else false;

    // Invariant 1: RX cannot be active without TX.
    // TX-only is valid (some kernels/ciphers support TX but not RX offload).
    // RX-only would indicate a setup bug — OpenSSL always enables TX first.
    if (server_rx) {
        try std.testing.expect(server_tx);
    }

    // Invariant 2: on non-kTLS host, both must be false.
    if (!ktls_available) {
        try std.testing.expect(!server_tx);
        try std.testing.expect(!server_rx);
    }

    // Invariant 3: if either direction is active, the kernel runtime must be available.
    // (Sanity: kTLS cannot activate without the kernel tls module.)
    if (server_tx or server_rx) {
        try std.testing.expect(ktls_available);
    }
}
```

This test makes three hard assertions on every host:
- RX implies TX (no RX-only state — catches setup ordering bugs)
- Non-kTLS host → both false (fallback works)
- If kTLS active in either direction → kernel runtime was available (causal consistency)

TX-only is explicitly allowed (valid on kernels that support TX offload but not RX for a given cipher). On a kTLS-capable host with OpenSSL 3.x, `server_tx == true` confirms native kTLS activated in this environment and configuration. On a non-kTLS host or BoringSSL, all three pass via the false path, confirming graceful fallback. Non-Linux runners and checkouts without the test cert fixtures skip this test explicitly via `error.SkipZigTest`.

**Step 6: Integration smoke test**

Verify the full server stack still works after the kTLS architecture change. These are functional correctness checks (connections succeed, data flows), not kTLS-specific assertions — the unit test in Step 5 covers kTLS BIO behavior directly.

```bash
zig build test-integration-tcp-runtime
```

With kTLS force-disabled (confirms userspace fallback path works end-to-end):
```bash
SERVAL_DISABLE_KTLS=1 zig build test-integration-tcp-runtime
```

Both commands exit non-zero on any test failure.
