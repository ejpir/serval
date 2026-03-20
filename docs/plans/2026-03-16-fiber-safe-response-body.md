# Fiber-Safe Response Body Forwarding

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix large payload test deadlock by making response body forwarding fiber-safe.

**Architecture:** The response path (`forwardResponse` → `forwardBody` → `forwardBodySplice`) uses raw `posix.poll()` which blocks the thread/fiber scheduler. When running concurrently with the background body-streaming fiber, this creates a deadlock: splice blocks waiting for upstream data, upstream can't send because it's waiting for the proxy to drain the request body, and the body fiber can't run because the scheduler is blocked. Fix: thread `Io` through the response path and use the existing fiber-safe `forwardBodyCopyFiber` (which uses io_uring-backed `netRead`/`netWrite`) instead of the raw-syscall splice path.

**Tech Stack:** Zig 0.16, io_uring, std.Io fiber runtime

---

### Task 1: Make `forwardBody` accept optional Io

**Files:**
- Modify: `serval-proxy/h1/body.zig:62-88`

**Step 1: Add Io parameter to forwardBody**

Change `forwardBody` signature to accept optional `Io`. When Io is provided, use `forwardBodyCopyFiber` (fiber-safe, io_uring-backed) instead of `forwardBodySplice` (raw syscall with blocking poll).

```zig
pub fn forwardBody(
    upstream: *Socket,
    client: *Socket,
    length_bytes: u64,
    io: ?Io,
) ForwardError!u64 {
    assert(upstream.get_fd() >= 0);
    assert(client.get_fd() >= 0);

    // When Io is available, use fiber-safe copy path (io_uring-backed netRead/netWrite).
    // This avoids blocking the fiber scheduler with raw splice poll(), which deadlocks
    // when running concurrently with the body-streaming background fiber.
    if (io) |runtime_io| {
        const result = try forwardBodyCopyFiber(upstream, client, length_bytes, runtime_io);
        assert(result <= length_bytes);
        return result;
    }

    // No Io: use zero-copy splice (non-concurrent path only).
    if (!upstream.is_tls() and !client.is_tls()) {
        if (comptime builtin.os.tag == .linux) {
            const result = try forwardBodySplice(upstream.get_fd(), client.get_fd(), length_bytes);
            assert(result <= length_bytes);
            return result;
        }
    }

    const result = try forwardBodyCopy(upstream, client, length_bytes);
    assert(result <= length_bytes);
    return result;
}
```

**Step 2: Build to verify compilation**

Run: `zig build 2>&1 | head -20`
Expected: Compilation error in response.zig (forwardBody call missing new argument) — confirms the signature change propagated.

---

### Task 2: Thread Io through response path

**Files:**
- Modify: `serval-proxy/h1/response.zig:29-30` (import)
- Modify: `serval-proxy/h1/response.zig:209-224` (forwardBody call site)

**Step 1: Pass io to forwardBody in forwardResponse**

In `forwardResponse`, the `io: Io` parameter is already available (line 119). Update the `forwardBody` call at line 223 to pass it:

```zig
total_body_bytes += try forwardBody(upstream_socket, client_socket, remaining, io);
```

Also make the pre-read body write fiber-safe (line 214):

```zig
if (pre_read_body.len > 0) {
    debugLog("recv: forwarding pre-read body bytes={d}", .{pre_read_body.len});
    try sendBuffer(&client_conn, io, pre_read_body);
    total_body_bytes += pre_read_body.len;
}
```

**Step 2: Build and run tests**

Run: `zig build` then `zig build test-integration-77`
Expected: PASS — large payload test no longer deadlocks.

---

### Task 3: Remove debug prints from forwardBodyCopyFiber

**Files:**
- Modify: `serval-proxy/h1/body.zig:443-454`

**Step 1: Remove debug print statements**

The `forwardBodyCopyFiber` function has debug print statements (lines 443-444, 452-453) that were added during development. Remove them since this is now a production code path.

**Step 2: Build to verify**

Run: `zig build`
Expected: Clean compilation.

---

### Task 4: Commit

```bash
git add serval-proxy/h1/body.zig serval-proxy/h1/response.zig
git commit -m "proxy: make response body forwarding fiber-safe

Thread Io through forwardBody so the response path uses io_uring-backed
netRead/netWrite instead of raw splice+poll. The blocking poll() in
forwardBodySplice was stalling the fiber scheduler, deadlocking when
running concurrently with the body-streaming background fiber on large
payloads."
```
