# io_uring Networking Patch Quality Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bring the io_uring Evented networking patch (`zig-0.16.0-dev.2821+3edaef9e0-uring.patch`) to Zig upstream quality — correct io_uring semantics, error handling parity with Threaded backend, clean commit separation.

**Architecture:** The patch enables networking on the io_uring `Evented` backend by implementing `netListenIp`, `netAccept`, `netConnectIp`, `netSend`, `netRead`, `netWrite`, and batch `net_receive`. Each function follows the `while(true) { awaitIoUring → enqueue SQE → yield → switch errno }` pattern. Fixes align error handling with both io_uring kernel semantics and the reference Threaded.zig backend.

**Tech Stack:** Zig 0.16.0-dev, Linux io_uring (kernel 6.11+ for BIND/LISTEN opcodes), patch format

**Reference files:**
- Patch: `integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch`
- Patched result: `.tmp_stdlib/Uring.zig`
- Reference backend: `/usr/local/zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/lib/std/Io/Threaded.zig`

---

## Background: io_uring Kernel Semantics

These kernel facts drive the correctness fixes below:

1. **CONNECT + IORING_FEAT_FAST_POLL (kernel 5.7+):** io_uring internally handles `EINPROGRESS`/`EAGAIN` by arming poll on the socket and retrying. The CQE should never contain `-EINPROGRESS` or `-EAGAIN`. No explicit runtime feature check is needed because the Uring backend already requires `IORING_SETUP_COOP_TASKRUN` (5.19) and `IORING_SETUP_SINGLE_ISSUER` (6.0) at init — if `io_uring_setup()` succeeds, the kernel is at minimum 6.0, well past the 5.7 threshold for `FAST_POLL`. The networking path further requires `IORING_OP_BIND`/`IORING_OP_LISTEN` (6.11). Treating `EINPROGRESS`/`EAGAIN` as `errnoBug` is therefore correct. Sources: liburing issues #26, #671, #841; kernel commit `3fb1bd68817288`.

2. **ACCEPT:** io_uring internally handles `EAGAIN` — it arms poll and waits for a connection. `SOCK_NONBLOCK` on accepted sockets is unnecessary when all I/O goes through io_uring SQEs. `SOCK_CLOEXEC` is still needed.

3. **SENDMSG buffer lifetime:** With `IORING_FEAT_SUBMIT_STABLE` (kernel 5.5+), `msghdr` and `iovec` metadata need only survive until SQE submission. Data buffers must survive until CQE completion. Since the Zig backend yields the fiber (which preserves the stack frame), all stack-local `msghdr`/`iov` structs remain valid through completion. This is correct.

4. **LISTEN/BIND (kernel 6.11+):** Synchronous wrappers — exist for the direct descriptor use case, not for async benefit. Complete immediately in CQE.

5. **sendmsg ordering:** Multiple outstanding `SENDMSG` SQEs to the same TCP socket may execute out of order unless linked with `IOSQE_IO_LINK`. The current serial approach (one SQE at a time) avoids this issue.

---

## Task 1: Separate `chdir` bug fix from networking patch

The `chdir` fix (line 4302: `ev.chdir(...)` → `chdir(...)`) is a real bug fix unrelated to networking. Zig authors expect clean commit separation.

**Files:**
- Modify: `integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch`

**Step 1: Extract the chdir hunk into its own patch file**

Create `zig-0.16.0-dev.2821+3edaef9e0-chdir-fix.patch` containing only the hunk at `@@ -4199,7 +4304,7 @@`:

```diff
--- zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/lib/std/Io/Uring.zig
+++ zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/lib/std/Io/Uring.zig
@@ -4199,7 +4199,7 @@
     const dir_path_posix = try pathToPosix(dir_path, &path_buffer);
     var sync: CancelRegion.Sync = try .init(ev);
     defer sync.deinit(ev);
-    return ev.chdir(&sync, dir_path_posix);
+    return chdir(&sync, dir_path_posix);
 }
```

**Step 2: Remove the chdir hunk from the networking patch**

Remove the `@@ -4199,7 +4304,7 @@` hunk from the uring patch and adjust the line number offsets in subsequent hunks (they shift by 0 lines since the chdir hunk is a 1:1 replacement).

**Step 3: Verify both patches apply cleanly**

```bash
cd /usr/local/zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/lib/std/Io
# Apply chdir fix first
patch --dry-run -p5 < /home/nick/repos/serval/integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-chdir-fix.patch
# Then networking
patch --dry-run -p5 < /home/nick/repos/serval/integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch
```

**Step 4: Update integration build to apply both patches**

Search for where the patch is applied in the build system (likely `Makefile` or a script in `integration/toolchains/`) and add the chdir patch as a separate step.

**Step 5: Commit**

```
fix(toolchain): separate chdir bug fix from io_uring networking patch
```

---

## Task 2: Fix `connect()` EAGAIN/EINPROGRESS handling

**The bug:** `connect()` at Uring.zig:5732 returns `error.WouldBlock` for `EAGAIN`/`EINPROGRESS`. This is correct for the Threaded backend (blocking syscalls) but wrong for io_uring. With `IORING_FEAT_FAST_POLL` (kernel 5.7+), io_uring handles `EINPROGRESS` internally — it arms poll on the socket and retries the connect. The CQE should never contain these errnos.

**The fix:** Treat `AGAIN`/`INPROGRESS` as `errnoBug` — if we see them, something is fundamentally wrong (kernel too old or bug).

**Files:**
- Modify: `integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch` (the `connect` function)

**Step 1: Change the error handling**

In the `connect()` function, change:

```zig
// BEFORE (wrong for io_uring):
.AGAIN, .INPROGRESS => return error.WouldBlock,
```

to:

```zig
// AFTER (correct — io_uring handles EINPROGRESS internally via FAST_POLL):
.AGAIN, .INPROGRESS => |err| return errnoBug(err),
```

**Step 2: Also move `ALREADY` to `errnoBug`**

`EALREADY` means "a previous connect on this non-blocking socket is still in progress." With io_uring, the previous connect should have completed via the CQE before we submit another. If we get `EALREADY`, it means we're double-connecting — a programming bug.

```zig
// BEFORE:
.ALREADY => return error.ConnectionPending,

// AFTER:
.ALREADY => |err| return errnoBug(err),
```

**Step 3: Verify the patch applies and builds**

```bash
cd .tmp_stdlib && zig build-lib Uring.zig  # or however the integration test works
```

**Step 4: Commit**

```
fix(toolchain): correct io_uring connect error handling for EAGAIN/EINPROGRESS/EALREADY
```

---

## Task 3: Fix `netWriteMsg` DESTADDRREQ error handling

**The bug:** `netWriteMsg` at Uring.zig:5442 returns `error.SocketNotBound` for `DESTADDRREQ`. This function is only called from `netWrite` (stream writes on connected sockets, with `name = null`). For a connected socket, `DESTADDRREQ` is a programming error — the socket should already be connected. The Threaded backend correctly returns `errnoBug(.DESTADDRREQ)` in `netWritePosix`.

**Files:**
- Modify: `integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch` (the `netWriteMsg` function)
- Modify: the `netWrite` function's error catch block

**Step 1: Change `netWriteMsg` DESTADDRREQ to errnoBug**

```zig
// BEFORE:
.DESTADDRREQ => return error.SocketNotBound,

// AFTER (matches Threaded.zig netWritePosix):
.DESTADDRREQ => |err| return errnoBug(err),
```

**Step 2: Remove `SocketNotBound` from `netWrite`'s error catch**

In `netWrite`, the error catch block at line 5558 has:

```zig
error.SocketNotBound => return error.SocketNotBound,
```

Remove this line — `SocketNotBound` is no longer in `netWriteMsg`'s error set, so Zig's exhaustive error handling will reject it.

**Step 3: Verify compilation**

The compiler will enforce that the error sets are correct. If `SocketNotBound` is still referenced, compilation fails.

**Step 4: Commit**

```
fix(toolchain): netWriteMsg DESTADDRREQ should be errnoBug for connected stream sockets
```

---

## Task 4: Add missing assert in `netWrite` splat loop

**The bug:** The Threaded backend's `netWritePosix` (Threaded.zig:13412) has `assert(buf.len == splat_buffer.len)` inside the splat `while` loop. This validates that after the first `@memset`+`addBuf`, the `buf` slice equals the full `splat_buffer`. If `splat < splat_buffer.len`, `buf` would be shorter, and the while loop's condition (`remaining_splat > splat_buffer.len`) would be false — so the assert never fires. But if there's a logic error, the assert catches it before silently using wrong-length buffers.

The Uring `netWrite` is missing this assert.

**Files:**
- Modify: `integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch` (the `netWrite` function)

**Step 1: Add the assert**

In `netWrite`, inside the splat `while` loop (after `while (remaining_splat > splat_buffer.len and iovecs.len - msg.iovlen != 0) {`), add:

```zig
// BEFORE:
while (remaining_splat > splat_buffer.len and iovecs.len - msg.iovlen != 0) {
    addBuf(&iovecs, &msg.iovlen, splat_buffer);

// AFTER (matches Threaded.zig:13412):
while (remaining_splat > splat_buffer.len and iovecs.len - msg.iovlen != 0) {
    assert(buf.len == splat_buffer.len);
    addBuf(&iovecs, &msg.iovlen, splat_buffer);
```

**Step 2: Verify `assert` is in scope**

Check that `std.debug.assert` is available as `assert` at this point in the file. The existing Uring.zig imports should already have it (search for `const assert =`).

**Step 3: Commit**

```
fix(toolchain): add missing splat buffer length assertion in io_uring netWrite
```

---

## Task 5: Align `netSendOne` error handling with Threaded

**The issue:** `netSendOne` in the Uring patch handles `CONNREFUSED` (line 5312) but the Threaded `netSendOne` does NOT handle `CONNREFUSED` — it falls through to `unexpectedErrno`. Check whether `CONNREFUSED` is actually possible from `sendmsg`.

**Files:**
- Modify: `integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch`

**Step 1: Audit `netSendOne` errors against Threaded**

Compare every errno case in the Uring `netSendOne` (lines 5287-5313) against the Threaded `netSendOne` (Threaded.zig:13098-13127). Document any differences:

| errno | Uring | Threaded | Action |
|-------|-------|----------|--------|
| CONNREFUSED | `error.ConnectionRefused` | not handled (falls to `else`) | Keep — valid for UDP sendmsg |
| All others | should match | reference | Verify match |

`CONNREFUSED` is valid from `sendmsg` on connectionless sockets (ICMP port unreachable from a previous send). The Threaded backend missed it. The Uring version is actually MORE correct here — keep it.

**Step 2: Verify no other discrepancies exist**

Walk through every case in both error switches. The Uring version should be a superset of Threaded (same errors + any io_uring-specific ones like treating AGAIN as errnoBug).

**Step 3: Commit (if changes needed)**

```
fix(toolchain): align io_uring netSendOne error handling with Threaded backend
```

---

## Task 6: Add inline comments on errnoBug cases

**The issue:** The pre-existing `bind()` function (written by Zig authors) annotates every errnoBug case with a brief comment explaining why it's a bug:

```zig
.BADF => |err| return errnoBug(err), // File descriptor used after closed.
.INVAL => |err| return errnoBug(err), // invalid parameters
.NOTSOCK => |err| return errnoBug(err), // invalid `sockfd`
.FAULT => |err| return errnoBug(err), // invalid `addr` pointer
```

The new functions have bare `errnoBug` without comments. Add comments matching the `bind()` style to all new functions.

**Files:**
- Modify: `.tmp_stdlib/Uring.zig` — all new networking functions

**Step 1: Add comments to `netAccept` errnoBug cases**

```zig
// BEFORE:
.AGAIN => |err| return errnoBug(err),
.BADF => |err| return errnoBug(err),
.FAULT => |err| return errnoBug(err),
.NOTSOCK => |err| return errnoBug(err),
.OPNOTSUPP => |err| return errnoBug(err),

// AFTER:
.AGAIN => |err| return errnoBug(err), // io_uring handles EAGAIN internally.
.BADF => |err| return errnoBug(err), // File descriptor used after closed.
.FAULT => |err| return errnoBug(err), // Invalid `addr` pointer.
.NOTSOCK => |err| return errnoBug(err), // `listen_handle` is not a socket.
.OPNOTSUPP => |err| return errnoBug(err), // Socket type does not support accept.
```

**Step 2: Add comments to `netSendOne` errnoBug cases**

```zig
.BADF => |err| return errnoBug(err), // File descriptor used after closed.
.DESTADDRREQ => |err| return errnoBug(err), // Address is always provided in msghdr.
.FAULT => |err| return errnoBug(err), // Invalid pointer.
.INVAL => |err| return errnoBug(err), // Invalid argument.
.ISCONN => |err| return errnoBug(err), // Connected socket with destination address.
.NOTSOCK => |err| return errnoBug(err), // `handle` is not a socket.
.OPNOTSUPP => |err| return errnoBug(err), // Flags not supported by socket type.
```

**Step 3: Add comments to `netWriteMsg` errnoBug cases**

```zig
.ACCES => |err| return errnoBug(err), // Connected stream socket, no permission check.
.AGAIN => |err| return errnoBug(err), // io_uring handles EAGAIN internally.
.BADF => |err| return errnoBug(err), // File descriptor used after closed.
.DESTADDRREQ => |err| return errnoBug(err), // Stream socket is already connected.
.FAULT => |err| return errnoBug(err), // Invalid pointer.
.INVAL => |err| return errnoBug(err), // Invalid argument.
.ISCONN => |err| return errnoBug(err), // Already connected.
.MSGSIZE => |err| return errnoBug(err), // Stream socket has no message size limit.
.NOTSOCK => |err| return errnoBug(err), // `handle` is not a socket.
.OPNOTSUPP => |err| return errnoBug(err), // Flags not supported by socket type.
```

**Step 4: Add comments to `connect` errnoBug cases**

```zig
.AGAIN, .INPROGRESS => |err| return errnoBug(err), // io_uring handles EINPROGRESS via FAST_POLL.
.ALREADY => |err| return errnoBug(err), // Previous connect should have completed via CQE.
.BADF => |err| return errnoBug(err), // File descriptor used after closed.
.CONNABORTED => |err| return errnoBug(err), // Connection aborted during connect.
.FAULT => |err| return errnoBug(err), // Invalid `addr` pointer.
.ISCONN => |err| return errnoBug(err), // Socket is already connected.
.NOENT => |err| return errnoBug(err), // Invalid address path.
.NOTSOCK => |err| return errnoBug(err), // `socket_fd` is not a socket.
.PERM => |err| return errnoBug(err), // Firewall rules prevent connection.
.PROTOTYPE => |err| return errnoBug(err), // Socket type mismatch.
```

**Step 5: Add comments to `listen` errnoBug cases**

```zig
.BADF => |err| return errnoBug(err), // File descriptor used after closed.
.NOTSOCK => |err| return errnoBug(err), // `socket_fd` is not a socket.
.OPNOTSUPP => |err| return errnoBug(err), // Socket type does not support listen.
```

**Step 6: Add comments to batch `batchDrainReady` net_receive errnoBug cases**

```zig
.BADF => .{ errnoBug(.BADF), 0 }, // File descriptor used after closed.
.FAULT => .{ errnoBug(.FAULT), 0 }, // Invalid pointer.
.INVAL => .{ errnoBug(.INVAL), 0 }, // Invalid argument.
.NOTSOCK => .{ errnoBug(.NOTSOCK), 0 }, // Handle is not a socket.
.OPNOTSUPP => .{ errnoBug(.OPNOTSUPP), 0 }, // Flags not supported by socket type.
```

**Step 7: Commit**

```
style(toolchain): add inline comments on errnoBug cases matching bind() convention
```

---

## Task 7: Regenerate the patch from the corrected `.tmp_stdlib/Uring.zig`

After making all fixes to the patched `Uring.zig`, regenerate a clean diff.

**Step 1: Make all fixes directly to `.tmp_stdlib/Uring.zig`**

Apply tasks 2-6 as edits to the working copy.

**Step 2: Generate the new patch**

```bash
diff -u \
  /usr/local/zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/lib/std/Io/Uring.zig \
  .tmp_stdlib/Uring.zig \
  > integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch
```

Fix the header paths to use relative strip-prefix format matching the existing patch style:

```
--- zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/lib/std/Io/Uring.zig
+++ zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/lib/std/Io/Uring.zig
```

**Step 3: Verify patch applies cleanly**

```bash
cd /usr/local/zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/lib/std/Io
patch --dry-run -p5 < /home/nick/repos/serval/integration/toolchains/zig-0.16.0-dev.2821+3edaef9e0-uring.patch
```

**Step 4: Run the smoke tests**

```bash
# Run whatever integration test exercises the io_uring networking path
# Check .tmp_stdlib/evented_uring_smoke.zig for the test harness
```

**Step 5: Commit**

```
feat(toolchain): io_uring evented networking — listen/accept/connect/send/recv/write
```

---

## What was reviewed and deemed correct (no changes needed)

These were investigated and found to match Zig upstream quality:

| Area | Verdict | Reasoning |
|------|---------|-----------|
| `netAccept` without `SOCK_NONBLOCK` | Correct | io_uring does all I/O through SQEs; accepted sockets don't need non-blocking mode |
| `netAccept` `AGAIN => errnoBug` | Correct | io_uring handles EAGAIN internally for accept |
| `netReceive` (single) control ptr without null-check | Correct | `recvmsg` doesn't validate control ptr when controllen=0 (unlike `sendmsg`). Matches Threaded |
| `netSendOne` control ptr null-check | Correct | `sendmsg` validates ptr even when controllen=0. Defensive check matches Threaded comment |
| Batch `netReceive` using `page_allocator` | Correct | Consistent with other batch ops (`batch_open`, `batch_read`). Allocates full page for ~80B struct — wasteful but consistent |
| `netRead` delegating to `preadv` with null offset | Correct | `readv`/`READV` work on sockets. `offset=null` → `maxInt(u64)` → "current position" semantics |
| `netSend` serial sends (no SQE batching) | Acceptable | Threaded also sends one-at-a-time when `sendmmsg` unavailable. Batch path exists separately in `Io.Batch`. Avoids TCP ordering issues |
| `netConnectIp` rejecting timeout with `error.OptionUnsupported` | Better than Threaded | Threaded `@panic()`s. Error return is safer. io_uring timeout support via `LINK_TIMEOUT` is a follow-up |
| `netListenIp` structure | Correct | Uses `CancelRegion.Sync.Maybe`, calls `socket → setsockopt → bind → listen → getsockname`. Matches Threaded flow exactly |
| `netWriteMsg` vs `netSendOne` duplication | Acceptable | Different error semantics (stream vs datagram). Threaded also doesn't dedup `netWritePosix`/`netSendOne`. Matches codebase style |
| `listen()` using `IORING_OP_LISTEN` | Correct | Valid opcode (kernel 6.11+). Synchronous wrapper — completes immediately |
| `connect()` SQE field layout | Correct | `.off = addr_len`, `.addr = @intFromPtr(addr)` matches `io_uring_prep_connect` |
