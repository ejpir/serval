# Zig io_uring + Threaded Patch Quality Plan

**Goal:** Bring the current Zig toolchain patch set for `zig-0.16.0-dev.3153+d6f43caad` to a quality level that is defensible against Zig stdlib expectations while keeping both fixes we need:

- `Threaded` backend connect timeout support
- `Uring` backend networking support

This plan assumes we want production-worthy behavior first and "closest possible to upstream shape" second. The work should reduce patch risk, remove known contract violations, and keep the Linux default backend usable instead of punting timeout support with `error.OptionUnsupported`.

## Scope

Target patch:

- `integration/toolchains/zig-0.16.0-dev.3153+d6f43caad-uring.patch`

Primary stdlib files affected by the patch:

- `lib/std/Io/Threaded.zig`
- `lib/std/Io/Uring.zig`
- `lib/std/Io.zig` only if batch-owned state needs a minimal storage extension
- `lib/std/os/linux/IoUring.zig` only if probe helpers or wrapper comments need adjustment

## Current Findings Driving This Plan

1. The `Threaded` connect-timeout implementation is directionally correct and should be kept, but it still needs explicit tests and cleanup review.
2. The current `Uring` batch `net_receive` implementation is not upstream-grade:
   - it allocates per operation from `std.heap.page_allocator`
   - it smuggles a heap pointer through `pending.userdata[3]`
   - it can return `error.ConcurrencyUnavailable` from `batchDrainSubmitted(..., concurrency = false)`, violating the function contract
3. `batch.userdata` is already part of the completion-chain and timeout mechanism in `Uring`; it cannot be reused as a plain pointer to batch-owned receive state.
4. `receiveManyTimeout` semantics are underspecified in the current patch. The single-op `operateTimeout` path is used by `Socket.receiveManyTimeout`, and that API promises that more than one message may be returned.
5. The current patch turns on `Uring` networking hooks unconditionally even though some `io_uring` socket opcodes are newer than the baseline kernels we should tolerate.

## Design Constraints

1. Keep both backends functional.
2. Do not regress the Linux default backend for `connect(..., .timeout != .none)`.
3. Avoid per-op heap allocation in the `Uring` batch fast path.
4. Preserve `Io.Batch` invariants:
   - `awaitAsync` must not fail with `error.ConcurrencyUnavailable`
   - `cancel` must leave `batch.userdata == null`
   - pending operation state must be fully reclaimed on completion or cancel
5. Prefer sync fallbacks for control-plane socket setup over relying on very new `io_uring` opcodes.

## Target Architecture

### Threaded

Keep the `Threaded.zig` connect-timeout approach:

- open socket
- save file status flags
- enable `NONBLOCK`
- call `connect`
- if it returns `WouldBlock` or `ConnectionPending`, wait with `poll`
- read `SO_ERROR`
- restore original flags

This is the right shape for the blocking backend.

### Uring

Split `Uring` networking into two classes:

1. Control-plane socket setup performed via sync syscall helpers entered through `CancelRegion.Sync.Maybe`:
   - socket creation
   - setsockopt
   - bind
   - listen
   - getsockname

2. Data-plane I/O and connection progress done with `io_uring` where supported:
   - accept
   - connect
   - sendmsg
   - recvmsg
   - readv

This reduces dependency on the newest socket opcodes while still preserving the value of the `Uring` backend.

## Workstream 1: Finalize Threaded Connect Timeout

### Files

- `lib/std/Io/Threaded.zig`
- `lib/std/Io/Threaded/test.zig` or the nearest stdlib test entry point used by this backend

### Changes

1. Keep `netConnectIpPosix` dispatching to `posixConnectWithTimeout` when `options.timeout != .none`.
2. Keep `posixConnectCheckSoError`, `posixGetStatusFlags`, and `posixSetStatusFlags`.
3. Review the deferred flag restore path so failures are treated as a deliberate stdlib-style best-effort cleanup path rather than an unexplained silent swallow.
4. Keep the zero-length `netWrite` guard already added in the patch.

### Tests

Add backend tests for:

1. `connect` with `timeout != .none` to a listening localhost socket succeeds.
2. `connect` with `timeout != .none` to a closed localhost port returns `error.ConnectionRefused` or `error.Timeout`, but never panics.
3. `connect` with `timeout == .none` still preserves existing behavior.

## Workstream 2: Reshape Uring Socket Setup

### Files

- `lib/std/Io/Uring.zig`

### Changes

Move these paths off direct `io_uring` socket opcodes and onto sync fallbacks:

1. `netListenIp`
2. `netBindIp`
3. helper paths for `socket`, `bind`, `listen`, and `getsockname` when used only for setup

Use:

- `CancelRegion.Sync.Maybe`
- sync syscalls already patterned elsewhere in `Uring.zig`

Reason:

- `IORING_OP_SOCKET`, `IORING_OP_BIND`, and `IORING_OP_LISTEN` are newer and not required for the value we need from the `Uring` backend.
- Control-plane setup does not benefit materially from asynchronous SQEs.

## Workstream 3: Add Uring Capability Gating

### Files

- `lib/std/Io/Uring.zig`
- possibly `lib/std/os/linux/IoUring.zig` if a small helper is needed

### Changes

Add explicit capability bits on `Evented`, populated during `Uring.init` from an `io_uring` probe.

Minimum probe bits if setup moves to sync fallbacks:

1. `have_accept`
2. `have_connect`
3. `have_sendmsg`
4. `have_recvmsg`

If any setup path still uses `IORING_OP_SOCKET`, `IORING_OP_BIND`, or `IORING_OP_LISTEN`, those need probe bits too.

### Behavior

1. If `ACCEPT` is unavailable, use a sync accept fallback.
2. If `CONNECT` is unavailable, use a sync nonblocking connect fallback with timeout support.
3. If `SENDMSG` or `RECVMSG` are unavailable, use sync fallback paths.

This keeps the backend functional on kernels that can run the `Uring` runtime but do not expose every desired network opcode.

## Workstream 4: Implement Uring Connect Timeout Properly

### Files

- `lib/std/Io/Uring.zig`

### Changes

Replace:

```zig
if (options.timeout != .none) return error.OptionUnsupported;
```

with a real timeout-aware connect path.

Preferred implementation:

1. queue `CONNECT`
2. if timeout is finite, set `IOSQE_IO_LINK` on that SQE
3. queue `LINK_TIMEOUT`
4. yield
5. map completion errno to `net.IpAddress.ConnectError`

This should mirror the existing `IO_LINK + LINK_TIMEOUT` pattern already used elsewhere in `Uring.zig`.

### Required behavior

1. finite timeout returns `error.Timeout` when the deadline expires
2. success path still returns connected socket + local address
3. `ConnectionRefused`, `HostUnreachable`, `NetworkUnreachable`, and `AccessDenied` remain mapped explicitly

If `CONNECT` is not supported by probe, use the same nonblocking connect-with-timeout logic as the `Threaded` backend under a sync fallback.

## Workstream 5: Redesign Batched `net_receive`

### Files

- `lib/std/Io/Uring.zig`
- possibly `lib/std/Io.zig` if the cleanest design needs a small storage extension

### Non-negotiable fixes

1. `awaitAsync` for `net_receive` must never allocate per operation.
2. `awaitAsync` for `net_receive` must never return `error.ConcurrencyUnavailable`.
3. `batchCancel` must reclaim every receive-state resource and leave `batch.userdata == null`.

### Correct design direction

The current design uses:

- `std.heap.page_allocator.create(BatchNetReceivePending)`
- `pending.userdata[3] = @intFromPtr(pending_state)`

That should be replaced with batch-owned receive state.

### Proposed structure

Introduce a batch-owned wrapper used only by the `Uring` backend:

```zig
const BatchBackendState = struct {
    completion_head: ?*anyopaque align(@max(@alignOf(?*anyopaque), 4)) = null,
    recv_state: []BatchNetReceiveState,
};

const BatchNetReceiveState = struct {
    active: bool = false,
    socket_handle: fd_t = -1,
    flags: net.ReceiveFlags = .{},
    message_buffer: []net.IncomingMessage = &.{},
    data_buffer: []u8 = &.{},
    message_count: u32 = 0,
    data_used: usize = 0,
    waiting_for_first: bool = true,
    storage: PosixAddress = undefined,
    iov: iovec = undefined,
    msg: linux.msghdr = undefined,
};
```

Use `batch.userdata` to point to this wrapper, not directly to the completion chain.

Then adjust the current `batch.userdata` users so they operate on:

- `state.completion_head` for CQE chaining and timeout tokens
- `state.recv_state[index]` for active receive state keyed by `batch.storage` index

Do not allocate receive slots separately. One `recv_state` entry per `batch.storage` entry is enough, because a storage index can only hold one active operation at a time.

### Why this is necessary

`batch.userdata` is already used by:

1. completion-chain enqueue
2. timeout insertion
3. timeout removal

So it cannot simultaneously be a raw `recv_pending` pointer without a wrapper.

### Concrete `Uring.zig` patch shape

Add these backend-private helpers:

```zig
fn batchBackendState(ev: *Evented, batch: *Io.Batch) Io.ConcurrentError!*BatchBackendState
fn batchBackendStateOrNull(batch: *Io.Batch) ?*BatchBackendState
fn batchBackendStateDeinit(ev: *Evented, batch: *Io.Batch) void
fn prepareNetReceiveMsg(state: *BatchNetReceiveState) void
fn finishNetReceiveFirst(state: *BatchNetReceiveState, res: i32) struct { ?net.Socket.ReceiveError, usize }
fn drainNetReceiveReady(sync: *CancelRegion.Sync, state: *BatchNetReceiveState) struct { ?net.Socket.ReceiveError, usize }
```

Intended call sites:

1. `batchDrainSubmitted`
   - `awaitAsync`: call `ev.netReceive(...)` directly and complete immediately
   - `awaitConcurrent`: initialize `state.recv_state[index]`, call `prepareNetReceiveMsg`, queue one `RECVMSG`

2. `batchDrainReady`
   - take `ev` and `maybe_sync` as parameters
   - read CQEs from `batchBackendState.completion_head`
   - for `.net_receive` success: decode the first datagram, then call `drainNetReceiveReady(try maybe_sync.enterSync(ev), state)`
   - for `.net_receive` completion or cancellation: clear `state.recv_state[index].active`

3. `batchAwaitAsync` and `batchAwaitConcurrent`
   - pass `ev` and `maybe_sync` into `batchDrainReady`
   - destroy backend state when the batch becomes fully unused again

4. `batchCancel`
   - cancel outstanding CQEs as today
   - after all pending operations are reclaimed, call `batchBackendStateDeinit(ev, batch)`

## Workstream 6: Fix `awaitAsync` vs `awaitConcurrent` Semantics for `net_receive`

### Files

- `lib/std/Io/Uring.zig`

### `awaitAsync`

For `.net_receive` in `batchDrainSubmitted(..., concurrency = false)`:

1. do not queue a synthetic concurrent receive SQE path
2. call `ev.netReceive(...)` synchronously
3. materialize a completion directly if data arrives
4. if no concurrency is needed, do not allocate batch receive state

This restores the documented `awaitAsync` contract.

### `awaitConcurrent`

For `.net_receive` in `batchDrainSubmitted(..., concurrency = true)`:

1. allocate or initialize batch-owned receive slots once
2. stage `msghdr`, `iovec`, source-address storage, and target `IncomingMessage`
3. queue `RECVMSG`
4. decode completion into the corresponding slot in `batchDrainReady`

## Workstream 7: Resolve `receiveManyTimeout` Semantics Explicitly

This was missing from the earlier plan and must be settled before implementation.

### Problem

`Socket.receiveManyTimeout` uses `Io.operateTimeout` with a single `.net_receive` operation. The API says it may return more than one message. The current patch only stages one message in the concurrent `Uring` path.

### Acceptable resolutions

Option A: Full support

Recommended design:

1. do not use `recvmmsg` or `io_uring` multishot `recv`
   - `recvmmsg` does not map cleanly to the stdlib API because `IncomingMessage` uses one caller-supplied shared data buffer rather than one iovec per message
   - `Threaded` already documents `recvmmsg` timeout issues in the current tree
   - `io_uring` multishot `recv` does not provide the `recvmsg` metadata this API needs (`from`, control data, flags)

2. treat one `.net_receive` as a two-phase state machine
   - `wait_first`: wait for the first datagram, with timeout if requested
   - `drain_ready`: after the first datagram arrives, stop waiting and drain only immediately-ready datagrams without blocking again

3. keep explicit batch-owned per-operation state
   - socket handle
   - receive flags
   - caller `message_buffer`
   - caller `data_buffer`
   - `message_count`
   - `data_used`
   - scratch `PosixAddress`
   - scratch `iovec`
   - scratch `msghdr`

4. submission behavior
   - if `message_buffer.len == 0` or `data_buffer.len == 0`, complete immediately with `{ null, 0 }`
   - build the first `msghdr` against `message_buffer[0]` and the full remaining `data_buffer`
   - submit exactly one blocking `RECVMSG` for the first datagram
   - if a timeout is requested, arm it only for this first blocking receive

5. completion behavior for the first datagram
   - on success, materialize `message_buffer[0]`
   - then enter sync through `CancelRegion.Sync.Maybe` and run a bounded nonblocking `recvmsg(MSG_DONTWAIT)` drain loop for additional messages
   - this avoids a complex multi-submit batch state machine while still using `io_uring` for the only blocking part

6. drain loop stop conditions
   - `message_buffer` is full
   - `data_buffer` is exhausted
   - socket returns `EAGAIN` / `WouldBlock`
   - a non-retryable receive error occurs

7. result semantics
   - timeout before the first message: `{ error.Timeout, 0 }`
   - fatal receive error before the first message: `{ err, 0 }`
   - timeout after at least one message: not applicable, because timeout only gates `wait_first`
   - `WouldBlock` after at least one message: `{ null, message_count }`
   - fatal receive error after at least one message: `{ err, message_count }`

8. required edge-case rules
   - `peek`: stop after one message even if more space remains, because peeking cannot advance the socket queue to a second datagram
   - `MSG_TRUNC`: size `message.data` using `min(returned_len, remaining_data.len)` so the API never slices beyond the caller buffer even when the kernel reports the full datagram length
   - zero-length datagrams: count as one received message and do not advance `data_used`
   - control buffers are per-message: each iteration must use `message_buffer[message_count].control`, not slot 0's control slice

9. implementation consequence
   - `batchDrainReady` will need access to `ev` and `maybe_sync`, because the first `RECVMSG` CQE is completed asynchronously but the post-first-message drain happens synchronously in bounded nonblocking mode

10. tests required for this option
   - timeout before first datagram returns `error.Timeout`
   - two queued datagrams return count `2`
   - one queued datagram plus later idle socket returns count `1`, not `error.Timeout`
   - oversized datagram with `flags.trunc` does not overrun the slice
   - `peek` returns exactly one message
   - zero-length datagram is counted correctly

### Concrete single-op timed path in `Uring.zig`

`Socket.receiveManyTimeout` currently reaches `Io.operateTimeout`, which builds a one-element batch and uses the generic batch timeout path. That is not a precise fit for this state machine, because the timeout must apply only before the first datagram.

Concrete implementation shape:

1. add a `batchAwaitConcurrentSingleNetReceive` fast path inside `Uring.batchAwaitConcurrent`
2. trigger it only when:
   - `batch.storage.len == 1`
   - the batch contains exactly one submitted `.net_receive`
   - `timeout != .none`
3. in that fast path:
   - submit one `RECVMSG`
   - arm timeout only for that first receive
   - on first success, synchronously drain ready datagrams with `MSG_DONTWAIT`
   - return a normal `.net_receive` completion without routing through the generic batch timeout CQE chain
4. leave the existing generic timeout machinery in place for true multi-operation batches

This keeps the generic `Batch.awaitConcurrent` behavior unchanged while giving `receiveManyTimeout` the semantics its API actually promises.

Option B: Honest limitation with fallback

1. detect the single-op `operateTimeout` case
2. for timed `net_receive`, use a synchronous `recvmsg` loop with deadline handling
3. reserve concurrent batched `RECVMSG` for the true multi-operation batch API

Recommendation: **Option B** first.

Reason:

- it preserves the public semantics now
- it avoids inventing a large multishot state machine in the patch
- it keeps the `Uring` backend usable while keeping the implementation reviewable

## Workstream 8: Cleanup Adjacent Write Hazards

There are still pre-existing empty-`data` indexing hazards in `Uring.zig` around:

- `fileWriteStreaming`
- any helper still assuming `data[data.len - 1]` without guarding `data.len > 0`

This is adjacent cleanup, not the primary feature, but it should be included in the same patch series if it touches the same code paths.

## Workstream 9: Testing Matrix

### Threaded tests

1. connect timeout success
2. connect timeout refusal or deadline expiry without panic
3. connect no-timeout regression check

### Uring tests

1. TCP listen + accept + connect + read + write
2. TCP connect with finite timeout succeeds
3. TCP connect with finite timeout to closed port returns `ConnectionRefused` or `Timeout`, not `OptionUnsupported`
4. UDP `receiveTimeout` returns one datagram with correct source address
5. UDP `receiveManyTimeout` preserves documented semantics under the chosen implementation strategy
6. `Batch.awaitAsync` with `.net_receive` does not fail with `error.ConcurrencyUnavailable`
7. `Batch.awaitConcurrent` with `.net_receive` frees batch-owned state on completion
8. `Batch.cancel` with pending `.net_receive` frees batch-owned state and leaves `batch.userdata == null`

### Findings from applied 3039 validation

These findings came from applying the current patch to the installed
`/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad` toolchain and then
running the targeted integration suites.

1. **The repo patch is canonical against a pristine toolchain tarball, not an
   already-mutated installed tree.**
   - Finding: direct `patch -p0` against the installed `/usr/local` tree failed
     once parts of the earlier `3039` patch were already present. `Threaded.zig`
     reported context drift and `Uring.zig` reported reversed or previously
     applied hunks.
   - Fix: keep
     `integration/toolchains/zig-0.16.0-dev.3153+d6f43caad-uring.patch` as the
     canonical patch against the pristine `tar.xz` contents, and use an
     incremental patch only when bringing an already-mutated local toolchain to
     the desired final state.

2. **The `Uring` batch receive redesign surfaced compile-time integration bugs
   that were not obvious from the patch diff alone.**
   - Finding: local variables named `allocator` shadowed the `Evented.allocator`
     method and failed to compile.
   - Fix: rename those locals to `backing_allocator`.
   - Finding: `batchDrainReady` now performs synchronous post-CQE drain work and
     therefore needs access to `ev`; leaving the old signature in place caused a
     compile failure.
   - Fix: change the helper to `batchDrainReady(ev, batch)` and thread `ev`
     through all call sites in `batchAwaitAsync`, `batchAwaitConcurrent`, and
     `batchCancel`.
   - Finding: after threading `ev` into `batchCancel`, the old `_ = ev;`
     discard became stale and broke the build.
   - Fix: remove the stale discard.

3. **The cleanup items identified during review were required in practice and
   should remain part of the plan.**
   - Finding: the `Threaded` timeout path still had a restore-path `catch {}`
     that was below Zig stdlib quality.
   - Fix: restore original fd flags explicitly on both success and failure
     paths; do not silently swallow restore failures.
   - Finding: concurrent `net_receive` treating `.INTR` as a successful
     zero-message completion would produce incorrect receive semantics.
   - Fix: route `.INTR` through the terminal error path instead of returning
     `{ null, 0 }`.

4. **The current patch shape is validated against the repository's exercised
   runtime paths, but not yet against the full toolchain verification matrix.**
   - Finding: the targeted runtime suites that exercise the patched networking
     paths all passed after the fixes above.
   - Fix/result:
     - `test-integration-tcp-runtime`: 5/5 passed
     - `test-integration-udp-runtime`: 6/6 passed
     - `test-integration-h2c-cancel-propagation`: 1/1 passed
   - Remaining gap: full
     `/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig build` and
     `/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig build test`
     have not been run yet against the patched toolchain.

### Verification matrix

Run at least:

```bash
/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig build
/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig build test
```

If stdlib-targeted verification is wired in the repo, also run the patch-application and integration path that exercises the patched toolchain.

Targeted verification already completed:

```bash
/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig build test-integration-tcp-runtime
# All 5 tests passed

/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig build test-integration-udp-runtime
# All 6 tests passed

/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig build test-integration-h2c-cancel-propagation
# All 1 tests passed
```

## Commit Split

Recommended commit order:

1. `toolchain(threaded): finish connect timeout support and add tests`
2. `toolchain(uring): move socket setup to sync fallbacks and add opcode capability gating`
3. `toolchain(uring): implement timeout-aware connect`
4. `toolchain(uring): redesign batch net_receive ownership and fix awaitAsync contract`
5. `toolchain(uring): restore receiveManyTimeout semantics and add backend tests`
6. `toolchain(uring): clean adjacent zero-length write hazards`

## Explicit Non-goals

1. Upstreaming every newest socket opcode just because `io_uring` has one.
2. Preserving the current per-op heap allocation design.
3. Keeping `error.OptionUnsupported` for connect timeout on Linux `Uring`.

## Exit Criteria

The plan is complete when all of the following are true:

1. `Threaded` connect timeout no longer panics and is tested.
2. `Uring` networking remains enabled.
3. `Uring` connect timeout is implemented, not rejected.
4. `awaitAsync` does not violate its no-concurrency-error contract.
5. `batchCancel` fully reclaims `Uring` batch receive state.
6. `receiveManyTimeout` behavior is explicitly implemented and tested.
7. Capability gating or sync fallback prevents accidental dependence on unsupported opcodes.
8. The patch series is split into reviewable logical commits.
