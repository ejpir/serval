# Relay Tunnel Fiber Cleanup Plan

## Goal

Replace the current upgraded-tunnel transport hybrid in `serval-proxy/tunnel.zig`
with a production-grade symmetric fiber/readiness model without regressing the
NetBird relay fixes that were required in March 2026.

This is a cleanup and hardening plan, not a speculative redesign. The current
implementation now works for the Android NetBird relay path, but it still
contains tactical retry/sleep behavior and asymmetric task structure that
should not remain as the long-term transport model.

## Why This Plan Exists

The NetBird relay regression exposed three concrete transport problems:

1. Long-lived upgraded-tunnel client reads were started with
   `std.Io.Group.async()`, which was not sufficient for the observed relay
   workload.
2. TLS read backpressure flattened `SSL_ERROR_WANT_READ` and
   `SSL_ERROR_WANT_WRITE` into one generic idle bucket.
3. Plain nonblocking relay-hop uploads were routed through Zig's buffered
   stream writer, which hid the real failure mode and was not robust on this
   path.

Those issues were fixed tactically by:

- switching long-lived relay work to `Group.concurrent()` in threaded runtimes
- preserving `WantRead` vs `WantWrite` through `serval-tls`
- using a direct bounded nonblocking `write(2)` loop for the plain relay hop

Those fixes are correct and must remain in place. The remaining issue is that
the upgraded-tunnel implementation is still structurally uneven:

- one direction is special-cased more than the other
- retry/sleep behavior still appears in protocol-adjacent code
- transport readiness semantics are still too visible at the tunnel layer

## Non-Goals

This plan does not introduce:

- WebSocket frame parsing in the tunnel path
- path-specific NetBird logic in `serval-proxy`
- unbounded background tasks
- a new module unless the existing `serval-proxy` and `serval-tls` files become
  materially harder to maintain

After `101 Switching Protocols`, the tunnel must remain a generic full-duplex
byte transport.

## Desired End State

The upgraded tunnel should behave like a proper symmetric fiber transport:

- one long-lived task per direction
- both directions scheduled with the same concurrency model
- explicit bounded cancellation and termination ownership
- no protocol logic depending on manual sleep/retry loops
- TLS reads preserving readiness intent (`want_read` vs `want_write`)
- plain-socket writes using explicit bounded nonblocking behavior
- final termination classified exactly once with stable observability

The tunnel layer should consume a transport contract that yields one of:

- bytes read or written
- clean peer close
- peer reset
- bounded timeout
- `want_read`
- `want_write`

Protocol code should not need to infer these from generic `WouldBlock`.

## Current State

The current upgraded-tunnel path is workable but transitional:

- downstream TLS reads now preserve `WantRead` and `WantWrite`
- long-lived threaded relay readers use `Group.concurrent()`
- plain relay upstream writes use a direct bounded nonblocking `write(2)` loop
- tunnel logs include byte counts, duration, side ownership, and termination

This is enough to match Caddy on the NetBird Android relay path, but it is not
yet the clean production transport model we want to maintain indefinitely.

## Work Items

### A1. Define the tunnel transport contract

Create or formalize a small internal contract for upgraded tunnel I/O that
separates transport readiness from tunnel lifecycle.

Required outputs:

- read result enum for:
  - bytes
  - eof
  - reset
  - want_read
  - want_write
  - timeout
- write result enum for:
  - bytes written
  - peer closed
  - want_read
  - want_write
  - timeout

Acceptance:

- `tunnel.zig` no longer interprets generic `WouldBlock`
- TLS and plain transport adapters both map into the same bounded surface

### A2. Make both tunnel directions symmetric

Remove the remaining asymmetry in how the two tunnel directions are executed.

Required:

- one long-lived task per direction
- same scheduling primitive for both directions in threaded runtimes
- same cancellation and completion rules in both directions

Acceptance:

- no inline-special direction remains in the upgraded tunnel fast path
- no observable bias where one direction can make progress only because the
  other remains inline on the caller stack

### A3. Move readiness waiting below the protocol loop

The tunnel loop should express "need read readiness" or "need write readiness",
not implement ad hoc timing/backoff itself.

Required:

- centralize bounded wait behavior behind transport helpers
- preserve timeout accounting and monotonic elapsed-time checks
- remove duplicated sleep/retry branches from tunnel-path logic where possible

Acceptance:

- tunnel loop reads as transport-state handling, not retry choreography
- timeout accounting stays explicit and bounded

### A4. Keep plain write behavior explicit and bounded

The plain relay-hop fix must remain intact during the refactor.

Required:

- keep direct nonblocking `write(2)` semantics for plain upgraded writes
- keep explicit handling for:
  - `EINTR`
  - `EAGAIN`
  - `EPIPE`
  - `ECONNRESET`
  - `ENOTCONN`
- keep bounded iteration count and timeout budget

Acceptance:

- no regression back to buffered writer wrappers on nonblocking upgraded fds
- exact unexpected errno remains observable

### A5. Preserve final termination ownership

Termination must still be finalized exactly once even when both directions race
to close or fail.

Required:

- explicit owner for final tunnel termination classification
- stable ordering between:
  - failure detection
  - termination finalization
  - final log snapshot

Acceptance:

- no mixed logs such as write failure paired with stale `idle_timeout`
- tunnel finalization remains assertion-safe under close races

## Testing Plan

### Unit and focused transport tests

Add or extend tests for:

- TLS read returning `WantRead`
- TLS read returning `WantWrite`
- plain write `EAGAIN`
- plain write `EPIPE`
- plain write `ECONNRESET`
- final termination snapshot after concurrent close race

### Integration tests

Add integration coverage for upgraded tunnels under:

- one request with no post-upgrade data
- first post-`101` client frame followed by upstream reply
- sustained bidirectional post-upgrade traffic
- upload-heavy tunnel traffic
- downstream close first
- upstream close first
- downstream TLS close-notify
- upstream reset while downstream still writing

### Real-system replay criteria

Before removing the transitional shape, rerun the real NetBird cases that
originally failed:

- Android relay connect through Serval
- Android sustained peer traffic / speedtest
- concurrent router + Android peer activity
- comparison against prior Caddy-good traces

Acceptance:

- no stall after the first `91 -> 35` relay exchange
- no early upstream close under upload-heavy Android relay traffic
- no duplicate `RST_STREAM` warning storms in the h2 bridge path

## Documentation Updates Required

When this work lands, update:

- `serval-proxy/README.md`
- `serval-tls/README.md`
- `serval-client/README.md`
- `serval-server/README.md`
- `serval/ARCHITECTURE.md` if transport ownership or concurrency wording changes

The documentation should clearly distinguish:

- tactical March 2026 relay fixes
- long-term production transport model

## Exit Criteria

This plan is complete when all of the following are true:

- upgraded tunnel directions are symmetric in execution model
- tunnel code no longer depends on ad hoc sleep/retry logic for correctness
- TLS readiness intent is preserved end-to-end
- plain upgraded writes remain explicit and bounded
- NetBird Android relay traffic remains stable under sustained upload and
  download traffic
- production diagnostics stay strong enough to debug future long-lived upgraded
  tunnel regressions without packet captures first
