# Terminated Transport Step-Driver Plan

## Goal

Implement the ideal nonblocking transport architecture for terminated protocols (`h1`, `h2`, and future terminated WebSocket-over-h2 paths):

- TLS `WANT_READ` / `WANT_WRITE` handling lives in exactly one transport layer
- protocol drivers do not contain transport retry choreography
- plain and TLS paths expose one unified bounded contract
- deadlines, readiness waits, and stall behavior are explicit, testable, and reusable

## Why This Plan Exists

Recent h2 conformance soak work exposed two realities:

1. Immediate crash fixes were necessary (including connection-state lifetime/cleanup correctness).
2. The longer-term architecture is still uneven when protocol loops own transport behavior details.

Even with tactical fixes in place, the codebase is cleaner and safer if terminated protocol drivers consume a transport contract and never interpret low-level nonblocking TLS states directly.

## Non-Goals

This plan does **not** introduce:

- a new event-loop runtime model for the whole repository
- speculative protocol features unrelated to transport semantics
- unbounded retries or hidden blocking behavior
- behavior changes to request routing policy (strategy/mechanics split remains intact)

## Desired End State

### Invariants

1. Terminated protocol code (`serval-server/h1/*`, `serval-server/h2/*`) never directly handles TLS `WantRead`/`WantWrite`.
2. Terminated protocol code does not contain ad hoc transport sleep/retry loops.
3. Transport waiting policy (readability/writability/deadline) is centralized.
4. All loops are bounded and deadline-based.
5. Plain and TLS expose equivalent high-level transport outcomes:
   - progress (`bytes > 0`)
   - clean close
   - timeout/stall
   - fatal transport failure

## Architecture Decision

### Placement

Introduce a terminated transport driver in **`serval-socket` (layer 2)** and consume it from `serval-server`.

Rationale:

- aligns with existing component guidance: unified TCP/TLS behavior belongs in `serval-socket`
- keeps transport mechanics below protocol orchestration code
- allows reuse by both h1 and h2 without duplicating code in each protocol driver

### API Shape

Use a two-level design:

1. **Step APIs** in `serval-tls/stream.zig` (single TLS operation, no waiting)
2. **Deadline/readiness driver** in `serval-socket` (bounded waits + retries around step APIs)

Protocol drivers call only the driver-level API.

## Current State (Summary)

- `TLSStream.readWithTimeout` / `writeWithTimeout` already centralize bounded TLS nonblocking progress.
- h2 currently uses a mix of protocol-local transport helpers and centralized TLS timeout helpers.
- relay/tunnel paths also have transport/readiness handling in mechanics-layer code.

This is workable, but still not the clean end-state contract.

## Proposed Design

### 1) Add explicit TLS step results (`serval-tls/stream.zig`)

Add non-waiting operations that perform one TLS operation and return explicit progress intent.

Example shape (illustrative):

```zig
pub const ReadStep = union(enum) {
    bytes: u32,
    closed,
    need_read,
    need_write,
};

pub const WriteStep = union(enum) {
    bytes: u32,
    closed,
    need_read,
    need_write,
};

pub fn readStep(self: *TLSStream, buf: []u8) ReadStepError!ReadStep;
pub fn writeStep(self: *TLSStream, data: []const u8) WriteStepError!WriteStep;
```

Rules:

- no waiting in step functions
- preserve TLS direction flip semantics (read may need write, write may need read)
- fatal TLS/socket failures remain explicit errors

### 2) Add terminated driver in `serval-socket`

Create a driver module (for example `serval-socket/terminated_driver.zig`) with unified plain/TLS contract.

Example shape (illustrative):

```zig
pub const ReadOutcome = union(enum) {
    bytes: u32,
    closed,
    timeout,
};

pub const WriteOutcome = union(enum) {
    bytes: u32,
    closed,
    timeout,
};

pub fn readWithDeadline(...)
pub fn writeWithDeadline(...)
```

Responsibilities:

- readiness waits (`read`/`write`)
- monotonic deadline budget tracking
- bounded iteration caps
- plain + TLS adaptation through one surface
- transport diagnostics (fd, transport kind, timeout cause)

### 3) Refactor h2 and h1 protocol drivers to consume driver API

- remove protocol-local readiness/retry mechanics
- map driver outcomes to existing protocol error surfaces
- keep protocol logic focused on framing/state transitions

### 4) Keep compatibility wrappers during migration

- keep existing bounded APIs (`readWithTimeout`, `writeWithTimeout`) as wrappers initially
- migrate call sites incrementally
- remove deprecated call paths after both h1 and h2 fully adopt driver API

## Implementation Plan

### Phase A — TLS Step API Foundation

1. Add `readStep` / `writeStep` to `TLSStream`.
2. Keep existing timeout helpers implemented via the step API internally.
3. Add unit tests for:
   - `need_read`
   - `need_write`
   - clean close
   - fatal error mapping

Acceptance:

- step API compiles and passes tests
- no behavior regressions in existing timeout-based callers

### Phase B — Terminated Driver Introduction

1. Add `serval-socket` terminated driver module.
2. Implement plain-fd step adaptation.
3. Implement TLS step adaptation via new `TLSStream` step API.
4. Add tests for bounded deadline behavior and wait-direction switching.

Acceptance:

- one reusable driver for plain+TLS terminated flows
- bounded loops and explicit deadlines verified in tests

### Phase C — Migrate h2 Driver

1. Replace h2 transport helpers with terminated driver calls.
2. Remove h2 transport-local readiness code.
3. Preserve current error semantics and connection-close mapping.
4. Re-run h2 conformance and soak loops.

Acceptance:

- h2 server contains no TLS `Want*` handling
- h2 conformance still passes
- soak loops remain stable

### Phase D — Migrate h1 Driver

1. Replace h1 transport-local mechanics with terminated driver.
2. Ensure upgraded and non-upgraded flows preserve behavior.
3. Verify no connection lifecycle regressions.

Acceptance:

- h1 and h2 share one transport semantics layer
- no protocol driver has transport-specific retry choreography

### Phase E — Cleanup + Docs

1. Remove obsolete compatibility pathways once migration is complete.
2. Update docs:
   - `serval-socket/README.md`
   - `serval-tls/README.md`
   - `serval-server/README.md`
   - `serval/ARCHITECTURE.md` (transport ownership notes)

Acceptance:

- architecture docs match implementation ownership
- no duplicated transport semantics remain in terminated protocol code

## Test and Verification Plan

### Unit-level

- TLS step API return semantics
- readiness direction switching (`need_read` <-> `need_write`)
- deadline expiration behavior
- bounded iteration enforcement

### Integration-level

- existing h1/h2 suites
- `integration/h2_conformance_ci.sh` cleartext and TLS runs
- repeated churn/soak loops for TLS h2 conformance

## Suggested verification commands

```bash
zig build
zig build test
zig build test-server
zig build test-h2
H2_CONFORMANCE_SKIP_BUILD=1 integration/h2_conformance_ci.sh --h2c-port 28080 --tls-port 28443
```

## Risks and Mitigations

1. **Risk:** semantic drift during migration (error mapping changes)
   - **Mitigation:** keep wrapper parity tests between old and new paths during migration.

2. **Risk:** hidden fairness regressions under stall scenarios
   - **Mitigation:** add explicit stall/churn tests with mixed healthy + stalled connections.

3. **Risk:** introducing duplicated transport layers (relay vs terminated)
   - **Mitigation:** define explicit ownership boundary in docs: terminated-driver API for terminated protocols; relay contract for long-lived tunnel mechanics.

## Exit Criteria

This plan is complete when:

1. h1/h2 terminated protocol drivers use one shared transport driver contract.
2. TLS `WantRead` / `WantWrite` handling is not present in protocol drivers.
3. No protocol driver uses ad hoc transport sleep/retry loops.
4. All required build/test/conformance commands pass.
5. Documentation reflects final ownership and layering.
