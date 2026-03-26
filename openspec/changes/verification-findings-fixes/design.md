## Context

`serval-server` verification identified three enterprise-blocking failure classes:

1. HTTP/1.1 keep-alive can be reused after short-circuit responses even when request bodies are not fully drained, enabling request desynchronization on persistent sockets.
2. Terminated HTTP/2 TLS read paths can wait indefinitely without bounded readiness behavior, creating stalled connections and operational unpredictability.
3. Runtime guardrails are incomplete in two control-plane/data-plane paths: tracker-capacity overflow silently overwrites state, and TLS reload lock contention can terminate the process instead of returning a recoverable error.

The change must harden behavior without widening blast radius. Existing architecture and TigerStyle constraints require explicit failure behavior, bounded loops/timeouts, and deterministic resource handling.

## Goals / Non-Goals

**Goals:**
- Enforce fail-closed safety semantics for h1 short-circuit paths when body-consumption state is uncertain or incomplete.
- Add bounded timeout/readiness semantics for terminated h2 TLS reads and keep docs aligned with implementation.
- Replace silent or process-fatal runtime behavior with explicit, typed failures for operator-visible recovery.
- Reduce targeted allocator churn on identified hot paths without broad allocator strategy refactors.
- Preserve external APIs while tightening runtime guarantees and test coverage.

**Non-Goals:**
- No protocol feature expansion (no new h1/h2 capabilities).
- No broad rewrite of server architecture, connection state machine, or allocator model.
- No cross-repo API redesign for callers beyond minimal error-surface propagation required by hardening.

## Decisions

1. Decision: H1 short-circuit path will gate keep-alive reuse on verified body-consumption completion.
Rationale: Reuse after unread body bytes is the direct root of desync risk. Fail-closed connection termination is safer than optimistic reuse when state is ambiguous.
Alternatives considered:
- Attempt opportunistic post-response drain before reuse: rejected due to timing ambiguity and complexity under partial reads.
- Preserve current behavior with stronger docs only: rejected because it leaves correctness risk unchanged.

2. Decision: Terminated h2 TLS read loops will use explicit bounded readiness timeout behavior.
Rationale: Bounded waits convert indefinite stalls into deterministic failure modes and improve operability under network/TLS edge conditions.
Alternatives considered:
- Infinite wait with periodic logging: rejected because it still permits unbounded stalls.
- Global timeout only at higher layer: rejected because lower-layer transport readiness must be bounded where blocking occurs.

3. Decision: Tracker-capacity overflow will fail closed instead of overwriting prior entries.
Rationale: Silent overwrite corrupts request-body tracking invariants and can mask protocol/data consistency errors.
Alternatives considered:
- Auto-grow tracker at runtime: rejected for this change due to memory-behavior uncertainty and larger blast radius.
- Keep overwrite and emit warning: rejected because warning does not preserve correctness.

4. Decision: TLS reload lock contention in runtime control-plane operations becomes explicit error return, never process crash.
Rationale: Enterprise control-plane operations must be fallible and observable, not fatal on transient contention.
Alternatives considered:
- Retain panic/abort for "should not happen": rejected because operational races do occur under load and automation.
- Spin/retry until lock available: rejected due to potential unbounded wait and degraded responsiveness.

5. Decision: Allocation reductions are limited to low-risk substitutions in verified hot paths.
Rationale: Targeted improvements reduce regression risk while still addressing measurable churn.
Alternatives considered:
- Broad allocator refactor in h1/h2 runtime: rejected as out of scope and high risk for this hardening change.

## Risks / Trade-offs

- [More connection closes in h1 short-circuit edge cases] -> Mitigation: document fail-closed behavior and add integration test proving correctness over reuse.
- [Timeout tuning for terminated h2 TLS paths may be too strict or too lax initially] -> Mitigation: use existing config constants where possible, keep timeout explicit, and verify via h2/integration coverage.
- [New explicit errors may require caller adjustments] -> Mitigation: keep error surfaces narrow and update affected module docs/callers in same change.
- [Hot-path allocation changes may shift performance characteristics unexpectedly] -> Mitigation: scope substitutions narrowly and validate with existing test suites before expansion.

## Migration Plan

1. Implement h1 fail-closed keep-alive gating and request-loop control-flow refactor in `serval-server/h1/server.zig`.
2. Implement bounded terminated h2 TLS readiness behavior in `serval-server/h2/server.zig` and align `serval-server/README.md`.
3. Implement fail-closed tracker-capacity behavior and explicit TLS reload lock errors in `serval-server/h2/runtime.zig`.
4. Add/update integration coverage in `integration/tests.zig` for persistent-socket short-circuit desync prevention.
5. Run verification suites (`zig build`, `zig build test`, targeted h2/integration tests) and confirm no behavior regressions.

Rollback strategy:
- Revert this change set as a unit if regressions are found.
- If rollback is partial, preserve fail-closed behaviors over permissive behavior to avoid reintroducing correctness risks.

## Open Questions

- Should terminated h2 TLS read timeout be configurable independently from existing transport/readiness constants, or reuse an existing shared timeout?
- Do any external control-plane callers currently assume non-fallible TLS reload semantics and require explicit migration notes?
- Is tracker capacity sufficient for observed enterprise traffic profiles, or should a follow-up change evaluate controlled capacity sizing guidelines?
