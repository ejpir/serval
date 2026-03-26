## Why

Recent verification found multiple high-severity gaps in `serval-server` that can cause request desynchronization, indefinite connection stalls, and unstable memory behavior under concurrency. We need a focused hardening change now to close these risks before enterprise rollout and establish explicit behavioral guarantees for short-circuit handling, HTTP/2 TLS read bounds, and runtime resource discipline.

## What Changes

- Add fail-closed connection handling for short-circuit HTTP/1.1 responses when request bodies are not fully consumed, and preserve keep-alive only when consumption is provably complete.
- Add bounded TLS-read readiness timeout behavior for terminated HTTP/2 server paths and align module documentation with actual retry/readiness semantics.
- Eliminate silent HTTP/2 request-body tracker overwrite behavior by failing closed when tracker capacity is exceeded.
- Replace process-crashing TLS reload lock contention in runtime control-plane APIs with explicit errors for fallible operations.
- Reduce high-cost per-request allocator churn in selected bridge hot paths and keep changes scoped to low-blast-radius substitutions.
- Add integration coverage for the original keep-alive desync class (single persistent socket, short-circuit with unread body, follow-on request rejection via connection close).
- Refactor the monolithic h1 request loop into explicit control-flow subroutines (`continue` / `close` / `fall-through`) without changing external behavior.

## Capabilities

### New Capabilities
- `h1-short-circuit-body-safety`: Defines required fail-closed behavior for h1 short-circuit response paths and keep-alive reuse rules based on verified body-consumption state.
- `terminated-h2-tls-read-bounds`: Defines bounded readiness/timeout requirements for terminated h2 TLS read loops and documented transport semantics.
- `server-runtime-safety-guardrails`: Defines required failure behavior for tracker-capacity overflow, TLS reload lock contention, and targeted hot-path allocation reduction.

### Modified Capabilities
- None.

## Impact

- Affected code:
  - `serval-server/h1/server.zig`
  - `serval-server/h2/server.zig`
  - `serval-server/h2/runtime.zig`
  - `serval-server/README.md`
  - `integration/tests.zig`
- Potentially affected supporting constants/callers (if resized by verified inventory):
  - `serval-core/config.zig`
  - `examples/gateway/controller/admin/handler.zig`
- No public API removals expected; behavior is hardened primarily through fail-closed safety semantics and improved runtime determinism.
- Verification impact: unit + h2 suite + integration coverage are required for acceptance.
