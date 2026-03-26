# Verification Plan

This plan defines verification coverage for the `serval-reverse-proxy-plugin-platform` change.

## 1) Conformance: ordering/admission determinism

### Goals
- Equivalent canonical IR inputs produce identical admission outcomes.
- Ordering remains deterministic for stable input.
- Invalid graphs and policy violations fail with stable diagnostics.

### Cases
1. Deterministic tie-break with equal priority (`id` lexical fallback)
2. Cycle detection with explicit cycle diagnostics
3. Missing dependency references rejected
4. Mandatory plugin disable rejected
5. DSL and schema inputs with equal semantics produce equal ordering/admission

## 2) Protocol correctness: h1/h2 framing + terminal behavior

### Goals
- Transformed payload framing is valid for h1 and h2.
- Mid-stream failures map to protocol-correct terminal actions.

### Cases
1. h1 transformed unknown-length response removes Content-Length and uses streaming-compatible framing
2. h2 transformed response emits valid DATA sequence without invalid length metadata
3. Response transform failure after headers sent:
   - h1: connection termination behavior
   - h2: stream reset behavior
4. Request-phase reject short-circuits upstream forwarding
5. Header mutation guard rejects forbidden pseudo/hop-by-hop mutations

## 3) Stress and resilience

### Goals
- Bounded memory/cpu/backpressure guarantees hold under load.
- Rollout guard-window and rollback behavior remain stable under churn.

### Cases
1. Backpressure saturation with bounded wait and timeout behavior
2. Emit amplification attempts exceed cap and are handled per policy
3. CPU budget overruns trigger expected failure-mode behavior
4. Generation churn test: repeated activate/drain/retire cycles without leaks
5. Guard-window regression trigger causes automatic rollback to last-known-good
6. Rollback failure path enters safe mode with expected controls

## 4) Tooling parity checks

### Goals
- Human and machine rollout threshold artifacts stay consistent.

### Cases
1. `threshold-profiles.json` and `threshold-profiles.md` parity checks in review workflow
2. Profile names and trigger-key parity (`canary`, `production`) verified
3. Baseline and safe-mode parity verified across both artifacts
