## 1. Canonical IR and runtime orchestrator (foundation)
- [x] 1.1 Define canonical IR schema as the single runtime source of truth.
- [x] 1.2 Define `serval-reverseproxy` orchestrator responsibilities and boundaries.
- [x] 1.3 Define runtime snapshot model (generation id, route/pool/chain refs, immutable fast path).
- [x] 1.4 Define apply lifecycle state machine (build, admit, activate, drain, retire).
- [x] 1.5 Define rollback and safe-mode transitions for orchestrator failures.

## 2. Manifest, ordering, and admission
- [x] 2.1 Define manifest schema fields and validation requirements.
- [x] 2.2 Define deterministic ordering resolver (DAG + tie-break).
- [x] 2.3 Define global+route chain merge rules and mandatory plugin policy.
- [x] 2.4 Define strict admission pipeline contract and atomic activation preconditions.

## 3. Filter SDK surface
- [x] 3.1 Define public SDK modules (`FilterContext`, header views, chunk view, emit writer, decisions).
- [x] 3.2 Define hidden/internal adapter boundary and non-exported internals.
- [x] 3.3 Define `verifyFilter` compile-time checks and diagnostics.
- [x] 3.4 Document filter author happy-path and top error guidance.

## 4. Policy plugin path (pre-transform slice)
- [x] 4.1 Define request/response header-phase execution for policy plugins.
- [x] 4.2 Define reject/short-circuit behavior before upstream forwarding.
- [x] 4.3 Define policy-plugin observability and error classification.

## 5. Streaming transform mechanics design
- [x] 5.1 Specify request/response stream callback lifecycle and state transitions.
- [x] 5.2 Specify bounded emit semantics and amplification guards.
- [x] 5.3 Specify backpressure behavior and stall timeout rules.
- [x] 5.4 Specify framing planner behavior for transformed vs pass-through bodies.

## 6. Failure model and hard caps
- [x] 6.1 Specify fail-open/fail-closed behavior by phase and protocol.
- [x] 6.2 Define sticky bypass semantics and constraints.
- [x] 6.3 Define canonical failure matrix and runtime terminal actions.
- [x] 6.4 Define global hard caps and non-negotiable bounds.
- [x] 6.5 Define aggregate memory budget model and admission/runtime checks.

## 7. Config DSL frontend (v2-now)
- [x] 7.1 Define initial DSL grammar for proxy/listener/pool/plugin/route blocks.
- [x] 7.2 Define DSL semantic validation and name/reference resolution rules.
- [x] 7.3 Define DSL unit normalization rules (durations, bytes, ratios).
- [x] 7.4 Define DSL->IR equivalence tests against schema/JSON inputs.
- [x] 7.5 Define unsupported advanced construct diagnostics (macros/functions/conditionals).

## 8. Operations and rollout
- [x] 8.1 Define operator runbook for dry-run, apply, monitor, rollback.
- [x] 8.2 Define alerting and SLO guardrails for plugin-related failures.
- [x] 8.3 Define rollback prerequisites and failure-handling policy.
- [x] 8.4 Define guard-window auto-rollback triggers and thresholds.
- [x] 8.5 Define safe-mode behavior when rollback fails.
- [x] 8.6 Keep `threshold-profiles.json` and `threshold-profiles.md` in parity and review together.

## 9. Verification planning
- [x] 9.1 Define conformance tests for ordering/admission determinism.
- [x] 9.2 Define protocol correctness tests for h1/h2 framing and termination paths.
- [x] 9.3 Define stress tests for backpressure, expansion caps, and CPU budgets.
