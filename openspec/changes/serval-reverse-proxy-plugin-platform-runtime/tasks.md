## 1. PR1 — Runtime foundation landed (canonical IR + lifecycle skeleton)

- [x] 1.1 Add `serval-reverseproxy` module/package scaffolding and build integration.
- [x] 1.2 Implement canonical IR core types (listener, route, pool, plugin catalog, chain plan).
- [x] 1.3 Implement explicit safety-critical IR fields (failure policy and runtime budget fields) with no implicit defaults.
- [x] 1.4 Implement IR validation entry points for structural checks and unresolved references.
- [x] 1.5 Implement orchestrator snapshot/lifecycle skeleton with atomic activation + drain/retire hooks.
- [x] 1.6 Add initial unit tests (validation determinism, admission no-op, activation swap, drain timeout, rollback hook).
- [x] 1.7 Update `README.md` + `serval/ARCHITECTURE.md` + module docs for new runtime foundation.

## 2. PR2 — Add optional orchestration boundary (no hard `serval-server` dependency)

- [x] 2.1 Define a minimal runtime-provider interface/adapter consumed by `serval-server` (strategy/runtime snapshot lookup only).
- [x] 2.2 Implement reverseproxy-owned adapter that routes apply/update through `build -> admit -> activate` lifecycle outside `serval-server`.
- [x] 2.3 Preserve active generation on admission failure with deterministic error surfacing while keeping baseline `serval-server` standalone.
- [x] 2.4 Add integration tests proving no partial activation for adapter path and no behavior regression for standalone server path.

## 3. PR3 — Deterministic plugin admission ordering engine (DAG + tie-break)

- [x] 3.1 Implement `before`/`after` DAG builder with cycle detection.
- [x] 3.2 Implement stable tie-break (`priority`, then `plugin_id`) for ready set.
- [x] 3.3 Integrate ordering results into chain-plan admission.
- [x] 3.4 Add conformance tests for ordering determinism and cycle rejection.

## 4. PR4a — IR model expansion for chain-merge and waiver policy

- [x] 4.1 Add canonical IR fields for global chain baseline and route-level disable/add directives.
- [x] 4.2 Add plugin catalog policy fields (`mandatory`, waiver policy metadata) and route waiver structures.
- [x] 4.3 Add structural/reference validation for new IR fields (duplicate directives, unknown plugin refs, invalid waiver refs).
- [x] 4.4 Add unit tests for IR model/validation of route disable/add/waiver metadata.

## 5. PR4b — Effective-chain composition + mandatory enforcement behavior

- [x] 5.1 Implement explicit effective-chain composition (`global - disables + route additions`).
- [x] 5.2 Enforce mandatory plugin policy/waiver behavior in admission.
- [x] 5.3 Add tests for mandatory plugin disable rejection and deterministic effective chains.

## 6. PR5 — Filter SDK public surface (safe boundary)

- [x] 5.1 Create `serval-filter-sdk` (or equivalent package boundary) with approved public types.
- [x] 5.2 Implement compile-time `verifyFilter` checks + actionable diagnostics.
- [x] 5.3 Block access to internal transport/runtime internals from user filter code.
- [x] 5.4 Add SDK compile-time contract tests and author examples.

## 7. PR6 — Policy plugin execution path (header-phase)

- [x] 6.1 Implement request/response header-phase policy plugin callbacks.
- [x] 6.2 Implement reject/short-circuit semantics before upstream forwarding.
- [x] 6.3 Add observability counters/tags for policy decisions and failures.
- [x] 6.4 Add tests for phase ordering and skipped downstream phases on reject.

## 8. PR7 — Streaming transform engine (request path)

- [x] 7.1 Implement request stream callback lifecycle (`headers/chunk/end`).
- [x] 7.2 Implement bounded `EmitWriter` semantics with amplification guards.
- [x] 7.3 Enforce upstream pause/resume on downstream backpressure.
- [x] 7.4 Add tests for bounded memory and backpressure timeout behavior.

## 9. PR8 — Streaming transform engine (response path + framing planner)

- [x] 8.1 Implement response stream callback lifecycle (`headers/chunk/end`).
- [x] 8.2 Implement framing planner behavior for transformed vs pass-through bodies.
- [x] 8.3 Enforce h1/h2 framing correctness when output length is unknown.
- [x] 8.4 Add protocol correctness tests for h1 chunked and h2 DATA semantics.

## 10. PR9 — Failure matrix + sticky bypass + terminal actions

- [x] 9.1 Implement canonical runtime failure classification.
- [x] 9.2 Implement phase/protocol-aware `fail_open`/`fail_closed` behavior.
- [x] 9.3 Implement sticky bypass constraints for safe continuation.
- [x] 9.4 Add tests for mid-stream failure termination behavior (h1 close / h2 reset).

## 11. PR10 — Guard window + rollback automation + safe mode

- [x] 10.1 Implement post-activation guard-window monitoring.
- [x] 10.2 Implement auto-rollback triggers based on threshold profiles.
- [x] 10.3 Implement rollback failure safe-mode behavior (freeze applies, preserve baseline controls).
- [x] 10.4 Add tests for rollback trigger, rollback success, and rollback failure path to safe mode.

## 12. PR11 — Config DSL parser + semantic resolver to canonical IR

- [x] 11.1 Implement initial DSL grammar (proxy/listener/pool/plugin/route blocks).
- [x] 11.2 Implement deterministic semantic validation and name/reference resolution.
- [x] 11.3 Implement explicit required safety fields (no implicit fail-policy/budget defaults).
- [x] 11.4 Add unsupported-feature diagnostics (macros/functions/conditionals).

## 13. PR12 — DSL/Schema equivalence + tooling

- [x] 12.1 Implement DSL->IR and schema->IR equivalence harness.
- [x] 12.2 Add deterministic equivalence tests and mismatch diagnostics.
- [x] 12.3 Add CI hooks for equivalence/conformance suites.

## 14. PR13 — Operational hardening docs + stress verification

- [x] 13.1 Finalize operator runbook (dry-run, apply, monitor, rollback, safe mode).
- [x] 13.2 Add alerting/SLO guardrail documentation and threshold profile parity checks.
- [x] 13.3 Add stress tests for backpressure, expansion caps, CPU budgets, and drain behavior.
- [x] 13.4 Run full verification (`zig build`, `zig build test`, focused suites) and capture outputs.
