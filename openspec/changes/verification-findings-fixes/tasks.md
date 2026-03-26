## 1. H1 short-circuit fail-closed hardening

- [x] 1.1 Refactor the h1 request loop in `serval-server/h1/server.zig` into explicit control-flow outcomes (`continue`, `close`, terminal fall-through) while preserving non-short-circuit behavior.
- [x] 1.2 Enforce keep-alive gating so short-circuit responses close the connection unless request-body consumption is verified complete.
- [x] 1.3 Add/adjust h1 unit coverage for short-circuit unread-body handling and verified-body keep-alive behavior.

## 2. Terminated h2 TLS bounded-read behavior

- [x] 2.1 Implement bounded readiness timeout handling for terminated h2 TLS read loops in `serval-server/h2/server.zig`.
- [x] 2.2 Ensure timeout paths fail closed by tearing down affected h2 connection/session state with deterministic cleanup.
- [x] 2.3 Update `serval-server/README.md` to match implemented terminated h2 TLS readiness and timeout semantics.

## 3. Runtime guardrails and hot-path resource discipline

- [x] 3.1 Change h2 request-body tracker overflow behavior in `serval-server/h2/runtime.zig` from silent overwrite to explicit fail-closed error.
- [x] 3.2 Replace process-fatal TLS reload lock contention behavior with explicit recoverable errors in runtime control-plane APIs.
- [x] 3.3 Apply targeted low-blast-radius allocator-churn reductions in verified bridge hot paths and keep semantics unchanged.

## 4. Integration verification and regression safety

- [x] 4.1 Add integration coverage in `integration/tests.zig` for persistent-socket short-circuit desync prevention (unread body followed by second request on same connection).
- [x] 4.2 Run focused verification for touched server/runtime/integration suites and fix regressions introduced by hardening changes.
- [x] 4.3 Run full project verification (`zig build` and `zig build test`) and capture passing exit codes for release readiness.
