# HTTP/2 Compliance Workboard (All Phases Started)

Last updated: 2026-03-12

This file tracks active execution across Phases 0–5 from
`2026-03-12-http2-rfc9113-compliance-plan.md`.

Related execution plan:
- `docs/plans/2026-03-13-generic-tls-h2-wiring-plan.md`

## Overall status

- Phase 0: ✅ started (matrix + baseline captured)
- Phase 1: ✅ started (critical blockers identified; implementation queue opened)
- Phase 2: ✅ started (frame/state-machine compliance backlog opened)
- Phase 3: ✅ started (header/HPACK strictness backlog opened)
- Phase 4: ✅ started (proxy/gRPC interoperability hardening backlog opened)
- Phase 5: ✅ started (rollout gates and canary policy defined)

---

## Phase 0 — Compliance Matrix + Gap Audit

### Completed
- [x] RFC matrix created: `docs/plans/http2-rfc9113-matrix.md`
- [x] Baseline capture created: `docs/plans/2026-03-12-http2-baseline.md`
- [x] Critical blocker IDs created (B1..B6)

### Next
- [x] Install `h2spec` and `nghttp` in dev/CI environment
  - Local dev installed and verified; CI now installs `h2spec` + `nghttp2-client` in `.github/workflows/ci.yml`
- [x] Add reproducible command scripts for each blocker
  - `integration/h2_conformance_runner.sh`
  - CI orchestration wrapper: `integration/h2_conformance_ci.sh`

---

## Phase 1 — Connection-Level Correctness

### Open implementation queue
- [~] P1-A: Fix TLS frontend ALPN/h2 dispatch gap (B2)
  - Completed for terminated-h2 handlers: ALPN `h2` now dispatches directly to terminated h2 runtime over TLS
  - Result: dedicated TLS conformance target now passes `h2spec` 145/145
  - Remaining: mixed-offer frontend policy is still conservative (`http/1.1` preferred) until full mixed-traffic rollout criteria are closed
- [x] P1-B: Ensure h2-negotiated connections always emit server SETTINGS first
  - Covered by integration regression: TLS ALPN h2 generic frontend validates first inbound frame is non-ACK SETTINGS before response frames
- [x] P1-C: Add targeted regression test for mixed ALPN client + non-gRPC route behavior
  - Added TLS ALPN h2 generic frontend non-gRPC route regression (h2 request to HTTP upstream forwarding path)
  - Existing ALPN policy unit coverage in `serval-tls/ssl.zig` continues to validate mixed-offer selection (`prefer_http11` vs `prefer_h2`)

### Exit gate
- [ ] h2spec connection/setup chapters green
- [ ] no `expected SETTINGS frame` failures in curl/nghttp/grpc repros

---

## Phase 2 — Frame + State-Machine Compliance

### Open implementation queue
- [x] P2-A: Unknown frame type tolerance (B1)
  - Implemented: unknown frame types map to `.extension` and are ignored in client/server runtime receive paths
- [x] P2-B: Peer max-frame-size outbound enforcement audit/fixes (B5)
  - Implemented: peer max-frame-aware response DATA chunking plus outbound HEADERS/trailers fragmentation via bounded HEADERS+CONTINUATION emission in client request and terminated server response paths
- [x] P2-C: Error-code mapping audit for protocol vs flow-control violations
  - Server runtime now classifies stream DATA window exhaustion as `StreamFlowControlError` without mutating connection window state
  - GOAWAY mapping now explicitly treats `StreamFlowControlError` as `FLOW_CONTROL_ERROR`

### Exit gate
- [~] h2spec frame/stream/flow-control chapters green
  - Cleartext h2c target: 145/145 passed (0 skipped, 0 failed)
  - TLS h2 conformance target: 145/145 passed (0 skipped, 0 failed)
  - Remaining work is rollout/policy hardening for mixed-traffic frontend behavior, not protocol conformance on the dedicated target
- [x] parser/state-machine fuzz invariants green
  - Added deterministic randomized runtime frame-sequence invariant test (bounded, fixed-seed) in `serval-server/h2/runtime.zig`

---

## Phase 3 — HPACK + Header Semantics

### Open implementation queue
- [x] P3-A: Full pseudo-header ordering/validity enforcement (B3)
  - Implemented in `serval-h2/request.zig` with deterministic errors for ordering, duplicates, CONNECT constraints, and missing mandatory pseudo headers
- [x] P3-B: Generic connection-specific header prohibition in h2 path (B4)
  - Implemented in `serval-h2/request.zig`; upgrade translation also lowercases forwarded regular header names for h2 correctness
- [x] P3-C: Strict `te=trailers` handling for generic h2 requests
  - Implemented in `serval-h2/request.zig` and covered by unit tests

### Exit gate
- [ ] h2spec header semantics + compression chapters green
- [ ] metadata/trailer interop corpus green

---

## Phase 4 — Proxy + gRPC Semantics

### Open implementation queue
- [ ] P4-A: Stream-binding correctness audit under churn
- [ ] P4-B: Deterministic cancellation/reset propagation audit
- [~] P4-C: Remove remaining retry-masked correctness paths
  - Removed bridge `sendDownstreamData` retry-on-`ConnectionClosing` behavior; now fail-closed, drop binding, and close affected session generation
  - ALPN `h2` frontend dispatch now falls back to generic h2 when terminated hooks are absent (prevents h1 parsing on negotiated h2 connections)
  - Added targeted runtime/bridge warning logs for frame-level protocol failures and connection-closing send path failures
  - Remaining stream-churn cleanup on graceful GOAWAY paths stays open under P4-A/P4-B

### Exit gate
- [ ] grpc-go/grpcurl/NetBird client interop stable under churn + soak
- [ ] management backend free of recurring proxy-originated PROTOCOL_ERROR

---

## Phase 5 — Rollout + Promotion Gates

### Open implementation queue
- [ ] P5-A: Keep stable profile conservative until gates are green
- [ ] P5-B: Canary h2-first profile with full conformance+interop suite
- [ ] P5-C: Production promotion only after all phase gates pass

### Exit gate
- [ ] all phase gates green
- [ ] rollout checklist signed off with reproducible evidence
