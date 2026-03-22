# HTTP/2 Compliance Workboard (All Phases Started)

Last updated: 2026-03-12

This file tracks active execution across Phases 0–5 from
`2026-03-12-http2-rfc9113-compliance-plan.md`.

Related execution plan:
- `docs/plans/2026-03-13-generic-tls-h2-wiring-plan.md`
- `docs/plans/2026-03-20-http2-completion-plan.md`

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
- [~] P4-A: Stream-binding correctness audit under churn
  - Added focused integration coverage for sibling stream isolation on upstream reset (`integration: grpc h2c upstream reset on one stream preserves sibling stream`)
  - Added focused fast-loop coverage for GOAWAY `last_stream_id` race via dedicated step over existing churn test (`integration: grpc h2c goaway last_stream_id resets higher stream and keeps lower stream`)
  - Added repeated GOAWAY rollover loop coverage to verify fresh upstream session opens across cycles (`integration: grpc h2c repeated goaway rollover opens fresh upstream sessions`)
  - Added targeted soak loops for reset isolation and GOAWAY rollover (`integration: grpc h2c reset isolation soak loop`, `integration: grpc h2c repeated goaway rollover soak loop`)
  - Added upgrade-path rollover loop/soak coverage to verify repeated graceful GOAWAY handling remains deterministic after `Upgrade: h2c` bootstrap (`integration: grpc h2c upgrade repeated goaway rollover opens fresh upstream sessions`, soak variant)
  - Remaining: larger multi-minute mixed reset/GOAWAY soak remains open
- [~] P4-B: Deterministic cancellation/reset propagation audit
  - Added focused integration coverage for downstream cancel propagation under active upstream response (`integration: grpc h2c downstream cancel propagates upstream and preserves next stream`)
  - Added cancel+GOAWAY overlap loop coverage across repeated cycles to verify continued progress on subsequent streams (`integration: grpc h2c cancel and goaway overlap loop preserves subsequent streams`)
  - Added targeted overlap soak loop coverage (`integration: grpc h2c cancel and goaway overlap soak loop`)
  - Added mixed protocol-class churn loop coverage to interleave graceful GOAWAY rollover with non-gRPC request-trailer fail-closed resets while preserving subsequent gRPC stream progress (`integration: grpc h2c mixed goaway and non-grpc trailer reset loop preserves progress`, soak variant)
  - Remaining: higher-duration soak for cancel-race + GOAWAY overlap remains open
- [~] P4-C: Remove remaining retry-masked correctness paths
  - Removed bridge `sendDownstreamData` retry-on-`ConnectionClosing` behavior; now fail-closed, drop binding, and close affected session generation
  - ALPN `h2` frontend dispatch now falls back to generic h2 when terminated hooks are absent (prevents h1 parsing on negotiated h2 connections)
  - Prior-knowledge and `Upgrade: h2c` ingress now route both supported `.h2c` and `.h2` upstreams through the stream-aware bridge path (no raw-tunnel steady-state fallback for supported HTTP/2 upstream protocols)
  - Generic h2->h1 request-body translation now has focused integration coverage for both framed modes: explicit `content-length` forwarding and no-`content-length` conversion to HTTP/1.1 `Transfer-Encoding: chunked`
  - Generic request trailers on active streams now fail closed at runtime with `RST_STREAM(PROTOCOL_ERROR)`; targeted integration step added
  - Added targeted integration coverage for invalid `TE` on generic h2 requests (`TE: gzip`) to assert fail-closed `RST_STREAM(PROTOCOL_ERROR)`
  - Added targeted runtime/bridge warning logs for frame-level protocol failures and connection-closing send path failures
  - Bridge completion validation is now request-class aware: `grpc-status` is enforced fail-closed only for streams classified as gRPC, while non-gRPC streams accept normal HTTP/2 terminal headers/trailers; targeted integration coverage added (`integration: h2c bridge forwards non-gRPC response trailers without grpc-status`, `integration: h2c bridge accepts non-gRPC headers-only end-stream response`)
  - Added bridge ingress coverage for non-gRPC request-trailer fail-closed semantics on both entry paths: prior-knowledge and upgrade now assert downstream `RST_STREAM(PROTOCOL_ERROR)` for unsupported request trailers (`integration: h2c bridge prior-knowledge resets non-gRPC request trailers with protocol error`, `integration: h2c bridge upgrade resets non-gRPC request trailers on additional stream`)
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
