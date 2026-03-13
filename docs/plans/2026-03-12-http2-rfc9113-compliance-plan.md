# HTTP/2 RFC 9113 Compliance Plan (Server + Proxy)

## Context

NetBird GUI is now stable again on Serval, but NetBird desktop/mobile clients still fail intermittently with management-side:

- `http2: server connection error ... PROTOCOL_ERROR`

This points to incomplete HTTP/2 interoperability in the Serval frontend/proxy path, especially when real clients negotiate ALPN and exercise full h2 behavior.

## Goal

Achieve production-grade RFC 9113 compliance for Serval HTTP/2 handling so that:

1. Browser/API traffic remains stable.
2. gRPC clients (grpc-go, NetBird client, grpcurl) interoperate reliably.
3. No correctness relies on retries or reconnect churn.

## Specs to Follow

Primary:
- RFC 9113 (HTTP/2)
- RFC 9110 (HTTP Semantics, pseudo-header mapping, field semantics)

Interop protocol:
- gRPC over HTTP/2 wire contract (`content-type`, `te: trailers`, trailers semantics)

Validation tools:
- h2spec
- nghttp2 clients (`nghttp`, `h2load`)
- grpcurl + grpc-go test clients

Execution tracker:
- `docs/plans/2026-03-12-http2-phase-workboard.md`

---

## Phase 0 — Compliance Matrix + Gap Audit

Create a strict MUST/SHOULD matrix from RFC 9113 and map each item to current Serval code paths:

- `serval-h2/*`
- `serval-server/h2/*`
- `serval-server/h1/server.zig` (TLS ALPN dispatch + h2c upgrade handoff)
- `serval-client/h2/*`
- `serval-proxy/h2/*`

### Deliverables

1. `docs/plans/http2-rfc9113-matrix.md` with per-section status:
   - ✅ implemented
   - ⚠ partial
   - ❌ missing
2. Explicit list of compliance blockers ranked by severity.
3. Repro commands for each blocker.
4. Baseline command report with compiler/tooling details.

### Phase 0 status (started)

Completed artifacts:
- `docs/plans/http2-rfc9113-matrix.md`
- `docs/plans/2026-03-12-http2-baseline.md`

---

## Phase 1 — Connection-Level Correctness (Highest Risk)

### 1.1 ALPN dispatch invariants (TLS frontend)

If ALPN negotiates `h2`, Serval must enter h2 runtime immediately and send server SETTINGS first.

No HTTP/1.1 bytes may be emitted on an h2-negotiated connection.

### 1.2 Preface and SETTINGS synchronization

Validate full connection startup behavior:
- client preface handling
- server initial SETTINGS emission
- SETTINGS ACK processing rules
- timeout/close behavior on malformed setup

### 1.3 Upgrade path correctness (`Upgrade: h2c`)

Ensure strict RFC sequence:
- valid `HTTP2-Settings` decoding/validation
- stream 1 bootstrap rules
- post-101 preface handling
- malformed post-101 fail-closed behavior

### Exit criteria

- h2spec connection/setup chapters pass.
- No `expected SETTINGS frame` class interop failures from curl/nghttp/grpc clients.

---

## Phase 2 — Frame Semantics + State Machine Compliance

### 2.1 Frame validation

Harden/verify all frame rules:
- stream-id constraints per frame type
- length constraints (PING/RST/WINDOW_UPDATE/PRIORITY/SETTINGS)
- CONTINUATION sequencing
- HEADERS flags combinations (PRIORITY/PADDED)

### 2.2 Stream lifecycle correctness

Enforce state transitions exactly:
- idle/open/half-closed/closed
- RST_STREAM behavior
- GOAWAY and last_stream_id handling
- reject illegal transitions with correct error codes

### 2.3 Flow control correctness

Connection + stream windows:
- decrement/increment invariants
- overflow/underflow rejection
- WINDOW_UPDATE constraints
- bounded handling under backpressure

### Exit criteria

- h2spec frame + stream + flow-control chapters pass.
- Fuzz/property tests cover parser/state transitions without UB/panics.

---

## Phase 3 — HPACK and Header Semantics Compliance

### 3.1 HPACK decoder/encoder strictness

Validate:
- indexed/literal representations
- dynamic table updates/eviction
- Huffman decoding strictness
- integer decoding bounds

### 3.2 HTTP semantics over h2

Validate pseudo-header and header rules:
- required pseudo-headers for requests
- pseudo-header ordering
- forbidden connection-specific headers
- `:authority`/`host` mapping behavior

### Exit criteria

- h2spec header-compression and header-rule chapters pass.
- grpc metadata/trailer round-trip tests stable (including `-bin` headers).

---

## Phase 4 — Proxy Interop and gRPC Semantics

### 4.1 Downstream/upstream stream binding correctness

For each downstream stream:
- deterministic upstream stream mapping
- response/trailer propagation
- cancellation propagation (RST_STREAM)
- GOAWAY rollover behavior

### 4.2 gRPC contract enforcement

Ensure:
- request metadata validation
- response trailers include valid `grpc-status`
- missing/invalid trailers fail closed deterministically

### 4.3 Remove retry-masked behavior

Any path currently “saved” by reconnect/retry must be made protocol-correct.

### Exit criteria

- grpc-go/grpcurl/NetBird client interop stable under churn and soak.
- Management backend logs free from recurring protocol errors during normal connect workflows.

---

## Phase 5 — NetBird Rollout Strategy

### 5.1 Stability profile (until full compliance is complete)

Keep mixed ALPN preference safe for web traffic and avoid forcing global h2 until compliance gates are met.

### 5.2 Canary profile

Run full h2-first profile on canary port/domain with:
- h2spec regression run
- grpc interop run
- NetBird real-client acceptance test

### 5.3 Promotion gate

Promote h2-first behavior to production only after all compliance gates are green.

---

## Testing Program

### Automated

- `zig build`
- `zig build test`
- `zig build test-h2`
- `zig build test-server`
- `zig build test-client`
- `zig build test-proxy`
- `zig build test-integration`

### Protocol conformance

- `h2spec` against Serval listeners (cleartext + TLS)
- `nghttp` script suite (SETTINGS/PRIORITY/CONTINUATION/GOAWAY/RST)
- `integration/h2_conformance_runner.sh` as local/CI execution wrapper

### Interop

- curl `--http2` and `--http2-prior-knowledge`
- grpcurl metadata/trailer checks
- grpc-go unary + streaming loops
- NetBird desktop/mobile/manual login and peer connect checks

### Soak

- sustained churn with bounded concurrent clients
- capture protocol errors + stream resets + GOAWAY distribution

---

## Work Breakdown (Recommended PRs)

1. RFC matrix + reproducible failing cases
2. ALPN dispatch + connection setup correctness
3. Frame/state-machine compliance fixes
4. HPACK/header semantics fixes
5. Proxy stream-binding + gRPC semantics hardening
6. h2spec + interop CI automation
7. rollout profile + docs update

---

## Definition of Done

1. h2spec passes for supported feature set (cleartext + TLS modes).
2. No recurring management-side `PROTOCOL_ERROR` during NetBird client connects.
3. GUI + API + websocket + gRPC all stable under concurrent real-client usage.
4. No retry dependence to mask protocol correctness defects.
5. Architecture/docs updated to reflect final h2 behavior and constraints.
