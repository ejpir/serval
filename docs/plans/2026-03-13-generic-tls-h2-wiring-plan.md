# Generic TLS-Frontend HTTP/2 Wiring Plan

Last updated: 2026-03-13

## Goal

Finish wiring **generic HTTP/2 over TLS frontend handling** in `serval-server` so that:

- ALPN `h2` can be safely used for non-gRPC web traffic (health/API/OIDC/UI),
- gRPC traffic continues to work correctly over h2,
- behavior is deterministic and RFC 9113-compliant,
- mixed deployments (web + gRPC + websocket) have an explicit rollout strategy.

## Problem Statement

Current implementation has strong h2 runtime/conformance coverage and gRPC-oriented h2 paths, but frontend orchestration is still conservative for mixed ALPN offers:

- ALPN callback currently prefers `http/1.1` when client offers both `h2,http/1.1`.
- This is safe for mixed traffic, but can block/complicate clients that need h2 by default.
- Generic non-gRPC h2 frontend path parity with h1 request handling needs explicit completion.

## Scope

### In scope

1. Generic TLS ALPN `h2` dispatch in main frontend path
2. Request/response handler orchestration parity for h2 vs h1
3. Deterministic stream/body/backpressure semantics for generic web traffic
4. Conformance and integration gates for both h2c and TLS h2
5. Rollout controls for mixed-offer ALPN policy

### Out of scope (this plan)

- HTTP/3 / QUIC
- RFC 8441 WebSocket over h2 (unless promoted to required scope)
- New routing features unrelated to h2 frontend wiring

---

## Architecture Decisions (must resolve first)

### D0 — Mixed endpoint strategy

If one hostname serves both web + websocket + gRPC:

- **Option A (recommended immediate): split hostnames**
  - `grpc.<domain>`: h2-first
  - `web.<domain>`: h1-first (until RFC8441 or full websocket-h2 plan)
- **Option B:** keep single hostname but remain conservative until websocket-over-h2 strategy is complete

Decision required before enabling mixed-offer `prefer_h2` globally.

### D1 — Explicit config knobs

Add frontend policy controls in `serval-core/config.zig`:

- `tls_h2_frontend_mode: enum { disabled, terminated_only, generic }`
- `alpn_mixed_offer_policy: enum { prefer_http11, prefer_h2 }`

Defaults remain conservative until phase gates are green.

---

## Phase Plan

## Phase 1 — Frontend Generic h2 Dispatch Foundation

### P1-A
Wire ALPN `h2` dispatch into generic h2 frontend handler path in `serval-server/h1/server.zig`.

### P1-B
Keep existing terminated-h2 callback path intact; add explicit branching so generic handler path is selected when configured.

### P1-C
Add regression tests for dispatch matrix:

- ALPN `h2` + generic mode
- ALPN `h2` + terminated-only mode
- ALPN mixed offers under both policies

### Exit gate

- Dispatch behavior deterministic for all policy combinations.

---

## Phase 2 — Generic Request/Response Orchestration Parity

### P2-A
Implement/finish h2 request adapter into normal handler contract:

- `onRequest`
- `selectUpstream`
- `onResponse`
- `onError`
- `onLog`

### P2-B
Support direct response paths over h2:

- `send_response`
- `reject`

### P2-C
Ensure request context fields (bytes, durations, connection info) are populated consistently between h1 and h2.

### Exit gate

- Generic handlers behave identically (semantically) under h1 and h2.

---

## Phase 3 — Body Streaming + Flow Control Hardening

### P3-A
Finish stream-scoped body reader semantics for h2 DATA frames.

### P3-B
Maintain bounded per-stream state and deterministic WINDOW_UPDATE behavior.

### P3-C
Audit backpressure behavior to avoid stalls/deadlocks under concurrent streams.

### Exit gate

- No unbounded buffering; flow-control accounting proven by tests.

---

## Phase 4 — Forwarder/Upstream Path Completion for Generic h2 Frontend

### P4-A
Ensure non-gRPC requests arriving over h2 frontend can forward correctly to configured upstream protocols.

### P4-B
Enforce upstream contract strictly:

- `.h2c` => plaintext
- `.h2` => TLS + ALPN `h2`

### P4-C
Keep websocket behavior explicit/fail-closed when arriving via h2 if unsupported.

### Exit gate

- Generic forwarding matrix passes without retry-masked correctness.

---

## Phase 5 — Conformance + Interop Gates

### P5-A
Maintain `h2spec` green gates:

- cleartext h2c: 145/145
- TLS h2: 145/145

### P5-B
Add integration coverage for generic TLS h2 web paths:

- `/healthz`
- `/api/*`
- OIDC paths (`/nb-auth`, `/nb-silent-auth`, etc.)

### P5-C
Keep NetBird matrix and gRPC interop checks green:

- grpcurl
- nghttp
- existing integration route matrix tests

### Exit gate

- All protocol and integration gates green in CI and locally.

---

## Phase 6 — Rollout Controls

### P6-A
Canary deploy with:

- `tls_h2_frontend_mode=generic`
- `alpn_mixed_offer_policy=prefer_http11`

### P6-B
After canary evidence, move selected endpoints to `prefer_h2`.

### P6-C
For mixed traffic on one hostname, only switch to global `prefer_h2` after explicit websocket strategy sign-off.

---

## Test Matrix

| Category | Scenario | Expected |
|---|---|---|
| ALPN | Client offers `h2,http/1.1` + policy `prefer_http11` | `http/1.1` |
| ALPN | Client offers `h2,http/1.1` + policy `prefer_h2` | `h2` |
| ALPN | Client offers `h2` only | `h2` |
| Generic web | TLS h2 `GET /healthz` | valid h2 response (SETTINGS-first, status 200) |
| Generic web | TLS h2 OIDC/UI paths | valid h2 responses |
| gRPC | TLS h2 gRPC unary/streaming | grpc-status semantics preserved |
| Route split | NetBird route matrix | gRPC paths h2, web paths h1/expected behavior |
| Error handling | malformed h2 requests | deterministic GOAWAY/RST mapping |

---

## Verification Command Matrix

```bash
# Core
zig build
zig build test

# Protocol-focused
zig build test-h2
zig build test-server
zig build build-h2-conformance-server

# Conformance
integration/h2_conformance_ci.sh --h2spec-timeout 1

# Integration
zig build test-integration

# Optional stress
SERVAL_RUN_5GB_TEST=1 zig build test-integration
```

---

## PR Slicing (recommended)

1. PR1: Config knobs + dispatch matrix tests
2. PR2: Generic h2 request/response handler adapter
3. PR3: h2 body reader + flow-control hardening
4. PR4: generic h2 frontend -> forwarder completion
5. PR5: integration + conformance expansions
6. PR6: rollout policy defaults + docs finalization

---

## Documentation Updates Required on Completion

- `serval-server/README.md`
- `serval/ARCHITECTURE.md`
- `integration/README.md`
- `docs/plans/http2-rfc9113-matrix.md`
- `docs/plans/2026-03-12-http2-phase-workboard.md`

---

## Completion Criteria

- Generic TLS-fronted h2 works for non-gRPC web routes with deterministic behavior.
- gRPC behavior remains correct and unchanged.
- h2spec cleartext and TLS gates remain fully green.
- CI contains required conformance gate.
- ALPN rollout policy is explicit, documented, and reversible.
