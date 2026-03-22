# HTTP/2 Completion Plan: gRPC Bridge + Full Generic Stream-Aware Stack

Last updated: 2026-03-20

## Scope

This plan defines how to complete both in-progress items:

1. gRPC over HTTP/2 proxying (prior knowledge + inbound upgrade)
2. HTTP/2 full stream-aware proxy/server stack (generic, not gRPC-only)

The plan is execution-focused and tied to normative protocol requirements.

## Normative Sources

Primary:
- RFC 9113 (HTTP/2): <https://www.rfc-editor.org/rfc/rfc9113>
- RFC 9110 (HTTP Semantics): <https://www.rfc-editor.org/rfc/rfc9110>
- RFC 7541 (HPACK): <https://www.rfc-editor.org/rfc/rfc7541>

Compatibility profile:
- RFC 7540 (legacy `Upgrade: h2c` behavior, obsoleted by RFC 9113): <https://www.rfc-editor.org/rfc/rfc7540>

gRPC transport contract:
- gRPC over HTTP/2: <https://grpc.github.io/grpc/core/md_doc__p_r_o_t_o_c_o_l-_h_t_t_p2.html>

## Current State (Code Reality)

- Stream-aware bridge exists and is stable for gRPC-focused flows.
- Full generic HTTP/2 stream-aware behavior is still incomplete.
- Generic frontend currently rejects non-gRPC request bodies with 413.
- Prior-knowledge cleartext routing is protocol-split today:
  - `.h2c` cleartext upstream uses bridge path (`forwardH2cWithBridge`).
  - `.h2` TLS upstream is routed to raw tunnel relay (`forwardGrpcH2c`).
  - This is explicit branch routing, not a retry fallback sequence.
- Upgrade path bridge choice is still constrained by upstream protocol checks.

Existing references:
- `serval-server/frontend/generic_h2.zig`
- `serval-server/h1/server.zig`
- `serval-proxy/h2/bridge.zig`
- `docs/plans/http2-rfc9113-matrix.md`
- `serval-server/README.md`

## Implementation Mapping (Actual Symbols)

For execution clarity, this plan uses the current symbol names:

- Prior-knowledge cleartext entry dispatcher:
  - `tryHandleH2cPriorKnowledge` (`serval-server/h1/server.zig`)
- Prior-knowledge bridge driver:
  - `forwardH2cWithBridge` (`serval-server/h1/server.zig`)
- Prior-knowledge tunnel driver:
  - `forwardGrpcH2c` (`serval-proxy/forwarder.zig`)
- Upgrade bridge driver:
  - `forwardH2cUpgradeWithBridge` (`serval-server/h1/server.zig`)
- Upgrade legacy driver:
  - `forwardGrpcH2cUpgrade` (`serval-proxy/forwarder.zig`)
- Core stream bridge:
  - `StreamBridge` / `H2StreamBridge` (`serval-proxy/h2/bridge.zig`)

## Definition of Complete

### Item A: gRPC over HTTP/2 proxying (prior knowledge + inbound upgrade)

Complete means:
- For supported upstream HTTP/2 targets (`.h2c` and `.h2`), cleartext prior-knowledge and cleartext upgrade entry paths are stream-aware end-to-end (no tunnel fallback as steady-state path).
- GOAWAY, RST_STREAM, cancellation, and trailer propagation are deterministic under churn.
- gRPC completion semantics are fail-closed (`grpc-status` and trailer handling).
- Interop is stable with grpcurl and grpc-go under repeated churn loops.

### Item B: full stream-aware HTTP/2 stack

Complete means:
- Generic HTTP/2 traffic (non-gRPC) is first-class for both:
  - `h2 -> h1` forwarding (including request body streaming)
  - `h2 -> h2` forwarding (headers/data/trailers/reset semantics)
- Stream fairness and flow-control correctness hold under mixed long/short streams.
- No critical user path relies on tunnel fallback for HTTP/2 semantics.
- Conformance and interop gates remain green for both cleartext and TLS profiles.

## Supported Profiles

### P1: Standards-first profile

Normative behavior follows RFC 9113/9110/7541 for production paths.

### P2: Legacy compatibility profile

`Upgrade: h2c` support remains as explicit compatibility behavior aligned with RFC 7540 upgrade mechanics. This profile is maintained intentionally, not by side effect.

## Workstreams and Phases

## Phase 0 - Freeze Completion Gates

Deliverables:
- Lock this completion plan and link it from `docs/plans/2026-03-12-http2-phase-workboard.md`.
- Convert current "in progress" labels into gate-based checklists.
- Separate "supported profile" and "compatibility profile" in docs.

Exit:
- One canonical gate list for Item A and Item B exists and is tracked.

## Phase 1 - Finish gRPC Bridge Coverage Across Entry Paths

Goal:
- Remove remaining behavior where supported HTTP/2 upstreams are not handled by stream bridge.

Required changes:
- Prior-knowledge cleartext path:
  - remove raw-tunnel routing for supported `.h2` TLS upstreams.
  - route both `.h2c` and `.h2` through stream bridge path.
- Upgrade cleartext path:
  - remove `.h2c`-only bridge gating.
  - support `.h2` upstreams through bridge path with proper TLS connection setup.
- Keep explicit fail-closed behavior for protocol errors.
- Keep gRPC completion validation as a distinct layer on top of generic bridge actions:
  - enforce `grpc-status` rules on terminal headers/trailers paths.
  - fail closed on missing/invalid grpc completion metadata.

Acceptance:
- No tunnel fallback for supported HTTP/2 upstream protocols in these entry paths.
- Existing gRPC interop and churn tests remain green.

Complexity note:
- `.h2` support for upgraded downstream cleartext sessions is not a simple protocol-check change.
- It requires end-to-end bridge wiring that performs upstream TLS connect/origination and preserves existing upgraded-stream bootstrap semantics safely.

## Phase 2 - Bridge Generalization (gRPC -> Generic HTTP/2)

Goal:
- Make stream bridge generic transport-first, with gRPC rules layered on top.

Required changes:
- Keep stream mapping/action model generic (headers/data/trailers/reset/close).
- Gate gRPC-only checks by request class, not by bridge architecture.
- Ensure non-gRPC trailer and end-stream handling is valid.
- Ensure gRPC-specific completion validation remains explicitly owned by the gRPC layer (not buried in generic bridge core).

Acceptance:
- Non-gRPC HTTP/2 streams can be bridged without grpc-specific assumptions.

## Phase 3 - Generic Frontend Request Body Completion

Goal:
- Eliminate `request body over generic h2 frontend not supported`.

Required changes in generic frontend:
- Accept request bodies for non-gRPC methods.
- Stream DATA with bounded backpressure.
- Respect END_STREAM timing (headers-only vs headers+data).
- Preserve per-stream isolation and fairness.

Acceptance:
- POST/PUT/PATCH over generic h2 frontend succeed across small/large bodies.
- One stalled stream does not block unrelated streams on the same connection.

## Phase 4 - Generic h2->h1 and h2->h2 Semantics Hardening

Goal:
- Production-grade semantics and translation correctness.

Required:
- Header translation correctness:
  - pseudo-header mapping
  - `:authority` and `host` behavior
  - connection-specific header stripping
  - `TE` handling
- Body framing correctness and trailer handling.
- Reset and GOAWAY behavior under races and partial progress.

Acceptance:
- RFC-invalid combinations fail closed.
- Valid traffic preserves HTTP semantics across translation boundaries.

## Phase 5 - Protocol Conformance and Interop Gates

Mandatory gates:
- `h2spec` cleartext and TLS suites pass in CI.
- `nghttp` checks pass in CI.
- grpcurl and grpc-go interop tests pass for:
  - unary
  - server-streaming
  - metadata/trailers assertions
  - churn loops

Additional required test expansion:
- Generic HTTP/2 client matrix (non-gRPC cases).
- Mixed-load fairness scenarios:
  - one long-lived stream + many short streams
  - slow upstream/downstream backpressure cases

## Phase 6 - Soak and Rollout

Goal:
- Promote with confidence under real traffic patterns.

Steps:
- Run canary with h2-first policy and full gate suite.
- Capture reset/GOAWAY/error distributions over sustained soak windows.
- Promote only after repeated green runs and no recurring protocol regressions.

## PR Breakdown

1. Gate and profile freeze docs update (Phase 0)
2. Prior-knowledge + upgrade bridge policy completion for `.h2` and `.h2c` (Phase 1)
3. Bridge transport generalization (Phase 2)
4. Generic frontend request-body implementation (Phase 3)
5. Generic h2->h1/h2->h2 semantic hardening (Phase 4)
6. Conformance + interop matrix expansion (Phase 5)
7. Soak + rollout evidence and promotion update (Phase 6)

## Test Program

Build/test baseline:
- `zig build`
- `zig build test`
- `zig build test-integration`

Conformance:
- `integration/h2_conformance_runner.sh`
- `integration/h2_conformance_ci.sh`

Interop:
- grpcurl plaintext + TLS cases
- grpc-go plaintext + TLS cases
- nghttp and curl HTTP/2 generic cases

Stress/soak:
- stream churn near `H2_MAX_CONCURRENT_STREAMS`
- GOAWAY rollover under active load
- reset race and cancellation loops
- long-lived stream coexistence with short unary bursts

## Risk Register

- Bridge stall regressions during `.h2` upstream unification.
- Fairness regressions when enabling generic request-body streaming.
- Accidental semantics drift between RFC 9113 profile and RFC 7540 compatibility paths.

Mitigations:
- Keep fail-closed behavior and explicit error mapping.
- Gate each phase with conformance + interop + stress before merge.
- Preserve backward compatibility in compatibility profile while production path follows RFC 9113.

## Final Exit Criteria

Item A and Item B are complete only when all are true:
- Required phase deliverables are merged.
- Mandatory protocol/interop/stress gates are green in CI and local reproducible runs.
- `serval-server/README.md` and `docs/plans/http2-rfc9113-matrix.md` reflect final behavior with no "pending" ambiguity for these two items.
