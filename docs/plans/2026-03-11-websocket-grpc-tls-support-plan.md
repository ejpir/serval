# WebSocket + gRPC TLS Support Plan

## Goal

Add production-grade TLS coverage and implementation for:

1. WebSocket over TLS (`wss`)
2. gRPC over TLS (HTTP/2 over TLS with ALPN `h2`)

while preserving existing cleartext behavior:
- HTTP/1.1 + WebSocket upgrade over plaintext
- gRPC over cleartext `h2c` (prior-knowledge and `Upgrade: h2c`)

## Current State (as of 2026-03-11)

### WebSocket
- WebSocket forwarding and native endpoint paths already use `Socket`/`TLSStream` abstractions.
- TLS termination and upstream TLS exist at server/proxy layers.
- Integration coverage today is strong for plaintext WebSocket, but missing explicit `wss` end-to-end test matrix.

### gRPC
- Stream-aware proxying is implemented for cleartext `h2c`.
- Current path explicitly rejects TLS for h2c bridge/upstream session pool:
  - `serval-client/h2/upstream_pool.zig` rejects `upstream.tls`
  - `serval-server/h1/server.zig` rejects h2c upgrade on TLS connections
- No end-to-end TLS gRPC interop matrix yet (`grpcurl`/`grpc-go` over TLS).

## Scope Split

## Phase A — WebSocket TLS Test Matrix + Fixes

### A1. Integration coverage for `wss`
Add integration tests for:
- `wss frontend -> ws backend`
- `ws frontend -> wss backend`
- `wss frontend -> wss backend`
- native WebSocket endpoint over TLS (`wss`)
- invalid upstream websocket `101` over TLS still fail-closes (`502`)

### A2. Reliability hardening
- Preserve existing timeout/fail-closed patterns in test harness and frame read loops.
- Ensure no indefinite waits in `wss` test paths.

### A3. Acceptance
- New `wss` tests pass consistently.
- Existing plaintext websocket tests remain green.

---

## Phase B — gRPC TLS Foundations (Protocol + ALPN)

### B1. Explicit protocol model
- Extend `serval-core/types.zig` `HttpProtocol` with `.h2` (TLS HTTP/2) while preserving `.h2c`.
- Keep backward compatibility defaults (`.h1`).

### B2. TLS ALPN plumbing
- Add ALPN configuration wrappers in `serval-tls` (client + server contexts).
- Configure server ALPN preference for `h2`, `http/1.1` where TLS termination is enabled.
- Configure upstream TLS client ALPN to request `h2` for `.h2` upstreams.

### B3. Acceptance
- Unit tests for ALPN helper encoding/selection.
- Exhaustive switch coverage where `HttpProtocol` is used.

---

## Phase C — gRPC TLS Ingress (Frontend Termination)

### C1. ALPN-based dispatch on accepted TLS connections
- In `serval-server` TLS accept path, dispatch by negotiated ALPN:
  - `h2` => HTTP/2 runtime path
  - `http/1.1` => existing HTTP/1.1 path
- Keep `Upgrade: h2c` strictly cleartext-only.

### C2. HTTP/2 runtime compatibility under TLS
- Reuse bounded runtime semantics (SETTINGS/ACK, flow control, CONTINUATION, fail-closed reset/goaway behavior) for TLS-backed streams.
- Ensure no raw-fd assumptions break TLS path.

### C3. Acceptance
- Integration tests for terminated gRPC over TLS unary + server-streaming.
- Existing h2c tests unchanged and still passing.

---

## Phase D — gRPC TLS Upstream Origination (Stream-Aware Bridge)

### D1. Upstream session pool support for `.h2 + tls`
- Update `serval-client/h2/upstream_pool.zig` validation:
  - allow `(.h2, tls=true)`
  - keep `(.h2c, tls=false)`
  - reject invalid combinations explicitly
- Require ALPN `h2` on upstream TLS handshake; fail closed on mismatch.

### D2. Bridge policy update
- Generalize bridge entry checks from "cleartext h2c only" to:
  - cleartext `h2c`
  - TLS `h2`
- Preserve session-generation-aware mapping, GOAWAY `last_stream_id` handling, and grpc-status fail-closed semantics.

### D3. Acceptance
- Integration tests for proxied gRPC TLS frontend->TLS upstream.
- GOAWAY/RST propagation tests over TLS path.

---

## Phase E — External TLS Interop + Churn/Soak

### E1. grpcurl TLS interop
- Process-level tests (`grpcurl -plaintext` equivalent replaced with TLS mode + `-insecure` for test certs):
  - unary success
  - metadata/header/trailer assertions (`-v`)
  - repeated churn loops

### E2. grpc-go TLS interop
- Process-level tests (`go run` grpc-go client):
  - unary + server-streaming
  - metadata/header/trailer assertions
  - repeated churn loops

### E3. Acceptance
- No-skip policy (if tool exists, failures are hard failures).
- Stable on repeated runs with bounded per-command timeout.

---

## Phase F — Documentation + Architecture Updates

Update:
- `integration/README.md` test matrix with TLS websocket/grpc rows
- `serval-server/README.md` protocol dispatch rules (`h2` via ALPN, `h2c` cleartext only)
- `serval-proxy/README.md` bridge capability matrix (`h2c` + `h2` TLS)
- `serval/ARCHITECTURE.md` request flows and protocol matrix

## Non-Goals (for this plan)

- HTTP/3/QUIC
- mTLS policy engine beyond current cert verification knobs
- dynamic cert reload control-plane work
- bidi/client-streaming gRPC application-level semantics beyond transport correctness

## Implementation Constraints (TigerStyle / Reliability)

- All loops bounded (test loops, retries, handshake polling)
- Explicit error handling (no `catch {}`)
- Fixed-capacity structures in runtime/bridge/session paths
- Fail-closed protocol handling on invalid ALPN/frames/metadata
- No hidden behavior changes to existing h2c paths

## PR Slicing (recommended)

1. PR1: WebSocket TLS integration matrix (tests + small fixes)
2. PR2: `HttpProtocol.h2` + ALPN wrappers + unit tests
3. PR3: TLS ingress ALPN dispatch to h2 runtime
4. PR4: `.h2 + tls` upstream session pool + bridge support
5. PR5: grpcurl/grpc-go TLS interop tests + churn loops
6. PR6: docs + final soak/stress pass

## Verification Commands (each PR)

```bash
zig build
zig build test
zig build test-server
zig build test-h2
zig build test-grpc
zig build test-client
zig build test-proxy
zig build test-integration
SERVAL_RUN_5GB_TEST=1 zig build test-integration
```

## Exit Criteria

- WebSocket `wss` matrix passes end-to-end.
- gRPC over TLS (`h2` + ALPN) works for terminated and proxied paths.
- Existing gRPC h2c behavior remains green and unchanged.
- External grpcurl/grpc-go TLS interop matrix (including metadata/trailer assertions and churn loops) passes reliably.
- Architecture/docs reflect final behavior accurately.
