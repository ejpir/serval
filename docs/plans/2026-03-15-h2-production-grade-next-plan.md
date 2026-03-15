# HTTP/2 Production-Grade Next Plan

## Goal

Close the remaining gap from "working HTTP/2 slices" to production-grade behavior for:

1. `h2 -> h1`
   ALPN `h2` or cleartext h2 frontend requests translated/forwarded to HTTP/1.1 upstreams.
2. `h2 -> h2`
   ALPN `h2` or cleartext h2 frontend requests forwarded over a real stream-aware HTTP/2 upstream path.

This plan is intentionally operational, not aspirational. It is driven by the current code and by bugs already observed under real NetBird traffic.

## Current State

### `h2 -> h1`

- Generic frontend HTTP/2 handler exists in `serval-server/frontend/generic_h2.zig`.
- It can:
  - accept ALPN `h2`
  - decode bounded HTTP/2 requests
  - route gRPC requests into the bridge path
  - route non-gRPC requests into HTTP/1.1 forwarding
  - support extended CONNECT WebSocket forwarding
- Current behavior is useful, but not yet production-grade:
  - request-body handling is intentionally incomplete for generic HTTP/2 non-gRPC traffic
  - backpressure, fairness, and long-lived stream lifecycle coverage are still partial
  - h2 frontend -> h1 upstream translation coverage is narrower than the route matrix implies

### `h2 -> h2`

- Stream-aware gRPC-focused bridge exists via:
  - `serval-server/h1/server.zig`
  - `serval-proxy/h2/bridge.zig`
  - `serval-client/h2/upstream_pool.zig`
- Current strengths:
  - bounded downstream/upstream stream binding
  - GOAWAY `last_stream_id` handling
  - per-generation session binding
  - grpc-status fail-closed behavior
  - `.h2c + tls=false` and `.h2 + tls=true` upstream support
- Current limitation:
  - this is still gRPC-focused transport behavior, not a complete generic production-grade `h2 -> h2` proxy

## Production Bugs Already Observed

These are no longer theoretical and must inform the next plan:

1. Tunnel termination correctness bug
   - TLS tunnel cleanup could assert on a valid closed-peer termination path.
   - Fixed by accepting close terminations in tunnel finalization.

2. H2 background-task scheduling bug
   - Background h2 bridge/websocket readers were started with `std.Io.Group.async()`.
   - In practice this could interfere with the per-connection h2 startup path.
   - Fixed by using `Group.concurrent()` for long-lived readers.

3. Stream selection / stale-binding fairness bug
   - Upstream bridge reader could keep revisiting stale bindings and starve later work on the same connection.
   - Fixed by round-robin scan plus stale-binding retirement.

These fixes are necessary, but they are not sufficient to call the h2 stack production-grade.

## What "Production-Grade" Means Here

For both `h2 -> h1` and `h2 -> h2`, production-grade means:

- multi-client concurrency works under long-lived connections
- no eager task scheduling surprises
- no unbounded waiting or silent starvation
- stream closure/reset/GOAWAY behavior is fail-closed and observable
- request/response-body handling is correct under backpressure
- no route-matrix-specific hidden assumptions
- external interop passes under churn, not just happy-path unit tests

## Track A - `h2 -> h1` Production Work

### A1. Complete generic request-body support

Current generic frontend behavior is still biased toward:
- gRPC over bridged HTTP/2
- bodyless non-gRPC requests
- WebSocket CONNECT special-cases

Required:
- fully support generic HTTP/2 request bodies into HTTP/1.1 upstream forwarding
- cover:
  - `content-length`
  - chunked translation where required on the h1 side
  - empty body vs explicit zero-length body
  - large bodies with bounded buffering
  - client-side END_STREAM arriving on headers vs later DATA

Acceptance:
- `h2 -> h1` POST/PUT/PATCH requests succeed across small, medium, and large bodies
- backpressure does not stall unrelated connections
- body accounting in logs/metrics remains correct

### A2. Header translation hardening

Required:
- exhaustively validate generic h2 request -> h1 upstream header translation
- explicitly test:
  - pseudo-header handling
  - `host` / `:authority`
  - connection-specific header stripping
  - TE handling
  - transfer-encoding correctness
  - duplicate header preservation rules where legal
  - path/query preservation

Acceptance:
- RFC-invalid header combinations fail closed
- valid browser/client traffic survives translation unchanged in semantics

### A3. Extended CONNECT / WebSocket lifecycle hardening

Required:
- productionize the generic h2 WebSocket path:
  - close propagation
  - reader cancellation
  - idle timeout behavior
  - upstream failure mapping
  - stream reset behavior while websocket reader task is alive

Acceptance:
- one long-lived h2 websocket stream does not degrade unrelated h2 streams on the same connection
- abrupt downstream or upstream close does not leak tracked websocket state

### A4. Concurrency and fairness testing

Required:
- explicit tests for:
  - one long-lived h2 stream plus many short unary requests
  - concurrent request bodies across multiple streams
  - one stalled upstream response not blocking other streams
  - connection-level flow-control pressure while other streams progress

Acceptance:
- no per-connection starvation
- no "first stream wins" behavior
- no task-start path that can hijack connection progress

### A5. External client matrix for generic h2

Required:
- process-level interop with at least:
  - curl with `--http2`
  - nghttp or equivalent h2 client
  - browser-like request patterns where feasible

Acceptance:
- ALPN `h2` frontend -> h1 upstream path behaves correctly with real clients, not just internal tests

## Track B - `h2 -> h2` Production Work

### B1. Broaden from gRPC-focused to generic stream-aware h2 proxying

Current stream-aware path is intentionally gRPC-focused.

Required:
- generalize request/response handling so non-gRPC HTTP/2 traffic is first-class
- support:
  - non-gRPC response headers/trailers semantics
  - generic DATA flow on arbitrary stream counts
  - generic reset/error propagation

Acceptance:
- `h2 -> h2` works for both gRPC and generic HTTP/2 request classes

### B2. Flow-control correctness under load

Required:
- targeted work on:
  - connection window updates
  - per-stream window updates
  - fairness across active streams
  - avoiding over-buffering
  - behavior under slow downstream and slow upstream peers

Acceptance:
- one blocked stream cannot permanently stall unrelated active streams
- no invalid WINDOW_UPDATE behavior
- no hidden dependence on grpc-go/grpcurl timing quirks

### B3. GOAWAY, rollover, and reconnect semantics

Required:
- productionize upstream session rollover:
  - `GOAWAY(NO_ERROR, last_stream_id)` during active load
  - active-stream drain vs new-stream reroute
  - draining-session cleanup
  - generation handoff during churn

Acceptance:
- active eligible streams finish
- new streams move to the correct generation
- stale sessions do not linger indefinitely

### B4. Reset and cancellation semantics

Required:
- validate both directions:
  - downstream `RST_STREAM` -> upstream reset
  - upstream reset -> downstream reset
  - local cancellation while upstream is still producing DATA
  - reset races with trailers/end-stream

Acceptance:
- no stuck bindings after reset
- no response delivery after stream terminal state

### B5. Multi-client / multi-connection stress

Required:
- reproduce and permanently guard against:
  - one connected client stalling others
  - one noisy connection starving other accepted connections
  - one upstream session issue degrading unrelated frontend connections

Acceptance:
- multiple concurrent NetBird clients stay healthy across reconnect churn
- long-lived management sync streams do not block new signal/relay/dashboard traffic

### B6. External interop matrix for h2 upstreams

Required:
- process-level interop with:
  - grpcurl
  - grpc-go
  - at least one generic h2 client
- both:
  - frontend TLS ALPN `h2`
  - upstream `.h2` TLS and `.h2c` cleartext where supported

Acceptance:
- stable under repeated churn loops, not just a single success case

## Cross-Cutting Work Required for Both Tracks

### C1. Better observability

Required:
- add high-signal structured logs/counters for:
  - stream open/close
  - reset cause
  - GOAWAY receive/send
  - session generation rollover
  - stalled-read / stalled-write paths
  - task-start failures

Acceptance:
- future field reports can identify whether a stall is:
  - listener-level
  - connection-startup-level
  - stream-level
  - upstream-session-level

### C2. Stronger test shapes

Required:
- unit tests for state machines
- integration tests for transport correctness
- churn/soak tests for long-lived streams
- concurrency tests with 2, 8, 32, and mixed clients
- failure-injection cases:
  - upstream close
  - downstream close
  - partial headers
  - mid-stream reset
  - GOAWAY during active calls

### C3. Explicit operational limits

Required:
- revisit and document:
  - max streams
  - max frame counts
  - idle timeouts
  - stall timeouts
  - retry counts
  - behavior when concurrent worker creation fails

Acceptance:
- limits are explicit, justified, and tested

### C4. Documentation and architecture alignment

Update:
- `serval-server/README.md`
- `serval-proxy/README.md`
- `serval/ARCHITECTURE.md`
- NetBird deployment docs where route behavior depends on h2 semantics

## Recommended PR Slicing

1. PR1 - Generic `h2 -> h1` request-body completion
2. PR2 - Generic `h2 -> h1` header translation + interop matrix
3. PR3 - Generic h2 websocket/extended CONNECT lifecycle hardening
4. PR4 - `h2 -> h2` generic non-gRPC stream-aware proxy semantics
5. PR5 - `h2 -> h2` GOAWAY/reset/rollover hardening
6. PR6 - multi-client churn/soak and NetBird-specific regression coverage
7. PR7 - observability/docs/architecture cleanup

## Verification Commands

```bash
zig build
zig build test
zig build test-server
zig build test-h2
zig build test-client
zig build test-proxy
zig build test-integration
SERVAL_RUN_5GB_TEST=1 zig build test-integration
```

## Exit Criteria

We can call the next h2 phase production-grade only when all of the following are true:

- `h2 -> h1` supports production-useful request/response bodies and survives concurrency/backpressure tests
- `h2 -> h2` is no longer only gRPC-focused and behaves correctly for generic HTTP/2 traffic
- multi-client long-lived traffic no longer exhibits listener-adjacent or connection-startup starvation
- GOAWAY/reset/rollover behavior passes churn tests repeatedly
- external interop matrix passes for both generic h2 and gRPC clients
- docs match actual runtime behavior
