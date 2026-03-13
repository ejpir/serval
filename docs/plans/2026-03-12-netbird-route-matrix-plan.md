# NetBird Route-Matrix Stabilization Plan

## Goal

Lock and validate the NetBird reverse-proxy protocol split in Serval so that routing is deterministic on first attempt (no retry masking):

- gRPC routes use HTTP/2 cleartext (`.h2c`)
- WebSocket and HTTP routes stay HTTP/1.1 semantics (`.h1`)
- mixed protocol routing on the same backend host:port uses explicit upstream entries and pool indices

## Locked Protocol Contract

| Path Pattern | Upstream Protocol | Semantics |
|---|---|---|
| `/signalexchange.SignalExchange/*` | `.h2c` | gRPC |
| `/management.ManagementService/*` | `.h2c` | gRPC |
| `/management.ProxyService/*` | `.h2c` | gRPC (optional feature) |
| `/relay*`, `/ws-proxy/signal*`, `/ws-proxy/management*` | `.h1` | WebSocket upgrade |
| `/api/*`, `/oauth2/*`, `/ui/*`, `/oidc/*`, `/oauth/*`, `/.well-known/*`, `/*` | `.h1` | HTTP |

## Phase Plan

### Phase 1 — Contract lock in docs/tests

- Publish the route/protocol matrix in integration docs.
- Keep h2c usage explicit: only gRPC service paths.

### Phase 2 — NetBird integration matrix test

- Add one end-to-end integration test that validates all path classes.
- Run mixed protocol split against one backend host:port with explicit upstream entries:
  - `.h2c` entry for signal gRPC
  - `.h2c` entry for management gRPC
  - `.h1` entry for HTTP/WebSocket/catch-all

### Phase 3 — Determinism hardening

- Ensure no wrapper retries for correctness.
- Keep bounded loops/timeouts and fail-fast assertions in test helpers.

### Phase 4 — Example strategy lock

- Keep `lb_example` as smoke-only.
- Keep route/protocol acceptance in integration matrix tests.

### Phase 5 — Verification gates

Run:

```bash
/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build
/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test
/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig build test-integration
```

## Execution Status

- [x] Phase 1 implemented
- [x] Phase 2 implemented
- [x] Phase 3 implemented (no test-level retry wrapper introduced)
- [x] Phase 4 implemented
- [x] Phase 5 verification completed (`zig build`, `zig build test`, `zig build test-integration`)
