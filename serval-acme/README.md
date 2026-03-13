# serval-acme

Automatic certificate lifecycle primitives for ACME (Let's Encrypt).

## Layer

Layer 2 (Infrastructure).

## Current Scope (PR1 + PR3 primitives)

- Explicit ACME certificate lifecycle state enum (`CertState`)
- Runtime-validated fixed-capacity ACME config copy (`RuntimeConfig`)
- Bounded HTTP-01 challenge token store (`Http01Store`)
- ACME client protocol primitives (`client.zig`):
  - bounded URL + replay-nonce types
  - directory/account/order response parsing helpers
  - bounded JSON serializers for new-account and new-order payloads
- ACME JWS scaffolding (`jws.zig`):
  - protected-header serializers for `jwk` and `kid` forms
  - signing-input serializer (`base64url(protected) + "." + base64url(payload)`)
  - flattened JWS envelope serializer
- ACME wire helpers (`wire.zig`):
  - absolute endpoint URL parsing to host/port/path
  - request builders for `newNonce`, `newAccount`, `newOrder`, generic signed POST
  - response header extraction helpers (`Replay-Nonce`, `Location`)
- ACME orchestration helpers (`orchestration.zig`):
  - stateful nonce carry and endpoint selection (`FlowContext`)
  - deterministic per-operation response status classification (`assessAcmeResponse`)
  - deterministic protocol error classification (`classifyAcmeProtocolError`)
  - bounded account/order response handling with explicit URL capture (`Location`)
- ACME transport adapter (`transport.zig`):
  - executes `AcmeWireRequest` via `serval-client` (`executeAcmeWireRequest`)
  - provides operation-level orchestration execution (`executeAcmeOperation`)
  - bounded response body decoding (content-length + chunked with pre-read support)
- ACME manager transition runner (`manager.zig`):
  - bounded per-tick state progression (`AcmeManager.runTick`)
  - explicit signed-body routing by operation (`AcmeSignedBodies`)
  - deterministic failure disposition (`fetch_nonce`, `backoff_wait`, `fatal`)

## Not in this slice yet

- ACME HTTPS transport execution (network I/O, JWS signing, retries)
- CSR/finalize/download flow
- Persistent journal/recovery
- TLS context hot-reload integration with ACME manager trigger
- Dedicated HTTP-01 server wiring
