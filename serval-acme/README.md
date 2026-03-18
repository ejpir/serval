# serval-acme

Automatic certificate lifecycle primitives for ACME (Let's Encrypt).

## Layer

Layer 2 (Infrastructure).

## Current Scope (PR1 + PR3 + PR4/PR-E partial)

- Explicit ACME certificate lifecycle state enum (`CertState`)
- Runtime-validated fixed-capacity ACME config copy (`RuntimeConfig`)
- Bounded exponential backoff helper (`backoff.zig`):
  - fixed min/max range validation
  - deterministic capped jitter
  - retry deadline computation
- ACME client protocol primitives (`client.zig`):
  - bounded URL + replay-nonce types
  - directory/account/order/authorization response parsing helpers
  - bounded JSON serializers for new-account/new-order/finalize payloads
- ACME JWS scaffolding (`jws.zig`):
  - protected-header serializers for `jwk` and `kid` forms
  - signing-input serializer (`base64url(protected) + "." + base64url(payload)`)
  - flattened JWS envelope serializer
- ACME wire helpers (`wire.zig`):
  - absolute endpoint URL parsing to host/port/path
  - request builders for `newNonce`, `newAccount`, `newOrder`, generic signed POST
  - response header extraction helpers (`Replay-Nonce`, `Location`)
- ACME signer (`signer.zig`):
  - in-process ECDSA P-256 account key generation
  - JWK coordinate rendering (`x`,`y`) for account bootstrap
  - flattened JWS signing for `jwk` and `kid` protected headers
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
  - bounded backoff deadline tracking for `backoff_wait` re-entry
  - automated issuance entrypoint (`runAutomatedIssuanceOnce`) using runtime flow
- ACME runtime issuance flow (`runtime.zig`):
  - directory fetch -> nonce -> account -> order -> authz/challenge -> finalize -> cert download
  - TLS-ALPN-01 challenge activation/poll/cleanup via hook provider
  - atomic cert/key persistence and optional TLS hot-activation
- ACME CSR helper (`csr.zig`):
  - generates P-256 key + PKCS#10 CSR DER for configured SAN list fully in-process (no openssl)
- ACME TLS-ALPN certificate helper (`tls_alpn_cert.zig`):
  - generates ephemeral self-signed challenge certificate + key (PEM)
  - includes SAN and critical `id-pe-acmeIdentifier` extension
- ACME bootstrap certificate helper (`bootstrap_cert.zig`):
  - generates short-lived self-signed startup certificate + key (PEM)
  - SAN dNSName for the configured host, used before first ACME issuance
- ACME storage helper (`storage.zig`):
  - tmp+fsync+rename persistence for cert and key
- ACME scheduler (`scheduler.zig`):
  - generic bounded renew loop with pluggable `should_renew` and `issue` callbacks
  - exponential backoff on transient failures
- ACME renewer (`renewer.zig`):
  - composes scheduler + runtime issuance + certificate expiry parsing
  - caller supplies only activation callback (`cert_path`,`key_path`)
  - supports optional TLS-ALPN hook provider for ALPN challenge flow
- ACME managed renewer (`renewer.zig`):
  - owns/initializes DNS resolver, ACME client, signer, and work buffers
  - init-time setup only; no hidden runtime allocations in `run`
  - explicit `deinit` frees owned TLS client context
  - convenience `initFromAcmeConfig(...)` accepts `serval-core.config.AcmeConfig` directly

## Integration Notes

- TLS-ALPN-01 hook integration is intentionally isolated:
  - install `AcmeTlsAlpnHookProvider` once at process startup
  - pass `*AcmeTlsAlpnHookProvider` to issuance entrypoints
  - runtime activates per-challenge temporary TLS context only during challenge validation
- Bootstrap-first startup flow is supported:
  - generate short-lived bootstrap cert (`bootstrap_cert.zig`)
  - start HTTPS listener
  - run ACME issuance and hot-activate issued cert/key
- ACME contact email is account metadata for CA notices (expiry/security); it is not an interactive confirmation step.

## Not in this slice yet

- Persistent journal/recovery
- Manager-internal persistence journal/recovery and replay-safe crash restart sequence
