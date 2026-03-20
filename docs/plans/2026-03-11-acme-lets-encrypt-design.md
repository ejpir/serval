# ACME / Let’s Encrypt Automatic Certificates Plan (TigerStyle)

## Goal

Add production-grade automatic certificate issuance and renewal using ACME (Let’s Encrypt), with:

- deterministic state transitions
- bounded resource usage
- zero-downtime TLS certificate activation
- crash-safe persistence
- no retry-masking of logic bugs

Primary target for first release:

- `HTTP-01` challenge only
- one managed certificate bundle per server instance (SAN list supported with bounded size)

## References

- RFC 8555 (ACME)
- Let’s Encrypt Integration Guide
- RFC 8737 (TLS-ALPN-01) — explicitly deferred to a later phase

## Non-goals (first release)

- wildcard certificates (`DNS-01` needed)
- external DNS provider integrations
- full multi-tenant dynamic cert routing
- certificate transparency monitoring service

## Architecture Placement (Z1)

Create new layer-2 infrastructure module:

- `serval-acme/`

Why layer 2:

- reusable infra capability
- independent lifecycle (`init/deinit`, periodic scheduler, persistent state)
- consumed by orchestration/server layer, not strategy modules

Dependencies:

- `serval-core` (config/time/log/types)
- `serval-client` (HTTPS ACME API calls)
- `serval-tls` (SSL_CTX creation + atomic swap)

No sideways deps with layer-4 strategy modules.

## TigerStyle Requirements Applied

1. **Bounded loops only**
   - bounded poll attempts
   - bounded transition steps per scheduler tick
   - bounded challenge table scans
2. **Explicit state machine**
   - no implicit "in progress" booleans
3. **Fixed capacities**
   - max domains, max active challenges, max retries, max payload bytes
4. **No `catch {}`**
   - all ACME/network/storage errors are classified and surfaced
5. **No runtime allocation after init (steady-state)**
   - preallocated buffers and fixed tables for periodic operations
6. **Assertions in every function**
   - preconditions (`ptr != 0`, bounds)
   - postconditions (state invariants, monotonic timestamps)

## High-Level Runtime Model

Two cooperating components:

1. **ACME Manager** (`serval-acme/manager.zig`)
   - owns ACME account, order flow, renewal scheduler, persistence
2. **HTTP-01 Challenge Endpoint** (`serval-acme/http01_handler.zig`)
   - serves `/.well-known/acme-challenge/{token}` from bounded challenge store

The manager updates a shared fixed-capacity challenge store; the handler reads from it.

## Proposed Module Layout

- `serval-acme/mod.zig`
- `serval-acme/README.md`
- `serval-acme/types.zig` (state structs/enums)
- `serval-acme/config.zig` (local validated runtime config copy)
- `serval-acme/manager.zig` (scheduler + state machine)
- `serval-acme/client.zig` (ACME HTTP protocol client)
- `serval-acme/jws.zig` (JWS protected header/payload/signature)
- `serval-acme/account.zig` (account lifecycle)
- `serval-acme/order.zig` (order/authz/challenge/finalize flow)
- `serval-acme/http01_store.zig` (bounded token store)
- `serval-acme/http01_handler.zig` (direct response handler)
- `serval-acme/storage.zig` (atomic persistence + recovery)
- `serval-acme/backoff.zig` (bounded retry schedule)

## Config Additions (`serval-core/config.zig`)

Compile-time bounds:

- `ACME_MAX_DOMAINS_PER_CERT: u8 = 16`
- `ACME_MAX_ACTIVE_CHALLENGES: u8 = 64`
- `ACME_MAX_POLL_ATTEMPTS: u16 = 120`
- `ACME_MAX_TRANSITIONS_PER_TICK: u8 = 32`
- `ACME_MAX_DIRECTORY_RESPONSE_BYTES: u32 = 64 * 1024`
- `ACME_MAX_CERT_PEM_BYTES: u32 = 256 * 1024`
- `ACME_MAX_JWS_BODY_BYTES: u32 = 64 * 1024`

Runtime config (new optional section):

```zig
pub const AcmeConfig = struct {
    enabled: bool = false,
    directory_url: []const u8,
    contact_email: []const u8,
    state_dir_path: []const u8,
    challenge_bind_port: u16 = 80,
    renew_before_ns: u64 = time.daysToNanos(30),
    poll_interval_ms: u32 = 2000,
    fail_backoff_min_ms: u32 = 1000,
    fail_backoff_max_ms: u32 = 3_600_000,
    domains: BoundedDomainList,
};
```

`Config` gains:

- `acme: ?AcmeConfig = null`

All string fields are copied into bounded internal buffers during init.

## State Machine (Explicit)

```zig
const CertState = enum(u8) {
    idle,
    due_for_renewal,
    fetch_directory,
    fetch_nonce,
    ensure_account,
    create_order,
    fetch_authorizations,
    publish_http01,
    notify_challenge_ready,
    poll_authorization,
    finalize_order,
    poll_order_ready,
    download_certificate,
    persist_and_activate,
    cleanup_challenges,
    backoff_wait,
    fatal,
};
```

Invariants:

- only one active order in first release
- state transitions are table-driven and validated
- each tick executes at most `ACME_MAX_TRANSITIONS_PER_TICK`
- any unexpected transition -> `fatal`

## HTTP-01 Integration Design

### Listener model

- run a dedicated lightweight HTTP listener on `challenge_bind_port` (default 80)
- use `serval-server.MinimalServer` with `AcmeHttp01Handler`
- handler responsibilities:
  - exact path prefix match: `/.well-known/acme-challenge/`
  - method must be `GET`
  - host must match managed domain set
  - token lookup in bounded store
  - return plain text key authorization

Why dedicated listener:

- keeps challenge serving independent from product routing rules
- avoids coupling challenge path handling to user handlers
- explicit operational model for ACME reachability

## TLS Context Reload (Zero-Downtime)

Add reloadable TLS context support in `serval-tls`:

- `ReloadableServerCtx` with atomic active generation
- handshake path acquires current generation + increments refcount
- manager swaps to new ctx atomically after successful cert validation
- old context retired when refcount reaches zero

Bounded resources:

- max retired ctx slots: 4
- if retire queue full, activation fails closed (keep old cert, log + metric)

No connection drop required; new handshakes see new cert.

## Persistent Storage (Crash-Safe)

Directory layout:

- `${state_dir}/account.json`
- `${state_dir}/account.key.pem`
- `${state_dir}/cert/current/fullchain.pem`
- `${state_dir}/cert/current/privkey.pem`
- `${state_dir}/cert/meta.json`
- `${state_dir}/journal.json`

Write protocol (atomic):

1. write `*.tmp` with `0600`
2. `fsync(file)`
3. `rename(tmp, final)`
4. `fsync(parent_dir)`

On startup:

- validate files + parse metadata
- if journal indicates interrupted activation, complete/rollback deterministically

## ACME Protocol Flow (Manager)

1. load/validate current cert metadata
2. if `now >= not_after - renew_before_ns` -> renewal flow
3. create order for bounded domain list
4. for each authorization:
   - select HTTP-01 challenge
   - publish token in store
   - notify ACME server challenge is ready
   - poll auth until valid/invalid/timeout
5. finalize order with CSR
6. poll order until ready
7. download certificate chain
8. persist cert/key atomically
9. create new `SSL_CTX` and swap
10. remove challenge tokens
11. return to `idle`

## Failure Policy

- renewal failures never delete current cert
- bounded exponential backoff with jitter (`min..max`)
- classify errors (`network`, `protocol`, `storage`, `crypto`, `rate_limited`)
- after `N` consecutive failures, emit critical log + metric each interval

## Security Controls

- private key file mode `0600`
- redact sensitive values from logs
- strict host/token/path validation on challenge endpoint
- production/staging directory URLs explicit in config
- default development profile uses Let’s Encrypt staging

## Observability

Counters:

- `acme_renew_attempt_total`
- `acme_renew_success_total`
- `acme_renew_failure_total`
- `acme_http01_challenge_active`
- `tls_ctx_reload_total`
- `tls_ctx_reload_failure_total`

Gauges:

- `tls_cert_not_after_unix_seconds`
- `acme_next_renewal_unix_seconds`
- `acme_consecutive_failures`

Structured logs include:

- state transition (`from`, `to`)
- order URL hash/id
- bounded failure reason enum

## Test Plan (Space-Shuttle Level)

### Unit

- state transition table validity
- backoff bounds + jitter range
- challenge store insert/replace/expire boundaries
- atomic storage happy/error paths
- cert activation rollback on swap failure

### Integration (with Pebble test ACME CA)

- fresh issuance success
- renewal success before expiry
- challenge timeout cleanup
- nonce invalid / replay handling
- restart during mid-order recovery
- context swap under concurrent handshakes

### Fault Injection

- disk full during write
- rename failure
- ACME 429 rate-limit responses
- ACME badNonce loop beyond bounded retry

## Implementation Status (2026-03-17)

Completed in repository:

- ✅ PR1 subset: module skeleton + bounded challenge store (`http01_store.zig`)
- ✅ PR3: ACME client/JWS/wire/orchestration primitives
- ✅ PR4 scaffolding: manager tick runner + operation execution + deterministic response/error assessment

Not completed yet:

- ⛔ `AcmeConfig` addition in `serval-core/config.zig` (plan item from PR1)
- ⛔ dedicated HTTP-01 listener wiring into `serval-server` orchestration path
- ⛔ reloadable TLS context implementation (`ReloadableServerCtx`) and handshake integration
- ⛔ CSR/finalize/certificate download/persistence/activation full flow
- ⛔ crash journal recovery + full ACME metrics set

## Remaining PR Sequence (finish plan)

### PR-A — Core config + runtime wiring

Scope:

- add `AcmeConfig` in `serval-core/config.zig` (bounded fields and validation)
- thread optional `config.acme` through server bootstrap path
- define explicit startup behavior when ACME disabled vs enabled

Definition of done:

- `Config` includes `acme: ?AcmeConfig`
- invalid ACME config fails fast at startup with explicit error
- module README/docs updated

### PR-B — Dedicated HTTP-01 challenge listener

Scope:

- add `serval-acme/http01_handler.zig`
- wire a dedicated `serval-server.MinimalServer` listener on `challenge_bind_port`
- route only `GET /.well-known/acme-challenge/{token}`
- strict host/method/path checks against managed domain list

Definition of done:

- challenge lookups are bounded and deterministic
- no coupling to product routing handlers
- integration test validates challenge visibility from ACME CA simulator

### PR-C — Reloadable TLS context (zero-downtime)

Scope:

- add `ReloadableServerCtx` in `serval-tls`
- implement atomic generation swap with bounded retire queue
- integrate handshake path to acquire/release context generation refs

Definition of done:

- new handshakes observe new cert after swap
- existing handshakes/active connections remain valid
- bounded retired ctx queue behavior tested (including full queue failure path)

### PR-D — End-to-end ACME order finalize + cert activation

Scope:

- implement CSR generation and finalize call path
- poll order readiness with bounded attempts
- download fullchain + key material (bounded buffers)
- persist atomically (`tmp` + `fsync` + `rename` + dir `fsync`)
- activate cert via reloadable TLS context swap

Definition of done:

- fresh issuance with Pebble passes end-to-end
- renewal before expiry activates without restart
- failure never removes currently active cert

### PR-E — Recovery, backoff, observability hardening

Scope:

- add persistent journal and deterministic startup recovery
- add bounded exponential backoff module (`backoff.zig`)
- expose planned metrics/counters/gauges and structured transition logs

Definition of done:

- restart during mid-order resumes/rolls back deterministically
- disk/network/429/badNonce fault injection tests pass
- soak test shows stable bounded behavior without retry masking

## Verification Commands (per PR)

```bash
zig build
zig build test
zig build test-server
zig build test-client
zig build test-integration
```

## Exit Criteria

- automatic issuance and renewal run without manual restarts
- cert/key activation is atomic and zero-downtime
- challenge endpoint is deterministic and bounded
- restart recovery is deterministic
- repeated integration runs are stable without retry wrappers
