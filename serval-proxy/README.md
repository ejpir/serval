# serval-proxy

Mechanics-layer upstream forwarding for Serval.

`serval-proxy` owns how traffic is forwarded once a strategy layer has already
selected an upstream. That includes upstream connect/reuse, HTTP/1 request and
response forwarding, WebSocket upgrade/tunnel relay, and the current bounded
HTTP/2 stream bridge used for gRPC proxying.

Canonical bridge writeup:
- [docs/architecture/h2-bridge.md](/home/nick/repos/serval/docs/architecture/h2-bridge.md)

## Layer

- Layer 3: mechanics
- Responsibility: connection management, forward-path I/O, protocol-specific
  forwarding mechanics
- Non-responsibility: route matching, load-balancing policy, gateway policy

## Public API

Top-level exports from [mod.zig](/home/nick/repos/serval/serval-proxy/mod.zig):

| Export | Purpose |
|------|---------|
| `Forwarder` | Main forwarding engine generic over pool and tracer types |
| `ForwardError` | Bounded forwarding error set used by proxy operations |
| `ForwardResult` | Result metadata for a completed forward |
| `BodyInfo` | Request-body forwarding metadata |
| `Protocol` | Upstream protocol enum (`.http1`, `.h2c`, `.h2`, etc. via shared core type) |
| `TunnelStats` | Bytes/termination summary for bidirectional upgraded tunnels |
| `TunnelTermination` | Explicit tunnel shutdown reason |
| `h1` | HTTP/1 forwarding helpers |
| `h2` | HTTP/2 bridge primitives |
| `H2Binding` | Downstream/upstream stream binding record |
| `H2BindingTable` | Fixed-capacity binding table |
| `H2BindingError` | Binding table error set |
| `H2StreamBridge` | Stream-aware downstream-to-upstream h2 bridge |
| `H2StreamBridgeError` | h2 bridge error set |
| `H2StreamBridgeOpenResult` | Open-stream result from the bridge |
| `H2StreamBridgeReceiveAction` | Mapped action returned from upstream receive |

## Main Developer Entry Points

### h2 StreamBridge contract surface

`H2StreamBridge` is the mechanics boundary consumed by `serval-server`.

```text
serval-server policy/orchestration
        │ stable mechanics contract
        ▼
serval-proxy H2StreamBridge
        │ reusable sessions/runtime
        ▼
serval-client
```

- `openDownstreamStream(...)` opens/binds a downstream stream to an upstream stream
- `sendDownstreamData(...)` forwards request DATA for an existing binding
- `cancelDownstreamStream(...)` maps downstream cancellation/reset upstream
- `pollNextAction(io, timeout)` provides bounded fair polling across active bindings
- `takeAffectedDownstreamsForConnectionClose(...)` returns/removes downstream
  streams that must be reset for a GOAWAY/session-close action
- `activeBindingCount()` exposes bounded active binding count only (no table
  internals)

The server/orchestration layer is expected to use only this contract and mapped
`ReceiveAction` values rather than accessing binding-table storage directly.
This is a boundary clarification only; module layer ownership is unchanged.

The forwarding surface in [forwarder.zig](/home/nick/repos/serval/serval-proxy/forwarder.zig):

| Function | Purpose |
|------|---------|
| `Forwarder.init(...)` | Initialize a forwarder with pool, tracer, DNS config, and TLS verification policy |
| `Forwarder.forward(...)` | Main HTTP request forwarding path |
| `Forwarder.forwardWebSocket(...)` | HTTP/1 upgrade forwarding followed by tunnel relay |
| `Forwarder.forwardGrpcH2c(...)` | Prior-knowledge cleartext h2 entry -> bounded h2 upstream bridge |
| `Forwarder.forwardGrpcH2cUpgrade(...)` | Inbound `Upgrade: h2c` entry -> bounded h2 upstream bridge |

## File Layout

| File | Purpose |
|------|---------|
| `mod.zig` | Public re-exports |
| `types.zig` | Shared proxy result/body/protocol types |
| `connect.zig` | Upstream connect helpers and local-port inspection |
| `forwarder.zig` | Main orchestration and protocol dispatch |
| `tunnel.zig` | Bidirectional tunnel relay for upgraded connections |
| `h1/mod.zig` | HTTP/1 forwarding exports |
| `h1/request.zig` | HTTP/1 request serialization and send helpers |
| `h1/response.zig` | HTTP/1 response header/body forwarding |
| `h1/body.zig` | Fixed-length request/response body forwarding |
| `h1/chunked.zig` | Bounded chunked transfer forwarding |
| `h1/websocket.zig` | HTTP/1 WebSocket upgrade request/response forwarding |
| `h2/mod.zig` | HTTP/2 bridge exports |
| `h2/bindings.zig` | Fixed-capacity downstream/upstream stream binding table |
| `h2/bridge.zig` | Current stream-aware h2 bridge over `serval-client` upstream sessions |

## Current Scope

### HTTP/1 forwarding

The production-complete path today is the traditional HTTP/1 forwarding path:

- upstream connect/reuse through `serval-pool`
- request serialization through `serval-client`-shared request helpers
- response header parsing and body forwarding
- bounded chunked transfer forwarding
- splice-based zero-copy body forwarding when plaintext/raw-fd paths permit it
- userspace-copy fallback when zero-copy is not possible

### WebSocket upgrade and tunnel relay

`serval-proxy` owns the HTTP/1 upgrade forwarding path and the post-upgrade
tunnel relay:

- validates and forwards the upgrade handshake
- relays bytes bidirectionally after `101 Switching Protocols`
- closes upgraded connections instead of returning them to the HTTP pool
- treats reset/closed-peer tunnel write termination as an explicit peer-closed
  outcome, not as an internal assertion failure
- emits route-scoped WebSocket upgrade diagnostics plus side-aware tunnel
  closure/failure logs so long-lived relay paths can be compared against other
  reverse proxies during field debugging
- emits focused RFC 6455 request/response header diagnostics for upgraded proxy
  paths, including subprotocol/extension negotiation without dumping raw
  `Sec-WebSocket-Key` or accept-key secrets
- emits byte-count and duration summaries on tunnel close/failure paths so
  upgraded relay sessions can be compared at the first post-`101` traffic phase
- runs the downstream client reader as a real concurrent task in threaded
  runtimes instead of relying only on opportunistic `Group.async()` execution
- distinguishes TLS read `WantRead` vs `WantWrite` in the upgraded tunnel so
  downstream TLS backpressure waits on the correct readiness condition
- maps plain-socket upgraded-tunnel write resets (`BrokenPipe`,
  `ConnectionResetByPeer`) to peer-closed termination instead of collapsing
  them into generic internal transport errors
- logs exact plain upgraded-tunnel write/flush error names before falling back
  to generic `client_error` / `upstream_error` classification

The tunnel implementation is shared by upgraded proxy paths, including the
non-stream-aware h2 WebSocket upgrade case.

#### NetBird relay note

The Android NetBird relay regression reproduced in March 2026 was not an HTTP
upgrade bug. The failing shape was:

- `101 Switching Protocols` succeeded
- the first post-upgrade relay exchange (`91` bytes downstream-to-upstream,
  `35` bytes upstream-to-downstream) succeeded
- then the downstream TLS side stopped forwarding follow-up frames, so the
  relay backend closed after its idle window

The root cause was the combination of:

- using `std.Io.Group.async()` for the long-lived downstream relay reader
  instead of true concurrent work in threaded runtimes
- collapsing TLS `SSL_ERROR_WANT_READ` and `SSL_ERROR_WANT_WRITE` into one
  generic idle/backpressure bucket

The fix was to:

- run the downstream relay reader with `std.Io.Group.concurrent()` when
  available
- preserve `WantRead` vs `WantWrite` through `serval-tls` so the tunnel waits
  on the correct readiness condition
- replace the plain upgraded upstream relay write path with a direct bounded
  nonblocking `write(2)` loop instead of Zig's buffered stream writer on a
  nonblocking fd

This is an upgraded-tunnel transport issue, not a WebSocket handshake issue.

#### gRPC prior-knowledge h2 -> TLS h2 tunnel startup note (integration 34)

A separate regression (integration test `34/98`) showed a startup deadlock in
raw gRPC h2 prior-knowledge tunnel mode when forwarding to a TLS h2 upstream.

Failing shape:

- downstream client sent the full prior-knowledge+h2 unary request preface
- upstream TLS handshake completed successfully
- no upstream application data was observed after handshake
- tunnel then stalled until downstream timeout

Root cause:

- relay startup order let the foreground path block on upstream read before the
  downstream initial bytes were guaranteed to be flushed upstream

Fix:

- move tunnel relay to an explicit fiber state machine with phases:
  `startup` -> `steady_state` -> `closing`
- both directions now follow the same startup contract:
  flush initial bytes, mark startup complete, then wait for both sides before
  entering steady-state forwarding
- keep one direction attached via `std.Io.Group.concurrent()` and the other on
  the current fiber, but with symmetric startup gating (no directional startup
  race)
- keep plain-socket relay I/O fiber-safe (`io.vtable.netRead/netWrite`) and TLS
  relay I/O on the socket/TLS path

Outcome:

- integration `34/98` no longer stalls after upstream TLS handshake
- startup behavior is explicit and testable, and steady-state relay remains
  bidirectional until close/error/cancel

### HTTP/2 / gRPC forwarding

The current h2 implementation is intentionally bounded and focused:

- downstream entry supports TLS ALPN `h2`, cleartext prior knowledge, and
  inbound `Upgrade: h2c`
- upstream support currently covers both cleartext `.h2c` and TLS `.h2`
- the active stream-aware bridge is gRPC-focused
- downstream streams are mapped to upstream stream ids through a fixed-capacity
  binding table
- the raw `Upgrade: h2c` fallback path uses a local `64 KiB` DATA-frame chunk
  buffer in [forwarder.zig](/home/nick/repos/serval/serval-proxy/forwarder.zig);
  configured H2 frame sizes may be larger, but this path will emit multiple
  smaller DATA frames rather than requiring a larger local scratch buffer
- raw gRPC h2 tunnel relay now takes deploy-time `Config.h2` runtime policy for
  idle timeout and outbound DATA frame sizing, but the proxy forwarder still
  enforces its own bounded internal frame capacity (`64 KiB`) for that raw
  upgrade/tunnel path
- upstream receive events are converted into explicit actions for downstream
  response headers, DATA, trailers, resets, or connection-close handling
- upstream GOAWAY handling is session-generation-aware and respects
  `last_stream_id`

This is enough for the current gRPC-over-HTTP/2 proxy path, but it is not yet a
generic “all HTTP/2 traffic” forwarding stack.

## Known Boundaries

`serval-proxy` does not currently provide:

- a fully generic stream-aware h2 proxy for arbitrary HTTP/2 request/response
  traffic
- full end-to-end generic h2-to-h2 proxying outside the current gRPC-focused
  path
- route selection or balancing policy
- HTTP/2 framing ownership outside the bridge/helper integration already
  provided by `serval-h2` and `serval-client`

When adding new behavior, keep strategy in layer 4 and keep protocol mechanics
here.

## Result and Error Model

### `ForwardResult`

`ForwardResult` captures outcome metadata for request forwarding, including:

- `status`
- `response_bytes`
- `connection_reused`
- timing fields such as DNS, connect, send, receive, and pool wait durations
- `upstream_local_port`

This struct is used for access logging, metrics, and request-level observability
without forcing callers to parse protocol-specific internals.

### `ForwardError`

`ForwardError` is the bounded error set returned by forward operations for
transport/protocol failures such as:

- connect failure
- invalid upstream address
- send/receive failure
- stale pooled connection
- invalid or oversized response headers
- splice/forwarding failure

Keep additions explicit and protocol-mechanical. Do not overload this set with
strategy or policy failures.

## Dependencies

- `serval-core` for shared config/types/logging
- `serval-net` for socket and DNS abstraction
- `serval-pool` for connection reuse
- `serval-client` for upstream client/session primitives
- `serval-http` for HTTP/1 parsing
- `serval-h2` for h2 framing/state helpers
- `serval-grpc` for gRPC request/response validation helpers
- `serval-websocket` for RFC 6455 handshake helpers
- `serval-tls` for upstream and client-side TLS
- `serval-tracing` for tracing integration

## Developer Notes

- Treat `Forwarder` as the orchestration surface. New forwarding features should
  usually extend existing protocol-specific helpers rather than add a second
  top-level orchestrator.
- Keep loops bounded and cleanup explicit. The tunnel and h2 bridge paths are
  long-lived and must fail closed on protocol confusion or connection loss.
- Do not widen the current h2 scope in documentation unless the generic
  stream-aware path is actually implemented and tested.
- Pooling and session reuse are part of the mechanics contract here; upgraded
  and tunneled connections must not be silently returned to the plain HTTP pool.

## Implementation Status

| Capability | Status |
|------|---------|
| HTTP/1 upstream forwarding | Complete |
| Connection pooling / stale retry | Complete |
| Plaintext zero-copy splice path | Complete |
| TLS/userspace-copy fallback | Complete |
| WebSocket HTTP/1 upgrade forwarding | Complete |
| Bidirectional upgraded tunnel relay | Complete |
| gRPC over HTTP/2 proxying | In progress, with stream-aware bridge active for downstream TLS ALPN `h2`, cleartext prior-knowledge, and cleartext `Upgrade: h2c` entry paths, plus upstream support for both `.h2c` and TLS `.h2` |
| Generic stream-aware HTTP/2 proxying | In progress |

## TigerStyle Notes

- fixed-capacity binding tables instead of unbounded maps
- explicit termination enums for tunnel shutdown
- bounded retries for splice/body forwarding
- no hidden protocol fallback in the gRPC h2 bridge path
- cleanup-first handling for stale pooled or upgraded connections
