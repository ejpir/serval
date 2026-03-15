# serval-proxy

Mechanics-layer upstream forwarding for Serval.

`serval-proxy` owns how traffic is forwarded once a strategy layer has already
selected an upstream. That includes upstream connect/reuse, HTTP/1 request and
response forwarding, WebSocket upgrade/tunnel relay, and the current bounded
HTTP/2 stream bridge used for gRPC proxying.

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

The forwarding surface in [forwarder.zig](/home/nick/repos/serval/serval-proxy/forwarder.zig):

| Function | Purpose |
|------|---------|
| `Forwarder.init(...)` | Initialize a forwarder with pool, tracer, DNS config, and TLS verification policy |
| `Forwarder.forward(...)` | Main HTTP request forwarding path |
| `Forwarder.forwardWebSocket(...)` | HTTP/1 upgrade forwarding followed by tunnel relay |
| `Forwarder.forwardGrpcH2c(...)` | Prior-knowledge cleartext h2 frontend -> bounded h2 upstream bridge |
| `Forwarder.forwardGrpcH2cUpgrade(...)` | Inbound `Upgrade: h2c` frontend -> bounded h2 upstream bridge |

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

The tunnel implementation is shared by upgraded proxy paths, including the
non-stream-aware h2 WebSocket upgrade case.

### HTTP/2 / gRPC forwarding

The current h2 implementation is intentionally bounded and focused:

- cleartext frontend entry supports both prior knowledge and inbound
  `Upgrade: h2c`
- upstream support currently covers both cleartext `.h2c` and TLS `.h2`
- the active stream-aware bridge is gRPC-focused
- downstream streams are mapped to upstream stream ids through a fixed-capacity
  binding table
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
| gRPC over HTTP/2 proxying | In progress, with stream-aware bridge active for cleartext frontend entry paths and upstream support for both `.h2c` and TLS `.h2` |
| Generic stream-aware HTTP/2 proxying | In progress |

## TigerStyle Notes

- fixed-capacity binding tables instead of unbounded maps
- explicit termination enums for tunnel shutdown
- bounded retries for splice/body forwarding
- no hidden protocol fallback in the gRPC h2 bridge path
- cleanup-first handling for stale pooled or upgraded connections
