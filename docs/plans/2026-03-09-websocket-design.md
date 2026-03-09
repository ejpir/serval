# WebSocket Proxying Design

Add RFC 6455 WebSocket proxy support to serval without violating the existing TigerStyle layering.

## Scope

This change implements **HTTP/1.1 WebSocket upgrade proxying/tunneling**:

- Detect `Upgrade: websocket` requests in `serval-server`
- Validate client handshake headers in a dedicated protocol module
- Forward the upgrade request through `serval-proxy`
- Validate upstream `101 Switching Protocols` response
- Switch from HTTP forwarding to raw bidirectional tunneling
- Never return upgraded upstream connections to the pool
- Add end-to-end integration tests

This change does **not** implement local WebSocket termination yet. That remains Phase 2.

## Module Placement

### New module: `serval-websocket`

Layer 1 (Protocol).

Responsibility:
- RFC 6455 handshake validation
- `Sec-WebSocket-Accept` generation
- Raw header token/header parsing helpers needed for handshake validation

Dependencies:
- `serval-core`
- `std`

Non-responsibilities:
- No socket ownership
- No server accept loop
- No proxy tunneling
- No local session state

### `serval-proxy`

Layer 3 (Mechanics).

Responsibility:
- Serialize WebSocket upgrade requests for upstreams
- Read and validate upstream upgrade responses
- Relay bytes bidirectionally after successful upgrade
- Close upgraded connections instead of pooling them

### `serval-server`

Layer 5 (Orchestration).

Responsibility:
- Detect WebSocket upgrade requests after HTTP parsing
- Fail closed on malformed upgrade requests
- Route valid upgrade requests into the proxy upgrade path
- Terminate the HTTP request loop after tunnel completion

## Files

### New

| File | Purpose |
|------|---------|
| `serval-websocket/mod.zig` | Public exports |
| `serval-websocket/handshake.zig` | RFC 6455 handshake validation + accept key generation |
| `serval-websocket/README.md` | Module documentation |
| `serval-proxy/tunnel.zig` | Bidirectional relay after successful upgrade |
| `serval-proxy/h1/websocket.zig` | HTTP/1.1 upgrade request/response handling |

### Modified

| File | Change |
|------|--------|
| `build.zig` | Register `serval-websocket` module and tests |
| `serval/mod.zig` | Re-export websocket module |
| `serval-core/config.zig` | Add WebSocket tunnel timeout/poll constants |
| `serval-proxy/mod.zig` | Export tunnel module transitively through tests |
| `serval-proxy/forwarder.zig` | Add `forwardWebSocket()` path |
| `serval-proxy/h1/mod.zig` | Export websocket helpers |
| `serval-server/h1/server.zig` | Detect upgrade requests and use websocket forwarding path |
| `serval-socket/socket.zig` | Expose pending-read check for TLS relay correctness |
| `serval-tls/ssl.zig` | Bind `SSL_pending()` |
| `integration/tests.zig` | Add end-to-end websocket proxy tests |
| `README.md`, `serval/ARCHITECTURE.md`, `serval-*/README.md` | Document module placement and support |

## Request Flow

### Normal HTTP request

Unchanged.

### WebSocket upgrade request

1. `serval-server` parses HTTP/1.1 request
2. `serval-server` checks if request looks like `Upgrade: websocket`
3. `serval-websocket.validateClientRequest()` validates:
   - `GET`
   - `Connection` contains `Upgrade`
   - `Upgrade: websocket`
   - valid `Sec-WebSocket-Key`
   - `Sec-WebSocket-Version: 13`
   - no HTTP message body framing
4. Handler selects upstream normally
5. `serval-proxy.forwardWebSocket()` sends a canonicalized upgrade request upstream
6. `serval-proxy` reads upstream response
7. If upstream returns non-`101`, forward it as plain HTTP and close the client connection
8. If upstream returns `101`, validate:
   - `Connection` contains `Upgrade`
   - `Upgrade: websocket`
   - `Sec-WebSocket-Accept` matches request key
9. After successful validation, switch to `serval-proxy.tunnel.relay()`
10. Tunnel relays bytes until close/timeout
11. Connection closes; upgraded upstream connection is not pooled

## Design Decisions

### Separate websocket request builder

`serval-client/request.zig` correctly strips hop-by-hop headers for normal HTTP proxying.
WebSocket upgrade requests intentionally need `Connection: Upgrade` and `Upgrade: websocket`.

Therefore the websocket path uses a dedicated request builder in `serval-proxy/h1/websocket.zig`.
The generic HTTP path remains unchanged.

### Validate before forwarding `101`

If an upstream sends an invalid `101`, the proxy must not pass it through. Otherwise
client and proxy state can diverge.

Invalid `101` responses return `ForwardError.InvalidResponse`, which results in `502 Bad Gateway`.

### No pooling after upgrade

HTTP pooling assumes request/response framing. After `101`, the connection becomes a raw
bidirectional byte stream and cannot safely return to the HTTP pool.

Upgraded connections are always released with `healthy=false`.

### Single-thread relay

The tunnel relay runs in a single thread/task so TLS socket reads and writes remain serialized
per socket. This avoids concurrent `SSL_read`/`SSL_write` access to the same `SSL*`.

### Idle timeout

TigerStyle requires bounded loops. Long-lived tunnel loops are bounded by an explicit idle timeout
plus finite poll intervals.

## Tests

### Unit tests

- handshake request validation
- invalid/missing websocket headers
- RFC sample `Sec-WebSocket-Accept`
- raw response header validation
- tunnel relay with socket pairs and pre-buffered data

### Integration tests

- proxy upgrades and relays a WebSocket frame end-to-end
- proxy forwards upstream `101` plus immediate post-upgrade bytes in the same write
- proxy closes upgraded connections instead of attempting keep-alive reuse implicitly

## Phase 2 (future)

Local WebSocket termination should live in `serval-server`, not `serval-core`.
The detailed Phase 2 native-endpoint plan now lives in:

- `docs/plans/2026-03-09-native-websocket-server-design.md`
