# serval-websocket

WebSocket protocol helpers for serval.

## Layer

Layer 1 (Protocol).

## Purpose

Provides RFC 6455 protocol primitives without owning sockets, connections, or
server state.

Current scope:
- detect likely WebSocket upgrade requests
- validate client handshake headers
- compute `Sec-WebSocket-Accept`
- validate upstream `101 Switching Protocols` responses
- parse and encode frame headers
- apply/remove masking
- validate close payloads and close codes
- validate subprotocol token lists and selections

Tunneling lives in `serval-proxy`. Native endpoint/session lifecycle lives in `serval-server`.

## Exports

| Symbol | Description |
|--------|-------------|
| `HandshakeError` | Client/server handshake validation errors |
| `FrameError` | Frame header validation errors |
| `CloseError` | Close-code / close-payload validation errors |
| `SubprotocolError` | Subprotocol token/selection validation errors |
| `looksLikeWebSocketUpgradeRequest(request)` | Broad detection for fail-closed handling |
| `validateClientRequest(request, body_framing)` | Strict RFC 6455 client request validation |
| `computeAcceptKey(client_key, out)` | Compute `Sec-WebSocket-Accept` |
| `validateServerResponse(status, raw_headers, expected_accept_key)` | Validate upstream `101` response |
| `parseFrameHeader(raw, role)` | Parse RFC 6455 frame header |
| `buildFrameHeader(out, header)` | Encode RFC 6455 frame header |
| `applyFrameMask(payload, mask_key)` | Mask/unmask frame payload in place |
| `parseClosePayload(payload)` | Validate and decode close payload |
| `buildClosePayload(out, code, reason)` | Encode close payload |
| `validateSubprotocolSelection(offered, selected)` | Ensure selected subprotocol was offered by client |

## Scope Boundaries

### In this module
- WebSocket HTTP upgrade semantics
- Frame header parse/encode
- Masking helpers
- Close validation
- Subprotocol parsing/validation

### Not in this module
- Socket ownership
- Proxy relay loops
- Native server session lifecycle
- Handler callbacks
- Accept loop orchestration

## Usage

```zig
const websocket = @import("serval-websocket");

if (websocket.looksLikeWebSocketUpgradeRequest(&request)) {
    try websocket.validateClientRequest(&request, parser.body_framing);

    var accept_buf: [websocket.websocket_accept_key_size_bytes]u8 = undefined;
    const key = request.headers.get("Sec-WebSocket-Key").?;
    const accept = try websocket.computeAcceptKey(key, &accept_buf);

    try websocket.validateServerResponse(101, raw_headers, accept);
}
```

## Implementation Status

| Feature | Status |
|---------|--------|
| Client handshake validation | Complete |
| Accept key generation | Complete |
| Upstream `101` validation | Complete |
| Frame header parsing/encoding | Complete |
| Close payload/code validation | Complete |
| Subprotocol validation | Complete |
| Proxy/session ownership | Not implemented here by design |

## TigerStyle Compliance

- Zero allocation
- Fixed-size stack buffers
- Explicit bounded parsing loops
- Assertions on preconditions and postconditions
- Clear separation from server/proxy ownership concerns
