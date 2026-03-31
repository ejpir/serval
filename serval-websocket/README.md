# serval-websocket

RFC 6455 WebSocket protocol helpers for Serval.

## Layer

Layer 1 (Protocol).

This module owns protocol parsing/validation only. It does not own sockets,
proxy tunnels, native session state, or the HTTP server accept loop.

## Purpose

`serval-websocket` centralizes the RFC 6455 rules that both proxy and native
server paths need:

- HTTP upgrade detection and validation
- `Sec-WebSocket-Accept` generation
- upstream `101 Switching Protocols` validation
- frame header parse/encode
- masking helpers
- close-code / close-payload validation
- subprotocol token and selection validation

Current users:

- `serval-proxy` for HTTP/1.1 upgrade forwarding and response validation
- `serval-server` for native websocket endpoint support

## Public Exports

| Symbol | Description |
|--------|-------------|
| `HandshakeError` | Client/server handshake validation errors |
| `max_control_payload_size_bytes` | RFC 6455 control-frame payload limit |
| `websocket_accept_guid` | RFC 6455 GUID constant |
| `websocket_client_nonce_size_bytes` | Client nonce size |
| `websocket_accept_key_size_bytes` | Base64 accept-key size |
| `looksLikeWebSocketUpgradeRequest(request)` | Broad upgrade detection helper |
| `validateClientRequest(request, body_framing)` | Strict client upgrade validation |
| `computeAcceptKey(client_key, out)` | Compute `Sec-WebSocket-Accept` |
| `validateServerResponse(status, raw_headers, expected_accept_key)` | Validate upstream `101` response |
| `headerHasToken(value, token)` | Comma-token lookup helper for a header value |
| `getHeaderValue(raw_headers, name)` | Raw header lookup helper |
| `PeerRole` | Client/server frame parsing role |
| `Opcode` | WebSocket opcode enum |
| `FrameHeader` | Parsed inbound frame header |
| `OutboundFrameHeader` | Encoded outbound frame header description |
| `FrameError` | Frame-parse / frame-validation errors |
| `max_frame_header_size_bytes` | Maximum frame header size |
| `parseFrameHeader(raw, role)` | Parse frame header |
| `buildFrameHeader(out, header)` | Encode frame header |
| `applyFrameMask(payload, mask_key)` | Mask/unmask payload in place |
| `isControlOpcode(opcode)` | Check control opcode class |
| `CloseInfo` | Decoded close-payload result |
| `CloseError` | Close-code / payload validation errors |
| `validateCloseCode(code)` | Validate close code |
| `parseClosePayload(payload)` | Decode close payload |
| `buildClosePayload(out, code, reason)` | Encode close payload |
| `SubprotocolError` | Subprotocol validation errors |
| `validateSubprotocolHeaderValue(value)` | Validate offered protocol list |
| `headerOffersSubprotocol(offered, candidate)` | Check if header offered a protocol |
| `validateSubprotocolSelection(offered, selected)` | Ensure selected protocol was offered |
| `isSubprotocolToken(value)` | Validate token syntax |

## File Layout

| File | Purpose |
|------|---------|
| `mod.zig` | Public API re-exports |
| `limits.zig` | Owner-local protocol payload limits |
| `handshake.zig` | Upgrade request/response validation helpers |
| `frame.zig` | Frame header parse/encode + masking helpers |
| `close.zig` | Close-code and close-payload validation |
| `subprotocol.zig` | Subprotocol token/selection validation |

## Developer-Facing Scope

### Handshake helpers

`handshake.zig` is responsible for HTTP-layer protocol checks only:

- broad upgrade detection via `looksLikeWebSocketUpgradeRequest()`
- strict request validation via `validateClientRequest()`
- accept-key generation via `computeAcceptKey()`
- upstream `101` validation via `validateServerResponse()`

This separation is intentional:

- server/proxy code can detect "maybe websocket" early
- then switch to strict RFC validation before accepting/upgrading

### Frame helpers

`frame.zig` provides bounded frame-header parsing and encoding only.
`parseFrameHeader` expects header-only input bytes (2-14 bytes), not payload bytes.
It does not own:

- fragmentation reassembly
- per-session state machines
- ping/pong policy
- tunnel loops

Those belong in higher layers.

### Close helpers

`close.zig` validates:

- legal close codes
- UTF-8 / reason payload structure
- close-payload encode/decode

This lets both proxy and native endpoint paths fail closed on invalid closes.

### Subprotocol helpers

`subprotocol.zig` enforces:

- valid token syntax in offered lists
- that the selected protocol was actually offered

## Example

```zig
const websocket = @import("serval-websocket");

if (websocket.looksLikeWebSocketUpgradeRequest(&request)) {
    try websocket.validateClientRequest(&request, parser.body_framing);

    var accept_buf: [websocket.websocket_accept_key_size_bytes]u8 = undefined;
    const client_key = request.headers.get("Sec-WebSocket-Key").?;
    const expected_accept = try websocket.computeAcceptKey(client_key, &accept_buf);

    try websocket.validateServerResponse(101, raw_headers, expected_accept);
}
```

## Scope Boundaries

### In this module

- RFC 6455 handshake rules
- frame-header parse/encode
- masking helpers
- close validation
- subprotocol validation

### Not in this module

- proxy relay loops
- native websocket session lifecycle
- socket ownership
- accept loop orchestration
- stream/tunnel timeout policy

## Developer Notes

- If a change is about HTTP upgrade and RFC 6455 syntax, it belongs here.
- If a change is about long-lived I/O, timeouts, or cancellation, it belongs in
  `serval-proxy` or `serval-server`.
- Keep this module allocation-free and reusable by both proxy and native paths.

## Implementation Status

| Feature | Status |
|---------|--------|
| Client handshake validation | Complete |
| Accept key generation | Complete |
| Upstream `101` validation | Complete |
| Frame header parsing/encoding | Complete |
| Masking helpers | Complete |
| Close payload/code validation | Complete |
| Subprotocol validation | Complete |
| Proxy/session ownership | Not implemented here by design |

## TigerStyle Compliance

- Zero allocation helpers
- Fixed-size stack outputs
- Explicit bounded parsing loops
- Precondition/postcondition assertions
- Strict separation from transport/session ownership
- Table-driven grammar checks and bounded fuzz-style parser tests
