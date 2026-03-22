# serval-h2

Bounded HTTP/2 protocol helpers for Serval.

## Layer

Layer 1 (Protocol).

`serval-h2` owns protocol parsing, encoding, and state-machine primitives. It
does not own socket lifecycles, accept loops, or the full server/proxy runtime.

## Purpose

This module is the shared protocol toolbox for:

- server-side HTTP/2 ingress
- outbound HTTP/2 client/session code
- h2c upgrade handling
- stream-aware proxy transport

Current responsibilities:

- frame header parsing/encoding
- client connection preface detection
- SETTINGS parsing/encoding/validation/application
- control-frame parsing/encoding for ACK, PING, WINDOW_UPDATE, RST_STREAM, GOAWAY
- bounded HPACK decoding and bounded header-block encoding helpers
- Huffman string decoding used by HPACK
- request-header decoding with RFC 9113 validation
- explicit stream state transitions and fixed-capacity stream tables
- flow-control window primitives
- `Upgrade: h2c` detection, validation, and preamble generation
- initial-request parsing for prior-knowledge routing/bootstrap

## Public Exports

### Framing and Preface

| Symbol | Description |
|--------|-------------|
| `FrameType` | HTTP/2 frame type enum |
| `FrameHeader` | Parsed/encoded frame header |
| `FrameError` | Frame-parse errors |
| `parseFrameHeader(raw)` | Parse frame header |
| `buildFrameHeader(out, header)` | Encode frame header |
| `frame_header_size_bytes` | Header size constant |
| `flags_end_stream`, `flags_ack`, `flags_end_headers`, `flags_padded`, `flags_priority` | Common frame flags |
| `client_connection_preface` | RFC 9113 client preface bytes |
| `looksLikeClientConnectionPreface(raw)` | Full preface detection |
| `looksLikeClientConnectionPrefacePrefix(raw)` | Prefix detection |

### HPACK

| Symbol | Description |
|--------|-------------|
| `HeaderField` | HPACK header field |
| `HpackDecoder` | Bounded decoder with dynamic-table state |
| `HpackError` | HPACK decode/encode errors |
| `decodeHeaderBlock(raw)` | Decode using fresh decoder |
| `decodeHeaderBlockWithDecoder(decoder, raw)` | Decode using caller-owned decoder |
| `encodeLiteralHeaderWithoutIndexing(...)` | Bounded literal encode helper |
| `encodeLiteralHeaderWithIncrementalIndexing(...)` | Bounded literal + index encode helper |
| `encodeIndexedHeaderField(...)` | Encode indexed field |

### SETTINGS and Control Frames

| Symbol | Description |
|--------|-------------|
| `SettingId`, `Setting`, `Settings`, `SettingsError` | SETTINGS types/errors |
| `parseSettingsFrame`, `validateSettingsFrame`, `parseSettingsPayload`, `buildSettingsPayload`, `applySettings` | SETTINGS helpers |
| `ErrorCode`, `GoAway`, `ControlError` | Control-frame types/errors |
| `buildSettingsAckFrame` | Encode SETTINGS ACK |
| `parsePingFrame`, `buildPingFrame` | PING helpers |
| `parseWindowUpdateFrame`, `buildWindowUpdateFrame` | WINDOW_UPDATE helpers |
| `parseRstStreamFrame`, `buildRstStreamFrame` | RST_STREAM helpers |
| `parseGoAwayFrame`, `buildGoAwayFrame` | GOAWAY helpers |

### Flow Control and Streams

| Symbol | Description |
|--------|-------------|
| `FlowControlError` | Flow-control primitive errors |
| `Window` | Per-window bookkeeping |
| `ConnectionFlowControl` | Connection-level flow-control bookkeeping |
| `StreamRole`, `StreamState`, `H2Stream`, `StreamTable`, `StreamError` | Stream state machine and fixed-capacity stream table |

### Request Decode / Upgrade

| Symbol | Description |
|--------|-------------|
| `RequestHead` | Decoded HTTP/2 request head |
| `InitialRequest` | Initial request + bootstrap parse result |
| `InitialRequestError` | Request/initial parse errors |
| `request_stable_storage_size_bytes` | Minimum caller-provided stable storage for decoded request strings |
| `decodeRequestHeaderBlock(header_block, stream_id, storage_out)` | Decode request header block into caller-owned stable storage |
| `decodeRequestHeaderBlockWithDecoder(decoder, header_block, stream_id, storage_out)` | Decode request block with caller-owned decoder and stable storage |
| `parseInitialRequest(input, storage_out)` | Parse initial request from prior-knowledge bytes into stable storage |
| `H2cUpgradeError` | h2c upgrade validation/build errors |
| `looksLikeUpgradeRequest(request)` | Detect HTTP/1.1 `Upgrade: h2c` |
| `validateUpgradeRequest(request)` | Strict upgrade request validation |
| `buildUpgradeResponse(out)` | Build `101 Switching Protocols` response |
| `buildPriorKnowledgePreambleFromUpgrade(...)` | Build upstream prior-knowledge preamble from upgrade request |
| `h2c_upgrade_response` | Static upgrade response bytes |

## File Layout

| File | Purpose |
|------|---------|
| `mod.zig` | Public API re-exports |
| `frame.zig` | Frame header parsing/encoding |
| `preface.zig` | Client preface detection |
| `settings.zig` | SETTINGS helpers |
| `control.zig` | ACK/PING/WINDOW_UPDATE/RST_STREAM/GOAWAY helpers |
| `flow_control.zig` | Window bookkeeping primitives |
| `stream.zig` | Stream state machine and table |
| `hpack.zig` | HPACK decode/encode helpers |
| `huffman.zig` | HPACK Huffman decoding helpers |
| `request.zig` | Request-head decode and initial request parsing |
| `upgrade.zig` | `Upgrade: h2c` detection/validation/build helpers |

## Current Protocol Scope

### Request decoding

`request.zig` now enforces the main correctness rules needed by server/client
runtimes:

- pseudo-header ordering
- duplicate pseudo-header rejection
- CONNECT constraints
- Extended CONNECT (`:protocol`) acceptance for WebSocket-over-h2
- connection-specific header rejection
- `te=trailers` enforcement

### HPACK

HPACK support is bounded and explicit:

- dynamic-table decode state is supported
- bounded header-block decode is supported
- bounded literal/indexed field encoding helpers exist
- this is not a general-purpose compression tuning module

### Upgrade and prior-knowledge bootstrap

`upgrade.zig` and `request.zig` provide the protocol glue needed by higher
layers to:

- accept and validate `Upgrade: h2c`
- parse prior-knowledge h2 connections
- translate upgrade requests into upstream prior-knowledge preambles

### Flow control and stream state

`flow_control.zig` and `stream.zig` provide primitives used by higher runtimes.
They are not, by themselves, a complete multiplexed connection runtime.

## Scope Boundaries

### In this module

- RFC 9113 / h2c protocol primitives
- HPACK decode/encode helpers
- stream state and flow-control primitives
- request-head validation
- upgrade bootstrap helpers

### Not in this module

- socket ownership
- accept loops
- complete server runtime ownership
- complete outbound session ownership
- proxy stream binding tables

Those live in:

- `serval-server/h2`
- `serval-client/h2`
- `serval-proxy/h2`

## Developer Notes

- If a feature is pure HTTP/2 protocol logic and reusable by both client and
  server runtimes, it belongs here.
- If a feature needs connection/task ownership, it likely belongs in
  `serval-server`, `serval-client`, or `serval-proxy`.
- Keep unsupported features fail-closed rather than partially permissive.
- Keep all structures bounded and fixed-capacity.
- For request decoding APIs, provide `storage_out` with at least
  `request_stable_storage_size_bytes` so returned header/path slices remain
  valid after decode returns.
- Property/fuzz-style coverage now includes deterministic corpora for
  `frame.zig`, `settings.zig`, `request.zig`, and `stream.zig` in addition to
  existing HPACK-focused fuzz/property tests.

## Current Status

What is complete here:

- bounded HTTP/2 framing helpers
- bounded SETTINGS/control-frame helpers
- bounded HPACK decode + helper encoding
- bounded request-head validation (including bounded HEADERS+CONTINUATION assembly and fail-closed pseudo-header/TE validation)
- stream/flow-control primitives
- h2c upgrade bootstrap helpers

How these primitives are currently used in the stack:

- prior-knowledge bootstrap parsing (`parseInitialRequest`) for route selection and bridge handoff
- `Upgrade: h2c` validation + preamble generation for stream-aware bridge startup
- terminated h2 runtime/server paths in `serval-server/h2/*`
- outbound h2 session/runtime paths in `serval-client/h2/*`
- stream-aware bridge mechanics in `serval-proxy/h2/*`

What is still broader-work-in-progress in the stack:

- full generic stream-aware proxying for arbitrary (non-gRPC-specific) h2 traffic classes
- complete production-grade multiplexed runtime behavior across all traffic classes

## TigerStyle Compliance

- Explicit bounded parsing/encoding
- Fixed-capacity stream/state tables
- Fail-closed protocol validation
- No socket ownership in protocol layer
- Reusable primitives shared by client/server/proxy code
