# serval-grpc

Bounded gRPC protocol helpers for Serval.

## Layer

Layer 2 (Infrastructure).

This module is transport-aware enough to validate gRPC-over-HTTP/2 semantics,
but it does not own sockets, connection lifecycles, protobuf schemas, or native
service dispatch.

## Purpose

`serval-grpc` exists to keep gRPC-specific wire and metadata rules out of the
generic HTTP/2 transport code while still letting server/proxy modules fail
closed on invalid gRPC traffic.

Current responsibilities:

- validate inbound gRPC request metadata
- validate outbound gRPC response/trailer metadata
- parse and build the 5-byte gRPC message envelope

Current users:

- `serval-server` h2 ingress paths
- `serval-proxy` stream-aware gRPC bridge paths

## Public Exports

| Symbol | Description |
|--------|-------------|
| `MessagePrefix` | Parsed 5-byte gRPC message envelope |
| `WireError` | Message-envelope parse/build errors |
| `parsePrefix(raw)` | Parse 5-byte prefix only |
| `buildMessage(out, compressed, payload)` | Build prefix + payload buffer |
| `parseMessage(raw)` | Validate and slice a full framed message |
| `MetadataError` | Request/trailer validation errors |
| `isGrpcContentType(value)` | Match `application/grpc`, `application/grpc+...`, and `application/grpc;...` |
| `validateRequest(request)` | Enforce gRPC request metadata requirements |
| `requireGrpcStatus(headers)` | Enforce numeric `grpc-status` presence |

## File Layout

| File | Purpose |
|------|---------|
| `mod.zig` | Public API re-exports |
| `metadata.zig` | HTTP/2 metadata validation helpers |
| `wire.zig` | gRPC message-envelope parsing/building |

## Current Protocol Rules

### Request validation

`validateRequest()` currently enforces:

- method must be `POST`
- request path must be non-empty
- `content-type` must be a gRPC content-type
- `te` must be exactly `trailers`

This is intentionally minimal and transport-safe. It does not try to interpret
protobuf payloads or application-level RPC semantics.

### Response / trailer validation

`requireGrpcStatus()` currently enforces:

- `grpc-status` must be present
- `grpc-status` must be numeric

This is used by stream-aware h2 proxying to fail closed when an upstream claims
to be gRPC but does not produce valid gRPC terminal metadata.

### Wire framing

`wire.zig` implements the fixed 5-byte gRPC message prefix:

- byte 0: compression flag (`0` or `1`)
- bytes 1-4: big-endian payload length

Length is bounded by `serval-core.config.GRPC_MAX_MESSAGE_SIZE_BYTES`.

## Example

```zig
const grpc = @import("serval-grpc");

try grpc.validateRequest(&request);

var envelope_buf: [1024]u8 = undefined;
const framed = try grpc.buildMessage(&envelope_buf, false, payload);
const body = try grpc.parseMessage(framed);

try grpc.requireGrpcStatus(&response.headers);
```

## Scope Boundaries

### In this module

- gRPC metadata validation
- gRPC wire-envelope parsing/building
- explicit fail-closed helpers for server/proxy code

### Not in this module

- protobuf schemas or code generation
- message compression codecs
- native gRPC server registration/dispatch
- reflection, health, or interceptors
- transport runtime ownership

## Developer Notes

- Keep this module allocation-free and transport-agnostic.
- Prefer adding narrowly-scoped validation helpers here instead of burying
  gRPC-specific rules inside `serval-server` or `serval-proxy`.
- If a new helper depends on generic HTTP/2 framing, it probably belongs in
  `serval-h2` instead.
- If a new helper depends on application-level RPC semantics, it probably does
  not belong here.

## Implementation Status

| Feature | Status |
|---------|--------|
| gRPC request metadata validation | Complete |
| `grpc-status` trailer/header validation | Complete |
| 5-byte envelope parsing/building | Complete |
| Native gRPC endpoint stack | Not implemented here by design |

## TigerStyle Compliance

- Fixed-size 5-byte wire prefix
- Explicit bounded length checks
- No socket or runtime ownership
- Fail-closed metadata validation
- No hidden allocations in hot protocol helpers
