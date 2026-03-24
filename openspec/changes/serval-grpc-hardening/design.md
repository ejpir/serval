## Context

Current `serval-grpc` provides:
- request metadata validation (`POST`, path, `content-type`, `te`)
- trailer/header `grpc-status` presence check
- bounded 5-byte envelope parse/build helpers

This is good baseline behavior, but production hardening requires stricter semantics and clearer policy primitives for stream-aware h2 bridging.

## Goals / Non-Goals

**Goals**
- Preserve strict module boundaries and allocation-free hot-path behavior.
- Increase protocol correctness and fail-closed behavior.
- Reduce duplicated or implicit gRPC policy logic in orchestration layers.
- Provide testable, explicit APIs for strict vs compatibility behavior.

**Non-Goals**
- Native gRPC service dispatch/registration.
- Protobuf schema/tooling integration.
- Compression codec implementations.
- Full gRPC application semantics beyond transport metadata/envelope rules.

## Decisions

### 1) Introduce explicit `grpc-status` parsing semantics

Add new helper(s):
- `parseGrpcStatus(headers: *const HeaderMap) Error!u8`
- `requireGrpcStatus(headers: *const HeaderMap) Error!void` (retained API, now semantic)

Error taxonomy:
- `MissingGrpcStatus`
- `InvalidGrpcStatusFormat`
- `InvalidGrpcStatusRange`

Validation:
- non-empty
- digits only
- bounded parse
- semantic range check (canonical gRPC status code range)

Rationale:
- Improves correctness and observability.
- Avoids downstream components interpreting malformed terminal state.

### 2) Add strict metadata validation profile

Keep existing compatibility path, add strict path:
- `validateRequest(request)` (compat baseline, retained)
- `validateRequestStrict(request)` (new)

Strict profile may enforce:
- tighter content-type grammar handling
- tighter TE semantics
- optional strict timeout/header format checks (bounded and explicit)

Rationale:
- Enables staged rollout without breaking existing integrations.

### 3) Add allocation-free frame scan helpers

Add wire helpers:
- `frameLength(raw)` / equivalent for quick prefix+payload length derivation
- bounded iterator/scanner over consecutive framed messages in a byte slice

Requirements:
- no allocation
- explicit NeedMoreData for truncation
- explicit errors for malformed frames
- bounded loop behavior only

Rationale:
- Reduces duplication and edge-case drift in stream bridge code.

### 4) Add request classification primitive

Expose:
- `classifyRequest(request) -> enum { grpc, non_grpc, invalid_grpc_like }`

Rationale:
- Centralizes detection policy in `serval-grpc`.
- Reduces ad-hoc checks in server/proxy.
- Supports request-class-aware completion behavior consistently.

### 5) Preserve fail-closed defaults and explicit mapping

For strict gRPC-class streams:
- invalid/missing terminal gRPC metadata remains fail-closed.
- error mapping in upper layers remains explicit (no catch-all suppression).

## Risks / Trade-offs

- [Compatibility regressions from stricter checks] -> Keep strict checks opt-in initially.
- [Operational confusion over status validation changes] -> Document new errors and mapping behavior.
- [Performance regression from additional checks] -> Keep checks branch-light, bounded, and allocation-free; benchmark hot paths.
- [Duplicate policy drift across modules] -> Centralize classification and status parse in `serval-grpc`.

## Migration Plan

1. Add new APIs and errors in `serval-grpc` while preserving existing call sites.
2. Update `serval-server` and `serval-proxy` to use new classification/status helpers.
3. Enable strict mode where appropriate behind explicit config/policy gates.
4. Expand tests and integration matrix.
5. Update architecture/module docs and usage guidance.

Rollback:
- Revert strict-path callsites to compatibility APIs.
- Keep enhanced parsing helpers as non-breaking library additions.

## Open Questions

- Should strict request validation be globally configured or per-listener/per-handler?
- Should non-canonical but numeric `grpc-status` be rejected always, or allowed under compatibility mode?
- Should strict mode validate additional gRPC headers (`grpc-message`, timeout format) in this slice or next slice?
