## Why

`serval-grpc` is architecturally clean and correctly scoped, but current validation is intentionally minimal. To improve production hardening for gRPC-over-HTTP/2 proxy/server paths, we need stronger protocol validation, better stream-framing helpers, and more exhaustive test coverage while preserving strict module boundaries.

## What Changes

- Strengthen `grpc-status` validation from "numeric string" to explicit parse + bounded semantic validation.
- Add strict metadata validation mode for hardened deployments while preserving current compatibility behavior.
- Add bounded streaming frame-scan helpers for incremental gRPC message processing.
- Add explicit request classification helpers to reduce duplicated policy logic in `serval-server` and `serval-proxy`.
- Expand tests: boundary, malformed grammar, fuzz/property behavior, and integration matrix extensions.
- Align architecture/docs with actual module dependencies and contracts.

## Capabilities

### New Capabilities
- `grpc-status-semantics`: Parse and validate `grpc-status` with explicit format/range errors.
- `grpc-metadata-strict-validation`: Optional strict request/response metadata validation profile.
- `grpc-wire-frame-scan`: Allocation-free helpers for scanning multiple framed gRPC messages in a bounded byte slice.
- `grpc-request-classification`: Centralized classification helper for gRPC/non-gRPC stream policy.

### Modified Capabilities
- `grpc-metadata-validation` (existing): extend rules and error taxonomy.
- `grpc-wire-envelope` (existing): add incremental scanning APIs in addition to existing prefix/message helpers.

## Impact

- Affected modules:
  - `serval-grpc` (primary)
  - `serval-server` (request-class/completion policy integration updates)
  - `serval-proxy` (classification + stricter error mapping)
- Affected docs:
  - `serval-grpc/README.md`
  - `serval/ARCHITECTURE.md`
  - root `README.md` section for gRPC behavior (if needed)
- No ownership/layer change: `serval-grpc` remains Layer 2 helper module without transport runtime ownership.
