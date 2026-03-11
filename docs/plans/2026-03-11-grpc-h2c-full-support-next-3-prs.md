# gRPC h2c Full-Support Next 3 PRs

## Goal

Close the remaining gap from "stream-aware working" to production-grade gRPC/h2c semantics.

## PR1 — gRPC completion semantics (implemented in this changeset)

### Scope
- Enforce mandatory gRPC completion metadata (`grpc-status`) on proxied responses.
- Apply to both:
  - prior-knowledge h2c entry
  - `Upgrade: h2c` entry
- Fail closed with downstream `RST_STREAM(PROTOCOL_ERROR)` when status is missing/invalid.

### Files
- `serval-grpc/metadata.zig`
- `serval-server/h1/server.zig`
- `serval-server/h2/server.zig`
- `integration/tests.zig`

### Acceptance
- Integration coverage for prior-knowledge and upgrade missing-`grpc-status` cases.

## PR2 — GOAWAY `last_stream_id` policy (initial slice implemented)

### Scope
- Track and honor upstream `GOAWAY.last_stream_id` per active upstream session.
- Drain/allow unaffected streams where valid.
- Fail-close only streams that are definitely beyond `last_stream_id` or cannot complete safely.

### Acceptance
- Integration tests for mixed affected/unaffected streams on one connection.
- Explicit assertions for stream-id ordering invariants.

### Current status
- `GOAWAY(NO_ERROR,last_stream_id>=active_stream)` now keeps that active stream running in both prior-knowledge and upgraded h2c paths.
- Integration coverage added:
  - `grpc h2c upstream goaway with last_stream_id keeps active stream`
  - `grpc h2c upgrade upstream goaway with last_stream_id keeps active stream`
  - `grpc h2c goaway last_stream_id resets higher stream and keeps lower stream`
- Bridge mapping is now upstream-index-aware for response stream-id lookups.
- Session reconnect policy now defers GOAWAY-driven reconnect while active streams remain.
- Upstream session pool now supports bounded rollover (one active + one draining session per upstream index) and session-generation-aware bridge bindings.

## PR3 — Full header/framing interoperability (initial slice implemented)

### Scope
- Implement CONTINUATION reassembly and bounded handling.
- Expand HPACK decode support (indexed names/fields, bounded dynamic table, Huffman decode).
- Keep fixed-capacity tables and deterministic rejection paths.

### Acceptance
- Unit/property tests for HPACK and continuation sequencing.
- Interop tests against grpc-go/grpcurl header patterns.

### Current status
- Added bounded HEADERS+CONTINUATION reassembly in:
  - `serval-h2/request.zig` (prior-knowledge initial request parse)
  - `serval-server/h2/runtime.zig` (inbound request headers)
  - `serval-client/h2/runtime.zig` (upstream response headers/trailers)
- Added bounded HPACK decode support for:
  - static-table and dynamic-table indexed header fields
  - indexed header names for literal fields
  - dynamic-table size update parsing with bounded eviction
  - Huffman string decoding with explicit invalid-padding rejection
- Integration coverage added for:
  - proxied response HEADERS/trailers split across CONTINUATION
  - upstream Huffman-coded response headers plus dynamic-table indexed trailer fields
  - grpc-go/grpcurl style metadata headers on proxied unary requests
  - binary `*-bin` metadata header forwarding to upstream
  - trailers-only gRPC completion (`grpc-status` on END_STREAM HEADERS)
  - many-stream churn on one proxied h2c connection (stress-oriented stream lifecycle coverage)
  - higher fan-out churn near concurrent-stream limits
  - process-level grpcurl plaintext interop test against prior-knowledge h2c proxy path
  - process-level grpcurl unary metadata/trailer assertions via verbose output (`-v`) plus backend-validated request metadata forwarding
  - process-level grpcurl unary metadata/trailer churn loop (repeated invocations) to stress session reuse/rollover under external client interop
  - process-level grpc-go client interop tests (`go run` + grpc-go) for unary and server-streaming against prior-knowledge h2c proxy path
  - process-level grpc-go unary metadata/trailer assertions (`grpc.Header`/`grpc.Trailer`) including request metadata forwarding checks
  - process-level grpc-go server-streaming metadata/trailer assertions (`Header()`, `Trailer()`) including request metadata forwarding checks
  - process-level grpc-go unary metadata/trailer churn loop (repeated invocations) for external interop stress
  - process-level grpc-go server-streaming metadata/trailer churn loop (repeated invocations) for external interop stress
  - prior-knowledge handshake interop where proxy emits server SETTINGS before waiting for first HEADERS (grpcurl/grpc-go compatibility)
  - graceful GOAWAY rollover path where next downstream stream opens a fresh upstream session
  - upgraded h2c server-streaming path with multiple DATA frames
- Additional malformed-path coverage added for:
  - cross-block HPACK dynamic-table shrink/regrow update sequences
  - multiple dynamic-table size updates before first header field
  - CONTINUATION invalid-flag permutations across request parser, server runtime, and client runtime

## Exit Criteria (after PR1..PR3)

- gRPC unary/streaming over h2c works for prior-knowledge and upgrade entry.
- Required gRPC metadata (`grpc-status`) enforced fail-closed.
- GOAWAY handling is stream-aware (`last_stream_id` respected).
- Header decoding supports real-world gRPC/HPACK patterns without tunnel fallback.

## Remaining Work for “Full gRPC h2c”

These items are still required for production-confidence “full support”:

- Harden malformed/corpus coverage further:
  - additional HPACK negative-path and cross-block dynamic-table update sequences
  - additional CONTINUATION protocol-violation permutations
- Expand external interop matrix (process-level grpc-go/grpcurl) beyond current coverage: add richer RPC shapes (e.g. bidi/client-streaming where applicable), connection-reuse-focused scenarios, and longer-duration soak loops.
- Expand stress/soak matrix near configured limits (`H2_MAX_CONCURRENT_STREAMS`, long churn runs).
- Keep PR hygiene strict: isolate stream-aware h2c work from unrelated workspace changes before merge.
