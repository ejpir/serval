# gRPC over h2c Design

Add production-grade gRPC support to serval by introducing cleartext HTTP/2 (`h2c`) in the correct layers, following RFCs and TigerStyle/TigerBeetle principles.

## Goal

Serval should be able to:

1. accept inbound `h2c` connections
2. proxy gRPC traffic to `h2c` upstreams without violating gRPC semantics
3. preserve headers, DATA frames, flow control, and trailers correctly
4. later expose a native gRPC endpoint API without coupling transport details into `serval-core`

The implementation must be:
- RFC-compliant
- explicitly bounded
- allocation-free on the hot path after init
- composable with existing serval routing/proxy modules
- testable with deterministic unit, integration, fuzz, and interop coverage

## Specifications

The implementation must follow these documents directly:

### HTTP/2 / h2c
- RFC 9113 — HTTP/2
  - connection preface
  - SETTINGS synchronization
  - HEADERS / CONTINUATION rules
  - flow control
  - stream lifecycle
  - GOAWAY / RST_STREAM behavior
- RFC 9110 — HTTP Semantics
  - pseudo-header mapping to request semantics
  - status and header handling

### gRPC
- gRPC over HTTP/2 protocol
  - `:method = POST`
  - `content-type = application/grpc` (or `application/grpc+proto`, etc.)
  - `te = trailers`
  - length-prefixed messages: 1 byte compression flag + 4 byte big-endian message length
  - `grpc-status` in trailers
  - optional `grpc-message`, `grpc-status-details-bin`, `grpc-timeout`
- gRPC health checking protocol for interoperability tests

## Scope

### Phase 1 scope

The first production slice should deliver:
- inbound cleartext HTTP/2 prior-knowledge support
- inbound `Upgrade: h2c` support on the server side
- outbound `h2c` prior-knowledge connections to upstreams
- gRPC proxy pass-through for unary and streaming calls
- trailers preservation and validation
- end-to-end interoperability with `grpcurl` and a reference Go gRPC server

### Phase 2 scope

After transport and proxying are stable:
- native gRPC endpoint handling inside `serval-server`
- message decoding helpers in a dedicated `serval-grpc` module
- unary-first native handler API
- streaming handler APIs after transport/state machines have proven reliable

### Explicit non-goals for the first slice

- TLS ALPN (`h2`) inbound or outbound
- gRPC-Web
- HTTP/2 server push
- header compression beyond RFC-required HPACK support
- transparent h1 ↔ gRPC transcoding
- protobuf code generation
- reflection service generation

## Module Placement

### New module: `serval-h2`

Layer 1 (Protocol).

Responsibility:
- HTTP/2 frame parsing/encoding
- connection preface handling
- SETTINGS parsing/validation
- HPACK decoding/encoding
- stream state machine primitives
- flow-control accounting
- `h2c` upgrade and prior-knowledge detection helpers

Dependencies:
- `serval-core`
- `std`

Non-responsibilities:
- no socket ownership
- no accept loop
- no routing
- no gRPC semantics
- no upstream pool management

### New module: `serval-grpc`

Layer 2 (Infrastructure).

Responsibility:
- gRPC message envelope parsing/encoding
- metadata validation helpers
- `grpc-timeout` parsing/formatting
- `grpc-status` / `grpc-message` / trailers helpers
- service/method path parsing
- native handler utilities once transport is stable

Dependencies:
- `serval-core`
- `serval-h2`
- `std`

Why layer 2 instead of layer 1:
- gRPC sits on top of HTTP/2
- layer 1 modules must not depend sideways on each other
- `serval-grpc` can depend downward on `serval-h2` cleanly if it lives above it

### `serval-server`

Layer 5 (Orchestration).

Responsibility:
- detect HTTP/2 prior knowledge preface before the HTTP/1.1 parser runs
- detect and handle `Upgrade: h2c` requests in the HTTP/1.1 path
- dispatch accepted h2c connections into `serval-server/h2`
- later: invoke native gRPC hooks after transport framing is established

### `serval-client`

Layer 2 (Infrastructure).

Responsibility:
- add `h2/` support for outbound HTTP/2 client behavior
- create upstream `h2c` connections using prior knowledge
- manage connection-level SETTINGS, windows, and stream creation

Rationale:
- project rules say HTTP client behavior must live in `serval-client`
- `serval-proxy` should continue delegating upstream connection details rather than opening raw sockets

### `serval-proxy`

Layer 3 (Mechanics).

Responsibility:
- proxy h2 streams using `serval-client/h2`
- forward gRPC metadata, DATA, and trailers without semantic corruption
- map transport failures to HTTP/2 / gRPC-visible outcomes correctly
- never translate between protocols implicitly

## Architecture Decisions

### 1. Build HTTP/2 first, then gRPC semantics on top

gRPC correctness depends on HTTP/2 correctness:
- stream multiplexing
- header block ordering
- flow control
- trailers
- half-closed stream state

Therefore the work must proceed in this order:
1. `serval-h2`
2. `serval-client/h2` + `serval-server/h2`
3. `serval-proxy/h2`
4. `serval-grpc`
5. native gRPC server hooks

### 2. Proxy first, native second

The smallest production-useful gRPC slice is **proxy pass-through over h2c**.

Why:
- it is immediately useful for sidecars, API gateways, and load balancers
- it minimizes new public handler API surface while the transport is still settling
- it exercises the hardest transport pieces first: multiplexing, trailers, flow control, stream resets

### 3. Do not overload HTTP/1.1 abstractions silently

Current `Request`, `Response`, and `Upstream` types are HTTP/1.1-biased.
For h2/gRPC we need explicit additions rather than hidden behavior.

Planned shared-type changes:
- add an explicit upstream HTTP protocol enum in `serval-core`
  - `.h1`
  - `.h2c`
  - later `.h2_tls`
- add explicit trailer support in shared response/request metadata where ownership truly belongs in layer 0
- add header iteration helpers for repeated metadata instead of pretending `get()` is sufficient for all gRPC metadata cases

### 4. Prior knowledge first for upstreams

For outbound upstream connections, Phase 1 should use **h2c prior knowledge** only.

Why:
- it is the common deployment mode for internal gRPC over cleartext
- it is deterministic
- it avoids a needless HTTP/1.1 upgrade round trip between proxy and upstream
- it reduces state-space during the first production slice

Inbound server support should still include `Upgrade: h2c`, because clients may use it and RFC 9113 defines it.

## File Plan

### New files

| File | Purpose |
|------|---------|
| `serval-h2/mod.zig` | Public exports |
| `serval-h2/frame.zig` | Frame header parse/encode |
| `serval-h2/settings.zig` | SETTINGS parsing, ACK rules, limits |
| `serval-h2/hpack.zig` | HPACK static + bounded dynamic table |
| `serval-h2/headers.zig` | Header block validation, pseudo-header rules |
| `serval-h2/stream.zig` | Stream state machine |
| `serval-h2/flow_control.zig` | Window accounting |
| `serval-h2/preface.zig` | Client preface and `h2c` upgrade helpers |
| `serval-h2/README.md` | Module documentation |
| `serval-grpc/mod.zig` | Public exports |
| `serval-grpc/wire.zig` | 5-byte gRPC message envelope |
| `serval-grpc/metadata.zig` | Metadata/trailer validation |
| `serval-grpc/status.zig` | gRPC status/trailer helpers |
| `serval-grpc/timeout.zig` | `grpc-timeout` parsing/formatting |
| `serval-grpc/path.zig` | `/package.Service/Method` helpers |
| `serval-grpc/README.md` | Module documentation |
| `serval-client/h2/mod.zig` | HTTP/2 client exports |
| `serval-client/h2/conn.zig` | Outbound h2c connection/session state |
| `serval-client/h2/stream.zig` | Outbound stream management |
| `serval-proxy/h2/mod.zig` | H2 proxy exports |
| `serval-proxy/h2/grpc.zig` | gRPC/h2 forwarding path |
| `serval-server/h2/mod.zig` | H2 server exports |
| `serval-server/h2/server.zig` | H2 server orchestration |
| `serval-server/h2/connection.zig` | Connection preface, SETTINGS, conn lifecycle |
| `serval-server/h2/streams.zig` | Bounded stream table + dispatch |
| `docs/plans/2026-03-09-grpc-h2c-design.md` | This design |

### Modified files

| File | Change |
|------|--------|
| `build.zig` | Register new modules and test steps |
| `serval-core/config.zig` | Add h2/gRPC limits and timeouts |
| `serval-core/types.zig` | Add explicit upstream protocol + trailer support as needed |
| `serval-core/header_map.zig` | Add repeated-header iteration helpers for metadata/trailers |
| `serval/mod.zig` | Re-export new modules |
| `serval-server/mod.zig` | Export h2 server types |
| `serval-server/h1/server.zig` | Detect `Upgrade: h2c` and hand off safely |
| `serval-client/mod.zig` | Export h2 client types |
| `serval-proxy/mod.zig` | Export h2 proxy types |
| `integration/tests.zig` | Add h2c + gRPC end-to-end tests |
| `README.md`, `serval/ARCHITECTURE.md`, module READMEs | Document placement and behavior |

## Phase Plan

## Phase 0: Limits, constants, and type ownership

Before implementing any frame I/O, define the bounds explicitly in `serval-core/config.zig`.

Required constants:
- `H2_MAX_FRAME_SIZE_BYTES`
- `H2_MAX_HEADER_LIST_SIZE_BYTES`
- `H2_MAX_DYNAMIC_TABLE_SIZE_BYTES`
- `H2_MAX_CONCURRENT_STREAMS`
- `H2_INITIAL_STREAM_WINDOW_SIZE_BYTES`
- `H2_INITIAL_CONNECTION_WINDOW_SIZE_BYTES`
- `H2_MAX_CONTINUATION_FRAMES`
- `H2_SETTINGS_TIMEOUT_NS`
- `H2_STREAM_IDLE_TIMEOUT_NS`
- `H2_CONNECTION_IDLE_TIMEOUT_NS`
- `H2_PING_TIMEOUT_NS`
- `GRPC_MAX_MESSAGE_SIZE_BYTES`
- `GRPC_MAX_METADATA_SIZE_BYTES`
- `GRPC_CLOSE_TIMEOUT_NS`

TigerStyle requirements:
- use explicit bounded integer types (`u16`, `u32`, `u64`, `i64`)
- every timeout has `_ns` or `_ms` suffix
- no local magic numbers in transport code

## Phase 1: `serval-h2` transport foundation

### Phase 1A: Frame codec

Implement:
- 9-byte frame header parse/encode
- frame type enum
- flags validation per frame type
- max-frame-size enforcement
- padding rules
- CONTINUATION sequencing rules

Must reject explicitly:
- oversized frames
- invalid flag combinations
- HEADERS/PUSH_PROMISE fragments not followed by CONTINUATION
- DATA on stream 0
- SETTINGS with stream id != 0
- invalid frame lengths for PING, RST_STREAM, WINDOW_UPDATE, PRIORITY

### Phase 1B: Connection preface + SETTINGS

Implement:
- client connection preface validation
- server initial SETTINGS emission
- SETTINGS ACK synchronization
- `Upgrade: h2c` request validation using `HTTP2-Settings`
- server-side h1 → h2 handoff rules

Important spec behavior:
- after `101 Switching Protocols`, stream 1 represents the upgraded request
- server must not re-parse post-upgrade bytes as HTTP/1.1
- connection errors produce GOAWAY with correct code before close where possible

### Phase 1C: HPACK

Implement a bounded HPACK table:
- full static table
- dynamic table with explicit byte cap
- indexed / literal / never-indexed decode
- bounded integer decoding with overflow checks
- Huffman decode with size caps

TigerStyle requirement:
- no allocator on the request path
- dynamic table storage must be caller-owned, fixed-capacity, and resettable

### Phase 1D: Stream state machine + flow control

Implement explicit stream states:
- idle
- reserved_local / reserved_remote (if needed for completeness)
- open
- half_closed_local
- half_closed_remote
- closed

Implement:
- bounded stream slot table per connection
- stream id monotonicity checks
- connection and stream window accounting
- WINDOW_UPDATE validation
- RST_STREAM handling
- GOAWAY handling

No unbounded structures are allowed. If the stream table is full, reject new streams deterministically.

## Phase 2: Server-side h2c transport

### Connection dispatch

`serval-server` should detect h2c in this order:

1. prior knowledge preface at connection start
2. otherwise HTTP/1.1 parser path
3. if parsed request is `Upgrade: h2c`, validate and switch protocols
4. otherwise remain in h1

### `serval-server/h2`

Responsibilities:
- own per-connection h2 state
- multiplex inbound streams across a bounded stream table
- translate validated header blocks into serval request semantics
- expose response/trailer writers to proxy/native layers
- handle stream cancellation and connection shutdown cleanly

Important constraint:
- do not spawn unbounded tasks per stream
- concurrency must be bounded by `H2_MAX_CONCURRENT_STREAMS`
- backpressure must come from flow-control windows, not ad hoc queues

## Phase 3: Outbound `serval-client/h2` + `serval-proxy/h2`

### `serval-client/h2`

Responsibilities:
- establish prior-knowledge `h2c` upstream sessions
- emit client preface + SETTINGS
- create outbound streams with validated pseudo-headers
- track per-connection and per-stream windows
- read response headers, DATA, and trailers
- surface resets, GOAWAY, and protocol errors explicitly

### `serval-proxy/h2`

Responsibilities:
- forward inbound h2 streams to outbound h2 upstream streams
- preserve gRPC framing exactly
- preserve trailers exactly
- map client cancellation to `RST_STREAM`
- close/mark unhealthy upstream sessions on transport corruption

Critical rule:
- do not translate gRPC to HTTP/1.1 internally
- if the selected upstream is not `h2c`, fail closed with explicit configuration error

## Phase 4: `serval-grpc` protocol helpers

Once h2 transport is stable, add gRPC protocol helpers.

Implement:
- request validation helpers:
  - `:method == POST`
  - `content-type` starts with `application/grpc`
  - `te == trailers`
- envelope parser/encoder for compressed flag + message length
- `grpc-timeout` parser with explicit unit handling
- trailer validation:
  - `grpc-status` required on completed calls
  - `grpc-message` optional
  - trailers-only responses supported
- service/method path parser

Explicitly reject:
- malformed 5-byte prefix
- message length > configured max
- invalid `grpc-timeout`
- missing `grpc-status` in completed response trailers
- forbidden HTTP/2 header misuse

## Phase 5: Native gRPC endpoint API

Native gRPC serving should **not** go into `serval-core`.
It belongs in `serval-server` and should use `serval-grpc` only for protocol helpers.

### Initial API direction

Do not finalize this before proxy transport is stable, but the likely shape is:

```zig
pub fn selectGrpc(self: *Handler, ctx: *Context, request: *const Request) GrpcRouteAction
pub fn handleGrpcUnary(self: *Handler, ctx: *Context, call: *GrpcUnaryCall) !void
```

Why unary first:
- smallest useful native slice
- easier to prove correctness for trailers and deadlines
- avoids exposing unstable stream APIs too early

Streaming APIs (`handleGrpcServerStream`, `handleGrpcBidi`) should come only after:
- flow control is proven under load
- cancellation and deadline propagation are correct
- trailers emission is deterministic

## gRPC Request Flow

### Inbound proxy call

1. server detects prior-knowledge h2c or upgrades h1 → h2c
2. `serval-server/h2` reads HEADERS and validates HTTP/2 framing
3. `serval-grpc` validates gRPC request metadata
4. handler selects an upstream with `http_protocol = .h2c`
5. `serval-proxy/h2` opens upstream stream through `serval-client/h2`
6. request HEADERS + DATA + END_STREAM are forwarded
7. upstream response HEADERS + DATA + trailers are forwarded back unchanged
8. `grpc-status` trailer is preserved and logged
9. cancellation maps to `RST_STREAM`
10. transport errors produce GOAWAY / stream reset as required and fail closed

### Native unary call (future)

1. transport path establishes an inbound stream
2. `serval-grpc` validates metadata and reads exactly one inbound message
3. handler receives decoded request bytes and deadline/metadata context
4. handler writes one response message
5. server sends response HEADERS, DATA, and final trailers with `grpc-status = 0`
6. on error, server sends trailers-only or response trailers with non-zero `grpc-status`

## TigerStyle / TigerBeetle Compliance

### Safety rules

- ~2 assertions per function
- all loops explicitly bounded
- explicit state machines for connection and stream lifecycles
- no recursion
- no `catch {}`
- no runtime allocation after init on the hot path
- use fixed-capacity tables for:
  - streams
  - HPACK dynamic entries
  - header/trailer storage
  - pending outbound frame buffers

### Design rules

- make every protocol transition explicit:
  - h1
  - h1 → h2c upgrade
  - h2 prior knowledge
  - h2 stream open/half-closed/closed
- no implicit default windows or table growth
- every limit comes from `serval-core.config`
- every timeout is bounded and logged on expiry
- every transport error is mapped to a specific HTTP/2 error code or gRPC-visible failure

### Performance rules

- parse frame headers without allocation
- batch socket reads/writes where possible
- avoid copying DATA payloads when forwarding
- preserve backpressure through HTTP/2 flow control instead of buffering unboundedly

## Testing Plan

### Unit tests

`serval-h2`:
- frame header decode/encode
- invalid frame lengths and flags
- connection preface parsing
- SETTINGS ACK rules
- CONTINUATION sequencing
- stream state transitions
- window update overflow checks
- HPACK indexed/literal/Huffman cases

`serval-grpc`:
- envelope parse/encode
- timeout parsing for all units
- status/trailer validation
- content-type validation
- service/method path parsing

### Property / fuzz tests

- fuzz frame parser with random bytes
- fuzz HPACK integer/Huffman decode
- fuzz header block ordering and pseudo-header validation
- fuzz gRPC envelope parser with random lengths/flags

### Integration tests

- h2c prior-knowledge unary proxy via `grpcurl -plaintext`
- h2c upgrade path request acceptance
- streaming response relay (server streaming)
- client cancellation maps to upstream `RST_STREAM`
- missing `grpc-status` trailer fails closed
- oversized message rejected deterministically
- flow-control stall/resume under bounded windows
- GOAWAY drains existing streams and rejects new ones

### Interop tests

- serval proxy in front of Go gRPC server
- serval proxy in front of grpc-go health service
- native serval endpoint called by `grpcurl`
- round-trip metadata with binary `-bin` headers

### Stress tests

- many concurrent unary streams up to `H2_MAX_CONCURRENT_STREAMS`
- repeated server-streaming calls with flow-control pressure
- upstream connection churn and GOAWAY rollover
- large but bounded protobuf payloads up to configured max

## Exit Criteria

Phase 1 is complete only when all of these are true:

- `serval-h2` passes unit + fuzz tests
- `serval-client/h2` and `serval-server/h2` interoperate on prior knowledge and `Upgrade: h2c`
- `serval-proxy/h2` proxies unary and streaming gRPC calls end-to-end
- `grpcurl -plaintext` works against proxy and native test targets
- trailers and `grpc-status` are preserved exactly
- connection/stream state machines are bounded and assertion-heavy
- no request-path allocations remain in transport hot paths
- docs are updated (`README.md`, `serval/ARCHITECTURE.md`, module READMEs)

## Recommended Implementation Order

1. config constants + shared type ownership updates
2. `serval-h2/frame.zig`
3. `serval-h2/preface.zig` + `settings.zig`
4. `serval-h2/stream.zig` + `flow_control.zig`
5. `serval-h2/hpack.zig`
6. `serval-server/h2` prior-knowledge server path
7. `serval-client/h2` prior-knowledge upstream path
8. `serval-proxy/h2` pass-through proxying
9. `serval-grpc` validation + envelope helpers
10. integration + interop + stress tests
11. native unary API
12. native streaming APIs

## Summary

The correct architecture is:
- `serval-h2` for HTTP/2 transport primitives
- `serval-grpc` above it for gRPC semantics
- `serval-client/h2` and `serval-proxy/h2` for production-useful proxying first
- `serval-server/h2` for orchestration and later native endpoints

This keeps layering clean, makes the smallest useful slice available early, and matches both RFC 9113 and gRPC protocol requirements without smuggling protocol-specific behavior into the wrong modules.
