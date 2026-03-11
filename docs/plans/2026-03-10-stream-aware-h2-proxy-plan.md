# Stream-Aware HTTP/2 Proxy Plan

Add the next production slice after the initial gRPC-over-h2c connection tunnel: a real,
bounded, stream-aware HTTP/2 transport and proxy path.

## Goal

Move Serval from:
- first-request h2c routing + whole-connection raw tunneling

to:
- explicit HTTP/2 connection state
- bounded multi-stream handling on one connection
- stream-aware proxying for concurrent gRPC calls
- correct SETTINGS / ACK / stream lifecycle / flow-control behavior

## Why this is next

The current gRPC slice is useful, but it is still **connection-oriented**:
- the first request chooses the upstream
- the whole downstream h2 connection is pinned to that upstream
- Serval does not yet understand multiple concurrent streams on one connection

That is not enough for production-grade long-lived gRPC clients.
The next slice must make stream ownership explicit.

## Status

- Phase A: implemented
- Phase B: complete; bounded `serval-server/h2` connection state and per-frame inbound runtime primitives are now wired into an early terminating plain-connection driver (`h2/server.zig`) plus main cleartext `serval-server` accept-loop dispatch for both prior-knowledge and `Upgrade: h2c`; integration now covers SETTINGS/ACK, PING ACK, interleaved dual-stream unary handling on one terminated connection, DATA-driven connection+stream WINDOW_UPDATE replenishment on multi-frame request bodies, client `RST_STREAM`, main-loop prior-knowledge dispatch, main-loop upgrade dispatch, post-101 optional client preface handling, malformed post-101 preface fail-closed rejection on upgraded terminated sessions, and fail-closed GOAWAY on invalid DATA-before-HEADERS ordering in direct terminated runtime, main-server prior-knowledge terminated dispatch, and post-101 upgrade terminated sessions. Per-stream lifecycle tracking in the terminated runtime now emits optional stream-open/stream-close summaries (status/bytes/duration/reason), and main-server terminated-h2 dispatch now wires those summaries into per-stream metrics, tracing spans, and stream-scoped `onLog` entries for both prior-knowledge and upgrade paths. Large-body integration reliability was also improved by switching the 5GB case to generated fixed-buffer streaming (no 5GB allocation), hardening proxy Content-Length body forwarding loops with bounded EAGAIN/EINTR retry + stall timeout behavior and exact splice pipe-drain checks, and adding bounded nonblocking control-frame write retries in `serval-server/h2/server.zig`; the 5GB test remains opt-in due runtime cost
- Phase C: in progress; `serval-client/h2` now includes bounded outbound session/runtime primitives for client preface + initial SETTINGS emission, peer SETTINGS/ACK synchronization, request stream creation with HEADERS/DATA frame builders, response HEADERS/DATA/trailer receive actions (including bounded HEADERS+CONTINUATION reassembly plus bounded HPACK dynamic-table/Huffman decode), and explicit GOAWAY/RST_STREAM/WINDOW_UPDATE handling, plus a fixed-buffer socket-owning `ClientConnection` driver for prior-knowledge h2c handshakes/frame I/O and a fixed-capacity `UpstreamSessionPool` with bounded GOAWAY rollover (active + draining session)
- Phase D: in progress; `serval-proxy/h2` now includes a bounded stream bridge primitive (`bridge.zig`) that composes `serval-client` upstream h2 session pooling with downstream↔upstream stream bindings and mapped response/reset actions, validated by integration coverage against the terminated h2 test server; main-path bridge integration now covers both prior-knowledge and `Upgrade: h2c` entry for cleartext h2c upstreams, including fail-closed downstream `RST_STREAM(CANCEL)` mapping for upstream stream closures (RST/GOAWAY), GOAWAY `last_stream_id`-aware handling that keeps still-allowed active streams running, and fail-closed `RST_STREAM(PROTOCOL_ERROR)` when mandatory gRPC `grpc-status` metadata is missing/invalid

## Scope Split

### Phase A — Protocol primitives in `serval-h2`

Implement the minimum bounded transport primitives needed before client/server session code:

1. `settings.zig`
   - SETTINGS payload parsing/encoding
   - ACK validation
   - per-setting value validation
   - fixed-capacity setting arrays
   - apply-to-state helper for peer/local settings

2. `stream.zig`
   - explicit stream state machine
   - open / half-closed / closed transitions
   - fixed-capacity stream table
   - stream-id parity and monotonicity checks

3. `flow_control.zig`
   - connection/stream window accounting
   - WINDOW_UPDATE validation
   - bounded increments, overflow rejection

4. Wire the new primitives into existing first-slice paths where safe
   - validate inbound SETTINGS frames during initial prior-knowledge parse
   - validate `HTTP2-Settings` upgrade payloads through the same SETTINGS parser

### Phase B — Inbound HTTP/2 connection state in `serval-server`

Add bounded per-connection HTTP/2 state:
- connection preface receipt
- local SETTINGS emission
- peer SETTINGS tracking
- stream table lifecycle
- HEADERS/DATA dispatch per stream
- GOAWAY / RST_STREAM handling

### Phase C — Outbound HTTP/2 connection state in `serval-client`

Add prior-knowledge h2c upstream sessions:
- client preface + SETTINGS
- stream creation on shared upstream h2 connections
- response HEADERS / DATA / trailers reading
- GOAWAY / RST_STREAM propagation

### Phase D — Stream-aware proxying in `serval-proxy`

Replace whole-connection pinning with real stream-aware forwarding:
- downstream stream ↔ upstream stream mapping
- preserve concurrent unary + streaming gRPC calls on one connection
- preserve trailers and cancellations exactly
- bounded per-connection stream fan-out

## Phase A Detailed Plan

### A1. SETTINGS parser

Add `serval-h2/settings.zig` with:
- `SettingId`
- `Setting`
- `Settings`
- `parseSettingsPayload(payload, out)`
- `buildSettingsPayload(out, settings)`
- `validateSettingsFrame(header, payload)`
- `applySettings(target, parsed_settings)`

Validation rules:
- stream id must be `0`
- ACK frames must have zero-length payload
- payload length must be a multiple of 6
- `SETTINGS_ENABLE_PUSH` must be 0 or 1
- `SETTINGS_INITIAL_WINDOW_SIZE <= 2^31 - 1`
- `SETTINGS_MAX_FRAME_SIZE` must be within RFC bounds
- unknown settings are preserved as raw ids and ignored by `applySettings`

### A2. Stream state machine

Add `serval-h2/stream.zig` with:
- `Role` (`client`, `server`)
- `State`
- `Stream`
- `StreamTable`

Required invariants:
- stream id `0` is invalid
- client-initiated streams are odd
- server-initiated streams are even
- stream ids are monotonic per side
- stream table capacity is fixed by config
- invalid transitions fail closed

### A3. Flow control

Add `serval-h2/flow_control.zig` with:
- window struct for connection/stream windows
- decrement on DATA send/recv
- increment on WINDOW_UPDATE
- reject zero increment and overflow
- explicit max window = `2^31 - 1`

### A4. Safe integration into current slice

Use the new primitives without changing the overall architecture yet:
- `request.zig` should validate SETTINGS frames via `settings.zig`
- `upgrade.zig` should validate decoded `HTTP2-Settings` via `settings.zig`
- no stream-aware proxying yet in this phase

## Config Additions

Add explicit bounds in `serval-core/config.zig`:
- `H2_MAX_SETTINGS_PER_FRAME`
- `H2_MAX_CONCURRENT_STREAMS`
- `H2_INITIAL_WINDOW_SIZE_BYTES`
- `H2_CONNECTION_WINDOW_SIZE_BYTES`
- `H2_MAX_WINDOW_SIZE_BYTES`

## Tests

### Unit tests

`serval-h2/settings.zig`
- parse valid payload
- reject bad ACK payload
- reject invalid enable_push
- reject invalid max_frame_size
- apply settings updates expected fields

`serval-h2/stream.zig`
- local/remote stream parity by role
- monotonicity enforcement
- open → half-closed → closed transitions
- invalid transitions fail
- fixed-capacity stream table rejects overflow deterministically

`serval-h2/flow_control.zig`
- decrement/increment happy paths
- zero increment rejected
- overflow rejected
- underflow rejected

### Regression tests

- WebSocket paths must still ignore h2c logic unless actual h2c signals are present
- existing gRPC prior-knowledge and upgrade integration tests must still pass

## Non-goals for this phase

- HPACK dynamic table
- CONTINUATION reassembly across arbitrary fragments
- full `serval-server/h2` runtime
- full `serval-client/h2` runtime
- stream-aware proxying itself

Those come after the primitives are proven correct.

## Deliverables for this first implementation step

1. plan document written
2. `serval-h2/settings.zig`
3. `serval-h2/stream.zig`
4. config bounds added
5. existing initial h2c slice wired to validate SETTINGS with the new helper
6. unit tests passing for the new primitives
