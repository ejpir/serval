# HTTP/2 Bridge Architecture

This document is the canonical developer explanation of Serval's current
stream-aware HTTP/2 bridge approach.

It explains the bridge path used today for gRPC-over-HTTP/2 proxying and the
boundary between that path and the older tunnel/translation fallbacks.

## Purpose

Serval currently has two different HTTP/2-related proxy shapes:

1. a bounded stream-aware bridge for the active gRPC-over-HTTP/2 path
2. older fallback behavior for cases that are not yet on the generic stream-aware
   path

The bridge exists because HTTP/2 is multiplexed. A transparent connection-level
byte tunnel is not sufficient once Serval needs to:

- inspect the first request to run `selectUpstream()`
- preserve per-stream semantics
- map downstream stream ids to upstream stream ids
- handle resets and GOAWAY deterministically
- enforce gRPC correctness rules such as mandatory `grpc-status`

## Current Scope

The bridge is active for:

- downstream TLS with ALPN `h2`
- downstream cleartext prior-knowledge HTTP/2
- downstream cleartext `Upgrade: h2c`
- upstream `.h2c` cleartext targets
- upstream `.h2` TLS targets

The current bridge is intentionally gRPC-focused. It is not yet the full generic
HTTP/2 proxy for arbitrary request/response traffic.

## Ownership by Module

| Module | Ownership |
|------|---------|
| `serval-server` | Detect downstream h2 entry path, validate/parse first request, choose bridge vs fallback, own downstream connection runtime |
| `serval-h2` | Frame, preface, HPACK, settings, flow-control, and upgrade helpers |
| `serval-grpc` | Validate gRPC request/response metadata and wire framing rules |
| `serval-proxy` | Own the downstream-to-upstream stream bridge and forwarding mechanics |
| `serval-client` | Own upstream h2 sessions, session pooling, and GOAWAY-aware rollover |

This split is intentional:

- `serval-server` decides when a connection enters bridge mode
- `serval-proxy` owns how streams are forwarded
- `serval-client` owns reusable upstream session state

## Bridge Model

At a high level, the bridge is:

- one downstream HTTP/2 connection
- zero or one selected upstream per request routing decision
- one reusable upstream HTTP/2 session per upstream generation
- many downstream streams mapped to many upstream streams through a fixed-capacity
  binding table

The bridge is stream-aware, not byte-tunnel-based.

That means Serval explicitly:

- opens upstream streams
- forwards request headers and DATA on a per-stream basis
- receives upstream actions
- maps those actions back to the correct downstream stream id

## Entry Paths

### 1. Downstream TLS with ALPN `h2`

Flow:

1. `serval-server` accepts a TLS connection.
2. TLS negotiates ALPN `h2`.
3. The server h2 runtime starts on the negotiated TLS stream.
4. Serval parses the first request HEADERS with bounded HPACK decode.
5. `serval-grpc` validates that the request is actually gRPC when it is routed
   into the active bridge path.
6. The normal handler runs `selectUpstream()` on the request view.
7. If the selected upstream protocol is `.h2c` or `.h2`, Serval enters bridge
   mode.
8. `serval-proxy/h2/bridge.zig` acquires or reuses an upstream session.
9. Downstream stream ids are bound to upstream stream ids and the connection
   continues in stream-aware mode.

### 2. Downstream cleartext prior-knowledge HTTP/2

Flow:

1. `serval-server` accepts a cleartext connection.
2. `serval-h2` detects the client preface.
3. Serval parses the first request HEADERS with bounded HPACK decode.
4. `serval-grpc` validates that the request is actually gRPC.
5. The normal handler runs `selectUpstream()` on a synthetic request view.
6. If the selected upstream protocol is `.h2c` or `.h2`, Serval enters bridge
   mode.
7. `serval-proxy/h2/bridge.zig` acquires or reuses an upstream session.
8. Downstream stream ids are bound to upstream stream ids and the connection
   continues in stream-aware mode.

### 3. Downstream cleartext `Upgrade: h2c`

Flow:

1. `serval-server` parses the HTTP/1.1 request.
2. `serval-h2` validates `Upgrade`, `Connection`, and `HTTP2-Settings`.
3. `serval-grpc` validates the gRPC request metadata.
4. The normal handler runs `selectUpstream()`.
5. If the selected upstream protocol is `.h2c` or `.h2`, Serval sends
   `101 Switching Protocols`.
6. The upgraded request is replayed as stream 1 in the h2 runtime.
7. The bridge then continues in the same stream-aware model as prior-knowledge
   entry.

The bridge is intentionally the same logical model for all three entry paths.
The difference is only how the downstream connection reached HTTP/2 mode.

## Downstream to Upstream Stream Binding

The core bridge data structure is the fixed-capacity binding table in
`serval-proxy/h2/bindings.zig`.

Each binding records:

- downstream stream id
- upstream stream id
- upstream index
- upstream session generation

The generation field matters because an upstream session can roll over after
GOAWAY. A downstream stream must stay associated with the session generation on
which it was opened, even if later streams for the same upstream are opened on a
new session.

This avoids stale-session confusion and prevents response actions from being
misdelivered to the wrong downstream stream.

## Upstream Session Reuse and Rollover

Upstream h2 sessions are owned by `serval-client` session-pool logic.

Current model:

- one active reusable session per upstream index
- at most one draining session during graceful GOAWAY rollover
- new streams open on the active session
- already-open streams may continue draining on the older generation if allowed

This is why the binding records both upstream index and session generation.

The bridge does not treat GOAWAY as a blanket “kill all active streams” signal.
It respects `last_stream_id`:

- streams already permitted by `last_stream_id` may continue
- new streams move to the next active session generation
- stale bindings for retired sessions are removed explicitly

## Receive-Action Mapping

The bridge does not expose raw upstream frame parsing to callers. Instead,
`serval-proxy/h2/bridge.zig` converts upstream receive results into explicit
actions such as:

- response headers
- response DATA
- response trailers
- stream reset
- connection-close / upstream-session-close signal

Those actions are then mapped back onto the downstream runtime for the matching
stream binding.

This keeps the forwarding logic stream-aware without making the rest of the
proxy stack reason directly about every upstream frame.

## gRPC Fail-Closed Policy

The current bridge is intentionally strict for gRPC traffic.

Examples:

- request metadata must validate as gRPC
- response metadata must include valid `grpc-status`
- missing or invalid `grpc-status` fails closed as downstream
  `RST_STREAM(PROTOCOL_ERROR)`
- upstream resets are mapped explicitly instead of being masked as successful
  completion

This is by design. The bridge is not allowed to silently convert protocol errors
into apparent success.

## Bridge Path vs Fallback Path

Today Serval still has two broad proxy behaviors for HTTP/2-related traffic.

### Bridge path

Used when:

- downstream entry is TLS ALPN `h2`, cleartext prior knowledge, or
  `Upgrade: h2c`
- the request is in the supported bridge scope
- the selected upstream protocol is `.h2c` or `.h2`

Behavior:

- stream-aware forwarding
- bounded downstream/upstream stream binding
- upstream session reuse
- explicit reset/GOAWAY handling
- gRPC fail-closed response validation

### Fallback path

Used when:

- the selected upstream is not on the active stream-aware h2 path
- the request falls outside the currently supported bridge scope

Behavior depends on path:

- HTTP/1 translation + normal forwarding for non-h2 upstreams where supported
- legacy tunnel-based behavior where stream-aware semantics do not yet exist

This boundary is important. Documentation should not imply that all h2 traffic
already uses the bridge.

## Concurrency and Scheduling Notes

The bridge has already hit real production-style concurrency bugs.

Important lessons now encoded in the implementation:

- long-lived background bridge readers must use `std.Io.Group.concurrent()`
  rather than `Group.async()` so connection startup cannot be hijacked by eager
  inline task execution
- upstream-action scanning must retire stale bindings and remain fair across
  active bindings
- tunnel termination and bridge termination paths must treat closed-peer cases
  as legitimate terminal states, not internal assertions

These are part of the bridge architecture now, not incidental bug notes.

## What This Architecture Does Not Yet Claim

This document does not claim that Serval already has:

- a generic production-grade `h2 -> h2` proxy for arbitrary HTTP/2 traffic
- complete generic `h2 -> h1` request-body and fairness coverage
- full control-frame propagation across all HTTP/2 edge cases
- a complete generic replacement for all legacy tunnel/translation fallbacks

Those are still tracked as next-phase work.

## Where to Read the Code

Start here, in order:

1. `serval-server/h1/server.zig`
   downstream entry detection, upgrade handling, and bridge handoff
2. `serval-server/frontend/generic_h2.zig`
   generic h2 dispatch and bridge/tunnel selection
3. `serval-proxy/h2/bridge.zig`
   downstream/upstream bridge orchestration
4. `serval-proxy/h2/bindings.zig`
   fixed-capacity stream binding table
5. `serval-client/h2/*`
   upstream session runtime and pooling

## Related Docs

- [serval-proxy README](/home/nick/repos/serval/serval-proxy/README.md)
- [serval-server README](/home/nick/repos/serval/serval-server/README.md)
- [ARCHITECTURE.md](/home/nick/repos/serval/serval/ARCHITECTURE.md)
- [2026-03-09 grpc h2c design](/home/nick/repos/serval/docs/plans/2026-03-09-grpc-h2c-design.md)
- [2026-03-10 stream-aware h2 proxy plan](/home/nick/repos/serval/docs/plans/2026-03-10-stream-aware-h2-proxy-plan.md)
- [2026-03-15 h2 production-grade next plan](/home/nick/repos/serval/docs/plans/2026-03-15-h2-production-grade-next-plan.md)
