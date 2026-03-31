# H2 Remaining Work Plan

## Goal

Document what remains after the March-April 2026 H2 ownership and storage cleanup, so the team can choose between:

- stopping at the current practical end state, or
- continuing toward a more fully parameterized H2 storage model

This plan is intentionally not a broad redesign spec. It is a checkpoint of the concrete work still left.

## Current State

The high-value cleanup is already done:

- deploy-time H2 and WebSocket knobs live in config schema rather than scattered module constants
- owner-internal H2/WebSocket/ACME limits were moved out of `serval-core/config.zig`
- server, client, and proxy H2 hot paths now use explicit owner-managed storage for most significant scratch
- h2c bootstrap paths moved large temporary state off fragile connection-stack frames
- `serval-h2/request.zig` now supports explicit caller-owned:
  - stable decoded request storage
  - temporary header-block assembly scratch
  - temporary decoded `HeaderField[MAX_HEADERS]` scratch
- the stdlib `io_uring` batch-completion crash triggered by integration churn was fixed in the patched Zig toolchain

What remains is narrower and mostly about how far to push explicit storage ownership versus keeping bounded helper-local capacities as intentional implementation detail.

## Recommendation

Recommended default:

- stop after a small documentation pass unless a concrete operational problem still points at the remaining helper-local or capacity-bounded code

Reason:

- ownership is explicit where it matters most
- the remaining work is no longer broad cleanup
- further changes are more API-design tradeoff than correctness fix

If the team wants a fully normalized H2 storage/runtime split, the remaining work is real but still bounded. See the implementation tracks below.

## Remaining Work Categories

### Category A: Acceptable To Leave As-Is

These are bounded helper-local buffers or convenience APIs that are now optional rather than architectural traps.

#### `serval-h2/control.zig`

Small local payload/frame arrays remain in control-frame helpers:

- `parsePingFrame`
- `buildWindowUpdateFrame`
- `buildRstStreamFrame`
- small local frame buffers in control-frame tests/helpers

These are tiny, fixed-size, and not part of the ownership confusion that motivated the larger cleanup.

#### `serval-h2/request.zig`

Convenience wrappers still create local storage:

- `parseInitialRequest`
- `parseInitialRequestWithDecoder`
- `parseInitialRequestWithDecoderAndHeaderStorage`
- `decodeRequestHeaderBlock`
- `decodeRequestHeaderBlockWithDecoder`

This is acceptable because explicit-storage variants now exist:

- `parseInitialRequestWithStorage`
- `parseInitialRequestWithDecoderAndStorage`
- `parseInitialRequestWithDecoderInto`
- `decodeRequestHeaderBlockWithFieldStorage`
- `decodeRequestHeaderBlockWithDecoderAndFieldStorage`

In other words, the hidden scratch is now convenience-only, not mandatory.

#### `serval-h2/upgrade.zig`

Remaining local convenience storage:

- `buildPriorKnowledgePreambleFromUpgrade(...)` still allocates local `header_block_storage`
- `appendHeaderLowercaseName(...)` still uses a small `lower_name_buf: [256]u8`

These are acceptable unless the team wants zero helper-local scratch even in convenience APIs.

### Category B: Real Remaining Design Work

This is the part that still materially shapes runtime behavior.

#### 1. `serval-h2/limits.zig` still bounds runtime behavior

Current owner-local capacities:

- `frame_payload_capacity_bytes = 16 * 1024`
- `header_block_capacity_bytes = 8 * 1024`

Even after the ownership cleanup, parts of the client/server runtime still assert configured runtime values against these capacities.

This means:

- runtime `max_frame_size_bytes` is still constrained by compile-time storage capacity
- runtime `max_header_block_size_bytes` is still constrained by compile-time storage capacity

This is currently intentional and documented, but it is the main reason the H2 storage model is not “fully runtime-sized”.

#### 2. `serval-server/h2/server.zig` still uses large fixed owner capacities

Important remaining fixed-capacity storage includes:

- connection read buffer sizing constants
- frame buffer sizing constants
- `pending_payload_storage`
- `upgrade_body_buf`
- `upgrade_header_block_storage`
- `H2ResponseWriter.header_block_buf`

This code is no longer confused about ownership, but it is still firmly designed around fixed compile-time capacities.

#### 3. `serval-client/h2/runtime.zig` still uses capacity-bounded decode/runtime paths

Important remaining constraints:

- runtime config is asserted against `h2.frame_payload_capacity_bytes`
- runtime config is asserted against `h2.header_block_capacity_bytes`
- response/trailer header decode helpers still allocate local `fields_buf`
- pending-response handling still assumes bounded header-block capacity

Again, this is not ownership drift anymore. It is a deliberate fixed-capacity runtime design.

#### 4. Proxy h2c upgrade/body paths are still capacity-bounded

`serval-proxy/forwarder.zig` now has explicit owner-managed scratch, but still depends on bounded compile-time capacities for:

- upgrade preamble scratch
- upgrade header-block scratch
- body relay scratch
- outbound frame-header scratch

This is likely acceptable unless the goal is a single normalized runtime-sized H2 storage model across protocol, server, client, and proxy.

## Decision Point

There are now two reasonable end states.

### Option 1: Practical End State

Stop after documenting the remaining intentional capacities.

This means:

- keep bounded helper-local convenience buffers
- keep `serval-h2/limits.zig` as the owner of protocol/helper capacities
- keep validating runtime config against those capacities
- treat the current client/server/proxy design as explicit and maintainable

This is the recommended option unless a real problem still exists.

### Option 2: Fully Normalized Storage Model

Continue until runtime frame/header sizing is less tied to compile-time arrays.

This means:

- redesign some client/server H2 runtime APIs around caller-owned or dynamically-sized frame/header storage
- reduce the number of places where runtime config is validated against fixed compile-time protocol/helper capacities
- potentially move more storage ownership outward from `serval-server/h2/server.zig` and `serval-client/h2/runtime.zig`
- possibly introduce a cleaner distinction among:
  - protocol wire limits
  - owner-local default capacities
  - caller-owned runtime scratch

This is achievable, but it is no longer simple cleanup. It is a design choice.

## Suggested Implementation Tracks

### Track 1: Stop Here Cleanly

Estimated effort: 0-1 small slices

Tasks:

1. Update docs to explicitly mark remaining helper-local convenience APIs as convenience-only.
2. Update `serval-h2/limits.zig` comments to clarify that these capacities are an intentional current runtime bound, not accidental drift.
3. Leave the rest unchanged.

Recommended if there is no current bug or operability issue tied to the remaining capacities.

### Track 2: Push One More Layer

Estimated effort: 2-4 focused slices

Tasks:

1. Reduce or externalize remaining server-side response/header scratch in `serval-server/h2/server.zig`.
2. Reduce or externalize remaining client-side response/trailer decode scratch in `serval-client/h2/runtime.zig`.
3. Revisit where `runtime_cfg.max_frame_size_bytes` and `max_header_block_size_bytes` are asserted against compile-time capacities.
4. Decide whether some storage should become caller-owned slices rather than fixed arrays embedded in runtime/connection structs.

Recommended only if the team explicitly wants a more fully parameterized H2 storage model.

## Concrete Open Questions

These questions should be answered before more refactoring:

1. Is a bounded owner-local `serval-h2/limits.zig` capacity acceptable as the stable end state?
2. Do we want explicit caller-owned scratch everywhere practical, or only on the major hot paths?
3. Is there any measured stack, memory, or operational issue remaining in the current H2 paths?
4. Do we want to optimize for API cleanliness now, or for future fully runtime-sized buffers?

If the answer to 1 is “yes” and 3 is “no”, the practical recommendation is to stop.

## Recommended Next Action

Recommended next action:

- do a short documentation-only pass and stop H2 storage refactoring here

Only continue deeper if a new bug, measured memory issue, or clear product requirement depends on removing the remaining fixed-capacity bounds.
