## Overview

Design a production-grade plugin platform for a Serval reverse proxy with Caddy-like extensibility while preserving TigerStyle safety constraints and Serval layering.

Key principle: **policy plugins and transform plugins are not the same class of concern**.

- Policy/decision plugins can map cleanly to existing hooks.
- Full body transforms require a new explicit streaming mechanics contract.

---

## Architecture Placement

```text
Layer 5 (Orchestration):   serval-server
        │  (hook lifecycle, route selection orchestration)
        ▼
Layer 4 (Strategy):        serval-router / serval-lb
        │  (vhost/path/backend selection)
        ▼
Layer 3 (Mechanics):       serval-proxy + transform pipeline engine
        │  (streaming forwarding + body transform execution)
        ▼
Layer 2/1:                 serval-client / socket / h1 / h2
```

Why this split:
- Route/vhost selection remains strategy.
- Transform execution is forwarding mechanics.

---

## Config DSL Strategy (v2-now on canonical IR)

Serval adopts the ergonomic config DSL immediately, but only as a frontend. Runtime semantics are owned by one canonical schema/IR and one admission engine.

```text
DSL source (author-facing)
   │
   ▼
Parser -> AST -> semantic resolver -> canonical IR
                                       │
                                       ▼
                         admission/order/budget checks
                                       │
                                       ▼
                               atomic runtime activation
```

Design rules:
- DSL and JSON/schema inputs MUST compile to the same canonical IR.
- No semantic drift across input formats.
- No advanced language features in initial DSL slice (no macros/functions/conditionals).
- Safety-critical behavior remains explicit (no implicit fail-policy/budget defaults).

---

## End-to-End Composition Model

```text
Connection
   │
   ▼
[Global chain]
  - baseline WAF/policy
  - global observability filter
   │
   ▼
[Virtual host + route selection]
  host/path -> route/pool
   │
   ▼
[Route chain]
  - auth/policy
  - cache lookup tap
  - request transforms
   │
   ▼
[Forwarding mechanics]
   │
   ▼
[Response chain]
  - response transforms
  - cache store tap
  - completion/logging
```

---

## Plugin Classes

1. **Policy plugins** (hooks): inspect, mutate headers, reject/short-circuit.
2. **Transform plugins** (new mechanics contract): streaming body mutation.
3. **Tap plugins** (cache/metrics): observe stream and emit side effects under bounded budgets.

---

## Filter SDK Boundary

Users write Zig code against `serval-filter-sdk`, not raw handler/server internals.

```text
┌───────────────────────────────────────────────┐
│                Serval Internals               │
│ sockets, pools, parser/runtime internals      │
└───────────────────┬───────────────────────────┘
                    │ adapter boundary
┌───────────────────▼───────────────────────────┐
│              Filter SDK Surface               │
│ FilterContext, HeaderView, ChunkView, Emit    │
└───────────────────┬───────────────────────────┘
                    │
┌───────────────────▼───────────────────────────┐
│             User Filter (Zig code)            │
└───────────────────────────────────────────────┘
```

SDK exports only safe context metadata + bounded emit APIs.

---

## Streaming Transform Contract

Per request/stream plugin instance:
- `onRequestHeaders`
- `onRequestChunk`
- `onRequestEnd`
- `onResponseHeaders`
- `onResponseChunk`
- `onResponseEnd`

Body mutation is output-driven via bounded `EmitWriter`.
Input slices are read-only.

### Backpressure rule

```text
upstream read -> plugin chain -> downstream write readiness
                     │
                     └─ if output blocked: stop reads, wait writable
```

No unbounded queues.

---

## Response Stream State Machine

```text
[R0 START]
   │ recv upstream headers
   ▼
[R1 READ_UPSTREAM_HEADERS]
   │
   ▼
[R2 APPLY_RESPONSE_HEADERS]
   ├─ reject/replace ─► [R_REJECT_OR_REPLACE] ─► [R7 COMPLETE]
   └─ continue
       ▼
[R3 PLAN_FRAMING]
   │
   ▼
[R4 SEND_DOWN_HEADERS]
   │
   ▼
[R5 STREAM_LOOP] ──backpressure──┐
   │ end_stream                  │
   ▼                             │
[R6 FLUSH_FINALIZERS]────────────┘
   │
   ▼
[R7 COMPLETE]
```

### Stream loop micro-states

```text
[R5.1 READ_INPUT_CHUNK] -> [R5.2 RUN_PLUGIN_CHAIN] -> [R5.3 WRITE_OUTPUT]
           ^                                                |
           |-------------- on write blocked ----------------|
```

---

## Framing and Header Correctness

If transformed body length is no longer fixed:
- h1: remove/ignore `Content-Length`, use chunked transfer semantics
- h2: stream DATA frames; no CL dependency

Forbidden mutations:
- h2 pseudo headers
- hop-by-hop headers
- unsafe framing headers except through runtime framing plan

---

## Failure Model

Per plugin policy:
- `fail_open` => sticky bypass plugin for remainder of stream when safe
- `fail_closed` => terminate request/stream with protocol-correct behavior

Terminal behavior:
- if headers not sent: send explicit error response
- if mid-body: h1 close connection, h2 reset stream

### Failure flow

```text
error
  │
  ▼
[CLASSIFY]
  ├─ plugin + fail_open   -> sticky bypass
  ├─ plugin + fail_closed -> terminate
  ├─ upstream read error  -> 502/reset
  └─ downstream write err -> close/reset
  │
  ▼
[COMPLETE + metrics/log/trace]
```

---

## Manifest and Ordering

Plugin manifest fields include:
- `id`, `version`, `enabled`
- `phases`, `protocols`, `capabilities`
- `failure_policy`, `sticky_bypass_on_fail`
- per-plugin budgets
- ordering constraints (`before`, `after`, `priority`)

### Ordering resolver

```text
Build DAG from before/after edges
  │
  ▼
Kahn topological sort
ready queue tie-break: priority, then id
  │
  ├─ cycle => reject
  ▼
Deterministic ordered chain
```

---

## Global + Route Chain Merge

```text
effective_chain = (global_enabled - route_disables) + route_additions
       │
       ▼
validate -> order -> admit -> atomically activate
```

Mandatory plugin classes (e.g., baseline security) cannot be disabled by route policy unless explicitly waived.

---

## Admission Pipeline

```text
[Load candidate]
   │
   ▼
[Structure checks]
   │
   ▼
[Capability compatibility]
   │
   ▼
[Budget checks]
   │
   ▼
[Ordering DAG checks]
   │
   ▼
[Framing/header safety checks]
   │
   ├─ FAIL -> reject, keep active config
   ▼
 PASS -> atomic activation
```

No partial activation.

---

## Hard Caps (Global)

Representative caps (values finalized in implementation design):
- max plugins per chain
- max mutators per chain
- max plugin state bytes/stream
- max total transform memory/stream
- max emit chunks/input
- max expansion ratio
- max output bytes/stream
- max CPU/finalize budget
- max backpressure wait

Admission rejects plugin manifests exceeding hard caps.

---

## Observability Contract

Required counters per plugin/route:
- fail-open / fail-closed totals
- bypass active streams
- expansion/cpu budget violations
- backpressure timeouts
- chain aborts

Required diagnostics tags:
- plugin id
- phase
- route id
- request/connection/stream identifiers

---

## Config DSL (Initial Surface)

Initial DSL provides ergonomic declarative blocks for listeners, pools, plugins, and routes while preserving explicit semantics.

```text
proxy "edge" {
  listener "https-main" { ... }
  pool "api" { upstream "10.0.1.10:8080" }
  plugin "security.scrub.v1" { phases = [...], fail_policy = "fail_closed" }
  route "api" { host = "api.example.com", to_pool = "api", chain = [...] }
}
```

Constraints:
- DSL supports bounded literals and units (`ms`, `KiB`, ratio).
- DSL compilation emits canonical IR equivalent to schema input.
- Advanced language constructs are deferred.

---

## Developer and Operator UX

### Author flow

```text
init -> code -> filter-check -> filter-test -> admit --dry-run -> apply
```

### Operator flow

```text
admit --dry-run -> atomic apply -> monitor -> rollback (if needed)
```

Both flows rely on the same canonical error catalog and admission report format.

---

## Rollout and Rollback Decision Matrix

| Failure Point | Example Signal | Auto Rollback | Immediate Action |
|---|---|---|---|
| Build/compile | DSL parse or unresolved reference | N/A (not activated) | reject candidate, keep active |
| Admission | ordering/budget/policy failure | N/A (not activated) | reject candidate, keep active |
| Post-activation critical regression | 5xx, chain abort, fail-closed spike | Yes | rollback to last-known-good |
| Draining timeout | old generation never retires | Usually no | force-retire per policy + alert |
| New generation invariant failure | critical runtime fault | Yes | immediate rollback + freeze applies |

Guard-window model after activation:

```text
[Activated Gn+1]
      │
      ▼
[Guard Window Monitor]
  ├─ healthy --------------------► [Stable Gn+1]
  ├─ critical breach ------------► [Auto Rollback to Gn]
  └─ monitor/rollback failure ---> [Safe Mode + Page]
```

Safe mode expectations:
- freeze new applies
- preserve mandatory baseline security controls
- page operators for manual intervention

---

## Risks and Mitigations

1. **Complexity explosion from over-composition**
   - Mitigation: strict chain and mutator caps.
2. **Framing/protocol correctness regressions**
   - Mitigation: explicit framing planner + protocol-specific invariants.
3. **Latency regressions from expensive plugins**
   - Mitigation: per-chunk CPU budgets + observability + fail policy.
4. **Operational surprises at rollout**
   - Mitigation: dry-run admission + atomic activation + required rollback target.

---

## Execution Order (Recommended)

Delivery sequencing should preserve foundation-first dependencies:

```text
Foundation:    PR1-PR6   (orchestrator, IR, admission, activation/rollback)
Plugins:       PR7-PR10  (SDK, policy path, streaming transforms, protocol correctness)
DSL + UX:      PR11-PR13 (DSL frontend, equivalence tooling, docs)
```

Dependency shape:
- Orchestrator + canonical IR + admission land before transform mechanics.
- Filter SDK lands before policy/transform plugin integration.
- DSL frontend compiles to canonical IR and reuses existing admission/runtime path.
- Final docs/guides land after runtime and DSL behavior are stable.

---

## Deferred Work

- Dynamic plugin ABI loading
- WS/CONNECT payload transforms
- Full decode/transform/re-encode content-coding stacks
- Advanced DSL language features (macros/functions/conditionals)
