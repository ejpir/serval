## Context

Serval currently separates strategy/orchestration from mechanics at the architecture level, but h2 bridge integration still has seam leakage:

- orchestration code in `serval-server` directly inspects and mutates bridge binding-table internals
- fairness/polling policy for upstream actions is partially owned outside the bridge
- generic h2 frontend contains forwarding mechanics that are not consistently owned by `serval-proxy`

These issues are manageable today but increase coupling risk and make future h1/h2 consistency harder.

## Goals / Non-Goals

**Goals**
- Define one explicit forwarding/bridge ownership model that applies to both h1 and h2.
- Keep policy in `serval-server` and mechanics in `serval-proxy`.
- Keep behavior parity (no protocol semantics regression).
- Preserve TigerStyle constraints: bounded loops, explicit error handling, fixed-capacity state.

**Non-Goals**
- Rewriting bridge transport behavior from scratch.
- Changing module layering.
- Introducing dynamic allocation in hot paths.
- Expanding protocol feature scope beyond current supported behavior.

## Decisions

### 1) Adopt unified h1/h2 transport-mechanics contract

Ownership split:

- `serval-server`:
  - connection entry routing
  - hooks + `selectUpstream`
  - request-class policy (gRPC vs non-gRPC)
  - lifecycle orchestration
- `serval-proxy`:
  - h1 forwarding mechanics
  - h2 binding ownership, fairness polling, mapped receive actions
  - upstream session generation handling and rollover behavior

### 2) Encapsulate bridge internals behind proxy APIs

Bridge public API must be sufficient so server does not inspect internals directly.

Target API shape (names illustrative, behavior normative):

- `open_downstream_stream(...) !OpenResult`
- `send_downstream_data(...) !void`
- `cancel_downstream_stream(...) !void`
- `poll_next_action(io, timeout) !ReceiveAction` (fairness owned by proxy)
- `active_binding_count() u16`

### 3) Preserve policy/mechanics split for gRPC completion rules

- Request classification remains centralized in `serval-grpc`.
- gRPC completion enforcement remains explicit policy in orchestration adapter layer.
- Generic h2 transport mechanics remain protocol-agnostic in proxy bridge core.

### 4) Enforce TigerStyle + Zig-idiomatic constraints at seam

For seam-facing APIs and adapters:

- assertions for non-trivial preconditions/invariants
- bounded loop/scan behavior with explicit caps/timeouts
- explicit integer widths for state/counters/ids where practical
- no `catch {}`
- explicit lifecycle start/stop/deinit for long-lived background tasks

## Contract Flow

```text
                Strategy / Orchestration (serval-server)
          (hooks, selectUpstream, lifecycle, policy decisions)
                                 │
                                 │  stable mechanics interface
                                 ▼
                    Mechanics (serval-proxy / forwarder)
            h1 request forwarding   +   h2 stream bridging/polling
                                 │
                                 ▼
                  Infrastructure (serval-client/session pool)
```

## Risks / Trade-offs

- [Behavior drift while moving ownership] -> lock parity tests before and after seam changes.
- [Over-abstracting too early] -> keep API minimal and transport-driven.
- [Regression in h2 fairness or close/reset handling] -> preserve existing integration and churn coverage; add targeted seam tests.
- [Mixing policy with transport] -> keep gRPC status rules in adapter policy layer, not bridge core.

## Migration Plan

1. Introduce/complete proxy-owned poll API for mapped upstream actions.
2. Switch server adapters to use bridge API only (remove direct table introspection).
3. Align generic h2 forwarding mechanics with proxy ownership model used by h1.
4. Add conformance checks and tests for boundary enforcement.
5. Update architecture and module docs.

Rollback:
- Re-enable previous adapter path behind guarded commits while retaining new API additions.
- Keep behavior tests as acceptance gate for re-merge.

## Open Questions

- Should h2 polling API expose optional upstream-index hinting or remain fully bridge-owned for fairness?
- Which minimal seam contract should be public export vs internal module API?
- Do we require a lightweight architecture conformance script check that blocks direct server access to bridge internals?
