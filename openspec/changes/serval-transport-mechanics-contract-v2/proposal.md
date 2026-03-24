## Why

Serval’s layer boundaries are mostly healthy, but the current h2 bridge path exposes mechanics internals to orchestration code (notably direct binding-table access from `serval-server`).

This creates avoidable coupling and makes it harder to keep h1 and h2 forwarding behavior contract-consistent. We want one explicit transport-mechanics contract shape across both protocols:

- server/orchestration decides policy and lifecycle
- proxy/mechanics owns forwarding and bridge internals
- client/infrastructure owns reusable upstream connection/session runtime

## What Changes

- Define a unified mechanics contract for both h1 and h2 paths.
- Move h2 binding scan/fairness/internal mutation behind proxy-owned APIs.
- Align generic h2 frontend forwarding mechanics with existing h1 forwarder ownership model.
- Document strict ownership boundaries and policy/mechanics split.
- Add conformance tests that assert server does not depend on bridge internals.

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

## Capabilities

### New Capabilities
- `transport-mechanics-contract`: explicit shared h1/h2 forwarding contract and ownership boundaries.
- `h2-bridge-api-encapsulation`: bridge polling/fairness/mutation through proxy APIs, not server internals.

### Modified Capabilities
- `h2-bridge-operations`: preserve behavior while enforcing server↔proxy boundary.
- `generic-h2-forwarding`: align mechanics ownership with forwarder conventions used by h1.

## Impact

- Affected modules:
  - `serval-server` (orchestration adapters)
  - `serval-proxy` (h1/h2 mechanics APIs)
  - `serval-client` (no ownership change; integration touch only)
- Affected docs:
  - `serval/ARCHITECTURE.md`
  - `docs/architecture/h2-bridge.md`
  - `serval-server/README.md`
  - `serval-proxy/README.md`
- No layer ownership changes.
