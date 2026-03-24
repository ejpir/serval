## Why

Serval currently focuses on HTTP infrastructure, leaving teams to operate separate tooling when they need generic TCP/UDP forwarding and encrypted overlay transport. Adding first-class tunneling support now enables Serval to consolidate edge transport use cases while keeping reliability, policy, and observability in one production-grade runtime.

## What Changes

- Introduce a new **serval-tcp** capability for L4 stream tunneling (TCP ingress/egress, bidirectional forwarding, lifecycle controls, and health-aware target selection).
- Introduce a new **serval-udp** capability for datagram tunneling (session mapping, idle expiry, bounded buffers, and safe forwarding semantics).
- Extract protocol-agnostic strategy/probing cores from existing HTTP-oriented modules so TCP/UDP can reuse RR+health and probe scheduling without embedding HTTP semantics.
- Add explicit transport configuration contracts for TCP and UDP listeners, upstream targets, timeout/limit controls, and observability metadata.
- Define failure handling and recovery requirements for tunnel setup, forwarding errors, backend unavailability, and resource exhaustion.
- Define metrics/logging requirements for tunnel acceptance, bytes/packets forwarded, drops, errors, and session churn.
- Add compatibility and migration requirements so HTTP deployments remain unaffected unless TCP/UDP features are enabled.
- Anchor transport semantics and validation to IETF standards: TCP (RFC 9293), UDP (RFC 768), and UDP usage guidance for congestion/robustness (RFC 8085).

## Capabilities

### New Capabilities
- `serval-tcp`: Production-grade TCP tunneling with bounded resource usage, deterministic failure behavior, and health-aware upstream routing.
- `serval-udp`: Production-grade UDP tunneling with bounded session state, datagram-safe forwarding semantics, and explicit timeout/drop behavior.

### Modified Capabilities
- None.

## Impact

- Affected code areas: transport listeners, forwarding pipeline, config validation, metrics/logging, and integration test harnesses.
- Public surface impact: new configuration sections and runtime endpoints for TCP/UDP tunnel services.
- Operational impact: additional capacity planning dimensions (connection/session limits, buffer sizing, timeout budgets).
- Dependencies/systems: socket handling and event loop integration for stream/datagram transport; no mandatory changes for existing HTTP-only deployments.
