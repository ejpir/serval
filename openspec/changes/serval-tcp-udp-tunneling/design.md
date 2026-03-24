## Context

Serval is currently positioned as production HTTP infrastructure, with routing, forwarding, and policy primitives optimized for L7 traffic. Operators who also need generic L4 stream/datagram tunnels must run separate daemons, fragmenting deployment and observability. This change adds first-class TCP and UDP tunneling capabilities (`serval-tcp`, `serval-udp`) while preserving strict bounded-resource behavior and deterministic failure handling expected by Serval’s reliability bar.

Key constraints:
- Maintain existing HTTP behavior unless TCP/UDP features are explicitly enabled.
- Keep strategy decisions outside transport mechanics (`serval-tcp`/`serval-udp` must not embed LB policy logic).
- Reuse `serval-health` as the single health-state source for all transport strategies.
- Refactor existing HTTP-shaped components (`serval-lb`, `serval-prober`) into reusable cores + protocol adapters.
- Ensure all data-path loops are bounded by connection/session lifetime and explicit timeout/capacity guards.
- Treat RFC 9293 (TCP) and RFC 768 (UDP) as normative protocol-semantic baselines, with RFC 8085 used for UDP congestion/robustness operational guidance.

## Goals / Non-Goals

**Goals:**
- Add a TCP tunneling data path that supports accept, connect, bidirectional forwarding, and deterministic shutdown behavior.
- Add a UDP tunneling data path that supports datagram forwarding with bounded session state, configurable session keying, explicit idle expiry, and controlled drop behavior under pressure.
- Extract a protocol-agnostic load-balancing strategy core (starting with round-robin + health-aware filtering) reusable by HTTP/TCP/UDP paths.
- Extract a protocol-agnostic probe scheduler core with protocol adapters (HTTP, TCP connect, UDP configurable probe behavior).
- Preserve backward compatibility for existing HTTP deployments via adapter wrappers in `serval-lb`/`serval-prober`.
- Enforce observability cardinality safety: bounded labels by default, endpoint-level detail in sampled logs or opt-in diagnostics.

**Non-Goals:**
- Building protocol-aware L7 parsing for arbitrary TCP payloads.
- Implementing VPN-specific control planes, mesh key exchange, or dynamic tunnel discovery.
- Replacing existing HTTP routing semantics with a unified cross-protocol policy engine in this change.
- Introducing kernel-bypass or zero-copy optimization work beyond current runtime model.

## Decisions

1. **Separate capabilities and runtime wiring for TCP vs UDP**
   - Decision: Implement `serval-tcp` and `serval-udp` as distinct capabilities with separate spec contracts and config sections.
   - Rationale: Stream and datagram semantics differ materially (connection lifecycle, backpressure behavior, ordering guarantees), so explicit separation reduces ambiguity and test gaps.
   - Alternative considered: single `serval-tunnel` capability with protocol switch; rejected due to conflated requirements and hidden protocol-specific edge cases.

2. **Extract shared LB strategy core from `serval-lb`**
   - Decision: Split current LB into protocol-agnostic strategy core (upstream set + `HealthState` + RR selection) and HTTP adapter preserving existing handler API.
   - Rationale: Meets requirement that RR policy must not live in `serval-tcp`/`serval-udp`, while preserving backward compatibility for HTTP users.
   - Alternative considered: reuse `LbHandler` directly in TCP/UDP; rejected because it is currently HTTP hook-shaped (`Request`, `LogEntry`, status-code semantics).

3. **Extract shared probing core from `serval-prober` with protocol adapters**
   - Decision: Keep one scheduler/lifecycle engine (intervals, timeouts, bounded iteration, health updates) and plug protocol adapters:
     - HTTP adapter (existing `2xx` semantics)
     - TCP adapter (connect success/failure)
     - UDP adapter (configurable send/expect or fire-and-observe behavior)
   - Rationale: Existing prober is HTTP request specific; adapters avoid forcing HTTP semantics into L4 while maximizing reuse.
   - Alternative considered: duplicate prober loops per protocol; rejected due to duplicated lifecycle/error/timeout code.

4. **Keep routing strategy decoupled from forwarding mechanics**
   - Decision: Strategy modules choose upstream targets; `serval-tcp` and `serval-udp` implement transport mechanics only.
   - Rationale: Aligns with Serval layering and enables the same strategy policy across HTTP/TCP/UDP.
   - Alternative considered: protocol-specific selection in workers; rejected as layering violation and duplicated policy logic.

5. **Bounded resource model with explicit operator controls**
   - Decision: Require configured maxima for active TCP connections, active UDP sessions, per-path buffers, and timeout controls.
   - Rationale: Prevents unbounded memory/file-descriptor growth and aligns with TigerStyle safety constraints.
   - Alternative considered: adaptive auto-sizing defaults; rejected for non-deterministic behavior under load.

6. **Observability cardinality policy (safe-by-default)**
   - Decision: Metrics labels limited to bounded sets (e.g., listener/protocol/pool/result). High-cardinality endpoint identity remains in sampled logs or opt-in diagnostics mode.
   - Rationale: Avoids cardinality explosions in production TSDB while still allowing troubleshooting.
   - Alternative considered: always include client/upstream endpoint labels in metrics; rejected due to high operational cost.

## Risks / Trade-offs

- **[Risk] Refactoring `serval-lb`/`serval-prober` introduces regressions in existing HTTP behavior** → **Mitigation:** keep adapter compatibility layer + run existing LB/router test suites unchanged.
- **[Risk] UDP session cardinality explosion increases memory pressure** → **Mitigation:** hard `max_sessions`, strict idle expiry, and explicit drop counters/alerts.
- **[Risk] Long-lived TCP tunnels consume descriptors and worker capacity** → **Mitigation:** connection caps, acceptance throttling, and enforced idle/absolute lifetime timeouts.
- **[Risk] Probe adapters create inconsistent health semantics across protocols** → **Mitigation:** define per-adapter success contracts explicitly and test contract matrix.
- **[Trade-off] Strong default bounds may drop traffic sooner during bursts** → **Mitigation:** expose tuning knobs with recommended sizing guidance and telemetry feedback.

## Migration Plan

1. Extract protocol-agnostic LB core from `serval-lb`, then wire HTTP adapter with no external API break.
2. Extract protocol-agnostic probe scheduler from `serval-prober`, then wire HTTP adapter with no external API break.
3. Add TCP/UDP strategy adapters that reuse shared LB core + `serval-health`.
4. Implement `serval-tcp` and `serval-udp` runtime mechanics under opt-in config gates.
5. Add protocol adapter probes for TCP/UDP and integrate with existing health workflow.
6. Add tests (existing HTTP regression + new TCP/UDP conformance and overload behavior).
7. Roll out in canary with conservative limits; rollback by disabling TCP/UDP listener configuration.

Rollback strategy:
- Disable TCP/UDP listener configuration and restart/reload service to return to HTTP-only operation.
- If needed, pin to HTTP-only adapters while keeping extracted cores internal (no config migration required).

## Open Questions

- For UDP probing, should default mode be passive-only (no active probe) unless explicitly configured?
- Should TLS origination defaults for TCP tunnel upstreams prefer strict verification or match current internal-trust defaults?
