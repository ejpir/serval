# TCP/UDP Transport Foundations

This document defines the implementation baseline for TCP/UDP transport work in Serval.

## 1) RFC Compliance Matrix

| Concern | RFC | Requirement for Serval | Verification Target |
|---|---|---|---|
| TCP stream semantics | RFC 9293 | Preserve reliable ordered byte-stream behavior through tunnel relay; honor half-close/full-close transitions deterministically | TCP integration tests: ordered relay, half-close propagation, full-close cleanup |
| UDP datagram semantics | RFC 768 | Preserve datagram boundaries and connectionless forwarding behavior | UDP integration tests: datagram boundary preservation and reply mapping |
| UDP operational robustness | RFC 8085 | Expose explicit overload controls, queue/session bounds, and observable drop behavior | UDP overload tests: bounded drops, counters, and no unrelated-session starvation |

## 2) Architecture Boundaries

Mandatory boundary for this change:

- Strategy/policy (where traffic goes) remains outside transport mechanics.
- `serval-tcp` and `serval-udp` consume strategy outputs and MUST NOT embed load-balancing policy implementation.
- Shared health truth remains in `serval-health`.
- `serval-lb` provides HTTP adapter behavior over reusable protocol-agnostic strategy core.
- `serval-prober` provides HTTP adapter behavior over reusable protocol-agnostic probe scheduler core.

Layer ownership summary:

- **Strategy layer**: upstream selection policy, health-aware filtering, probe scheduling orchestration.
- **Mechanics layer**: TCP byte relay and UDP datagram/session forwarding mechanics.

## 3) Capability Contracts (Frontend + Shared Cores)

Contract summary for current implementation:

- Frontend (`serval-server/frontend`) owns startup preflight and runtime
  orchestration for optional TCP/UDP capabilities.
- TCP runtime (`tcp_runtime.zig`) owns stream mechanics only (accept/connect/
  relay/idle+capacity enforcement).
- UDP runtime (`udp_runtime.zig`) owns datagram/session mechanics only
  (session keying, bounded table, expiry, drops).
- Strategy core (`serval-lb/strategy_core.zig`) remains protocol-agnostic and is
  consumed by HTTP/TCP/UDP adapters.
- Prober scheduler core (`serval-prober/scheduler.zig`) remains protocol-agnostic
  with HTTP/TCP/UDP adapters in `serval-prober/adapters.zig`.

## 4) Observability Cardinality Defaults

To keep production telemetry safe by default:

- Allowed metric labels (bounded): `listener`, `protocol`, `upstream_pool`, `result`.
- Disallowed by default in metrics (high cardinality): raw `client_ip`, `client_port`, full `upstream_addr`.
- Endpoint-level detail goes to sampled logs.
- High-cardinality metrics require explicit opt-in diagnostics mode and short TTL operational guidance.
