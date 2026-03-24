# Layering and Type Ownership Reference

This document contains the detailed layering constraints previously embedded in `AGENTS.md`.

## Layer Stack

0. **foundation**
   - `serval-core`
   - Shared types/config/errors/context/logging

1. **protocol**
   - `serval-http`, `serval-net`, `serval-tls`, `serval-h2` (when enabled)
   - Protocol parsing/framing and socket/TLS primitives

2. **infrastructure**
   - `serval-pool`, `serval-metrics`, `serval-tracing`, `serval-otel`, `serval-health`, `serval-prober`, `serval-client`
   - Reusable infra, handler-agnostic services

3. **mechanics**
   - `serval-proxy`
   - Forwarding mechanics (I/O strategy, timing, connection behavior)

4. **strategy**
   - `serval-lb`, `serval-router`, `serval-forward` (future)
   - Upstream selection/routing decisions

5. **orchestration**
   - `serval-server`, `serval`, `serval-cli`
   - Composition, lifecycle, accept-loop orchestration

## Hard Rules

- **No sideways deps:** modules in same layer do not depend on each other.
- **High → low only:** higher layers depend on lower layers only.
- **Strategy vs mechanics:** routing decisions remain separate from forwarding implementation.
- **Type ownership:** place shared types in the lowest layer that needs them.

## Core Type Placement

- `Upstream`, `Request`, `Response`, `Context`: `serval-core`
- Proxy-internal result/error types: `serval-proxy`

## Implementation Triggers

- New upstream selection algorithm → layer 4 strategy module.
- New forwarding capability → layer 3 (`serval-proxy`).
- New protocol support → layer 1 protocol module.
- New reusable cross-cutting concern → layer 2 infrastructure module.

## Canonical Architecture

The full request flow and module API contracts live in:
- `serval/ARCHITECTURE.md`
