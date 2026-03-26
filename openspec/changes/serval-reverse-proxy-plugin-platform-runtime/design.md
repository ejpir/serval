## Context

The prior `serval-reverse-proxy-plugin-platform` change established behavior contracts, but runtime code paths are still fragmented across existing proxy/server modules without a dedicated orchestrator owner. Serval needs a concrete implementation slice that translates admitted canonical IR into immutable, generation-based runtime snapshots with atomic activation and safe draining semantics.

Constraints:
- Must preserve Serval architecture boundaries (strategy routing in router/lb, forwarding mechanics in proxy).
- Must satisfy AGENTS.md TigerStyle constraints (bounded loops, explicit errors, assertions, no hidden defaults).
- Must be implementable incrementally without breaking current runtime behavior.

Stakeholders:
- Runtime maintainers (correctness, rollback safety)
- Filter/plugin implementers (stable runtime contract)
- Operators (deterministic apply diagnostics)

## Goals / Non-Goals

**Goals:**
- Introduce canonical IR runtime types as the single orchestrator input.
- Introduce a `serval-reverseproxy` orchestrator that owns generation lifecycle (`build`, `admit`, `activate`, `drain`, `retire`).
- Provide atomic generation swap with deterministic no-op behavior on admission/activation failure.
- Provide initial rollback/safe-mode control flow and observability events for lifecycle failures.
- Land tests that prove lifecycle invariants before adding full plugin transform mechanics.

**Non-Goals:**
- Dynamic plugin ABI loading.
- Full request/response transform execution engine.
- DSL parser implementation (this slice consumes admitted canonical IR, not source DSL).
- WebSocket/CONNECT body transform semantics.

## Decisions

1. **Create a new `serval-reverseproxy` module for orchestrator ownership**
   - **Why:** Keeps orchestration separate from low-level forwarding mechanics and aligns with requirement ownership.
   - **Alternative considered:** Extend `serval-proxy` directly with lifecycle state machine.
   - **Why not alternative:** Blurs module ownership and increases coupling between apply control plane and data-plane forwarding code.

2. **Use immutable runtime snapshots with generation IDs and atomic active pointer swap**
   - **Why:** Fast-path requests read a stable snapshot without mutation; apply pipeline can fail safely before swap.
   - **Alternative considered:** In-place mutation of route/pool/plugin tables.
   - **Why not alternative:** Harder to guarantee consistency and rollback; increases risk of partial activation.

3. **Model apply lifecycle as explicit enum-backed state machine with transition functions**
   - **Why:** Makes transition failures observable and testable; enforces deterministic stage ownership.
   - **Alternative considered:** Ad-hoc procedural apply sequence.
   - **Why not alternative:** Hidden implicit transitions and weak diagnostics.

4. **Defer advanced rollback automation but provide explicit hooks now**
   - **Why:** Allows immediate safe failure handling while keeping implementation scope bounded.
   - **Alternative considered:** Implement full guard-window threshold engine in this slice.
   - **Why not alternative:** Too large for first runtime slice; risks delayed delivery of core lifecycle safety.

5. **Add focused invariants tests before broader integration**
   - **Why:** Proves core lifecycle semantics early: admission-failure no-op, atomic activate, drain-to-retire progression.
   - **Alternative considered:** Wait for full end-to-end integration tests.
   - **Why not alternative:** Delays detection of lifecycle invariants regressions.

## Risks / Trade-offs

- **[Risk] New module boundary causes temporary duplication with existing proxy wiring** → **Mitigation:** keep initial orchestrator API minimal and add adapter shims where necessary.
- **[Risk] Snapshot retention during draining increases memory usage under long-lived requests** → **Mitigation:** enforce bounded drain timeout policy and explicit retirement diagnostics.
- **[Risk] Partial rollout without full transform engine may appear incomplete** → **Mitigation:** clearly scope this change as runtime foundation and keep transform execution in follow-on slices.
- **[Risk] Concurrency bugs in generation swap** → **Mitigation:** use atomic pointer/reference swap and deterministic unit tests for concurrent read/apply paths.

## Migration Plan

1. Add canonical IR types and validator entry points without changing active runtime wiring.
2. Introduce orchestrator with lifecycle states and snapshot model behind a controlled integration path.
3. Wire existing reverse-proxy assembly through orchestrator build/admit/activate path.
4. Enable draining/retirement for prior generations with bounded timeout policy.
5. Validate with unit/integration tests, then switch default runtime assembly path.
6. Keep rollback path to previous stable generation and preserve ability to disable orchestrator integration if needed during rollout.

## Open Questions

- Which module should host shared IR validation error taxonomy (`serval-core` vs `serval-reverseproxy`)?
- Should guard-window policy configuration live in orchestrator config now or in a follow-up operations slice?
- What is the minimal stable public API for other modules to read active generation metadata without exposing internals?
