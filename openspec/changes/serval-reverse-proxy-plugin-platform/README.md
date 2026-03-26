# serval-reverse-proxy-plugin-platform (OpenSpec Change)

This change includes both human-readable and machine-readable rollout threshold definitions:

- `threshold-profiles.md` — explanatory documentation and operator guidance
- `threshold-profiles.json` — machine-readable profile data for tooling/runtime integration

## Sync Policy

When updating thresholds:

1. Update `threshold-profiles.json` first (source for automation).
2. Update `threshold-profiles.md` to match values and rationale.
3. Ensure profile names and trigger keys remain aligned across both files.
4. Include both files in review to prevent semantic drift.

## Suggested Review Check

- Profile parity (`canary`, `production`)
- Guard-window parity
- Trigger threshold parity
- Hard-stop and safe-mode parity
- Baseline calculation parity

If parity fails, treat the change as incomplete.

## PR Build Plan and Dependency Graph

The implementation plan is staged so that canonical IR + runtime orchestration land before plugin mechanics and DSL frontend hardening.

### PR Sequence (summary)

1. PR1: Reverseproxy runtime orchestrator skeleton
2. PR2: Canonical IR + schema contracts
3. PR3: Admission engine core (structure + references)
4. PR4: Ordering resolver + chain composition
5. PR5: Atomic activation + drain/retire lifecycle
6. PR6: Rollback + guard window + safe mode
7. PR7: Filter SDK v1 surface + `verifyFilter`
8. PR8: Policy plugin path (header phases)
9. PR9: Streaming transform engine v1 (identity bodies)
10. PR10: Framing correctness + protocol terminal behavior
11. PR11: DSL parser + semantic resolver
12. PR12: DSL↔IR equivalence + ops tooling
13. PR13: Docs + guides + error catalog

### Dependency graph

```text
PR1 -> PR2 -> PR3 -> PR4 -> PR5 -> PR6
               \            \        \
                \            \        -> PR12 -> PR13
                 \            -> PR8 -> PR9 -> PR10 -> PR13
                  -> PR11 ----/

PR7 -> PR8
PR7 -> PR9
```

Expanded view (for planning):

```text
[PR1] Orchestrator Skeleton
   │
   ├──> [PR2] Canonical IR
   │       └──> [PR3] Admission Core
   │               └──> [PR4] Ordering + Chain Merge
   │                       ├──> [PR8] Policy Plugin Header Path
   │                       │       └──> [PR9] Streaming Transform Engine
   │                       │               └──> [PR10] Framing + h1/h2 Terminal Correctness
   │                       ├──> [PR11] DSL Parser/Semantic
   │                       │       └──> [PR12] DSL↔IR Equivalence + Ops Tooling
   │                       └──> [PR12] DSL↔IR Equivalence + Ops Tooling
   │
   └──> [PR5] Atomic Activate/Drain
           └──> [PR6] Rollback/Guard/SafeMode

[PR7] Filter SDK + verifyFilter
   ├──> [PR8]
   └──> [PR9]

[PR10] + [PR12] + [PR6] -> [PR13] Docs/Guides/Error Catalog
```

### Suggested milestone cuts

- Milestone A: PR1–PR6 (runtime orchestration + safe rollout)
- Milestone B: PR7–PR10 (custom plugin execution + streaming transforms)
- Milestone C: PR11–PR13 (DSL-first UX + docs finalization)

## Verification Planning

See `verification-plan.md` for conformance, protocol correctness, stress/resilience, and tooling parity test planning tied to tasks 9.1–9.3.
