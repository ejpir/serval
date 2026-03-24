---
name: zig-idiomatic-tigerstyle
description: Review and refactor Zig code to be more idiomatic while preserving TigerStyle safety rules and Serval architecture constraints. Use for code quality reviews, cleanup PRs, and pre-merge hardening.
compatibility: Requires Zig project with AGENTS.md quality gates and serval-* layering docs.
---

# Zig Idiomatic + TigerStyle Skill

Use this skill when you need to improve Zig code quality without weakening safety, reliability, or Serval architecture boundaries.

## Outcomes

- Improve Zig idiomaticity (clarity, cohesion, reduced duplication)
- Preserve TigerStyle constraints (assertions, bounded loops, explicit errors, no leaks)
- Preserve Serval architecture/layering/component usage rules
- Produce test-backed, reviewable changes

## Inputs

- Target files/modules (e.g. `serval-websocket/*`)
- Current behavior constraints (must-not-break list)
- Test commands to run

## Mandatory Read Order

1. `AGENTS.md`
2. `serval/ARCHITECTURE.md`
3. Modified module README(s) (e.g. `serval-websocket/README.md`)
4. Target source files + tests

Do not refactor until all four are read.

## Review Rubric (Score Each 1-10)

1. **API minimalism**
   - Small public surface
   - Internal helpers private
   - No leaked internal mechanics
2. **Cohesion and function size**
   - One responsibility per function
   - Keep functions short and auditable
3. **Control-flow clarity**
   - Prefer `switch` for enum/classification/state
   - Avoid repeated condition chains
4. **Error semantics**
   - Precise error names (`Missing`, `Format`, `Range`)
   - Explicit mapping at module boundaries
5. **State modeling**
   - Explicit enums/unions over ad-hoc booleans
   - Transition rules centralized
6. **Safety invariants**
   - ~2 assertions/function where logic exists
   - Bounded loops, no recursion, no `catch {}`
7. **Data/alloc discipline**
   - Zero alloc in hot paths
   - Explicit integer widths; `usize` for indexing
8. **Test quality**
   - Table-driven grammar/state matrices
   - Error-path coverage
   - Boundary + fuzz/property tests for parsers/state machines
9. **Layer correctness (Serval Z1-Z4)**
   - No sideways deps
   - Correct type ownership
   - Component usage rules followed
10. **Docs alignment**
   - README + architecture docs match behavior

## Refactor Playbook

Apply in this order:

1. **De-duplicate internal logic**
   - Extract private helper functions for repeated parsing/validation/timeout logic.
2. **Centralize state transitions**
   - Add small internal state machine helpers where session/protocol flows are dense.
3. **Narrow interfaces**
   - Keep exports stable and minimal.
4. **Normalize error taxonomy**
   - Remove ambiguous aliases unless required for compatibility boundary mapping.
5. **Convert repetitive tests to matrices**
   - Prefer table-driven test cases for grammar and classification behavior.
6. **Add parser hardening tests**
   - Add bounded fuzz/property tests for parser/state-machine modules.

## Hard Constraints

- No behavior changes unless explicitly requested.
- No TODOs, no deferred fixes.
- No unbounded loops.
- No runtime allocation added to hot path.
- No new layer violations.

## Verification Commands

Run after edits:

```bash
zig build
zig build test
```

Also run affected focused suites (examples):

```bash
zig build test-websocket
zig build test-grpc
zig build test-integration-h2c-mixed-grpc-nongrpc-same-conn
```

## Required Output Template

Use this exact structure:

```markdown
## Zig Idiomatic + TigerStyle Review

### Scope
- [files reviewed]

### Scorecard
| Dimension | Score (1-10) | Notes |
|---|---:|---|
| API minimalism |  |  |
| Cohesion/function size |  |  |
| Control-flow clarity |  |  |
| Error semantics |  |  |
| State modeling |  |  |
| Safety invariants |  |  |
| Data/alloc discipline |  |  |
| Test quality |  |  |
| Layer correctness |  |  |
| Docs alignment |  |  |

### Refactors Applied
- [change]

### Tests Run
- `zig build` (exit: )
- `zig build test` (exit: )
- [focused commands] (exit: )

### Remaining Risks
- [none or explicit]
```

## Project-Specific Notes (Serval)

- `serval-websocket` stays Layer 1 protocol-only.
- Session lifecycle belongs in `serval-server/websocket`.
- Tunnel relay belongs in `serval-proxy`.
- Keep RFC 6455 validation fail-closed by default.
