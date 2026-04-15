---
policy_id: serval-agent-contract
version: 1
format: markdown
strictness: production
owner: serval-maintainers
applies_to:
  - "**/*.zig"
  - "**/*.md"
canonical_docs:
  architecture: serval/ARCHITECTURE.md
  roadmap: ROADMAP.md
  plans: docs/plans/
references:
  layering: docs/architecture/layering-and-ownership.md
  component_usage: docs/engineering/component-usage.md
  code_placement: docs/engineering/code-placement.md
  tigerstyle: docs/standards/tigerstyle-serval.md
  tigerstyle_matrix: docs/standards/tigerstyle-rule-matrix.md
  testing: docs/standards/testing-and-verification.md
completion_gate_required: true
---

# AGENTS.md — Serval Coding Agent Contract

> Project: **zzz-fix**
> 
> Domain: production HTTP infrastructure in Zig (servers, proxies, load balancers, gateways, sidecars)

## 0) Non-Negotiable Quality Bar

This repository is **production-grade infrastructure software**.

- No prototypes, no partial implementations, no TODO placeholders.
- Reliability target: “space-shuttle mindset” for correctness, testing, and recovery behavior.
- Follow RFCs, architecture layers, API contracts, and TigerStyle constraints.

If a change weakens safety, correctness, or operability, reject it.

---

## 1) Required Workflow (in order)

1. Read specs and relevant docs (RFCs, plans, module docs, TigerStyle guidance).
2. Implement with explicit assertions, bounded loops, and full error handling.
3. Add exhaustive tests (happy path, edge cases, error paths, resource cleanup).
4. Run build/test commands and verify successful exit codes.
5. Update documentation for touched modules and architecture references.

---

## 2) Architecture and Dependency Rules (must hold)

- Respect layer boundaries; no sideways dependencies.
- Keep “where to route” (strategy) separate from “how to forward” (mechanics).
- Keep shared types in the lowest valid layer (usually `serval-core`).
- Use Serval components consistently (no raw substitutes at higher layers).

Canonical architecture doc:
- `serval/ARCHITECTURE.md`

Detailed references moved to:
- `docs/architecture/layering-and-ownership.md`
- `docs/engineering/component-usage.md`
- `docs/engineering/code-placement.md`

---

## 3) Command Canon

- Build: `zig build`
- Full tests: `zig build test`
- Focused suites (as needed):
  - `zig build test-lb`
  - `zig build test-router`
  - `zig build test-health`
  - `zig build run-lb-example`
  - `zig build run-router-example`

Compiler path:
- `/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig`

---

## 4) Hard Engineering Rules

- No `catch {}`.
- No unbounded loops.
- Assertions in every non-trivial function (~2/function: pre + post/invariant).
- Prefer explicit bounded integer types (`u32`, `u64`, etc.); avoid `usize` unless required (e.g., slice indexing).
- No implicit defaults where behavior matters.
- Every resource has cleanup (`defer`/`errdefer`).
- Use existing module constants/utilities (especially `serval-core.config` and `serval-core.time`).

TigerStyle and testing details:
- `docs/standards/tigerstyle-serval.md`
- `docs/standards/tigerstyle-rule-matrix.md` (S1-S7, P1-P4, C1-C5, Y1-Y6 definitions)
- `docs/standards/testing-and-verification.md`

---

## 5) Rejection Criteria

Reject changes that include **any** of the following:

- Missing error handling
- Unbounded loops / no timeout / no max iterations
- Resource leaks
- Missing assertions
- TigerStyle violations (S1-S7, P1-P4, C1-C5, Y1-Y6)
- Missing tests for new/changed logic
- Spec or architecture violations
- TODO comments in production code
- Magic numbers where named constants should exist
- Implicit behavior that should be explicit

---

## 6) Completion Gate (mandatory before claiming completion)

Before saying “ready to commit”, “done”, or “all tests pass”, output:

## Completion Verification

### Files Changed
[List EVERY modified file from git status]

### Each File Reviewed
| File | TigerStyle | Tests | Docs |
|------|-----------|-------|------|
| path/to/file.zig | ✓ S1-S7, P1-P4, C1-C5, Y1-Y6 checked | ✓ or N/A | ✓ or N/A |

### Verification Commands Run
```bash
zig build              # Exit code: 0
zig build test         # Exit code: 0
```

### Checklist
- [ ] All TigerStyle rules checked (not delegated to subagent without verification)
- [ ] All modified files listed and reviewed
- [ ] Tests pass (with actual output shown)
- [ ] README.md updated for affected modules
- [ ] No usize where bounded type would work
- [ ] No catch {}
- [ ] Assertions in every function (~2 per function)

Do not claim completion without this block.

---

## 7) Canonical Documentation Map

Read/update these when relevant:

- `ROADMAP.md`
- `docs/plans/`
- `serval/ARCHITECTURE.md`
- `serval-*/README.md`

New split references from previous AGENTS content:

- `docs/architecture/layering-and-ownership.md`
- `docs/engineering/component-usage.md`
- `docs/engineering/code-placement.md`
- `docs/standards/tigerstyle-serval.md`
- `docs/standards/tigerstyle-rule-matrix.md`
- `docs/standards/testing-and-verification.md`

---

## 8) Format Policy

This file intentionally uses **plain Markdown** (not XML-like tags):

- Better model compatibility across providers (including OpenAI-family models).
- Easier maintenance/review in diffs.
- Less brittle parsing for humans and agents.

If machine parsing is needed later, add a small structured section (YAML frontmatter or JSON appendix) rather than converting the whole policy back to XML.
