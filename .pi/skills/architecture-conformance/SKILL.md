---
name: architecture-conformance
description: Audits Serval module exposure, layer dependencies, and handler hook passthrough contracts against AGENTS.md and serval/ARCHITECTURE.md.
---

# Architecture Conformance (Serval)

Use this skill when you need to verify that module boundaries, exports, and hook passthrough behavior stay aligned with Serval architecture and handler contracts.

## Mandatory Read Order

1. `AGENTS.md`
2. `serval/ARCHITECTURE.md`
3. Target module `README.md`
4. Target `mod.zig`, source files, and tests

Do not propose refactors before these are read.

## What This Skill Checks

### 1) Layer dependency correctness (Z1)
- Builds an import edge graph from `@import("serval-*")` and `@import("serval")`.
- Verifies each edge against `policy/layers.json`.
- Flags:
  - upward dependencies (lower layer importing higher layer)
  - same-layer dependencies not explicitly allowed in policy

### 2) Module exposure hygiene
- Audits `serval*/mod.zig` exports.
- Flags likely internal leaks (`internal` paths/names, underscored exports).
- Keeps public facade intentional and minimal.

### 3) Hook passthrough conformance (Z4)
- Finds generic wrapper types (e.g. `ShieldedHandler(comptime Inner: type)`).
- Verifies wrapper exposes expected handler hooks and delegates correctly via `@hasDecl(Inner, ...)` + `self.inner.<hook>(...)`.
- Verifies `selectUpstream` delegation exists.

### 4) Cross-module reuse enforcement (Z2)
- Flags direct usage of lower-level replacements when project APIs exist.
- Enforces policy from `policy/reuse_rules.json` with required rule classes:
  - `forbid` (hard-ban replacements)
  - `prefer` (migration guidance + fail in current mode)
  - `duplicate_api` (prevent redeclaring shared helpers)
- Legacy schema key `rules` is rejected; policy must use the new schema.
- Supports explicit per-file exceptions in `allow_paths` for audited edge cases.
- Supports strict mode (`check_reuse.sh --strict`) for broader policy (e.g. raw socket primitives, `std.debug.print` outside CLI/core).

## Commands

Run all checks:

```bash
./.pi/skills/architecture-conformance/scripts/check_layers.sh
./.pi/skills/architecture-conformance/scripts/check_exports.sh
./.pi/skills/architecture-conformance/scripts/check_hooks.sh
./.pi/skills/architecture-conformance/scripts/check_reuse.sh
```

Discovery audit (non-blocking inventory for missed reinventions):

```bash
./.pi/skills/architecture-conformance/scripts/audit_reinvention_candidates.sh
```

Target specific modules:

```bash
./.pi/skills/architecture-conformance/scripts/check_layers.sh serval-waf serval-server
./.pi/skills/architecture-conformance/scripts/check_exports.sh serval-waf
./.pi/skills/architecture-conformance/scripts/check_hooks.sh serval-waf
./.pi/skills/architecture-conformance/scripts/check_reuse.sh serval-waf
./.pi/skills/architecture-conformance/scripts/check_reuse.sh --strict
```

Verification build/test:

```bash
zig build
zig build test
```

## Output Contract

Use this exact report shape:

```markdown
## Architecture Conformance Report

### Scope
- [modules/files checked]

### Violations
| Severity | Rule | From | To | Location | Message |
|---|---|---|---|---|---|
| CRITICAL/MAJOR/MINOR | Z1/Z2/Z4 | module | module | file:line | detail |

### Summary
- Total violations: N
- Critical: N
- Major: N
- Minor: N
- Result: PASS/FAIL

### Commands Run
- `./.pi/skills/architecture-conformance/scripts/check_layers.sh ...` (exit: )
- `./.pi/skills/architecture-conformance/scripts/check_exports.sh ...` (exit: )
- `./.pi/skills/architecture-conformance/scripts/check_hooks.sh ...` (exit: )
- `./.pi/skills/architecture-conformance/scripts/check_reuse.sh ...` (exit: )
- `zig build` (exit: )
- `zig build test` (exit: )
```

## Notes
- Policy is authoritative: update `policy/layers.json` when architecture intentionally changes.
- Prefer failing closed: treat unknown layer edges as violations until reviewed.
- Do not suppress violations without documenting architectural rationale.
