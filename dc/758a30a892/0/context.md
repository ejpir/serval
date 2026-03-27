# Session Context

## User Prompts

### Prompt 1

• Findings (Ordered by Severity)

  1. High: Router.onLog() can update the wrong pool when upstream idx values overlap across pools

  - Evidence: serval-router/router.zig:255, serval-router/router.zig:256, serval-router/router.zig:266
  - Current matching uses only u.idx == upstream.idx. In real configs, per-pool upstream arrays commonly reuse local indices (0,1,2...), so the first matching pool can be chosen incorrectly,
    corrupting health state.
  - Enterprise impact: incorrect backend e...

### Prompt 2

Base directory for this skill: /home/nick/.claude/plugins/cache/superpowers-marketplace/superpowers/4.0.3/skills/writing-plans

# Writing Plans

## Overview

Write comprehensive implementation plans assuming the engineer has zero context for our codebase and questionable taste. Document everything they need to know: which files to touch for each task, code, testing, docs they might need to check, how to test it. Give them the whole plan as bite-sized tasks. DRY. YAGNI. TDD. Frequent commits.

As...

### Prompt 3

• Findings

  1. High: Task 1 does not actually fix the performance finding (#4)

  - The plan claims Task 1 “eliminate O(n²) scan” and “fix #4 for free” (docs/plans/2026-03-27-router-findings-fixes.md:13, docs/plans/2026-03-27-router-findings-fixes.md:17).
  - But the proposed implementation still scans for pools + for upstreams and only changes comparison key to (host, port) (docs/plans/2026-03-27-router-findings-fixes.md:125, docs/plans/2026-03-
    27-router-findings-fixes.md:127)...

### Prompt 4

• Much better. This revision fixes the major gaps from the previous version. Remaining issues:

  1. High: stale ctx.pool_idx risk is not addressed

  - In Task 1, ctx.pool_idx is only set on successful route match (docs/plans/2026-03-27-router-findings-fixes.md:181, docs/plans/2026-03-27-router-findings-fixes.md:187).
  - If Context is ever reused without reset, reject paths (421/404) can leave stale pool_idx, and onLog() will target the wrong pool or hit assert (docs/plans/2026-03-27-router-...

### Prompt 5

• Findings (Ordered by Severity)

  1. Medium: Missing regression test for stale-context safety in Task 1

  - The plan now correctly says to clear ctx.pool_idx at selectUpstream() entry (docs/plans/2026-03-27-router-findings-fixes.md:19, docs/plans/2026-03-27-router-findings-fixes.md:185).
  - But there is no explicit test for: forward request sets pool, next request on reused Context is rejected (421/404), then onLog() must not mutate any pool.
  - Add one test to lock this behavior down; ot...

### Prompt 6

• Findings (Ordered by Severity)

  1. Medium: Verification scope is too narrow for a cross-module change

  - The plan changes serval-core/context.zig (docs/plans/2026-03-27-router-findings-fixes.md:24, docs/plans/2026-03-27-router-findings-fixes.md:664).
  - But verification only mandates zig build test-router (docs/plans/2026-03-27-router-findings-fixes.md:9).
  - For enterprise-readiness, add at least zig build test (or a defined broader matrix) after Task 1, since Context is shared infras...

