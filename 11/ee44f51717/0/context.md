# Session Context

## User Prompts

### Prompt 1

• ## Findings (ordered by severity)

  1. High — Header-name validation is incomplete (protocol safety / smuggling risk)
     Code only checks “not uppercase”, but does not enforce RFC token validity (no SP/CTL/separators).
      - serval-h2/request.zig:316
      - serval-h2/request.zig:511
        Impact: malformed names like bad name or control-byte names can pass decode and enter routing/header logic.
  2. High — Connection token parsing has a hard cutoff that can bypass hop-by-hop ...

### Prompt 2

Base directory for this skill: /home/nick/.claude/plugins/cache/superpowers-marketplace/superpowers/4.0.3/skills/writing-plans

# Writing Plans

## Overview

Write comprehensive implementation plans assuming the engineer has zero context for our codebase and questionable taste. Document everything they need to know: which files to touch for each task, code, testing, docs they might need to check, how to test it. Give them the whole plan as bite-sized tasks. DRY. YAGNI. TDD. Frequent commits.

As...

### Prompt 3

• Findings from review of docs/plans/2026-03-27-h2-findings-fixes.md:

  1. High — Task 2 test section contains contradictory/invalid snippet that should be removed
     The plan includes a broken draft test (cursor += 8; // oops this is 9) before the corrected version. This is easy to copy accidentally and will create churn/confusion.
     Reference: docs/plans/2026-03-27-h2-findings-fixes.md:131
  2. Medium — Task 3 fix is incomplete for WINDOW_UPDATE semantics
     Proposed code checks ...

