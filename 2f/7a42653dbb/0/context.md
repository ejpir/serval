# Session Context

## User Prompts

### Prompt 1

• Findings (ordered by severity)

  1. Critical: parseInitialRequest can return requests with dangling header slices.
     HeaderMap is zero-copy, so header name/value slices are stored by reference, not copied (serval-core/header_map.zig:54).
     parseInitialRequest builds CONTINUATION fragments into a local stack buffer (serval-h2/request.zig:75, serval-h2/request.zig:133, serval-h2/request.zig:145).
     It then calls decodeRequestHeaderBlock, which uses a local decoder (serval-h2/request....

### Prompt 2

[Request interrupted by user]

### Prompt 3

4. High: reserved-bit handling is too strict in control parsers (interop risk).
     parseWindowUpdateFrame and parseGoAwayFrame reject reserved-bit set inputs (serval-h2/control.zig:80, serval-h2/control.zig:129).
     For these fields, receivers should ignore the reserved bit and process the 31-bit value.
  5. Medium: TigerStyle compliance gaps are widespread in serval-h2.
     Automated scan: 114 functions total, 85 with fewer than 2 assertions, 2 functions over 70 lines.
     Over-70 example...

### Prompt 4

Base directory for this skill: /home/nick/.claude/plugins/cache/superpowers-marketplace/superpowers/4.0.3/skills/writing-plans

# Writing Plans

## Overview

Write comprehensive implementation plans assuming the engineer has zero context for our codebase and questionable taste. Document everything they need to know: which files to touch for each task, code, testing, docs they might need to check, how to test it. Give them the whole plan as bite-sized tasks. DRY. YAGNI. TDD. Frequent commits.

As...

### Prompt 5

[Request interrupted by user]

### Prompt 6

no superpowers

### Prompt 7

[Request interrupted by user for tool use]

### Prompt 8

what abouuy 3 5 6

### Prompt 9

3. High: parseInitialRequest does not enforce key RFC startup constraints.

