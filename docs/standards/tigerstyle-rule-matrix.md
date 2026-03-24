# TigerStyle Rule Matrix (Serval Enforcement)

This file defines the **review shorthand** used in Serval verification blocks:

- `S1-S7` (Safety)
- `P1-P4` (Performance)
- `C1-C5` (Correctness)
- `Y1-Y6` (Style)

> Notes
> - This is a Serval-oriented enforcement matrix for code review/checklists.

## S — Safety (S1-S7)

- **S1 Assertions present:** preconditions + invariants/postconditions in non-trivial functions.
- **S2 Explicit error handling:** no swallowed errors; no `catch {}`.
- **S3 Bounded control flow:** loops have explicit bound/timeout/max-iterations.
- **S4 Resource lifecycle closed:** `defer`/`errdefer`, no leaks on error/success paths.
- **S5 Explicit integer widths:** prefer `u32/u64/...`; avoid `usize` unless required.
- **S6 No recursion:** iterative state machines only.
- **S7 No implicit risky defaults:** behavior-impacting defaults are explicit and documented.

## P — Performance (P1-P4)

- **P1 Bottleneck order respected:** optimize network → disk → memory → CPU.
- **P2 Data movement minimized:** zero-copy/slice-based paths where practical.
- **P3 Batching used where possible:** I/O and repetitive operations avoid per-item overhead.
- **P4 Allocation discipline:** avoid runtime allocations in hot paths after init.

## C — Correctness (C1-C5)

- **C1 Spec adherence:** protocol behavior matches RFC + Serval plans.
- **C2 Layer conformance:** no sideways deps; module stays in owning layer.
- **C3 Contract conformance:** function/handler API contracts preserved.
- **C4 Failure behavior verified:** timeouts/retries/error mapping deterministic and tested.
- **C5 Boundary coverage:** zero/min/max/overflow-adjacent cases handled and tested.

## Y — Style (Y1-Y6)

- **Y1 Small functions:** target < ~70 lines when practical.
- **Y2 Naming:** `snake_case`; names include units (`timeout_ns`, `size_bytes`).
- **Y3 Comments explain why:** avoid narration of obvious mechanics.
- **Y4 No magic numbers:** use named constants in canonical config modules.
- **Y5 Cohesion and placement:** code goes to owning module/file; avoid premature abstraction.
- **Y6 Readability first:** explicit control flow and intent over cleverness.

## Suggested review use

When filling completion blocks, mark each file as checked against:

- `S1-S7`
- `P1-P4`
- `C1-C5`
- `Y1-Y6`

and cite exceptions explicitly when a rule is `N/A`.
