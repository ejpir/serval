# TigerStyle + Serval Enforcement Notes

References:
- https://tigerstyle.dev/
- https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md

Priority order: **Safety > Performance > Developer Experience**.

## Safety

- ~2 assertions per function (preconditions + postconditions/invariants)
- No recursion
- All loops bounded
- Explicit integer widths (`u32`, `u64`, etc.), avoid `usize` unless required
- No runtime allocation after initialization (where applicable)
- No `catch {}`; handle every error path explicitly

## Performance

- Optimize bottlenecks in this order: network > disk > memory > CPU
- Prefer zero-copy where practical
- Batch operations when possible

## Style

- Keep functions small (target under ~70 lines when practical)
- `snake_case` for files, vars, funcs
- Include units in names (`timeout_ns`, `size_bytes`, `interval_ms`)
- Comments explain **why**, not obvious **what**

## Serval-specific add-ons

- Prefer `serval-core.time` over `std.time` in Serval modules.
- Prefer `serval-core.config` constants over local magic values.
- Keep module dependencies aligned with architecture layers.
