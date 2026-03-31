# Code Placement Decision Tree

Default behavior: **modify existing files/modules unless cohesion requires a split**.

## Decision flow

1. Is this a bug fix or small enhancement?
   - Yes → change existing file.
   - No → continue.

2. Does it belong to an existing module responsibility?
   - Yes:
     - Existing file still cohesive and reasonably sized (~<=300 lines)?
       - Yes → add there.
       - No → add a new file inside the same module.
   - No → continue.

3. Is this a reusable cross-cutting infra capability with lifecycle/state?
   - Yes → create a new layer-2 module.
   - No → continue.

4. Is this a new routing/selection algorithm?
   - Yes → layer-4 strategy module.
   - No → place according to owning layer responsibility.

## Split criteria for new files

Create a new file inside a module when:

- Existing file exceeds ~300 lines
- New section introduces distinct concern
- Imports indicate mixed responsibilities
- Filename no longer describes content accurately

## Avoid premature abstraction

Follow TigerStyle bias toward concreteness:

- 1st use: inline implementation
- 2nd use: tolerate duplication
- 3rd+ use: extract shared abstraction

## Placement examples

- Timeout constants → `serval-core/config.zig`
- New shared error type → `serval-core/errors.zig`
- Parser helper → `serval-http/parser.zig` (or split file if parser gets too large)
- Weighted round-robin → `serval-lb`
- New forwarding mechanism → `serval-proxy`

## Public Const Ownership Audit

- Single-owner values should usually be private `const` in the owning file, not `pub const` in `serval-core`.
- Top-level non-core `pub const` aliases that resolve back into `serval-core` are ownership-drift candidates.
- Exact semantic duplicates across non-core top-level `pub const` declarations are duplication candidates even when names differ.
- Use `zig build audit-pub-consts-report` to inspect current findings.
- Use `zig build audit-pub-consts` to fail the build on those findings.

To enforce this locally before each commit:

```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

The repo-managed pre-commit hook runs `zig build audit-pub-consts`.
