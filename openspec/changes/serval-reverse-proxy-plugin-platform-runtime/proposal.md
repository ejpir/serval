## Why

The reverse-proxy plugin platform change defined requirements and design, but it did not deliver runtime Zig modules. We need an implementation-focused change now so Serval can execute the orchestrator, generation lifecycle, and admission-safe activation path described by the spec.

## What Changes

- Implement canonical reverse-proxy IR data structures used as the single runtime source of truth.
- Add a `serval-reverseproxy` orchestrator module that builds immutable runtime snapshots from admitted IR.
- Implement explicit apply lifecycle state handling (`build`, `admit`, `activate`, `drain`, `retire`) with deterministic errors.
- Implement atomic generation activation and draining/retirement bookkeeping for prior generations.
- Add initial rollback/safe-mode control flow hooks and observability events for lifecycle failures.
- Add focused tests for admission-failure no-op, atomic pointer swap, and generation drain transitions.

## Capabilities

### New Capabilities
- `reverseproxy-canonical-ir-runtime`: Canonical IR types and validation entry points used by orchestrator runtime assembly.
- `reverseproxy-orchestrator-lifecycle-runtime`: Runtime orchestrator, generation snapshots, lifecycle transitions, and atomic activation semantics.

### Modified Capabilities
- None.

## Impact

- Affected code: `serval-proxy`, `serval-server`, and new `serval-reverseproxy` module(s).
- Affected tests: new unit/integration tests for generation lifecycle and activation/rollback safety.
- Affected docs: runtime module README sections and architecture references for orchestrator ownership.
