## ADDED Requirements

### Requirement: Reverse-proxy orchestrator SHALL manage explicit apply lifecycle states
The system SHALL implement orchestrator lifecycle states `build`, `admit`, `activate`, `drain`, and `retire` with deterministic transition rules and stage-specific diagnostics.

#### Scenario: Admission stage failure preserves active generation
- **WHEN** a candidate generation fails during `admit`
- **THEN** the orchestrator records an admission-stage diagnostic and the active generation remains unchanged

### Requirement: Active generation swap SHALL be atomic
The system SHALL activate a new generation by a single atomic swap of the active snapshot reference after successful `build` and `admit` stages.

#### Scenario: Successful activation updates active generation atomically
- **WHEN** a candidate generation passes `build` and `admit`
- **THEN** activation performs one atomic active-pointer swap and all new requests observe the new generation

### Requirement: Prior generations SHALL transition through draining before retirement
The system SHALL retain the previous active generation in draining state after activation until in-flight references are released or drain timeout policy triggers force-retire behavior.

#### Scenario: Prior generation enters drain after activation
- **WHEN** activation swaps generation N to generation N+1
- **THEN** generation N enters `drain` state and is not retired until drain completion or timeout handling executes

### Requirement: Orchestrator SHALL expose rollback and safe-mode transition hooks
The system SHALL expose explicit rollback-to-last-known-good and safe-mode transition paths for critical lifecycle failures, with structured observability events.

#### Scenario: Activation invariant failure triggers rollback path
- **WHEN** a critical post-activation invariant fails for generation N+1
- **THEN** orchestrator executes rollback transition to last-known-good generation and emits structured rollback outcome diagnostics
