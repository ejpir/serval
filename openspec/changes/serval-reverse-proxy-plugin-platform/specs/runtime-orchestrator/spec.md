## ADDED Requirements

### Requirement: Reverse proxy runtime SHALL be orchestrator-owned
The system SHALL provide a `serval-reverseproxy` orchestrator that owns runtime assembly from canonical IR, including listeners, route tables, pool tables, plugin catalogs, and chain execution plans.

#### Scenario: Build runtime from admitted IR
- **WHEN** an admitted canonical IR generation is available
- **THEN** the orchestrator builds a complete runtime snapshot without requiring request-path mutation of configuration structures

### Requirement: Runtime snapshots SHALL be generation-based and immutable on fast path
The system SHALL use generation-based runtime snapshots where request handling reads immutable snapshot references and configuration updates occur via generation swap.

#### Scenario: Request reads active generation
- **WHEN** a request is processed during normal traffic
- **THEN** the request reads the active snapshot generation and executes against immutable route/pool/chain references

### Requirement: Activation SHALL be atomic with drain-aware retirement
The system SHALL activate new generations atomically and SHALL retain prior generations in draining state until in-flight references complete or drain policy timeout handling is applied.

#### Scenario: Successful generation update
- **WHEN** a new generation passes admission and activation
- **THEN** the active pointer swaps atomically and the prior generation enters draining before retirement

### Requirement: Apply lifecycle SHALL use explicit state transitions
The orchestrator SHALL implement explicit apply states (build, admit, activate, drain, retire) and SHALL emit deterministic diagnostics for transition failures.

#### Scenario: Admission failure during apply
- **WHEN** admission fails for a candidate generation
- **THEN** the active generation remains unchanged and diagnostics include failed stage and reason

### Requirement: Rollback and safe mode SHALL be orchestrator-governed
The orchestrator SHALL execute rollback to last-known-good generation on critical activation regressions and SHALL enter defined safe mode when rollback cannot be completed.

#### Scenario: Critical regression in guard window
- **WHEN** critical rollback thresholds are breached after activation
- **THEN** the orchestrator rolls back to last-known-good generation and records rollback outcome
