## ADDED Requirements

### Requirement: Activation SHALL use a post-apply guard window
The system SHALL monitor newly activated configurations for a bounded guard window and evaluate defined health/error thresholds before considering the generation stable.

#### Scenario: New generation remains healthy through guard window
- **WHEN** a newly activated generation stays within configured thresholds for the guard window duration
- **THEN** the generation is marked stable

### Requirement: Critical regressions SHALL trigger automatic rollback
The system SHALL automatically roll back to the last-known-good generation when configured critical regression thresholds are breached during the guard window.

#### Scenario: Error-rate breach after activation
- **WHEN** critical error metrics exceed rollback thresholds during guard window monitoring
- **THEN** automatic rollback is executed and the prior generation remains active

### Requirement: Rollback failures SHALL enter safe mode
The system SHALL enter a defined safe mode when automatic rollback cannot complete, including freezing further applies and preserving mandatory baseline controls.

#### Scenario: Rollback execution failure
- **WHEN** rollback cannot restore a valid prior generation
- **THEN** the system enters safe mode, emits critical diagnostics, and requires operator intervention

### Requirement: Draining outcomes SHALL be explicit
The system SHALL define explicit handling for old-generation draining completion and draining timeout paths.

#### Scenario: Old generation drain timeout
- **WHEN** old-generation resources do not retire before drain timeout
- **THEN** the configured force-retire policy is applied and an operator alert is emitted
