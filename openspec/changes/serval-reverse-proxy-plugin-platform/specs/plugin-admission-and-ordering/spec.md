## ADDED Requirements

### Requirement: Plugin ordering SHALL be deterministic
The system SHALL compute plugin execution order via dependency constraints (`before`/`after`) and deterministic tie-break rules. Equivalent input configuration MUST produce identical ordered chains.

#### Scenario: Stable order with equal priorities
- **WHEN** two plugins are both eligible in the ready set with equal priority
- **THEN** deterministic tie-break ordering is applied consistently

### Requirement: Invalid ordering graphs SHALL be rejected
The system SHALL reject chains with unresolved dependencies, cycles, or contradictory constraints during admission.

#### Scenario: Cycle in plugin constraints
- **WHEN** plugin dependency constraints form a cycle
- **THEN** admission fails and the active chain remains unchanged

### Requirement: Admission SHALL enforce hard caps
The system SHALL enforce global hard limits for plugin count, mutator count, memory budgets, expansion ratios, output byte caps, and compute budgets. Configurations exceeding caps MUST be rejected.

#### Scenario: Manifest exceeds expansion hard cap
- **WHEN** a plugin manifest declares an expansion ratio above the global hard cap
- **THEN** admission fails with an explicit budget violation diagnostic

### Requirement: Activation SHALL be atomic
The system SHALL activate admitted chains atomically and SHALL keep the previous active configuration when admission or activation fails.

#### Scenario: Admission failure during update
- **WHEN** a chain update fails validation
- **THEN** no partial update is applied and the previously active chain remains in service
