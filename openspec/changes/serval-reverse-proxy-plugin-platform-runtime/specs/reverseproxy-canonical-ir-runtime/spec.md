## ADDED Requirements

### Requirement: Canonical reverse-proxy IR SHALL be the only orchestrator runtime input
The system SHALL define canonical reverse-proxy IR types for listeners, route tables, pool tables, plugin catalog entries, and chain plans. Runtime assembly MUST consume these types directly and MUST NOT depend on source-format structures (DSL AST or schema parser internals).

#### Scenario: Runtime build consumes admitted canonical IR
- **WHEN** apply starts with an admitted candidate configuration
- **THEN** orchestrator build uses canonical IR structures only and produces a runtime snapshot without reading source-format parser state

### Requirement: Canonical IR validation SHALL provide deterministic diagnostics
The system SHALL provide canonical IR validation entry points that return deterministic, stage-labeled diagnostics for structural errors, unresolved references, and invariant violations required before activation.

#### Scenario: Unresolved chain reference fails validation
- **WHEN** canonical IR contains a route referencing a missing chain id
- **THEN** validation fails with a deterministic diagnostic that includes stage, object id, and missing reference name

### Requirement: Canonical IR types SHALL enforce explicit safety-critical fields
The system SHALL represent safety-critical fields explicitly in canonical IR, including failure policy and resource budget values where omission would change runtime safety behavior.

#### Scenario: Missing required failure policy in candidate IR
- **WHEN** a plugin chain entry omits required failure policy metadata
- **THEN** validation rejects the candidate IR and activation cannot proceed
