## ADDED Requirements

### Requirement: DSL SHALL compile to canonical IR equivalently
The system SHALL compile DSL configuration into the same canonical schema/IR used by structured schema inputs. Equivalent intent expressed in DSL and schema form MUST produce equivalent canonical IR.

#### Scenario: Equivalent DSL and schema inputs
- **WHEN** an operator provides semantically equivalent DSL and schema configuration documents
- **THEN** canonical IR outputs are equivalent and admission outcomes match

### Requirement: DSL validation SHALL be explicit and deterministic
The DSL compiler SHALL perform deterministic semantic validation, including name/reference resolution, duplicate detection, and bounded literal/unit parsing, with stable diagnostics.

#### Scenario: Unknown pool reference in route
- **WHEN** a route references a non-existent pool
- **THEN** compilation fails with a deterministic diagnostic identifying route and missing reference

### Requirement: DSL SHALL keep safety-critical behavior explicit
The DSL SHALL require explicit configuration for safety-critical plugin behavior, including failure policy and resource budgets where behavior materially changes runtime safety.

#### Scenario: Missing failure policy
- **WHEN** a plugin declaration omits required failure policy
- **THEN** compilation fails rather than applying an implicit default

### Requirement: Initial DSL feature set SHALL remain declarative
The initial DSL SHALL support declarative proxy/listener/pool/plugin/route blocks and SHALL defer advanced language constructs (macros/functions/conditionals).

#### Scenario: Disallowed advanced construct
- **WHEN** configuration includes a deferred advanced construct class
- **THEN** compilation fails with an unsupported-feature diagnostic
