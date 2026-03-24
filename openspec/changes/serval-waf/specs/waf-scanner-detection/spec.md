## ADDED Requirements

### Requirement: Scanner signatures produce stable matches
The system SHALL evaluate inspection input against a configured set of scanner signatures and heuristics. Each signature MUST have a stable identifier, and each match MUST be recorded in the detection result.

#### Scenario: Known scanner user-agent matches a stable rule
- **WHEN** a request contains a configured scanner user-agent pattern
- **THEN** the detection result records the stable identifier of the matched scanner rule

#### Scenario: Sensitive probe path matches a stable rule
- **WHEN** a request targets a configured high-signal probe path
- **THEN** the detection result records the stable identifier of the matched scanner rule

### Requirement: Detection returns explicit action candidates
The system SHALL return an explicit detection result containing matched rule identifiers, aggregate score, and an action candidate of `allow`, `flag`, or `block`. A direct block rule MUST produce a `block` candidate, and multiple lower-severity matches MUST be able to raise the aggregate score to a configurable threshold.

#### Scenario: Direct blocking signature produces block candidate
- **WHEN** a request matches a scanner signature configured as directly blocking
- **THEN** the detection result action candidate is `block`

#### Scenario: Multiple suspicious matches raise a block candidate
- **WHEN** a request matches multiple non-blocking scanner signatures whose combined score reaches the configured threshold
- **THEN** the detection result action candidate is `block`

#### Scenario: Single low-severity signal produces flag candidate
- **WHEN** a request matches a suspicious scanner signature that does not meet the block threshold
- **THEN** the detection result action candidate is `flag`

### Requirement: Initial detection scope is scanner-focused
The system SHALL limit the first slice of rule evaluation to scanner-oriented signals. The first slice MUST support matching on known scanner user-agent patterns, high-signal probe paths, suspicious query patterns associated with scanning, and optionally lightweight probing heuristics that remain bounded.

#### Scenario: Broad attack-class detection is not required for first slice
- **WHEN** a request does not match any configured scanner-oriented signal
- **THEN** the scanner detection result is based only on the scanner rule set and not on broader general-purpose WAF signatures
