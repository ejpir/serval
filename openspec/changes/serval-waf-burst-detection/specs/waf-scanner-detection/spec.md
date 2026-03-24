## MODIFIED Requirements

### Requirement: Scanner signatures and behavioral signals produce stable matches
The system SHALL evaluate inspection input against a configured set of scanner signatures and behavioral heuristics. Each static signature and each behavioral signal MUST have a stable identifier, and each match MUST be recorded in the detection result.

#### Scenario: Known scanner user-agent matches a stable rule
- **WHEN** a request contains a configured scanner user-agent pattern
- **THEN** the detection result records the stable identifier of the matched scanner rule

#### Scenario: Sensitive probe path matches a stable rule
- **WHEN** a request targets a configured high-signal probe path
- **THEN** the detection result records the stable identifier of the matched scanner rule

#### Scenario: Burst-scanning behavior matches a stable behavioral signal
- **WHEN** a client crosses a configured burst-detection threshold
- **THEN** the detection result records the stable identifier of the matched behavioral signal

### Requirement: Detection returns explicit action candidates from unified scoring
The system SHALL return an explicit detection result containing matched rule identifiers, aggregate score, and an action candidate of `allow`, `flag`, or `block`. A direct block rule MUST produce a `block` candidate, and combined static plus behavioral matches MUST be able to raise the aggregate score to a configurable threshold.

#### Scenario: Direct blocking signature produces block candidate
- **WHEN** a request matches a scanner signature configured as directly blocking
- **THEN** the detection result action candidate is `block`

#### Scenario: Multiple suspicious matches raise a block candidate
- **WHEN** a request matches multiple non-blocking scanner signatures whose combined score reaches the configured threshold
- **THEN** the detection result action candidate is `block`

#### Scenario: Single low-severity signal produces flag candidate
- **WHEN** a request matches a suspicious static or behavioral signal that does not meet the block threshold
- **THEN** the detection result action candidate is `flag`

#### Scenario: Behavioral and static signals combine into one block candidate
- **WHEN** a request has active behavioral matches and static matches whose aggregate score reaches the configured threshold
- **THEN** the detection result action candidate is `block`

### Requirement: Scanner detection remains bounded while expanding beyond static signatures
The system SHALL extend the scanner-focused slice beyond static signatures without introducing unbounded tracking or arbitrary request-history retention. Behavioral detection MUST rely on bounded per-client state, short windows, and capped counters.

#### Scenario: Arbitrary path scanning is detected by bounded behavior
- **WHEN** a client probes many distinct paths in one short window without matching a known scanner user-agent
- **THEN** the scanner detection result is able to flag or block the request using bounded behavioral signals
