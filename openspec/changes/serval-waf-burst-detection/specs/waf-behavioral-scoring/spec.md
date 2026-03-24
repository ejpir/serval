## ADDED Requirements

### Requirement: Behavioral signals contribute to unified scanner scoring
The system SHALL combine behavioral burst signals with existing static scanner signatures in a unified decision model. Each behavioral signal MUST have a stable identifier, MUST contribute an explicit score or block contribution, and MUST appear in the detection result when matched.

#### Scenario: Behavioral signal is reported with a stable identifier
- **WHEN** a client crosses a configured burst heuristic threshold
- **THEN** the detection result records the stable identifier of the matched behavioral signal

#### Scenario: Behavioral score combines with static matches
- **WHEN** a request matches one or more static scanner signatures and the client also has active behavioral signals
- **THEN** the final aggregate score includes both static and behavioral contributions

### Requirement: Behavioral detection preserves explicit allow flag and block outcomes
The system SHALL continue to return explicit `allow`, `flag`, or `block` action candidates after adding behavioral scoring. Behavioral signals below the block threshold MUST produce `flag`, and combined static plus behavioral scores at or above the threshold MUST produce `block`.

#### Scenario: Behavioral signal below threshold flags the request
- **WHEN** only behavioral signals match and their aggregate score remains below the configured block threshold
- **THEN** the detection result action candidate is `flag`

#### Scenario: Combined behavioral and static scores block the request
- **WHEN** static and behavioral contributions together reach the configured block threshold
- **THEN** the detection result action candidate is `block`

### Requirement: Pre-decision scoring uses prior committed state
The system SHALL evaluate one request using tracker state committed before that request's post-response feedback is applied. Outcome feedback from a request MUST affect only subsequent requests from that client.

#### Scenario: Same request is not double-counted
- **WHEN** one request is evaluated and later contributes outcome feedback through `onLog`
- **THEN** that feedback is not re-applied to the same request's already produced decision

### Requirement: Behavioral detection is operator-configurable
The system SHALL expose explicit configuration for burst tracking and behavioral scoring. The first configuration surface MUST include a window duration, tracker table capacity, and heuristic thresholds needed to tune request-count, path-diversity, and miss or reject signals.

#### Scenario: Operators tune burst sensitivity explicitly
- **WHEN** an operator changes the configured behavioral thresholds or window duration
- **THEN** subsequent requests are scored using the updated explicit burst-detection settings
