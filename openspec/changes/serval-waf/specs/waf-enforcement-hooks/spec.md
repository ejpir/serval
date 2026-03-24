## ADDED Requirements

### Requirement: Enforcement occurs before upstream selection
The system SHALL apply WAF enforcement through request hooks before upstream selection. A `block` decision MUST prevent upstream selection and MUST allow the handler to return a direct rejection response.

#### Scenario: Blocked scanner request stops before routing
- **WHEN** scanner detection returns a `block` decision
- **THEN** the request is rejected before any upstream is selected or forwarding begins

### Requirement: Detect-only mode never blocks
The system SHALL support a detect-only mode for scanner enforcement. In detect-only mode, a request that would otherwise be blocked MUST continue through normal request processing while preserving the matched-rule and action metadata for logs and observability.

#### Scenario: Detect-only mode preserves traffic flow
- **WHEN** scanner detection returns a blocking candidate while enforcement mode is detect-only
- **THEN** the request continues through normal routing and the matched-rule metadata remains available for logging

### Requirement: Enforce mode blocks scanner traffic
The system SHALL support an enforce mode for scanner enforcement. In enforce mode, a blocking detection result MUST produce a rejection response with an explicit blocked outcome for hooks and logs.

#### Scenario: Enforce mode rejects scanner request
- **WHEN** scanner detection returns a blocking candidate while enforcement mode is enforce
- **THEN** the request receives a rejection response and the blocked decision is emitted to hook consumers and logs

### Requirement: Enforcement failures are explicit
The system SHALL make internal WAF execution failures explicit to the caller. The enforcement path MUST support configured fail-open or fail-closed behavior, and the chosen behavior MUST be reflected in decision metadata.

#### Scenario: Fail-open preserves traffic on WAF execution failure
- **WHEN** WAF execution fails and the enforcement configuration is fail-open
- **THEN** the request continues and the failure is recorded in decision metadata and logs

#### Scenario: Fail-closed rejects traffic on WAF execution failure
- **WHEN** WAF execution fails and the enforcement configuration is fail-closed
- **THEN** the request is rejected and the failure reason is recorded in decision metadata and logs
