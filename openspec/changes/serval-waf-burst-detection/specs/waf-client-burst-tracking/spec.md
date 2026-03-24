## ADDED Requirements

### Requirement: Per-client burst tracking remains bounded
The system SHALL maintain bounded per-client burst-tracking state inside `serval-waf`. Tracking state MUST use a fixed-capacity CAS-based table keyed by client identity, MUST cap per-entry counters, and MUST avoid unbounded request-history storage.

#### Scenario: New client uses a bounded tracker entry
- **WHEN** a request arrives from a client without an active tracker entry
- **THEN** the system allocates or replaces exactly one fixed-capacity tracker entry for that client

#### Scenario: Repeated requests do not allocate unbounded history
- **WHEN** a tracked client sends additional requests inside the active window
- **THEN** the system updates bounded counters in the existing tracker entry without storing an unbounded request log

#### Scenario: CAS contention remains bounded
- **WHEN** multiple workers concurrently update the same client tracker entry
- **THEN** the system uses bounded CAS retries and records degraded/saturation metadata if retries are exhausted

### Requirement: Tracking windows reset deterministically
The system SHALL track burst activity within an explicit short window per client. When a client's active window expires, the system MUST reset the window counters before scoring subsequent requests in the new window.

#### Scenario: Expired window starts clean
- **WHEN** a client's next request arrives after the configured burst window has elapsed
- **THEN** the system resets the prior window counters and begins a new window for that client

### Requirement: Tracker saturation is explicit and deterministic
The system SHALL apply a deterministic replacement policy when the per-client tracker table is full. The implementation MUST prefer expired or stalest eligible entries for replacement, and saturation events MUST remain observable to operators.

#### Scenario: Full table replaces an expired entry first
- **WHEN** the tracker table is full and a new client request arrives while an expired entry exists
- **THEN** the system replaces an expired entry instead of dropping the new client from tracking

#### Scenario: Full table exposes degraded tracking
- **WHEN** the tracker table is full and replacement occurs for an active entry
- **THEN** the system records an observable saturation signal indicating tracking fidelity has degraded
