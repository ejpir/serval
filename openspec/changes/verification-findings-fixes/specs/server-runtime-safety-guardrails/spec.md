## ADDED Requirements

### Requirement: H2 request-body tracker capacity overflow must fail closed
The system MUST reject additional tracker entries when tracker capacity is exhausted and MUST NOT overwrite existing tracker state silently.

#### Scenario: Capacity exhaustion produces explicit failure
- **WHEN** a new request-body tracker entry is required and the tracker is at capacity
- **THEN** the operation fails with an explicit error and no existing tracker entry is overwritten

### Requirement: TLS reload lock contention must be recoverable
Control-plane TLS reload operations MUST return explicit fallible errors on lock contention and MUST NOT terminate the process.

#### Scenario: Concurrent reload contention returns an error without crash
- **WHEN** a TLS reload operation cannot acquire the required lock due to contention
- **THEN** the operation returns an explicit error and the server process remains running

### Requirement: Bridge hot-path memory behavior must remain bounded under load
Targeted bridge hot paths MUST avoid unnecessary per-request allocator churn and maintain bounded allocation behavior under sustained concurrency.

#### Scenario: Repeated requests do not require unbounded allocation growth
- **WHEN** the server processes sustained request traffic through the targeted bridge paths
- **THEN** allocation behavior remains bounded and does not show unbounded per-request growth attributable to avoidable churn
