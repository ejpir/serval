## ADDED Requirements

### Requirement: Burst heuristics evaluate short-window request volume and diversity
The system SHALL derive behavioral burst signals from bounded per-client window counters. The first burst heuristic set MUST support request-count thresholds, distinct normalized full-path thresholds, and sensitive namespace family diversity thresholds within one active short window.

#### Scenario: High request volume raises a behavioral signal
- **WHEN** a client's request count reaches the configured burst threshold inside one active window
- **THEN** the detector records a behavioral signal for elevated short-window request volume

#### Scenario: Many distinct paths raise a behavioral signal
- **WHEN** a client's distinct-path count reaches the configured diversity threshold inside one active window
- **THEN** the detector records a behavioral signal for path diversity consistent with scanning

### Requirement: Suspicious namespace diversity is tracked separately
The system SHALL distinguish generic path diversity from suspicious namespace probing. The first heuristic set MUST support counting probes across configured sensitive path families such as hidden files, admin surfaces, or framework-specific probe namespaces.

#### Scenario: Multiple sensitive namespaces strengthen scanner suspicion
- **WHEN** a client probes multiple configured sensitive path families inside one active window
- **THEN** the detector records a behavioral signal for suspicious namespace diversity

### Requirement: Outcome feedback contributes to burst heuristics
The system SHALL support updating behavioral burst state from request outcomes after request processing completes. The first implementation MUST support bounded counters for local rejects and for misses identified by an explicit `isMiss` classifier hook.

#### Scenario: Repeated misses raise a behavioral signal
- **WHEN** a client's requests accumulate the configured miss or reject threshold inside one active window
- **THEN** the detector records a behavioral signal for burst behavior with a high miss ratio
