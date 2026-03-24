## ADDED Requirements

### Requirement: UDP tunnel behavior must conform to RFC 768 semantics with RFC 8085 operational guidance
The system MUST preserve UDP datagram semantics defined by RFC 768, including message boundary preservation and connectionless forwarding behavior. The system MUST implement operational controls consistent with RFC 8085 guidance by exposing explicit rate/queue/drop behavior and observability under load.

#### Scenario: Datagram boundaries are preserved end-to-end
- **WHEN** a client sends UDP datagrams through the tunnel
- **THEN** each datagram is forwarded as a discrete message without stream aggregation or segmentation semantics in the forwarding layer

#### Scenario: Load handling is controlled and measurable
- **WHEN** forwarding pressure exceeds configured queue or session bounds
- **THEN** the system applies configured drop behavior and emits telemetry sufficient to identify sustained overload conditions

### Requirement: UDP tunnel listeners must be explicitly configured and validated
The system MUST start UDP tunnel listeners only when a `serval-udp` listener configuration is present and valid. Configuration MUST include bind address, upstream target set, session idle timeout, and maximum active sessions, and startup MUST fail with validation errors when required fields are missing or limits are invalid.

#### Scenario: Valid UDP configuration enables listener startup
- **WHEN** an operator provides a complete `serval-udp` listener configuration with valid bounds
- **THEN** the system starts the UDP listener and marks it ready for datagram forwarding

#### Scenario: Invalid UDP configuration blocks startup
- **WHEN** an operator provides a `serval-udp` listener configuration with missing required fields or invalid bounds
- **THEN** the system rejects startup with explicit validation errors and does not start a partial listener

### Requirement: UDP upstream selection must use shared strategy components
The system MUST perform UDP upstream selection through a protocol-agnostic strategy component shared with other transports. `serval-udp` MUST consume strategy outputs and MUST NOT embed transport-specific round-robin policy logic.

#### Scenario: Shared round-robin strategy is applied to UDP sessions
- **WHEN** a UDP listener receives traffic for multiple healthy upstreams
- **THEN** upstream selection is delegated to the shared strategy component and distributed according to configured policy

#### Scenario: Health state drives UDP target eligibility
- **WHEN** health state marks an upstream unhealthy
- **THEN** the shared strategy excludes that upstream from UDP selection until health recovery criteria are satisfied

### Requirement: UDP forwarding must preserve datagram semantics
The system MUST forward UDP payloads as discrete datagrams between downstream clients and selected upstream targets without stream reassembly. The system MUST preserve per-datagram boundaries and MUST not introduce ordering guarantees beyond network behavior.

#### Scenario: Downstream datagram is forwarded upstream
- **WHEN** a downstream client sends a UDP datagram for an active listener
- **THEN** the system forwards the datagram to the selected upstream target as a single datagram unit

#### Scenario: Upstream response datagram is forwarded downstream
- **WHEN** an upstream target sends a UDP response datagram for a mapped session
- **THEN** the system forwards the response to the corresponding downstream client endpoint

### Requirement: UDP session state must be bounded, expirable, and key-configurable
The system MUST maintain bounded UDP session mappings using a deterministic key derived from a configurable keying mode. The system MUST enforce configured maximum active sessions and idle expiration. The system MUST remove expired session state and reclaim resources without manual intervention.

#### Scenario: Session mapping is created and reused
- **WHEN** the first datagram arrives from a new client tuple
- **THEN** the system creates a session mapping and reuses it for subsequent datagrams from that tuple until expiry

#### Scenario: Configured key mode changes session grouping behavior
- **WHEN** an operator configures a non-default UDP session keying mode
- **THEN** session mapping identity follows the configured key definition consistently for create/reuse/expiry decisions

#### Scenario: Idle session expires and is reclaimed
- **WHEN** a UDP session remains inactive longer than the configured idle timeout
- **THEN** the system removes the mapping and frees resources before accepting new sessions under pressure

### Requirement: UDP overload behavior must be explicit and observable
When session limits or forwarding buffers are exhausted, the system MUST apply explicit drop behavior for affected datagrams, MUST increment drop/error telemetry, and MUST continue processing unrelated sessions.

#### Scenario: Session capacity exhaustion causes controlled drops
- **WHEN** active UDP sessions are at configured maximum and a new tuple sends a datagram
- **THEN** the system drops the datagram, records a capacity-drop event, and preserves forwarding for existing sessions

### Requirement: UDP health probing must use shared prober scheduler with configurable UDP adapter mode
The system MUST implement UDP active health probing through the shared probe scheduler and a UDP-specific probe adapter when enabled. The probe mode MUST be explicitly configurable so operators can choose passive-only or active UDP probe semantics appropriate to their protocol.

#### Scenario: Passive-only mode skips active UDP probes
- **WHEN** UDP probe mode is configured as passive-only
- **THEN** the shared prober does not send active UDP probe traffic and health state is driven by passive outcomes

#### Scenario: Active UDP probe mode updates shared health state
- **WHEN** UDP probe mode is configured for active probing and probe criteria succeed/fail
- **THEN** the shared prober records success/failure for the targeted upstream without impacting unrelated upstreams

### Requirement: UDP tunnel telemetry must expose packet/session outcomes
The system MUST emit UDP tunnel telemetry including packets received/forwarded/dropped, active session count, session creations/expirations, and upstream forwarding errors.

#### Scenario: Telemetry captures session churn and packet flow
- **WHEN** UDP sessions are created, forward packets, expire, and experience drops or errors
- **THEN** metrics/log events reflect these transitions for operational monitoring and alerting
