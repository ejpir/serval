## ADDED Requirements

### Requirement: TCP tunnel behavior must conform to RFC 9293 semantics
The system MUST preserve TCP stream semantics defined by RFC 9293 while acting as a forwarding intermediary, including reliable ordered byte-stream relay and connection lifecycle correctness for open, half-close, and full close transitions.

#### Scenario: Ordered byte stream is preserved across tunnel
- **WHEN** downstream and upstream endpoints exchange TCP payloads through the tunnel
- **THEN** the tunnel relays bytes as an ordered stream without introducing application-layer framing semantics

#### Scenario: Half-close propagates correctly
- **WHEN** one side sends FIN and transitions to half-closed state
- **THEN** the tunnel propagates closure state according to TCP lifecycle rules and completes deterministic resource cleanup after terminal close

### Requirement: TCP tunnel listeners must be explicitly configured and validated
The system MUST start TCP tunnel listeners only when a `serval-tcp` listener configuration is present and valid. Configuration MUST include bind address, upstream target set, connect timeout, idle timeout, and maximum concurrent connections, and startup MUST fail with a validation error when required fields are missing or limits are invalid.

#### Scenario: Valid listener configuration enables startup
- **WHEN** an operator provides a complete `serval-tcp` listener configuration with valid limits
- **THEN** the system starts the listener and marks it ready for accepting connections

#### Scenario: Invalid listener configuration blocks startup
- **WHEN** an operator provides a `serval-tcp` listener configuration with missing required fields or non-positive limits
- **THEN** the system rejects startup with explicit validation errors and does not start a partial listener

### Requirement: TCP upstream selection must use shared strategy components
The system MUST perform TCP upstream selection through a protocol-agnostic strategy component shared with other transports. `serval-tcp` MUST consume strategy outputs and MUST NOT embed transport-specific round-robin policy logic.

#### Scenario: Shared round-robin strategy is applied to TCP sessions
- **WHEN** a TCP listener with multiple healthy upstreams accepts new connections
- **THEN** upstream selection is delegated to the shared strategy component and distributed according to configured policy

#### Scenario: Health state drives TCP target eligibility
- **WHEN** health state marks an upstream unhealthy
- **THEN** the shared strategy excludes that upstream from TCP selection until health recovery criteria are satisfied

### Requirement: TCP tunnels must forward bytes bidirectionally for established streams
For each accepted downstream TCP connection, the system MUST establish an upstream connection using configured target selection and MUST relay bytes bidirectionally until either side closes or an enforced timeout or error occurs.

#### Scenario: Tunnel forwards data in both directions
- **WHEN** a downstream TCP client connects and an upstream connection is established
- **THEN** bytes sent by either endpoint are forwarded to the peer endpoint without protocol-aware transformation

#### Scenario: Tunnel closes deterministically on peer close
- **WHEN** either downstream or upstream endpoint closes the TCP stream
- **THEN** the system closes the opposite side and releases tunnel resources within configured shutdown bounds

### Requirement: TCP tunnel resource usage must remain bounded
The system MUST enforce configured limits for concurrent TCP tunnels and MUST apply configured connect/idle timeouts per tunnel. The system MUST refuse or shed new connections when limits are reached and MUST avoid unbounded memory or descriptor growth.

#### Scenario: Connection cap is enforced
- **WHEN** active TCP tunnels reach the configured maximum concurrent connections
- **THEN** additional connection attempts are refused and a capacity rejection event is emitted

#### Scenario: Idle timeout closes inactive tunnel
- **WHEN** a TCP tunnel has no traffic for longer than the configured idle timeout
- **THEN** the system terminates the tunnel and frees all associated resources

### Requirement: TCP target unavailability must produce deterministic failures
When upstream target selection or connection establishment fails, the system MUST fail the affected tunnel attempt deterministically, record the failure reason, and preserve service availability for unrelated connections.

#### Scenario: Upstream connect failure is reported and isolated
- **WHEN** a downstream connection is accepted but upstream connect fails within timeout
- **THEN** the tunnel attempt is terminated with a logged failure reason and other active tunnels continue unaffected

### Requirement: TCP health probing must use shared prober scheduler with TCP adapter semantics
The system MUST implement TCP active health probing through a shared probe scheduler component and a TCP-specific probe adapter. Probe outcomes MUST update shared health state without requiring HTTP status semantics.

#### Scenario: TCP connect probe marks upstream healthy
- **WHEN** a TCP probe adapter successfully establishes a probe connection under configured timeout
- **THEN** the shared prober records success for that upstream in shared health state

#### Scenario: TCP connect probe failure does not affect unrelated upstreams
- **WHEN** a TCP probe adapter cannot connect to one upstream within timeout
- **THEN** the shared prober records failure only for that upstream and continues probing others within configured bounds

### Requirement: TCP tunnel telemetry must expose operational outcomes
The system MUST emit TCP tunnel telemetry that includes accepted connections, active tunnel count, bytes forwarded in each direction, connect failures, timeout closures, and capacity rejections.

#### Scenario: Telemetry reflects lifecycle events
- **WHEN** TCP tunnels are opened, forward traffic, and close
- **THEN** corresponding counters/gauges are updated so operators can observe throughput, failure, and saturation trends
