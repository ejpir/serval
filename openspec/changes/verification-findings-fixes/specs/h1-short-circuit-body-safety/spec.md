## ADDED Requirements

### Requirement: H1 short-circuit responses must gate keep-alive on verified body consumption
The system MUST treat HTTP/1.1 short-circuit response paths as fail-closed unless request-body consumption is verified complete. The connection MUST be closed when body-consumption state is incomplete, unknown, or invalid for safe socket reuse.

#### Scenario: Unread request body forces connection close after short-circuit
- **WHEN** a short-circuit response is produced before consuming the full request body on a persistent HTTP/1.1 connection
- **THEN** the system closes the connection and does not allow keep-alive reuse

#### Scenario: Fully consumed body permits normal keep-alive behavior
- **WHEN** a short-circuit response is produced and request-body consumption is verified complete
- **THEN** the system may preserve keep-alive behavior according to existing connection policy

### Requirement: Follow-on request processing must not proceed on contaminated sockets
The system MUST prevent follow-on request parsing on connections that still contain unread bytes from a prior short-circuit request. Recovery behavior MUST be connection termination rather than speculative draining.

#### Scenario: Pipelined follow-on request is rejected by connection termination
- **WHEN** a client sends a second request on the same socket after a short-circuit path left unread body bytes
- **THEN** the server terminates the connection before processing the follow-on request

### Requirement: Short-circuit request-loop outcomes must remain deterministic
The request loop MUST make explicit and deterministic continuation decisions (`continue`, `close`, or terminal fall-through) for each short-circuit outcome. Loop refactoring MUST preserve externally observable behavior for non-short-circuit requests.

#### Scenario: Non-short-circuit request behavior remains unchanged
- **WHEN** a request does not take a short-circuit path
- **THEN** the request loop preserves prior success/error connection behavior for that request class
