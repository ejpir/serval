## ADDED Requirements

### Requirement: Global and route chains SHALL compose explicitly
The system SHALL build effective plugin chains by explicit composition of global plugins and route-specific plugins, including explicit route-level disable/add semantics subject to policy.

#### Scenario: Route adds plugin on top of global baseline
- **WHEN** a route declares an additional plugin while inheriting global plugins
- **THEN** the effective chain includes global baseline plus route plugin in deterministic order

### Requirement: Mandatory baseline plugins SHALL be enforceable
The system SHALL allow policy classes (for example, baseline security controls) to be marked mandatory such that route configurations cannot disable them without explicit waiver policy.

#### Scenario: Route attempts to disable mandatory security plugin
- **WHEN** route configuration disables a mandatory plugin
- **THEN** admission rejects the route configuration with an explicit policy violation

### Requirement: Virtual host routing SHALL remain strategy-owned
Virtual host and path matching decisions SHALL remain in strategy components (router layer) and SHALL execute before forwarding mechanics transform chains.

#### Scenario: Host/path routing picks route before transform chain
- **WHEN** a request arrives for a configured host/path
- **THEN** route selection resolves first and the selected route's effective chain is used for subsequent plugin execution

### Requirement: Cache/WAF/filter integration SHALL preserve phase boundaries
Cache taps, WAF decisions, and transform filters SHALL execute in explicit phases with deterministic ordering and MUST NOT implicitly reorder each other at runtime.

#### Scenario: WAF reject before upstream forwarding
- **WHEN** WAF policy in the request phase returns a reject decision
- **THEN** upstream forwarding is skipped and later upstream/response-phase plugins do not run
