## ADDED Requirements

### Requirement: Bounded scanner inspection input
The system SHALL construct scanner inspection input from bounded request metadata before upstream selection. Inspection input MUST include the HTTP method, host, path, query string, header fields, and connection metadata available at request handling time. The system MUST NOT require request body inspection for the first scanner-detection slice.

#### Scenario: Request metadata is available before forwarding
- **WHEN** a request reaches the WAF inspection step
- **THEN** the system produces an inspection input containing method, host, path, query, headers, and connection metadata before any upstream is selected

#### Scenario: First slice does not depend on request body bytes
- **WHEN** a request body has not been read at inspection time
- **THEN** scanner inspection still proceeds using metadata-only input without blocking on body availability

### Requirement: Canonicalized request fields for matching
The system SHALL normalize request fields needed for deterministic scanner matching. Path and query MUST be percent-decoded once before matching, header names MUST be matched case-insensitively, and host and user-agent values MUST be normalized into stable comparison forms.

#### Scenario: Encoded probe path is normalized before evaluation
- **WHEN** a request path contains percent-encoded characters
- **THEN** the decoded path is used for scanner rule matching

#### Scenario: Header name casing does not change match outcome
- **WHEN** the same user-agent header is presented with different header-name casing
- **THEN** scanner matching produces the same result for each request

### Requirement: Inspection remains bounded
The system SHALL keep scanner inspection bounded in time and input size. The first slice MUST inspect only request metadata that is already available from request parsing and MUST NOT trigger unbounded buffering, streaming reads, or deep body parsing.

#### Scenario: Large request body does not expand inspection scope
- **WHEN** a request includes a large body payload
- **THEN** the scanner inspection step evaluates only bounded metadata and does not read arbitrary additional body bytes for this slice
