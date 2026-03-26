## ADDED Requirements

### Requirement: User filters SHALL use a restricted SDK surface
The system SHALL provide a public filter SDK that exposes only approved hook-facing types (`FilterContext`, header views, chunk views, bounded emit writer, and decision types). User filter code MUST NOT require direct access to server, socket, pool, parser, or runtime transport internals.

#### Scenario: Filter author builds against SDK only
- **WHEN** a user creates a custom filter
- **THEN** the filter compiles against the filter SDK public surface without importing server/proxy internals

### Requirement: Filter signatures SHALL be verified at compile time
The system SHALL verify filter hook signatures and declared capabilities at compile time using explicit diagnostics.

#### Scenario: Invalid hook signature fails build
- **WHEN** a filter method signature does not match the SDK contract
- **THEN** compile-time verification fails with a diagnostic identifying the hook and expected signature

### Requirement: SDK context SHALL provide bounded observability metadata
The filter context SHALL provide stable request/connection/stream metadata and bounded observability tagging/counter APIs without exposing mutable runtime internals.

#### Scenario: Filter adds diagnostic tags safely
- **WHEN** a filter records tags/counters through SDK observability APIs
- **THEN** values are accepted within configured bounds and the filter cannot mutate tracer/logger backend internals directly
