## ADDED Requirements

### Requirement: Body transforms SHALL operate in streaming mode only
The system SHALL process request and response body transforms incrementally on bounded chunks and SHALL NOT require full-body buffering as a normal execution path.

#### Scenario: Large body processed without full buffering
- **WHEN** a transformed request or response body exceeds in-memory chunk size
- **THEN** the pipeline processes it incrementally with bounded buffers and without loading the entire body into memory

### Requirement: Transform execution SHALL enforce backpressure
The system SHALL enforce downstream backpressure by pausing upstream reads when transformed output cannot be written, and SHALL bound backpressure wait with explicit timeout handling.

#### Scenario: Downstream blocked during transform output
- **WHEN** transformed output cannot be written immediately
- **THEN** upstream reads pause until writable or timeout, and timeout follows configured terminal behavior

### Requirement: Transform framing SHALL remain protocol-correct
The system SHALL maintain protocol-correct response/request framing after transformation. If transformed body length is unknown in h1, the system MUST use streaming-compatible framing and MUST NOT emit an invalid Content-Length.

#### Scenario: Response body modified with unknown final length
- **WHEN** a response transform changes payload length unpredictably
- **THEN** h1 uses streaming-compatible framing and h2 emits correct DATA stream semantics without invalid length metadata

### Requirement: Mid-stream failures SHALL terminate safely by protocol
The system SHALL map mid-stream transform failures to protocol-correct terminal behavior (h1 connection termination or h2 stream reset as appropriate) and SHALL emit structured diagnostics.

#### Scenario: Response transform fails after headers sent
- **WHEN** a response transform error occurs after response headers are emitted
- **THEN** the stream terminates with protocol-correct behavior and logs include plugin id, phase, and failure reason
