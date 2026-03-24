## 1. Standards and Architecture Baseline

- [x] 1.1 Build an RFC compliance matrix for implementation/tests covering TCP (RFC 9293), UDP (RFC 768), and UDP operations (RFC 8085).
- [x] 1.2 Define and document architecture boundaries: strategy outside transport mechanics, with `serval-tcp`/`serval-udp` consuming shared strategy outputs only.
- [x] 1.3 Add/confirm observability cardinality policy defaults (bounded metric labels + sampled high-cardinality logs).

## 2. Extract Shared Load-Balancing Strategy Core

- [x] 2.1 Extract protocol-agnostic RR+health selection core from `serval-lb` (no HTTP `Request`/`LogEntry` dependency in core).
- [x] 2.2 Keep `serval-lb` HTTP adapter API behavior stable by wiring existing `LbHandler` to the new core.
- [x] 2.3 Add strategy config plumbing so TCP/UDP can consume shared strategy without embedding RR logic.
- [x] 2.4 Add regression tests proving existing HTTP LB/router behavior remains unchanged after extraction.

## 3. Extract Shared Prober Scheduler Core

- [x] 3.1 Extract protocol-agnostic probe scheduler/lifecycle core from `serval-prober` (bounded loop, interval/timeout handling, health updates).
- [x] 3.2 Implement HTTP probe adapter preserving current `2xx` success semantics and backward compatibility.
- [x] 3.3 Implement TCP probe adapter using connect-time success/failure semantics.
- [x] 3.4 Implement UDP probe adapter with explicit mode configuration (passive-only vs active probe behavior).
- [x] 3.5 Add regression tests proving existing HTTP probe behavior remains unchanged after extraction.

## 4. Configuration and Capability Wiring

- [x] 4.1 Add `serval-tcp` and `serval-udp` configuration schema sections (listeners, upstream targets, limits, timeouts, TLS mode, probing mode, UDP keying mode) with strict validation errors.
- [x] 4.2 Wire capability enablement so TCP/UDP subsystems are opt-in and HTTP-only deployments remain unchanged when transport configs are absent.
- [x] 4.3 Add startup readiness/registration paths for TCP and UDP listeners with explicit failure propagation on invalid or partial initialization.

## 5. TCP Tunnel Runtime

- [x] 5.1 Implement TCP listener accept loop with bounded concurrency enforcement and explicit connection rejection when at capacity.
- [x] 5.2 Integrate shared strategy selection + health state for TCP upstream selection.
- [x] 5.3 Implement upstream connect path with timeout handling for plain/passthrough and TLS modes.
- [x] 5.4 Implement bidirectional TCP forwarding lifecycle (open, relay, half-close/full-close, deterministic cleanup).
- [x] 5.5 Enforce per-tunnel idle timeout and ensure resource reclamation on all shutdown/error paths.

## 6. UDP Tunnel Runtime

- [x] 6.1 Implement UDP ingress/egress forwarding preserving datagram boundaries.
- [x] 6.2 Integrate shared strategy selection + health state for UDP upstream selection.
- [x] 6.3 Implement configurable UDP session keying modes with bounded mapping table.
- [x] 6.4 Enforce session idle expiration and bounded max active sessions with automatic reclamation.
- [x] 6.5 Implement explicit overload/drop behavior for session/buffer exhaustion while preserving unrelated session forwarding.

## 7. Observability, Verification, and Documentation

- [x] 7.1 Add TCP telemetry: accepted connections, active tunnels, directional bytes, connect failures, timeout closures, capacity rejections.
- [x] 7.2 Add UDP telemetry: packets received/forwarded/dropped, active sessions, session create/expire counts, upstream forwarding/probe errors.
- [ ] 7.3 Add structured logs for tunnel establishment, forwarding failures, and bounded-resource rejection/drop events (with sampling for endpoint-heavy detail).
- [x] 7.4 Add unit/integration tests for config validation, strategy/prober extraction regression, TCP/UDP happy paths, failures, and overload behavior.
- [x] 7.5 Update module docs/READMEs and architecture references for shared strategy/prober cores plus new `serval-tcp`/`serval-udp` capability contracts.
