## 1. Bounded Tracker Core

- [x] 1.1 Add bounded per-client tracker types, constants, and configuration fields to `serval-waf` for window duration, table capacity, and heuristic thresholds
- [x] 1.2 Implement a fixed-capacity CAS-based client tracker table keyed by `ctx.client_addr` with bounded retry budgets, deterministic window reset, and deterministic degraded handling on saturation/retry exhaustion
- [x] 1.3 Implement bounded distinct normalized full-path and sensitive-namespace-family counters that avoid storing unbounded request history

## 2. Behavioral Detection

- [x] 2.1 Add stable behavioral signal identifiers and score contributions for request-count, path-diversity, suspicious-namespace, and miss-or-reject heuristics
- [x] 2.2 Integrate behavioral scoring into the existing scanner decision model so static and behavioral signals contribute to one aggregate `allow` / `flag` / `block` result
- [x] 2.3 Surface tracker saturation and behavioral matches in decision metadata so operators can observe degraded tracking and burst detections

## 3. Hook Feedback Integration

- [x] 3.1 Update `serval-waf` request handling so pre-routing evaluation uses prior committed tracker state and preserves bounded hot-path guarantees
- [x] 3.2 Add an explicit `isMiss` classifier hook in `ShieldedHandler` and feed post-request reject/miss outcomes through existing hook flow so they affect subsequent requests only
- [x] 3.3 Preserve fail-open and fail-closed semantics when behavioral tracking or scoring encounters explicit internal failures

## 4. NetBird Configuration And Wiring

- [x] 4.1 Expose NetBird proxy configuration for burst window, tracker table capacity, and behavioral thresholds alongside the existing WAF knobs
- [x] 4.2 Wire the NetBird proxy `ShieldedHandler` configuration to enable burst detection with conservative defaults and startup logging of active behavioral settings
- [x] 4.3 Document the new behavioral WAF knobs in the relevant README and NetBird example config files

## 5. Verification

- [x] 5.1 Add unit tests for tracker allocation, window reset, CAS contention/retry exhaustion, saturation replacement, and bounded full-path and namespace counting
- [x] 5.2 Add behavioral scoring tests covering `allow`, `flag`, and `block` outcomes from static-only, behavioral-only, and combined signals, including no same-request double counting
- [x] 5.3 Add NetBird-facing tests proving burst scans from one client are blocked or flagged while normal low-rate traffic and health endpoints still pass
