## Why

The first `serval-waf` slice can block obvious scanner signatures, but it still misses scanners that probe arbitrary paths without exposing a known user-agent or exact path signature. The next slice should add bounded per-client behavioral detection so Serval can identify short-window burst scanning based on request patterns rather than an ever-growing static rule list.

## What Changes

- Add a new `serval-waf-burst-detection` change that extends the WAF from purely per-request evaluation to bounded per-client behavioral scoring.
- Define a bounded per-client tracking capability keyed by client identity, with explicit limits on table size, counters, and time windows.
- Define burst-detection heuristics for short-window scanning behavior such as many distinct paths, many unrelated sensitive prefixes, and high miss or reject ratios.
- Define how behavioral scores combine with existing high-confidence signature matches to produce `allow`, `flag`, or `block` outcomes.
- Define integration expectations for feeding request outcomes back into WAF state through existing request and log hooks without violating Serval layering rules.

## Capabilities

### New Capabilities
- `waf-client-burst-tracking`: Track bounded per-client request activity over a short window for scanner detection.
- `waf-burst-heuristics`: Evaluate short-window request bursts, path diversity, and suspicious namespace probing as scanner signals.
- `waf-behavioral-scoring`: Combine behavioral burst signals with existing scanner signatures into a unified WAF decision.

### Modified Capabilities
- `waf-scanner-detection`: Extend scanner detection requirements so decisions can include bounded per-client behavioral signals in addition to static signatures.

## Impact

Affected systems include the `serval-waf` module's state model and evaluation path, hook integration points that provide request outcomes back into WAF state, the operator-facing configuration surface for burst thresholds and window size, and test coverage for concurrent per-client tracking and bounded eviction behavior. This change expands `serval-waf` from stateless request evaluation into a bounded stateful detector, so it has broader implementation and verification impact than the initial signature-only slice.
