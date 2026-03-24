## Context

Serval's architecture already reserves `serval-waf` as a future layer-2 infrastructure module responsible for request inspection, rule evaluation, and blocking decisions before upstream forwarding. The proposal now narrows the first slice to three capabilities: bounded request inspection, scanner detection, and enforcement hooks. The design must fit Serval's layering rules, avoid sideways dependencies, keep all inspection bounded, and integrate through existing handler hooks so strategy and proxy modules do not absorb WAF-specific logic.

The immediate consumers are higher-level handler compositions in `serval-server`, `serval-lb`, and `serval-router`, which need a reusable decision engine they can call during request processing. Because this is security-sensitive infrastructure, the design favors explicit configuration, deterministic rule evaluation, and failure behavior that does not silently bypass policy.

## Goals / Non-Goals

**Goals:**
- Provide a reusable layer-2 WAF module with a small, explicit API for scanner-oriented request inspection and decision evaluation.
- Support bounded analysis of request path, query, headers, and connection metadata required to identify scanner traffic.
- Support rule matching for an initial scanner-focused rule set, such as suspicious paths, probing sequences, and known scanner user-agent patterns.
- Support both detect-only and enforce modes with structured decision output for logs and hooks.
- Preserve Serval layering by exposing WAF decisions to orchestration layers without embedding WAF logic in strategy or proxy modules.

**Non-Goals:**
- Full OWASP CRS parity in the first implementation.
- Deep semantic parsing of arbitrary body formats or unbounded body buffering.
- General-purpose detection for every attack class beyond the initial scanner slice.
- Distributed rule synchronization or dynamic remote rule loading.
- Response-body inspection in the first iteration.
- Replacing existing handler hooks or introducing a separate policy engine outside Serval.

## Decisions

### 1. Implement `serval-waf` as a standalone layer-2 module
The WAF belongs in its own infrastructure module because it is reusable across multiple handlers, has its own configuration and rule lifecycle, and should remain independent from load-balancing or forwarding strategy.

Alternative considered:
- Embedding WAF checks directly into `serval-server` or `serval-router` would violate the architecture by coupling a cross-cutting concern to orchestration or strategy modules.

### 2. Expose a two-stage API: inspect request input, then evaluate rules
The module should separate request normalization/collection from decision evaluation. A practical shape is:
- an immutable inspection input containing method, host, path, query, headers, connection metadata, and optional bounded body bytes
- an evaluation result containing mode, matched rule identifiers, threat categories, score, and final action (`allow`, `flag`, `block`)

This keeps parsing and policy distinct, makes testing easier, and lets higher-level modules decide when bounded body bytes are available.

Alternative considered:
- A single monolithic `evaluate(request)` entry point would hide data collection and make it harder to reason about bounded-body behavior and hook integration.

### 3. Normalize only the inputs needed for deterministic scanner matching
The WAF should operate on canonicalized request fields before scanner evaluation:
- path and query are percent-decoded once with invalid encodings treated as inspection failures or suspicious input based on mode
- header names are normalized for case-insensitive matching
- user-agent and host are normalized into stable comparison forms

Normalization is necessary for stable matching and to avoid duplicate scanner signatures across raw and decoded forms.

Alternative considered:
- Matching directly on raw request bytes is simpler but produces inconsistent behavior and misses encoded attack variants.

### 4. Use statically configured scanner signatures and heuristics
Rules should be configured locally from explicit data structures in the first iteration, grouped by scanner signal type and carrying stable identifiers, severity, and action contribution. The first slice should prioritize signals such as known scanner user-agents, requests for high-signal probe paths, and short-window repeated probing against unrelated sensitive endpoints. This makes decisions auditable and deterministic and avoids introducing a remote dependency or runtime rule compiler.

Alternative considered:
- Loading third-party dynamic rule languages initially would expand scope, add parsing complexity, and weaken the boundedness guarantees required by TigerStyle.

### 5. Use simple score-based evaluation with mode-specific enforcement
Each matched scanner signal contributes to a decision record. Enforcement applies as follows:
- `detect-only`: never blocks, but returns `flag` for suspicious requests and records matches
- `enforce`: blocks when a blocking rule matches or when aggregate score reaches a configured threshold

This balances direct signature blocks with flexible multi-signal scoring and gives operators a safer rollout path.

Alternative considered:
- Pure binary rule blocking is simpler but makes gradual deployment and signal tuning harder.

### 6. Integrate through existing request hooks before upstream selection
Higher-level handlers should invoke the WAF during request handling before `selectUpstream`. On a `block` decision, the handler returns a direct rejection response. On `allow` or `flag`, normal routing continues, with `flag` attached to logs or metrics.

This preserves the existing abstraction rule that strategy modules decide where traffic goes while WAF remains an infrastructure capability used by orchestration.

Alternative considered:
- Running WAF checks after upstream selection wastes work and complicates failure semantics because the request may already have been partially committed to forwarding.

### 7. Failures in WAF execution are explicit and configurable
Internal failures such as malformed configuration, exceeded inspection bounds, or normalization errors should never be swallowed. The module should support explicit fail-open or fail-closed behavior in configuration, with the chosen behavior reflected in the decision result and logs.

Alternative considered:
- Implicit fail-open behavior reduces security predictability and makes operational issues hard to detect.

## Risks / Trade-offs

- [False positives block legitimate traffic] -> Start with detect-only mode, stable rule identifiers, and operator-visible match reporting before enabling enforcement.
- [Scanner heuristics miss low-and-slow probes] -> Start with explicit high-signal signatures and add lightweight sequence-based signals only after the baseline path is stable.
- [Inspection cost increases request latency] -> Keep inspection bounded, normalize only required fields, and avoid body parsing in the first iteration.
- [Hook integration leaks WAF concerns into higher layers] -> Keep the WAF API narrow and return generic actions and metadata rather than exposing rule internals throughout the stack.
- [Rule sets become hard to evolve] -> Use stable categories and identifiers from the start so future spec changes can extend rather than rename behavior.
- [Fail-closed behavior can amplify outages] -> Make failure mode explicit per deployment and surface errors clearly in logs and metrics.

## Migration Plan

1. Add the `serval-waf` module with its core types, configuration, rule representation, and evaluation engine.
2. Integrate invocation into handler request hooks before upstream selection, initially with detect-only mode available by default.
3. Add observability for matched rules, decision counts, and internal WAF failures.
4. Enable enforce mode for selected deployments after validating false-positive rates.
5. Extend beyond scanner detection only after the scanner-focused slice is stable and false-positive behavior is understood.

Rollback is straightforward because WAF participation is configuration-driven: disable WAF integration or revert to detect-only mode to stop blocking while preserving the rest of the request path.

## Open Questions

- Should the first slice include any short-window correlation across requests, or remain purely per-request?
- Should invalid percent-encoding always be treated as suspicious input, or should that be rule-driven?
- How much structured match detail should be exposed to logs without leaking sensitive payload fragments?
- Should the first iteration include per-rule overrides for detect-only versus block behavior, or only signature and score thresholds?
