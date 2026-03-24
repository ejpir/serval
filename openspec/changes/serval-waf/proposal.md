## Why

Serval has routing, load balancing, health checks, TLS, and proxying, but it does not yet have a first-class request inspection and blocking layer for obvious hostile traffic. The first slice should focus on reliably identifying scanner traffic and blocking it before it reaches upstream services, while preserving a path to broader WAF coverage later.

## What Changes

- Add a new `serval-waf` change that defines a reusable request inspection and blocking capability before upstream selection.
- Define bounded request inspection requirements for path, query, headers, and connection metadata needed to identify common scanner signatures and probing behavior.
- Define rule evaluation requirements for scanner detection, including stable rule identifiers, matched-signal reporting, and an explicit block decision.
- Define enforcement behavior for detect-only and enforce modes, including blocking responses and structured decision reporting for logs and hooks.
- Defer broader general-purpose WAF coverage such as deep body inspection and broad attack-class scoring to later slices.
- Define integration expectations for using the WAF from Serval handler hooks without introducing sideways layer dependencies.

## Capabilities

### New Capabilities
- `waf-request-inspection`: Inspect inbound HTTP request metadata needed to identify scanner traffic before forwarding.
- `waf-scanner-detection`: Evaluate request data against scanner signatures and probing heuristics, track matched rules, and compute an allow, flag, or block decision.
- `waf-enforcement-hooks`: Apply WAF decisions through Serval request hooks with explicit behavior for detect-only and enforce modes.

### Modified Capabilities
- None.

## Impact

Affected systems include the future `serval-waf` layer-2 module, request hook integration points in higher-level handler composition, logging/observability for WAF decisions, and the operator-facing configuration surface for scanner signatures and enforcement mode. No existing published capability spec is modified by this change.
