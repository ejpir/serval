## 1. Module scaffolding

- [x] 1.1 Create the `serval-waf` module layout and public exports for scanner inspection, detection results, configuration, and enforcement mode types
- [x] 1.2 Add explicit configuration types for scanner signatures, score thresholds, and fail-open or fail-closed enforcement behavior
- [x] 1.3 Add README documentation for `serval-waf` describing the first scanner-blocking slice and its boundaries

## 2. Request inspection pipeline

- [x] 2.1 Implement bounded inspection input construction from request metadata available before upstream selection
- [x] 2.2 Implement canonicalization for path, query, host, and user-agent values used by scanner matching
- [x] 2.3 Add unit tests for normalized matching inputs, including percent-encoded probe paths and case-insensitive header handling

## 3. Scanner rule evaluation

- [x] 3.1 Implement scanner signature definitions with stable rule identifiers, severity, and action contribution
- [x] 3.2 Implement evaluation that returns matched rule identifiers, aggregate score, and `allow` or `flag` or `block` candidates
- [x] 3.3 Add initial scanner-focused rules for known scanner user-agents, high-signal probe paths, and suspicious query patterns
- [x] 3.4 Add unit tests covering direct block signatures, score-threshold blocks, and low-severity flag outcomes

## 4. Enforcement hook integration

- [x] 4.1 Integrate WAF evaluation into request handling before `selectUpstream` without violating Serval layering rules
- [x] 4.2 Implement detect-only behavior that preserves request flow while emitting matched-rule metadata
- [x] 4.3 Implement enforce behavior that returns a direct rejection response on blocking decisions
- [x] 4.4 Implement explicit fail-open and fail-closed handling for WAF execution failures
- [x] 4.5 Add integration tests proving blocked requests stop before upstream selection and detect-only requests continue

## 5. Observability and verification

- [x] 5.1 Emit structured decision metadata for logs and hook consumers, including matched rule identifiers and failure causes
- [x] 5.2 Add tests for failure metadata and enforcement-mode reporting
- [x] 5.3 Verify `serval/ARCHITECTURE.md` remains accurate for the new `serval-waf` first slice and update if required
- [x] 5.4 Run build and targeted test commands for the new module and hook integration paths
