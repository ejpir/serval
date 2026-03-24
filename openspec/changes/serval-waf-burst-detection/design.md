## Context

The current `serval-waf` slice is intentionally narrow and mostly stateless: it normalizes one request, evaluates scanner signatures, and returns a decision before upstream selection. That works for obvious signatures such as `sqlmap`, `nikto`, `/.git/config`, and `/.env`, but it fails to catch scanners that probe arbitrary paths or cycle through large path sets without exposing a known scanner user-agent.

The next slice extends `serval-waf` into a bounded stateful detector. The state must remain compatible with TigerStyle and Serval's production constraints: fixed-size structures, bounded loops, explicit eviction, no unbounded allocation, and clean integration through existing request and log hooks. This is a more invasive step than adding more signatures because it introduces per-client tracking, time-window accounting, and feedback from request outcomes back into WAF state.

## Goals / Non-Goals

**Goals:**
- Add bounded per-client burst tracking keyed by client identity so `serval-waf` can detect short-window scanning behavior.
- Add behavioral heuristics based on request volume, path diversity, suspicious namespace diversity, and miss or reject ratios.
- Combine behavioral signals with the existing signature-based scanner detection into a unified `allow`, `flag`, or `block` decision.
- Keep memory usage bounded with explicit table capacity, deterministic eviction, and bounded per-entry counters.
- Preserve the current layering model: `serval-waf` remains a layer-2 capability used through request and log hooks.

**Non-Goals:**
- Distributed or cross-process scanner state sharing.
- Full anomaly detection or ML-based behavior classification.
- Long-term reputation scoring across hours or days.
- General-purpose session analysis beyond simple client identity and request outcome feedback.
- Body-based behavioral features in this slice.

## Decisions

### 1. Add a fixed-size per-client tracker inside `serval-waf`
The burst detector should own a bounded table keyed by client identity, with each entry storing the current short-window counters needed for behavioral scoring. The implementation should use a fixed-size CAS-based table with bounded probe and retry budgets so updates remain lock-free but deterministic under contention.

Each table entry should hold only the data needed for the first heuristic set, such as:
- client key (initially client IP / `ctx.client_addr`)
- last seen timestamp
- current window start timestamp
- request count in the active window
- unique path hash count in the active window
- suspicious namespace hit count
- reject or miss count

Alternative considered:
- Dynamic hash maps would be easier to code but violate the bounded-memory goals for the hot path.
- Coarse-grained mutexes are simpler but introduce avoidable global contention in the request path.

### 2. Use short tumbling windows instead of sliding-history logs
The first implementation should use a short bounded window, such as 10s or 30s, represented by a start timestamp plus counters. When the active window expires, the entry resets its counters and begins a new window. Tumbling windows are simpler, deterministic, and avoid storing per-request history.

Alternative considered:
- Sliding windows or ring-buffered request logs provide finer granularity but require more per-entry memory and more complex update logic.

### 3. Track two bounded diversity signals: full-path and sensitive namespaces
The detector needs to distinguish repeated legitimate traffic from scanners probing many distinct paths. The first slice should track both:
- bounded distinct normalized full-path hashes
- bounded sensitive namespace family diversity (for example `/.git`, `/.env`, `/wp-*`, `/phpmyadmin`, `/admin*`, `/actuator`)

Both metrics must be maintained in fixed-size bounded structures rather than storing full path strings.

The design goal is to capture arbitrary-path burst behavior and cross-family probing in one short window without retaining arbitrary request strings in memory.

Alternative considered:
- Storing raw path strings is more accurate but increases memory use, complicates eviction, and leaks more user input into long-lived state.

### 4. Model behavioral signals as scorer inputs, not hard-coded binary blocks
Behavioral detection should produce additional scores and matched behavioral signal identifiers rather than acting as a separate independent block engine. That lets the WAF combine high-confidence signature matches and lower-confidence burst heuristics into one decision model and reuse the existing `allow`, `flag`, and `block` actions.

Initial behavioral signal examples:
- request count threshold exceeded in one short window
- distinct path threshold exceeded in one short window
- suspicious namespace diversity exceeded in one short window
- reject or miss count threshold exceeded in one short window

Alternative considered:
- A separate binary "burst detector" block path would be simpler initially but would split policy logic and make tuning harder.

### 5. Feed request outcomes back through hook integration with explicit ordering
Some behavioral signals require feedback from how the request ended. The detector should integrate at two points:
- pre-routing request inspection and decision evaluation in `onRequest` using a snapshot of previously committed counters
- post-response feedback in `onLog` (or equivalent hook output) to update outcome counters for subsequent requests only

This ordering guarantees that one request is not double-counted in both pre-decision scoring and post-response feedback.

This keeps the WAF as the owner of its own state while using the existing Serval lifecycle hooks rather than inventing a new side-channel API.

Outcome classification should use an explicit `isMiss` classifier hook exposed by `ShieldedHandler`, with a conservative default policy and deployment-specific override points.

Alternative considered:
- Pre-request-only state updates would miss reject-ratio and miss-ratio heuristics.

### 6. Treat table saturation as an explicit degraded mode
When the per-client table is full, the detector should use explicit replacement behavior such as evicting the stalest expired entry or the least recently seen eligible entry. The replacement policy must be deterministic and bounded. Saturation should be observable so operators can tell when tracking fidelity has degraded.

Alternative considered:
- Silent fail-open on saturation would hide coverage loss and make scanner detection quality unpredictable.

### 7. Keep client identity simple in the first slice
The first implementation should key by client address from `ctx.client_addr`. This is enough to support the NetBird and general ingress cases immediately. More complex identity derivation such as forwarded IPs, session keys, or compound keys can be a later extension once the bounded tracking core is proven.

Alternative considered:
- Supporting `X-Forwarded-For` or proxy-aware identity selection immediately expands ambiguity and policy surface too early.

## Risks / Trade-offs

- [Shared client IPs can cause false positives] -> Keep the first thresholds conservative, default to detect-only for new deployments, and make the window and score thresholds explicit operator settings.
- [Approximate distinct-path counting loses precision] -> Prefer bounded approximation over unbounded storage, and use direct signature matches as the high-confidence fast path.
- [State-table saturation reduces detection quality] -> Use explicit replacement rules and emit observable saturation signals for tuning.
- [Per-request state updates increase hot-path cost] -> Keep entry updates O(1), use fixed-size storage, and restrict the first heuristic set to a small number of counters.
- [Miss-ratio heuristics depend on route-specific semantics] -> Use an explicit `isMiss` classifier hook with a conservative default and deployment-specific overrides.

## Migration Plan

1. Add bounded per-client tracker types and configuration to `serval-waf`.
2. Add behavioral scoring that combines burst heuristics with the current signature-based detection path.
3. Integrate outcome feedback into WAF state through existing hook flow (`onRequest` + `onLog`).
4. Expose operator configuration for window size, table size, and behavioral thresholds.
5. Roll out in detect-only mode first, validate false positives, then enable enforce mode where appropriate.

Rollback remains configuration-driven: disable the burst detector or switch it to detect-only mode while keeping the existing signature-based scanner slice active.

## Open Questions

- Should the first burst detector expose only a single combined behavioral score, or also preserve individual behavioral signal identifiers for operators?
- What fixed table size is reasonable for the first slice without overcommitting memory in embedded router deployments?
- What bounded CAS retry budget should be the default before treating a tracker update as saturation/degraded mode?
