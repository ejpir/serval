# serval-waf

Scanner-focused request inspection and blocking for Serval.

## Purpose

`serval-waf` is a layer-2 infrastructure module that identifies scanner traffic before upstream selection. It supports direct signatures and bounded per-client burst heuristics.

## First Slice Scope

Included:
- Metadata-only inspection before upstream selection
- Canonicalized path, query, host, and `User-Agent` matching
- Bounded per-client short-window burst tracking keyed by client address
- Behavioral scoring for request burst, path diversity, suspicious namespace diversity, and miss/reject bursts
- Stable rule identifiers and explicit `allow` / `flag` / `block` decisions
- Detect-only and enforce modes
- Explicit fail-open and fail-closed behavior for normalization failures
- A generic handler wrapper that applies WAF checks in `onRequest` and feeds outcomes in `onLog`

Deferred:
- Deep body inspection
- General-purpose OWASP CRS style coverage
- Dynamic rule loading
- Response-body inspection
- Distributed correlation state

## Exports

- `Config` - scanner rule set, thresholds, enforcement mode, failure mode
- `ScannerRule` - stable rule identifier plus field, pattern, score, and disposition
- `InspectionInput` - normalized request metadata used for matching
- `Decision` - match metadata, score, action, and optional failure cause
- `BehavioralSnapshot` - bounded per-client counters used for burst heuristics
- `ShieldedHandler(Inner)` - generic wrapper that applies WAF checks before `selectUpstream`
- `default_scanner_rules` - initial scanner-oriented signatures for obvious probes
- `evaluate()` - pure scanner evaluation helper

## Usage

```zig
const serval = @import("serval");
const serval_lb = @import("serval-lb");
const serval_waf = @import("serval-waf");

const rules = serval_waf.default_scanner_rules[0..];
var lb_handler: serval_lb.LbHandler = undefined;
try lb_handler.init(&upstreams, .{ .enable_probing = false }, null, null);

var protected = try serval_waf.ShieldedHandler(serval_lb.LbHandler).init(
    &lb_handler,
    .{
        .rules = rules,
        .block_threshold = 100,
        .enforcement_mode = .enforce,
        .failure_mode = .fail_closed,
    },
    null,
    null,
);

var server = serval.MinimalServer(@TypeOf(protected)).init(
    &protected,
    &pool,
    &metrics,
    &tracer,
    .{},
    null,
    dns_config,
);
```

## Matching Model

The first slice supports scanner-oriented signals only:
- known scanner `User-Agent` patterns such as `sqlmap` and `nikto`
- high-signal probe paths such as `/.git/config` and `/.env`
- suspicious query patterns associated with probing

Each signal has a stable identifier. Static and behavioral matches accumulate score and may produce direct block or threshold block decisions.

Behavioral signals:
- short-window request burst
- distinct normalized path burst
- suspicious namespace family diversity
- miss/reject burst

## Enforcement Model

- `detect_only`: blocking candidates continue through normal routing, but the observer still receives decision metadata
- `enforce`: blocking candidates return a reject action before `selectUpstream`
- `fail_open`: normalization failures are reported but traffic continues
- `fail_closed`: normalization failures are reported and rejected

## Burst Tracking Knobs

- `burst_enabled` - enables per-client burst scoring
- `burst_window_ns` - short window duration in nanoseconds
- `burst_tracker_capacity` - fixed client table capacity
- `burst_tracker_retry_budget` - bounded CAS retries before degraded mode
- `burst_request_threshold`, `burst_unique_path_threshold`, `burst_namespace_threshold`, `burst_miss_reject_threshold`
- `burst_request_score`, `burst_unique_path_score`, `burst_namespace_score`, `burst_miss_reject_score`

## Testing

The module includes unit coverage for:
- percent-decoding and normalization
- case-insensitive header and signature matching
- direct block and score-threshold decisions
- detect-only vs enforce behavior
- fail-closed failure reporting
