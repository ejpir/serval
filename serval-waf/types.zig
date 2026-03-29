//! serval-waf/types.zig
//! Scanner-focused WAF types.
//!
//! TigerStyle: fixed-size config, explicit enums, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");

const Request = core.Request;
const Context = core.Context;
const Method = core.Method;
const strings = core.strings;
const config = core.config;

/// Maximum number of scanner rules supported by the WAF.
/// Use this constant as the upper bound for rule-count validation and fixed-capacity allocations.
/// Stored as `u8`; valid configured counts are expected to be in the range `0..=MAX_SCANNER_RULES`.
pub const MAX_SCANNER_RULES: u8 = 32;
/// Upper bound on how many WAF rules may be recorded as matched in one operation.
/// This is a compile-time `u8` limit set to `8`.
/// Code that stores matched-rule results should treat this value as the capacity cap.
pub const MAX_MATCHED_RULES: u8 = 8;
/// Maximum number of entries a tracker is allowed to hold.
/// Use this as the hard upper bound when validating or sizing tracker-backed storage.
/// Compile-time constant (`u16`); this declaration itself does not allocate or return errors.
pub const MAX_TRACKER_CAPACITY: u16 = 1024;
/// Maximum number of distinct path hashes tracked per burst-tracker entry.
/// Used as the fixed capacity for per-entry `path_hashes` storage and as the bound for `unique_path_count`.
/// When this limit is reached, additional distinct path hashes are not recorded for that entry.
/// Compile-time `u8` constant; this declaration has no ownership or error behavior.
pub const MAX_TRACKED_PATH_HASHES: u8 = 16;
/// Maximum number of compare-and-swap retry attempts allowed for tracker updates.
/// This constant bounds CAS retry loops to prevent unbounded spinning under contention.
/// Callers should treat reaching this limit as a failed update attempt and return/propagate
/// their operation-specific contention/retry-exhausted error path.
pub const MAX_TRACKER_CAS_RETRIES: u8 = 32;
/// Maximum size, in bytes, for a normalized path.
/// Use this constant as the hard upper bound when sizing buffers or validating normalized-path length.
/// Fixed compile-time limit (`2048`) expressed as `u16` for bounded path-size handling.
pub const MAX_NORMALIZED_PATH_BYTES: u16 = 2048;
/// Upper bound, in bytes, for a normalized query string representation.
/// Use this constant when sizing buffers or validating normalized query length in `serval-waf`.
/// Inputs larger than this limit must be rejected or truncated by the calling logic.
pub const MAX_NORMALIZED_QUERY_BYTES: u16 = 1024;
/// Maximum allowed size, in bytes, for a normalized host value.
/// Callers should ensure any normalized host buffer or serialized host field does not exceed this limit.
/// Use this as a validation bound before allocation or normalization-dependent processing.
pub const MAX_NORMALIZED_HOST_BYTES: u16 = 512;
/// Maximum byte length allowed for a normalized `User-Agent` value.
/// Use this as the hard upper bound when allocating buffers or validating normalized header data.
/// Values beyond this limit must be handled by caller logic (for example, reject or truncate before storage).
pub const MAX_NORMALIZED_USER_AGENT_BYTES: u16 = 512;

/// Controls how WAF decisions are applied at runtime.
/// `detect_only` records/observes matches but does not actively block requests.
/// `enforce` applies blocking actions when rules match.
/// This enum is a pure policy selector and does not allocate or return errors by itself.
pub const EnforcementMode = enum {
    detect_only,
    enforce,
};

/// Selects how request handling behaves when WAF evaluation cannot complete.
/// `fail_open` permits traffic on WAF failure to preserve availability.
/// `fail_closed` denies traffic on WAF failure to preserve security.
/// Callers should set this explicitly based on their availability vs. security requirements.
pub const FailureMode = enum {
    fail_open,
    fail_closed,
};

/// Disposition returned by WAF decision logic for a request or event.
/// `allow` permits normal processing with no enforcement action.
/// `flag` keeps processing but marks the event for reporting/audit handling.
/// `block` denies processing and triggers enforcement in the caller.
pub const DecisionAction = enum {
    allow,
    flag,
    block,
};

/// Enumerates failure modes produced while processing/normalizing input fields.
/// `invalid_percent_encoding` indicates malformed percent-encoded data.
/// `normalized_field_too_long` indicates normalization would exceed the allowed field-length limit.
/// Use this value to branch on failure cause; it carries no ownership or lifetime semantics.
pub const FailureReason = enum {
    invalid_percent_encoding,
    normalized_field_too_long,
};

/// Snapshot of per-source behavioral counters used by WAF policy evaluation.
/// `request_count` tracks total observed requests; `miss_reject_count` tracks rejected misses.
/// `unique_path_count` and `namespace_family_count` are compact cardinality counters (`u8`).
/// `tracker_degraded` is `true` when tracking quality is degraded and counts may be incomplete.
/// All fields are value data with zero defaults; no ownership or lifetime management is required.
pub const BehavioralSnapshot = struct {
    request_count: u16 = 0,
    unique_path_count: u8 = 0,
    namespace_family_count: u8 = 0,
    miss_reject_count: u16 = 0,
    tracker_degraded: bool = false,
};

/// Selects which HTTP request field a WAF match condition evaluates.
/// `path` targets the request path, `query` targets the URL query string,
/// `host` targets the `Host` header value, and `user_agent` targets the `User-Agent` header value.
/// This enum is a pure selector and performs no allocation or error-producing work.
pub const MatchField = enum {
    path,
    query,
    host,
    user_agent,
};

/// Selects the string-matching strategy for rule evaluation.
/// All variants are ASCII case-insensitive (`ascii_ci`) and differ by match shape.
/// `contains_ascii_ci` matches a substring, `prefix_ascii_ci` matches from the start,
/// and `exact_ascii_ci` requires the full value to match.
pub const MatchKind = enum {
    contains_ascii_ci,
    prefix_ascii_ci,
    exact_ascii_ci,
};

/// Disposition a WAF rule can produce when it matches.
/// `score` indicates the rule contributes to scoring rather than immediate rejection.
/// `block` indicates the rule requests blocking the traffic immediately.
/// This enum is a plain value type with no owned resources or lifetimes.
pub const RuleDisposition = enum {
    score,
    block,
};

/// Defines a single WAF scanner rule: which field to inspect, how to match, and the resulting score/disposition.
/// `init` builds the value without allocation or copying; `id` and `pattern` are retained as borrowed slices.
/// Callers must ensure `id.len > 0`, `pattern.len > 0`, and `score > 0` unless `disposition == .block`.
/// Invalid inputs are rejected via `assert` checks (no error return).
pub const ScannerRule = struct {
    id: []const u8,
    field: MatchField,
    kind: MatchKind,
    pattern: []const u8,
    score: u16,
    disposition: RuleDisposition,

    /// Initializes a `ScannerRule` from caller-provided fields without copying `id` or `pattern`.
    /// Preconditions: `id.len > 0`, `pattern.len > 0`, and either `score > 0` or `disposition == .block`.
    /// Stores `id` and `pattern` slices by reference; the underlying bytes must remain valid for the rule's lifetime.
    /// This function does not return an error; precondition violations trigger assertions.
    pub fn init(
        id: []const u8,
        field: MatchField,
        kind: MatchKind,
        pattern: []const u8,
        score: u16,
        disposition: RuleDisposition,
    ) ScannerRule {
        assert(id.len > 0);
        assert(pattern.len > 0);
        assert(score > 0 or disposition == .block);
        return .{
            .id = id,
            .field = field,
            .kind = kind,
            .pattern = pattern,
            .score = score,
            .disposition = disposition,
        };
    }
};

/// Runtime configuration for WAF scanning, enforcement, and optional burst-based scoring controls.
/// `rules` is required and is borrowed (`[]const ScannerRule`); the underlying rule storage must outlive any user of this `Config`.
/// `block_threshold` and burst thresholds/scores tune when traffic is considered blockable; `enforcement_mode` and `failure_mode` define whether decisions are enforced and how failures are handled.
/// Defaults are conservative: detect-only, fail-open, HTTP `403`, reason `"Scanner blocked"`, and burst detection disabled unless `burst_enabled` is set.
pub const Config = struct {
    /// Default request/block decision threshold used by the WAF when no override is configured.
    /// Value is `100` and stored as `u16`, so callers should keep configured thresholds within `u16` range.
    /// This constant has no allocation, ownership, or error behavior.
    pub const DEFAULT_BLOCK_THRESHOLD: u16 = 100;
    /// Default burst-window duration, in nanoseconds, for WAF rate/burst calculations.
    /// Value is `10 * core.time.ns_per_s` (10 seconds).
    /// Stored as `u64` to match nanosecond-based timing/config fields.
    pub const DEFAULT_BURST_WINDOW_NS: u64 = 10 * core.time.ns_per_s;
    /// Default capacity used for burst-tracker storage when no explicit capacity is configured.
    /// Value is fixed at `256` entries and expressed as `u16` for configuration/type consistency.
    pub const DEFAULT_BURST_TRACKER_CAPACITY: u16 = 256;
    /// Default retry budget for burst-tracker operations in `Config`.
    /// Used to initialize `Config.burst_tracker_retry_budget` when callers do not provide an explicit value.
    /// Fixed at `8` (`u8`); this constant has no ownership, lifetime, allocation, or error behavior.
    pub const DEFAULT_BURST_TRACKER_RETRY_BUDGET: u8 = 8;
    /// Default burst-request threshold used by WAF rate/burst checks.
    /// Value is a request count (`u16`): traffic at or above this count is treated as burst traffic by logic that uses this default.
    /// This constant is compile-time configuration data and has no ownership or error behavior.
    pub const DEFAULT_BURST_REQUEST_THRESHOLD: u16 = 20;
    /// Default cap for the "unique paths in a burst" threshold used by WAF configuration.
    /// Applied when no explicit `burst_unique_path_threshold` value is provided.
    /// Value is `16` (`u8`), so any override must fit in the `u8` range.
    pub const DEFAULT_BURST_UNIQUE_PATH_THRESHOLD: u8 = 16;
    /// Default burst namespace threshold used when no explicit value is configured.
    /// This constant provides the baseline limit for namespace-threshold checks.
    /// The default value is `3` (`u8`).
    pub const DEFAULT_BURST_NAMESPACE_THRESHOLD: u8 = 3;
    /// Default threshold for burst-miss rejection logic.
    /// Used when no explicit burst-miss reject threshold is configured.
    /// Value: `10` (`u16`).
    pub const DEFAULT_BURST_MISS_REJECT_THRESHOLD: u16 = 10;
    /// Default score assigned to a burst-request signal in WAF scoring logic.
    /// Use this constant when no rule-specific burst-request score is configured.
    /// Value is `u16` and represents score points (`40` by default).
    pub const DEFAULT_BURST_REQUEST_SCORE: u16 = 40;
    /// Default score contribution for detections involving a burst of unique request paths.
    /// Used as the baseline `u16` value when this signal is not explicitly overridden in configuration.
    /// Pure constant data (`50`): no ownership, lifetime, or error semantics apply.
    pub const DEFAULT_BURST_UNIQUE_PATH_SCORE: u16 = 50;
    /// Default burst-namespace score value used when no namespace-specific score is configured.
    /// Stored as `u16` and initialized to `60`; callers may override this with an explicit per-namespace score.
    pub const DEFAULT_BURST_NAMESPACE_SCORE: u16 = 60;
    /// Default rejection score contribution for a burst miss condition in WAF scoring.
    /// Used as the baseline `u16` value when no explicit burst-miss reject score is configured.
    /// Higher values increase the chance that burst misses push a request over a reject threshold.
    pub const DEFAULT_BURST_MISS_REJECT_SCORE: u16 = 60;

    rules: []const ScannerRule,
    block_threshold: u16 = DEFAULT_BLOCK_THRESHOLD,
    enforcement_mode: EnforcementMode = .detect_only,
    failure_mode: FailureMode = .fail_open,
    block_status: u16 = 403,
    block_reason: []const u8 = "Scanner blocked",
    burst_enabled: bool = false,
    burst_window_ns: u64 = DEFAULT_BURST_WINDOW_NS,
    burst_tracker_capacity: u16 = DEFAULT_BURST_TRACKER_CAPACITY,
    burst_tracker_retry_budget: u8 = DEFAULT_BURST_TRACKER_RETRY_BUDGET,
    burst_request_threshold: u16 = DEFAULT_BURST_REQUEST_THRESHOLD,
    burst_unique_path_threshold: u8 = DEFAULT_BURST_UNIQUE_PATH_THRESHOLD,
    burst_namespace_threshold: u8 = DEFAULT_BURST_NAMESPACE_THRESHOLD,
    burst_miss_reject_threshold: u16 = DEFAULT_BURST_MISS_REJECT_THRESHOLD,
    burst_request_score: u16 = DEFAULT_BURST_REQUEST_SCORE,
    burst_unique_path_score: u16 = DEFAULT_BURST_UNIQUE_PATH_SCORE,
    burst_namespace_score: u16 = DEFAULT_BURST_NAMESPACE_SCORE,
    burst_miss_reject_score: u16 = DEFAULT_BURST_MISS_REJECT_SCORE,

    /// Validates this `Config` and returns the first configuration error encountered.
    /// Requires `rules.len` to be in `1..=MAX_SCANNER_RULES` and `block_status` to be in `400..=599`.
    /// When `burst_enabled` is `true`, additionally requires non-zero burst window, thresholds, and scores, plus tracker bounds `1..=MAX_TRACKER_CAPACITY` and retry budget `1..=MAX_TRACKER_CAS_RETRIES`.
    /// Preconditions are also enforced with assertions: `block_threshold > 0` must hold (assert failure, not an error return).
    pub fn validate(
        self: *const Config,
    ) error{
        TooManyRules,
        EmptyRules,
        InvalidBlockStatus,
        InvalidBurstWindow,
        InvalidBurstTrackerCapacity,
        InvalidBurstRetryBudget,
        InvalidBurstThreshold,
        InvalidBurstScore,
    }!void {
        assert(self.block_threshold > 0);
        if (self.rules.len == 0) return error.EmptyRules;
        if (self.rules.len > MAX_SCANNER_RULES) return error.TooManyRules;
        if (self.block_status < 400 or self.block_status > 599) return error.InvalidBlockStatus;
        if (!self.burst_enabled) return;
        if (self.burst_window_ns == 0) return error.InvalidBurstWindow;
        if (self.burst_tracker_capacity == 0 or self.burst_tracker_capacity > MAX_TRACKER_CAPACITY) {
            return error.InvalidBurstTrackerCapacity;
        }
        if (self.burst_tracker_retry_budget == 0 or self.burst_tracker_retry_budget > MAX_TRACKER_CAS_RETRIES) {
            return error.InvalidBurstRetryBudget;
        }
        if (self.burst_request_threshold == 0 or self.burst_unique_path_threshold == 0 or self.burst_namespace_threshold == 0 or self.burst_miss_reject_threshold == 0) {
            return error.InvalidBurstThreshold;
        }
        if (self.burst_request_score == 0 or self.burst_unique_path_score == 0 or self.burst_namespace_score == 0 or self.burst_miss_reject_score == 0) {
            return error.InvalidBurstScore;
        }
    }
};

/// Fixed-capacity scratch buffers used during request inspection/normalization.
/// Stores path, query, host, and user-agent bytes in-place, each bounded by its corresponding `MAX_NORMALIZED_*_BYTES` constant.
/// Buffers are zero-initialized on construction and are owned by the `InspectionScratch` instance.
/// No allocation or error-returning behavior is provided by this type itself.
pub const InspectionScratch = struct {
    path_buf: [MAX_NORMALIZED_PATH_BYTES]u8 = std.mem.zeroes([MAX_NORMALIZED_PATH_BYTES]u8),
    query_buf: [MAX_NORMALIZED_QUERY_BYTES]u8 = std.mem.zeroes([MAX_NORMALIZED_QUERY_BYTES]u8),
    host_buf: [MAX_NORMALIZED_HOST_BYTES]u8 = std.mem.zeroes([MAX_NORMALIZED_HOST_BYTES]u8),
    user_agent_buf: [MAX_NORMALIZED_USER_AGENT_BYTES]u8 = std.mem.zeroes([MAX_NORMALIZED_USER_AGENT_BYTES]u8),
};

/// Canonical WAF inspection view of a request with normalized string fields.
/// `fromRequest` splits `request.path` into path/query, percent-decodes both, and lowercases `host` and `user-agent`.
/// Preconditions (asserted): `request.path.len <= config.MAX_URI_LENGTH_BYTES` and `ctx.client_addr.len > 0`.
/// Returned `path`, `query`, `host`, and `user_agent` slices are backed by `scratch` buffers and are valid only while `scratch` is unchanged.
/// Returns `error.InvalidPercentEncoding` for bad `%` escapes and `error.NormalizedFieldTooLong` if decoded/normalized output does not fit destination buffers.
pub const InspectionInput = struct {
    method: Method,
    path: []const u8,
    query: []const u8,
    host: []const u8,
    user_agent: []const u8,
    client_addr: []const u8,

    /// Builds `InspectionInput` from `request`/`ctx` by splitting `request.path` at `?`, percent-decoding path/query, and lowercasing `Host`/`user-agent` header values.
    /// Requires `request.path.len <= config.MAX_URI_LENGTH_BYTES` and `ctx.client_addr.len > 0` (asserted).
    /// Returned `path`, `query`, `host`, and `user_agent` slices alias `scratch` buffers; they are valid only while `scratch` remains alive and unchanged.
    /// `client_addr` aliases storage in `ctx` (NUL-terminated slice view) and must not outlive `ctx`.
    /// Returns `error.InvalidPercentEncoding` for malformed `%xx` sequences and `error.NormalizedFieldTooLong` when normalized output would exceed fixed scratch buffer capacity.
    pub fn fromRequest(
        request: *const Request,
        ctx: *const Context,
        scratch: *InspectionScratch,
    ) error{ InvalidPercentEncoding, NormalizedFieldTooLong }!InspectionInput {
        assert(request.path.len <= config.MAX_URI_LENGTH_BYTES);
        assert(ctx.client_addr.len > 0);

        const split = splitPathAndQuery(request.path);
        const path = try decodePercentInto(scratch.path_buf[0..], split.path);
        const query = try decodePercentInto(scratch.query_buf[0..], split.query);
        const host = try normalizeLowerInto(scratch.host_buf[0..], request.headers.getHost() orelse "");
        const user_agent = try normalizeLowerInto(scratch.user_agent_buf[0..], request.headers.get("user-agent") orelse "");
        const client_addr = std.mem.sliceTo(&ctx.client_addr, 0);

        return .{
            .method = request.method,
            .path = path,
            .query = query,
            .host = host,
            .user_agent = user_agent,
            .client_addr = client_addr,
        };
    }
};

/// Aggregates WAF evaluation output: selected `action`/`enforcement_mode`, accumulated `score`, counters, optional `failure_reason`, and up to `MAX_MATCHED_RULES` matched rule IDs.
/// `addMatch` and `addBehavioralMatch` require `id.len > 0` (asserted) and record IDs only while capacity remains.
/// `match_count` and `behavioral_match_count` use saturating increments; counts may exceed stored ID capacity, so use `effectiveMatchCount()` for bounded iteration.
/// `matched_rule_ids` stores borrowed `[]const u8` slices without copying; callers own backing memory and must keep it valid for the `Decision`’s use lifetime.
/// `addBehavioralMatch` increments `behavioral_match_count` and then performs the same match-recording behavior as `addMatch`.
pub const Decision = struct {
    action: DecisionAction = .allow,
    enforcement_mode: EnforcementMode = .detect_only,
    score: u16 = 0,
    match_count: u8 = 0,
    behavioral_match_count: u8 = 0,
    tracker_degraded: bool = false,
    matched_rule_ids: [MAX_MATCHED_RULES]?[]const u8 = [_]?[]const u8{null} ** MAX_MATCHED_RULES,
    failure_reason: ?FailureReason = null,

    /// Records a matched rule identifier for this decision.
    /// `id` must be non-empty (`assert(id.len > 0)`); otherwise debug/safe builds will trap.
    /// Stores `id` by slice reference (no copy) while `match_count < MAX_MATCHED_RULES`; extra matches are counted but not stored.
    /// Never returns an error; `match_count` is incremented with saturating addition.
    pub fn addMatch(self: *Decision, id: []const u8) void {
        assert(id.len > 0);
        if (self.match_count < MAX_MATCHED_RULES) {
            self.matched_rule_ids[self.match_count] = id;
        }
        self.match_count +|= 1;
    }

    /// Returns the number of matches capped to the representable rule limit.
    /// This is `min(self.match_count, MAX_MATCHED_RULES)`, so values above the cap are saturated.
    /// Requires `self` to point to a valid `Decision`.
    /// Does not allocate, mutate state, or return errors.
    pub fn effectiveMatchCount(self: *const Decision) u8 {
        return @min(self.match_count, MAX_MATCHED_RULES);
    }

    /// Records a behavioral match and tracks it in the decision totals.
    /// Preconditions: `id.len > 0` (enforced with `assert`).
    /// Increments `behavioral_match_count` using saturating addition (`+|=`), so it clamps at the counter’s max value.
    /// Delegates to `addMatch(id)` to register the same match identifier; this function does not return errors.
    pub fn addBehavioralMatch(self: *Decision, id: []const u8) void {
        assert(id.len > 0);
        self.behavioral_match_count +|= 1;
        self.addMatch(id);
    }
};

/// Callback type for WAF observation hooks, invoked with the request context, request, and computed decision.
/// All parameters are borrowed, read-only pointers; implementations must treat them as immutable input data.
/// Preconditions: `ctx`, `request`, and `decision` must point to valid initialized values for the duration of the call.
/// Returns `void` and cannot propagate errors; observer-side failure handling must be internal.
pub const ObserveFn = *const fn (
    ctx: *const Context,
    request: *const Request,
    decision: *const Decision,
) void;

const SplitPathAndQuery = struct {
    path: []const u8,
    query: []const u8,
};

fn splitPathAndQuery(raw_target: []const u8) SplitPathAndQuery {
    assert(raw_target.len <= config.MAX_URI_LENGTH_BYTES);
    const query_idx = std.mem.indexOfScalar(u8, raw_target, '?') orelse {
        return .{ .path = raw_target, .query = "" };
    };
    return .{
        .path = raw_target[0..query_idx],
        .query = raw_target[query_idx + 1 ..],
    };
}

fn normalizeLowerInto(dest: []u8, src: []const u8) error{NormalizedFieldTooLong}![]const u8 {
    assert(dest.len > 0);
    if (src.len > dest.len) return error.NormalizedFieldTooLong;

    var idx: u16 = 0;
    while (idx < src.len) : (idx += 1) {
        const byte = src[idx];
        dest[idx] = if (byte >= 'A' and byte <= 'Z') byte + 32 else byte;
    }
    return dest[0..src.len];
}

fn decodePercentInto(dest: []u8, src: []const u8) error{ InvalidPercentEncoding, NormalizedFieldTooLong }![]const u8 {
    assert(dest.len > 0);
    var src_idx: u16 = 0;
    var dest_idx: u16 = 0;

    while (src_idx < src.len) {
        if (dest_idx >= dest.len) return error.NormalizedFieldTooLong;

        const byte = src[src_idx];
        if (byte == '%') {
            if (src_idx + 2 >= src.len) return error.InvalidPercentEncoding;
            const high = parseHexNibble(src[src_idx + 1]) orelse return error.InvalidPercentEncoding;
            const low = parseHexNibble(src[src_idx + 2]) orelse return error.InvalidPercentEncoding;
            dest[dest_idx] = (high << 4) | low;
            src_idx += 3;
        } else {
            dest[dest_idx] = byte;
            src_idx += 1;
        }
        dest_idx += 1;
    }

    return dest[0..dest_idx];
}

fn parseHexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

/// Returns whether `input` satisfies `rule` by selecting the field indicated by `rule.field`
/// (`path`, `query`, `host`, or `user_agent`) and applying the rule’s match kind.
/// Matching is ASCII case-insensitive for all kinds: contains, prefix, or exact equality.
/// Preconditions: `input` and `rule` must point to valid initialized values for the call duration.
/// This function is pure, does not allocate, and cannot fail; it returns `true` only on a match.
pub fn matchesRule(input: *const InspectionInput, rule: *const ScannerRule) bool {
    const field_value = switch (rule.field) {
        .path => input.path,
        .query => input.query,
        .host => input.host,
        .user_agent => input.user_agent,
    };

    return switch (rule.kind) {
        .contains_ascii_ci => strings.containsIgnoreCase(field_value, rule.pattern),
        .prefix_ascii_ci => hasPrefixIgnoreCase(field_value, rule.pattern),
        .exact_ascii_ci => strings.eqlIgnoreCase(field_value, rule.pattern),
    };
}

fn hasPrefixIgnoreCase(value: []const u8, prefix: []const u8) bool {
    if (prefix.len > value.len) return false;
    return strings.eqlIgnoreCase(value[0..prefix.len], prefix);
}

test "InspectionInput percent decodes path and query" {
    var headers = core.HeaderMap.init();
    try headers.put("Host", "API.Example.com:8443");
    try headers.put("User-Agent", "Nikto/2.5");
    const request = Request{
        .method = .GET,
        .path = "/.git%2Fconfig?scan=%2Fwp-admin",
        .headers = headers,
    };
    var ctx = Context.init();
    ctx.client_addr[0] = '1';
    ctx.client_addr[1] = '0';
    ctx.client_addr[2] = '.';
    ctx.client_addr[3] = 0;
    var scratch = InspectionScratch{};

    const input = try InspectionInput.fromRequest(&request, &ctx, &scratch);

    try std.testing.expectEqualStrings("/.git/config", input.path);
    try std.testing.expectEqualStrings("scan=/wp-admin", input.query);
    try std.testing.expectEqualStrings("api.example.com:8443", input.host);
    try std.testing.expectEqualStrings("nikto/2.5", input.user_agent);
}

test "InspectionInput rejects invalid percent encoding" {
    var scratch = InspectionScratch{};
    try std.testing.expectError(
        error.InvalidPercentEncoding,
        decodePercentInto(scratch.path_buf[0..], "/bad%2"),
    );
}

test "matchesRule uses case-insensitive comparisons" {
    const input = InspectionInput{
        .method = .GET,
        .path = "/WP-ADMIN/setup.php",
        .query = "",
        .host = "example.com",
        .user_agent = "sqlmap/1.8",
        .client_addr = "127.0.0.1",
    };
    const ua_rule = ScannerRule.init("ua", .user_agent, .contains_ascii_ci, "SQLMAP", 120, .block);
    const path_rule = ScannerRule.init("path", .path, .prefix_ascii_ci, "/wp-admin", 60, .score);

    try std.testing.expect(matchesRule(&input, &ua_rule));
    try std.testing.expect(matchesRule(&input, &path_rule));
}

test "Config validates burst fields when enabled" {
    const rules = [_]ScannerRule{
        ScannerRule.init("path", .path, .contains_ascii_ci, "/wp-admin", 60, .score),
    };
    const cfg = Config{
        .rules = rules[0..],
        .burst_enabled = true,
        .burst_tracker_capacity = 128,
        .burst_tracker_retry_budget = 4,
    };

    try cfg.validate();
}
