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

pub const MAX_SCANNER_RULES: u8 = 32;
pub const MAX_MATCHED_RULES: u8 = 8;
pub const MAX_TRACKER_CAPACITY: u16 = 1024;
pub const MAX_TRACKED_PATH_HASHES: u8 = 16;
pub const MAX_TRACKER_CAS_RETRIES: u8 = 32;
pub const MAX_NORMALIZED_PATH_BYTES: u16 = 2048;
pub const MAX_NORMALIZED_QUERY_BYTES: u16 = 1024;
pub const MAX_NORMALIZED_HOST_BYTES: u16 = 512;
pub const MAX_NORMALIZED_USER_AGENT_BYTES: u16 = 512;

pub const EnforcementMode = enum {
    detect_only,
    enforce,
};

pub const FailureMode = enum {
    fail_open,
    fail_closed,
};

pub const DecisionAction = enum {
    allow,
    flag,
    block,
};

pub const FailureReason = enum {
    invalid_percent_encoding,
    normalized_field_too_long,
};

pub const BehavioralSnapshot = struct {
    request_count: u16 = 0,
    unique_path_count: u8 = 0,
    namespace_family_count: u8 = 0,
    miss_reject_count: u16 = 0,
    tracker_degraded: bool = false,
};

pub const MatchField = enum {
    path,
    query,
    host,
    user_agent,
};

pub const MatchKind = enum {
    contains_ascii_ci,
    prefix_ascii_ci,
    exact_ascii_ci,
};

pub const RuleDisposition = enum {
    score,
    block,
};

pub const ScannerRule = struct {
    id: []const u8,
    field: MatchField,
    kind: MatchKind,
    pattern: []const u8,
    score: u16,
    disposition: RuleDisposition,

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

pub const Config = struct {
    pub const DEFAULT_BLOCK_THRESHOLD: u16 = 100;
    pub const DEFAULT_BURST_WINDOW_NS: u64 = 10 * core.time.ns_per_s;
    pub const DEFAULT_BURST_TRACKER_CAPACITY: u16 = 256;
    pub const DEFAULT_BURST_TRACKER_RETRY_BUDGET: u8 = 8;
    pub const DEFAULT_BURST_REQUEST_THRESHOLD: u16 = 20;
    pub const DEFAULT_BURST_UNIQUE_PATH_THRESHOLD: u8 = 16;
    pub const DEFAULT_BURST_NAMESPACE_THRESHOLD: u8 = 3;
    pub const DEFAULT_BURST_MISS_REJECT_THRESHOLD: u16 = 10;
    pub const DEFAULT_BURST_REQUEST_SCORE: u16 = 40;
    pub const DEFAULT_BURST_UNIQUE_PATH_SCORE: u16 = 50;
    pub const DEFAULT_BURST_NAMESPACE_SCORE: u16 = 60;
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

pub const InspectionScratch = struct {
    path_buf: [MAX_NORMALIZED_PATH_BYTES]u8 = std.mem.zeroes([MAX_NORMALIZED_PATH_BYTES]u8),
    query_buf: [MAX_NORMALIZED_QUERY_BYTES]u8 = std.mem.zeroes([MAX_NORMALIZED_QUERY_BYTES]u8),
    host_buf: [MAX_NORMALIZED_HOST_BYTES]u8 = std.mem.zeroes([MAX_NORMALIZED_HOST_BYTES]u8),
    user_agent_buf: [MAX_NORMALIZED_USER_AGENT_BYTES]u8 = std.mem.zeroes([MAX_NORMALIZED_USER_AGENT_BYTES]u8),
};

pub const InspectionInput = struct {
    method: Method,
    path: []const u8,
    query: []const u8,
    host: []const u8,
    user_agent: []const u8,
    client_addr: []const u8,

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

pub const Decision = struct {
    action: DecisionAction = .allow,
    enforcement_mode: EnforcementMode = .detect_only,
    score: u16 = 0,
    match_count: u8 = 0,
    behavioral_match_count: u8 = 0,
    tracker_degraded: bool = false,
    matched_rule_ids: [MAX_MATCHED_RULES]?[]const u8 = [_]?[]const u8{null} ** MAX_MATCHED_RULES,
    failure_reason: ?FailureReason = null,

    pub fn addMatch(self: *Decision, id: []const u8) void {
        assert(id.len > 0);
        if (self.match_count < MAX_MATCHED_RULES) {
            self.matched_rule_ids[self.match_count] = id;
        }
        self.match_count +|= 1;
    }

    pub fn effectiveMatchCount(self: *const Decision) u8 {
        return @min(self.match_count, MAX_MATCHED_RULES);
    }

    pub fn addBehavioralMatch(self: *Decision, id: []const u8) void {
        assert(id.len > 0);
        self.behavioral_match_count +|= 1;
        self.addMatch(id);
    }
};

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
