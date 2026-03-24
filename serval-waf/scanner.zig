//! serval-waf/scanner.zig
//! Scanner rule evaluation.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");
pub const burst = @import("burst.zig");
pub const Tracker = burst.Tracker;

pub const signal_request_burst = "behavior-request-burst";
pub const signal_path_diversity = "behavior-path-diversity";
pub const signal_namespace_diversity = "behavior-namespace-diversity";
pub const signal_miss_reject_burst = "behavior-miss-reject-burst";

pub const default_scanner_rules = [_]types.ScannerRule{
    types.ScannerRule.init("ua-sqlmap", .user_agent, .contains_ascii_ci, "sqlmap", 120, .block),
    types.ScannerRule.init("ua-nikto", .user_agent, .contains_ascii_ci, "nikto", 120, .block),
    types.ScannerRule.init("ua-acunetix", .user_agent, .contains_ascii_ci, "acunetix", 120, .block),
    types.ScannerRule.init("path-git-config", .path, .contains_ascii_ci, "/.git/config", 120, .block),
    types.ScannerRule.init("path-env", .path, .contains_ascii_ci, "/.env", 120, .block),
    types.ScannerRule.init("path-wp-admin", .path, .contains_ascii_ci, "/wp-admin", 60, .score),
    types.ScannerRule.init("path-phpmyadmin", .path, .contains_ascii_ci, "phpmyadmin", 80, .score),
    types.ScannerRule.init("query-xdebug", .query, .contains_ascii_ci, "xdebug_session_start", 50, .score),
};

pub fn evaluate(config: *const types.Config, input: *const types.InspectionInput) types.Decision {
    return evaluateWithBehavior(config, input, .{});
}

pub fn evaluateWithBehavior(
    config: *const types.Config,
    input: *const types.InspectionInput,
    snapshot: types.BehavioralSnapshot,
) types.Decision {
    assert(config.rules.len > 0);
    assert(config.rules.len <= types.MAX_SCANNER_RULES);

    var decision = types.Decision{
        .action = .allow,
        .enforcement_mode = config.enforcement_mode,
        .tracker_degraded = snapshot.tracker_degraded,
    };
    var has_block_match = false;

    for (config.rules) |rule| {
        if (!types.matchesRule(input, &rule)) continue;
        decision.addMatch(rule.id);
        if (rule.disposition == .block) has_block_match = true;
        decision.score +|= rule.score;
    }

    applyBehavioralSignals(config, snapshot, &decision);
    decision.action = selectAction(decision.score, decision.effectiveMatchCount(), has_block_match, config.block_threshold);
    return decision;
}

pub fn buildFailureDecision(
    enforcement_mode: types.EnforcementMode,
    failure_reason: types.FailureReason,
    failure_mode: types.FailureMode,
) types.Decision {
    return .{
        .action = if (failure_mode == .fail_closed) .block else .allow,
        .enforcement_mode = enforcement_mode,
        .failure_reason = failure_reason,
    };
}

fn selectAction(score: u16, match_count: u8, has_block_match: bool, block_threshold: u16) types.DecisionAction {
    if (has_block_match) return .block;
    if (score >= block_threshold) return .block;
    if (match_count > 0) return .flag;
    return .allow;
}

fn applyBehavioralSignals(config: *const types.Config, snapshot: types.BehavioralSnapshot, decision: *types.Decision) void {
    if (!config.burst_enabled) return;
    if (snapshot.request_count >= config.burst_request_threshold) {
        decision.addBehavioralMatch(signal_request_burst);
        decision.score +|= config.burst_request_score;
    }
    if (snapshot.unique_path_count >= config.burst_unique_path_threshold) {
        decision.addBehavioralMatch(signal_path_diversity);
        decision.score +|= config.burst_unique_path_score;
    }
    if (snapshot.namespace_family_count >= config.burst_namespace_threshold) {
        decision.addBehavioralMatch(signal_namespace_diversity);
        decision.score +|= config.burst_namespace_score;
    }
    if (snapshot.miss_reject_count >= config.burst_miss_reject_threshold) {
        decision.addBehavioralMatch(signal_miss_reject_burst);
        decision.score +|= config.burst_miss_reject_score;
    }
}

test "evaluate returns direct block for blocking signature" {
    const config = types.Config{
        .rules = default_scanner_rules[0..],
        .block_threshold = 100,
        .enforcement_mode = .enforce,
    };
    const input = types.InspectionInput{
        .method = .GET,
        .path = "/",
        .query = "",
        .host = "example.com",
        .user_agent = "sqlmap/1.8",
        .client_addr = "127.0.0.1",
    };

    const decision = evaluate(&config, &input);

    try std.testing.expectEqual(types.DecisionAction.block, decision.action);
    try std.testing.expectEqual(@as(u8, 1), decision.effectiveMatchCount());
    try std.testing.expectEqualStrings("ua-sqlmap", decision.matched_rule_ids[0].?);
}

test "evaluate returns threshold block for multiple suspicious matches" {
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/wp-admin", 60, .score),
        types.ScannerRule.init("query", .query, .contains_ascii_ci, "xdebug_session_start", 50, .score),
    };
    const config = types.Config{
        .rules = rules[0..],
        .block_threshold = 100,
        .enforcement_mode = .enforce,
    };
    const input = types.InspectionInput{
        .method = .GET,
        .path = "/wp-admin/index.php",
        .query = "xdebug_session_start=phpstorm",
        .host = "example.com",
        .user_agent = "curl/8.0",
        .client_addr = "127.0.0.1",
    };

    const decision = evaluate(&config, &input);

    try std.testing.expectEqual(types.DecisionAction.block, decision.action);
    try std.testing.expectEqual(@as(u16, 110), decision.score);
}

test "evaluate returns flag for low severity match" {
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/wp-admin", 40, .score),
    };
    const config = types.Config{
        .rules = rules[0..],
        .block_threshold = 100,
        .enforcement_mode = .detect_only,
    };
    const input = types.InspectionInput{
        .method = .GET,
        .path = "/wp-admin/",
        .query = "",
        .host = "example.com",
        .user_agent = "curl/8.0",
        .client_addr = "127.0.0.1",
    };

    const decision = evaluate(&config, &input);

    try std.testing.expectEqual(types.DecisionAction.flag, decision.action);
    try std.testing.expectEqual(@as(u8, 1), decision.effectiveMatchCount());
}

test "evaluateWithBehavior combines static and behavioral matches" {
    const rules = [_]types.ScannerRule{
        types.ScannerRule.init("path", .path, .contains_ascii_ci, "/wp-admin", 40, .score),
    };
    const config = types.Config{
        .rules = rules[0..],
        .block_threshold = 100,
        .enforcement_mode = .detect_only,
        .burst_enabled = true,
        .burst_request_threshold = 2,
        .burst_request_score = 70,
    };
    const input = types.InspectionInput{
        .method = .GET,
        .path = "/wp-admin/",
        .query = "",
        .host = "example.com",
        .user_agent = "curl/8.0",
        .client_addr = "127.0.0.1",
    };

    const decision = evaluateWithBehavior(&config, &input, .{
        .request_count = 2,
    });

    try std.testing.expectEqual(types.DecisionAction.block, decision.action);
    try std.testing.expectEqual(@as(u16, 110), decision.score);
    try std.testing.expect(decision.behavioral_match_count > 0);
}
