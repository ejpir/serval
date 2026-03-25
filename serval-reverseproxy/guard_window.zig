//! Post-activation guard-window monitoring and rollback triggers.

const std = @import("std");
const assert = std.debug.assert;
const orchestrator_mod = @import("orchestrator.zig");

pub const ThresholdProfile = struct {
    guard_window_ns: u64,
    max_error_rate_milli: u32,
    max_fail_closed_count: u32,

    pub fn isValid(self: ThresholdProfile) bool {
        assert(self.max_error_rate_milli <= 1_000_000);
        return self.guard_window_ns > 0 and self.max_error_rate_milli > 0;
    }
};

pub const GuardSample = struct {
    request_count: u64,
    error_count: u64,
    fail_closed_count: u32,
};

pub const GuardDecision = enum(u8) {
    monitor,
    stable,
    auto_rollback,
    safe_mode,
};

pub const GuardWindowMonitor = struct {
    orchestrator: *orchestrator_mod.Orchestrator,
    profile: ThresholdProfile,
    activated_generation: u64,
    activated_at_ns: u64,

    pub fn init(
        orchestrator: *orchestrator_mod.Orchestrator,
        profile: ThresholdProfile,
        activated_generation: u64,
        activated_at_ns: u64,
    ) GuardWindowMonitor {
        assert(@intFromPtr(orchestrator) != 0);
        assert(profile.isValid());
        assert(activated_generation > 0);
        assert(activated_at_ns > 0);

        return .{
            .orchestrator = orchestrator,
            .profile = profile,
            .activated_generation = activated_generation,
            .activated_at_ns = activated_at_ns,
        };
    }

    pub fn evaluate(self: *GuardWindowMonitor, sample: GuardSample, now_ns: u64) GuardDecision {
        assert(@intFromPtr(self) != 0);
        assert(now_ns >= self.activated_at_ns);

        if (now_ns - self.activated_at_ns > self.profile.guard_window_ns) {
            return .stable;
        }

        const breach = hasCriticalBreach(self.profile, sample);
        if (!breach) return .monitor;

        self.orchestrator.rollbackOrEnterSafeMode(now_ns);
        return if (self.orchestrator.getStage() == .safe_mode) .safe_mode else .auto_rollback;
    }
};

fn hasCriticalBreach(profile: ThresholdProfile, sample: GuardSample) bool {
    assert(profile.isValid());

    if (sample.request_count == 0) return sample.fail_closed_count > profile.max_fail_closed_count;

    const error_rate_milli = (sample.error_count * 1000) / sample.request_count;
    return error_rate_milli > profile.max_error_rate_milli or
        sample.fail_closed_count > profile.max_fail_closed_count;
}

test "guard window triggers rollback when thresholds breach" {
    const ir = @import("ir.zig");

    var orchestrator = orchestrator_mod.Orchestrator.init(1_000_000);

    const budget = ir.RuntimeBudget{ .max_state_bytes = 1024, .max_output_bytes = 1024 * 1024, .max_expansion_ratio_milli = 2000, .max_cpu_micros_per_chunk = 1000 };
    const entries = [_]ir.ChainEntry{.{ .plugin_id = "p", .failure_policy = .fail_closed, .budget = budget, .priority = 1, .before = &.{}, .after = &.{} }};
    const routes = [_]ir.Route{.{ .id = "r", .listener_id = "l", .host = "example.com", .path_prefix = "/", .pool_id = "pool", .chain_id = "c", .disable_plugin_ids = &.{}, .add_plugin_ids = &.{}, .waivers = &.{} }};
    const candidate = ir.CanonicalIr{
        .listeners = &[_]ir.Listener{.{ .id = "l", .bind = "0.0.0.0:443" }},
        .pools = &[_]ir.Pool{.{ .id = "pool" }},
        .routes = routes[0..],
        .plugins = &[_]ir.PluginCatalogEntry{.{ .id = "p", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }},
        .chains = &[_]ir.ChainPlan{.{ .id = "c", .entries = entries[0..] }},
        .global_plugin_ids = &.{},
    };
    var snapshot1 = orchestrator_mod.RuntimeSnapshot.fromCanonicalIr(&candidate, 1, 10);
    try orchestrator.admitAndActivate(&candidate, &snapshot1, 11);
    var snapshot2 = orchestrator_mod.RuntimeSnapshot.fromCanonicalIr(&candidate, 2, 20);
    try orchestrator.admitAndActivate(&candidate, &snapshot2, 21);

    var monitor = GuardWindowMonitor.init(&orchestrator, .{ .guard_window_ns = 1000, .max_error_rate_milli = 10, .max_fail_closed_count = 1 }, 2, 21);
    const decision = monitor.evaluate(.{ .request_count = 100, .error_count = 50, .fail_closed_count = 0 }, 30);
    try std.testing.expectEqual(GuardDecision.auto_rollback, decision);
}

test "guard window enters safe mode when rollback unavailable" {
    var orchestrator = orchestrator_mod.Orchestrator.init(1_000_000);
    var monitor = GuardWindowMonitor.init(&orchestrator, .{ .guard_window_ns = 1000, .max_error_rate_milli = 10, .max_fail_closed_count = 1 }, 1, 10);
    const decision = monitor.evaluate(.{ .request_count = 10, .error_count = 10, .fail_closed_count = 0 }, 15);
    try std.testing.expectEqual(GuardDecision.safe_mode, decision);
    try std.testing.expectEqual(orchestrator_mod.ApplyStage.safe_mode, orchestrator.getStage());
}

test "threshold profiles markdown and json remain in parity" {
    const json = @embedFile("threshold-profiles.json");
    const md = @embedFile("threshold-profiles.md");

    try std.testing.expect(std.mem.indexOf(u8, json, "\"strict\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"balanced\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"lenient\"") != null);

    try std.testing.expect(std.mem.indexOf(u8, md, "## strict") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "## balanced") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "## lenient") != null);
}
