//! Post-activation guard-window monitoring and rollback triggers.

const std = @import("std");
const assert = std.debug.assert;
const orchestrator_mod = @import("orchestrator.zig");

/// Thresholds that define when the guard-window monitor should escalate.
/// `guard_window_ns` bounds the activation window in nanoseconds, while `max_error_rate_milli` and `max_fail_closed_count` define breach limits.
/// Use `isValid` before constructing a monitor from this profile.
/// The profile is copied by value and does not manage external ownership.
pub const ThresholdProfile = struct {
    guard_window_ns: u64,
    max_error_rate_milli: u32,
    max_fail_closed_count: u32,

    /// Reports whether a threshold profile is usable by the guard-window monitor.
    /// A valid profile requires a positive guard window and a positive maximum error rate.
    /// The method asserts that `max_error_rate_milli` is within the expected upper bound before evaluating the profile.
    /// It returns `false` for zero-valued guard windows or error-rate thresholds.
    pub fn isValid(self: ThresholdProfile) bool {
        assert(self.max_error_rate_milli <= 1_000_000);
        return self.guard_window_ns > 0 and self.max_error_rate_milli > 0;
    }
};

/// Snapshot of request and failure counts observed during a guard-window evaluation.
/// `request_count` and `error_count` are carried as `u64` counters, and `fail_closed_count` uses `u32`.
/// This type stores sample data only; it does not own any external resources.
/// The counts are consumed by breach detection logic outside this declaration.
pub const GuardSample = struct {
    request_count: u64,
    error_count: u64,
    fail_closed_count: u32,
};

/// Decision returned after evaluating a guard-window sample.
/// `.monitor` means the activation is still within the guard window and no critical breach was detected.
/// `.stable` means the guard window has elapsed; `.auto_rollback` and `.safe_mode` reflect orchestrator action.
/// The enum uses `u8` as its representation for compact storage and transport.
pub const GuardDecision = enum(u8) {
    monitor,
    stable,
    auto_rollback,
    safe_mode,
};

/// Monitor for a single guard window after activation.
/// Use `init` to bind the monitor to an orchestrator and `evaluate` to classify each sample.
/// The monitor keeps a borrowed pointer to the orchestrator and copies the threshold profile and activation metadata.
/// `activated_generation` and `activated_at_ns` identify the activation epoch being monitored.
pub const GuardWindowMonitor = struct {
    orchestrator: *orchestrator_mod.Orchestrator,
    profile: ThresholdProfile,
    activated_generation: u64,
    activated_at_ns: u64,

    /// Creates a monitor for a specific orchestrator activation and threshold profile.
    /// The monitor stores the orchestrator pointer and the activation metadata used by `evaluate`.
    /// Preconditions: `orchestrator` must be non-null, `profile` must be valid, and both `activated_generation` and `activated_at_ns` must be greater than zero.
    /// This does not take ownership of `orchestrator`; the caller retains lifetime responsibility.
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

    /// Evaluates a guard-window sample against the active threshold profile.
    /// Returns `.stable` once `now_ns` is past the configured guard window, or `.monitor` when no critical breach is present.
    /// When a critical breach is detected inside the guard window, this may request the orchestrator to roll back or enter safe mode.
    /// Preconditions: `self` must be valid and `now_ns` must be at or after `activated_at_ns`.
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
