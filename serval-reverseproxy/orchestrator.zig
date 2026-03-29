//! Reverse-proxy runtime orchestrator and generation lifecycle.

const std = @import("std");
const assert = std.debug.assert;
const ir = @import("ir.zig");

/// Represents the orchestrator's apply lifecycle.
/// `idle` is the quiescent state, `build` and `admit` cover candidate preparation and validation, and `activate` installs a new generation.
/// `drain` and `retire` cover retirement of the previous generation.
/// `safe_mode` is the fallback state entered when rollback cannot recover a last known good snapshot.
/// The orchestrator enforces valid transitions between these states; callers do not mutate this directly.
pub const ApplyStage = enum(u8) {
    idle,
    build,
    admit,
    activate,
    drain,
    retire,
    safe_mode,
};

/// Classifies the last orchestrator event for logging and diagnostics.
/// `stage_transition` records a successful lifecycle step, and the remaining variants record apply, drain, rollback, or safe-mode outcomes.
/// The orchestrator stores one of these values in `OrchestratorEvent.kind` when it updates `last_event`.
/// Use this together with the event stage and generation to understand the most recent state change.
pub const EventKind = enum(u8) {
    stage_transition,
    apply_failure,
    apply_success,
    drain_retired,
    drain_timeout_force_retire,
    rollback_success,
    rollback_failure,
    safe_mode_entered,
};

/// Describes the most recent state-machine event emitted by the orchestrator.
/// `kind` identifies the event family, while `stage` captures the lifecycle stage reached.
/// `generation_id` names the candidate or snapshot generation associated with the event.
/// `reason` is populated when the event carries a validation reason; otherwise it is null.
pub const OrchestratorEvent = struct {
    kind: EventKind,
    stage: ApplyStage,
    generation_id: u64,
    reason: ?ir.ValidationReason,
};

/// Immutable runtime view of a validated configuration generation.
/// The fields are borrowed slice views, so the underlying canonical IR storage must remain valid for as long as the snapshot is referenced.
/// `generation_id` identifies the configuration version and `created_at_ns` records when the snapshot was created.
/// Use `fromCanonicalIr` to construct a snapshot from validated IR without copying.
pub const RuntimeSnapshot = struct {
    generation_id: u64,
    listeners: []const ir.Listener,
    pools: []const ir.Pool,
    routes: []const ir.Route,
    plugins: []const ir.PluginCatalogEntry,
    chains: []const ir.ChainPlan,
    created_at_ns: u64,

    /// Builds a runtime snapshot by borrowing slice views from a canonical IR instance.
/// The returned snapshot does not copy the underlying arrays; the caller must keep `candidate` alive while the snapshot is in use.
/// `generation_id` and `created_at_ns` must both be non-zero.
/// This helper preserves the candidate's listeners, pools, routes, plugins, and chains verbatim.
    pub fn fromCanonicalIr(candidate: *const ir.CanonicalIr, generation_id: u64, created_at_ns: u64) RuntimeSnapshot {
        assert(generation_id > 0);
        assert(created_at_ns > 0);

        return RuntimeSnapshot{
            .generation_id = generation_id,
            .listeners = candidate.listeners,
            .pools = candidate.pools,
            .routes = candidate.routes,
            .plugins = candidate.plugins,
            .chains = candidate.chains,
            .created_at_ns = created_at_ns,
        };
    }
};

const DrainingSnapshot = struct {
    snapshot: *const RuntimeSnapshot,
    deadline_ns: u64,
};

/// Errors returned by orchestrator lifecycle operations.
/// Includes canonical IR validation failures plus state-machine errors such as invalid transitions and missing rollback targets.
/// `DrainTimeoutExceeded` is reported when draining has to be forced past its deadline.
pub const OrchestratorError = ir.ValidationError || error{
    InvalidStateTransition,
    NoLastKnownGood,
    DrainTimeoutExceeded,
};

/// Coordinates snapshot admission, activation, draining, and rollback state.
/// `active_snapshot_ptr` is the published snapshot pointer; the remaining fields track the current lifecycle and diagnostics.
/// The struct stores borrowed snapshot references and slice views, so referenced data must outlive any active use.
/// Public methods enforce stage transitions and record the most recent event for observability.
pub const Orchestrator = struct {
    active_snapshot_ptr: std.atomic.Value(usize),
    last_known_good: ?*const RuntimeSnapshot,
    draining: ?DrainingSnapshot,
    stage: ApplyStage,
    max_drain_ns: u64,
    last_event: ?OrchestratorEvent,
    last_diagnostics: [ir.MAX_VALIDATION_DIAGNOSTICS]ir.ValidationDiagnostic,
    last_diagnostics_count: u32,

    /// Creates a new orchestrator with no active snapshot and idle stage.
/// `max_drain_ns` must be non-zero and is used as the deadline for draining retired snapshots.
/// The diagnostics buffer is left uninitialized until a validation attempt fills it.
/// The returned value owns its internal atomic state and can be used immediately.
    pub fn init(max_drain_ns: u64) Orchestrator {
        assert(max_drain_ns > 0);

        return Orchestrator{
            .active_snapshot_ptr = std.atomic.Value(usize).init(0),
            .last_known_good = null,
            .draining = null,
            .stage = .idle,
            .max_drain_ns = max_drain_ns,
            .last_event = null,
            .last_diagnostics = undefined,
            .last_diagnostics_count = 0,
        };
    }

    /// Returns the currently active runtime snapshot, if one has been published.
/// The returned pointer aliases orchestrator-owned state and must only be used while the snapshot remains active.
/// Returns `null` when no active snapshot pointer has been stored yet.
/// The pointer is loaded with acquire ordering to pair with the release store used on activation.
    pub fn getActiveSnapshot(self: *const Orchestrator) ?*const RuntimeSnapshot {
        const ptr_int = self.active_snapshot_ptr.load(.acquire);
        if (ptr_int == 0) return null;

        return @ptrFromInt(ptr_int);
    }

    /// Returns the orchestrator's current apply stage.
/// The stored stage is expected to remain within the `ApplyStage` range through `.safe_mode`.
/// This is a read-only accessor and does not mutate orchestrator state.
    pub fn getStage(self: *const Orchestrator) ApplyStage {
        assert(@intFromEnum(self.stage) <= @intFromEnum(ApplyStage.safe_mode));
        return self.stage;
    }

    /// Validates and activates a candidate snapshot for the provided generation.
/// On validation failure, this records an `apply_failure` event, resets the stage to `.idle`, and returns the validation error.
/// When a previous active snapshot exists, it becomes `last_known_good` and is moved into drain state.
/// `candidate_snapshot.generation_id` and `now_ns` must both be non-zero.
    pub fn admitAndActivate(
        self: *Orchestrator,
        candidate_ir: *const ir.CanonicalIr,
        candidate_snapshot: *const RuntimeSnapshot,
        now_ns: u64,
    ) OrchestratorError!void {
        assert(candidate_snapshot.generation_id > 0);
        assert(now_ns > 0);

        try self.transitionTo(.build, candidate_snapshot.generation_id, null);
        try self.transitionTo(.admit, candidate_snapshot.generation_id, null);

        self.last_diagnostics_count = 0;
        ir.validateCanonicalIr(candidate_ir, &self.last_diagnostics, &self.last_diagnostics_count) catch |err| {
            const reason = if (self.last_diagnostics_count > 0) self.last_diagnostics[0].reason else null;
            self.last_event = .{
                .kind = .apply_failure,
                .stage = .admit,
                .generation_id = candidate_snapshot.generation_id,
                .reason = reason,
            };
            self.stage = .idle;
            return err;
        };

        try self.transitionTo(.activate, candidate_snapshot.generation_id, null);

        const previous_active = self.getActiveSnapshot();
        self.active_snapshot_ptr.store(@intFromPtr(candidate_snapshot), .release);

        if (previous_active) |previous| {
            self.last_known_good = previous;
            self.draining = .{
                .snapshot = previous,
                .deadline_ns = now_ns + self.max_drain_ns,
            };
            try self.transitionTo(.drain, candidate_snapshot.generation_id, null);
        } else {
            self.last_known_good = candidate_snapshot;
            try self.transitionTo(.retire, candidate_snapshot.generation_id, null);
            try self.transitionTo(.idle, candidate_snapshot.generation_id, null);
        }

        self.last_event = .{
            .kind = .apply_success,
            .stage = self.stage,
            .generation_id = candidate_snapshot.generation_id,
            .reason = null,
        };
    }

    /// Advances a drain cycle based on the number of in-flight references and the current time.
/// Returns `true` when draining is finished, including the no-drain case where nothing is pending.
/// When references reach zero, or when the deadline is exceeded, the old snapshot is retired and the stage is moved to `.idle`.
/// Exceeds the drain deadline with `error.DrainTimeoutExceeded` after forcing retirement.
    pub fn progressDrain(self: *Orchestrator, in_flight_refs: u32, now_ns: u64) OrchestratorError!bool {
        assert(now_ns > 0);
        assert(self.stage == .drain or self.draining == null);

        const draining_snapshot = self.draining orelse return true;

        if (in_flight_refs == 0) {
            self.draining = null;
            try self.transitionTo(.retire, draining_snapshot.snapshot.generation_id, null);
            try self.transitionTo(.idle, draining_snapshot.snapshot.generation_id, null);
            self.last_event = .{
                .kind = .drain_retired,
                .stage = .retire,
                .generation_id = draining_snapshot.snapshot.generation_id,
                .reason = null,
            };
            return true;
        }

        if (now_ns >= draining_snapshot.deadline_ns) {
            self.draining = null;
            try self.transitionTo(.retire, draining_snapshot.snapshot.generation_id, null);
            try self.transitionTo(.idle, draining_snapshot.snapshot.generation_id, null);
            self.last_event = .{
                .kind = .drain_timeout_force_retire,
                .stage = .retire,
                .generation_id = draining_snapshot.snapshot.generation_id,
                .reason = null,
            };
            return error.DrainTimeoutExceeded;
        }

        return false;
    }

    /// Restores the active snapshot to `last_known_good` and updates rollback state.
/// Returns `error.NoLastKnownGood` when no previous snapshot has been recorded.
/// If a different snapshot is currently active, it begins draining that snapshot before switching.
/// `now_ns` must be non-zero and this method must not be called while already in `.safe_mode`.
    pub fn rollbackToLastKnownGood(self: *Orchestrator, now_ns: u64) OrchestratorError!void {
        assert(now_ns > 0);
        assert(self.stage != .safe_mode);

        const lkg = self.last_known_good orelse return error.NoLastKnownGood;
        const active = self.getActiveSnapshot();
        if (active) |previous| {
            if (previous.generation_id != lkg.generation_id) {
                self.draining = .{
                    .snapshot = previous,
                    .deadline_ns = now_ns + self.max_drain_ns,
                };
                self.stage = .drain;
            }
        }

        self.active_snapshot_ptr.store(@intFromPtr(lkg), .release);
        self.last_event = .{
            .kind = .rollback_success,
            .stage = self.stage,
            .generation_id = lkg.generation_id,
            .reason = null,
        };
    }

    /// Rolls back to the last known good snapshot, or enters safe mode if rollback fails.
/// On rollback failure, this method suppresses the error, records a `safe_mode_entered` event,
/// and forces `stage` to `.safe_mode`.
/// `now_ns` must be non-zero and the orchestrator must not already be in `.build`.
    pub fn rollbackOrEnterSafeMode(self: *Orchestrator, now_ns: u64) void {
        assert(now_ns > 0);
        assert(self.stage != .build);

        self.rollbackToLastKnownGood(now_ns) catch {
            self.stage = .safe_mode;
            self.last_event = .{
                .kind = .safe_mode_entered,
                .stage = .safe_mode,
                .generation_id = 0,
                .reason = null,
            };
        };
    }

    fn transitionTo(
        self: *Orchestrator,
        next: ApplyStage,
        generation_id: u64,
        reason: ?ir.ValidationReason,
    ) OrchestratorError!void {
        assert(generation_id > 0);
        assert(@intFromEnum(next) <= @intFromEnum(ApplyStage.safe_mode));

        if (!isValidTransition(self.stage, next)) return error.InvalidStateTransition;

        self.stage = next;
        self.last_event = .{
            .kind = .stage_transition,
            .stage = next,
            .generation_id = generation_id,
            .reason = reason,
        };
    }

    fn isValidTransition(current: ApplyStage, next: ApplyStage) bool {
        assert(@intFromEnum(current) <= @intFromEnum(ApplyStage.safe_mode));
        assert(@intFromEnum(next) <= @intFromEnum(ApplyStage.safe_mode));

        return switch (current) {
            .idle => next == .build or next == .safe_mode,
            .build => next == .admit or next == .idle,
            .admit => next == .activate or next == .idle,
            .activate => next == .drain or next == .retire,
            .drain => next == .retire,
            .retire => next == .idle,
            .safe_mode => next == .idle,
        };
    }
};

fn validBudget() ir.RuntimeBudget {
    return .{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };
}

test "admission failure keeps active generation unchanged" {
    var orchestrator = Orchestrator.init(5_000_000);

    const listeners = [_]ir.Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }};
    const pools = [_]ir.Pool{.{ .id = "pool-a" }};
    const plugins = [_]ir.PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }};
    const chain_entries = [_]ir.ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = validBudget(),
        .priority = 10,
        .before = &.{},
        .after = &.{},
    }};
    const chains = [_]ir.ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }};
    const routes_v1 = [_]ir.Route{.{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    }};
    const ir_v1 = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes_v1[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };

    var snapshot_v1 = RuntimeSnapshot.fromCanonicalIr(&ir_v1, 1, 100);
    try orchestrator.admitAndActivate(&ir_v1, &snapshot_v1, 110);

    const active_before = orchestrator.getActiveSnapshot().?;
    try std.testing.expectEqual(@as(u64, 1), active_before.generation_id);

    const routes_invalid = [_]ir.Route{.{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "missing-chain",
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    }};
    const ir_invalid = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes_invalid[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };

    var snapshot_invalid = RuntimeSnapshot.fromCanonicalIr(&ir_invalid, 2, 200);
    try std.testing.expectError(
        error.MissingChainReference,
        orchestrator.admitAndActivate(&ir_invalid, &snapshot_invalid, 210),
    );

    const active_after = orchestrator.getActiveSnapshot().?;
    try std.testing.expectEqual(@as(u64, 1), active_after.generation_id);
    try std.testing.expectEqual(ApplyStage.idle, orchestrator.getStage());
}

test "activation swaps active generation and drains prior generation" {
    var orchestrator = Orchestrator.init(1_000);

    const listeners = [_]ir.Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }};
    const pools = [_]ir.Pool{.{ .id = "pool-a" }};
    const plugins = [_]ir.PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }};
    const chain_entries = [_]ir.ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = validBudget(),
        .priority = 10,
        .before = &.{},
        .after = &.{},
    }};
    const chains = [_]ir.ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }};
    const routes = [_]ir.Route{.{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    }};

    const ir_v1 = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };
    var snapshot_v1 = RuntimeSnapshot.fromCanonicalIr(&ir_v1, 1, 100);
    try orchestrator.admitAndActivate(&ir_v1, &snapshot_v1, 100);

    const ir_v2 = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };
    var snapshot_v2 = RuntimeSnapshot.fromCanonicalIr(&ir_v2, 2, 200);
    try orchestrator.admitAndActivate(&ir_v2, &snapshot_v2, 210);

    const active = orchestrator.getActiveSnapshot().?;
    try std.testing.expectEqual(@as(u64, 2), active.generation_id);
    try std.testing.expectEqual(ApplyStage.drain, orchestrator.getStage());
    try std.testing.expect(orchestrator.draining != null);
    try std.testing.expectEqual(@as(u64, 1), orchestrator.draining.?.snapshot.generation_id);

    try std.testing.expectEqual(false, try orchestrator.progressDrain(1, 250));
    try std.testing.expectEqual(true, try orchestrator.progressDrain(0, 260));
    try std.testing.expectEqual(ApplyStage.idle, orchestrator.getStage());
    try std.testing.expect(orchestrator.draining == null);
}

test "drain timeout force-retires prior generation" {
    var orchestrator = Orchestrator.init(100);

    const listeners = [_]ir.Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }};
    const pools = [_]ir.Pool{.{ .id = "pool-a" }};
    const plugins = [_]ir.PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }};
    const chain_entries = [_]ir.ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = validBudget(),
        .priority = 10,
        .before = &.{},
        .after = &.{},
    }};
    const chains = [_]ir.ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }};
    const routes = [_]ir.Route{.{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    }};

    const ir_v1 = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };
    var snapshot_v1 = RuntimeSnapshot.fromCanonicalIr(&ir_v1, 1, 100);
    try orchestrator.admitAndActivate(&ir_v1, &snapshot_v1, 110);

    const ir_v2 = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };
    var snapshot_v2 = RuntimeSnapshot.fromCanonicalIr(&ir_v2, 2, 200);
    try orchestrator.admitAndActivate(&ir_v2, &snapshot_v2, 220);

    try std.testing.expectError(error.DrainTimeoutExceeded, orchestrator.progressDrain(3, 400));
    try std.testing.expectEqual(ApplyStage.idle, orchestrator.getStage());
    try std.testing.expect(orchestrator.draining == null);
}

test "rollback hook restores last-known-good generation" {
    var orchestrator = Orchestrator.init(1000);

    const listeners = [_]ir.Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }};
    const pools = [_]ir.Pool{.{ .id = "pool-a" }};
    const plugins = [_]ir.PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }};
    const chain_entries = [_]ir.ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = validBudget(),
        .priority = 10,
        .before = &.{},
        .after = &.{},
    }};
    const chains = [_]ir.ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }};
    const routes = [_]ir.Route{.{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    }};

    const ir_v1 = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };
    var snapshot_v1 = RuntimeSnapshot.fromCanonicalIr(&ir_v1, 1, 10);
    try orchestrator.admitAndActivate(&ir_v1, &snapshot_v1, 20);

    const ir_v2 = ir.CanonicalIr{
        .listeners = listeners[0..],
        .pools = pools[0..],
        .routes = routes[0..],
        .plugins = plugins[0..],
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };
    var snapshot_v2 = RuntimeSnapshot.fromCanonicalIr(&ir_v2, 2, 30);
    try orchestrator.admitAndActivate(&ir_v2, &snapshot_v2, 40);

    try orchestrator.rollbackToLastKnownGood(50);
    const active = orchestrator.getActiveSnapshot().?;
    try std.testing.expectEqual(@as(u64, 1), active.generation_id);
}

test "orchestrator handles repeated generation swaps with bounded drain progression" {
    var orchestrator = Orchestrator.init(1000);

    const listeners = [_]ir.Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }};
    const pools = [_]ir.Pool{.{ .id = "pool-a" }};
    const plugins = [_]ir.PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }};
    const chain_entries = [_]ir.ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = validBudget(),
        .priority = 10,
        .before = &.{},
        .after = &.{},
    }};
    const chains = [_]ir.ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }};
    const routes = [_]ir.Route{.{
        .id = "route-a",
        .listener_id = "listener-a",
        .host = "example.com",
        .path_prefix = "/",
        .pool_id = "pool-a",
        .chain_id = "chain-a",
        .disable_plugin_ids = &.{},
        .add_plugin_ids = &.{},
        .waivers = &.{},
    }};

    var generation: u64 = 1;
    while (generation <= 8) : (generation += 1) {
        const candidate = ir.CanonicalIr{
            .listeners = listeners[0..],
            .pools = pools[0..],
            .routes = routes[0..],
            .plugins = plugins[0..],
            .chains = chains[0..],
            .global_plugin_ids = &.{},
        };
        var snapshot = RuntimeSnapshot.fromCanonicalIr(&candidate, generation, generation * 10);
        try orchestrator.admitAndActivate(&candidate, &snapshot, generation * 10 + 1);
        if (orchestrator.getStage() == .drain) {
            _ = try orchestrator.progressDrain(0, generation * 10 + 2);
        }
    }

    const active = orchestrator.getActiveSnapshot().?;
    try std.testing.expectEqual(@as(u64, 8), active.generation_id);
    try std.testing.expectEqual(ApplyStage.idle, orchestrator.getStage());
}
