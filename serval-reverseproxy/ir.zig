//! Canonical reverse-proxy IR types and validation.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const config = core.config;
const ordering = @import("ordering.zig");
const composition = @import("composition.zig");

/// Maximum number of validation diagnostics that may be reported.
/// This cap bounds diagnostic growth during validation and keeps output predictable.
/// The value is a small unsigned integer constant and is intended for fixed-size limits.
pub const MAX_VALIDATION_DIAGNOSTICS: u8 = 16;

/// Controls how the reverse proxy behaves when a failure is encountered.
/// The policy is encoded as a compact `u8` enum for configuration and serialization use.
/// Choose `fail_open` to continue past failures, or `fail_closed` to stop on failures.
pub const FailurePolicy = enum(u8) {
    fail_open,
    fail_closed,
};

/// Runtime limits that control state size, output size, expansion ratio, and CPU time per chunk.
/// The fields are plain numeric limits; callers are responsible for choosing values that satisfy
/// `isValid` before using the budget in validation or admission logic.
pub const RuntimeBudget = struct {
    max_state_bytes: u32,
    max_output_bytes: u64,
    max_expansion_ratio_milli: u32,
    max_cpu_micros_per_chunk: u32,

    /// Returns whether this runtime budget satisfies the configured bounds.
    /// The check requires all budget fields to be non-zero and within the limits from `config`.
    /// This function does not allocate or report detailed errors; it returns `false` on any invalid field.
    pub fn isValid(self: RuntimeBudget) bool {
        assert(config.MAX_ADMIN_REQUEST_BYTES > 0);
        assert(config.MAX_BODY_SIZE_BYTES > 0);
        return self.max_state_bytes > 0 and
            self.max_state_bytes <= config.MAX_ADMIN_REQUEST_BYTES and
            self.max_output_bytes > 0 and
            self.max_output_bytes <= config.MAX_BODY_SIZE_BYTES and
            self.max_expansion_ratio_milli >= 1000 and
            self.max_expansion_ratio_milli <= 100_000 and
            self.max_cpu_micros_per_chunk > 0;
    }
};

/// Selects which TLS certificate source the reverse proxy should use.
/// The discriminants are stable `u8` values so the enum can be serialized or stored compactly.
/// Use the variant that matches the configured certificate management mode.
pub const TlsProvider = enum(u8) {
    static,
    selfsigned,
    acme,
};

/// Configuration for serving TLS from pre-existing certificate files.
/// `cert_path` and `key_path` are borrowed path slices; this type does not take ownership of the
/// underlying storage and expects both files to be readable when the config is used.
pub const StaticTlsConfig = struct {
    cert_path: []const u8,
    key_path: []const u8,
};

/// Configuration for generating or reusing a self-signed TLS setup.
/// `state_dir_path` points to the directory used to persist generator state, and `domain` is the
/// DNS name the certificate should cover. `rotate_on_boot` defaults to `false` when omitted.
pub const SelfSignedTlsConfig = struct {
    state_dir_path: []const u8,
    domain: []const u8,
    rotate_on_boot: bool = false,
};

/// ACME TLS configuration for listener certificate management.
/// The URL, contact email, state directory, and domain are borrowed strings required by the ACME flow.
/// The timeout and backoff fields default from `serval-core.config`, and validation requires the interval and backoff values to be positive and ordered.
pub const AcmeTlsConfig = struct {
    directory_url: []const u8,
    contact_email: []const u8,
    state_dir_path: []const u8,
    domain: []const u8,
    renew_before_ns: u64 = config.ACME_DEFAULT_RENEW_BEFORE_NS,
    poll_interval_ms: u32 = config.ACME_DEFAULT_POLL_INTERVAL_MS,
    fail_backoff_min_ms: u32 = config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS,
    fail_backoff_max_ms: u32 = config.ACME_DEFAULT_FAIL_BACKOFF_MAX_MS,
};

/// TLS configuration for a listener.
/// `provider` selects which optional provider-specific block must be populated for validation to succeed.
/// Validation rejects missing or malformed provider data, so only the matching config field should be set for the chosen provider.
pub const ListenerTls = struct {
    provider: TlsProvider,
    static: ?StaticTlsConfig = null,
    selfsigned: ?SelfSignedTlsConfig = null,
    acme: ?AcmeTlsConfig = null,
};

/// An inbound listener definition.
/// `bind` names the address or socket to listen on, and `tls` optionally enables one of the supported TLS provider modes.
/// The listener `id` is the stable reference used by routes and validation diagnostics.
pub const Listener = struct {
    id: []const u8,
    bind: []const u8,
    tls: ?ListenerTls = null,
};

/// A backend pool referenced by routes.
/// `upstream_spec` is optional; when present it carries the pool's upstream definition as borrowed text.
/// The pool `id` is the stable identifier used by route references and duplicate-id checks.
pub const Pool = struct {
    id: []const u8,
    upstream_spec: ?[]const u8 = null,
};

/// A route waiver binding a plugin id to a waiver identifier.
/// The plugin id selects the plugin being waived, and the waiver id carries the external waiver reference.
/// Both fields are borrowed strings and must remain valid while the route is used.
pub const RouteWaiver = struct {
    plugin_id: []const u8,
    waiver_id: []const u8,
};

/// Canonical route definition used by validation and composition.
/// `listener_id` may be left empty in source data, but validation requires a referenced listener before admission succeeds.
/// The plugin-id lists and waiver set are borrowed slices that drive route-level policy composition.
pub const Route = struct {
    id: []const u8,
    listener_id: []const u8 = "",
    host: []const u8,
    path_prefix: []const u8,
    pool_id: []const u8,
    chain_id: []const u8,
    disable_plugin_ids: []const []const u8,
    add_plugin_ids: []const []const u8,
    waivers: []const RouteWaiver,
};

/// A plugin catalog entry available to routes and chains.
/// `enabled` indicates the initial availability state, while `mandatory` and `disable_requires_waiver` influence validation and composition.
/// The `id` and `version` slices are borrowed metadata and are not owned by the struct.
pub const PluginCatalogEntry = struct {
    id: []const u8,
    version: []const u8,
    enabled: bool,
    mandatory: bool,
    disable_requires_waiver: bool,
};

/// One plugin entry within a chain plan.
/// `plugin_id` selects the catalog entry, `failure_policy` controls failure handling, and `budget` must pass `RuntimeBudget.isValid`.
/// `before` and `after` express ordering constraints that are resolved when the chain is validated.
pub const ChainEntry = struct {
    plugin_id: []const u8,
    failure_policy: FailurePolicy,
    budget: RuntimeBudget,
    priority: i32,
    before: []const []const u8,
    after: []const []const u8,
};

/// A named chain of policy entries.
/// `id` is the chain identifier referenced by routes, and `entries` holds the ordered plugin definitions for that chain.
/// The chain must not be empty when validated.
pub const ChainPlan = struct {
    id: []const u8,
    entries: []const ChainEntry,
};

/// Canonical reverse-proxy IR input for validation and runtime admission.
/// All slices are borrowed; the caller owns the backing storage and must keep it alive for the duration of use.
/// Validation reads these collections directly and does not allocate or copy the IR graph.
pub const CanonicalIr = struct {
    listeners: []const Listener,
    pools: []const Pool,
    routes: []const Route,
    plugins: []const PluginCatalogEntry,
    chains: []const ChainPlan,
    global_plugin_ids: []const []const u8,
};

/// Validation phase that produced a diagnostic.
/// Structure checks cover shape and local constraints, references check cross-links, and invariants cover semantic consistency.
/// Callers can use the stage to decide whether a failure is a parsing issue, a missing dependency, or a deeper policy error.
pub const ValidationStage = enum(u8) {
    structure,
    references,
    invariants,
};

/// Kind of object associated with a validation diagnostic.
/// Use this to distinguish which IR collection or entry produced the failure.
/// `chain_entry` is used for per-plugin entries inside a chain.
pub const ValidationObjectKind = enum(u8) {
    listener,
    pool,
    route,
    plugin,
    chain,
    chain_entry,
};

/// Machine-readable reasons emitted by the validator.
/// The enum mirrors `ValidationError` so callers can match failures without parsing text.
/// Values cover size limits, duplicate ids, missing references, ordering failures, TLS misconfiguration, and diagnostic overflow.
pub const ValidationReason = enum(u8) {
    too_many_listeners,
    too_many_pools,
    too_many_routes,
    too_many_chains,
    duplicate_pool_id,
    duplicate_route_id,
    duplicate_plugin_id,
    duplicate_chain_id,
    empty_chain,
    invalid_budget,
    missing_listener_reference,
    missing_pool_reference,
    missing_chain_reference,
    missing_plugin_reference,
    missing_global_plugin_reference,
    missing_route_disable_plugin_reference,
    missing_route_add_plugin_reference,
    missing_route_waiver_plugin_reference,
    duplicate_global_plugin_reference,
    duplicate_route_disable_plugin_reference,
    duplicate_route_add_plugin_reference,
    duplicate_route_waiver_plugin_reference,
    invalid_route_waiver_target,
    mandatory_plugin_disable_rejected,
    missing_required_waiver,
    missing_order_dependency,
    cyclic_order_constraints,
    duplicate_order_plugin_id,
    invalid_listener_tls_config,
    too_many_diagnostics,
};

/// One validation failure captured from canonical IR checking.
/// `object_id` is borrowed text and does not transfer ownership; it should identify the offending item or named reference.
/// Diagnostics are emitted in validation order and pair a stage, object kind, and machine-readable reason.
pub const ValidationDiagnostic = struct {
    stage: ValidationStage,
    object_kind: ValidationObjectKind,
    object_id: []const u8,
    reason: ValidationReason,
};

/// Errors returned when canonical IR validation fails.
/// Each case maps to a specific structural, reference, or invariant violation recorded in `ValidationDiagnostic.reason`.
/// `TooManyDiagnostics` is raised when validation cannot append another diagnostic to the caller-provided buffer.
pub const ValidationError = error{
    TooManyListeners,
    TooManyPools,
    TooManyRoutes,
    TooManyChains,
    DuplicatePoolId,
    DuplicateRouteId,
    DuplicatePluginId,
    DuplicateChainId,
    EmptyChain,
    InvalidBudget,
    MissingListenerReference,
    MissingPoolReference,
    MissingChainReference,
    MissingPluginReference,
    MissingGlobalPluginReference,
    MissingRouteDisablePluginReference,
    MissingRouteAddPluginReference,
    MissingRouteWaiverPluginReference,
    DuplicateGlobalPluginReference,
    DuplicateRouteDisablePluginReference,
    DuplicateRouteAddPluginReference,
    DuplicateRouteWaiverPluginReference,
    InvalidRouteWaiverTarget,
    MandatoryPluginDisableRejected,
    MissingRequiredWaiver,
    MissingOrderDependency,
    CyclicOrderConstraints,
    DuplicateOrderPluginId,
    InvalidListenerTlsConfig,
    TooManyDiagnostics,
};

/// Validate a canonical reverse-proxy IR snapshot.
/// The caller must provide a diagnostics buffer with capacity for `MAX_VALIDATION_DIAGNOSTICS` entries and a count pointer within bounds on entry.
/// `diagnostics_count` is reset to zero before validation starts; the first failure appends one diagnostic, then returns the matching `ValidationError`.
pub fn validateCanonicalIr(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);
    diagnostics_count.* = 0;

    try validateStructure(candidate, diagnostics, diagnostics_count);
    try validateReferences(candidate, diagnostics, diagnostics_count);
    try validatePolicyReferences(candidate, diagnostics, diagnostics_count);

    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);
}

fn validateStructure(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);

    if (candidate.listeners.len > config.MAX_ALLOWED_HOSTS) {
        try appendDiagnostic(diagnostics, diagnostics_count, .{
            .stage = .structure,
            .object_kind = .listener,
            .object_id = "listeners",
            .reason = .too_many_listeners,
        });
        return error.TooManyListeners;
    }
    if (candidate.pools.len > config.MAX_POOLS) {
        try appendDiagnostic(diagnostics, diagnostics_count, .{
            .stage = .structure,
            .object_kind = .pool,
            .object_id = "pools",
            .reason = .too_many_pools,
        });
        return error.TooManyPools;
    }
    if (candidate.routes.len > config.MAX_ROUTES) {
        try appendDiagnostic(diagnostics, diagnostics_count, .{
            .stage = .structure,
            .object_kind = .route,
            .object_id = "routes",
            .reason = .too_many_routes,
        });
        return error.TooManyRoutes;
    }
    if (candidate.chains.len > config.MAX_ROUTES) {
        try appendDiagnostic(diagnostics, diagnostics_count, .{
            .stage = .structure,
            .object_kind = .chain,
            .object_id = "chains",
            .reason = .too_many_chains,
        });
        return error.TooManyChains;
    }

    try validateUniqueIds(candidate, diagnostics, diagnostics_count);
    try validateListeners(candidate, diagnostics, diagnostics_count);
    try validateRoutePolicyStructure(candidate, diagnostics, diagnostics_count);
    try validateGlobalPolicyStructure(candidate, diagnostics, diagnostics_count);
    try validateChains(candidate, diagnostics, diagnostics_count);

    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);
}

fn validateReferences(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);

    var route_index: usize = 0;
    while (route_index < candidate.routes.len) : (route_index += 1) {
        const route = candidate.routes[route_index];
        if (route.listener_id.len == 0 or !containsListener(candidate.listeners, route.listener_id)) {
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .references,
                .object_kind = .route,
                .object_id = route.id,
                .reason = .missing_listener_reference,
            });
            return error.MissingListenerReference;
        }
        if (!containsPool(candidate.pools, route.pool_id)) {
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .references,
                .object_kind = .route,
                .object_id = route.id,
                .reason = .missing_pool_reference,
            });
            return error.MissingPoolReference;
        }
        if (!containsChain(candidate.chains, route.chain_id)) {
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .references,
                .object_kind = .route,
                .object_id = route.id,
                .reason = .missing_chain_reference,
            });
            return error.MissingChainReference;
        }
    }

    var chain_index: usize = 0;
    while (chain_index < candidate.chains.len) : (chain_index += 1) {
        const chain = candidate.chains[chain_index];
        var entry_index: usize = 0;
        while (entry_index < chain.entries.len) : (entry_index += 1) {
            const entry = chain.entries[entry_index];
            if (!containsPlugin(candidate.plugins, entry.plugin_id)) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .references,
                    .object_kind = .chain_entry,
                    .object_id = entry.plugin_id,
                    .reason = .missing_plugin_reference,
                });
                return error.MissingPluginReference;
            }
        }
    }

    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);
}

fn validateUniqueIds(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    assert(candidate.pools.len <= config.MAX_POOLS);

    var i: usize = 0;
    while (i < candidate.pools.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < candidate.pools.len) : (j += 1) {
            if (std.mem.eql(u8, candidate.pools[i].id, candidate.pools[j].id)) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .structure,
                    .object_kind = .pool,
                    .object_id = candidate.pools[i].id,
                    .reason = .duplicate_pool_id,
                });
                return error.DuplicatePoolId;
            }
        }
    }

    i = 0;
    while (i < candidate.routes.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < candidate.routes.len) : (j += 1) {
            if (std.mem.eql(u8, candidate.routes[i].id, candidate.routes[j].id)) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .structure,
                    .object_kind = .route,
                    .object_id = candidate.routes[i].id,
                    .reason = .duplicate_route_id,
                });
                return error.DuplicateRouteId;
            }
        }
    }

    i = 0;
    while (i < candidate.plugins.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < candidate.plugins.len) : (j += 1) {
            if (std.mem.eql(u8, candidate.plugins[i].id, candidate.plugins[j].id)) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .structure,
                    .object_kind = .plugin,
                    .object_id = candidate.plugins[i].id,
                    .reason = .duplicate_plugin_id,
                });
                return error.DuplicatePluginId;
            }
        }
    }

    i = 0;
    while (i < candidate.chains.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < candidate.chains.len) : (j += 1) {
            if (std.mem.eql(u8, candidate.chains[i].id, candidate.chains[j].id)) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .structure,
                    .object_kind = .chain,
                    .object_id = candidate.chains[i].id,
                    .reason = .duplicate_chain_id,
                });
                return error.DuplicateChainId;
            }
        }
    }

    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);
}

fn validateListeners(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    assert(@intFromPtr(candidate) != 0);
    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);

    var listener_index: usize = 0;
    while (listener_index < candidate.listeners.len) : (listener_index += 1) {
        const listener = candidate.listeners[listener_index];
        if (listener.tls == null) continue;

        const tls_cfg = listener.tls.?;
        switch (tls_cfg.provider) {
            .static => {
                const static_cfg = tls_cfg.static orelse {
                    try appendDiagnostic(diagnostics, diagnostics_count, .{
                        .stage = .structure,
                        .object_kind = .listener,
                        .object_id = listener.id,
                        .reason = .invalid_listener_tls_config,
                    });
                    return error.InvalidListenerTlsConfig;
                };
                if (static_cfg.cert_path.len == 0 or static_cfg.key_path.len == 0) {
                    try appendDiagnostic(diagnostics, diagnostics_count, .{
                        .stage = .structure,
                        .object_kind = .listener,
                        .object_id = listener.id,
                        .reason = .invalid_listener_tls_config,
                    });
                    return error.InvalidListenerTlsConfig;
                }
            },
            .selfsigned => {
                const selfsigned_cfg = tls_cfg.selfsigned orelse {
                    try appendDiagnostic(diagnostics, diagnostics_count, .{
                        .stage = .structure,
                        .object_kind = .listener,
                        .object_id = listener.id,
                        .reason = .invalid_listener_tls_config,
                    });
                    return error.InvalidListenerTlsConfig;
                };
                if (selfsigned_cfg.state_dir_path.len == 0 or selfsigned_cfg.domain.len == 0) {
                    try appendDiagnostic(diagnostics, diagnostics_count, .{
                        .stage = .structure,
                        .object_kind = .listener,
                        .object_id = listener.id,
                        .reason = .invalid_listener_tls_config,
                    });
                    return error.InvalidListenerTlsConfig;
                }
            },
            .acme => {
                const acme_cfg = tls_cfg.acme orelse {
                    try appendDiagnostic(diagnostics, diagnostics_count, .{
                        .stage = .structure,
                        .object_kind = .listener,
                        .object_id = listener.id,
                        .reason = .invalid_listener_tls_config,
                    });
                    return error.InvalidListenerTlsConfig;
                };
                if (acme_cfg.directory_url.len == 0 or
                    acme_cfg.contact_email.len == 0 or
                    acme_cfg.state_dir_path.len == 0 or
                    acme_cfg.domain.len == 0 or
                    acme_cfg.poll_interval_ms == 0 or
                    acme_cfg.fail_backoff_min_ms == 0 or
                    acme_cfg.fail_backoff_min_ms > acme_cfg.fail_backoff_max_ms)
                {
                    try appendDiagnostic(diagnostics, diagnostics_count, .{
                        .stage = .structure,
                        .object_kind = .listener,
                        .object_id = listener.id,
                        .reason = .invalid_listener_tls_config,
                    });
                    return error.InvalidListenerTlsConfig;
                }
            },
        }
    }
}

fn validateGlobalPolicyStructure(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    assert(candidate.global_plugin_ids.len <= config.MAX_ROUTES);

    if (hasDuplicateId(candidate.global_plugin_ids)) {
        try appendDiagnostic(diagnostics, diagnostics_count, .{
            .stage = .structure,
            .object_kind = .chain,
            .object_id = "global_plugin_ids",
            .reason = .duplicate_global_plugin_reference,
        });
        return error.DuplicateGlobalPluginReference;
    }
}

fn validateRoutePolicyStructure(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    var route_index: usize = 0;
    while (route_index < candidate.routes.len) : (route_index += 1) {
        const route = candidate.routes[route_index];
        if (hasDuplicateId(route.disable_plugin_ids)) {
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .structure,
                .object_kind = .route,
                .object_id = route.id,
                .reason = .duplicate_route_disable_plugin_reference,
            });
            return error.DuplicateRouteDisablePluginReference;
        }
        if (hasDuplicateId(route.add_plugin_ids)) {
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .structure,
                .object_kind = .route,
                .object_id = route.id,
                .reason = .duplicate_route_add_plugin_reference,
            });
            return error.DuplicateRouteAddPluginReference;
        }
        if (hasDuplicateWaiverPlugin(route.waivers)) {
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .structure,
                .object_kind = .route,
                .object_id = route.id,
                .reason = .duplicate_route_waiver_plugin_reference,
            });
            return error.DuplicateRouteWaiverPluginReference;
        }
    }
}

fn validatePolicyReferences(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    var global_index: usize = 0;
    while (global_index < candidate.global_plugin_ids.len) : (global_index += 1) {
        const plugin_id = candidate.global_plugin_ids[global_index];
        if (!containsPlugin(candidate.plugins, plugin_id)) {
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .references,
                .object_kind = .chain,
                .object_id = plugin_id,
                .reason = .missing_global_plugin_reference,
            });
            return error.MissingGlobalPluginReference;
        }
    }

    var route_index: usize = 0;
    while (route_index < candidate.routes.len) : (route_index += 1) {
        const route = candidate.routes[route_index];

        var disable_index: usize = 0;
        while (disable_index < route.disable_plugin_ids.len) : (disable_index += 1) {
            const plugin_id = route.disable_plugin_ids[disable_index];
            if (!containsPlugin(candidate.plugins, plugin_id)) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .references,
                    .object_kind = .route,
                    .object_id = route.id,
                    .reason = .missing_route_disable_plugin_reference,
                });
                return error.MissingRouteDisablePluginReference;
            }
        }

        var add_index: usize = 0;
        while (add_index < route.add_plugin_ids.len) : (add_index += 1) {
            const plugin_id = route.add_plugin_ids[add_index];
            if (!containsPlugin(candidate.plugins, plugin_id)) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .references,
                    .object_kind = .route,
                    .object_id = route.id,
                    .reason = .missing_route_add_plugin_reference,
                });
                return error.MissingRouteAddPluginReference;
            }
        }

        var waiver_index: usize = 0;
        while (waiver_index < route.waivers.len) : (waiver_index += 1) {
            const waiver = route.waivers[waiver_index];
            const plugin = findPlugin(candidate.plugins, waiver.plugin_id) orelse {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .references,
                    .object_kind = .route,
                    .object_id = route.id,
                    .reason = .missing_route_waiver_plugin_reference,
                });
                return error.MissingRouteWaiverPluginReference;
            };

            if (!plugin.disable_requires_waiver and !plugin.mandatory) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .invariants,
                    .object_kind = .route,
                    .object_id = route.id,
                    .reason = .invalid_route_waiver_target,
                });
                return error.InvalidRouteWaiverTarget;
            }

            if (waiver.waiver_id.len == 0) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .structure,
                    .object_kind = .route,
                    .object_id = route.id,
                    .reason = .invalid_route_waiver_target,
                });
                return error.InvalidRouteWaiverTarget;
            }
        }

        _ = composition.composeEffectiveChain(candidate.plugins, candidate.global_plugin_ids, &route) catch |err| {
            const reason: ValidationReason = switch (err) {
                error.MandatoryPluginDisableRejected => .mandatory_plugin_disable_rejected,
                error.MissingRequiredWaiver => .missing_required_waiver,
                error.MissingGlobalPlugin => .missing_global_plugin_reference,
                error.MissingRouteAddPlugin => .missing_route_add_plugin_reference,
                error.MissingRouteDisablePlugin => .missing_route_disable_plugin_reference,
                error.TooManyEffectivePlugins => .too_many_chains,
            };
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .invariants,
                .object_kind = .route,
                .object_id = route.id,
                .reason = reason,
            });
            return switch (err) {
                error.MandatoryPluginDisableRejected => error.MandatoryPluginDisableRejected,
                error.MissingRequiredWaiver => error.MissingRequiredWaiver,
                error.MissingGlobalPlugin => error.MissingGlobalPluginReference,
                error.MissingRouteAddPlugin => error.MissingRouteAddPluginReference,
                error.MissingRouteDisablePlugin => error.MissingRouteDisablePluginReference,
                error.TooManyEffectivePlugins => error.TooManyChains,
            };
        };
    }
}

fn validateChains(
    candidate: *const CanonicalIr,
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
) ValidationError!void {
    assert(candidate.chains.len <= config.MAX_ROUTES);

    var chain_index: usize = 0;
    while (chain_index < candidate.chains.len) : (chain_index += 1) {
        const chain = candidate.chains[chain_index];
        if (chain.entries.len == 0) {
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .invariants,
                .object_kind = .chain,
                .object_id = chain.id,
                .reason = .empty_chain,
            });
            return error.EmptyChain;
        }

        var entry_index: usize = 0;
        while (entry_index < chain.entries.len) : (entry_index += 1) {
            const entry = chain.entries[entry_index];
            if (!entry.budget.isValid()) {
                try appendDiagnostic(diagnostics, diagnostics_count, .{
                    .stage = .invariants,
                    .object_kind = .chain_entry,
                    .object_id = entry.plugin_id,
                    .reason = .invalid_budget,
                });
                return error.InvalidBudget;
            }
        }

        var ordering_entries: [ordering.MAX_CHAIN_PLUGINS]ordering.ConstraintEntry = undefined;
        var ordering_index: usize = 0;
        while (ordering_index < chain.entries.len) : (ordering_index += 1) {
            const entry = chain.entries[ordering_index];
            ordering_entries[ordering_index] = .{
                .plugin_id = entry.plugin_id,
                .priority = entry.priority,
                .before = entry.before,
                .after = entry.after,
            };
        }

        _ = ordering.resolve(ordering_entries[0..chain.entries.len]) catch |err| {
            const reason: ValidationReason = switch (err) {
                error.MissingDependency => .missing_order_dependency,
                error.CycleDetected => .cyclic_order_constraints,
                error.DuplicatePluginId => .duplicate_order_plugin_id,
                error.TooManyPlugins => .too_many_chains,
            };
            try appendDiagnostic(diagnostics, diagnostics_count, .{
                .stage = .invariants,
                .object_kind = .chain,
                .object_id = chain.id,
                .reason = reason,
            });
            return switch (err) {
                error.MissingDependency => error.MissingOrderDependency,
                error.CycleDetected => error.CyclicOrderConstraints,
                error.DuplicatePluginId => error.DuplicateOrderPluginId,
                error.TooManyPlugins => error.TooManyChains,
            };
        };
    }

    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);
}

fn appendDiagnostic(
    diagnostics: *[MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic,
    diagnostics_count: *u32,
    diagnostic: ValidationDiagnostic,
) ValidationError!void {
    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);
    if (diagnostics_count.* >= MAX_VALIDATION_DIAGNOSTICS) return error.TooManyDiagnostics;

    diagnostics[diagnostics_count.*] = diagnostic;
    diagnostics_count.* += 1;

    assert(diagnostics_count.* <= MAX_VALIDATION_DIAGNOSTICS);
}

fn hasDuplicateId(ids: []const []const u8) bool {
    var i: usize = 0;
    while (i < ids.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < ids.len) : (j += 1) {
            if (std.mem.eql(u8, ids[i], ids[j])) return true;
        }
    }
    return false;
}

fn hasDuplicateWaiverPlugin(waivers: []const RouteWaiver) bool {
    var i: usize = 0;
    while (i < waivers.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < waivers.len) : (j += 1) {
            if (std.mem.eql(u8, waivers[i].plugin_id, waivers[j].plugin_id)) return true;
        }
    }
    return false;
}

fn findPlugin(plugins: []const PluginCatalogEntry, id: []const u8) ?PluginCatalogEntry {
    assert(id.len > 0);

    var index: usize = 0;
    while (index < plugins.len) : (index += 1) {
        if (std.mem.eql(u8, plugins[index].id, id)) return plugins[index];
    }
    return null;
}

fn containsListener(listeners: []const Listener, id: []const u8) bool {
    var index: usize = 0;
    while (index < listeners.len) : (index += 1) {
        if (std.mem.eql(u8, listeners[index].id, id)) return true;
    }
    return false;
}

fn containsPool(pools: []const Pool, id: []const u8) bool {
    assert(id.len > 0);

    var index: usize = 0;
    while (index < pools.len) : (index += 1) {
        if (std.mem.eql(u8, pools[index].id, id)) return true;
    }
    return false;
}

fn containsChain(chains: []const ChainPlan, id: []const u8) bool {
    assert(id.len > 0);

    var index: usize = 0;
    while (index < chains.len) : (index += 1) {
        if (std.mem.eql(u8, chains[index].id, id)) return true;
    }
    return false;
}

fn containsPlugin(plugins: []const PluginCatalogEntry, id: []const u8) bool {
    assert(id.len > 0);

    var index: usize = 0;
    while (index < plugins.len) : (index += 1) {
        if (std.mem.eql(u8, plugins[index].id, id)) return true;
    }
    return false;
}

test "validation diagnostics are deterministic for missing chain reference" {
    const budget = RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };
    const chain_entries = [_]ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = budget,
        .priority = 10,
        .before = &.{},
        .after = &.{},
    }};
    const chains = [_]ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }};
    const candidate = CanonicalIr{
        .listeners = &[_]Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }},
        .pools = &[_]Pool{.{ .id = "pool-a" }},
        .routes = &[_]Route{.{
            .id = "route-a",
            .listener_id = "listener-a",
            .host = "example.com",
            .path_prefix = "/",
            .pool_id = "pool-a",
            .chain_id = "missing-chain",
            .disable_plugin_ids = &.{},
            .add_plugin_ids = &.{},
            .waivers = &.{},
        }},
        .plugins = &[_]PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }},
        .chains = chains[0..],
        .global_plugin_ids = &.{},
    };

    var diagnostics_a: [MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic = undefined;
    var diagnostics_count_a: u32 = 0;
    try std.testing.expectError(
        error.MissingChainReference,
        validateCanonicalIr(&candidate, &diagnostics_a, &diagnostics_count_a),
    );

    var diagnostics_b: [MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic = undefined;
    var diagnostics_count_b: u32 = 0;
    try std.testing.expectError(
        error.MissingChainReference,
        validateCanonicalIr(&candidate, &diagnostics_b, &diagnostics_count_b),
    );

    try std.testing.expectEqual(@as(u32, 1), diagnostics_count_a);
    try std.testing.expectEqual(@as(u32, 1), diagnostics_count_b);
    try std.testing.expectEqual(diagnostics_a[0].stage, diagnostics_b[0].stage);
    try std.testing.expectEqual(diagnostics_a[0].object_kind, diagnostics_b[0].object_kind);
    try std.testing.expectEqual(diagnostics_a[0].reason, diagnostics_b[0].reason);
    try std.testing.expectEqualStrings(diagnostics_a[0].object_id, diagnostics_b[0].object_id);

    try std.testing.expectEqual(ValidationStage.references, diagnostics_a[0].stage);
    try std.testing.expectEqual(ValidationObjectKind.route, diagnostics_a[0].object_kind);
    try std.testing.expectEqual(ValidationReason.missing_chain_reference, diagnostics_a[0].reason);
    try std.testing.expectEqualStrings("route-a", diagnostics_a[0].object_id);
}

test "validation fails when referenced plugin is missing" {
    const budget = RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };
    const candidate = CanonicalIr{
        .listeners = &[_]Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }},
        .pools = &[_]Pool{.{ .id = "pool-a" }},
        .routes = &[_]Route{.{
            .id = "route-a",
            .listener_id = "listener-a",
            .host = "example.com",
            .path_prefix = "/",
            .pool_id = "pool-a",
            .chain_id = "chain-a",
            .disable_plugin_ids = &.{},
            .add_plugin_ids = &.{},
            .waivers = &.{},
        }},
        .plugins = &[_]PluginCatalogEntry{},
        .chains = &[_]ChainPlan{.{ .id = "chain-a", .entries = &[_]ChainEntry{.{
            .plugin_id = "plugin-a",
            .failure_policy = .fail_open,
            .budget = budget,
            .priority = 1,
            .before = &.{},
            .after = &.{},
        }} }},
        .global_plugin_ids = &.{},
    };

    var diagnostics: [MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;

    try std.testing.expectError(
        error.MissingPluginReference,
        validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count),
    );
    try std.testing.expectEqual(@as(u32, 1), diagnostics_count);
    try std.testing.expectEqual(ValidationReason.missing_plugin_reference, diagnostics[0].reason);
}

test "validation rejects cyclic order constraints" {
    const budget = RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };
    const entries = [_]ChainEntry{
        .{ .plugin_id = "plugin-a", .failure_policy = .fail_closed, .budget = budget, .priority = 1, .before = &.{}, .after = &.{"plugin-b"} },
        .{ .plugin_id = "plugin-b", .failure_policy = .fail_closed, .budget = budget, .priority = 1, .before = &.{}, .after = &.{"plugin-a"} },
    };
    const candidate = CanonicalIr{
        .listeners = &[_]Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }},
        .pools = &[_]Pool{.{ .id = "pool-a" }},
        .routes = &[_]Route{.{
            .id = "route-a",
            .listener_id = "listener-a",
            .host = "example.com",
            .path_prefix = "/",
            .pool_id = "pool-a",
            .chain_id = "chain-a",
            .disable_plugin_ids = &.{},
            .add_plugin_ids = &.{},
            .waivers = &.{},
        }},
        .plugins = &[_]PluginCatalogEntry{
            .{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false },
            .{ .id = "plugin-b", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false },
        },
        .chains = &[_]ChainPlan{.{ .id = "chain-a", .entries = entries[0..] }},
        .global_plugin_ids = &.{},
    };

    var diagnostics: [MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;

    try std.testing.expectError(error.CyclicOrderConstraints, validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count));
    try std.testing.expectEqual(@as(u32, 1), diagnostics_count);
    try std.testing.expectEqual(ValidationReason.cyclic_order_constraints, diagnostics[0].reason);
}

test "validation rejects unknown route disable plugin reference" {
    const budget = RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };
    const chain_entries = [_]ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = budget,
        .priority = 1,
        .before = &.{},
        .after = &.{},
    }};
    const candidate = CanonicalIr{
        .listeners = &[_]Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }},
        .pools = &[_]Pool{.{ .id = "pool-a" }},
        .routes = &[_]Route{.{
            .id = "route-a",
            .listener_id = "listener-a",
            .host = "example.com",
            .path_prefix = "/",
            .pool_id = "pool-a",
            .chain_id = "chain-a",
            .disable_plugin_ids = &.{"missing-plugin"},
            .add_plugin_ids = &.{},
            .waivers = &.{},
        }},
        .plugins = &[_]PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }},
        .chains = &[_]ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }},
        .global_plugin_ids = &.{},
    };

    var diagnostics: [MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;

    try std.testing.expectError(error.MissingRouteDisablePluginReference, validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count));
    try std.testing.expectEqual(@as(u32, 1), diagnostics_count);
    try std.testing.expectEqual(ValidationReason.missing_route_disable_plugin_reference, diagnostics[0].reason);
}

test "validation rejects duplicate route disable directives" {
    const budget = RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };
    const chain_entries = [_]ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = budget,
        .priority = 1,
        .before = &.{},
        .after = &.{},
    }};
    const candidate = CanonicalIr{
        .listeners = &[_]Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }},
        .pools = &[_]Pool{.{ .id = "pool-a" }},
        .routes = &[_]Route{.{
            .id = "route-a",
            .listener_id = "listener-a",
            .host = "example.com",
            .path_prefix = "/",
            .pool_id = "pool-a",
            .chain_id = "chain-a",
            .disable_plugin_ids = &.{ "plugin-a", "plugin-a" },
            .add_plugin_ids = &.{},
            .waivers = &.{},
        }},
        .plugins = &[_]PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }},
        .chains = &[_]ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }},
        .global_plugin_ids = &.{},
    };

    var diagnostics: [MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;

    try std.testing.expectError(error.DuplicateRouteDisablePluginReference, validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count));
    try std.testing.expectEqual(@as(u32, 1), diagnostics_count);
    try std.testing.expectEqual(ValidationReason.duplicate_route_disable_plugin_reference, diagnostics[0].reason);
}

test "validation rejects waiver target when plugin does not require waiver" {
    const budget = RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };
    const chain_entries = [_]ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = budget,
        .priority = 1,
        .before = &.{},
        .after = &.{},
    }};
    const waivers = [_]RouteWaiver{.{ .plugin_id = "plugin-a", .waiver_id = "ticket-123" }};
    const candidate = CanonicalIr{
        .listeners = &[_]Listener{.{ .id = "listener-a", .bind = "0.0.0.0:443" }},
        .pools = &[_]Pool{.{ .id = "pool-a" }},
        .routes = &[_]Route{.{
            .id = "route-a",
            .listener_id = "listener-a",
            .host = "example.com",
            .path_prefix = "/",
            .pool_id = "pool-a",
            .chain_id = "chain-a",
            .disable_plugin_ids = &.{},
            .add_plugin_ids = &.{},
            .waivers = waivers[0..],
        }},
        .plugins = &[_]PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }},
        .chains = &[_]ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }},
        .global_plugin_ids = &.{},
    };

    var diagnostics: [MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;

    try std.testing.expectError(error.InvalidRouteWaiverTarget, validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count));
    try std.testing.expectEqual(@as(u32, 1), diagnostics_count);
    try std.testing.expectEqual(ValidationReason.invalid_route_waiver_target, diagnostics[0].reason);
}

test "validation rejects static tls listener with missing cert path" {
    const budget = RuntimeBudget{
        .max_state_bytes = 1024,
        .max_output_bytes = 1024 * 1024,
        .max_expansion_ratio_milli = 2000,
        .max_cpu_micros_per_chunk = 1000,
    };
    const chain_entries = [_]ChainEntry{.{
        .plugin_id = "plugin-a",
        .failure_policy = .fail_closed,
        .budget = budget,
        .priority = 1,
        .before = &.{},
        .after = &.{},
    }};

    const candidate = CanonicalIr{
        .listeners = &[_]Listener{.{
            .id = "listener-a",
            .bind = "0.0.0.0:443",
            .tls = .{ .provider = .static, .static = .{ .cert_path = "", .key_path = "/tmp/key.pem" } },
        }},
        .pools = &[_]Pool{.{ .id = "pool-a" }},
        .routes = &[_]Route{.{
            .id = "route-a",
            .listener_id = "listener-a",
            .host = "example.com",
            .path_prefix = "/",
            .pool_id = "pool-a",
            .chain_id = "chain-a",
            .disable_plugin_ids = &.{},
            .add_plugin_ids = &.{},
            .waivers = &.{},
        }},
        .plugins = &[_]PluginCatalogEntry{.{ .id = "plugin-a", .version = "1", .enabled = true, .mandatory = false, .disable_requires_waiver = false }},
        .chains = &[_]ChainPlan{.{ .id = "chain-a", .entries = chain_entries[0..] }},
        .global_plugin_ids = &.{},
    };

    var diagnostics: [MAX_VALIDATION_DIAGNOSTICS]ValidationDiagnostic = undefined;
    var diagnostics_count: u32 = 0;

    try std.testing.expectError(error.InvalidListenerTlsConfig, validateCanonicalIr(&candidate, &diagnostics, &diagnostics_count));
    try std.testing.expectEqual(@as(u32, 1), diagnostics_count);
    try std.testing.expectEqual(ValidationReason.invalid_listener_tls_config, diagnostics[0].reason);
}
