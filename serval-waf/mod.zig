//! serval-waf - Scanner-focused request inspection and blocking.
//!
//! Layer 2 infrastructure module for identifying obvious scanner traffic
//! before upstream selection.

/// Re-exports the WAF type definitions from `types.zig` under `mod.types`.
/// Use this namespace to access shared WAF structs/enums without importing `types.zig` directly.
/// This is a compile-time module alias only; it has no runtime state, ownership, or error behavior.
pub const types = @import("types.zig");
/// Re-exports the WAF scanner module from `scanner.zig`.
/// Use this namespace to access scanner types and functions as `waf.scanner.*`.
/// This declaration performs no runtime work and introduces no direct error behavior.
pub const scanner = @import("scanner.zig");
/// Re-exports the `handler.zig` module under `serval-waf.handler`.
/// Use this namespace to access WAF handler types and functions from one import point.
/// This is a compile-time module alias and does not allocate or introduce runtime behavior.
pub const handler = @import("handler.zig");
/// Re-export of the `burst.zig` module under the `burst` namespace.
/// Use `waf.burst.*` to access its public declarations from this package.
/// This is a compile-time module alias (`@import`), with no runtime allocation or ownership semantics.
pub const burst = @import("burst.zig");

/// Public alias of [`types.Config`], the WAF runtime configuration struct.
/// Includes rule set, block policy, and optional burst-detection thresholds/scores with safe defaults.
/// Preconditions: `rules` must be non-empty (and within max size), and `block_threshold` is asserted to be `> 0`.
/// Call `validate()` before use; it returns explicit config errors (for status code and burst limits) instead of silently accepting invalid values.
/// `Config` contains borrowed slices (for example `rules` and `block_reason`), so referenced memory must outlive config use.
pub const Config = types.Config;
/// Public re-export of [`types.ScannerRule`] for the `serval-waf` module API.
/// This is a type alias; values and semantics are exactly those of `types.ScannerRule`.
/// `id` and `pattern` are borrowed `[]const u8` slices (no ownership transfer); callers keep backing memory valid for use.
/// Construction via `types.ScannerRule.init` enforces `id.len > 0`, `pattern.len > 0`, and `score > 0` unless `disposition == .block` (asserts).
pub const ScannerRule = types.ScannerRule;
/// Normalized request metadata consumed by WAF scanner and behavioral matching.
/// Includes method, path, query, host, user-agent, and client address fields.
/// When built with `fromRequest`, path/query are percent-decoded and host/user-agent are ASCII-lowercased.
/// Slice fields are borrowed (`path/query/host/user_agent` from `InspectionScratch`, `client_addr` from `Context`) and must not outlive those owners.
pub const InspectionInput = types.InspectionInput;
/// Re-export of [`types.InspectionScratch`], the mutable workspace for request normalization.
/// Holds fixed-size buffers for decoded path/query and normalized host/user-agent fields.
/// Caller owns this struct and passes `*InspectionScratch` into `InspectionInput.fromRequest`.
/// Any slices returned in `InspectionInput` reference this scratch storage and are valid only while it remains alive.
pub const InspectionScratch = types.InspectionScratch;
/// Alias of `types.Decision`, the mutable WAF inspection outcome returned by evaluation paths.
/// Stores action/enforcement mode, score/counters, degradation/failure state, and matched rule identifiers.
/// `addMatch` and `addBehavioralMatch` assert `id.len > 0`; they store borrowed `[]const u8` slices, so caller-owned backing memory must outlive any use of the decision.
/// Mutation helpers return no errors; `match_count` saturates on overflow, and retained rule IDs are capped (query with `effectiveMatchCount`).
pub const Decision = types.Decision;
/// Public re-export of `types.DecisionAction` for `serval-waf` consumers.
/// Represents scanner outcomes: `.allow`, `.flag`, or `.block`.
/// This is a compile-time alias, not a distinct enum; values are identical to `types.DecisionAction`.
/// Using this declaration has no ownership/lifetime implications and introduces no error behavior.
pub const DecisionAction = types.DecisionAction;
/// Re-export of [`types.BehavioralSnapshot`], a value-type snapshot of per-client burst heuristics.
/// Holds bounded counters (`request_count`, `unique_path_count`, `namespace_family_count`, `miss_reject_count`)
/// plus `tracker_degraded` to indicate tracker read/update contention/degraded state.
/// No ownership or lifetime coupling: all fields are plain scalars, copied by value, and this type has no error set.
pub const BehavioralSnapshot = types.BehavioralSnapshot;
/// Re-export of `types.EnforcementMode`, the WAF policy mode enum.
/// `.detect_only` keeps scanner decisions observational and does not trigger reject behavior.
/// `.enforce` allows block decisions to be enforced by shielding handlers.
/// This is a type alias only; it has no allocation, lifetime, or error behavior.
pub const EnforcementMode = types.EnforcementMode;
/// Re-export of [`types.FailureMode`], exposed at the `serval-waf` module root.
/// Controls how inspection failures are handled (for example, invalid percent encoding or normalized field overflow).
/// `.fail_open` maps failures to an `allow` decision; `.fail_closed` maps failures to a `block` decision.
/// This mode applies only to failure-path decisions; non-failure blocking still follows `EnforcementMode`.
pub const FailureMode = types.FailureMode;
/// Re-export of [`types.FailureReason`] for the `serval-waf` public API surface.
/// Identifies why request normalization/inspection failed before rule evaluation.
/// Current values map to input preparation errors: invalid percent encoding and normalized field length overflow.
/// Used in `Decision.failure_reason` and `scanner.buildFailureDecision`; this declaration cannot fail and owns no resources.
pub const FailureReason = types.FailureReason;
/// Re-export of [`types.MatchField`] for the `serval-waf` public API.
/// This is a type alias, so it has identical semantics, layout, and lifetime rules as the source type.
/// Any validation or error behavior is defined by code that consumes `types.MatchField`, not by this alias.
pub const MatchField = types.MatchField;
/// Re-export of [`types.MatchKind`] used by the WAF module API.
/// Represents the available match-kind enum/tag values defined in `types`.
/// Behavior, valid variants, and any associated semantics are exactly those of `types.MatchKind`.
pub const MatchKind = types.MatchKind;
/// Public re-export of [`types.RuleDisposition`] for `serval-waf` callers.
/// Classifies a scanner rule's disposition (`ScannerRule.disposition`).
/// Current variants are `.score` and `.block`; handle them exhaustively in switches.
/// This is a plain enum value type with no allocation, ownership transfer, or error return.
pub const RuleDisposition = types.RuleDisposition;
/// Callback type for observing the WAF decision produced for a request.
/// Implementations receive read-only pointers to `Context`, `Request`, and `Decision`.
/// The function is non-fallible (`void`): it cannot return an error to the caller.
/// Any data needed after return must be copied by the callback; pointed values are caller-owned.
pub const ObserveFn = types.ObserveFn;
/// Re-export of [`handler.ShieldedHandler`] for the `serval-waf` public API.
/// This is a type alias, not a wrapper: behavior, preconditions, ownership,
/// and error semantics are exactly those documented on `handler.ShieldedHandler`.
pub const ShieldedHandler = handler.ShieldedHandler;
/// Function pointer type for classifying whether a log entry represents a miss.
/// Used by `ShieldedHandler` during `onLog`; `true` marks the entry as a miss for tracker outcome accounting.
/// Preconditions: `ctx` and `entry` must point to valid data for the duration of the call.
/// Ownership/lifetime: the callee must not retain either pointer; this callback cannot fail (returns `bool`).
pub const IsMissFn = handler.IsMissFn;
/// Re-exports the built-in scanner signature set used for baseline probe detection.
/// Includes initial high-signal `User-Agent`, path, and query rules (for example `sqlmap`, `/.git/config`, and `xdebug_session_start`).
/// This value is an immutable fixed array with static lifetime; pass it as a slice (`default_scanner_rules[0..]`) when setting `Config.rules`.
/// Accessing it performs no allocation and cannot fail.
pub const default_scanner_rules = scanner.default_scanner_rules;
/// Evaluates `input` against `config.rules` and returns a `Decision` for this request.
/// This is a direct alias of `scanner.evaluate` and uses a zeroed behavioral snapshot (`.{}`).
/// Preconditions: `config.rules.len > 0` and `config.rules.len <= types.MAX_SCANNER_RULES` (enforced via `assert`).
/// Does not return errors; it only reads the provided pointers during the call and does not take ownership.
pub const evaluate = scanner.evaluate;

test {
    _ = types;
    _ = scanner;
    _ = handler;
    _ = burst;
}
