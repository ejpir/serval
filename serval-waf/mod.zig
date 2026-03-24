//! serval-waf - Scanner-focused request inspection and blocking.
//!
//! Layer 2 infrastructure module for identifying obvious scanner traffic
//! before upstream selection.

pub const types = @import("types.zig");
pub const scanner = @import("scanner.zig");
pub const handler = @import("handler.zig");
pub const burst = @import("burst.zig");

pub const Config = types.Config;
pub const ScannerRule = types.ScannerRule;
pub const InspectionInput = types.InspectionInput;
pub const InspectionScratch = types.InspectionScratch;
pub const Decision = types.Decision;
pub const DecisionAction = types.DecisionAction;
pub const BehavioralSnapshot = types.BehavioralSnapshot;
pub const EnforcementMode = types.EnforcementMode;
pub const FailureMode = types.FailureMode;
pub const FailureReason = types.FailureReason;
pub const MatchField = types.MatchField;
pub const MatchKind = types.MatchKind;
pub const RuleDisposition = types.RuleDisposition;
pub const ObserveFn = types.ObserveFn;
pub const ShieldedHandler = handler.ShieldedHandler;
pub const IsMissFn = handler.IsMissFn;
pub const default_scanner_rules = scanner.default_scanner_rules;
pub const evaluate = scanner.evaluate;

test {
    _ = types;
    _ = scanner;
    _ = handler;
    _ = burst;
}
