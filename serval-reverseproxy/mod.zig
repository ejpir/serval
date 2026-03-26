//! serval-reverseproxy - Reverse-proxy runtime orchestration foundation.
//!
//! Owns canonical IR validation and generation lifecycle orchestration.

pub const ir = @import("ir.zig");
pub const ordering = @import("ordering.zig");
pub const composition = @import("composition.zig");
pub const policy = @import("policy.zig");
pub const filter_runtime = @import("filter_runtime.zig");
pub const stream_request = @import("stream_request.zig");
pub const stream_response = @import("stream_response.zig");
pub const failure = @import("failure.zig");
pub const guard_window = @import("guard_window.zig");
pub const dsl = @import("dsl.zig");
pub const equivalence = @import("equivalence.zig");
pub const runtime = @import("runtime.zig");
pub const integration = @import("integration.zig");
pub const orchestrator = @import("orchestrator.zig");
pub const certs = @import("certs/mod.zig");
pub const components = @import("components.zig");

pub const CanonicalIr = ir.CanonicalIr;
pub const ValidationStage = ir.ValidationStage;
pub const ValidationReason = ir.ValidationReason;
pub const ValidationDiagnostic = ir.ValidationDiagnostic;
pub const ValidationError = ir.ValidationError;
pub const validateCanonicalIr = ir.validateCanonicalIr;

pub const RuntimeSnapshot = orchestrator.RuntimeSnapshot;
pub const ApplyStage = orchestrator.ApplyStage;
pub const EventKind = orchestrator.EventKind;
pub const OrchestratorEvent = orchestrator.OrchestratorEvent;
pub const Orchestrator = orchestrator.Orchestrator;
pub const OrchestratorError = orchestrator.OrchestratorError;
pub const OrderingConstraintEntry = ordering.ConstraintEntry;
pub const OrderedChain = ordering.OrderedChain;
pub const resolveOrdering = ordering.resolve;
pub const EffectiveChain = composition.EffectiveChain;
pub const composeEffectiveChain = composition.composeEffectiveChain;
pub const PolicyPhase = policy.PolicyPhase;
pub const PolicyObservation = policy.PolicyObservation;
pub const PolicyExecutionResult = policy.PolicyExecutionResult;
pub const executeRequestHeaders = policy.executeRequestHeaders;
pub const FilterRuntimeError = filter_runtime.RuntimeError;
pub const FilterRegistry = filter_runtime.FilterRegistry;
pub const HookObservation = filter_runtime.HookObservation;
pub const executeResponseHeaders = policy.executeResponseHeaders;
pub const executeHeaderPhases = policy.executeHeaderPhases;
pub const BackpressureController = stream_request.BackpressureController;
pub const StreamObservation = stream_request.StreamObservation;
pub const executeRequestStream = stream_request.executeRequestStream;
pub const ResponseFramingPlan = stream_response.ResponseFramingPlan;
pub const planResponseFraming = stream_response.planResponseFraming;
pub const shouldEmitContentLength = stream_response.shouldEmitContentLength;
pub const ResponseObservation = stream_response.ResponseObservation;
pub const executeResponseStream = stream_response.executeResponseStream;
pub const FailurePhase = failure.FailurePhase;
pub const FailureSource = failure.FailureSource;
pub const TerminalAction = failure.TerminalAction;
pub const FailureDecision = failure.FailureDecision;
pub const classifyFailure = failure.classifyFailure;
pub const ThresholdProfile = guard_window.ThresholdProfile;
pub const GuardSample = guard_window.GuardSample;
pub const GuardDecision = guard_window.GuardDecision;
pub const GuardWindowMonitor = guard_window.GuardWindowMonitor;
pub const ParsedDsl = dsl.ParsedDsl;
pub const parseDsl = dsl.parse;
pub const EquivalenceReport = equivalence.EquivalenceReport;
pub const compareDslToCanonical = equivalence.compareDslToCanonical;
pub const RuntimeLoadOptions = runtime.LoadOptions;
pub const RuntimeRunOptions = runtime.RunOptions;
pub const Runtime = runtime.Runtime;
pub const load = runtime.load;

pub const ComponentPoolKind = components.PoolKind;
pub const ComponentMetricsKind = components.MetricsKind;
pub const ComponentTracerKind = components.TracerKind;
pub const RuntimePool = components.RuntimePool;
pub const RuntimeMetrics = components.RuntimeMetrics;
pub const RuntimeTracer = components.RuntimeTracer;

pub const CertActivationResult = certs.ActivationResult;
pub const CertMaterial = certs.CertMaterial;
pub const StaticCertProvider = certs.StaticProvider;
pub const SelfSignedCertProvider = certs.SelfSignedProvider;
pub const AcmeCertProvider = certs.AcmeProvider;

pub const FailurePolicy = ir.FailurePolicy;
pub const RuntimeBudget = ir.RuntimeBudget;
pub const TlsProvider = ir.TlsProvider;
pub const ListenerTls = ir.ListenerTls;
pub const StaticTlsConfig = ir.StaticTlsConfig;
pub const SelfSignedTlsConfig = ir.SelfSignedTlsConfig;
pub const AcmeTlsConfig = ir.AcmeTlsConfig;
pub const Listener = ir.Listener;
pub const Pool = ir.Pool;
pub const Route = ir.Route;
pub const PluginCatalogEntry = ir.PluginCatalogEntry;
pub const ChainPlan = ir.ChainPlan;
pub const ChainEntry = ir.ChainEntry;

test {
    _ = ir;
    _ = ordering;
    _ = composition;
    _ = policy;
    _ = filter_runtime;
    _ = stream_request;
    _ = stream_response;
    _ = failure;
    _ = guard_window;
    _ = dsl;
    _ = equivalence;
    _ = runtime;
    _ = integration;
    _ = orchestrator;
    _ = certs;
    _ = components;
}
