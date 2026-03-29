//! serval-reverseproxy - Reverse-proxy runtime orchestration foundation.
//!
//! Owns canonical IR validation and generation lifecycle orchestration.

/// Re-exports the IR submodule used by the reverse-proxy package.
/// Import this namespace to work with intermediate representation types and helpers from `ir.zig`.
pub const ir = @import("ir.zig");
/// Re-exports the ordering submodule for reverse-proxy ordering rules and related helpers.
/// Use this namespace to access ordering logic defined in `ordering.zig`.
pub const ordering = @import("ordering.zig");
/// Re-exports the composition submodule for building or combining reverse-proxy behavior.
/// Import this namespace to access composition logic defined in `composition.zig`.
pub const composition = @import("composition.zig");
/// Re-exports the policy submodule for reverse-proxy policy definitions and evaluation helpers.
/// Use this namespace to access policy-related types and logic defined in `policy.zig`.
pub const policy = @import("policy.zig");
/// Re-exports the filter runtime submodule for reverse-proxy filter execution support.
/// Import this namespace when you need runtime filter primitives and helpers from `filter_runtime.zig`.
pub const filter_runtime = @import("filter_runtime.zig");
/// Reverse proxy streaming request namespace.
/// This module is imported from `stream_request.zig` and exposes streaming request APIs.
/// Use it for request-side streaming behavior in the reverse proxy package.
pub const stream_request = @import("stream_request.zig");
/// Reverse proxy streaming response namespace.
/// This module is imported from `stream_response.zig` and exposes streaming response APIs.
/// Use it for response-side streaming behavior in the reverse proxy package.
pub const stream_response = @import("stream_response.zig");
/// Reverse proxy failure handling namespace.
/// This module is imported from `failure.zig` and contains failure-related APIs.
/// Use it for logic that models, classifies, or handles reverse proxy failures.
pub const failure = @import("failure.zig");
/// Reverse proxy guard window namespace.
/// This module is imported from `guard_window.zig` and contains guard-window APIs.
/// Use it for logic that constrains or validates time or state windows.
pub const guard_window = @import("guard_window.zig");
/// Reverse proxy DSL namespace.
/// This module is imported from `dsl.zig` and exposes DSL-related APIs.
/// Use it for declarative reverse proxy configuration or construction helpers.
pub const dsl = @import("dsl.zig");
/// Reverse proxy equivalence helpers namespace.
/// This module is imported from `equivalence.zig` and contains comparison utilities.
/// Use it when checking whether reverse proxy structures or states are equivalent.
pub const equivalence = @import("equivalence.zig");
/// Reverse proxy runtime namespace.
/// This module is imported from `runtime.zig` and provides runtime-facing APIs.
/// Use it for execution-time behavior that belongs to the reverse proxy package.
pub const runtime = @import("runtime.zig");
/// Reverse proxy integration namespace.
/// This module is imported from `integration.zig` and contains integration-facing APIs.
/// Use it where reverse proxy code integrates with other package boundaries.
pub const integration = @import("integration.zig");
/// Reverse proxy orchestration namespace.
/// This module is imported from `orchestrator.zig` and exposes orchestration APIs.
/// Use it for coordination logic that drives reverse proxy behavior.
pub const orchestrator = @import("orchestrator.zig");
/// Reverse proxy certificate utilities namespace.
/// This module is imported from `certs/mod.zig` and contains certificate-related APIs.
/// Use it for certificate handling that belongs to the reverse proxy package.
pub const certs = @import("certs/mod.zig");
/// Reverse proxy component namespace.
/// This module is imported from `components.zig` and groups component-level APIs.
/// Use it to access the reverse proxy component definitions and helpers.
pub const components = @import("components.zig");

/// Re-export of the canonical reverse proxy IR type from `ir`.
/// This type represents the normalized form used by downstream reverse proxy code.
/// It carries the same ownership and lifetime rules as `ir.CanonicalIr`.
pub const CanonicalIr = ir.CanonicalIr;
/// Re-export of the validation stage enum from `ir`.
/// Stages identify which validation phase produced a result or failure.
/// Use this alias to report or inspect the validation phase in a stable way.
pub const ValidationStage = ir.ValidationStage;
/// Re-export of the validation reason enum from `ir`.
/// Reasons identify why validation rejected a configuration or IR node.
/// This alias preserves the exact values and meaning defined by `ir.ValidationReason`.
pub const ValidationReason = ir.ValidationReason;
/// Re-export of validation diagnostics from `ir`.
/// Diagnostics describe the details associated with a validation failure.
/// Use this alias when surfacing structured validation information to callers.
pub const ValidationDiagnostic = ir.ValidationDiagnostic;
/// Re-export of the reverse proxy validation error type from `ir`.
/// Use this alias when reporting validation failures produced while checking the IR.
/// It has the same semantics and shape as `ir.ValidationError`.
pub const ValidationError = ir.ValidationError;
/// Validates a canonical reverse-proxy IR snapshot.
/// `diagnostics` must have capacity for `MAX_VALIDATION_DIAGNOSTICS`, and `diagnostics_count` is reset to zero before validation starts.
/// On the first failure, appends one diagnostic and returns the matching `ValidationError`.
pub const validateCanonicalIr = ir.validateCanonicalIr;

/// Immutable runtime view of a validated configuration generation.
/// All collection fields are borrowed slices, so the underlying canonical IR storage must remain valid while the snapshot is in use.
/// Build one with `RuntimeSnapshot.fromCanonicalIr()` after validation has succeeded.
pub const RuntimeSnapshot = orchestrator.RuntimeSnapshot;
/// Represents the orchestrator apply lifecycle.
/// `idle`, `build`, `admit`, `activate`, `drain`, and `retire` model normal generation changes, and `safe_mode` is the rollback fallback state.
/// The orchestrator enforces valid transitions between these stages.
pub const ApplyStage = orchestrator.ApplyStage;
/// Classifies the last orchestrator event for logging and diagnostics.
/// `stage_transition` marks a lifecycle step, while the remaining variants cover apply, drain, rollback, and safe-mode outcomes.
/// Store this with `OrchestratorEvent` to explain the most recent orchestrator state change.
pub const EventKind = orchestrator.EventKind;
/// Describes the most recent state-machine event emitted by the orchestrator.
/// `kind` identifies the event family, `stage` captures the lifecycle stage reached, and `generation_id` names the associated generation.
/// `reason` is populated only when the event carries a validation reason.
pub const OrchestratorEvent = orchestrator.OrchestratorEvent;
/// Coordinates snapshot admission, activation, draining, and rollback state.
/// The orchestrator stores borrowed snapshot references and slice views, so referenced data must outlive any active use.
/// Public methods enforce valid stage transitions and record the most recent event and diagnostics.
pub const Orchestrator = orchestrator.Orchestrator;
/// Error set returned by orchestrator lifecycle operations.
/// Includes canonical IR validation failures plus state-machine errors such as invalid transitions, missing rollback targets, and drain timeout.
/// Use this with the orchestrator APIs that admit, activate, drain, or roll back snapshots.
pub const OrchestratorError = orchestrator.OrchestratorError;
/// Describes one plugin and its relative ordering constraints.
/// `plugin_id` names the plugin being placed, while `before` and `after` list peer plugin IDs that must come later or earlier.
/// All slices are borrowed and must remain valid for the lifetime of the resolved ordering inputs.
pub const OrderingConstraintEntry = ordering.ConstraintEntry;
/// Stores a resolved plugin ordering and the number of valid entries.
/// The chain owns no allocations; the `plugin_ids` entries borrow from the input constraint entries.
/// Use `OrderedChain.init()` to start empty and `slice()` to read the populated prefix.
pub const OrderedChain = ordering.OrderedChain;
/// Resolves ordering constraints into a deterministic plugin order.
/// The result is ordered by dependency graph, with priority and plugin ID used to break ties among ready entries.
/// Returns `TooManyPlugins`, `DuplicatePluginId`, `MissingDependency`, or `CycleDetected` when the constraints cannot be satisfied.
pub const resolveOrdering = ordering.resolve;
/// Fixed-capacity list of plugin IDs representing the computed effective chain.
/// The stored IDs are borrowed slices; the type owns no heap memory and the borrowed data must outlive the chain.
/// Use `EffectiveChain.init()` and `slice()` to build and read the active prefix safely.
pub const EffectiveChain = composition.EffectiveChain;
/// Composes the effective plugin chain for a route from the global catalog and route overrides.
/// The returned chain borrows plugin ID slices from the inputs and does not allocate.
/// Fails when a required plugin is missing, a disable requires a waiver that is absent, or the chain would exceed capacity.
pub const composeEffectiveChain = composition.composeEffectiveChain;
/// Identifies which header phase is being executed.
/// `request_headers` runs before upstream forwarding, and `response_headers` runs after a response is available.
/// Use this to select the matching policy hook and observation counter.
pub const PolicyPhase = policy.PolicyPhase;
/// Tracks request-phase and response-phase policy execution counts plus the most recent error class.
/// Use `PolicyObservation.init()` to create a zeroed value with no recorded invocations, rejections, or bypasses.
/// This type owns no heap memory and is updated in place by the policy execution helpers.
pub const PolicyObservation = policy.PolicyObservation;
/// Result of running a policy phase.
/// `continue_forwarding` means processing may continue, while `reject` carries the response that should be returned upstream.
/// The reject payload is provided by the filter that stopped execution.
pub const PolicyExecutionResult = policy.PolicyExecutionResult;
/// Executes request-header policy filters in order and records per-phase observation data.
/// `filter_ctx` and `observation` must point to valid storage, and `filters.len` must not exceed `MAX_POLICY_FILTERS`.
/// Returns `continue_forwarding` when every filter continues or bypasses; returns `reject` immediately on the first policy rejection.
pub const executeRequestHeaders = policy.executeRequestHeaders;
/// Re-export of `filter_runtime.RuntimeError` from `serval-reverseproxy/filter_runtime.zig`.
/// Reports registry setup and route-execution lookup failures in the reverse-proxy runtime.
/// Includes capacity, duplicate-binding, and missing-route or missing-filter conditions.
pub const FilterRuntimeError = filter_runtime.RuntimeError;
/// Re-export of `filter_runtime.FilterRegistry` from `serval-reverseproxy/filter_runtime.zig`.
/// Stores borrowed runtime-loaded filter bindings and dispatches route hooks through generated vtables.
/// `registerTyped()` binds a plugin ID to typed filter state without taking ownership of that state.
/// Route execution propagates missing-route, missing-chain, missing-filter, and backpressure errors.
pub const FilterRegistry = filter_runtime.FilterRegistry;
/// Re-export of `filter_runtime.HookObservation` from `serval-reverseproxy/filter_runtime.zig`.
/// Tracks per-hook invocation counts across request and response execution phases.
/// Call `HookObservation.init()` to obtain a zero-initialized record for a fresh run.
pub const HookObservation = filter_runtime.HookObservation;
/// Re-export of `policy.executeResponseHeaders` from `serval-reverseproxy/policy.zig`.
/// Executes response-header filters in order and records observation data for each decision.
/// A rejection stops iteration immediately; bypass decisions are counted and processing continues.
/// The filter slice must not exceed the policy filter limit.
pub const executeResponseHeaders = policy.executeResponseHeaders;
/// Re-export of `policy.executeHeaderPhases` from `serval-reverseproxy/policy.zig`.
/// Executes request-header filters first and response-header filters only if the request phase succeeds.
/// Returns the first rejection immediately and leaves the observation updated with the work that ran.
/// Both filter slices are bounded by the policy filter limit.
pub const executeHeaderPhases = policy.executeHeaderPhases;
/// Re-export of `stream_request.BackpressureController` from `serval-reverseproxy/stream_request.zig`.
/// Encapsulates writable backpressure polling for stream execution.
/// `waitWritable()` retries up to the configured attempt budget and returns `error.BackpressureTimeout` on failure.
/// The controller borrows its context pointer and does not own any resources.
pub const BackpressureController = stream_request.BackpressureController;
/// Re-export of `stream_request.StreamObservation` from `serval-reverseproxy/stream_request.zig`.
/// Captures request-stream callback counts and the total number of emitted bytes.
/// Use `StreamObservation.init()` to obtain a zeroed observation before execution.
pub const StreamObservation = stream_request.StreamObservation;
/// Re-export of `stream_request.executeRequestStream` from `serval-reverseproxy/stream_request.zig`.
/// Drives a filter through request headers, each request chunk, and the end callback in order.
/// Waits for writable backpressure before each chunk and before `onRequestEnd`.
/// Returns the first rejection unchanged and records callback counts plus emitted bytes.
pub const executeRequestStream = stream_request.executeRequestStream;
/// Re-export of `stream_response.ResponseFramingPlan` from `serval-reverseproxy/stream_response.zig`.
/// Describes how response bytes are framed on the wire for HTTP/1.1 or HTTP/2.
/// Use this plan to decide whether a `Content-Length` header should be emitted.
pub const ResponseFramingPlan = stream_response.ResponseFramingPlan;
/// Re-export of `stream_response.planResponseFraming` from `serval-reverseproxy/stream_response.zig`.
/// Chooses the wire framing plan from the negotiated protocol and whether the response was transformed.
/// HTTP/1.1 uses chunked framing when transformed output has no known length.
/// HTTP/2 and HTTP/2 cleartext always use a data-stream plan.
pub const planResponseFraming = stream_response.planResponseFraming;
/// Re-export of `stream_response.shouldEmitContentLength` from `serval-reverseproxy/stream_response.zig`.
/// Returns `true` only for the framing plan that emits an explicit HTTP/1.1 content length.
/// Other framing plans stream without a `Content-Length` header.
pub const shouldEmitContentLength = stream_response.shouldEmitContentLength;
/// Re-export of `stream_response.ResponseObservation` from `serval-reverseproxy/stream_response.zig`.
/// Captures response-stream callback counts and the total number of emitted bytes.
/// Call `ResponseObservation.init()` to create a zeroed record before execution.
pub const ResponseObservation = stream_response.ResponseObservation;
/// Re-export of `stream_response.executeResponseStream` from `serval-reverseproxy/stream_response.zig`.
/// Drives a filter through response headers, each response chunk, and the end callback in order.
/// Propagates backpressure timeout errors and returns the first filter rejection unchanged.
/// Updates the supplied observation with callback counts and emitted-byte totals.
pub const executeResponseStream = stream_response.executeResponseStream;
/// Re-export of `failure.FailurePhase` from `serval-reverseproxy/failure.zig`.
/// Records how far request or response processing progressed before a failure occurred.
/// The phase ordering is used by failure classification to decide whether bypass is still safe.
pub const FailurePhase = failure.FailurePhase;
/// Re-export of `failure.FailureSource` from `serval-reverseproxy/failure.zig`.
/// Identifies which part of the reverse-proxy pipeline produced a failure.
/// Use this discriminator when classifying plugin, upstream, downstream, or timeout errors.
pub const FailureSource = failure.FailureSource;
/// Re-export of `failure.TerminalAction` from `serval-reverseproxy/failure.zig`.
/// Selects the terminal HTTP transport action after failure classification.
/// The enum owns no data and follows the same protocol-specific behavior as the source type.
pub const TerminalAction = failure.TerminalAction;
/// Result of failure classification.
/// `action` selects the terminal handling path, and `sticky_bypass_active` records whether sticky bypass remains enabled for the exchange.
/// This type is returned by value and does not own any resources.
pub const FailureDecision = failure.FailureDecision;
/// Classifies a reverse-proxy failure into the terminal action the connection or stream should take.
/// Fail-open plugin errors may select sticky bypass when the failure is still safe for bypass; otherwise the action is derived from the HTTP protocol.
/// For pre-header plugin or upstream read failures, the result requests an error response and disables sticky bypass.
pub const classifyFailure = failure.classifyFailure;
/// Thresholds that control when the guard-window monitor escalates.
/// `guard_window_ns` bounds the activation window in nanoseconds, while `max_error_rate_milli` and `max_fail_closed_count` define breach limits.
/// The profile is copied by value; call `isValid` before constructing a monitor from it.
pub const ThresholdProfile = guard_window.ThresholdProfile;
/// Snapshot of request and failure counts observed during a guard-window evaluation.
/// `request_count` and `error_count` are carried as `u64` counters, and `fail_closed_count` uses `u32`.
/// This type stores sample data only and does not own any resources.
pub const GuardSample = guard_window.GuardSample;
/// Decision returned after evaluating a guard-window sample.
/// `.monitor` means the activation is still within the guard window and no critical breach was detected.
/// `.stable`, `.auto_rollback`, and `.safe_mode` reflect later-stage monitor outcomes and orchestrator actions.
pub const GuardDecision = guard_window.GuardDecision;
/// Monitor for a single post-activation guard window.
/// Holds a borrowed orchestrator pointer plus copied threshold and activation metadata; it does not own the orchestrator.
/// Use `init` to construct it and `evaluate` to classify samples during the guard window.
pub const GuardWindowMonitor = guard_window.GuardWindowMonitor;
/// In-memory representation of the reverseproxy DSL after parsing and validation.
/// Stores listeners, pools, plugins, chains, and routes in fixed-capacity arrays with explicit used counts.
/// `toCanonicalIr` borrows storage from the parsed value, so the returned slices remain valid only while `self` is alive and unchanged.
pub const ParsedDsl = dsl.ParsedDsl;
/// Parses reverseproxy DSL text into a validated `ParsedDsl` value.
/// Blank lines and `#` comments are ignored after trimming ASCII space, tab, and carriage return.
/// Requires non-empty input and may return `ParseError` values for structural, capacity, or reference failures.
pub const parseDsl = dsl.parse;
/// Result of an equivalence comparison between two canonical IR values.
/// `equivalent` is `true` when the compared structures match under this module's rules.
/// When `equivalent` is `false`, `mismatch` describes the first observed difference; otherwise it is `null`.
pub const EquivalenceReport = equivalence.EquivalenceReport;
/// Parses `dsl_source` and compares the resulting canonical IR against `expected`.
/// The parsed DSL is used only for the duration of the call and ownership is not transferred.
/// Returns DSL parse errors from the parse step and a mismatch report when the canonical IR differs.
pub const compareDslToCanonical = equivalence.compareDslToCanonical;
/// Options for loading a reverseproxy runtime from disk.
/// `config_file` must name a readable DSL file and must not be empty.
/// The file is loaded relative to the current working directory.
pub const RuntimeLoadOptions = runtime.LoadOptions;
/// Options for starting a reverseproxy runtime with `Runtime.run`.
/// When `port` is `null`, the runtime derives the listener port from the loaded configuration.
/// A zero port is rejected by the run path as `error.InvalidListenerPort`.
pub const RuntimeRunOptions = runtime.RunOptions;
/// Loaded reverseproxy runtime state returned by `load`.
/// Owns the parsed DSL buffer, threaded IO context, and derived routing storage; call `deinit` to release them.
/// `run` reuses the stored DSL to configure the router and start serving traffic.
pub const Runtime = runtime.Runtime;
/// Loads and validates a reverseproxy runtime from `LoadOptions.config_file`.
/// The config file is read relative to the current working directory and the returned `Runtime` owns the DSL buffer and threaded IO handle.
/// Returns parse, IO, or validation errors, including `error.InvalidCanonicalIr` when canonical validation reports diagnostics.
pub const load = runtime.load;

/// Alias for the runtime pool backend selector used by `RuntimePool`.
/// `.simple` uses the simple connection pool backend, while `.none` disables pooling behavior.
/// The value is copied by value and does not own any resources.
pub const ComponentPoolKind = components.PoolKind;
/// Alias for the runtime metrics backend selector used by `RuntimeMetrics`.
/// `.noop` suppresses metrics emission, while `.prometheus` enables the Prometheus-backed path.
/// The value is copied by value and does not own any resources.
pub const ComponentMetricsKind = components.MetricsKind;
/// Selects the runtime tracer implementation.
/// `noop` disables tracing work, while `otel` configures the OpenTelemetry-backed path.
/// Use this with `RuntimeTracer.init` to choose the concrete backend.
pub const ComponentTracerKind = components.TracerKind;
/// Runtime-selected pool facade used by the reverse proxy wiring.
/// Stores the chosen pool kind plus the concrete backend implementations needed for dispatch.
/// Use `init`, then call `acquire`, `release`, and `drain` against the selected backend.
pub const RuntimePool = components.RuntimePool;
/// Runtime metrics facade that dispatches to the no-op or Prometheus implementation.
/// The selected backend is fixed by `kind`, and both backend instances are embedded in the value.
/// This type owns no external resources and has no `deinit` method.
pub const RuntimeMetrics = components.RuntimeMetrics;
/// Runtime tracer facade that dispatches to the no-op or OTEL implementation.
/// The selected backend is fixed by `kind`, and OTEL fields are populated only after successful initialization.
/// Call `deinit` to release any OTEL resources before the value goes out of scope.
pub const RuntimeTracer = components.RuntimeTracer;

/// Result of attempting to activate certificate material.
/// `success` means activation completed, `transient_failure` may succeed on retry,
/// and `fatal_failure` indicates a non-recoverable failure for the current input or state.
pub const CertActivationResult = certs.ActivationResult;
/// Paths identifying the certificate material and matching private key to activate.
/// Both fields are borrowed slices and are not copied by this type.
/// Keep the referenced paths valid for as long as the consumer needs them.
pub const CertMaterial = certs.CertMaterial;
/// Static certificate provider implementation.
/// Re-exported from `certs/static_provider.zig` for consumers that need the concrete provider through the package root.
/// The provider stores borrowed certificate paths and returns them without taking ownership or allocating.
pub const StaticCertProvider = certs.StaticProvider;
/// Self-signed certificate provider implementation.
/// Re-exported from `certs/selfsigned_provider.zig` for callers that need the concrete provider type via the package root.
/// The provider stores borrowed config data and can generate or reuse listener-scoped certificate material.
pub const SelfSignedCertProvider = certs.SelfSignedProvider;
/// ACME certificate provider implementation.
/// Re-exported from `certs/acme_provider.zig` for callers that want the concrete provider through the package root.
/// The provider initializes ACME state, loads initial certificate material, and runs the renewal loop.
pub const AcmeCertProvider = certs.AcmeProvider;

/// Controls how the reverse proxy behaves when a failure is encountered.
/// Use `fail_open` to continue past failures or `fail_closed` to stop on failures.
/// The enum is encoded as `u8` for compact configuration and serialization use.
pub const FailurePolicy = ir.FailurePolicy;
/// Runtime limits that control state size, output size, expansion ratio, and CPU time per chunk.
/// All fields are plain numeric limits, and callers should validate the budget with `isValid()` before admission or validation logic uses it.
/// This type owns no memory and reports validity with a boolean rather than a detailed error.
pub const RuntimeBudget = ir.RuntimeBudget;
/// Selects which TLS certificate source the reverse proxy should use.
/// The discriminants are stable `u8` values so the enum can be serialized or stored compactly.
/// Use the variant that matches the configured certificate management mode.
pub const TlsProvider = ir.TlsProvider;
/// TLS configuration for a listener.
/// `provider` selects the active TLS mode, and only the matching provider-specific field should be populated.
/// Validation rejects missing or malformed provider data for the chosen mode.
pub const ListenerTls = ir.ListenerTls;
/// Configuration for serving TLS from pre-existing certificate files.
/// `cert_path` and `key_path` are borrowed path slices and are not copied or owned by the config.
/// Both files must be readable when the config is used.
pub const StaticTlsConfig = ir.StaticTlsConfig;
/// Configuration for generating or reusing a self-signed TLS setup.
/// `state_dir_path` and `domain` are borrowed strings, and `rotate_on_boot` defaults to `false`.
/// The struct does not own any certificate material; it only describes where state is stored.
pub const SelfSignedTlsConfig = ir.SelfSignedTlsConfig;
/// ACME TLS configuration for listener certificate management.
/// The URL, contact email, state directory, and domain are borrowed strings; default timing values come from `serval-core.config`.
/// Validation requires the polling and backoff fields to be positive and ordered.
pub const AcmeTlsConfig = ir.AcmeTlsConfig;
/// An inbound listener definition.
/// `id` and `bind` are borrowed identifiers, and `tls` optionally selects one of the supported TLS provider modes.
/// Keep the borrowed strings valid for as long as the listener is used by validation or runtime admission.
pub const Listener = ir.Listener;
/// A backend pool referenced by routes.
/// `id` is the stable pool identifier and `upstream_spec` optionally stores borrowed upstream configuration text.
/// The struct does not allocate and does not copy the upstream specification.
pub const Pool = ir.Pool;
/// Canonical route definition used by validation and composition.
/// All string fields and plugin and waiver slices are borrowed; the route does not own its backing storage.
/// `listener_id` may be empty in source data, but validation requires a referenced listener before admission succeeds.
pub const Route = ir.Route;
/// A plugin catalog entry available to routes and chains.
/// `id` and `version` are borrowed metadata; `enabled`, `mandatory`, and `disable_requires_waiver` affect validation and composition.
/// This type owns no heap memory and carries no additional behavior beyond its fields.
pub const PluginCatalogEntry = ir.PluginCatalogEntry;
/// A named chain of policy entries.
/// `id` is the chain identifier referenced by routes, and `entries` is a borrowed slice of chain definitions.
/// The plan does not own entry storage; keep the backing slice alive while the plan is in use.
pub const ChainPlan = ir.ChainPlan;
/// One plugin entry within a chain plan.
/// `plugin_id`, `before`, and `after` are borrowed slices; `failure_policy` and `budget` control per-plugin execution behavior.
/// Validate the budget with `RuntimeBudget.isValid()` before using the entry in admission or composition logic.
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
