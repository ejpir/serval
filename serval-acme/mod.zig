//! Serval ACME - Automatic certificate lifecycle primitives
//!
//! Layer 2 (Infrastructure).
//! TigerStyle: Explicit state machine types and fixed-capacity stores.

/// Imports the ACME types module for state and runtime configuration helpers.
/// This module defines `Error`, `CertState`, `DomainName`, and `RuntimeConfig`.
/// The imported module is shared by the rest of `serval-acme` through this re-export.
pub const types = @import("types.zig");
/// Re-exports `types.CertState` from the ACME types module.
/// Use this alias to refer to the explicit certificate lifecycle state machine.
/// The enum values and semantics are defined in `serval-acme/types.zig`.
pub const CertState = types.CertState;
/// Runtime ACME configuration copied into fixed-capacity storage.
/// The struct owns its copied directory URL, contact email, state path, and domain names, so the resulting slices remain valid while the value is alive.
/// `initFromConfig` performs range and length validation before copying any enabled configuration data into the struct.
pub const RuntimeConfig = types.RuntimeConfig;
/// Error set returned by ACME runtime configuration parsing and domain-name updates.
/// These errors cover invalid directory URLs, contact data, state paths, domain counts, domain syntax, and out-of-range timing values.
/// Treat each case as a hard validation failure when building runtime ACME state.
pub const TypesError = types.Error;

/// Re-export of the ACME backoff utilities module.
/// This namespace contains the bounded retry scheduler and its associated error set.
/// Use it when you need the module-level backoff helpers rather than the type aliases in `mod.zig`.
pub const backoff = @import("backoff.zig");
/// Bounded exponential backoff helper with deterministic jitter.
/// `delayMs` computes a capped retry delay from the number of consecutive failures, and `nextRetryDeadlineNs` converts that delay into a monotonic deadline.
/// Initialization validates the configured delay range before the helper can be used.
pub const AcmeBackoff = backoff.BoundedBackoff;
/// Error set returned by bounded ACME backoff initialization.
/// The only current validation failure is `InvalidRange`, which covers zero minimum delay or an inverted min/max pair.
/// Use this alias with `AcmeBackoff.init` and other backoff setup code.
pub const AcmeBackoffError = backoff.Error;

/// Re-export of the ACME client protocol module.
/// This namespace provides bounded URL and nonce types plus JSON parsing helpers for directory, account, order, and authorization responses.
/// Import this module when you need the full client-facing ACME protocol surface.
pub const client = @import("client.zig");
/// Fixed-capacity holder for absolute ACME URLs.
/// `set` accepts only non-empty `http://` or `https://` values and rejects whitespace and line breaks.
/// `slice()` returns a view into the internal buffer; the stored bytes are owned by the struct.
pub const AcmeUrl = client.Url;
/// Fixed-capacity holder for the `Replay-Nonce` response header.
/// `set` rejects empty values, oversize values, and values containing spaces or line breaks before copying them in-place.
/// `slice()` returns a read-only view into the internal buffer and does not allocate.
pub const AcmeReplayNonce = client.ReplayNonce;
/// Parsed ACME directory metadata with fixed-capacity endpoint URLs.
/// The directory stores the `newNonce`, `newAccount`, and `newOrder` endpoints required to start protocol operations.
/// Each URL is validated and copied into owned in-struct storage; the resulting slices remain valid while the struct is alive.
pub const AcmeDirectory = client.Directory;
/// Progress state for an ACME account.
/// The enum captures the account lifecycle states reported by the ACME server.
/// This alias is used as a compact status field in parsed account responses.
pub const AcmeAccountStatus = client.AccountStatus;
/// Progress state for an ACME order.
/// The enum represents the server-reported order lifecycle from pending through valid or invalid.
/// It is a pure protocol value with no allocation or ownership concerns.
pub const AcmeOrderStatus = client.OrderStatus;
/// Parsed ACME account response with fixed-capacity storage for the optional orders URL.
/// `status` is always present in a successfully parsed response; `has_orders_url` indicates whether `orders_url` was supplied.
/// When present, `orders_url` owns no memory and simply stores the validated URL bytes in-place.
pub const AcmeAccountResponse = client.AccountResponse;
/// Progress state for an ACME authorization object.
/// The enum covers the server-reported authorization lifecycle, including terminal states such as valid, invalid, expired, and revoked.
/// Use this status together with the authorization challenges to decide whether validation can continue.
pub const AcmeAuthorizationStatus = client.AuthorizationStatus;
/// Progress state for an individual ACME challenge.
/// The enum values represent the server-reported lifecycle of a challenge entry.
/// No ownership or allocation is involved; this is a compact protocol status value.
pub const AcmeChallengeStatus = client.ChallengeStatus;
/// Challenge type discriminator used by ACME authorization responses.
/// This alias currently exposes the protocol-supported challenge variants from `client.zig`.
/// Code consuming the type should treat unknown variants as unsupported protocol input.
pub const AcmeChallengeType = client.ChallengeType;
/// ACME authorization challenge metadata with fixed-capacity token storage.
/// The `challenge_type`, `status`, and `url` fields describe the server-provided challenge entry.
/// `setToken` validates token length and character set before copying it into the internal buffer; `token()` returns a slice aliasing that storage.
pub const AcmeAuthorizationChallenge = client.AuthorizationChallenge;
/// Re-export of `client.AuthorizationResponse`, the parsed ACME authorization response container.
/// It stores authorization status, the identifier domain, and a fixed-capacity challenge array.
/// The response keeps all protocol data inline and exposes helper methods for selecting challenges.
pub const AcmeAuthorizationResponse = client.AuthorizationResponse;
/// Re-export of `client.NewOrderRequest`, the bounded ACME new-order request container.
/// It stores a fixed-capacity array of identifiers and a count of populated entries.
/// Use the provided client helpers to initialize and append identifiers within the configured limit.
pub const AcmeNewOrderRequest = client.NewOrderRequest;
/// Re-export of `client.OrderResponse`, the parsed ACME order response container.
/// It stores order status, the finalize URL, and bounded arrays for authorization and certificate links.
/// All URLs are stored inline in fixed-size buffers owned by the value.
pub const AcmeOrderResponse = client.OrderResponse;
/// Re-export of `client.NewAccountPayload`, the payload shape used for ACME new-account requests.
/// `contact_email` is a borrowed slice, while the boolean flags control terms-of-service and existing-account behavior.
/// Ownership of the email text remains with the caller.
pub const AcmeNewAccountPayload = client.NewAccountPayload;
/// Re-export of `client.Error`, the error set used by ACME client parsing and protocol helpers.
/// Handle the named tags from `client.zig` directly; the alias does not change the error surface.
/// The set covers invalid URLs, malformed protocol data, response limits, and output sizing failures.
pub const AcmeClientError = client.Error;

/// Re-export of the `jws.zig` submodule.
/// This module provides bounded ACME JWS serialization, protected-header construction, and coordinate validation.
/// Imported aliases in this namespace preserve the behavior defined by the underlying module.
pub const jws = @import("jws.zig");
/// Re-export of `jws.JwkP256`, the inline storage used for ACME P-256 public-key coordinates.
/// The value stores base64url-encoded `x` and `y` coordinate text in fixed-size buffers.
/// Its accessor methods return borrowed slices into that internal storage.
pub const AcmeJwkP256 = jws.JwkP256;
/// Re-export of `jws.ProtectedHeaderJwkParams`, the parameter bundle for `jwk` protected-header serialization.
/// It carries borrowed pointers to the replay nonce, request URL, and inline P-256 JWK coordinates.
/// The pointed-to values must remain valid for the duration of serialization.
pub const AcmeProtectedHeaderJwkParams = jws.ProtectedHeaderJwkParams;
/// Re-export of `jws.ProtectedHeaderKidParams`, the parameter bundle for `kid` protected-header serialization.
/// It carries borrowed pointers to the replay nonce, request URL, and key identifier URL.
/// The pointed-to values must remain valid for the duration of serialization.
pub const AcmeProtectedHeaderKidParams = jws.ProtectedHeaderKidParams;
/// Re-export of `jws.FlattenedJwsParams`, the input bundle for flattened JWS serialization.
/// The struct holds borrowed protected-header JSON, payload JSON, and signature slices.
/// Callers must keep each backing slice valid until serialization completes.
pub const AcmeFlattenedJwsParams = jws.FlattenedJwsParams;
/// Re-export of `jws.Error`, the error set used by ACME JWS serialization helpers.
/// Use the named tags from `jws.zig` when handling protected-header, payload, signature, or output-size failures.
/// The alias is exact and carries no additional semantics beyond the underlying error set.
pub const AcmeJwsError = jws.Error;

/// Re-export of the `signer.zig` submodule.
/// This module contains ACME account signing, key-authorization generation, and JWS assembly helpers.
/// Imported aliases in this namespace behave exactly like the declarations in the underlying module.
pub const signer = @import("signer.zig");
/// Re-export of `signer.AccountSigner`, the in-process ACME account key signer.
/// The value owns the ECDSA P-256 key pair and writes JWS output into caller-provided buffers.
/// Methods return slices that borrow the provided storage, so the caller owns the backing memory.
pub const AcmeAccountSigner = signer.AccountSigner;
/// Re-export of `signer.Error`, the error set returned by ACME account-signing helpers.
/// Match on the named error tags from `signer.zig`; the alias does not add or remove any cases.
/// The set covers invalid inputs, encoding limits, and signing or JWK-rendering failures.
pub const AcmeSignerError = signer.Error;

/// Re-export of the `wire.zig` submodule.
/// This module provides ACME wire-format URL parsing, request composition, and response-header helpers.
/// Imported types and errors in this namespace preserve the behavior defined by the underlying module.
pub const wire = @import("wire.zig");
/// Re-export of `wire.ParsedUrl`, the fixed-size parsed URL container used by ACME wire helpers.
/// The struct stores host and path bytes inline and returns borrowed slices from its internal buffers.
/// Use the `wire` module APIs to populate and validate it before converting it to an upstream target.
pub const AcmeParsedUrl = wire.ParsedUrl;
/// Re-exports `wire.WireRequest`.
/// This request stores parsed target data and borrows body and header slices from caller-owned storage.
pub const AcmeWireRequest = wire.WireRequest;
/// Re-exports `wire.Error`.
/// Use this set for URL parsing, validation, body-size, and required-header failures at the wire layer.
pub const AcmeWireError = wire.Error;
/// Re-exports `wire.ComposeSignedRequestError`.
/// This error set combines wire-format validation failures with JWS serialization failures while building a signed request.
pub const AcmeComposeSignedRequestError = wire.ComposeSignedRequestError;

/// Imports the ACME orchestration helper module.
/// The namespace provides endpoint selection, response assessment, and error classification helpers for account and order flows.
pub const orchestration = @import("orchestration.zig");
/// Re-exports `orchestration.Operation`.
/// This internal operation kind drives request construction and response handling.
pub const AcmeOperation = orchestration.Operation;
/// Re-exports `orchestration.Endpoint`.
/// Use this enum to identify the ACME endpoint being selected or routed to.
pub const AcmeEndpoint = orchestration.Endpoint;
/// Re-exports `orchestration.FlowContext`.
/// This stateful context carries selected ACME URLs and replay nonce data by value.
pub const AcmeFlowContext = orchestration.FlowContext;
/// Re-exports `orchestration.ResponseView`.
/// The headers and body in this view borrow storage owned elsewhere and are not managed here.
pub const AcmeResponseView = orchestration.ResponseView;
/// Re-exports `orchestration.ParsedBody`.
/// This tagged union holds no body, an account response, or an order response.
pub const AcmeParsedBody = orchestration.ParsedBody;
/// Re-exports `orchestration.HandledResponse`.
/// This pairs a response assessment with an optional parsed ACME body, if decoding succeeded.
pub const AcmeHandledResponse = orchestration.HandledResponse;
/// Re-exports `orchestration.ResponseOutcome`.
/// Use this enum to record whether a response should succeed, retry, back off, or fail fatally.
pub const AcmeResponseOutcome = orchestration.ResponseOutcome;
/// Re-exports `orchestration.ResponseReason`.
/// This enum classifies why a response was not treated as a clean success.
pub const AcmeResponseReason = orchestration.ResponseReason;
/// Re-exports `orchestration.ResponseAssessment`.
/// Use this struct to carry the response outcome, reason, and HTTP status from ACME response evaluation.
pub const AcmeResponseAssessment = orchestration.ResponseAssessment;
/// Re-exports `orchestration.ProtocolError`.
/// This combined error set includes orchestration, client, and wire-level failures.
pub const AcmeProtocolError = orchestration.ProtocolError;
/// Re-exports `orchestration.ErrorClass`.
/// This class groups failures by retry policy, protocol handling, or caller input.
pub const AcmeErrorClass = orchestration.ErrorClass;
/// Re-exports `orchestration.ErrorReason`.
/// Use this enum to distinguish why an ACME orchestration failure was classified as an error.
pub const AcmeErrorReason = orchestration.ErrorReason;
/// Alias of `orchestration.ErrorAssessment`, the classification of an orchestration error.
/// `class` records the broad handling category and `reason` records the specific failure mode.
/// This type is a plain value and does not own any external resources.
pub const AcmeErrorAssessment = orchestration.ErrorAssessment;
/// Alias of `orchestration.assessResponse` for HTTP response assessment.
/// Use this helper to classify upstream ACME responses into retry or success outcomes.
/// The assessment reflects the response view and does not take ownership of any buffers.
pub const assessAcmeResponse = orchestration.assessResponse;
/// Alias of `orchestration.classifyProtocolError` for protocol-error classification.
/// Use this helper to map lower-level failures into ACME retry and reporting categories.
/// It operates on the orchestration module's combined protocol error set.
pub const classifyAcmeProtocolError = orchestration.classifyProtocolError;

/// Imports the ACME transport execution submodule namespace.
/// Use this module to access wire-request execution helpers and transport-specific types.
/// It does not add behavior beyond the underlying transport implementation.
pub const transport = @import("transport.zig");
/// Alias of `transport.ExecuteParams` for prebuilt request execution input.
/// This bundles the wire request, I/O handle, and parsing/body buffers.
/// The request and buffers must remain valid while `execute` is running.
pub const AcmeTransportExecuteParams = transport.ExecuteParams;
/// Alias of `transport.ExecuteOperationParams` for full-operation execution input.
/// This bundles the orchestration operation, optional signed body, I/O handle, and work buffers.
/// The provided buffers must remain valid for the duration of the call.
pub const AcmeTransportExecuteOperationParams = transport.ExecuteOperationParams;
/// Alias of `transport.ExecuteResponse`, the result returned by `execute`.
/// The response carries the upstream status, headers, and body slice.
/// The body is owned by the caller's provided buffer and is not separately allocated.
pub const AcmeTransportExecuteResponse = transport.ExecuteResponse;
/// Alias of `transport.Error` for transport-layer request and response failures.
/// Use this when executing a wire request against an upstream server.
/// It includes client failures plus header, body-read, and chunked-encoding errors.
pub const AcmeTransportError = transport.Error;
/// Alias of `transport.ExecuteOperationError` for ACME operation execution failures.
/// Use this error set when a full operation cannot be built, sent, or classified.
/// It combines transport, wire, and orchestration protocol error sets.
pub const AcmeTransportExecuteOperationError = transport.ExecuteOperationError;
/// Alias of `transport.execute` for sending a prebuilt ACME wire request.
/// This forwards the request to the selected upstream and returns the parsed response.
/// The caller provides the request, I/O context, and workspace buffers.
pub const executeAcmeWireRequest = transport.execute;
/// Alias of `transport.executeOperation` for executing a full ACME operation.
/// This forwards through the transport layer without adding extra behavior.
/// Request construction, upstream I/O, and response handling errors come from the transport API.
pub const executeAcmeOperation = transport.executeOperation;

/// Imports the ACME CSR generation submodule namespace.
/// Use this module to access CSR generation helpers and related types.
/// The module itself has no side effects beyond the compile-time import.
pub const csr = @import("csr.zig");
/// Alias of `csr.Error` for ACME CSR generation failures.
/// Use this error set when building a CSR or keypair through the CSR module.
/// It covers input validation, encoding, output-size, and signature failures.
pub const AcmeCsrError = csr.Error;
/// Alias of `csr.Result` for generated CSR output.
/// The returned slices point into caller-provided output buffers.
/// Keep those buffers alive and unchanged for as long as the result is in use.
pub const AcmeCsrResult = csr.Result;

/// Imports the ACME storage submodule namespace.
/// Use this module to access persistence helpers and storage-specific types.
/// The imported module does not allocate or own any runtime state.
pub const storage = @import("storage.zig");
/// Alias of `storage.Error` for ACME persistence failures.
/// Use this error set when handling certificate and key storage operations.
/// It includes validation, path-length, directory creation, write, sync, and rename failures.
pub const AcmeStorageError = storage.Error;
/// Alias of `storage.PersistedPaths`.
/// The certificate and key path slices borrow the caller-provided output buffers used during persistence.
/// Keep those buffers alive and unchanged while the paths are referenced.
pub const AcmePersistedPaths = storage.PersistedPaths;

/// ACME automated issuance runtime namespace.
/// Re-exports the single-run issuance entry point, work-buffer type, and runtime error set from `runtime.zig`.
pub const runtime = @import("runtime.zig");
/// Alias of `runtime.Error`.
/// This error set includes runtime validation failures, ACME protocol and transport errors, storage failures, TLS reload failures, and cancellation.
pub const AcmeRuntimeError = runtime.Error;
/// Alias of `runtime.WorkBuffers`.
/// These scratch buffers are owned by the caller and must stay alive and writable for the full issuance run.
/// `cert_path_buf` and `key_path_buf` receive the persisted output paths.
pub const AcmeRuntimeWorkBuffers = runtime.WorkBuffers;
/// Alias of `runtime.runIssuanceOnce`.
/// Runs one bounded ACME issuance cycle, including challenge activation, certificate download, persistence, and optional TLS reload.
/// The hook provider argument is required, and the returned persisted paths alias the caller-provided work buffers.
pub const runAcmeIssuanceOnce = runtime.runIssuanceOnce;

/// Process-wide TLS-ALPN hook provider namespace.
/// Re-exports the hook provider type and its lifecycle/error surface from `tls_alpn_hook.zig`.
pub const tls_alpn_hook = @import("tls_alpn_hook.zig");
/// Alias of `tls_alpn_hook.TlsAlpnHookProvider`.
/// This provider manages the process-wide TLS-ALPN hooks used for ACME challenge handling.
/// It stores only borrowed pointers and copies the selected challenge domain into internal fixed-capacity storage.
pub const AcmeTlsAlpnHookProvider = tls_alpn_hook.TlsAlpnHookProvider;
/// Alias of `tls_alpn_hook.Error`.
/// This error set covers hook-provider validation and lifecycle failures such as invalid domains, hook conflicts, and missing installation.
pub const AcmeTlsAlpnHookError = tls_alpn_hook.Error;

/// ACME TLS-ALPN-01 challenge certificate namespace.
/// Re-exports the material and error types used to build the ephemeral challenge certificate and private key.
pub const tls_alpn_cert = @import("tls_alpn_cert.zig");
/// Alias of `tls_alpn_cert.Error`.
/// This error set covers TLS-ALPN challenge material generation failures, including invalid inputs, output sizing, and signing.
pub const AcmeTlsAlpnCertError = tls_alpn_cert.Error;
/// Alias of `tls_alpn_cert.Materials`.
/// The certificate and key PEM slices reference caller-provided buffers and are only valid while those buffers remain alive.
/// Use this type for ephemeral TLS-ALPN-01 challenge material.
pub const AcmeTlsAlpnMaterials = tls_alpn_cert.Materials;

/// Bootstrap self-signed certificate generation namespace.
/// Re-exports the bootstrap material and error types used to create a temporary certificate before ACME issuance completes.
pub const bootstrap_cert = @import("bootstrap_cert.zig");
/// Alias of `bootstrap_cert.Error`.
/// This error set reports bootstrap certificate generation failures such as invalid input, insufficient output space, and signature errors.
pub const AcmeBootstrapCertError = bootstrap_cert.Error;
/// Alias of `bootstrap_cert.Materials`.
/// The returned PEM slices borrow caller-provided output buffers and do not own storage.
/// Keep the backing buffers alive and unchanged while the slices are in use.
pub const AcmeBootstrapCertMaterials = bootstrap_cert.Materials;

/// ACME renewal scheduler namespace.
/// Re-exports the bounded scheduler loop, config, callback types, step results, and scheduler errors from `scheduler.zig`.
pub const scheduler = @import("scheduler.zig");
/// Alias of `scheduler.Scheduler`.
/// Use this stateful scheduler to drive ACME renewal checks with `init`, `step`, and `run`.
/// It stores borrowed callback pointers and does not allocate heap memory itself.
pub const AcmeScheduler = scheduler.Scheduler;
/// Alias for `scheduler.Config` in the ACME API surface.
/// Pass this configuration to control ACME scheduler behavior using the underlying scheduler settings.
pub const AcmeSchedulerConfig = scheduler.Config;
/// Alias for `scheduler.Error` in the ACME API surface.
/// Errors returned by ACME scheduler operations use the same cases and semantics as the scheduler module.
pub const AcmeSchedulerError = scheduler.Error;
/// Alias for `scheduler.ShouldRenewResult` in the ACME API surface.
/// Use this type to inspect whether a certificate should be renewed by the scheduler logic.
pub const AcmeShouldRenewResult = scheduler.ShouldRenewResult;
/// Alias for `scheduler.IssueResult` in the ACME API surface.
/// Use this type when handling the result of issuing ACME work through the scheduler layer.
pub const AcmeIssueResult = scheduler.IssueResult;

/// Imports the ACME renewer implementation module.
/// This value is a module handle and carries no separate ownership.
pub const renewer = @import("renewer.zig");
/// Re-export of the ACME renewer type.
/// Use this alias for renewer behavior defined in `renewer.zig`.
pub const AcmeRenewer = renewer.Renewer;
/// Re-export of the base renewer parameter type.
/// Supply the values expected by the renewer implementation before construction.
pub const AcmeRenewerParams = renewer.Params;
/// Re-export of the managed renewer type.
/// Use this alias for managed renewal workflows implemented in `renewer.zig`.
pub const AcmeManagedRenewer = renewer.ManagedRenewer;
/// Re-export of the parameters used to construct a managed renewer.
/// Follow the ownership and lifetime rules defined by `renewer.zig`.
pub const AcmeManagedRenewerParams = renewer.ManagedParams;
/// Re-export of the parameters used to build a managed renewer from ACME config.
/// Populate all required fields before passing the value into renewer setup.
pub const AcmeManagedFromAcmeConfigParams = renewer.ManagedFromAcmeConfigParams;
/// Re-export of the ACME renewer error set.
/// Use this alias when handling failures from renewer operations.
pub const AcmeRenewerError = renewer.Error;
/// Re-export of the renewer activation result type.
/// Returned by activation flows to report success or failure state.
pub const AcmeActivationResult = renewer.ActivationResult;
/// Re-export of the renewer activation callback type.
/// Implementations should match the signature defined in `renewer.zig`.
pub const AcmeActivateFn = renewer.ActivateFn;
/// Re-export of the ACME renewer parse-buffer storage type.
/// Use this alias when supplying temporary buffers to renewer parsing logic.
pub const AcmeParseBuffers = renewer.ParseBuffers;

/// Imports the ACME manager implementation module.
/// This value is a module handle; it does not allocate or transfer ownership.
pub const manager = @import("manager.zig");
/// Re-export of the signed-bodies container used by the ACME manager.
/// Preserve any ownership and lifetime rules defined by `manager.zig`.
pub const AcmeSignedBodies = manager.SignedBodies;
/// Re-export of the ACME manager tick result type.
/// Returned by manager tick operations to describe the outcome of a cycle.
pub const AcmeTickResult = manager.TickResult;
/// Re-export of the ACME executor type.
/// Use this alias for executor implementations defined in `manager.zig`.
pub const AcmeExecutor = manager.Executor;
/// Re-export of the ACME manager type.
/// Own and use it through `manager.zig`; this module only forwards the declaration.
pub const AcmeManager = manager.Manager;
/// Re-export of the ACME manager error set.
/// Use this alias when handling failures from manager operations.
pub const AcmeManagerError = manager.Error;

test {
    _ = @import("types.zig");
    _ = @import("backoff.zig");
    _ = @import("client.zig");
    _ = @import("jws.zig");
    _ = @import("signer.zig");
    _ = @import("wire.zig");
    _ = @import("orchestration.zig");
    _ = @import("transport.zig");
    _ = @import("csr.zig");
    _ = @import("storage.zig");
    _ = @import("runtime.zig");
    _ = @import("tls_alpn_hook.zig");
    _ = @import("tls_alpn_cert.zig");
    _ = @import("bootstrap_cert.zig");
    _ = @import("scheduler.zig");
    _ = @import("renewer.zig");
    _ = @import("manager.zig");
}
