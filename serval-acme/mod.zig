//! Serval ACME - Automatic certificate lifecycle primitives
//!
//! Layer 2 (Infrastructure).
//! TigerStyle: Explicit state machine types and fixed-capacity stores.

pub const types = @import("types.zig");
pub const CertState = types.CertState;
pub const RuntimeConfig = types.RuntimeConfig;
pub const TypesError = types.Error;

pub const backoff = @import("backoff.zig");
pub const AcmeBackoff = backoff.BoundedBackoff;
pub const AcmeBackoffError = backoff.Error;

pub const client = @import("client.zig");
pub const AcmeUrl = client.Url;
pub const AcmeReplayNonce = client.ReplayNonce;
pub const AcmeDirectory = client.Directory;
pub const AcmeAccountStatus = client.AccountStatus;
pub const AcmeOrderStatus = client.OrderStatus;
pub const AcmeAccountResponse = client.AccountResponse;
pub const AcmeAuthorizationStatus = client.AuthorizationStatus;
pub const AcmeChallengeStatus = client.ChallengeStatus;
pub const AcmeChallengeType = client.ChallengeType;
pub const AcmeAuthorizationChallenge = client.AuthorizationChallenge;
pub const AcmeAuthorizationResponse = client.AuthorizationResponse;
pub const AcmeNewOrderRequest = client.NewOrderRequest;
pub const AcmeOrderResponse = client.OrderResponse;
pub const AcmeNewAccountPayload = client.NewAccountPayload;
pub const AcmeClientError = client.Error;

pub const jws = @import("jws.zig");
pub const AcmeJwkP256 = jws.JwkP256;
pub const AcmeProtectedHeaderJwkParams = jws.ProtectedHeaderJwkParams;
pub const AcmeProtectedHeaderKidParams = jws.ProtectedHeaderKidParams;
pub const AcmeFlattenedJwsParams = jws.FlattenedJwsParams;
pub const AcmeJwsError = jws.Error;

pub const signer = @import("signer.zig");
pub const AcmeAccountSigner = signer.AccountSigner;
pub const AcmeSignerError = signer.Error;

pub const wire = @import("wire.zig");
pub const AcmeParsedUrl = wire.ParsedUrl;
pub const AcmeWireRequest = wire.WireRequest;
pub const AcmeWireError = wire.Error;
pub const AcmeComposeSignedRequestError = wire.ComposeSignedRequestError;

pub const orchestration = @import("orchestration.zig");
pub const AcmeOperation = orchestration.Operation;
pub const AcmeEndpoint = orchestration.Endpoint;
pub const AcmeFlowContext = orchestration.FlowContext;
pub const AcmeResponseView = orchestration.ResponseView;
pub const AcmeParsedBody = orchestration.ParsedBody;
pub const AcmeHandledResponse = orchestration.HandledResponse;
pub const AcmeResponseOutcome = orchestration.ResponseOutcome;
pub const AcmeResponseReason = orchestration.ResponseReason;
pub const AcmeResponseAssessment = orchestration.ResponseAssessment;
pub const AcmeProtocolError = orchestration.ProtocolError;
pub const AcmeErrorClass = orchestration.ErrorClass;
pub const AcmeErrorReason = orchestration.ErrorReason;
pub const AcmeErrorAssessment = orchestration.ErrorAssessment;
pub const assessAcmeResponse = orchestration.assessResponse;
pub const classifyAcmeProtocolError = orchestration.classifyProtocolError;

pub const transport = @import("transport.zig");
pub const AcmeTransportExecuteParams = transport.ExecuteParams;
pub const AcmeTransportExecuteOperationParams = transport.ExecuteOperationParams;
pub const AcmeTransportExecuteResponse = transport.ExecuteResponse;
pub const AcmeTransportError = transport.Error;
pub const AcmeTransportExecuteOperationError = transport.ExecuteOperationError;
pub const executeAcmeWireRequest = transport.execute;
pub const executeAcmeOperation = transport.executeOperation;

pub const csr = @import("csr.zig");
pub const AcmeCsrError = csr.Error;
pub const AcmeCsrResult = csr.Result;

pub const storage = @import("storage.zig");
pub const AcmeStorageError = storage.Error;
pub const AcmePersistedPaths = storage.PersistedPaths;

pub const runtime = @import("runtime.zig");
pub const AcmeRuntimeError = runtime.Error;
pub const AcmeRuntimeWorkBuffers = runtime.WorkBuffers;
pub const runAcmeIssuanceOnce = runtime.runIssuanceOnce;

pub const tls_alpn_hook = @import("tls_alpn_hook.zig");
pub const AcmeTlsAlpnHookProvider = tls_alpn_hook.TlsAlpnHookProvider;
pub const AcmeTlsAlpnHookError = tls_alpn_hook.Error;

pub const tls_alpn_cert = @import("tls_alpn_cert.zig");
pub const AcmeTlsAlpnCertError = tls_alpn_cert.Error;
pub const AcmeTlsAlpnMaterials = tls_alpn_cert.Materials;

pub const bootstrap_cert = @import("bootstrap_cert.zig");
pub const AcmeBootstrapCertError = bootstrap_cert.Error;
pub const AcmeBootstrapCertMaterials = bootstrap_cert.Materials;

pub const scheduler = @import("scheduler.zig");
pub const AcmeScheduler = scheduler.Scheduler;
pub const AcmeSchedulerConfig = scheduler.Config;
pub const AcmeSchedulerError = scheduler.Error;
pub const AcmeShouldRenewResult = scheduler.ShouldRenewResult;
pub const AcmeIssueResult = scheduler.IssueResult;

pub const renewer = @import("renewer.zig");
pub const AcmeRenewer = renewer.Renewer;
pub const AcmeRenewerParams = renewer.Params;
pub const AcmeManagedRenewer = renewer.ManagedRenewer;
pub const AcmeManagedRenewerParams = renewer.ManagedParams;
pub const AcmeManagedFromAcmeConfigParams = renewer.ManagedFromAcmeConfigParams;
pub const AcmeRenewerError = renewer.Error;
pub const AcmeActivationResult = renewer.ActivationResult;
pub const AcmeActivateFn = renewer.ActivateFn;
pub const AcmeParseBuffers = renewer.ParseBuffers;

pub const manager = @import("manager.zig");
pub const AcmeSignedBodies = manager.SignedBodies;
pub const AcmeTickResult = manager.TickResult;
pub const AcmeExecutor = manager.Executor;
pub const AcmeManager = manager.Manager;
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
