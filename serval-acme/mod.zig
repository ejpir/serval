//! Serval ACME - Automatic certificate lifecycle primitives
//!
//! Layer 2 (Infrastructure).
//! TigerStyle: Explicit state machine types and fixed-capacity stores.

pub const types = @import("types.zig");
pub const CertState = types.CertState;
pub const RuntimeConfig = types.RuntimeConfig;
pub const TypesError = types.Error;

pub const http01_store = @import("http01_store.zig");
pub const Http01Store = http01_store.Http01Store;
pub const Http01StoreError = http01_store.Error;
pub const ChallengeView = http01_store.ChallengeView;

pub const client = @import("client.zig");
pub const AcmeUrl = client.Url;
pub const AcmeReplayNonce = client.ReplayNonce;
pub const AcmeDirectory = client.Directory;
pub const AcmeAccountStatus = client.AccountStatus;
pub const AcmeOrderStatus = client.OrderStatus;
pub const AcmeAccountResponse = client.AccountResponse;
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

pub const manager = @import("manager.zig");
pub const AcmeSignedBodies = manager.SignedBodies;
pub const AcmeTickResult = manager.TickResult;
pub const AcmeExecutor = manager.Executor;
pub const AcmeManager = manager.Manager;
pub const AcmeManagerError = manager.Error;

test {
    _ = @import("types.zig");
    _ = @import("http01_store.zig");
    _ = @import("client.zig");
    _ = @import("jws.zig");
    _ = @import("wire.zig");
    _ = @import("orchestration.zig");
    _ = @import("transport.zig");
    _ = @import("manager.zig");
}
