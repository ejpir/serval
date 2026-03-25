// lib/serval/mod.zig
//! Serval - HTTP/1.1 Server Library
//!
//! Complete server library composing all serval modules.
//! TigerStyle: Batteries included, explicit re-exports.
//!
//! ## Facade Pattern
//!
//! This module re-exports types from sub-modules for convenient single-import usage:
//!
//! ```zig
//! const serval = @import("serval");
//! var parser = serval.Parser.init();           // Flat access
//! var parser2 = serval.http.Parser.init();     // Explicit module access
//! ```
//!
//! **Maintenance**: When adding public types to sub-modules, add re-exports here.
//! See ARCHITECTURE.md for full guidelines.

const std = @import("std");

// =============================================================================
// Core Types (from serval-core)
// =============================================================================

pub const core = @import("serval-core");

// Types
pub const types = core.types;
pub const Request = core.Request;
pub const Response = core.Response;
pub const Upstream = core.Upstream;
pub const HttpProtocol = core.HttpProtocol;
pub const Action = core.Action;
pub const Method = core.Method;
pub const Version = core.Version;
pub const Header = core.Header;
pub const HeaderMap = core.HeaderMap;
pub const ConnectionInfo = core.ConnectionInfo;
pub const UpstreamConnectInfo = core.UpstreamConnectInfo;

// Config
pub const config = core.config;
pub const Config = core.Config;

// Time utilities
pub const time = core.time;

// Errors
pub const errors = core.errors;
pub const ParseError = core.ParseError;
pub const ConnectionError = core.ConnectionError;
pub const UpstreamError = core.UpstreamError;
pub const RequestError = core.RequestError;
pub const ErrorContext = core.ErrorContext;
pub const LogEntry = core.LogEntry;

// Context
pub const context = core.context;
pub const Context = core.Context;
pub const BodyReader = core.BodyReader;
pub const BodyReadError = core.BodyReadError;

// Handler hook verification
pub const hooks = core.hooks;
pub const verifyHandler = core.verifyHandler;
pub const hasHook = core.hasHook;

// =============================================================================
// Network Utilities (from serval-net)
// =============================================================================

pub const net = @import("serval-net");
pub const set_tcp_no_delay = net.set_tcp_no_delay;

// =============================================================================
// Socket Abstraction (from serval-socket)
// =============================================================================

pub const socket = @import("serval-socket");
pub const Socket = socket.Socket;
pub const SocketError = socket.SocketError;

// =============================================================================
// HTTP Parsing (from serval-http)
// =============================================================================

pub const http = @import("serval-http");
pub const Parser = http.Parser;

// =============================================================================
// WebSocket Protocol Helpers (from serval-websocket)
// =============================================================================

pub const websocket = @import("serval-websocket");
pub const WebSocketHandshakeError = websocket.HandshakeError;
pub const WebSocketFrameError = websocket.FrameError;
pub const WebSocketCloseError = websocket.CloseError;
pub const WebSocketSubprotocolError = websocket.SubprotocolError;
pub const WebSocketOpcode = websocket.Opcode;
pub const WebSocketFrameHeader = websocket.FrameHeader;
pub const WebSocketCloseInfo = websocket.CloseInfo;
pub const looksLikeWebSocketUpgradeRequest = websocket.looksLikeWebSocketUpgradeRequest;
pub const validateWebSocketRequest = websocket.validateClientRequest;
pub const computeWebSocketAcceptKey = websocket.computeAcceptKey;
pub const parseWebSocketFrameHeader = websocket.parseFrameHeader;
pub const buildWebSocketFrameHeader = websocket.buildFrameHeader;
pub const applyWebSocketMask = websocket.applyFrameMask;
pub const parseWebSocketClosePayload = websocket.parseClosePayload;
pub const buildWebSocketClosePayload = websocket.buildClosePayload;
pub const validateWebSocketSubprotocolSelection = websocket.validateSubprotocolSelection;

// =============================================================================
// HTTP/2 / h2c Helpers (from serval-h2)
// =============================================================================

pub const h2 = @import("serval-h2");
pub const H2FrameType = h2.FrameType;
pub const H2FrameHeader = h2.FrameHeader;
pub const H2FrameError = h2.FrameError;
pub const H2ErrorCode = h2.ErrorCode;
pub const H2GoAway = h2.GoAway;
pub const H2HeaderField = h2.HeaderField;
pub const H2RequestHead = h2.RequestHead;
pub const H2InitialRequest = h2.InitialRequest;
pub const parseH2FrameHeader = h2.parseFrameHeader;
pub const buildH2FrameHeader = h2.buildFrameHeader;
pub const decodeH2HeaderBlock = h2.decodeHeaderBlock;
pub const decodeH2RequestHeaderBlock = h2.decodeRequestHeaderBlock;
pub const encodeH2LiteralHeaderWithoutIndexing = h2.encodeLiteralHeaderWithoutIndexing;
pub const buildH2SettingsAckFrame = h2.buildSettingsAckFrame;
pub const parseH2PingFrame = h2.parsePingFrame;
pub const buildH2PingFrame = h2.buildPingFrame;
pub const parseH2WindowUpdateFrame = h2.parseWindowUpdateFrame;
pub const buildH2WindowUpdateFrame = h2.buildWindowUpdateFrame;
pub const parseH2RstStreamFrame = h2.parseRstStreamFrame;
pub const buildH2RstStreamFrame = h2.buildRstStreamFrame;
pub const parseH2GoAwayFrame = h2.parseGoAwayFrame;
pub const buildH2GoAwayFrame = h2.buildGoAwayFrame;
pub const parseInitialH2Request = h2.parseInitialRequest;
pub const looksLikeH2ClientPreface = h2.looksLikeClientConnectionPreface;
pub const looksLikeH2cUpgradeRequest = h2.looksLikeUpgradeRequest;
pub const validateH2cUpgradeRequest = h2.validateUpgradeRequest;
pub const buildH2cUpgradeResponse = h2.buildUpgradeResponse;

// =============================================================================
// gRPC Helpers (from serval-grpc)
// =============================================================================

pub const grpc = @import("serval-grpc");
pub const GrpcMessagePrefix = grpc.MessagePrefix;
pub const GrpcWireError = grpc.WireError;
pub const GrpcMetadataError = grpc.MetadataError;
pub const buildGrpcMessage = grpc.buildMessage;
pub const parseGrpcMessage = grpc.parseMessage;
pub const validateGrpcRequest = grpc.validateRequest;

// =============================================================================
// ACME Helpers (from serval-acme)
// =============================================================================

pub const acme = @import("serval-acme");
pub const AcmeCertState = acme.CertState;
pub const AcmeRuntimeConfig = acme.RuntimeConfig;
pub const AcmeHttp01Store = acme.Http01Store;
pub const AcmeChallengeView = acme.ChallengeView;
pub const AcmeUrl = acme.AcmeUrl;
pub const AcmeReplayNonce = acme.AcmeReplayNonce;
pub const AcmeDirectory = acme.AcmeDirectory;
pub const AcmeAccountStatus = acme.AcmeAccountStatus;
pub const AcmeOrderStatus = acme.AcmeOrderStatus;
pub const AcmeAccountResponse = acme.AcmeAccountResponse;
pub const AcmeNewOrderRequest = acme.AcmeNewOrderRequest;
pub const AcmeOrderResponse = acme.AcmeOrderResponse;
pub const AcmeNewAccountPayload = acme.AcmeNewAccountPayload;
pub const AcmeClientError = acme.AcmeClientError;
pub const AcmeJwkP256 = acme.AcmeJwkP256;
pub const AcmeProtectedHeaderJwkParams = acme.AcmeProtectedHeaderJwkParams;
pub const AcmeProtectedHeaderKidParams = acme.AcmeProtectedHeaderKidParams;
pub const AcmeFlattenedJwsParams = acme.AcmeFlattenedJwsParams;
pub const AcmeJwsError = acme.AcmeJwsError;
pub const AcmeParsedUrl = acme.AcmeParsedUrl;
pub const AcmeWireRequest = acme.AcmeWireRequest;
pub const AcmeWireError = acme.AcmeWireError;
pub const AcmeComposeSignedRequestError = acme.AcmeComposeSignedRequestError;
pub const AcmeOperation = acme.AcmeOperation;
pub const AcmeEndpoint = acme.AcmeEndpoint;
pub const AcmeFlowContext = acme.AcmeFlowContext;
pub const AcmeResponseView = acme.AcmeResponseView;
pub const AcmeParsedBody = acme.AcmeParsedBody;
pub const AcmeHandledResponse = acme.AcmeHandledResponse;
pub const AcmeResponseOutcome = acme.AcmeResponseOutcome;
pub const AcmeResponseReason = acme.AcmeResponseReason;
pub const AcmeResponseAssessment = acme.AcmeResponseAssessment;
pub const AcmeProtocolError = acme.AcmeProtocolError;
pub const AcmeErrorClass = acme.AcmeErrorClass;
pub const AcmeErrorReason = acme.AcmeErrorReason;
pub const AcmeErrorAssessment = acme.AcmeErrorAssessment;
pub const assessAcmeResponse = acme.assessAcmeResponse;
pub const classifyAcmeProtocolError = acme.classifyAcmeProtocolError;
pub const AcmeTransportExecuteParams = acme.AcmeTransportExecuteParams;
pub const AcmeTransportExecuteOperationParams = acme.AcmeTransportExecuteOperationParams;
pub const AcmeTransportExecuteResponse = acme.AcmeTransportExecuteResponse;
pub const AcmeTransportError = acme.AcmeTransportError;
pub const AcmeTransportExecuteOperationError = acme.AcmeTransportExecuteOperationError;
pub const executeAcmeWireRequest = acme.executeAcmeWireRequest;
pub const executeAcmeOperation = acme.executeAcmeOperation;
pub const AcmeSignedBodies = acme.AcmeSignedBodies;
pub const AcmeTickResult = acme.AcmeTickResult;
pub const AcmeExecutor = acme.AcmeExecutor;
pub const AcmeManager = acme.AcmeManager;
pub const AcmeManagerError = acme.AcmeManagerError;

// =============================================================================
// Connection Pooling (from serval-pool)
// =============================================================================

pub const pool = @import("serval-pool");
pub const Connection = pool.Connection;
pub const NoPool = pool.NoPool;
pub const SimplePool = pool.SimplePool;
pub const verifyPool = pool.verifyPool;

// =============================================================================
// Upstream Forwarding (from serval-proxy)
// =============================================================================

pub const proxy = @import("serval-proxy");
pub const Forwarder = proxy.Forwarder;
pub const ForwardError = proxy.ForwardError;
pub const ForwardResult = proxy.ForwardResult;

// =============================================================================
// Reverse Proxy Orchestrator (from serval-reverseproxy)
// =============================================================================

pub const reverseproxy = @import("serval-reverseproxy");
pub const ReverseProxyCanonicalIr = reverseproxy.CanonicalIr;
pub const ReverseProxyRuntimeSnapshot = reverseproxy.RuntimeSnapshot;
pub const ReverseProxyOrchestrator = reverseproxy.Orchestrator;

// =============================================================================
// Filter SDK (from serval-filter-sdk)
// =============================================================================

pub const filter_sdk = @import("serval-filter-sdk");
pub const FilterContext = filter_sdk.FilterContext;
pub const FilterDecision = filter_sdk.Decision;
pub const verifyFilter = filter_sdk.verifyFilter;

// =============================================================================
// Metrics (from serval-metrics)
// =============================================================================

pub const metrics = @import("serval-metrics");
pub const NoopMetrics = metrics.NoopMetrics;
pub const PrometheusMetrics = metrics.PrometheusMetrics;
pub const verifyMetrics = metrics.verifyMetrics;

// =============================================================================
// WAF (from serval-waf)
// =============================================================================

pub const waf = @import("serval-waf");
pub const WafConfig = waf.Config;
pub const WafScannerRule = waf.ScannerRule;
pub const WafInspectionInput = waf.InspectionInput;
pub const WafDecision = waf.Decision;
pub const WafDecisionAction = waf.DecisionAction;
pub const WafBehavioralSnapshot = waf.BehavioralSnapshot;
pub const WafEnforcementMode = waf.EnforcementMode;
pub const WafFailureMode = waf.FailureMode;
pub const WafFailureReason = waf.FailureReason;
pub const WafIsMissFn = waf.IsMissFn;
pub const ShieldedHandler = waf.ShieldedHandler;
pub const default_scanner_rules = waf.default_scanner_rules;

// =============================================================================
// Tracing (from serval-tracing)
// =============================================================================

pub const tracing = @import("serval-tracing");
pub const SpanHandle = tracing.SpanHandle;
pub const NoopTracer = tracing.NoopTracer;
pub const verifyTracer = tracing.verifyTracer;

// =============================================================================
// Server (from serval-server)
// =============================================================================

pub const server = @import("serval-server");
pub const Server = server.Server;
pub const MinimalServer = server.MinimalServer;
pub const WebSocketRouteAction = server.WebSocketRouteAction;
pub const WebSocketAccept = server.WebSocketAccept;
pub const WebSocketMessageKind = server.WebSocketMessageKind;
pub const WebSocketMessage = server.WebSocketMessage;
pub const WebSocketSession = server.WebSocketSession;
pub const WebSocketSessionError = server.WebSocketSessionError;
pub const WebSocketSessionState = server.WebSocketSessionState;
pub const WebSocketSessionStats = server.WebSocketSessionStats;
pub const H2ResponseHeader = server.H2ResponseHeader;
pub const H2ResponseWriter = server.H2ResponseWriter;
pub const H2ServerError = server.H2ServerError;
pub const servePlainH2Connection = server.servePlainH2Connection;

// =============================================================================
// Router (from serval-router)
// =============================================================================

pub const router = @import("serval-router");
pub const Router = router.Router;
pub const Route = router.Route;
pub const PathMatch = router.PathMatch;
pub const PoolConfig = router.PoolConfig;

// =============================================================================
// Tests
// =============================================================================

test {
    // Import all modules to include their tests
    _ = @import("serval-core");
    _ = @import("serval-net");
    _ = @import("serval-socket");
    _ = @import("serval-http");
    _ = @import("serval-websocket");
    _ = @import("serval-h2");
    _ = @import("serval-grpc");
    _ = @import("serval-acme");
    _ = @import("serval-pool");
    _ = @import("serval-proxy");
    _ = @import("serval-reverseproxy");
    _ = @import("serval-filter-sdk");
    _ = @import("serval-metrics");
    _ = @import("serval-tracing");
    _ = @import("serval-otel");
    _ = @import("serval-waf");
    _ = @import("serval-server");
}
