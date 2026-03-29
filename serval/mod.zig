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

/// Re-export of the `serval-core` module namespace for convenient single-import access.
/// This alias performs no runtime work; it simply exposes the core package through `serval.core`.
pub const core = @import("serval-core");

// Types
/// Re-export of `core.types`, the namespace that groups Serval's shared core types.
/// This is a compile-time module alias only and introduces no runtime behavior or ownership semantics.
pub const types = core.types;
/// Re-export of `core.Request`, the zero-copy HTTP request container used throughout Serval.
/// Its fields borrow parser-owned storage, so the backing buffers must remain valid while the request is in use.
pub const Request = core.Request;
/// Re-export of `core.Response`, the HTTP response container used by handlers and server internals.
/// It carries a status code, a header map, and an optional borrowed body slice.
pub const Response = core.Response;
/// Re-export of `core.Upstream`, the destination description used when selecting a backend.
/// `host` is a borrowed slice, and `port`, `idx`, `tls`, and `http_protocol` describe how the server should connect.
pub const Upstream = core.Upstream;
/// Re-export of `core.HttpProtocol`, the application protocol spoken by an upstream.
/// Use `.h1`, `.h2c`, or `.h2` to describe the upstream transport and negotiated protocol.
pub const HttpProtocol = core.HttpProtocol;
/// Re-export of `core.Action`, the hook return type that controls request processing.
/// Use its variants to continue normal handling, send a direct response, reject the request, or stream chunked output.
pub const Action = core.Action;
/// Re-export of `core.Method`, the HTTP request method enum used by parsed requests.
/// It covers the standard request methods supported by Serval's core request types.
pub const Method = core.Method;
/// Re-export of `core.Version`, the HTTP protocol version enum used by parsed requests.
/// It currently distinguishes HTTP/1.0 and HTTP/1.1.
pub const Version = core.Version;
/// Re-export of `core.Header`, the name/value pair stored inside `HeaderMap`.
/// Both fields are borrowed slices and the struct performs no validation or allocation on its own.
pub const Header = core.Header;
/// Re-export of `core.HeaderMap`, the fixed-size HTTP header container with cached lookups for common fields.
/// Header values are borrowed slices and the map owns no heap memory; insertions can fail with header-count or duplicate-content-length errors.
pub const HeaderMap = core.HeaderMap;
/// Re-export of `core.ConnectionInfo`, the fixed-size connection metadata struct used by logging hooks.
/// It carries connection, address, and TCP timing data and does not allocate memory.
pub const ConnectionInfo = core.ConnectionInfo;
/// Connection timing and transport metadata for the `onUpstreamConnect` hook.
/// It records DNS, TCP, TLS, and pool-wait durations, plus whether the connection was reused and which local port was used.
/// TLS cipher and version are fixed-size buffers that are empty when the upstream is plaintext.
pub const UpstreamConnectInfo = core.UpstreamConnectInfo;

// Config
/// Namespace alias exposing the configuration module from `serval-core`.
/// Use it for `Config` and the module-level constants that define default limits and feature flags.
/// This is a compile-time module alias only; it adds no runtime behavior.
pub const config = core.config;
/// Global server configuration with explicit defaults for listener, buffers, TLS, and transport subsystems.
/// String fields are borrowed slices owned by the caller; optional nested configs use `null` to disable features.
/// Use this type to construct the top-level service configuration passed into the server.
pub const Config = core.Config;

// Time utilities
/// Namespace alias exposing the serval-core timing helpers and unit constants.
/// Use it for monotonic durations, realtime timestamps, and explicit nanosecond conversions.
/// The module is stateless and performs no allocation.
pub const time = core.time;

// Errors
/// Namespace alias exposing the typed error sets and `ErrorContext` from `serval-core.errors`.
/// Use it to refer to `ParseError`, `ConnectionError`, `UpstreamError`, `RequestError`, and `ErrorContext` together.
/// This is a compile-time module alias only; it has no runtime behavior.
pub const errors = core.errors;
/// Request parsing errors raised while decoding the incoming HTTP message.
/// It includes malformed request-line, header, URI, and body-framing conditions, plus policy rejections such as missing Host.
/// Use this for failures detected before handler execution or upstream selection begins.
pub const ParseError = core.ParseError;
/// Connection-level errors for backend or transport setup.
/// It covers connect failures, refusals, resets, and timeouts.
/// Treat these as transport failures before any upstream request or response exchange begins.
pub const ConnectionError = core.ConnectionError;
/// Errors reported while talking to an upstream server.
/// It includes send, receive, empty-response, invalid-response, and stale-connection failures.
/// Use this when surfacing backend-specific I/O or protocol errors.
pub const UpstreamError = core.UpstreamError;
/// Combined error set covering parse, connection, and upstream failures.
/// Use this when a failure can originate from request parsing, backend connection setup, or upstream I/O and response handling.
/// The set is a compile-time alias with no runtime cost.
pub const RequestError = core.RequestError;
/// Error details passed to `onError` handlers for request-processing failures.
/// The `err` field is a `RequestError`, `phase` identifies where it occurred, and `upstream` is present when a backend was involved.
/// `is_retry` tells handlers whether the current attempt is a retry or the initial request.
pub const ErrorContext = core.ErrorContext;
/// Structured access-log data emitted after a request completes.
/// It includes timing, request and response byte counts, upstream information, and any error phase or error name.
/// `path` and `error_name` are borrowed views that are only valid during the `onLog` callback.
pub const LogEntry = core.LogEntry;

// Context
/// Namespace alias exposing the request-context API from `serval-core.context`.
/// Use it for `Context`, `BodyReader`, `BodyReadError`, and the lazy body-reading helpers.
/// This is a compile-time module alias only; it adds no runtime behavior.
pub const context = core.context;
/// Per-request state passed to handler hooks for routing, timing, logging, and body access.
/// It carries connection-scoped metadata, per-request counters, optional upstream selection, and an optional body reader.
/// Use `init()` for a fresh request and `reset()` to reuse an instance across requests while preserving connection fields.
pub const Context = core.Context;
/// Lazy request-body reader used by `Context` to read buffered or streamed bodies on demand.
/// The `initial_body` slice points into the server receive buffer and is valid only for the current request.
/// Reads are bounded by the framing mode and caller-provided buffer; chunked bodies are rejected for lazy reads.
pub const BodyReader = core.BodyReader;
/// Error set returned by `Context.readBody()` and `Context.readBodyChunk()`.
/// It covers unavailable body readers, missing server configuration, oversized bodies,
/// unexpected read failures, and chunked bodies where lazy reading is not supported.
pub const BodyReadError = core.BodyReadError;

// Handler hook verification
/// Namespace alias exposing the handler hook helpers from `serval-core.hooks`.
/// Use it to verify required and optional hook signatures at comptime before a handler is accepted.
/// This is a compile-time module alias only; it performs no runtime work.
pub const hooks = core.hooks;
/// Re-export of `core.verifyHandler`, the comptime handler-interface validator.
/// It checks that `selectUpstream` exists and that optional hooks, when present, match the expected signatures.
/// Signature mismatches are reported as compile errors before the build succeeds.
pub const verifyHandler = core.verifyHandler;
/// Re-export of `core.hasHook`, the comptime helper that checks whether a handler declares a named hook.
/// It returns `true` when `@hasDecl(Handler, name)` succeeds and `false` otherwise.
/// This helper performs no runtime work and does not validate hook signatures.
pub const hasHook = core.hasHook;

// =============================================================================
// Network Utilities (from serval-net)
// =============================================================================

/// Namespace re-export for `serval-net`.
/// Use this module for TCP socket configuration helpers and DNS utilities.
/// The import is compile-time only and has no runtime side effects.
pub const net = @import("serval-net");
/// Re-export of `net.set_tcp_no_delay`, the TCP_NODELAY helper.
/// It returns `true` when the socket option is applied successfully and `false` when the system call fails.
/// A sentinel file descriptor of `-1` is treated as a no-op success by the underlying helper.
pub const set_tcp_no_delay = net.set_tcp_no_delay;

// =============================================================================
// Socket Abstraction (from serval-socket)
// =============================================================================

/// Namespace re-export for `serval-socket`.
/// Use this module for the unified socket abstraction and socket-layer errors.
/// The import is compile-time only and does not allocate or open connections.
pub const socket = @import("serval-socket");
/// Re-export of `socket.Socket`, the unified plain-TCP and TLS socket type.
/// It is the tagged-union socket abstraction used by higher-level modules.
/// Ownership and lifecycle are defined by `serval-socket`.
pub const Socket = socket.Socket;
/// Re-export of `socket.SocketError`, the error set for socket operations.
/// It is the socket-layer error taxonomy used by `serval-socket`.
/// This alias does not change ownership or lifetime rules.
pub const SocketError = socket.SocketError;

// =============================================================================
// HTTP Parsing (from serval-http)
// =============================================================================

/// Namespace re-export for `serval-http`.
/// Use this module for HTTP/1.1 parser types and response-header parsing helpers.
/// The import is compile-time only and adds no runtime overhead.
pub const http = @import("serval-http");
/// Re-export of `http.Parser`, the zero-allocation HTTP/1.x parser type.
/// Parsed request data remains borrowed from the caller's input buffers until those buffers are reused or dropped.
/// See `serval-http` for parsing behavior and error details.
pub const Parser = http.Parser;

// =============================================================================
// WebSocket Protocol Helpers (from serval-websocket)
// =============================================================================

/// Namespace re-export for `serval-websocket`.
/// Use this module for RFC 6455 handshake, frame, close, and subprotocol helpers.
/// The import is compile-time only and transfers no ownership.
pub const websocket = @import("serval-websocket");
/// Re-export of `websocket.HandshakeError`, the error set for WebSocket handshake validation.
/// It includes invalid methods, missing or malformed headers, unsupported versions, unexpected bodies, and invalid accept values.
/// The set is shared by client request validation and server response validation.
pub const WebSocketHandshakeError = websocket.HandshakeError;
/// Re-export of `websocket.FrameError`, the error set for WebSocket frame header parsing and building.
/// It covers incomplete or oversized headers, unsupported opcodes, reserved-bit violations, masking mismatches, and invalid control frames.
/// Use this error set with the frame helpers in `websocket`.
pub const WebSocketFrameError = websocket.FrameError;
/// Re-export of `websocket.CloseError`, the error set for close-payload validation and encoding.
/// It covers invalid close codes, invalid UTF-8 reasons, oversized control payloads, and too-small output buffers.
/// The alias itself owns no memory and performs no runtime work.
pub const WebSocketCloseError = websocket.CloseError;
/// Re-export of `websocket.SubprotocolError`, the error set for subprotocol parsing and selection.
/// It reports invalid tokens, empty entries, too many tokens, and protocols that were not offered.
/// Use it with the WebSocket subprotocol validation helpers in `websocket`.
pub const WebSocketSubprotocolError = websocket.SubprotocolError;
/// Re-export of `websocket.Opcode`, the WebSocket opcode enum used by frame helpers.
/// It covers the data opcodes and control opcodes recognized by this package.
/// This is a compile-time alias only and introduces no runtime behavior.
pub const WebSocketOpcode = websocket.Opcode;
/// Re-export of `websocket.FrameHeader`, the parsed WebSocket frame metadata type.
/// It carries the frame flags, opcode, masking state, payload length, and optional mask key.
/// Any slices or embedded state are borrowed from caller-owned buffers; this alias adds no ownership.
pub const WebSocketFrameHeader = websocket.FrameHeader;
/// Re-export of `websocket.CloseInfo`.
/// `code` is null when the close payload carried no status code.
/// `reason` borrows the original payload bytes and stays valid only while that payload remains alive.
pub const WebSocketCloseInfo = websocket.CloseInfo;
/// Re-export of `websocket.looksLikeWebSocketUpgradeRequest`.
/// This is a fail-closed heuristic rather than full validation: it checks `GET` plus upgrade-related headers.
/// Use it to route suspicious requests into the handshake validator instead of accepting them early.
pub const looksLikeWebSocketUpgradeRequest = websocket.looksLikeWebSocketUpgradeRequest;
/// Re-export of `websocket.validateClientRequest`.
/// Requires `GET`, no message body, `Connection: Upgrade`, `Upgrade: websocket`, a valid `Sec-WebSocket-Key`, and `Sec-WebSocket-Version: 13`.
/// Returns a handshake error for malformed or unsupported requests; the request remains caller-owned.
pub const validateWebSocketRequest = websocket.validateClientRequest;
/// Re-export of `websocket.computeAcceptKey`.
/// Writes the RFC 6455 `Sec-WebSocket-Accept` value into `out` and returns a slice of that buffer.
/// `client_key` must be a valid WebSocket key; `out` must be large enough for the 28-byte encoded value.
pub const computeWebSocketAcceptKey = websocket.computeAcceptKey;
/// Re-export of `websocket.parseFrameHeader`.
/// Parses header bytes only, up to 14 bytes, and validates masking rules for the given peer role.
/// On success the returned header includes a copied mask key when present; the input slice is borrowed.
pub const parseWebSocketFrameHeader = websocket.parseFrameHeader;
/// Re-export of `websocket.buildFrameHeader`.
/// Serializes an outbound WebSocket frame header into `out` and returns a subslice of that buffer.
/// Returns `null` when `out` is too small or the payload length cannot be encoded.
pub const buildWebSocketFrameHeader = websocket.buildFrameHeader;
/// Re-export of `websocket.applyFrameMask`.
/// XORs the 4-byte mask key across `payload` in place; the operation is its own inverse.
/// No allocation occurs and the slice is modified directly.
pub const applyWebSocketMask = websocket.applyFrameMask;
/// Re-export of `websocket.parseClosePayload`.
/// Parses a close frame payload into an optional code plus a borrowed UTF-8 reason slice.
/// Empty payloads return a null code and an empty reason; one-byte payloads are invalid.
pub const parseWebSocketClosePayload = websocket.parseClosePayload;
/// Re-export of `websocket.buildClosePayload`.
/// Encodes a WebSocket close code and optional UTF-8 reason into `out`, then returns a slice of that buffer.
/// The caller owns `out`; errors include invalid codes, invalid UTF-8, payloads that exceed the control-frame limit, and too-small buffers.
pub const buildWebSocketClosePayload = websocket.buildClosePayload;
/// Re-export of `websocket.validateSubprotocolSelection`.
/// A null selected protocol succeeds immediately; otherwise the chosen token must be valid and present in the offered header value.
/// The input slices are borrowed and no ownership is transferred.
pub const validateWebSocketSubprotocolSelection = websocket.validateSubprotocolSelection;

// =============================================================================
// HTTP/2 / h2c Helpers (from serval-h2)
// =============================================================================

/// Re-export of the `serval-h2` namespace.
/// Use this alias for HTTP/2 frame, HPACK, request parsing, and h2c upgrade helpers.
/// It is a module import only and does not transfer ownership.
pub const h2 = @import("serval-h2");
/// Re-export of `h2.FrameType`.
/// Classifies HTTP/2 frame headers by on-wire type.
/// Use it to branch on DATA, HEADERS, SETTINGS, PING, GOAWAY, and related frame kinds.
pub const H2FrameType = h2.FrameType;
/// Re-export of `h2.FrameHeader`.
/// Stores the wire fields for an HTTP/2 frame header: length, type, flags, and stream identifier.
/// The struct owns no memory and is safe to copy by value.
pub const H2FrameHeader = h2.FrameHeader;
/// Re-export of `h2.FrameError`.
/// Returned by HTTP/2 frame header parsing and encoding when input is incomplete, oversized, or malformed.
/// It covers invalid frame types, reserved-bit violations, and buffer sizing failures.
pub const H2FrameError = h2.FrameError;
/// Re-export of `h2.ErrorCode`.
/// Enumerates the HTTP/2 connection and stream error codes used by control frames.
/// Use it when interpreting GOAWAY and RST_STREAM error values.
pub const H2ErrorCode = h2.ErrorCode;
/// Re-export of `h2.GoAway`.
/// Represents a parsed HTTP/2 GOAWAY payload with the last stream ID, raw error code, and debug data.
/// `debug_data` borrows the original payload slice and remains valid only while that payload is alive.
pub const H2GoAway = h2.GoAway;
/// HPACK header field name and value pair.
/// Both slices are borrowed views; this type does not own or copy the bytes.
/// Callers that need persistent storage must copy the field data themselves.
pub const H2HeaderField = h2.HeaderField;
/// Decoded HTTP/2 request metadata for a single stream.
/// `request` contains the parsed request head and `stream_id` identifies the
/// source stream. Any slices stored inside `request` are borrowed from caller-
/// provided stable storage, not heap-owned.
pub const H2RequestHead = h2.RequestHead;
/// Parsed initial h2c request data plus the consumed byte count.
/// `request` contains the decoded request metadata, `stream_id` identifies the
/// request stream, and `consumed_bytes` records how many input bytes were used
/// when parsing the prior-knowledge bootstrap sequence.
pub const H2InitialRequest = h2.InitialRequest;
/// Parse a 9-byte HTTP/2 frame header from `raw`.
/// Returns `error.NeedMoreData` when fewer than 9 bytes are available and
/// `error.FrameTooLarge` when the advertised length exceeds the configured max.
/// Unknown frame types are mapped to `.extension`, and the reserved stream bit
/// is masked out.
pub const parseH2FrameHeader = h2.parseFrameHeader;
/// Encode a 9-byte HTTP/2 frame header into `out`.
/// `header.stream_id` must fit in 31 bits, and `header.length` must not exceed
/// `config.H2_MAX_FRAME_SIZE_BYTES`. Returns `error.BufferTooSmall` if `out`
/// cannot hold the header.
pub const buildH2FrameHeader = h2.buildFrameHeader;
/// Decode an HPACK header block with a fresh bounded decoder.
/// `out_fields` must be non-empty and large enough for the decoded field count.
/// The returned slice aliases `out_fields`; header names and values may borrow
/// decoder-managed scratch storage, so copy them if you need longer lifetime.
pub const decodeH2HeaderBlock = h2.decodeHeaderBlock;
/// Decode an HTTP/2 request header block into stable request storage.
/// `stream_id` must be non-zero, and `request_storage_out` must be at least
/// `request_stable_storage_size_bytes` bytes so returned request slices remain
/// valid after the call returns.
pub const decodeH2RequestHeaderBlock = h2.decodeRequestHeaderBlock;
/// Encode an HPACK literal header field without indexing.
/// The header name is written in lowercase before encoding, which matches the
/// HTTP/2 header-name rules enforced by the HPACK helpers. Returns `error.BufferTooSmall`
/// if `out` cannot hold the encoded name and value.
pub const encodeH2LiteralHeaderWithoutIndexing = h2.encodeLiteralHeaderWithoutIndexing;
/// Encode an empty SETTINGS frame with the ACK flag set.
/// `out` must be large enough for the 9-byte frame header. The function writes
/// no payload and returns a slice covering the encoded frame bytes.
pub const buildH2SettingsAckFrame = h2.buildSettingsAckFrame;
/// Parse a PING frame payload into the opaque 8-byte data block.
/// `header` must describe a PING frame with stream id `0` and an 8-byte payload.
/// The returned array is a by-value copy, so it does not borrow from `payload`.
pub const parseH2PingFrame = h2.parsePingFrame;
/// Encode a PING frame into `out`.
/// `flags` may contain only `frame.flags_ack`; the frame is always written with
/// stream id `0`. `opaque_data` is copied into the 8-byte payload, and the call
/// fails with `error.BufferTooSmall` if `out` cannot fit the frame.
pub const buildH2PingFrame = h2.buildPingFrame;
/// Parse a WINDOW_UPDATE frame payload into the advertised increment.
/// `header` must describe a WINDOW_UPDATE frame with a 4-byte payload. The
/// reserved bit in the payload is ignored; zero or oversized increments return
/// `error.InvalidIncrement`.
pub const parseH2WindowUpdateFrame = h2.parseWindowUpdateFrame;
/// Encode a WINDOW_UPDATE frame into `out`.
/// `stream_id` may be `0` for a connection-level update or a non-zero stream id.
/// `increment` must be in the range `1..=config.H2_MAX_WINDOW_SIZE_BYTES`, or
/// the function returns `error.InvalidIncrement`.
pub const buildH2WindowUpdateFrame = h2.buildWindowUpdateFrame;
/// Parse a RST_STREAM frame payload into the raw error code.
/// `header` must describe a RST_STREAM frame with a non-zero stream id and a
/// 4-byte payload. Unknown error-code values are preserved as raw `u32` data.
pub const parseH2RstStreamFrame = h2.parseRstStreamFrame;
/// Encode a RST_STREAM frame into `out`.
/// `stream_id` must be non-zero and fit in 31 bits; `error_code_raw` is written
/// verbatim as the 4-byte payload. Returns `error.BufferTooSmall` if `out` cannot
/// hold the frame header plus payload.
pub const buildH2RstStreamFrame = h2.buildRstStreamFrame;
/// Parse a GOAWAY frame payload into a `GoAway` record.
/// `header` must describe a GOAWAY frame with stream id `0` and a payload
/// of at least 8 bytes. The returned `debug_data` slice aliases `payload` and
/// stays valid only while that input buffer remains alive.
pub const parseH2GoAwayFrame = h2.parseGoAwayFrame;
/// Re-export of `h2.buildGoAwayFrame`, which encodes an HTTP/2 GOAWAY frame into caller-provided storage.
/// The frame includes the last stream id, error code, and optional debug data, and the returned slice aliases `out`.
/// It requires a 31-bit `last_stream_id` and returns `error.BufferTooSmall` when the output buffer is insufficient.
pub const buildH2GoAwayFrame = h2.buildGoAwayFrame;
/// Re-export of `h2.parseInitialRequest`, which parses the HTTP/2 client preface and initial request frames.
/// The returned `InitialRequest` borrows storage from `request_storage_out`, so that buffer must remain valid for the request lifetime.
/// It reports `NeedMoreData`, invalid preface or frame state, and storage-capacity failures when parsing cannot complete.
pub const parseInitialH2Request = h2.parseInitialRequest;
/// Re-export of `h2.looksLikeClientConnectionPreface`, which checks for the HTTP/2 client connection preface.
/// It returns `false` for shorter input or any byte mismatch and does not allocate or fail.
/// Use it for prior-knowledge h2 detection before attempting to parse frames.
pub const looksLikeH2ClientPreface = h2.looksLikeClientConnectionPreface;
/// Re-export of `h2.looksLikeUpgradeRequest`, a lightweight heuristic for h2c upgrade detection.
/// It returns `true` when the request carries `HTTP2-Settings`, `Upgrade: h2c`, or a `Connection` token for `http2-settings`.
/// This helper does not fully validate the request and performs no allocation.
pub const looksLikeH2cUpgradeRequest = h2.looksLikeUpgradeRequest;
/// Re-export of `h2.validateUpgradeRequest`, which validates an HTTP/1.1 h2c upgrade request.
/// It checks the request version, `Connection` and `Upgrade` headers, and decodes the `HTTP2-Settings` value into the provided buffer.
/// The returned slice aliases `decoded_settings_out`; errors report invalid headers, unsupported body framing, or malformed settings data.
pub const validateH2cUpgradeRequest = h2.validateUpgradeRequest;
/// Re-export of `h2.buildUpgradeResponse`, which writes the fixed `101 Switching Protocols` h2c response.
/// The returned slice aliases `out`; the function does not allocate or retain caller-owned storage.
/// It returns `error.BufferTooSmall` when the output buffer cannot hold the full response.
pub const buildH2cUpgradeResponse = h2.buildUpgradeResponse;

// =============================================================================
// gRPC Helpers (from serval-grpc)
// =============================================================================

/// Namespace alias for the `serval-grpc` module.
/// Use it to access gRPC wire helpers and request-metadata validation together from a single import.
/// This alias is compile-time only and has no runtime side effects.
pub const grpc = @import("serval-grpc");
/// Re-export of `grpc.MessagePrefix`, the fixed 5-byte gRPC message prefix metadata struct.
/// `compressed` records the wire compression flag and `length_bytes` records the payload length from the prefix.
/// The type is plain data with no allocation, borrowing, or cleanup requirements.
pub const GrpcMessagePrefix = grpc.MessagePrefix;
/// Re-export of `grpc.WireError`, the error set for gRPC message envelope parsing and encoding.
/// It includes `NeedMoreData`, `BufferTooSmall`, `InvalidCompressionFlag`, and `MessageTooLarge`.
/// Use it with the wire helpers in `grpc.wire`; the set does not imply any ownership transfer.
pub const GrpcWireError = grpc.WireError;
/// Re-export of `grpc.MetadataError`, the error set for gRPC request metadata validation.
/// It covers invalid method, content-type, and `te` combinations, plus missing or malformed `grpc-status` values.
/// Use it with request-validation helpers in `grpc.metadata`.
pub const GrpcMetadataError = grpc.MetadataError;
/// Re-export of `grpc.buildMessage`, which encodes a gRPC message envelope into caller-provided storage.
/// The returned slice aliases `out`; the function does not allocate or retain the payload.
/// It fails with `GrpcWireError` when the buffer is too small or the payload exceeds the configured message limit.
pub const buildGrpcMessage = grpc.buildMessage;
/// Re-export of `grpc.parseMessage`, which parses a gRPC message envelope and returns the payload slice.
/// The payload slice aliases the caller's input buffer and remains valid only while that buffer is valid.
/// Truncated input, malformed prefixes, or oversize messages are reported through `GrpcWireError`.
pub const parseGrpcMessage = grpc.parseMessage;
/// Re-export of `grpc.validateRequest`, the compatibility-mode gRPC request validator.
/// It requires a `POST` request with a non-empty path, a gRPC content type, and `te: trailers`.
/// Validation failures are reported with `GrpcMetadataError`; the function does not allocate.
pub const validateGrpcRequest = grpc.validateRequest;

// =============================================================================
// ACME Helpers (from serval-acme)
// =============================================================================

/// Namespace alias for the `serval-acme` module.
/// Use it to access ACME types, state machine helpers, transport primitives, and runtime orchestration in one import.
/// This alias has no runtime cost and introduces no ownership of its own.
pub const acme = @import("serval-acme");
/// Re-export of `acme.CertState`, the explicit ACME certificate lifecycle state enum.
/// Use it to track the manager's current phase without separate in-progress flags or implicit state.
/// The enum is copyable and carries no ownership or allocation behavior.
pub const AcmeCertState = acme.CertState;
/// Re-export of `acme.RuntimeConfig`, the fixed-capacity ACME runtime configuration type.
/// Values are copied into owned buffers during `initFromConfig`; validation errors are reported by that constructor.
/// String slices are not retained by the constructor, so callers should use the accessor methods on the stored config.
pub const AcmeRuntimeConfig = acme.RuntimeConfig;
/// Re-export of `acme.Http01Store` through the `serval` facade.
/// Use this type with ACME HTTP-01 challenge storage and lookup in `serval-acme`.
pub const AcmeHttp01Store = acme.Http01Store;
/// Re-export of `acme.ChallengeView` through the `serval` facade.
/// Use this type with ACME HTTP-01 challenge handling in `serval-acme`.
pub const AcmeChallengeView = acme.ChallengeView;
/// Bounded storage for an ACME URL value.
/// `set()` accepts non-empty `http://` or `https://` URLs without whitespace or line breaks, and `slice()` returns a borrowed view of the stored bytes.
pub const AcmeUrl = acme.AcmeUrl;
/// Stored value for the ACME `Replay-Nonce` header.
/// `set()` copies a validated nonce into fixed-capacity storage, and `slice()` returns a borrowed view of the stored bytes.
pub const AcmeReplayNonce = acme.AcmeReplayNonce;
/// Parsed ACME directory endpoints.
/// Each field stores one of the required service URLs used to fetch a nonce, create an account, or create an order.
pub const AcmeDirectory = acme.AcmeDirectory;
/// ACME account lifecycle state.
/// The enum models the account states exposed by ACME account resources: `valid`, `deactivated`, and `revoked`.
pub const AcmeAccountStatus = acme.AcmeAccountStatus;
/// ACME order lifecycle state.
/// The enum covers the standard order states returned by ACME servers: `pending`, `ready`, `processing`, `valid`, and `invalid`.
pub const AcmeOrderStatus = acme.AcmeOrderStatus;
/// Parsed ACME account resource data.
/// `status` is required; `orders_url` is only meaningful when `has_orders_url` is `true`.
pub const AcmeAccountResponse = acme.AcmeAccountResponse;
/// Outbound ACME new-order request data.
/// Use `init()` for an empty request, `addIdentifier()` to append validated domain names, or `initFromRuntimeConfig()` to populate from ACME runtime settings.
pub const AcmeNewOrderRequest = acme.AcmeNewOrderRequest;
/// Parsed ACME order resource data.
/// The response stores the order status, finalize URL, authorization URLs, and optional certificate URL in bounded in-memory fields.
pub const AcmeOrderResponse = acme.AcmeOrderResponse;
/// Payload for creating a new ACME account request.
/// `contact_email` is a caller-owned slice that must remain valid until the payload is serialized; the boolean flags control the request body fields.
pub const AcmeNewAccountPayload = acme.AcmeNewAccountPayload;
/// Errors returned by ACME client parsing and serialization helpers.
/// This set covers malformed JSON, missing required fields, invalid URLs/nonces/status values, and output or length limits.
pub const AcmeClientError = acme.AcmeClientError;
/// Fixed-capacity storage for a P-256 JWK public key coordinate pair.
/// `setCoordinates()` validates and copies base64url `x` and `y` values into the internal buffers; `xSlice()` and `ySlice()` return borrowed views of that storage.
pub const AcmeJwkP256 = acme.AcmeJwkP256;
/// Parameters for building a protected ACME JWS header with an embedded P-256 JWK.
/// `nonce`, `url`, and `jwk` must point to initialized values that stay alive for the duration of the serialization call.
pub const AcmeProtectedHeaderJwkParams = acme.AcmeProtectedHeaderJwkParams;
/// Parameters for building a protected ACME JWS header with a `kid` reference.
/// `nonce`, `url`, and `kid` must point to initialized values that stay alive for the duration of the serialization call.
pub const AcmeProtectedHeaderKidParams = acme.AcmeProtectedHeaderKidParams;
/// Parameters for serializing a flattened ACME JWS envelope.
/// The fields borrow caller-owned protected-header JSON, payload JSON, and signature bytes; the type itself performs no allocation.
pub const AcmeFlattenedJwsParams = acme.AcmeFlattenedJwsParams;
/// Re-export of `acme.JwsError`, the error set for ACME flattened-JWS serialization and validation.
/// It reports invalid nonce, URL, kid, JWK coordinate, signature, or buffer-size inputs encountered while building protected headers and envelopes.
pub const AcmeJwsError = acme.AcmeJwsError;
/// Re-export of `acme.ParsedUrl`, the bounded parsed form of an absolute ACME URL.
/// It stores copied host and path bytes plus the selected port and TLS flag; `host()` and `path()` return slices into that internal storage.
pub const AcmeParsedUrl = acme.AcmeParsedUrl;
/// Re-export of `acme.WireRequest`, the fixed request envelope used to send ACME wire requests.
/// `body`, `content_type`, and `accept` borrow caller-owned data, while the parsed target URL is stored by value.
pub const AcmeWireRequest = acme.AcmeWireRequest;
/// Re-export of `acme.WireError`, the error set for ACME wire-level URL parsing and header extraction.
/// It covers invalid absolute URLs, bad schemes or hosts, invalid ports, oversized bodies, and missing replay-nonce or location headers.
pub const AcmeWireError = acme.AcmeWireError;
/// Re-export of `acme.ComposeSignedRequestError`, the error set returned when composing a signed ACME request.
/// It combines JWS serialization errors with wire-level URL and request construction failures such as invalid URLs or oversized bodies.
pub const AcmeComposeSignedRequestError = acme.AcmeComposeSignedRequestError;
/// Re-export of `acme.Operation`, the ACME flow operation selector used by request building and response handling.
/// It covers nonce fetches, new account and new order creation, and follow-up account/order/finalize requests.
pub const AcmeOperation = acme.AcmeOperation;
/// Re-export of `acme.Endpoint`, the endpoint selector used by `AcmeFlowContext`.
/// It distinguishes directory endpoints from the stored account, order, and finalize URLs.
pub const AcmeEndpoint = acme.AcmeEndpoint;
/// Re-export of `acme.FlowContext`, the mutable ACME state container used across a certificate flow.
/// It carries the directory, replay nonce, and discovered account/order/finalize URLs, and its setters copy those values into owned fixed storage.
pub const AcmeFlowContext = acme.AcmeFlowContext;
/// Re-export of `acme.ResponseView`, a lightweight borrowed view over an HTTP response.
/// The status code, headers, and body are read-only references; the caller must keep the backing storage alive while it is used.
pub const AcmeResponseView = acme.AcmeResponseView;
/// Re-export of `acme.ParsedBody`, the parsed payload carried by `AcmeHandledResponse`.
/// The union is either empty, an account response, or an order response parsed from the response body.
pub const AcmeParsedBody = acme.AcmeParsedBody;
/// Re-export of `acme.HandledResponse`, the result of processing an ACME HTTP response.
/// It carries the assessment plus an optional parsed payload, or `.none` when no body-level result was produced.
pub const AcmeHandledResponse = acme.AcmeHandledResponse;
/// Re-export of `acme.ResponseOutcome`, the coarse result category returned by ACME response classification.
/// It separates successful responses from retry-with-nonce, retry-with-backoff, and fatal outcomes.
pub const AcmeResponseOutcome = acme.AcmeResponseOutcome;
/// Re-export of `acme.ResponseReason`, the detailed reason attached to an ACME response assessment.
/// Use it to distinguish success, bad-nonce retries, rate limiting, server failures, client failures, and malformed problem documents.
pub const AcmeResponseReason = acme.AcmeResponseReason;
/// Re-export of `acme.ResponseAssessment`, the summary returned by ACME response classification.
/// It records the overall outcome, a reason code, and the HTTP status that was assessed.
pub const AcmeResponseAssessment = acme.AcmeResponseAssessment;
/// Re-export of `acme.ProtocolError`, the combined error set used by ACME response handling and request-building helpers.
/// It includes orchestration state errors, client response parsing errors, and wire-level parsing errors.
pub const AcmeProtocolError = acme.AcmeProtocolError;
/// Re-export of `acme.ErrorClass`, the ACME orchestration error classification enum.
/// Use it to distinguish input failures, protocol failures, and retry-oriented cases when handling `AcmeProtocolError` values.
pub const AcmeErrorClass = acme.AcmeErrorClass;
/// Re-export of `acme.AcmeErrorReason`, the specific reason category used for ACME protocol and input failure classification.
/// It covers missing replay-nonce or location headers, unavailable endpoints, missing signed bodies, invalid responses, oversized responses, invalid inputs, and a generic fallback.
/// Use it with `AcmeErrorAssessment` to distinguish retryable protocol issues from caller-side errors.
pub const AcmeErrorReason = acme.AcmeErrorReason;
/// Re-export of `acme.AcmeErrorAssessment`, the class-and-reason pair returned by `classifyAcmeProtocolError`.
/// The assessment records whether a failure is protocol-level or input-related, along with the specific reason.
/// It is a plain value with no ownership or lifetime requirements.
pub const AcmeErrorAssessment = acme.AcmeErrorAssessment;
/// Re-export of `acme.assessAcmeResponse`, the helper that classifies an HTTP response for a specific ACME operation.
/// It treats expected success statuses as success, 400 `badNonce` responses as a retry with a new nonce, and 429 or 5xx responses as backoff retries.
/// Other 4xx responses are fatal, and malformed problem documents are reported as invalid.
pub const assessAcmeResponse = acme.assessAcmeResponse;
/// Re-export of `acme.classifyAcmeProtocolError`, the helper that maps ACME protocol and input failures to a stable assessment.
/// It groups failures into a class and a reason for use by the manager and diagnostics paths.
/// Unrecognized errors are classified as `.protocol` with reason `.other`.
pub const classifyAcmeProtocolError = acme.classifyAcmeProtocolError;
/// Re-export of `acme.AcmeTransportExecuteParams`, the arguments for executing a prepared ACME wire request.
/// `wire_request` points at the request to send, and the caller provides I/O plus response buffers.
/// `upstream_idx` selects the upstream backend index used for the outgoing request.
pub const AcmeTransportExecuteParams = acme.AcmeTransportExecuteParams;
/// Re-export of `acme.AcmeTransportExecuteOperationParams`, the arguments for executing one ACME orchestration operation.
/// `operation` selects the ACME step, `signed_body` supplies the request body when one is required, and the caller provides I/O plus response buffers.
/// `upstream_idx` selects which upstream backend index to use for the request.
pub const AcmeTransportExecuteOperationParams = acme.AcmeTransportExecuteOperationParams;
/// Re-export of `acme.AcmeTransportExecuteResponse`, the response returned by `executeAcmeWireRequest`.
/// It carries the HTTP status, parsed response headers, and a body slice sourced from the transport buffer.
/// Call `responseView()` when you need to pass the response into orchestration.
pub const AcmeTransportExecuteResponse = acme.AcmeTransportExecuteResponse;
/// Re-export of `acme.AcmeTransportError`, the error set for executing a prepared ACME wire request.
/// It covers client failures plus invalid buffers, oversized or malformed response bodies, and chunked-body parsing errors.
/// The caller must supply writable header and body buffers for response handling.
pub const AcmeTransportError = acme.AcmeTransportError;
/// Re-export of `acme.AcmeTransportExecuteOperationError`, the combined error set for ACME operation execution.
/// It includes transport errors together with orchestration protocol and request-building failures.
/// Use it when a failure can come from request construction, transport I/O, or response classification.
pub const AcmeTransportExecuteOperationError = acme.AcmeTransportExecuteOperationError;
/// Re-export of `acme.executeAcmeWireRequest`, the lower-level transport helper for a prepared ACME wire request.
/// It applies the request headers, executes the client request, and reads the response body into the caller-provided buffers.
/// Errors report client, header, body, and framing failures from the transport path.
pub const executeAcmeWireRequest = acme.executeAcmeWireRequest;
/// Re-export of `acme.executeAcmeOperation`, the high-level ACME transport helper for an orchestration operation.
/// It builds the request from the flow context, sends it through the client, and feeds the response back into ACME orchestration.
/// The call can fail with transport, protocol, or request-construction errors from the underlying ACME layers.
pub const executeAcmeOperation = acme.executeAcmeOperation;
/// Re-export of `acme.AcmeSignedBodies`, the set of precomputed JWS bodies used by manager transitions.
/// `bodyForOperation()` returns the body required for the selected ACME operation and reports `error.MissingSignedBody` when a required body is absent.
/// Operations that fetch a nonce do not require a signed body.
pub const AcmeSignedBodies = acme.AcmeSignedBodies;
/// Re-export of `acme.AcmeTickResult`, the per-tick summary returned by the ACME manager.
/// `transitions_executed` counts how many state transitions ran, `did_work` reports whether any step was performed, and `state` is the manager state on return.
/// The result is a plain value and owns no external resources.
pub const AcmeTickResult = acme.AcmeTickResult;
/// Re-export of `acme.AcmeExecutor`, the callback wrapper used by `AcmeManager` to execute ACME transport operations.
/// Construct it from an opaque context pointer or from a `serval-client.Client`.
/// The wrapped execute function must remain valid for the lifetime of the executor value.
pub const AcmeExecutor = acme.AcmeExecutor;
/// Re-export of `acme.AcmeManager`, the bounded ACME state machine that drives nonce, account, order, and finalize transitions.
/// Use it to advance issuance one step at a time or to run the automated issuance flow with the provided executor and buffers.
/// The manager stores retry state, backoff deadlines, and the last response or error assessment internally.
pub const AcmeManager = acme.AcmeManager;
/// Re-export of `acme.AcmeManagerError`, the error set returned by the ACME manager state machine.
/// It covers invalid transition limits, empty header buffers, empty body buffers, and missing signed bodies.
pub const AcmeManagerError = acme.AcmeManagerError;

// =============================================================================
// Connection Pooling (from serval-pool)
// =============================================================================

/// Compile-time module alias for `serval-pool`.
/// Use this namespace to access pool types and verification helpers without importing the package directly.
pub const pool = @import("serval-pool");
/// Re-export of `pool.Connection`, the pool-managed wrapper around a plain-TCP or TLS socket.
/// Treat an acquired connection as exclusively owned while in use; call `close()` to retire the underlying socket.
/// `get_fd()` asserts that the descriptor is valid, and `isUnusable()` returns true for invalid file descriptors or poll-detected peer/socket errors.
pub const Connection = pool.Connection;
/// Re-export of `pool.NoPool`, the stateless pool implementation that never retains reusable connections.
/// `acquire` always returns `null`, `release` closes the provided connection immediately, and `drain` is a no-op.
/// Use it when callers must establish a fresh upstream connection for every request.
pub const NoPool = pool.NoPool;
/// Re-export of `pool.SimplePool`, the fixed-capacity connection pool implementation.
/// It uses bounded storage, a mutex for internal synchronization, and eviction policies for idle or over-age connections.
/// The type performs no runtime allocation; observability is optional through its metrics callback.
pub const SimplePool = pool.SimplePool;
/// Re-export of `pool.verifyPool`, the comptime contract checker for pool implementations.
/// It requires `acquire`, `release`, and `drain` declarations and fails compilation when any are missing.
/// This helper performs no runtime work and does not validate behavior beyond declaration presence.
pub const verifyPool = pool.verifyPool;

// =============================================================================
// Upstream Forwarding (from serval-proxy)
// =============================================================================

/// Compile-time module alias for `serval-proxy`.
/// Use this namespace to access forwarding types, tunnel helpers, and protocol-specific proxy APIs from a single import.
pub const proxy = @import("serval-proxy");
/// Re-export of `proxy.Forwarder`, the comptime factory for a concrete upstream forwarder type.
/// The generated type validates `Pool` and tracer implementations at comptime and stores caller-owned pool/tracer pointers.
/// Instances also hold an optional upstream TLS context and embedded DNS resolver state; ownership remains with the caller unless a callee explicitly states otherwise.
pub const Forwarder = proxy.Forwarder;
/// Re-export of `proxy.ForwardError`, the error set reported by upstream forwarding operations.
/// It covers connection setup, DNS, request send/response receive, stale pooled connections, size limits, invalid responses, and protocol mismatches.
/// Handle it as a forward-path failure and branch on specific tags when retry or reporting behavior differs.
pub const ForwardError = proxy.ForwardError;
/// Re-export of `proxy.ForwardResult`, the value returned after a successful upstream forward.
/// It records response metadata, connection-reuse state, and per-phase timing fields in nanoseconds.
/// This is a plain value type with no owned resources or cleanup requirements.
pub const ForwardResult = proxy.ForwardResult;

// =============================================================================
// Reverse Proxy Orchestrator (from serval-reverseproxy)
// =============================================================================

/// Compile-time module alias for `serval-reverseproxy`.
/// Use this namespace to access the reverse-proxy IR, validation, and orchestration types without importing the package directly.
pub const reverseproxy = @import("serval-reverseproxy");
/// Re-export of `reverseproxy.CanonicalIr`, the canonical reverse-proxy configuration model consumed by validation and orchestration.
/// It holds borrowed slices for listeners, pools, routes, plugins, chains, and global plugin IDs.
/// The struct is plain data and does not own or free the referenced storage.
pub const ReverseProxyCanonicalIr = reverseproxy.CanonicalIr;
/// Re-export of `reverseproxy.RuntimeSnapshot`, the immutable runtime view built from a validated canonical IR.
/// Its slices reference listener, pool, route, plugin, and chain data that must remain valid for the snapshot lifetime.
/// This alias adds no ownership transfer or cleanup requirements.
pub const ReverseProxyRuntimeSnapshot = reverseproxy.RuntimeSnapshot;
/// Re-export of `reverseproxy.Orchestrator`, the runtime state machine that applies canonical IR updates.
/// It coordinates validation, activation, draining, rollback, and safe-mode transitions for reverse-proxy generations.
/// See `serval-reverseproxy` for the exact transition rules and error set.
pub const ReverseProxyOrchestrator = reverseproxy.Orchestrator;

// =============================================================================
// Filter SDK (from serval-filter-sdk)
// =============================================================================

/// Compile-time module alias for `serval-filter-sdk`.
/// Import this namespace when you need the filter SDK types or verification helpers without importing the package directly.
pub const filter_sdk = @import("serval-filter-sdk");
/// Re-export of `filter_sdk.FilterContext`, the per-request context passed into filter hooks.
/// It carries route, chain, plugin, request, and stream identifiers plus optional observability callbacks.
/// `setTag` and `incrementCounter` require keys within the documented size limits and become no-ops when callbacks are absent.
pub const FilterContext = filter_sdk.FilterContext;
/// Re-export of `filter_sdk.Decision`, the filter hook decision union used to control request processing.
/// Use it to continue filtering, reject the request, or bypass the plugin; this alias adds no new behavior or ownership rules.
pub const FilterDecision = filter_sdk.Decision;
/// Re-export of `filter_sdk.verifyFilter`, the comptime validator for filter types.
/// It checks the supported hook signatures and emits a compile error if `Filter` implements none of them.
/// The check runs at comptime only and does not instantiate or call `Filter`.
pub const verifyFilter = filter_sdk.verifyFilter;

// =============================================================================
// Metrics (from serval-metrics)
// =============================================================================

/// Compile-time module alias for `serval-metrics`.
/// Use this namespace to reach the metrics interface, concrete backends, and verification helpers without importing the package directly.
/// This alias performs no runtime work and adds no ownership or lifetime requirements.
pub const metrics = @import("serval-metrics");
/// Re-export of `metrics.NoopMetrics`, the zero-overhead metrics backend for callers that do not collect metrics.
/// It implements the shared metrics interface but intentionally does no work.
/// Methods never return errors.
pub const NoopMetrics = metrics.NoopMetrics;
/// Re-export of `metrics.PrometheusMetrics`, the atomic Prometheus-compatible metrics backend.
/// It uses fixed counters, gauges, and histogram buckets, with monotonic atomic updates.
/// The type does not allocate or return errors, and upstream latency is intentionally a no-op.
pub const PrometheusMetrics = metrics.PrometheusMetrics;
/// Re-export of `metrics.verifyMetrics`, the comptime validator for metrics backends.
/// It requires `requestStart` and `requestEnd` to exist on `M`, and emits a compile error when either hook is missing.
/// The type is checked at comptime only; `M` is not instantiated or called.
pub const verifyMetrics = metrics.verifyMetrics;

// =============================================================================
// WAF (from serval-waf)
// =============================================================================

/// Compile-time module alias for `serval-waf`.
/// Import this namespace when you need WAF scanner types, helpers, or public decision types without importing the package directly.
/// This alias performs no runtime work and transfers no ownership.
pub const waf = @import("serval-waf");
/// Re-export of `waf.Config`, the runtime configuration for the WAF module.
/// It contains the rule set, enforcement policy, and optional burst-detection tuning.
/// Borrowed slices must outlive the config, and `validate()` should be called before use.
pub const WafConfig = waf.Config;
/// Re-export of `waf.ScannerRule`, the scanner rule definition consumed by the WAF scanner.
/// The rule id and pattern are borrowed slices, so backing storage must remain valid for the rule's lifetime.
/// Constructors in `serval-waf` enforce non-empty identifiers/patterns and a positive score for score-based rules.
pub const WafScannerRule = waf.ScannerRule;
/// Re-export of `waf.InspectionInput`, the normalized request metadata consumed by scanner and behavioral matching.
/// When built from a request, path/query are decoded and host/user-agent are normalized; slice fields remain borrowed.
/// Any borrowed views must not outlive the scratch buffer and connection/request data that produced them.
pub const WafInspectionInput = waf.InspectionInput;
/// Re-export of `waf.Decision`, the mutable outcome returned by WAF evaluation.
/// It captures the chosen action, score/counters, failure state, and matched rule identifiers.
/// Match helpers store borrowed ids, so caller-owned memory must remain valid for any retained references.
pub const WafDecision = waf.Decision;
/// Alias of `waf.DecisionAction`, the WAF decision result enum.
/// Use `.allow`, `.flag`, or `.block` to describe the disposition of a matched request or event.
/// This is a plain enum with no ownership, allocation, or error behavior.
pub const WafDecisionAction = waf.DecisionAction;
/// Alias of `waf.BehavioralSnapshot`, the value-type snapshot used by WAF behavior scoring.
/// It stores bounded counters for request, path, namespace, and miss-reject activity plus a `tracker_degraded` flag.
/// All fields are plain scalars copied by value; no ownership or lifetime management is required.
pub const WafBehavioralSnapshot = waf.BehavioralSnapshot;
/// Alias of `waf.EnforcementMode`, the scanner policy selector.
/// Use `.detect_only` to observe matches without blocking, or `.enforce` to apply blocking decisions.
/// The alias itself has no ownership or error behavior.
pub const WafEnforcementMode = waf.EnforcementMode;
/// Alias of `waf.FailureMode`, the policy for WAF failures.
/// Use `.fail_open` to allow traffic on inspection failure or `.fail_closed` to deny it.
/// This is a pure enum value with no runtime behavior on its own.
pub const WafFailureMode = waf.FailureMode;
/// Alias of `waf.FailureReason`, the reason enum for normalization and inspection failures.
/// Current values cover invalid percent-encoding and normalized-field length overflow.
/// This type carries no ownership, allocation, or lifetime semantics.
pub const WafFailureReason = waf.FailureReason;
/// Alias of `waf.IsMissFn`, the optional `onLog` miss-classification callback used by `ShieldedHandler`.
/// It receives borrowed `Context` and `LogEntry` pointers and returns `true` when the entry should count as a miss.
/// The callback cannot fail and must not retain either pointer.
pub const WafIsMissFn = waf.IsMissFn;
/// Alias of `waf.ShieldedHandler`, the generic WAF wrapper around an inner handler type.
/// It adds the same request inspection, enforcement, and tracker-update behavior documented on the underlying type.
/// Use the `serval-waf` docs for ownership, callback, and error details; this alias adds no new semantics.
pub const ShieldedHandler = waf.ShieldedHandler;
/// Immutable fixed array of baseline scanner rules for common automated scanner fingerprints.
/// It includes static `User-Agent`, path, and query signatures such as `sqlmap`, `/.git/config`, and `xdebug_session_start`.
/// Treat the array as read-only; pass a slice when assigning `Config.rules`.
pub const default_scanner_rules = waf.default_scanner_rules;

// =============================================================================
// Tracing (from serval-tracing)
// =============================================================================

/// Compile-time module alias for `serval-tracing`.
/// Import this namespace to access span handles, the no-op tracer, and tracer validation helpers through `serval.tracing`.
/// The alias has no runtime state and introduces no ownership or error behavior.
pub const tracing = @import("serval-tracing");
/// Alias of `tracing.SpanHandle`, the fixed-size handle used to refer to a span.
/// The handle type is defined in `serval-core` and re-exported here for convenience.
/// This alias adds no allocation, ownership transfer, or runtime behavior.
pub const SpanHandle = tracing.SpanHandle;
/// Alias of `tracing.NoopTracer`, the no-op tracer implementation used by Serval.
/// Its methods ignore their inputs and do not record spans, attributes, or events.
/// The type is infallible and retains no caller-owned data.
pub const NoopTracer = tracing.NoopTracer;
/// Compile-time tracer interface validator re-exported from `tracing.verifyTracer`.
/// Call `comptime verifyTracer(T)` to ensure `T` declares `startSpan` and `endSpan`; optional attribute methods are checked when present.
/// On mismatch it raises `@compileError`; it performs no runtime work, allocation, or ownership transfer.
pub const verifyTracer = tracing.verifyTracer;

// =============================================================================
// Server (from serval-server)
// =============================================================================

/// Compile-time module alias for `serval-server`.
/// Use this namespace to access HTTP server, WebSocket, and HTTP/2 APIs through `serval.server`.
/// The alias has no runtime state, ownership, or error behavior.
pub const server = @import("serval-server");
/// Alias of `server.Server`, the generic HTTP/1.1 server type from `serval-server`.
/// It is parameterized by the caller-selected handler, pool, metrics, and tracer implementations.
/// Lifecycle, cleanup, and error behavior follow the underlying type; this alias adds no extra semantics.
pub const Server = server.Server;
/// Alias of `server.MinimalServer`, the convenience HTTP/1.1 server variant.
/// It uses the server module's simple pool, no-op metrics, and no-op tracer defaults for a lower-overhead setup.
/// All behavior, lifetime, and error semantics are defined by the underlying generic server type.
pub const MinimalServer = server.MinimalServer;
/// Alias of `server.WebSocketRouteAction`, the routing result for WebSocket upgrade requests.
/// Use `.decline` to leave the request untouched, `.accept` to start a session, or `.reject` to return an HTTP rejection.
/// This declaration adds no ownership, allocation, or error behavior beyond the underlying type.
pub const WebSocketRouteAction = server.WebSocketRouteAction;
/// Re-export of `server.WebSocketAccept`, the parameters used to accept a WebSocket upgrade.
/// It carries the selected subprotocol, optional extra headers, message-size and idle-timeout limits, and the auto-pong policy for ping frames.
pub const WebSocketAccept = server.WebSocketAccept;
/// Re-export of `server.WebSocketMessageKind`, the message-classification enum for WebSocket payloads.
/// `text` indicates UTF-8 data, while `binary` indicates opaque bytes.
pub const WebSocketMessageKind = server.WebSocketMessageKind;
/// Re-export of `server.WebSocketMessage`, a complete WebSocket message returned by session reads.
/// `payload` borrows the caller-provided assembly buffer, `kind` classifies text versus binary data, and `fragmented` reports whether multiple frames were consumed.
pub const WebSocketMessage = server.WebSocketMessage;
/// Re-export of `server.WebSocketSession`, the server-side WebSocket session type.
/// `init` stores borrowed transport and input state, so those values must remain valid for the session lifetime; session methods return `WebSocketSessionError` on protocol or I/O failure.
pub const WebSocketSession = server.WebSocketSession;
/// Re-export of `server.WebSocketSessionError`, the error set used by WebSocket session operations.
/// It covers protocol violations, invalid UTF-8, message-size limits, transport failures, timeouts, and invalid close information.
pub const WebSocketSessionError = server.WebSocketSessionError;
/// Re-export of `server.WebSocketSessionState`, the lifecycle state of a WebSocket session.
/// `open`, `close_sent`, and `closed` describe whether the session can still process messages or is already finished.
pub const WebSocketSessionState = server.WebSocketSessionState;
/// Re-export of `server.WebSocketSessionStats`, the per-session accounting record.
/// It tracks bytes sent and received, the last close code, and whether the peer has initiated close processing.
pub const WebSocketSessionStats = server.WebSocketSessionStats;
/// Re-export of `server.H2ResponseHeader`, the HTTP/2 response header name/value pair.
/// Both fields are borrowed slices, and the type owns no storage or cleanup responsibilities.
pub const H2ResponseHeader = server.H2ResponseHeader;
/// Re-export of `server.H2ResponseWriter`, the per-stream HTTP/2 response writer.
/// Use it to send headers, data, trailers, and resets against caller-owned connection state; errors follow the server module definition.
pub const H2ResponseWriter = server.H2ResponseWriter;
/// Re-export of `server.H2ServerError`, the error set reported by the HTTP/2 server driver.
/// It covers connection, response, frame, HPACK, and h2c-upgrade failures together with lower-level runtime errors.
pub const H2ServerError = server.H2ServerError;
/// Re-export of `server.servePlainH2Connection`, the plain-file-descriptor HTTP/2 connection driver.
/// It runs the HTTP/2 server loop over a caller-owned descriptor and handler, and reports the same errors as the server module definition.
pub const servePlainH2Connection = server.servePlainH2Connection;

// =============================================================================
// Router (from serval-router)
// =============================================================================

/// Re-export of the `serval-router` package namespace for router types and helpers.
/// This is a compile-time module alias only and has no runtime behavior or ownership implications.
pub const router = @import("serval-router");
/// Re-export of `router.Router`, the content-based router with per-pool load balancing.
/// `init` stores caller-owned route, pool, and host slices, so they must outlive the router; `deinit` stops embedded pool handlers and probers.
pub const Router = router.Router;
/// Re-export of `router.Route`, a single route entry evaluated in first-match order.
/// It combines a route name, host and path match criteria, a backend pool index, and optional prefix stripping.
pub const Route = router.Route;
/// Re-export of `router.PathMatch`, the tagged-union path matcher used in route selection.
/// Exact, exact-path, and prefix variants borrow their pattern slices from caller-owned configuration and do not allocate.
pub const PathMatch = router.PathMatch;
/// Re-export of `router.PoolConfig`, the backend-pool configuration used by `Router`.
/// It stores a pool name, a caller-owned slice of upstreams, and the load balancer config for that pool.
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
