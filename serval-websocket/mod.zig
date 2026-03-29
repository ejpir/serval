//! Serval WebSocket Protocol Helpers
//!
//! RFC 6455 handshake validation, frame parsing, close validation,
//! and subprotocol negotiation helpers.
//! TigerStyle: Protocol-only module, no socket ownership.

/// Re-exports the `serval-websocket/handshake.zig` namespace.
/// Use this module for WebSocket handshake validation, accept-key computation, and related constants.
/// The helpers operate on caller-owned request and header data without taking ownership.
pub const handshake = @import("handshake.zig");
/// Re-exports the `serval-websocket/frame.zig` namespace.
/// Use this module for frame header parsing, construction, masking, and opcode utilities.
/// Frame buffers and any I/O remain the caller's responsibility.
pub const frame = @import("frame.zig");
/// Re-exports the `serval-websocket/close.zig` namespace.
/// Use this module for close-code constants, payload encoding, and close validation helpers.
/// The module only provides protocol helpers and does not own any connection state.
pub const close = @import("close.zig");
/// Re-exports the `serval-websocket/subprotocol.zig` namespace.
/// Use this module for subprotocol token validation and selection helpers.
/// No socket or buffer ownership is implied by this alias.
pub const subprotocol = @import("subprotocol.zig");

/// Error set returned by the handshake helpers.
/// Covers invalid methods, missing or malformed headers, unsupported versions, and invalid accept or key values.
/// The set is shared by client request validation, server response validation, and accept-key computation.
pub const HandshakeError = handshake.HandshakeError;
/// RFC 6455 magic GUID appended to `Sec-WebSocket-Key` before hashing.
/// This value is fixed by the protocol and is used by `computeAcceptKey`.
pub const websocket_accept_guid = handshake.websocket_accept_guid;
/// Size in bytes of the decoded WebSocket client nonce.
/// RFC 6455 client keys decode to 16 bytes before the accept key is computed.
pub const websocket_client_nonce_size_bytes = handshake.websocket_client_nonce_size_bytes;
/// Size in bytes of the RFC 6455 `Sec-WebSocket-Accept` value.
/// The accept key is SHA-1 output encoded with standard base64, which yields 28 bytes.
pub const websocket_accept_key_size_bytes = handshake.websocket_accept_key_size_bytes;
/// Returns true when the request appears to be a WebSocket upgrade attempt.
/// This is a fail-closed heuristic, not full validation: it checks `GET` plus upgrade-related headers.
/// Use this to route suspicious requests into the handshake validator instead of accepting them early.
pub const looksLikeWebSocketUpgradeRequest = handshake.looksLikeWebSocketUpgradeRequest;
/// Validates a client WebSocket opening handshake request.
/// Requires `GET`, no message body, `Connection: Upgrade`, `Upgrade: websocket`, a valid `Sec-WebSocket-Key`, and `Sec-WebSocket-Version: 13`.
/// Returns `HandshakeError` for malformed or unsupported inputs; the request and its headers remain owned by the caller.
pub const validateClientRequest = handshake.validateClientRequest;
/// Computes the RFC 6455 `Sec-WebSocket-Accept` value for a validated client key.
/// Writes the encoded result into `out` and returns a slice pointing at that buffer.
/// `client_key` must be a valid WebSocket key; `out` must be large enough for `websocket_accept_key_size_bytes`.
pub const computeAcceptKey = handshake.computeAcceptKey;
/// Validates an upstream WebSocket switching-protocols response.
/// Returns `error.InvalidStatusCode` unless `status` is `101`, and checks `Connection`, `Upgrade`, and `Sec-WebSocket-Accept`.
/// `expected_accept_key` must be the 28-byte base64 accept value produced for the client nonce; no ownership is transferred.
pub const validateServerResponse = handshake.validateServerResponse;
/// Returns true when a comma-separated header value contains `token`.
/// Comparison is case-insensitive and trims surrounding ASCII spaces and tabs on each item.
/// `token` must be non-empty. The scan is bounded to avoid untrusted header values causing unbounded work.
pub const headerHasToken = handshake.headerHasToken;
/// Returns the first matching header value from a raw HTTP/1.1 header block.
/// The search skips the status line, stops at the first empty line, and returns a trimmed slice into `raw_headers` or `null` when the header is absent.
/// No allocation is performed.
pub const getHeaderValue = handshake.getHeaderValue;

/// Identifies the peer role used when validating frame masking rules.
/// Client peers are expected to receive masked frames; server peers are expected to receive unmasked frames.
pub const PeerRole = frame.PeerRole;
/// WebSocket opcodes recognized by the frame helpers.
/// Includes continuation, text, binary, close, ping, and pong.
pub const Opcode = frame.Opcode;
/// Parsed WebSocket frame metadata.
/// `header_len_bytes` records the header size, `mask_key` is present only for masked frames, and `isControl()` reports control opcodes.
pub const FrameHeader = frame.Header;
/// Input used to serialize a WebSocket frame header.
/// `fin` defaults to `true`; set `mask_key` when the outbound frame must be masked.
/// `payload_len` must be representable by the frame encoder.
pub const OutboundFrameHeader = frame.OutboundHeader;
/// Errors returned while parsing or building WebSocket frame headers.
/// Covers incomplete headers, unsupported opcodes, invalid masking rules, reserved-bit violations, invalid lengths, invalid control frames, and headers larger than 14 bytes.
pub const FrameError = frame.FrameError;
/// Maximum size, in bytes, of a serialized WebSocket frame header.
/// This includes the optional extended length and masking key fields.
pub const max_frame_header_size_bytes = frame.max_header_size_bytes;
/// Parses a WebSocket frame header from `input` for the given peer role.
/// `input` must contain header bytes only, up to 14 bytes; the function rejects incomplete, oversized, masked, or unmasked headers as appropriate.
/// On success the returned `Header` contains the parsed metadata and, when masked, a copied 4-byte mask key.
pub const parseFrameHeader = frame.parseHeader;
/// Serializes an outbound frame header into `out`.
/// Returns a subslice of `out` on success or `null` if the buffer is too small or the payload length is not representable.
/// The returned slice aliases the caller-owned buffer.
pub const buildFrameHeader = frame.buildHeader;
/// Applies the WebSocket masking XOR in place over `payload`.
/// The mask key must be 4 bytes long; the slice is mutated directly and no allocation occurs.
pub const applyFrameMask = frame.applyMask;
/// Returns true for control opcodes: close, ping, and pong.
/// This is a pure opcode check and does not validate a full frame header.
pub const isControlOpcode = frame.isControlOpcode;

/// Parsed WebSocket close information.
/// `code` is null for an empty payload; otherwise it contains the close code.
/// `reason` is a borrowed UTF-8 slice that points into the parsed payload or caller buffer.
pub const CloseInfo = close.CloseInfo;
/// Errors returned by close-code validation and close payload parsing/building.
/// Covers invalid codes, invalid UTF-8 reasons, oversized control payloads, and too-small output buffers.
pub const CloseError = close.CloseError;
/// RFC 6455 close code 1000, "normal closure".
/// Use this for a clean shutdown where no protocol error occurred.
pub const close_normal_closure = close.normal_closure;
/// RFC 6455 close code 1001, "going away".
/// Use this when the endpoint is shutting down or otherwise leaving the connection intentionally.
pub const close_going_away = close.going_away;
/// RFC 6455 close code 1002, "protocol error".
/// Use this when the peer violates framing or handshake rules and the connection must be closed.
pub const close_protocol_error = close.protocol_error;
/// Re-export of `close.unsupported_data`.
/// WebSocket close code `1003` for unsupported data.
pub const close_unsupported_data = close.unsupported_data;
/// Re-export of `close.invalid_frame_payload_data`.
/// WebSocket close code `1007` for invalid frame payload data.
pub const close_invalid_frame_payload_data = close.invalid_frame_payload_data;
/// Re-export of `close.policy_violation`.
/// WebSocket close code `1008` for policy violation.
pub const close_policy_violation = close.policy_violation;
/// Re-export of `close.message_too_big`.
/// WebSocket close code `1009` for message too big.
pub const close_message_too_big = close.message_too_big;
/// Re-export of `close.mandatory_extension`.
/// WebSocket close code `1010` for mandatory extension.
pub const close_mandatory_extension = close.mandatory_extension;
/// Re-export of `close.service_restart`.
/// WebSocket close code `1012` for service restart.
pub const close_service_restart = close.service_restart;
/// Re-export of `close.try_again_later`.
/// WebSocket close code `1013` for try again later.
pub const close_try_again_later = close.try_again_later;
/// Re-export of `close.bad_gateway`.
/// WebSocket close code `1014` for bad gateway.
pub const close_bad_gateway = close.bad_gateway;
/// Re-export of `close.validateCloseCode`.
/// Accepts standard close codes and private-use codes in the 3000-4999 range.
/// Rejects reserved or otherwise invalid codes with `error.InvalidCloseCode`.
pub const validateCloseCode = close.validateCloseCode;
/// Re-export of `close.parseClosePayload`.
/// Parses a close frame payload into an optional code plus a borrowed UTF-8 reason slice.
/// Empty payloads return `.code = null` and `.reason = ""`; one-byte payloads are invalid. Errors include `error.InvalidClosePayload`, `error.InvalidCloseCode`, `error.InvalidCloseReason`, and `error.PayloadTooLarge`.
pub const parseClosePayload = close.parseClosePayload;
/// Re-export of `close.buildClosePayload`.
/// Encodes a WebSocket close code and optional UTF-8 reason into `out` and returns a slice of that buffer.
/// The caller owns `out`; the returned slice borrows it and no allocation occurs. Errors include `error.InvalidCloseCode`, `error.InvalidCloseReason`, `error.PayloadTooLarge`, and `error.BufferTooSmall`.
pub const buildClosePayload = close.buildClosePayload;

/// Re-export of `subprotocol.SubprotocolError`.
/// This error set covers invalid tokens, empty entries, too many tokens, and a selected protocol that was not offered.
/// Use it with the subprotocol helpers in this module.
pub const SubprotocolError = subprotocol.SubprotocolError;
/// Re-export of `subprotocol.validateHeaderValue`.
/// Validates a comma-separated `Sec-WebSocket-Protocol` header value with trimmed tokens.
/// Returns `error.EmptyToken`, `error.InvalidToken`, or `error.TooManyTokens` for malformed values; the input slice is borrowed.
pub const validateSubprotocolHeaderValue = subprotocol.validateHeaderValue;
/// Re-export of `subprotocol.headerOffersProtocol`.
/// Returns whether `value` contains `protocol` as an exact comma-separated token after trimming ASCII spaces and tabs.
/// Comparison is case-sensitive, `protocol` must be non-empty, and at most 64 tokens are examined.
pub const headerOffersSubprotocol = subprotocol.headerOffersProtocol;
/// Re-export of `subprotocol.validateSelection`.
/// A null `selected_protocol` is accepted and returns success without further checks.
/// Otherwise, the selected token must be valid and appear in `offered_header_value`, or the helper returns `error.InvalidToken` or `error.ProtocolNotOffered`.
pub const validateSubprotocolSelection = subprotocol.validateSelection;
/// Re-export of `subprotocol.isToken`.
/// Returns `true` for non-empty WebSocket token bytes made only of the allowed RFC 6455 token characters.
/// This helper does not allocate and only inspects the provided slice.
pub const isSubprotocolToken = subprotocol.isToken;

test {
    _ = @import("handshake.zig");
    _ = @import("frame.zig");
    _ = @import("close.zig");
    _ = @import("subprotocol.zig");
}
