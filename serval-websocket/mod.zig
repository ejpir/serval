//! Serval WebSocket Protocol Helpers
//!
//! RFC 6455 handshake validation, frame parsing, close validation,
//! and subprotocol negotiation helpers.
//! TigerStyle: Protocol-only module, no socket ownership.

pub const handshake = @import("handshake.zig");
pub const frame = @import("frame.zig");
pub const close = @import("close.zig");
pub const subprotocol = @import("subprotocol.zig");

pub const HandshakeError = handshake.HandshakeError;
pub const websocket_accept_guid = handshake.websocket_accept_guid;
pub const websocket_client_nonce_size_bytes = handshake.websocket_client_nonce_size_bytes;
pub const websocket_accept_key_size_bytes = handshake.websocket_accept_key_size_bytes;
pub const looksLikeWebSocketUpgradeRequest = handshake.looksLikeWebSocketUpgradeRequest;
pub const validateClientRequest = handshake.validateClientRequest;
pub const computeAcceptKey = handshake.computeAcceptKey;
pub const validateServerResponse = handshake.validateServerResponse;
pub const headerHasToken = handshake.headerHasToken;
pub const getHeaderValue = handshake.getHeaderValue;

pub const PeerRole = frame.PeerRole;
pub const Opcode = frame.Opcode;
pub const FrameHeader = frame.Header;
pub const OutboundFrameHeader = frame.OutboundHeader;
pub const FrameError = frame.FrameError;
pub const max_frame_header_size_bytes = frame.max_header_size_bytes;
pub const parseFrameHeader = frame.parseHeader;
pub const buildFrameHeader = frame.buildHeader;
pub const applyFrameMask = frame.applyMask;
pub const isControlOpcode = frame.isControlOpcode;

pub const CloseInfo = close.CloseInfo;
pub const CloseError = close.CloseError;
pub const close_normal_closure = close.normal_closure;
pub const close_going_away = close.going_away;
pub const close_protocol_error = close.protocol_error;
pub const close_unsupported_data = close.unsupported_data;
pub const close_invalid_frame_payload_data = close.invalid_frame_payload_data;
pub const close_policy_violation = close.policy_violation;
pub const close_message_too_big = close.message_too_big;
pub const close_mandatory_extension = close.mandatory_extension;
pub const close_internal_error = close.internal_error;
pub const close_service_restart = close.service_restart;
pub const close_try_again_later = close.try_again_later;
pub const close_bad_gateway = close.bad_gateway;
pub const validateCloseCode = close.validateCloseCode;
pub const parseClosePayload = close.parseClosePayload;
pub const buildClosePayload = close.buildClosePayload;

pub const SubprotocolError = subprotocol.SubprotocolError;
pub const validateSubprotocolHeaderValue = subprotocol.validateHeaderValue;
pub const headerOffersSubprotocol = subprotocol.headerOffersProtocol;
pub const validateSubprotocolSelection = subprotocol.validateSelection;
pub const isSubprotocolToken = subprotocol.isToken;

test {
    _ = @import("handshake.zig");
    _ = @import("frame.zig");
    _ = @import("close.zig");
    _ = @import("subprotocol.zig");
}
