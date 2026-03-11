//! Serval H2 - Minimal HTTP/2 / h2c helpers
//!
//! Layer 1 (Protocol).
//! TigerStyle: Bounded parsing, explicit errors, no socket ownership.

pub const frame = @import("frame.zig");
pub const FrameType = frame.FrameType;
pub const FrameHeader = frame.FrameHeader;
pub const FrameError = frame.Error;
pub const parseFrameHeader = frame.parseFrameHeader;
pub const buildFrameHeader = frame.buildFrameHeader;
pub const frame_header_size_bytes = frame.frame_header_size_bytes;
pub const flags_end_stream = frame.flags_end_stream;
pub const flags_ack = frame.flags_ack;
pub const flags_end_headers = frame.flags_end_headers;
pub const flags_padded = frame.flags_padded;
pub const flags_priority = frame.flags_priority;

pub const preface = @import("preface.zig");
pub const client_connection_preface = preface.client_connection_preface;
pub const looksLikeClientConnectionPreface = preface.looksLikeClientConnectionPreface;
pub const looksLikeClientConnectionPrefacePrefix = preface.looksLikeClientConnectionPrefacePrefix;

pub const hpack = @import("hpack.zig");
pub const HeaderField = hpack.HeaderField;
pub const HpackDecoder = hpack.Decoder;
pub const HpackError = hpack.Error;
pub const decodeHeaderBlock = hpack.decodeHeaderBlock;
pub const decodeHeaderBlockWithDecoder = hpack.decodeHeaderBlockWithDecoder;
pub const encodeLiteralHeaderWithoutIndexing = hpack.encodeLiteralHeaderWithoutIndexing;
pub const encodeLiteralHeaderWithIncrementalIndexing = hpack.encodeLiteralHeaderWithIncrementalIndexing;
pub const encodeIndexedHeaderField = hpack.encodeIndexedHeaderField;

pub const settings = @import("settings.zig");
pub const SettingId = settings.SettingId;
pub const Setting = settings.Setting;
pub const Settings = settings.Settings;
pub const SettingsError = settings.Error;
pub const setting_size_bytes = settings.setting_size_bytes;
pub const parseSettingsFrame = settings.parseFrame;
pub const validateSettingsFrame = settings.validateFrame;
pub const parseSettingsPayload = settings.parsePayload;
pub const buildSettingsPayload = settings.buildPayload;
pub const applySettings = settings.applySettings;

pub const control = @import("control.zig");
pub const ErrorCode = control.ErrorCode;
pub const GoAway = control.GoAway;
pub const ControlError = control.Error;
pub const buildSettingsAckFrame = control.buildSettingsAckFrame;
pub const parsePingFrame = control.parsePingFrame;
pub const buildPingFrame = control.buildPingFrame;
pub const parseWindowUpdateFrame = control.parseWindowUpdateFrame;
pub const buildWindowUpdateFrame = control.buildWindowUpdateFrame;
pub const parseRstStreamFrame = control.parseRstStreamFrame;
pub const buildRstStreamFrame = control.buildRstStreamFrame;
pub const parseGoAwayFrame = control.parseGoAwayFrame;
pub const buildGoAwayFrame = control.buildGoAwayFrame;

pub const flow_control = @import("flow_control.zig");
pub const FlowControlError = flow_control.Error;
pub const Window = flow_control.Window;
pub const ConnectionFlowControl = flow_control.ConnectionFlowControl;

pub const stream = @import("stream.zig");
pub const StreamRole = stream.Role;
pub const StreamState = stream.State;
pub const H2Stream = stream.Stream;
pub const StreamTable = stream.StreamTable;
pub const StreamError = stream.Error;

pub const request = @import("request.zig");
pub const RequestHead = request.RequestHead;
pub const InitialRequest = request.InitialRequest;
pub const InitialRequestError = request.Error;
pub const decodeRequestHeaderBlock = request.decodeRequestHeaderBlock;
pub const decodeRequestHeaderBlockWithDecoder = request.decodeRequestHeaderBlockWithDecoder;
pub const parseInitialRequest = request.parseInitialRequest;

pub const upgrade = @import("upgrade.zig");
pub const H2cUpgradeError = upgrade.Error;
pub const looksLikeUpgradeRequest = upgrade.looksLikeUpgradeRequest;
pub const validateUpgradeRequest = upgrade.validateUpgradeRequest;
pub const buildUpgradeResponse = upgrade.buildUpgradeResponse;
pub const buildPriorKnowledgePreambleFromUpgrade = upgrade.buildPriorKnowledgePreambleFromUpgrade;
pub const h2c_upgrade_response = upgrade.upgrade_response;

test {
    _ = @import("frame.zig");
    _ = @import("preface.zig");
    _ = @import("hpack.zig");
    _ = @import("huffman.zig");
    _ = @import("settings.zig");
    _ = @import("control.zig");
    _ = @import("flow_control.zig");
    _ = @import("stream.zig");
    _ = @import("request.zig");
    _ = @import("upgrade.zig");
}
