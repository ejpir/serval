//! Serval H2 - Minimal HTTP/2 / h2c helpers
//!
//! Layer 1 (Protocol).
//! TigerStyle: Bounded parsing, explicit errors, no socket ownership.

/// Re-exports owner-local protocol limits from `limits.zig`.
pub const limits = @import("limits.zig");
/// Maximum frames inspected while parsing the initial prior-knowledge request.
pub const max_initial_parse_frames = limits.max_initial_parse_frames;
/// Maximum CONTINUATION frames accepted while assembling a single header block.
pub const max_continuation_frames = limits.max_continuation_frames;
/// Maximum SETTINGS entries accepted in a single SETTINGS payload.
pub const max_settings_per_frame = limits.max_settings_per_frame;
/// Fixed compile-time frame payload capacity used by current h2 helpers.
pub const frame_payload_capacity_bytes = limits.frame_payload_capacity_bytes;
/// Fixed compile-time header-block storage capacity used by current h2 helpers.
pub const header_block_capacity_bytes = limits.header_block_capacity_bytes;
/// Maximum payload length encodable in the HTTP/2 24-bit frame-length field.
pub const max_frame_payload_size_bytes = frame.max_frame_payload_size_bytes;

/// Namespace for HTTP/2 frame header helpers and related constants.
/// Re-exports the frame types, error set, flags, and encode/parse functions used by the h2 layer.
/// This module contains no socket or connection ownership.
pub const frame = @import("frame.zig");
/// HTTP/2 frame type values recognized by Serval.
/// Parsed unknown numeric values are represented as `.extension` rather than rejected.
/// The enum values match the wire type codes defined by RFC 9113.
pub const FrameType = frame.FrameType;
/// Parsed HTTP/2 frame header fields.
/// `length` is the payload length, `frame_type` is the decoded frame type, `flags` carries the raw flag byte, and `stream_id` is the 31-bit stream identifier.
/// Returned by `parseFrameHeader` and accepted by `buildFrameHeader`.
pub const FrameHeader = frame.FrameHeader;
/// Shared error set for HTTP/2 frame header parsing and encoding.
/// Includes `NeedMoreData`, `InvalidFrameType`, `ReservedBitSet`, `FrameTooLarge`, and `BufferTooSmall`.
pub const FrameError = frame.Error;
/// Parse an HTTP/2 frame header from the first 9 bytes of `raw`.
/// Returns `error.NeedMoreData` if fewer than 9 bytes are available and `error.FrameTooLarge` if the encoded length exceeds the configured maximum.
/// Only the first 9 bytes are inspected; extra bytes are ignored by this helper.
/// Unknown wire values map to `.extension`, and the reserved stream-id bit is cleared in the returned header.
pub const parseFrameHeader = frame.parseFrameHeader;
/// Encode an HTTP/2 frame header into `out`.
/// Returns the encoded 9-byte prefix on success and writes only into the caller-provided buffer.
/// The returned slice aliases `out`.
/// Fails with `error.BufferTooSmall` if `out` is shorter than 9 bytes or `error.FrameTooLarge` if `header.length` exceeds the configured maximum.
/// The caller must provide a `header.stream_id` in the valid 31-bit stream-id range.
pub const buildFrameHeader = frame.buildFrameHeader;
/// Fixed size of an HTTP/2 frame header in bytes.
/// Both `parseFrameHeader` and `buildFrameHeader` use this 9-byte layout.
pub const frame_header_size_bytes = frame.frame_header_size_bytes;
/// HTTP/2 `END_STREAM` flag bit.
/// Marks that the sender will not transmit more body data on the stream in this direction.
pub const flags_end_stream = frame.flags_end_stream;
/// HTTP/2 `ACK` flag bit.
/// Used by acknowledgement-capable control frames such as SETTINGS and PING.
pub const flags_ack = frame.flags_ack;
/// HTTP/2 `END_HEADERS` flag bit.
/// Marks the final frame in a header block, including header fragments continued across CONTINUATION frames.
pub const flags_end_headers = frame.flags_end_headers;
/// HTTP/2 `PADDED` flag bit.
/// Indicates that the frame payload includes a pad-length field and trailing padding bytes.
pub const flags_padded = frame.flags_padded;
/// HTTP/2 `PRIORITY` flag bit.
/// Use this bit with frame types that carry a priority section.
pub const flags_priority = frame.flags_priority;

/// Namespace for HTTP/2 client connection preface helpers.
/// Re-exports the fixed preface bytes plus prefix/full-match checks for prior-knowledge h2 detection.
/// This module does not own any I/O or socket state.
pub const preface = @import("preface.zig");
/// The fixed HTTP/2 client connection preface byte sequence.
/// The value is the exact string `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` and is never modified at runtime.
/// Use this constant when validating a prior-knowledge HTTP/2 client preface.
pub const client_connection_preface = preface.client_connection_preface;
/// Returns `true` when `data` begins with the full HTTP/2 client connection preface.
/// Returns `false` if `data` is shorter than the preface or if any byte differs.
/// This is a pure byte comparison with no allocation or error reporting.
pub const looksLikeClientConnectionPreface = preface.looksLikeClientConnectionPreface;
/// Returns `true` when `data` matches the start of the HTTP/2 client connection preface.
/// If `data` is longer than the preface, only the preface-length prefix is compared.
/// Returns `false` for an empty slice or any mismatch; this helper does not allocate or return errors.
pub const looksLikeClientConnectionPrefacePrefix = preface.looksLikeClientConnectionPrefacePrefix;

/// Imports the HPACK helper module for `serval-h2`.
/// Use this namespace to access HPACK types, errors, encoders, and decoders re-exported by this file.
/// The module is compile-time only and owns no runtime state.
pub const hpack = @import("hpack.zig");
/// Re-export of the HPACK header field representation.
/// Each field carries borrowed `name` and `value` slices; the type does not allocate or copy by itself.
/// Returned slices remain valid only as long as the backing storage used by the decoder remains valid.
pub const HeaderField = hpack.HeaderField;
/// Re-export of the HPACK decoder used by `serval-h2`.
/// Create it with `hpack.Decoder.init()` and configure limits before decoding if needed.
/// The decoder stores its own bounded dynamic-table and scratch buffers; it does not own transport state.
pub const HpackDecoder = hpack.Decoder;
/// Public alias of `hpack.Error` for HPACK encode and decode failures.
/// Includes bounded parsing and encoding errors such as `NeedMoreData`, `BufferTooSmall`, `TooManyHeaders`, `InvalidIndex`, and `InvalidHuffman`.
/// Use this error set when handling any of the HPACK helpers re-exported from `serval-h2`.
pub const HpackError = hpack.Error;
/// Convenience wrapper that decodes an HPACK header block with a fresh `Decoder`.
/// Dynamic-table state does not carry across calls, so use `decodeHeaderBlockWithDecoder` when a peer's indexed references must persist between blocks.
/// The returned fields borrow from the decoder's internal storage when dynamic-table or Huffman decoding is involved, so consume them immediately.
pub const decodeHeaderBlock = hpack.decodeHeaderBlock;
/// Decodes an HPACK header block with a caller-owned `Decoder`.
/// The decoder's dynamic table and Huffman scratch are updated in place, so keep the decoder alive while using any borrowed field data.
/// Returns a prefix of `out_fields`, or an HPACK error such as `NeedMoreData`, `InvalidIndex`, `UnsupportedDynamicTableIndex`, or `InvalidHuffman`.
pub const decodeHeaderBlockWithDecoder = hpack.decodeHeaderBlockWithDecoder;
/// Encodes a literal HPACK header field without indexing into `out`.
/// The header name is lowercased before encoding, and the value is copied as provided.
/// Returns a slice of `out` on success, or `error.BufferTooSmall` if the buffer does not fit the encoded field.
pub const encodeLiteralHeaderWithoutIndexing = hpack.encodeLiteralHeaderWithoutIndexing;
/// Encodes a literal HPACK header field with incremental indexing into `out`.
/// The header name is lowercased before encoding, matching HTTP/2 header-name requirements used by Serval.
/// Returns a slice of `out` on success, or `error.BufferTooSmall` if the buffer does not fit the encoded field.
pub const encodeLiteralHeaderWithIncrementalIndexing = hpack.encodeLiteralHeaderWithIncrementalIndexing;
/// Encodes an HPACK indexed header field using the caller-provided output buffer.
/// `index` must be nonzero; `error.InvalidIndex` is returned for `0`, and `error.BufferTooSmall` is returned if `out` cannot hold the encoded integer.
/// The returned slice aliases `out`.
pub const encodeIndexedHeaderField = hpack.encodeIndexedHeaderField;

/// Re-export of `settings.zig` for HTTP/2 SETTINGS frame types and helpers.
/// This namespace covers SETTINGS parsing, validation, payload encoding, and application logic used by `serval-h2`.
pub const settings = @import("settings.zig");
/// Named HTTP/2 SETTINGS identifiers defined by the protocol.
/// These values are encoded on the wire as `u16` identifiers and are used by `Setting.knownId` and validation helpers.
/// Identifiers that are not listed here are treated as unknown raw values by the parser.
pub const SettingId = settings.SettingId;
/// A raw HTTP/2 SETTINGS entry with a numeric identifier and 32-bit value.
/// Use `knownId()` to map `id` to a typed `SettingId` when the identifier is recognized.
/// The struct stores wire-format fields only and does not allocate or own external resources.
pub const Setting = settings.Setting;
/// In-memory HTTP/2 connection settings.
/// The fields default to the protocol or Serval-configured initial state used when constructing SETTINGS frames.
/// `enable_push` and `enable_connect_protocol` are boolean feature toggles; the remaining fields are size or count limits.
pub const Settings = settings.Settings;
/// Errors returned by SETTINGS parsing, validation, and encoding helpers.
/// These cover frame-shape violations, buffer sizing failures, and invalid setting values.
/// Callers should treat them as protocol or caller-input errors.
pub const SettingsError = settings.Error;
/// Size in bytes of one HTTP/2 SETTINGS entry on the wire.
/// Each entry consists of a 2-byte identifier followed by a 4-byte value.
/// Use this constant when validating payload lengths or advancing fixed-width cursors.
pub const setting_size_bytes = settings.setting_size_bytes;
/// Validate and parse an HTTP/2 SETTINGS frame into `out_settings`.
/// `header` must describe a SETTINGS frame whose length matches `payload.len`.
/// ACK frames return an empty slice; non-empty payloads are decoded through `parseSettingsPayload` and may fail with `SettingsError`.
pub const parseSettingsFrame = settings.parseFrame;
/// Validate the frame-level invariants for an HTTP/2 SETTINGS frame.
/// SETTINGS frames must use stream 0; ACK frames must have an empty payload; non-ACK payloads must be a whole number of 6-byte entries.
/// Returns `SettingsError` when the frame shape or entry count is invalid.
pub const validateSettingsFrame = settings.validateFrame;
/// Parse a SETTINGS payload into `out_settings`.
/// `payload.len` must be a valid SETTINGS payload length, and `out_settings` must have room for every decoded entry.
/// Returns the initialized prefix of `out_settings`, or the corresponding `SettingsError` when the payload is malformed.
pub const parseSettingsPayload = settings.parsePayload;
/// Encode SETTINGS entries into a wire-format payload in network byte order.
/// The returned slice aliases `out` and contains the initialized payload prefix.
/// Each setting is validated before it is written; buffer sizing and validation failures are reported through `SettingsError`.
pub const buildSettingsPayload = settings.buildPayload;
/// Apply a sequence of SETTINGS entries to `target` in order.
/// Each entry is validated before it mutates the current settings state.
/// Returns the first validation error or application error encountered.
pub const applySettings = settings.applySettings;

/// Namespace for HTTP/2 control-frame helpers.
/// Re-exports the parsing and encoding helpers from `control.zig` for use at the `serval-h2` package root.
/// This module contains protocol logic only and does not own socket or connection state.
pub const control = @import("control.zig");
/// Named HTTP/2 error codes used by control frames.
/// The numeric values match the wire-format codes defined by RFC 9113.
/// Use this enum when interpreting `GOAWAY` and `RST_STREAM` error codes.
pub const ErrorCode = control.ErrorCode;
/// Parsed HTTP/2 GOAWAY payload data.
/// `debug_data` borrows from the original frame payload and remains valid only while that payload storage is alive.
/// `errorCode()` maps `error_code_raw` to a typed `ErrorCode` when recognized and returns `null` otherwise.
pub const GoAway = control.GoAway;
/// Errors returned by HTTP/2 control-frame parsing and encoding helpers.
/// This set covers invalid stream IDs, invalid payload lengths, invalid WINDOW_UPDATE increments, and frame-encoding errors from `frame.zig`.
/// Treat these as protocol or caller-input failures rather than transport failures.
pub const ControlError = control.Error;
/// Encode an empty HTTP/2 SETTINGS acknowledgement frame into `out`.
/// The returned slice aliases the caller-provided buffer and contains only the encoded frame bytes.
/// Returns `error.BufferTooSmall` if `out` cannot hold the frame header, along with the frame-encoding errors exposed by `control.zig`.
pub const buildSettingsAckFrame = control.buildSettingsAckFrame;
/// Parse an HTTP/2 PING frame payload into its fixed 8-byte opaque data.
/// `header` must describe a PING frame on stream 0, and `payload.len` must be exactly 8 bytes.
/// Returns `error.InvalidStreamId` or `error.InvalidPayloadLength` when the frame shape is invalid; other frame-level errors come from the control helpers.
pub const parsePingFrame = control.parsePingFrame;
/// Encode a PING control frame into the caller-provided buffer.
/// The frame always uses stream id `0` and copies the 8-byte opaque payload verbatim.
/// Returns `error.BufferTooSmall` if the output buffer cannot hold the full frame; only the ACK flag bit is permitted.
pub const buildPingFrame = control.buildPingFrame;
/// Parse a WINDOW_UPDATE control frame payload from the provided header and bytes.
/// Returns the 31-bit increment value after masking off the reserved bit in the wire encoding.
/// Returns `error.InvalidPayloadLength` when the payload is not 4 bytes long and `error.InvalidIncrement` when the decoded increment is zero or out of range.
pub const parseWindowUpdateFrame = control.parseWindowUpdateFrame;
/// Encode a WINDOW_UPDATE control frame into the caller-provided buffer.
/// The frame may target stream `0` for connection-level updates or a nonzero stream id for stream-level updates.
/// Returns `error.InvalidIncrement` when the increment is zero or exceeds the configured HTTP/2 maximum, and `error.BufferTooSmall` when the output buffer is too short.
pub const buildWindowUpdateFrame = control.buildWindowUpdateFrame;
/// Parse an RST_STREAM control frame payload from the provided header and bytes.
/// Returns the raw 32-bit error code exactly as it appears on the wire.
/// Returns `error.InvalidStreamId` for stream id `0` and `error.InvalidPayloadLength` when the payload is not 4 bytes long.
pub const parseRstStreamFrame = control.parseRstStreamFrame;
/// Encode an RST_STREAM control frame into the caller-provided buffer.
/// The frame uses a nonzero 31-bit stream id and carries the raw 32-bit error code as its payload.
/// Returns `error.BufferTooSmall` if the output buffer cannot hold the full frame.
pub const buildRstStreamFrame = control.buildRstStreamFrame;
/// Parse a GOAWAY control frame payload from the provided header and bytes.
/// The returned `GoAway` borrows `debug_data` directly from the input payload slice.
/// Returns `error.InvalidStreamId` for a nonzero connection stream id and `error.InvalidPayloadLength` when the payload is shorter than the fixed GOAWAY prefix.
pub const parseGoAwayFrame = control.parseGoAwayFrame;
/// Encode a GOAWAY control frame into the caller-provided buffer.
/// Writes the 9-byte frame header plus the fixed GOAWAY payload and any trailing debug data.
/// Returns `error.BufferTooSmall` if the output buffer cannot hold the full frame; `last_stream_id` must fit in the 31-bit HTTP/2 stream-id range.
pub const buildGoAwayFrame = control.buildGoAwayFrame;

/// Imported namespace for HTTP/2 flow-control helpers.
/// Use this module to access the window and connection-level flow-control types re-exported by `serval-h2/mod.zig`.
/// The module owns no runtime state and performs no allocation.
pub const flow_control = @import("flow_control.zig");
/// Error set used by flow-control window helpers.
/// Covers invalid initial sizes, invalid increments, window underflow, and window overflow.
/// Re-exported for callers that need to handle bounded window-accounting failures explicitly.
pub const FlowControlError = flow_control.Error;
/// Fixed-size HTTP/2 flow-control window.
/// Supports initialization, consumption, increment, and direct set operations with bounded accounting.
/// Returns errors when the initial size, increment, or consumption would violate the configured limits.
pub const Window = flow_control.Window;
/// Fixed-capacity connection-level flow-control state.
/// Tracks separate receive and send windows using bounded accounting with explicit overflow and underflow checks.
/// Initialize it with a window size that does not exceed the configured HTTP/2 maximum.
pub const ConnectionFlowControl = flow_control.ConnectionFlowControl;

/// Imported namespace for HTTP/2 stream helpers and types.
/// Use this module to access the stream state machine, table, and related errors re-exported by `serval-h2/mod.zig`.
/// This namespace owns no runtime state and performs no I/O by itself.
pub const stream = @import("stream.zig");
/// Endpoint role used to validate stream-id parity in `StreamTable`.
/// The role determines whether locally or remotely initiated streams must use odd or even ids.
/// Initialize a table with the correct role before opening streams.
pub const StreamRole = stream.Role;
/// Lifecycle state for an HTTP/2 stream.
/// The enum tracks idle, reserved, open, half-closed, and closed states used by `Stream` and `StreamTable`.
/// Transitions are explicit; there is no implicit recovery path.
pub const StreamState = stream.State;
/// HTTP/2 stream record with an id, lifecycle state, and separate send/recv windows.
/// Streams start idle with the configured initial window sizes and zero send-window debt.
/// Mutation happens through the stream helpers; callers must preserve the stream's valid id and state invariants.
pub const H2Stream = stream.Stream;
/// Fixed-capacity table of HTTP/2 streams for one connection role.
/// Stores stream lifecycle, per-stream flow-control state, and active-slot bookkeeping.
/// Methods return borrowed pointers into internal storage; those pointers stay valid only while the table entry remains allocated.
pub const StreamTable = stream.StreamTable;
/// Errors returned by stream lifecycle, table, and flow-control helpers.
/// Includes invalid stream IDs, parity and monotonicity checks, duplicate stream handling, capacity exhaustion, missing streams, and invalid state transitions.
/// This set also includes flow-control errors from bounded window accounting operations.
pub const StreamError = stream.Error;

/// Namespace for parsing the initial HTTP/2 request sequence and request header blocks.
/// Re-exports the request result types, stable-storage sizing constant, and decoding helpers from `request.zig`.
/// This import owns no runtime state and performs no allocation on its own.
pub const request = @import("request.zig");
/// Result of decoding a single request header block.
/// `request` contains the decoded request and `stream_id` identifies the HTTP/2 stream.
/// The request is zero-copy and points into caller-provided stable storage.
pub const RequestHead = request.RequestHead;
/// Result of parsing the initial HTTP/2 request sequence.
/// `request` contains the decoded request, `stream_id` identifies the request stream, and `consumed_bytes` reports the bytes consumed through the end of the request headers.
/// All request slices point into caller-provided stable storage and remain valid only while that storage is intact.
pub const InitialRequest = request.InitialRequest;
/// Errors returned by initial request parsing and HPACK request-header decoding.
/// The set covers preface, frame, HPACK, header-validation, and storage-capacity failures.
/// It also includes errors forwarded from the frame, settings, and HPACK helpers used by the request parser.
pub const InitialRequestError = request.Error;
/// Minimum caller-provided stable storage required to decode one request.
/// The size is currently set to two full header-block budgets: one for copied header names and one for copied header values.
/// This constant owns no storage and is used only to size caller buffers.
pub const request_stable_storage_size_bytes = request.request_stable_storage_size_bytes;
/// Convenience wrapper around `decodeRequestHeaderBlockWithDecoder` that creates a fresh HPACK decoder.
/// Use this when decoder state does not need to be reused across requests.
/// The same bounds apply: `stream_id` must be non-zero, the header block must fit within the configured limit, and stable request storage must be available.
pub const decodeRequestHeaderBlock = request.decodeRequestHeaderBlock;
/// Convenience wrapper around `decodeRequestHeaderBlockWithDecoderAndFieldStorage` that creates a
/// fresh HPACK decoder while still using caller-owned decoded-field scratch.
/// Use this when decoder state does not need to persist but hidden helper-local `HeaderField`
/// storage is still undesirable.
pub const decodeRequestHeaderBlockWithFieldStorage = request.decodeRequestHeaderBlockWithFieldStorage;
/// Decodes an HPACK request header block using a caller-supplied decoder instance.
/// `decoder` must be valid, `stream_id` must be non-zero, and `header_block` must fit within the configured header-block limit.
/// `request_storage_out` must be large enough for stable header and path storage, or the call fails with `error.StableStorageTooSmall`.
/// Header names must already be lowercase and pseudo-headers must satisfy HTTP/2 request rules.
/// Slices stored in the returned request reference `request_storage_out` and remain valid until that storage is overwritten or reused.
pub const decodeRequestHeaderBlockWithDecoder = request.decodeRequestHeaderBlockWithDecoder;
/// Decodes an HPACK request header block using caller-owned decoder state plus caller-owned
/// temporary `HeaderField` storage.
/// Use this variant when the caller wants the bounded decoded-field scratch under explicit owner
/// control instead of relying on helper-local storage.
pub const decodeRequestHeaderBlockWithDecoderAndFieldStorage = request.decodeRequestHeaderBlockWithDecoderAndFieldStorage;
/// Parses the client connection preface and initial HTTP/2 frames for the first request.
/// Returns an `InitialRequest` once the request header block has been fully assembled and decoded.
/// `input` must begin with the HTTP/2 client preface prefix, and the first frame after the preface must be a SETTINGS frame.
/// The returned request uses slices backed by `request_storage_out`; those slices remain valid only while that storage is intact.
/// Incomplete input returns `error.NeedMoreData`, and `consumed_bytes` reports how far parsing advanced.
pub const parseInitialRequest = request.parseInitialRequest;
/// Parses the initial client preface and request sequence using a fresh HPACK decoder plus
/// caller-owned header-block assembly storage and decoded-field scratch.
/// Use this variant when the caller wants explicit control over bounded bootstrap scratch without
/// retaining decoder state between calls.
pub const parseInitialRequestWithStorage = request.parseInitialRequestWithStorage;
/// Parses the client connection preface and initial HTTP/2 frames for the first request using a caller-owned HPACK decoder.
/// Use this variant when the caller wants to keep the large decoder object off a constrained stack.
/// The same input, storage, and lifetime rules as `parseInitialRequest` apply.
pub const parseInitialRequestWithDecoder = request.parseInitialRequestWithDecoder;
/// Parses the initial client preface and request using caller-owned HPACK decoder plus caller-owned
/// HEADERS/CONTINUATION assembly scratch storage.
/// Use this variant when both decoder state and temporary header-block assembly storage need to stay
/// under explicit owner control.
pub const parseInitialRequestWithDecoderAndHeaderStorage = request.parseInitialRequestWithDecoderAndHeaderStorage;
/// Parses the initial client preface and request using caller-owned HPACK decoder, temporary
/// header-block assembly storage, and decoded-field scratch.
/// Use this variant when the caller wants full control over all bounded temporary storage on the
/// bootstrap parse path rather than relying on helper-local `HeaderField[MAX_HEADERS]` storage.
pub const parseInitialRequestWithDecoderAndStorage = request.parseInitialRequestWithDecoderAndStorage;
/// Parses the initial client preface and request into caller-owned output storage.
/// Use this variant on constrained stacks to avoid returning `InitialRequest` by value through nested parser frames.
/// The caller also supplies the temporary HEADERS/CONTINUATION assembly buffer and decoded-field
/// scratch so the bootstrap parse path does not allocate hidden helper storage.
pub const parseInitialRequestWithDecoderInto = request.parseInitialRequestWithDecoderInto;

/// Namespace for HTTP/2 upgrade helpers and the h2c request-to-preface bridge.
/// Re-exports validation, response-building, and prior-knowledge preamble construction helpers from `upgrade.zig`.
/// This import owns no runtime state and performs no I/O on its own.
pub const upgrade = @import("upgrade.zig");
/// Errors reported by HTTP/2 upgrade validation and request-to-preface conversion.
/// This set covers version mismatches, missing or invalid upgrade headers, unsupported body framing, and malformed settings data.
/// It also includes errors forwarded from the frame, settings, and HPACK helpers used by the upgrade path.
pub const H2cUpgradeError = upgrade.Error;
/// Returns `true` when the request has header signals commonly associated with an h2c upgrade.
/// This is a heuristic only; it does not fully validate the request or decode `HTTP2-Settings`.
/// The check succeeds if `HTTP2-Settings` is present, `Upgrade: h2c` is present, or `Connection` contains the `http2-settings` token.
/// `request` must be a valid pointer and its header count must stay within the configured header limit.
pub const looksLikeUpgradeRequest = upgrade.looksLikeUpgradeRequest;
/// Validates an HTTP/1.1 `Upgrade: h2c` request and decodes its `HTTP2-Settings` payload.
/// On success, returns the decoded SETTINGS bytes stored in `decoded_settings_out` and ready for frame parsing.
/// `request` must be HTTP/1.1, `body_framing` must not be chunked, and the request must carry the required upgrade headers.
/// The returned slice aliases `decoded_settings_out`; it remains valid until that buffer is overwritten.
/// Returns errors for missing or invalid headers, duplicate or malformed settings data, and unsupported body framing.
pub const validateUpgradeRequest = upgrade.validateUpgradeRequest;
/// Writes the canonical `101 Switching Protocols` response used for h2c upgrade handling.
/// The bytes are copied into `out` and the returned slice aliases that caller-provided buffer.
/// `out` must be large enough for the full response or the function returns `error.BufferTooSmall`.
/// This function does not allocate and does not retain any caller-owned storage.
pub const buildUpgradeResponse = upgrade.buildUpgradeResponse;
/// Builds an HTTP/2 prior-knowledge preamble from an upgrade request.
/// Writes the client connection preface, a SETTINGS frame, and a HEADERS frame into `out`.
/// `request` must have a non-empty path and `Host` header; `effective_path` overrides `request.path` when provided.
/// `settings_payload` must already be a valid SETTINGS payload that fits within the configured frame-size limit.
/// Returned slices alias `out`; the function does not allocate.
/// Returns errors for missing request data, oversized output, or invalid frame/header construction.
pub const buildPriorKnowledgePreambleFromUpgrade = upgrade.buildPriorKnowledgePreambleFromUpgrade;
/// Builds an HTTP/2 prior-knowledge preamble from an upgrade request using caller-owned temporary
/// HEADERS encoding storage.
pub const buildPriorKnowledgePreambleFromUpgradeWithHeaderStorage = upgrade.buildPriorKnowledgePreambleFromUpgradeWithHeaderStorage;
/// Fixed `101 Switching Protocols` response used for a successful h2c handshake.
/// Contains `Connection: Upgrade` and `Upgrade: h2c` with the terminating CRLF sequence.
/// This constant owns no memory and can be copied directly into an output buffer.
pub const h2c_upgrade_response = upgrade.upgrade_response;

test {
    _ = @import("limits.zig");
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
