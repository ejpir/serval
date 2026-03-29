//! Serval gRPC - Minimal gRPC protocol helpers
//!
//! Layer 2 (Infrastructure).
//! TigerStyle: Explicit wire validation, no transport ownership.

/// Imports the `wire.zig` module for the gRPC wire helpers namespace.
/// This is the source of the public frame parsing and building APIs re-exported by `serval-grpc`.
/// The binding is a module handle, not a runtime value.
pub const wire = @import("wire.zig");
/// Re-exports the parsed gRPC frame view type from `wire.zig`.
/// The frame view borrows its payload slice from the source buffer and does not copy data.
/// Keep the backing bytes alive for as long as the view is used.
pub const MessagePrefix = wire.MessagePrefix;
/// Re-exports the decoded 5-byte gRPC message prefix type from `wire.zig`.
/// Use this alias when you need the parsed compression flag and payload length.
/// The type is a plain value and carries no ownership.
pub const FrameView = wire.FrameView;
/// Re-exports `wire.Error` as the gRPC wire error set.
/// Covers incomplete input, invalid compression flags, oversized messages, and output-buffer limits.
/// Use this alias for error handling around gRPC prefix, frame, and message helpers.
pub const WireError = wire.Error;
/// Re-exports `wire.parsePrefix` for gRPC wire parsing.
/// Decodes the fixed 5-byte prefix consisting of the compression flag and big-endian payload length.
/// Returns `error.NeedMoreData`, `error.InvalidCompressionFlag`, or `error.MessageTooLarge` on invalid input.
pub const parsePrefix = wire.parsePrefix;
/// Re-exports `wire.frameLengthBytes` for gRPC frame sizing.
/// Validates the frame prefix and returns the total frame length in bytes, including the 5-byte prefix.
/// Returns the same errors as `parsePrefix` when the prefix is incomplete or invalid.
pub const frameLengthBytes = wire.frameLengthBytes;
/// Re-exports `wire.parseFrame` for gRPC frame parsing.
/// Parses a complete frame and returns a borrowed `FrameView` with prefix metadata and payload slice.
/// Returns `error.NeedMoreData` for truncated input and the prefix errors reported by `parsePrefix` for invalid input.
pub const parseFrame = wire.parseFrame;
/// Re-exports `wire.nextFrame` for iterating gRPC frames in a byte buffer.
/// Parses the next frame at `cursor_bytes` and advances the cursor by the full frame size on success.
/// Returns `null` when the cursor is already at the end of `raw`; the returned frame view borrows from `raw`.
pub const nextFrame = wire.nextFrame;
/// Re-exports `wire.buildMessage` for gRPC message encoding.
/// Writes the 5-byte gRPC prefix and payload into `out`, then returns the written prefix of `out`.
/// Returns `error.MessageTooLarge` or `error.BufferTooSmall` when the payload or destination buffer is invalid.
pub const buildMessage = wire.buildMessage;
/// Re-exports `wire.parseMessage` for gRPC message parsing.
/// Parses a complete gRPC frame and returns the message payload slice only.
/// The returned slice borrows from `raw` and is valid only while `raw` remains valid.
pub const parseMessage = wire.parseMessage;

/// Imports the `metadata.zig` module into the public gRPC surface.
/// This module provides request validation, classification, and `grpc-status` parsing helpers.
/// The imported module itself has no ownership or runtime cost.
pub const metadata = @import("metadata.zig");
/// Re-exports `metadata.Error` as the gRPC metadata error set.
/// Includes validation failures for method, path, content type, `te`, and `grpc-status` parsing.
/// Use this alias when handling errors from the metadata helpers in this module.
pub const MetadataError = metadata.Error;
/// Re-exports `metadata.RequestClass` for request classification results.
/// The values distinguish non-gRPC requests, valid gRPC requests, and gRPC-like requests that failed validation.
/// This type carries no ownership and is returned by `classifyRequest`.
pub const RequestClass = metadata.RequestClass;
/// Re-exports `metadata.isGrpcContentType` for gRPC metadata validation.
/// Returns `true` when a value starts with `application/grpc` and is either exact or followed by `+` or `;`.
/// The check is case-insensitive for the base media type prefix.
pub const isGrpcContentType = metadata.isGrpcContentType;
/// Re-exports `metadata.validateRequest` for compatibility-mode gRPC request validation.
/// Requires a POST request with a non-empty path, a valid `content-type`, and a `te` header matching `trailers` case-insensitively.
/// Returns `metadata.Error` values for the first violated requirement.
pub const validateRequest = metadata.validateRequest;
/// Re-exports `metadata.validateRequestStrict` for strict gRPC request validation.
/// Requires a POST request with a non-empty path, a valid `content-type`, and an exact `te: trailers` header.
/// Returns `metadata.Error` values for the first violated requirement.
pub const validateRequestStrict = metadata.validateRequestStrict;
/// Re-exports `metadata.classifyRequest` for gRPC request classification.
/// Classifies a request as non-gRPC, valid gRPC, or gRPC-like but invalid.
/// A request is treated as `invalid_grpc_like` when validation fails after gRPC headers are present.
pub const classifyRequest = metadata.classifyRequest;
/// Re-exports `metadata.parseGrpcStatus` for gRPC metadata validation.
/// Reads the `grpc-status` header from the provided header map and returns its numeric status code.
/// Returns `error.MissingGrpcStatus`, `error.InvalidGrpcStatusFormat`, or `error.InvalidGrpcStatusRange` on invalid input.
pub const parseGrpcStatus = metadata.parseGrpcStatus;
/// Re-exports `metadata.requireGrpcStatus` for gRPC metadata validation.
/// Parses the `grpc-status` header from a header map and ignores the decoded value.
/// Returns the same errors as `parseGrpcStatus` when the header is missing or malformed.
pub const requireGrpcStatus = metadata.requireGrpcStatus;

test {
    _ = @import("wire.zig");
    _ = @import("metadata.zig");
}
