//! Serval gRPC - Minimal gRPC protocol helpers
//!
//! Layer 2 (Infrastructure).
//! TigerStyle: Explicit wire validation, no transport ownership.

pub const wire = @import("wire.zig");
pub const MessagePrefix = wire.MessagePrefix;
pub const WireError = wire.Error;
pub const parsePrefix = wire.parsePrefix;
pub const buildMessage = wire.buildMessage;
pub const parseMessage = wire.parseMessage;

pub const metadata = @import("metadata.zig");
pub const MetadataError = metadata.Error;
pub const isGrpcContentType = metadata.isGrpcContentType;
pub const validateRequest = metadata.validateRequest;
pub const requireGrpcStatus = metadata.requireGrpcStatus;

test {
    _ = @import("wire.zig");
    _ = @import("metadata.zig");
}
