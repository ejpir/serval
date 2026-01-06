// lib/serval-proxy/h1/mod.zig
//! HTTP/1.1 Upstream Forwarding
//!
//! Sends HTTP/1.1 requests and forwards responses using text-based protocol.
//! TigerStyle: Protocol-specific code isolated for future h2 support.

pub const request = @import("request.zig");
pub const response = @import("response.zig");
pub const body = @import("body.zig");

// Re-export commonly used functions for convenience
pub const sendRequest = request.sendRequest;
pub const buildRequestBuffer = request.buildRequestBuffer;
pub const methodToString = request.methodToString;
pub const isHopByHopHeader = request.isHopByHopHeader;
pub const eqlIgnoreCase = request.eqlIgnoreCase;

pub const forwardResponse = response.forwardResponse;

pub const streamRequestBody = body.streamRequestBody;
pub const forwardBody = body.forwardBody;

test {
    _ = @import("request.zig");
    _ = @import("response.zig");
    _ = @import("body.zig");
    _ = @import("chunked.zig");
}
