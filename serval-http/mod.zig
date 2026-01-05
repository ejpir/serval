// lib/serval-http/mod.zig
//! Serval HTTP - HTTP/1.1 Parser
//!
//! Zero-allocation HTTP/1.1 request and response parser.
//! TigerStyle: Fixed buffers, explicit sizes.

pub const parser = @import("parser.zig");
pub const Parser = parser.Parser;

// Response parsing functions
pub const parseStatusCode = parser.parseStatusCode;
pub const parseContentLength = parser.parseContentLength;
pub const parseContentLengthValue = parser.parseContentLengthValue;

test {
    _ = @import("parser.zig");
}
