// lib/serval-http/mod.zig
//! Serval HTTP - HTTP/1.1 Parser
//!
//! Zero-allocation HTTP/1.1 request and response parser.
//! TigerStyle: Fixed buffers, explicit sizes.

/// Re-exports the HTTP parser module defined in `parser.zig`.
/// Use this namespace to access parser types and functions via `http.parser`.
/// This declaration performs a compile-time import and introduces no runtime behavior or ownership changes.
pub const parser = @import("parser.zig");
/// Re-export of `parser.Parser`, a stateful zero-allocation HTTP/1.x request-header parser.
/// `parseHeaders` expects a complete header block ending in `\r\n\r\n` and fills `request`, `headers_end`, and `body_framing`.
/// Parsed request/header strings are borrowed slices into the input buffer, so that buffer must outlive parser consumers.
/// Errors from parsing are surfaced as `ParseError` (for example malformed/oversized headers or invalid message framing); call `reset()` before reuse.
pub const Parser = parser.Parser;

// Response parsing functions
/// Parses a 3-digit HTTP status code from a response status line slice.
/// Expects an `HTTP/1.x NNN ...`-style line and at least `HTTP/1.1 200`-length input.
/// Returns `null` if the format is invalid, any status digit is non-numeric, or the code is outside `100..599`.
/// Performs no allocation and no ownership transfer; `header` is read-only and used only during the call.
pub const parseStatusCode = parser.parseStatusCode;
/// Parses a raw HTTP header block for a `Content-Length:` field (ASCII case-insensitive).
/// `header` is read-only input that must be valid for the call; no allocation or retained references occur.
/// After `:`, spaces/tabs are skipped, then the value is parsed as decimal `u64`.
/// Returns `null` when the field is missing, empty, non-numeric, overflowed, or has leading zeros (except `"0"`).
pub const parseContentLength = parser.parseContentLength;
/// Parses a `Content-Length` field value slice into a `u64`.
/// Accepts only non-empty ASCII decimal digits, with no leading zeros unless the value is exactly `"0"`.
/// Returns `null` for invalid input (empty, non-digit bytes, more than 20 digits, or `u64` overflow).
/// Reads `value` without allocation or ownership transfer; callers should pass a trimmed numeric token.
pub const parseContentLengthValue = parser.parseContentLengthValue;

// Chunked transfer encoding parser
/// Namespace re-export for `chunked.zig`.
/// Provides access to the chunked HTTP transfer-encoding API through `http.chunked`.
/// Behavior, ownership/lifetime requirements, and error semantics are defined by the declarations inside `chunked.zig`.
pub const chunked = @import("chunked.zig");

test {
    _ = @import("parser.zig");
    _ = @import("chunked.zig");
}
