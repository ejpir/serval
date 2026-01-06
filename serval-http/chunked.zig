// serval-http/chunked.zig
//! Chunked Transfer Encoding Parser (RFC 9112 Section 7)
//!
//! Parses chunked transfer encoding chunk sizes from HTTP message bodies.
//! Each chunk begins with a hex size followed by optional extensions and CRLF.
//! A zero-size chunk signals the end of the message body.
//!
//! TigerStyle: Bounded loops, explicit overflow checks, ~2 assertions per function.

const std = @import("std");
const assert = std.debug.assert;

// =============================================================================
// Constants
// =============================================================================

/// Maximum hex digits for chunk size (u64 max = 16 hex digits).
pub const MAX_HEX_DIGITS: u8 = 16;

/// Maximum bytes allowed for chunk extensions (RFC 9112 Section 7.1.1).
/// Extensions are rarely used; limit prevents DoS via unbounded extension parsing.
pub const MAX_EXTENSION_BYTES: u16 = 256;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during chunk size parsing.
pub const ChunkParseError = error{
    /// Buffer contains non-hex character in chunk size position.
    InvalidHexDigit,
    /// Chunk size overflows u64 (exceeds 16 hex digits or value overflow).
    ChunkSizeOverflow,
    /// Chunk size line does not end with CRLF.
    MissingCRLF,
    /// Chunk extension exceeds MAX_EXTENSION_BYTES limit.
    ExtensionTooLong,
    /// Buffer does not contain complete chunk size line.
    IncompleteChunk,
};

// =============================================================================
// Result Types
// =============================================================================

/// Result of parsing a chunk size line.
pub const ChunkSizeResult = struct {
    /// Parsed chunk size in bytes.
    size: u64,
    /// Total bytes consumed from buffer (including size, extension, and CRLF).
    consumed: usize,
};

// =============================================================================
// Parser Functions
// =============================================================================

/// Parse chunk-size from buffer start per RFC 9112 Section 7.1.
///
/// Format: chunk-size [chunk-ext] CRLF
/// - chunk-size: 1*HEXDIG (1-16 hex digits, case-insensitive)
/// - chunk-ext: *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
/// - Terminated by CRLF
///
/// Returns chunk size and total bytes consumed (including CRLF).
/// Extensions are validated for length but otherwise ignored.
pub fn parseChunkSize(buffer: []const u8) ChunkParseError!ChunkSizeResult {
    // Precondition: buffer must have at least "0\r\n" (3 bytes minimum).
    if (buffer.len < 3) return error.IncompleteChunk;
    assert(buffer.len >= 3);

    var size: u64 = 0;
    var hex_digit_count: u8 = 0;
    var pos: usize = 0;

    // Parse hex digits (bounded: max 16 digits for u64).
    while (pos < buffer.len and hex_digit_count < MAX_HEX_DIGITS + 1) : (pos += 1) {
        const ch = buffer[pos];
        const digit_value: u64 = switch (ch) {
            '0'...'9' => ch - '0',
            'A'...'F' => ch - 'A' + 10,
            'a'...'f' => ch - 'a' + 10,
            ';', '\r' => break, // Extension start or line end - stop parsing hex.
            else => return error.InvalidHexDigit,
        };

        hex_digit_count += 1;

        // TigerStyle: Explicit overflow detection using builtins.
        const mul_result = @mulWithOverflow(size, 16);
        if (mul_result[1] != 0) return error.ChunkSizeOverflow;

        const add_result = @addWithOverflow(mul_result[0], digit_value);
        if (add_result[1] != 0) return error.ChunkSizeOverflow;

        size = add_result[0];
    }

    // Must have at least one hex digit.
    if (hex_digit_count == 0) return error.InvalidHexDigit;

    // Check for overflow due to too many digits.
    if (hex_digit_count > MAX_HEX_DIGITS) return error.ChunkSizeOverflow;

    // Skip chunk extensions if present (bounded: max MAX_EXTENSION_BYTES).
    var extension_bytes: u16 = 0;
    if (pos < buffer.len and buffer[pos] == ';') {
        pos += 1;
        extension_bytes += 1;

        // Skip extension content until CRLF (bounded loop).
        while (pos < buffer.len and extension_bytes <= MAX_EXTENSION_BYTES) : ({
            pos += 1;
            extension_bytes += 1;
        }) {
            if (buffer[pos] == '\r') break;
        }

        if (extension_bytes > MAX_EXTENSION_BYTES) return error.ExtensionTooLong;
    }

    // Verify CRLF terminator.
    if (pos + 1 >= buffer.len) return error.IncompleteChunk;
    if (buffer[pos] != '\r' or buffer[pos + 1] != '\n') return error.MissingCRLF;

    const consumed = pos + 2; // Include CRLF in consumed count.

    // Postcondition: consumed bytes is valid offset into buffer.
    assert(consumed <= buffer.len);
    assert(hex_digit_count >= 1 and hex_digit_count <= MAX_HEX_DIGITS);

    return .{
        .size = size,
        .consumed = consumed,
    };
}

/// Check if chunk size indicates the last chunk (terminator).
/// Per RFC 9112 Section 7.1: A chunk size of zero signals the end of chunked data.
/// TigerStyle: Trivial single-expression predicate, assertion-exempt.
/// Precondition: Any u64 is valid input.
/// Postcondition: Returns true only for exactly zero.
pub fn isLastChunk(size: u64) bool {
    return size == 0;
}

// =============================================================================
// Tests
// =============================================================================

test "parseChunkSize: single digit" {
    const result = try parseChunkSize("0\r\n");
    try std.testing.expectEqual(@as(u64, 0), result.size);
    try std.testing.expectEqual(@as(usize, 3), result.consumed);
}

test "parseChunkSize: single hex digit" {
    const result = try parseChunkSize("f\r\n");
    try std.testing.expectEqual(@as(u64, 15), result.size);
    try std.testing.expectEqual(@as(usize, 3), result.consumed);
}

test "parseChunkSize: uppercase hex" {
    const result = try parseChunkSize("ABC\r\n");
    try std.testing.expectEqual(@as(u64, 0xABC), result.size);
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
}

test "parseChunkSize: lowercase hex" {
    const result = try parseChunkSize("abc\r\n");
    try std.testing.expectEqual(@as(u64, 0xabc), result.size);
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
}

test "parseChunkSize: mixed case hex" {
    const result = try parseChunkSize("AbC123\r\n");
    try std.testing.expectEqual(@as(u64, 0xAbC123), result.size);
    try std.testing.expectEqual(@as(usize, 8), result.consumed);
}

test "parseChunkSize: max 16 hex digits" {
    const result = try parseChunkSize("ffffffffffffffff\r\n");
    try std.testing.expectEqual(@as(u64, 0xffffffffffffffff), result.size);
    try std.testing.expectEqual(@as(usize, 18), result.consumed);
}

test "parseChunkSize: typical chunk size" {
    const result = try parseChunkSize("1a4\r\n");
    try std.testing.expectEqual(@as(u64, 0x1a4), result.size);
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
}

test "parseChunkSize: with extension" {
    const result = try parseChunkSize("1a;name=value\r\n");
    try std.testing.expectEqual(@as(u64, 0x1a), result.size);
    try std.testing.expectEqual(@as(usize, 15), result.consumed);
}

test "parseChunkSize: with multiple extensions" {
    const result = try parseChunkSize("ff;ext1;ext2=val\r\n");
    try std.testing.expectEqual(@as(u64, 0xff), result.size);
    try std.testing.expectEqual(@as(usize, 18), result.consumed);
}

test "parseChunkSize: with trailing data" {
    const buffer = "100\r\nchunk data here";
    const result = try parseChunkSize(buffer);
    try std.testing.expectEqual(@as(u64, 0x100), result.size);
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
}

test "parseChunkSize: error InvalidHexDigit" {
    try std.testing.expectError(error.InvalidHexDigit, parseChunkSize("xyz\r\n"));
    try std.testing.expectError(error.InvalidHexDigit, parseChunkSize("12g4\r\n"));
    try std.testing.expectError(error.InvalidHexDigit, parseChunkSize(" 10\r\n")); // Leading space.
}

test "parseChunkSize: error InvalidHexDigit empty" {
    try std.testing.expectError(error.InvalidHexDigit, parseChunkSize(";\r\n")); // No digits before extension.
    try std.testing.expectError(error.InvalidHexDigit, parseChunkSize("\r\n")); // No digits at all.
}

test "parseChunkSize: error ChunkSizeOverflow too many digits" {
    // 17 hex digits should overflow.
    try std.testing.expectError(error.ChunkSizeOverflow, parseChunkSize("10000000000000000\r\n"));
}

test "parseChunkSize: error MissingCRLF" {
    try std.testing.expectError(error.MissingCRLF, parseChunkSize("100\n"));
    try std.testing.expectError(error.MissingCRLF, parseChunkSize("100\r"));
    try std.testing.expectError(error.MissingCRLF, parseChunkSize("100 \r\n")); // Space before CRLF.
}

test "parseChunkSize: error ExtensionTooLong" {
    // Create extension longer than MAX_EXTENSION_BYTES.
    const long_ext = "1;" ++ "x" ** 300 ++ "\r\n";
    try std.testing.expectError(error.ExtensionTooLong, parseChunkSize(long_ext));
}

test "parseChunkSize: error IncompleteChunk" {
    try std.testing.expectError(error.IncompleteChunk, parseChunkSize(""));
    try std.testing.expectError(error.IncompleteChunk, parseChunkSize("1"));
    try std.testing.expectError(error.IncompleteChunk, parseChunkSize("10"));
    try std.testing.expectError(error.IncompleteChunk, parseChunkSize("10\r"));
}

test "parseChunkSize: extension at max length boundary" {
    // Extension exactly at MAX_EXTENSION_BYTES should succeed.
    const ext_content = "x" ** (MAX_EXTENSION_BYTES - 1); // -1 for the semicolon.
    const chunk_line = "1;" ++ ext_content ++ "\r\n";
    const result = try parseChunkSize(chunk_line);
    try std.testing.expectEqual(@as(u64, 1), result.size);
}

test "isLastChunk: zero is last chunk" {
    try std.testing.expect(isLastChunk(0));
}

test "isLastChunk: non-zero is not last chunk" {
    try std.testing.expect(!isLastChunk(1));
    try std.testing.expect(!isLastChunk(0xff));
    try std.testing.expect(!isLastChunk(0xffffffffffffffff));
}

test "parseChunkSize: leading zeros allowed" {
    // RFC 9112 does not prohibit leading zeros in chunk size.
    const result = try parseChunkSize("000a\r\n");
    try std.testing.expectEqual(@as(u64, 10), result.size);
    try std.testing.expectEqual(@as(usize, 6), result.consumed);
}
