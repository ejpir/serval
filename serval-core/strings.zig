// serval-core/strings.zig
//! String Utilities for Case-Insensitive Operations
//!
//! Provides ASCII case-insensitive string comparison and search functions
//! used across serval modules for HTTP header handling.
//! TigerStyle: Bounded loops, explicit types, ~2 assertions per function.

const std = @import("std");
const assert = std.debug.assert;

// =============================================================================
// Case-Insensitive String Comparison
// =============================================================================

/// Case-insensitive ASCII string equality comparison.
///
/// Compares two strings for equality, treating uppercase and lowercase
/// ASCII letters as equivalent. Non-ASCII bytes are compared exactly.
///
/// TigerStyle:
/// - S3: Loop bounded by string length (checked at entry via len comparison).
/// - Explicit inline ASCII lowercasing (no allocation).
///
/// Returns: true if strings are equal (case-insensitive), false otherwise.
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    // Fast path: different lengths cannot be equal.
    if (a.len != b.len) return false;

    // Empty strings are equal.
    if (a.len == 0) return true;

    // S3: Loop bounded by string length (both slices have same length).
    for (a, b) |ac, bc| {
        // ASCII lowercase conversion: 'A'-'Z' (65-90) -> 'a'-'z' (97-122).
        const a_lower = if (ac >= 'A' and ac <= 'Z') ac + 32 else ac;
        const b_lower = if (bc >= 'A' and bc <= 'Z') bc + 32 else bc;
        if (a_lower != b_lower) return false;
    }

    return true;
}

// =============================================================================
// Case-Insensitive Substring Search
// =============================================================================

/// Case-insensitive ASCII substring search.
///
/// Returns true if needle is found anywhere within haystack, using
/// case-insensitive comparison for ASCII letters.
///
/// TigerStyle:
/// - S1: Precondition - empty needle always matches.
/// - S3: Outer loop bounded by (haystack.len - needle.len + 1).
/// - S3: Inner loop bounded by needle.len.
///
/// Returns: true if needle is found in haystack (case-insensitive).
pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    // S1: Empty needle is always found (standard substring semantics).
    if (needle.len == 0) return true;

    // S1: Needle longer than haystack cannot match.
    if (haystack.len < needle.len) return false;

    // S3: Bounded outer loop - check each possible starting position.
    const max_start = haystack.len - needle.len + 1;
    for (0..max_start) |i| {
        // S3: Bounded inner loop - compare needle length characters.
        var matches = true;
        for (0..needle.len) |j| {
            const h = haystack[i + j];
            const n = needle[j];
            // ASCII lowercase conversion.
            const h_lower = if (h >= 'A' and h <= 'Z') h + 32 else h;
            const n_lower = if (n >= 'A' and n <= 'Z') n + 32 else n;
            if (h_lower != n_lower) {
                matches = false;
                break;
            }
        }
        if (matches) return true;
    }

    return false;
}

// =============================================================================
// Tests
// =============================================================================

test "eqlIgnoreCase - exact match" {
    try std.testing.expect(eqlIgnoreCase("Connection", "Connection"));
    try std.testing.expect(eqlIgnoreCase("Host", "Host"));
    try std.testing.expect(eqlIgnoreCase("a", "a"));
    try std.testing.expect(eqlIgnoreCase("content-length", "content-length"));
}

test "eqlIgnoreCase - case insensitive match" {
    try std.testing.expect(eqlIgnoreCase("CONNECTION", "connection"));
    try std.testing.expect(eqlIgnoreCase("connection", "CONNECTION"));
    try std.testing.expect(eqlIgnoreCase("CoNnEcTiOn", "cOnNeCtIoN"));
    try std.testing.expect(eqlIgnoreCase("HOST", "host"));
    try std.testing.expect(eqlIgnoreCase("Content-Type", "content-type"));
    try std.testing.expect(eqlIgnoreCase("Content-Length", "content-length"));
    try std.testing.expect(eqlIgnoreCase("CONTENT-LENGTH", "content-length"));
    try std.testing.expect(eqlIgnoreCase("Transfer-Encoding", "transfer-encoding"));
}

test "eqlIgnoreCase - different strings" {
    try std.testing.expect(!eqlIgnoreCase("Host", "Connection"));
    try std.testing.expect(!eqlIgnoreCase("Hosts", "Host"));
    try std.testing.expect(!eqlIgnoreCase("Accept", "Content-Type"));
    try std.testing.expect(!eqlIgnoreCase("Content-Length", "Transfer-Encoding"));
}

test "eqlIgnoreCase - different lengths" {
    try std.testing.expect(!eqlIgnoreCase("Host", "Hos"));
    try std.testing.expect(!eqlIgnoreCase("Ho", "Host"));
    try std.testing.expect(!eqlIgnoreCase("", "a"));
    try std.testing.expect(!eqlIgnoreCase("a", ""));
    try std.testing.expect(!eqlIgnoreCase("Content", "Content-Length"));
}

test "eqlIgnoreCase - empty strings" {
    try std.testing.expect(eqlIgnoreCase("", ""));
}

test "eqlIgnoreCase - non-ASCII bytes compared exactly" {
    // Non-ASCII bytes are compared without case conversion.
    try std.testing.expect(eqlIgnoreCase("\x80\x90", "\x80\x90"));
    try std.testing.expect(!eqlIgnoreCase("\x80", "\xa0"));
}

test "containsIgnoreCase - exact match" {
    try std.testing.expect(containsIgnoreCase("chunked", "chunked"));
    try std.testing.expect(containsIgnoreCase("gzip", "gzip"));
}

test "containsIgnoreCase - case insensitive match" {
    try std.testing.expect(containsIgnoreCase("CHUNKED", "chunked"));
    try std.testing.expect(containsIgnoreCase("Chunked", "chunked"));
    try std.testing.expect(containsIgnoreCase("chunked", "CHUNKED"));
    try std.testing.expect(containsIgnoreCase("gzip, CHUNKED", "chunked"));
}

test "containsIgnoreCase - substring match" {
    try std.testing.expect(containsIgnoreCase("gzip, chunked", "chunked"));
    try std.testing.expect(containsIgnoreCase("chunked, gzip", "chunked"));
    try std.testing.expect(containsIgnoreCase("deflate, chunked, br", "chunked"));
    try std.testing.expect(containsIgnoreCase("xxxchunkedyyy", "chunked"));
}

test "containsIgnoreCase - no match" {
    try std.testing.expect(!containsIgnoreCase("gzip", "chunked"));
    try std.testing.expect(!containsIgnoreCase("chunk", "chunked"));
    try std.testing.expect(!containsIgnoreCase("chunke", "chunked"));
}

test "containsIgnoreCase - empty needle always matches" {
    try std.testing.expect(containsIgnoreCase("abc", ""));
    try std.testing.expect(containsIgnoreCase("", ""));
    try std.testing.expect(containsIgnoreCase("chunked", ""));
}

test "containsIgnoreCase - empty haystack with non-empty needle" {
    try std.testing.expect(!containsIgnoreCase("", "chunked"));
    try std.testing.expect(!containsIgnoreCase("", "a"));
}

test "containsIgnoreCase - needle longer than haystack" {
    try std.testing.expect(!containsIgnoreCase("abc", "abcdef"));
    try std.testing.expect(!containsIgnoreCase("ch", "chunked"));
}

test "containsIgnoreCase - single character" {
    try std.testing.expect(containsIgnoreCase("abc", "a"));
    try std.testing.expect(containsIgnoreCase("abc", "b"));
    try std.testing.expect(containsIgnoreCase("abc", "c"));
    try std.testing.expect(containsIgnoreCase("ABC", "a"));
    try std.testing.expect(!containsIgnoreCase("abc", "d"));
}

test "containsIgnoreCase - at boundaries" {
    // Match at start
    try std.testing.expect(containsIgnoreCase("chunked, gzip", "chunked"));
    // Match at end
    try std.testing.expect(containsIgnoreCase("gzip, chunked", "chunked"));
    // Match entire string
    try std.testing.expect(containsIgnoreCase("chunked", "chunked"));
}
