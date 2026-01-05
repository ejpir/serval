// lib/serval-server/h1/connection.zig
//! HTTP/1.1 Connection Utilities
//!
//! Connection lifecycle management: unique IDs, keep-alive detection,
//! and request processing state.
//!
//! TigerStyle: Explicit state management, no hidden globals in public API.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const HeaderMap = serval_core.types.HeaderMap;

// =============================================================================
// Connection State
// =============================================================================

/// Global connection counter for unique connection IDs.
/// TigerStyle: Module-level state with atomic access, monotonic ordering sufficient.
var global_connection_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Result of processing a single HTTP request.
/// TigerStyle: Explicit enum for control flow, no magic booleans.
pub const ProcessResult = enum {
    keep_alive,
    close_connection,
    fatal_error,
};

// =============================================================================
// Connection Functions
// =============================================================================

/// Generate a unique connection ID.
/// Thread-safe via atomic increment, monotonically increasing.
/// TigerStyle: Wraps module-level state with explicit function.
pub fn nextConnectionId() u64 {
    // Postcondition: returned ID is unique (monotonic counter)
    const id = global_connection_id.fetchAdd(1, .monotonic);
    return id;
}

/// Check if client requested connection close (RFC 9112).
/// HTTP/1.1 defaults to keep-alive, only close if explicitly requested.
///
/// Returns true if Connection header is present and equals "close" (case-insensitive).
pub fn clientWantsClose(headers: *const HeaderMap) bool {
    // Precondition: headers pointer is valid
    assert(@intFromPtr(headers) != 0);

    const conn = headers.get("Connection") orelse return false;

    // Postcondition: only returns true for exact "close" match
    // "close" is exactly 5 characters
    if (conn.len != 5) return false;
    return std.ascii.eqlIgnoreCase(conn, "close");
}

// =============================================================================
// Tests
// =============================================================================

test "nextConnectionId returns monotonically increasing values" {
    const id1 = nextConnectionId();
    const id2 = nextConnectionId();
    const id3 = nextConnectionId();

    try std.testing.expect(id2 > id1);
    try std.testing.expect(id3 > id2);
}

test "clientWantsClose returns false for missing header" {
    var headers = HeaderMap{};
    try std.testing.expect(!clientWantsClose(&headers));
}

test "clientWantsClose returns true for 'close' header" {
    var headers = HeaderMap{};
    try headers.put("Connection", "close");
    try std.testing.expect(clientWantsClose(&headers));
}

test "clientWantsClose is case-insensitive" {
    var headers = HeaderMap{};

    try headers.put("Connection", "Close");
    try std.testing.expect(clientWantsClose(&headers));

    try headers.put("Connection", "CLOSE");
    try std.testing.expect(clientWantsClose(&headers));

    try headers.put("Connection", "cLoSe");
    try std.testing.expect(clientWantsClose(&headers));
}

test "clientWantsClose returns false for keep-alive" {
    var headers = HeaderMap{};
    try headers.put("Connection", "keep-alive");
    try std.testing.expect(!clientWantsClose(&headers));
}

test "clientWantsClose returns false for wrong length values" {
    var headers = HeaderMap{};

    // Too short
    try headers.put("Connection", "clos");
    try std.testing.expect(!clientWantsClose(&headers));

    // Too long
    try headers.put("Connection", "closed");
    try std.testing.expect(!clientWantsClose(&headers));

    // Empty
    try headers.put("Connection", "");
    try std.testing.expect(!clientWantsClose(&headers));
}
