//! HTTP/2 Connection Preface Helpers
//!
//! TigerStyle: Explicit prefix checks, no partial-state allocation.

const std = @import("std");
const assert = std.debug.assert;

/// The fixed HTTP/2 client connection preface sequence.
/// This value is the exact byte string `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`.
/// It is a compile-time constant and is never modified at runtime.
pub const client_connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Size of the HTTP/2 client connection preface in bytes.
/// This value is derived directly from `client_connection_preface.len`.
/// Use this constant when validating buffer length before comparing against the preface.
pub const client_connection_preface_size_bytes: u32 = client_connection_preface.len;

/// Returns `true` when `data` matches the start of the HTTP/2 client connection preface.
/// If `data` is longer than the preface, only the first `client_connection_preface.len` bytes are compared.
/// Returns `false` for an empty slice or any mismatch; this function does not allocate or fail.
pub fn looksLikeClientConnectionPrefacePrefix(data: []const u8) bool {
    assert(data.len <= client_connection_preface.len or data.len > 0);
    assert(client_connection_preface_size_bytes == client_connection_preface.len);

    if (data.len == 0) return false;
    if (data.len > client_connection_preface.len) {
        return std.mem.eql(u8, data[0..client_connection_preface.len], client_connection_preface);
    }
    return std.mem.eql(u8, data, client_connection_preface[0..data.len]);
}

/// Returns `true` when `data` begins with the HTTP/2 client connection preface.
/// Returns `false` if `data` is shorter than the full preface or if any byte differs.
/// This is a pure byte comparison and does not allocate or report errors.
pub fn looksLikeClientConnectionPreface(data: []const u8) bool {
    assert(client_connection_preface_size_bytes == client_connection_preface.len);
    assert(client_connection_preface.len > 0);
    if (data.len < client_connection_preface.len) return false;
    return std.mem.eql(u8, data[0..client_connection_preface.len], client_connection_preface);
}

test "looksLikeClientConnectionPreface matches full preface" {
    try std.testing.expect(looksLikeClientConnectionPreface(client_connection_preface));
}

test "looksLikeClientConnectionPrefacePrefix matches partial preface" {
    try std.testing.expect(looksLikeClientConnectionPrefacePrefix(client_connection_preface[0..8]));
    try std.testing.expect(!looksLikeClientConnectionPrefacePrefix("POST /"));
}
