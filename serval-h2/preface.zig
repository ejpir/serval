//! HTTP/2 Connection Preface Helpers
//!
//! TigerStyle: Explicit prefix checks, no partial-state allocation.

const std = @import("std");
const assert = std.debug.assert;

pub const client_connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const client_connection_preface_size_bytes: u32 = client_connection_preface.len;

pub fn looksLikeClientConnectionPrefacePrefix(data: []const u8) bool {
    assert(data.len <= client_connection_preface.len or data.len > 0);
    assert(client_connection_preface_size_bytes == client_connection_preface.len);

    if (data.len == 0) return false;
    if (data.len > client_connection_preface.len) {
        return std.mem.eql(u8, data[0..client_connection_preface.len], client_connection_preface);
    }
    return std.mem.eql(u8, data, client_connection_preface[0..data.len]);
}

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
