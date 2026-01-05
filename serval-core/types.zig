// lib/serval-core/types.zig
//! Serval Core Types
//!
//! HTTP/1.1 request/response types for the serval library.
//! All types are zero-copy where possible (slices into buffers).
//!
//! TigerStyle: Zero undefined buffers, explicit sizes

const std = @import("std");
const assert = std.debug.assert;
const config = @import("config.zig");

// =============================================================================
// HTTP Method
// =============================================================================

pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
};

// =============================================================================
// HTTP Version
// =============================================================================

pub const Version = enum {
    @"HTTP/1.0",
    @"HTTP/1.1",
};

// =============================================================================
// Header Map (fixed-size, no allocation)
// =============================================================================

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Fixed-size header map with O(1) lookups for frequently-accessed headers.
///
/// Why cached indices: HTTP proxies access Content-Length, Host, Connection, and
/// Transfer-Encoding on nearly every request. Caching their indices avoids O(n)
/// scans through the header list, reducing latency for high-throughput scenarios.
/// The trade-off is 4 bytes of extra memory per HeaderMap.
pub const HeaderMap = struct {
    // TigerStyle: Zero buffer for defense-in-depth, prevents info leaks if count is wrong.
    headers: [config.MAX_HEADERS]Header = std.mem.zeroes([config.MAX_HEADERS]Header),
    count: u8 = 0,

    // Cached indices for frequently-accessed headers (null = not present).
    // Why u8: MAX_HEADERS is 64, so u8 is sufficient and explicit per TigerStyle.
    content_length_idx: ?u8 = null,
    host_idx: ?u8 = null,
    connection_idx: ?u8 = null,
    transfer_encoding_idx: ?u8 = null,

    pub fn init() HeaderMap {
        return .{};
    }

    pub fn put(self: *HeaderMap, name: []const u8, value: []const u8) error{ TooManyHeaders, DuplicateContentLength }!void {
        assert(self.count <= config.MAX_HEADERS);
        assert(name.len > 0); // Header names must be non-empty per HTTP spec
        if (self.count >= config.MAX_HEADERS) return error.TooManyHeaders;

        const idx = self.count;
        self.headers[idx] = .{ .name = name, .value = value };
        self.count += 1;

        // Cache index if this is a frequently-accessed header.
        // Why inline caching: Avoids repeated O(n) scans in hot paths like
        // request parsing and proxy forwarding.
        try self.cacheHeaderIndex(name, value, idx);
    }

    /// Caches the index for known high-frequency headers.
    /// Detects duplicate Content-Length headers with differing values (smuggling vector).
    /// TigerStyle: Separate function keeps put() under 70 lines.
    fn cacheHeaderIndex(self: *HeaderMap, name: []const u8, value: []const u8, idx: u8) error{DuplicateContentLength}!void {
        assert(idx < config.MAX_HEADERS);
        assert(idx < self.count);

        // Check each cached header using case-insensitive comparison.
        // Order by frequency: Content-Length and Host are most common.
        if (eqlIgnoreCase(name, "content-length")) {
            // RFC 7230 Section 3.3.2: If a message with multiple Content-Length headers
            // is received, and the values differ, reject as invalid. Identical values
            // indicate redundant headers (uncommon but allowed by some implementations).
            // We reject ALL duplicates to prevent request smuggling attacks where
            // intermediaries disagree on which Content-Length to use.
            if (self.content_length_idx) |existing_idx| {
                const existing_value = self.headers[existing_idx].value;
                if (!std.mem.eql(u8, existing_value, value)) {
                    return error.DuplicateContentLength;
                }
                // Same value - keep original index, ignore duplicate
            } else {
                self.content_length_idx = idx;
            }
        } else if (eqlIgnoreCase(name, "host")) {
            self.host_idx = idx;
        } else if (eqlIgnoreCase(name, "connection")) {
            self.connection_idx = idx;
        } else if (eqlIgnoreCase(name, "transfer-encoding")) {
            self.transfer_encoding_idx = idx;
        }
    }

    pub fn get(self: *const HeaderMap, name: []const u8) ?[]const u8 {
        assert(self.count <= config.MAX_HEADERS);

        for (self.headers[0..self.count]) |header| {
            if (eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    /// O(1) lookup for Content-Length header value.
    /// Why: Content-Length is checked on every request to determine body size.
    pub fn getContentLength(self: *const HeaderMap) ?[]const u8 {
        assert(self.count <= config.MAX_HEADERS);
        const idx = self.content_length_idx orelse return null;
        assert(idx < self.count);
        return self.headers[idx].value;
    }

    /// O(1) lookup for Host header value.
    /// Why: Host is required for HTTP/1.1 and used for virtual host routing.
    pub fn getHost(self: *const HeaderMap) ?[]const u8 {
        assert(self.count <= config.MAX_HEADERS);
        const idx = self.host_idx orelse return null;
        assert(idx < self.count);
        return self.headers[idx].value;
    }

    /// O(1) lookup for Connection header value.
    /// Why: Connection determines keep-alive behavior for connection pooling.
    pub fn getConnection(self: *const HeaderMap) ?[]const u8 {
        assert(self.count <= config.MAX_HEADERS);
        const idx = self.connection_idx orelse return null;
        assert(idx < self.count);
        return self.headers[idx].value;
    }

    /// O(1) lookup for Transfer-Encoding header value.
    /// Why: Transfer-Encoding (chunked) affects body parsing strategy.
    pub fn getTransferEncoding(self: *const HeaderMap) ?[]const u8 {
        assert(self.count <= config.MAX_HEADERS);
        const idx = self.transfer_encoding_idx orelse return null;
        assert(idx < self.count);
        return self.headers[idx].value;
    }

    pub fn reset(self: *HeaderMap) void {
        self.count = 0;
        // Clear cached indices to prevent stale lookups after reset.
        self.content_length_idx = null;
        self.host_idx = null;
        self.connection_idx = null;
        self.transfer_encoding_idx = null;
    }
};

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (std.ascii.toLower(ac) != std.ascii.toLower(bc)) return false;
    }
    return true;
}

// =============================================================================
// Request (zero-copy, references buffer)
// =============================================================================

pub const Request = struct {
    method: Method = .GET,
    path: []const u8 = "",
    version: Version = .@"HTTP/1.1",
    headers: HeaderMap = .{},
    body: ?[]const u8 = null,
};

// =============================================================================
// Response
// =============================================================================

pub const Response = struct {
    status: u16 = 200,
    headers: HeaderMap = .{},
    body: ?[]const u8 = null,
};

// =============================================================================
// Upstream
// =============================================================================

pub const Upstream = struct {
    host: []const u8,
    port: u16,
    /// Index into connection pool to retrieve/release connections for this upstream.
    idx: u32 = 0,
};

// =============================================================================
// Action (control flow from hooks)
// =============================================================================

pub const Action = enum {
    continue_request,
    send_response,
};

// =============================================================================
// Connection Info (for logging hooks)
// =============================================================================

/// Client connection information for logging hooks.
/// TigerStyle: Fixed-size struct, no allocations.
pub const ConnectionInfo = struct {
    /// Unique connection identifier for correlation.
    connection_id: u64,
    /// IPv4 or IPv6 address string, null-terminated (max 45 chars + null).
    client_addr: [46]u8,
    /// Client source port.
    client_port: u16,
    /// Server port client connected to.
    local_port: u16,
    /// TCP round-trip time estimate in microseconds.
    tcp_rtt_us: u32,
    /// TCP RTT variance in microseconds.
    tcp_rtt_var_us: u32,
};

/// Upstream connection timing for logging.
/// TigerStyle: Explicit timing with u64 nanoseconds.
pub const UpstreamConnectInfo = struct {
    /// DNS resolution duration in nanoseconds.
    dns_duration_ns: u64,
    /// TCP connect duration in nanoseconds.
    tcp_connect_duration_ns: u64,
    /// Whether this connection was reused from pool.
    reused: bool,
    /// Time spent waiting for pool connection in nanoseconds.
    pool_wait_ns: u64,
    /// Local port used for upstream connection.
    local_port: u16,
};

// =============================================================================
// Tests
// =============================================================================

test "HeaderMap put and get" {
    var map = HeaderMap.init();
    try map.put("Content-Type", "text/html");

    try std.testing.expectEqual(@as(u8, 1), map.count);
    try std.testing.expectEqualStrings("text/html", map.get("Content-Type").?);
    try std.testing.expectEqualStrings("text/html", map.get("content-type").?);
}

test "HeaderMap max headers" {
    var map = HeaderMap.init();

    var i: u8 = 0;
    while (i < config.MAX_HEADERS) : (i += 1) {
        try map.put("X-Header", "value");
    }

    try std.testing.expectError(error.TooManyHeaders, map.put("Extra", "value"));
}

test "HeaderMap cached indices - Content-Length" {
    var map = HeaderMap.init();

    // Before adding, should return null
    try std.testing.expect(map.getContentLength() == null);

    try map.put("X-Custom", "ignored");
    try map.put("Content-Length", "42");
    try map.put("X-Another", "also-ignored");

    // O(1) lookup should return correct value
    try std.testing.expectEqualStrings("42", map.getContentLength().?);
    // Verify index was cached correctly
    try std.testing.expectEqual(@as(?u8, 1), map.content_length_idx);
}

test "HeaderMap cached indices - Host" {
    var map = HeaderMap.init();

    try std.testing.expect(map.getHost() == null);

    try map.put("Host", "example.com:8080");

    try std.testing.expectEqualStrings("example.com:8080", map.getHost().?);
    try std.testing.expectEqual(@as(?u8, 0), map.host_idx);
}

test "HeaderMap cached indices - Connection" {
    var map = HeaderMap.init();

    try std.testing.expect(map.getConnection() == null);

    try map.put("Connection", "keep-alive");

    try std.testing.expectEqualStrings("keep-alive", map.getConnection().?);
    try std.testing.expectEqual(@as(?u8, 0), map.connection_idx);
}

test "HeaderMap cached indices - Transfer-Encoding" {
    var map = HeaderMap.init();

    try std.testing.expect(map.getTransferEncoding() == null);

    try map.put("Transfer-Encoding", "chunked");

    try std.testing.expectEqualStrings("chunked", map.getTransferEncoding().?);
    try std.testing.expectEqual(@as(?u8, 0), map.transfer_encoding_idx);
}

test "HeaderMap cached indices - case insensitive" {
    var map = HeaderMap.init();

    // Headers are matched case-insensitively during put()
    try map.put("content-length", "100");
    try map.put("HOST", "localhost");
    try map.put("CONNECTION", "close");
    try map.put("transfer-ENCODING", "gzip");

    try std.testing.expectEqualStrings("100", map.getContentLength().?);
    try std.testing.expectEqualStrings("localhost", map.getHost().?);
    try std.testing.expectEqualStrings("close", map.getConnection().?);
    try std.testing.expectEqualStrings("gzip", map.getTransferEncoding().?);
}

test "HeaderMap cached indices - reset clears indices" {
    var map = HeaderMap.init();

    try map.put("Content-Length", "42");
    try map.put("Host", "example.com");
    try map.put("Connection", "keep-alive");
    try map.put("Transfer-Encoding", "chunked");

    // Verify all indices are set
    try std.testing.expect(map.content_length_idx != null);
    try std.testing.expect(map.host_idx != null);
    try std.testing.expect(map.connection_idx != null);
    try std.testing.expect(map.transfer_encoding_idx != null);

    map.reset();

    // After reset, all indices should be null
    try std.testing.expect(map.content_length_idx == null);
    try std.testing.expect(map.host_idx == null);
    try std.testing.expect(map.connection_idx == null);
    try std.testing.expect(map.transfer_encoding_idx == null);
    try std.testing.expectEqual(@as(u8, 0), map.count);

    // O(1) getters should return null
    try std.testing.expect(map.getContentLength() == null);
    try std.testing.expect(map.getHost() == null);
    try std.testing.expect(map.getConnection() == null);
    try std.testing.expect(map.getTransferEncoding() == null);
}

test "HeaderMap cached indices - all four in one map" {
    var map = HeaderMap.init();

    try map.put("Host", "api.example.com");
    try map.put("Content-Length", "1024");
    try map.put("Connection", "close");
    try map.put("Transfer-Encoding", "identity");
    try map.put("X-Request-Id", "abc123");

    // All cached getters should work
    try std.testing.expectEqualStrings("api.example.com", map.getHost().?);
    try std.testing.expectEqualStrings("1024", map.getContentLength().?);
    try std.testing.expectEqualStrings("close", map.getConnection().?);
    try std.testing.expectEqualStrings("identity", map.getTransferEncoding().?);

    // Generic get() should also work
    try std.testing.expectEqualStrings("abc123", map.get("X-Request-Id").?);

    // Verify indices
    try std.testing.expectEqual(@as(?u8, 0), map.host_idx);
    try std.testing.expectEqual(@as(?u8, 1), map.content_length_idx);
    try std.testing.expectEqual(@as(?u8, 2), map.connection_idx);
    try std.testing.expectEqual(@as(?u8, 3), map.transfer_encoding_idx);
}

test "HeaderMap duplicate Content-Length with different values" {
    var map = HeaderMap.init();

    // First Content-Length should succeed
    try map.put("Content-Length", "100");
    try std.testing.expectEqualStrings("100", map.getContentLength().?);

    // Second Content-Length with different value should fail
    try std.testing.expectError(error.DuplicateContentLength, map.put("Content-Length", "200"));

    // Original value should still be there
    try std.testing.expectEqualStrings("100", map.getContentLength().?);
}

test "HeaderMap duplicate Content-Length with same value allowed" {
    var map = HeaderMap.init();

    // First Content-Length
    try map.put("Content-Length", "42");
    try std.testing.expectEqualStrings("42", map.getContentLength().?);

    // Second Content-Length with same value should be allowed
    try map.put("Content-Length", "42");

    // Original value should still be returned
    try std.testing.expectEqualStrings("42", map.getContentLength().?);
}

test "HeaderMap duplicate Content-Length case insensitive" {
    var map = HeaderMap.init();

    try map.put("content-length", "100");
    try std.testing.expectEqualStrings("100", map.getContentLength().?);

    // Different case but different value should still fail
    try std.testing.expectError(error.DuplicateContentLength, map.put("CONTENT-LENGTH", "200"));
}
