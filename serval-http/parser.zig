// lib/serval-http/parser.zig
//! HTTP/1.1 Parser
//!
//! Zero-allocation HTTP/1.1 request parser.
//! TigerStyle: Fixed-size buffers, explicit sizes, ~2 assertions per function.

const std = @import("std");
const assert = std.debug.assert;
const serval_core = @import("serval-core");
const types = serval_core.types;
const config = serval_core.config;
const errors = serval_core.errors;

const Request = types.Request;
const Method = types.Method;
const Version = types.Version;
const HeaderMap = types.HeaderMap;
const BodyFraming = types.BodyFraming;
const ParseError = errors.ParseError;

// =============================================================================
// Parser
// =============================================================================

pub const Parser = struct {
    request: Request = .{},
    headers_end: usize = 0, // byte offset after \r\n\r\n
    body_framing: BodyFraming = .none, // determined by Transfer-Encoding or Content-Length

    pub fn init() Parser {
        return .{};
    }

    pub fn reset(self: *Parser) void {
        self.request = .{};
        self.headers_end = 0;
        self.body_framing = .none;
    }

    /// Parse HTTP/1.1 request headers from buffer.
    /// Buffer must contain complete headers (up to \r\n\r\n).
    /// Returns slice pointing into input buffer (zero-copy).
    pub fn parseHeaders(self: *Parser, buffer: []const u8) ParseError!void {
        if (buffer.len == 0) return error.EmptyRequest;
        if (buffer.len > config.MAX_HEADER_SIZE_BYTES) return error.HeadersTooLarge;

        const headers_end_pos = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse
            return error.MalformedHeader;

        self.headers_end = headers_end_pos + 4; // byte offset after \r\n\r\n

        const first_line_end = std.mem.indexOf(u8, buffer, "\r\n") orelse
            return error.MalformedRequestLine;

        try self.parseRequestLine(buffer[0..first_line_end]);

        if (first_line_end + 2 < headers_end_pos) {
            try self.parseHeaderLines(buffer[first_line_end + 2 .. headers_end_pos]);
        }

        // RFC 7230 Section 5.4: HTTP/1.1 requests MUST contain a Host header.
        // HTTP/1.0 does not require Host, so we only enforce this for 1.1.
        if (self.request.version == .@"HTTP/1.1") {
            if (self.request.headers.getHost() == null) {
                return error.MissingHostHeader;
            }
        }

        // Validate message framing to prevent request smuggling attacks.
        // Must be called after headers are parsed but before processing body.
        try self.validateMessageFraming();

        assert(self.request.path.len > 0);
        assert(self.request.headers.count <= config.MAX_HEADERS);
    }

    fn parseRequestLine(self: *Parser, line: []const u8) ParseError!void {
        if (line.len == 0) return error.EmptyRequest;
        assert(line.len <= config.MAX_HEADER_SIZE_BYTES);

        // RFC 7230 Section 3.1.1: Request line uses SP (space, 0x20) as delimiter.
        // HTAB (0x09) in request line would be included in a token and fail validation
        // (method lookup fails, URI validation rejects control chars).
        // splitScalar on ' ' produces empty strings for multiple consecutive spaces.
        var iter = std.mem.splitScalar(u8, line, ' ');

        const method_str = iter.next() orelse return error.MalformedRequestLine;
        // Empty method = leading space or multiple spaces before method
        if (method_str.len == 0) return error.MalformedRequestLine;
        self.request.method = parseMethod(method_str) orelse return error.InvalidMethod;

        const uri_str = iter.next() orelse return error.MalformedRequestLine;
        // Empty URI = multiple spaces between method and URI
        if (uri_str.len == 0) return error.MalformedRequestLine;
        if (uri_str.len > config.MAX_URI_LENGTH_BYTES) return error.UriTooLong;

        // Check for asterisk-form (OPTIONS * HTTP/1.1) per RFC 7230 Section 5.3.4
        if (uri_str.len == 1 and uri_str[0] == '*') {
            // Only OPTIONS method allows asterisk-form request-target
            if (self.request.method != .OPTIONS) {
                return error.InvalidUri;
            }
            self.request.path = uri_str;
        } else {
            // Origin-form must start with '/'
            if (uri_str[0] != '/') return error.InvalidUri;

            for (uri_str) |ch| {
                if (ch <= 0x1F or ch == 0x7F or ch == ' ') return error.InvalidUri;
            }
            self.request.path = uri_str;
        }

        const version_str = iter.next() orelse return error.MalformedRequestLine;
        // Empty version = multiple spaces between URI and version
        if (version_str.len == 0) return error.MalformedRequestLine;
        self.request.version = parseVersion(version_str) orelse return error.InvalidHttpVersion;

        if (iter.next() != null) return error.MalformedRequestLine;

        assert(self.request.path.len > 0);
    }

    fn parseHeaderLines(self: *Parser, buffer: []const u8) ParseError!void {
        assert(self.request.headers.count == 0);

        var lines = std.mem.splitSequence(u8, buffer, "\r\n");

        // TigerStyle: Bounded loop - limit iterations to MAX_HEADERS + 1
        // (extra 1 for potential empty lines between headers)
        var line_count: u8 = 0;
        const max_lines: u8 = config.MAX_HEADERS + 1;

        while (lines.next()) |line| : (line_count += 1) {
            if (line_count >= max_lines) return error.TooManyHeaders;
            if (line.len == 0) continue;

            // RFC 7230 Section 3.2.4: obs-fold (line continuation with leading SP/HTAB)
            // is deprecated and MUST be rejected to prevent request smuggling.
            // Attackers use obs-fold to hide headers from proxies that don't unfold.
            if (line[0] == 0x20 or line[0] == 0x09) {
                return error.MalformedHeader;
            }

            const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse
                return error.MalformedHeader;

            if (colon_pos == 0) return error.InvalidHeaderName;

            const name = line[0..colon_pos];
            const value_start = colon_pos + 1;
            const value = if (value_start < line.len)
                std.mem.trim(u8, line[value_start..], " \t")
            else
                "";

            // Validate header name (token characters per RFC 7230)
            for (name) |ch| {
                const valid = switch (ch) {
                    '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.',
                    '0'...'9', 'A'...'Z', '^', '_', '`', 'a'...'z', '|', '~',
                    => true,
                    else => false,
                };
                if (!valid) return error.InvalidHeaderName;
            }

            // Validate header value (no control chars except HTAB)
            for (value) |ch| {
                if ((ch < 0x20 and ch != 0x09) or ch == 0x7F) {
                    return error.InvalidHeaderValue;
                }
            }

            self.request.headers.put(name, value) catch |err| switch (err) {
                error.TooManyHeaders => return error.TooManyHeaders,
                error.DuplicateContentLength => return error.DuplicateContentLength,
            };
        }

        assert(self.request.headers.count <= config.MAX_HEADERS);
    }

    /// Validates message framing and determines body_framing after header parsing.
    /// RFC 7230 Section 3.3.3: Reject ambiguous message length indicators.
    /// TigerStyle: Security checks as explicit validation step, ~2 assertions.
    fn validateMessageFraming(self: *Parser) ParseError!void {
        const content_length_str = self.request.headers.getContentLength();
        const transfer_encoding = self.request.headers.getTransferEncoding();

        // CL-TE/TE-CL smuggling prevention: Both headers present is ambiguous.
        // Different intermediaries may interpret the body length differently,
        // allowing attackers to smuggle requests past security controls.
        if (content_length_str != null and transfer_encoding != null) {
            return error.AmbiguousMessageLength;
        }

        // Determine body framing per RFC 9112 Section 6.
        // Priority: Transfer-Encoding > Content-Length > none
        if (transfer_encoding) |te| {
            if (containsIgnoreCase(te, "chunked")) {
                self.body_framing = .chunked;
            } else {
                // Non-chunked Transfer-Encoding (e.g., "identity") has no body framing.
                // Per RFC 9112 Section 6.1, "identity" is obsolete and MUST NOT be sent.
                self.body_framing = .none;
            }
        } else if (content_length_str) |cl_str| {
            const content_length = parseContentLengthValue(cl_str) orelse
                return error.InvalidContentLength;
            self.body_framing = .{ .content_length = content_length };
        } else {
            self.body_framing = .none;
        }

        assert(self.body_framing == .chunked or
            self.body_framing == .none or
            self.body_framing.hasKnownLength());
    }
};

fn parseMethod(s: []const u8) ?Method {
    const map = std.StaticStringMap(Method).initComptime(.{
        .{ "GET", .GET },
        .{ "HEAD", .HEAD },
        .{ "POST", .POST },
        .{ "PUT", .PUT },
        .{ "DELETE", .DELETE },
        .{ "CONNECT", .CONNECT },
        .{ "OPTIONS", .OPTIONS },
        .{ "TRACE", .TRACE },
        .{ "PATCH", .PATCH },
    });
    return map.get(s);
}

fn parseVersion(s: []const u8) ?Version {
    if (std.mem.eql(u8, s, "HTTP/1.0")) return .@"HTTP/1.0";
    if (std.mem.eql(u8, s, "HTTP/1.1")) return .@"HTTP/1.1";
    return null;
}

/// Case-insensitive substring search.
/// Returns true if needle is found within haystack (case-insensitive).
/// TigerStyle: Bounded loop - iterations limited by haystack length.
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    const max_start = haystack.len - needle.len + 1;
    for (0..max_start) |i| {
        var matches = true;
        for (0..needle.len) |j| {
            const h = haystack[i + j];
            const n = needle[j];
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
// Response Parsing
// =============================================================================

/// Parse HTTP status code from response line.
/// Expects "HTTP/1.x NNN Reason" format.
/// Returns null for invalid format or out-of-range status.
/// TigerStyle: Bounded loop, explicit size checks.
pub fn parseStatusCode(header: []const u8) ?u16 {
    if (header.len < 12) return null; // "HTTP/1.1 200" minimum

    // Find first space after HTTP version
    const space_idx = std.mem.indexOfScalar(u8, header, ' ') orelse return null;
    if (space_idx + 4 > header.len) return null;

    const status_start = space_idx + 1;
    const status_str = header[status_start..][0..3];

    var result: u16 = 0;
    for (status_str) |ch| {
        if (ch < '0' or ch > '9') return null;
        result = result * 10 + (ch - '0');
    }

    if (result < 100 or result > 599) return null;

    assert(result >= 100 and result <= 599);
    return result;
}

/// Parse Content-Length header value from a raw header block.
/// Searches for Content-Length header (case-insensitive) and extracts value.
/// Returns null if not found, invalid, or has leading zeros.
/// TigerStyle: Returns u64 for Content-Length (can exceed 4GB), bounded loops.
pub fn parseContentLength(header: []const u8) ?u64 {
    if (header.len == 0) return null;

    // Case-insensitive search for Content-Length
    const lower_header = "content-length:";
    var search_pos: usize = 0;
    const max_search_iterations: u32 = config.MAX_HEADER_SIZE_BYTES;
    var iterations: u32 = 0;

    while (search_pos + lower_header.len < header.len and iterations < max_search_iterations) : (iterations += 1) {
        const candidate = header[search_pos .. search_pos + lower_header.len];
        var matches = true;
        for (candidate, 0..) |ch, i| {
            const lower_ch = if (ch >= 'A' and ch <= 'Z') ch + 32 else ch;
            if (lower_ch != lower_header[i]) {
                matches = false;
                break;
            }
        }

        if (matches) {
            // Found header, parse value
            var value_start = search_pos + lower_header.len;

            // Skip whitespace
            while (value_start < header.len and (header[value_start] == ' ' or header[value_start] == '\t')) {
                value_start += 1;
            }

            // Find end of value (until \r, \n, or end)
            var value_end = value_start;
            while (value_end < header.len and header[value_end] != '\r' and header[value_end] != '\n') {
                value_end += 1;
            }

            if (value_end > value_start) {
                return parseContentLengthValue(header[value_start..value_end]);
            }
            return null;
        }

        // Move to next line
        if (std.mem.indexOfScalar(u8, header[search_pos..], '\n')) |newline_offset| {
            search_pos += newline_offset + 1;
        } else {
            break;
        }
    }

    return null;
}

/// Parse Content-Length value string to u64.
/// Returns null for empty, oversized (>20 digits), non-numeric, overflow, or leading zeros.
/// TigerStyle: Explicit overflow detection, no hidden behavior.
pub fn parseContentLengthValue(value: []const u8) ?u64 {
    if (value.len == 0) return null;
    if (value.len > 20) return null; // u64 max is 20 digits

    // TigerStyle: Reject leading zeros (except single "0")
    // "007" is invalid, "0" is valid
    if (value.len > 1 and value[0] == '0') return null;

    var result: u64 = 0;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return null;

        // Check for overflow on multiply
        const mul_result = @mulWithOverflow(result, 10);
        if (mul_result[1] != 0) return null;

        // Check for overflow on add
        const add_result = @addWithOverflow(mul_result[0], ch - '0');
        if (add_result[1] != 0) return null;

        result = add_result[0];
    }
    return result;
}

// =============================================================================
// Tests
// =============================================================================

test "parse GET request" {
    const request_text =
        "GET /api/users HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    var parser = Parser.init();
    try parser.parseHeaders(request_text);

    try std.testing.expectEqual(Method.GET, parser.request.method);
    try std.testing.expectEqualStrings("/api/users", parser.request.path);
    try std.testing.expectEqual(Version.@"HTTP/1.1", parser.request.version);
    try std.testing.expectEqualStrings("example.com", parser.request.headers.get("Host").?);
}

test "parse POST request with headers" {
    const request_text =
        "POST /api/login HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 42\r\n" ++
        "\r\n";

    var parser = Parser.init();
    try parser.parseHeaders(request_text);

    try std.testing.expectEqual(Method.POST, parser.request.method);
    try std.testing.expectEqualStrings("/api/login", parser.request.path);
    try std.testing.expectEqual(@as(u8, 3), parser.request.headers.count);
}

test "reject empty request" {
    var parser = Parser.init();
    try std.testing.expectError(error.EmptyRequest, parser.parseHeaders(""));
}

test "reject invalid method" {
    var parser = Parser.init();
    try std.testing.expectError(error.InvalidMethod, parser.parseHeaders("INVALID / HTTP/1.1\r\n\r\n"));
}

test "reject missing header terminator" {
    var parser = Parser.init();
    try std.testing.expectError(error.MalformedHeader, parser.parseHeaders("GET / HTTP/1.1\r\nHost: x\r\n"));
}

test "parse OPTIONS * request (asterisk-form)" {
    const request_text =
        "OPTIONS * HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    var parser = Parser.init();
    try parser.parseHeaders(request_text);

    try std.testing.expectEqual(Method.OPTIONS, parser.request.method);
    try std.testing.expectEqualStrings("*", parser.request.path);
    try std.testing.expectEqual(Version.@"HTTP/1.1", parser.request.version);
}

test "reject asterisk-form for non-OPTIONS method" {
    var parser = Parser.init();
    try std.testing.expectError(error.InvalidUri, parser.parseHeaders("GET * HTTP/1.1\r\n\r\n"));

    parser.reset();
    try std.testing.expectError(error.InvalidUri, parser.parseHeaders("POST * HTTP/1.1\r\n\r\n"));
}

// =============================================================================
// Response Parsing Tests
// =============================================================================

test "parseStatusCode valid" {
    try std.testing.expectEqual(@as(?u16, 200), parseStatusCode("HTTP/1.1 200 OK\r\n"));
    try std.testing.expectEqual(@as(?u16, 404), parseStatusCode("HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expectEqual(@as(?u16, 500), parseStatusCode("HTTP/1.1 500 Internal Server Error\r\n"));
    try std.testing.expectEqual(@as(?u16, 100), parseStatusCode("HTTP/1.1 100 Continue\r\n"));
    try std.testing.expectEqual(@as(?u16, 599), parseStatusCode("HTTP/1.1 599 Custom\r\n"));
}

test "parseStatusCode invalid" {
    try std.testing.expectEqual(@as(?u16, null), parseStatusCode(""));
    try std.testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 ABC\r\n"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 99 Too Low\r\n"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusCode("HTTP/1.1 600 Too High\r\n"));
}

test "parseContentLength valid" {
    try std.testing.expectEqual(@as(?u64, 1234), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"));
    try std.testing.expectEqual(@as(?u64, 0), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    try std.testing.expectEqual(@as(?u64, 1234), parseContentLength("HTTP/1.1 200 OK\r\ncontent-length: 1234\r\n\r\n"));
    try std.testing.expectEqual(@as(?u64, 1234), parseContentLength("HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 1234\r\n\r\n"));
}

test "parseContentLength missing" {
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("HTTP/1.1 200 OK\r\n\r\n"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength(""));
}

test "parseContentLength rejects leading zeros" {
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 007\r\n\r\n"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("HTTP/1.1 200 OK\r\nContent-Length: 0123\r\n\r\n"));
}

test "parseContentLengthValue valid" {
    try std.testing.expectEqual(@as(?u64, 0), parseContentLengthValue("0"));
    try std.testing.expectEqual(@as(?u64, 1234), parseContentLengthValue("1234"));
    try std.testing.expectEqual(@as(?u64, 18446744073709551615), parseContentLengthValue("18446744073709551615")); // u64 max
}

test "parseContentLengthValue invalid" {
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue(""));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("abc"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("12a34"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("18446744073709551616")); // overflow
}

test "parseContentLengthValue rejects leading zeros" {
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("007"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("00"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLengthValue("0123"));
}

// =============================================================================
// Request Line Validation Tests (RFC 7230)
// =============================================================================

test "reject multiple spaces in request line" {
    var parser = Parser.init();
    // Multiple spaces between method and URI
    try std.testing.expectError(error.MalformedRequestLine, parser.parseHeaders("GET  /path HTTP/1.1\r\nHost: example.com\r\n\r\n"));

    parser.reset();
    // Multiple spaces between URI and version
    try std.testing.expectError(error.MalformedRequestLine, parser.parseHeaders("GET /path  HTTP/1.1\r\nHost: example.com\r\n\r\n"));

    parser.reset();
    // Leading space before method
    try std.testing.expectError(error.MalformedRequestLine, parser.parseHeaders(" GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"));

    parser.reset();
    // Multiple spaces everywhere
    try std.testing.expectError(error.MalformedRequestLine, parser.parseHeaders("GET  /path  HTTP/1.1\r\nHost: example.com\r\n\r\n"));
}

test "reject HTTP/1.1 request without Host header" {
    var parser = Parser.init();
    // HTTP/1.1 requires Host header (RFC 7230 Section 5.4)
    try std.testing.expectError(error.MissingHostHeader, parser.parseHeaders("GET /path HTTP/1.1\r\n\r\n"));

    parser.reset();
    // HTTP/1.1 with empty headers still needs Host
    try std.testing.expectError(error.MissingHostHeader, parser.parseHeaders("POST /api HTTP/1.1\r\nContent-Length: 0\r\n\r\n"));
}

test "allow HTTP/1.0 request without Host header" {
    var parser = Parser.init();
    // HTTP/1.0 does not require Host header
    try parser.parseHeaders("GET /path HTTP/1.0\r\n\r\n");

    try std.testing.expectEqual(Method.GET, parser.request.method);
    try std.testing.expectEqualStrings("/path", parser.request.path);
    try std.testing.expectEqual(Version.@"HTTP/1.0", parser.request.version);
}

// =============================================================================
// HTTP Request Smuggling Prevention Tests (RFC 7230 Section 3.3.3)
// =============================================================================

test "reject CL-TE: Content-Length and Transfer-Encoding together" {
    var parser = Parser.init();
    // RFC 7230 Section 3.3.3: Ambiguous message length - reject to prevent smuggling
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 42\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";
    try std.testing.expectError(error.AmbiguousMessageLength, parser.parseHeaders(request));
}

test "accept chunked Transfer-Encoding and set body_framing" {
    var parser = Parser.init();
    // Chunked Transfer-Encoding is now supported
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";
    try parser.parseHeaders(request);
    try std.testing.expect(parser.body_framing == .chunked);
    try std.testing.expectEqualStrings("chunked", parser.request.headers.getTransferEncoding().?);
}

test "accept chunked Transfer-Encoding case insensitive" {
    var parser = Parser.init();
    // Case insensitive detection of "chunked"
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: CHUNKED\r\n" ++
        "\r\n";
    try parser.parseHeaders(request);
    try std.testing.expect(parser.body_framing == .chunked);

    parser.reset();
    const request2 =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: Chunked\r\n" ++
        "\r\n";
    try parser.parseHeaders(request2);
    try std.testing.expect(parser.body_framing == .chunked);
}

test "reject duplicate Content-Length with different values" {
    var parser = Parser.init();
    // Duplicate Content-Length with different values is a smuggling vector
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 42\r\n" ++
        "Content-Length: 100\r\n" ++
        "\r\n";
    try std.testing.expectError(error.DuplicateContentLength, parser.parseHeaders(request));
}

test "allow duplicate Content-Length with same values" {
    var parser = Parser.init();
    // Same value is allowed (some proxies may add it redundantly)
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 42\r\n" ++
        "Content-Length: 42\r\n" ++
        "\r\n";
    try parser.parseHeaders(request);
    try std.testing.expectEqualStrings("42", parser.request.headers.getContentLength().?);
}

test "reject obs-fold line continuation with space" {
    var parser = Parser.init();
    // RFC 7230 Section 3.2.4: obs-fold is deprecated, reject to prevent smuggling
    const request =
        "GET /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "X-Custom: value\r\n" ++
        " continued\r\n" ++ // obs-fold with space
        "\r\n";
    try std.testing.expectError(error.MalformedHeader, parser.parseHeaders(request));
}

test "reject obs-fold line continuation with tab" {
    var parser = Parser.init();
    // obs-fold with HTAB should also be rejected
    const request =
        "GET /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "X-Custom: value\r\n" ++
        "\tcontinued\r\n" ++ // obs-fold with tab
        "\r\n";
    try std.testing.expectError(error.MalformedHeader, parser.parseHeaders(request));
}

test "allow identity Transfer-Encoding" {
    var parser = Parser.init();
    // identity Transfer-Encoding is valid and does not imply chunked
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: identity\r\n" ++
        "\r\n";
    try parser.parseHeaders(request);
    try std.testing.expectEqualStrings("identity", parser.request.headers.getTransferEncoding().?);
}

test "containsIgnoreCase helper" {
    try std.testing.expect(containsIgnoreCase("chunked", "chunked"));
    try std.testing.expect(containsIgnoreCase("CHUNKED", "chunked"));
    try std.testing.expect(containsIgnoreCase("Chunked", "chunked"));
    try std.testing.expect(containsIgnoreCase("gzip, chunked", "chunked"));
    try std.testing.expect(containsIgnoreCase("chunked, gzip", "chunked"));
    try std.testing.expect(!containsIgnoreCase("gzip", "chunked"));
    try std.testing.expect(!containsIgnoreCase("", "chunked"));
    try std.testing.expect(containsIgnoreCase("abc", ""));
}

// =============================================================================
// Body Framing Tests
// =============================================================================

test "body_framing set to content_length for Content-Length header" {
    var parser = Parser.init();
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 42\r\n" ++
        "\r\n";
    try parser.parseHeaders(request);
    try std.testing.expect(parser.body_framing == .content_length);
    try std.testing.expectEqual(@as(u64, 42), parser.body_framing.getContentLength().?);
}

test "body_framing set to none for GET request without body" {
    var parser = Parser.init();
    const request =
        "GET /api/users HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";
    try parser.parseHeaders(request);
    try std.testing.expect(parser.body_framing == .none);
}

test "body_framing set to none for identity Transfer-Encoding" {
    var parser = Parser.init();
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: identity\r\n" ++
        "\r\n";
    try parser.parseHeaders(request);
    // Per RFC 9112 Section 6.1, "identity" is obsolete; treated as no body framing
    try std.testing.expect(parser.body_framing == .none);
}

test "body_framing reset clears to none" {
    var parser = Parser.init();
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 100\r\n" ++
        "\r\n";
    try parser.parseHeaders(request);
    try std.testing.expect(parser.body_framing == .content_length);

    parser.reset();
    try std.testing.expect(parser.body_framing == .none);
}

test "reject invalid Content-Length value" {
    var parser = Parser.init();
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: abc\r\n" ++
        "\r\n";
    try std.testing.expectError(error.InvalidContentLength, parser.parseHeaders(request));
}

test "reject Content-Length with leading zeros" {
    var parser = Parser.init();
    const request =
        "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 007\r\n" ++
        "\r\n";
    try std.testing.expectError(error.InvalidContentLength, parser.parseHeaders(request));
}
