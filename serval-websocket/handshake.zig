//! WebSocket HTTP/1.1 Handshake Helpers
//!
//! RFC 6455 opening handshake validation and accept-key generation.
//! TigerStyle: Zero allocation, explicit validation, bounded parsing.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const types = serval_core.types;

const Request = types.Request;
const BodyFraming = types.BodyFraming;

/// RFC 6455 Section 1.3: Magic GUID appended to Sec-WebSocket-Key.
pub const websocket_accept_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// RFC 6455 Section 4.1: Client key decodes to 16 bytes.
pub const websocket_client_nonce_size_bytes: u32 = 16;

/// SHA-1 digest (20 bytes) base64-encodes to 28 bytes.
pub const websocket_accept_key_size_bytes: u32 = 28;

/// Maximum input length for key + GUID when computing accept value.
const websocket_accept_input_size_bytes: u32 = 128;

pub const HandshakeError = error{
    InvalidMethod,
    MissingConnectionHeader,
    MissingUpgradeHeader,
    InvalidUpgradeHeader,
    MissingWebSocketKey,
    InvalidWebSocketKey,
    MissingWebSocketVersion,
    UnsupportedWebSocketVersion,
    UnexpectedMessageBody,
    InvalidStatusCode,
    MissingAcceptHeader,
    InvalidAcceptHeader,
};

/// Returns true when the request looks like a WebSocket upgrade attempt.
/// This is intentionally broader than full validation so malformed attempts
/// still fail closed in the server path.
pub fn looksLikeWebSocketUpgradeRequest(request: *const Request) bool {
    assert(@intFromPtr(request) != 0);
    assert(request.path.len <= std.math.maxInt(u32));

    if (request.method != .GET) return false;

    if (request.headers.get("Sec-WebSocket-Key") != null) return true;
    if (request.headers.get("Sec-WebSocket-Version") != null) return true;

    if (request.headers.get("Upgrade")) |upgrade| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "websocket")) {
            return true;
        }
    }

    if (request.headers.getConnection()) |connection| {
        if (headerHasToken(connection, "upgrade")) return true;
    }

    return false;
}

/// Validate a client WebSocket opening handshake request.
pub fn validateClientRequest(
    request: *const Request,
    body_framing: BodyFraming,
) HandshakeError!void {
    assert(@intFromPtr(request) != 0);
    assert(request.path.len <= std.math.maxInt(u32));

    if (request.method != .GET) return error.InvalidMethod;
    if (body_framing != .none) return error.UnexpectedMessageBody;

    const connection = request.headers.getConnection() orelse
        return error.MissingConnectionHeader;
    if (!headerHasToken(connection, "upgrade")) {
        return error.MissingConnectionHeader;
    }

    const upgrade = request.headers.get("Upgrade") orelse
        return error.MissingUpgradeHeader;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "websocket")) {
        return error.InvalidUpgradeHeader;
    }

    const key = request.headers.get("Sec-WebSocket-Key") orelse
        return error.MissingWebSocketKey;
    try validateClientKey(key);

    const version = request.headers.get("Sec-WebSocket-Version") orelse
        return error.MissingWebSocketVersion;
    if (!std.mem.eql(u8, std.mem.trim(u8, version, " \t"), "13")) {
        return error.UnsupportedWebSocketVersion;
    }
}

/// Compute RFC 6455 Sec-WebSocket-Accept value from a validated client key.
pub fn computeAcceptKey(
    client_key: []const u8,
    out: *[websocket_accept_key_size_bytes]u8,
) HandshakeError![]const u8 {
    assert(client_key.len > 0);

    try validateClientKey(client_key);

    var sha_input: [websocket_accept_input_size_bytes]u8 =
        std.mem.zeroes([websocket_accept_input_size_bytes]u8);
    const input_len = client_key.len + websocket_accept_guid.len;
    assert(input_len <= sha_input.len);

    @memcpy(sha_input[0..client_key.len], client_key);
    @memcpy(sha_input[client_key.len..][0..websocket_accept_guid.len], websocket_accept_guid);

    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(sha_input[0..input_len], &digest, .{});

    const encoded = std.base64.standard.Encoder.encode(out, &digest);
    assert(encoded.len == websocket_accept_key_size_bytes);
    return encoded;
}

/// Validate an upstream server WebSocket switching-protocols response.
pub fn validateServerResponse(
    status: u16,
    raw_headers: []const u8,
    expected_accept_key: []const u8,
) HandshakeError!void {
    assert(raw_headers.len > 0);
    assert(expected_accept_key.len == websocket_accept_key_size_bytes);

    if (status != 101) return error.InvalidStatusCode;

    const connection = getHeaderValue(raw_headers, "Connection") orelse
        return error.MissingConnectionHeader;
    if (!headerHasToken(connection, "upgrade")) {
        return error.MissingConnectionHeader;
    }

    const upgrade = getHeaderValue(raw_headers, "Upgrade") orelse
        return error.MissingUpgradeHeader;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "websocket")) {
        return error.InvalidUpgradeHeader;
    }

    const accept = getHeaderValue(raw_headers, "Sec-WebSocket-Accept") orelse
        return error.MissingAcceptHeader;
    if (!std.mem.eql(u8, std.mem.trim(u8, accept, " \t"), expected_accept_key)) {
        return error.InvalidAcceptHeader;
    }
}

/// Returns true if a comma-separated header value contains the given token.
pub fn headerHasToken(value: []const u8, token: []const u8) bool {
    assert(token.len > 0);
    assert(value.len <= std.math.maxInt(u32));

    var parts = std.mem.splitScalar(u8, value, ',');
    var iterations: u32 = 0;
    const max_iterations: u32 = 64;
    assert(max_iterations > 0);

    while (parts.next()) |part| : (iterations += 1) {
        if (iterations >= max_iterations) break;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) {
            return true;
        }
    }

    return false;
}

/// Get a header value from a raw HTTP/1.1 header block.
/// Stops at the first empty line and ignores any bytes after the header section.
pub fn getHeaderValue(raw_headers: []const u8, name: []const u8) ?[]const u8 {
    assert(raw_headers.len > 0);
    assert(name.len > 0);

    var lines = std.mem.splitSequence(u8, raw_headers, "\r\n");
    _ = lines.next() orelse return null; // Skip status line

    var iterations: u32 = 0;
    const max_iterations: u32 = 128;

    while (lines.next()) |line| : (iterations += 1) {
        if (iterations >= max_iterations) return null;
        if (line.len == 0) return null;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (colon == 0) continue;

        const header_name = line[0..colon];
        if (!std.ascii.eqlIgnoreCase(header_name, name)) continue;

        const value_start = colon + 1;
        return std.mem.trim(u8, line[value_start..], " \t");
    }

    return null;
}

fn validateClientKey(client_key: []const u8) HandshakeError!void {
    assert(client_key.len > 0);

    const trimmed = std.mem.trim(u8, client_key, " \t");
    if (trimmed.len > websocket_accept_input_size_bytes) return error.InvalidWebSocketKey;
    assert(trimmed.len <= websocket_accept_input_size_bytes);
    if (trimmed.len == 0) return error.InvalidWebSocketKey;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(trimmed) catch {
        return error.InvalidWebSocketKey;
    };
    if (decoded_len != websocket_client_nonce_size_bytes) {
        return error.InvalidWebSocketKey;
    }

    var nonce: [websocket_client_nonce_size_bytes]u8 = undefined;
    std.base64.standard.Decoder.decode(&nonce, trimmed) catch {
        return error.InvalidWebSocketKey;
    };
}

test "looksLikeWebSocketUpgradeRequest detects malformed attempts for fail-closed handling" {
    var request = Request{
        .method = .GET,
        .path = "/ws",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "example.com");
    try request.headers.put("Upgrade", "websocket");

    try std.testing.expect(looksLikeWebSocketUpgradeRequest(&request));
}

test "validateClientRequest accepts RFC 6455 request" {
    var request = Request{
        .method = .GET,
        .path = "/chat",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "server.example.com");
    try request.headers.put("Upgrade", "websocket");
    try request.headers.put("Connection", "Upgrade");
    try request.headers.put("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try request.headers.put("Sec-WebSocket-Version", "13");

    try validateClientRequest(&request, .none);
}

test "validateClientRequest rejects missing upgrade token" {
    var request = Request{
        .method = .GET,
        .path = "/chat",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "server.example.com");
    try request.headers.put("Upgrade", "websocket");
    try request.headers.put("Connection", "keep-alive");
    try request.headers.put("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try request.headers.put("Sec-WebSocket-Version", "13");

    const result = validateClientRequest(&request, .none);
    try std.testing.expectError(error.MissingConnectionHeader, result);
}

test "validateClientRequest rejects invalid websocket key" {
    var request = Request{
        .method = .GET,
        .path = "/chat",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "server.example.com");
    try request.headers.put("Upgrade", "websocket");
    try request.headers.put("Connection", "Upgrade");
    try request.headers.put("Sec-WebSocket-Key", "invalid");
    try request.headers.put("Sec-WebSocket-Version", "13");

    const result = validateClientRequest(&request, .none);
    try std.testing.expectError(error.InvalidWebSocketKey, result);
}

test "validateClientRequest rejects unsupported version" {
    var request = Request{
        .method = .GET,
        .path = "/chat",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "server.example.com");
    try request.headers.put("Upgrade", "websocket");
    try request.headers.put("Connection", "Upgrade");
    try request.headers.put("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try request.headers.put("Sec-WebSocket-Version", "12");

    const result = validateClientRequest(&request, .none);
    try std.testing.expectError(error.UnsupportedWebSocketVersion, result);
}

test "validateClientRequest rejects request body framing" {
    var request = Request{
        .method = .GET,
        .path = "/chat",
        .version = .@"HTTP/1.1",
        .headers = .{},
    };
    try request.headers.put("Host", "server.example.com");
    try request.headers.put("Upgrade", "websocket");
    try request.headers.put("Connection", "Upgrade");
    try request.headers.put("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    try request.headers.put("Sec-WebSocket-Version", "13");

    const result = validateClientRequest(&request, .{ .content_length = 1 });
    try std.testing.expectError(error.UnexpectedMessageBody, result);
}

test "computeAcceptKey matches RFC example" {
    var out: [websocket_accept_key_size_bytes]u8 = undefined;
    const accept = try computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", &out);

    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "headerHasToken matches comma-separated tokens case-insensitively" {
    try std.testing.expect(headerHasToken("keep-alive, Upgrade", "upgrade"));
    try std.testing.expect(headerHasToken("Upgrade", "upgrade"));
    try std.testing.expect(!headerHasToken("keep-alive", "upgrade"));
}

test "getHeaderValue finds headers and stops at body" {
    const headers =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: value\r\n" ++
        "\r\n" ++
        "body-bytes";

    try std.testing.expectEqualStrings("websocket", getHeaderValue(headers, "Upgrade").?);
    try std.testing.expectEqualStrings("Upgrade", getHeaderValue(headers, "Connection").?);
    try std.testing.expect(getHeaderValue(headers, "X-Missing") == null);
}

test "validateServerResponse accepts valid switching protocols response" {
    const headers =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";

    try validateServerResponse(101, headers, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

test "validateServerResponse rejects wrong accept key" {
    const headers =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: wrong\r\n" ++
        "\r\n";

    const result = validateServerResponse(101, headers, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    try std.testing.expectError(error.InvalidAcceptHeader, result);
}

test "validateClientRequest matrix" {
    const cases = [_]struct {
        method: types.Method,
        connection: []const u8,
        upgrade: []const u8,
        key: []const u8,
        version: []const u8,
        body_framing: BodyFraming,
        expected_error: ?HandshakeError,
    }{
        .{
            .method = .GET,
            .connection = "Upgrade",
            .upgrade = "websocket",
            .key = "dGhlIHNhbXBsZSBub25jZQ==",
            .version = "13",
            .body_framing = .none,
            .expected_error = null,
        },
        .{
            .method = .POST,
            .connection = "Upgrade",
            .upgrade = "websocket",
            .key = "dGhlIHNhbXBsZSBub25jZQ==",
            .version = "13",
            .body_framing = .none,
            .expected_error = error.InvalidMethod,
        },
        .{
            .method = .GET,
            .connection = "keep-alive",
            .upgrade = "websocket",
            .key = "dGhlIHNhbXBsZSBub25jZQ==",
            .version = "13",
            .body_framing = .none,
            .expected_error = error.MissingConnectionHeader,
        },
        .{
            .method = .GET,
            .connection = "Upgrade",
            .upgrade = "websocket",
            .key = "invalid",
            .version = "13",
            .body_framing = .none,
            .expected_error = error.InvalidWebSocketKey,
        },
        .{
            .method = .GET,
            .connection = "Upgrade",
            .upgrade = "websocket",
            .key = "dGhlIHNhbXBsZSBub25jZQ==",
            .version = "12",
            .body_framing = .none,
            .expected_error = error.UnsupportedWebSocketVersion,
        },
        .{
            .method = .GET,
            .connection = "Upgrade",
            .upgrade = "websocket",
            .key = "dGhlIHNhbXBsZSBub25jZQ==",
            .version = "13",
            .body_framing = .{ .content_length = 1 },
            .expected_error = error.UnexpectedMessageBody,
        },
    };

    var index: usize = 0;
    while (index < cases.len) : (index += 1) {
        var request = Request{
            .method = cases[index].method,
            .path = "/chat",
            .version = .@"HTTP/1.1",
            .headers = .{},
        };
        try request.headers.put("Host", "server.example.com");
        try request.headers.put("Upgrade", cases[index].upgrade);
        try request.headers.put("Connection", cases[index].connection);
        try request.headers.put("Sec-WebSocket-Key", cases[index].key);
        try request.headers.put("Sec-WebSocket-Version", cases[index].version);

        const result = validateClientRequest(&request, cases[index].body_framing);
        if (cases[index].expected_error) |expected_error| {
            try std.testing.expectError(expected_error, result);
        } else {
            try result;
        }
    }
}

test "fuzz headerHasToken and getHeaderValue remain bounded" {
    var prng = std.Random.DefaultPrng.init(0x53a9_6b11_9112_44d1);
    const random = prng.random();

    var value_buf: [256]u8 = undefined;
    var headers_buf: [1024]u8 = undefined;

    var iteration: u32 = 0;
    while (iteration < 512) : (iteration += 1) {
        const value_len = random.uintLessThan(usize, value_buf.len + 1);
        random.bytes(value_buf[0..value_len]);
        _ = headerHasToken(value_buf[0..value_len], "upgrade");

        const body_len = random.uintLessThan(usize, 64) + 1;
        random.bytes(headers_buf[0..body_len]);
        _ = getHeaderValue(headers_buf[0..body_len], "Connection");
    }
}
