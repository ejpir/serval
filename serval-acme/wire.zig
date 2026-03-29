//! ACME wire-level request/response helpers.
//!
//! Bridges parsed ACME endpoint URLs with serval-core request primitives and
//! provides bounded header extraction helpers.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const config = core.config;
const types = core.types;
const HeaderMap = core.HeaderMap;
const Method = types.Method;
const client = @import("client.zig");
const jws = @import("jws.zig");

const max_host_bytes = config.ACME_MAX_DOMAIN_NAME_LEN;
const max_path_bytes = config.ACME_MAX_DIRECTORY_URL_BYTES;
const max_body_bytes = config.ACME_MAX_JWS_BODY_BYTES;

/// Errors raised while parsing or validating wire-format URL and ACME response data.
/// This set includes invalid URL parts, oversize host or path data, invalid ports, oversized bodies, and missing ACME headers.
/// Match on the named tags instead of relying on any numeric representation.
pub const Error = error{
    InvalidUrl,
    InvalidScheme,
    InvalidHost,
    HostTooLong,
    PathTooLong,
    InvalidPort,
    BodyTooLarge,
    MissingReplayNonceHeader,
    MissingLocationHeader,
};

/// Parsed URL data stored inline with fixed-size host and path buffers.
/// Use `init()` to obtain the default `/` path, then read host and path through the accessor methods.
/// `host()` and `path()` return slices into the embedded storage, and `toUpstream()` converts the parsed values into an upstream descriptor.
pub const ParsedUrl = struct {
    tls: bool = false,
    host_len: u16 = 0,
    host_bytes: [max_host_bytes]u8 = [_]u8{0} ** max_host_bytes,
    port: u16 = 0,
    path_len: u16 = 1,
    path_bytes: [max_path_bytes]u8 = [_]u8{0} ** max_path_bytes,

    /// Returns a default `ParsedUrl` with the path initialized to `/`.
    /// The host is empty, the port is unset, and `tls` defaults to `false`.
    /// `max_host_bytes` and `max_path_bytes` must both be greater than zero.
    pub fn init() ParsedUrl {
        assert(max_host_bytes > 0);
        assert(max_path_bytes > 0);
        var parsed = ParsedUrl{};
        parsed.path_bytes[0] = '/';
        parsed.path_len = 1;
        return parsed;
    }

    /// Returns the parsed host as a slice into the internal host buffer.
    /// `self.host_len` must not exceed `max_host_bytes`.
    /// The returned slice is borrowed from `self`; this function does not allocate or copy.
    pub fn host(self: *const ParsedUrl) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.host_len <= max_host_bytes);
        return self.host_bytes[0..self.host_len];
    }

    /// Returns the parsed path as a slice into the internal path buffer.
    /// `self.path_len` must be at least 1 and no larger than `max_path_bytes`; `init()` sets the default path to `/`.
    /// The returned slice is borrowed from `self` and remains valid only while the buffer is unchanged.
    pub fn path(self: *const ParsedUrl) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.path_len >= 1);
        assert(self.path_len <= max_path_bytes);
        return self.path_bytes[0..self.path_len];
    }

    /// Builds an upstream descriptor from this parsed URL.
    /// `self` must already contain a non-empty host and a port greater than zero.
    /// The returned value borrows the host slice from `self`, copies the port and TLS flag, and always uses HTTP/1.
    pub fn toUpstream(self: *const ParsedUrl, idx: config.UpstreamIndex) types.Upstream {
        assert(@intFromPtr(self) != 0);
        assert(self.host_len > 0);
        assert(self.port > 0);

        return .{
            .host = self.host(),
            .port = self.port,
            .idx = idx,
            .tls = self.tls,
            .http_protocol = .h1,
        };
    }
};

/// A wire-format HTTP request built from parsed URL data and optional payload metadata.
/// `body` and header value slices are borrowed; the caller owns the backing storage.
/// Public helpers on this type expose the request path, upstream endpoint, and body presence.
pub const WireRequest = struct {
    method: Method,
    target: ParsedUrl,
    body: []const u8 = &.{},
    content_type: ?[]const u8 = null,
    accept: []const u8 = "application/json",

    /// Converts the request target into an upstream endpoint using `idx`.
    /// The target must contain a valid host before conversion.
    /// The returned upstream value is derived from the stored parsed URL and does not allocate.
    pub fn upstream(self: *const WireRequest, idx: config.UpstreamIndex) types.Upstream {
        assert(@intFromPtr(self) != 0);
        assert(self.target.host_len > 0);
        return self.target.toUpstream(idx);
    }

    /// Returns the request path from the parsed target URL.
    /// The target must already contain a non-empty path component.
    /// The returned slice aliases the stored target URL and remains valid with `self`.
    pub fn path(self: *const WireRequest) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.target.path_len >= 1);
        return self.target.path();
    }

    /// Returns `true` when the request body is non-empty.
    /// The body length is expected to stay within `max_body_bytes`.
    /// This does not inspect headers or method; it only checks the payload slice.
    pub fn hasBody(self: *const WireRequest) bool {
        assert(@intFromPtr(self) != 0);
        assert(self.body.len <= max_body_bytes);
        return self.body.len > 0;
    }
};

/// Errors that can occur while composing a signed request.
/// This combines wire-format validation errors with JWS serialization errors.
/// Callers can handle request-building and serialization failures through one error set.
pub const ComposeSignedRequestError = Error || jws.Error;

/// Parses an absolute URL from `url` into a `ParsedUrl`.
/// The input must contain a valid `http://` or `https://` URL string.
/// Propagates the validation and parsing errors produced by `parseAbsoluteUrlSlice`.
pub fn parseAbsoluteUrl(url: *const client.Url) Error!ParsedUrl {
    assert(@intFromPtr(url) != 0);
    const parsed = try parseAbsoluteUrlSlice(url.slice());
    assert(parsed.host_len > 0);
    return parsed;
}

/// Parses an absolute `http://` or `https://` URL from `value` into a `ParsedUrl`.
/// Requires a non-empty input with a supported scheme and an authority component.
/// Returns `error.InvalidUrl`, `error.InvalidScheme`, or other parse errors from authority and path handling.
pub fn parseAbsoluteUrlSlice(value: []const u8) Error!ParsedUrl {
    assert(max_host_bytes > 0);
    assert(max_path_bytes > 0);
    if (value.len == 0) return error.InvalidUrl;
    if (value.len > std.math.maxInt(u32)) return error.InvalidUrl;
    const value_len: u32 = @intCast(value.len);

    var parsed = ParsedUrl.init();

    var cursor: u32 = 0;
    if (std.mem.startsWith(u8, value, "https://")) {
        parsed.tls = true;
        parsed.port = 443;
        cursor = "https://".len;
    } else if (std.mem.startsWith(u8, value, "http://")) {
        parsed.tls = false;
        parsed.port = 80;
        cursor = "http://".len;
    } else {
        return error.InvalidScheme;
    }

    if (cursor >= value_len) return error.InvalidHost;

    var authority_end: u32 = cursor;
    while (authority_end < value_len) : (authority_end += 1) {
        const c = value[@intCast(authority_end)];
        if (c == '/' or c == '?' or c == '#') break;
    }

    const authority = value[@intCast(cursor)..@intCast(authority_end)];
    try parseAuthority(&parsed, authority);

    const path_source = if (authority_end < value_len) value[@intCast(authority_end)..] else "";
    try setPathFromRemainder(&parsed, path_source);

    assert(parsed.host_len > 0);
    assert(parsed.path_len >= 1);
    return parsed;
}

/// Builds a HEAD request to the directory's `new_nonce_url`.
/// The request body is empty and the content type is unset.
/// The returned request borrows the directory URL data; the caller must keep `directory` valid.
pub fn buildNewNonceRequest(directory: *const client.Directory) Error!WireRequest {
    assert(@intFromPtr(directory) != 0);
    var request = WireRequest{
        .method = .HEAD,
        .target = try parseAbsoluteUrl(&directory.new_nonce_url),
        .body = &.{},
        .content_type = null,
    };
    assert(request.body.len == 0);
    return request;
}

/// Builds a POST request to the directory's `new_account_url` with a JOSE JSON body.
/// Rejects bodies larger than `max_body_bytes` with `error.BodyTooLarge`.
/// The returned request stores `body` by slice reference; the caller retains ownership of the backing memory.
pub fn buildNewAccountRequest(directory: *const client.Directory, body: []const u8) Error!WireRequest {
    assert(@intFromPtr(directory) != 0);

    if (body.len > max_body_bytes) return error.BodyTooLarge;
    var request = WireRequest{
        .method = .POST,
        .target = try parseAbsoluteUrl(&directory.new_account_url),
        .body = body,
        .content_type = "application/jose+json",
    };
    assert(request.body.len == body.len);
    return request;
}

/// Builds a POST request to the directory's `new_order_url` with a JOSE JSON body.
/// Rejects bodies larger than `max_body_bytes` with `error.BodyTooLarge`.
/// The returned request stores `body` by slice reference; the caller retains ownership of the backing memory.
pub fn buildNewOrderRequest(directory: *const client.Directory, body: []const u8) Error!WireRequest {
    assert(@intFromPtr(directory) != 0);

    if (body.len > max_body_bytes) return error.BodyTooLarge;
    var request = WireRequest{
        .method = .POST,
        .target = try parseAbsoluteUrl(&directory.new_order_url),
        .body = body,
        .content_type = "application/jose+json",
    };
    assert(request.body.len == body.len);
    return request;
}

/// Builds a POST request to `target_url` with a JOSE JSON body.
/// Rejects bodies larger than `max_body_bytes` with `error.BodyTooLarge`.
/// The returned request stores `body` by slice reference; the caller retains ownership of the backing memory.
pub fn buildSignedPostRequest(target_url: *const client.Url, body: []const u8) Error!WireRequest {
    assert(@intFromPtr(target_url) != 0);

    if (body.len > max_body_bytes) return error.BodyTooLarge;
    var request = WireRequest{
        .method = .POST,
        .target = try parseAbsoluteUrl(target_url),
        .body = body,
        .content_type = "application/jose+json",
    };
    assert(request.body.len == body.len);
    return request;
}

/// Serializes `params` into `body_out` as flattened JWS and builds a new-account POST request.
/// `body_out` must provide enough space for the serialized payload.
/// Returns a request-building or JWS serialization error from the underlying helpers.
pub fn composeNewAccountRequestWithFlattenedJws(
    body_out: []u8,
    directory: *const client.Directory,
    params: jws.FlattenedJwsParams,
) ComposeSignedRequestError!WireRequest {
    assert(@intFromPtr(directory) != 0);

    const body = try jws.serializeFlattenedJws(body_out, params);
    assert(body.len <= max_body_bytes);
    return try buildNewAccountRequest(directory, body);
}

/// Serializes `params` into `body_out` as flattened JWS and builds a new-order POST request.
/// `body_out` must provide enough space for the serialized payload.
/// Returns a request-building or JWS serialization error from the underlying helpers.
pub fn composeNewOrderRequestWithFlattenedJws(
    body_out: []u8,
    directory: *const client.Directory,
    params: jws.FlattenedJwsParams,
) ComposeSignedRequestError!WireRequest {
    assert(@intFromPtr(directory) != 0);

    const body = try jws.serializeFlattenedJws(body_out, params);
    assert(body.len <= max_body_bytes);
    return try buildNewOrderRequest(directory, body);
}

/// Serializes `params` into `body_out` as flattened JWS and builds a signed POST request.
/// `body_out` must provide enough space for the serialized payload.
/// Returns a request-building or JWS serialization error from the underlying helpers.
pub fn composeSignedPostRequestWithFlattenedJws(
    body_out: []u8,
    target_url: *const client.Url,
    params: jws.FlattenedJwsParams,
) ComposeSignedRequestError!WireRequest {
    assert(@intFromPtr(target_url) != 0);

    const body = try jws.serializeFlattenedJws(body_out, params);
    assert(body.len <= max_body_bytes);
    return try buildSignedPostRequest(target_url, body);
}

/// Extracts the `Replay-Nonce` header from `headers` and parses it as a nonce.
/// Returns `error.MissingReplayNonceHeader` when the header is absent.
/// Propagates nonce parsing errors from `client.parseReplayNonceHeader`.
pub fn parseReplayNonceFromHeaders(headers: *const HeaderMap) (Error || client.Error)!client.ReplayNonce {
    assert(@intFromPtr(headers) != 0);
    assert(config.MAX_HEADERS > 0);

    const replay_nonce_value = headers.get("replay-nonce") orelse return error.MissingReplayNonceHeader;
    return client.parseReplayNonceHeader(replay_nonce_value);
}

/// Extracts the `Location` header from `headers` and parses it as a client URL.
/// Returns `error.MissingLocationHeader` when the header is absent.
/// Propagates URL parsing errors from `client.parseLocationHeader`.
pub fn parseLocationFromHeaders(headers: *const HeaderMap) (Error || client.Error)!client.Url {
    assert(@intFromPtr(headers) != 0);
    assert(config.MAX_HEADERS > 0);

    const location_value = headers.get("location") orelse return error.MissingLocationHeader;
    return client.parseLocationHeader(location_value);
}

fn parseAuthority(parsed: *ParsedUrl, authority: []const u8) Error!void {
    assert(@intFromPtr(parsed) != 0);
    assert(parsed.path_len >= 1);

    if (authority.len == 0) return error.InvalidHost;

    const first_colon = std.mem.indexOfScalar(u8, authority, ':');
    const last_colon = std.mem.lastIndexOfScalar(u8, authority, ':');

    var host_part = authority;
    if (first_colon) |idx| {
        if (last_colon.? != idx) return error.InvalidHost;
        host_part = authority[0..idx];

        const port_part = authority[idx + 1 ..];
        parsed.port = try parsePort(port_part);
    }

    try validateHost(host_part);
    if (host_part.len > max_host_bytes) return error.HostTooLong;

    @memset(parsed.host_bytes[0..], 0);
    @memcpy(parsed.host_bytes[0..host_part.len], host_part);
    parsed.host_len = @intCast(host_part.len);
    assert(parsed.host_len > 0);
}

fn parsePort(port_part: []const u8) Error!u16 {
    assert(std.math.maxInt(u16) == 65535);
    assert(max_host_bytes > 0);
    if (port_part.len == 0) return error.InvalidPort;
    if (port_part.len > 5) return error.InvalidPort;
    const port_len: u8 = @intCast(port_part.len);

    var port_value: u32 = 0;
    var index: u8 = 0;
    while (index < port_len) : (index += 1) {
        const c = port_part[@intCast(index)];
        if (c < '0' or c > '9') return error.InvalidPort;

        port_value = port_value * 10 + (c - '0');
        if (port_value > std.math.maxInt(u16)) return error.InvalidPort;
    }

    if (port_value == 0) return error.InvalidPort;
    return @intCast(port_value);
}

fn validateHost(host: []const u8) Error!void {
    assert(max_host_bytes > 0);
    if (host.len == 0) return error.InvalidHost;
    if (host.len > std.math.maxInt(u16)) return error.InvalidHost;
    const host_len: u16 = @intCast(host.len);

    var index: u16 = 0;
    while (index < host_len) : (index += 1) {
        const c = host[@intCast(index)];
        const is_digit = c >= '0' and c <= '9';
        const is_upper = c >= 'A' and c <= 'Z';
        const is_lower = c >= 'a' and c <= 'z';
        const is_dot = c == '.';
        const is_dash = c == '-';

        if (!is_digit and !is_upper and !is_lower and !is_dot and !is_dash) {
            return error.InvalidHost;
        }
    }

    if (host[0] == '.' or host[host.len - 1] == '.') return error.InvalidHost;
    assert(host[0] != '.' and host[host.len - 1] != '.');
}

fn setPathFromRemainder(parsed: *ParsedUrl, remainder: []const u8) Error!void {
    assert(@intFromPtr(parsed) != 0);
    assert(parsed.host_len <= max_host_bytes);

    if (remainder.len == 0) {
        parsed.path_bytes[0] = '/';
        parsed.path_len = 1;
        return;
    }

    if (remainder.len > std.math.maxInt(u16)) return error.PathTooLong;
    var fragment_index: u16 = @intCast(remainder.len);
    if (std.mem.indexOfScalar(u8, remainder, '#')) |idx| {
        fragment_index = @intCast(idx);
    }

    const no_fragment = remainder[0..fragment_index];
    if (no_fragment.len == 0) {
        parsed.path_bytes[0] = '/';
        parsed.path_len = 1;
        return;
    }

    if (no_fragment[0] == '/') {
        try setPath(parsed, no_fragment);
        return;
    }

    if (no_fragment[0] == '?') {
        if (no_fragment.len + 1 > max_path_bytes) return error.PathTooLong;
        @memset(parsed.path_bytes[0..], 0);
        parsed.path_bytes[0] = '/';
        @memcpy(parsed.path_bytes[1 .. 1 + no_fragment.len], no_fragment);
        parsed.path_len = @intCast(no_fragment.len + 1);
        return;
    }

    return error.InvalidUrl;
}

fn setPath(parsed: *ParsedUrl, path: []const u8) Error!void {
    assert(@intFromPtr(parsed) != 0);
    assert(max_path_bytes > 0);

    if (path.len == 0) return error.PathTooLong;
    if (path.len > max_path_bytes) return error.PathTooLong;
    assert(path[0] == '/');

    @memset(parsed.path_bytes[0..], 0);
    @memcpy(parsed.path_bytes[0..path.len], path);
    parsed.path_len = @intCast(path.len);
    assert(parsed.path_len == @as(u16, @intCast(path.len)));
}

test "parseAbsoluteUrlSlice parses https default port and path" {
    const parsed = try parseAbsoluteUrlSlice("https://acme.example/directory");
    try std.testing.expect(parsed.tls);
    try std.testing.expectEqual(@as(u16, 443), parsed.port);
    try std.testing.expectEqualStrings("acme.example", parsed.host());
    try std.testing.expectEqualStrings("/directory", parsed.path());
}

test "parseAbsoluteUrlSlice parses explicit port and query" {
    const parsed = try parseAbsoluteUrlSlice("http://acme.example:4001/new-order?profile=dev");
    try std.testing.expect(!parsed.tls);
    try std.testing.expectEqual(@as(u16, 4001), parsed.port);
    try std.testing.expectEqualStrings("acme.example", parsed.host());
    try std.testing.expectEqualStrings("/new-order?profile=dev", parsed.path());
}

test "parseAbsoluteUrlSlice rejects invalid scheme" {
    try std.testing.expectError(error.InvalidScheme, parseAbsoluteUrlSlice("ftp://acme.example/test"));
}

test "buildNewOrderRequest creates POST jose request" {
    var directory = client.Directory{};
    try directory.new_order_url.set("https://acme.example/new-order");

    const request = try buildNewOrderRequest(&directory, "{\"jws\":1}");
    try std.testing.expectEqual(Method.POST, request.method);
    try std.testing.expectEqualStrings("/new-order", request.path());
    try std.testing.expect(request.hasBody());
    try std.testing.expectEqualStrings("application/jose+json", request.content_type.?);
}

test "parseReplayNonceFromHeaders extracts replay nonce" {
    var headers = HeaderMap.init();
    try headers.put("Replay-Nonce", "abc_DEF-123");

    const nonce = try parseReplayNonceFromHeaders(&headers);
    try std.testing.expectEqualStrings("abc_DEF-123", nonce.slice());
}

test "parseReplayNonceFromHeaders reports missing header" {
    var headers = HeaderMap.init();
    try std.testing.expectError(error.MissingReplayNonceHeader, parseReplayNonceFromHeaders(&headers));
}

test "composeNewAccountRequestWithFlattenedJws composes body and target" {
    var directory = client.Directory{};
    try directory.new_account_url.set("https://acme.example/new-account");

    var body_out: [max_body_bytes]u8 = undefined;
    const request = try composeNewAccountRequestWithFlattenedJws(&body_out, &directory, .{
        .protected_header_json = "{}",
        .payload_json = "{\"contact\":[\"mailto:ops@example.com\"]}",
        .signature = &.{ 0x01, 0x02, 0x03 },
    });

    try std.testing.expectEqual(Method.POST, request.method);
    try std.testing.expectEqualStrings("/new-account", request.path());
    try std.testing.expect(request.body.len > 0);
}
