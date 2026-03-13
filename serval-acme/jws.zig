//! ACME JWS serialization scaffolding.
//!
//! ACME requests are carried in flattened JSON JWS envelopes. This file provides
//! bounded serializers for protected headers (jwk/kid forms), signing input, and
//! flattened envelope rendering.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const client = @import("client.zig");

const max_jws_body_bytes: usize = config.ACME_MAX_JWS_BODY_BYTES;
const max_signature_bytes: usize = config.ACME_MAX_JWS_SIGNATURE_BYTES;
const max_jwk_coordinate_b64_bytes: usize = 96;

pub const Error = error{
    InvalidNonce,
    InvalidUrl,
    InvalidKid,
    InvalidJwkCoordinate,
    JwkCoordinateTooLong,
    EmptyProtectedHeader,
    ProtectedHeaderTooLarge,
    PayloadTooLarge,
    SignatureTooLarge,
    InvalidSignature,
    OutputTooSmall,
};

pub const JwkP256 = struct {
    x_len: u8 = 0,
    x_bytes: [max_jwk_coordinate_b64_bytes]u8 = [_]u8{0} ** max_jwk_coordinate_b64_bytes,
    y_len: u8 = 0,
    y_bytes: [max_jwk_coordinate_b64_bytes]u8 = [_]u8{0} ** max_jwk_coordinate_b64_bytes,

    pub fn setCoordinates(self: *JwkP256, x_b64u: []const u8, y_b64u: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);

        try validateCoordinate(x_b64u);
        try validateCoordinate(y_b64u);

        @memset(self.x_bytes[0..], 0);
        @memset(self.y_bytes[0..], 0);
        @memcpy(self.x_bytes[0..x_b64u.len], x_b64u);
        @memcpy(self.y_bytes[0..y_b64u.len], y_b64u);

        self.x_len = @intCast(x_b64u.len);
        self.y_len = @intCast(y_b64u.len);
    }

    pub fn xSlice(self: *const JwkP256) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.x_len <= max_jwk_coordinate_b64_bytes);
        return self.x_bytes[0..self.x_len];
    }

    pub fn ySlice(self: *const JwkP256) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.y_len <= max_jwk_coordinate_b64_bytes);
        return self.y_bytes[0..self.y_len];
    }
};

pub const ProtectedHeaderJwkParams = struct {
    nonce: *const client.ReplayNonce,
    url: *const client.Url,
    jwk: *const JwkP256,
};

pub const ProtectedHeaderKidParams = struct {
    nonce: *const client.ReplayNonce,
    url: *const client.Url,
    kid: *const client.Url,
};

pub const FlattenedJwsParams = struct {
    protected_header_json: []const u8,
    payload_json: []const u8,
    signature: []const u8,
};

pub fn serializeProtectedHeaderWithJwk(
    out: []u8,
    params: ProtectedHeaderJwkParams,
) Error![]const u8 {
    assert(@intFromPtr(params.nonce) != 0);
    assert(@intFromPtr(params.url) != 0);
    assert(@intFromPtr(params.jwk) != 0);

    const nonce = params.nonce.slice();
    const url = params.url.slice();
    const x = params.jwk.xSlice();
    const y = params.jwk.ySlice();

    if (nonce.len == 0) return error.InvalidNonce;
    if (url.len == 0) return error.InvalidUrl;
    try validateBase64UrlText(nonce, error.InvalidNonce);
    validateJsonString(url) catch return error.InvalidUrl;

    if (x.len == 0 or y.len == 0) return error.InvalidJwkCoordinate;

    var cursor: usize = 0;
    cursor = try appendChunk(out, cursor, "{\"alg\":\"ES256\",\"nonce\":\"");
    cursor = try appendChunk(out, cursor, nonce);
    cursor = try appendChunk(out, cursor, "\",\"url\":\"");
    cursor = try appendChunk(out, cursor, url);
    cursor = try appendChunk(out, cursor, "\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"");
    cursor = try appendChunk(out, cursor, x);
    cursor = try appendChunk(out, cursor, "\",\"y\":\"");
    cursor = try appendChunk(out, cursor, y);
    cursor = try appendChunk(out, cursor, "\"}}");

    if (cursor > max_jws_body_bytes) return error.ProtectedHeaderTooLarge;
    assert(cursor > 0);
    return out[0..cursor];
}

pub fn serializeProtectedHeaderWithKid(
    out: []u8,
    params: ProtectedHeaderKidParams,
) Error![]const u8 {
    assert(@intFromPtr(params.nonce) != 0);
    assert(@intFromPtr(params.url) != 0);
    assert(@intFromPtr(params.kid) != 0);

    const nonce = params.nonce.slice();
    const url = params.url.slice();
    const kid = params.kid.slice();

    if (nonce.len == 0) return error.InvalidNonce;
    if (url.len == 0) return error.InvalidUrl;
    if (kid.len == 0) return error.InvalidKid;

    try validateBase64UrlText(nonce, error.InvalidNonce);
    validateJsonString(url) catch return error.InvalidUrl;
    validateJsonString(kid) catch return error.InvalidKid;

    var cursor: usize = 0;
    cursor = try appendChunk(out, cursor, "{\"alg\":\"ES256\",\"nonce\":\"");
    cursor = try appendChunk(out, cursor, nonce);
    cursor = try appendChunk(out, cursor, "\",\"url\":\"");
    cursor = try appendChunk(out, cursor, url);
    cursor = try appendChunk(out, cursor, "\",\"kid\":\"");
    cursor = try appendChunk(out, cursor, kid);
    cursor = try appendChunk(out, cursor, "\"}");

    if (cursor > max_jws_body_bytes) return error.ProtectedHeaderTooLarge;
    assert(cursor > 0);
    return out[0..cursor];
}

pub fn serializeSigningInput(
    out: []u8,
    protected_header_json: []const u8,
    payload_json: []const u8,
) Error![]const u8 {
    if (protected_header_json.len == 0) return error.EmptyProtectedHeader;
    if (protected_header_json.len > max_jws_body_bytes) return error.ProtectedHeaderTooLarge;
    if (payload_json.len > max_jws_body_bytes) return error.PayloadTooLarge;

    const protected_b64_len = base64UrlEncodedLenNoPad(protected_header_json.len);
    const payload_b64_len = base64UrlEncodedLenNoPad(payload_json.len);

    var total_len: usize = 0;
    total_len = try checkedAdd(total_len, protected_b64_len);
    total_len = try checkedAdd(total_len, 1);
    total_len = try checkedAdd(total_len, payload_b64_len);

    if (total_len > out.len) return error.OutputTooSmall;
    if (total_len > max_jws_body_bytes) return error.OutputTooSmall;

    var cursor: usize = 0;
    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[cursor .. cursor + protected_b64_len],
        protected_header_json,
    );
    cursor += protected_b64_len;

    out[cursor] = '.';
    cursor += 1;

    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[cursor .. cursor + payload_b64_len],
        payload_json,
    );
    cursor += payload_b64_len;

    assert(cursor == total_len);
    return out[0..cursor];
}

pub fn serializeFlattenedJws(out: []u8, params: FlattenedJwsParams) Error![]const u8 {
    if (params.protected_header_json.len == 0) return error.EmptyProtectedHeader;
    if (params.protected_header_json.len > max_jws_body_bytes) return error.ProtectedHeaderTooLarge;
    if (params.payload_json.len > max_jws_body_bytes) return error.PayloadTooLarge;
    if (params.signature.len == 0) return error.InvalidSignature;
    if (params.signature.len > max_signature_bytes) return error.SignatureTooLarge;

    const protected_b64_len = base64UrlEncodedLenNoPad(params.protected_header_json.len);
    const payload_b64_len = base64UrlEncodedLenNoPad(params.payload_json.len);
    const signature_b64_len = base64UrlEncodedLenNoPad(params.signature.len);

    var total_len: usize = 0;
    total_len = try checkedAdd(total_len, "{\"protected\":\"".len);
    total_len = try checkedAdd(total_len, protected_b64_len);
    total_len = try checkedAdd(total_len, "\",\"payload\":\"".len);
    total_len = try checkedAdd(total_len, payload_b64_len);
    total_len = try checkedAdd(total_len, "\",\"signature\":\"".len);
    total_len = try checkedAdd(total_len, signature_b64_len);
    total_len = try checkedAdd(total_len, "\"}".len);

    if (total_len > out.len) return error.OutputTooSmall;
    if (total_len > max_jws_body_bytes) return error.OutputTooSmall;

    var cursor: usize = 0;
    cursor = try appendChunk(out, cursor, "{\"protected\":\"");

    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[cursor .. cursor + protected_b64_len],
        params.protected_header_json,
    );
    cursor += protected_b64_len;

    cursor = try appendChunk(out, cursor, "\",\"payload\":\"");

    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[cursor .. cursor + payload_b64_len],
        params.payload_json,
    );
    cursor += payload_b64_len;

    cursor = try appendChunk(out, cursor, "\",\"signature\":\"");

    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[cursor .. cursor + signature_b64_len],
        params.signature,
    );
    cursor += signature_b64_len;

    cursor = try appendChunk(out, cursor, "\"}");
    assert(cursor == total_len);

    return out[0..cursor];
}

fn validateCoordinate(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidJwkCoordinate;
    if (value.len > max_jwk_coordinate_b64_bytes) return error.JwkCoordinateTooLong;
    try validateBase64UrlText(value, error.InvalidJwkCoordinate);
}

fn validateBase64UrlText(value: []const u8, invalid_err: Error) Error!void {
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const c = value[index];
        const is_digit = c >= '0' and c <= '9';
        const is_upper = c >= 'A' and c <= 'Z';
        const is_lower = c >= 'a' and c <= 'z';
        const is_dash = c == '-';
        const is_underscore = c == '_';

        if (!is_digit and !is_upper and !is_lower and !is_dash and !is_underscore) {
            return invalid_err;
        }
    }
}

fn validateJsonString(value: []const u8) Error!void {
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const c = value[index];
        if (c < 0x20) return error.InvalidUrl;
        if (c == '"') return error.InvalidUrl;
        if (c == '\\') return error.InvalidUrl;
    }
}

fn appendChunk(out: []u8, cursor: usize, chunk: []const u8) Error!usize {
    assert(cursor <= out.len);

    if (cursor + chunk.len > out.len) return error.OutputTooSmall;
    @memcpy(out[cursor..][0..chunk.len], chunk);

    return cursor + chunk.len;
}

fn checkedAdd(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.OutputTooSmall;
}

fn base64UrlEncodedLenNoPad(input_len: usize) usize {
    return std.base64.url_safe_no_pad.Encoder.calcSize(input_len);
}

test "JwkP256 setCoordinates stores values" {
    var jwk = JwkP256{};
    try jwk.setCoordinates("abc_DEF-123", "xyz-987_Q");

    try std.testing.expectEqualStrings("abc_DEF-123", jwk.xSlice());
    try std.testing.expectEqualStrings("xyz-987_Q", jwk.ySlice());
}

test "JwkP256 rejects invalid base64url coordinates" {
    var jwk = JwkP256{};
    try std.testing.expectError(error.InvalidJwkCoordinate, jwk.setCoordinates("abc+def", "xyz"));
}

test "serializeProtectedHeaderWithJwk emits deterministic json" {
    var nonce = client.ReplayNonce{};
    try nonce.set("abc_DEF-123");

    var url = client.Url{};
    try url.set("https://acme.example/new-order");

    var jwk = JwkP256{};
    try jwk.setCoordinates("abc_DEF", "xyz_123");

    var out: [512]u8 = undefined;
    const encoded = try serializeProtectedHeaderWithJwk(&out, .{
        .nonce = &nonce,
        .url = &url,
        .jwk = &jwk,
    });

    try std.testing.expectEqualStrings(
        "{\"alg\":\"ES256\",\"nonce\":\"abc_DEF-123\",\"url\":\"https://acme.example/new-order\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc_DEF\",\"y\":\"xyz_123\"}}",
        encoded,
    );
}

test "serializeProtectedHeaderWithKid emits deterministic json" {
    var nonce = client.ReplayNonce{};
    try nonce.set("abc_DEF-123");

    var url = client.Url{};
    try url.set("https://acme.example/order/1");

    var kid = client.Url{};
    try kid.set("https://acme.example/account/1");

    var out: [512]u8 = undefined;
    const encoded = try serializeProtectedHeaderWithKid(&out, .{
        .nonce = &nonce,
        .url = &url,
        .kid = &kid,
    });

    try std.testing.expectEqualStrings(
        "{\"alg\":\"ES256\",\"nonce\":\"abc_DEF-123\",\"url\":\"https://acme.example/order/1\",\"kid\":\"https://acme.example/account/1\"}",
        encoded,
    );
}

test "serializeSigningInput encodes protected and payload" {
    var out: [256]u8 = undefined;
    const signing_input = try serializeSigningInput(&out, "{}", "{\"a\":1}");

    try std.testing.expectEqualStrings("e30.eyJhIjoxfQ", signing_input);
}

test "serializeFlattenedJws encodes flattened jws object" {
    var out: [512]u8 = undefined;
    const encoded = try serializeFlattenedJws(&out, .{
        .protected_header_json = "{}",
        .payload_json = "{\"a\":1}",
        .signature = &.{ 0x01, 0x02, 0x03 },
    });

    try std.testing.expectEqualStrings(
        "{\"protected\":\"e30\",\"payload\":\"eyJhIjoxfQ\",\"signature\":\"AQID\"}",
        encoded,
    );
}

test "serializeFlattenedJws rejects too-small output buffer" {
    var out: [16]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        serializeFlattenedJws(&out, .{
            .protected_header_json = "{}",
            .payload_json = "{\"a\":1}",
            .signature = &.{ 0x01, 0x02, 0x03 },
        }),
    );
}
