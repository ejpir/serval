//! ACME JWS serialization scaffolding.
//!
//! ACME requests are carried in flattened JSON JWS envelopes. This file provides
//! bounded serializers for protected headers (jwk/kid forms), signing input, and
//! flattened envelope rendering.

const std = @import("std");
const assert = std.debug.assert;
const client = @import("client.zig");
const limits = @import("limits.zig");

const max_jws_body_bytes = limits.max_jws_body_bytes;
const max_signature_bytes = limits.max_jws_signature_bytes;
const max_jwk_coordinate_b64_bytes = 96;
const JwsLen = u16;

/// Error set used by ACME JWS header, signing-input, and flattened-JWS
/// serialization helpers.
/// These errors cover invalid nonce, URL, kid, and JWK coordinate values as
/// well as size checks for headers, payloads, signatures, and output buffers.
/// Serialization helpers return these errors directly when validation or
/// bounded-buffer checks fail.
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

/// Fixed-size storage for a P-256 JSON Web Key coordinate pair.
/// The struct keeps `x` and `y` in caller-managed memory and exposes them
/// through slices that reference the internal buffers.
/// Call `setCoordinates` to validate and populate both coordinates; call
/// `xSlice` and `ySlice` to read back the stored base64url text.
/// The public API is bounded and does not allocate.
pub const JwkP256 = struct {
    x_len: u8 = 0,
    x_bytes: [max_jwk_coordinate_b64_bytes]u8 = [_]u8{0} ** max_jwk_coordinate_b64_bytes,
    y_len: u8 = 0,
    y_bytes: [max_jwk_coordinate_b64_bytes]u8 = [_]u8{0} ** max_jwk_coordinate_b64_bytes,

    /// Stores validated base64url `x` and `y` coordinates in the fixed buffers.
    /// Both inputs must be non-empty, must fit within the coordinate limit, and
    /// must contain only unpadded base64url characters.
    /// On success, the previous contents are cleared before the new values are
    /// copied in place; no allocation is performed.
    /// Returns `error.InvalidJwkCoordinate` for empty or malformed input and
    /// `error.JwkCoordinateTooLong` when either coordinate exceeds the limit.
    pub fn setCoordinates(self: *JwkP256, x_b64u: []const u8, y_b64u: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.x_len <= max_jwk_coordinate_b64_bytes);

        try validateCoordinate(x_b64u);
        try validateCoordinate(y_b64u);

        @memset(self.x_bytes[0..], 0);
        @memset(self.y_bytes[0..], 0);
        @memcpy(self.x_bytes[0..x_b64u.len], x_b64u);
        @memcpy(self.y_bytes[0..y_b64u.len], y_b64u);

        self.x_len = @intCast(x_b64u.len);
        self.y_len = @intCast(y_b64u.len);
        assert(self.x_len == @as(u8, @intCast(x_b64u.len)));
    }

    /// Returns the stored `y` coordinate as a base64url slice without padding.
    /// The slice aliases the struct's internal buffer and is valid until the
    /// `JwkP256` value is mutated or discarded.
    /// Preconditions are enforced with assertions: the receiver must be non-null
    /// and the stored length must stay within the fixed coordinate buffer.
    pub fn xSlice(self: *const JwkP256) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.x_len <= max_jwk_coordinate_b64_bytes);
        return self.x_bytes[0..self.x_len];
    }

    /// Returns the stored `x` coordinate as a base64url slice without padding.
    /// The slice aliases the struct's internal buffer and is valid until the
    /// `JwkP256` value is mutated or discarded.
    /// Preconditions are enforced with assertions: the receiver must be non-null
    /// and the stored length must stay within the fixed coordinate buffer.
    pub fn ySlice(self: *const JwkP256) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.y_len <= max_jwk_coordinate_b64_bytes);
        return self.y_bytes[0..self.y_len];
    }
};

/// Borrowed inputs for building a protected header that carries a JWK.
/// The nonce, URL, and JWK are not owned here; they must remain valid for
/// the duration of any serialization that reads them.
/// Use this with `serializeProtectedHeaderWithJwk` when the ACME request
/// authenticates with an embedded P-256 public key.
pub const ProtectedHeaderJwkParams = struct {
    nonce: *const client.ReplayNonce,
    url: *const client.Url,
    jwk: *const JwkP256,
};

/// Inputs for building a protected header with a `kid` reference.
/// `nonce`, `url`, and `kid` are borrowed pointers to existing client values and are not owned here.
/// The referenced values must remain valid for the duration of serialization.
pub const ProtectedHeaderKidParams = struct {
    nonce: *const client.ReplayNonce,
    url: *const client.Url,
    kid: *const client.Url,
};

/// Inputs for serializing a flattened JWS object.
/// The fields are borrowed slices; the caller retains ownership of the underlying data.
/// Each field must contain the JSON fragment to encode for the protected header, payload, and signature.
pub const FlattenedJwsParams = struct {
    protected_header_json: []const u8,
    payload_json: []const u8,
    signature: []const u8,
};

/// Serializes an ACME protected header containing `alg`, `nonce`, `url`, and an embedded EC JWK.
/// `nonce` must be valid base64url text, `url` must be valid JSON string content, and both JWK coordinates must be present.
/// The embedded JWK is emitted as `{"kty":"EC","crv":"P-256",...}` using the coordinate slices from `params.jwk`.
/// Returns validation or size errors if any required field is empty, malformed, or does not fit in `out`.
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

    var cursor: JwsLen = 0;
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
    return out[0..@intCast(cursor)];
}

/// Serializes an ACME protected header containing `alg`, `nonce`, `url`, and `kid`.
/// `nonce` must be valid base64url text, while `url` and `kid` must be valid JSON string content.
/// The returned slice aliases `out`; the caller owns the buffer and must keep it alive for the result's lifetime.
/// Returns validation or size errors if any field is empty, malformed, or does not fit in `out`.
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

    var cursor: JwsLen = 0;
    cursor = try appendChunk(out, cursor, "{\"alg\":\"ES256\",\"nonce\":\"");
    cursor = try appendChunk(out, cursor, nonce);
    cursor = try appendChunk(out, cursor, "\",\"url\":\"");
    cursor = try appendChunk(out, cursor, url);
    cursor = try appendChunk(out, cursor, "\",\"kid\":\"");
    cursor = try appendChunk(out, cursor, kid);
    cursor = try appendChunk(out, cursor, "\"}");

    if (cursor > max_jws_body_bytes) return error.ProtectedHeaderTooLarge;
    assert(cursor > 0);
    return out[0..@intCast(cursor)];
}

/// Serializes JWS signing input into `out` as `<protected>.<payload>`.
/// Both inputs are base64url-encoded without padding and concatenated with a single `'.'` separator.
/// Rejects empty or oversized protected headers and oversized payloads before writing.
/// Returns `error.OutputTooSmall` if the output buffer cannot hold the encoded input.
pub fn serializeSigningInput(
    out: []u8,
    protected_header_json: []const u8,
    payload_json: []const u8,
) Error![]const u8 {
    assert(max_jws_body_bytes > 0);
    if (protected_header_json.len == 0) return error.EmptyProtectedHeader;
    if (protected_header_json.len > max_jws_body_bytes) return error.ProtectedHeaderTooLarge;
    if (payload_json.len > max_jws_body_bytes) return error.PayloadTooLarge;

    const protected_input_len = std.math.cast(JwsLen, protected_header_json.len) orelse return error.ProtectedHeaderTooLarge;
    const payload_input_len = std.math.cast(JwsLen, payload_json.len) orelse return error.PayloadTooLarge;
    const protected_b64_len = base64UrlEncodedLenNoPad(protected_input_len);
    const payload_b64_len = base64UrlEncodedLenNoPad(payload_input_len);

    var total_len: JwsLen = 0;
    total_len = try checkedAdd(total_len, protected_b64_len);
    total_len = try checkedAdd(total_len, 1);
    total_len = try checkedAdd(total_len, payload_b64_len);

    if (total_len > out.len) return error.OutputTooSmall;
    if (total_len > max_jws_body_bytes) return error.OutputTooSmall;

    var cursor: JwsLen = 0;
    const protected_end = std.math.add(JwsLen, cursor, protected_b64_len) catch return error.OutputTooSmall;
    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[@intCast(cursor)..@intCast(protected_end)],
        protected_header_json,
    );
    cursor = protected_end;

    out[@intCast(cursor)] = '.';
    cursor += 1;

    const payload_end = std.math.add(JwsLen, cursor, payload_b64_len) catch return error.OutputTooSmall;
    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[@intCast(cursor)..@intCast(payload_end)],
        payload_json,
    );
    cursor = payload_end;

    assert(cursor == total_len);
    return out[0..@intCast(cursor)];
}

/// Serializes a flattened JWS object into `out` and returns the written slice.
/// The protected header, payload, and signature are base64url-encoded without padding and wrapped in the flattened JSON shape.
/// Returns `error.EmptyProtectedHeader`, `error.InvalidSignature`, or size-related errors for empty or oversized inputs.
/// Returns `error.OutputTooSmall` when `out` cannot hold the full serialized object.
pub fn serializeFlattenedJws(out: []u8, params: FlattenedJwsParams) Error![]const u8 {
    assert(max_signature_bytes > 0);
    if (params.protected_header_json.len == 0) return error.EmptyProtectedHeader;
    if (params.protected_header_json.len > max_jws_body_bytes) return error.ProtectedHeaderTooLarge;
    if (params.payload_json.len > max_jws_body_bytes) return error.PayloadTooLarge;
    if (params.signature.len == 0) return error.InvalidSignature;
    if (params.signature.len > max_signature_bytes) return error.SignatureTooLarge;

    const protected_input_len = std.math.cast(JwsLen, params.protected_header_json.len) orelse return error.ProtectedHeaderTooLarge;
    const payload_input_len = std.math.cast(JwsLen, params.payload_json.len) orelse return error.PayloadTooLarge;
    const signature_input_len = std.math.cast(JwsLen, params.signature.len) orelse return error.SignatureTooLarge;
    const protected_b64_len = base64UrlEncodedLenNoPad(protected_input_len);
    const payload_b64_len = base64UrlEncodedLenNoPad(payload_input_len);
    const signature_b64_len = base64UrlEncodedLenNoPad(signature_input_len);

    var total_len: JwsLen = 0;
    total_len = try checkedAdd(total_len, "{\"protected\":\"".len);
    total_len = try checkedAdd(total_len, protected_b64_len);
    total_len = try checkedAdd(total_len, "\",\"payload\":\"".len);
    total_len = try checkedAdd(total_len, payload_b64_len);
    total_len = try checkedAdd(total_len, "\",\"signature\":\"".len);
    total_len = try checkedAdd(total_len, signature_b64_len);
    total_len = try checkedAdd(total_len, "\"}".len);

    if (total_len > out.len) return error.OutputTooSmall;
    if (total_len > max_jws_body_bytes) return error.OutputTooSmall;

    var cursor: JwsLen = 0;
    cursor = try appendChunk(out, cursor, "{\"protected\":\"");

    const protected_end = std.math.add(JwsLen, cursor, protected_b64_len) catch return error.OutputTooSmall;
    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[@intCast(cursor)..@intCast(protected_end)],
        params.protected_header_json,
    );
    cursor = protected_end;

    cursor = try appendChunk(out, cursor, "\",\"payload\":\"");

    const payload_end = std.math.add(JwsLen, cursor, payload_b64_len) catch return error.OutputTooSmall;
    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[@intCast(cursor)..@intCast(payload_end)],
        params.payload_json,
    );
    cursor = payload_end;

    cursor = try appendChunk(out, cursor, "\",\"signature\":\"");

    const signature_end = std.math.add(JwsLen, cursor, signature_b64_len) catch return error.OutputTooSmall;
    _ = std.base64.url_safe_no_pad.Encoder.encode(
        out[@intCast(cursor)..@intCast(signature_end)],
        params.signature,
    );
    cursor = signature_end;

    cursor = try appendChunk(out, cursor, "\"}");
    assert(cursor == total_len);

    return out[0..@intCast(cursor)];
}

fn validateCoordinate(value: []const u8) Error!void {
    assert(max_jwk_coordinate_b64_bytes > 0);
    assert(max_jwk_coordinate_b64_bytes <= std.math.maxInt(u8));
    if (value.len == 0) return error.InvalidJwkCoordinate;
    if (value.len > max_jwk_coordinate_b64_bytes) return error.JwkCoordinateTooLong;
    try validateBase64UrlText(value, error.InvalidJwkCoordinate);
}

fn validateBase64UrlText(value: []const u8, invalid_err: Error) Error!void {
    assert(max_jws_body_bytes > 0);
    assert(value.len <= max_jws_body_bytes);
    const value_len = std.math.cast(JwsLen, value.len) orelse return invalid_err;
    var index: JwsLen = 0;
    while (index < value_len) : (index += 1) {
        const c = value[@intCast(index)];
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
    assert(max_jws_body_bytes > 0);
    assert(value.len <= max_jws_body_bytes);
    const value_len = std.math.cast(JwsLen, value.len) orelse return error.InvalidUrl;
    var index: JwsLen = 0;
    while (index < value_len) : (index += 1) {
        const c = value[@intCast(index)];
        if (c < 0x20) return error.InvalidUrl;
        if (c == '"') return error.InvalidUrl;
        if (c == '\\') return error.InvalidUrl;
    }
}

fn appendChunk(out: []u8, cursor: JwsLen, chunk: []const u8) Error!JwsLen {
    assert(out.len <= std.math.maxInt(JwsLen));
    assert(cursor <= @as(JwsLen, @intCast(out.len)));
    assert(chunk.len <= out.len);

    const chunk_len = std.math.cast(JwsLen, chunk.len) orelse return error.OutputTooSmall;
    const end = std.math.add(JwsLen, cursor, chunk_len) catch return error.OutputTooSmall;
    if (end > @as(JwsLen, @intCast(out.len))) return error.OutputTooSmall;
    @memcpy(out[@intCast(cursor)..][0..@intCast(chunk_len)], chunk);

    return end;
}

fn checkedAdd(a: JwsLen, b: JwsLen) Error!JwsLen {
    assert(a <= std.math.maxInt(JwsLen));
    assert(b <= std.math.maxInt(JwsLen));
    return std.math.add(JwsLen, a, b) catch error.OutputTooSmall;
}

fn base64UrlEncodedLenNoPad(input_len: JwsLen) JwsLen {
    assert(max_jws_body_bytes > 0);
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(input_len);
    assert(encoded_len >= input_len);
    return @intCast(encoded_len);
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
