//! ACME JWS signing using in-process ECDSA P-256 keys.
//!
//! Produces flattened JWS bodies for ACME signed POST requests.

const std = @import("std");
const assert = std.debug.assert;

const client = @import("client.zig");
const jws = @import("jws.zig");
const limits = @import("limits.zig");

const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const max_body_bytes = limits.max_jws_body_bytes;
const max_sig_bytes = Scheme.Signature.encoded_length;

/// Errors returned by ACME account signing and key-authorization helpers.
/// These cover token validation, nonce and URL validation, payload and header size limits, and signing or JWK rendering failures.
/// Check the specific helper method to see which subset can be emitted on a given call.
/// Size-related errors mean the caller-provided buffers or encoded payload exceeded the module's limits.
pub const Error = error{
    InvalidNonce,
    InvalidUrl,
    InvalidKid,
    InvalidPayload,
    MissingJwkCoordinates,
    ProtectedHeaderTooLarge,
    SigningInputTooLarge,
    FlattenedTooLarge,
    SignFailed,
    InvalidToken,
    KeyAuthorizationTooLarge,
};

/// ACME account signer backed by a `Scheme.KeyPair`.
/// The value stores the private key material needed to render JWK coordinates and produce JWS payloads.
/// Methods on this type write into caller-provided buffers and return slices into those buffers.
/// No allocator is embedded in the type; ownership stays with the caller who holds the value.
pub const AccountSigner = struct {
    key_pair: Scheme.KeyPair,

    /// Generate an `AccountSigner` using randomness from `io`.
    /// This returns a signer value by copy and does not allocate.
    /// The caller owns the returned signer and is responsible for its lifetime.
    /// Panics or traps are not documented here; any failure handling is delegated to `Scheme.KeyPair.generate`.
    pub fn generate(io: std.Io) AccountSigner {
        assert(max_body_bytes > 0);
        assert(max_sig_bytes > 0);
        const key_pair = Scheme.KeyPair.generate(io);
        return .{ .key_pair = key_pair };
    }

    /// Deterministically derive an `AccountSigner` from `seed`.
    /// `seed` must have exactly `Scheme.KeyPair.seed_length` bytes.
    /// Returns a signer value by copy; no allocator is involved.
    /// Propagates any failure reported by `Scheme.KeyPair.generateDeterministic`.
    pub fn generateDeterministic(seed: [Scheme.KeyPair.seed_length]u8) !AccountSigner {
        assert(Scheme.KeyPair.seed_length > 0);
        assert(seed.len == Scheme.KeyPair.seed_length);
        const key_pair = try Scheme.KeyPair.generateDeterministic(seed);
        return .{ .key_pair = key_pair };
    }

    /// Render public key JWK coordinates (base64url, no padding) into provided buffers.
    pub fn renderJwkCoordinates(
        self: *const AccountSigner,
        out_x: []u8,
        out_y: []u8,
    ) Error!jws.JwkP256 {
        assert(@intFromPtr(self) != 0);
        assert(out_x.len > 0 and out_y.len > 0);

        const sec1 = self.key_pair.public_key.toUncompressedSec1();
        if (sec1.len != 65 or sec1[0] != 0x04) return error.MissingJwkCoordinates;

        const x_raw = sec1[1..33];
        const y_raw = sec1[33..65];

        const x_len = std.base64.url_safe_no_pad.Encoder.calcSize(x_raw.len);
        const y_len = std.base64.url_safe_no_pad.Encoder.calcSize(y_raw.len);
        if (x_len > out_x.len or y_len > out_y.len) return error.MissingJwkCoordinates;

        _ = std.base64.url_safe_no_pad.Encoder.encode(out_x[0..x_len], x_raw);
        _ = std.base64.url_safe_no_pad.Encoder.encode(out_y[0..y_len], y_raw);

        var jwk_pub = jws.JwkP256{};
        jwk_pub.setCoordinates(out_x[0..x_len], out_y[0..y_len]) catch return error.MissingJwkCoordinates;
        return jwk_pub;
    }

    /// Build flattened JWS body using `jwk` header (newAccount flow).
    pub fn signWithJwk(
        self: *const AccountSigner,
        out_body: []u8,
        nonce: *const client.ReplayNonce,
        url: *const client.Url,
        payload_json: []const u8,
    ) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(nonce) != 0);
        assert(@intFromPtr(url) != 0);

        var x_buf: [96]u8 = undefined;
        var y_buf: [96]u8 = undefined;
        const jwk_pub = try self.renderJwkCoordinates(&x_buf, &y_buf);

        var protected_buf: [max_body_bytes]u8 = undefined;
        const protected = jws.serializeProtectedHeaderWithJwk(&protected_buf, .{
            .nonce = nonce,
            .url = url,
            .jwk = &jwk_pub,
        }) catch |err| return mapJwsError(err);

        return try self.finalizeJws(out_body, protected, payload_json);
    }

    /// Build flattened JWS body using `kid` header (post-account flows).
    pub fn signWithKid(
        self: *const AccountSigner,
        out_body: []u8,
        nonce: *const client.ReplayNonce,
        url: *const client.Url,
        kid: *const client.Url,
        payload_json: []const u8,
    ) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(nonce) != 0);
        assert(@intFromPtr(url) != 0);
        assert(@intFromPtr(kid) != 0);

        var protected_buf: [max_body_bytes]u8 = undefined;
        const protected = jws.serializeProtectedHeaderWithKid(&protected_buf, .{
            .nonce = nonce,
            .url = url,
            .kid = kid,
        }) catch |err| return mapJwsError(err);

        return try self.finalizeJws(out_body, protected, payload_json);
    }

    /// Compute the ACME key authorization string for `token` using this account key.
    /// `token` must be non-empty, at most `u16`-sized, and limited to ASCII letters, digits, `-`, and `_`.
    /// Writes into `out` and returns a slice of that buffer; the returned slice aliases caller-owned memory.
    /// Returns `error.InvalidToken` for invalid input, `error.MissingJwkCoordinates` if the public key cannot be rendered, and `error.KeyAuthorizationTooLarge` if the result does not fit.
    pub fn computeKeyAuthorization(
        self: *const AccountSigner,
        token: []const u8,
        out: []u8,
    ) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        assert(out.len > 0);
        if (token.len == 0) return error.InvalidToken;
        if (token.len > std.math.maxInt(u16)) return error.InvalidToken;
        const token_len: u16 = @intCast(token.len);

        var i: u16 = 0;
        while (i < token_len) : (i += 1) {
            const c = token[@intCast(i)];
            const is_digit = c >= '0' and c <= '9';
            const is_upper = c >= 'A' and c <= 'Z';
            const is_lower = c >= 'a' and c <= 'z';
            const is_dash = c == '-';
            const is_underscore = c == '_';
            if (!is_digit and !is_upper and !is_lower and !is_dash and !is_underscore) {
                return error.InvalidToken;
            }
        }

        var x_buf: [96]u8 = undefined;
        var y_buf: [96]u8 = undefined;
        const jwk_pub = try self.renderJwkCoordinates(&x_buf, &y_buf);

        var canonical_buf: [256]u8 = undefined;
        const canonical = std.fmt.bufPrint(
            &canonical_buf,
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}",
            .{ jwk_pub.xSlice(), jwk_pub.ySlice() },
        ) catch return error.KeyAuthorizationTooLarge;

        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(canonical, &digest, .{});

        var thumbprint_buf: [64]u8 = undefined;
        const thumbprint_len = std.base64.url_safe_no_pad.Encoder.calcSize(digest.len);
        _ = std.base64.url_safe_no_pad.Encoder.encode(thumbprint_buf[0..thumbprint_len], &digest);

        const combined = std.fmt.bufPrint(out, "{s}.{s}", .{ token, thumbprint_buf[0..thumbprint_len] }) catch {
            return error.KeyAuthorizationTooLarge;
        };
        return combined;
    }

    fn finalizeJws(
        self: *const AccountSigner,
        out_body: []u8,
        protected_header_json: []const u8,
        payload_json: []const u8,
    ) Error![]const u8 {
        assert(@intFromPtr(self) != 0);
        if (payload_json.len > max_body_bytes) return error.InvalidPayload;

        var signing_input_buf: [max_body_bytes]u8 = undefined;
        const signing_input = jws.serializeSigningInput(
            &signing_input_buf,
            protected_header_json,
            payload_json,
        ) catch |err| return mapJwsError(err);

        const signature = self.key_pair.sign(signing_input, null) catch return error.SignFailed;
        const signature_raw = signature.toBytes();
        comptime assert(signature_raw.len == max_sig_bytes);

        const body = jws.serializeFlattenedJws(out_body, .{
            .protected_header_json = protected_header_json,
            .payload_json = payload_json,
            .signature = signature_raw[0..],
        }) catch |err| return mapJwsError(err);

        return body;
    }
};

fn mapJwsError(err: anyerror) Error {
    assert(@sizeOf(@TypeOf(err)) > 0);
    assert(@sizeOf(Error) > 0);
    return switch (err) {
        error.InvalidNonce => error.InvalidNonce,
        error.InvalidUrl => error.InvalidUrl,
        error.InvalidKid => error.InvalidKid,
        error.ProtectedHeaderTooLarge, error.OutputTooSmall => error.ProtectedHeaderTooLarge,
        error.PayloadTooLarge => error.InvalidPayload,
        else => error.FlattenedTooLarge,
    };
}

test "AccountSigner signWithJwk emits flattened envelope" {
    const seed = [_]u8{7} ** Scheme.KeyPair.seed_length;
    const signer = try AccountSigner.generateDeterministic(seed);

    var nonce = client.ReplayNonce{};
    try nonce.set("abcDEF123");
    var url = client.Url{};
    try url.set("https://acme.example/new-account");

    var out: [max_body_bytes]u8 = undefined;
    const body = try signer.signWithJwk(&out, &nonce, &url, "{\"termsOfServiceAgreed\":true}");

    try std.testing.expect(std.mem.indexOf(u8, body, "\"protected\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"payload\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"signature\":\"") != null);
}

test "AccountSigner signWithKid emits flattened envelope" {
    const seed = [_]u8{9} ** Scheme.KeyPair.seed_length;
    const signer = try AccountSigner.generateDeterministic(seed);

    var nonce = client.ReplayNonce{};
    try nonce.set("xyz123");
    var url = client.Url{};
    try url.set("https://acme.example/new-order");
    var kid = client.Url{};
    try kid.set("https://acme.example/acct/1");

    var out: [max_body_bytes]u8 = undefined;
    const body = try signer.signWithKid(&out, &nonce, &url, &kid, "{}");
    try std.testing.expect(body.len > 0);
}

test "AccountSigner computeKeyAuthorization returns token.thumbprint" {
    const seed = [_]u8{3} ** Scheme.KeyPair.seed_length;
    const signer = try AccountSigner.generateDeterministic(seed);

    var out: [256]u8 = undefined;
    const key_auth = try signer.computeKeyAuthorization("abc123", &out);
    try std.testing.expect(std.mem.startsWith(u8, key_auth, "abc123."));
    try std.testing.expect(key_auth.len > "abc123.".len);
}
