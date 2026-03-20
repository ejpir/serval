//! ACME CSR generation helper.
//!
//! Generates a P-256 keypair and PKCS#10 CSR DER fully in-process using Zig
//! crypto + deterministic DER assembly. No external openssl dependency.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const config = @import("serval-core").config;

const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{
    InvalidStateDir,
    InvalidDomainCount,
    InvalidDomain,
    ConfigTooLarge,
    CsrTooLarge,
    KeyTooLarge,
    KeyEncodingFailed,
    SignatureFailed,
};

pub const Result = struct {
    csr_der: []const u8,
    key_pem: []const u8,
};

const oid_id_ec_public_key = [_]u8{ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_ecdsa_sha256 = [_]u8{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_common_name = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };
const oid_extension_request = [_]u8{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E };
const oid_subject_alt_name = [_]u8{ 0x06, 0x03, 0x55, 0x1D, 0x11 };
const DerCursor = u16;

pub fn generate(
    allocator: std.mem.Allocator,
    state_dir: []const u8,
    domains: []const []const u8,
    csr_der_buf: []u8,
    key_pem_buf: []u8,
) Error!Result {
    _ = allocator;
    assert(state_dir.len > 0);
    assert(domains.len > 0);

    if (state_dir.len == 0) return error.InvalidStateDir;
    if (domains.len == 0) return error.InvalidDomainCount;

    const io = std.Options.debug_io;
    Io.Dir.cwd().createDirPath(io, state_dir) catch return error.InvalidStateDir;

    var i: u8 = 0;
    const domain_count = std.math.cast(u8, domains.len) orelse return error.InvalidDomainCount;
    while (i < domain_count) : (i += 1) {
        const domain = domains[@intCast(i)];
        if (domain.len == 0 or domain.len > config.ACME_MAX_DOMAIN_NAME_LEN) return error.InvalidDomain;
    }

    const key_pair = Scheme.KeyPair.generate(io);
    const secret_key = key_pair.secret_key.toBytes();
    const public_key = key_pair.public_key.toUncompressedSec1();

    var key_der_buf: [256]u8 = undefined;
    const key_der = encodeSec1EcPrivateKeyDer(&key_der_buf, &secret_key, &public_key) catch {
        return error.KeyEncodingFailed;
    };

    const key_pem = encodePem("EC PRIVATE KEY", key_der, key_pem_buf) catch return error.KeyTooLarge;
    if (key_pem.len == 0) return error.KeyTooLarge;

    var cri_buf: [4096]u8 = undefined;
    const cri_der = try buildCertificationRequestInfo(&cri_buf, domains, &public_key);

    const signature = key_pair.sign(cri_der, null) catch return error.SignatureFailed;
    var sig_der_storage: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = signature.toDer(&sig_der_storage);

    const csr_der = try buildCertificationRequest(csr_der_buf, cri_der, sig_der);
    if (csr_der.len == 0 or csr_der.len > csr_der_buf.len) return error.CsrTooLarge;

    return .{
        .csr_der = csr_der,
        .key_pem = key_pem,
    };
}

fn buildCertificationRequestInfo(
    out: []u8,
    domains: []const []const u8,
    public_key_sec1: *const [Scheme.PublicKey.uncompressed_sec1_encoded_length]u8,
) Error![]const u8 {
    assert(out.len > 0);
    assert(domains.len > 0);

    var subject_buf: [512]u8 = undefined;
    const subject_der = try buildSubjectName(&subject_buf, domains[0]);

    var spki_buf: [256]u8 = undefined;
    const spki_der = try buildSubjectPublicKeyInfo(&spki_buf, public_key_sec1);

    var attrs_buf: [2048]u8 = undefined;
    const attrs_der = try buildAttributesWithSubjectAltName(&attrs_buf, domains);

    var content_buf: [4096]u8 = undefined;
    var cursor: DerCursor = 0;

    // version INTEGER 0
    cursor = appendBytes(&content_buf, cursor, &.{ 0x02, 0x01, 0x00 }) catch return error.ConfigTooLarge;
    cursor = appendBytes(&content_buf, cursor, subject_der) catch return error.ConfigTooLarge;
    cursor = appendBytes(&content_buf, cursor, spki_der) catch return error.ConfigTooLarge;
    cursor = appendBytes(&content_buf, cursor, attrs_der) catch return error.ConfigTooLarge;

    return wrapDerTlv(out, 0x30, content_buf[0..@intCast(cursor)]) catch return error.ConfigTooLarge;
}

fn buildCertificationRequest(
    out: []u8,
    cri_der: []const u8,
    signature_der: []const u8,
) Error![]const u8 {
    assert(out.len > 0);
    assert(cri_der.len > 0);

    var sig_alg_buf: [32]u8 = undefined;
    const sig_alg_der = wrapSequenceFromParts(&sig_alg_buf, &.{&oid_ecdsa_sha256}) catch return error.CsrTooLarge;

    var sig_bitstring_content_buf: [256]u8 = undefined;
    var sig_cursor: DerCursor = 0;
    sig_cursor = appendBytes(&sig_bitstring_content_buf, sig_cursor, &.{0x00}) catch return error.CsrTooLarge;
    sig_cursor = appendBytes(&sig_bitstring_content_buf, sig_cursor, signature_der) catch return error.CsrTooLarge;

    var sig_bitstring_buf: [280]u8 = undefined;
    const sig_bitstring = wrapDerTlv(&sig_bitstring_buf, 0x03, sig_bitstring_content_buf[0..@intCast(sig_cursor)]) catch {
        return error.CsrTooLarge;
    };

    var csr_content_buf: [8192]u8 = undefined;
    var cursor: DerCursor = 0;
    cursor = appendBytes(&csr_content_buf, cursor, cri_der) catch return error.CsrTooLarge;
    cursor = appendBytes(&csr_content_buf, cursor, sig_alg_der) catch return error.CsrTooLarge;
    cursor = appendBytes(&csr_content_buf, cursor, sig_bitstring) catch return error.CsrTooLarge;

    return wrapDerTlv(out, 0x30, csr_content_buf[0..@intCast(cursor)]) catch return error.CsrTooLarge;
}

fn buildSubjectName(out: []u8, common_name: []const u8) Error![]const u8 {
    assert(out.len > 0);
    assert(common_name.len > 0);
    if (common_name.len == 0 or common_name.len > config.ACME_MAX_DOMAIN_NAME_LEN) return error.InvalidDomain;

    var cn_value_buf: [320]u8 = undefined;
    const cn_value = wrapDerTlv(&cn_value_buf, 0x0C, common_name) catch return error.ConfigTooLarge; // UTF8String

    var atv_buf: [352]u8 = undefined;
    const atv = wrapSequenceFromParts(&atv_buf, &.{ &oid_common_name, cn_value }) catch return error.ConfigTooLarge;

    var rdn_buf: [384]u8 = undefined;
    const rdn = wrapDerTlv(&rdn_buf, 0x31, atv) catch return error.ConfigTooLarge; // SET

    return wrapSequenceFromParts(out, &.{rdn}) catch return error.ConfigTooLarge;
}

fn buildSubjectPublicKeyInfo(
    out: []u8,
    public_key_sec1: *const [Scheme.PublicKey.uncompressed_sec1_encoded_length]u8,
) Error![]const u8 {
    assert(out.len > 0);
    assert(@intFromPtr(public_key_sec1) != 0);

    var alg_buf: [64]u8 = undefined;
    const alg_der = wrapSequenceFromParts(&alg_buf, &.{ &oid_id_ec_public_key, &oid_prime256v1 }) catch {
        return error.ConfigTooLarge;
    };

    var pubkey_content_buf: [80]u8 = undefined;
    var cursor: DerCursor = 0;
    cursor = appendBytes(&pubkey_content_buf, cursor, &.{0x00}) catch return error.ConfigTooLarge;
    cursor = appendBytes(&pubkey_content_buf, cursor, public_key_sec1) catch return error.ConfigTooLarge;

    var pubkey_bitstring_buf: [96]u8 = undefined;
    const pubkey_bitstring = wrapDerTlv(&pubkey_bitstring_buf, 0x03, pubkey_content_buf[0..cursor]) catch {
        return error.ConfigTooLarge;
    };

    return wrapSequenceFromParts(out, &.{ alg_der, pubkey_bitstring }) catch return error.ConfigTooLarge;
}

fn buildAttributesWithSubjectAltName(out: []u8, domains: []const []const u8) Error![]const u8 {
    assert(out.len > 0);
    assert(domains.len > 0);

    var general_names_content: [2048]u8 = undefined;
    var general_cursor: DerCursor = 0;

    var i: u8 = 0;
    const domain_count = std.math.cast(u8, domains.len) orelse return error.InvalidDomainCount;
    while (i < domain_count) : (i += 1) {
        const domain = domains[@intCast(i)];
        if (domain.len == 0 or domain.len > config.ACME_MAX_DOMAIN_NAME_LEN) return error.InvalidDomain;

        // dNSName [2] IA5String -> tag 0x82
        var dns_tlv_buf: [320]u8 = undefined;
        const dns_tlv = wrapDerTlv(&dns_tlv_buf, 0x82, domain) catch return error.ConfigTooLarge;
        general_cursor = appendBytes(&general_names_content, general_cursor, dns_tlv) catch return error.ConfigTooLarge;
    }

    var general_names_buf: [2304]u8 = undefined;
    const general_names = wrapDerTlv(&general_names_buf, 0x30, general_names_content[0..@intCast(general_cursor)]) catch {
        return error.ConfigTooLarge;
    };

    var extn_value_buf: [2304]u8 = undefined;
    const extn_value = wrapDerTlv(&extn_value_buf, 0x04, general_names) catch return error.ConfigTooLarge; // OCTET STRING

    var extension_buf: [2400]u8 = undefined;
    const extension = wrapSequenceFromParts(&extension_buf, &.{ &oid_subject_alt_name, extn_value }) catch {
        return error.ConfigTooLarge;
    };

    var extensions_buf: [2464]u8 = undefined;
    const extensions = wrapSequenceFromParts(&extensions_buf, &.{extension}) catch return error.ConfigTooLarge;

    var values_set_buf: [2528]u8 = undefined;
    const values_set = wrapDerTlv(&values_set_buf, 0x31, extensions) catch return error.ConfigTooLarge; // SET OF values

    var attribute_buf: [2592]u8 = undefined;
    const attribute = wrapSequenceFromParts(&attribute_buf, &.{ &oid_extension_request, values_set }) catch {
        return error.ConfigTooLarge;
    };

    // attributes [0] IMPLICIT SET OF Attribute
    return wrapDerTlv(out, 0xA0, attribute) catch return error.ConfigTooLarge;
}

fn wrapSequenceFromParts(out: []u8, parts: []const []const u8) error{OutputTooSmall}![]const u8 {
    assert(out.len > 0);
    assert(parts.len > 0);

    var content_buf: [8192]u8 = undefined;
    var cursor: DerCursor = 0;

    var i: u16 = 0;
    const parts_len = std.math.cast(u16, parts.len) orelse return error.OutputTooSmall;
    while (i < parts_len) : (i += 1) {
        cursor = appendBytes(&content_buf, cursor, parts[@intCast(i)]) catch return error.OutputTooSmall;
    }

    return wrapDerTlv(out, 0x30, content_buf[0..@intCast(cursor)]);
}

fn wrapDerTlv(out: []u8, tag: u8, value: []const u8) error{OutputTooSmall}![]const u8 {
    assert(out.len > 0);
    assert(tag != 0);

    var cursor: DerCursor = 0;
    cursor = appendByte(out, cursor, tag) catch return error.OutputTooSmall;
    const value_len = std.math.cast(u16, value.len) orelse return error.OutputTooSmall;
    cursor = appendDerLength(out, cursor, value_len) catch return error.OutputTooSmall;
    cursor = appendBytes(out, cursor, value) catch return error.OutputTooSmall;
    return out[0..@intCast(cursor)];
}

fn appendByte(out: []u8, cursor: DerCursor, value: u8) error{OutputTooSmall}!DerCursor {
    assert(out.len <= std.math.maxInt(DerCursor));
    assert(cursor <= @as(DerCursor, @intCast(out.len)));
    assert(value <= std.math.maxInt(u8));
    if (cursor >= @as(DerCursor, @intCast(out.len))) return error.OutputTooSmall;
    out[@intCast(cursor)] = value;
    return std.math.add(DerCursor, cursor, 1) catch error.OutputTooSmall;
}

fn appendBytes(out: []u8, cursor: DerCursor, bytes: []const u8) error{OutputTooSmall}!DerCursor {
    assert(out.len <= std.math.maxInt(DerCursor));
    assert(cursor <= @as(DerCursor, @intCast(out.len)));
    assert(bytes.len <= out.len);
    const bytes_len = std.math.cast(DerCursor, bytes.len) orelse return error.OutputTooSmall;
    const end = std.math.add(DerCursor, cursor, bytes_len) catch return error.OutputTooSmall;
    if (end > @as(DerCursor, @intCast(out.len))) return error.OutputTooSmall;
    @memcpy(out[@intCast(cursor)..][0..@intCast(bytes_len)], bytes);
    return end;
}

fn appendDerLength(out: []u8, cursor: DerCursor, len: u16) error{OutputTooSmall}!DerCursor {
    assert(cursor <= @as(DerCursor, @intCast(out.len)));
    assert(len <= 65_535);
    if (len <= 127) {
        return appendByte(out, cursor, @intCast(len));
    }

    if (len <= 255) {
        var next = try appendByte(out, cursor, 0x81);
        next = try appendByte(out, next, @intCast(len));
        return next;
    }

    if (len <= 65_535) {
        var next = try appendByte(out, cursor, 0x82);
        next = try appendByte(out, next, @intCast((len >> 8) & 0xFF));
        next = try appendByte(out, next, @intCast(len & 0xFF));
        return next;
    }

    return error.OutputTooSmall;
}

fn encodeSec1EcPrivateKeyDer(
    out: []u8,
    secret_key: *const [Scheme.SecretKey.encoded_length]u8,
    public_key_sec1: *const [Scheme.PublicKey.uncompressed_sec1_encoded_length]u8,
) error{OutputTooSmall}![]const u8 {
    assert(out.len >= 128);
    assert(@intFromPtr(secret_key) != 0 and @intFromPtr(public_key_sec1) != 0);

    // ECPrivateKey ::= SEQUENCE {
    //   version        INTEGER(1),
    //   privateKey     OCTET STRING,
    //   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    //   publicKey  [1] BIT STRING OPTIONAL
    // }
    var content_buf: [192]u8 = undefined;
    var cursor: DerCursor = 0;

    cursor = appendBytes(&content_buf, cursor, &.{ 0x02, 0x01, 0x01 }) catch return error.OutputTooSmall;

    cursor = appendBytes(&content_buf, cursor, &.{ 0x04, Scheme.SecretKey.encoded_length }) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, secret_key) catch return error.OutputTooSmall;

    var params_buf: [16]u8 = undefined;
    const params_tlv = wrapDerTlv(&params_buf, 0xA0, &oid_prime256v1) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, params_tlv) catch return error.OutputTooSmall;

    var pubkey_content_buf: [80]u8 = undefined;
    var pubkey_cursor: DerCursor = 0;
    pubkey_cursor = appendBytes(&pubkey_content_buf, pubkey_cursor, &.{0x00}) catch return error.OutputTooSmall;
    pubkey_cursor = appendBytes(&pubkey_content_buf, pubkey_cursor, public_key_sec1) catch return error.OutputTooSmall;

    var pubkey_bitstring_buf: [96]u8 = undefined;
    const pubkey_bitstring = wrapDerTlv(&pubkey_bitstring_buf, 0x03, pubkey_content_buf[0..@intCast(pubkey_cursor)]) catch {
        return error.OutputTooSmall;
    };

    var pubkey_ctx_buf: [112]u8 = undefined;
    const pubkey_ctx = wrapDerTlv(&pubkey_ctx_buf, 0xA1, pubkey_bitstring) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, pubkey_ctx) catch return error.OutputTooSmall;

    return wrapDerTlv(out, 0x30, content_buf[0..@intCast(cursor)]);
}

fn encodePem(label: []const u8, der: []const u8, out: []u8) error{OutputTooSmall}![]const u8 {
    assert(label.len > 0);
    assert(der.len > 0);

    const b64_len = std.base64.standard.Encoder.calcSize(der.len);
    var b64_buf: [4096]u8 = undefined;
    if (b64_len > b64_buf.len) return error.OutputTooSmall;

    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], der);

    var cursor: DerCursor = 0;
    cursor = appendBytes(out, cursor, "-----BEGIN ") catch return error.OutputTooSmall;
    cursor = appendBytes(out, cursor, label) catch return error.OutputTooSmall;
    cursor = appendBytes(out, cursor, "-----\n") catch return error.OutputTooSmall;

    const b64_len_u16 = std.math.cast(u16, b64_len) orelse return error.OutputTooSmall;
    var line_start: u16 = 0;
    while (line_start < b64_len_u16) {
        const remaining = b64_len_u16 - line_start;
        const line_len: u16 = @min(@as(u16, 64), remaining);
        cursor = appendBytes(
            out,
            cursor,
            b64_buf[@intCast(line_start) .. @intCast(line_start + line_len)],
        ) catch return error.OutputTooSmall;
        cursor = appendBytes(out, cursor, "\n") catch return error.OutputTooSmall;
        line_start += line_len;
    }

    cursor = appendBytes(out, cursor, "-----END ") catch return error.OutputTooSmall;
    cursor = appendBytes(out, cursor, label) catch return error.OutputTooSmall;
    cursor = appendBytes(out, cursor, "-----\n") catch return error.OutputTooSmall;

    return out[0..@intCast(cursor)];
}

test "buildSubjectAltName remains deterministic" {
    var out: [256]u8 = undefined;
    const attrs = try buildAttributesWithSubjectAltName(&out, &.{ "example.com", "api.example.com" });
    try std.testing.expect(attrs.len > 0);
    try std.testing.expectEqual(@as(u8, 0xA0), attrs[0]);
}

test "encodeSec1EcPrivateKeyDer emits expected sequence header" {
    const seed = [_]u8{11} ** Scheme.KeyPair.seed_length;
    const key_pair = try Scheme.KeyPair.generateDeterministic(seed);
    const secret = key_pair.secret_key.toBytes();
    const public = key_pair.public_key.toUncompressedSec1();

    var der_buf: [256]u8 = undefined;
    const der = try encodeSec1EcPrivateKeyDer(&der_buf, &secret, &public);

    try std.testing.expect(der.len > 0);
    try std.testing.expectEqual(@as(u8, 0x30), der[0]);
    try std.testing.expectEqual(@as(u8, 0x02), der[2]);
}

test "encodePem wraps DER with EC PRIVATE KEY label" {
    const der = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var out: [256]u8 = undefined;
    const pem = try encodePem("EC PRIVATE KEY", &der, &out);

    try std.testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN EC PRIVATE KEY-----\n"));
    try std.testing.expect(std.mem.endsWith(u8, pem, "-----END EC PRIVATE KEY-----\n"));
}

test "generate emits non-empty key and csr" {
    var csr_buf: [4096]u8 = undefined;
    var key_buf: [4096]u8 = undefined;

    const result = try generate(
        std.testing.allocator,
        "/tmp/serval-acme-csr-test",
        &.{ "example.com", "api.example.com" },
        &csr_buf,
        &key_buf,
    );

    try std.testing.expect(result.csr_der.len > 0);
    try std.testing.expect(result.key_pem.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, result.key_pem, "-----BEGIN EC PRIVATE KEY-----\n"));
}
