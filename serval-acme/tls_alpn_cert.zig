//! ACME TLS-ALPN-01 challenge certificate generation.
//!
//! Builds an ephemeral self-signed certificate for a single domain with
//! required extensions:
//! - subjectAltName = dNSName:<domain>
//! - id-pe-acmeIdentifier (critical) = SHA-256(keyAuthorization)

const std = @import("std");
const assert = std.debug.assert;

const config = @import("serval-core").config;

const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{
    InvalidDomain,
    InvalidKeyAuthorization,
    OutputTooSmall,
    SignatureFailed,
};

pub const Materials = struct {
    cert_pem: []const u8,
    key_pem: []const u8,
};

const oid_id_ec_public_key = [_]u8{ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_ecdsa_sha256 = [_]u8{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_common_name = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };
const oid_subject_alt_name = [_]u8{ 0x06, 0x03, 0x55, 0x1D, 0x11 };
const oid_acme_identifier = [_]u8{ 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F };
const DerCursor = u16;

pub fn generateMaterials(
    io: std.Io,
    domain: []const u8,
    key_authorization: []const u8,
    cert_pem_buf: []u8,
    key_pem_buf: []u8,
) Error!Materials {
    assert(cert_pem_buf.len > 0);
    assert(key_pem_buf.len > 0);
    if (domain.len == 0 or domain.len > config.ACME_MAX_DOMAIN_NAME_LEN) return error.InvalidDomain;
    if (key_authorization.len == 0) return error.InvalidKeyAuthorization;

    const key_pair = Scheme.KeyPair.generate(io);
    const secret_key = key_pair.secret_key.toBytes();
    const public_key = key_pair.public_key.toUncompressedSec1();

    var key_der_buf: [256]u8 = undefined;
    const key_der = try encodeSec1EcPrivateKeyDer(&key_der_buf, &secret_key, &public_key);
    const key_pem = try encodePem("EC PRIVATE KEY", key_der, key_pem_buf);

    var tbs_buf: [4096]u8 = undefined;
    const tbs_der = try buildTbsCertificate(io, &tbs_buf, domain, key_authorization, &public_key);

    const signature = key_pair.sign(tbs_der, null) catch return error.SignatureFailed;
    var sig_der_storage: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = signature.toDer(&sig_der_storage);

    var cert_der_buf: [8192]u8 = undefined;
    const cert_der = try buildCertificate(&cert_der_buf, tbs_der, sig_der);
    const cert_pem = try encodePem("CERTIFICATE", cert_der, cert_pem_buf);

    return .{ .cert_pem = cert_pem, .key_pem = key_pem };
}

fn buildTbsCertificate(
    io: std.Io,
    out: []u8,
    domain: []const u8,
    key_authorization: []const u8,
    public_key_sec1: *const [Scheme.PublicKey.uncompressed_sec1_encoded_length]u8,
) Error![]const u8 {
    assert(out.len > 0);
    assert(@intFromPtr(public_key_sec1) != 0);
    var serial_bytes: [16]u8 = undefined;
    io.random(&serial_bytes);
    serial_bytes[0] &= 0x7F;
    if (serial_bytes[0] == 0) serial_bytes[0] = 1;

    var serial_tlv_buf: [24]u8 = undefined;
    const serial_tlv = try buildInteger(&serial_tlv_buf, &serial_bytes);

    var sig_alg_buf: [32]u8 = undefined;
    const sig_alg = try wrapSequenceFromParts(&sig_alg_buf, &.{&oid_ecdsa_sha256});

    var name_buf: [512]u8 = undefined;
    const name = try buildNameFromCommonName(&name_buf, domain);

    var validity_buf: [96]u8 = undefined;
    const validity = try buildWideValidity(&validity_buf);

    var spki_buf: [256]u8 = undefined;
    const spki = try buildSubjectPublicKeyInfo(&spki_buf, public_key_sec1);

    var ext_buf: [2048]u8 = undefined;
    const extensions = try buildCertificateExtensions(&ext_buf, domain, key_authorization);

    var content_buf: [4096]u8 = undefined;
    var cursor: DerCursor = 0;

    // version [0] EXPLICIT INTEGER 2
    cursor = appendBytes(&content_buf, cursor, &.{ 0xA0, 0x03, 0x02, 0x01, 0x02 }) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, serial_tlv) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, sig_alg) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, name) catch return error.OutputTooSmall; // issuer
    cursor = appendBytes(&content_buf, cursor, validity) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, name) catch return error.OutputTooSmall; // subject
    cursor = appendBytes(&content_buf, cursor, spki) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, extensions) catch return error.OutputTooSmall;

    return wrapDerTlv(out, 0x30, content_buf[0..@intCast(cursor)]);
}

fn buildCertificate(out: []u8, tbs_der: []const u8, signature_der: []const u8) Error![]const u8 {
    assert(out.len > 0);
    assert(tbs_der.len > 0 and signature_der.len > 0);
    var sig_alg_buf: [32]u8 = undefined;
    const sig_alg = try wrapSequenceFromParts(&sig_alg_buf, &.{&oid_ecdsa_sha256});

    var sig_bitstring_content: [256]u8 = undefined;
    var sig_cursor: DerCursor = 0;
    sig_cursor = appendBytes(&sig_bitstring_content, sig_cursor, &.{0x00}) catch return error.OutputTooSmall;
    sig_cursor = appendBytes(&sig_bitstring_content, sig_cursor, signature_der) catch return error.OutputTooSmall;

    var sig_bitstring_buf: [280]u8 = undefined;
    const sig_bitstring = try wrapDerTlv(&sig_bitstring_buf, 0x03, sig_bitstring_content[0..@intCast(sig_cursor)]);

    var content_buf: [8192]u8 = undefined;
    var cursor: DerCursor = 0;
    cursor = appendBytes(&content_buf, cursor, tbs_der) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, sig_alg) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, sig_bitstring) catch return error.OutputTooSmall;

    return wrapDerTlv(out, 0x30, content_buf[0..@intCast(cursor)]);
}

fn buildCertificateExtensions(out: []u8, domain: []const u8, key_authorization: []const u8) Error![]const u8 {
    assert(out.len > 0);
    assert(domain.len > 0 and key_authorization.len > 0);
    var san_ext_buf: [1024]u8 = undefined;
    const san_ext = try buildSanExtension(&san_ext_buf, domain);

    var acme_ext_buf: [256]u8 = undefined;
    const acme_ext = try buildAcmeIdentifierExtension(&acme_ext_buf, key_authorization);

    var ext_seq_buf: [1400]u8 = undefined;
    const ext_seq = try wrapSequenceFromParts(&ext_seq_buf, &.{ san_ext, acme_ext });

    // [3] EXPLICIT Extensions
    return wrapDerTlv(out, 0xA3, ext_seq);
}

fn buildSanExtension(out: []u8, domain: []const u8) Error![]const u8 {
    assert(out.len > 0);
    assert(domain.len > 0);
    var dns_tlv_buf: [320]u8 = undefined;
    const dns_tlv = try wrapDerTlv(&dns_tlv_buf, 0x82, domain); // dNSName [2]

    var general_names_buf: [384]u8 = undefined;
    const general_names = try wrapDerTlv(&general_names_buf, 0x30, dns_tlv);

    var extn_value_buf: [448]u8 = undefined;
    const extn_value = try wrapDerTlv(&extn_value_buf, 0x04, general_names);

    return wrapSequenceFromParts(out, &.{ &oid_subject_alt_name, extn_value });
}

fn buildAcmeIdentifierExtension(out: []u8, key_authorization: []const u8) Error![]const u8 {
    assert(out.len > 0);
    assert(key_authorization.len > 0);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key_authorization, &digest, .{});

    var inner_value_buf: [48]u8 = undefined;
    const inner_value = try wrapDerTlv(&inner_value_buf, 0x04, &digest);

    var extn_value_buf: [64]u8 = undefined;
    const extn_value = try wrapDerTlv(&extn_value_buf, 0x04, inner_value);

    return wrapSequenceFromParts(out, &.{ &oid_acme_identifier, &.{ 0x01, 0x01, 0xFF }, extn_value });
}

fn buildNameFromCommonName(out: []u8, common_name: []const u8) Error![]const u8 {
    assert(out.len > 0);
    assert(common_name.len > 0);
    var cn_value_buf: [320]u8 = undefined;
    const cn_value = try wrapDerTlv(&cn_value_buf, 0x0C, common_name);

    var atv_buf: [352]u8 = undefined;
    const atv = try wrapSequenceFromParts(&atv_buf, &.{ &oid_common_name, cn_value });

    var rdn_buf: [384]u8 = undefined;
    const rdn = try wrapDerTlv(&rdn_buf, 0x31, atv);

    return wrapSequenceFromParts(out, &.{rdn});
}

fn buildWideValidity(out: []u8) Error![]const u8 {
    assert(out.len > 0);
    assert(config.ACME_MAX_DOMAIN_NAME_LEN > 0);
    // Wide static window to avoid clock edge issues in challenge validation.
    const not_before = "20000101000000Z";
    const not_after = "20491231235959Z";

    var nb_buf: [24]u8 = undefined;
    const nb = try wrapDerTlv(&nb_buf, 0x18, not_before); // GeneralizedTime

    var na_buf: [24]u8 = undefined;
    const na = try wrapDerTlv(&na_buf, 0x18, not_after);

    return wrapSequenceFromParts(out, &.{ nb, na });
}

fn buildSubjectPublicKeyInfo(
    out: []u8,
    public_key_sec1: *const [Scheme.PublicKey.uncompressed_sec1_encoded_length]u8,
) Error![]const u8 {
    assert(out.len > 0);
    assert(@intFromPtr(public_key_sec1) != 0);
    var alg_buf: [64]u8 = undefined;
    const alg = try wrapSequenceFromParts(&alg_buf, &.{ &oid_id_ec_public_key, &oid_prime256v1 });

    var bit_content_buf: [80]u8 = undefined;
    var bit_cursor: DerCursor = 0;
    bit_cursor = appendBytes(&bit_content_buf, bit_cursor, &.{0x00}) catch return error.OutputTooSmall;
    bit_cursor = appendBytes(&bit_content_buf, bit_cursor, public_key_sec1) catch return error.OutputTooSmall;

    var bit_tlv_buf: [96]u8 = undefined;
    const bit_tlv = try wrapDerTlv(&bit_tlv_buf, 0x03, bit_content_buf[0..@intCast(bit_cursor)]);

    return wrapSequenceFromParts(out, &.{ alg, bit_tlv });
}

fn buildInteger(out: []u8, bytes: []const u8) Error![]const u8 {
    assert(out.len > 0);
    assert(bytes.len > 0);
    const bytes_len_u16 = std.math.cast(u16, bytes.len) orelse return error.OutputTooSmall;
    var i: u16 = 0;
    while (i + 1 < bytes_len_u16 and bytes[@intCast(i)] == 0) : (i += 1) {}
    const trimmed = bytes[@intCast(i)..];

    var value_buf: [32]u8 = undefined;
    var cursor: DerCursor = 0;
    if (trimmed[0] & 0x80 != 0) {
        cursor = appendBytes(&value_buf, cursor, &.{0x00}) catch return error.OutputTooSmall;
    }
    cursor = appendBytes(&value_buf, cursor, trimmed) catch return error.OutputTooSmall;

    return wrapDerTlv(out, 0x02, value_buf[0..@intCast(cursor)]);
}

fn wrapSequenceFromParts(out: []u8, parts: []const []const u8) Error![]const u8 {
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

fn wrapDerTlv(out: []u8, tag: u8, value: []const u8) Error![]const u8 {
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
) Error![]const u8 {
    assert(out.len > 0);
    assert(@intFromPtr(secret_key) != 0 and @intFromPtr(public_key_sec1) != 0);
    var content_buf: [192]u8 = undefined;
    var cursor: DerCursor = 0;

    cursor = appendBytes(&content_buf, cursor, &.{ 0x02, 0x01, 0x01 }) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, &.{ 0x04, Scheme.SecretKey.encoded_length }) catch return error.OutputTooSmall;
    cursor = appendBytes(&content_buf, cursor, secret_key) catch return error.OutputTooSmall;

    var params_buf: [16]u8 = undefined;
    const params = try wrapDerTlv(&params_buf, 0xA0, &oid_prime256v1);
    cursor = appendBytes(&content_buf, cursor, params) catch return error.OutputTooSmall;

    var pubkey_content_buf: [80]u8 = undefined;
    var pk_cursor: DerCursor = 0;
    pk_cursor = appendBytes(&pubkey_content_buf, pk_cursor, &.{0x00}) catch return error.OutputTooSmall;
    pk_cursor = appendBytes(&pubkey_content_buf, pk_cursor, public_key_sec1) catch return error.OutputTooSmall;

    var pubkey_bit_tlv_buf: [96]u8 = undefined;
    const pubkey_bit_tlv = try wrapDerTlv(&pubkey_bit_tlv_buf, 0x03, pubkey_content_buf[0..@intCast(pk_cursor)]);

    var pubkey_ctx_buf: [112]u8 = undefined;
    const pubkey_ctx = try wrapDerTlv(&pubkey_ctx_buf, 0xA1, pubkey_bit_tlv);
    cursor = appendBytes(&content_buf, cursor, pubkey_ctx) catch return error.OutputTooSmall;

    return wrapDerTlv(out, 0x30, content_buf[0..@intCast(cursor)]);
}

fn encodePem(label: []const u8, der: []const u8, out: []u8) Error![]const u8 {
    assert(label.len > 0);
    assert(der.len > 0);
    const b64_len = std.base64.standard.Encoder.calcSize(der.len);
    var b64_buf: [8192]u8 = undefined;
    if (b64_len > b64_buf.len) return error.OutputTooSmall;
    const b64_len_u16 = std.math.cast(u16, b64_len) orelse return error.OutputTooSmall;

    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], der);

    var cursor: DerCursor = 0;
    cursor = appendBytes(out, cursor, "-----BEGIN ") catch return error.OutputTooSmall;
    cursor = appendBytes(out, cursor, label) catch return error.OutputTooSmall;
    cursor = appendBytes(out, cursor, "-----\n") catch return error.OutputTooSmall;

    var line_start: u16 = 0;
    while (line_start < b64_len_u16) {
        const line_len: u16 = @min(@as(u16, 64), b64_len_u16 - line_start);
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

test "generateMaterials emits cert+key PEM" {
    var cert_buf: [8192]u8 = undefined;
    var key_buf: [4096]u8 = undefined;
    var io_threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer io_threaded.deinit();

    const materials = try generateMaterials(
        io_threaded.io(),
        "example.com",
        "abc.def",
        &cert_buf,
        &key_buf,
    );

    try std.testing.expect(std.mem.startsWith(u8, materials.cert_pem, "-----BEGIN CERTIFICATE-----\n"));
    try std.testing.expect(std.mem.startsWith(u8, materials.key_pem, "-----BEGIN EC PRIVATE KEY-----\n"));
}
