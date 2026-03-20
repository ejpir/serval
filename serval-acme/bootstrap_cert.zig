//! Bootstrap self-signed TLS certificate generation.
//!
//! Generates a bootstrap self-signed P-256 certificate with SAN for initial
//! server startup before ACME issuance completes.

const std = @import("std");
const config = @import("serval-core").config;

const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{
    InvalidDomain,
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
const bootstrap_not_before_generalized_time: []const u8 = "20000101000000Z";
const bootstrap_not_after_generalized_time: []const u8 = "20991231235959Z";

pub fn generateMaterials(
    io: std.Io,
    domain: []const u8,
    cert_pem_buf: []u8,
    key_pem_buf: []u8,
) Error!Materials {
    if (domain.len == 0 or domain.len > config.ACME_MAX_DOMAIN_NAME_LEN) return error.InvalidDomain;

    const key_pair = Scheme.KeyPair.generate(io);
    const secret_key = key_pair.secret_key.toBytes();
    const public_key = key_pair.public_key.toUncompressedSec1();

    var key_der_buf: [256]u8 = undefined;
    const key_der = try encodeSec1EcPrivateKeyDer(&key_der_buf, &secret_key, &public_key);
    const key_pem = try encodePem("EC PRIVATE KEY", key_der, key_pem_buf);

    var tbs_buf: [3072]u8 = undefined;
    const tbs_der = try buildTbsCertificate(io, &tbs_buf, domain, &public_key);

    const signature = key_pair.sign(tbs_der, null) catch return error.SignatureFailed;
    var sig_der_storage: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = signature.toDer(&sig_der_storage);

    var cert_der_buf: [6144]u8 = undefined;
    const cert_der = try buildCertificate(&cert_der_buf, tbs_der, sig_der);
    const cert_pem = try encodePem("CERTIFICATE", cert_der, cert_pem_buf);

    return .{ .cert_pem = cert_pem, .key_pem = key_pem };
}

fn buildTbsCertificate(io: std.Io, out: []u8, domain: []const u8, public_key_sec1: *const [65]u8) Error![]const u8 {
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
    const validity = try buildValidity(&validity_buf);

    var spki_buf: [256]u8 = undefined;
    const spki = try buildSubjectPublicKeyInfo(&spki_buf, public_key_sec1);

    var ext_buf: [1024]u8 = undefined;
    const extensions = try buildExtensions(&ext_buf, domain);

    var content_buf: [4096]u8 = undefined;
    var cursor: usize = 0;
    cursor = try appendBytes(&content_buf, cursor, &.{ 0xA0, 0x03, 0x02, 0x01, 0x02 });
    cursor = try appendBytes(&content_buf, cursor, serial_tlv);
    cursor = try appendBytes(&content_buf, cursor, sig_alg);
    cursor = try appendBytes(&content_buf, cursor, name);
    cursor = try appendBytes(&content_buf, cursor, validity);
    cursor = try appendBytes(&content_buf, cursor, name);
    cursor = try appendBytes(&content_buf, cursor, spki);
    cursor = try appendBytes(&content_buf, cursor, extensions);

    return wrapDerTlv(out, 0x30, content_buf[0..cursor]);
}

fn buildCertificate(out: []u8, tbs_der: []const u8, signature_der: []const u8) Error![]const u8 {
    var sig_alg_buf: [32]u8 = undefined;
    const sig_alg = try wrapSequenceFromParts(&sig_alg_buf, &.{&oid_ecdsa_sha256});

    var sig_bitstring_content: [256]u8 = undefined;
    var sig_cursor: usize = 0;
    sig_cursor = try appendBytes(&sig_bitstring_content, sig_cursor, &.{0x00});
    sig_cursor = try appendBytes(&sig_bitstring_content, sig_cursor, signature_der);

    var sig_bitstring_buf: [280]u8 = undefined;
    const sig_bitstring = try wrapDerTlv(&sig_bitstring_buf, 0x03, sig_bitstring_content[0..sig_cursor]);

    var content_buf: [8192]u8 = undefined;
    var cursor: usize = 0;
    cursor = try appendBytes(&content_buf, cursor, tbs_der);
    cursor = try appendBytes(&content_buf, cursor, sig_alg);
    cursor = try appendBytes(&content_buf, cursor, sig_bitstring);

    return wrapDerTlv(out, 0x30, content_buf[0..cursor]);
}

fn buildExtensions(out: []u8, domain: []const u8) Error![]const u8 {
    var dns_tlv_buf: [320]u8 = undefined;
    const dns_tlv = try wrapDerTlv(&dns_tlv_buf, 0x82, domain);

    var general_names_buf: [384]u8 = undefined;
    const general_names = try wrapDerTlv(&general_names_buf, 0x30, dns_tlv);

    var extn_value_buf: [448]u8 = undefined;
    const extn_value = try wrapDerTlv(&extn_value_buf, 0x04, general_names);

    var san_ext_buf: [512]u8 = undefined;
    const san_ext = try wrapSequenceFromParts(&san_ext_buf, &.{ &oid_subject_alt_name, extn_value });

    var ext_seq_buf: [640]u8 = undefined;
    const ext_seq = try wrapSequenceFromParts(&ext_seq_buf, &.{san_ext});

    return wrapDerTlv(out, 0xA3, ext_seq);
}

fn buildNameFromCommonName(out: []u8, common_name: []const u8) Error![]const u8 {
    var cn_value_buf: [320]u8 = undefined;
    const cn_value = try wrapDerTlv(&cn_value_buf, 0x0C, common_name);

    var atv_buf: [352]u8 = undefined;
    const atv = try wrapSequenceFromParts(&atv_buf, &.{ &oid_common_name, cn_value });

    var rdn_buf: [384]u8 = undefined;
    const rdn = try wrapDerTlv(&rdn_buf, 0x31, atv);

    return wrapSequenceFromParts(out, &.{rdn});
}

fn buildValidity(out: []u8) Error![]const u8 {
    var nb_buf: [24]u8 = undefined;
    const nb = try wrapDerTlv(&nb_buf, 0x18, bootstrap_not_before_generalized_time);

    var na_buf: [24]u8 = undefined;
    const na = try wrapDerTlv(&na_buf, 0x18, bootstrap_not_after_generalized_time);

    return wrapSequenceFromParts(out, &.{ nb, na });
}

fn buildSubjectPublicKeyInfo(out: []u8, public_key_sec1: *const [65]u8) Error![]const u8 {
    var alg_buf: [64]u8 = undefined;
    const alg = try wrapSequenceFromParts(&alg_buf, &.{ &oid_id_ec_public_key, &oid_prime256v1 });

    var bit_content_buf: [80]u8 = undefined;
    var bit_cursor: usize = 0;
    bit_cursor = try appendBytes(&bit_content_buf, bit_cursor, &.{0x00});
    bit_cursor = try appendBytes(&bit_content_buf, bit_cursor, public_key_sec1);

    var bit_tlv_buf: [96]u8 = undefined;
    const bit_tlv = try wrapDerTlv(&bit_tlv_buf, 0x03, bit_content_buf[0..bit_cursor]);

    return wrapSequenceFromParts(out, &.{ alg, bit_tlv });
}

fn buildInteger(out: []u8, bytes: []const u8) Error![]const u8 {
    var i: usize = 0;
    while (i + 1 < bytes.len and bytes[i] == 0) : (i += 1) {}
    const trimmed = bytes[i..];

    var value_buf: [32]u8 = undefined;
    var cursor: usize = 0;
    if (trimmed[0] & 0x80 != 0) {
        cursor = try appendBytes(&value_buf, cursor, &.{0x00});
    }
    cursor = try appendBytes(&value_buf, cursor, trimmed);
    return wrapDerTlv(out, 0x02, value_buf[0..cursor]);
}

fn wrapSequenceFromParts(out: []u8, parts: []const []const u8) Error![]const u8 {
    var content_buf: [8192]u8 = undefined;
    var cursor: usize = 0;
    for (parts) |part| cursor = try appendBytes(&content_buf, cursor, part);
    return wrapDerTlv(out, 0x30, content_buf[0..cursor]);
}

fn wrapDerTlv(out: []u8, tag: u8, value: []const u8) Error![]const u8 {
    var cursor: usize = 0;
    cursor = try appendByte(out, cursor, tag);
    cursor = try appendDerLength(out, cursor, value.len);
    cursor = try appendBytes(out, cursor, value);
    return out[0..cursor];
}

fn appendByte(out: []u8, cursor: usize, value: u8) error{OutputTooSmall}!usize {
    if (cursor >= out.len) return error.OutputTooSmall;
    out[cursor] = value;
    return cursor + 1;
}

fn appendBytes(out: []u8, cursor: usize, bytes: []const u8) error{OutputTooSmall}!usize {
    if (cursor + bytes.len > out.len) return error.OutputTooSmall;
    @memcpy(out[cursor..][0..bytes.len], bytes);
    return cursor + bytes.len;
}

fn appendDerLength(out: []u8, cursor: usize, len: usize) error{OutputTooSmall}!usize {
    if (len <= 127) return appendByte(out, cursor, @intCast(len));
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

fn encodeSec1EcPrivateKeyDer(out: []u8, secret_key: *const [32]u8, public_key_sec1: *const [65]u8) Error![]const u8 {
    var content_buf: [192]u8 = undefined;
    var cursor: usize = 0;

    cursor = try appendBytes(&content_buf, cursor, &.{ 0x02, 0x01, 0x01 });
    cursor = try appendBytes(&content_buf, cursor, &.{ 0x04, 32 });
    cursor = try appendBytes(&content_buf, cursor, secret_key);

    var params_buf: [16]u8 = undefined;
    const params = try wrapDerTlv(&params_buf, 0xA0, &oid_prime256v1);
    cursor = try appendBytes(&content_buf, cursor, params);

    var pubkey_content_buf: [80]u8 = undefined;
    var pk_cursor: usize = 0;
    pk_cursor = try appendBytes(&pubkey_content_buf, pk_cursor, &.{0x00});
    pk_cursor = try appendBytes(&pubkey_content_buf, pk_cursor, public_key_sec1);

    var pubkey_bit_tlv_buf: [96]u8 = undefined;
    const pubkey_bit_tlv = try wrapDerTlv(&pubkey_bit_tlv_buf, 0x03, pubkey_content_buf[0..pk_cursor]);

    var pubkey_ctx_buf: [112]u8 = undefined;
    const pubkey_ctx = try wrapDerTlv(&pubkey_ctx_buf, 0xA1, pubkey_bit_tlv);
    cursor = try appendBytes(&content_buf, cursor, pubkey_ctx);

    return wrapDerTlv(out, 0x30, content_buf[0..cursor]);
}

fn encodePem(label: []const u8, der: []const u8, out: []u8) Error![]const u8 {
    const b64_len = std.base64.standard.Encoder.calcSize(der.len);
    var b64_buf: [8192]u8 = undefined;
    if (b64_len > b64_buf.len) return error.OutputTooSmall;

    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], der);

    var cursor: usize = 0;
    cursor = try appendBytes(out, cursor, "-----BEGIN ");
    cursor = try appendBytes(out, cursor, label);
    cursor = try appendBytes(out, cursor, "-----\n");

    var line_start: usize = 0;
    while (line_start < b64_len) {
        const line_len: usize = @min(@as(usize, 64), b64_len - line_start);
        cursor = try appendBytes(out, cursor, b64_buf[line_start .. line_start + line_len]);
        cursor = try appendBytes(out, cursor, "\n");
        line_start += line_len;
    }

    cursor = try appendBytes(out, cursor, "-----END ");
    cursor = try appendBytes(out, cursor, label);
    cursor = try appendBytes(out, cursor, "-----\n");

    return out[0..cursor];
}

test "generate bootstrap cert materials" {
    var io_threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer io_threaded.deinit();

    var cert_buf: [8192]u8 = undefined;
    var key_buf: [4096]u8 = undefined;

    const materials = try generateMaterials(io_threaded.io(), "netbird.coreworks.be", &cert_buf, &key_buf);
    try std.testing.expect(std.mem.startsWith(u8, materials.cert_pem, "-----BEGIN CERTIFICATE-----\n"));
    try std.testing.expect(std.mem.startsWith(u8, materials.key_pem, "-----BEGIN EC PRIVATE KEY-----\n"));
}
