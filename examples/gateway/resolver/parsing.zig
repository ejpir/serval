//! Resolver JSON Parsing
//!
//! JSON parsing functions for Kubernetes resource data:
//! - Endpoints JSON (service pod IPs)
//! - Secret JSON (TLS certificates)
//!
//! TigerStyle: Bounded storage, explicit errors, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;

// Import types from types.zig
const resolver_types = @import("types.zig");

pub const MAX_ENDPOINTS_PER_SERVICE = resolver_types.MAX_ENDPOINTS_PER_SERVICE;
pub const MAX_CERT_SIZE = resolver_types.MAX_CERT_SIZE;
pub const MAX_IP_LEN = resolver_types.MAX_IP_LEN;
pub const MAX_BASE64_INPUT_SIZE = resolver_types.MAX_BASE64_INPUT_SIZE;
pub const ResolverError = resolver_types.ResolverError;

// Internal type aliases
const CertStorage = resolver_types.CertStorage;
const StoredEndpoint = resolver_types.StoredEndpoint;

// Internal constants from resolver_types
const MAX_SUBSETS = resolver_types.MAX_SUBSETS;
const MAX_ADDRESSES_PER_SUBSET = resolver_types.MAX_ADDRESSES_PER_SUBSET;

// ============================================================================
// JSON Types for K8s Resource Parsing
// ============================================================================

/// JSON types for K8s Endpoints parsing.
pub const EndpointsJson = struct {
    subsets: ?[]const SubsetJson = null,
};

pub const SubsetJson = struct {
    addresses: ?[]const AddressJson = null,
    ports: ?[]const PortJson = null,
};

pub const AddressJson = struct {
    ip: []const u8,
};

pub const PortJson = struct {
    port: u16,
};

/// JSON types for K8s Secret parsing.
pub const SecretJson = struct {
    type: ?[]const u8 = null,
    data: ?DataJson = null,
};

pub const DataJson = struct {
    @"tls.crt": ?[]const u8 = null,
    @"tls.key": ?[]const u8 = null,
};

// ============================================================================
// JSON Parsing Functions
// ============================================================================

/// Parse K8s Endpoints JSON into StoredEndpoint array.
pub fn parseEndpointsJson(
    json_data: []const u8,
    out_endpoints: *[MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint,
    out_count: *u8,
) ResolverError!void {
    assert(json_data.len > 0);

    const parsed = std.json.parseFromSlice(
        EndpointsJson,
        std.heap.page_allocator, // Temporary allocator for parsing only
        json_data,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return error.InvalidEndpointsJson;
    };
    defer parsed.deinit();

    const endpoints = parsed.value;
    var count: u8 = 0;

    const subsets = endpoints.subsets orelse {
        out_count.* = 0;
        return;
    };

    // Bound loop iterations (TigerStyle: no unbounded loops)
    const max_subsets = @min(subsets.len, MAX_SUBSETS);

    for (subsets[0..max_subsets]) |subset| {
        const addresses = subset.addresses orelse continue;
        const ports = subset.ports orelse continue;

        if (ports.len == 0) continue;

        // Use first port (simplification - full impl would handle named ports)
        const port = ports[0].port;

        const max_addresses = @min(addresses.len, MAX_ADDRESSES_PER_SUBSET);

        for (addresses[0..max_addresses]) |addr| {
            if (count >= MAX_ENDPOINTS_PER_SERVICE) {
                return error.EndpointLimitExceeded;
            }

            if (addr.ip.len > MAX_IP_LEN) {
                return error.IpTooLong;
            }

            var stored = &out_endpoints[count];
            @memcpy(stored.ip_storage[0..addr.ip.len], addr.ip);
            stored.ip_len = @intCast(addr.ip.len);
            stored.port = port;
            count += 1;
        }
    }

    out_count.* = count;

    // Postcondition
    assert(out_count.* <= MAX_ENDPOINTS_PER_SERVICE);
}

/// Parse K8s Secret JSON and decode base64 cert/key.
pub fn parseSecretJson(
    json_data: []const u8,
    out_cert: *CertStorage,
    out_cert_len: *u16,
    out_key: *CertStorage,
    out_key_len: *u16,
) ResolverError!void {
    assert(json_data.len > 0);

    const parsed = std.json.parseFromSlice(
        SecretJson,
        std.heap.page_allocator, // Temporary allocator for parsing only
        json_data,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return error.InvalidSecretJson;
    };
    defer parsed.deinit();

    const secret = parsed.value;

    // Verify secret type
    if (secret.type) |secret_type| {
        if (!std.mem.eql(u8, secret_type, "kubernetes.io/tls")) {
            return error.InvalidSecretType;
        }
    }

    const data = secret.data orelse return error.InvalidSecretJson;

    // Decode certificate
    const cert_b64 = data.@"tls.crt" orelse return error.MissingTlsCert;
    if (cert_b64.len > MAX_BASE64_INPUT_SIZE) {
        return error.CertTooLarge;
    }
    const cert_len = decodeBase64(cert_b64, out_cert) catch {
        return error.Base64DecodeFailed;
    };
    if (cert_len > MAX_CERT_SIZE) {
        return error.CertTooLarge;
    }
    out_cert_len.* = @intCast(cert_len);

    // Decode key
    const key_b64 = data.@"tls.key" orelse return error.MissingTlsKey;
    if (key_b64.len > MAX_BASE64_INPUT_SIZE) {
        return error.CertTooLarge;
    }
    const key_len = decodeBase64(key_b64, out_key) catch {
        return error.Base64DecodeFailed;
    };
    if (key_len > MAX_CERT_SIZE) {
        return error.CertTooLarge;
    }
    out_key_len.* = @intCast(key_len);

    // Postconditions
    assert(out_cert_len.* <= MAX_CERT_SIZE);
    assert(out_key_len.* <= MAX_CERT_SIZE);
}

/// Decode base64 data into output buffer.
/// Returns decoded length.
pub fn decodeBase64(input: []const u8, output: *CertStorage) !usize {
    if (input.len == 0) return 0;

    // Calculate expected decoded size
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(input) catch {
        return error.InvalidCharacter;
    };

    if (decoded_len > MAX_CERT_SIZE) {
        return error.NoSpaceLeft;
    }

    // Decode
    std.base64.standard.Decoder.decode(output[0..decoded_len], input) catch {
        return error.InvalidCharacter;
    };

    return decoded_len;
}

// ============================================================================
// Unit Tests
// ============================================================================

test "parseEndpointsJson empty subsets" {
    var endpoints: [MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint = undefined;
    var count: u8 = 0;

    const json = "{}";
    try parseEndpointsJson(json, &endpoints, &count);
    try std.testing.expectEqual(@as(u8, 0), count);
}

test "parseEndpointsJson multiple subsets" {
    var endpoints: [MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint = undefined;
    var count: u8 = 0;

    const json =
        \\{
        \\  "subsets": [
        \\    {
        \\      "addresses": [{ "ip": "10.0.1.1" }],
        \\      "ports": [{ "port": 8080 }]
        \\    },
        \\    {
        \\      "addresses": [{ "ip": "10.0.2.1" }],
        \\      "ports": [{ "port": 9090 }]
        \\    }
        \\  ]
        \\}
    ;

    try parseEndpointsJson(json, &endpoints, &count);
    try std.testing.expectEqual(@as(u8, 2), count);
    try std.testing.expectEqualStrings("10.0.1.1", endpoints[0].ip());
    try std.testing.expectEqual(@as(u16, 8080), endpoints[0].port);
    try std.testing.expectEqualStrings("10.0.2.1", endpoints[1].ip());
    try std.testing.expectEqual(@as(u16, 9090), endpoints[1].port);
}

test "parseEndpointsJson invalid JSON" {
    var endpoints: [MAX_ENDPOINTS_PER_SERVICE]StoredEndpoint = undefined;
    var count: u8 = 0;

    const json = "not valid json";
    try std.testing.expectError(error.InvalidEndpointsJson, parseEndpointsJson(json, &endpoints, &count));
}

test "parseSecretJson missing tls.crt" {
    var cert: CertStorage = undefined;
    var cert_len: u16 = 0;
    var key: CertStorage = undefined;
    var key_len: u16 = 0;

    const json =
        \\{
        \\  "type": "kubernetes.io/tls",
        \\  "data": {
        \\    "tls.key": "a2V5"
        \\  }
        \\}
    ;

    try std.testing.expectError(error.MissingTlsCert, parseSecretJson(json, &cert, &cert_len, &key, &key_len));
}

test "parseSecretJson missing tls.key" {
    var cert: CertStorage = undefined;
    var cert_len: u16 = 0;
    var key: CertStorage = undefined;
    var key_len: u16 = 0;

    const json =
        \\{
        \\  "type": "kubernetes.io/tls",
        \\  "data": {
        \\    "tls.crt": "Y2VydA=="
        \\  }
        \\}
    ;

    try std.testing.expectError(error.MissingTlsKey, parseSecretJson(json, &cert, &cert_len, &key, &key_len));
}

test "parseSecretJson invalid type" {
    var cert: CertStorage = undefined;
    var cert_len: u16 = 0;
    var key: CertStorage = undefined;
    var key_len: u16 = 0;

    const json =
        \\{
        \\  "type": "Opaque",
        \\  "data": {
        \\    "tls.crt": "Y2VydA==",
        \\    "tls.key": "a2V5"
        \\  }
        \\}
    ;

    try std.testing.expectError(error.InvalidSecretType, parseSecretJson(json, &cert, &cert_len, &key, &key_len));
}

test "parseSecretJson invalid base64" {
    var cert: CertStorage = undefined;
    var cert_len: u16 = 0;
    var key: CertStorage = undefined;
    var key_len: u16 = 0;

    const json =
        \\{
        \\  "type": "kubernetes.io/tls",
        \\  "data": {
        \\    "tls.crt": "not-valid-base64!!!",
        \\    "tls.key": "a2V5"
        \\  }
        \\}
    ;

    try std.testing.expectError(error.Base64DecodeFailed, parseSecretJson(json, &cert, &cert_len, &key, &key_len));
}

test "decodeBase64 empty input" {
    var output: CertStorage = undefined;
    const len = try decodeBase64("", &output);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "decodeBase64 valid input" {
    var output: CertStorage = undefined;
    const len = try decodeBase64("SGVsbG8gV29ybGQ=", &output);
    try std.testing.expectEqual(@as(usize, 11), len);
    try std.testing.expectEqualStrings("Hello World", output[0..len]);
}
