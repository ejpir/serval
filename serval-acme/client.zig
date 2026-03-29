//! ACME protocol client primitives (directory/nonce/account/order).
//!
//! TigerStyle: Bounded parsing/serialization, explicit protocol types,
//! no hidden allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const acme_types = @import("types.zig");

const max_url_bytes = config.ACME_MAX_DIRECTORY_URL_BYTES;
const max_nonce_bytes = config.ACME_MAX_NONCE_BYTES;
const max_contact_email_bytes = config.ACME_MAX_CONTACT_EMAIL_BYTES;
const max_identifiers_per_order = config.ACME_MAX_DOMAINS_PER_CERT;
const max_authorization_urls_per_order = config.ACME_MAX_AUTHORIZATION_URLS_PER_ORDER;
const max_directory_response_bytes = config.ACME_MAX_DIRECTORY_RESPONSE_BYTES;
const max_account_response_bytes = config.ACME_MAX_ACCOUNT_RESPONSE_BYTES;
const max_order_response_bytes = config.ACME_MAX_ORDER_RESPONSE_BYTES;
const max_jws_body_bytes = config.ACME_MAX_JWS_BODY_BYTES;
const max_challenges_per_authorization = 16;
const max_challenge_token_bytes = config.ACME_MAX_HTTP01_TOKEN_BYTES;
const output_cursor_max: u32 = max_jws_body_bytes;

const json_parse_scratch_size_bytes = 8192;

/// Error set used by the ACME client for parsing, validation, and output sizing failures.
/// It includes JSON decode failures, missing required fields, invalid status and type values, and length limits for URLs, nonces, identifiers, authorizations, challenges, and output buffers.
pub const Error = error{
    EmptyInput,
    ResponseTooLarge,
    JsonParseFailed,
    JsonScratchExhausted,
    MissingDirectoryEndpoint,
    MissingAccountField,
    MissingOrderField,
    InvalidUrl,
    UrlTooLong,
    InvalidNonce,
    NonceTooLong,
    InvalidAccountStatus,
    InvalidOrderStatus,
    InvalidIdentifierCount,
    InvalidContactEmail,
    InvalidDomainName,
    InvalidAuthorizationStatus,
    InvalidChallengeStatus,
    InvalidChallengeType,
    InvalidChallengeToken,
    TooManyIdentifiers,
    TooManyAuthorizations,
    TooManyChallenges,
    OutputTooSmall,
};

/// Bounded URL storage used by ACME endpoint and resource links.
pub const Url = struct {
    len: u16 = 0,
    bytes: [max_url_bytes]u8 = [_]u8{0} ** max_url_bytes,

    /// Stores a URL after validating size, whitespace, and scheme constraints.
    /// Empty values, values longer than `max_url_bytes`, values containing space, newline, or carriage return, or values without an `http://` or `https://` prefix return an error.
    /// On success, the URL buffer is cleared and the new bytes are copied into place.
    pub fn set(self: *Url, value: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.len <= max_url_bytes);

        if (value.len == 0) return error.InvalidUrl;
        if (value.len > max_url_bytes) return error.UrlTooLong;
        if (std.mem.indexOfScalar(u8, value, ' ')) |_| return error.InvalidUrl;
        if (std.mem.indexOfScalar(u8, value, '\n')) |_| return error.InvalidUrl;
        if (std.mem.indexOfScalar(u8, value, '\r')) |_| return error.InvalidUrl;

        const is_http = std.mem.startsWith(u8, value, "http://");
        const is_https = std.mem.startsWith(u8, value, "https://");
        if (!is_http and !is_https) return error.InvalidUrl;

        @memset(self.bytes[0..], 0);
        @memcpy(self.bytes[0..value.len], value);
        self.len = @intCast(value.len);
        assert(self.len == @as(u16, @intCast(value.len)));
    }

    /// Returns the stored URL as a byte slice.
    /// The returned slice aliases the internal buffer and is valid until the URL is replaced or the struct is discarded.
    /// `len` must not exceed `max_url_bytes`.
    pub fn slice(self: *const Url) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.len <= max_url_bytes);
        return self.bytes[0..self.len];
    }
};

/// Replay-Nonce header value holder.
pub const ReplayNonce = struct {
    len: u16 = 0,
    bytes: [max_nonce_bytes]u8 = [_]u8{0} ** max_nonce_bytes,

    /// Stores a replay nonce after validating size and whitespace constraints.
    /// Empty values, values longer than `max_nonce_bytes`, or values containing space, newline, or carriage return return an error.
    /// On success, the nonce buffer is cleared and the new bytes are copied into place.
    pub fn set(self: *ReplayNonce, value: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.len <= max_nonce_bytes);

        if (value.len == 0) return error.InvalidNonce;
        if (value.len > max_nonce_bytes) return error.NonceTooLong;
        if (std.mem.indexOfScalar(u8, value, ' ')) |_| return error.InvalidNonce;
        if (std.mem.indexOfScalar(u8, value, '\n')) |_| return error.InvalidNonce;
        if (std.mem.indexOfScalar(u8, value, '\r')) |_| return error.InvalidNonce;

        @memset(self.bytes[0..], 0);
        @memcpy(self.bytes[0..value.len], value);
        self.len = @intCast(value.len);
        assert(self.len == @as(u16, @intCast(value.len)));
    }

    /// Returns the current replay nonce as a slice of bytes.
    /// The returned slice aliases the internal buffer and is valid until the nonce is replaced or the struct is discarded.
    /// `len` must not exceed `max_nonce_bytes`.
    pub fn slice(self: *const ReplayNonce) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.len <= max_nonce_bytes);
        return self.bytes[0..self.len];
    }
};

/// ACME directory endpoints discovered from the server's directory response.
/// Each field is stored inline as a `Url` and defaults to an empty value until populated.
/// Use these endpoints for nonce, account, and order creation requests.
pub const Directory = struct {
    new_nonce_url: Url = .{},
    new_account_url: Url = .{},
    new_order_url: Url = .{},
};

/// ACME account status values as represented by the client.
/// These variants reflect the server-reported state of an account.
pub const AccountStatus = enum(u8) {
    valid,
    deactivated,
    revoked,
};

/// ACME order status values as represented by the client.
/// These variants cover the order lifecycle returned by ACME servers.
pub const OrderStatus = enum(u8) {
    pending,
    ready,
    processing,
    valid,
    invalid,
};

/// ACME authorization status values as represented by the client.
/// These variants cover the authorization lifecycle returned by ACME servers.
pub const AuthorizationStatus = enum(u8) {
    pending,
    valid,
    invalid,
    deactivated,
    expired,
    revoked,
};

/// ACME challenge status values as represented by the client.
/// These variants track the server-reported lifecycle of an authorization challenge.
pub const ChallengeStatus = enum(u8) {
    pending,
    processing,
    valid,
    invalid,
};

/// Identifies the supported ACME challenge type.
/// This client currently models only `tls_alpn01`.
pub const ChallengeType = enum(u8) {
    tls_alpn01,
};

/// ACME challenge state for an authorization.
/// `challenge_type`, `status`, and `url` describe the challenge, while `token_len` and `token_bytes` store the challenge token inline.
/// Use `setToken` to validate and store a token, and `token` to read the currently stored slice.
pub const AuthorizationChallenge = struct {
    challenge_type: ChallengeType,
    status: ChallengeStatus,
    url: Url,
    token_len: u16 = 0,
    token_bytes: [max_challenge_token_bytes]u8 = [_]u8{0} ** max_challenge_token_bytes,

    /// Sets the challenge token to `token_value` after validating length and allowed characters.
    /// Empty tokens, tokens longer than `max_challenge_token_bytes`, or tokens containing non-alphanumeric, non-`-`, non-`_` bytes return `error.InvalidChallengeToken`.
    /// On success, the previous token bytes are cleared and the new token is copied into the fixed buffer.
    pub fn setToken(self: *AuthorizationChallenge, token_value: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.token_len <= max_challenge_token_bytes);
        if (token_value.len == 0 or token_value.len > max_challenge_token_bytes) return error.InvalidChallengeToken;
        const token_len: u16 = @intCast(token_value.len);

        var i: u16 = 0;
        while (i < token_len) : (i += 1) {
            const c = token_value[@intCast(i)];
            const is_digit = c >= '0' and c <= '9';
            const is_upper = c >= 'A' and c <= 'Z';
            const is_lower = c >= 'a' and c <= 'z';
            const is_dash = c == '-';
            const is_underscore = c == '_';
            if (!is_digit and !is_upper and !is_lower and !is_dash and !is_underscore) {
                return error.InvalidChallengeToken;
            }
        }

        @memset(self.token_bytes[0..], 0);
        @memcpy(self.token_bytes[0..token_value.len], token_value);
        self.token_len = token_len;
        assert(self.token_len == token_len);
    }

    /// Returns the active token bytes for this challenge.
    /// The slice aliases `self.token_bytes` and is limited to the current `token_len` value.
    /// `token_len` must not exceed `max_challenge_token_bytes`.
    pub fn token(self: *const AuthorizationChallenge) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.token_len <= max_challenge_token_bytes);
        return self.token_bytes[0..self.token_len];
    }
};

/// ACME authorization response state returned by the client.
/// `identifier_dns` and `challenges` are stored inline; `challenge_count` controls how many entries in `challenges` are considered valid.
/// Use `firstTlsAlpn01Challenge` to locate the first `tls_alpn01` challenge when one is present.
pub const AuthorizationResponse = struct {
    status: AuthorizationStatus,
    identifier_dns: acme_types.DomainName = .{},
    challenges: [max_challenges_per_authorization]AuthorizationChallenge = [_]AuthorizationChallenge{.{
        .challenge_type = .tls_alpn01,
        .status = .pending,
        .url = .{},
    }} ** max_challenges_per_authorization,
    challenge_count: u8 = 0,

    /// Returns the first `tls_alpn01` challenge stored on this authorization, or `null` if none exists.
    /// The returned pointer aliases `self.challenges` and stays valid only while `self` remains alive and unchanged.
    /// `self.challenge_count` must not exceed `max_challenges_per_authorization`.
    pub fn firstTlsAlpn01Challenge(self: *const AuthorizationResponse) ?*const AuthorizationChallenge {
        assert(@intFromPtr(self) != 0);
        assert(self.challenge_count <= max_challenges_per_authorization);

        var i: u8 = 0;
        while (i < self.challenge_count) : (i += 1) {
            const challenge = &self.challenges[i];
            if (challenge.challenge_type == .tls_alpn01) return challenge;
        }
        return null;
    }
};

/// Parsed ACME account response data.
/// `status` is required; `orders_url` is optional and only valid when `has_orders_url` is set.
/// The URL field is copied into the struct, so the returned value does not borrow from the source JSON.
pub const AccountResponse = struct {
    status: AccountStatus,
    has_orders_url: bool = false,
    orders_url: Url = .{},
};

/// Mutable builder for an ACME new-order request.
/// The request stores up to `max_identifiers_per_order` DNS identifiers and tracks the number of populated entries explicitly.
/// Use `init`, `addIdentifier`, and `initFromRuntimeConfig` to construct a request before passing it to the serializer.
pub const NewOrderRequest = struct {
    identifiers: [max_identifiers_per_order]acme_types.DomainName = [_]acme_types.DomainName{.{}} ** max_identifiers_per_order,
    identifier_count: u8 = 0,

    /// Creates an empty `NewOrderRequest`.
    /// The returned value has `identifier_count == 0` and all identifier slots zero-initialized.
    /// Call `addIdentifier` to populate the request before serialization.
    pub fn init() NewOrderRequest {
        assert(max_identifiers_per_order > 0);
        const request = NewOrderRequest{};
        assert(request.identifier_count == 0);
        return request;
    }

    /// Appends one identifier to a new-order request.
    /// The request must have remaining capacity in `identifiers`, and the domain is validated before being stored.
    /// Returns `error.TooManyIdentifiers` when the request is full, or `error.InvalidDomainName` if the domain cannot be represented.
    pub fn addIdentifier(self: *NewOrderRequest, domain: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);

        if (self.identifier_count >= max_identifiers_per_order) return error.TooManyIdentifiers;
        const slot_index: u8 = self.identifier_count;
        self.identifiers[slot_index].set(domain) catch |err| switch (err) {
            error.InvalidDomainName, error.DomainTooLong => return error.InvalidDomainName,
            else => return error.InvalidDomainName,
        };

        self.identifier_count += 1;
        assert(self.identifier_count <= max_identifiers_per_order);
    }

    /// Builds a `NewOrderRequest` from a runtime configuration.
    /// The runtime must not be null, and `runtime.domain_count` must not exceed `max_identifiers_per_order`.
    /// Returns `error.InvalidIdentifierCount` for an empty domain list and `error.InvalidDomainName` if any runtime domain is missing or invalid.
    pub fn initFromRuntimeConfig(runtime: *const acme_types.RuntimeConfig) Error!NewOrderRequest {
        assert(@intFromPtr(runtime) != 0);
        assert(runtime.domain_count <= max_identifiers_per_order);

        var request = NewOrderRequest.init();
        if (runtime.domain_count == 0) return error.InvalidIdentifierCount;

        var index: u8 = 0;
        while (index < runtime.domain_count) : (index += 1) {
            const domain = runtime.domainAt(index) orelse return error.InvalidDomainName;
            try request.addIdentifier(domain);
        }

        assert(request.identifier_count == runtime.domain_count);
        return request;
    }
};

/// Parsed ACME order response data.
/// `finalize_url` is always required; `authorization_urls` stores up to `max_authorization_urls_per_order` entries.
/// `authorization_count` tracks how many entries are valid, and `has_certificate_url` indicates whether `certificate_url` was present.
pub const OrderResponse = struct {
    status: OrderStatus,
    finalize_url: Url,
    authorization_urls: [max_authorization_urls_per_order]Url = [_]Url{.{}} ** max_authorization_urls_per_order,
    authorization_count: u8 = 0,
    has_certificate_url: bool = false,
    certificate_url: Url = .{},
};

/// Payload used to create a new ACME account.
/// `contact_email` is the caller-provided address string; the serializer wraps it as a `mailto:` contact entry.
/// `terms_of_service_agreed` and `only_return_existing` default to the ACME-friendly values used by the serializer.
pub const NewAccountPayload = struct {
    contact_email: []const u8,
    terms_of_service_agreed: bool = true,
    only_return_existing: bool = false,
};

/// Parses the ACME directory response from JSON.
/// Requires `newNonce`, `newAccount`, and `newOrder`, and rejects bodies larger than `max_directory_response_bytes`.
/// Unknown fields are ignored; JSON parse failures are mapped through `mapJsonParseError`, and the returned `Directory` owns copied URL values.
pub fn parseDirectoryResponseJson(json_body: []const u8) Error!Directory {
    assert(max_directory_response_bytes > 0);
    assert(json_parse_scratch_size_bytes > 0);
    if (json_body.len == 0) return error.EmptyInput;
    if (json_body.len > max_directory_response_bytes) return error.ResponseTooLarge;

    const DirectoryJson = struct {
        newNonce: ?[]const u8 = null,
        newAccount: ?[]const u8 = null,
        newOrder: ?[]const u8 = null,
    };

    var scratch: [json_parse_scratch_size_bytes]u8 = undefined;
    var fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(&scratch);

    const parsed = std.json.parseFromSlice(
        DirectoryJson,
        fixed_buffer_allocator.allocator(),
        json_body,
        .{ .ignore_unknown_fields = true },
    ) catch |err| return mapJsonParseError(err);
    defer parsed.deinit();

    const nonce_raw = parsed.value.newNonce orelse return error.MissingDirectoryEndpoint;
    const account_raw = parsed.value.newAccount orelse return error.MissingDirectoryEndpoint;
    const order_raw = parsed.value.newOrder orelse return error.MissingDirectoryEndpoint;

    var directory = Directory{};
    try directory.new_nonce_url.set(nonce_raw);
    try directory.new_account_url.set(account_raw);
    try directory.new_order_url.set(order_raw);
    assert(directory.new_nonce_url.slice().len > 0);
    return directory;
}

/// Parses and stores a replay-nonce header value.
/// The input is copied into the returned `ReplayNonce`, so the result does not borrow from `replay_nonce_value`.
/// Returns any validation error reported by `ReplayNonce.set`.
pub fn parseReplayNonceHeader(replay_nonce_value: []const u8) Error!ReplayNonce {
    assert(max_nonce_bytes > 0);
    var nonce = ReplayNonce{};
    try nonce.set(replay_nonce_value);
    assert(nonce.slice().len == replay_nonce_value.len);
    return nonce;
}

/// Parses and stores a `Location` header value as a URL.
/// The input is copied into the returned `Url`, so the result does not borrow from `location_header_value`.
/// Returns any validation error reported by `Url.set`.
pub fn parseLocationHeader(location_header_value: []const u8) Error!Url {
    assert(max_url_bytes > 0);
    var location = Url{};
    try location.set(location_header_value);
    assert(location.slice().len == location_header_value.len);
    return location;
}

/// Parses an ACME account response from JSON.
/// Requires a non-empty body within `max_account_response_bytes` and a `status` field; `orders` is optional.
/// Unknown fields are ignored; JSON parse failures are mapped through `mapJsonParseError`, and any present orders URL is copied into the returned response.
pub fn parseAccountResponseJson(json_body: []const u8) Error!AccountResponse {
    assert(max_account_response_bytes > 0);
    assert(json_parse_scratch_size_bytes > 0);
    if (json_body.len == 0) return error.EmptyInput;
    if (json_body.len > max_account_response_bytes) return error.ResponseTooLarge;

    const AccountJson = struct {
        status: ?[]const u8 = null,
        orders: ?[]const u8 = null,
    };

    var scratch: [json_parse_scratch_size_bytes]u8 = undefined;
    var fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(&scratch);

    const parsed = std.json.parseFromSlice(
        AccountJson,
        fixed_buffer_allocator.allocator(),
        json_body,
        .{ .ignore_unknown_fields = true },
    ) catch |err| return mapJsonParseError(err);
    defer parsed.deinit();

    const status_raw = parsed.value.status orelse return error.MissingAccountField;

    var response = AccountResponse{
        .status = try parseAccountStatus(status_raw),
    };

    if (parsed.value.orders) |orders_url| {
        response.has_orders_url = true;
        try response.orders_url.set(orders_url);
    }

    assert(!response.has_orders_url or response.orders_url.slice().len > 0);
    return response;
}

/// Parses an ACME order response from JSON.
/// Requires `status`, `finalize`, and `authorizations`, with the authorization URL count capped by `max_authorization_urls_per_order`.
/// Unknown fields are ignored; JSON parse failures are mapped through `mapJsonParseError`, and any parsed URLs are copied into the returned response.
pub fn parseOrderResponseJson(json_body: []const u8) Error!OrderResponse {
    assert(max_order_response_bytes > 0);
    assert(max_authorization_urls_per_order > 0);
    if (json_body.len == 0) return error.EmptyInput;
    if (json_body.len > max_order_response_bytes) return error.ResponseTooLarge;

    const OrderJson = struct {
        status: ?[]const u8 = null,
        authorizations: ?[]const []const u8 = null,
        finalize: ?[]const u8 = null,
        certificate: ?[]const u8 = null,
    };

    var scratch: [json_parse_scratch_size_bytes]u8 = undefined;
    var fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(&scratch);

    const parsed = std.json.parseFromSlice(
        OrderJson,
        fixed_buffer_allocator.allocator(),
        json_body,
        .{ .ignore_unknown_fields = true },
    ) catch |err| return mapJsonParseError(err);
    defer parsed.deinit();

    const status_raw = parsed.value.status orelse return error.MissingOrderField;
    const final_url_raw = parsed.value.finalize orelse return error.MissingOrderField;
    const authorization_urls = parsed.value.authorizations orelse return error.MissingOrderField;

    if (authorization_urls.len > max_authorization_urls_per_order) {
        return error.TooManyAuthorizations;
    }
    const authorization_count: u8 = @intCast(authorization_urls.len);

    var response = OrderResponse{
        .status = try parseOrderStatus(status_raw),
        .finalize_url = .{},
    };
    try response.finalize_url.set(final_url_raw);

    var index: u8 = 0;
    while (index < authorization_count) : (index += 1) {
        try response.authorization_urls[index].set(authorization_urls[index]);
        response.authorization_count += 1;
    }
    assert(response.authorization_count == authorization_count);

    if (parsed.value.certificate) |certificate_url| {
        response.has_certificate_url = true;
        try response.certificate_url.set(certificate_url);
    }

    assert(response.authorization_count <= max_authorization_urls_per_order);
    return response;
}

/// Parses an ACME authorization response from JSON.
/// Requires a non-empty body within `max_order_response_bytes`, and expects `status`, `identifier`, and `challenges` fields.
/// The identifier must be `dns`, challenge count is bounded by `max_challenges_per_authorization`, and JSON parse failures are mapped through `mapJsonParseError`.
pub fn parseAuthorizationResponseJson(json_body: []const u8) Error!AuthorizationResponse {
    assert(max_order_response_bytes > 0);
    assert(max_challenges_per_authorization > 0);
    if (json_body.len == 0) return error.EmptyInput;
    if (json_body.len > max_order_response_bytes) return error.ResponseTooLarge;

    const ChallengeJson = struct {
        type: ?[]const u8 = null,
        status: ?[]const u8 = null,
        url: ?[]const u8 = null,
        token: ?[]const u8 = null,
    };
    const IdentifierJson = struct {
        type: ?[]const u8 = null,
        value: ?[]const u8 = null,
    };
    const AuthorizationJson = struct {
        status: ?[]const u8 = null,
        identifier: ?IdentifierJson = null,
        challenges: ?[]const ChallengeJson = null,
    };

    var scratch: [json_parse_scratch_size_bytes]u8 = undefined;
    var fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(&scratch);

    const parsed = std.json.parseFromSlice(
        AuthorizationJson,
        fixed_buffer_allocator.allocator(),
        json_body,
        .{ .ignore_unknown_fields = true },
    ) catch |err| return mapJsonParseError(err);
    defer parsed.deinit();
    const status_raw = parsed.value.status orelse return error.MissingOrderField;
    const identifier = parsed.value.identifier orelse return error.MissingOrderField;
    const identifier_type = identifier.type orelse return error.MissingOrderField;
    const identifier_value = identifier.value orelse return error.MissingOrderField;
    if (!std.mem.eql(u8, identifier_type, "dns")) return error.InvalidDomainName;
    const challenges = parsed.value.challenges orelse return error.MissingOrderField;
    if (challenges.len > max_challenges_per_authorization) return error.TooManyChallenges;
    const challenges_len: u8 = @intCast(challenges.len);
    var response = AuthorizationResponse{ .status = try parseAuthorizationStatus(status_raw) };
    response.identifier_dns.set(identifier_value) catch return error.InvalidDomainName;

    var i: u8 = 0;
    while (i < challenges_len) : (i += 1) {
        const challenge = challenges[@intCast(i)];
        const challenge_type_raw = challenge.type orelse return error.MissingOrderField;
        const challenge_type = parseChallengeTypeOptional(challenge_type_raw) orelse continue;

        const challenge_status_raw = challenge.status orelse return error.MissingOrderField;
        const challenge_url_raw = challenge.url orelse return error.MissingOrderField;

        if (response.challenge_count >= max_challenges_per_authorization) return error.TooManyChallenges;
        const out_index: u8 = response.challenge_count;
        response.challenges[out_index] = .{
            .challenge_type = challenge_type,
            .status = try parseChallengeStatus(challenge_status_raw),
            .url = .{},
        };
        try response.challenges[out_index].url.set(challenge_url_raw);

        if (challenge.token) |token_raw| {
            try response.challenges[out_index].setToken(token_raw);
        }
        response.challenge_count += 1;
    }

    assert(response.challenge_count <= max_challenges_per_authorization);
    return response;
}

/// Serializes a finalize payload containing a DER CSR into ACME JSON.
/// The CSR must be non-empty; the function base64url-encodes it into `out` and returns a slice of the rendered body.
/// Returns `error.OutputTooSmall` if the encoded payload does not fit in `out` or would exceed `max_jws_body_bytes`.
pub fn serializeFinalizePayload(out: []u8, csr_der: []const u8) Error![]const u8 {
    assert(max_jws_body_bytes > 0);
    assert(csr_der.len <= std.math.maxInt(u32));
    assert(max_jws_body_bytes <= std.math.maxInt(u32));
    if (csr_der.len == 0) return error.OutputTooSmall;

    const csr_b64_len = std.base64.url_safe_no_pad.Encoder.calcSize(csr_der.len);
    if (csr_b64_len + 10 > out.len) return error.OutputTooSmall;
    if (csr_b64_len > std.math.maxInt(u32)) return error.OutputTooSmall;

    var cursor: u32 = 0;
    cursor = try appendToOutput(out, cursor, "{\"csr\":\"");
    const csr_b64_len_u32: u32 = @intCast(csr_b64_len);
    const csr_b64_end = cursor + csr_b64_len_u32;
    _ = std.base64.url_safe_no_pad.Encoder.encode(out[@intCast(cursor)..@intCast(csr_b64_end)], csr_der);
    cursor = csr_b64_end;
    cursor = try appendToOutput(out, cursor, "\"}");
    if (cursor > max_jws_body_bytes) return error.OutputTooSmall;
    assert(cursor <= @as(u32, @intCast(out.len)));

    return out[0..@intCast(cursor)];
}

/// Serializes a new-account payload into `out` as ACME JSON.
/// The contact email must be non-empty, fit within `max_contact_email_bytes`, and pass JSON-string validation.
/// Returns a slice of `out`, or `error.OutputTooSmall` when the buffer cannot hold the rendered payload or the JWS body limit would be exceeded.
pub fn serializeNewAccountPayload(
    out: []u8,
    payload: NewAccountPayload,
) Error![]const u8 {
    assert(max_contact_email_bytes > 0);
    assert(max_jws_body_bytes > 0);
    if (payload.contact_email.len == 0) return error.InvalidContactEmail;
    if (payload.contact_email.len > max_contact_email_bytes) return error.InvalidContactEmail;
    validateJsonString(payload.contact_email) catch return error.InvalidContactEmail;

    const terms_value = if (payload.terms_of_service_agreed) "true" else "false";
    const existing_value = if (payload.only_return_existing) "true" else "false";

    const rendered = std.fmt.bufPrint(
        out,
        "{{\"termsOfServiceAgreed\":{s},\"onlyReturnExisting\":{s},\"contact\":[\"mailto:{s}\"]}}",
        .{ terms_value, existing_value, payload.contact_email },
    ) catch return error.OutputTooSmall;

    if (rendered.len > max_jws_body_bytes) return error.OutputTooSmall;
    assert(rendered.len <= out.len);
    return rendered;
}

/// Serializes a new-order payload into `out` as ACME JSON.
/// Returns a slice of `out` containing the rendered body, or `error.OutputTooSmall` if the buffer or JWS body limit is exceeded.
/// Rejects empty identifier lists, empty domain names, and domain strings that fail JSON-string validation.
pub fn serializeNewOrderPayload(out: []u8, request: *const NewOrderRequest) Error![]const u8 {
    assert(@intFromPtr(request) != 0);
    assert(request.identifier_count <= max_identifiers_per_order);

    if (request.identifier_count == 0) return error.InvalidIdentifierCount;

    var cursor: u32 = 0;
    cursor = try appendToOutput(out, cursor, "{\"identifiers\":[");

    var index: u8 = 0;
    while (index < request.identifier_count) : (index += 1) {
        const domain = request.identifiers[index].slice();
        if (domain.len == 0) return error.InvalidDomainName;
        validateJsonString(domain) catch return error.InvalidDomainName;

        if (index > 0) {
            cursor = try appendToOutput(out, cursor, ",");
        }

        cursor = try appendToOutput(out, cursor, "{\"type\":\"dns\",\"value\":\"");
        cursor = try appendToOutput(out, cursor, domain);
        cursor = try appendToOutput(out, cursor, "\"}");
    }

    cursor = try appendToOutput(out, cursor, "]}");
    if (cursor > max_jws_body_bytes) return error.OutputTooSmall;
    return out[0..@intCast(cursor)];
}

fn parseAccountStatus(value: []const u8) Error!AccountStatus {
    assert(@sizeOf(AccountStatus) == 1);
    assert(value.len <= max_account_response_bytes);
    if (std.mem.eql(u8, value, "valid")) return .valid;
    if (std.mem.eql(u8, value, "deactivated")) return .deactivated;
    if (std.mem.eql(u8, value, "revoked")) return .revoked;
    return error.InvalidAccountStatus;
}

fn parseOrderStatus(value: []const u8) Error!OrderStatus {
    assert(@sizeOf(OrderStatus) == 1);
    assert(value.len <= max_order_response_bytes);
    if (std.mem.eql(u8, value, "pending")) return .pending;
    if (std.mem.eql(u8, value, "ready")) return .ready;
    if (std.mem.eql(u8, value, "processing")) return .processing;
    if (std.mem.eql(u8, value, "valid")) return .valid;
    if (std.mem.eql(u8, value, "invalid")) return .invalid;
    return error.InvalidOrderStatus;
}

fn parseAuthorizationStatus(value: []const u8) Error!AuthorizationStatus {
    assert(@sizeOf(AuthorizationStatus) == 1);
    assert(value.len <= max_order_response_bytes);
    if (std.mem.eql(u8, value, "pending")) return .pending;
    if (std.mem.eql(u8, value, "valid")) return .valid;
    if (std.mem.eql(u8, value, "invalid")) return .invalid;
    if (std.mem.eql(u8, value, "deactivated")) return .deactivated;
    if (std.mem.eql(u8, value, "expired")) return .expired;
    if (std.mem.eql(u8, value, "revoked")) return .revoked;
    return error.InvalidAuthorizationStatus;
}

fn parseChallengeStatus(value: []const u8) Error!ChallengeStatus {
    assert(@sizeOf(ChallengeStatus) == 1);
    assert(value.len <= max_order_response_bytes);
    if (std.mem.eql(u8, value, "pending")) return .pending;
    if (std.mem.eql(u8, value, "processing")) return .processing;
    if (std.mem.eql(u8, value, "valid")) return .valid;
    if (std.mem.eql(u8, value, "invalid")) return .invalid;
    return error.InvalidChallengeStatus;
}

fn parseChallengeTypeOptional(value: []const u8) ?ChallengeType {
    assert(@sizeOf(ChallengeType) == 1);
    assert(value.len <= max_order_response_bytes);
    if (std.mem.eql(u8, value, "tls-alpn-01")) return .tls_alpn01;
    return null;
}

fn mapJsonParseError(err: anyerror) Error {
    assert(@typeInfo(@TypeOf(err)) == .error_set);
    assert(json_parse_scratch_size_bytes > 0);
    return switch (err) {
        error.OutOfMemory => error.JsonScratchExhausted,
        else => error.JsonParseFailed,
    };
}

fn validateJsonString(value: []const u8) Error!void {
    assert(max_jws_body_bytes > 0);
    assert(value.len <= max_jws_body_bytes);
    const value_len: u32 = @intCast(value.len);
    var index: u32 = 0;
    while (index < value_len) : (index += 1) {
        const c = value[@intCast(index)];
        if (c < 0x20) return error.InvalidDomainName;
        if (c == '"') return error.InvalidDomainName;
        if (c == '\\') return error.InvalidDomainName;
    }
}

fn appendToOutput(out: []u8, cursor: u32, chunk: []const u8) Error!u32 {
    assert(out.len <= output_cursor_max);
    const out_len_u32: u32 = @intCast(out.len);
    assert(cursor <= out_len_u32);
    assert(chunk.len <= out_len_u32);

    const chunk_len_u32: u32 = @intCast(chunk.len);
    if (chunk_len_u32 > out_len_u32 - cursor) return error.OutputTooSmall;
    @memcpy(out[@intCast(cursor)..][0..chunk.len], chunk);
    return cursor + chunk_len_u32;
}

test "parseDirectoryResponseJson reads required endpoints" {
    const body =
        "{" ++
        "\"newNonce\":\"https://acme.example/new-nonce\"," ++
        "\"newAccount\":\"https://acme.example/new-account\"," ++
        "\"newOrder\":\"https://acme.example/new-order\"" ++
        "}";

    const directory = try parseDirectoryResponseJson(body);
    try std.testing.expect(std.mem.eql(u8, "https://acme.example/new-nonce", directory.new_nonce_url.slice()));
    try std.testing.expect(std.mem.eql(u8, "https://acme.example/new-account", directory.new_account_url.slice()));
    try std.testing.expect(std.mem.eql(u8, "https://acme.example/new-order", directory.new_order_url.slice()));
}

test "parseReplayNonceHeader validates bounds" {
    const nonce = try parseReplayNonceHeader("abc123_nonce");
    try std.testing.expect(std.mem.eql(u8, "abc123_nonce", nonce.slice()));

    try std.testing.expectError(error.InvalidNonce, parseReplayNonceHeader(""));
}

test "parseDirectoryResponseJson rejects missing endpoint" {
    const body =
        "{" ++
        "\"newNonce\":\"https://acme.example/new-nonce\"," ++
        "\"newAccount\":\"https://acme.example/new-account\"" ++
        "}";

    try std.testing.expectError(error.MissingDirectoryEndpoint, parseDirectoryResponseJson(body));
}

test "serializeNewAccountPayload emits deterministic body" {
    var out: [max_jws_body_bytes]u8 = undefined;
    const payload = NewAccountPayload{
        .contact_email = "ops@example.com",
        .terms_of_service_agreed = true,
        .only_return_existing = false,
    };

    const encoded = try serializeNewAccountPayload(&out, payload);
    try std.testing.expectEqualStrings(
        "{\"termsOfServiceAgreed\":true,\"onlyReturnExisting\":false,\"contact\":[\"mailto:ops@example.com\"]}",
        encoded,
    );
}

test "serializeNewOrderPayload encodes identifiers" {
    var request = NewOrderRequest.init();
    try request.addIdentifier("example.com");
    try request.addIdentifier("api.example.com");

    var out: [max_jws_body_bytes]u8 = undefined;
    const encoded = try serializeNewOrderPayload(&out, &request);

    try std.testing.expectEqualStrings(
        "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"example.com\"},{\"type\":\"dns\",\"value\":\"api.example.com\"}]}",
        encoded,
    );
}

test "NewOrderRequest initFromRuntimeConfig copies configured domains" {
    const acme_cfg = config.AcmeConfig{
        .enabled = true,
        .directory_url = "https://acme.example/directory",
        .contact_email = "ops@example.com",
        .state_dir_path = "/var/lib/serval/acme",
        .domains = &.{ "example.com", "api.example.com" },
    };
    const runtime = try acme_types.RuntimeConfig.initFromConfig(acme_cfg);

    const request = try NewOrderRequest.initFromRuntimeConfig(&runtime);
    try std.testing.expectEqual(@as(u8, 2), request.identifier_count);
    try std.testing.expectEqualStrings("example.com", request.identifiers[0].slice());
    try std.testing.expectEqualStrings("api.example.com", request.identifiers[1].slice());
}

test "parseOrderResponseJson parses response fields" {
    const body =
        "{" ++
        "\"status\":\"pending\"," ++
        "\"authorizations\":[" ++
        "\"https://acme.example/authz/1\"," ++
        "\"https://acme.example/authz/2\"" ++
        "]," ++
        "\"finalize\":\"https://acme.example/order/1/finalize\"," ++
        "\"certificate\":\"https://acme.example/cert/1\"" ++
        "}";

    const response = try parseOrderResponseJson(body);
    try std.testing.expectEqual(OrderStatus.pending, response.status);
    try std.testing.expectEqual(@as(u8, 2), response.authorization_count);
    try std.testing.expect(response.has_certificate_url);
    try std.testing.expectEqualStrings(
        "https://acme.example/order/1/finalize",
        response.finalize_url.slice(),
    );
}

test "parseAccountResponseJson parses status and orders url" {
    const body =
        "{" ++
        "\"status\":\"valid\"," ++
        "\"orders\":\"https://acme.example/account/1/orders\"" ++
        "}";

    const response = try parseAccountResponseJson(body);
    try std.testing.expectEqual(AccountStatus.valid, response.status);
    try std.testing.expect(response.has_orders_url);
    try std.testing.expectEqualStrings(
        "https://acme.example/account/1/orders",
        response.orders_url.slice(),
    );
}

test "parseAccountResponseJson rejects unknown status" {
    const body = "{\"status\":\"pending\"}";
    try std.testing.expectError(error.InvalidAccountStatus, parseAccountResponseJson(body));
}

test "parseOrderResponseJson rejects too many authorization urls" {
    var body_buf: [4096]u8 = undefined;
    var cursor: u32 = 0;

    cursor = try appendToOutput(&body_buf, cursor, "{\"status\":\"pending\",\"authorizations\":[");

    var index: u16 = 0;
    while (index < max_authorization_urls_per_order + 1) : (index += 1) {
        if (index > 0) {
            cursor = try appendToOutput(&body_buf, cursor, ",");
        }

        var url_buf: [96]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "\"https://acme.example/authz/{d}\"", .{index});
        cursor = try appendToOutput(&body_buf, cursor, url);
    }

    cursor = try appendToOutput(
        &body_buf,
        cursor,
        "],\"finalize\":\"https://acme.example/order/finalize\"}",
    );

    try std.testing.expectError(error.TooManyAuthorizations, parseOrderResponseJson(body_buf[0..@intCast(cursor)]));
}

test "parseAuthorizationResponseJson parses tls-alpn-01 and ignores unsupported challenge types" {
    const body =
        "{" ++
        "\"status\":\"pending\"," ++
        "\"identifier\":{\"type\":\"dns\",\"value\":\"example.com\"}," ++
        "\"challenges\":[{" ++
        "\"type\":\"dns-01\"," ++
        "\"status\":\"pending\"," ++
        "\"url\":\"https://acme.example/challenge/1\"," ++
        "\"token\":\"abc123_TOKEN\"" ++
        "},{" ++
        "\"type\":\"tls-alpn-01\"," ++
        "\"status\":\"pending\"," ++
        "\"url\":\"https://acme.example/challenge/2\"," ++
        "\"token\":\"def456_TOKEN\"" ++
        "}]" ++
        "}";

    const authorization = try parseAuthorizationResponseJson(body);
    try std.testing.expectEqual(AuthorizationStatus.pending, authorization.status);
    try std.testing.expectEqual(@as(u8, 1), authorization.challenge_count);

    const tls_challenge = authorization.firstTlsAlpn01Challenge() orelse return error.MissingOrderField;
    try std.testing.expectEqual(ChallengeType.tls_alpn01, tls_challenge.challenge_type);
    try std.testing.expectEqualStrings("def456_TOKEN", tls_challenge.token());
}

test "serializeFinalizePayload encodes csr as base64url" {
    var out: [max_jws_body_bytes]u8 = undefined;
    const payload = try serializeFinalizePayload(&out, &[_]u8{ 0x30, 0x82, 0x01, 0x22 });
    try std.testing.expect(std.mem.startsWith(u8, payload, "{\"csr\":\""));
    try std.testing.expect(std.mem.endsWith(u8, payload, "\"}"));
}
