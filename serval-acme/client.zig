//! ACME protocol client primitives (directory/nonce/account/order).
//!
//! TigerStyle: Bounded parsing/serialization, explicit protocol types,
//! no hidden allocation.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("serval-core").config;
const acme_types = @import("types.zig");

const max_url_bytes: usize = config.ACME_MAX_DIRECTORY_URL_BYTES;
const max_nonce_bytes: usize = config.ACME_MAX_NONCE_BYTES;
const max_contact_email_bytes: usize = config.ACME_MAX_CONTACT_EMAIL_BYTES;
const max_identifiers_per_order: usize = config.ACME_MAX_DOMAINS_PER_CERT;
const max_authorization_urls_per_order: usize = config.ACME_MAX_AUTHORIZATION_URLS_PER_ORDER;
const max_directory_response_bytes: usize = config.ACME_MAX_DIRECTORY_RESPONSE_BYTES;
const max_account_response_bytes: usize = config.ACME_MAX_ACCOUNT_RESPONSE_BYTES;
const max_order_response_bytes: usize = config.ACME_MAX_ORDER_RESPONSE_BYTES;
const max_jws_body_bytes: usize = config.ACME_MAX_JWS_BODY_BYTES;

const json_parse_scratch_size_bytes: usize = 8192;

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
    TooManyIdentifiers,
    TooManyAuthorizations,
    OutputTooSmall,
};

/// Bounded URL storage used by ACME endpoint and resource links.
pub const Url = struct {
    len: u16 = 0,
    bytes: [max_url_bytes]u8 = [_]u8{0} ** max_url_bytes,

    pub fn set(self: *Url, value: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);

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
    }

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

    pub fn set(self: *ReplayNonce, value: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);

        if (value.len == 0) return error.InvalidNonce;
        if (value.len > max_nonce_bytes) return error.NonceTooLong;
        if (std.mem.indexOfScalar(u8, value, ' ')) |_| return error.InvalidNonce;
        if (std.mem.indexOfScalar(u8, value, '\n')) |_| return error.InvalidNonce;
        if (std.mem.indexOfScalar(u8, value, '\r')) |_| return error.InvalidNonce;

        @memset(self.bytes[0..], 0);
        @memcpy(self.bytes[0..value.len], value);
        self.len = @intCast(value.len);
    }

    pub fn slice(self: *const ReplayNonce) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.len <= max_nonce_bytes);
        return self.bytes[0..self.len];
    }
};

pub const Directory = struct {
    new_nonce_url: Url = .{},
    new_account_url: Url = .{},
    new_order_url: Url = .{},
};

pub const AccountStatus = enum(u8) {
    valid,
    deactivated,
    revoked,
};

pub const OrderStatus = enum(u8) {
    pending,
    ready,
    processing,
    valid,
    invalid,
};

pub const AccountResponse = struct {
    status: AccountStatus,
    has_orders_url: bool = false,
    orders_url: Url = .{},
};

pub const NewOrderRequest = struct {
    identifiers: [max_identifiers_per_order]acme_types.DomainName = [_]acme_types.DomainName{.{}} ** max_identifiers_per_order,
    identifier_count: u8 = 0,

    pub fn init() NewOrderRequest {
        return .{};
    }

    pub fn addIdentifier(self: *NewOrderRequest, domain: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);

        if (self.identifier_count >= max_identifiers_per_order) return error.TooManyIdentifiers;
        const slot_index: usize = self.identifier_count;
        self.identifiers[slot_index].set(domain) catch |err| switch (err) {
            error.InvalidDomainName, error.DomainTooLong => return error.InvalidDomainName,
            else => return error.InvalidDomainName,
        };

        self.identifier_count += 1;
        assert(self.identifier_count <= max_identifiers_per_order);
    }

    pub fn initFromRuntimeConfig(runtime: *const acme_types.RuntimeConfig) Error!NewOrderRequest {
        assert(@intFromPtr(runtime) != 0);

        var request = NewOrderRequest.init();
        if (runtime.domain_count == 0) return error.InvalidIdentifierCount;

        var index: u8 = 0;
        while (index < runtime.domain_count) : (index += 1) {
            const domain = runtime.domainAt(index) orelse return error.InvalidDomainName;
            try request.addIdentifier(domain);
        }

        return request;
    }
};

pub const OrderResponse = struct {
    status: OrderStatus,
    finalize_url: Url,
    authorization_urls: [max_authorization_urls_per_order]Url = [_]Url{.{}} ** max_authorization_urls_per_order,
    authorization_count: u8 = 0,
    has_certificate_url: bool = false,
    certificate_url: Url = .{},
};

pub const NewAccountPayload = struct {
    contact_email: []const u8,
    terms_of_service_agreed: bool = true,
    only_return_existing: bool = false,
};

pub fn parseDirectoryResponseJson(json_body: []const u8) Error!Directory {
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
    return directory;
}

pub fn parseReplayNonceHeader(replay_nonce_value: []const u8) Error!ReplayNonce {
    var nonce = ReplayNonce{};
    try nonce.set(replay_nonce_value);
    return nonce;
}

pub fn parseLocationHeader(location_header_value: []const u8) Error!Url {
    var location = Url{};
    try location.set(location_header_value);
    return location;
}

pub fn parseAccountResponseJson(json_body: []const u8) Error!AccountResponse {
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

    return response;
}

pub fn parseOrderResponseJson(json_body: []const u8) Error!OrderResponse {
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

    var response = OrderResponse{
        .status = try parseOrderStatus(status_raw),
        .finalize_url = .{},
    };
    try response.finalize_url.set(final_url_raw);

    var index: usize = 0;
    while (index < authorization_urls.len) : (index += 1) {
        try response.authorization_urls[index].set(authorization_urls[index]);
        response.authorization_count += 1;
    }
    assert(@as(usize, response.authorization_count) == authorization_urls.len);

    if (parsed.value.certificate) |certificate_url| {
        response.has_certificate_url = true;
        try response.certificate_url.set(certificate_url);
    }

    return response;
}

pub fn serializeNewAccountPayload(
    out: []u8,
    payload: NewAccountPayload,
) Error![]const u8 {
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
    return rendered;
}

pub fn serializeNewOrderPayload(out: []u8, request: *const NewOrderRequest) Error![]const u8 {
    assert(@intFromPtr(request) != 0);

    if (request.identifier_count == 0) return error.InvalidIdentifierCount;

    var cursor: usize = 0;
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
    return out[0..cursor];
}

fn parseAccountStatus(value: []const u8) Error!AccountStatus {
    if (std.mem.eql(u8, value, "valid")) return .valid;
    if (std.mem.eql(u8, value, "deactivated")) return .deactivated;
    if (std.mem.eql(u8, value, "revoked")) return .revoked;
    return error.InvalidAccountStatus;
}

fn parseOrderStatus(value: []const u8) Error!OrderStatus {
    if (std.mem.eql(u8, value, "pending")) return .pending;
    if (std.mem.eql(u8, value, "ready")) return .ready;
    if (std.mem.eql(u8, value, "processing")) return .processing;
    if (std.mem.eql(u8, value, "valid")) return .valid;
    if (std.mem.eql(u8, value, "invalid")) return .invalid;
    return error.InvalidOrderStatus;
}

fn mapJsonParseError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.JsonScratchExhausted,
        else => error.JsonParseFailed,
    };
}

fn validateJsonString(value: []const u8) Error!void {
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const c = value[index];
        if (c < 0x20) return error.InvalidDomainName;
        if (c == '"') return error.InvalidDomainName;
        if (c == '\\') return error.InvalidDomainName;
    }
}

fn appendToOutput(out: []u8, cursor: usize, chunk: []const u8) Error!usize {
    assert(cursor <= out.len);

    if (cursor + chunk.len > out.len) return error.OutputTooSmall;
    @memcpy(out[cursor..][0..chunk.len], chunk);
    return cursor + chunk.len;
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
    var cursor: usize = 0;

    cursor = try appendToOutput(&body_buf, cursor, "{\"status\":\"pending\",\"authorizations\":[");

    var index: usize = 0;
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

    try std.testing.expectError(error.TooManyAuthorizations, parseOrderResponseJson(body_buf[0..cursor]));
}
