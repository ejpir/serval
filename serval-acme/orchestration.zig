//! ACME request/response orchestration helpers.
//!
//! Provides deterministic endpoint selection, nonce carry, and status/error
//! classification for account/order flows. Transport execution and signing are
//! intentionally out-of-scope.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const config = core.config;
const HeaderMap = core.HeaderMap;
const Method = core.types.Method;
const client = @import("client.zig");
const wire = @import("wire.zig");

const max_problem_document_bytes: usize = @intCast(@max(config.ACME_MAX_ACCOUNT_RESPONSE_BYTES, config.ACME_MAX_ORDER_RESPONSE_BYTES));
const problem_parse_scratch_size_bytes: usize = 2048;

pub const Error = error{
    NonceUnavailable,
    AccountUrlUnavailable,
    OrderUrlUnavailable,
    FinalizeUrlUnavailable,
    SignedBodyRequired,
};

pub const ProtocolError = Error || client.Error || wire.Error;

pub const Operation = enum(u8) {
    fetch_nonce,
    new_account,
    new_order,
    fetch_account,
    fetch_order,
    finalize_order,
};

pub const Endpoint = enum(u8) {
    directory_new_nonce,
    directory_new_account,
    directory_new_order,
    account,
    order,
    finalize,
};

pub const ResponseOutcome = enum(u8) {
    success,
    retry_with_new_nonce,
    retry_with_backoff,
    fatal,
};

pub const ResponseReason = enum(u8) {
    none,
    bad_nonce,
    rate_limited,
    server_error,
    client_error,
    unexpected_status,
    invalid_problem_document,
};

pub const ResponseAssessment = struct {
    outcome: ResponseOutcome = .success,
    reason: ResponseReason = .none,
    http_status: u16 = 0,

    pub fn isSuccess(self: *const ResponseAssessment) bool {
        assert(@intFromPtr(self) != 0);
        return self.outcome == .success;
    }
};

pub const ResponseView = struct {
    status: u16,
    headers: *const HeaderMap,
    body: []const u8,
};

pub const ParsedBody = union(enum) {
    none,
    account: client.AccountResponse,
    order: client.OrderResponse,
};

pub const HandledResponse = struct {
    assessment: ResponseAssessment,
    parsed: ParsedBody = .none,
};

pub const ErrorClass = enum(u8) {
    retry_with_new_nonce,
    retry_with_backoff,
    protocol,
    input,
};

pub const ErrorReason = enum(u8) {
    missing_replay_nonce,
    missing_location,
    unavailable_endpoint,
    signed_body_required,
    invalid_response,
    response_too_large,
    invalid_request_inputs,
    other,
};

pub const ErrorAssessment = struct {
    class: ErrorClass,
    reason: ErrorReason,
};

/// Stateful ACME account/order context with carried nonce and selected endpoints.
pub const FlowContext = struct {
    directory: client.Directory = .{},

    has_nonce: bool = false,
    nonce: client.ReplayNonce = .{},

    has_account_url: bool = false,
    account_url: client.Url = .{},

    has_order_url: bool = false,
    order_url: client.Url = .{},

    has_finalize_url: bool = false,
    finalize_url: client.Url = .{},

    pub fn init(directory: *const client.Directory) FlowContext {
        assert(@intFromPtr(directory) != 0);
        return .{ .directory = directory.* };
    }

    pub fn setNonce(self: *FlowContext, nonce: *const client.ReplayNonce) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(nonce) != 0);

        self.nonce = nonce.*;
        self.has_nonce = true;
    }

    pub fn requireNonce(self: *const FlowContext) Error!client.ReplayNonce {
        assert(@intFromPtr(self) != 0);

        if (!self.has_nonce) return error.NonceUnavailable;
        return self.nonce;
    }

    pub fn setAccountUrl(self: *FlowContext, account_url: *const client.Url) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(account_url) != 0);

        self.account_url = account_url.*;
        self.has_account_url = true;
    }

    pub fn setOrderUrl(self: *FlowContext, order_url: *const client.Url) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(order_url) != 0);

        self.order_url = order_url.*;
        self.has_order_url = true;
    }

    pub fn setFinalizeUrl(self: *FlowContext, finalize_url: *const client.Url) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(finalize_url) != 0);

        self.finalize_url = finalize_url.*;
        self.has_finalize_url = true;
    }

    pub fn selectEndpoint(self: *const FlowContext, endpoint: Endpoint) Error!client.Url {
        assert(@intFromPtr(self) != 0);

        return switch (endpoint) {
            .directory_new_nonce => self.directory.new_nonce_url,
            .directory_new_account => self.directory.new_account_url,
            .directory_new_order => self.directory.new_order_url,
            .account => if (self.has_account_url) self.account_url else error.AccountUrlUnavailable,
            .order => if (self.has_order_url) self.order_url else error.OrderUrlUnavailable,
            .finalize => if (self.has_finalize_url) self.finalize_url else error.FinalizeUrlUnavailable,
        };
    }

    pub fn buildRequest(
        self: *const FlowContext,
        operation: Operation,
        signed_body: []const u8,
    ) (Error || wire.Error)!wire.WireRequest {
        assert(@intFromPtr(self) != 0);

        if (operation != .fetch_nonce and signed_body.len == 0) {
            return error.SignedBodyRequired;
        }

        return switch (operation) {
            .fetch_nonce => try wire.buildNewNonceRequest(&self.directory),
            .new_account => try wire.buildNewAccountRequest(&self.directory, signed_body),
            .new_order => try wire.buildNewOrderRequest(&self.directory, signed_body),
            .fetch_account => try buildSignedRequestForEndpoint(self, .account, signed_body),
            .fetch_order => try buildSignedRequestForEndpoint(self, .order, signed_body),
            .finalize_order => try buildSignedRequestForEndpoint(self, .finalize, signed_body),
        };
    }

    pub fn handleResponse(
        self: *FlowContext,
        operation: Operation,
        response: *const ResponseView,
    ) ProtocolError!HandledResponse {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(response) != 0);

        const assessment = assessResponse(operation, response);
        if (!assessment.isSuccess()) {
            return .{ .assessment = assessment, .parsed = .none };
        }

        const nonce = try wire.parseReplayNonceFromHeaders(response.headers);
        self.setNonce(&nonce);

        return switch (operation) {
            .fetch_nonce => .{ .assessment = assessment, .parsed = .none },
            .new_account => try self.handleAccountResponse(assessment, response, true),
            .fetch_account => try self.handleAccountResponse(assessment, response, false),
            .new_order => try self.handleOrderResponse(assessment, response, true),
            .fetch_order, .finalize_order => try self.handleOrderResponse(assessment, response, false),
        };
    }

    fn handleAccountResponse(
        self: *FlowContext,
        assessment: ResponseAssessment,
        response: *const ResponseView,
        require_location: bool,
    ) ProtocolError!HandledResponse {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(response) != 0);

        if (require_location) {
            const account_url = try wire.parseLocationFromHeaders(response.headers);
            self.setAccountUrl(&account_url);
        }

        const account = try client.parseAccountResponseJson(response.body);
        return .{
            .assessment = assessment,
            .parsed = .{ .account = account },
        };
    }

    fn handleOrderResponse(
        self: *FlowContext,
        assessment: ResponseAssessment,
        response: *const ResponseView,
        require_location: bool,
    ) ProtocolError!HandledResponse {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(response) != 0);

        if (require_location) {
            const order_url = try wire.parseLocationFromHeaders(response.headers);
            self.setOrderUrl(&order_url);
        }

        const order = try client.parseOrderResponseJson(response.body);
        self.setFinalizeUrl(&order.finalize_url);

        return .{
            .assessment = assessment,
            .parsed = .{ .order = order },
        };
    }

    fn buildSignedRequestForEndpoint(
        self: *const FlowContext,
        endpoint: Endpoint,
        signed_body: []const u8,
    ) (Error || wire.Error)!wire.WireRequest {
        assert(@intFromPtr(self) != 0);
        assert(signed_body.len > 0);

        var url = try self.selectEndpoint(endpoint);
        return wire.buildSignedPostRequest(&url, signed_body);
    }
};

pub fn assessResponse(operation: Operation, response: *const ResponseView) ResponseAssessment {
    assert(@intFromPtr(response) != 0);

    if (isExpectedSuccessStatus(operation, response.status)) {
        return .{ .outcome = .success, .reason = .none, .http_status = response.status };
    }

    if (response.status == 400) {
        return assessBadRequest(response.status, response.body);
    }

    if (response.status == 429) {
        return .{
            .outcome = .retry_with_backoff,
            .reason = .rate_limited,
            .http_status = response.status,
        };
    }

    if (response.status >= 500 and response.status <= 599) {
        return .{
            .outcome = .retry_with_backoff,
            .reason = .server_error,
            .http_status = response.status,
        };
    }

    if (response.status >= 400 and response.status <= 499) {
        return .{
            .outcome = .fatal,
            .reason = .client_error,
            .http_status = response.status,
        };
    }

    return .{
        .outcome = .fatal,
        .reason = .unexpected_status,
        .http_status = response.status,
    };
}

pub fn classifyProtocolError(err: ProtocolError) ErrorAssessment {
    return switch (err) {
        error.MissingReplayNonceHeader => .{
            .class = .protocol,
            .reason = .missing_replay_nonce,
        },
        error.MissingLocationHeader => .{
            .class = .protocol,
            .reason = .missing_location,
        },
        error.NonceUnavailable,
        error.AccountUrlUnavailable,
        error.OrderUrlUnavailable,
        error.FinalizeUrlUnavailable,
        => .{
            .class = .input,
            .reason = .unavailable_endpoint,
        },
        error.SignedBodyRequired => .{
            .class = .input,
            .reason = .signed_body_required,
        },
        error.ResponseTooLarge,
        error.JsonScratchExhausted,
        => .{
            .class = .protocol,
            .reason = .response_too_large,
        },
        error.JsonParseFailed,
        error.MissingAccountField,
        error.MissingOrderField,
        error.InvalidAccountStatus,
        error.InvalidOrderStatus,
        error.TooManyAuthorizations,
        => .{
            .class = .protocol,
            .reason = .invalid_response,
        },
        error.InvalidUrl,
        error.InvalidScheme,
        error.InvalidHost,
        error.HostTooLong,
        error.PathTooLong,
        error.InvalidPort,
        error.BodyTooLarge,
        => .{
            .class = .input,
            .reason = .invalid_request_inputs,
        },
        else => .{ .class = .protocol, .reason = .other },
    };
}

fn isExpectedSuccessStatus(operation: Operation, status: u16) bool {
    return switch (operation) {
        .fetch_nonce => status == 200 or status == 204,
        .new_account => status == 200 or status == 201,
        .new_order => status == 201,
        .fetch_account => status == 200,
        .fetch_order => status == 200,
        .finalize_order => status == 200,
    };
}

fn assessBadRequest(status: u16, body: []const u8) ResponseAssessment {
    assert(status == 400);

    const problem_type = parseProblemType(body) catch {
        return .{
            .outcome = .fatal,
            .reason = .invalid_problem_document,
            .http_status = status,
        };
    };

    if (problem_type) |value| {
        if (std.mem.endsWith(u8, value, ":badNonce") or std.mem.eql(u8, value, "badNonce")) {
            return .{
                .outcome = .retry_with_new_nonce,
                .reason = .bad_nonce,
                .http_status = status,
            };
        }
    }

    return .{
        .outcome = .fatal,
        .reason = .client_error,
        .http_status = status,
    };
}

fn parseProblemType(body: []const u8) error{ ProblemTooLarge, ParseFailed }!?[]const u8 {
    if (body.len == 0) return null;
    if (body.len > max_problem_document_bytes) return error.ProblemTooLarge;

    const ProblemJson = struct {
        type: ?[]const u8 = null,
    };

    var scratch: [problem_parse_scratch_size_bytes]u8 = undefined;
    var fixed_buffer_allocator = std.heap.FixedBufferAllocator.init(&scratch);

    const parsed = std.json.parseFromSlice(
        ProblemJson,
        fixed_buffer_allocator.allocator(),
        body,
        .{ .ignore_unknown_fields = true },
    ) catch {
        return error.ParseFailed;
    };
    defer parsed.deinit();

    return parsed.value.type;
}

test "FlowContext buildRequest selects directory endpoints" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    const ctx = FlowContext.init(&directory);

    const nonce_request = try ctx.buildRequest(.fetch_nonce, &.{});
    try std.testing.expectEqual(Method.HEAD, nonce_request.method);
    try std.testing.expectEqualStrings("/new-nonce", nonce_request.path());

    const order_request = try ctx.buildRequest(.new_order, "{\"jws\":1}");
    try std.testing.expectEqual(Method.POST, order_request.method);
    try std.testing.expectEqualStrings("/new-order", order_request.path());
}

test "FlowContext buildRequest requires stored endpoint for account fetch" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    const ctx = FlowContext.init(&directory);

    try std.testing.expectError(
        error.AccountUrlUnavailable,
        ctx.buildRequest(.fetch_account, "{\"jws\":1}"),
    );
}

test "assessResponse classifies badNonce as retry-with-new-nonce" {
    var headers = HeaderMap.init();
    const response = ResponseView{
        .status = 400,
        .headers = &headers,
        .body = "{\"type\":\"urn:ietf:params:acme:error:badNonce\"}",
    };

    const assessment = assessResponse(.new_order, &response);
    try std.testing.expectEqual(ResponseOutcome.retry_with_new_nonce, assessment.outcome);
    try std.testing.expectEqual(ResponseReason.bad_nonce, assessment.reason);
}

test "FlowContext handleResponse stores nonce and account location" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    var ctx = FlowContext.init(&directory);

    var headers = HeaderMap.init();
    try headers.put("Replay-Nonce", "abc_DEF-123");
    try headers.put("Location", "https://acme.example/account/1");

    const response = ResponseView{
        .status = 201,
        .headers = &headers,
        .body = "{\"status\":\"valid\",\"orders\":\"https://acme.example/account/1/orders\"}",
    };

    const handled = try ctx.handleResponse(.new_account, &response);
    try std.testing.expect(handled.assessment.isSuccess());
    try std.testing.expect(ctx.has_nonce);
    try std.testing.expect(ctx.has_account_url);
    try std.testing.expectEqualStrings("abc_DEF-123", ctx.nonce.slice());
    try std.testing.expectEqualStrings("https://acme.example/account/1", ctx.account_url.slice());
}

test "FlowContext handleResponse stores order and finalize urls" {
    var directory = client.Directory{};
    try directory.new_nonce_url.set("https://acme.example/new-nonce");
    try directory.new_account_url.set("https://acme.example/new-account");
    try directory.new_order_url.set("https://acme.example/new-order");

    var ctx = FlowContext.init(&directory);

    var headers = HeaderMap.init();
    try headers.put("Replay-Nonce", "next_nonce_123");
    try headers.put("Location", "https://acme.example/order/42");

    const response = ResponseView{
        .status = 201,
        .headers = &headers,
        .body = "{" ++
            "\"status\":\"pending\"," ++
            "\"authorizations\":[\"https://acme.example/authz/1\"]," ++
            "\"finalize\":\"https://acme.example/order/42/finalize\"" ++
            "}",
    };

    const handled = try ctx.handleResponse(.new_order, &response);
    try std.testing.expect(handled.assessment.isSuccess());
    try std.testing.expect(ctx.has_order_url);
    try std.testing.expect(ctx.has_finalize_url);
    try std.testing.expectEqualStrings("https://acme.example/order/42", ctx.order_url.slice());
    try std.testing.expectEqualStrings("https://acme.example/order/42/finalize", ctx.finalize_url.slice());
}

test "classifyProtocolError maps missing replay nonce" {
    const classified = classifyProtocolError(error.MissingReplayNonceHeader);
    try std.testing.expectEqual(ErrorClass.protocol, classified.class);
    try std.testing.expectEqual(ErrorReason.missing_replay_nonce, classified.reason);
}
