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
const limits = @import("limits.zig");
const wire = @import("wire.zig");

const max_problem_document_bytes: u32 = @intCast(
    @max(limits.max_account_response_bytes, limits.max_order_response_bytes),
);
const problem_parse_scratch_size_bytes = 2048;

/// Errors returned when required ACME URLs or request preconditions are missing.
/// These failures indicate that the caller cannot continue the requested operation as configured.
/// `SignedBodyRequired` is raised when a signed request body is needed but unavailable.
pub const Error = error{
    NonceUnavailable,
    AccountUrlUnavailable,
    OrderUrlUnavailable,
    FinalizeUrlUnavailable,
    SignedBodyRequired,
};

/// Error set used by protocol-level helpers in this module.
/// This aliases errors from the local `Error` set, `client.Error`, and `wire.Error`.
/// Callers should handle the combined set when propagating failures across protocol boundaries.
pub const ProtocolError = Error || client.Error || wire.Error;

/// Internal operation kind used to drive request construction and response handling.
/// The values correspond to nonce fetches, account and order creation, and resource lookups.
/// `finalize_order` represents the order-finalization step.
pub const Operation = enum(u8) {
    fetch_nonce,
    new_account,
    new_order,
    fetch_account,
    fetch_order,
    finalize_order,
};

/// Identifies an ACME endpoint used by this module.
/// Each tag names a directory or resource endpoint such as account, order, or finalize.
/// Use these values when routing a request to the corresponding protocol target.
pub const Endpoint = enum(u8) {
    directory_new_nonce,
    directory_new_account,
    directory_new_order,
    account,
    order,
    finalize,
};

/// High-level decision produced after assessing a response.
/// `success` accepts the result, while the retry variants describe which recovery strategy to apply.
/// `fatal` indicates the caller should stop retrying this path.
pub const ResponseOutcome = enum(u8) {
    success,
    retry_with_new_nonce,
    retry_with_backoff,
    fatal,
};

/// Classifies why a response was not treated as a clean success.
/// The values distinguish nonce, rate-limit, server, client, and protocol-shape failures.
/// `none` indicates that no failure reason has been assigned.
pub const ResponseReason = enum(u8) {
    none,
    bad_nonce,
    rate_limited,
    server_error,
    client_error,
    unexpected_status,
    invalid_problem_document,
};

/// Captures the outcome of evaluating an ACME response.
/// `outcome` describes the retry decision, `reason` records the classification, and `http_status` stores the observed status code.
/// Field defaults represent a successful, unclassified assessment with no HTTP status recorded.
pub const ResponseAssessment = struct {
    outcome: ResponseOutcome = .success,
    reason: ResponseReason = .none,
    http_status: u16 = 0,

    /// Reports whether the assessment ended in `.success`.
    /// The pointer must be valid and non-null when called.
    /// Debug assertions also require `http_status <= 999` before the check runs.
    pub fn isSuccess(self: *const ResponseAssessment) bool {
        assert(@intFromPtr(self) != 0);
        assert(self.http_status <= 999);
        return self.outcome == .success;
    }
};

/// Read-only view of an assessed HTTP response.
/// `headers` and `body` borrow storage owned elsewhere; this type does not manage lifetime.
/// `status` carries the HTTP status code associated with the response.
pub const ResponseView = struct {
    status: u16,
    headers: *const HeaderMap,
    body: []const u8,
};

/// Parsed response body returned by ACME response handling.
/// `.none` means no body was decoded; `.account` and `.order` carry the corresponding typed client response.
pub const ParsedBody = union(enum) {
    none,
    account: client.AccountResponse,
    order: client.OrderResponse,
};

/// Pairs an HTTP response assessment with an optional parsed ACME body.
/// `parsed` defaults to `.none` when the response does not carry a successfully decoded account or order body.
pub const HandledResponse = struct {
    assessment: ResponseAssessment,
    parsed: ParsedBody = .none,
};

/// High-level handling class for orchestration failures.
/// The class determines whether a caller should retry immediately, back off, treat the failure as protocol-level, or treat it as input-related.
pub const ErrorClass = enum(u8) {
    retry_with_new_nonce,
    retry_with_backoff,
    protocol,
    input,
};

/// Explains why an orchestration error was classified the way it was.
/// These reasons are used to distinguish missing endpoints, malformed responses, bad inputs, and other failures.
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

/// Describes how an ACME error should be classified for retry and reporting decisions.
/// The `class` field captures the handling category and `reason` captures the specific failure mode.
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

    /// Initializes a flow context from the ACME directory metadata.
    /// The directory is copied by value into the new context, so the caller retains ownership of the input pointer.
    /// The directory's new-nonce URL must satisfy the configured maximum length assertion.
    pub fn init(directory: *const client.Directory) FlowContext {
        assert(@intFromPtr(directory) != 0);
        assert(directory.new_nonce_url.len <= config.ACME_MAX_DIRECTORY_URL_BYTES);
        return .{ .directory = directory.* };
    }

    /// Records a replay nonce in the flow context.
    /// The pointed-to nonce is copied into the context; the caller retains ownership of the input value.
    /// After this call, `requireNonce` can return the stored nonce.
    pub fn setNonce(self: *FlowContext, nonce: *const client.ReplayNonce) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(nonce) != 0);

        self.nonce = nonce.*;
        self.has_nonce = true;
    }

    /// Returns the current replay nonce if one has been recorded in the flow context.
    /// When no nonce is available, returns `error.NonceUnavailable` instead of fabricating a value.
    /// The returned nonce is owned by the context and remains valid until the context is updated or discarded.
    pub fn requireNonce(self: *const FlowContext) Error!client.ReplayNonce {
        assert(@intFromPtr(self) != 0);
        assert(!self.has_nonce or self.nonce.len > 0);

        if (!self.has_nonce) return error.NonceUnavailable;
        return self.nonce;
    }

    /// Stores the account URL for later request construction.
    /// The pointed-to URL is copied into the flow context; the caller retains ownership of the input value.
    /// After this call, `.account` becomes available to `selectEndpoint` and request builders.
    pub fn setAccountUrl(self: *FlowContext, account_url: *const client.Url) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(account_url) != 0);

        self.account_url = account_url.*;
        self.has_account_url = true;
    }

    /// Stores the order URL for later request construction.
    /// The pointed-to URL is copied into the flow context; the caller retains ownership of the input value.
    /// After this call, `.order` becomes available to `selectEndpoint` and request builders.
    pub fn setOrderUrl(self: *FlowContext, order_url: *const client.Url) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(order_url) != 0);

        self.order_url = order_url.*;
        self.has_order_url = true;
    }

    /// Stores the finalize URL for later request construction.
    /// The pointed-to URL is copied into the flow context; the caller retains ownership of the input value.
    /// After this call, `.finalize` becomes available to `selectEndpoint` and request builders.
    pub fn setFinalizeUrl(self: *FlowContext, finalize_url: *const client.Url) void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(finalize_url) != 0);

        self.finalize_url = finalize_url.*;
        self.has_finalize_url = true;
    }

    /// Selects the URL associated with an endpoint in the current flow context.
    /// Directory endpoints are always available; account, order, and finalize URLs require their corresponding `has_*` flag to be set.
    /// Returns an error when the requested endpoint has not been populated yet.
    pub fn selectEndpoint(self: *const FlowContext, endpoint: Endpoint) Error!client.Url {
        assert(@intFromPtr(self) != 0);
        assert(self.directory.new_nonce_url.len <= config.ACME_MAX_DIRECTORY_URL_BYTES);

        return switch (endpoint) {
            .directory_new_nonce => self.directory.new_nonce_url,
            .directory_new_account => self.directory.new_account_url,
            .directory_new_order => self.directory.new_order_url,
            .account => if (self.has_account_url) self.account_url else error.AccountUrlUnavailable,
            .order => if (self.has_order_url) self.order_url else error.OrderUrlUnavailable,
            .finalize => if (self.has_finalize_url) self.finalize_url else error.FinalizeUrlUnavailable,
        };
    }

    /// Builds the wire request for an ACME operation from the current flow context.
    /// `signed_body` is required for every operation except `.fetch_nonce`; passing an empty body for other operations returns `error.SignedBodyRequired`.
    /// The returned request borrows from `self.directory` and any supplied body slice for request construction.
    pub fn buildRequest(
        self: *const FlowContext,
        operation: Operation,
        signed_body: []const u8,
    ) (Error || wire.Error)!wire.WireRequest {
        assert(@intFromPtr(self) != 0);
        assert(@sizeOf(Operation) == 1);

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

    /// Processes a response for an ACME flow and updates nonce or resource state on success.
    /// Returns the response assessment together with any parsed body; non-success responses are returned without parsing.
    /// On successful responses, the replay nonce is extracted from headers before the operation-specific response handler runs.
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

/// Assesses an HTTP response for the given ACME operation.
/// Successful statuses are passed through with `.success`; 400/429/5xx and other 4xx statuses are mapped to retry or fatal outcomes.
/// `response` must point to a valid `ResponseView` with a bounded HTTP status code and accessible headers/body slices.
pub fn assessResponse(operation: Operation, response: *const ResponseView) ResponseAssessment {
    assert(@intFromPtr(response) != 0);
    assert(response.status <= 999);

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

/// Classifies a protocol-layer parsing or validation failure for ACME orchestration.
/// The result separates caller input mistakes from remote protocol defects so retry policy can be chosen correctly.
/// Unknown errors are treated as protocol issues with the `.other` reason.
pub fn classifyProtocolError(err: ProtocolError) ErrorAssessment {
    assert(@sizeOf(ErrorAssessment) > 0);
    assert(@sizeOf(@TypeOf(err)) > 0);
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
    assert(@sizeOf(Operation) == 1);
    assert(status <= 999);
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
    assert(body.len <= max_problem_document_bytes);

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
    assert(max_problem_document_bytes > 0);
    assert(problem_parse_scratch_size_bytes > 0);
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
