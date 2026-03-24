//! gRPC Metadata Validation Helpers
//!
//! TigerStyle: Explicit validation of gRPC-over-HTTP/2 request semantics.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const Request = core.Request;
const eqlIgnoreCase = core.eqlIgnoreCase;

const grpc_content_type = "application/grpc";
const trailers_value = "trailers";

pub const max_grpc_status_code: u8 = 16;

pub const RequestClass = enum {
    grpc,
    non_grpc,
    invalid_grpc_like,
};

const ValidationMode = enum {
    compatibility,
    strict,
};

const RequestSignals = enum {
    none,
    grpc_like,
};

pub const Error = error{
    InvalidMethod,
    MissingPath,
    MissingContentType,
    InvalidContentType,
    MissingTe,
    InvalidTe,
    MissingGrpcStatus,
    InvalidGrpcStatusFormat,
    InvalidGrpcStatusRange,
};

pub fn isGrpcContentType(value: []const u8) bool {
    assert(grpc_content_type.len <= core.config.MAX_HEADER_SIZE_BYTES);
    if (value.len < grpc_content_type.len) return false;
    if (!std.ascii.startsWithIgnoreCase(value, grpc_content_type)) return false;
    if (value.len == grpc_content_type.len) return true;

    assert(value.len > grpc_content_type.len);
    const suffix_delimiter = value[grpc_content_type.len];
    return suffix_delimiter == '+' or suffix_delimiter == ';';
}

pub fn validateRequest(request: *const Request) Error!void {
    try validateRequestWithMode(request, .compatibility);
}

pub fn validateRequestStrict(request: *const Request) Error!void {
    try validateRequestWithMode(request, .strict);
}

pub fn classifyRequest(request: *const Request) RequestClass {
    assert(@intFromPtr(request) != 0);
    assert(request.headers.count <= core.config.MAX_HEADERS);

    return switch (requestSignals(request)) {
        .none => .non_grpc,
        .grpc_like => blk: {
            validateRequest(request) catch break :blk .invalid_grpc_like;
            break :blk .grpc;
        },
    };
}

pub fn parseGrpcStatus(headers: *const core.HeaderMap) Error!u8 {
    assert(@intFromPtr(headers) != 0);
    assert(headers.count <= core.config.MAX_HEADERS);

    const grpc_status = headers.get("grpc-status") orelse return error.MissingGrpcStatus;
    if (grpc_status.len == 0) return error.InvalidGrpcStatusFormat;

    const status = try parseBoundedDecimalStatus(grpc_status);
    assert(status <= max_grpc_status_code);
    return status;
}

pub fn requireGrpcStatus(headers: *const core.HeaderMap) Error!void {
    _ = try parseGrpcStatus(headers);
}

fn validateRequestWithMode(request: *const Request, mode: ValidationMode) Error!void {
    assert(@intFromPtr(request) != 0);
    assert(request.headers.count <= core.config.MAX_HEADERS);

    if (request.method != .POST) return error.InvalidMethod;
    if (request.path.len == 0) return error.MissingPath;

    const content_type = request.headers.get("content-type") orelse return error.MissingContentType;
    const content_type_ok = switch (mode) {
        .compatibility => isGrpcContentType(content_type),
        .strict => isGrpcContentTypeStrict(content_type),
    };
    if (!content_type_ok) return error.InvalidContentType;

    const te = request.headers.get("te") orelse return error.MissingTe;
    const te_ok = switch (mode) {
        .compatibility => eqlIgnoreCase(te, trailers_value),
        .strict => std.mem.eql(u8, te, trailers_value),
    };
    if (!te_ok) return error.InvalidTe;
}

fn requestSignals(request: *const Request) RequestSignals {
    assert(@intFromPtr(request) != 0);

    const has_content_type = request.headers.get("content-type") != null;
    const has_te = request.headers.get("te") != null;
    if (!has_content_type and !has_te) return .none;
    return .grpc_like;
}

fn parseBoundedDecimalStatus(value: []const u8) Error!u8 {
    assert(value.len > 0);

    var status: u32 = 0;
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const c = value[index];
        if (c < '0' or c > '9') return error.InvalidGrpcStatusFormat;

        const digit: u32 = c - '0';
        if (status > (std.math.maxInt(u32) - digit) / 10) return error.InvalidGrpcStatusRange;

        status = (status * 10) + digit;
        if (status > max_grpc_status_code) return error.InvalidGrpcStatusRange;
    }

    return @intCast(status);
}

fn isGrpcContentTypeStrict(value: []const u8) bool {
    assert(grpc_content_type.len <= core.config.MAX_HEADER_SIZE_BYTES);

    if (!isGrpcContentType(value)) return false;
    if (containsAsciiWhitespace(value)) return false;
    if (value.len == grpc_content_type.len) return true;

    const delimiter = value[grpc_content_type.len];
    const suffix = value[(grpc_content_type.len + 1)..];
    return switch (delimiter) {
        '+' => isHttpToken(suffix),
        ';' => areValidMediaTypeParams(suffix),
        else => false,
    };
}

fn containsAsciiWhitespace(value: []const u8) bool {
    assert(value.len <= core.config.MAX_HEADER_SIZE_BYTES);

    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        if (std.ascii.isWhitespace(value[index])) return true;
    }
    return false;
}

fn isHttpToken(value: []const u8) bool {
    assert(value.len <= core.config.MAX_HEADER_SIZE_BYTES);

    if (value.len == 0) return false;

    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        if (!isHttpTokenChar(value[index])) return false;
    }
    return true;
}

fn isHttpTokenChar(c: u8) bool {
    if (c >= 'a' and c <= 'z') return true;
    if (c >= 'A' and c <= 'Z') return true;
    if (c >= '0' and c <= '9') return true;

    return switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn areValidMediaTypeParams(value: []const u8) bool {
    assert(value.len <= core.config.MAX_HEADER_SIZE_BYTES);
    if (value.len == 0) return false;

    var start: usize = 0;
    while (start < value.len) {
        const remaining = value[start..];
        const delimiter_index_opt = std.mem.indexOfScalar(u8, remaining, ';');
        const part_end: usize = if (delimiter_index_opt) |delimiter_index| start + delimiter_index else value.len;

        const part = value[start..part_end];
        if (!isValidMediaTypeParam(part)) return false;

        if (part_end == value.len) return true;
        start = part_end + 1;
    }

    return false;
}

fn isValidMediaTypeParam(part: []const u8) bool {
    assert(part.len <= core.config.MAX_HEADER_SIZE_BYTES);

    if (part.len == 0) return false;
    const eq_index = std.mem.indexOfScalar(u8, part, '=') orelse return false;
    if (eq_index == 0) return false;
    if (eq_index + 1 >= part.len) return false;

    const key = part[0..eq_index];
    const value = part[(eq_index + 1)..];
    return isHttpToken(key) and isHttpToken(value);
}

test "validateRequest accepts canonical gRPC request" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    try validateRequest(&request);
}

test "validateRequestStrict accepts canonical gRPC request" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    try validateRequestStrict(&request);
}

test "isGrpcContentType accepts grpc+proto" {
    try std.testing.expect(isGrpcContentType("application/grpc+proto"));
    try std.testing.expect(isGrpcContentType("application/grpc;charset=utf-8"));
    try std.testing.expect(!isGrpcContentType("application/grpcx"));
    try std.testing.expect(!isGrpcContentType("application/json"));
}

test "validateRequest rejects non-POST method" {
    var request = Request{ .method = .GET, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    try std.testing.expectError(error.InvalidMethod, validateRequest(&request));
}

test "validateRequest rejects missing path" {
    var request = Request{ .method = .POST, .path = "" };
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    try std.testing.expectError(error.MissingPath, validateRequest(&request));
}

test "validateRequest rejects missing content-type" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("te", "trailers");

    try std.testing.expectError(error.MissingContentType, validateRequest(&request));
}

test "validateRequest rejects invalid content-type" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/json");
    try request.headers.put("te", "trailers");

    try std.testing.expectError(error.InvalidContentType, validateRequest(&request));
}

test "validateRequest rejects missing te header" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/grpc");

    try std.testing.expectError(error.MissingTe, validateRequest(&request));
}

test "validateRequest rejects invalid te header" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "gzip");

    try std.testing.expectError(error.InvalidTe, validateRequest(&request));
}

test "validateRequestStrict content-type grammar matrix" {
    const cases = [_]struct {
        content_type: []const u8,
        expected_valid: bool,
    }{
        .{ .content_type = "application/grpc", .expected_valid = true },
        .{ .content_type = "application/grpc+proto", .expected_valid = true },
        .{ .content_type = "application/grpc+json", .expected_valid = true },
        .{ .content_type = "application/grpc;charset=utf-8", .expected_valid = true },
        .{ .content_type = "application/grpc;charset=utf-8;version=v1", .expected_valid = true },
        .{ .content_type = "application/grpc+", .expected_valid = false },
        .{ .content_type = "application/grpc;", .expected_valid = false },
        .{ .content_type = "application/grpc;=utf-8", .expected_valid = false },
        .{ .content_type = "application/grpc;charset=", .expected_valid = false },
        .{ .content_type = "application/grpc; charset=utf-8", .expected_valid = false },
        .{ .content_type = "application/grpc +proto", .expected_valid = false },
        .{ .content_type = "application/grpc;charset=\"utf-8\"", .expected_valid = false },
    };

    var index: usize = 0;
    while (index < cases.len) : (index += 1) {
        var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
        try request.headers.put("content-type", cases[index].content_type);
        try request.headers.put("te", "trailers");

        const result = validateRequestStrict(&request);
        if (cases[index].expected_valid) {
            try result;
        } else {
            try std.testing.expectError(error.InvalidContentType, result);
        }
    }
}

test "validateRequestStrict te grammar matrix" {
    const cases = [_]struct {
        te: []const u8,
        expected_valid: bool,
    }{
        .{ .te = "trailers", .expected_valid = true },
        .{ .te = "Trailers", .expected_valid = false },
        .{ .te = "trailers, deflate", .expected_valid = false },
        .{ .te = " trailers", .expected_valid = false },
        .{ .te = "trailers ", .expected_valid = false },
        .{ .te = "", .expected_valid = false },
        .{ .te = "gzip", .expected_valid = false },
    };

    var index: usize = 0;
    while (index < cases.len) : (index += 1) {
        var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
        try request.headers.put("content-type", "application/grpc");
        try request.headers.put("te", cases[index].te);

        const result = validateRequestStrict(&request);
        if (cases[index].expected_valid) {
            try result;
        } else {
            try std.testing.expectError(error.InvalidTe, result);
        }
    }
}

test "validateRequest compatibility accepts uppercase te" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "Trailers");

    try validateRequest(&request);
}

test "validateRequestStrict rejects uppercase te" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "Trailers");

    try std.testing.expectError(error.InvalidTe, validateRequestStrict(&request));
}

test "classifyRequest matrix" {
    const cases = [_]struct {
        method: core.Method,
        path: []const u8,
        content_type: ?[]const u8,
        te: ?[]const u8,
        expected: RequestClass,
    }{
        .{ .method = .POST, .path = "/grpc.health.v1.Health/Check", .content_type = "application/grpc", .te = "trailers", .expected = .grpc },
        .{ .method = .GET, .path = "/status", .content_type = null, .te = null, .expected = .non_grpc },
        .{ .method = .POST, .path = "/grpc.health.v1.Health/Check", .content_type = "application/grpc", .te = "gzip", .expected = .invalid_grpc_like },
    };

    var index: usize = 0;
    while (index < cases.len) : (index += 1) {
        var request = Request{ .method = cases[index].method, .path = cases[index].path };
        if (cases[index].content_type) |content_type| {
            try request.headers.put("content-type", content_type);
        }
        if (cases[index].te) |te| {
            try request.headers.put("te", te);
        }

        try std.testing.expectEqual(cases[index].expected, classifyRequest(&request));
    }
}

test "parseGrpcStatus matrix" {
    const cases = [_]struct {
        value: ?[]const u8,
        expected_status: ?u8,
        expected_error: ?Error,
    }{
        .{ .value = "0", .expected_status = 0, .expected_error = null },
        .{ .value = "16", .expected_status = max_grpc_status_code, .expected_error = null },
        .{ .value = null, .expected_status = null, .expected_error = error.MissingGrpcStatus },
        .{ .value = "bad", .expected_status = null, .expected_error = error.InvalidGrpcStatusFormat },
        .{ .value = "", .expected_status = null, .expected_error = error.InvalidGrpcStatusFormat },
        .{ .value = "17", .expected_status = null, .expected_error = error.InvalidGrpcStatusRange },
        .{ .value = "42949672960", .expected_status = null, .expected_error = error.InvalidGrpcStatusRange },
    };

    var index: usize = 0;
    while (index < cases.len) : (index += 1) {
        var headers = core.HeaderMap.init();
        if (cases[index].value) |value| {
            try headers.put("grpc-status", value);
        }

        const result = parseGrpcStatus(&headers);
        if (cases[index].expected_status) |expected_status| {
            const status = try result;
            try std.testing.expectEqual(expected_status, status);
        } else {
            const expected_error = cases[index].expected_error orelse unreachable;
            try std.testing.expectError(expected_error, result);
        }
    }
}

test "requireGrpcStatus rejects malformed status" {
    var headers = core.HeaderMap.init();
    try headers.put("grpc-status", "-1");
    try std.testing.expectError(error.InvalidGrpcStatusFormat, requireGrpcStatus(&headers));
}
