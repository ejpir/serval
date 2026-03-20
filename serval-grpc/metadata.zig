//! gRPC Metadata Validation Helpers
//!
//! TigerStyle: Explicit validation of gRPC-over-HTTP/2 request semantics.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const Request = core.Request;
const eqlIgnoreCase = core.eqlIgnoreCase;

pub const Error = error{
    InvalidMethod,
    MissingPath,
    MissingContentType,
    InvalidContentType,
    MissingTe,
    InvalidTe,
    MissingGrpcStatus,
    InvalidGrpcStatus,
};

pub fn isGrpcContentType(value: []const u8) bool {
    const grpc_content_type = "application/grpc";
    assert(grpc_content_type.len <= core.config.MAX_HEADER_SIZE_BYTES);
    if (value.len < grpc_content_type.len) return false;
    if (!std.ascii.startsWithIgnoreCase(value, grpc_content_type)) return false;
    if (value.len == grpc_content_type.len) return true;

    assert(value.len > grpc_content_type.len);
    const suffix_delimiter = value[grpc_content_type.len];
    return suffix_delimiter == '+' or suffix_delimiter == ';';
}

pub fn validateRequest(request: *const Request) Error!void {
    assert(@intFromPtr(request) != 0);
    assert(request.headers.count <= core.config.MAX_HEADERS);

    if (request.method != .POST) return error.InvalidMethod;
    if (request.path.len == 0) return error.MissingPath;

    const content_type = request.headers.get("content-type") orelse return error.MissingContentType;
    if (!isGrpcContentType(content_type)) return error.InvalidContentType;

    const te = request.headers.get("te") orelse return error.MissingTe;
    if (!eqlIgnoreCase(te, "trailers")) return error.InvalidTe;
}

pub fn requireGrpcStatus(headers: *const core.HeaderMap) Error!void {
    assert(@intFromPtr(headers) != 0);
    assert(headers.count <= core.config.MAX_HEADERS);

    const grpc_status = headers.get("grpc-status") orelse return error.MissingGrpcStatus;
    if (grpc_status.len == 0) return error.InvalidGrpcStatus;

    var index: u32 = 0;
    while (index < grpc_status.len) : (index += 1) {
        const c = grpc_status[index];
        if (c < '0' or c > '9') return error.InvalidGrpcStatus;
    }
}

test "validateRequest accepts canonical gRPC request" {
    var request = Request{ .method = .POST, .path = "/grpc.health.v1.Health/Check" };
    try request.headers.put("content-type", "application/grpc");
    try request.headers.put("te", "trailers");

    try validateRequest(&request);
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

test "requireGrpcStatus accepts numeric grpc-status" {
    var headers = core.HeaderMap.init();
    try headers.put("grpc-status", "0");
    try requireGrpcStatus(&headers);
}

test "requireGrpcStatus rejects missing grpc-status" {
    var headers = core.HeaderMap.init();
    try std.testing.expectError(error.MissingGrpcStatus, requireGrpcStatus(&headers));
}

test "requireGrpcStatus rejects non-numeric grpc-status" {
    var headers = core.HeaderMap.init();
    try headers.put("grpc-status", "bad");
    try std.testing.expectError(error.InvalidGrpcStatus, requireGrpcStatus(&headers));
}

test "requireGrpcStatus rejects empty grpc-status" {
    var headers = core.HeaderMap.init();
    try headers.put("grpc-status", "");
    try std.testing.expectError(error.InvalidGrpcStatus, requireGrpcStatus(&headers));
}
