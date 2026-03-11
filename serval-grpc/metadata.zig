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
    if (value.len < "application/grpc".len) return false;
    if (!std.ascii.startsWithIgnoreCase(value, "application/grpc")) return false;
    if (value.len == "application/grpc".len) return true;
    return value["application/grpc".len] == '+' or value["application/grpc".len] == ';';
}

pub fn validateRequest(request: *const Request) Error!void {
    assert(@intFromPtr(request) != 0);
    assert(request.path.len > 0);

    if (request.method != .POST) return error.InvalidMethod;
    if (request.path.len == 0) return error.MissingPath;

    const content_type = request.headers.get("content-type") orelse return error.MissingContentType;
    if (!isGrpcContentType(content_type)) return error.InvalidContentType;

    const te = request.headers.get("te") orelse return error.MissingTe;
    if (!eqlIgnoreCase(te, "trailers")) return error.InvalidTe;
}

pub fn requireGrpcStatus(headers: *const core.HeaderMap) Error!void {
    assert(@intFromPtr(headers) != 0);

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
    try std.testing.expect(!isGrpcContentType("application/json"));
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
