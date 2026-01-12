// examples/router/json/response.zig
//! JSON Response Utilities
//!
//! Comptime error messages and direct buffer writes for responses.
//! TigerStyle: Zero allocations, comptime where possible.

const std = @import("std");

// =============================================================================
// Comptime Error Messages (zero runtime cost)
// =============================================================================

pub const errors = struct {
    pub const missing_body = comptimeJson("missing request body");
    pub const empty_body = comptimeJson("empty request body");
    pub const body_too_large = comptimeJson("request body too large");
    pub const json_parse = comptimeJson("JSON parse error");
    pub const no_router = comptimeJson("no router configured");
    pub const invalid_pool_idx = comptimeJson("route references invalid pool_idx");
    pub const route_needs_path = comptimeJson("route must have path_prefix or path_exact");
    pub const pool_no_upstreams = comptimeJson("pool has no upstreams");
    pub const pool_too_many_upstreams = comptimeJson("pool has too many upstreams");
    pub const pool_not_found = comptimeJson("pool not found");
    pub const route_not_found = comptimeJson("route not found");
    pub const route_exists = comptimeJson("route with this name already exists");
    pub const pool_exists = comptimeJson("pool with this name already exists");
    pub const pool_referenced = comptimeJson("pool is referenced by routes");
    pub const too_many_routes = comptimeJson("too many routes");
    pub const too_many_pools = comptimeJson("too many pools");
    pub const too_many_allowed_hosts = comptimeJson("too many allowed_hosts");
    pub const max_routes = comptimeJson("maximum routes reached");
    pub const max_pools = comptimeJson("maximum pools reached");
    pub const max_upstreams = comptimeJson("maximum upstreams per pool reached");
    pub const upstream_idx_max = comptimeJson("upstream idx exceeds maximum");
    pub const upstream_exists = comptimeJson("upstream with this idx already exists in pool");
    pub const last_pool = comptimeJson("cannot remove last pool");
    pub const last_upstream = comptimeJson("cannot remove last upstream from pool");
    pub const upstream_not_found = comptimeJson("upstream not found in pool");
    pub const swap_failed = comptimeJson("router swap failed");
    pub const buffer_overflow = comptimeJson("response buffer overflow");
    pub const at_least_one_pool = comptimeJson("at least one pool is required");
};

fn comptimeJson(comptime msg: []const u8) []const u8 {
    return std.fmt.comptimePrint("{{\"error\":\"{s}\"}}", .{msg});
}

// =============================================================================
// Dynamic Responses (direct buffer write, no allocator)
// =============================================================================

/// Format success response with generation.
pub fn success(buf: []u8, generation: u64) []const u8 {
    return std.fmt.bufPrint(buf, "{{\"status\":\"ok\",\"generation\":{d}}}", .{generation}) catch
        "{\"status\":\"ok\"}";
}

/// Format success response with generation and pool_idx.
pub fn poolAdded(buf: []u8, generation: u64, pool_idx: usize) []const u8 {
    return std.fmt.bufPrint(buf, "{{\"status\":\"ok\",\"generation\":{d},\"pool_idx\":{d}}}", .{ generation, pool_idx }) catch
        "{\"status\":\"ok\"}";
}

// =============================================================================
// Body Validation (shared by admin handlers)
// =============================================================================

/// Result of body validation - either the valid body or an error response.
pub const BodyValidation = union(enum) {
    valid: []const u8,
    err: ErrorResult,
};

/// Error result for returning from handlers.
pub const ErrorResult = struct {
    status: u16,
    body: []const u8,
};

/// Validate request body for admin endpoints.
/// Returns the body if valid, or an error result to return immediately.
/// TigerStyle: Consolidates repeated validation logic.
pub fn validateBody(body: ?[]const u8, max_size: u32) BodyValidation {
    const request_body = body orelse {
        return .{ .err = .{ .status = 400, .body = errors.missing_body } };
    };

    if (request_body.len == 0) {
        return .{ .err = .{ .status = 400, .body = errors.empty_body } };
    }

    if (request_body.len > max_size) {
        return .{ .err = .{ .status = 413, .body = errors.body_too_large } };
    }

    return .{ .valid = request_body };
}
