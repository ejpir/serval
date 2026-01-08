// serval-router/types.zig
//! Router Types
//!
//! Route matching and configuration types for content-based routing.
//! Routes requests to backend pools based on host and path matching.
//!
//! TigerStyle: Fixed-size types, no allocation, explicit defaults.

const std = @import("std");
const core = @import("serval-core");
const lb = @import("serval-lb");

pub const LbHandler = lb.LbHandler;
pub const LbConfig = lb.LbConfig;
pub const Upstream = core.Upstream;

// =============================================================================
// Path Matching
// =============================================================================

/// Path match mode for route matching.
///
/// TigerStyle: Tagged union prevents invalid states (can't be both exact and prefix).
pub const PathMatch = union(enum) {
    /// Exact path match: "/api/v1/users" matches only "/api/v1/users".
    /// Does not match "/api/v1/users/" or "/api/v1/users/123".
    exact: []const u8,

    /// Prefix match: "/api/" matches "/api/users", "/api/v1/health", etc.
    /// The prefix must match the start of the request path.
    prefix: []const u8,

    /// Check if a request path matches this pattern.
    /// TigerStyle: Bounded, returns bool (no allocation).
    pub fn matches(self: PathMatch, request_path: []const u8) bool {
        return switch (self) {
            .exact => |pattern| std.mem.eql(u8, request_path, pattern),
            .prefix => |pattern| std.mem.startsWith(u8, request_path, pattern),
        };
    }

    /// Get the pattern string for logging/debugging.
    /// TigerStyle: Trivial accessor, assertion-exempt.
    pub fn getPattern(self: PathMatch) []const u8 {
        return switch (self) {
            .exact => |p| p,
            .prefix => |p| p,
        };
    }
};

// =============================================================================
// Route Matcher
// =============================================================================

/// Route match criteria combining host and path matching.
///
/// Both host and path must match for the route to be selected.
/// TigerStyle: Optional host (null = any host), required path.
pub const RouteMatcher = struct {
    /// Host to match (null = match any host).
    /// Compared case-insensitively per RFC 9110.
    host: ?[]const u8 = null,

    /// Path match mode (exact or prefix).
    path: PathMatch,

    /// Check if a request matches this route.
    /// TigerStyle: Returns bool, no allocation.
    pub fn matches(self: RouteMatcher, request_host: ?[]const u8, request_path: []const u8) bool {
        // Check host match (if specified)
        if (self.host) |expected_host| {
            const actual_host = request_host orelse return false;
            // Case-insensitive host comparison (RFC 9110)
            if (!std.ascii.eqlIgnoreCase(expected_host, actual_host)) {
                return false;
            }
        }

        // Check path match
        return self.path.matches(request_path);
    }
};

// =============================================================================
// Route
// =============================================================================

/// A single route entry mapping match criteria to a backend pool.
///
/// Routes are evaluated in order; first match wins.
/// TigerStyle: Fixed-size, explicit pool_idx for array indexing.
pub const Route = struct {
    /// Route name for logging/debugging (e.g., "api-v1", "static-assets").
    name: []const u8,

    /// Match criteria (host + path).
    matcher: RouteMatcher,

    /// Index into the backend pools array.
    /// TigerStyle: u8 allows up to 256 pools (more than sufficient).
    pool_idx: u8,

    /// Strip matched prefix before forwarding.
    /// Only applies to prefix matches.
    /// Example: route "/api/" -> backend, strip=true: "/api/users" -> "/users"
    strip_prefix: bool = false,
};

// =============================================================================
// Pool Configuration
// =============================================================================

/// Configuration for a backend pool with load balancer settings.
///
/// Each pool has its own set of upstreams and LB configuration.
/// TigerStyle: Fixed-size references, no heap allocation.
pub const PoolConfig = struct {
    /// Pool name for logging/debugging (e.g., "api-backends", "static-servers").
    name: []const u8,

    /// Upstream servers in this pool.
    /// Slice into caller-owned array (not heap-allocated).
    upstreams: []const Upstream,

    /// Load balancer configuration for this pool.
    lb_config: LbConfig = .{},
};

// =============================================================================
// Tests
// =============================================================================

test "PathMatch exact matches" {
    const pattern = PathMatch{ .exact = "/api/v1/users" };

    // Exact match succeeds
    try std.testing.expect(pattern.matches("/api/v1/users"));

    // Trailing slash fails
    try std.testing.expect(!pattern.matches("/api/v1/users/"));

    // Subpath fails
    try std.testing.expect(!pattern.matches("/api/v1/users/123"));

    // Different path fails
    try std.testing.expect(!pattern.matches("/api/v2/users"));

    // Prefix of pattern fails
    try std.testing.expect(!pattern.matches("/api/v1"));
}

test "PathMatch prefix matches" {
    const pattern = PathMatch{ .prefix = "/api/" };

    // Prefix matches
    try std.testing.expect(pattern.matches("/api/"));
    try std.testing.expect(pattern.matches("/api/users"));
    try std.testing.expect(pattern.matches("/api/v1/health"));

    // Non-prefix fails
    try std.testing.expect(!pattern.matches("/v1/api/"));
    try std.testing.expect(!pattern.matches("/apifoo"));
    try std.testing.expect(!pattern.matches("/ap"));
}

test "PathMatch getPattern" {
    const exact = PathMatch{ .exact = "/health" };
    const prefix = PathMatch{ .prefix = "/api/" };

    try std.testing.expectEqualStrings("/health", exact.getPattern());
    try std.testing.expectEqualStrings("/api/", prefix.getPattern());
}

test "RouteMatcher host and path" {
    const matcher = RouteMatcher{
        .host = "api.example.com",
        .path = .{ .prefix = "/v1/" },
    };

    // Both match
    try std.testing.expect(matcher.matches("api.example.com", "/v1/users"));

    // Host mismatch
    try std.testing.expect(!matcher.matches("www.example.com", "/v1/users"));

    // Path mismatch
    try std.testing.expect(!matcher.matches("api.example.com", "/v2/users"));

    // Null host with required host
    try std.testing.expect(!matcher.matches(null, "/v1/users"));
}

test "RouteMatcher any host" {
    const matcher = RouteMatcher{
        .host = null, // Any host
        .path = .{ .exact = "/health" },
    };

    // Any host matches
    try std.testing.expect(matcher.matches("api.example.com", "/health"));
    try std.testing.expect(matcher.matches("www.example.com", "/health"));
    try std.testing.expect(matcher.matches(null, "/health"));

    // Path must still match
    try std.testing.expect(!matcher.matches("api.example.com", "/ready"));
}

test "RouteMatcher case insensitive host" {
    const matcher = RouteMatcher{
        .host = "API.Example.COM",
        .path = .{ .prefix = "/" },
    };

    // Case variations match
    try std.testing.expect(matcher.matches("api.example.com", "/"));
    try std.testing.expect(matcher.matches("API.EXAMPLE.COM", "/"));
    try std.testing.expect(matcher.matches("Api.Example.Com", "/"));
}

test "Route defaults" {
    const route = Route{
        .name = "default",
        .matcher = .{ .path = .{ .prefix = "/" } },
        .pool_idx = 0,
    };

    // strip_prefix defaults to false
    try std.testing.expect(!route.strip_prefix);
}

test "Route with strip_prefix" {
    const route = Route{
        .name = "api",
        .matcher = .{ .path = .{ .prefix = "/api/" } },
        .pool_idx = 1,
        .strip_prefix = true,
    };

    try std.testing.expectEqualStrings("api", route.name);
    try std.testing.expectEqual(@as(u8, 1), route.pool_idx);
    try std.testing.expect(route.strip_prefix);
}

test "PoolConfig defaults" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    };

    const pool = PoolConfig{
        .name = "test-pool",
        .upstreams = &upstreams,
    };

    try std.testing.expectEqualStrings("test-pool", pool.name);
    try std.testing.expectEqual(@as(usize, 1), pool.upstreams.len);
    // LbConfig has defaults
    try std.testing.expect(pool.lb_config.enable_probing);
}

test "PoolConfig with custom lb_config" {
    const upstreams = [_]Upstream{
        .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
        .{ .host = "127.0.0.1", .port = 8002, .idx = 1 },
    };

    const pool = PoolConfig{
        .name = "custom-pool",
        .upstreams = &upstreams,
        .lb_config = .{
            .unhealthy_threshold = 5,
            .healthy_threshold = 3,
            .enable_probing = false,
        },
    };

    try std.testing.expectEqual(@as(u8, 5), pool.lb_config.unhealthy_threshold);
    try std.testing.expectEqual(@as(u8, 3), pool.lb_config.healthy_threshold);
    try std.testing.expect(!pool.lb_config.enable_probing);
}
