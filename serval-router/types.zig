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
            inline else => |p| p,
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
            // Strip port if present. RFC 9110 §7.2: Host header may include port.
            const hostname = if (std.mem.indexOfScalar(u8, actual_host, ':')) |i| actual_host[0..i] else actual_host;

            if (!matchHost(expected_host, hostname)) {
                return false;
            }
        }

        // Check path match
        return self.path.matches(request_path);
    }

    /// Match hostname against pattern, supporting wildcards.
    ///
    /// Wildcard patterns (e.g., "*.example.com") match exactly one subdomain level:
    /// - "*.example.com" matches "foo.example.com", "bar.example.com"
    /// - Does NOT match "example.com" (requires a subdomain)
    /// - Does NOT match "foo.bar.example.com" (only one subdomain level)
    ///
    /// TigerStyle: Pure function, no allocation, bounded iteration.
    fn matchHost(pattern: []const u8, hostname: []const u8) bool {
        // Preconditions: pattern comes from route config, hostname from request
        std.debug.assert(pattern.len > 0); // Route config validation ensures non-empty
        std.debug.assert(hostname.len > 0); // Caller strips port, empty hostname rejected earlier

        // Check for wildcard pattern: must start with "*."
        if (std.mem.startsWith(u8, pattern, "*.")) {
            const base_domain = pattern[2..]; // Skip "*."

            // Base domain must be non-empty (e.g., "*.com" has base "com")
            if (base_domain.len == 0) {
                return false;
            }

            // Hostname must be longer than base domain + 1 (for subdomain + dot)
            // This ensures there's room for at least "x." before the base domain
            if (hostname.len <= base_domain.len + 1) {
                return false;
            }

            // Hostname must end with "." + base_domain (case-insensitive)
            // We check if hostname ends with the base domain pattern
            const suffix_start = hostname.len - base_domain.len;
            const suffix = hostname[suffix_start..];
            if (!std.ascii.eqlIgnoreCase(suffix, base_domain)) {
                return false;
            }

            // Character before suffix must be a dot
            if (hostname[suffix_start - 1] != '.') {
                return false;
            }

            // Extract the subdomain part (everything before the dot + base_domain)
            const subdomain = hostname[0 .. suffix_start - 1];

            // Subdomain must not be empty and must not contain dots
            // (ensures exactly one subdomain level: "foo" OK, "foo.bar" NOT OK)
            if (subdomain.len == 0) {
                return false;
            }

            // Check for dots in subdomain - if found, reject (multi-level subdomain)
            // TigerStyle: indexOfScalar is bounded by subdomain.len
            if (std.mem.indexOfScalar(u8, subdomain, '.') != null) {
                return false;
            }

            return true;
        }

        // Non-wildcard: exact case-insensitive match (RFC 9110 §4.2.3)
        return std.ascii.eqlIgnoreCase(pattern, hostname);
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

test "RouteMatcher strips port from host" {
    const matcher = RouteMatcher{
        .host = "api.example.com",
        .path = .{ .prefix = "/" },
    };

    // Host with port should match after stripping (RFC 9110 §7.2)
    try std.testing.expect(matcher.matches("api.example.com:8080", "/"));
    try std.testing.expect(matcher.matches("api.example.com:443", "/"));
    try std.testing.expect(matcher.matches("api.example.com:31588", "/")); // NodePort

    // Without port still works
    try std.testing.expect(matcher.matches("api.example.com", "/"));

    // Different host with port should not match
    try std.testing.expect(!matcher.matches("other.example.com:8080", "/"));
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

test "RouteMatcher wildcard host" {
    const matcher = RouteMatcher{
        .host = "*.example.com",
        .path = .{ .prefix = "/" },
    };

    // Should match single subdomain
    try std.testing.expect(matcher.matches("foo.example.com", "/"));
    try std.testing.expect(matcher.matches("bar.example.com", "/"));
    try std.testing.expect(matcher.matches("FOO.EXAMPLE.COM", "/")); // case-insensitive
    try std.testing.expect(matcher.matches("foo.example.com:8080", "/")); // with port

    // Should NOT match base domain
    try std.testing.expect(!matcher.matches("example.com", "/"));

    // Should NOT match multiple subdomains
    try std.testing.expect(!matcher.matches("foo.bar.example.com", "/"));

    // Should NOT match different domain
    try std.testing.expect(!matcher.matches("foo.other.com", "/"));
}

test "RouteMatcher wildcard host edge cases" {
    // Wildcard with deeper base domain
    const matcher_deep = RouteMatcher{
        .host = "*.api.example.com",
        .path = .{ .prefix = "/" },
    };

    try std.testing.expect(matcher_deep.matches("v1.api.example.com", "/"));
    try std.testing.expect(matcher_deep.matches("v2.api.example.com", "/"));
    try std.testing.expect(!matcher_deep.matches("api.example.com", "/")); // no subdomain
    try std.testing.expect(!matcher_deep.matches("foo.v1.api.example.com", "/")); // multi-level

    // Single-label base domain (e.g., *.localhost - unusual but valid)
    const matcher_single = RouteMatcher{
        .host = "*.localhost",
        .path = .{ .prefix = "/" },
    };

    try std.testing.expect(matcher_single.matches("app.localhost", "/"));
    try std.testing.expect(!matcher_single.matches("localhost", "/"));
    try std.testing.expect(!matcher_single.matches("foo.app.localhost", "/"));
}

test "RouteMatcher wildcard host with path matching" {
    const matcher = RouteMatcher{
        .host = "*.example.com",
        .path = .{ .prefix = "/api/" },
    };

    // Both host and path must match
    try std.testing.expect(matcher.matches("foo.example.com", "/api/users"));
    try std.testing.expect(!matcher.matches("foo.example.com", "/other")); // path mismatch
    try std.testing.expect(!matcher.matches("example.com", "/api/users")); // host mismatch
}
