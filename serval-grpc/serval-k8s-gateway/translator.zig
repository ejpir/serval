//! GatewayConfig to Router JSON Translator
//!
//! Translates Kubernetes Gateway API configuration to JSON format
//! for the serval-router admin API (POST /routes/update).
//!
//! JSON Output Format:
//! ```json
//! {
//!   "allowed_hosts": ["api.example.com", "www.example.com"],
//!   "routes": [
//!     {"name": "api", "host": "api.example.com", "path_prefix": "/api/", "pool_idx": 0, "strip_prefix": true}
//!   ],
//!   "pools": [
//!     {"name": "api-pool", "upstreams": [{"host": "10.0.1.5", "port": 8001, "idx": 0, "tls": false}]}
//!   ]
//! }
//! ```
//!
//! TigerStyle: Fixed-size buffers, bounded loops, explicit error handling, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;
const core = @import("serval-core");
const core_config = core.config;
const gw_config = @import("config.zig");

// ============================================================================
// Constants (TigerStyle: Named constants with units)
// ============================================================================

/// Maximum JSON output size in bytes (1MB).
/// Matches MAX_ADMIN_REQUEST_BYTES from serval-core/config.zig.
/// TigerStyle Y3: Units in name.
pub const MAX_JSON_SIZE_BYTES: u32 = core_config.MAX_ADMIN_REQUEST_BYTES;

/// Maximum routes to include in JSON output.
pub const MAX_ROUTES: u8 = core_config.MAX_ROUTES;

/// Maximum pools to include in JSON output.
pub const MAX_POOLS: u8 = core_config.MAX_POOLS;

/// Maximum upstreams per pool in JSON output.
pub const MAX_UPSTREAMS_PER_POOL: u8 = core_config.MAX_UPSTREAMS_PER_POOL;

/// Maximum allowed hosts to include in JSON output.
/// TigerStyle S7: Bounded by MAX_ALLOWED_HOSTS from serval-core.
pub const MAX_ALLOWED_HOSTS: u8 = core_config.MAX_ALLOWED_HOSTS;

/// Maximum iterations for route generation loop.
/// Accounts for: routes * rules * matches * hostnames (or 1 if no hostnames).
const MAX_ROUTE_ITERATIONS: u32 = @as(u32, MAX_ROUTES) * @as(u32, gw_config.MAX_RULES) * @as(u32, gw_config.MAX_MATCHES) * @as(u32, gw_config.MAX_HOSTNAMES);

// ============================================================================
// Error Types
// ============================================================================

pub const TranslatorError = error{
    /// JSON output buffer is too small.
    BufferTooSmall,
    /// Too many routes in configuration.
    TooManyRoutes,
    /// Too many pools in configuration.
    TooManyPools,
    /// Too many upstreams in pool.
    TooManyUpstreams,
    /// Backend service not found in resolver.
    BackendNotFound,
    /// Route references invalid pool index.
    InvalidPoolIndex,
    /// No routes generated (config may be empty).
    NoRoutes,
    /// Invalid configuration state.
    InvalidConfig,
};

// ============================================================================
// Translator
// ============================================================================

/// Translate GatewayConfig to JSON for router admin API.
///
/// Takes pre-resolved backends (Service -> Endpoints already looked up).
/// Output format matches POST /routes/update expected JSON.
///
/// Arguments:
///   config: Gateway API configuration (HTTPRoutes).
///   resolved_backends: Pre-resolved backend endpoints (from K8s or other source).
///   out_buf: Output buffer for JSON (must be at least MAX_JSON_SIZE_BYTES bytes).
///
/// Returns:
///   Number of bytes written to out_buf.
///
/// TigerStyle: Bounded loops, explicit error handling, no allocation.
pub fn translateToJson(
    config_ptr: *const gw_config.GatewayConfig,
    resolved_backends: []const gw_config.ResolvedBackend,
    out_buf: *[MAX_JSON_SIZE_BYTES]u8,
) TranslatorError!usize {
    // S1: Preconditions
    assert(out_buf.len >= MAX_JSON_SIZE_BYTES);

    var writer = JsonWriter.init(out_buf);

    // Start root object
    writer.writeRaw("{") catch return error.BufferTooSmall;

    // Write allowed_hosts array from HTTPRoute hostnames.
    // TigerStyle Y5: We use HTTPRoute hostnames (not Gateway listener hostnames)
    // because HTTPRoutes have specific hostnames while Gateway listeners may have wildcards.
    writer.writeRaw("\"allowed_hosts\":[") catch return error.BufferTooSmall;
    var host_count: u8 = 0;

    // Storage for tracking seen hostnames to deduplicate.
    // TigerStyle S7: Bounded by MAX_ALLOWED_HOSTS.
    var seen_hosts: [MAX_ALLOWED_HOSTS][gw_config.MAX_NAME_LEN]u8 = undefined;
    var seen_hosts_len: [MAX_ALLOWED_HOSTS]u8 = undefined;

    for (config_ptr.http_routes, 0..) |http_route, route_i| {
        // S3: Bounded loop check
        if (route_i >= gw_config.MAX_HTTP_ROUTES) break;

        for (http_route.hostnames, 0..) |hostname, h_i| {
            // S3: Bounded loop check
            if (h_i >= gw_config.MAX_HOSTNAMES) break;
            // S7: Bounded by MAX_ALLOWED_HOSTS
            if (host_count >= MAX_ALLOWED_HOSTS) break;

            // Skip duplicates (simple O(n) check, bounded by MAX_ALLOWED_HOSTS)
            var is_duplicate = false;
            var dup_i: u8 = 0;
            while (dup_i < host_count) : (dup_i += 1) {
                const seen_len = seen_hosts_len[dup_i];
                if (seen_len == hostname.len and
                    std.mem.eql(u8, seen_hosts[dup_i][0..seen_len], hostname))
                {
                    is_duplicate = true;
                    break;
                }
            }

            if (!is_duplicate) {
                if (host_count > 0) {
                    writer.writeRaw(",") catch return error.BufferTooSmall;
                }
                writer.writeRaw("\"") catch return error.BufferTooSmall;
                writer.writeRaw(hostname) catch return error.BufferTooSmall;
                writer.writeRaw("\"") catch return error.BufferTooSmall;

                // Track this hostname to prevent duplicates
                const copy_len: u8 = @intCast(@min(hostname.len, gw_config.MAX_NAME_LEN));
                @memcpy(seen_hosts[host_count][0..copy_len], hostname[0..copy_len]);
                seen_hosts_len[host_count] = copy_len;
                host_count += 1;
            }
        }
    }

    writer.writeRaw("],") catch return error.BufferTooSmall;

    // Write routes array
    writer.writeRaw("\"routes\":[") catch return error.BufferTooSmall;
    var route_count: u8 = 0;
    var pool_count_for_routes: u8 = 0; // Tracks pools for route->pool mapping

    // Process each HTTPRoute
    for (config_ptr.http_routes, 0..) |http_route, route_i| {
        // S3: Bounded loop check
        if (route_i >= gw_config.MAX_HTTP_ROUTES) break;

        // Build hostname list: either actual hostnames or [null] for match-all
        // TigerStyle: Use sentinel to indicate "no hostname filter"
        const hostnames = http_route.hostnames;
        const hostname_count: u8 = if (hostnames.len > 0) @intCast(@min(hostnames.len, gw_config.MAX_HOSTNAMES)) else 1;

        // Process each rule
        for (http_route.rules, 0..) |rule, rule_i| {
            // S3: Bounded loop check
            if (rule_i >= gw_config.MAX_RULES) break;

            // Pool index for this rule's backends (one pool per rule)
            const pool_idx = pool_count_for_routes;
            if (pool_idx >= MAX_POOLS) {
                return error.TooManyPools;
            }
            pool_count_for_routes += 1;

            // Check if rule has URLRewrite filter for strip_prefix
            const strip_prefix = hasUrlRewriteFilter(rule.filters);

            // For each hostname, generate routes for this rule
            var hostname_i: u8 = 0;
            while (hostname_i < hostname_count) : (hostname_i += 1) {
                // S3: Bounded loop check
                if (hostname_i >= gw_config.MAX_HOSTNAMES) break;

                // Get current hostname (null if route has no hostnames)
                const host: ?[]const u8 = if (hostnames.len > 0) hostnames[hostname_i] else null;

                // Process each match in the rule
                if (rule.matches.len == 0) {
                    // No matches means catch-all route for this host
                    if (route_count >= MAX_ROUTES) {
                        return error.TooManyRoutes;
                    }

                    if (route_count > 0) {
                        writer.writeRaw(",") catch return error.BufferTooSmall;
                    }
                    // Catch-all routes default to prefix match on "/"
                    try writeRoute(&writer, http_route.name, host, null, pool_idx, false);
                    route_count += 1;
                } else {
                    for (rule.matches, 0..) |match, match_i| {
                        // S3: Bounded loop check
                        if (match_i >= gw_config.MAX_MATCHES) break;

                        if (route_count >= MAX_ROUTES) {
                            return error.TooManyRoutes;
                        }

                        if (route_count > 0) {
                            writer.writeRaw(",") catch return error.BufferTooSmall;
                        }

                        // Pass full PathMatch to preserve match type (Exact vs PathPrefix)
                        try writeRoute(&writer, http_route.name, host, match.path, pool_idx, strip_prefix);
                        route_count += 1;
                    }
                }
            }
        }
    }

    writer.writeRaw("],") catch return error.BufferTooSmall;

    // Write pools array
    writer.writeRaw("\"pools\":[") catch return error.BufferTooSmall;
    var pool_count: u8 = 0;

    // Generate pools from HTTPRoute backend refs
    for (config_ptr.http_routes, 0..) |http_route, route_i| {
        // S3: Bounded loop check
        if (route_i >= gw_config.MAX_HTTP_ROUTES) break;

        for (http_route.rules, 0..) |rule, rule_i| {
            // S3: Bounded loop check
            if (rule_i >= gw_config.MAX_RULES) break;

            if (pool_count >= MAX_POOLS) {
                return error.TooManyPools;
            }

            if (pool_count > 0) {
                writer.writeRaw(",") catch return error.BufferTooSmall;
            }

            try writePool(&writer, http_route.name, rule.backend_refs, resolved_backends, pool_count);
            pool_count += 1;
        }
    }

    writer.writeRaw("]") catch return error.BufferTooSmall;

    // Close root object
    writer.writeRaw("}") catch return error.BufferTooSmall;

    const written = writer.pos;

    // S2: Postconditions
    assert(written <= MAX_JSON_SIZE_BYTES);

    return written;
}

/// Check if any filter has a URL rewrite path configured.
fn hasUrlRewriteFilter(filters: []const gw_config.HTTPRouteFilter) bool {
    assert(filters.len <= gw_config.MAX_FILTERS); // S1: precondition

    for (filters) |filter| {
        if (filter.type != .URLRewrite) continue;
        const rewrite = filter.url_rewrite orelse continue;
        if (rewrite.path != null) return true;
    }
    return false;
}

/// Write a single route object to JSON (outputs path_exact or path_prefix based on match type).
fn writeRoute(
    writer: *JsonWriter,
    name: []const u8,
    host: ?[]const u8,
    path_match: ?gw_config.PathMatch,
    pool_idx: u8,
    strip_prefix: bool,
) TranslatorError!void {
    assert(name.len > 0); // S1: precondition
    assert(pool_idx < MAX_POOLS); // S1: precondition

    writer.writeRaw("{\"name\":\"") catch return error.BufferTooSmall;
    writer.writeRaw(name) catch return error.BufferTooSmall;
    writer.writeRaw("\",") catch return error.BufferTooSmall;

    if (host) |h| {
        writer.writeRaw("\"host\":\"") catch return error.BufferTooSmall;
        writer.writeRaw(h) catch return error.BufferTooSmall;
        writer.writeRaw("\",") catch return error.BufferTooSmall;
    }

    // Exact vs prefix path match (defaults to prefix "/" for catch-all routes)
    const path_value = if (path_match) |pm| pm.value else "/";
    const is_exact = if (path_match) |pm| pm.type == .Exact else false;
    const path_key = if (is_exact) "\"path_exact\":\"" else "\"path_prefix\":\"";

    writer.writeRaw(path_key) catch return error.BufferTooSmall;
    writer.writeRaw(path_value) catch return error.BufferTooSmall;
    writer.writeRaw("\",") catch return error.BufferTooSmall;

    writer.writeRaw("\"pool_idx\":") catch return error.BufferTooSmall;
    var idx_buf: [4]u8 = undefined;
    const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{pool_idx}) catch return error.BufferTooSmall;
    writer.writeRaw(idx_str) catch return error.BufferTooSmall;

    writer.writeRaw(",\"strip_prefix\":") catch return error.BufferTooSmall;
    writer.writeRaw(if (strip_prefix) "true}" else "false}") catch return error.BufferTooSmall;
}

/// Find resolved backend by name and namespace.
fn findResolvedBackend(
    backends: []const gw_config.ResolvedBackend,
    name: []const u8,
    namespace: []const u8,
) ?*const gw_config.ResolvedBackend {
    assert(name.len > 0); // S1: precondition
    assert(namespace.len > 0); // S1: precondition
    assert(backends.len <= gw_config.MAX_RESOLVED_BACKENDS); // S1: precondition

    for (backends) |*backend| {
        const name_match = std.mem.eql(u8, backend.getName(), name);
        const ns_match = std.mem.eql(u8, backend.getNamespace(), namespace);
        if (name_match and ns_match) return backend;
    }
    return null;
}

/// Write a single pool object to JSON with resolved upstreams.
fn writePool(
    writer: *JsonWriter,
    name: []const u8,
    backend_refs: []const gw_config.BackendRef,
    resolved_backends: []const gw_config.ResolvedBackend,
    pool_idx: u8,
) TranslatorError!void {
    _ = pool_idx; // Used for assertion in caller
    assert(name.len > 0); // S1: precondition
    assert(resolved_backends.len <= gw_config.MAX_RESOLVED_BACKENDS); // S1: precondition

    writer.writeRaw("{\"name\":\"") catch return error.BufferTooSmall;
    writer.writeRaw(name) catch return error.BufferTooSmall;
    writer.writeRaw("-pool\",\"upstreams\":[") catch return error.BufferTooSmall;

    var upstream_count: u8 = 0;

    for (backend_refs, 0..) |backend_ref, ref_i| {
        if (ref_i >= gw_config.MAX_BACKEND_REFS) break; // S3: bounded loop

        const resolved = findResolvedBackend(
            resolved_backends,
            backend_ref.name,
            backend_ref.namespace,
        ) orelse continue; // Skip backends without resolved endpoints

        for (resolved.getEndpoints(), 0..) |ep, ep_i| {
            if (ep_i >= gw_config.MAX_RESOLVED_ENDPOINTS) break; // S3: bounded loop
            if (upstream_count >= MAX_UPSTREAMS_PER_POOL) return error.TooManyUpstreams;

            if (upstream_count > 0) {
                writer.writeRaw(",") catch return error.BufferTooSmall;
            }

            try writeUpstream(writer, ep.getIp(), backend_ref.port, upstream_count);
            upstream_count += 1;
        }
    }

    // Probing disabled: router_example passes null dns_resolver to swapRouter()
    writer.writeRaw("],\"lb_config\":{\"enable_probing\":false,\"probe_interval_ms\":5000,\"health_path\":\"/\"}}") catch return error.BufferTooSmall;
}

/// Write a single upstream object to JSON.
fn writeUpstream(
    writer: *JsonWriter,
    host: []const u8,
    port: u16,
    idx: u8,
) TranslatorError!void {
    assert(host.len > 0); // S1: precondition
    assert(port > 0); // S1: precondition

    writer.writeRaw("{\"host\":\"") catch return error.BufferTooSmall;
    writer.writeRaw(host) catch return error.BufferTooSmall;
    writer.writeRaw("\",\"port\":") catch return error.BufferTooSmall;

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch return error.BufferTooSmall;
    writer.writeRaw(port_str) catch return error.BufferTooSmall;

    writer.writeRaw(",\"idx\":") catch return error.BufferTooSmall;
    var idx_buf: [4]u8 = undefined;
    const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{idx}) catch return error.BufferTooSmall;
    writer.writeRaw(idx_str) catch return error.BufferTooSmall;

    writer.writeRaw(",\"tls\":false}") catch return error.BufferTooSmall;
}

// ============================================================================
// JSON Writer Helper
// ============================================================================

/// Simple bounded JSON writer (no allocation, explicit overflow error).
const JsonWriter = struct {
    buf: []u8,
    pos: u32, // Matches MAX_JSON_SIZE_BYTES bound

    fn init(buf: *[MAX_JSON_SIZE_BYTES]u8) JsonWriter {
        return .{ .buf = buf, .pos = 0 };
    }

    fn writeRaw(self: *JsonWriter, data: []const u8) !void {
        assert(data.len <= MAX_JSON_SIZE_BYTES); // S1: precondition

        const data_len: u32 = @intCast(data.len);
        if (self.pos + data_len > @as(u32, @intCast(self.buf.len))) {
            return error.BufferTooSmall;
        }
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data_len;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

/// Helper to create a ResolvedBackend for tests.
/// TigerStyle: Fixed-size buffer helper, no allocation.
fn createTestBackend(
    name: []const u8,
    namespace: []const u8,
    ips: []const []const u8,
    port: u16,
) gw_config.ResolvedBackend {
    // S1: Preconditions
    assert(name.len <= gw_config.MAX_NAME_LEN);
    assert(namespace.len <= gw_config.MAX_NAME_LEN);
    assert(ips.len <= gw_config.MAX_RESOLVED_ENDPOINTS);

    var backend: gw_config.ResolvedBackend = undefined;

    // Set name
    @memcpy(backend.name[0..name.len], name);
    backend.name_len = @intCast(name.len);

    // Set namespace
    @memcpy(backend.namespace[0..namespace.len], namespace);
    backend.namespace_len = @intCast(namespace.len);

    // Set endpoints
    for (ips, 0..) |ip, i| {
        @memcpy(backend.endpoints[i].ip[0..ip.len], ip);
        backend.endpoints[i].ip_len = @intCast(ip.len);
        backend.endpoints[i].port = port;
    }
    backend.endpoint_count = @intCast(ips.len);

    return backend;
}

test "translateToJson empty config" {
    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &.{},
    };

    const resolved_backends = [_]gw_config.ResolvedBackend{};
    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;

    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    try std.testing.expect(len > 0);

    // Should have valid JSON structure
    const json = out_buf[0..len];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"allowed_hosts\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"routes\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"pools\":[]") != null);
    // default_route should NOT be present
    try std.testing.expect(std.mem.indexOf(u8, json, "\"default_route\":") == null);
}

test "translateToJson with simple HTTPRoute" {
    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/api/" } },
    };
    var backend_refs = [_]gw_config.BackendRef{
        .{ .name = "api-svc", .namespace = "default", .port = 8080 },
    };
    var rules = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "api-route",
            .namespace = "default",
            .hostnames = &.{},
            .rules = &rules,
        },
    };

    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    // Set up resolved backends with service endpoints
    const ips = [_][]const u8{ "10.0.1.1", "10.0.1.2" };
    var resolved_backends = [_]gw_config.ResolvedBackend{
        createTestBackend("api-svc", "default", &ips, 8080),
    };

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    try std.testing.expect(len > 0);

    const json = out_buf[0..len];

    // Verify route is present
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"api-route\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"path_prefix\":\"/api/\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"pool_idx\":0") != null);

    // Verify pool is present with upstreams
    try std.testing.expect(std.mem.indexOf(u8, json, "\"upstreams\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"host\":\"10.0.1.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"host\":\"10.0.1.2\"") != null);
}

test "translateToJson with exact path match" {
    // HTTPRoute with Exact path match type should output path_exact in JSON
    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .Exact, .value = "/health" } },
    };
    var backend_refs = [_]gw_config.BackendRef{
        .{ .name = "health-svc", .namespace = "default", .port = 8080 },
    };
    var rules = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "health-route",
            .namespace = "default",
            .hostnames = &.{},
            .rules = &rules,
        },
    };

    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    const ips = [_][]const u8{"10.0.1.1"};
    var resolved_backends = [_]gw_config.ResolvedBackend{
        createTestBackend("health-svc", "default", &ips, 8080),
    };

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    try std.testing.expect(len > 0);

    const json = out_buf[0..len];

    // Verify path_exact is used (not path_prefix)
    try std.testing.expect(std.mem.indexOf(u8, json, "\"path_exact\":\"/health\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"path_prefix\":\"/health\"") == null);
}

test "translateToJson with host matching" {
    var hostnames = [_][]const u8{"api.example.com"};
    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/" } },
    };
    var backend_refs = [_]gw_config.BackendRef{
        .{ .name = "api-svc", .namespace = "default", .port = 8080 },
    };
    var rules = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "host-route",
            .namespace = "default",
            .hostnames = &hostnames,
            .rules = &rules,
        },
    };

    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    // Set up resolved backends with service endpoints
    const ips = [_][]const u8{"10.0.1.1"};
    var resolved_backends = [_]gw_config.ResolvedBackend{
        createTestBackend("api-svc", "default", &ips, 8080),
    };

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    const json = out_buf[0..len];

    // Verify host is present in route
    try std.testing.expect(std.mem.indexOf(u8, json, "\"host\":\"api.example.com\"") != null);
}

test "translateToJson with URLRewrite filter" {
    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/api/" } },
    };
    var filters = [_]gw_config.HTTPRouteFilter{
        .{
            .type = .URLRewrite,
            .url_rewrite = .{
                .path = .{ .type = .ReplacePrefixMatch, .value = "/" },
            },
        },
    };
    var backend_refs = [_]gw_config.BackendRef{
        .{ .name = "api-svc", .namespace = "default", .port = 8080 },
    };
    var rules = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &filters,
            .backend_refs = &backend_refs,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "rewrite-route",
            .namespace = "default",
            .hostnames = &.{},
            .rules = &rules,
        },
    };

    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    // Set up resolved backends with service endpoints
    const ips = [_][]const u8{"10.0.1.1"};
    var resolved_backends = [_]gw_config.ResolvedBackend{
        createTestBackend("api-svc", "default", &ips, 8080),
    };

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    const json = out_buf[0..len];

    // Verify strip_prefix is true for URLRewrite filter
    try std.testing.expect(std.mem.indexOf(u8, json, "\"strip_prefix\":true") != null);
}

test "hasUrlRewriteFilter" {
    // Test with URLRewrite filter
    var filters_with_rewrite = [_]gw_config.HTTPRouteFilter{
        .{
            .type = .URLRewrite,
            .url_rewrite = .{
                .path = .{ .type = .ReplacePrefixMatch, .value = "/" },
            },
        },
    };
    try std.testing.expect(hasUrlRewriteFilter(&filters_with_rewrite));

    // Test without path (should be false)
    var filters_no_path = [_]gw_config.HTTPRouteFilter{
        .{
            .type = .URLRewrite,
            .url_rewrite = .{ .path = null },
        },
    };
    try std.testing.expect(!hasUrlRewriteFilter(&filters_no_path));

    // Test empty filters
    try std.testing.expect(!hasUrlRewriteFilter(&.{}));
}

test "JsonWriter basic operations" {
    var buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    var writer = JsonWriter.init(&buf);

    try writer.writeRaw("{\"test\":");
    try writer.writeRaw("true");
    try writer.writeRaw("}");

    const result = buf[0..writer.pos];
    try std.testing.expectEqualStrings("{\"test\":true}", result);
}

test "JsonWriter overflow detection" {
    var small_buf: [10]u8 = undefined;
    var writer = JsonWriter{
        .buf = &small_buf,
        .pos = 0,
    };

    try writer.writeRaw("123456789"); // 9 bytes, fits
    try std.testing.expectError(error.BufferTooSmall, writer.writeRaw("ab")); // 2 more bytes, doesn't fit
}

test "translateToJson full lb_config structure" {
    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/api/" } },
    };
    var backend_refs = [_]gw_config.BackendRef{
        .{ .name = "api-svc", .namespace = "default", .port = 8080 },
    };
    var rules = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "api-route",
            .namespace = "default",
            .hostnames = &.{},
            .rules = &rules,
        },
    };

    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    // Set up resolved backends with service endpoints
    const ips = [_][]const u8{"10.0.1.5"};
    var resolved_backends = [_]gw_config.ResolvedBackend{
        createTestBackend("api-svc", "default", &ips, 8080),
    };

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    const json = out_buf[0..len];

    // Verify lb_config structure (probing disabled for now - see TODO in writePool)
    try std.testing.expect(std.mem.indexOf(u8, json, "\"lb_config\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"enable_probing\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"probe_interval_ms\":5000") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"health_path\":\"/\"") != null);
}

test "findResolvedBackend basic lookup" {
    const ips = [_][]const u8{"10.0.0.1"};
    var backends = [_]gw_config.ResolvedBackend{
        createTestBackend("api-svc", "default", &ips, 8080),
    };

    // Should find the backend
    const found = findResolvedBackend(&backends, "api-svc", "default");
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("api-svc", found.?.getName());
    try std.testing.expectEqualStrings("default", found.?.getNamespace());

    // Should not find non-existent backend
    const not_found = findResolvedBackend(&backends, "other-svc", "default");
    try std.testing.expect(not_found == null);

    // Should not find with wrong namespace
    const wrong_ns = findResolvedBackend(&backends, "api-svc", "production");
    try std.testing.expect(wrong_ns == null);
}

test "translateToJson with multiple hostnames" {
    // An HTTPRoute with two hostnames should generate two routes pointing to the same pool
    var hostnames = [_][]const u8{ "api.example.com", "api.staging.example.com" };
    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/api/" } },
    };
    var backend_refs = [_]gw_config.BackendRef{
        .{ .name = "api-svc", .namespace = "default", .port = 8080 },
    };
    var rules = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "multi-host-route",
            .namespace = "default",
            .hostnames = &hostnames,
            .rules = &rules,
        },
    };

    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    // Set up resolved backends with service endpoints
    const ips = [_][]const u8{ "10.0.1.1", "10.0.1.2" };
    var resolved_backends = [_]gw_config.ResolvedBackend{
        createTestBackend("api-svc", "default", &ips, 8080),
    };

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    try std.testing.expect(len > 0);

    const json = out_buf[0..len];

    // Verify BOTH hostnames have routes generated
    try std.testing.expect(std.mem.indexOf(u8, json, "\"host\":\"api.example.com\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"host\":\"api.staging.example.com\"") != null);

    // Both routes should point to pool_idx 0 (same backends)
    // Count occurrences of the route path to verify two routes were created
    var count: u8 = 0;
    var search_start: usize = 0;
    while (std.mem.indexOfPos(u8, json, search_start, "\"path_prefix\":\"/api/\"")) |pos| {
        count += 1;
        search_start = pos + 1;
        if (count > 10) break; // S3: bounded loop
    }
    try std.testing.expectEqual(@as(u8, 2), count);

    // Verify only one pool was created (both routes share same backends)
    var pool_count: u8 = 0;
    var pool_search: usize = 0;
    while (std.mem.indexOfPos(u8, json, pool_search, "\"name\":\"multi-host-route-pool\"")) |pos| {
        pool_count += 1;
        pool_search = pos + 1;
        if (pool_count > 10) break; // S3: bounded loop
    }
    try std.testing.expectEqual(@as(u8, 1), pool_count);
}

test "translateToJson includes allowed_hosts from HTTPRoute hostnames" {
    var hostnames = [_][]const u8{ "api.example.com", "www.example.com" };
    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/" } },
    };
    var backend_refs = [_]gw_config.BackendRef{
        .{ .name = "api-svc", .namespace = "default", .port = 8080 },
    };
    var rules = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "host-route",
            .namespace = "default",
            .hostnames = &hostnames,
            .rules = &rules,
        },
    };

    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    // Set up resolved backends with service endpoints
    const ips = [_][]const u8{"10.0.1.1"};
    var resolved_backends = [_]gw_config.ResolvedBackend{
        createTestBackend("api-svc", "default", &ips, 8080),
    };

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    const json = out_buf[0..len];

    // Verify allowed_hosts is present with both hostnames
    try std.testing.expect(std.mem.indexOf(u8, json, "\"allowed_hosts\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"api.example.com\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"www.example.com\"") != null);

    // Verify default_route is NOT present
    try std.testing.expect(std.mem.indexOf(u8, json, "\"default_route\":") == null);
}

test "translateToJson deduplicates allowed_hosts" {
    // Two HTTPRoutes with overlapping hostnames
    var hostnames1 = [_][]const u8{ "api.example.com", "www.example.com" };
    var hostnames2 = [_][]const u8{ "api.example.com", "admin.example.com" }; // api.example.com is duplicate

    var matches = [_]gw_config.HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/" } },
    };
    var backend_refs1 = [_]gw_config.BackendRef{
        .{ .name = "api-svc", .namespace = "default", .port = 8080 },
    };
    var backend_refs2 = [_]gw_config.BackendRef{
        .{ .name = "admin-svc", .namespace = "default", .port = 8080 },
    };
    var rules1 = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs1,
        },
    };
    var rules2 = [_]gw_config.HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &.{},
            .backend_refs = &backend_refs2,
        },
    };
    var http_routes = [_]gw_config.HTTPRoute{
        .{
            .name = "api-route",
            .namespace = "default",
            .hostnames = &hostnames1,
            .rules = &rules1,
        },
        .{
            .name = "admin-route",
            .namespace = "default",
            .hostnames = &hostnames2,
            .rules = &rules2,
        },
    };

    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &http_routes,
    };

    // Set up resolved backends
    const ips = [_][]const u8{"10.0.1.1"};
    var resolved_backends = [_]gw_config.ResolvedBackend{
        createTestBackend("api-svc", "default", &ips, 8080),
        createTestBackend("admin-svc", "default", &ips, 8080),
    };

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved_backends, &out_buf);

    const json = out_buf[0..len];

    // Verify allowed_hosts contains all 3 unique hostnames
    try std.testing.expect(std.mem.indexOf(u8, json, "\"api.example.com\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"www.example.com\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"admin.example.com\"") != null);

    // Count occurrences of api.example.com - should only appear once in allowed_hosts
    // (may appear in routes too, so just check first occurrence in allowed_hosts section)
    const allowed_hosts_start = std.mem.indexOf(u8, json, "\"allowed_hosts\":[").?;
    const allowed_hosts_end = std.mem.indexOfPos(u8, json, allowed_hosts_start, "],").?;
    const allowed_hosts_section = json[allowed_hosts_start..allowed_hosts_end];

    // Count api.example.com in allowed_hosts section
    var api_count: u8 = 0;
    var search_pos: usize = 0;
    while (std.mem.indexOfPos(u8, allowed_hosts_section, search_pos, "\"api.example.com\"")) |pos| {
        api_count += 1;
        search_pos = pos + 1;
        if (api_count > 10) break; // S3: bounded loop
    }
    try std.testing.expectEqual(@as(u8, 1), api_count);
}
