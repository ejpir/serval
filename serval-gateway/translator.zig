//! GatewayConfig to Router JSON Translator
//!
//! Translates Kubernetes Gateway API configuration to JSON format
//! for the serval-router admin API (POST /routes/update).
//!
//! JSON Output Format:
//! ```json
//! {
//!   "routes": [
//!     {"name": "api", "host": "api.example.com", "path_prefix": "/api/", "pool_idx": 0, "strip_prefix": true}
//!   ],
//!   "default_route": {"name": "default", "path_prefix": "/", "pool_idx": 0, "strip_prefix": false},
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
const resolver_mod = @import("resolver.zig");
const Resolver = resolver_mod.Resolver;

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

/// Maximum iterations for route generation loop.
const MAX_ROUTE_ITERATIONS: u32 = @as(u32, MAX_ROUTES) * @as(u32, gw_config.MAX_RULES) * @as(u32, gw_config.MAX_MATCHES);

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
/// Resolves backend references to pod IPs using the provided resolver.
/// Output format matches POST /routes/update expected JSON.
///
/// Arguments:
///   config: Gateway API configuration (HTTPRoutes).
///   resolver: Resolver with Service -> Endpoints mappings.
///   out_buf: Output buffer for JSON (must be at least MAX_JSON_SIZE_BYTES bytes).
///
/// Returns:
///   Number of bytes written to out_buf.
///
/// TigerStyle: Bounded loops, explicit error handling, no allocation.
pub fn translateToJson(
    config_ptr: *const gw_config.GatewayConfig,
    resolver: *const Resolver,
    out_buf: *[MAX_JSON_SIZE_BYTES]u8,
) TranslatorError!usize {
    // S1: Preconditions
    assert(out_buf.len >= MAX_JSON_SIZE_BYTES);

    var writer = JsonWriter.init(out_buf);

    // Start root object
    writer.writeRaw("{") catch return error.BufferTooSmall;

    // Write routes array
    writer.writeRaw("\"routes\":[") catch return error.BufferTooSmall;
    var route_count: u8 = 0;
    var default_route_written = false;

    // Process each HTTPRoute
    for (config_ptr.http_routes, 0..) |http_route, route_i| {
        // S3: Bounded loop check
        if (route_i >= gw_config.MAX_HTTP_ROUTES) break;

        // Get host from first hostname if available
        const host: ?[]const u8 = if (http_route.hostnames.len > 0) http_route.hostnames[0] else null;

        // Process each rule
        for (http_route.rules, 0..) |rule, rule_i| {
            // S3: Bounded loop check
            if (rule_i >= gw_config.MAX_RULES) break;

            // Calculate pool index for this rule's backends
            const pool_idx = route_count;
            if (pool_idx >= MAX_POOLS) {
                return error.TooManyPools;
            }

            // Check if rule has URLRewrite filter for strip_prefix
            const strip_prefix = hasUrlRewriteFilter(rule.filters);

            // Process each match in the rule
            if (rule.matches.len == 0) {
                // No matches means catch-all route
                if (route_count > 0) {
                    writer.writeRaw(",") catch return error.BufferTooSmall;
                }
                try writeRoute(&writer, http_route.name, host, "/", pool_idx, false);
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

                    const path_value = if (match.path) |p| p.value else "/";
                    try writeRoute(&writer, http_route.name, host, path_value, pool_idx, strip_prefix);
                    route_count += 1;
                }
            }
        }
    }

    writer.writeRaw("],") catch return error.BufferTooSmall;

    // Write default_route (first pool or empty catch-all)
    writer.writeRaw("\"default_route\":") catch return error.BufferTooSmall;
    if (route_count > 0) {
        try writeRoute(&writer, "default", null, "/", 0, false);
        default_route_written = true;
    } else {
        // Empty config - write minimal default route
        try writeRoute(&writer, "default", null, "/", 0, false);
        default_route_written = true;
    }

    writer.writeRaw(",") catch return error.BufferTooSmall;

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

            try writePool(&writer, http_route.name, rule.backend_refs, resolver, pool_count);
            pool_count += 1;
        }
    }

    writer.writeRaw("]") catch return error.BufferTooSmall;

    // Close root object
    writer.writeRaw("}") catch return error.BufferTooSmall;

    const written = writer.pos;

    // S2: Postconditions
    assert(written <= MAX_JSON_SIZE_BYTES);
    assert(default_route_written);

    return written;
}

/// Check if any filter has a URL rewrite path configured.
fn hasUrlRewriteFilter(filters: []const gw_config.HTTPRouteFilter) bool {
    for (filters) |filter| {
        if (filter.type == .URLRewrite) {
            if (filter.url_rewrite) |rewrite| {
                if (rewrite.path != null) {
                    return true;
                }
            }
        }
    }
    return false;
}

/// Write a single route object to JSON.
fn writeRoute(
    writer: *JsonWriter,
    name: []const u8,
    host: ?[]const u8,
    path_prefix: []const u8,
    pool_idx: u8,
    strip_prefix: bool,
) TranslatorError!void {
    // S1: Preconditions
    assert(name.len > 0);
    assert(path_prefix.len > 0);
    assert(pool_idx < MAX_POOLS);

    writer.writeRaw("{") catch return error.BufferTooSmall;
    writer.writeRaw("\"name\":\"") catch return error.BufferTooSmall;
    writer.writeRaw(name) catch return error.BufferTooSmall;
    writer.writeRaw("\",") catch return error.BufferTooSmall;

    if (host) |h| {
        writer.writeRaw("\"host\":\"") catch return error.BufferTooSmall;
        writer.writeRaw(h) catch return error.BufferTooSmall;
        writer.writeRaw("\",") catch return error.BufferTooSmall;
    }

    writer.writeRaw("\"path_prefix\":\"") catch return error.BufferTooSmall;
    writer.writeRaw(path_prefix) catch return error.BufferTooSmall;
    writer.writeRaw("\",") catch return error.BufferTooSmall;

    writer.writeRaw("\"pool_idx\":") catch return error.BufferTooSmall;
    var idx_buf: [4]u8 = undefined;
    const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{pool_idx}) catch return error.BufferTooSmall;
    writer.writeRaw(idx_str) catch return error.BufferTooSmall;
    writer.writeRaw(",") catch return error.BufferTooSmall;

    writer.writeRaw("\"strip_prefix\":") catch return error.BufferTooSmall;
    writer.writeRaw(if (strip_prefix) "true" else "false") catch return error.BufferTooSmall;

    writer.writeRaw("}") catch return error.BufferTooSmall;
}

/// Write a single pool object to JSON with resolved upstreams.
fn writePool(
    writer: *JsonWriter,
    name: []const u8,
    backend_refs: []const gw_config.BackendRef,
    resolver: *const Resolver,
    pool_idx: u8,
) TranslatorError!void {
    // S1: Preconditions
    assert(name.len > 0);
    assert(pool_idx < MAX_POOLS);

    writer.writeRaw("{") catch return error.BufferTooSmall;
    writer.writeRaw("\"name\":\"") catch return error.BufferTooSmall;
    writer.writeRaw(name) catch return error.BufferTooSmall;
    writer.writeRaw("-pool\",") catch return error.BufferTooSmall;

    writer.writeRaw("\"upstreams\":[") catch return error.BufferTooSmall;

    var upstream_count: u8 = 0;
    const global_upstream_idx: u8 = pool_idx * MAX_UPSTREAMS_PER_POOL;

    for (backend_refs, 0..) |backend_ref, ref_i| {
        // S3: Bounded loop check
        if (ref_i >= gw_config.MAX_BACKEND_REFS) break;

        // Resolve backend ref to endpoints
        var endpoints: [resolver_mod.MAX_ENDPOINTS_PER_SERVICE]gw_config.ResolvedEndpoint = undefined;
        const ep_count = resolver.getServiceEndpoints(
            backend_ref.name,
            backend_ref.namespace,
            &endpoints,
        );

        // Write each endpoint as an upstream
        for (endpoints[0..ep_count], 0..) |ep, ep_i| {
            // S3: Bounded loop check
            if (ep_i >= resolver_mod.MAX_ENDPOINTS_PER_SERVICE) break;

            if (upstream_count >= MAX_UPSTREAMS_PER_POOL) {
                return error.TooManyUpstreams;
            }

            if (upstream_count > 0) {
                writer.writeRaw(",") catch return error.BufferTooSmall;
            }

            try writeUpstream(writer, ep.address, backend_ref.port, global_upstream_idx + upstream_count);
            upstream_count += 1;
        }
    }

    writer.writeRaw("]") catch return error.BufferTooSmall;

    // Add lb_config with full probing configuration
    writer.writeRaw(",\"lb_config\":{") catch return error.BufferTooSmall;
    writer.writeRaw("\"enable_probing\":true,") catch return error.BufferTooSmall;
    writer.writeRaw("\"probe_interval_ms\":5000,") catch return error.BufferTooSmall;
    writer.writeRaw("\"health_path\":\"/\"") catch return error.BufferTooSmall;
    writer.writeRaw("}") catch return error.BufferTooSmall;

    writer.writeRaw("}") catch return error.BufferTooSmall;
}

/// Write a single upstream object to JSON.
fn writeUpstream(
    writer: *JsonWriter,
    host: []const u8,
    port: u16,
    idx: u8,
) TranslatorError!void {
    // S1: Preconditions
    assert(host.len > 0);
    assert(port > 0);

    writer.writeRaw("{") catch return error.BufferTooSmall;
    writer.writeRaw("\"host\":\"") catch return error.BufferTooSmall;
    writer.writeRaw(host) catch return error.BufferTooSmall;
    writer.writeRaw("\",") catch return error.BufferTooSmall;

    writer.writeRaw("\"port\":") catch return error.BufferTooSmall;
    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch return error.BufferTooSmall;
    writer.writeRaw(port_str) catch return error.BufferTooSmall;
    writer.writeRaw(",") catch return error.BufferTooSmall;

    writer.writeRaw("\"idx\":") catch return error.BufferTooSmall;
    var idx_buf: [4]u8 = undefined;
    const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{idx}) catch return error.BufferTooSmall;
    writer.writeRaw(idx_str) catch return error.BufferTooSmall;
    writer.writeRaw(",") catch return error.BufferTooSmall;

    writer.writeRaw("\"tls\":false") catch return error.BufferTooSmall;

    writer.writeRaw("}") catch return error.BufferTooSmall;
}

// ============================================================================
// JSON Writer Helper
// ============================================================================

/// Simple bounded JSON writer.
/// TigerStyle: No allocation, fixed buffer, explicit error on overflow.
const JsonWriter = struct {
    buf: []u8,
    /// Current write position. TigerStyle S2: u32 matches MAX_JSON_SIZE_BYTES bound.
    pos: u32,

    const Self = @This();

    fn init(buf: *[MAX_JSON_SIZE_BYTES]u8) Self {
        // S1: Precondition - buffer is valid and sized
        assert(buf.len == MAX_JSON_SIZE_BYTES);

        return Self{
            .buf = buf,
            .pos = 0,
        };
    }

    fn writeRaw(self: *Self, data: []const u8) !void {
        // S1: Precondition - data within reasonable bounds
        assert(data.len <= MAX_JSON_SIZE_BYTES);

        const data_len: u32 = @intCast(data.len);
        if (self.pos + data_len > MAX_JSON_SIZE_BYTES) {
            return error.BufferTooSmall;
        }
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data_len;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "translateToJson empty config" {
    const config_data = gw_config.GatewayConfig{
        .gateways = &.{},
        .http_routes = &.{},
    };

    var resolver = Resolver.init();
    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;

    const len = try translateToJson(&config_data, &resolver, &out_buf);

    try std.testing.expect(len > 0);

    // Should have valid JSON structure
    const json = out_buf[0..len];
    try std.testing.expect(std.mem.indexOf(u8, json, "\"routes\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"default_route\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"pools\":[]") != null);
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

    // Set up resolver with service endpoints
    var resolver = Resolver.init();
    const endpoints_json =
        \\{
        \\  "subsets": [{
        \\    "addresses": [{ "ip": "10.0.1.1" }, { "ip": "10.0.1.2" }],
        \\    "ports": [{ "port": 8080 }]
        \\  }]
        \\}
    ;
    try resolver.updateService("api-svc", "default", endpoints_json);

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolver, &out_buf);

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

    var resolver = Resolver.init();
    const endpoints_json =
        \\{
        \\  "subsets": [{
        \\    "addresses": [{ "ip": "10.0.1.1" }],
        \\    "ports": [{ "port": 8080 }]
        \\  }]
        \\}
    ;
    try resolver.updateService("api-svc", "default", endpoints_json);

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolver, &out_buf);

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

    var resolver = Resolver.init();
    const endpoints_json =
        \\{
        \\  "subsets": [{
        \\    "addresses": [{ "ip": "10.0.1.1" }],
        \\    "ports": [{ "port": 8080 }]
        \\  }]
        \\}
    ;
    try resolver.updateService("api-svc", "default", endpoints_json);

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolver, &out_buf);

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

    var resolver = Resolver.init();
    const endpoints_json =
        \\{
        \\  "subsets": [{
        \\    "addresses": [{ "ip": "10.0.1.5" }],
        \\    "ports": [{ "port": 8080 }]
        \\  }]
        \\}
    ;
    try resolver.updateService("api-svc", "default", endpoints_json);

    var out_buf: [MAX_JSON_SIZE_BYTES]u8 = undefined;
    const len = try translateToJson(&config_data, &resolver, &out_buf);

    const json = out_buf[0..len];

    // Verify lb_config structure
    try std.testing.expect(std.mem.indexOf(u8, json, "\"lb_config\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"enable_probing\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"probe_interval_ms\":5000") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"health_path\":\"/\"") != null);
}
