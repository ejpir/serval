//! EndpointSlice Types and Discovery
//!
//! Kubernetes EndpointSlice API types and discovery functions for
//! multi-instance config push. EndpointSlices provide the pod IPs
//! for a service, enabling config push to all router replicas.
//!
//! TigerStyle: Bounded arrays, explicit errors, no allocation after init.

const std = @import("std");
const log = @import("serval-core").log.scoped(.gateway_k8s_client);
const assert = std.debug.assert;
const Io = std.Io;

const k8s_client_mod = @import("mod.zig");
const Client = k8s_client_mod.Client;
const ClientError = k8s_client_mod.ClientError;

// ============================================================================
// Constants (TigerStyle Y3: Units in names, explicit bounds)
// ============================================================================

/// Maximum number of router endpoints to discover.
/// TigerStyle: Explicit bound (typical K8s deployments have < 32 replicas).
pub const MAX_ROUTER_ENDPOINTS: u8 = 32;

/// Maximum IP address length (IPv4 = 15, IPv6 = 45 with scope).
pub const MAX_IP_LEN: u8 = 45;

/// Maximum pod name length (K8s DNS label limit).
pub const MAX_POD_NAME_LEN: u8 = 63;

/// Maximum namespace length (K8s DNS label limit).
pub const MAX_NAMESPACE_LEN: u8 = 63;

/// Maximum service name length (K8s DNS label limit).
pub const MAX_SERVICE_NAME_LEN: u8 = 63;

/// Maximum URL buffer size for EndpointSlice list requests.
const MAX_URL_SIZE: u32 = 512;

/// Maximum JSON response buffer size (reuses K8s client buffer).
/// EndpointSlice list responses are typically < 64KB even with 32 replicas.
const MAX_RESPONSE_BUFFER_SIZE: u32 = 128 * 1024;

// ============================================================================
// Error Types (TigerStyle S6: Explicit error set)
// ============================================================================

pub const EndpointSliceError = error{
    /// K8s API request failed.
    RequestFailed,
    /// JSON parsing failed.
    ParseFailed,
    /// No endpoints found in EndpointSlice.
    NoEndpointsFound,
    /// Endpoint buffer overflow.
    BufferOverflow,
    /// Port not found in EndpointSlice.
    PortNotFound,
    /// Invalid endpoint data.
    InvalidEndpoint,
    /// URL construction failed.
    UrlTooLarge,
};

// ============================================================================
// Types (TigerStyle: Fixed-size storage, no allocation)
// ============================================================================

/// A single router endpoint (pod IP and admin port).
/// TigerStyle: Fixed-size buffer, no allocation needed.
pub const RouterEndpoint = struct {
    /// IP address storage (IPv4 or IPv6).
    ip: [MAX_IP_LEN]u8,
    ip_len: u8,

    /// Pod name for identity tracking (changes on pod restart).
    pod_name: [MAX_POD_NAME_LEN]u8,
    pod_name_len: u8,

    /// Admin port number.
    port: u16,

    /// Whether this endpoint is ready to receive traffic.
    ready: bool,

    /// Get IP as slice.
    ///
    /// TigerStyle S1: Precondition - ip_len within bounds.
    pub fn getIp(self: *const RouterEndpoint) []const u8 {
        assert(self.ip_len <= MAX_IP_LEN); // S1: precondition
        return self.ip[0..self.ip_len];
    }

    /// Get pod name as slice.
    ///
    /// TigerStyle S1: Precondition - pod_name_len within bounds.
    pub fn getPodName(self: *const RouterEndpoint) []const u8 {
        assert(self.pod_name_len <= MAX_POD_NAME_LEN); // S1: precondition
        return self.pod_name[0..self.pod_name_len];
    }

    /// Initialize an empty endpoint.
    pub fn init() RouterEndpoint {
        return RouterEndpoint{
            .ip = undefined,
            .ip_len = 0,
            .pod_name = undefined,
            .pod_name_len = 0,
            .port = 0,
            .ready = false,
        };
    }

    /// Set IP address from slice.
    ///
    /// TigerStyle S1: Precondition - ip fits in buffer.
    pub fn setIp(self: *RouterEndpoint, ip: []const u8) void {
        assert(ip.len <= MAX_IP_LEN); // S1: precondition
        @memcpy(self.ip[0..ip.len], ip);
        self.ip_len = @intCast(ip.len);
    }

    /// Set pod name from slice.
    ///
    /// TigerStyle S1: Precondition - name fits in buffer.
    pub fn setPodName(self: *RouterEndpoint, name: []const u8) void {
        assert(name.len <= MAX_POD_NAME_LEN); // S1: precondition
        @memcpy(self.pod_name[0..name.len], name);
        self.pod_name_len = @intCast(name.len);
    }
};

/// Collection of discovered router endpoints.
/// TigerStyle: Fixed-size array, explicit count.
pub const RouterEndpoints = struct {
    /// Endpoint storage.
    endpoints: [MAX_ROUTER_ENDPOINTS]RouterEndpoint,

    /// Number of valid endpoints.
    count: u8,

    /// Initialize empty collection.
    pub fn init() RouterEndpoints {
        var self = RouterEndpoints{
            .endpoints = undefined,
            .count = 0,
        };
        var idx: u8 = 0;
        while (idx < MAX_ROUTER_ENDPOINTS) : (idx += 1) {
            self.endpoints[idx] = RouterEndpoint.init();
        }
        return self;
    }

    /// Get endpoints as slice.
    ///
    /// TigerStyle S1: Postcondition - slice length matches count.
    pub fn slice(self: *const RouterEndpoints) []const RouterEndpoint {
        assert(self.count <= MAX_ROUTER_ENDPOINTS); // S1: precondition
        return self.endpoints[0..self.count];
    }

    /// Get only ready endpoints as iterator.
    ///
    /// Returns count of ready endpoints in output buffer.
    /// TigerStyle S3: Bounded loop.
    pub fn getReady(
        self: *const RouterEndpoints,
        out: []RouterEndpoint,
    ) u8 {
        assert(self.count <= MAX_ROUTER_ENDPOINTS); // S1: precondition

        var ready_count: u8 = 0;
        var idx: u8 = 0;
        while (idx < self.count and ready_count < out.len) : (idx += 1) {
            if (self.endpoints[idx].ready) {
                out[ready_count] = self.endpoints[idx];
                ready_count += 1;
            }
        }
        return ready_count;
    }
};

// ============================================================================
// EndpointSlice Discovery (TigerStyle: Uses K8s client, explicit errors)
// ============================================================================

/// Discover router endpoints by listing EndpointSlices for the router service.
///
/// Queries:
/// GET /apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices?labelSelector=kubernetes.io/service-name={service_name}
///
/// TigerStyle S1: ~2 assertions per function.
/// TigerStyle S3: Bounded loops with explicit limits.
///
/// Parameters:
/// - k8s: K8s API client (borrowed reference)
/// - namespace: Namespace where router service lives (e.g., "serval-system")
/// - service_name: Router service name (e.g., "serval-router-admin")
/// - admin_port: Admin port to look for in EndpointSlice ports array
/// - io: Io runtime for async operations
///
/// Returns discovered endpoints or error.
pub fn discoverRouterEndpoints(
    k8s: *Client,
    namespace: []const u8,
    service_name: []const u8,
    admin_port: u16,
    io: Io,
) EndpointSliceError!RouterEndpoints {
    // S1: Preconditions
    assert(namespace.len > 0 and namespace.len <= MAX_NAMESPACE_LEN);
    assert(service_name.len > 0 and service_name.len <= MAX_SERVICE_NAME_LEN);
    assert(admin_port > 0);

    // Build list URL with label selector
    var url_buf: [MAX_URL_SIZE]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "/apis/discovery.k8s.io/v1/namespaces/{s}/endpointslices?labelSelector=kubernetes.io/service-name={s}", .{
        namespace,
        service_name,
    }) catch {
        return EndpointSliceError.UrlTooLarge;
    };

    log.debug("endpoint_slice: GET {s}", .{url});

    // Make K8s API request
    const response_json = k8s.get(url, io) catch |err| {
        log.err("endpoint_slice: K8s API request failed: {s}", .{@errorName(err)});
        return EndpointSliceError.RequestFailed;
    };

    log.debug("endpoint_slice: got response len={d}", .{response_json.len});

    // Parse EndpointSlice list response
    const endpoints = parseEndpointSliceList(response_json, admin_port) catch |err| {
        log.err("endpoint_slice: parse failed: {s}", .{@errorName(err)});
        return err;
    };

    log.info("endpoint_slice: discovered {d} endpoints", .{endpoints.count});
    return endpoints;
}

/// Parse EndpointSlice list JSON response.
///
/// Expected format (simplified):
/// ```json
/// {
///   "items": [{
///     "endpoints": [{
///       "addresses": ["10.42.0.5"],
///       "conditions": { "ready": true }
///     }],
///     "ports": [{ "port": 9901, "name": "admin" }]
///   }]
/// }
/// ```
///
/// TigerStyle S1: Assertions for pre/postconditions.
/// TigerStyle S3: Bounded loops with MAX_* limits.
fn parseEndpointSliceList(
    json_data: []const u8,
    target_port: u16,
) EndpointSliceError!RouterEndpoints {
    // S1: Precondition
    assert(json_data.len > 0);
    assert(target_port > 0);

    var result = RouterEndpoints.init();

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, json_data, .{}) catch {
        log.err("endpoint_slice: JSON parse failed", .{});
        return EndpointSliceError.ParseFailed;
    };
    defer parsed.deinit();

    const root = parsed.value;

    // Get items array
    const items = root.object.get("items") orelse {
        log.debug("endpoint_slice: no 'items' field in response", .{});
        return EndpointSliceError.NoEndpointsFound;
    };

    if (items != .array) {
        log.debug("endpoint_slice: 'items' is not an array", .{});
        return EndpointSliceError.ParseFailed;
    }

    // Iterate EndpointSlices (TigerStyle S3: bounded)
    const max_slices: u32 = 16;
    var slice_idx: u32 = 0;
    for (items.array.items) |slice_item| {
        if (slice_idx >= max_slices) break;
        slice_idx += 1;

        if (slice_item != .object) continue;

        // Find matching port in this EndpointSlice
        const port_matches = findMatchingPort(slice_item.object, target_port);
        if (!port_matches) continue;

        // Parse endpoints from this slice
        parseEndpointsFromSlice(slice_item.object, target_port, &result) catch |err| {
            log.debug("endpoint_slice: parseEndpointsFromSlice failed: {s}", .{@errorName(err)});
            continue;
        };
    }

    // S1: Postcondition
    assert(result.count <= MAX_ROUTER_ENDPOINTS);

    log.info("endpoint_slice: discovered {d} router endpoints", .{result.count});

    if (result.count == 0) {
        return EndpointSliceError.NoEndpointsFound;
    }

    return result;
}

/// Check if an EndpointSlice has a port matching target_port.
///
/// TigerStyle S3: Bounded loop.
fn findMatchingPort(slice_obj: std.json.ObjectMap, target_port: u16) bool {
    const ports = slice_obj.get("ports") orelse return false;
    if (ports != .array) return false;

    const max_ports: u32 = 8;
    var port_idx: u32 = 0;
    for (ports.array.items) |port_item| {
        if (port_idx >= max_ports) break;
        port_idx += 1;

        if (port_item != .object) continue;

        const port_val = port_item.object.get("port") orelse continue;
        if (port_val != .integer) continue;

        if (port_val.integer == target_port) {
            return true;
        }
    }

    return false;
}

/// Parse endpoints from a single EndpointSlice object.
///
/// TigerStyle S3: Bounded loops with MAX_* limits.
fn parseEndpointsFromSlice(
    slice_obj: std.json.ObjectMap,
    target_port: u16,
    result: *RouterEndpoints,
) EndpointSliceError!void {
    const endpoints = slice_obj.get("endpoints") orelse {
        return EndpointSliceError.NoEndpointsFound;
    };

    if (endpoints != .array) {
        return EndpointSliceError.ParseFailed;
    }

    // Iterate endpoints (TigerStyle S3: bounded)
    const max_endpoints_per_slice: u32 = 64;
    var ep_idx: u32 = 0;
    for (endpoints.array.items) |endpoint_item| {
        if (ep_idx >= max_endpoints_per_slice) break;
        ep_idx += 1;

        if (result.count >= MAX_ROUTER_ENDPOINTS) {
            return EndpointSliceError.BufferOverflow;
        }

        if (endpoint_item != .object) continue;

        // Check if endpoint is ready
        const ready = checkEndpointReady(endpoint_item.object);

        // Get pod name from targetRef
        const pod_name = getPodName(endpoint_item.object);

        // Get addresses array
        const addresses = endpoint_item.object.get("addresses") orelse continue;
        if (addresses != .array) continue;

        // Parse each address (TigerStyle S3: bounded)
        const max_addresses: u32 = 8;
        var addr_idx: u32 = 0;
        for (addresses.array.items) |addr_item| {
            if (addr_idx >= max_addresses) break;
            addr_idx += 1;

            if (result.count >= MAX_ROUTER_ENDPOINTS) {
                return EndpointSliceError.BufferOverflow;
            }

            if (addr_item != .string) continue;
            const ip_str = addr_item.string;

            if (ip_str.len > MAX_IP_LEN) {
                log.warn("endpoint_slice: IP too long: {d} chars", .{ip_str.len});
                continue;
            }

            // Add endpoint to result
            var endpoint = &result.endpoints[result.count];
            endpoint.setIp(ip_str);
            if (pod_name) |name| {
                endpoint.setPodName(name);
            }
            endpoint.port = target_port;
            endpoint.ready = ready;
            result.count += 1;

            log.debug("endpoint_slice: found endpoint {s}:{d} pod={s} ready={}", .{
                ip_str,
                target_port,
                if (pod_name) |n| n else "<unknown>",
                ready,
            });
        }
    }
}

/// Get pod name from endpoint's targetRef.
///
/// Returns null if targetRef or name is missing.
fn getPodName(endpoint_obj: std.json.ObjectMap) ?[]const u8 {
    const target_ref = endpoint_obj.get("targetRef") orelse return null;
    if (target_ref != .object) return null;

    const name = target_ref.object.get("name") orelse return null;
    if (name != .string) return null;

    if (name.string.len > MAX_POD_NAME_LEN) {
        log.warn("endpoint_slice: pod name too long: {d} chars", .{name.string.len});
        return null;
    }

    return name.string;
}

/// Check if an endpoint is ready based on conditions.
///
/// Returns true if conditions.ready is true or not present (default ready).
fn checkEndpointReady(endpoint_obj: std.json.ObjectMap) bool {
    const conditions = endpoint_obj.get("conditions") orelse return true;
    if (conditions != .object) return true;

    const ready = conditions.object.get("ready") orelse return true;
    if (ready != .bool) return true;

    return ready.bool;
}

// ============================================================================
// Unit Tests
// ============================================================================

test "RouterEndpoint init and setIp" {
    var ep = RouterEndpoint.init();
    try std.testing.expectEqual(@as(u8, 0), ep.ip_len);
    try std.testing.expectEqual(false, ep.ready);

    ep.setIp("10.42.0.5");
    try std.testing.expectEqual(@as(u8, 9), ep.ip_len);
    try std.testing.expectEqualStrings("10.42.0.5", ep.getIp());

    ep.port = 9901;
    ep.ready = true;
    try std.testing.expectEqual(@as(u16, 9901), ep.port);
    try std.testing.expect(ep.ready);
}

test "RouterEndpoints init and count" {
    const endpoints = RouterEndpoints.init();
    try std.testing.expectEqual(@as(u8, 0), endpoints.count);
    try std.testing.expectEqual(@as(usize, 0), endpoints.slice().len);
}

test "RouterEndpoints getReady filters" {
    var endpoints = RouterEndpoints.init();

    // Add 3 endpoints: 2 ready, 1 not ready
    endpoints.endpoints[0].setIp("10.0.0.1");
    endpoints.endpoints[0].port = 9901;
    endpoints.endpoints[0].ready = true;

    endpoints.endpoints[1].setIp("10.0.0.2");
    endpoints.endpoints[1].port = 9901;
    endpoints.endpoints[1].ready = false;

    endpoints.endpoints[2].setIp("10.0.0.3");
    endpoints.endpoints[2].port = 9901;
    endpoints.endpoints[2].ready = true;

    endpoints.count = 3;

    var ready_buf: [MAX_ROUTER_ENDPOINTS]RouterEndpoint = undefined;
    const ready_count = endpoints.getReady(&ready_buf);

    try std.testing.expectEqual(@as(u8, 2), ready_count);
    try std.testing.expectEqualStrings("10.0.0.1", ready_buf[0].getIp());
    try std.testing.expectEqualStrings("10.0.0.3", ready_buf[1].getIp());
}

test "parseEndpointSliceList basic" {
    const json =
        \\{
        \\  "items": [{
        \\    "endpoints": [{
        \\      "addresses": ["10.42.0.5"],
        \\      "conditions": { "ready": true }
        \\    }],
        \\    "ports": [{ "port": 9901, "name": "admin" }]
        \\  }]
        \\}
    ;

    const result = try parseEndpointSliceList(json, 9901);

    try std.testing.expectEqual(@as(u8, 1), result.count);
    try std.testing.expectEqualStrings("10.42.0.5", result.endpoints[0].getIp());
    try std.testing.expectEqual(@as(u16, 9901), result.endpoints[0].port);
    try std.testing.expect(result.endpoints[0].ready);
}

test "parseEndpointSliceList multiple endpoints" {
    const json =
        \\{
        \\  "items": [{
        \\    "endpoints": [
        \\      {
        \\        "addresses": ["10.42.0.5", "10.42.0.6"],
        \\        "conditions": { "ready": true }
        \\      },
        \\      {
        \\        "addresses": ["10.42.0.7"],
        \\        "conditions": { "ready": false }
        \\      }
        \\    ],
        \\    "ports": [{ "port": 9901 }]
        \\  }]
        \\}
    ;

    const result = try parseEndpointSliceList(json, 9901);

    try std.testing.expectEqual(@as(u8, 3), result.count);

    // First 2 are ready
    try std.testing.expect(result.endpoints[0].ready);
    try std.testing.expect(result.endpoints[1].ready);
    // Third is not ready
    try std.testing.expect(!result.endpoints[2].ready);
}

test "parseEndpointSliceList wrong port" {
    const json =
        \\{
        \\  "items": [{
        \\    "endpoints": [{
        \\      "addresses": ["10.42.0.5"]
        \\    }],
        \\    "ports": [{ "port": 8080 }]
        \\  }]
        \\}
    ;

    const result = parseEndpointSliceList(json, 9901);
    try std.testing.expectError(EndpointSliceError.NoEndpointsFound, result);
}

test "parseEndpointSliceList empty items" {
    const json =
        \\{
        \\  "items": []
        \\}
    ;

    const result = parseEndpointSliceList(json, 9901);
    try std.testing.expectError(EndpointSliceError.NoEndpointsFound, result);
}

test "parseEndpointSliceList multiple slices" {
    const json =
        \\{
        \\  "items": [
        \\    {
        \\      "endpoints": [{
        \\        "addresses": ["10.42.0.1"]
        \\      }],
        \\      "ports": [{ "port": 9901 }]
        \\    },
        \\    {
        \\      "endpoints": [{
        \\        "addresses": ["10.42.0.2"]
        \\      }],
        \\      "ports": [{ "port": 9901 }]
        \\    }
        \\  ]
        \\}
    ;

    const result = try parseEndpointSliceList(json, 9901);

    try std.testing.expectEqual(@as(u8, 2), result.count);
    try std.testing.expectEqualStrings("10.42.0.1", result.endpoints[0].getIp());
    try std.testing.expectEqualStrings("10.42.0.2", result.endpoints[1].getIp());
}

test "Constants are within bounds" {
    comptime {
        assert(MAX_ROUTER_ENDPOINTS <= 255);
        assert(MAX_IP_LEN <= 255);
        assert(MAX_NAMESPACE_LEN <= 255);
        assert(MAX_SERVICE_NAME_LEN <= 255);
    }
}
