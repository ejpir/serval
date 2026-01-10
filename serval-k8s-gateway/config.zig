//! Gateway API Configuration Types
//!
//! Zig structs mirroring Kubernetes Gateway API resources.
//! Used for JSON parsing of K8s watch events.
//!
//! These types represent the core Gateway API resources:
//! - Gateway: Defines listeners (ports/protocols) for accepting traffic
//! - HTTPRoute: Defines routing rules matching requests to backends
//! - BackendRef: References to upstream services
//!
//! TigerStyle: Fixed-size types, explicit bounds, no allocation after init.
//! All slices are bounded by MAX_* constants when stored in runtime structures.

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Bounded Array Limits (TigerStyle: explicit bounds, no unbounded growth)
// ============================================================================

/// Maximum number of Gateway resources per configuration.
pub const MAX_GATEWAYS: u8 = 16;

/// Maximum number of listeners per Gateway.
pub const MAX_LISTENERS: u8 = 16;

/// Maximum number of HTTPRoute resources per configuration.
pub const MAX_HTTP_ROUTES: u8 = 128;

/// Maximum number of rules per HTTPRoute.
pub const MAX_RULES: u8 = 32;

/// Maximum number of matches per rule.
pub const MAX_MATCHES: u8 = 8;

/// Maximum number of filters per rule.
pub const MAX_FILTERS: u8 = 8;

/// Maximum number of backend references per rule.
pub const MAX_BACKEND_REFS: u8 = 16;

/// Maximum number of hostnames per HTTPRoute.
pub const MAX_HOSTNAMES: u8 = 16;

/// Maximum number of certificate references per TLS config.
pub const MAX_CERTIFICATE_REFS: u8 = 4;

/// Maximum name length for K8s resources (names are max 63 chars).
pub const MAX_NAME_LEN: u8 = 63;

/// Maximum endpoints per resolved backend.
/// TigerStyle: Explicit bound matching resolver limits.
pub const MAX_RESOLVED_ENDPOINTS: u8 = 64;

/// Maximum resolved backends in a translation batch.
/// TigerStyle: Matches MAX_HTTP_ROUTES * MAX_RULES for worst case.
pub const MAX_RESOLVED_BACKENDS: u16 = 256;

/// Maximum number of GatewayClass resources.
/// TigerStyle: Explicit bound, typically 1-2 per cluster.
pub const MAX_GATEWAY_CLASSES: u8 = 8;

/// Maximum JSON size for status updates.
/// TigerStyle: Explicit bound for buffer allocation.
pub const MAX_STATUS_JSON_SIZE: u32 = 4096;

/// Maximum conditions per status object.
/// TigerStyle: Gateway API typically has 2-3 conditions per resource.
pub const MAX_CONDITIONS: u8 = 8;

/// Maximum length for condition reason field.
/// TigerStyle: K8s convention is short CamelCase reasons.
pub const MAX_REASON_LEN: u8 = 64;

/// Maximum length for condition message field.
/// TigerStyle: Human-readable message with context.
pub const MAX_MESSAGE_LEN: u16 = 256;

// ============================================================================
// Top-Level Configuration
// ============================================================================

/// Complete Gateway API configuration snapshot.
/// Represents the desired state from Kubernetes watch events.
pub const GatewayConfig = struct {
    gateways: []const Gateway,
    http_routes: []const HTTPRoute,
};

// ============================================================================
// Gateway Resource
// ============================================================================

/// Gateway defines listeners for accepting traffic.
/// Maps to gateway.networking.k8s.io/Gateway.
pub const Gateway = struct {
    /// Resource name (metadata.name).
    name: []const u8,
    /// Resource namespace (metadata.namespace).
    namespace: []const u8,
    /// Listeners define ports and protocols.
    listeners: []const Listener,
};

// ============================================================================
// GatewayClass Resource
// ============================================================================

/// GatewayClass defines a class of Gateways managed by a controller.
/// Maps to gateway.networking.k8s.io/GatewayClass.
/// Cluster-scoped resource (no namespace).
pub const GatewayClass = struct {
    /// Resource name (metadata.name).
    name: []const u8,
    /// Controller that manages this class (spec.controllerName).
    controller_name: []const u8,
};

/// Listener defines a port and protocol for accepting connections.
pub const Listener = struct {
    /// Listener name (unique within Gateway).
    name: []const u8,
    /// Port number to listen on (1-65535).
    port: u16,
    /// Protocol for this listener.
    protocol: Protocol,
    /// Optional hostname filter (SNI for TLS, Host header for HTTP).
    hostname: ?[]const u8 = null,
    /// TLS configuration (required if protocol is HTTPS).
    tls: ?TLSConfig = null,

    pub const Protocol = enum {
        HTTP,
        HTTPS,

        /// Parse protocol from string (case-insensitive).
        pub fn fromString(s: []const u8) ?Protocol {
            if (std.ascii.eqlIgnoreCase(s, "HTTP")) return .HTTP;
            if (std.ascii.eqlIgnoreCase(s, "HTTPS")) return .HTTPS;
            return null;
        }

        /// Convert to string for serialization.
        pub fn toString(self: Protocol) []const u8 {
            return switch (self) {
                .HTTP => "HTTP",
                .HTTPS => "HTTPS",
            };
        }
    };
};

/// TLS configuration for HTTPS listeners.
pub const TLSConfig = struct {
    /// TLS termination mode.
    mode: Mode,
    /// References to TLS certificates (Secrets).
    certificate_refs: []const CertificateRef,

    pub const Mode = enum {
        /// Terminate TLS at the gateway, forward plaintext to backends.
        Terminate,
        /// Pass TLS connections through to backends unchanged.
        Passthrough,

        /// Parse mode from string (case-insensitive).
        pub fn fromString(s: []const u8) ?Mode {
            if (std.ascii.eqlIgnoreCase(s, "Terminate")) return .Terminate;
            if (std.ascii.eqlIgnoreCase(s, "Passthrough")) return .Passthrough;
            return null;
        }

        /// Convert to string for serialization.
        pub fn toString(self: Mode) []const u8 {
            return switch (self) {
                .Terminate => "Terminate",
                .Passthrough => "Passthrough",
            };
        }
    };
};

/// Reference to a TLS certificate Secret.
pub const CertificateRef = struct {
    /// Secret name containing tls.crt and tls.key.
    name: []const u8,
    /// Secret namespace.
    namespace: []const u8,
};

// ============================================================================
// HTTPRoute Resource
// ============================================================================

/// HTTPRoute defines routing rules for HTTP traffic.
/// Maps to gateway.networking.k8s.io/HTTPRoute.
pub const HTTPRoute = struct {
    /// Resource name (metadata.name).
    name: []const u8,
    /// Resource namespace (metadata.namespace).
    namespace: []const u8,
    /// Hostnames this route matches (empty matches all).
    hostnames: []const []const u8,
    /// Routing rules evaluated in order.
    rules: []const HTTPRouteRule,
};

/// HTTPRouteRule defines a single routing rule.
pub const HTTPRouteRule = struct {
    /// Match conditions (OR'd together).
    matches: []const HTTPRouteMatch,
    /// Filters to apply to matching requests.
    filters: []const HTTPRouteFilter,
    /// Backend services to route to.
    backend_refs: []const BackendRef,
};

/// HTTPRouteMatch defines conditions for matching a request.
pub const HTTPRouteMatch = struct {
    /// Path match condition.
    path: ?PathMatch = null,
    // Future extensions:
    // headers: ?[]HeaderMatch = null,
    // query_params: ?[]QueryParamMatch = null,
    // method: ?Method = null,
};

/// PathMatch defines path matching criteria.
pub const PathMatch = struct {
    /// Match type.
    type: Type,
    /// Path value to match against.
    value: []const u8,

    pub const Type = enum {
        /// Exact path match (e.g., "/api/v1/users").
        Exact,
        /// Path prefix match (e.g., "/api/").
        PathPrefix,

        /// Parse type from string (case-insensitive).
        pub fn fromString(s: []const u8) ?Type {
            if (std.ascii.eqlIgnoreCase(s, "Exact")) return .Exact;
            if (std.ascii.eqlIgnoreCase(s, "PathPrefix")) return .PathPrefix;
            return null;
        }

        /// Convert to string for serialization.
        pub fn toString(self: Type) []const u8 {
            return switch (self) {
                .Exact => "Exact",
                .PathPrefix => "PathPrefix",
            };
        }
    };

    /// Check if a request path matches this condition.
    pub fn matches(self: PathMatch, request_path: []const u8) bool {
        assert(self.value.len > 0); // Precondition: value must be non-empty
        assert(request_path.len > 0); // Precondition: path must be non-empty

        return switch (self.type) {
            .Exact => std.mem.eql(u8, request_path, self.value),
            .PathPrefix => std.mem.startsWith(u8, request_path, self.value),
        };
    }
};

// ============================================================================
// Filters
// ============================================================================

/// HTTPRouteFilter modifies requests/responses.
pub const HTTPRouteFilter = struct {
    /// Filter type.
    type: Type,
    /// URL rewrite configuration (when type is URLRewrite).
    url_rewrite: ?URLRewrite = null,

    pub const Type = enum {
        /// Rewrite the request URL.
        URLRewrite,
        // Future extensions:
        // RequestHeaderModifier,
        // ResponseHeaderModifier,
        // RequestRedirect,

        /// Parse type from string (case-insensitive).
        pub fn fromString(s: []const u8) ?Type {
            if (std.ascii.eqlIgnoreCase(s, "URLRewrite")) return .URLRewrite;
            return null;
        }

        /// Convert to string for serialization.
        pub fn toString(self: Type) []const u8 {
            return switch (self) {
                .URLRewrite => "URLRewrite",
            };
        }
    };
};

/// URLRewrite filter configuration.
pub const URLRewrite = struct {
    /// Path rewrite configuration.
    path: ?PathRewrite = null,
    // Future: hostname rewrite
};

/// PathRewrite defines how to rewrite request paths.
pub const PathRewrite = struct {
    /// Rewrite type.
    type: Type,
    /// Replacement value.
    value: []const u8,

    pub const Type = enum {
        /// Replace the matched prefix with the value.
        ReplacePrefixMatch,
        /// Replace the entire path with the value.
        ReplaceFullPath,

        /// Parse type from string (case-insensitive).
        pub fn fromString(s: []const u8) ?Type {
            if (std.ascii.eqlIgnoreCase(s, "ReplacePrefixMatch")) return .ReplacePrefixMatch;
            if (std.ascii.eqlIgnoreCase(s, "ReplaceFullPath")) return .ReplaceFullPath;
            return null;
        }

        /// Convert to string for serialization.
        pub fn toString(self: Type) []const u8 {
            return switch (self) {
                .ReplacePrefixMatch => "ReplacePrefixMatch",
                .ReplaceFullPath => "ReplaceFullPath",
            };
        }
    };

    /// Apply this rewrite to a path, returning the replacement value.
    /// For ReplaceFullPath: returns the full replacement path.
    /// For ReplacePrefixMatch: returns just the replacement prefix.
    /// Caller is responsible for appending the suffix (original_path[matched_prefix.len..])
    /// when using ReplacePrefixMatch, which requires a buffer.
    pub fn apply(self: PathRewrite) []const u8 {
        assert(self.value.len > 0); // Precondition: value must be non-empty
        return self.value;
    }
};

// ============================================================================
// Backend References
// ============================================================================

/// BackendRef references a backend service.
pub const BackendRef = struct {
    /// Service name.
    name: []const u8,
    /// Service namespace.
    namespace: []const u8,
    /// Service port.
    port: u16,
    /// Traffic weight for load balancing (1-100, default 1).
    weight: u16 = 1,
};

// ============================================================================
// Status Types (for K8s status updates)
// ============================================================================

/// Status for a GatewayClass resource.
/// Used to report whether the controller accepts the GatewayClass.
pub const GatewayClassStatus = struct {
    /// Status conditions for this GatewayClass.
    conditions: []const Condition,
};

/// Status for a Gateway resource.
/// Reports listener attachment and overall gateway health.
pub const GatewayStatus = struct {
    /// Overall status conditions for the Gateway.
    conditions: []const Condition,
    /// Per-listener status information.
    listeners: []const ListenerStatus,
};

/// Status for an individual listener within a Gateway.
pub const ListenerStatus = struct {
    /// Listener name (matches Listener.name).
    name: []const u8,
    /// Number of routes attached to this listener.
    attached_routes: u32,
    /// Status conditions for this listener.
    conditions: []const Condition,
};

/// Condition represents a status condition for Gateway API resources.
/// Follows the standard K8s metav1.Condition format.
pub const Condition = struct {
    /// Type of condition (e.g., Accepted, Programmed).
    type: ConditionType,
    /// Status of the condition (True, False, Unknown).
    status: ConditionStatus,
    /// Machine-readable reason for the condition (CamelCase).
    reason: []const u8,
    /// Human-readable message with details.
    message: []const u8,
    /// RFC3339 timestamp of last transition.
    last_transition_time: []const u8,
    /// Generation of the resource this condition was observed at.
    observed_generation: i64,
};

/// Type of status condition.
/// Maps to Gateway API condition types.
pub const ConditionType = enum {
    /// Resource has been validated and accepted.
    Accepted,
    /// Resource has been programmed into the data plane.
    Programmed,
    /// All backend references have been resolved.
    ResolvedRefs,

    /// Parse condition type from string (case-insensitive).
    pub fn fromString(s: []const u8) ?ConditionType {
        if (std.ascii.eqlIgnoreCase(s, "Accepted")) return .Accepted;
        if (std.ascii.eqlIgnoreCase(s, "Programmed")) return .Programmed;
        if (std.ascii.eqlIgnoreCase(s, "ResolvedRefs")) return .ResolvedRefs;
        return null;
    }

    /// Convert to string for serialization.
    pub fn toString(self: ConditionType) []const u8 {
        return switch (self) {
            .Accepted => "Accepted",
            .Programmed => "Programmed",
            .ResolvedRefs => "ResolvedRefs",
        };
    }
};

/// Status value for a condition.
pub const ConditionStatus = enum {
    /// Condition is satisfied.
    True,
    /// Condition is not satisfied.
    False,
    /// Condition status is unknown.
    Unknown,

    /// Parse condition status from string (case-insensitive).
    pub fn fromString(s: []const u8) ?ConditionStatus {
        if (std.ascii.eqlIgnoreCase(s, "True")) return .True;
        if (std.ascii.eqlIgnoreCase(s, "False")) return .False;
        if (std.ascii.eqlIgnoreCase(s, "Unknown")) return .Unknown;
        return null;
    }

    /// Convert to string for serialization.
    pub fn toString(self: ConditionStatus) []const u8 {
        return switch (self) {
            .True => "True",
            .False => "False",
            .Unknown => "Unknown",
        };
    }
};

// ============================================================================
// Resolved Resources (after K8s lookups)
// ============================================================================

/// Resolved endpoint after Service -> Endpoints lookup.
/// Represents an actual pod IP:port to connect to.
pub const ResolvedEndpoint = struct {
    /// Pod IP address.
    address: []const u8,
    /// Container port.
    port: u16,
};

/// Resolved certificate after Secret lookup.
/// Contains the actual PEM-encoded certificate and key.
pub const ResolvedCertificate = struct {
    /// Original Secret name.
    name: []const u8,
    /// Original Secret namespace.
    namespace: []const u8,
    /// PEM-encoded certificate chain.
    cert_pem: []const u8,
    /// PEM-encoded private key.
    key_pem: []const u8,
};

/// A single resolved endpoint with fixed-size IP buffer (for translator API).
/// TigerStyle: Fixed-size buffer, no allocation needed.
pub const FixedResolvedEndpoint = struct {
    /// IP address as string (IPv4 or IPv6).
    ip: [45]u8, // Max IPv6 length with scope
    ip_len: u8,

    /// Port number.
    port: u16,

    /// Get IP as slice.
    pub fn getIp(self: *const FixedResolvedEndpoint) []const u8 {
        assert(self.ip_len <= 45); // S1: precondition - length within buffer bounds
        return self.ip[0..self.ip_len];
    }
};

/// A backend reference with resolved endpoint addresses.
/// Used by translator to avoid coupling to K8s-specific Resolver.
///
/// TigerStyle: Fixed-size arrays, explicit bounds, no allocation.
pub const ResolvedBackend = struct {
    /// Service name (matches HTTPBackendRef.name for lookup).
    name: [MAX_NAME_LEN]u8,
    name_len: u8,

    /// Namespace (matches HTTPBackendRef.namespace).
    namespace: [MAX_NAME_LEN]u8,
    namespace_len: u8,

    /// Resolved endpoint IP addresses.
    endpoints: [MAX_RESOLVED_ENDPOINTS]FixedResolvedEndpoint,
    endpoint_count: u8,

    /// Get name as slice.
    pub fn getName(self: *const ResolvedBackend) []const u8 {
        assert(self.name_len <= MAX_NAME_LEN); // S1: precondition - length within buffer bounds
        return self.name[0..self.name_len];
    }

    /// Get namespace as slice.
    pub fn getNamespace(self: *const ResolvedBackend) []const u8 {
        assert(self.namespace_len <= MAX_NAME_LEN); // S1: precondition - length within buffer bounds
        return self.namespace[0..self.namespace_len];
    }

    /// Get endpoints as slice.
    pub fn getEndpoints(self: *const ResolvedBackend) []const FixedResolvedEndpoint {
        assert(self.endpoint_count <= MAX_RESOLVED_ENDPOINTS); // S1: precondition - count within bounds
        return self.endpoints[0..self.endpoint_count];
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "Protocol enum fromString" {
    // Test valid protocols
    try std.testing.expectEqual(Listener.Protocol.HTTP, Listener.Protocol.fromString("HTTP").?);
    try std.testing.expectEqual(Listener.Protocol.HTTPS, Listener.Protocol.fromString("HTTPS").?);

    // Test case insensitivity
    try std.testing.expectEqual(Listener.Protocol.HTTP, Listener.Protocol.fromString("http").?);
    try std.testing.expectEqual(Listener.Protocol.HTTPS, Listener.Protocol.fromString("https").?);

    // Test invalid protocol
    try std.testing.expect(Listener.Protocol.fromString("TCP") == null);
    try std.testing.expect(Listener.Protocol.fromString("") == null);
}

test "Protocol enum toString" {
    try std.testing.expectEqualStrings("HTTP", Listener.Protocol.HTTP.toString());
    try std.testing.expectEqualStrings("HTTPS", Listener.Protocol.HTTPS.toString());
}

test "TLSConfig.Mode enum fromString" {
    try std.testing.expectEqual(TLSConfig.Mode.Terminate, TLSConfig.Mode.fromString("Terminate").?);
    try std.testing.expectEqual(TLSConfig.Mode.Passthrough, TLSConfig.Mode.fromString("Passthrough").?);

    // Case insensitivity
    try std.testing.expectEqual(TLSConfig.Mode.Terminate, TLSConfig.Mode.fromString("terminate").?);

    // Invalid
    try std.testing.expect(TLSConfig.Mode.fromString("Invalid") == null);
}

test "PathMatch.Type enum fromString" {
    try std.testing.expectEqual(PathMatch.Type.Exact, PathMatch.Type.fromString("Exact").?);
    try std.testing.expectEqual(PathMatch.Type.PathPrefix, PathMatch.Type.fromString("PathPrefix").?);

    // Case insensitivity
    try std.testing.expectEqual(PathMatch.Type.Exact, PathMatch.Type.fromString("exact").?);

    // Invalid
    try std.testing.expect(PathMatch.Type.fromString("Regex") == null);
}

test "PathMatch.matches exact" {
    const match = PathMatch{
        .type = .Exact,
        .value = "/api/v1/users",
    };

    try std.testing.expect(match.matches("/api/v1/users"));
    try std.testing.expect(!match.matches("/api/v1/users/123"));
    try std.testing.expect(!match.matches("/api/v1"));
    try std.testing.expect(!match.matches("/"));
}

test "PathMatch.matches prefix" {
    const match = PathMatch{
        .type = .PathPrefix,
        .value = "/api/",
    };

    try std.testing.expect(match.matches("/api/"));
    try std.testing.expect(match.matches("/api/v1"));
    try std.testing.expect(match.matches("/api/v1/users"));
    try std.testing.expect(!match.matches("/api")); // Missing trailing slash
    try std.testing.expect(!match.matches("/other"));
}

test "PathRewrite.Type enum fromString" {
    try std.testing.expectEqual(PathRewrite.Type.ReplacePrefixMatch, PathRewrite.Type.fromString("ReplacePrefixMatch").?);
    try std.testing.expectEqual(PathRewrite.Type.ReplaceFullPath, PathRewrite.Type.fromString("ReplaceFullPath").?);

    // Invalid
    try std.testing.expect(PathRewrite.Type.fromString("Invalid") == null);
}

test "PathRewrite.apply ReplaceFullPath" {
    const rewrite = PathRewrite{
        .type = .ReplaceFullPath,
        .value = "/new/path",
    };

    const result = rewrite.apply();
    try std.testing.expectEqualStrings("/new/path", result);
}

test "PathRewrite.apply ReplacePrefixMatch" {
    const rewrite = PathRewrite{
        .type = .ReplacePrefixMatch,
        .value = "/v2",
    };

    // Returns just the replacement prefix; caller appends suffix
    const result = rewrite.apply();
    try std.testing.expectEqualStrings("/v2", result);
}

test "HTTPRouteFilter.Type enum fromString" {
    try std.testing.expectEqual(HTTPRouteFilter.Type.URLRewrite, HTTPRouteFilter.Type.fromString("URLRewrite").?);

    // Invalid
    try std.testing.expect(HTTPRouteFilter.Type.fromString("RequestMirror") == null);
}

test "BackendRef default weight" {
    const backend = BackendRef{
        .name = "my-service",
        .namespace = "default",
        .port = 8080,
    };

    try std.testing.expectEqual(@as(u16, 1), backend.weight);
}

test "Gateway struct construction" {
    var listeners = [_]Listener{
        .{
            .name = "http",
            .port = 80,
            .protocol = .HTTP,
        },
        .{
            .name = "https",
            .port = 443,
            .protocol = .HTTPS,
            .hostname = "*.example.com",
            .tls = .{
                .mode = .Terminate,
                .certificate_refs = &[_]CertificateRef{
                    .{ .name = "example-cert", .namespace = "default" },
                },
            },
        },
    };

    const gateway = Gateway{
        .name = "my-gateway",
        .namespace = "default",
        .listeners = &listeners,
    };

    try std.testing.expectEqualStrings("my-gateway", gateway.name);
    try std.testing.expectEqual(@as(usize, 2), gateway.listeners.len);
    try std.testing.expectEqual(@as(u16, 80), gateway.listeners[0].port);
    try std.testing.expectEqual(@as(u16, 443), gateway.listeners[1].port);
    try std.testing.expectEqual(TLSConfig.Mode.Terminate, gateway.listeners[1].tls.?.mode);
}

test "HTTPRoute struct construction" {
    var hostnames = [_][]const u8{ "api.example.com", "www.example.com" };
    var matches = [_]HTTPRouteMatch{
        .{ .path = .{ .type = .PathPrefix, .value = "/api/" } },
    };
    var filters = [_]HTTPRouteFilter{
        .{
            .type = .URLRewrite,
            .url_rewrite = .{
                .path = .{ .type = .ReplacePrefixMatch, .value = "/" },
            },
        },
    };
    var backends = [_]BackendRef{
        .{ .name = "api-service", .namespace = "default", .port = 8080, .weight = 80 },
        .{ .name = "api-service-canary", .namespace = "default", .port = 8080, .weight = 20 },
    };
    var rules = [_]HTTPRouteRule{
        .{
            .matches = &matches,
            .filters = &filters,
            .backend_refs = &backends,
        },
    };

    const route = HTTPRoute{
        .name = "api-route",
        .namespace = "default",
        .hostnames = &hostnames,
        .rules = &rules,
    };

    try std.testing.expectEqualStrings("api-route", route.name);
    try std.testing.expectEqual(@as(usize, 2), route.hostnames.len);
    try std.testing.expectEqual(@as(usize, 1), route.rules.len);
    try std.testing.expectEqual(@as(usize, 2), route.rules[0].backend_refs.len);
    try std.testing.expectEqual(@as(u16, 80), route.rules[0].backend_refs[0].weight);
}

test "ResolvedEndpoint construction" {
    const endpoint = ResolvedEndpoint{
        .address = "10.0.0.5",
        .port = 8080,
    };

    try std.testing.expectEqualStrings("10.0.0.5", endpoint.address);
    try std.testing.expectEqual(@as(u16, 8080), endpoint.port);
}

test "ResolvedCertificate construction" {
    const cert = ResolvedCertificate{
        .name = "example-cert",
        .namespace = "default",
        .cert_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        .key_pem = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    };

    try std.testing.expectEqualStrings("example-cert", cert.name);
    try std.testing.expect(std.mem.startsWith(u8, cert.cert_pem, "-----BEGIN CERTIFICATE-----"));
    try std.testing.expect(std.mem.startsWith(u8, cert.key_pem, "-----BEGIN PRIVATE KEY-----"));
}

test "MAX constants are within bounds" {
    // Verify all MAX constants fit in their respective types (compile-time check via type)
    comptime {
        // u8 bounds
        assert(MAX_GATEWAYS <= 255);
        assert(MAX_LISTENERS <= 255);
        assert(MAX_HTTP_ROUTES <= 255);
        assert(MAX_RULES <= 255);
        assert(MAX_MATCHES <= 255);
        assert(MAX_FILTERS <= 255);
        assert(MAX_BACKEND_REFS <= 255);
        assert(MAX_HOSTNAMES <= 255);
        assert(MAX_CERTIFICATE_REFS <= 255);
        assert(MAX_NAME_LEN <= 255);
        assert(MAX_RESOLVED_ENDPOINTS <= 255);
        // u16 bounds
        assert(MAX_RESOLVED_BACKENDS <= 65535);
    }
}

test "FixedResolvedEndpoint construction and getIp" {
    var endpoint: FixedResolvedEndpoint = undefined;
    const ip = "192.168.1.100";
    @memcpy(endpoint.ip[0..ip.len], ip);
    endpoint.ip_len = ip.len;
    endpoint.port = 8080;

    try std.testing.expectEqualStrings("192.168.1.100", endpoint.getIp());
    try std.testing.expectEqual(@as(u16, 8080), endpoint.port);
}

test "FixedResolvedEndpoint IPv6 address" {
    var endpoint: FixedResolvedEndpoint = undefined;
    const ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    @memcpy(endpoint.ip[0..ip.len], ip);
    endpoint.ip_len = ip.len;
    endpoint.port = 443;

    try std.testing.expectEqualStrings("2001:0db8:85a3:0000:0000:8a2e:0370:7334", endpoint.getIp());
    try std.testing.expectEqual(@as(u16, 443), endpoint.port);
}

test "ResolvedBackend construction and accessors" {
    var backend: ResolvedBackend = undefined;

    // Set name
    const name = "my-service";
    @memcpy(backend.name[0..name.len], name);
    backend.name_len = name.len;

    // Set namespace
    const namespace = "production";
    @memcpy(backend.namespace[0..namespace.len], namespace);
    backend.namespace_len = namespace.len;

    // Set one endpoint
    const ip = "10.0.0.5";
    @memcpy(backend.endpoints[0].ip[0..ip.len], ip);
    backend.endpoints[0].ip_len = ip.len;
    backend.endpoints[0].port = 8080;
    backend.endpoint_count = 1;

    try std.testing.expectEqualStrings("my-service", backend.getName());
    try std.testing.expectEqualStrings("production", backend.getNamespace());
    try std.testing.expectEqual(@as(u8, 1), backend.endpoint_count);
    try std.testing.expectEqualStrings("10.0.0.5", backend.endpoints[0].getIp());
    try std.testing.expectEqual(@as(u16, 8080), backend.endpoints[0].port);
}

test "ResolvedBackend with multiple endpoints" {
    var backend: ResolvedBackend = undefined;

    // Set name and namespace
    const name = "api-svc";
    @memcpy(backend.name[0..name.len], name);
    backend.name_len = name.len;
    const namespace = "default";
    @memcpy(backend.namespace[0..namespace.len], namespace);
    backend.namespace_len = namespace.len;

    // Set multiple endpoints (simulating multiple pods)
    const ips = [_][]const u8{ "10.0.0.1", "10.0.0.2", "10.0.0.3" };
    const ports = [_]u16{ 8080, 8080, 8080 };

    for (ips, ports, 0..) |ip, port, i| {
        @memcpy(backend.endpoints[i].ip[0..ip.len], ip);
        backend.endpoints[i].ip_len = @intCast(ip.len);
        backend.endpoints[i].port = port;
    }
    backend.endpoint_count = 3;

    try std.testing.expectEqual(@as(u8, 3), backend.endpoint_count);
    try std.testing.expectEqualStrings("10.0.0.1", backend.endpoints[0].getIp());
    try std.testing.expectEqualStrings("10.0.0.2", backend.endpoints[1].getIp());
    try std.testing.expectEqualStrings("10.0.0.3", backend.endpoints[2].getIp());
}

test "ResolvedBackend max name length" {
    var backend: ResolvedBackend = undefined;

    // K8s resource names are max 63 characters
    const max_name = "a" ** MAX_NAME_LEN;
    @memcpy(backend.name[0..max_name.len], max_name);
    backend.name_len = MAX_NAME_LEN;

    try std.testing.expectEqual(@as(usize, 63), backend.getName().len);
}

// ============================================================================
// Status Types Unit Tests
// ============================================================================

test "ConditionType enum fromString" {
    // Test valid condition types
    try std.testing.expectEqual(ConditionType.Accepted, ConditionType.fromString("Accepted").?);
    try std.testing.expectEqual(ConditionType.Programmed, ConditionType.fromString("Programmed").?);
    try std.testing.expectEqual(ConditionType.ResolvedRefs, ConditionType.fromString("ResolvedRefs").?);

    // Test case insensitivity
    try std.testing.expectEqual(ConditionType.Accepted, ConditionType.fromString("accepted").?);
    try std.testing.expectEqual(ConditionType.Programmed, ConditionType.fromString("PROGRAMMED").?);
    try std.testing.expectEqual(ConditionType.ResolvedRefs, ConditionType.fromString("resolvedrefs").?);

    // Test invalid condition type
    try std.testing.expect(ConditionType.fromString("Ready") == null);
    try std.testing.expect(ConditionType.fromString("") == null);
    try std.testing.expect(ConditionType.fromString("Invalid") == null);
}

test "ConditionType enum toString" {
    try std.testing.expectEqualStrings("Accepted", ConditionType.Accepted.toString());
    try std.testing.expectEqualStrings("Programmed", ConditionType.Programmed.toString());
    try std.testing.expectEqualStrings("ResolvedRefs", ConditionType.ResolvedRefs.toString());
}

test "ConditionStatus enum fromString" {
    // Test valid condition statuses
    try std.testing.expectEqual(ConditionStatus.True, ConditionStatus.fromString("True").?);
    try std.testing.expectEqual(ConditionStatus.False, ConditionStatus.fromString("False").?);
    try std.testing.expectEqual(ConditionStatus.Unknown, ConditionStatus.fromString("Unknown").?);

    // Test case insensitivity
    try std.testing.expectEqual(ConditionStatus.True, ConditionStatus.fromString("true").?);
    try std.testing.expectEqual(ConditionStatus.False, ConditionStatus.fromString("FALSE").?);
    try std.testing.expectEqual(ConditionStatus.Unknown, ConditionStatus.fromString("unknown").?);

    // Test invalid condition status
    try std.testing.expect(ConditionStatus.fromString("Yes") == null);
    try std.testing.expect(ConditionStatus.fromString("") == null);
    try std.testing.expect(ConditionStatus.fromString("1") == null);
}

test "ConditionStatus enum toString" {
    try std.testing.expectEqualStrings("True", ConditionStatus.True.toString());
    try std.testing.expectEqualStrings("False", ConditionStatus.False.toString());
    try std.testing.expectEqualStrings("Unknown", ConditionStatus.Unknown.toString());
}

test "GatewayClass struct construction" {
    const gateway_class = GatewayClass{
        .name = "serval-gateway",
        .controller_name = "example.com/serval-gateway-controller",
    };

    try std.testing.expectEqualStrings("serval-gateway", gateway_class.name);
    try std.testing.expectEqualStrings("example.com/serval-gateway-controller", gateway_class.controller_name);
}

test "Condition struct construction" {
    const condition = Condition{
        .type = .Accepted,
        .status = .True,
        .reason = "Accepted",
        .message = "Gateway class accepted by controller",
        .last_transition_time = "2024-01-15T10:30:00Z",
        .observed_generation = 1,
    };

    try std.testing.expectEqual(ConditionType.Accepted, condition.type);
    try std.testing.expectEqual(ConditionStatus.True, condition.status);
    try std.testing.expectEqualStrings("Accepted", condition.reason);
    try std.testing.expectEqualStrings("Gateway class accepted by controller", condition.message);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", condition.last_transition_time);
    try std.testing.expectEqual(@as(i64, 1), condition.observed_generation);
}

test "GatewayClassStatus struct construction" {
    var conditions = [_]Condition{
        .{
            .type = .Accepted,
            .status = .True,
            .reason = "Accepted",
            .message = "Controller accepts this GatewayClass",
            .last_transition_time = "2024-01-15T10:30:00Z",
            .observed_generation = 1,
        },
    };

    const status = GatewayClassStatus{
        .conditions = &conditions,
    };

    try std.testing.expectEqual(@as(usize, 1), status.conditions.len);
    try std.testing.expectEqual(ConditionType.Accepted, status.conditions[0].type);
    try std.testing.expectEqual(ConditionStatus.True, status.conditions[0].status);
}

test "ListenerStatus struct construction" {
    var conditions = [_]Condition{
        .{
            .type = .Accepted,
            .status = .True,
            .reason = "Accepted",
            .message = "Listener is valid",
            .last_transition_time = "2024-01-15T10:30:00Z",
            .observed_generation = 2,
        },
        .{
            .type = .Programmed,
            .status = .True,
            .reason = "Programmed",
            .message = "Listener has been programmed",
            .last_transition_time = "2024-01-15T10:30:01Z",
            .observed_generation = 2,
        },
    };

    const listener_status = ListenerStatus{
        .name = "https",
        .attached_routes = 5,
        .conditions = &conditions,
    };

    try std.testing.expectEqualStrings("https", listener_status.name);
    try std.testing.expectEqual(@as(u32, 5), listener_status.attached_routes);
    try std.testing.expectEqual(@as(usize, 2), listener_status.conditions.len);
}

test "GatewayStatus struct construction" {
    var gateway_conditions = [_]Condition{
        .{
            .type = .Accepted,
            .status = .True,
            .reason = "Accepted",
            .message = "Gateway is valid",
            .last_transition_time = "2024-01-15T10:30:00Z",
            .observed_generation = 3,
        },
        .{
            .type = .Programmed,
            .status = .True,
            .reason = "Programmed",
            .message = "Gateway has been programmed",
            .last_transition_time = "2024-01-15T10:30:01Z",
            .observed_generation = 3,
        },
    };

    var listener_conditions = [_]Condition{
        .{
            .type = .Accepted,
            .status = .True,
            .reason = "Accepted",
            .message = "Listener accepted",
            .last_transition_time = "2024-01-15T10:30:00Z",
            .observed_generation = 3,
        },
    };

    var listeners = [_]ListenerStatus{
        .{
            .name = "http",
            .attached_routes = 3,
            .conditions = &listener_conditions,
        },
        .{
            .name = "https",
            .attached_routes = 2,
            .conditions = &listener_conditions,
        },
    };

    const status = GatewayStatus{
        .conditions = &gateway_conditions,
        .listeners = &listeners,
    };

    try std.testing.expectEqual(@as(usize, 2), status.conditions.len);
    try std.testing.expectEqual(@as(usize, 2), status.listeners.len);
    try std.testing.expectEqualStrings("http", status.listeners[0].name);
    try std.testing.expectEqual(@as(u32, 3), status.listeners[0].attached_routes);
    try std.testing.expectEqualStrings("https", status.listeners[1].name);
    try std.testing.expectEqual(@as(u32, 2), status.listeners[1].attached_routes);
}

test "Status constants are within bounds" {
    // Verify status constants fit in their respective types (compile-time check)
    comptime {
        // u8 bounds
        assert(MAX_GATEWAY_CLASSES <= 255);
        assert(MAX_CONDITIONS <= 255);
        assert(MAX_REASON_LEN <= 255);
        // u16 bounds
        assert(MAX_MESSAGE_LEN <= 65535);
        // u32 bounds
        assert(MAX_STATUS_JSON_SIZE <= 4294967295);
    }
}
