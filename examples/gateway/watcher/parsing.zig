//! Kubernetes Resource Watcher JSON Parsing
//!
//! JSON parsing functions for Kubernetes Gateway API watch events.
//! Parses K8s watch event JSON into typed config structures.
//!
//! TigerStyle: Bounded parsing, explicit error handling, no allocation after init.

const std = @import("std");
const assert = std.debug.assert;

const gateway = @import("serval-k8s-gateway");
const gw_config = gateway.config;

const k8s_json = @import("../k8s_client/json_types.zig");
const types = @import("types.zig");

// Import types from types.zig
const WatcherError = types.WatcherError;
const EventType = types.EventType;
const WatchEvent = types.WatchEvent;
const ResourceMeta = types.ResourceMeta;
const StoredGateway = types.StoredGateway;
const StoredGatewayClass = types.StoredGatewayClass;
const StoredHTTPRoute = types.StoredHTTPRoute;
const StoredListener = types.StoredListener;
const StoredHTTPRouteRule = types.StoredHTTPRouteRule;
const StoredHTTPRouteMatch = types.StoredHTTPRouteMatch;
const StoredHTTPRouteFilter = types.StoredHTTPRouteFilter;
const StoredBackendRef = types.StoredBackendRef;
const ControllerNameStorage = types.ControllerNameStorage;
const MAX_CONTROLLER_NAME_LEN = types.MAX_CONTROLLER_NAME_LEN;

// Import constants
const MAX_NAME_LEN = types.MAX_NAME_LEN;
const MAX_HOSTNAME_LEN = types.MAX_HOSTNAME_LEN;
const MAX_PATH_VALUE_LEN = types.MAX_PATH_VALUE_LEN;

// =============================================================================
// JSON Parsing Functions (using std.json)
// =============================================================================

/// Parse a watch event from JSON line.
/// K8s watch events are newline-delimited JSON with "type" and "object" fields.
pub fn parseEvent(line: []const u8) WatcherError!WatchEvent {
    assert(line.len > 0); // S1: precondition

    const parsed = std.json.parseFromSlice(k8s_json.WatchEventJson, std.heap.page_allocator, line, .{
        .ignore_unknown_fields = true,
    }) catch return WatcherError.ParseError;
    defer parsed.deinit();

    const event_type = EventType.fromString(parsed.value.type) orelse return WatcherError.UnknownEventType;

    // Serialize the object back to JSON string for raw_object.
    // We need the raw JSON for storage in ResourceStore.
    // Find the "object" field in the original JSON and extract it.
    const object_start = findJsonObjectField(line, "object") orelse return WatcherError.MissingField;

    return WatchEvent{
        .event_type = event_type,
        .raw_object = object_start,
    };
}

/// Find a JSON object field and return the raw JSON for that object.
/// Returns slice from opening brace to closing brace (inclusive).
pub fn findJsonObjectField(json: []const u8, field_name: []const u8) ?[]const u8 {
    assert(json.len > 0); // S1: precondition - non-empty JSON
    assert(field_name.len > 0); // S1: precondition - non-empty field name
    assert(field_name.len < 64); // S1: precondition - field name fits in pattern buffer

    // Build search pattern: "fieldName":{
    var pattern_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":{{", .{field_name}) catch return null;

    // Find pattern in JSON.
    const pattern_start = std.mem.indexOf(u8, json, pattern) orelse return null;
    const object_start = pattern_start + pattern.len - 1; // Include opening brace.

    // Find matching closing brace.
    var depth: u32 = 0;
    var pos: usize = object_start;
    const max_iterations: u32 = 65536; // TigerStyle: bounded loop
    var iteration: u32 = 0;

    while (pos < json.len and iteration < max_iterations) : ({
        pos += 1;
        iteration += 1;
    }) {
        const c = json[pos];
        if (c == '{') {
            depth += 1;
        } else if (c == '}') {
            if (depth == 1) {
                return json[object_start .. pos + 1];
            }
            depth -= 1;
        }
    }

    return null;
}

/// Extract resource metadata from K8s object JSON using std.json.
pub fn extractResourceMeta(json: []const u8) WatcherError!ResourceMeta {
    assert(json.len > 0); // S1: precondition

    // Parse just the metadata we need.
    const MetadataWrapper = struct {
        metadata: ?k8s_json.MetadataJson = null,
    };

    const parsed = std.json.parseFromSlice(MetadataWrapper, std.heap.page_allocator, json, .{
        .ignore_unknown_fields = true,
    }) catch return WatcherError.ParseError;
    defer parsed.deinit();

    const metadata = parsed.value.metadata orelse return WatcherError.MissingField;
    const name = metadata.name orelse return WatcherError.MissingField;
    const namespace = metadata.namespace orelse "default";
    const resource_version = metadata.resourceVersion orelse "";

    return ResourceMeta{
        .name = name,
        .namespace = namespace,
        .resource_version = resource_version,
    };
}

/// Parse a Gateway resource from raw K8s JSON into StoredGateway using std.json.
pub fn parseGatewayJson(json: []const u8, out: *StoredGateway) WatcherError!void {
    assert(json.len > 0); // S1: precondition - non-empty JSON
    assert(@intFromPtr(out) != 0); // S1: precondition - valid output pointer

    // Reset output.
    out.* = StoredGateway.init();

    const parsed = std.json.parseFromSlice(k8s_json.GatewayJson, std.heap.page_allocator, json, .{
        .ignore_unknown_fields = true,
    }) catch return WatcherError.ParseError;
    defer parsed.deinit();

    // Parse metadata.
    const metadata = parsed.value.metadata orelse return WatcherError.MissingField;
    const name = metadata.name orelse return WatcherError.MissingField;
    const namespace = metadata.namespace orelse "default";

    if (name.len > MAX_NAME_LEN or namespace.len > MAX_NAME_LEN) {
        return WatcherError.InvalidJson;
    }

    out.name.set(name);
    out.namespace.set(namespace);

    // Parse spec.listeners.
    const spec = parsed.value.spec orelse return WatcherError.MissingField;
    const listeners = spec.listeners orelse {
        // No listeners is valid (empty gateway).
        out.listeners_count = 0;
        return;
    };

    // Parse each listener (bounded by MAX_LISTENERS).
    var listener_idx: u8 = 0;
    for (listeners) |listener_json| {
        if (listener_idx >= gw_config.MAX_LISTENERS) break;

        parseListenerFromJson(listener_json, &out.listeners[listener_idx]);
        out.listeners[listener_idx].active = true;
        listener_idx += 1;
    }
    out.listeners_count = listener_idx;

    // S2: Postconditions
    assert(out.name.len > 0);
    assert(out.listeners_count <= gw_config.MAX_LISTENERS);
}

/// Parse a GatewayClass from K8s watch event JSON.
/// Extracts metadata.name and spec.controllerName.
/// GatewayClass is cluster-scoped (no namespace field).
pub fn parseGatewayClassJson(json: []const u8, out: *StoredGatewayClass) WatcherError!void {
    assert(json.len > 0); // S1: precondition - non-empty JSON
    assert(@intFromPtr(out) != 0); // S1: precondition - valid output pointer

    // Reset output.
    out.* = StoredGatewayClass.init();

    const parsed = std.json.parseFromSlice(k8s_json.GatewayClassJson, std.heap.page_allocator, json, .{
        .ignore_unknown_fields = true,
    }) catch return WatcherError.ParseError;
    defer parsed.deinit();

    // Parse metadata (required).
    const metadata = parsed.value.metadata orelse return WatcherError.MissingField;
    const name = metadata.name orelse return WatcherError.MissingField;

    // Validate name length.
    if (name.len > MAX_NAME_LEN) {
        return WatcherError.InvalidJson;
    }

    out.name.set(name);

    // Parse spec (required for controllerName).
    const spec = parsed.value.spec orelse return WatcherError.MissingField;
    const controller_name = spec.controllerName orelse return WatcherError.MissingField;

    // Validate controller name length.
    if (controller_name.len > MAX_CONTROLLER_NAME_LEN) {
        return WatcherError.InvalidJson;
    }

    out.controller_name.set(controller_name);
    out.active = true;

    // S2: Postconditions
    assert(out.name.len > 0);
    assert(out.controller_name.len > 0);
    assert(out.active);
}

/// Parse a single Listener from JSON struct.
fn parseListenerFromJson(listener_json: k8s_json.ListenerJson, out: *types.StoredListener) void {
    assert(@intFromPtr(out) != 0); // S1: precondition - valid output pointer

    out.* = types.StoredListener.init();

    // Extract name.
    const name = listener_json.name orelse return;
    if (name.len > MAX_NAME_LEN) return;
    out.name.set(name);

    // Extract port.
    out.port = if (listener_json.port) |p| @intCast(@as(u16, @truncate(@as(u64, @intCast(p))))) else return;

    // Extract protocol.
    const protocol_str = listener_json.protocol orelse "HTTP";
    out.protocol = gw_config.Listener.Protocol.fromString(protocol_str) orelse .HTTP;

    // Extract optional hostname.
    if (listener_json.hostname) |hostname| {
        if (hostname.len <= MAX_HOSTNAME_LEN) {
            out.hostname.set(hostname);
            out.has_hostname = true;
        }
    }

    out.active = true;
}

/// Parse an HTTPRoute resource from raw K8s JSON into StoredHTTPRoute using std.json.
pub fn parseHTTPRouteJson(json: []const u8, out: *StoredHTTPRoute) WatcherError!void {
    assert(json.len > 0); // S1: precondition - non-empty JSON
    assert(@intFromPtr(out) != 0); // S1: precondition - valid output pointer

    // Reset output.
    out.* = StoredHTTPRoute.init();

    const parsed = std.json.parseFromSlice(k8s_json.HTTPRouteJson, std.heap.page_allocator, json, .{
        .ignore_unknown_fields = true,
    }) catch return WatcherError.ParseError;
    defer parsed.deinit();

    // Parse metadata.
    const metadata = parsed.value.metadata orelse return WatcherError.MissingField;
    const name = metadata.name orelse return WatcherError.MissingField;
    const namespace = metadata.namespace orelse "default";

    if (name.len > MAX_NAME_LEN or namespace.len > MAX_NAME_LEN) {
        return WatcherError.InvalidJson;
    }

    out.name.set(name);
    out.namespace.set(namespace);

    // Parse spec.
    const spec = parsed.value.spec orelse return WatcherError.MissingField;

    // Parse hostnames array.
    if (spec.hostnames) |hostnames| {
        var hostname_idx: u8 = 0;
        for (hostnames) |hostname| {
            if (hostname_idx >= gw_config.MAX_HOSTNAMES) break;
            if (hostname.len <= MAX_HOSTNAME_LEN) {
                out.hostnames[hostname_idx].set(hostname);
                hostname_idx += 1;
            }
        }
        out.hostnames_count = hostname_idx;
    }

    // Parse rules array.
    const rules = spec.rules orelse {
        // No rules is valid (empty route).
        out.rules_count = 0;
        return;
    };

    var rule_idx: u8 = 0;
    for (rules) |rule_json| {
        if (rule_idx >= gw_config.MAX_RULES) break;

        parseRuleFromJson(rule_json, &out.rules[rule_idx]);
        out.rules[rule_idx].active = true;
        rule_idx += 1;
    }
    out.rules_count = rule_idx;

    // S2: Postconditions
    assert(out.name.len > 0);
    assert(out.rules_count <= gw_config.MAX_RULES);
}

/// Parse a single HTTPRouteRule from JSON struct.
fn parseRuleFromJson(rule_json: k8s_json.HTTPRouteRuleJson, out: *StoredHTTPRouteRule) void {
    assert(@intFromPtr(out) != 0); // S1: precondition - valid output pointer

    out.* = StoredHTTPRouteRule.init();

    // Parse matches array.
    if (rule_json.matches) |matches| {
        var match_idx: u8 = 0;
        for (matches) |match_json| {
            if (match_idx >= gw_config.MAX_MATCHES) break;

            parseMatchFromJson(match_json, &out.matches[match_idx]);
            out.matches[match_idx].active = true;
            match_idx += 1;
        }
        out.matches_count = match_idx;
    }

    // Parse filters array.
    if (rule_json.filters) |filters| {
        var filter_idx: u8 = 0;
        for (filters) |filter_json| {
            if (filter_idx >= gw_config.MAX_FILTERS) break;

            parseFilterFromJson(filter_json, &out.filters[filter_idx]);
            out.filters[filter_idx].active = true;
            filter_idx += 1;
        }
        out.filters_count = filter_idx;
    }

    // Parse backendRefs array.
    if (rule_json.backendRefs) |backend_refs| {
        var backend_idx: u8 = 0;
        for (backend_refs) |backend_json| {
            if (backend_idx >= gw_config.MAX_BACKEND_REFS) break;

            parseBackendRefFromJson(backend_json, &out.backend_refs[backend_idx]);
            out.backend_refs[backend_idx].active = true;
            backend_idx += 1;
        }
        out.backend_refs_count = backend_idx;
    }

    out.active = true;
}

/// Parse a single HTTPRouteMatch from JSON struct.
fn parseMatchFromJson(match_json: k8s_json.HTTPRouteMatchJson, out: *StoredHTTPRouteMatch) void {
    assert(@intFromPtr(out) != 0); // S1: precondition - valid output pointer

    out.* = StoredHTTPRouteMatch.init();

    // Parse path match.
    if (match_json.path) |path_json| {
        const path_type_str = path_json.type orelse "PathPrefix";
        const path_value = path_json.value orelse "/";

        if (path_value.len <= MAX_PATH_VALUE_LEN) {
            out.path.match_type = gw_config.PathMatch.Type.fromString(path_type_str) orelse .PathPrefix;
            out.path.value.set(path_value);
            out.path.active = true;
            out.has_path = true;
        }
    }

    out.active = true;
}

/// Parse a single HTTPRouteFilter from JSON struct.
pub fn parseFilterFromJson(filter_json: k8s_json.HTTPRouteFilterJson, out: *StoredHTTPRouteFilter) void {
    assert(@intFromPtr(out) != 0); // S1: precondition - valid output pointer

    out.* = StoredHTTPRouteFilter.init();

    // Get filter type.
    const filter_type_str = filter_json.type orelse return;
    out.filter_type = gw_config.HTTPRouteFilter.Type.fromString(filter_type_str) orelse return;

    // Parse URLRewrite filter.
    if (out.filter_type == .URLRewrite) {
        if (filter_json.urlRewrite) |rewrite_json| {
            if (rewrite_json.path) |path_json| {
                const rewrite_type_str = path_json.type orelse "ReplacePrefixMatch";
                // K8s uses "replacePrefixMatch" or "replaceFullPath" field for the value.
                const rewrite_value = path_json.replacePrefixMatch orelse
                    path_json.replaceFullPath orelse "/";

                if (rewrite_value.len <= MAX_PATH_VALUE_LEN) {
                    out.url_rewrite.path.rewrite_type = gw_config.PathRewrite.Type.fromString(rewrite_type_str) orelse .ReplacePrefixMatch;
                    out.url_rewrite.path.value.set(rewrite_value);
                    out.url_rewrite.path.active = true;
                    out.url_rewrite.has_path = true;
                }
            }
        }
    }

    out.active = true;
}

/// Parse a single BackendRef from JSON struct.
fn parseBackendRefFromJson(backend_json: k8s_json.BackendRefJson, out: *StoredBackendRef) void {
    assert(@intFromPtr(out) != 0); // S1: precondition - valid output pointer

    out.* = StoredBackendRef.init();

    // Extract name (required).
    const name = backend_json.name orelse return;
    if (name.len > MAX_NAME_LEN) return;
    out.name.set(name);

    // Extract namespace (defaults to route's namespace, but we use "default" here).
    const namespace = backend_json.namespace orelse "default";
    if (namespace.len > MAX_NAME_LEN) return;
    out.namespace.set(namespace);

    // Extract port (required).
    out.port = if (backend_json.port) |p| @intCast(@as(u16, @truncate(@as(u64, @intCast(p))))) else return;

    // Extract weight (optional, defaults to 1).
    out.weight = if (backend_json.weight) |w| @intCast(@as(u16, @truncate(@as(u64, @intCast(w))))) else 1;

    out.active = true;
}

// =============================================================================
// Unit Tests
// =============================================================================

test "parseEvent - ADDED event" {
    const line =
        \\{"type":"ADDED","object":{"kind":"Gateway","metadata":{"name":"my-gw","namespace":"default","resourceVersion":"12345"}}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.ADDED, event.event_type);
    try std.testing.expect(std.mem.indexOf(u8, event.raw_object, "Gateway") != null);
}

test "parseEvent - MODIFIED event" {
    const line =
        \\{"type":"MODIFIED","object":{"kind":"HTTPRoute","metadata":{"name":"route1","namespace":"prod"}}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.MODIFIED, event.event_type);
    try std.testing.expect(std.mem.indexOf(u8, event.raw_object, "HTTPRoute") != null);
}

test "parseEvent - DELETED event" {
    const line =
        \\{"type":"DELETED","object":{"metadata":{"name":"old-gw","namespace":"default"}}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.DELETED, event.event_type);
}

test "parseEvent - BOOKMARK event" {
    const line =
        \\{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"99999"}}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.BOOKMARK, event.event_type);
}

test "parseEvent - ERROR event" {
    const line =
        \\{"type":"ERROR","object":{"message":"watch error","code":410}}
    ;
    const event = try parseEvent(line);
    try std.testing.expectEqual(EventType.ERROR, event.event_type);
}

test "parseEvent - missing type field" {
    const line =
        \\{"object":{"metadata":{"name":"gw"}}}
    ;
    const result = parseEvent(line);
    try std.testing.expectError(WatcherError.ParseError, result);
}

test "parseEvent - unknown type" {
    const line =
        \\{"type":"UNKNOWN","object":{}}
    ;
    const result = parseEvent(line);
    try std.testing.expectError(WatcherError.UnknownEventType, result);
}

test "parseEvent - missing object field" {
    const line =
        \\{"type":"ADDED"}
    ;
    const result = parseEvent(line);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "extractResourceMeta - full metadata" {
    const json =
        \\{"kind":"Gateway","metadata":{"name":"my-gateway","namespace":"production","resourceVersion":"12345"}}
    ;
    const meta = try extractResourceMeta(json);
    try std.testing.expectEqualStrings("my-gateway", meta.name);
    try std.testing.expectEqualStrings("production", meta.namespace);
    try std.testing.expectEqualStrings("12345", meta.resource_version);
}

test "extractResourceMeta - default namespace" {
    const json =
        \\{"metadata":{"name":"cluster-resource","resourceVersion":"999"}}
    ;
    // Namespace defaults to "default" when not present.
    const meta = try extractResourceMeta(json);
    try std.testing.expectEqualStrings("cluster-resource", meta.name);
    try std.testing.expectEqualStrings("default", meta.namespace);
}

test "extractResourceMeta - missing name" {
    const json =
        \\{"metadata":{"namespace":"ns"}}
    ;
    const result = extractResourceMeta(json);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "extractResourceMeta - missing metadata" {
    const json =
        \\{"kind":"Gateway","spec":{}}
    ;
    const result = extractResourceMeta(json);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseGatewayJson - basic gateway" {
    const json =
        \\{
        \\  "metadata": {"name": "my-gateway", "namespace": "production"},
        \\  "spec": {
        \\    "listeners": [
        \\      {"name": "http", "port": 80, "protocol": "HTTP"},
        \\      {"name": "https", "port": 443, "protocol": "HTTPS", "hostname": "*.example.com"}
        \\    ]
        \\  }
        \\}
    ;

    var gw = StoredGateway.init();
    try parseGatewayJson(json, &gw);

    try std.testing.expectEqualStrings("my-gateway", gw.name.slice());
    try std.testing.expectEqualStrings("production", gw.namespace.slice());
    try std.testing.expectEqual(@as(u8, 2), gw.listeners_count);

    // Check first listener
    try std.testing.expectEqualStrings("http", gw.listeners[0].name.slice());
    try std.testing.expectEqual(@as(u16, 80), gw.listeners[0].port);
    try std.testing.expectEqual(gw_config.Listener.Protocol.HTTP, gw.listeners[0].protocol);
    try std.testing.expect(!gw.listeners[0].has_hostname);

    // Check second listener
    try std.testing.expectEqualStrings("https", gw.listeners[1].name.slice());
    try std.testing.expectEqual(@as(u16, 443), gw.listeners[1].port);
    try std.testing.expectEqual(gw_config.Listener.Protocol.HTTPS, gw.listeners[1].protocol);
    try std.testing.expect(gw.listeners[1].has_hostname);
    try std.testing.expectEqualStrings("*.example.com", gw.listeners[1].hostname.slice());
}

test "parseGatewayJson - no listeners" {
    const json =
        \\{
        \\  "metadata": {"name": "empty-gw", "namespace": "default"},
        \\  "spec": {}
        \\}
    ;

    var gw = StoredGateway.init();
    try parseGatewayJson(json, &gw);

    try std.testing.expectEqualStrings("empty-gw", gw.name.slice());
    try std.testing.expectEqual(@as(u8, 0), gw.listeners_count);
}

test "parseGatewayJson - default namespace" {
    const json =
        \\{
        \\  "metadata": {"name": "gw"},
        \\  "spec": {"listeners": []}
        \\}
    ;

    var gw = StoredGateway.init();
    try parseGatewayJson(json, &gw);

    try std.testing.expectEqualStrings("gw", gw.name.slice());
    try std.testing.expectEqualStrings("default", gw.namespace.slice());
}

test "parseGatewayJson - missing metadata" {
    const json =
        \\{
        \\  "spec": {"listeners": []}
        \\}
    ;

    var gw = StoredGateway.init();
    const result = parseGatewayJson(json, &gw);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseGatewayJson - missing name" {
    const json =
        \\{
        \\  "metadata": {"namespace": "default"},
        \\  "spec": {"listeners": []}
        \\}
    ;

    var gw = StoredGateway.init();
    const result = parseGatewayJson(json, &gw);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseHTTPRouteJson - full route" {
    const json =
        \\{
        \\  "metadata": {"name": "api-route", "namespace": "prod"},
        \\  "spec": {
        \\    "hostnames": ["api.example.com", "www.example.com"],
        \\    "rules": [
        \\      {
        \\        "matches": [
        \\          {"path": {"type": "PathPrefix", "value": "/api/"}}
        \\        ],
        \\        "filters": [
        \\          {"type": "URLRewrite", "urlRewrite": {"path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/"}}}
        \\        ],
        \\        "backendRefs": [
        \\          {"name": "api-svc", "namespace": "prod", "port": 8080, "weight": 90},
        \\          {"name": "api-svc-canary", "port": 8080, "weight": 10}
        \\        ]
        \\      }
        \\    ]
        \\  }
        \\}
    ;

    var route = StoredHTTPRoute.init();
    try parseHTTPRouteJson(json, &route);

    // Check metadata
    try std.testing.expectEqualStrings("api-route", route.name.slice());
    try std.testing.expectEqualStrings("prod", route.namespace.slice());

    // Check hostnames
    try std.testing.expectEqual(@as(u8, 2), route.hostnames_count);
    try std.testing.expectEqualStrings("api.example.com", route.hostnames[0].slice());
    try std.testing.expectEqualStrings("www.example.com", route.hostnames[1].slice());

    // Check rules
    try std.testing.expectEqual(@as(u8, 1), route.rules_count);

    const rule = &route.rules[0];

    // Check matches
    try std.testing.expectEqual(@as(u8, 1), rule.matches_count);
    try std.testing.expect(rule.matches[0].has_path);
    try std.testing.expectEqual(gw_config.PathMatch.Type.PathPrefix, rule.matches[0].path.match_type);
    try std.testing.expectEqualStrings("/api/", rule.matches[0].path.value.slice());

    // Check filters
    try std.testing.expectEqual(@as(u8, 1), rule.filters_count);
    try std.testing.expectEqual(gw_config.HTTPRouteFilter.Type.URLRewrite, rule.filters[0].filter_type);
    try std.testing.expect(rule.filters[0].url_rewrite.has_path);
    try std.testing.expectEqual(gw_config.PathRewrite.Type.ReplacePrefixMatch, rule.filters[0].url_rewrite.path.rewrite_type);
    try std.testing.expectEqualStrings("/", rule.filters[0].url_rewrite.path.value.slice());

    // Check backend refs
    try std.testing.expectEqual(@as(u8, 2), rule.backend_refs_count);
    try std.testing.expectEqualStrings("api-svc", rule.backend_refs[0].name.slice());
    try std.testing.expectEqualStrings("prod", rule.backend_refs[0].namespace.slice());
    try std.testing.expectEqual(@as(u16, 8080), rule.backend_refs[0].port);
    try std.testing.expectEqual(@as(u16, 90), rule.backend_refs[0].weight);

    try std.testing.expectEqualStrings("api-svc-canary", rule.backend_refs[1].name.slice());
    try std.testing.expectEqualStrings("default", rule.backend_refs[1].namespace.slice()); // defaults
    try std.testing.expectEqual(@as(u16, 10), rule.backend_refs[1].weight);
}

test "parseHTTPRouteJson - minimal route" {
    const json =
        \\{
        \\  "metadata": {"name": "minimal"},
        \\  "spec": {}
        \\}
    ;

    var route = StoredHTTPRoute.init();
    try parseHTTPRouteJson(json, &route);

    try std.testing.expectEqualStrings("minimal", route.name.slice());
    try std.testing.expectEqualStrings("default", route.namespace.slice());
    try std.testing.expectEqual(@as(u8, 0), route.hostnames_count);
    try std.testing.expectEqual(@as(u8, 0), route.rules_count);
}

test "parseHTTPRouteJson - exact path match" {
    const json =
        \\{
        \\  "metadata": {"name": "exact-route", "namespace": "default"},
        \\  "spec": {
        \\    "rules": [
        \\      {
        \\        "matches": [
        \\          {"path": {"type": "Exact", "value": "/health"}}
        \\        ],
        \\        "backendRefs": [
        \\          {"name": "health-svc", "port": 8080}
        \\        ]
        \\      }
        \\    ]
        \\  }
        \\}
    ;

    var route = StoredHTTPRoute.init();
    try parseHTTPRouteJson(json, &route);

    try std.testing.expectEqual(@as(u8, 1), route.rules_count);
    const match = &route.rules[0].matches[0];
    try std.testing.expectEqual(gw_config.PathMatch.Type.Exact, match.path.match_type);
    try std.testing.expectEqualStrings("/health", match.path.value.slice());
}

test "parseHTTPRouteJson - missing spec" {
    const json =
        \\{
        \\  "metadata": {"name": "no-spec"}
        \\}
    ;

    var route = StoredHTTPRoute.init();
    const result = parseHTTPRouteJson(json, &route);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseFilterFromJson - URLRewrite with ReplaceFullPath" {
    const filter_json = k8s_json.HTTPRouteFilterJson{
        .type = "URLRewrite",
        .urlRewrite = k8s_json.URLRewriteJson{
            .path = k8s_json.PathRewriteJson{
                .type = "ReplaceFullPath",
                .replaceFullPath = "/new/path",
            },
        },
    };

    var filter = StoredHTTPRouteFilter.init();
    parseFilterFromJson(filter_json, &filter);

    try std.testing.expectEqual(gw_config.HTTPRouteFilter.Type.URLRewrite, filter.filter_type);
    try std.testing.expect(filter.url_rewrite.has_path);
    try std.testing.expectEqual(gw_config.PathRewrite.Type.ReplaceFullPath, filter.url_rewrite.path.rewrite_type);
    try std.testing.expectEqualStrings("/new/path", filter.url_rewrite.path.value.slice());
}

// =============================================================================
// GatewayClass Parsing Tests
// =============================================================================

test "parseGatewayClassJson - basic gateway class" {
    const json =
        \\{
        \\  "apiVersion": "gateway.networking.k8s.io/v1",
        \\  "kind": "GatewayClass",
        \\  "metadata": {
        \\    "name": "serval",
        \\    "resourceVersion": "12345"
        \\  },
        \\  "spec": {
        \\    "controllerName": "serval.dev/gateway-controller"
        \\  }
        \\}
    ;

    var gc = StoredGatewayClass.init();
    try parseGatewayClassJson(json, &gc);

    try std.testing.expectEqualStrings("serval", gc.name.slice());
    try std.testing.expectEqualStrings("serval.dev/gateway-controller", gc.controller_name.slice());
    try std.testing.expect(gc.active);
}

test "parseGatewayClassJson - minimal valid JSON" {
    const json =
        \\{
        \\  "metadata": {"name": "minimal-class"},
        \\  "spec": {"controllerName": "example.com/controller"}
        \\}
    ;

    var gc = StoredGatewayClass.init();
    try parseGatewayClassJson(json, &gc);

    try std.testing.expectEqualStrings("minimal-class", gc.name.slice());
    try std.testing.expectEqualStrings("example.com/controller", gc.controller_name.slice());
    try std.testing.expect(gc.active);
}

test "parseGatewayClassJson - missing metadata" {
    const json =
        \\{
        \\  "spec": {"controllerName": "example.com/controller"}
        \\}
    ;

    var gc = StoredGatewayClass.init();
    const result = parseGatewayClassJson(json, &gc);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseGatewayClassJson - missing name" {
    const json =
        \\{
        \\  "metadata": {"resourceVersion": "123"},
        \\  "spec": {"controllerName": "example.com/controller"}
        \\}
    ;

    var gc = StoredGatewayClass.init();
    const result = parseGatewayClassJson(json, &gc);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseGatewayClassJson - missing spec" {
    const json =
        \\{
        \\  "metadata": {"name": "no-spec-class"}
        \\}
    ;

    var gc = StoredGatewayClass.init();
    const result = parseGatewayClassJson(json, &gc);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseGatewayClassJson - missing controllerName" {
    const json =
        \\{
        \\  "metadata": {"name": "no-controller-class"},
        \\  "spec": {}
        \\}
    ;

    var gc = StoredGatewayClass.init();
    const result = parseGatewayClassJson(json, &gc);
    try std.testing.expectError(WatcherError.MissingField, result);
}

test "parseGatewayClassJson - invalid JSON" {
    const json = "not valid json";

    var gc = StoredGatewayClass.init();
    const result = parseGatewayClassJson(json, &gc);
    try std.testing.expectError(WatcherError.ParseError, result);
}

test "parseGatewayClassJson - resets output before parsing" {
    // Pre-populate the output with data
    var gc = StoredGatewayClass.init();
    gc.name.set("old-name");
    gc.controller_name.set("old-controller");
    gc.active = true;

    const json =
        \\{
        \\  "metadata": {"name": "new-name"},
        \\  "spec": {"controllerName": "new-controller"}
        \\}
    ;

    try parseGatewayClassJson(json, &gc);

    // Verify old data was replaced
    try std.testing.expectEqualStrings("new-name", gc.name.slice());
    try std.testing.expectEqualStrings("new-controller", gc.controller_name.slice());
}

test "parseGatewayClassJson - long controller name" {
    // Test with a reasonably long but valid controller name
    const json =
        \\{
        \\  "metadata": {"name": "gc"},
        \\  "spec": {"controllerName": "very-long-domain.example.com/path/to/gateway-controller-implementation"}
        \\}
    ;

    var gc = StoredGatewayClass.init();
    try parseGatewayClassJson(json, &gc);

    try std.testing.expectEqualStrings("gc", gc.name.slice());
    try std.testing.expectEqualStrings("very-long-domain.example.com/path/to/gateway-controller-implementation", gc.controller_name.slice());
}
