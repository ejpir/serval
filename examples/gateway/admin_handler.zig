//! Admin API Handler for serval-server
//!
//! Implements serval-server Handler interface for K8s health probes and config API.
//! Returns direct responses without forwarding to any upstream.
//!
//! TigerStyle: Uses serval-server, bounded responses, explicit returns.

const std = @import("std");
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const types = serval_core.types;
const core_config = serval_core.config;
const Context = serval_core.Context;
const Request = types.Request;
const Upstream = types.Upstream;
const Action = types.Action;
const DirectResponse = types.DirectResponse;

const gateway = @import("serval-gateway");
const GatewayConfig = gateway.GatewayConfig;

// ============================================================================
// Admin Handler (implements serval-server Handler interface)
// ============================================================================

pub const AdminHandler = struct {
    const Self = @This();

    /// Ready flag for K8s probes (set by controller).
    ready: *std.atomic.Value(bool),

    /// Current gateway config pointer (set by controller).
    gateway_config: *?*const GatewayConfig,

    /// Response buffer for JSON responses (TigerStyle S7: bounded).
    response_buffer: [core_config.DIRECT_RESPONSE_BUFFER_SIZE_BYTES]u8,

    /// Initialize admin handler.
    ///
    /// TigerStyle S1: Assertions for preconditions.
    pub fn init(
        ready: *std.atomic.Value(bool),
        gateway_config: *?*const GatewayConfig,
    ) Self {
        assert(@intFromPtr(ready) != 0); // S1: precondition - valid pointer
        assert(@intFromPtr(gateway_config) != 0); // S1: precondition - valid pointer

        return Self{
            .ready = ready,
            .gateway_config = gateway_config,
            .response_buffer = undefined,
        };
    }

    /// Required by serval-server: select upstream for forwarding.
    /// Admin API never forwards - all requests handled by onRequest.
    ///
    /// TigerStyle: Trivial stub returning dummy value, assertion-exempt.
    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        // Never used - onRequest returns direct responses
        return Upstream{ .host = "127.0.0.1", .port = 0, .tls = false, .idx = 0 };
    }

    /// Handle admin API requests directly without forwarding.
    ///
    /// Endpoints:
    /// - GET /healthz - Liveness probe (always 200)
    /// - GET /readyz  - Readiness probe (200 if ready, 503 if not)
    /// - GET /config  - Config status (200 if configured, 503 if not)
    ///
    /// TigerStyle S1: ~2 assertions per function (pre/postconditions).
    pub fn onRequest(
        self: *Self,
        ctx: *Context,
        request: *Request,
        response_buf: []u8,
    ) Action {
        _ = ctx;
        _ = response_buf;
        assert(request.path.len > 0); // S1: precondition - non-empty path
        assert(@intFromPtr(self.ready) != 0); // S1: precondition - ready flag initialized

        const path = request.path;

        // GET /healthz - liveness probe
        if (std.mem.eql(u8, path, "/healthz") or std.mem.startsWith(u8, path, "/healthz?")) {
            return self.okResponse("OK");
        }

        // GET /readyz - readiness probe
        if (std.mem.eql(u8, path, "/readyz") or std.mem.startsWith(u8, path, "/readyz?")) {
            if (self.ready.load(.acquire)) {
                return self.okResponse("OK");
            }
            return self.errorResponse(503, "Not Ready");
        }

        // GET /config - config status
        if (std.mem.eql(u8, path, "/config") or std.mem.startsWith(u8, path, "/config?")) {
            if (self.gateway_config.* != null) {
                return self.jsonResponse(200, "{\"status\":\"configured\"}");
            }
            return self.jsonResponse(503, "{\"status\":\"not_configured\"}");
        }

        // 404 for unknown paths
        return self.errorResponse(404, "Not Found");
    }

    /// Build 200 OK response.
    ///
    /// TigerStyle: Trivial response builder, assertion-exempt.
    fn okResponse(self: *Self, body: []const u8) Action {
        _ = self;
        return Action{ .send_response = DirectResponse{
            .status = 200,
            .content_type = "text/plain",
            .body = body,
            .extra_headers = "",
        } };
    }

    /// Build error response.
    ///
    /// TigerStyle: Trivial response builder, assertion-exempt.
    fn errorResponse(self: *Self, status: u16, body: []const u8) Action {
        _ = self;
        return Action{ .send_response = DirectResponse{
            .status = status,
            .content_type = "text/plain",
            .body = body,
            .extra_headers = "",
        } };
    }

    /// Build JSON response.
    ///
    /// TigerStyle: Trivial response builder, assertion-exempt.
    fn jsonResponse(self: *Self, status: u16, body: []const u8) Action {
        _ = self;
        return Action{ .send_response = DirectResponse{
            .status = status,
            .content_type = "application/json",
            .body = body,
            .extra_headers = "",
        } };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "AdminHandler init" {
    var ready = std.atomic.Value(bool).init(false);
    var config_ptr: ?*const GatewayConfig = null;

    const handler = AdminHandler.init(&ready, &config_ptr);

    try std.testing.expectEqual(false, handler.ready.load(.acquire));
    try std.testing.expect(handler.gateway_config.* == null);
}

test "AdminHandler onRequest /healthz returns 200" {
    var ready = std.atomic.Value(bool).init(false);
    var config_ptr: ?*const GatewayConfig = null;
    var handler = AdminHandler.init(&ready, &config_ptr);

    var request = Request{
        .path = "/healthz",
    };
    var response_buf: [1024]u8 = undefined;

    const action = handler.onRequest(undefined, &request, &response_buf);

    switch (action) {
        .send_response => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
            try std.testing.expectEqualStrings("OK", resp.body);
        },
        else => try std.testing.expect(false),
    }
}

test "AdminHandler onRequest /healthz with query params returns 200" {
    var ready = std.atomic.Value(bool).init(false);
    var config_ptr: ?*const GatewayConfig = null;
    var handler = AdminHandler.init(&ready, &config_ptr);

    var request = Request{
        .path = "/healthz?verbose=true",
    };
    var response_buf: [1024]u8 = undefined;

    const action = handler.onRequest(undefined, &request, &response_buf);

    switch (action) {
        .send_response => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
        },
        else => try std.testing.expect(false),
    }
}

test "AdminHandler onRequest /readyz returns 503 when not ready" {
    var ready = std.atomic.Value(bool).init(false);
    var config_ptr: ?*const GatewayConfig = null;
    var handler = AdminHandler.init(&ready, &config_ptr);

    var request = Request{
        .path = "/readyz",
    };
    var response_buf: [1024]u8 = undefined;

    const action = handler.onRequest(undefined, &request, &response_buf);

    switch (action) {
        .send_response => |resp| {
            try std.testing.expectEqual(@as(u16, 503), resp.status);
            try std.testing.expectEqualStrings("Not Ready", resp.body);
        },
        else => try std.testing.expect(false),
    }
}

test "AdminHandler onRequest /readyz returns 200 when ready" {
    var ready = std.atomic.Value(bool).init(true);
    var config_ptr: ?*const GatewayConfig = null;
    var handler = AdminHandler.init(&ready, &config_ptr);

    var request = Request{
        .path = "/readyz",
    };
    var response_buf: [1024]u8 = undefined;

    const action = handler.onRequest(undefined, &request, &response_buf);

    switch (action) {
        .send_response => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
            try std.testing.expectEqualStrings("OK", resp.body);
        },
        else => try std.testing.expect(false),
    }
}

test "AdminHandler onRequest /config returns 503 when not configured" {
    var ready = std.atomic.Value(bool).init(false);
    var config_ptr: ?*const GatewayConfig = null;
    var handler = AdminHandler.init(&ready, &config_ptr);

    var request = Request{
        .path = "/config",
    };
    var response_buf: [1024]u8 = undefined;

    const action = handler.onRequest(undefined, &request, &response_buf);

    switch (action) {
        .send_response => |resp| {
            try std.testing.expectEqual(@as(u16, 503), resp.status);
            try std.testing.expectEqualStrings("application/json", resp.content_type);
            try std.testing.expectEqualStrings("{\"status\":\"not_configured\"}", resp.body);
        },
        else => try std.testing.expect(false),
    }
}

test "AdminHandler onRequest unknown path returns 404" {
    var ready = std.atomic.Value(bool).init(false);
    var config_ptr: ?*const GatewayConfig = null;
    var handler = AdminHandler.init(&ready, &config_ptr);

    var request = Request{
        .path = "/unknown",
    };
    var response_buf: [1024]u8 = undefined;

    const action = handler.onRequest(undefined, &request, &response_buf);

    switch (action) {
        .send_response => |resp| {
            try std.testing.expectEqual(@as(u16, 404), resp.status);
            try std.testing.expectEqualStrings("Not Found", resp.body);
        },
        else => try std.testing.expect(false),
    }
}

test "AdminHandler selectUpstream returns dummy upstream" {
    var ready = std.atomic.Value(bool).init(false);
    var config_ptr: ?*const GatewayConfig = null;
    var handler = AdminHandler.init(&ready, &config_ptr);

    const request = Request{
        .path = "/healthz",
    };

    const upstream = handler.selectUpstream(undefined, &request);

    // Should return a valid (but dummy) upstream
    try std.testing.expectEqualStrings("127.0.0.1", upstream.host);
    try std.testing.expectEqual(@as(u16, 0), upstream.port);
    try std.testing.expect(!upstream.tls);
}
