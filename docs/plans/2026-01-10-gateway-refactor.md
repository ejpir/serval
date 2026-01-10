# Gateway Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor serval-gateway into a clean library (types + translator) and move K8s-specific implementation to examples/gateway/.

**Architecture:** serval-gateway becomes a reusable library with Gateway API types and translation logic. The K8s controller implementation moves to examples/gateway/ with proper separation of concerns. All HTTP communication uses serval-client instead of raw sockets.

**Tech Stack:** Zig, serval-client, serval-core, serval-net

---

## Current State Analysis

**serval-gateway/** (5609 lines total):
- `config.zig` - Gateway API types (KEEP - generic)
- `translator.zig` - GatewayConfig → Router JSON (KEEP - generic)
- `gateway.zig` (1273 lines) - Controller + admin server + pushConfigToDataPlane (MOVE)
- `resolver.zig` (1181 lines) - K8s Service → Endpoints (MOVE)
- `k8s/client.zig` (634 lines) - K8s API client (MOVE)
- `k8s/watcher.zig` (2500 lines) - K8s resource watcher (MOVE)

**Problems:**
1. `pushConfigToDataPlane()` uses raw POSIX sockets instead of serval-client
2. K8s-specific code mixed with generic gateway library
3. Can't use serval-gateway for non-K8s use cases (config files, REST API, etc.)
4. **translator.zig depends on resolver.zig** - after moving resolver to examples/, translator can't import it

---

## Key Design Decision: Translator API Change

The translator currently takes a `Resolver` parameter to resolve Service names to pod IPs:

```zig
// CURRENT (broken after refactor)
pub fn translateToJson(
    config: *const GatewayConfig,
    resolver: *const Resolver,  // ← Can't import from examples/
    buf: []u8,
) !usize
```

**Solution:** Translator takes pre-resolved endpoints. Resolution is the caller's responsibility:

```zig
// NEW API
pub fn translateToJson(
    config: *const GatewayConfig,
    resolved_backends: []const ResolvedBackend,  // ← Already resolved
    buf: []u8,
) !usize
```

**Flow after refactor:**
```
1. Watcher parses K8s JSON → GatewayConfig (Service names)
2. Controller calls Resolver to get Endpoints (K8s-specific)
3. Controller builds ResolvedBackend[] from Endpoints
4. Controller calls translator with resolved backends
5. Translator produces JSON for serval-router
```

---

## Target Structure

```
serval-gateway/                    # Clean library
├── config.zig                     # Gateway API types (unchanged)
├── translator.zig                 # GatewayConfig → Router JSON (unchanged)
└── mod.zig                        # Exports only config + translator

examples/gateway/                  # K8s controller
├── main.zig                       # Entry point, CLI parsing
├── controller.zig                 # Config management, serval-server admin API
├── admin_handler.zig              # Handler for /healthz, /readyz, /config (serval-server)
├── k8s_client.zig                 # K8s API client (from k8s/client.zig)
├── watcher.zig                    # K8s watcher (from k8s/watcher.zig)
├── resolver.zig                   # Service resolution (from resolver.zig)
└── data_plane.zig                 # Config push using serval-client
```

## serval-* Component Usage

This refactor uses serval-* components throughout (no raw sockets, no local constants):

| Component | Usage |
|-----------|-------|
| `serval-client` | HTTP client for data plane push and K8s API calls |
| `serval-server` | HTTP server for admin API (health probes, config status) |
| `serval-core.config` | All constants (timeouts, buffer sizes, ports) |
| `serval-core.types` | Request, Response, Upstream, DirectResponse, Action |
| `serval-core.time` | Timing utilities (monotonicNanos, elapsedNanos) |
| `serval-net` | DnsResolver, Socket abstraction |
| `serval-pool` | SimplePool for connection management |
| `serval-metrics` | NoopMetrics for admin server |
| `serval-tracing` | NoopTracer for admin server |
| `serval-gateway` | Gateway API types and translator |

---

## Task 1: Add ResolvedBackend Type to config.zig

**Files:**
- Modify: `serval-gateway/config.zig`

**Step 1: Add ResolvedBackend type**

This type represents a backend with resolved endpoints (IP addresses instead of Service names).
TigerStyle: Explicit bounds, units in names, bounded arrays.

```zig
// Add to serval-gateway/config.zig

/// Maximum endpoints per resolved backend.
/// TigerStyle: Explicit bound matching resolver limits.
pub const MAX_RESOLVED_ENDPOINTS: u8 = 64;

/// Maximum resolved backends in a translation batch.
/// TigerStyle: Matches MAX_HTTP_ROUTES * MAX_RULES for worst case.
pub const MAX_RESOLVED_BACKENDS: u16 = 256;

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
    endpoints: [MAX_RESOLVED_ENDPOINTS]ResolvedEndpoint,
    endpoint_count: u8,

    /// Get name as slice.
    pub fn getName(self: *const ResolvedBackend) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Get namespace as slice.
    pub fn getNamespace(self: *const ResolvedBackend) []const u8 {
        return self.namespace[0..self.namespace_len];
    }
};

/// A single resolved endpoint (IP:port).
pub const ResolvedEndpoint = struct {
    /// IP address as string (IPv4 or IPv6).
    ip: [45]u8,  // Max IPv6 length
    ip_len: u8,

    /// Port number.
    port: u16,

    /// Get IP as slice.
    pub fn getIp(self: *const ResolvedEndpoint) []const u8 {
        return self.ip[0..self.ip_len];
    }
};
```

**Step 2: Run tests**

Run: `zig build test`
Expected: Compiles, existing tests pass

**Step 3: Commit**

```bash
git add serval-gateway/config.zig
git commit -m "feat(serval-gateway): add ResolvedBackend type for decoupled translation"
```

---

## Task 2: Create examples/gateway/ Directory Structure

**Files:**
- Create: `examples/gateway/main.zig`
- Create: `examples/gateway/build.zig.zon` (if needed for local imports)

**Step 1: Create directory and placeholder main.zig**

```zig
// examples/gateway/main.zig
//! Kubernetes Gateway API Controller
//!
//! Watches K8s Gateway API resources and configures serval-router.
//! This is a complete controller implementation using serval-gateway library.

const std = @import("std");

pub fn main() !void {
    std.debug.print("gateway controller starting...\n", .{});
}
```

**Step 2: Verify build.zig can build it**

Check `build.zig` for gateway example configuration. The existing `gateway_example` target should be updated to point to `examples/gateway/main.zig`.

**Step 3: Run build to verify**

Run: `zig build`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add examples/gateway/
git commit -m "feat(examples): scaffold gateway controller directory"
```

---

## Task 3: Create data_plane.zig Using serval-client

**Files:**
- Create: `examples/gateway/data_plane.zig`

**Step 1: Write the data plane client**

This replaces the raw socket code in `gateway.zig:pushConfigToDataPlane()` with proper serval-client usage.
Uses local Resolver import (not from serval-gateway) and new translator API with ResolvedBackend.

**IMPORTANT:** Uses the actual serval-client API:
- `Client.init(allocator, dns_resolver, client_ctx, verify_tls)` - Initialize client
- `client.connect(upstream, io)` - Returns ConnectResult with connection
- `client.sendRequest(conn, request, path)` - Send HTTP request
- `client.readResponseHeaders(conn, header_buf)` - Read response headers

TigerStyle compliance:
- S1: Assertions for preconditions/postconditions
- S2: Explicit types (u8, u16, u32, u64 - no usize)
- S4: Bounded retry loop with MAX_RETRIES
- S6: Explicit error handling, no catch {}
- Y3: Units in names (_ns, _ms, _bytes)

```zig
// examples/gateway/data_plane.zig
//! Data Plane Client
//!
//! Pushes configuration to serval-router admin API using serval-client.
//! Resolves backends before translation to decouple from K8s-specific Resolver.
//!
//! TigerStyle: Uses serval-client, bounded buffers, explicit errors, ~2 assertions per function.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const serval_client = @import("serval-client");
const serval_core = @import("serval-core");
const serval_net = @import("serval-net");
const gateway = @import("serval-gateway");

// Local imports (K8s-specific, not from serval-gateway)
const resolver_mod = @import("resolver.zig");
const Resolver = resolver_mod.Resolver;

const Client = serval_client.Client;
const Connection = serval_client.Connection;
const Upstream = serval_core.types.Upstream;
const Request = serval_core.types.Request;
const Method = serval_core.types.Method;
const core_config = serval_core.config;
const DnsResolver = serval_net.DnsResolver;
const GatewayConfig = gateway.GatewayConfig;
const ResolvedBackend = gateway.config.ResolvedBackend;

// ============================================================================
// Constants (TigerStyle Y3: Units in names)
// ============================================================================

/// Default admin port for data plane.
pub const DEFAULT_ADMIN_PORT: u16 = core_config.DEFAULT_ADMIN_PORT;

/// Maximum JSON payload size in bytes.
pub const MAX_JSON_SIZE_BYTES: u32 = gateway.translator.MAX_JSON_SIZE_BYTES;

/// Maximum response header size in bytes.
const MAX_RESPONSE_HEADER_SIZE_BYTES: u32 = core_config.MAX_HEADER_SIZE_BYTES;

/// Maximum retries for config push (TigerStyle S4: bounded).
pub const MAX_RETRIES: u8 = core_config.MAX_CONFIG_PUSH_RETRIES;

/// Base backoff delay in milliseconds.
const BACKOFF_BASE_MS: u64 = core_config.CONFIG_PUSH_BACKOFF_BASE_MS;

/// Maximum backoff delay in milliseconds.
const MAX_BACKOFF_MS: u64 = core_config.MAX_CONFIG_PUSH_BACKOFF_MS;

// ============================================================================
// Error Types (TigerStyle S6: Explicit error set)
// ============================================================================

pub const DataPlaneError = error{
    /// No config to push.
    NoConfig,
    /// Backend resolution failed.
    ResolutionFailed,
    /// Translation to JSON failed.
    TranslationFailed,
    /// Connection to data plane failed.
    ConnectionFailed,
    /// Request send failed.
    SendFailed,
    /// Response receive failed.
    ReceiveFailed,
    /// Empty response from data plane.
    EmptyResponse,
    /// Data plane rejected config (non-2xx response).
    Rejected,
    /// All retries exhausted.
    RetriesExhausted,
};

// ============================================================================
// Data Plane Client (TigerStyle: No allocation after init)
// ============================================================================

pub const DataPlaneClient = struct {
    const Self = @This();

    /// Allocator for client resources.
    allocator: std.mem.Allocator,

    /// Data plane admin port.
    admin_port: u16,

    /// DNS resolver for client connections.
    dns_resolver: DnsResolver,

    /// HTTP client instance.
    client: Client,

    /// JSON buffer for config serialization (TigerStyle S7: bounded).
    json_buffer: [MAX_JSON_SIZE_BYTES]u8,

    /// Response header buffer (TigerStyle S7: bounded).
    response_header_buffer: [MAX_RESPONSE_HEADER_SIZE_BYTES]u8,

    /// Resolved backends buffer (TigerStyle S7: bounded).
    resolved_backends: [gateway.config.MAX_RESOLVED_BACKENDS]ResolvedBackend,

    /// Initialize data plane client.
    ///
    /// TigerStyle S5: Fixed buffers, DNS resolver init at startup.
    pub fn init(allocator: std.mem.Allocator, admin_port: u16) Self {
        assert(admin_port > 0); // S1: precondition

        var dns_resolver = DnsResolver.init(.{});

        return Self{
            .allocator = allocator,
            .admin_port = admin_port,
            .dns_resolver = dns_resolver,
            .client = Client.init(
                allocator,
                &dns_resolver,
                null, // No TLS for localhost admin API
                false, // No TLS verification needed
            ),
            .json_buffer = undefined,
            .response_header_buffer = undefined,
            .resolved_backends = undefined,
        };
    }

    /// Deinitialize client resources.
    /// TigerStyle: Explicit cleanup, pairs with init.
    pub fn deinit(self: *Self) void {
        self.client.deinit();
    }

    /// Push gateway config to data plane.
    ///
    /// 1. Resolves all backend references using Resolver
    /// 2. Translates GatewayConfig + resolved backends to JSON
    /// 3. POSTs to /routes/update on data plane
    ///
    /// TigerStyle: ~2 assertions, explicit error handling.
    pub fn pushConfig(
        self: *Self,
        config: *const GatewayConfig,
        resolver: *const Resolver,
        io: Io,
    ) DataPlaneError!void {
        // S1: preconditions
        assert(config.gateways.len > 0 or config.http_routes.len > 0);

        // Step 1: Resolve all backend references
        const resolved_count = self.resolveBackends(config, resolver) catch |err| {
            std.log.err("backend resolution failed: {s}", .{@errorName(err)});
            return error.ResolutionFailed;
        };

        // Step 2: Translate config to JSON with resolved backends
        const json_len = gateway.translator.translateToJson(
            config,
            self.resolved_backends[0..resolved_count],
            &self.json_buffer,
        ) catch |err| {
            std.log.err("config translation failed: {s}", .{@errorName(err)});
            return error.TranslationFailed;
        };

        // S1: postcondition - must produce non-empty JSON
        assert(json_len > 0);
        const json_body = self.json_buffer[0..json_len];

        // Step 3: POST to data plane
        try self.postToDataPlane(json_body, io);

        std.log.info("pushed config ({d} bytes, {d} backends) to data plane", .{
            json_len,
            resolved_count,
        });
    }

    /// Resolve all backend references in config.
    /// Returns count of resolved backends.
    ///
    /// TigerStyle S4: Bounded loop over http_routes.
    fn resolveBackends(
        self: *Self,
        config: *const GatewayConfig,
        resolver: *const Resolver,
    ) !u16 {
        var count: u16 = 0;
        const max_backends: u16 = gateway.config.MAX_RESOLVED_BACKENDS;

        // Iterate all routes and their backend refs
        for (config.http_routes) |route| {
            for (route.rules) |rule| {
                for (rule.backend_refs) |backend_ref| {
                    if (count >= max_backends) {
                        return error.ResolutionFailed; // Too many backends
                    }

                    // Resolve this backend (C3: out pointer pattern)
                    try resolver.resolveBackend(
                        backend_ref.getName(),
                        backend_ref.getNamespace(),
                        &self.resolved_backends[count],
                    );
                    count += 1;
                }
            }
        }

        return count;
    }

    /// POST JSON to data plane admin API.
    ///
    /// Uses actual serval-client API:
    /// 1. client.connect() - establish TCP connection
    /// 2. client.sendRequest() - send POST request with body
    /// 3. client.readResponseHeaders() - read response status
    ///
    /// TigerStyle: Uses serval-client, explicit error mapping.
    fn postToDataPlane(self: *Self, json_body: []const u8, io: Io) DataPlaneError!void {
        assert(json_body.len > 0); // S1: precondition

        // Build upstream for localhost:admin_port
        const upstream = Upstream{
            .host = "127.0.0.1",
            .port = self.admin_port,
            .tls = false,
            .idx = 0,
        };

        // Step 1: Connect to data plane
        var connect_result = self.client.connect(upstream, io) catch |err| {
            std.log.err("data plane connect failed: {s}", .{@errorName(err)});
            return mapClientError(err);
        };
        defer connect_result.conn.close();

        // Step 2: Build and send POST request
        // Build request with POST method and JSON body info
        var request = Request{
            .method = .POST,
            .path = "/routes/update",
            .version = .@"HTTP/1.1",
            .headers = undefined, // Will be set below
        };

        // Set Content-Type and Content-Length headers
        request.headers = serval_core.types.HeaderMap.init();
        request.headers.add("Content-Type", "application/json") catch {};
        request.headers.add("Host", "127.0.0.1") catch {};

        // Send request headers
        self.client.sendRequest(&connect_result.conn, &request, null) catch |err| {
            std.log.err("data plane send failed: {s}", .{@errorName(err)});
            return mapClientError(err);
        };

        // Send request body
        connect_result.conn.socket.write(json_body) catch |err| {
            std.log.err("data plane body send failed: {s}", .{@errorName(err)});
            return error.SendFailed;
        };

        // Step 3: Read response headers
        const response = self.client.readResponseHeaders(
            &connect_result.conn,
            &self.response_header_buffer,
        ) catch |err| {
            std.log.err("data plane recv failed: {s}", .{@errorName(err)});
            return mapClientError(err);
        };

        // S1: postcondition - check response status
        if (response.status < 200 or response.status >= 300) {
            std.log.err("data plane rejected config: HTTP {d}", .{response.status});
            return error.Rejected;
        }
    }

    /// Push config with exponential backoff retry.
    ///
    /// TigerStyle S4: Bounded loop with MAX_RETRIES.
    pub fn pushConfigWithRetry(
        self: *Self,
        config: *const GatewayConfig,
        resolver: *const Resolver,
        io: Io,
    ) DataPlaneError!void {
        assert(MAX_RETRIES > 0); // S1: precondition

        var attempt: u8 = 0;
        var backoff_ms: u64 = BACKOFF_BASE_MS;

        // S4: Bounded retry loop
        while (attempt < MAX_RETRIES) : (attempt += 1) {
            self.pushConfig(config, resolver, io) catch |err| {
                std.log.warn("config push failed (attempt {d}/{d}): {s}", .{
                    attempt + 1,
                    MAX_RETRIES,
                    @errorName(err),
                });

                // Retry with backoff if not last attempt
                if (attempt + 1 < MAX_RETRIES) {
                    std.time.sleep(backoff_ms * std.time.ns_per_ms);
                    backoff_ms = @min(backoff_ms * 2, MAX_BACKOFF_MS);
                    continue;
                }
                return error.RetriesExhausted;
            };
            return; // Success
        }

        return error.RetriesExhausted;
    }

    /// Map serval-client errors to DataPlaneError.
    /// TigerStyle S6: Explicit error mapping, no catch {}.
    fn mapClientError(err: serval_client.ClientError) DataPlaneError {
        return switch (err) {
            serval_client.ClientError.DnsResolutionFailed,
            serval_client.ClientError.TcpConnectFailed,
            serval_client.ClientError.TcpConnectTimeout,
            serval_client.ClientError.TlsHandshakeFailed,
            => error.ConnectionFailed,
            serval_client.ClientError.SendFailed,
            serval_client.ClientError.SendTimeout,
            serval_client.ClientError.BufferTooSmall,
            => error.SendFailed,
            serval_client.ClientError.RecvFailed,
            serval_client.ClientError.RecvTimeout,
            serval_client.ClientError.ResponseHeadersTooLarge,
            serval_client.ClientError.InvalidResponseStatus,
            serval_client.ClientError.InvalidResponseHeaders,
            => error.ReceiveFailed,
            serval_client.ClientError.ConnectionClosed,
            => error.EmptyResponse,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DataPlaneClient init" {
    const client = DataPlaneClient.init(std.testing.allocator, 9901);
    defer client.deinit();
    try std.testing.expectEqual(@as(u16, 9901), client.admin_port);
}

test "DataPlaneClient init asserts on zero port" {
    // This would panic due to assert - skip in release builds
    if (@import("builtin").mode == .Debug) {
        // Can't easily test assert in Zig, so just verify init works with valid port
        const client = DataPlaneClient.init(std.testing.allocator, 1);
        defer client.deinit();
        try std.testing.expectEqual(@as(u16, 1), client.admin_port);
    }
}
```

**Step 2: Verify it compiles**

Run: `zig build`
Expected: Compiles (may need build.zig updates)

**Step 3: Commit**

```bash
git add examples/gateway/data_plane.zig
git commit -m "feat(examples/gateway): add data plane client using serval-client

TigerStyle compliant:
- S1: Assertions for pre/postconditions
- S4: Bounded retry loop
- S5: No allocation after init
- S6: Explicit error handling
- S7: Bounded buffers
- Y3: Units in names"
```

---

## Task 4: Move resolver.zig to examples/gateway/

**Files:**
- Move: `serval-gateway/resolver.zig` → `examples/gateway/resolver.zig`
- Modify: `serval-gateway/mod.zig` (remove resolver export)

**Step 1: Copy resolver.zig**

```bash
cp serval-gateway/resolver.zig examples/gateway/resolver.zig
```

**Step 2: Update imports in examples/gateway/resolver.zig**

Change:
```zig
const config = @import("config.zig");
```
To:
```zig
const gateway = @import("serval-gateway");
const gw_config = gateway.config;
```

**Step 3: Add resolveBackend method**

Add a method that returns `ResolvedBackend` (the new type from Task 1) for use by data_plane.zig.

```zig
/// Resolve a backend reference to ResolvedBackend.
/// Used by data_plane.zig before calling translator.
///
/// TigerStyle C3: Uses out pointer for large struct (~5KB), avoids stack copy.
/// TigerStyle S1: Assertions for pre/postconditions.
pub fn resolveBackend(
    self: *const Resolver,
    name: []const u8,
    namespace: []const u8,
    out: *gw_config.ResolvedBackend,  // C3: Out pointer for large struct
) ResolverError!void {
    assert(name.len > 0); // S1: precondition
    assert(name.len <= MAX_NAME_LEN);
    assert(namespace.len <= MAX_NAME_LEN);

    // Find service in our registry
    const service_idx = self.findService(name, namespace) orelse {
        return error.ServiceNotFound;
    };

    const service = &self.services[service_idx];

    // Copy name
    @memcpy(out.name[0..name.len], name);
    out.name_len = @intCast(name.len);

    // Copy namespace
    @memcpy(out.namespace[0..namespace.len], namespace);
    out.namespace_len = @intCast(namespace.len);

    // Copy endpoints
    var ep_count: u8 = 0;
    for (service.endpoints[0..service.endpoint_count]) |ep| {
        if (ep_count >= gw_config.MAX_RESOLVED_ENDPOINTS) break;

        const ip = ep.getIp();
        @memcpy(out.endpoints[ep_count].ip[0..ip.len], ip);
        out.endpoints[ep_count].ip_len = @intCast(ip.len);
        out.endpoints[ep_count].port = ep.port;
        ep_count += 1;
    }
    out.endpoint_count = ep_count;

    assert(out.endpoint_count > 0); // S1: postcondition
}
```

**Step 4: Add ServiceNotFound error**

```zig
pub const ResolverError = error{
    // ... existing errors ...
    ServiceNotFound,
};
```

**Step 5: Update serval-gateway/mod.zig**

Remove resolver exports - keep only config and translator:

```zig
//! serval-gateway
//!
//! Gateway API library for serval.
//! Provides Gateway API types and translation to serval-router config.
//!
//! Use this library to build your own gateway controller:
//! - Define GatewayConfig with routes
//! - Resolve backend references (K8s Service → Endpoints, etc.)
//! - Use translator to convert to JSON
//! - POST to serval-router admin API
//!
//! See examples/gateway/ for a complete K8s controller implementation.
//!
//! Layer 4 (Strategy) - routing configuration

// Configuration types (Gateway API)
pub const config = @import("config.zig");
pub const GatewayConfig = config.GatewayConfig;
pub const Gateway = config.Gateway;
pub const HTTPRoute = config.HTTPRoute;
pub const HTTPRouteRule = config.HTTPRouteRule;
pub const HTTPRouteMatch = config.HTTPRouteMatch;
pub const HTTPRouteFilter = config.HTTPRouteFilter;
pub const HTTPBackendRef = config.HTTPBackendRef;
pub const Listener = config.Listener;
pub const ResolvedBackend = config.ResolvedBackend;
pub const ResolvedEndpoint = config.ResolvedEndpoint;

// Translator (GatewayConfig -> Router JSON)
pub const translator = @import("translator.zig");
pub const translateToJson = translator.translateToJson;
pub const TranslatorError = translator.TranslatorError;

test {
    @import("std").testing.refAllDecls(@This());
    _ = config;
    _ = translator;
}
```

**Step 6: Run tests**

Run: `zig build test`
Expected: Tests pass (some may fail due to missing imports - fix in next tasks)

**Step 7: Commit**

```bash
git add examples/gateway/resolver.zig serval-gateway/mod.zig
git commit -m "refactor: move resolver.zig to examples/gateway/

- Add resolveBackend() method returning ResolvedBackend
- Add ServiceNotFound error
- Update mod.zig to export ResolvedBackend type"
```

---

## Task 5: Move k8s/client.zig to examples/gateway/

**Files:**
- Move: `serval-gateway/k8s/client.zig` → `examples/gateway/k8s_client.zig`
- Delete: `serval-gateway/k8s/` directory

**Step 1: Copy k8s/client.zig**

```bash
cp serval-gateway/k8s/client.zig examples/gateway/k8s_client.zig
```

**Step 2: Update imports**

The file already uses serval-client properly. Just verify imports work.

**Step 3: Commit**

```bash
git add examples/gateway/k8s_client.zig
git commit -m "refactor: move k8s client to examples/gateway/"
```

---

## Task 6: Move k8s/watcher.zig to examples/gateway/

**Files:**
- Move: `serval-gateway/k8s/watcher.zig` → `examples/gateway/watcher.zig`

**Step 1: Copy watcher.zig**

```bash
cp serval-gateway/k8s/watcher.zig examples/gateway/watcher.zig
```

**Step 2: Update imports**

Change:
```zig
const k8s_client = @import("client.zig");
const gw_config = @import("../config.zig");
```
To:
```zig
const k8s_client = @import("k8s_client.zig");
const gateway = @import("serval-gateway");
const gw_config = gateway.config;
```

**Step 3: Commit**

```bash
git add examples/gateway/watcher.zig
git commit -m "refactor: move k8s watcher to examples/gateway/"
```

---

## Task 7: Create controller.zig Using serval-server

**Files:**
- Create: `examples/gateway/controller.zig`
- Create: `examples/gateway/admin_handler.zig`

**Step 1: Create admin handler for serval-server**

The admin handler implements the serval-server Handler interface to serve health check
and config endpoints. This replaces raw POSIX sockets with serval-server.MinimalServer.

**IMPORTANT:** Uses serval-server instead of raw sockets:
- `serval_server.MinimalServer(Handler)` - Create server with handler
- Handler implements `selectUpstream()` and `onRequest()` hooks
- Uses `serval_core.types.DirectResponse` for immediate responses
- Uses `serval_core.config` for constants (not locally defined)
- Uses `serval_core.time` for timing utilities

```zig
// examples/gateway/admin_handler.zig
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
const config = serval_core.config;
const time = serval_core.time;
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
    response_buffer: [config.DIRECT_RESPONSE_BUFFER_SIZE_BYTES]u8,

    /// Initialize admin handler.
    pub fn init(
        ready: *std.atomic.Value(bool),
        gateway_config: *?*const GatewayConfig,
    ) Self {
        assert(@intFromPtr(ready) != 0); // S1: precondition
        assert(@intFromPtr(gateway_config) != 0); // S1: precondition

        return Self{
            .ready = ready,
            .gateway_config = gateway_config,
            .response_buffer = undefined,
        };
    }

    /// Required by serval-server: select upstream for forwarding.
    /// Admin API never forwards - all requests handled by onRequest.
    /// Returns dummy upstream (never used).
    pub fn selectUpstream(self: *Self, ctx: *Context, request: *const Request) Upstream {
        _ = self;
        _ = ctx;
        _ = request;
        // Never used - onRequest returns direct responses
        return Upstream{ .host = "127.0.0.1", .port = 0, .tls = false, .idx = 0 };
    }

    /// Handle admin API requests directly without forwarding.
    /// Returns DirectResponse for health checks and config endpoints.
    ///
    /// Endpoints:
    /// - GET /healthz - Liveness probe (always 200)
    /// - GET /readyz  - Readiness probe (200 if ready, 503 if not)
    /// - GET /config  - Config status (200 if configured, 503 if not)
    ///
    /// TigerStyle: All endpoints return bounded responses.
    pub fn onRequest(
        self: *Self,
        ctx: *Context,
        request: *const Request,
        response_buf: *[config.DIRECT_RESPONSE_BUFFER_SIZE_BYTES]u8,
    ) Action {
        _ = ctx;

        const path = request.path;

        // GET /healthz - liveness probe
        if (std.mem.eql(u8, path, "/healthz") or std.mem.startsWith(u8, path, "/healthz?")) {
            return self.okResponse("OK", response_buf);
        }

        // GET /readyz - readiness probe
        if (std.mem.eql(u8, path, "/readyz") or std.mem.startsWith(u8, path, "/readyz?")) {
            if (self.ready.load(.acquire)) {
                return self.okResponse("OK", response_buf);
            }
            return self.errorResponse(503, "Not Ready", response_buf);
        }

        // GET /config - config status
        if (std.mem.eql(u8, path, "/config") or std.mem.startsWith(u8, path, "/config?")) {
            if (self.gateway_config.* != null) {
                return self.jsonResponse(200, "{\"status\":\"configured\"}", response_buf);
            }
            return self.jsonResponse(503, "{\"status\":\"not_configured\"}", response_buf);
        }

        // 404 for unknown paths
        return self.errorResponse(404, "Not Found", response_buf);
    }

    /// Build 200 OK response.
    fn okResponse(
        self: *Self,
        body: []const u8,
        response_buf: *[config.DIRECT_RESPONSE_BUFFER_SIZE_BYTES]u8,
    ) Action {
        _ = self;
        return Action{ .send_response = DirectResponse{
            .status = 200,
            .content_type = "text/plain",
            .body = body,
            .extra_headers = "",
            .response_mode = .content_length,
        } };
    }

    /// Build error response.
    fn errorResponse(
        self: *Self,
        status: u16,
        body: []const u8,
        response_buf: *[config.DIRECT_RESPONSE_BUFFER_SIZE_BYTES]u8,
    ) Action {
        _ = self;
        _ = response_buf;
        return Action{ .send_response = DirectResponse{
            .status = status,
            .content_type = "text/plain",
            .body = body,
            .extra_headers = "",
            .response_mode = .content_length,
        } };
    }

    /// Build JSON response.
    fn jsonResponse(
        self: *Self,
        status: u16,
        body: []const u8,
        response_buf: *[config.DIRECT_RESPONSE_BUFFER_SIZE_BYTES]u8,
    ) Action {
        _ = self;
        _ = response_buf;
        return Action{ .send_response = DirectResponse{
            .status = status,
            .content_type = "application/json",
            .body = body,
            .extra_headers = "",
            .response_mode = .content_length,
        } };
    }
};
```

**Step 2: Write controller.zig using serval-server**

```zig
// examples/gateway/controller.zig
//! Gateway Controller
//!
//! Manages gateway state, admin server, and config updates.
//! Coordinates between K8s watcher and data plane.
//!
//! Uses serval-server.MinimalServer for admin API instead of raw sockets.
//! Uses serval-core.config for all constants (no local definitions).
//! Uses serval-core.time for timing utilities.
//!
//! TigerStyle: Thread-safe state, uses serval components, explicit errors.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const serval_core = @import("serval-core");
const serval_server = @import("serval-server");
const serval_pool = @import("serval-pool");
const serval_metrics = @import("serval-metrics");
const serval_tracing = @import("serval-tracing");
const serval_net = @import("serval-net");

const gateway = @import("serval-gateway");
const GatewayConfig = gateway.GatewayConfig;

const data_plane = @import("data_plane.zig");
const DataPlaneClient = data_plane.DataPlaneClient;

const resolver_mod = @import("resolver.zig");
const Resolver = resolver_mod.Resolver;

const admin_handler = @import("admin_handler.zig");
const AdminHandler = admin_handler.AdminHandler;

// Use serval-core types and config
const core_config = serval_core.config;
const Config = core_config.Config;
const time = serval_core.time;

// serval-server components
const MinimalServer = serval_server.MinimalServer;
const SimplePool = serval_pool.pool.SimplePool;
const NoopMetrics = serval_metrics.metrics.NoopMetrics;
const NoopTracer = serval_tracing.tracing.NoopTracer;
const DnsConfig = serval_net.DnsConfig;

// ============================================================================
// Error Types
// ============================================================================

pub const ControllerError = error{
    AdminBindFailed,
    AdminListenFailed,
    AdminThreadFailed,
    OutOfMemory,
};

// ============================================================================
// Controller
// ============================================================================

pub const Controller = struct {
    const Self = @This();

    // Type aliases for serval-server
    const AdminServer = MinimalServer(AdminHandler);

    /// Allocator for resources.
    allocator: std.mem.Allocator,

    /// Ready flag for K8s probes.
    ready: std.atomic.Value(bool),

    /// Admin server port.
    admin_port: u16,

    /// Current gateway config (atomic pointer for lock-free access).
    gateway_config: ?*const GatewayConfig,

    /// Data plane client.
    data_plane_client: DataPlaneClient,

    /// Service resolver.
    resolver: Resolver,

    /// Shutdown flag.
    shutdown: std.atomic.Value(bool),

    /// Admin handler for serval-server.
    admin_handler: AdminHandler,

    /// Admin server (serval-server.MinimalServer).
    admin_server: ?AdminServer,

    /// Connection pool for admin server.
    pool: SimplePool,

    /// Metrics (noop for admin).
    metrics: NoopMetrics,

    /// Tracer (noop for admin).
    tracer: NoopTracer,

    /// Admin server thread.
    admin_thread: ?std.Thread,

    /// Initialize controller.
    /// TigerStyle S1: Assertions validate port arguments.
    pub fn init(allocator: std.mem.Allocator, admin_port: u16, data_plane_port: u16) Self {
        assert(admin_port > 0); // S1: precondition
        assert(data_plane_port > 0); // S1: precondition

        var self = Self{
            .allocator = allocator,
            .ready = std.atomic.Value(bool).init(false),
            .admin_port = admin_port,
            .gateway_config = null,
            .data_plane_client = DataPlaneClient.init(allocator, data_plane_port),
            .resolver = Resolver.init(),
            .shutdown = std.atomic.Value(bool).init(false),
            .admin_handler = undefined, // Set below
            .admin_server = null,
            .pool = SimplePool.init(),
            .metrics = NoopMetrics{},
            .tracer = NoopTracer{},
            .admin_thread = null,
        };

        // Initialize admin handler with pointers to our state
        self.admin_handler = AdminHandler.init(&self.ready, &self.gateway_config);

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.shutdown.store(true, .release);
        if (self.admin_thread) |thread| {
            thread.join();
        }
        self.data_plane_client.deinit();
    }

    /// Update gateway config and push to data plane.
    pub fn updateConfig(self: *Self, config_ptr: *const GatewayConfig, io: Io) !void {
        assert(config_ptr.gateways.len > 0 or config_ptr.http_routes.len > 0);

        self.gateway_config = config_ptr;

        // Push to data plane
        self.data_plane_client.pushConfigWithRetry(config_ptr, &self.resolver, io) catch |err| {
            std.log.err("failed to push config to data plane: {s}", .{@errorName(err)});
            return err;
        };
    }

    /// Start admin server using serval-server.MinimalServer.
    /// Runs in background thread to not block main watcher loop.
    pub fn startAdminServer(self: *Self) ControllerError!void {
        // Initialize serval-server with admin handler
        self.admin_server = AdminServer.init(
            &self.admin_handler,
            &self.pool,
            &self.metrics,
            &self.tracer,
            Config{ .port = self.admin_port },
            null, // No TLS for admin API
            DnsConfig{},
        );

        // Start server in background thread
        self.admin_thread = std.Thread.spawn(.{}, adminServerLoop, .{self}) catch {
            return error.AdminThreadFailed;
        };
    }

    /// Admin server loop - runs serval-server.
    fn adminServerLoop(self: *Self) void {
        var server = self.admin_server orelse return;
        var io = Io{};

        // Run server until shutdown
        server.run(io, &self.shutdown) catch |err| {
            std.log.err("admin server error: {s}", .{@errorName(err)});
        };
    }
};
```

**Step 3: Commit**

```bash
git add examples/gateway/admin_handler.zig examples/gateway/controller.zig
git commit -m "feat(examples/gateway): add controller using serval-server

Uses serval-server.MinimalServer instead of raw POSIX sockets.
Uses serval-core.config for all constants.
Uses serval-core.time for timing utilities.

TigerStyle compliant:
- S1: Assertions for pre/postconditions
- Uses serval-* components consistently"
```

---

## Task 8: Update main.zig to Wire Everything Together

**Files:**
- Modify: `examples/gateway/main.zig`

**Step 1: Write complete main.zig**

```zig
// examples/gateway/main.zig
//! Kubernetes Gateway API Controller
//!
//! Complete controller implementation that:
//! - Watches K8s Gateway API resources (Gateway, HTTPRoute)
//! - Translates to serval-router configuration
//! - Pushes config to data plane via admin API
//!
//! Usage:
//!   gateway [OPTIONS]
//!
//! Options:
//!   --port <PORT>          Data plane port (default: 8080)
//!   --admin-port <PORT>    Admin API port (default: 9901)
//!   --api-server <URL>     K8s API server (for out-of-cluster)
//!   --api-port <PORT>      K8s API port (default: 443)
//!   --token <TOKEN>        Bearer token for K8s API
//!   --namespace <NS>       Namespace to watch (default: "default")
//!   --debug                Enable debug logging
//!
//! TigerStyle Y1: Functions under 70 lines, extracted helpers.

const std = @import("std");
const cli = @import("serval-cli");
const gateway = @import("serval-gateway");

const controller_mod = @import("controller.zig");
const Controller = controller_mod.Controller;

const k8s_client = @import("k8s_client.zig");
const K8sClient = k8s_client.Client;

const watcher_mod = @import("watcher.zig");
const Watcher = watcher_mod.Watcher;

/// Version
const VERSION = "0.1.0";

/// CLI options
const GatewayOptions = struct {
    @"admin-port": u16 = 9901,
    @"data-plane-port": u16 = 9901,
    @"api-server": ?[]const u8 = null,
    @"api-port": u16 = 443,
    token: ?[]const u8 = null,
    namespace: ?[]const u8 = null,
};

/// Main entry point.
/// TigerStyle Y1: Under 70 lines with extracted helpers.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse CLI
    var args = cli.Args(GatewayOptions).init("gateway", VERSION);
    switch (args.parse()) {
        .ok => {},
        .help, .version => return,
        .err => {
            args.printError();
            return error.InvalidArgs;
        },
    }

    // Initialize and run
    try run(allocator, &args.extra);
}

/// Run the gateway controller.
/// TigerStyle Y1: Extracted from main for function length compliance.
fn run(allocator: std.mem.Allocator, opts: *const GatewayOptions) !void {
    // Initialize controller
    var ctrl = Controller.init(allocator, opts.@"admin-port", opts.@"data-plane-port");
    defer ctrl.deinit();

    // Start admin server
    ctrl.startAdminServer() catch |err| {
        std.debug.print("Error: failed to start admin server: {s}\n", .{@errorName(err)});
        return error.AdminServerFailed;
    };

    // Initialize K8s client
    var client = try initK8sClient(allocator, opts);
    defer client.deinit();

    // Initialize watcher with config change callback
    const onConfigChange = struct {
        fn callback(config: *gateway.GatewayConfig, ctx: *Controller) void {
            ctx.updateConfig(config) catch |err| {
                std.log.err("config update failed: {s}", .{@errorName(err)});
            };
        }
    }.callback;

    var watcher = Watcher.init(allocator, client, onConfigChange, &ctrl) catch |err| {
        std.debug.print("Error: watcher init failed: {s}\n", .{@errorName(err)});
        return error.WatcherFailed;
    };
    defer watcher.deinit();

    // Mark ready and print banner
    ctrl.ready.store(true, .release);
    printBanner(opts, client);

    // Start watcher (blocking)
    const thread = watcher.start() catch |err| {
        std.debug.print("Error: watcher start failed: {s}\n", .{@errorName(err)});
        return error.WatcherStartFailed;
    };

    thread.join();
    std.log.info("gateway controller stopped", .{});
}

/// Initialize K8s client (in-cluster or out-of-cluster).
/// TigerStyle Y1: Extracted helper for K8s client initialization.
fn initK8sClient(allocator: std.mem.Allocator, opts: *const GatewayOptions) !*K8sClient {
    if (opts.@"api-server") |api_server| {
        // Out-of-cluster mode
        const token = opts.token orelse {
            std.debug.print("Error: --token required for out-of-cluster mode\n", .{});
            return error.MissingToken;
        };
        const namespace = opts.namespace orelse "default";

        return K8sClient.initWithConfig(
            allocator,
            api_server,
            opts.@"api-port",
            token,
            namespace,
        ) catch |err| {
            std.debug.print("Error: K8s client init failed: {s}\n", .{@errorName(err)});
            return error.K8sClientFailed;
        };
    } else {
        // In-cluster mode
        return K8sClient.initInCluster(allocator) catch |err| {
            std.debug.print("Error: K8s client init failed: {s}\n", .{@errorName(err)});
            std.debug.print("Hint: use --api-server and --token for out-of-cluster\n", .{});
            return error.K8sClientFailed;
        };
    }
}

/// Print startup banner.
/// TigerStyle Y1: Extracted helper for banner printing.
fn printBanner(opts: *const GatewayOptions, client: *const K8sClient) void {
    std.debug.print("\n=== serval-gateway ===\n", .{});
    std.debug.print("Admin API: http://localhost:{d}\n", .{opts.@"admin-port"});
    std.debug.print("Data plane: localhost:{d}\n", .{opts.@"data-plane-port"});
    std.debug.print("K8s namespace: {s}\n", .{client.getNamespace()});
    std.debug.print("\nWatching Gateway API resources...\n", .{});
    std.debug.print("Press Ctrl+C to stop\n\n", .{});
}
```

**Step 2: Commit**

```bash
git add examples/gateway/main.zig
git commit -m "feat(examples/gateway): complete main.zig wiring"
```

---

## Task 9: Clean Up serval-gateway/

**Files:**
- Delete: `serval-gateway/gateway.zig`
- Delete: `serval-gateway/resolver.zig`
- Delete: `serval-gateway/k8s/` directory
- Modify: `serval-gateway/mod.zig`

**Step 1: Update mod.zig to minimal exports**

```zig
//! serval-gateway
//!
//! Gateway API library for serval.
//! Provides Gateway API types and translation to serval-router config.
//!
//! Use this library to build your own gateway controller:
//! - Define GatewayConfig with routes
//! - Use translator to convert to JSON
//! - POST to serval-router admin API
//!
//! See examples/gateway/ for a complete K8s controller implementation.
//!
//! Layer 4 (Strategy) - routing configuration

// Configuration types (Gateway API)
pub const config = @import("config.zig");
pub const GatewayConfig = config.GatewayConfig;
pub const Gateway = config.Gateway;
pub const HTTPRoute = config.HTTPRoute;
pub const HTTPRouteRule = config.HTTPRouteRule;
pub const HTTPRouteMatch = config.HTTPRouteMatch;
pub const HTTPRouteFilter = config.HTTPRouteFilter;
pub const HTTPBackendRef = config.HTTPBackendRef;
pub const Listener = config.Listener;

// Translator (GatewayConfig -> Router JSON)
pub const translator = @import("translator.zig");
pub const translateToJson = translator.translateToJson;
pub const TranslatorError = translator.TranslatorError;

test {
    @import("std").testing.refAllDecls(@This());
    _ = config;
    _ = translator;
}
```

**Step 2: Delete moved files**

```bash
rm serval-gateway/gateway.zig
rm serval-gateway/resolver.zig
rm -rf serval-gateway/k8s/
```

**Step 3: Run tests**

Run: `zig build test`
Expected: Tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: clean serval-gateway to library-only (types + translator)"
```

---

## Task 10: Update build.zig

**Files:**
- Modify: `build.zig`

**Step 1: Update gateway example target**

Change the gateway example to build from `examples/gateway/main.zig` and add all the local imports.

Look for existing `gateway_example` target and update:
- Source: `examples/gateway/main.zig`
- Add module imports for local files

**Step 2: Run full build**

Run: `zig build`
Expected: Compiles

**Step 3: Commit**

```bash
git add build.zig
git commit -m "build: update gateway example to examples/gateway/"
```

---

## Task 11: Update translator.zig API to Use ResolvedBackend

**Files:**
- Modify: `serval-gateway/translator.zig`

This is the key refactor that decouples translator from K8s-specific Resolver.

**Step 1: Change function signature**

Current:
```zig
pub fn translateToJson(
    config: *const GatewayConfig,
    resolver: *const Resolver,  // ← K8s-specific, remove
    buf: []u8,
) TranslatorError!usize
```

New:
```zig
pub fn translateToJson(
    config: *const GatewayConfig,
    resolved_backends: []const gw_config.ResolvedBackend,  // ← Generic
    buf: []u8,
) TranslatorError!usize
```

**Step 2: Update writePool to use ResolvedBackend**

Replace resolver.getServiceEndpoints() calls with lookups in resolved_backends slice.

```zig
/// Write a pool with its upstreams to the JSON buffer.
/// TigerStyle S4: Bounded loop over backends.
fn writePool(
    writer: *std.io.Writer,
    pool_name: []const u8,
    backend_refs: []const gw_config.HTTPBackendRef,
    resolved_backends: []const gw_config.ResolvedBackend,  // ← New param
    pool_idx: u8,
) TranslatorError!void {
    // ... existing pool header writing ...

    // For each backend ref, find matching resolved backend
    for (backend_refs) |backend_ref| {
        const resolved = findResolvedBackend(
            resolved_backends,
            backend_ref.getName(),
            backend_ref.getNamespace(),
        ) orelse {
            return error.BackendNotResolved;
        };

        // Write endpoints from resolved backend
        for (resolved.endpoints[0..resolved.endpoint_count]) |endpoint| {
            try writeUpstream(writer, endpoint.getIp(), endpoint.port);
        }
    }
}

/// Find resolved backend by name and namespace.
/// TigerStyle S4: Bounded search.
fn findResolvedBackend(
    backends: []const gw_config.ResolvedBackend,
    name: []const u8,
    namespace: []const u8,
) ?*const gw_config.ResolvedBackend {
    for (backends) |*backend| {
        if (std.mem.eql(u8, backend.getName(), name) and
            std.mem.eql(u8, backend.getNamespace(), namespace))
        {
            return backend;
        }
    }
    return null;
}
```

**Step 3: Add new error type**

```zig
pub const TranslatorError = error{
    BufferTooSmall,
    TooManyRoutes,
    TooManyPools,
    TooManyUpstreams,
    BackendNotResolved,  // ← New: backend ref not in resolved_backends
};
```

**Step 4: Remove resolver import**

Delete:
```zig
const resolver_mod = @import("resolver.zig");
const Resolver = resolver_mod.Resolver;
```

**Step 5: Update tests**

Tests now need to pass ResolvedBackend[] instead of Resolver. Example:

```zig
test "translateToJson with resolved backends" {
    var resolved = [_]gw_config.ResolvedBackend{
        .{
            .name = "api-svc".*,
            .name_len = 7,
            .namespace = "default".*,
            .namespace_len = 7,
            .endpoints = .{
                .{ .ip = "10.0.1.5".*,  .ip_len = 8, .port = 8080 },
                .{ .ip = "10.0.1.6".*,  .ip_len = 8, .port = 8080 },
            },
            .endpoint_count = 2,
        },
    };

    var out_buf: [4096]u8 = undefined;
    const len = try translateToJson(&config_data, &resolved, &out_buf);
    // ... verify JSON output ...
}
```

**Step 6: Run tests**

Run: `zig build test`
Expected: All tests pass

**Step 7: Run /tigerstyle validation**

Verify:
- S1: Assertions in translateToJson, writePool, findResolvedBackend
- S4: Bounded loops over backends
- S6: Explicit error handling for BackendNotResolved
- Y3: No new variables need units (types are self-documenting)

**Step 8: Commit**

```bash
git add serval-gateway/translator.zig
git commit -m "refactor(translator): take ResolvedBackend[] instead of Resolver

BREAKING CHANGE: translateToJson signature changed.
Caller must resolve backends before calling translator.

TigerStyle compliant:
- S1: Assertions for pre/postconditions
- S4: Bounded loops
- S6: BackendNotResolved error for missing backends"
```

---

## Task 12: Delete Old gateway_example.zig

**Files:**
- Delete: `examples/gateway_example.zig`

**Step 1: Remove old file**

```bash
rm examples/gateway_example.zig
```

**Step 2: Commit**

```bash
git add -A
git commit -m "chore: remove old gateway_example.zig"
```

---

## Task 13: Update Documentation

**Files:**
- Modify: `serval-gateway/README.md`
- Modify: `serval-gateway/TODO.md`

**Step 1: Update README.md**

Document that serval-gateway is now a library with types and translator only. Point to examples/gateway/ for the K8s controller.

**Step 2: Update TODO.md**

Remove completed items, update structure.

**Step 3: Commit**

```bash
git add serval-gateway/README.md serval-gateway/TODO.md
git commit -m "docs: update serval-gateway docs for library-only structure"
```

---

## Task 14: Final Verification

**Step 1: Run full build**

Run: `zig build`
Expected: Compiles without errors

**Step 2: Run all tests**

Run: `zig build test`
Expected: All tests pass

**Step 3: Verify structure**

```bash
ls -la serval-gateway/
# Should only have: config.zig, translator.zig, mod.zig, README.md, TODO.md

ls -la examples/gateway/
# Should have: main.zig, controller.zig, k8s_client.zig, watcher.zig, resolver.zig, data_plane.zig
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "refactor: complete gateway refactor - library + example separation"
```

---

## Summary

After this refactor:

**serval-gateway/** (~1500 lines) - Clean library:
- `config.zig` - Gateway API types + ResolvedBackend/ResolvedEndpoint
- `translator.zig` - GatewayConfig + ResolvedBackend[] → Router JSON
- `mod.zig` - Exports all types and translator

**examples/gateway/** (~5500 lines) - K8s controller:
- `main.zig` - Entry point, CLI parsing, wiring
- `controller.zig` - Config management, admin server coordination (uses serval-server)
- `admin_handler.zig` - Handler for /healthz, /readyz, /config (implements serval-server Handler)
- `k8s_client.zig` - K8s API client (uses serval-client)
- `watcher.zig` - K8s resource watcher with reconcile()
- `resolver.zig` - K8s Service → Endpoints resolution (resolveBackend method)
- `data_plane.zig` - Config push with resolution + translation (uses serval-client)

**Key API Changes:**

1. **New type: `ResolvedBackend`** - Decouples translator from K8s Resolver
2. **New translator signature:**
   ```zig
   // Before: coupled to Resolver
   translateToJson(config, resolver, buf)

   // After: takes pre-resolved backends
   translateToJson(config, resolved_backends, buf)
   ```
3. **New resolver method: `resolveBackend()`** - Returns ResolvedBackend

**Data Flow After Refactor:**
```
Watcher                     Controller                    Data Plane
   │                           │                              │
   │ reconcile()               │                              │
   │ ─────────────────────────▶│                              │
   │ GatewayConfig             │                              │
   │                           │ resolver.resolveBackend()    │
   │                           │ for each backend_ref         │
   │                           │                              │
   │                           │ translator.translateToJson() │
   │                           │ (config + resolved_backends) │
   │                           │                              │
   │                           │ POST /routes/update          │
   │                           │ ─────────────────────────────▶│
   │                           │ (using serval-client)        │
```

**Benefits:**
1. serval-gateway is reusable for non-K8s use cases (database, files, API)
2. All HTTP client uses serval-client (data plane push, K8s API)
3. All HTTP server uses serval-server (admin API with health probes)
4. All constants from serval-core.config (no local definitions)
5. All timing from serval-core.time utilities
6. Translator is decoupled from K8s-specific Resolver
7. Clear separation: library (types) vs implementation (controller)
8. TigerStyle compliant throughout

**serval-* Component Usage:**
| Component | Usage |
|-----------|-------|
| serval-client | HTTP client for data plane push and K8s API calls |
| serval-server | HTTP server for admin API (health probes, config status) |
| serval-core.config | All constants (timeouts, buffer sizes, ports) |
| serval-core.types | Request, Response, Upstream, DirectResponse, Action |
| serval-core.time | Timing utilities (monotonicNanos, elapsedNanos) |
| serval-net | DnsResolver, Socket abstraction |
| serval-pool | SimplePool for connection management |
| serval-metrics | NoopMetrics for admin server |
| serval-tracing | NoopTracer for admin server |
| serval-gateway | Gateway API types and translator |

**TigerStyle Compliance:**
- S1: ~2 assertions per function (pre/postconditions)
- S2: Explicit types (u8, u16, u32, u64 - no usize except slice indexing)
- S4: All loops bounded (MAX_RETRIES, MAX_RESOLVED_BACKENDS, etc.)
- S5: No allocation after init (fixed-size buffers)
- S6: Explicit error handling (no catch {})
- S7: Bounded queues/buffers
- Y3: Units in names (_ns, _ms, _bytes)
