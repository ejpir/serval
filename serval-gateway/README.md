# serval-gateway

> **Status: Library Implemented**
>
> Gateway API types and translator to serval-router JSON config.
> For a complete K8s controller implementation, see `examples/gateway/`.

Gateway API library for serval — provides types and translation for building ingress controllers.

## What is this?

**serval-gateway is a library**, not a controller. It provides:

1. **Gateway API types** (config.zig) — Zig structs mirroring Kubernetes Gateway API resources
2. **Translator** (translator.zig) — Converts GatewayConfig to JSON for serval-router admin API

Use this library to build your own gateway controller that:
- Watches Kubernetes resources (Gateway, HTTPRoute, Service, Endpoints)
- Resolves Service references to pod IPs
- Translates to serval-router config using this library
- Pushes JSON to serval-router admin API

For a complete Kubernetes controller implementation, see `examples/gateway/`.

## File Structure

```
serval-gateway/
├── config.zig      # Gateway API types (GatewayConfig, HTTPRoute, etc.)
├── translator.zig  # GatewayConfig → Router JSON translation
└── mod.zig         # Module exports
```

## Exports

```zig
const gateway = @import("serval-gateway");

// Configuration types (Gateway API)
gateway.GatewayConfig     // Complete Gateway API config snapshot
gateway.Gateway           // Gateway resource (listeners)
gateway.HTTPRoute         // HTTPRoute resource (routing rules)
gateway.HTTPRouteRule     // Rule within HTTPRoute
gateway.HTTPRouteMatch    // Match conditions (path, headers)
gateway.HTTPRouteFilter   // Filters (URLRewrite, etc.)
gateway.BackendRef        // Reference to backend service
gateway.Listener          // Gateway listener (port, protocol)

// Resolved types (for translator API)
gateway.ResolvedBackend       // Backend with resolved endpoints
gateway.FixedResolvedEndpoint // Single endpoint (host:port)

// Translation
gateway.translator.translateToJson  // GatewayConfig → JSON bytes
gateway.TranslatorError             // Translation errors
```

## Usage

### Building a Controller

```zig
const std = @import("std");
const gateway = @import("serval-gateway");

pub fn translateAndPush(
    config: *const gateway.GatewayConfig,
    resolved_backends: []const gateway.ResolvedBackend,
    buffer: []u8,
) !void {
    // Translate to JSON
    const json_len = try gateway.translateToJson(
        config,
        resolved_backends,
        buffer,
    );

    const json = buffer[0..json_len];

    // POST to serval-router admin API
    // (use serval-client or your HTTP client)
    try postToRouter("http://localhost:9901/routes/update", json);
}
```

### JSON Output Format

The translator outputs JSON matching the serval-router admin API:

```json
{
  "routes": [
    {
      "name": "api",
      "host": "api.example.com",
      "path_prefix": "/api/",
      "pool_idx": 0,
      "strip_prefix": true
    }
  ],
  "default_route": {
    "name": "default",
    "path_prefix": "/",
    "pool_idx": 0,
    "strip_prefix": false
  },
  "pools": [
    {
      "name": "api-pool",
      "upstreams": [
        {"host": "10.0.1.5", "port": 8001, "idx": 0, "tls": false}
      ]
    }
  ]
}
```

## Configuration Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_GATEWAYS` | 16 | Max Gateway resources |
| `MAX_LISTENERS` | 16 | Max listeners per Gateway |
| `MAX_HTTP_ROUTES` | 128 | Max HTTPRoute resources |
| `MAX_RULES` | 32 | Max rules per HTTPRoute |
| `MAX_MATCHES` | 8 | Max matches per rule |
| `MAX_BACKEND_REFS` | 16 | Max backends per rule |
| `MAX_ROUTES` | 128 | Max translated routes |
| `MAX_POOLS` | 64 | Max backend pools |
| `MAX_UPSTREAMS_PER_POOL` | 64 | Max upstreams per pool |

## Complete Controller Implementation

For a full Kubernetes Gateway controller, see `examples/gateway/`:

```
examples/gateway/
├── main.zig          # Entry point
├── controller.zig    # Orchestration and reconciliation
├── k8s_client.zig    # K8s API HTTP client
├── watcher.zig       # Resource watch with reconnection
├── resolver.zig      # Service → Endpoints resolution
├── data_plane.zig    # Push config to serval-router
└── admin_handler.zig # Health/readiness endpoints
```

The example controller demonstrates:
- ServiceAccount authentication (`/var/run/secrets/kubernetes.io/serviceaccount/token`)
- Watch API for Gateway, HTTPRoute, Service, Endpoints
- Exponential backoff on reconnection
- Service → pod IP resolution
- Atomic config push to data plane

## Gateway API Resources

This library supports the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/):

| Resource | Description |
|----------|-------------|
| Gateway | Defines listeners (ports/protocols) for accepting traffic |
| HTTPRoute | Defines routing rules matching requests to backends |
| BackendRef | References to upstream services |

Gateway API is the newer, more expressive replacement for the Ingress API:

| Feature | Ingress | Gateway API |
|---------|---------|-------------|
| Role separation | No | Yes (GatewayClass -> Gateway -> HTTPRoute) |
| Header matching | Limited | Full support |
| Traffic splitting | No | Yes (weighted backends) |
| URL rewriting | Annotations | Native |
| TLS per-route | No | Yes |

## Implementation Status

| Feature | Status |
|---------|--------|
| Gateway types | Implemented |
| HTTPRoute types | Implemented |
| Listener types | Implemented |
| PathPrefix matching | Implemented |
| Exact path matching | Implemented |
| URLRewrite filter | Implemented |
| JSON translation | Implemented |
| Header matching | Planned |
| Traffic splitting | Planned |

## Dependencies

- `serval-core`: Types, config constants

## TigerStyle Compliance

- Fixed-size types with explicit MAX_* limits
- No allocation after initialization
- Explicit error handling (no catch {})
- All loops bounded with MAX_* iteration limits
- Units in names (MAX_JSON_SIZE_BYTES)
