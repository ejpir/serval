# serval-gateway

> **Status: Data Plane Integration Implemented**
>
> Control plane (K8s watcher) and data plane (router_example) are integrated.
> Gateway translates HTTPRoute resources to Router config via the translator module.
> Runtime config updates are pushed to router_example via `pushConfigToDataPlane()`.

Kubernetes Gateway API ingress controller for serval — can be used as an **AWS ALB Controller replacement**.

## What is this?

**serval-gateway is an ingress controller** — it routes external traffic into your Kubernetes cluster based on [Gateway API](https://gateway-api.sigs.k8s.io/) resources.

Gateway API is the newer, more expressive replacement for the Ingress API:

| Feature | Ingress | Gateway API |
|---------|---------|-------------|
| Role separation | No | Yes (GatewayClass → Gateway → HTTPRoute) |
| Header matching | Limited | Full support |
| Traffic splitting | No | Yes (weighted backends) |
| URL rewriting | Annotations | Native |
| TLS per-route | No | Yes |

## Architecture Overview

serval-gateway follows a **control plane / data plane separation**:

```
┌────────────────────────────────────────────────────────────────┐
│                 serval-gateway (Control Plane)                 │
│                                                                │
│  k8s/client.zig        k8s/watcher.zig         gateway.zig    │
│  ┌──────────────┐     ┌───────────────┐     ┌──────────────┐  │
│  │ K8s HTTP     │     │ Watch Loop    │     │ Translate    │  │
│  │ - Bearer auth│────▶│ - Gateway     │────▶│ GatewayConfig│  │
│  │ - TLS        │     │ - HTTPRoute   │     │ to Routes    │  │
│  │ - SA token   │     │ - Service     │     │              │  │
│  └──────────────┘     │ - Endpoints   │     │ Push to      │──┼──▶
│                       │ - Secrets     │     │ Data Plane   │  │
│                       │               │     └──────────────┘  │
│                       │ on_config_    │                       │
│                       │ change()      │                       │
│                       └───────────────┘                       │
└────────────────────────────────────────────────────────────────┘
                                                                 │
                          POST /routes/update                    │
                                                                 ▼
┌────────────────────────────────────────────────────────────────┐
│                 router_example (Data Plane)                    │
│                                                                │
│    Admin API :9901 ────▶ Atomic Swap ────▶ Router             │
│    Traffic :8080 ───────────────────────▶ Backends            │
└────────────────────────────────────────────────────────────────┘
```

### Component Breakdown

| Component | File | Description |
|-----------|------|-------------|
| **K8s HTTP client** | `k8s/client.zig` | HTTP client with ServiceAccount auth |
| **ServiceAccount auth** | `k8s/client.zig:31-33` | Bearer token from pod mount |
| **Watch stream** | `k8s/client.zig:466-507` | WatchStream for K8s watch API |
| **Resource watcher** | `k8s/watcher.zig` | Watches all Gateway API resource types |
| **Event parsing** | `k8s/watcher.zig:598-631` | JSON parsing for watch events |
| **Resource stores** | `k8s/watcher.zig:157-289` | Bounded storage for tracked resources |
| **Reconnect backoff** | `k8s/watcher.zig:577-586` | Exponential backoff on disconnect |
| **Config translation** | `gateway.zig:803-840` | GatewayConfig → Router Routes |
| **Push to data plane** | `gateway.zig:442-522` | HTTP POST with retry to router_example |

### Control Plane (serval-gateway)

Watches Kubernetes Gateway API resources and pushes configuration to data planes:

- **k8s/client.zig**: HTTP client for K8s API with ServiceAccount authentication
  - `initInCluster()` - reads token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
  - `get()` - GET requests with Bearer auth header
  - `watch()` - returns WatchStream for streaming events

- **k8s/watcher.zig**: Resource watcher with reconnection
  - Watches: Gateway, HTTPRoute, Service, Endpoints, Secrets
  - Parses JSON watch events (ADDED, MODIFIED, DELETED, BOOKMARK, ERROR)
  - `on_config_change` callback triggers reconciliation
  - Exponential backoff on connection failure

- **gateway.zig**: Config translation and data plane management
  - `updateConfig()` - translates GatewayConfig and pushes to data plane
  - `pushConfigToDataPlane()` - HTTP POST to router_example admin API
  - Admin API for health/readiness probes

### Data Plane (router_example)

Handles actual HTTP traffic routing:

- **examples/router_example.zig**: HTTP server with dynamic routing
  - Admin API on port 9901 receives config updates
  - Atomic double-buffered config swap (zero-downtime updates)
  - Uses `serval-router` for path/host matching

### Integration Flow

```
1. K8s watcher detects HTTPRoute/Service/Endpoints changes
       │
       ▼
2. Watcher calls on_config_change() callback
       │
       ▼
3. gateway.updateConfig() translates GatewayConfig → Routes
       │
       ▼
4. gateway.pushConfigToDataPlane() POSTs JSON to router_example
       │
       ▼
5. router_example performs atomic config swap (double-buffer)
       │
       ▼
6. New routes take effect immediately (no restart needed)
```

## Using as AWS ALB Controller Replacement

Deploy serval-gateway + router_example behind an AWS NLB for full ALB replacement:

```
Internet ──▶ NLB (TCP/TLS passthrough) ──▶ serval fleet ──▶ Backend Services
                                               ▲
                                        Control Plane
                                     (watches K8s, pushes config)
```

**Advantages over AWS ALB Controller:**
- No AWS API calls for route changes (faster updates)
- Full control over routing logic
- Works in any environment (not just AWS)
- TigerStyle: zero allocation after init, bounded buffers

## Features

- **Gateway API v1 Support**: Watches GatewayClass, Gateway, and HTTPRoute resources
- **Service Resolution**: Resolves Service references to Endpoints (pod IPs)
- **Secret Resolution**: Resolves TLS certificate Secrets for HTTPS listeners
- **Atomic Config Updates**: Lock-free config swap for zero-downtime updates
- **Admin API**: Health checks, metrics, and config inspection on port 9901
- **Reconnection with Backoff**: Exponential backoff for K8s API watch reconnection

## Exports

```zig
const gateway = @import("serval-gateway");

// Core types
gateway.Gateway           // Main gateway controller
gateway.ADMIN_PORT        // Admin API port (9901)

// Configuration types
gateway.GatewayConfig     // Complete Gateway API config snapshot
gateway.HTTPRoute         // HTTPRoute resource
gateway.Listener          // Gateway listener config

// K8s integration
gateway.k8s.Client        // K8s API HTTP client
gateway.k8s.Watcher       // Resource watcher with reconnection
gateway.k8s.EventType     // Watch event types (ADDED, MODIFIED, DELETED)

// Resolution
gateway.Resolver          // Service/Secret resolver

// Translation (Gateway API -> Router config)
gateway.translator.TranslatedConfig     // Output config for router_example
gateway.translator.TranslatedRoute      // Single route configuration
gateway.translator.TranslatedPool       // Backend pool with upstreams
gateway.translator.translateConfig      // Main translation function
```

## Translator Module

The translator converts Gateway API resources into Router-compatible configuration:

```zig
// serval-gateway/translator.zig

// Translate HTTPRoutes to router config
pub fn translateConfig(
    gw_config: *const GatewayConfig,
    resolver: *const Resolver,
) TranslateError!TranslatedConfig

// Output structures match router_example admin API format
pub const TranslatedConfig = struct {
    routes: [MAX_ROUTES]TranslatedRoute,
    route_count: u32,
    pools: [MAX_POOLS]TranslatedPool,
    pool_count: u32,
    default_route: TranslatedRoute,
};
```

**Translation rules:**
- HTTPRoute path matches -> Route path_prefix
- HTTPRoute hostnames -> Route host filter
- URLRewrite filter -> Route strip_prefix flag
- BackendRef -> Pool with resolved pod IPs

## pushConfigToDataPlane Flow

When K8s resources change, gateway pushes config to router_example:

```
1. Watcher callback fires (HTTPRoute/Service change)
       |
       v
2. translateConfig(gw_config, resolver) -> TranslatedConfig
       |
       v
3. serializeConfig(config) -> JSON bytes
       |
       v
4. POST http://127.0.0.1:9901/routes/update
       |
       v
5. router_example performs atomic swap (double-buffer)
```

**Retry behavior:**
- 3 retry attempts with exponential backoff
- Base delay: 100ms, max delay: 5000ms
- On failure: keep previous config, log warning

## Usage

### In-Cluster Deployment

```zig
const std = @import("std");
const gateway = @import("serval-gateway");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // Initialize K8s client (reads ServiceAccount credentials)
    const client = try gateway.k8s.Client.initInCluster(allocator);
    defer client.deinit();

    // Initialize gateway controller
    var gw = gateway.Gateway.init(allocator);
    defer gw.deinit();

    // Start admin API
    try gw.startAdminServer();

    // Initialize watcher with config update callback
    const watcher = try gateway.k8s.Watcher.init(
        allocator,
        client,
        &onConfigChange,
    );
    defer watcher.deinit();

    // Start watching K8s resources
    const watch_thread = try watcher.start();
    watch_thread.join();
}

fn onConfigChange(config: *gateway.GatewayConfig) void {
    // Handle config update - translate to router routes
    std.log.info("Config updated: {d} gateways, {d} routes", .{
        config.gateways.len,
        config.http_routes.len,
    });
}
```

### Testing Outside Cluster

```zig
// Initialize with explicit config for testing
const client = try gateway.k8s.Client.initWithConfig(
    allocator,
    "https://localhost:6443",  // API server URL
    "test-token",              // Bearer token
    "default",                 // Namespace
);
```

## Admin API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Liveness probe - always returns 200 OK |
| `/readyz` | GET | Readiness probe - 200 if config loaded, 503 otherwise |
| `/config` | GET | JSON dump of current routing config |
| `/metrics` | GET | Prometheus-format metrics |
| `/reload` | POST | Trigger config re-sync from K8s |

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

## Kubernetes Deployment

See `deploy/serval-gateway.yaml` for complete deployment manifests including:
- ServiceAccount with RBAC permissions
- GatewayClass registration
- Deployment with health probes
- LoadBalancer Service

### Prerequisites

Install Gateway API CRDs:
```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.0.0/standard-install.yaml
```

### Deploy

```bash
kubectl apply -f deploy/serval-gateway.yaml
```

### Example Resources

See `deploy/examples/` for example Gateway and HTTPRoute resources:
- `basic-gateway.yaml` - Simple HTTP gateway
- `basic-httproute.yaml` - HTTPRoute with path matching and URL rewrite

## Implementation Status

| Feature | Status |
|---------|--------|
| GatewayClass watch | Implemented |
| Gateway watch | Implemented |
| HTTPRoute watch | Implemented |
| Service/Endpoints resolution | Implemented |
| Secret/TLS resolution | Implemented |
| PathPrefix matching | Implemented |
| Exact path matching | Implemented |
| URLRewrite filter | Implemented |
| Admin API | Implemented |
| Atomic config swap | Implemented |
| Watch reconnection | Implemented |
| **Translator module** | **Implemented** |
| **pushConfigToDataPlane()** | **Implemented** |
| **Resolver integration** | **Implemented** |
| TLS termination | Planned |
| Header matching | Planned |
| Request/Response header modification | Planned |
| Traffic splitting | Planned |

## Dependencies

- `serval-core`: Types, config, errors
- `serval-router`: Route matching (future integration)
- `std.http`: K8s API communication

## TigerStyle Compliance

- Bounded storage with explicit MAX_* limits
- No allocation after initialization
- Atomic operations for thread-safe config updates
- Explicit error handling (no catch {})
- All loops bounded with MAX_* iteration limits
- Exponential backoff with MAX_BACKOFF_MS cap
