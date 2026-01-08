# serval-gateway

> **Status: Work In Progress**
>
> The control plane (K8s watcher) is functional but needs code review and cleanup.
> The data plane currently uses `serval-router` with hardcoded config via `deploy/serval-router.yaml`.
> Runtime config updates from K8s watches are not yet implemented.

Kubernetes Gateway API ingress controller for serval.

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

## Architecture

```
                                    ┌─────────────────────────────────────────┐
                                    │           serval-gateway                │
                                    │                                         │
┌─────────────┐                     │  ┌─────────────┐    ┌───────────────┐  │
│  K8s API    │──watch──────────────┼─▶│  Watcher    │───▶│ serval-router │──┼───▶ Backend Pods
│             │                     │  │  (control)  │    │ (data plane)  │  │
└─────────────┘                     │  └─────────────┘    └───────────────┘  │
      │                             │                            │            │
      ▼                             │                     Admin API (9901)    │
 Gateway API Resources              │                     - /healthz          │
 - GatewayClass                     │                     - /readyz           │
 - Gateway                          │                     - /config           │
 - HTTPRoute                        │                     - /metrics          │
 - Services/Endpoints               │                     - /reload           │
 - Secrets (TLS)                    └─────────────────────────────────────────┘
```

**Control plane**: Watches Gateway API resources and translates them into routing config

**Data plane**: Uses `serval-router` to route HTTP traffic based on:
- Hostname matching (`api.example.com`)
- Path matching (`/api/v1/*`, exact or prefix)
- URL rewriting (strip `/api` prefix before forwarding)

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
```

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
