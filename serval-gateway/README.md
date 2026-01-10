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

Deploy serval-gateway + router_example as a full ALB replacement.

### Deployment Options

**You don't always need a load balancer.** Choose based on your requirements:

```
Option A: Direct (single instance, simplest)
┌──────────┐     ┌────────────────┐     ┌──────────┐
│  Client  │────▶│ serval-router  │────▶│ Backends │
│          │     │ (EC2/ECS/K8s)  │     │          │
└──────────┘     │ Public IP/DNS  │     └──────────┘
                 └────────────────┘

Option B: Behind NLB (HA, multiple instances)
┌──────────┐     ┌─────┐     ┌────────────────┐     ┌──────────┐
│  Client  │────▶│ NLB │────▶│ serval-router  │────▶│ Backends │
│          │     │     │     │ (multiple)     │     │          │
└──────────┘     └─────┘     └────────────────┘     └──────────┘

Option C: Behind existing ALB (serval as internal router)
┌──────────┐     ┌─────┐     ┌────────────────┐     ┌──────────┐
│  Client  │────▶│ ALB │────▶│ serval-router  │────▶│ Backends │
│          │     │     │     │ (internal)     │     │          │
└──────────┘     └─────┘     └────────────────┘     └──────────┘
```

| Scenario | Load Balancer | Why |
|----------|---------------|-----|
| Single instance | None | Direct access, simplest setup |
| High availability | NLB | Distribute across multiple instances |
| Need AWS WAF | ALB | NLB doesn't support WAF |
| WebSockets/gRPC | NLB | ALB has idle timeouts |
| Maximum performance | NLB | Lower latency than ALB |
| Already have ALB | Keep ALB | serval as internal router |

### Simplest AWS Setup (No Load Balancer)

```bash
# 1. Launch EC2 with security group allowing 8080, 9901
# 2. Run serval
./router_example &

# 3. Push config
curl -X PUT http://your-ec2-ip:9901/config \
  -H "Content-Type: application/json" \
  -d '{
    "routes": [{"name": "api", "match": {"path_prefix": "/api"}, "pool": "backend"}],
    "pools": [{"name": "backend", "upstreams": [{"host": "10.0.1.5", "port": 8080}]}],
    "default_pool": "backend"
  }'

# 4. Point Route53 to EC2 public IP
# 5. Done - clients access directly
```

### How It Gets Triggered

There's no explicit "trigger" — it's **event-driven via K8s watch API**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Kubernetes Cluster                              │
│                                                                              │
│  1. User applies HTTPRoute           2. K8s API notifies watcher            │
│     ┌──────────────┐                    ┌─────────────────────┐             │
│     │ kubectl apply│───────────────────▶│   K8s API Server    │             │
│     │ httproute.yaml                    │                     │             │
│     └──────────────┘                    └──────────┬──────────┘             │
│                                                    │ watch stream           │
│                                                    ▼                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     serval-gateway (Control Plane)                   │   │
│  │                                                                      │   │
│  │  3. Watcher receives     4. reconcile()        5. Push config       │   │
│  │     ADDED event             parses JSON           to data plane     │   │
│  │     ┌──────────┐         ┌──────────┐         ┌──────────────┐     │   │
│  │     │ Watcher  │────────▶│reconcile │────────▶│pushConfigTo- │     │   │
│  │     │          │         │          │         │DataPlane()   │     │   │
│  │     └──────────┘         └──────────┘         └──────┬───────┘     │   │
│  └──────────────────────────────────────────────────────┼──────────────┘   │
│                                                         │                   │
│                                            POST /routes/update              │
│                                                         │                   │
│  ┌──────────────────────────────────────────────────────▼──────────────┐   │
│  │                     router_example (Data Plane)                      │   │
│  │                                                                      │   │
│  │  6. Receive config    7. Atomic swap         8. Route traffic       │   │
│  │     ┌──────────┐      ┌──────────┐          ┌──────────────┐       │   │
│  │     │Admin API │─────▶│ConfigSwap│─────────▶│   Router     │       │   │
│  │     │  :9901   │      │          │          │              │       │   │
│  │     └──────────┘      └──────────┘          └──────┬───────┘       │   │
│  └──────────────────────────────────────────────────────┼──────────────┘   │
│                                                         │                   │
└─────────────────────────────────────────────────────────┼───────────────────┘
                                                          │
                     Internet ◀───── NLB ◀────────────────┘
                         │
                         ▼
                    Your Users
```

**Event Flow:**

1. **User creates HTTPRoute** via `kubectl apply -f httproute.yaml`
2. **K8s API Server** stores the resource and notifies all watchers
3. **Watcher** has an open HTTP connection: `GET /apis/gateway.networking.k8s.io/v1/httproutes?watch=true`
4. K8s sends newline-delimited JSON: `{"type":"ADDED","object":{...}}`
5. **`reconcile()`** parses JSON into typed config structs
6. **`pushConfigToDataPlane()`** POSTs to router_example admin API
7. **Router atomically swaps** config → new routes active immediately

### Kubernetes Deployment

```yaml
# Control Plane (watches K8s, pushes config)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: serval-gateway
spec:
  replicas: 2  # HA - both watch, only leader pushes
  template:
    spec:
      serviceAccountName: serval-gateway
      containers:
      - name: gateway
        image: serval-gateway:latest
        env:
        - name: DATA_PLANE_URL
          value: "http://serval-router:9901"
---
# Data Plane (handles actual traffic)
apiVersion: apps/v1
kind: DaemonSet  # Run on every node for low latency
metadata:
  name: serval-router
spec:
  template:
    spec:
      containers:
      - name: router
        image: serval-router:latest
        ports:
        - containerPort: 8080  # traffic
        - containerPort: 9901  # admin API
---
# Expose data plane via NLB (TCP passthrough)
apiVersion: v1
kind: Service
metadata:
  name: serval-router
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-scheme: "internet-facing"
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: serval-router
```

### Testing Without Kubernetes

You can test the data plane directly by simulating what the control plane does:

```bash
# Terminal 1: Start data plane
zig build run-router-example

# Terminal 2: Push config (simulates control plane)
curl -X PUT http://localhost:9901/config \
  -H "Content-Type: application/json" \
  -d '{
    "routes": [
      {"name": "api", "match": {"path_prefix": "/api"}, "pool": "api-pool"}
    ],
    "pools": [
      {"name": "api-pool", "upstreams": [{"host": "httpbin.org", "port": 80}]}
    ],
    "default_pool": "api-pool"
  }'

# Terminal 2: Verify config was applied
curl http://localhost:9901/routes

# Terminal 2: Test routing (proxies to httpbin.org)
curl http://localhost:8080/api/get
```

### Testing in Kubernetes (k3s)

```bash
# Start k3s
k3s server &

# Deploy serval
kubectl apply -f deploy/serval-gateway.yaml

# Create an HTTPRoute
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: test-route
spec:
  hostnames: ["test.example.com"]
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /api
    backendRefs:
    - name: echo-server
      port: 8080
EOF

# Check if config was pushed to data plane
kubectl exec -it deploy/serval-router -- curl localhost:9901/routes

# Test traffic (via NodePort or port-forward)
kubectl port-forward svc/serval-router 8080:80 &
curl -H "Host: test.example.com" http://localhost:8080/api/test
```

### Advantages over AWS ALB Controller

| Feature | AWS ALB Controller | serval-gateway |
|---------|-------------------|----------------|
| Config update speed | ~30s (AWS API) | <100ms (direct push) |
| AWS dependency | Yes | No |
| Works outside AWS | No | Yes |
| Memory allocations | Runtime | Zero after init |
| Observability | CloudWatch | Built-in metrics |

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
