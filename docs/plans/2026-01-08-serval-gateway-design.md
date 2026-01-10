# serval-k8s-gateway Design

Kubernetes Gateway API data plane for serval. Watches K8s resources directly and configures serval-router at runtime.

## Overview

**serval-k8s-gateway** is an in-process Gateway API controller that:
- Watches GatewayClass, Gateway, HTTPRoute resources from K8s API
- Resolves Service references to pod IPs (via Endpoints)
- Resolves Secret references to TLS certificates
- Configures serval-router with atomic config swaps
- Serves HTTP/HTTPS traffic

## Architecture

```
┌─────────────────┐         ┌─────────────────────────────┐
│  K8s API Server │◄────────│      serval-k8s-gateway         │
│                 │  watch  │                             │
│  - GatewayClass │         │  ┌───────────────────────┐  │
│  - Gateway      │         │  │ Watcher Thread        │  │
│  - HTTPRoute    │         │  │ - Watch resources     │  │
│  - Services     │         │  │ - Resolve refs        │  │
│  - Endpoints    │         │  │ - Build config        │  │
│  - Secrets      │         │  │ - Atomic swap         │  │
│                 │         │  └───────────┬───────────┘  │
└─────────────────┘         │              │              │
                            │              ▼              │
                            │  ┌───────────────────────┐  │
                            │  │ Main Thread           │  │
                            │  │ - Traffic serving     │  │
                            │  │ - serval-router       │  │
                            │  │ - io_uring            │  │
                            │  └───────────────────────┘  │
                            │                             │
                            │  ┌───────────────────────┐  │
                            │  │ Admin API (:9901)     │  │
                            │  │ - localhost only      │  │
                            │  └───────────────────────┘  │
                            └─────────────────────────────┘
```

## Design Decisions

| Decision | Choice | Future |
|----------|--------|--------|
| Deployment model | In-process (watches K8s directly) | Operator model optional |
| Config format | Pure Gateway API (serval resolves refs) | - |
| Admin API auth | Localhost only (:9901) | Token auth, mTLS |
| Gateway API scope | Minimal HTTPRoute | TLSRoute, headers, query params |
| Threading | Single watcher thread | - |
| Config reload | Atomic pointer swap | - |

## Module Structure

```
serval-k8s-gateway/
├── mod.zig           # Re-exports
├── gateway.zig       # Main: admin API, config management, router setup
├── config.zig        # Gateway API types (Gateway, HTTPRoute, etc.)
├── k8s/
│   ├── mod.zig       # K8s client re-exports
│   ├── client.zig    # HTTP client for K8s API
│   └── watcher.zig   # Watch streams, resource parsing
└── resolver.zig      # Service → IPs, Secret → certs
```

**Swappable design:** The `k8s/` module can be replaced with a file watcher for operator model later.

## K8s API Client

### Authentication

Read ServiceAccount token from pod:
```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### Watch Endpoints

```
GET /apis/gateway.networking.k8s.io/v1/gatewayclasses?watch=true
GET /apis/gateway.networking.k8s.io/v1/gateways?watch=true
GET /apis/gateway.networking.k8s.io/v1/httproutes?watch=true
GET /api/v1/namespaces/{ns}/services
GET /api/v1/namespaces/{ns}/endpoints
GET /api/v1/namespaces/{ns}/secrets
```

### Event Stream

K8s watch returns newline-delimited JSON:
```json
{"type": "ADDED", "object": {...}}
{"type": "MODIFIED", "object": {...}}
{"type": "DELETED", "object": {...}}
```

### Reconciliation

When resources change:
1. Watcher thread builds new GatewayConfig
2. Resolves Service refs → Endpoint IPs
3. Resolves Secret refs → cert/key data
4. Translates to serval-router config
5. Atomic pointer swap to new Router
6. Old Router cleanup

## Gateway API Types

```zig
pub const GatewayConfig = struct {
    gateways: []Gateway,
    http_routes: []HTTPRoute,
};

pub const Gateway = struct {
    name: []const u8,
    namespace: []const u8,
    listeners: []Listener,
};

pub const Listener = struct {
    name: []const u8,
    port: u16,
    protocol: Protocol,
    hostname: ?[]const u8,
    tls: ?TLSConfig,

    pub const Protocol = enum { HTTP, HTTPS };
};

pub const TLSConfig = struct {
    mode: Mode,
    certificate_refs: []CertificateRef,

    pub const Mode = enum { Terminate, Passthrough };
};

pub const CertificateRef = struct {
    name: []const u8,
    namespace: []const u8,
};

pub const HTTPRoute = struct {
    name: []const u8,
    namespace: []const u8,
    hostnames: []const []const u8,
    rules: []HTTPRouteRule,
};

pub const HTTPRouteRule = struct {
    matches: []HTTPRouteMatch,
    filters: []HTTPRouteFilter,
    backend_refs: []BackendRef,
};

pub const HTTPRouteMatch = struct {
    path: ?PathMatch,
    // Future: headers, query_params, method
};

pub const PathMatch = struct {
    type: Type,
    value: []const u8,

    pub const Type = enum { Exact, PathPrefix };
};

pub const HTTPRouteFilter = struct {
    type: Type,
    url_rewrite: ?URLRewrite,

    pub const Type = enum { URLRewrite };
};

pub const URLRewrite = struct {
    path: ?PathRewrite,

    pub const PathRewrite = struct {
        type: Type,
        value: []const u8,

        pub const Type = enum { ReplacePrefixMatch, ReplaceFullPath };
    };
};

pub const BackendRef = struct {
    name: []const u8,
    namespace: []const u8,
    port: u16,
};
```

## Admin API

**Endpoint:** `127.0.0.1:9901` (localhost only)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/healthz` | GET | Liveness probe (always 200) |
| `/readyz` | GET | Readiness (200 if config loaded, 503 if not) |
| `/config` | GET | Dump current config as JSON |
| `/reload` | POST | Force re-sync from K8s API |
| `/metrics` | GET | Prometheus metrics |

## Threading Model

```
┌─────────────────────────────────────────────────────────┐
│                    serval-k8s-gateway                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Watcher Thread (single)                                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │ while (running) {                                  │ │
│  │   watch GatewayClass, Gateway, HTTPRoute           │ │
│  │   watch Services, Endpoints for referenced svcs    │ │
│  │   watch Secrets for referenced certs               │ │
│  │   on change: reconcile → atomic swap               │ │
│  │   on disconnect: reconnect with backoff            │ │
│  │ }                                                  │ │
│  └────────────────────────────────────────────────────┘ │
│                          │                               │
│                          │ atomic swap                   │
│                          ▼                               │
│  Main Thread (io_uring)                                  │
│  ┌────────────────────────────────────────────────────┐ │
│  │ - Accept connections                               │ │
│  │ - Read current Router config (atomic load)         │ │
│  │ - Route requests via serval-router                 │ │
│  │ - Forward to upstreams                             │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  Admin Thread (optional, or reuse main)                  │
│  ┌────────────────────────────────────────────────────┐ │
│  │ - Serve /healthz, /readyz, /config, /reload        │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Config Reload Strategy

**Atomic swap** - zero lock contention on traffic path:

1. Watcher thread detects change
2. Builds new Router config (allocates new pools, routes)
3. Atomic pointer swap: `@atomicStore(&current_router, new_router, .release)`
4. Main thread sees new config on next request
5. Old config freed after grace period (in-flight requests complete)

## Testing Approach

### Unit Tests

- Config parsing (JSON → Zig structs)
- Route matching logic
- Service → Upstream translation
- Path rewriting

### K8s Integration Tests

```bash
# 1. Create kind cluster
kind create cluster

# 2. Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.0.0/standard-install.yaml

# 3. Deploy serval-k8s-gateway
kubectl apply -f deploy/serval-k8s-gateway.yaml

# 4. Create test resources
kubectl apply -f examples/basic-gateway.yaml
kubectl apply -f examples/basic-httproute.yaml

# 5. Test routing
curl -H "Host: api.example.com" http://localhost:8080/v1/users
```

### Conformance Tests (Future)

Gateway API project provides conformance test suite to validate spec compliance.

## Future Work

### v1 (Initial)

- Path matching (prefix, exact)
- Host matching
- Backend refs → resolved endpoints
- Path rewriting (strip prefix)
- TLS termination (via Gateway listeners)
- Admin API (localhost)
- K8s watcher with reconnection

### v2

- Header matching
- Query param matching
- Traffic weighting (canary deployments)
- Replace prefix (not just strip)

### v3

- TLSRoute (SNI-based passthrough)
- Token auth / mTLS for admin API
- GRPCRoute

### Optional

- Operator model (external controller writes JSON config file)
- Multi-gateway support (multiple listener sets)

## TigerStyle Compliance

- Bounded buffers for K8s watch responses
- Reconnection with exponential backoff on failures
- No allocation after init (pre-allocate route/pool storage with MAX_* limits)
- Atomic config swap (no locks on hot path)
- Single watcher thread (bounded, predictable)
- Assertions on K8s response parsing

## Dependencies

- serval-core (types, config)
- serval-router (routing, per-pool LB)
- serval-server (HTTP serving)
- serval-tls (TLS termination)
- std.http.Client (K8s API calls)
- std.json (config parsing)
