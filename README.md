# Serval

HTTP server framework for Zig — build backends, proxies, load balancers, API gateways, and sidecars. Built-in observability with metrics and OpenTelemetry tracing. Inspired by TigerBeetle and Pingora.

## Features

- **Modular architecture** — Use the full server or individual components (parser, pool, forwarder)
- **Compile-time composition** — Generic interfaces verified at build time, zero runtime dispatch
- **TLS support** — Client-side termination and upstream HTTPS (OpenSSL)
- **kTLS kernel offload** — Hardware-accelerated TLS with automatic fallback
- **Zero-copy forwarding** — Linux splice() for body transfer (including kTLS)
- **Connection pooling** — Reuse upstream connections across requests
- **Pluggable components** — Custom handlers, metrics, and tracing implementations
- **No runtime allocation** — All memory allocated at startup

## Quick Start

```zig
const serval = @import("serval");
const serval_lb = @import("serval-lb");
const serval_net = @import("serval-net");

const upstreams = [_]serval.Upstream{
    .{ .host = "127.0.0.1", .port = 8001, .idx = 0 },
    .{ .host = "127.0.0.1", .port = 8002, .idx = 1, .tls = true }, // HTTPS backend
};

var handler = serval_lb.LbHandler.init(&upstreams);
var pool = serval.SimplePool.init();
var metrics = serval.NoopMetrics{};
var tracer = serval.NoopTracer{};

var server = serval.Server(
    serval_lb.LbHandler,
    serval.SimplePool,
    serval.NoopMetrics,
    serval.NoopTracer,
).init(&handler, &pool, &metrics, &tracer, .{
    .port = 8080,
    // Optional: TLS termination for client connections
    // .tls = .{ .cert_path = "cert.pem", .key_path = "key.pem" },
}, null, serval_net.DnsConfig{});  // DNS config with default TTL

var shutdown = std.atomic.Value(bool).init(false);
try server.run(io, &shutdown);
```

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .serval = .{
        .url = "https://github.com/ejpir/serval/archive/refs/heads/main.tar.gz",
        .hash = "...", // Run: zig fetch <url>
    },
},
```

Then in `build.zig`:

```zig
const serval = b.dependency("serval", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("serval", serval.module("serval"));
exe.root_module.addImport("serval-lb", serval.module("serval-lb"));
```

## Modules

| Module | Purpose |
|--------|---------|
| `serval` | Umbrella module — re-exports everything |
| `serval-core` | Types, config, errors, context |
| `serval-http` | HTTP/1.1 request parser |
| `serval-client` | HTTP/1.1 client library for upstream connections |
| `serval-tls` | TLS termination/origination with kTLS offload |
| `serval-pool` | Connection pooling |
| `serval-proxy` | Upstream forwarding |
| `serval-server` | HTTP/1.1 server |
| `serval-lb` | Load balancer handler (round-robin) |
| `serval-router` | Content-based routing (host/path matching, path rewriting) |
| `serval-gateway` | Kubernetes Gateway API controller |
| `serval-health` | Backend health tracking (atomic bitmap) |
| `serval-metrics` | Metrics interfaces |
| `serval-tracing` | Distributed tracing interfaces |
| `serval-otel` | OpenTelemetry implementation |
| `serval-cli` | CLI argument parsing |

## Handler Interface

Implement `selectUpstream` to route requests:

```zig
const MyHandler = struct {
    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, req: *const serval.Request) serval.Upstream {
        // Route based on path, headers, etc.
        return self.upstreams[0];
    }

    // Optional hooks
    pub fn onRequest(self: *@This(), ctx: *serval.Context, req: *serval.Request, response_buf: []u8) serval.Action {
        _ = response_buf;
        return .continue_request;
    }

    pub fn onLog(self: *@This(), ctx: *serval.Context, entry: serval.LogEntry) void {
        std.log.info("{s} {s} -> {d}", .{ @tagName(entry.method), entry.path, entry.status });
    }
};
```

## Building

```bash
zig build                       # Build lb_example (default)
zig build build-echo-backend    # Build echo backend
zig build build-router-example  # Build router example
zig build build-gateway-example # Build gateway example (K8s controller)
zig build test                  # Run all tests
```

## Examples

### Load Balancer with Echo Backends

Start two echo backends, then run the load balancer:

```bash
# Terminal 1: Start backend on port 8001
zig build run-echo-backend -- --port 8001 --id backend-1

# Terminal 2: Start backend on port 8002
zig build run-echo-backend -- --port 8002 --id backend-2

# Terminal 3: Start load balancer
zig build run-lb-example -- --port 8080 --backends 127.0.0.1:8001,127.0.0.1:8002

# Terminal 4: Test round-robin
curl http://localhost:8080/test
curl http://localhost:8080/test
```

Each request alternates between backends. The response shows which backend handled it:

```
=== Echo Backend: backend-1 (port 8001) ===

Method: GET
Path: /test
Version: HTTP/1.1

Headers:
  Host: 127.0.0.1:8080
  User-Agent: curl/8.0
  Accept: */*

Body: (empty)
```

### Load Balancer with HTTPS Backends

Health probes automatically use HTTPS when backends are marked with `--upstream-tls`:

```bash
# Terminal 1: Start HTTP backend
zig build run-echo-backend -- --port 8001 --id backend-1

# Terminal 2: Start HTTPS backend (requires cert/key)
zig build run-echo-backend -- --port 8002 --id backend-2 \
  --cert experiments/tls-poc/cert.pem \
  --key experiments/tls-poc/key.pem

# Terminal 3: Start load balancer with mixed backends
# Note: Use --insecure-skip-verify for self-signed certificates (testing only)
zig build run-lb-example -- --port 8080 \
  --backends 127.0.0.1:8001,127.0.0.1:8002 \
  --upstream-tls 127.0.0.1:8002 \
  --insecure-skip-verify

# The load balancer will:
# - Forward requests to both backends via HTTP
# - Send healthcheck probes to :8001 via HTTP
# - Send healthcheck probes to :8002 via HTTPS (with TLS handshake, skipping cert verification)
```

**Security Note:** The `--insecure-skip-verify` flag disables TLS certificate verification for:
- Health probe connections (prober → backends)
- Request forwarding connections (proxy → backends)

Only use this flag for testing with self-signed certificates. In production, use properly signed certificates and omit this flag.

### Content-Based Router

Route requests to different backend pools based on path:

```bash
# Terminal 1: Start API backend
zig build run-echo-backend -- --port 8001 --id api-backend

# Terminal 2: Start static backend
zig build run-echo-backend -- --port 8002 --id static-backend

# Terminal 3: Start router
zig build run-router-example -- --port 8080 \
  --api-backends 127.0.0.1:8001 \
  --static-backends 127.0.0.1:8002

# Terminal 4: Test routing
curl http://localhost:8080/api/users    # -> api-backend, path rewritten to /users
curl http://localhost:8080/static/img   # -> static-backend, path rewritten to /img
curl http://localhost:8080/other        # -> api-backend (default), path unchanged
```

The router strips path prefixes before forwarding:
- `/api/users` → api-pool receives `/users`
- `/static/image.png` → static-pool receives `/image.png`

### Kubernetes Gateway API (serval-gateway)

serval-gateway is an ingress controller that implements the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/). It watches Gateway API resources and configures serval-router for traffic routing.

```
┌─────────────┐       ┌─────────────────┐       ┌───────────────┐
│  K8s API    │──────▶│ serval-gateway  │──────▶│ Backend Pods  │
│  (watch)    │       │ (data plane)    │       │               │
└─────────────┘       └─────────────────┘       └───────────────┘
      │
      ▼
 Gateway API Resources:
 - GatewayClass (defines controller)
 - Gateway (defines listeners/ports)
 - HTTPRoute (defines routing rules)
```

**Deploy to k3s:**

```bash
# Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.0.0/standard-install.yaml

# Deploy serval-gateway (builds binaries, images, deploys to k3s)
./deploy/deploy-k3s.sh
```

**Example Gateway and HTTPRoute:**

```yaml
# Gateway - defines a listener on port 80
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
spec:
  gatewayClassName: serval
  listeners:
    - name: http
      port: 80
      protocol: HTTP
---
# HTTPRoute - routes traffic to backend service
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
spec:
  parentRefs:
    - name: my-gateway
  hostnames:
    - "api.example.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      backendRefs:
        - name: api-service
          port: 8080
```

See [serval-gateway/README.md](serval-gateway/README.md) for full documentation.

### Direct Response Handler

Handlers can respond directly without forwarding using `DirectResponse`:

```zig
const HealthHandler = struct {
    pub fn selectUpstream(self: *@This(), ctx: *serval.Context, req: *const serval.Request) serval.Upstream {
        _ = self; _ = ctx; _ = req;
        unreachable; // Never called - onRequest handles everything
    }

    pub fn onRequest(self: *@This(), ctx: *serval.Context, req: *serval.Request, response_buf: []u8) serval.Action {
        _ = self; _ = ctx; _ = req;
        const body = "OK";
        @memcpy(response_buf[0..body.len], body);
        return .{ .send_response = .{
            .status = 200,
            .body = response_buf[0..body.len],
            .content_type = "text/plain",
        } };
    }
};
```

### CLI Options

Both examples support these options:

```bash
# Load balancer
zig build run-lb-example -- --help
  --port <PORT>                Listening port (default: 8080)
  --backends <HOSTS>           Comma-separated backend addresses (default: 127.0.0.1:8001,127.0.0.1:8002)
  --upstream-tls <HOSTS>       Comma-separated TLS backend addresses (enables HTTPS)
  --insecure-skip-verify       Skip TLS certificate verification for upstream connections (insecure, for testing only)
  --cert <PATH>                Server certificate file (PEM format, enables TLS termination)
  --key <PATH>                 Server private key file (PEM format, required with --cert)
  --stats                      Enable real-time terminal stats
  --trace                      Enable OpenTelemetry tracing
  --debug                      Enable debug logging

# Echo backend
zig build run-echo-backend -- --help
  --port <PORT>       Listening port (default: 8001)
  --id <ID>           Instance identifier (default: echo-1)
  --cert <PATH>       Server certificate file (PEM format, enables HTTPS)
  --key <PATH>        Server private key file (PEM format, required with --cert)
  --chunked           Use Transfer-Encoding: chunked for responses
  --debug             Enable debug logging
```

## Documentation

- [Architecture Guide](serval/ARCHITECTURE.md) — Module structure, request flow, interfaces
- Module READMEs in each `serval-*/` directory

## Implementation Status

| Feature | Status |
|---------|--------|
| HTTP/1.1 parsing | Complete |
| Keep-alive connections | Complete |
| Upstream forwarding | Complete |
| Connection pooling | Complete |
| Zero-copy (splice) | Complete |
| Request body streaming | Complete |
| Metrics collection | Complete |
| OpenTelemetry tracing | Complete |
| Health tracking | Complete |
| Active health probing (HTTP/HTTPS) | Complete |
| TLS termination (server-side) | Complete |
| TLS origination (upstream HTTPS) | Complete |
| kTLS kernel offload | Complete |
| Chunked encoding | Complete |
| Content-based routing | Complete |
| Path rewriting | Complete |
| Gateway API controller | In progress |
| HTTP/2 | Not implemented |

## License

MIT
