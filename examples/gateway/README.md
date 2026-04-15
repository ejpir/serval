# Gateway Controller Example

Kubernetes Gateway API controller example for Serval.

This example is the **control plane** half of a Gateway deployment. It watches Gateway API resources from Kubernetes, resolves them into concrete backend endpoints, translates the result into `serval-router` admin JSON, and pushes full configuration snapshots to the data plane.

It does **not** proxy user traffic itself. Traffic handling stays in the router example under `examples/router/`.

## Scope

This example shows how to build a Serval controller that:

- watches `GatewayClass`, `Gateway`, `HTTPRoute`, `Service`, `Endpoints`, and `Secret`
- filters Gateways by `spec.gatewayClassName -> GatewayClass.spec.controllerName`
- resolves backend Services into pod IP endpoints
- translates a bounded in-memory `GatewayConfig` into router JSON with `serval-k8s-gateway`
- pushes config to one router instance or all discovered router replicas
- exposes `/healthz`, `/readyz`, and `/config` for Kubernetes probes
- updates Gateway status best-effort after reconciliation

If you want the type system and translator only, use [`serval-k8s-gateway`](../../serval-k8s-gateway/README.md). If you want the traffic-handling side, use `examples/router/`.

## Architecture

### Control Plane vs Data Plane

```text
Kubernetes API
    |
    v
Watcher threads
    |
    v
bounded resource stores
    |
    v
reconcile -> GatewayConfig snapshot
    |
    v
Resolver -> concrete backend endpoints
    |
    v
RouterClient -> JSON push to router admin API
    |
    v
examples/router/ data plane
```

### Module Layout

| Path | Responsibility |
|------|----------------|
| `main.zig` | CLI parsing, startup, admin server thread, watcher startup, endpoint sync loop |
| `watcher/` | Kubernetes watch streams, raw resource stores, reconciliation into `GatewayConfig` |
| `resolver/` | `Service`/`Endpoints` and `Secret` resolution into concrete runtime data |
| `controller/` | Orchestration, config publication, router push policy, readiness/shutdown, status updates |
| `controller/routerclient/` | Translation, change detection, router admin HTTP client, multi-endpoint push logic |
| `controller/status/` | Gateway status PATCH requests to Kubernetes |
| `controller/admin/` | Admin handler for `/healthz`, `/readyz`, `/config` |
| `k8s_client/` | Kubernetes API client, watch stream support, EndpointSlice discovery |
| `PARKED.md` | Deferred features and design notes |

### Key Architecture Choices

#### 1. Strict control-plane/data-plane split

This example keeps Kubernetes interaction, reconciliation, and status management in the controller, while request routing and upstream forwarding stay in the router.

Why:

- preserves Serval’s architecture rule that strategy and orchestration stay separate from forwarding mechanics
- keeps the controller simple to reason about and easy to restart independently
- makes router rollout and controller rollout separable

#### 2. Snapshot reconciliation instead of incremental mutation

The watcher builds a complete bounded `GatewayConfig` snapshot and hands that snapshot to the controller. The controller publishes full config to the router admin API rather than streaming partial diffs.

Why:

- avoids partial state drift between controller and router
- makes restart/replay behavior deterministic
- keeps failure handling simple: either a snapshot is applied or it is retried later

#### 3. Resolver owns late binding

Service references are not sent to the router. The controller resolves them to concrete pod IP endpoints first.

Why:

- avoids sending Kubernetes-specific service discovery concerns into the data plane
- allows per-endpoint health-aware routing in the router
- removes kube-proxy from the request path

#### 4. Separate watch, resolve, and publish stages

The example intentionally separates:

- `watcher/` for raw API observation and reconciliation
- `resolver/` for endpoint and secret materialization
- `controller/` for publication, readiness, and status

Why:

- each layer has one reason to change
- endpoint arrival and config arrival can happen independently
- controller logic stays small enough to extend without turning `main.zig` into a monolith

#### 5. Single-endpoint by default, EndpointSlice fan-out for HA

By default the controller pushes to one router admin endpoint. If `--router-service` is set, it discovers router replicas with EndpointSlice and pushes to all of them.

Why:

- default path is simple for local development and single-instance deployment
- HA behavior is explicit instead of implicit
- newly created router pods can be synchronized by the background endpoint sync loop

#### 6. Serval components instead of raw substitutes

This example uses Serval libraries consistently:

- `serval-server.MinimalServer` for the controller admin HTTP server
- `serval-client` for router and Kubernetes HTTP communication
- `serval-k8s-gateway` for Gateway API types and translation

Why:

- stays aligned with repository component-usage rules
- avoids duplicating socket, HTTP, and translation logic in example code
- keeps the example representative of how Serval code should be written elsewhere in the repo

## Runtime Flow

### Startup

1. Parse CLI arguments.
2. Initialize the Kubernetes client.
3. Create the controller, resolver, router client, and status manager.
4. Start the admin server on `--admin-port`.
5. Start watcher threads for each resource type.
6. Optionally start the endpoint sync loop for multi-endpoint router mode.
7. Mark the controller ready.

### Reconciliation Flow

1. A watcher thread receives a Kubernetes watch event.
2. The event is stored in the bounded resource store for that type.
3. `Endpoints` and `Secret` updates refresh resolver state.
4. The watcher rebuilds a `GatewayConfig` snapshot.
5. The controller stores the snapshot pointer.
6. The router client resolves backend refs to concrete upstream endpoints.
7. The snapshot is translated to router JSON.
8. The controller pushes the config to one or more router admin endpoints.
9. Gateway status is updated best-effort.

### Admin Endpoints

The controller serves a small admin surface intended for probes and inspection:

| Endpoint | Meaning |
|----------|---------|
| `/healthz` | Liveness probe, always `200` while the admin server is running |
| `/readyz` | Readiness probe, `200` after controller startup completes |
| `/config` | Returns whether a config snapshot has been observed |

## Development

### Build

From the repository root:

```bash
/usr/local/zig-x86_64-linux-0.16.0-dev.3039+b490412cd/zig build build-gateway-example
```

Or with the repo-default `zig` on your `PATH`:

```bash
zig build build-gateway-example
```

### Run

The controller has two operating modes.

#### In-cluster

Run inside Kubernetes and let the controller read the mounted ServiceAccount token, namespace, and CA bundle:

```bash
zig build run-gateway-example -- \
  --admin-port 8080 \
  --data-plane-host serval-router.default.svc.cluster.local. \
  --data-plane-port 9901 \
  --namespace default
```

#### Out-of-cluster

Provide the API server host and bearer token explicitly:

```bash
zig build run-gateway-example -- \
  --api-server kubernetes.default.svc.cluster.local. \
  --api-port 443 \
  --token "$(cat /path/to/token)" \
  --namespace default \
  --data-plane-host 127.0.0.1 \
  --data-plane-port 9901
```

### High-availability router mode

Enable router replica discovery and fan-out pushes:

```bash
zig build run-gateway-example -- \
  --router-service serval-router-admin \
  --router-namespace serval-system
```

When enabled, the controller:

- discovers router endpoints via EndpointSlice
- pushes config to all discovered replicas
- periodically syncs newly added router pods with the current config

### Local end-to-end development loop

A practical local loop is:

1. Run one or two echo backends.
2. Run the router example in controller mode.
3. Run the gateway controller against a dev cluster.
4. Apply `GatewayClass`, `Gateway`, and `HTTPRoute` resources.
5. Inspect router admin config and send test requests through the router.

Example commands:

```bash
zig build run-echo-backend -- --port 8001 --id api-1
zig build run-echo-backend -- --port 8002 --id api-2
zig build run-router-example -- --port 8080 --admin-port 9901 --controller-mode
zig build run-gateway-example -- --data-plane-host 127.0.0.1 --data-plane-port 9901 --api-server <host> --token <token>
```

For a disposable cluster setup, see [`deploy/examples/k3d/README.md`](../../deploy/examples/k3d/README.md).

## Change Guide

If you need to modify behavior, start in the owning module instead of adding logic to `main.zig`.

| Change | Start here |
|--------|------------|
| watch resource selection, reconciliation, filtering | `watcher/` |
| service endpoint or secret materialization | `resolver/` |
| router push policy, retry behavior, HA fan-out | `controller/routerclient/` |
| controller readiness, shutdown, publication flow | `controller/controller.zig` |
| Kubernetes status behavior | `controller/status/` |
| probe or inspection endpoints | `controller/admin/` |
| Kubernetes transport/auth/watch mechanics | `k8s_client/` |

### Invariants worth preserving

- The controller should remain a control-plane binary only; do not add request forwarding here.
- The watcher should own raw resource state and snapshot construction.
- The resolver should stay responsible for translating Kubernetes references into concrete runtime data.
- Router pushes should stay idempotent and bounded.
- Kubernetes status updates should remain best-effort and must not block controller progress indefinitely.

## CLI Reference

| Flag | Default | Purpose |
|------|---------|---------|
| `--admin-port` | `8080` | Controller admin and health probe port |
| `--data-plane-host` | `serval-router.default.svc.cluster.local.` | Router admin host for single-endpoint mode |
| `--data-plane-port` | `9901` | Router admin port |
| `--api-server` | in-cluster default | Kubernetes API host for out-of-cluster operation |
| `--api-port` | `443` | Kubernetes API port |
| `--token` | service account token | Bearer token for out-of-cluster operation |
| `--namespace` | `default` | Namespace watched by the controller |
| `--controller-name` | `serval.dev/gateway-controller` | GatewayClass controller name filter |
| `--router-service` | unset | Enables multi-endpoint router discovery |
| `--router-namespace` | `default` | Namespace of the router admin Service |

## Verification

Useful commands while developing this example:

```bash
zig build
zig build test
zig build build-gateway-example
zig build run-router-example -- --controller-mode
zig build audit-pub-consts-report
```

## Known Gaps

This example is intentionally incomplete in a few areas. Current deferred items are tracked in [`PARKED.md`](./PARKED.md).

Examples of currently parked or partial work:

- richer path rewrite support beyond simple prefix stripping
- full GatewayClass and HTTPRoute status coverage
- TLS listener termination and certificate wiring
- additional Gateway API match/filter features

## Related Docs

- [`serval/ARCHITECTURE.md`](../../serval/ARCHITECTURE.md)
- [`docs/architecture/layering-and-ownership.md`](../../docs/architecture/layering-and-ownership.md)
- [`docs/engineering/component-usage.md`](../../docs/engineering/component-usage.md)
- [`docs/engineering/code-placement.md`](../../docs/engineering/code-placement.md)
- [`docs/standards/testing-and-verification.md`](../../docs/standards/testing-and-verification.md)
- [`serval-k8s-gateway/README.md`](../../serval-k8s-gateway/README.md)
- [`deploy/GATEWAY_ARCHITECTURE.md`](../../deploy/GATEWAY_ARCHITECTURE.md)
