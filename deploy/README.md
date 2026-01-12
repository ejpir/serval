# Serval Kubernetes Deployment

Kubernetes deployment manifests for serval components.

## Prerequisites

- k3d, k3s, or kind cluster running
- `kubectl` configured
- `docker` for building images

## k3d Setup (Recommended for Development)

### Quick Start

```bash
# 1. Create cluster with edge/internal node topology
./deploy/examples/k3d/k3d-setup.sh

# 2. Build and import images
./deploy/examples/k3d/k3d-build-images.sh

# 3. Deploy components
kubectl apply -f deploy/examples/k3d/router-daemonset.yaml
kubectl apply -f deploy/examples/k3d/gateway-deployment.yaml
kubectl apply -f deploy/examples/k3d/test-backend.yaml

# 4. Test
curl -H "Host: echo.example.com" http://localhost:30080/
```

### Port Mappings

The router runs as a DaemonSet on edge nodes using hostPort. k3d maps these to localhost:

| Service | Edge Node 0 | Edge Node 1 |
|---------|-------------|-------------|
| HTTP    | `localhost:30080` | `localhost:30180` |
| HTTPS   | `localhost:30443` | `localhost:30543` |
| Admin   | `localhost:30901` | `localhost:30902` |

### Architecture

```
                    Internet
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Edge Nodes (agent-0, agent-1)                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │  serval-router (DaemonSet, hostPort 80/443)       │  │
│  │  - Receives all inbound traffic                   │  │
│  │  - Routes based on Host header / path             │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Internal Nodes (agent-2, agent-3)                      │
│  ┌────────────────┐  ┌────────────────┐                 │
│  │  echo-backend  │  │  other-backend │  ...            │
│  └────────────────┘  └────────────────┘                 │
└─────────────────────────────────────────────────────────┘
```

**k3d local development:** The `--port` flags in `k3d-setup.sh` tell k3d to expose edge node ports to localhost. k3d handles this internally - you just use `localhost:30080` to reach the router.

### Useful Commands

```bash
# Check router status
kubectl get pods -l app=serval-router -o wide

# View router logs
kubectl logs -l app=serval-router -f

# Check router health
curl http://localhost:30901/readyz

# Rebuild and redeploy after code changes
./deploy/examples/k3d/k3d-build-images.sh
kubectl rollout restart daemonset/serval-router
```

## Components

| Component | Description | Status |
|-----------|-------------|--------|
| serval-router | Content-based router (hardcoded config) | Ready |
| serval-k8s-gateway | K8s Gateway API controller | WIP |
| echo-backend | Test backend for routing validation | Ready |

## Scripts

| Script | Purpose |
|--------|---------|
| `examples/k3d/k3d-setup.sh` | Create k3d cluster with edge/internal node topology |
| `examples/k3d/k3d-build-images.sh` | Build Zig binaries, create Docker images, import to k3d |
| `examples/k3s/deploy-k3s.sh` | Full deployment with prereq checks, status, cleanup (k3s) |
| `examples/k3s/build-and-load.sh` | Quick rebuild helper for iterating on single component (k3s) |

## k3s Quick Start

```bash
# Option 1: Full deployment script (recommended)
./deploy/examples/k3s/deploy-k3s.sh

# Option 2: Manual steps
zig build build-router-example
./deploy/examples/k3s/build-and-load.sh router
sudo kubectl apply -f deploy/examples/k3s/echo-backend.yaml
sudo kubectl apply -f deploy/examples/k3s/serval-router.yaml

# Test
curl http://localhost:31588/
curl http://localhost:31588/api/users
curl http://localhost:31588/static/image.png
```

## Build Commands

```bash
# Build router binary
zig build build-router-example

# Build gateway binary
zig build build-gateway-example

# Build echo-backend binary
zig build

# Build docker images
sudo docker build -f deploy/examples/k3s/Dockerfile.router -t serval-router:latest .
sudo docker build -f deploy/examples/k3s/Dockerfile.gateway -t serval-k8s-gateway:latest .
sudo docker build -f deploy/examples/k3s/Dockerfile.echo-backend -t echo-backend:latest .

# Load into k3s
sudo docker save serval-router:latest | sudo k3s ctr images import -
sudo docker save serval-k8s-gateway:latest | sudo k3s ctr images import -
sudo docker save echo-backend:latest | sudo k3s ctr images import -
```

## Deploy Commands

```bash
# Deploy echo-backend
sudo kubectl apply -f deploy/examples/k3s/echo-backend.yaml

# Deploy router
sudo kubectl apply -f deploy/examples/k3s/serval-router.yaml

# Deploy gateway (WIP)
sudo kubectl apply -f deploy/examples/k3s/serval-gateway.yaml
```

## Status Commands

```bash
# Check all serval pods
sudo kubectl get pods -l app=serval-router
sudo kubectl get pods -l app=serval-k8s-gateway
sudo kubectl get pods -l app=echo-backend

# Check services
sudo kubectl get svc serval-router serval-k8s-gateway echo-backend

# Check all at once
sudo kubectl get pods,svc | grep -E 'serval|echo'
```

## Logs Commands

```bash
# Router logs
sudo kubectl logs -l app=serval-router -f
sudo kubectl logs -l app=serval-router --tail=100

# Gateway logs
sudo kubectl logs -l app=serval-k8s-gateway -f
sudo kubectl logs -l app=serval-k8s-gateway --tail=100

# Echo backend logs
sudo kubectl logs -l app=echo-backend -f

# All pods for a deployment
sudo kubectl logs deployment/serval-router -f
sudo kubectl logs deployment/serval-k8s-gateway -f
```

## Debug Commands

```bash
# Describe pod (events, conditions)
sudo kubectl describe pod -l app=serval-router
sudo kubectl describe pod -l app=serval-k8s-gateway

# Exec into pod
sudo kubectl exec -it deployment/serval-router -- /bin/sh
sudo kubectl exec -it deployment/serval-k8s-gateway -- /bin/sh

# Check endpoints (backend IPs)
sudo kubectl get endpoints echo-backend
sudo kubectl get endpoints serval-router

# Port forward for local testing
sudo kubectl port-forward svc/serval-router 8080:80
sudo kubectl port-forward svc/serval-k8s-gateway 8080:80

# Check events
sudo kubectl get events --sort-by='.lastTimestamp' | tail -20
```

## Restart Commands

```bash
# Restart deployment (rolling)
sudo kubectl rollout restart deployment/serval-router
sudo kubectl rollout restart deployment/serval-k8s-gateway

# Delete and recreate
sudo kubectl delete -f deploy/serval-router.yaml && sudo kubectl apply -f deploy/serval-router.yaml

# Scale
sudo kubectl scale deployment/serval-router --replicas=3
sudo kubectl scale deployment/serval-router --replicas=1
```

## Clean Up

```bash
# Delete router
sudo kubectl delete -f deploy/serval-router.yaml

# Delete gateway
sudo kubectl delete -f deploy/serval-k8s-gateway.yaml

# Delete echo-backend
sudo kubectl delete -f deploy/examples/echo-backend.yaml

# Delete all
sudo kubectl delete -f deploy/serval-router.yaml -f deploy/serval-k8s-gateway.yaml -f deploy/examples/echo-backend.yaml
```

## Testing

```bash
# Get NodePort
NODE_PORT=$(sudo kubectl get svc serval-router -o jsonpath='{.spec.ports[0].nodePort}')

# Test routes
curl http://localhost:$NODE_PORT/
curl http://localhost:$NODE_PORT/api/users
curl http://localhost:$NODE_PORT/static/image.png

# Test with headers
curl -H "Host: api.example.com" http://localhost:$NODE_PORT/v1/users

# Load test
hey -n 1000 -c 10 http://localhost:$NODE_PORT/
```

## Troubleshooting

### Pod not starting

```bash
# Check pod status
sudo kubectl get pods -l app=serval-router -o wide

# Check events
sudo kubectl describe pod -l app=serval-router

# Common issues:
# - ImagePullBackOff: Image not loaded into k3s
# - CrashLoopBackOff: Check logs for startup errors
```

### Service not reachable

```bash
# Check service endpoints
sudo kubectl get endpoints serval-router

# Check if pods are ready
sudo kubectl get pods -l app=serval-router

# Test from within cluster
sudo kubectl run -it --rm debug --image=curlimages/curl -- curl http://serval-router/
```

### Backend not reachable

```bash
# Check echo-backend is running
sudo kubectl get pods -l app=echo-backend

# Check echo-backend service
sudo kubectl get svc echo-backend
sudo kubectl get endpoints echo-backend

# Test DNS resolution from router pod
sudo kubectl exec deployment/serval-router -- nslookup echo-backend
```
