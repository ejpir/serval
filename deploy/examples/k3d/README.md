# k3d Development Cluster

Local multi-node k3s cluster for testing serval edge node deployment.

## Quick Start

```bash
# Create cluster
./deploy/examples/k3d/k3d-setup.sh

# Set up kubectl context
source deploy/examples/k3d/k3d-env.sh

# Build and load images
./deploy/examples/k3d/k3d-build-images.sh

# Deploy router and test backends
kubectl apply -f deploy/examples/k3d/router-daemonset.yaml
kubectl apply -f deploy/examples/k3d/test-backend.yaml

# Test
curl http://localhost:30080/
```

## Cluster Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    k3d Cluster "serval"                     │
├─────────────────────────────────────────────────────────────┤
│  Server (control plane)                                     │
│    k3d-serval-server-0                                      │
├─────────────────────────────────────────────────────────────┤
│  Edge Agents (hostNetwork, port-mapped)                     │
│    k3d-serval-agent-0  ←  localhost:30080/30443/30901       │
│    k3d-serval-agent-1  ←  localhost:30180/30543/30902       │
├─────────────────────────────────────────────────────────────┤
│  Internal Agents (backends, gateway controller)             │
│    k3d-serval-agent-2                                       │
│    k3d-serval-agent-3                                       │
└─────────────────────────────────────────────────────────────┘
```

## Port Mappings

Edge nodes have hostNetwork enabled. k3d maps container ports to localhost:

| Node | HTTP | HTTPS | Admin |
|------|------|-------|-------|
| agent-0 | localhost:30080 | localhost:30443 | localhost:30901 |
| agent-1 | localhost:30180 | localhost:30543 | localhost:30902 |

**Pattern**: `30080 + (node_index * 100)` for HTTP, `30443 + (node_index * 100)` for HTTPS, `30901 + node_index` for admin.

### Getting External Ports

k3d routes traffic through a load balancer container (`k3d-serval-serverlb`):

```bash
# List all port mappings
sudo docker port k3d-serval-serverlb

# Get specific port (HTTP)
sudo docker port k3d-serval-serverlb 80

# JSON output for scripting
sudo docker inspect k3d-serval-serverlb --format '{{json .NetworkSettings.Ports}}' | jq .
```

## Testing

```bash
# Test HTTP routing
curl -v http://localhost:30080/

# Test with Host header
curl -H "Host: api.example.com" http://localhost:30080/api/v1/users

# Check router health
curl http://localhost:30901/healthz

# Check router readiness
curl http://localhost:30901/readyz

# Get router config (admin endpoint)
curl http://localhost:30901/config
```

## Scripts

| Script | Purpose |
|--------|---------|
| `k3d-setup.sh` | Create cluster with edge/internal node topology |
| `k3d-env.sh` | Set KUBECONFIG for kubectl |
| `k3d-build-images.sh` | Build serval images and load into k3d |

## Cleanup

```bash
k3d cluster delete serval
```
