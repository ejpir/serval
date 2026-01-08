# Serval Kubernetes Deployment

Kubernetes deployment manifests for serval components.

## Prerequisites

- k3s or kind cluster running
- `kubectl` configured
- `docker` for building images

## Components

| Component | Description | Status |
|-----------|-------------|--------|
| serval-router | Content-based router (hardcoded config) | Ready |
| serval-gateway | K8s Gateway API controller | WIP |
| echo-backend | Test backend for routing validation | Ready |

## Scripts

| Script | Purpose |
|--------|---------|
| `deploy-k3s.sh` | Full deployment with prereq checks, status, cleanup |
| `build-and-load.sh` | Quick rebuild helper for iterating on single component |

## Quick Start

```bash
# Option 1: Full deployment script (recommended)
./deploy/deploy-k3s.sh

# Option 2: Manual steps
zig build build-router-example
./deploy/build-and-load.sh router
sudo kubectl apply -f deploy/examples/echo-backend.yaml
sudo kubectl apply -f deploy/serval-router.yaml

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
sudo docker build -f deploy/Dockerfile.router -t serval-router:latest .
sudo docker build -f deploy/Dockerfile.gateway -t serval-gateway:latest .
sudo docker build -f deploy/Dockerfile.echo-backend -t echo-backend:latest .

# Load into k3s
sudo docker save serval-router:latest | sudo k3s ctr images import -
sudo docker save serval-gateway:latest | sudo k3s ctr images import -
sudo docker save echo-backend:latest | sudo k3s ctr images import -
```

## Deploy Commands

```bash
# Deploy echo-backend
sudo kubectl apply -f deploy/examples/echo-backend.yaml

# Deploy router
sudo kubectl apply -f deploy/serval-router.yaml

# Deploy gateway (WIP)
sudo kubectl apply -f deploy/serval-gateway.yaml
```

## Status Commands

```bash
# Check all serval pods
sudo kubectl get pods -l app=serval-router
sudo kubectl get pods -l app=serval-gateway
sudo kubectl get pods -l app=echo-backend

# Check services
sudo kubectl get svc serval-router serval-gateway echo-backend

# Check all at once
sudo kubectl get pods,svc | grep -E 'serval|echo'
```

## Logs Commands

```bash
# Router logs
sudo kubectl logs -l app=serval-router -f
sudo kubectl logs -l app=serval-router --tail=100

# Gateway logs
sudo kubectl logs -l app=serval-gateway -f
sudo kubectl logs -l app=serval-gateway --tail=100

# Echo backend logs
sudo kubectl logs -l app=echo-backend -f

# All pods for a deployment
sudo kubectl logs deployment/serval-router -f
sudo kubectl logs deployment/serval-gateway -f
```

## Debug Commands

```bash
# Describe pod (events, conditions)
sudo kubectl describe pod -l app=serval-router
sudo kubectl describe pod -l app=serval-gateway

# Exec into pod
sudo kubectl exec -it deployment/serval-router -- /bin/sh
sudo kubectl exec -it deployment/serval-gateway -- /bin/sh

# Check endpoints (backend IPs)
sudo kubectl get endpoints echo-backend
sudo kubectl get endpoints serval-router

# Port forward for local testing
sudo kubectl port-forward svc/serval-router 8080:80
sudo kubectl port-forward svc/serval-gateway 8080:80

# Check events
sudo kubectl get events --sort-by='.lastTimestamp' | tail -20
```

## Restart Commands

```bash
# Restart deployment (rolling)
sudo kubectl rollout restart deployment/serval-router
sudo kubectl rollout restart deployment/serval-gateway

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
sudo kubectl delete -f deploy/serval-gateway.yaml

# Delete echo-backend
sudo kubectl delete -f deploy/examples/echo-backend.yaml

# Delete all
sudo kubectl delete -f deploy/serval-router.yaml -f deploy/serval-gateway.yaml -f deploy/examples/echo-backend.yaml
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
