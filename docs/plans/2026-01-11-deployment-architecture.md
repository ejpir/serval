# Deployment Architecture: Edge Nodes and CDN Integration

## Overview

This document describes how to deploy serval-gateway (control plane) and serval-router (data plane) in Kubernetes for production use, particularly when serving as a CDN origin.

## Control Plane vs Data Plane

Serval uses a split architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                          │
│                                                                  │
│  ┌──────────────────────┐      ┌──────────────────────────────┐  │
│  │     Edge Nodes       │      │       Internal Nodes         │  │
│  │    (logical DMZ)     │      │                              │  │
│  │                      │      │  ┌────────────────────────┐  │  │
│  │  ┌────────────────┐  │ push │  │    serval-gateway      │  │  │
│  │  │ serval-router  │◄─┼──────┼──│    (control plane)     │  │  │
│  │  │ (data plane)   │  │ config  │                        │  │  │
│  │  │ hostNetwork    │  │      │  │  • watches K8s API     │  │  │
│  │  └───────┬────────┘  │      │  │  • translates Gateway  │  │  │
│  │          │           │      │  │    API to router config│  │  │
│  │          │ forward   │      │  │  • pushes to data plane│  │  │
│  │          ▼           │      │  └────────────────────────┘  │  │
│  │    ┌───────────┐     │      │                              │  │
│  │    │ backends  │◄────┼──────┼─── pod network ─────────────►│  │
│  │    │ (via pod  │     │      │                              │  │
│  │    │  network) │     │      │  ┌──────────┐  ┌──────────┐  │  │
│  │    └───────────┘     │      │  │  app-1   │  │  app-2   │  │  │
│  │                      │      │  └──────────┘  └──────────┘  │  │
│  └──────────────────────┘      └──────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
              ▲
              │
        CDN / Internet
```

### Component Responsibilities

| Component | Role | Location | Network |
|-----------|------|----------|---------|
| **serval-router** | Data plane - receives external traffic, routes to backends | Edge nodes | `hostNetwork: true` |
| **serval-gateway** | Control plane - watches K8s API, generates config, pushes to routers | Internal nodes | Normal pod network |
| **backends** | Application workloads | Internal nodes | Normal pod network |

### Why This Split?

**serval-router (data plane)** runs on edge nodes because:
- Receives all external HTTP/HTTPS traffic
- Needs public IP exposure (hostNetwork)
- Performance critical - no extra hops
- Stateless - config pushed from control plane

**serval-gateway (control plane)** runs on internal nodes because:
- Only talks to K8s API server (internal)
- Only pushes config to router admin port (internal)
- Never handles external traffic
- Can run with normal pod networking

This is the same pattern used by nginx-ingress, Traefik, Envoy/Istio - the controller that watches K8s resources is separate from the proxy that handles traffic. They're often packaged in the same binary but serve different roles.

## The Problem

Kubernetes' default networking adds hops between external traffic and your workloads:

```
CDN → Cloud Load Balancer → kube-proxy → Pod
              ↑                  ↑
         Extra $$$          iptables NAT
         Extra latency      Extra latency
```

For a gateway/ingress that handles all external traffic, this overhead is significant.

## Solution: HostNetwork on Dedicated Edge Nodes

Edge nodes are regular Kubernetes worker nodes that:
1. Have public IPs (or are behind a simple L4 passthrough)
2. Run **only** the data plane (serval-router)
3. Use `hostNetwork: true` to bypass kube-proxy

```
                         ┌─────────────────┐
                         │      CDN        │
                         │  (Cloudflare,   │
                         │   Fastly, etc)  │
                         └────────┬────────┘
                                  │
               ┌──────────────────┼──────────────────┐
               ▼                  ▼                  ▼
          ┌─────────┐       ┌─────────┐       ┌─────────┐
          │ edge-1  │       │ edge-2  │       │ edge-3  │
          │ router  │       │ router  │       │ router  │
          │ :80/:443│       │ :80/:443│       │ :80/:443│
          │ public  │       │ public  │       │ public  │
          └────┬────┘       └────┬────┘       └────┬────┘
               │                 │                 │
               │    ┌────────────┴────────────┐    │
               │    │                         │    │
               └────┤   K8s internal network  ├────┘
                    │      (pod network)      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
               ┌────┴────┐             ┌──────┴──────┐
               │ backends│             │ serval-     │
               │ (apps)  │             │ gateway     │
               └─────────┘             │ (control)   │
                                       └─────────────┘
```

**Key point**: The control plane (serval-gateway) does NOT run on edge nodes. It runs on internal nodes and pushes config to the routers via the internal pod network.

## Are Edge Nodes a DMZ?

**Yes, conceptually.** They're part of the cluster but serve a distinct role:

| Aspect | Edge Nodes | Internal Nodes |
|--------|------------|----------------|
| Network exposure | Public IPs, ports 80/443 open | Private IPs only |
| Workloads | **Only** serval-router (data plane) | serval-gateway, backends, everything else |
| Traffic direction | Receives external traffic | Internal only |
| Security posture | Hardened, minimal attack surface | Standard |

The edge nodes are the **only** nodes that receive external traffic directly. Internal nodes are reachable only through the edge layer.

However, unlike a traditional DMZ:
- Edge nodes are full cluster members (kubelet, CNI, etc.)
- They can reach internal services via pod networking
- They share the same etcd, API server, etc.

Think of it as a **logical DMZ** enforced by taints and node selectors, not network segmentation.

### What Runs Where

```
Edge Nodes (public facing):
  └── serval-router (DaemonSet, hostNetwork: true)
        • Binds to node's public IP on :80/:443
        • Receives CDN/external traffic
        • Routes to backend pod IPs

Internal Nodes (private):
  ├── serval-gateway (Deployment)
  │     • Watches Gateway API resources
  │     • Pushes config to routers
  │
  └── Application backends (Deployments)
        • Your actual services
        • Reached via pod network
```

## Deployment Manifests

### Step 1: Label and Taint Edge Nodes

```bash
# Label nodes as edge nodes
kubectl label node edge-1 node-role.kubernetes.io/edge=true
kubectl label node edge-2 node-role.kubernetes.io/edge=true

# Taint so only gateway workloads run there
kubectl taint node edge-1 node-role.kubernetes.io/edge=true:NoSchedule
kubectl taint node edge-2 node-role.kubernetes.io/edge=true:NoSchedule
```

### Step 2: Deploy Data Plane (serval-router)

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: serval-router
  namespace: serval-system
spec:
  selector:
    matchLabels:
      app: serval-router
  template:
    metadata:
      labels:
        app: serval-router
    spec:
      # Use host network - pod binds directly to node IP
      hostNetwork: true

      # Required: restore K8s DNS resolution when using hostNetwork
      dnsPolicy: ClusterFirstWithHostNet

      # Only run on edge nodes
      nodeSelector:
        node-role.kubernetes.io/edge: "true"

      # Tolerate the edge taint
      tolerations:
      - key: node-role.kubernetes.io/edge
        operator: Exists
        effect: NoSchedule

      containers:
      - name: router
        image: your-registry/serval-router:latest
        args:
          - "--admin-port=9901"  # For config pushes from control plane
        ports:
        - name: http
          containerPort: 80
          hostPort: 80
          protocol: TCP
        - name: https
          containerPort: 443
          hostPort: 443
          protocol: TCP
        - name: admin
          containerPort: 9901
          hostPort: 9901
          protocol: TCP
        securityContext:
          capabilities:
            add:
            - NET_BIND_SERVICE  # Required to bind ports < 1024
        resources:
          requests:
            cpu: 100m
            memory: 64Mi
          limits:
            cpu: 2000m
            memory: 256Mi
```

### Step 3: Deploy Control Plane (serval-gateway)

The control plane doesn't need hostNetwork - it only talks to the K8s API and pushes config to data plane.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: serval-gateway
  namespace: serval-system
spec:
  replicas: 2  # HA for leader election (future)
  selector:
    matchLabels:
      app: serval-gateway
  template:
    metadata:
      labels:
        app: serval-gateway
    spec:
      serviceAccountName: serval-gateway
      containers:
      - name: gateway
        image: your-registry/serval-gateway:latest
        args:
          - "--data-plane-url=http://serval-router-internal:9901"
        resources:
          requests:
            cpu: 50m
            memory: 32Mi
          limits:
            cpu: 500m
            memory: 128Mi
---
# Internal service for control plane to reach data plane admin ports
# This uses the pod network, not hostNetwork
apiVersion: v1
kind: Service
metadata:
  name: serval-router-internal
  namespace: serval-system
spec:
  selector:
    app: serval-router
  ports:
  - name: admin
    port: 9901
    targetPort: 9901
  clusterIP: None  # Headless - control plane can reach any/all instances
```

### Step 4: RBAC for Control Plane

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: serval-gateway
  namespace: serval-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: serval-gateway
rules:
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["gateways", "httproutes", "gatewayclasses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["gateways/status", "httproutes/status"]
  verbs: ["update", "patch"]
- apiGroups: [""]
  resources: ["services", "endpoints", "endpointslices"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]  # For TLS certificates
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: serval-gateway
subjects:
- kind: ServiceAccount
  name: serval-gateway
  namespace: serval-system
roleRef:
  kind: ClusterRole
  name: serval-gateway
  apiGroup: rbac.authorization.k8s.io
```

## CDN Configuration

Once deployed, configure your CDN with the edge node IPs as origin servers:

```
CDN Origin Configuration:
  - Origin 1: edge-1.example.com:80 (or IP)
  - Origin 2: edge-2.example.com:80 (or IP)
  - Origin 3: edge-3.example.com:80 (or IP)

  Health Check: GET / or custom path
  Protocol: HTTP (TLS terminated at CDN) or HTTPS (TLS terminated at edge)
```

### Getting Edge Node IPs

```bash
kubectl get nodes -l node-role.kubernetes.io/edge=true \
  -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="ExternalIP")].address}{"\n"}{end}'
```

## Traffic Flow

```
1. User request → CDN
2. CDN → edge node public IP:80 (direct, no LB)
3. hostNetwork pod receives on node IP
4. serval-router matches route, selects backend
5. serval-router → backend pod IP (via pod network)
6. Response flows back
```

## Comparison with LoadBalancer Service

| Aspect | LoadBalancer Service | HostNetwork + Edge Nodes |
|--------|---------------------|-------------------------|
| Setup complexity | Simple | More infrastructure work |
| Cost | Cloud LB fees | No extra cost |
| Latency | +1-2ms (extra hop) | Minimal |
| Scaling | Cloud LB handles it | Add more edge nodes |
| Health checks | Cloud LB built-in | CDN health checks edge nodes |
| TLS termination | At LB or pod | At pod |
| Port restrictions | Any port | Need NET_BIND_SERVICE for <1024 |

## Security Considerations

### Edge Node Hardening

Since edge nodes receive external traffic directly:

1. **Minimal workloads**: Only run ingress/gateway pods
2. **Network policies**: Restrict egress to known backend namespaces
3. **Pod security**: Run as non-root where possible
4. **Firewall**: Only allow 80/443 inbound, block other ports
5. **Monitoring**: Enhanced logging and alerting for edge nodes

### Network Policy Example

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: serval-router-egress
  namespace: serval-system
spec:
  podSelector:
    matchLabels:
      app: serval-router
  policyTypes:
  - Egress
  egress:
  # Allow traffic to application backends
  - to:
    - namespaceSelector:
        matchLabels:
          serval-backend: "true"
  # Allow DNS
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

## Alternative: Cloud-Native Load Balancing

Some clouds offer "container-native" load balancing that routes directly to pod IPs:

- **AWS**: Network Load Balancer with `target-type: ip` (requires AWS VPC CNI)
- **GCP**: Container-native load balancing with NEGs

This is a middle ground: still uses cloud LB, but avoids the kube-proxy hop.

```yaml
# AWS NLB with IP targets (still a cloud LB, but direct to pods)
apiVersion: v1
kind: Service
metadata:
  name: serval-router
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: "ip"
spec:
  type: LoadBalancer
  selector:
    app: serval-router
  ports:
  - port: 80
    targetPort: 80
```

## When to Use Each Approach

| Scenario | Recommendation |
|----------|----------------|
| Quick setup, cost not critical | LoadBalancer Service |
| High traffic, latency sensitive | HostNetwork + Edge Nodes |
| Multi-cloud / bare metal | HostNetwork + Edge Nodes |
| AWS with VPC CNI | NLB with IP targets |
| GCP | Container-native LB (NEGs) |

## Local Testing with k3d

k3d runs k3s nodes as Docker containers, allowing you to simulate multi-node clusters on a single machine.

### Quick Start

```bash
# 1. Create cluster with edge/internal nodes
./deploy/k3d-setup.sh

# 2. Build and import serval images
./deploy/k3d-build-images.sh

# 3. Deploy components
kubectl apply -f examples/gateway/k8s/router-daemonset.yaml
kubectl apply -f examples/gateway/k8s/gateway-deployment.yaml
kubectl apply -f examples/gateway/k8s/test-backend.yaml

# 4. Test
curl -H "Host: echo.example.com" http://localhost:30080/
```

### What the Scripts Create

**k3d-setup.sh** creates:
- 1 server node (k3s control plane)
- 2 edge agent nodes (labeled, tainted, ports mapped)
- 2 internal agent nodes

```
Cluster topology:

  k3d-serval-server-0     (k3s control plane)
  k3d-serval-agent-0      (edge, localhost:30080->:80, localhost:30901->:9901)
  k3d-serval-agent-1      (edge, localhost:30180->:80, localhost:30902->:9901)
  k3d-serval-agent-2      (internal)
  k3d-serval-agent-3      (internal)
```

**k3d-build-images.sh**:
- Builds Zig binaries with `zig build -Doptimize=ReleaseFast`
- Creates minimal container images using distroless base
- Imports images into the k3d cluster

### Port Mappings

Since k3d nodes are Docker containers, `hostNetwork: true` binds to the container's network. The `--port` flags in k3d bridge to your actual host:

```
Your machine                 k3d container (edge node)
localhost:30080   ──────►    container:80    ──────►    serval-router:80
                              (hostNetwork)
```

### Verifying the Setup

```bash
# Check nodes
kubectl get nodes -L node-role.kubernetes.io/edge

# Check router pods (should be on edge nodes)
kubectl get pods -l app=serval-router -o wide

# Check gateway pod (should be on internal node)
kubectl get pods -n serval-system -l app=serval-gateway -o wide

# Check backends (should be on internal nodes)
kubectl get pods -l app=echo-backend -o wide

# Test routing
curl -H "Host: echo.example.com" http://localhost:30080/
curl -H "Host: localhost" http://localhost:30080/
```

### Cleanup

```bash
k3d cluster delete serval
```
