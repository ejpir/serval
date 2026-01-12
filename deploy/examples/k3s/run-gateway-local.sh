#!/bin/bash
# Run the gateway controller locally against a K8s cluster
# Requires: kubectl with cluster access, zig build completed

set -e

cd "$(dirname "$0")/.."

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$PORT_FORWARD_PID" ]; then
        kill $PORT_FORWARD_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Get fresh token (valid for 1 hour)
TOKEN=$(sudo kubectl create token serval-gateway -n default --duration=1h 2>/dev/null)

if [ -z "$TOKEN" ]; then
    echo "Error: Failed to get token. Make sure serval-gateway ServiceAccount exists."
    echo "Run: kubectl apply -f deploy/examples/k3s/serval-gateway.yaml"
    exit 1
fi

echo "Got fresh token for serval-gateway (valid 1h)"

# Build if needed
if [ ! -f ./zig-out/bin/gateway_example ]; then
    echo "Building gateway_example..."
    zig build
fi

# Start port-forward for router admin API
echo "Starting port-forward for serval-router:9901..."
sudo kubectl port-forward svc/serval-router 9901:9901 &
PORT_FORWARD_PID=$!
sleep 2

# Check if port-forward is running
if ! kill -0 $PORT_FORWARD_PID 2>/dev/null; then
    echo "Error: Failed to start port-forward. Is serval-router running?"
    exit 1
fi

echo "Port-forward started (PID: $PORT_FORWARD_PID)"
echo ""

# Run the gateway
exec ./zig-out/bin/gateway_example \
    --api-server 127.0.0.1 \
    --api-port 6443 \
    --data-plane-host 127.0.0.1 \
    --token "$TOKEN"
