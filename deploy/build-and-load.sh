#!/bin/bash
# Build serval images and load into k3s
# Usage: ./deploy/build-and-load.sh [component]
# Examples:
#   ./deploy/build-and-load.sh          # Build all
#   ./deploy/build-and-load.sh router   # Build router only
#   ./deploy/build-and-load.sh gateway  # Build gateway only

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

build_router() {
    echo "=== Building router ==="
    zig build build-router-example
    sudo docker build -f deploy/Dockerfile.router -t serval-router:latest .
    sudo docker save serval-router:latest | sudo k3s ctr images import -
    echo "Router image loaded"
}

build_gateway() {
    echo "=== Building gateway ==="
    zig build build-gateway-example
    sudo docker build -f deploy/Dockerfile.gateway -t serval-gateway:latest .
    sudo docker save serval-gateway:latest | sudo k3s ctr images import -
    echo "Gateway image loaded"
}

build_echo() {
    echo "=== Building echo-backend ==="
    zig build
    sudo docker build -f deploy/Dockerfile.echo-backend -t echo-backend:latest .
    sudo docker save echo-backend:latest | sudo k3s ctr images import -
    echo "Echo-backend image loaded"
}

case "${1:-all}" in
    router)
        build_router
        ;;
    gateway)
        build_gateway
        ;;
    echo)
        build_echo
        ;;
    all)
        build_echo
        build_router
        build_gateway
        ;;
    *)
        echo "Usage: $0 [router|gateway|echo|all]"
        exit 1
        ;;
esac

echo ""
echo "=== Images loaded ==="
sudo k3s ctr images ls | grep -E 'serval|echo'
