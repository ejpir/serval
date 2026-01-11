#!/bin/bash
# Build serval binaries and import them into k3d as container images
#
# This creates minimal container images from the Zig binaries
# and imports them into the k3d cluster.
#
# Usage: ./deploy/k3d-build-images.sh [--debug] [cluster-name]
#
# Options:
#   --debug    Build with debug mode (enables debug logging)

set -euo pipefail

# Parse arguments
DEBUG_MODE=false
CLUSTER_NAME="serval"

for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG_MODE=true
            ;;
        *)
            CLUSTER_NAME="$arg"
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

cd "$PROJECT_ROOT"

# Build the Zig binaries
if [[ "$DEBUG_MODE" == "true" ]]; then
    log "Building serval binaries (DEBUG mode)..."
    zig build
else
    log "Building serval binaries (ReleaseFast)..."
    zig build -Doptimize=ReleaseFast
fi

# Check binaries exist
if [[ ! -f "zig-out/bin/router_example" ]]; then
    echo "Error: zig-out/bin/router_example not found"
    echo "Run: zig build"
    exit 1
fi

if [[ ! -f "zig-out/bin/gateway_example" ]]; then
    warn "zig-out/bin/gateway_example not found, skipping gateway image"
    BUILD_GATEWAY=false
else
    BUILD_GATEWAY=true
fi

# Create temporary directory for Docker builds
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Build router image
log "Building serval-router image..."
cat > "$TMPDIR/Dockerfile.router" << 'EOF'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY router_example /usr/local/bin/serval-router
RUN chmod +x /usr/local/bin/serval-router
ENTRYPOINT ["/usr/local/bin/serval-router"]
EOF

cp zig-out/bin/router_example "$TMPDIR/"
docker build -t serval-router:local -f "$TMPDIR/Dockerfile.router" "$TMPDIR"

# Build gateway image if available
if [[ "$BUILD_GATEWAY" == "true" ]]; then
    log "Building serval-gateway image..."
    cat > "$TMPDIR/Dockerfile.gateway" << 'EOF'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY gateway /usr/local/bin/serval-gateway
RUN chmod +x /usr/local/bin/serval-gateway
ENTRYPOINT ["/usr/local/bin/serval-gateway"]
EOF

    cp zig-out/bin/gateway_example "$TMPDIR/gateway"
    docker build -t serval-gateway:local -f "$TMPDIR/Dockerfile.gateway" "$TMPDIR"
fi

# Import into k3d
log "Importing images into k3d cluster '${CLUSTER_NAME}'..."
k3d image import serval-router:local -c "${CLUSTER_NAME}"

if [[ "$BUILD_GATEWAY" == "true" ]]; then
    k3d image import serval-gateway:local -c "${CLUSTER_NAME}"
fi

log "Done!"
echo ""
echo "Images available in cluster:"
echo "  - serval-router:local"
if [[ "$BUILD_GATEWAY" == "true" ]]; then
    echo "  - serval-gateway:local"
fi
echo ""
echo "Deploy with:"
echo "  kubectl apply -f examples/gateway/k8s/router-daemonset.yaml"
echo "  kubectl apply -f examples/gateway/k8s/gateway-deployment.yaml"
echo "  kubectl apply -f examples/gateway/k8s/test-backend.yaml"
