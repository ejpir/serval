#!/bin/bash
# deploy-k3s.sh - Deploy serval-gateway to a local k3s cluster
#
# Prerequisites:
#   - k3s installed and running (k3s server)
#   - Docker installed (for building images)
#   - Zig compiler available
#
# Usage:
#   ./deploy/deploy-k3s.sh [OPTIONS]
#
# Options:
#   --build-only     Only build binaries and images, don't deploy
#   --deploy-only    Only deploy (assumes images already built)
#   --clean          Remove all deployed resources
#   --help           Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ZIG_PATH="${ZIG_PATH:-/usr/local/zig-x86_64-linux-0.16.0-dev.1912+0cbaaa5eb/zig}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check k3s
    if ! command -v k3s &> /dev/null; then
        log_error "k3s not found. Install with: curl -sfL https://get.k3s.io | sh -"
        exit 1
    fi

    # Check kubectl (use k3s kubectl if system kubectl not available)
    if command -v kubectl &> /dev/null; then
        KUBECTL="kubectl"
    else
        KUBECTL="k3s kubectl"
    fi

    # Check docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Install Docker to build images."
        exit 1
    fi

    # Check zig
    if [[ ! -x "$ZIG_PATH" ]]; then
        log_error "Zig compiler not found at $ZIG_PATH"
        log_error "Set ZIG_PATH environment variable to your Zig installation"
        exit 1
    fi

    # Setup kubeconfig for k3s
    if [[ -f /etc/rancher/k3s/k3s.yaml ]]; then
        mkdir -p ~/.kube
        sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
        sudo chown "$(id -u):$(id -g)" ~/.kube/config
        export KUBECONFIG=~/.kube/config
    fi

    # Verify cluster connection
    if ! $KUBECTL cluster-info &> /dev/null; then
        log_error "Cannot connect to k3s cluster. Is k3s running?"
        exit 1
    fi

    log_info "All prerequisites satisfied"
}

# Build Zig binaries
build_binaries() {
    log_info "Building Zig binaries..."
    cd "$PROJECT_ROOT"

    log_info "  Building echo_backend..."
    $ZIG_PATH build build-echo-backend

    log_info "  Building router_example..."
    $ZIG_PATH build build-router-example

    log_info "  Building gateway_example..."
    $ZIG_PATH build build-gateway-example

    log_info "Binaries built successfully"
    ls -lh zig-out/bin/echo_backend zig-out/bin/router_example zig-out/bin/gateway_example
}

# Build Docker images
build_images() {
    log_info "Building Docker images..."
    cd "$PROJECT_ROOT"

    log_info "  Building echo-backend:latest..."
    sudo docker build -f deploy/Dockerfile.echo-backend -t echo-backend:latest .

    log_info "  Building serval-router:latest..."
    sudo docker build -f deploy/Dockerfile.router -t serval-router:latest .

    log_info "  Building serval-gateway:latest..."
    sudo docker build -f deploy/Dockerfile.gateway -t serval-gateway:latest .

    log_info "Docker images built successfully"
}

# Import images into k3s containerd
import_images() {
    log_info "Importing images into k3s..."

    log_info "  Importing echo-backend:latest..."
    sudo docker save echo-backend:latest | sudo k3s ctr images import -

    log_info "  Importing serval-router:latest..."
    sudo docker save serval-router:latest | sudo k3s ctr images import -

    log_info "  Importing serval-gateway:latest..."
    sudo docker save serval-gateway:latest | sudo k3s ctr images import -

    log_info "Images imported successfully"
    sudo k3s ctr images ls | grep -E "echo-backend|serval-router|serval-gateway" || true
}

# Install Gateway API CRDs
install_gateway_api() {
    log_info "Installing Gateway API CRDs..."

    if $KUBECTL get crd gateways.gateway.networking.k8s.io &> /dev/null; then
        log_info "  Gateway API CRDs already installed"
    else
        $KUBECTL apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.0.0/standard-install.yaml
        log_info "  Gateway API CRDs installed"
    fi
}

# Deploy components
deploy_components() {
    log_info "Deploying components..."
    cd "$PROJECT_ROOT"

    log_info "  Deploying echo-backend..."
    $KUBECTL apply -f deploy/examples/echo-backend.yaml

    log_info "  Deploying serval-router (data plane)..."
    $KUBECTL apply -f deploy/serval-router.yaml

    log_info "  Deploying serval-gateway (control plane - WIP)..."
    $KUBECTL apply -f deploy/serval-gateway.yaml

    log_info "  Creating Gateway and HTTPRoute..."
    $KUBECTL apply -f deploy/examples/basic-gateway.yaml
    $KUBECTL apply -f deploy/examples/basic-httproute.yaml

    log_info "Waiting for pods to be ready..."
    $KUBECTL wait --for=condition=ready pod -l app=echo-backend --timeout=60s || true
    $KUBECTL wait --for=condition=ready pod -l app=serval-router --timeout=60s || true

    log_info "Deployment complete"
}

# Show status
show_status() {
    log_info "Current status:"
    echo ""
    echo "=== Pods ==="
    $KUBECTL get pods -l 'app in (echo-backend, serval-router, serval-gateway)'
    echo ""
    echo "=== Services ==="
    $KUBECTL get svc -l 'app in (echo-backend, serval-router, serval-gateway)'
    echo ""
    echo "=== Gateway API Resources ==="
    $KUBECTL get gatewayclasses,gateways,httproutes
    echo ""
}

# Test the deployment
test_deployment() {
    log_info "Testing echo-backend service..."

    # Run a test curl pod
    $KUBECTL run test-curl --image=curlimages/curl --rm -it --restart=Never \
        -- curl -s http://echo-backend.default.svc.cluster.local:8080/test 2>/dev/null || {
        log_warn "Test curl failed (this is normal if curl image isn't cached)"
    }
}

# Clean up all resources
clean_up() {
    log_info "Cleaning up deployed resources..."
    cd "$PROJECT_ROOT"

    $KUBECTL delete -f deploy/examples/basic-httproute.yaml --ignore-not-found
    $KUBECTL delete -f deploy/examples/basic-gateway.yaml --ignore-not-found
    $KUBECTL delete -f deploy/serval-gateway.yaml --ignore-not-found
    $KUBECTL delete -f deploy/serval-router.yaml --ignore-not-found
    $KUBECTL delete -f deploy/examples/echo-backend.yaml --ignore-not-found

    log_info "Clean up complete"
}

# Show help
show_help() {
    cat << 'EOF'
deploy-k3s.sh - Deploy serval-gateway to a local k3s cluster

Prerequisites:
  - k3s installed and running (k3s server)
  - Docker installed (for building images)
  - Zig compiler available

Usage:
  ./deploy/deploy-k3s.sh [OPTIONS]

Options:
  --build-only     Only build binaries and images, don't deploy
  --deploy-only    Only deploy (assumes images already built)
  --status         Show current deployment status
  --clean          Remove all deployed resources
  --help           Show this help message

Examples:
  ./deploy/deploy-k3s.sh              # Full build and deploy
  ./deploy/deploy-k3s.sh --build-only # Just build binaries and images
  ./deploy/deploy-k3s.sh --status     # Show deployment status
  ./deploy/deploy-k3s.sh --clean      # Remove all resources
EOF
}

# Main
main() {
    local build_only=false
    local deploy_only=false
    local status_only=false
    local clean=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --build-only)
                build_only=true
                shift
                ;;
            --deploy-only)
                deploy_only=true
                shift
                ;;
            --status)
                status_only=true
                shift
                ;;
            --clean)
                clean=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    check_prerequisites

    if $status_only; then
        show_status
        exit 0
    fi

    if $clean; then
        clean_up
        exit 0
    fi

    if ! $deploy_only; then
        build_binaries
        build_images
        import_images
    fi

    if ! $build_only; then
        install_gateway_api
        deploy_components
        show_status
        # test_deployment  # Uncomment to run test
    fi

    log_info "Done!"
    echo ""
    echo "Next steps:"
    echo "  - Check pod logs: kubectl logs -l app=serval-gateway"
    echo "  - Test echo-backend: kubectl run test -it --rm --image=curlimages/curl -- curl http://echo-backend:8080/test"
    echo "  - Clean up: $0 --clean"
}

main "$@"
