#!/bin/bash
# k3d cluster setup for testing serval edge node deployment
#
# Creates a multi-node k3s cluster with:
# - 1 server (control plane)
# - 2 edge agents (hostNetwork, public-facing)
# - 2 internal agents (backends, control plane workloads)
#
# Usage: ./deploy/k3d-setup.sh [cluster-name]

set -euo pipefail

CLUSTER_NAME="${1:-serval}"
EDGE_NODES=2
INTERNAL_NODES=2

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    if ! command -v docker &> /dev/null; then
        error "Docker not found. Install docker first."
    fi

    if ! docker info &> /dev/null; then
        error "Docker daemon not running or not accessible."
    fi

    if ! command -v k3d &> /dev/null; then
        warn "k3d not found. Installing..."
        curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
    fi

    if ! command -v kubectl &> /dev/null; then
        error "kubectl not found. Install kubectl first."
    fi

    log "Prerequisites OK"
}

# Delete existing cluster if it exists
cleanup_existing() {
    if k3d cluster list | grep -q "^${CLUSTER_NAME} "; then
        warn "Cluster '${CLUSTER_NAME}' already exists"
        read -p "Delete and recreate? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Deleting existing cluster..."
            k3d cluster delete "${CLUSTER_NAME}"
        else
            error "Aborted"
        fi
    fi
}

# Create the cluster
create_cluster() {
    local total_agents=$((EDGE_NODES + INTERNAL_NODES))

    log "Creating k3d cluster '${CLUSTER_NAME}'..."
    log "  - 1 server (k3s control plane)"
    log "  - ${EDGE_NODES} edge agents (will have hostNetwork ports mapped)"
    log "  - ${INTERNAL_NODES} internal agents"

    # Build port mappings for edge nodes
    # Each edge node gets ports mapped: 80, 443, 9901 (admin)
    # We offset by node index to avoid conflicts on the host
    # Using 30000+ range to avoid conflicts with common services
    local port_args=""
    for i in $(seq 0 $((EDGE_NODES - 1))); do
        local http_port=$((30080 + i * 100))
        local https_port=$((30443 + i * 100))
        local admin_port=$((30901 + i))
        port_args+=" --port ${http_port}:80@agent:${i}"
        port_args+=" --port ${https_port}:443@agent:${i}"
        port_args+=" --port ${admin_port}:9901@agent:${i}"
    done

    # Create cluster
    # shellcheck disable=SC2086
    k3d cluster create "${CLUSTER_NAME}" \
        --servers 1 \
        --agents ${total_agents} \
        ${port_args} \
        --k3s-arg "--disable=traefik@server:0" \
        --wait

    log "Cluster created"
}

# Label and taint edge nodes
configure_nodes() {
    log "Getting k3d kubeconfig..."

    # Write kubeconfig to a temp file and use it directly
    # This avoids issues with sudo writing to wrong home directory
    local kubeconfig_file
    kubeconfig_file=$(mktemp)
    k3d kubeconfig get "${CLUSTER_NAME}" > "${kubeconfig_file}"
    export KUBECONFIG="${kubeconfig_file}"

    log "Waiting for nodes to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=120s

    log "Installing Gateway API CRDs..."
    kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml

    log "Configuring edge nodes..."
    for i in $(seq 0 $((EDGE_NODES - 1))); do
        local node_name="k3d-${CLUSTER_NAME}-agent-${i}"

        log "  Labeling ${node_name} as edge node"
        kubectl label node "${node_name}" node-role.kubernetes.io/edge=true --overwrite

        log "  Tainting ${node_name}"
        kubectl taint node "${node_name}" node-role.kubernetes.io/edge=true:NoSchedule --overwrite 2>/dev/null || true
    done

    log "Labeling internal nodes..."
    for i in $(seq ${EDGE_NODES} $((EDGE_NODES + INTERNAL_NODES - 1))); do
        local node_name="k3d-${CLUSTER_NAME}-agent-${i}"

        log "  Labeling ${node_name} as internal node"
        kubectl label node "${node_name}" node-role.kubernetes.io/internal=true --overwrite
    done

    # Cleanup temp kubeconfig
    rm -f "${kubeconfig_file}"
}

# Print summary
print_summary() {
    local ctx="k3d-${CLUSTER_NAME}"

    # Get kubeconfig again for summary (previous one was in configure_nodes scope)
    local kubeconfig_file
    kubeconfig_file=$(mktemp)
    k3d kubeconfig get "${CLUSTER_NAME}" > "${kubeconfig_file}"
    export KUBECONFIG="${kubeconfig_file}"

    echo ""
    echo "=============================================="
    echo " k3d Cluster '${CLUSTER_NAME}' Ready"
    echo "=============================================="
    echo ""
    echo "Nodes:"
    kubectl get nodes -o wide -L node-role.kubernetes.io/edge,node-role.kubernetes.io/internal

    rm -f "${kubeconfig_file}"
    echo ""
    echo "Edge node port mappings (host -> container):"
    for i in $(seq 0 $((EDGE_NODES - 1))); do
        local http_port=$((30080 + i * 100))
        local https_port=$((30443 + i * 100))
        local admin_port=$((30901 + i))
        echo "  k3d-${CLUSTER_NAME}-agent-${i}:"
        echo "    HTTP:  localhost:${http_port} -> :80"
        echo "    HTTPS: localhost:${https_port} -> :443"
        echo "    Admin: localhost:${admin_port} -> :9901"
    done
    echo ""
    echo "To use this cluster, first merge the kubeconfig:"
    echo "  k3d kubeconfig merge ${CLUSTER_NAME} --kubeconfig-merge-default"
    echo "  kubectl config use-context ${ctx}"
    echo ""
    echo "Or use KUBECONFIG directly:"
    echo "  export KUBECONFIG=\$(k3d kubeconfig write ${CLUSTER_NAME})"
    echo ""
    echo "To deploy serval-router on edge nodes:"
    echo "  kubectl apply -f examples/gateway/k8s/router-daemonset.yaml"
    echo ""
    echo "To deploy serval-gateway on internal nodes:"
    echo "  kubectl apply -f examples/gateway/k8s/gateway-deployment.yaml"
    echo ""
    echo "To test hostNetwork (after deploying router):"
    echo "  curl http://localhost:30080/"
    echo ""
    echo "To delete cluster:"
    echo "  k3d cluster delete ${CLUSTER_NAME}"
    echo ""
}

# Main
main() {
    check_prerequisites
    cleanup_existing
    create_cluster
    configure_nodes
    print_summary
}

main "$@"
