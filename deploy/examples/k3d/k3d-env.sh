#!/bin/bash
# Source this file to set up kubectl for the k3d serval cluster
#
# Usage: source deploy/examples/k3d/k3d-env.sh [cluster-name]
#
# After sourcing, kubectl commands will use the k3d cluster.
# If docker requires sudo, run: sudo -E bash -c 'source deploy/examples/k3d/k3d-env.sh'

CLUSTER_NAME="${1:-serval}"

# Check if k3d can access docker (may need sudo)
if ! k3d cluster list 2>/dev/null | grep -q "^${CLUSTER_NAME} "; then
    # Try with sudo if regular access fails
    if sudo k3d cluster list 2>/dev/null | grep -q "^${CLUSTER_NAME} "; then
        echo "Note: docker requires sudo"
        KUBECONFIG_FILE=$(mktemp)
        sudo k3d kubeconfig get "${CLUSTER_NAME}" > "${KUBECONFIG_FILE}"
        chmod 600 "${KUBECONFIG_FILE}"
        export KUBECONFIG="${KUBECONFIG_FILE}"
        echo "KUBECONFIG set to k3d cluster '${CLUSTER_NAME}'"
        echo "kubectl is now configured (no sudo needed for kubectl)"
        return 0 2>/dev/null || exit 0
    fi
    echo "Error: k3d cluster '${CLUSTER_NAME}' not found"
    echo "Run: ./deploy/examples/k3d/k3d-setup.sh"
    return 1 2>/dev/null || exit 1
fi

export KUBECONFIG=$(k3d kubeconfig write "${CLUSTER_NAME}")
echo "KUBECONFIG set to k3d cluster '${CLUSTER_NAME}'"
echo "kubectl is now configured for the k3d cluster"
