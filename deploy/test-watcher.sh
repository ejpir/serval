#!/bin/bash
# Test script to trigger K8s watch events
# Run while gateway controller is running to see it process events

set -e

echo "=== Testing Gateway Watcher ==="
echo ""

# 1. Annotate Gateway (triggers MODIFIED)
echo "[1/5] Triggering Gateway MODIFIED event..."
sudo kubectl annotate gateway example-gateway test-timestamp="$(date +%s)" --overwrite
sleep 1

# 2. Create test HTTPRoute (triggers ADDED)
echo "[2/5] Creating test HTTPRoute..."
sudo kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: watcher-test-route
  namespace: default
spec:
  parentRefs:
    - name: example-gateway
  hostnames:
    - "test.example.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /test
      backendRefs:
        - name: echo-backend
          port: 8080
EOF
sleep 1

# 3. Update the HTTPRoute (triggers MODIFIED)
echo "[3/5] Updating HTTPRoute..."
sudo kubectl annotate httproute watcher-test-route test-update="$(date +%s)" --overwrite
sleep 1

# 4. Check Gateway status
echo "[4/5] Checking Gateway status..."
sudo kubectl get gateway example-gateway -o jsonpath='{.status.conditions[*].type}: {.status.conditions[*].status}'
echo ""
echo ""

# 5. Cleanup
echo "[5/5] Cleaning up test route..."
sudo kubectl delete httproute watcher-test-route --ignore-not-found
sleep 1

echo ""
echo "=== Test Complete ==="
echo "Check controller logs for ADDED/MODIFIED/DELETED events"
