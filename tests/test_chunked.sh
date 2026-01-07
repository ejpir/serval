#!/bin/bash
set -e

echo "=== Chunked Transfer Encoding Test ==="

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $LB_PID 2>/dev/null || true
}
trap cleanup EXIT

# Start chunked backend
echo "Starting chunked backend on :9001..."
python3 tests/chunked_backend.py 9001 &
BACKEND_PID=$!
sleep 1

# Build and start load balancer
echo "Building load balancer..."
zig build

echo "Starting load balancer on :8080 -> :9001..."
./zig-out/bin/lb_example --port 8080 --backend 127.0.0.1:9001 &
LB_PID=$!
sleep 2

# Test 1: GET with chunked response
echo ""
echo "Test 1: GET request, expect chunked response"
RESPONSE=$(curl -s -i http://127.0.0.1:8080/)
echo "$RESPONSE"

if echo "$RESPONSE" | grep -q "Hello from chunked backend!"; then
    echo "✓ Test 1 PASSED: Chunked response forwarded correctly"
else
    echo "✗ Test 1 FAILED: Response body incorrect"
    exit 1
fi

# Test 2: POST with body, expect chunked response
echo ""
echo "Test 2: POST request with body"
RESPONSE=$(curl -s -i -X POST -d "test data" http://127.0.0.1:8080/)
echo "$RESPONSE"

if echo "$RESPONSE" | grep -q "Received: test data"; then
    echo "✓ Test 2 PASSED: POST body received and echoed"
else
    echo "✗ Test 2 FAILED: POST body not echoed correctly"
    exit 1
fi

# Test 3: Large chunked response
echo ""
echo "Test 3: Request that generates large chunked response"
RESPONSE=$(curl -s -X POST -d "$(head -c 5000 /dev/zero | tr '\0' 'A')" http://127.0.0.1:8080/)
EXPECTED_LEN=$((5000 + 10))  # "Received: " + 5000 A's
ACTUAL_LEN=${#RESPONSE}

if [ "$ACTUAL_LEN" -ge 5000 ]; then
    echo "✓ Test 3 PASSED: Large response ($ACTUAL_LEN bytes)"
else
    echo "✗ Test 3 FAILED: Response too small ($ACTUAL_LEN bytes)"
    exit 1
fi

echo ""
echo "=== All tests PASSED ==="
