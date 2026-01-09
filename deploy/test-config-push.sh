#!/bin/bash
# test-config-push.sh - Test router_example admin API config push
#
# Usage:
#   ./scripts/test-config-push.sh [ADMIN_PORT]
#
# Prerequisites:
#   1. Build: zig build
#   2. Start router_example: zig build run-router-example
#   3. Run this script in another terminal

set -e

ADMIN_PORT=${1:-9901}
BASE_URL="http://localhost:$ADMIN_PORT"

echo "=== Testing router_example Admin API ==="
echo "Admin URL: $BASE_URL"
echo ""

# Test healthz
echo -n "1. GET /healthz: "
if curl -sf "$BASE_URL/healthz" > /dev/null; then
    echo "OK (liveness probe passed)"
else
    echo "FAILED - is router_example running?"
    exit 1
fi

# Test readyz
echo -n "2. GET /readyz: "
if curl -sf "$BASE_URL/readyz" > /dev/null; then
    echo "OK (router initialized)"
else
    echo "FAILED - router not ready"
    exit 1
fi

# Test get routes (initial state)
echo "3. GET /routes (initial state):"
curl -sf "$BASE_URL/routes" | jq . 2>/dev/null || curl -sf "$BASE_URL/routes"
echo ""

# Test full config update
echo "4. POST /routes/update (full config replacement):"
RESPONSE=$(curl -sf -X POST "$BASE_URL/routes/update" \
  -H "Content-Type: application/json" \
  -d '{
    "routes": [
      {
        "name": "api-route",
        "path_prefix": "/api/",
        "pool_idx": 0,
        "strip_prefix": true
      },
      {
        "name": "static-route",
        "path_prefix": "/static/",
        "pool_idx": 1,
        "strip_prefix": true
      }
    ],
    "default_route": {
      "name": "default",
      "path_prefix": "/",
      "pool_idx": 0,
      "strip_prefix": false
    },
    "pools": [
      {
        "name": "api-pool",
        "upstreams": [
          {"host": "127.0.0.1", "port": 8001, "idx": 0, "tls": false}
        ],
        "lb_config": {"enable_probing": false}
      },
      {
        "name": "static-pool",
        "upstreams": [
          {"host": "127.0.0.1", "port": 9001, "idx": 1, "tls": false}
        ],
        "lb_config": {"enable_probing": false}
      }
    ]
  }' 2>&1)

if [ $? -eq 0 ]; then
    echo "   Response: $RESPONSE"
else
    echo "   FAILED: $RESPONSE"
    exit 1
fi
echo ""

# =============================================================================
# Test incremental CRUD operations
# =============================================================================

echo "=== Testing Incremental CRUD Operations ==="
echo ""

# Test adding a new route
echo "5. POST /routes/add (add new route):"
RESPONSE=$(curl -sf -X POST "$BASE_URL/routes/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "metrics-route",
    "path_prefix": "/metrics/",
    "pool_idx": 0,
    "strip_prefix": true
  }' 2>&1)

if [ $? -eq 0 ]; then
    echo "   Response: $RESPONSE"
else
    echo "   FAILED: $RESPONSE"
    exit 1
fi
echo ""

# Verify route was added
echo "6. GET /routes (verify route added):"
curl -sf "$BASE_URL/routes" | jq '.routes[] | select(.name == "metrics-route")' 2>/dev/null || echo "   (route should be visible)"
echo ""

# Test adding duplicate route (should fail with 409)
echo "7. POST /routes/add (duplicate - expect 409):"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/routes/add" \
  -H "Content-Type: application/json" \
  -d '{"name": "metrics-route", "path_prefix": "/other/", "pool_idx": 0}' 2>/dev/null)
if [ "$HTTP_CODE" = "409" ]; then
    echo "   OK (got 409 Conflict as expected)"
else
    echo "   UNEXPECTED: got $HTTP_CODE, expected 409"
fi
echo ""

# Test removing a route
echo "8. POST /routes/remove (remove route):"
RESPONSE=$(curl -sf -X POST "$BASE_URL/routes/remove" \
  -H "Content-Type: application/json" \
  -d '{"name": "metrics-route"}' 2>&1)

if [ $? -eq 0 ]; then
    echo "   Response: $RESPONSE"
else
    echo "   FAILED: $RESPONSE"
    exit 1
fi
echo ""

# Test removing non-existent route (should fail with 404)
echo "9. POST /routes/remove (non-existent - expect 404):"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/routes/remove" \
  -H "Content-Type: application/json" \
  -d '{"name": "non-existent-route"}' 2>/dev/null)
if [ "$HTTP_CODE" = "404" ]; then
    echo "   OK (got 404 Not Found as expected)"
else
    echo "   UNEXPECTED: got $HTTP_CODE, expected 404"
fi
echo ""

# Test adding a new pool
echo "10. POST /pools/add (add new pool):"
RESPONSE=$(curl -sf -X POST "$BASE_URL/pools/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "cache-pool",
    "upstreams": [
      {"host": "127.0.0.1", "port": 6379, "idx": 10, "tls": false}
    ],
    "lb_config": {"enable_probing": false}
  }' 2>&1)

if [ $? -eq 0 ]; then
    echo "   Response: $RESPONSE"
else
    echo "   FAILED: $RESPONSE"
    exit 1
fi
echo ""

# Verify pool was added
echo "11. GET /routes (verify pool added):"
curl -sf "$BASE_URL/routes" | jq '.pools[] | select(.name == "cache-pool")' 2>/dev/null || echo "   (pool should be visible)"
echo ""

# Test adding upstream to pool
echo "12. POST /upstreams/add (add upstream to cache-pool):"
RESPONSE=$(curl -sf -X POST "$BASE_URL/upstreams/add" \
  -H "Content-Type: application/json" \
  -d '{
    "pool_name": "cache-pool",
    "host": "127.0.0.1",
    "port": 6380,
    "idx": 11,
    "tls": false
  }' 2>&1)

if [ $? -eq 0 ]; then
    echo "   Response: $RESPONSE"
else
    echo "   FAILED: $RESPONSE"
    exit 1
fi
echo ""

# Verify upstream was added
echo "13. GET /routes (verify upstream added):"
curl -sf "$BASE_URL/routes" | jq '.pools[] | select(.name == "cache-pool") | .upstreams' 2>/dev/null || echo "   (should show 2 upstreams)"
echo ""

# Test removing upstream from pool
echo "14. POST /upstreams/remove (remove upstream from cache-pool):"
RESPONSE=$(curl -sf -X POST "$BASE_URL/upstreams/remove" \
  -H "Content-Type: application/json" \
  -d '{
    "pool_name": "cache-pool",
    "upstream_idx": 11
  }' 2>&1)

if [ $? -eq 0 ]; then
    echo "   Response: $RESPONSE"
else
    echo "   FAILED: $RESPONSE"
    exit 1
fi
echo ""

# Test removing last upstream (should fail with 400)
echo "15. POST /upstreams/remove (last upstream - expect 400):"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/upstreams/remove" \
  -H "Content-Type: application/json" \
  -d '{"pool_name": "cache-pool", "upstream_idx": 10}' 2>/dev/null)
if [ "$HTTP_CODE" = "400" ]; then
    echo "   OK (got 400 Bad Request as expected - cannot remove last upstream)"
else
    echo "   UNEXPECTED: got $HTTP_CODE, expected 400"
fi
echo ""

# Test removing pool (cache-pool has no routes, should succeed)
echo "16. POST /pools/remove (remove unused pool):"
RESPONSE=$(curl -sf -X POST "$BASE_URL/pools/remove" \
  -H "Content-Type: application/json" \
  -d '{"name": "cache-pool"}' 2>&1)

if [ $? -eq 0 ]; then
    echo "   Response: $RESPONSE"
else
    echo "   FAILED: $RESPONSE"
    exit 1
fi
echo ""

# Test removing pool in use (should fail with 409)
echo "17. POST /pools/remove (pool in use - expect 409):"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/pools/remove" \
  -H "Content-Type: application/json" \
  -d '{"name": "api-pool"}' 2>/dev/null)
if [ "$HTTP_CODE" = "409" ]; then
    echo "   OK (got 409 Conflict as expected - pool is referenced by routes)"
else
    echo "   UNEXPECTED: got $HTTP_CODE, expected 409"
fi
echo ""

# Test 404 for unknown path
echo "18. GET /unknown (expect 404): "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/unknown" 2>/dev/null)
if [ "$HTTP_CODE" = "404" ]; then
    echo "   OK (got 404 as expected)"
else
    echo "   UNEXPECTED: got $HTTP_CODE"
fi

# Final state
echo ""
echo "19. GET /routes (final state):"
curl -sf "$BASE_URL/routes" | jq . 2>/dev/null || curl -sf "$BASE_URL/routes"
echo ""

echo ""
echo "=== All tests passed! ==="
echo ""
echo "Next steps to verify routing:"
echo "  1. Start backend servers on ports 8001, 9001"
echo "  2. Send requests to http://localhost:8080/api/test"
echo "  3. Check that requests are routed to the api-pool backends"
