# serval-gateway TODO

Status: **Proof of Concept** - K8s API integration works, data plane not implemented.

## What Works

- K8s API client connects and authenticates via ServiceAccount token
- Watches Gateway API resources (GatewayClass, Gateway, HTTPRoute)
- Admin API server responds to health probes (`/healthz`, `/readyz`)
- TLS connection to K8s API using serval-tls (userspace mode)
- Runs in k3s with proper RBAC permissions

## Shortcuts Taken

### 1. Insecure TLS (No Certificate Verification)
**File:** `serval-gateway/k8s/client.zig:478`
```zig
tls.ssl.SSL_CTX_set_verify(ctx, tls.ssl.SSL_VERIFY_NONE, null);
```
**Fix:** Load CA cert from `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` and verify K8s API server certificate.

### 2. kTLS Disabled
**File:** `serval-gateway/k8s/client.zig:407`
```zig
net.Socket.TLS.TLSSocket.initClientWithOptions(fd, self.ssl_ctx, self.api_server, false)
```
**Reason:** kTLS read returned EBADMSG (errno 74) on K8s API responses.
**Fix:** Investigate kTLS compatibility with K8s API server's TLS implementation, or keep userspace TLS for control plane (acceptable - not performance critical).

### 3. TLSError Treated as Normal EOF
**File:** `serval-gateway/k8s/client.zig:322`
```zig
if (err == net.SocketError.ConnectionClosed or err == net.SocketError.TLSError) {
    break; // Use data we have
}
```
**Reason:** K8s API server closes connection after response, causing TLS shutdown error.
**Fix:** Properly handle TLS shutdown vs errors. Parse Content-Length header to know when response is complete.

### 4. Gateway Marked Ready Immediately
**File:** `examples/gateway_example.zig:140`
```zig
gw.ready.store(true, .release);
```
**Reason:** Watcher callback doesn't update gateway state.
**Fix:** Wire up watcher → gateway config updates properly. Mark ready only after first successful config sync.

### 5. No Data Plane
The gateway watches K8s API but doesn't route any traffic.
**Fix:** See "Data Plane Implementation" below.

### 6. Service Resolution Not Implemented
HTTPRoute references Services by name, but we don't resolve to ClusterIP/Endpoints.
**Fix:** Watch Services and Endpoints resources, resolve backend refs to actual IPs.

### 7. Admin Server Binds to 0.0.0.0
**File:** `serval-gateway/gateway.zig:342`
**Reason:** K8s probes come from kubelet, not localhost.
**Decision:** Acceptable for K8s deployment. Could add flag for localhost-only in non-K8s mode.

## Production TODO

### High Priority

#### Data Plane Implementation
1. Add serval-server to gateway_example for HTTP traffic
2. Translate HTTPRoute → serval-router routes dynamically
3. Watch Endpoints to get pod IPs for backends
4. Support path rewriting (`URLRewrite` filter)
5. Support header matching/modification

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│   Client    │────▶│  serval-gateway  │────▶│   Backend   │
│             │     │  (port 8080)     │     │   Pods      │
└─────────────┘     └──────────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │ serval-router│
                    │ (dynamic)    │
                    └─────────────┘
```

#### Secure TLS to K8s API
1. Load CA from ServiceAccount mount
2. Verify K8s API server certificate
3. Handle certificate rotation

#### Watch Streaming
Current implementation polls K8s API repeatedly. Should use proper watch with:
1. Long-lived HTTP connection
2. Chunked transfer encoding
3. resourceVersion tracking for resume
4. Bookmark events

### Medium Priority

#### Config Hot Reload
1. Atomic config swap without dropping connections
2. Graceful drain of old routes
3. Health check during reload

#### Gateway Status Updates
1. Update Gateway resource status in K8s
2. Report listener status (bound ports)
3. Report attached routes

#### Multiple Listeners
1. Support multiple ports (HTTP, HTTPS)
2. TLS termination per listener
3. SNI-based routing

#### Metrics
1. Expose Prometheus metrics for:
   - Requests per route
   - Backend health
   - Config sync latency
2. Integration with serval-metrics

### Lower Priority

#### TLS Features
- Client certificate auth (mTLS)
- TLS passthrough mode
- Certificate auto-reload

#### Advanced Routing
- Header-based routing
- Query parameter matching
- Traffic splitting (weighted backends)
- Request mirroring

#### Rate Limiting
- Per-route rate limits
- Integration with serval-ratelimit (future)

#### Cross-Namespace Routes
- ReferenceGrant support
- Namespace isolation

## Files Changed

### New/Modified for K8s Integration
- `serval-gateway/k8s/client.zig` - K8s API HTTP client using serval-tls
- `serval-gateway/gateway.zig` - Admin server bind address
- `serval-tls/stream.zig` - Added `enable_ktls` parameter
- `serval-net/tls_socket.zig` - Added `initClientWithOptions`
- `examples/gateway_example.zig` - Main entry point
- `build.zig` - Added gateway example, serval-net dependency

### Deployment
- `deploy/deploy-k3s.sh` - Deployment script
- `deploy/Dockerfile.gateway` - Container image
- `deploy/serval-gateway.yaml` - K8s deployment
- `deploy/examples/echo-backend.yaml` - Test backend

## Testing Checklist

- [x] Gateway starts in k3s pod
- [x] K8s API authentication works
- [x] Health probes pass (pod becomes Ready)
- [x] Watches Gateway API resources
- [ ] Routes traffic to backends
- [ ] Handles backend failures
- [ ] Config updates without restart
- [ ] TLS termination
- [ ] Metrics exposed
