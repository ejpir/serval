# Parked Features

This document tracks features that are supported by the Kubernetes Gateway API specification but are not yet implemented in the serval gateway controller. These are intentional deferred features, not bugs.

## Path Rewrite Enhancement

**Current State**: Router only supports `strip_prefix: true/false`

**Kubernetes Gateway API Support**:
- `replacePrefixMatch("/new")` - replace matched path prefix with a custom value
- `replaceFullPath("/exact")` - replace entire path with a custom value

**Current Workaround**: Use `strip_prefix` for simple cases where you only need to remove the prefix

**Implementation Plan**:
- [ ] Extend `serval-router` path rewriting API to support custom replacement values
- [ ] Update translator to extract path replacement config from HTTPRoute spec
- [ ] Add path replacement logic to request path handling in router handler
- [ ] Test with various prefix/replacement combinations

**Priority**: Medium - useful for path normalization but not critical for basic routing

---

## Exact Path Match Type

**Status**: ✅ IMPLEMENTED (Exact and PathPrefix)

Supports both match types from Kubernetes Gateway API:
- `type: Exact` - outputs `path_exact` in router JSON, matches only exact path
- `type: PathPrefix` - outputs `path_prefix` in router JSON, matches prefix

**Regex**: Not implemented - would require regex library.

See:
- `serval-router/types.zig` - `PathMatch` union with `.exact` and `.prefix`
- `serval-k8s-gateway/translator.zig` - `writeRoute()` outputs correct field
- `examples/router_example.zig` - Admin API accepts both `path_prefix` and `path_exact`

---

## Per-Route Health Check Config

**Current State**: Health check configuration is hardcoded in translator:
- `probe_interval_ms: 5000`
- `health_path: "/"`
- No per-route customization

**Kubernetes Gateway API Support**: Custom health checks via BackendPolicy (future Gateway API enhancement, not yet standardized)

**Current Workaround**: Configure health checks via GatewayClass parameters (cluster-wide, not per-route)

**Implementation Plan**:
- [ ] Add health check configuration fields to GatewayConfig structure
- [ ] Extract health check config from Gateway/HTTPRoute specs (or BackendPolicy once standardized)
- [ ] Pass per-backend health config to serval-prober
- [ ] Support custom health paths and probe intervals per route
- [ ] Add validation for health check configuration bounds

**Priority**: Low - hardcoded defaults work for most cases, customization can be added when BackendPolicy stabilizes in Gateway API

---

## Wildcard Host Matching

**Status**: ✅ IMPLEMENTED

Router supports wildcard host matching:
- `*.example.com` matches `foo.example.com`, `bar.example.com`, etc.
- Case-insensitive comparison per RFC 9110
- Works in both route matching and `allowed_hosts` validation

See: `serval-router/types.zig` - `matchesHost()` function

---

## Gateway Listener Hostname Validation

**Status**: ✅ IMPLEMENTED

Router now validates Host header against `allowed_hosts` (extracted from HTTPRoute hostnames):
- Returns 421 Misdirected Request for unknown hosts
- Returns 404 Not Found when no route matches
- Empty `allowed_hosts` = allow any host (backwards compatible)

See: `docs/plans/2026-01-10-allowed-hosts-design.md`

---

## Rename /routes/update API Endpoint

**Current State**: Endpoint is `POST /routes/update` but it replaces the entire config (routes, pools, upstreams, allowed_hosts).

**Expected Behavior**: Name should reflect that it's a full config replacement, not just routes.

**Options**:
- `POST /config` - simple, clear
- `PUT /config` - RESTful (PUT = full replacement)
- `POST /config/replace` - explicit about replacement

**Priority**: Low - cosmetic, current API works fine

---

## Config Change Detection

**Status**: ✅ IMPLEMENTED

DataPlaneClient now hashes the generated JSON config before pushing:
- Uses Wyhash (fast, good distribution) on the JSON bytes
- Stores `last_config_hash: u64` in DataPlaneClient struct
- Compares hash before push, skips if unchanged
- Logs "config unchanged (hash=X), skipping push" when skipped
- Logs "config pushed successfully (hash=X)" on actual push

See: `examples/gateway/data_plane.zig`

---

## Health Probe Dns Resolver

**Current State**: Health probing is disabled in translator (`enable_probing: false`) because `router_example`'s `handleRouteUpdate` passes `null` for `dns_resolver` to `swapRouter`.

**Expected Behavior**: Health probing should work for dynamically pushed configs.

**Implementation Plan**:
- [ ] Add global `DnsResolver` to `router_example`
- [ ] Pass `DnsResolver` to `swapRouter` from `handleRouteUpdate`
- [ ] Re-enable `enable_probing: true` in translator
- [ ] Test health probing with pushed configs

**Priority**: Medium - health probing improves reliability but not critical for basic routing

---

## Gateway/HTTPRoute Status Updates

**Current State**: Gateway controller doesn't update status subresources on Gateway or HTTPRoute objects.

**Expected Behavior**: Per Gateway API spec, controller should update:
- `GatewayClass.status.conditions` - Accepted
- `Gateway.status.conditions` - Accepted, Programmed
- `Gateway.status.listeners[].conditions` - per-listener status
- `HTTPRoute.status.parents[].conditions` - Accepted, ResolvedRefs

**Impact**: Users can't see if their routes are actually programmed and working.

**Implementation Plan**:
- [ ] Implement status update logic in StatusManager
- [ ] Update GatewayClass status when controller starts
- [ ] Update Gateway status after successful config push
- [ ] Update HTTPRoute status with parent conditions
- [ ] Handle partial failures (some routes work, some don't)

**Priority**: Medium - important for observability but not critical for routing

---

## TLS Termination

**Current State**: Only HTTP traffic is supported. No HTTPS/TLS termination.

**Expected Behavior**: Support TLS listeners in Gateway with certificate references to Kubernetes Secrets.

**Implementation Plan**:
- [ ] Watch Secret resources for TLS certificates
- [ ] Parse `tls.certificateRefs` from Gateway listeners
- [ ] Pass certificate data to serval-router
- [ ] Configure serval-tls for TLS termination
- [ ] Support SNI for multiple certificates

**Priority**: High for production use, but can be deferred for initial development

---

# Design Decisions

This section documents intentional design choices and their rationale.

## Pod IPs vs Service Names for Upstreams

**Decision**: Use pod IPs directly, not Kubernetes Service names.

**Example output**:
```json
{
  "upstreams": [
    {"host": "10.42.0.106", "port": 8080, "idx": 0},
    {"host": "10.42.0.68", "port": 8080, "idx": 1}
  ]
}
```

**Why pod IPs (not service names)**:

| Approach | Pros | Cons |
|----------|------|------|
| **Pod IPs** | Direct connection (no kube-proxy hop) | Must watch Endpoints for changes |
| | Serval does health-aware load balancing | More complex controller |
| | Per-pod health tracking | Pod IPs are ephemeral |
| | Lower latency | |
| **Service name** | Simple - just "echo-backend:8080" | Extra hop through kube-proxy |
| | K8s handles endpoint tracking | Can't do per-pod health tracking |
| | | kube-proxy does random LB, not health-aware |

**This is the standard pattern** for Gateway/LB implementations:
- Envoy (Istio) resolves endpoints directly
- nginx-ingress resolves endpoints directly
- Traefik resolves endpoints directly

**Requirement**: Gateway controller must watch EndpointSlices and push new config when pods change. Without this, stale pod IPs cause connection failures.

---

## Future Considerations

As the Kubernetes Gateway API specification evolves, these additional features may be implemented:

- **Header Matching**: Route selection based on request headers
- **Query Parameter Matching**: Route selection based on query parameters
- **Request Mirrors**: Mirror traffic to additional backends for testing
- **Weighted Routing**: Distribute traffic across multiple backends by percentage
- **Timeout Configuration**: Per-route timeout settings (separate from serval's hardcoded values)
- **Retry Configuration**: Per-route retry policies with configurable max attempts and backoff
- **Circuit Breaking**: Per-route circuit breaker configuration (future serval-health feature)


---

## Multi-Instance Config Push

**Status**: ✅ IMPLEMENTED

Gateway now pushes config to ALL data plane endpoints:
- Accepts comma-separated endpoint list via `--data-plane-endpoints`
- Pushes config to each endpoint in parallel
- Reports per-endpoint success/failure
- Supports both DNS names and direct IPs

See: `examples/gateway/data_plane.zig` - `pushConfig()` iterates over all endpoints

---

## DNS Resolver in Containers

**Status**: ✅ PARTIALLY ADDRESSED

Added `DnsResolver.normalizeFqdn()` to auto-append trailing dot to FQDN-like hostnames (4+ dots).
This is a general-purpose DNS utility that helps bypass search domain resolution in any
environment (Kubernetes, Docker, bare metal) where resolv.conf has search domains configured.

**Remaining Issues**:
- Zig's async DNS still may have issues in some container environments
- Not all resolution failures have been debugged

**Workaround** (still recommended for reliability):
- Use FQDN with trailing dot: `service.namespace.svc.cluster.local.`
- Or use `normalizeFqdn()` helper before resolving
- In Kubernetes: use `hostNetwork: true` on gateway pod

See: `serval-net/dns.zig` - `normalizeFqdn()` function

---

## DNS Returns Only First IP

**Status**: ✅ IMPLEMENTED

Added `DnsResolver.resolveAll()` to return all IP addresses from DNS response:
- Returns up to `DNS_MAX_ADDRESSES` (16) addresses
- Backwards compatible - existing `resolve()` unchanged
- Cache only stores first address (multi-address caching not needed)

Note: Gateway controller uses EndpointSlice discovery (not DNS) for multi-instance
config push, so this was not blocking HA deployments.

See: `serval-net/dns.zig` - `resolveAll()` and `ResolveAllResult`

---

## CLI Argument Parsing Format

**Current State**: Args parsed as `--flag value` (two elements), not `--flag=value` (one element).

**Impact**: Kubernetes deployments using `--flag=value` format silently ignore the values.

**Implementation Plan**:
- [ ] Support both `--flag=value` and `--flag value` formats
- [ ] Use standard arg parsing library or add split logic
- [ ] Document expected format in help text

**Priority**: Low - documented workaround (use separate array elements)

---

# Known Bugs

## Empty Routes Returns 400

**Symptom**: Pushing config with `{"routes":[],"pools":[]}` returns HTTP 400 from router.

**Expected**: Accept empty config (removes all routes).

**Workaround**: Ensure at least one route exists.

---

## Host Header Port Stripping

**Status**: ✅ IMPLEMENTED

Router now strips port from Host header before matching routes:
- `test1.example.com:31588` matches route with host `test1.example.com`
- Case-insensitive comparison per RFC 9110 §4.2.3
- Port stripping per RFC 9110 §7.2

See: `serval-router/types.zig` - `RouteMatcher.matches()`

---

# Local Testing with k3d

See `docs/plans/2026-01-11-deployment-architecture.md` for full deployment guide.

**Quick Start**:
```bash
# Create cluster
./deploy/k3d-setup.sh

# Build and import images
./deploy/k3d-build-images.sh

# Deploy
kubectl apply -f examples/gateway/k8s/router-daemonset.yaml
kubectl apply -f examples/gateway/k8s/gateway-deployment.yaml
kubectl apply -f examples/gateway/k8s/test-backend.yaml

# Test
curl -H "Host: echo.example.com" http://localhost:30180/
```

**Key Learnings**:
1. Use FQDN with trailing dot for DNS names
2. Use separate array elements for args (`--flag` then `value`)
3. Gateway needs `hostNetwork: true` + `dnsPolicy: ClusterFirstWithHostNet`
4. Config only pushed to first endpoint (multi-instance TODO)
