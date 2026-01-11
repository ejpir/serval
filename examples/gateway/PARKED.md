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

**Current State**: All path matches are treated as prefix matches

**Kubernetes Gateway API Support**:
- `type: Exact` - exact string match only
- `type: PathPrefix` - prefix match (default, currently-implemented)
- `type: RegularExpression` - regex pattern match

**Current Workaround**: Use prefix matching (works for most cases, but `/health` will incorrectly match `/healthcheck`)

**Implementation Plan**:
- [ ] Add `PathMatchType` enum to translator types
- [ ] Parse `type` field from HTTPRoute PathMatch spec
- [ ] Pass match type through GatewayConfig to router
- [ ] Implement exact match logic in router handler
- [ ] Implement regex match logic in router handler (requires regex library)

**Priority**: High - exact matching is critical for precise routing and avoiding false matches

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

**Current State**: Router does exact string matching on Host header. `*.example.com` is treated as a literal string, not a wildcard pattern.

**Expected Behavior**: `*.example.com` should match `foo.example.com`, `bar.example.com`, etc.

**Impact**: Routes with wildcard hostnames don't work correctly - they only match if the request has the literal `Host: *.example.com` header.

**Implementation Plan**:
- [ ] Add wildcard matching logic to `RouteMatcher.matches()` in `serval-router/types.zig`
- [ ] Handle `*` prefix: `*.example.com` matches any subdomain of `example.com`
- [ ] Ensure case-insensitive comparison per RFC 9110
- [ ] Add tests for wildcard matching edge cases

**Priority**: High - wildcard hostnames are commonly used in Gateway API

---

## Gateway Listener Hostname Validation

**Status**: ✅ IMPLEMENTED

Router now validates Host header against `allowed_hosts` (extracted from HTTPRoute hostnames):
- Returns 421 Misdirected Request for unknown hosts
- Returns 404 Not Found when no route matches
- Empty `allowed_hosts` = allow any host (backwards compatible)

See: `docs/plans/2026-01-10-allowed-hosts-design.md`

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
